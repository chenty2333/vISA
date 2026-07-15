use std::{cell::Cell, fmt};

use visa_joint_handoff::{
    JointProjectionAppendError, JointProjectionAppendOutcome, JointProjectionLog,
    JointProjectionLogHead, JointProjectionRecord,
};

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LostAckProjectionLogError<E> {
    Inner(E),
    AcknowledgementLost,
}

impl<E> fmt::Display for LostAckProjectionLogError<E>
where
    E: fmt::Display,
{
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Inner(error) => error.fmt(formatter),
            Self::AcknowledgementLost => {
                formatter.write_str("projection append committed but its acknowledgement was lost")
            }
        }
    }
}

impl<E> std::error::Error for LostAckProjectionLogError<E> where E: std::error::Error + 'static {}

/// Qualification-only fault wrapper. The delegated append reaches its durable
/// boundary first; the wrapper then drops exactly one acknowledgement so the
/// caller must recover or confirm the exact stored record.
pub struct LostAckProjectionLog<L> {
    inner: L,
    lose_next_ack: Cell<bool>,
}

impl<L> LostAckProjectionLog<L> {
    pub const fn new(inner: L) -> Self {
        Self { inner, lose_next_ack: Cell::new(false) }
    }

    pub fn arm_append_ack_loss(&self) {
        self.lose_next_ack.set(true);
    }

    pub const fn inner(&self) -> &L {
        &self.inner
    }

    pub fn into_inner(self) -> L {
        self.inner
    }
}

impl<L> JointProjectionLog for LostAckProjectionLog<L>
where
    L: JointProjectionLog,
{
    type Error = LostAckProjectionLogError<L::Error>;

    fn head(&self) -> Result<Option<JointProjectionLogHead>, Self::Error> {
        self.inner.head().map_err(LostAckProjectionLogError::Inner)
    }

    fn read(&self, sequence: u64) -> Result<Option<JointProjectionRecord>, Self::Error> {
        self.inner.read(sequence).map_err(LostAckProjectionLogError::Inner)
    }

    fn append(
        &mut self,
        expected_head: Option<JointProjectionLogHead>,
        record: &JointProjectionRecord,
    ) -> Result<JointProjectionAppendOutcome, JointProjectionAppendError<Self::Error>> {
        let outcome = self.inner.append(expected_head, record).map_err(|error| match error {
            JointProjectionAppendError::Conflict => JointProjectionAppendError::Conflict,
            JointProjectionAppendError::Backend(error) => {
                JointProjectionAppendError::Backend(LostAckProjectionLogError::Inner(error))
            }
        })?;
        if self.lose_next_ack.replace(false) {
            Err(JointProjectionAppendError::Backend(LostAckProjectionLogError::AcknowledgementLost))
        } else {
            Ok(outcome)
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{
        fs,
        sync::atomic::{AtomicU64, Ordering},
    };

    use contract_core::{Digest, EntityRef, Identity, LeaseEpoch, NodeIdentity};
    use joint_handoff_core::JointHandoffKey;

    use super::*;
    use crate::SqliteJointProjectionLog;

    static NEXT_DB: AtomicU64 = AtomicU64::new(1);

    fn id(value: u128) -> Identity {
        Identity::from_u128(value)
    }

    fn record() -> JointProjectionRecord {
        JointProjectionRecord {
            version: visa_joint_handoff::JOINT_PROJECTION_LOG_VERSION,
            key: JointHandoffKey {
                continuity_unit: EntityRef::initial(id(1)),
                handoff: id(2),
                source: NodeIdentity::new(id(3)),
                destination: NodeIdentity::new(id(4)),
                expected_epoch: LeaseEpoch(1),
                next_epoch: LeaseEpoch(2),
            },
            issuer_set_digest: Digest::from_bytes([9; 32]),
            sequence: 1,
            previous_record_digest: None,
            kind: visa_joint_handoff::JointProjectionRecordKind::BeginDestinationActivation {
                command_identity: id(10),
            },
        }
    }

    #[test]
    fn lost_ack_is_reported_only_after_the_sqlite_record_is_durable() {
        let path = std::env::temp_dir().join(format!(
            "visa-joint-lost-ack-{}-{}.sqlite3",
            std::process::id(),
            NEXT_DB.fetch_add(1, Ordering::Relaxed),
        ));
        for suffix in ["", "-wal", "-shm"] {
            let _ = fs::remove_file(format!("{}{}", path.display(), suffix));
        }
        let inner = SqliteJointProjectionLog::open(&path).unwrap();
        let mut faulting = LostAckProjectionLog::new(inner);
        faulting.arm_append_ack_loss();
        let record = record();
        assert!(matches!(
            faulting.append(None, &record),
            Err(JointProjectionAppendError::Backend(
                LostAckProjectionLogError::AcknowledgementLost
            ))
        ));
        drop(faulting);

        let reopened = SqliteJointProjectionLog::open(&path).unwrap();
        assert_eq!(reopened.read(1).unwrap(), Some(record));
        assert_eq!(reopened.head().unwrap().map(|head| head.sequence), Some(1));
        drop(reopened);
        for suffix in ["", "-wal", "-shm"] {
            let _ = fs::remove_file(format!("{}{}", path.display(), suffix));
        }
    }
}
