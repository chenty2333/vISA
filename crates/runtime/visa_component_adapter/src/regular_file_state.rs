use contract_core::Digest;
use visa_profile::{FileDurability, FileLockState, RegularFileState};

const MAGIC: &[u8; 8] = b"VISAFS01";
const MAX_FIELD_BYTES: usize = 64 * 1024;

pub const REGULAR_FILE_COMPONENT_STATE_ENCODING: &str = "visa-regular-file-state-v1";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RegularFileWorkloadPhase {
    Active,
    Frozen,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RegularFileComponentState {
    pub session_id: String,
    pub relative_path: String,
    pub logical_offset: u64,
    pub version: u64,
    pub size: u64,
    pub content_digest: Digest,
    pub durable_through: FileDurability,
    pub lock_state: FileLockState,
    pub last_operation: Option<String>,
    pub phase: RegularFileWorkloadPhase,
}

impl RegularFileComponentState {
    pub fn from_canonical(
        session_id: String,
        state: &RegularFileState,
        phase: RegularFileWorkloadPhase,
    ) -> Result<Self, RegularFileStateCodecError> {
        let relative_path = String::from_utf8(state.claim.relative_path.clone())
            .map_err(|_| RegularFileStateCodecError::InvalidUtf8)?;
        Ok(Self {
            session_id,
            relative_path,
            logical_offset: state.logical_offset,
            version: state.version,
            size: state.size,
            content_digest: state.content_digest,
            durable_through: state.durable_through,
            lock_state: state.lock_state,
            last_operation: state.last_operation.map(crate::identity_string),
            phase,
        })
    }

    pub fn validate_canonical(
        &self,
        state: &RegularFileState,
    ) -> Result<(), RegularFileStateCodecError> {
        if self.relative_path.as_bytes() != state.claim.relative_path
            || self.logical_offset != state.logical_offset
            || self.version != state.version
            || self.size != state.size
            || self.content_digest != state.content_digest
            || self.durable_through != state.durable_through
            || self.lock_state != state.lock_state
            || self.last_operation.as_deref()
                != state.last_operation.map(crate::identity_string).as_deref()
        {
            return Err(RegularFileStateCodecError::CanonicalMismatch);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PortableRegularFileState(Vec<u8>);

impl PortableRegularFileState {
    pub fn encode(state: &RegularFileComponentState) -> Result<Self, RegularFileStateCodecError> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(MAGIC);
        push_string(&mut bytes, &state.session_id)?;
        push_string(&mut bytes, &state.relative_path)?;
        bytes.extend_from_slice(&state.logical_offset.to_be_bytes());
        bytes.extend_from_slice(&state.version.to_be_bytes());
        bytes.extend_from_slice(&state.size.to_be_bytes());
        bytes.extend_from_slice(&state.content_digest.0);
        bytes.push(durability_tag(state.durable_through));
        bytes.push(lock_tag(state.lock_state));
        match &state.last_operation {
            Some(operation) => {
                bytes.push(1);
                push_string(&mut bytes, operation)?;
            }
            None => bytes.push(0),
        }
        bytes.push(phase_tag(state.phase));
        Ok(Self(bytes))
    }

    pub fn try_from_bytes(bytes: Vec<u8>) -> Result<Self, RegularFileStateCodecError> {
        decode(&bytes)?;
        Ok(Self(bytes))
    }

    pub fn decode(&self) -> Result<RegularFileComponentState, RegularFileStateCodecError> {
        decode(&self.0)
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    pub fn into_bytes(self) -> Vec<u8> {
        self.0
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RegularFileStateCodecError {
    InvalidMagic,
    Truncated,
    InvalidUtf8,
    InvalidDurability,
    InvalidLockState,
    InvalidOptional,
    InvalidPhase,
    TrailingBytes,
    FieldTooLarge,
    CanonicalMismatch,
}

fn decode(bytes: &[u8]) -> Result<RegularFileComponentState, RegularFileStateCodecError> {
    let mut decoder = Decoder { bytes, offset: 0 };
    if decoder.take(MAGIC.len())? != MAGIC {
        return Err(RegularFileStateCodecError::InvalidMagic);
    }
    let session_id = decoder.string()?;
    let relative_path = decoder.string()?;
    let logical_offset = decoder.u64()?;
    let version = decoder.u64()?;
    let size = decoder.u64()?;
    let content_digest = Digest::from_bytes(
        decoder.take(32)?.try_into().map_err(|_| RegularFileStateCodecError::Truncated)?,
    );
    let durable_through = match decoder.byte()? {
        0 => FileDurability::Visible,
        1 => FileDurability::Data,
        2 => FileDurability::DataAndMetadata,
        _ => return Err(RegularFileStateCodecError::InvalidDurability),
    };
    let lock_state = match decoder.byte()? {
        0 => FileLockState::Unlocked,
        1 => FileLockState::Held,
        _ => return Err(RegularFileStateCodecError::InvalidLockState),
    };
    let last_operation = match decoder.byte()? {
        0 => None,
        1 => Some(decoder.string()?),
        _ => return Err(RegularFileStateCodecError::InvalidOptional),
    };
    let phase = match decoder.byte()? {
        0 => RegularFileWorkloadPhase::Active,
        1 => RegularFileWorkloadPhase::Frozen,
        _ => return Err(RegularFileStateCodecError::InvalidPhase),
    };
    if decoder.offset != bytes.len() {
        return Err(RegularFileStateCodecError::TrailingBytes);
    }
    Ok(RegularFileComponentState {
        session_id,
        relative_path,
        logical_offset,
        version,
        size,
        content_digest,
        durable_through,
        lock_state,
        last_operation,
        phase,
    })
}

fn push_string(output: &mut Vec<u8>, value: &str) -> Result<(), RegularFileStateCodecError> {
    if value.len() > MAX_FIELD_BYTES {
        return Err(RegularFileStateCodecError::FieldTooLarge);
    }
    let length =
        u32::try_from(value.len()).map_err(|_| RegularFileStateCodecError::FieldTooLarge)?;
    output.extend_from_slice(&length.to_be_bytes());
    output.extend_from_slice(value.as_bytes());
    Ok(())
}

const fn durability_tag(value: FileDurability) -> u8 {
    match value {
        FileDurability::Visible => 0,
        FileDurability::Data => 1,
        FileDurability::DataAndMetadata => 2,
    }
}

const fn lock_tag(value: FileLockState) -> u8 {
    match value {
        FileLockState::Unlocked => 0,
        FileLockState::Held => 1,
    }
}

const fn phase_tag(value: RegularFileWorkloadPhase) -> u8 {
    match value {
        RegularFileWorkloadPhase::Active => 0,
        RegularFileWorkloadPhase::Frozen => 1,
    }
}

struct Decoder<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Decoder<'a> {
    fn take(&mut self, length: usize) -> Result<&'a [u8], RegularFileStateCodecError> {
        let end = self.offset.checked_add(length).ok_or(RegularFileStateCodecError::Truncated)?;
        let value =
            self.bytes.get(self.offset..end).ok_or(RegularFileStateCodecError::Truncated)?;
        self.offset = end;
        Ok(value)
    }

    fn byte(&mut self) -> Result<u8, RegularFileStateCodecError> {
        Ok(self.take(1)?[0])
    }

    fn u64(&mut self) -> Result<u64, RegularFileStateCodecError> {
        Ok(u64::from_be_bytes(
            self.take(8)?.try_into().map_err(|_| RegularFileStateCodecError::Truncated)?,
        ))
    }

    fn string(&mut self) -> Result<String, RegularFileStateCodecError> {
        let length = u32::from_be_bytes(
            self.take(4)?.try_into().map_err(|_| RegularFileStateCodecError::Truncated)?,
        ) as usize;
        if length > MAX_FIELD_BYTES {
            return Err(RegularFileStateCodecError::FieldTooLarge);
        }
        String::from_utf8(self.take(length)?.to_vec())
            .map_err(|_| RegularFileStateCodecError::InvalidUtf8)
    }
}

#[cfg(test)]
mod tests {
    use contract_core::{EntityRef, Identity, Rights};
    use visa_profile::{ContinuityDisposition, FileAccessMode, FileLockPolicy, RegularFileClaim};

    use super::*;

    fn canonical() -> RegularFileState {
        RegularFileState {
            claim: RegularFileClaim {
                resource: EntityRef::initial(Identity::from_u128(1)),
                namespace: Identity::from_u128(2),
                relative_path: b"state/data.bin".to_vec(),
                required_rights: Rights::PROFILE_READ.union(Rights::REBIND),
                access_mode: FileAccessMode::ReadOnly,
                durability: FileDurability::Data,
                lock_policy: FileLockPolicy::None,
                max_size: 1024,
            },
            logical_offset: 3,
            version: 4,
            size: 5,
            content_digest: Digest::from_bytes([7; 32]),
            durable_through: FileDurability::Data,
            lock_state: FileLockState::Unlocked,
            disposition: ContinuityDisposition::Revalidate,
            last_operation: Some(Identity::from_u128(8)),
        }
    }

    #[test]
    fn portable_file_state_round_trips_and_matches_canonical_truth() {
        let state = RegularFileComponentState::from_canonical(
            "session-a".into(),
            &canonical(),
            RegularFileWorkloadPhase::Frozen,
        )
        .unwrap();
        let portable = PortableRegularFileState::encode(&state).unwrap();
        let decoded = portable.decode().unwrap();
        assert_eq!(decoded, state);
        decoded.validate_canonical(&canonical()).unwrap();
    }

    #[test]
    fn canonical_drift_is_rejected() {
        let state = RegularFileComponentState::from_canonical(
            "session-a".into(),
            &canonical(),
            RegularFileWorkloadPhase::Active,
        )
        .unwrap();
        let mut changed = canonical();
        changed.version += 1;
        assert_eq!(
            state.validate_canonical(&changed),
            Err(RegularFileStateCodecError::CanonicalMismatch)
        );
    }
}
