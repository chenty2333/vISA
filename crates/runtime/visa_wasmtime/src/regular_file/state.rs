use contract_core::Digest;
use visa_component_adapter::{
    RegularFileComponentState, RegularFileStateCodecError, RegularFileWorkloadPhase,
};
use visa_profile::{FileDurability, FileLockState};

use super::bindings::{
    exports::visa::file_continuity::workload::{
        ComponentState as WitComponentState, Phase as WitPhase,
    },
    visa::file_continuity::regular_file::Durability as WitDurability,
};

pub(crate) fn from_wit_state(
    state: WitComponentState,
) -> Result<RegularFileComponentState, RegularFileStateCodecError> {
    let content_digest: [u8; 32] =
        state.content_digest.try_into().map_err(|_| RegularFileStateCodecError::Truncated)?;
    Ok(RegularFileComponentState {
        session_id: state.session_id,
        relative_path: state.relative_path,
        logical_offset: state.logical_offset,
        version: state.version,
        size: state.size,
        content_digest: Digest::from_bytes(content_digest),
        durable_through: from_wit_durability(state.durable_through),
        lock_state: if state.lock_held { FileLockState::Held } else { FileLockState::Unlocked },
        last_operation: state.last_operation_id,
        phase: from_wit_phase(state.phase),
    })
}

pub(crate) fn to_wit_state(state: &RegularFileComponentState) -> WitComponentState {
    WitComponentState {
        session_id: state.session_id.clone(),
        relative_path: state.relative_path.clone(),
        logical_offset: state.logical_offset,
        version: state.version,
        size: state.size,
        content_digest: state.content_digest.0.to_vec(),
        durable_through: to_wit_durability(state.durable_through),
        lock_held: state.lock_state == FileLockState::Held,
        last_operation_id: state.last_operation.clone(),
        phase: to_wit_phase(state.phase),
    }
}

pub(crate) const fn from_wit_durability(value: WitDurability) -> FileDurability {
    match value {
        WitDurability::Visible => FileDurability::Visible,
        WitDurability::Data => FileDurability::Data,
        WitDurability::DataAndMetadata => FileDurability::DataAndMetadata,
    }
}

pub(crate) const fn to_wit_durability(value: FileDurability) -> WitDurability {
    match value {
        FileDurability::Visible => WitDurability::Visible,
        FileDurability::Data => WitDurability::Data,
        FileDurability::DataAndMetadata => WitDurability::DataAndMetadata,
    }
}

const fn from_wit_phase(value: WitPhase) -> RegularFileWorkloadPhase {
    match value {
        WitPhase::Active => RegularFileWorkloadPhase::Active,
        WitPhase::Frozen => RegularFileWorkloadPhase::Frozen,
    }
}

const fn to_wit_phase(value: RegularFileWorkloadPhase) -> WitPhase {
    match value {
        RegularFileWorkloadPhase::Active => WitPhase::Active,
        RegularFileWorkloadPhase::Frozen => WitPhase::Frozen,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wit_state_round_trips_without_engine_local_data() {
        let state = RegularFileComponentState {
            session_id: "session-a".into(),
            relative_path: "state/data.bin".into(),
            logical_offset: 7,
            version: 8,
            size: 9,
            content_digest: Digest::from_bytes([4; 32]),
            durable_through: FileDurability::Data,
            lock_state: FileLockState::Held,
            last_operation: Some("operation-a".into()),
            phase: RegularFileWorkloadPhase::Frozen,
        };

        assert_eq!(from_wit_state(to_wit_state(&state)).unwrap(), state);
    }

    #[test]
    fn wit_state_rejects_a_non_digest_content_field() {
        let state = RegularFileComponentState {
            session_id: "session-a".into(),
            relative_path: "state/data.bin".into(),
            logical_offset: 0,
            version: 1,
            size: 0,
            content_digest: Digest::from_bytes([0; 32]),
            durable_through: FileDurability::Visible,
            lock_state: FileLockState::Unlocked,
            last_operation: None,
            phase: RegularFileWorkloadPhase::Active,
        };
        let mut wit = to_wit_state(&state);
        wit.content_digest.pop();
        assert_eq!(from_wit_state(wit), Err(RegularFileStateCodecError::Truncated));
    }
}
