use serde::{Deserialize, Serialize};
use serde_json::Value;
use visa_component_adapter::{
    RegularFileAdapterError, RegularFileComponentState, RegularFileStateCodecError,
    RegularFileWorkloadPhase,
};
use visa_profile::{FileDurability, FileLockState};

use crate::state::{decode_canonical_hex, parse_canonical_u64};

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RegularFileStateWire {
    session_id: String,
    relative_path: String,
    logical_offset: String,
    version: String,
    size: String,
    content_digest_hex: String,
    durable_through: String,
    lock_held: bool,
    last_operation_id: Option<String>,
    phase: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct ObservationWire {
    pub operation_id: String,
    pub logical_offset: String,
    pub version: String,
    pub size: String,
    pub content_digest_hex: String,
    pub durable_through: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct ReadWire {
    pub observation: ObservationWire,
    pub bytes_hex: String,
}

pub(crate) struct Observation {
    pub operation_id: String,
    pub logical_offset: u64,
    pub version: u64,
    pub size: u64,
    pub content_digest: [u8; 32],
    pub durable_through: FileDurability,
}

pub(crate) fn state_to_value(
    state: &RegularFileComponentState,
) -> Result<Value, RegularFileAdapterError> {
    serde_json::to_value(RegularFileStateWire {
        session_id: state.session_id.clone(),
        relative_path: state.relative_path.clone(),
        logical_offset: state.logical_offset.to_string(),
        version: state.version.to_string(),
        size: state.size.to_string(),
        content_digest_hex: hex::encode(state.content_digest.0),
        durable_through: durability_name(state.durable_through).into(),
        lock_held: state.lock_state == FileLockState::Held,
        last_operation_id: state.last_operation.clone(),
        phase: phase_name(state.phase).into(),
    })
    .map_err(|error| {
        RegularFileAdapterError::Engine(format!(
            "encoding wacogo regular-file component state: {error}"
        ))
    })
}

pub(crate) fn state_from_value(
    value: Value,
) -> Result<RegularFileComponentState, RegularFileAdapterError> {
    let state: RegularFileStateWire = serde_json::from_value(value).map_err(|error| {
        RegularFileAdapterError::GuestTrap(format!(
            "wacogo returned an invalid regular-file component state: {error}"
        ))
    })?;
    if state.last_operation_id.as_deref() == Some("") {
        return Err(RegularFileAdapterError::GuestTrap(
            "wacogo regular-file state carried an empty last operation id".into(),
        ));
    }
    let content_digest: [u8; 32] = decode_canonical_hex(&state.content_digest_hex)
        .map_err(|detail| {
            RegularFileAdapterError::GuestTrap(format!(
                "wacogo regular-file state contentDigestHex was invalid: {detail}"
            ))
        })?
        .try_into()
        .map_err(|_| {
            RegularFileAdapterError::PortableState(RegularFileStateCodecError::Truncated)
        })?;
    Ok(RegularFileComponentState {
        session_id: state.session_id,
        relative_path: state.relative_path,
        logical_offset: canonical_u64(&state.logical_offset, "logicalOffset")?,
        version: canonical_u64(&state.version, "version")?,
        size: canonical_u64(&state.size, "size")?,
        content_digest: contract_core::Digest::from_bytes(content_digest),
        durable_through: parse_durability(&state.durable_through)?,
        lock_state: if state.lock_held { FileLockState::Held } else { FileLockState::Unlocked },
        last_operation: state.last_operation_id,
        phase: parse_phase(&state.phase)?,
    })
}

impl ObservationWire {
    pub(crate) fn decode(self) -> Result<Observation, RegularFileAdapterError> {
        if self.operation_id.is_empty() {
            return Err(RegularFileAdapterError::GuestTrap(
                "wacogo regular-file observation omitted its operation id".into(),
            ));
        }
        let content_digest = decode_canonical_hex(&self.content_digest_hex)
            .map_err(|detail| {
                RegularFileAdapterError::GuestTrap(format!(
                    "wacogo regular-file observation contentDigestHex was invalid: {detail}"
                ))
            })?
            .try_into()
            .map_err(|_| {
                RegularFileAdapterError::GuestTrap(
                    "wacogo regular-file observation digest was not 32 bytes".into(),
                )
            })?;
        Ok(Observation {
            operation_id: self.operation_id,
            logical_offset: canonical_u64(&self.logical_offset, "logicalOffset")?,
            version: canonical_u64(&self.version, "version")?,
            size: canonical_u64(&self.size, "size")?,
            content_digest,
            durable_through: parse_durability(&self.durable_through)?,
        })
    }
}

pub(crate) fn parse_durability(value: &str) -> Result<FileDurability, RegularFileAdapterError> {
    match value {
        "visible" => Ok(FileDurability::Visible),
        "data" => Ok(FileDurability::Data),
        "data-and-metadata" => Ok(FileDurability::DataAndMetadata),
        other => Err(RegularFileAdapterError::GuestTrap(format!(
            "wacogo regular-file durability was invalid: {other}"
        ))),
    }
}

pub(crate) const fn durability_name(value: FileDurability) -> &'static str {
    match value {
        FileDurability::Visible => "visible",
        FileDurability::Data => "data",
        FileDurability::DataAndMetadata => "data-and-metadata",
    }
}

fn parse_phase(value: &str) -> Result<RegularFileWorkloadPhase, RegularFileAdapterError> {
    match value {
        "active" => Ok(RegularFileWorkloadPhase::Active),
        "frozen" => Ok(RegularFileWorkloadPhase::Frozen),
        other => Err(RegularFileAdapterError::GuestTrap(format!(
            "wacogo regular-file phase was invalid: {other}"
        ))),
    }
}

const fn phase_name(value: RegularFileWorkloadPhase) -> &'static str {
    match value {
        RegularFileWorkloadPhase::Active => "active",
        RegularFileWorkloadPhase::Frozen => "frozen",
    }
}

fn canonical_u64(value: &str, name: &str) -> Result<u64, RegularFileAdapterError> {
    parse_canonical_u64(value).ok_or_else(|| {
        RegularFileAdapterError::GuestTrap(format!(
            "wacogo regular-file {name} was not canonical u64 text"
        ))
    })
}

#[cfg(test)]
mod tests {
    use contract_core::Digest;

    use super::*;

    #[test]
    fn state_wire_round_trips_without_engine_local_data() {
        let state = RegularFileComponentState {
            session_id: "session-a".into(),
            relative_path: "state/data.bin".into(),
            logical_offset: u64::MAX,
            version: 8,
            size: 9,
            content_digest: Digest::from_bytes([4; 32]),
            durable_through: FileDurability::Data,
            lock_state: FileLockState::Held,
            last_operation: Some("operation-a".into()),
            phase: RegularFileWorkloadPhase::Frozen,
        };
        assert_eq!(state_from_value(state_to_value(&state).unwrap()).unwrap(), state);
    }
}
