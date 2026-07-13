use serde::{Deserialize, Serialize};
use serde_json::Value;
use visa_component_adapter::{AdapterError, ComponentState, WorkloadPhase};

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ComponentStateWire {
    session_id: String,
    key: String,
    expected_version: String,
    completion_value_hex: String,
    timer_operation_id: String,
    timer_idempotency_key: String,
    completion_idempotency_key: String,
    phase: String,
}

pub(crate) fn state_to_value(state: &ComponentState) -> Result<Value, AdapterError> {
    serde_json::to_value(ComponentStateWire {
        session_id: state.session_id.clone(),
        key: state.key.clone(),
        expected_version: state.expected_version.to_string(),
        completion_value_hex: hex::encode(&state.completion_value),
        timer_operation_id: state.timer_operation_id.clone(),
        timer_idempotency_key: state.timer_idempotency_key.clone(),
        completion_idempotency_key: state.completion_idempotency_key.clone(),
        phase: phase_name(state.phase).into(),
    })
    .map_err(|error| AdapterError::Engine(format!("encoding wacogo component state: {error}")))
}

pub(crate) fn state_from_value(value: Value) -> Result<ComponentState, AdapterError> {
    let state: ComponentStateWire = serde_json::from_value(value).map_err(|error| {
        AdapterError::GuestTrap(format!("wacogo returned an invalid component state: {error}"))
    })?;
    let expected_version = parse_canonical_u64(&state.expected_version).ok_or_else(|| {
        AdapterError::GuestTrap("wacogo state version was not canonical u64 text".into())
    })?;
    let completion_value = decode_canonical_hex(&state.completion_value_hex).map_err(|detail| {
        AdapterError::GuestTrap(format!("wacogo state completionValueHex was invalid: {detail}"))
    })?;
    let phase = match state.phase.as_str() {
        "armed" => WorkloadPhase::Armed,
        "frozen" => WorkloadPhase::Frozen,
        "completed" => WorkloadPhase::Completed,
        "cancelled" => WorkloadPhase::Cancelled,
        other => {
            return Err(AdapterError::GuestTrap(format!(
                "wacogo state phase was invalid: {other}"
            )));
        }
    };
    Ok(ComponentState {
        session_id: state.session_id,
        key: state.key,
        expected_version,
        completion_value,
        timer_operation_id: state.timer_operation_id,
        timer_idempotency_key: state.timer_idempotency_key,
        completion_idempotency_key: state.completion_idempotency_key,
        phase,
    })
}

pub(crate) fn parse_canonical_u64(value: &str) -> Option<u64> {
    let parsed = value.parse::<u64>().ok()?;
    (parsed.to_string() == value).then_some(parsed)
}

pub(crate) fn decode_canonical_hex(value: &str) -> Result<Vec<u8>, &'static str> {
    if !value.len().is_multiple_of(2) {
        return Err("hex text has odd length");
    }
    if !value.bytes().all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)) {
        return Err("hex text is not lowercase canonical hex");
    }
    hex::decode(value).map_err(|_| "hex text failed to decode")
}

const fn phase_name(phase: WorkloadPhase) -> &'static str {
    match phase {
        WorkloadPhase::Armed => "armed",
        WorkloadPhase::Frozen => "frozen",
        WorkloadPhase::Completed => "completed",
        WorkloadPhase::Cancelled => "cancelled",
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn state() -> ComponentState {
        ComponentState {
            session_id: "session-a".into(),
            key: "work".into(),
            expected_version: u64::MAX,
            completion_value: vec![0, 1, 255],
            timer_operation_id: "operation".into(),
            timer_idempotency_key: "timer-key".into(),
            completion_idempotency_key: "completion-key".into(),
            phase: WorkloadPhase::Frozen,
        }
    }

    #[test]
    fn state_wire_round_trips_exact_u64_hex_and_phase() {
        let encoded = state_to_value(&state()).unwrap();
        assert_eq!(encoded["expectedVersion"], json!(u64::MAX.to_string()));
        assert_eq!(encoded["completionValueHex"], json!("0001ff"));
        assert_eq!(encoded["phase"], json!("frozen"));
        assert_eq!(state_from_value(encoded).unwrap(), state());
    }

    #[test]
    fn state_wire_rejects_unknown_fields_noncanonical_numbers_and_hex() {
        let base = state_to_value(&state()).unwrap();
        for (field, value) in [
            ("expectedVersion", json!("01")),
            ("completionValueHex", json!("AA")),
            ("completionValueHex", json!("0")),
            ("phase", json!("paused")),
        ] {
            let mut changed = base.clone();
            changed.as_object_mut().unwrap().insert(field.into(), value);
            assert!(state_from_value(changed).is_err(), "field {field} must fail closed");
        }

        let mut extra = base;
        extra.as_object_mut().unwrap().insert("unexpected".into(), json!(true));
        assert!(state_from_value(extra).is_err());
    }

    #[test]
    fn canonical_u64_text_rejects_alternate_spellings_and_overflow() {
        for value in ["0", "1", "18446744073709551615"] {
            assert!(parse_canonical_u64(value).is_some());
        }
        for value in ["", "00", "01", "+1", "-0", " 1", "18446744073709551616"] {
            assert!(parse_canonical_u64(value).is_none(), "{value}");
        }
    }
}
