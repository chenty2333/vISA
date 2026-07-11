const MAGIC: &[u8; 8] = b"VISACS01";

/// Canonical encoding used for component-owned Stage 1 state.
pub const COMPONENT_STATE_ENCODING: &str = "visa-component-state-v1";

/// Engine-neutral representation of the accepted component state record.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ComponentState {
    pub session_id: String,
    pub key: String,
    pub expected_version: u64,
    pub completion_value: Vec<u8>,
    pub timer_operation_id: String,
    pub timer_idempotency_key: String,
    pub completion_idempotency_key: String,
    pub phase: WorkloadPhase,
}

pub type ComponentStatus = ComponentState;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WorkloadPhase {
    Armed,
    Frozen,
    Completed,
    Cancelled,
}

/// Portable component state after all owned host resources have been dropped.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PortableComponentState(Vec<u8>);

impl PortableComponentState {
    pub fn try_from_bytes(bytes: Vec<u8>) -> Result<Self, StateCodecError> {
        decode(&bytes)?;
        Ok(Self(bytes))
    }

    pub fn encode(state: &ComponentState) -> Result<Self, StateCodecError> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(MAGIC);
        push_string(&mut bytes, &state.session_id)?;
        push_string(&mut bytes, &state.key)?;
        bytes.extend_from_slice(&state.expected_version.to_be_bytes());
        push_bytes(&mut bytes, &state.completion_value)?;
        push_string(&mut bytes, &state.timer_operation_id)?;
        push_string(&mut bytes, &state.timer_idempotency_key)?;
        push_string(&mut bytes, &state.completion_idempotency_key)?;
        bytes.push(phase_tag(state.phase));
        Ok(Self(bytes))
    }

    pub fn decode(&self) -> Result<ComponentState, StateCodecError> {
        decode(&self.0)
    }

    pub fn phase(&self) -> Result<WorkloadPhase, StateCodecError> {
        self.decode().map(|state| state.phase)
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    pub fn into_bytes(self) -> Vec<u8> {
        self.0
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StateCodecError {
    InvalidMagic,
    Truncated,
    InvalidUtf8,
    InvalidPhase,
    TrailingBytes,
    FieldTooLarge,
}

fn decode(bytes: &[u8]) -> Result<ComponentState, StateCodecError> {
    let mut decoder = Decoder { bytes, offset: 0 };
    if decoder.take(MAGIC.len())? != MAGIC {
        return Err(StateCodecError::InvalidMagic);
    }
    let session_id = decoder.string()?;
    let key = decoder.string()?;
    let expected_version =
        u64::from_be_bytes(decoder.take(8)?.try_into().map_err(|_| StateCodecError::Truncated)?);
    let completion_value = decoder.bytes()?;
    let timer_operation_id = decoder.string()?;
    let timer_idempotency_key = decoder.string()?;
    let completion_idempotency_key = decoder.string()?;
    let phase = match decoder.byte()? {
        0 => WorkloadPhase::Armed,
        1 => WorkloadPhase::Frozen,
        2 => WorkloadPhase::Completed,
        3 => WorkloadPhase::Cancelled,
        _ => return Err(StateCodecError::InvalidPhase),
    };
    if decoder.offset != bytes.len() {
        return Err(StateCodecError::TrailingBytes);
    }
    Ok(ComponentState {
        session_id,
        key,
        expected_version,
        completion_value,
        timer_operation_id,
        timer_idempotency_key,
        completion_idempotency_key,
        phase,
    })
}

fn push_string(output: &mut Vec<u8>, value: &str) -> Result<(), StateCodecError> {
    push_bytes(output, value.as_bytes())
}

fn push_bytes(output: &mut Vec<u8>, value: &[u8]) -> Result<(), StateCodecError> {
    let length = u32::try_from(value.len()).map_err(|_| StateCodecError::FieldTooLarge)?;
    output.extend_from_slice(&length.to_be_bytes());
    output.extend_from_slice(value);
    Ok(())
}

const fn phase_tag(phase: WorkloadPhase) -> u8 {
    match phase {
        WorkloadPhase::Armed => 0,
        WorkloadPhase::Frozen => 1,
        WorkloadPhase::Completed => 2,
        WorkloadPhase::Cancelled => 3,
    }
}

struct Decoder<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl Decoder<'_> {
    fn take(&mut self, length: usize) -> Result<&[u8], StateCodecError> {
        let end = self.offset.checked_add(length).ok_or(StateCodecError::Truncated)?;
        let value = self.bytes.get(self.offset..end).ok_or(StateCodecError::Truncated)?;
        self.offset = end;
        Ok(value)
    }

    fn byte(&mut self) -> Result<u8, StateCodecError> {
        Ok(self.take(1)?[0])
    }

    fn bytes(&mut self) -> Result<Vec<u8>, StateCodecError> {
        let length =
            u32::from_be_bytes(self.take(4)?.try_into().map_err(|_| StateCodecError::Truncated)?);
        Ok(self.take(length as usize)?.to_vec())
    }

    fn string(&mut self) -> Result<String, StateCodecError> {
        String::from_utf8(self.bytes()?).map_err(|_| StateCodecError::InvalidUtf8)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn state() -> ComponentState {
        ComponentState {
            session_id: "session-a".into(),
            key: "work".into(),
            expected_version: 7,
            completion_value: vec![0, 1, 255],
            timer_operation_id: "timer-op".into(),
            timer_idempotency_key: "timer-key".into(),
            completion_idempotency_key: "completion-key".into(),
            phase: WorkloadPhase::Frozen,
        }
    }

    #[test]
    fn component_state_encoding_is_deterministic_and_round_trips() {
        let first = PortableComponentState::encode(&state()).unwrap();
        let second = PortableComponentState::encode(&state()).unwrap();
        assert_eq!(first, second);
        let decoded = first.decode().unwrap();
        assert_eq!(decoded.session_id, "session-a");
        assert_eq!(decoded.phase, WorkloadPhase::Frozen);
        assert_eq!(PortableComponentState::encode(&decoded).unwrap(), first);
    }

    #[test]
    fn component_state_encoding_preserves_the_visacs01_golden_bytes() {
        let state = ComponentState {
            session_id: "s".into(),
            key: "k".into(),
            expected_version: 7,
            completion_value: vec![0, 255],
            timer_operation_id: "op".into(),
            timer_idempotency_key: "tk".into(),
            completion_idempotency_key: "ck".into(),
            phase: WorkloadPhase::Frozen,
        };
        let expected = [
            b'V', b'I', b'S', b'A', b'C', b'S', b'0', b'1', 0, 0, 0, 1, b's', 0, 0, 0, 1, b'k', 0,
            0, 0, 0, 0, 0, 0, 7, 0, 0, 0, 2, 0, 255, 0, 0, 0, 2, b'o', b'p', 0, 0, 0, 2, b't',
            b'k', 0, 0, 0, 2, b'c', b'k', 1,
        ];
        assert_eq!(PortableComponentState::encode(&state).unwrap().as_bytes(), expected);
    }

    #[test]
    fn component_state_decoder_rejects_corruption_and_trailing_data() {
        let encoded = PortableComponentState::encode(&state()).unwrap();
        let mut corrupt = encoded.as_bytes().to_vec();
        corrupt[0] ^= 0xff;
        assert_eq!(
            PortableComponentState::try_from_bytes(corrupt),
            Err(StateCodecError::InvalidMagic)
        );

        let mut trailing = encoded.into_bytes();
        trailing.push(0);
        assert_eq!(
            PortableComponentState::try_from_bytes(trailing),
            Err(StateCodecError::TrailingBytes)
        );
    }
}
