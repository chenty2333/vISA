use contract_core::{CanonicalState, Digest, JournalEntry, JournalPosition, Rejection};

use crate::apply;

/// A journal entry cannot be applied unless both order and state digests agree.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ReplayError {
    UnsupportedVersion,
    JournalGap { expected: JournalPosition, actual: JournalPosition },
    InputStateDigestMismatch { expected: Digest, actual: Digest },
    OutputStateDigestMismatch { expected: Digest, actual: Digest },
    EventRejected(Rejection),
}

/// Replay a digest-bound journal from an initial state.
///
/// The caller supplies the canonical state digest function so the reducer does
/// not couple the contract to one encoding or hashing implementation.
pub fn replay<F>(
    initial: &CanonicalState,
    entries: &[JournalEntry],
    digest: F,
) -> Result<CanonicalState, ReplayError>
where
    F: Fn(&CanonicalState) -> Digest,
{
    replay_from(initial, JournalPosition::ORIGIN, entries, digest)
}

/// Replay entries that continue from an already committed snapshot cursor.
pub fn replay_from<F>(
    initial: &CanonicalState,
    base_position: JournalPosition,
    entries: &[JournalEntry],
    digest: F,
) -> Result<CanonicalState, ReplayError>
where
    F: Fn(&CanonicalState) -> Digest,
{
    let mut state = initial.clone();
    let mut position = base_position;

    for entry in entries {
        if !entry.version.is_supported() {
            return Err(ReplayError::UnsupportedVersion);
        }
        let expected_position = position
            .next()
            .ok_or(ReplayError::JournalGap { expected: position, actual: entry.position })?;
        if entry.position != expected_position {
            return Err(ReplayError::JournalGap {
                expected: expected_position,
                actual: entry.position,
            });
        }

        let actual_input = digest(&state);
        if entry.input_state != actual_input {
            return Err(ReplayError::InputStateDigestMismatch {
                expected: entry.input_state,
                actual: actual_input,
            });
        }

        state = apply(&state, &entry.event).map_err(ReplayError::EventRejected)?.into_state();

        let actual_output = digest(&state);
        if entry.output_state != actual_output {
            return Err(ReplayError::OutputStateDigestMismatch {
                expected: entry.output_state,
                actual: actual_output,
            });
        }
        position = entry.position;
    }

    Ok(state)
}
