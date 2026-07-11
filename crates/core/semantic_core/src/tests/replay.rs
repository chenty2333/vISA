use super::*;

#[test]
fn journal_replay_checks_the_digest_of_each_input_state() {
    let fixture = fixture();
    let activate = match preflight(
        &fixture.state,
        &command(
            360,
            CommandKind::Activate {
                authority: fixture.component_authority,
                lease_epoch: LeaseEpoch(1),
            },
        ),
    ) {
        Decision::Commit(event) => event,
        other => panic!("expected event, got {other:?}"),
    };
    let active = apply(&fixture.state, &activate).expect("activation applies").into_state();
    let state_digest = |state: &CanonicalState| {
        let mut bytes = [0_u8; 32];
        bytes[0] = state.phase as u8;
        bytes[1..9].copy_from_slice(&state.component.generation.0.to_be_bytes());
        bytes[9..17].copy_from_slice(&state.ownership.epoch().0.to_be_bytes());
        Digest(bytes)
    };
    let entry = JournalEntry {
        version: CONTRACT_VERSION,
        position: JournalPosition(1),
        input_state: state_digest(&fixture.state),
        output_state: state_digest(&active),
        event: activate,
    };
    assert_eq!(
        replay(&fixture.state, core::slice::from_ref(&entry), state_digest)
            .expect("journal replays"),
        active
    );
    let continued = JournalEntry { position: JournalPosition(8), ..entry.clone() };
    assert_eq!(
        replay_from(&fixture.state, JournalPosition(7), &[continued], state_digest,)
            .expect("snapshot cursor continues"),
        active
    );

    let wrong = JournalEntry { input_state: digest(0xff), ..entry };
    assert!(matches!(
        replay(&fixture.state, &[wrong], state_digest),
        Err(ReplayError::InputStateDigestMismatch { .. })
    ));
}
