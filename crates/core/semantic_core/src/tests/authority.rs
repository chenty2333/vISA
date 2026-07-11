use super::*;

#[test]
fn every_rejection_leaves_state_equal() {
    let fixture = fixture();
    let state = activate(&fixture);
    let cases = [
        command(
            301,
            CommandKind::RequestEffect(EffectRequest {
                subject: EntityRef::new(fixture.component.identity, Generation(99)),
                ..kv_request(&fixture, 1_000, 1)
            }),
        ),
        command(
            302,
            CommandKind::RequestEffect(EffectRequest {
                authority: fixture.timer_authority,
                ..kv_request(&fixture, 1_001, 2)
            }),
        ),
        command(
            303,
            CommandKind::Freeze { portable_state: vec![1], timer: TimerDisposition::Idle },
        ),
    ];

    for rejected in cases {
        let before = state.clone();
        assert!(matches!(preflight(&state, &rejected), Decision::Reject(_)));
        assert_eq!(state, before);
    }
}

#[test]
fn stale_revoked_and_attenuated_authority_are_enforced() {
    let fixture = fixture();
    let state = activate(&fixture);
    let child = AuthorityGrant {
        authority: EntityRef::initial(id(20)),
        parent: Some(fixture.kv_authority),
        subject: fixture.component,
        resource: fixture.kv,
        rights: Rights::KV_WRITE,
        status: AuthorityStatus::Active,
    };
    let state = commit(
        &state,
        command(
            310,
            CommandKind::AttenuateAuthority {
                parent: fixture.kv_authority,
                derived: child.clone(),
            },
        ),
    );
    let accepted = EffectRequest { authority: child.authority, ..kv_request(&fixture, 1_010, 10) };
    assert!(matches!(
        preflight(&state, &command(311, CommandKind::RequestEffect(accepted))),
        Decision::Execute { .. }
    ));

    let state = commit(
        &state,
        command(312, CommandKind::RevokeAuthority { authority: fixture.kv_authority }),
    );
    let rejected = EffectRequest { authority: child.authority, ..kv_request(&fixture, 1_011, 11) };
    assert!(matches!(
        preflight(&state, &command(313, CommandKind::RequestEffect(rejected))),
        Decision::Reject(Rejection::AuthorityRevoked { .. })
            | Decision::Reject(Rejection::StaleGeneration { .. })
    ));
}
