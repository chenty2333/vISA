use super::*;

pub(super) fn id(value: u128) -> Identity {
    Identity::from_u128(value)
}

pub(super) fn digest(value: u8) -> Digest {
    Digest::from_bytes([value; 32])
}

pub(super) fn evidence(value: u128, kind: EvidenceKind) -> EvidenceRef {
    EvidenceRef { identity: id(value), kind, digest: digest(value as u8) }
}

pub(super) struct Fixture {
    pub(super) state: CanonicalState,
    pub(super) component: EntityRef,
    pub(super) timer: EntityRef,
    pub(super) kv: EntityRef,
    pub(super) component_authority: EntityRef,
    pub(super) timer_authority: EntityRef,
    pub(super) kv_authority: EntityRef,
    pub(super) source_node: NodeIdentity,
    pub(super) destination_node: NodeIdentity,
}

pub(super) fn fixture() -> Fixture {
    let component = EntityRef::initial(id(1));
    let timer = EntityRef::initial(id(2));
    let kv = EntityRef::initial(id(3));
    let component_authority = EntityRef::initial(id(10));
    let timer_authority = EntityRef::initial(id(11));
    let kv_authority = EntityRef::initial(id(12));
    let source_node = NodeIdentity::new(id(100));
    let destination_node = NodeIdentity::new(id(101));
    let timer_rights = Rights::TIMER_ARM.union(Rights::TIMER_CANCEL).union(Rights::REBIND);
    let kv_rights = Rights::KV_READ.union(Rights::KV_WRITE).union(Rights::REBIND);
    let claims = ResourceClaims {
        timer: TimerClaim {
            resource: timer,
            clock: TimerClock::PausedMonotonicDuration,
            required_rights: timer_rights,
        },
        key_value: KeyValueClaim {
            resource: kv,
            namespace: id(30),
            required_rights: kv_rights,
            delivery: DeliveryPolicy::Deduplicated,
        },
    };
    let authorities = vec![
        AuthorityGrant::active_root(component_authority, component, component, Rights::HANDOFF),
        AuthorityGrant::active_root(timer_authority, component, timer, timer_rights),
        AuthorityGrant::active_root(kv_authority, component, kv, kv_rights),
    ];
    Fixture {
        state: CanonicalState::dormant(
            component,
            source_node,
            digest(1),
            digest(2),
            CONTRACT_VERSION,
            claims,
            authorities,
        ),
        component,
        timer,
        kv,
        component_authority,
        timer_authority,
        kv_authority,
        source_node,
        destination_node,
    }
}

pub(super) fn command(value: u128, kind: CommandKind) -> Command {
    Command::new(id(value), kind)
}

pub(super) fn commit(state: &CanonicalState, command: Command) -> CanonicalState {
    let event = match preflight(state, &command) {
        Decision::Commit(event) => event,
        other => panic!("expected commit, got {other:?}"),
    };
    apply(state, &event).expect("event applies").into_state()
}

pub(super) fn activate(fixture: &Fixture) -> CanonicalState {
    commit(
        &fixture.state,
        command(
            100,
            CommandKind::Activate {
                authority: fixture.component_authority,
                lease_epoch: LeaseEpoch(1),
            },
        ),
    )
}

pub(super) fn kv_request(fixture: &Fixture, operation: u128, key: u128) -> EffectRequest {
    EffectRequest {
        operation: id(operation),
        idempotency_key: IdempotencyKey::from_u128(key),
        causal_parent: None,
        node: fixture.source_node,
        subject: fixture.component,
        resource: fixture.kv,
        authority: fixture.kv_authority,
        lease_epoch: LeaseEpoch(1),
        request_digest: digest(operation as u8),
        kind: EffectKind::KeyValueCompareAndSet {
            key: vec![1],
            expected_version: None,
            value: vec![2],
        },
    }
}

pub(super) fn prepare_effect(state: &CanonicalState, request: EffectRequest) -> CanonicalState {
    let decision = preflight(
        state,
        &command(200 + request.operation.0[15] as u128, CommandKind::RequestEffect(request)),
    );
    let Decision::Execute { intent, .. } = decision else {
        panic!("expected effect execution, got {decision:?}");
    };
    apply(state, &intent).expect("intent applies").into_state()
}
