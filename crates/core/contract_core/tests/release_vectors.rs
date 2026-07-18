use contract_core::{
    AuthorityGrant, Command, CommandKind, DeliveryPolicy, Digest, EntityRef, Event, EventKind,
    EvidenceKind, EvidenceRef, Generation, Identity, JournalEntry, JournalPosition, KeyValueClaim,
    LeaseEpoch, LogicalDurationNanos, NodeIdentity, ResourceClaims, Rights, SchemaVersion,
    SnapshotBody, SnapshotEnvelope, SnapshotRecord, TimerClaim, TimerClock, TimerDisposition,
    canonical_bytes, snapshot_integrity,
};
use sha2::{Digest as _, Sha256};

fn identity(value: u8) -> Identity {
    let mut bytes = [0; 16];
    bytes[15] = value;
    Identity::from_bytes(bytes)
}

fn entity(value: u8, generation: u64) -> EntityRef {
    EntityRef::new(identity(value), Generation(generation))
}

fn digest(value: u8) -> Digest {
    Digest::from_bytes([value; 32])
}

fn evidence(value: u8, kind: EvidenceKind) -> EvidenceRef {
    EvidenceRef { identity: identity(value), kind, digest: digest(value) }
}

fn command_vector() -> Command {
    Command::new(identity(1), CommandKind::BeginHandoff { authority: entity(2, 1) })
}

fn event_vector() -> Event {
    Event::new(identity(3), EventKind::HandoffStarted)
}

fn journal_vector() -> JournalEntry {
    JournalEntry {
        version: SchemaVersion::new(1, 0),
        position: JournalPosition(4),
        input_state: digest(5),
        output_state: digest(6),
        event: event_vector(),
    }
}

fn snapshot_vector() -> SnapshotEnvelope {
    let body = SnapshotBody {
        version: SchemaVersion::new(1, 0),
        profile_version: SchemaVersion::new(1, 0),
        snapshot: SnapshotRecord {
            handoff: identity(7),
            snapshot: identity(8),
            journal_position: JournalPosition(9),
            evidence: evidence(10, EvidenceKind::SnapshotIntegrity),
        },
        source_node: NodeIdentity::new(identity(12)),
        component: entity(13, 1),
        component_digest: digest(14),
        profile_digest: digest(15),
        source_lease_epoch: LeaseEpoch(2),
        portable_state: vec![0xaa, 0x55],
        claims: ResourceClaims {
            timer: TimerClaim {
                resource: entity(16, 1),
                clock: TimerClock::PausedMonotonicDuration,
                required_rights: Rights::TIMER_ARM,
            },
            key_value: KeyValueClaim {
                resource: entity(17, 1),
                namespace: identity(18),
                required_rights: Rights::KV_READ,
                delivery: DeliveryPolicy::Deduplicated,
            },
        },
        timer: TimerDisposition::Pending {
            remaining: LogicalDurationNanos(5),
            arm_operation: identity(19),
        },
        key_value_last_version: Some(7),
        key_value_last_operation: Some(identity(20)),
        extensions: Vec::new(),
        authorities: Vec::<AuthorityGrant>::new(),
        operations: Vec::new(),
    };
    SnapshotEnvelope {
        version: SchemaVersion::new(1, 0),
        integrity: snapshot_integrity(&body).expect("snapshot body encodes"),
        body,
    }
}

fn lower_hex(bytes: &[u8]) -> String {
    use core::fmt::Write as _;
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        write!(&mut output, "{byte:02x}").expect("String writes do not fail");
    }
    output
}

#[test]
fn portable_contract_schema_version_1_0_is_exact() {
    let id = "portable-contract-schema-version-1.0";
    let bytes = canonical_bytes(&SchemaVersion::new(1, 0)).unwrap();
    assert_eq!(lower_hex(&bytes), "0100", "{id} Postcard bytes drifted");
}

#[test]
fn release_vectors_are_exact() {
    let vectors = [
        (
            "command-begin-handoff-v1",
            canonical_bytes(&command_vector()).unwrap(),
            "010000000000000000000000000000000001080000000000000000000000000000000201",
            "b600058adce044aa8ca33557dd1df596ea78806406bea61e08d8c393b4339f56",
        ),
        (
            "event-handoff-started-v1",
            canonical_bytes(&event_vector()).unwrap(),
            "01000000000000000000000000000000000308",
            "ac12160b47c3d811e8c8bf970ab8b6d1406405d4922604b04e88519455c96de4",
        ),
        (
            "journal-handoff-started-v1",
            canonical_bytes(&journal_vector()).unwrap(),
            "0100040505050505050505050505050505050505050505050505050505050505050505060606060606060606060606060606060606060606060606060606060606060601000000000000000000000000000000000308",
            "612039494c98c0ca61e732547101f1f09866d9e33b0b65acfd59332eb86c8405",
        ),
        (
            "snapshot-envelope-minimal-v1",
            canonical_bytes(&snapshot_vector()).unwrap(),
            "0100010001000000000000000000000000000000000700000000000000000000000000000008090000000000000000000000000000000a020a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0000000000000000000000000000000c0000000000000000000000000000000d010e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0202aa550000000000000000000000000000001001000100000000000000000000000000000011010000000000000000000000000000001204000105000000000000000000000000000000130107010000000000000000000000000000001400000064f953e59559e19d0bd4822984b470d2ad2d6dad6e120f1eefb26f4939b35a7e",
            "001ef85c3a98b842f2e817e263985fa533847e254e65d62403919ea5ac235d2f",
        ),
    ];

    for (id, bytes, expected_hex, expected_sha256) in vectors {
        assert_eq!(lower_hex(&bytes), expected_hex, "{id} Postcard bytes drifted");
        assert_eq!(lower_hex(&Sha256::digest(&bytes)), expected_sha256, "{id} SHA-256 drifted");
    }
}
