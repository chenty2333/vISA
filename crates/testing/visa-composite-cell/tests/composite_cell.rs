use std::{fs, path::PathBuf};

struct TestRoot(PathBuf);

impl TestRoot {
    fn new(label: &str) -> Self {
        let path = std::env::temp_dir()
            .join(format!("visa-composite-cell-{label}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&path);
        fs::create_dir_all(&path).unwrap();
        Self(path)
    }
}

impl Drop for TestRoot {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

/// The vendored dependency copies must stay byte-identical to the packages
/// they were taken from, otherwise the composite world could drift away from
/// the single-resource worlds it is meant to compose.
#[test]
fn vendored_wit_dependencies_match_their_source_packages() {
    let repository = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../..");
    for (source, copy) in [
        ("wit/cooperative-handoff/world.wit", "wit/composite-continuity/deps/continuity/world.wit"),
        (
            "wit/regular-file-continuity/world.wit",
            "wit/composite-continuity/deps/file-continuity/world.wit",
        ),
        (
            "wit/logical-request-continuity/world.wit",
            "wit/composite-continuity/deps/request-continuity/world.wit",
        ),
    ] {
        let original = fs::read(repository.join(source)).unwrap();
        let vendored = fs::read(repository.join(copy)).unwrap();
        assert_eq!(original, vendored, "{copy} drifted from {source}");
    }
}

#[test]
fn composite_state_encoding_round_trips_and_is_deterministic() {
    use visa_component_adapter::{
        LogicalRequestComponentState, LogicalRequestWorkloadLifecycle, RegularFileComponentState,
        RegularFileWorkloadPhase,
    };
    use visa_composite_cell::state::{
        CompositeComponentState, CompositePhase, PortableCompositeState, TimerKvComponentState,
    };

    let state = CompositeComponentState {
        session_id: "composite:session".into(),
        timer_kv: TimerKvComponentState {
            key: "composite-work".into(),
            expected_version: 3,
            completion_value: vec![1, 2, 255],
            timer_operation_id: Some("a".repeat(32)),
            timer_idempotency_key: "timer-key".into(),
            completion_idempotency_key: "completion-key".into(),
            timer_completed: false,
        },
        file: RegularFileComponentState {
            session_id: "composite:session".into(),
            relative_path: "data.bin".into(),
            logical_offset: 7,
            version: 2,
            size: 7,
            content_digest: contract_core::Digest::from_bytes([9; 32]),
            durable_through: visa_profile::FileDurability::Data,
            lock_state: visa_profile::FileLockState::Unlocked,
            last_operation: Some("b".repeat(32)),
            phase: RegularFileWorkloadPhase::Frozen,
        },
        request: LogicalRequestComponentState {
            session_id: "composite:session".into(),
            peer_identity: "visa-composite-loopback-peer".into(),
            credential_reference: "c".repeat(32),
            transport: visa_profile::LogicalRequestTransport::Reconnectable,
            delivery: contract_core::DeliveryPolicy::Deduplicated,
            replay: visa_profile::LogicalRequestReplay::WithOperationId,
            idempotency: visa_profile::LogicalRequestIdempotency::OperationIdDeduplicated,
            timeout_millis: 1_000,
            max_request_size: 1024,
            max_response_size: 4096,
            operation_id: "d".repeat(32),
            request_size: 4,
            request_digest: contract_core::Digest::from_bytes([5; 32]),
            request_phase: visa_profile::LogicalRequestPhase::Completed,
            response_cursor: 4,
            response: Some(visa_profile::LogicalResponseMetadata {
                size: 4,
                digest: contract_core::Digest::from_bytes([6; 32]),
            }),
            rejection: None,
            disposition: visa_profile::ContinuityDisposition::Revalidate,
            lifecycle: LogicalRequestWorkloadLifecycle::Frozen,
        },
        phase: CompositePhase::Frozen,
    };

    let first = PortableCompositeState::encode(&state).unwrap();
    let second = PortableCompositeState::encode(&state).unwrap();
    assert_eq!(first, second);
    assert_eq!(first.decode().unwrap(), state);

    let mut corrupt = first.as_bytes().to_vec();
    corrupt[0] ^= 0xff;
    assert!(PortableCompositeState::try_from_bytes(corrupt).is_err());

    let mut trailing = first.into_bytes();
    trailing.push(0);
    assert!(PortableCompositeState::try_from_bytes(trailing).is_err());
}

/// End-to-end smoke: four resources cross one handoff together.
#[test]
fn composite_cell_carries_four_resources_across_one_handoff() {
    let root = TestRoot::new("smoke");
    let report = visa_composite_cell::run(&root.0, "composite-smoke", 1_000_000_000)
        .unwrap_or_else(|error| panic!("composite cell failed: {error}"));

    let contents = fs::read(&report).unwrap();
    let report: serde_json::Value = serde_json::from_slice(&contents).unwrap();
    assert_eq!(report["schema"], "visa-composite-cell-report-v1");
    assert_eq!(report["passed"], true);

    let assertions = report["observations"]["assertions"].as_array().unwrap();
    assert!(!assertions.is_empty());
    for assertion in assertions {
        assert_eq!(assertion["passed"], true, "assertion {} failed", assertion["name"]);
    }
    assert_eq!(report["observations"]["epochs"]["source"], 1);
    assert_eq!(report["observations"]["epochs"]["destination"], 2);
    assert_eq!(report["observations"]["regular_file"]["after_destination_append"], "abcdef!?");
    assert_eq!(report["observations"]["logical_request"]["response"], "ping");
    assert_eq!(report["observations"]["timer"]["fired_operations"].as_array().unwrap().len(), 1);
}
