use alloc::{vec, vec::Vec};

use crate::{conformance, *};

struct BufferConsole {
    bytes: Vec<u8>,
}

impl ConsoleAuthority for BufferConsole {
    fn console_write(&mut self, bytes: &[u8]) -> SubstrateResult<usize> {
        self.bytes.extend_from_slice(bytes);
        Ok(bytes.len())
    }
}

#[test]
fn semantic_harness_profile_is_precise() {
    let capabilities = SubstrateCapabilitySet::semantic_harness();

    assert!(capabilities.supports_profile(SubstrateProfile::SemanticHarness));
    assert!(!capabilities.supports_profile(SubstrateProfile::MinimalBareMetal));
    assert!(!capabilities.supports_profile(SubstrateProfile::GuestFrontend));
    assert!(!capabilities.supports_profile(SubstrateProfile::DeviceCapable));
    assert!(!capabilities.supports_profile(SubstrateProfile::SnapshotReplayCapable));
}

#[test]
fn profile_capability_sets_satisfy_their_own_contract() {
    for profile in [
        SubstrateProfile::SemanticHarness,
        SubstrateProfile::MinimalBareMetal,
        SubstrateProfile::GuestFrontend,
        SubstrateProfile::DeviceCapable,
        SubstrateProfile::SnapshotReplayCapable,
    ] {
        assert_eq!(SubstrateProfile::parse(profile.as_str()), Some(profile));
        assert!(SubstrateCapabilitySet::for_profile(profile).supports_profile(profile));
    }
}

#[test]
fn host_validation_capabilities_cover_all_declared_contract_profiles() {
    let capabilities = SubstrateCapabilitySet::host_validation();

    assert!(capabilities.supports_profile(SubstrateProfile::SemanticHarness));
    assert!(capabilities.supports_profile(SubstrateProfile::MinimalBareMetal));
    assert!(capabilities.supports_profile(SubstrateProfile::GuestFrontend));
    assert!(capabilities.supports_profile(SubstrateProfile::DeviceCapable));
    assert!(capabilities.supports_profile(SubstrateProfile::SnapshotReplayCapable));
}

#[test]
fn authority_requirements_parse_manifest_tokens() {
    let requirements = AuthorityRequirementSet::from_tokens([
        "console",
        "timer",
        "event-queue",
        "guest-memory",
        "artifact-loading",
        "dmw:logical-or-better",
        "mmio",
        "irq",
        "dma:mediated-or-better",
        "snapshot:deterministic-replay",
        "code-publish:metadata-only",
    ])
    .unwrap();

    assert!(requirements.is_satisfied_by(SubstrateCapabilitySet::host_validation()));
    assert_eq!(AuthorityRequirementSet::from_tokens(["raw-mmio"]).unwrap_err().token, "raw-mmio");
}

#[test]
fn missing_optional_and_forbidden_authorities_are_reported() {
    let requirements = SubstrateAuthorityRequirements {
        required: AuthorityRequirementSet {
            console: true,
            dma: DmaRequirement::MediatedOrBetter,
            ..AuthorityRequirementSet::default()
        },
        optional: AuthorityRequirementSet {
            snapshot: SnapshotRequirement::DeterministicReplay,
            ..AuthorityRequirementSet::default()
        },
        forbidden: AuthorityRequirementSet { mmio: true, ..AuthorityRequirementSet::default() },
    };
    let mut capabilities = SubstrateCapabilitySet::semantic_harness();
    capabilities.mmio = true;

    let report = requirements.check(capabilities);

    assert!(!report.ok);
    assert_eq!(
        report.missing_required,
        vec![AuthorityMismatch::new("dma", "mediated-or-better", "none")]
    );
    assert_eq!(
        report.degraded_optional,
        vec![AuthorityMismatch::new("snapshot", "deterministic-replay", "none")]
    );
    assert_eq!(report.forbidden_present, vec![AuthorityPresent::new("mmio", "true")]);
}

#[test]
fn default_unsupported_errors_name_authority_and_operation() {
    let mut dma = NoDma;
    let mut dmw = NoDmw;

    conformance::dma_unsupported_is_reported(&mut dma).unwrap();
    conformance::dmw_unsupported_is_reported(&mut dmw).unwrap();
}

#[test]
fn event_queue_conformance_preserves_fifo_and_denials() {
    let mut queue = SimpleEventQueue::default();

    conformance::event_queue_fifo_or_declared_order(&mut queue).unwrap();
    conformance::capability_denied_event_is_visible(&mut queue).unwrap();
    assert!(queue.is_empty());
}

#[test]
fn console_conformance_requires_full_write() {
    let mut console = BufferConsole { bytes: Vec::new() };

    conformance::console_write_smoke(&mut console, b"vmos").unwrap();
    assert_eq!(console.bytes, b"vmos");
}

#[test]
fn profile_report_lists_all_missing_required_authorities() {
    let report = SubstrateCapabilitySet::empty().check_profile(SubstrateProfile::GuestFrontend);
    let missing: Vec<&str> = report.missing_required.iter().map(|item| item.authority).collect();

    assert!(!report.ok);
    assert_eq!(
        missing,
        vec![
            "console",
            "timer",
            "event-queue",
            "guest-memory",
            "artifact-loading",
            "dmw",
            "code-publish"
        ]
    );
}

#[test]
fn handles_reject_zero_identity_or_generation() {
    assert!(StoreRef::new(1, 1).is_valid());
    assert!(!StoreRef::new(0, 1).is_valid());
    assert!(!StoreRef::new(1, 0).is_valid());
}
