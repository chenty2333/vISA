use alloc::{vec, vec::Vec};

use crate::{
    conformance::{self, ConformancePolicy},
    *,
};

struct BufferConsole {
    bytes: Vec<u8>,
}

impl ConsoleAuthority for BufferConsole {
    fn console_write(&mut self, bytes: &[u8]) -> SubstrateResult<usize> {
        self.bytes.extend_from_slice(bytes);
        Ok(bytes.len())
    }
}

#[derive(Default)]
struct FullConformanceBackend {
    console: Vec<u8>,
    events: Vec<SubstrateEvent>,
    memory: Vec<u8>,
    loaded: Vec<ArtifactImageRef>,
    published: Vec<(ArtifactImageRef, CodeObjectRef)>,
    mmio: u32,
    dma_live: bool,
    snapshot_live: bool,
}

impl ConsoleAuthority for FullConformanceBackend {
    fn console_write(&mut self, bytes: &[u8]) -> SubstrateResult<usize> {
        self.console.extend_from_slice(bytes);
        Ok(bytes.len())
    }
}

impl TimerAuthority for FullConformanceBackend {
    fn now(&self) -> SubstrateResult<VirtualTime> {
        Ok(VirtualTime::from_ticks(42))
    }

    fn arm_timer(&mut self, _deadline: VirtualTime, _token: WaitTokenRef) -> SubstrateResult<()> {
        Ok(())
    }
}

impl EventQueueAuthority for FullConformanceBackend {
    fn push_event(&mut self, event: SubstrateEvent) -> SubstrateResult<()> {
        self.events.push(event);
        Ok(())
    }

    fn pop_event(&mut self) -> Option<SubstrateEvent> {
        if self.events.is_empty() { None } else { Some(self.events.remove(0)) }
    }
}

impl GuestMemoryAuthority for FullConformanceBackend {
    fn copyin(&self, _mem: UserMemoryHandle, _ptr: u64, len: usize) -> SubstrateResult<GuestBytes> {
        Ok(self.memory.iter().copied().take(len).collect())
    }

    fn copyout(&mut self, _mem: UserMemoryHandle, _ptr: u64, data: &[u8]) -> SubstrateResult<()> {
        self.memory.clear();
        self.memory.extend_from_slice(data);
        Ok(())
    }
}

impl DmwAuthority for FullConformanceBackend {
    fn map_user_window(
        &mut self,
        _mem: UserMemoryHandle,
        _ptr: u64,
        _len: usize,
        _perms: WindowPerms,
    ) -> SubstrateResult<WindowLeaseRef> {
        Ok(WindowLeaseRef::new(1, 1))
    }

    fn unmap_user_window(&mut self, lease: WindowLeaseRef) -> SubstrateResult<()> {
        if lease.is_valid() {
            Ok(())
        } else {
            Err(SubstrateError::InvalidObject { object: "window-lease" })
        }
    }
}

impl ArtifactAuthority for FullConformanceBackend {
    fn load_artifact_image(&mut self, artifact: ArtifactImageRef) -> SubstrateResult<()> {
        self.loaded.push(artifact);
        Ok(())
    }
}

impl CodePublisherAuthority for FullConformanceBackend {
    fn publish_code(
        &mut self,
        artifact: ArtifactImageRef,
        code: CodeObjectRef,
    ) -> SubstrateResult<PublishedCodeRef> {
        self.published.push((artifact, code));
        Ok(PublishedCodeRef::new(code.id, code.generation))
    }
}

impl MmioAuthority for FullConformanceBackend {
    fn mmio_read32(&self, _region: MmioRegionRef, _offset: u64) -> SubstrateResult<u32> {
        Ok(self.mmio)
    }

    fn mmio_write32(
        &mut self,
        _region: MmioRegionRef,
        _offset: u64,
        value: u32,
    ) -> SubstrateResult<()> {
        self.mmio = value;
        Ok(())
    }
}

impl DmaAuthority for FullConformanceBackend {
    fn dma_alloc(&mut self, _req: DmaAllocRequest) -> SubstrateResult<DmaBufferCapability> {
        self.dma_live = true;
        Ok(DmaBufferCapability::new(1, 1))
    }

    fn dma_free(&mut self, cap: DmaBufferCapability) -> SubstrateResult<()> {
        if cap.is_valid() && self.dma_live {
            self.dma_live = false;
            Ok(())
        } else {
            Err(SubstrateError::InvalidObject { object: "dma-buffer" })
        }
    }
}

impl IrqAuthority for FullConformanceBackend {
    fn irq_ack(&mut self, irq: IrqLine) -> SubstrateResult<()> {
        if irq.is_valid() { Ok(()) } else { Err(SubstrateError::InvalidObject { object: "irq" }) }
    }

    fn irq_mask(&mut self, irq: IrqLine) -> SubstrateResult<()> {
        if irq.is_valid() { Ok(()) } else { Err(SubstrateError::InvalidObject { object: "irq" }) }
    }

    fn irq_unmask(&mut self, irq: IrqLine) -> SubstrateResult<()> {
        if irq.is_valid() { Ok(()) } else { Err(SubstrateError::InvalidObject { object: "irq" }) }
    }
}

impl SnapshotAuthority for FullConformanceBackend {
    fn enter_snapshot_barrier(&mut self) -> SubstrateResult<SnapshotBarrierRef> {
        self.snapshot_live = true;
        Ok(SnapshotBarrierRef::new(1, 1))
    }

    fn exit_snapshot_barrier(&mut self, barrier: SnapshotBarrierRef) -> SubstrateResult<()> {
        if barrier.is_valid() && self.snapshot_live {
            self.snapshot_live = false;
            Ok(())
        } else {
            Err(SubstrateError::InvalidObject { object: "snapshot-barrier" })
        }
    }
}

struct UnsupportedConformanceBackend;

impl ConsoleAuthority for UnsupportedConformanceBackend {}
impl TimerAuthority for UnsupportedConformanceBackend {}
impl EventQueueAuthority for UnsupportedConformanceBackend {}
impl GuestMemoryAuthority for UnsupportedConformanceBackend {}
impl DmwAuthority for UnsupportedConformanceBackend {}
impl ArtifactAuthority for UnsupportedConformanceBackend {}
impl CodePublisherAuthority for UnsupportedConformanceBackend {}
impl MmioAuthority for UnsupportedConformanceBackend {}
impl DmaAuthority for UnsupportedConformanceBackend {}
impl IrqAuthority for UnsupportedConformanceBackend {}
impl SnapshotAuthority for UnsupportedConformanceBackend {}

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
fn profile_conformance_suite_passes_snapshot_replay_backend() {
    let mut backend = FullConformanceBackend::default();
    let fixtures = conformance::ConformanceFixtures::default();

    let report = conformance::check_substrate_profile(
        &mut backend,
        SubstrateProfile::SnapshotReplayCapable,
        SubstrateCapabilitySet::for_profile(SubstrateProfile::SnapshotReplayCapable),
        &fixtures,
    );

    assert!(report.ok);
    assert!(report.failures().next().is_none());
    assert!(
        report
            .checks
            .iter()
            .filter(|check| check.required)
            .all(|check| check.status != conformance::ConformanceStatus::Skipped)
    );
    assert_eq!(backend.loaded, vec![fixtures.artifact]);
    assert_eq!(backend.published, vec![(fixtures.artifact, fixtures.code)]);
    assert!(!backend.dma_live);
    assert!(!backend.snapshot_live);

    let host_side = report.evidence_summary(conformance::ConformanceEvidenceContext::host_side());
    assert!(host_side.can_claim_profile);
    assert!(!host_side.can_claim_real_target_substrate);
    assert!(!host_side.real_target_substrate_run);

    let legacy_bool = report.evidence_summary(true);
    assert!(legacy_bool.can_claim_profile);
    assert!(legacy_bool.real_target_substrate_run);
    assert_eq!(legacy_bool.real_target_concrete_arch, None);
    assert!(!legacy_bool.real_target_extraction_events_observed);
    assert_eq!(legacy_bool.real_target_extraction_event_count, 0);
    assert!(!legacy_bool.can_claim_real_target_substrate);

    let incomplete_real_target = report
        .evidence_summary(conformance::ConformanceEvidenceContext::real_target("riscv64", false));
    assert!(incomplete_real_target.real_target_substrate_run);
    assert_eq!(incomplete_real_target.real_target_concrete_arch, Some("riscv64"));
    assert!(!incomplete_real_target.real_target_extraction_events_observed);
    assert_eq!(incomplete_real_target.real_target_extraction_event_count, 0);
    assert!(!incomplete_real_target.can_claim_real_target_substrate);

    let real_target = report.evidence_summary(
        conformance::ConformanceEvidenceContext::real_target_with_extraction_event_count(
            "riscv64", 3,
        ),
    );
    assert!(real_target.can_claim_real_target_substrate);
    assert_eq!(real_target.profile, SubstrateProfile::SnapshotReplayCapable);
    assert_eq!(real_target.strongest_profile, Some(SubstrateProfile::SnapshotReplayCapable));
    assert_eq!(real_target.real_target_concrete_arch, Some("riscv64"));
    assert!(real_target.real_target_extraction_events_observed);
    assert_eq!(real_target.real_target_extraction_event_count, 3);

    let unsupported_arch = report.evidence_summary(
        conformance::ConformanceEvidenceContext::real_target_with_extraction_event_count(
            "banana64", 3,
        ),
    );
    assert!(unsupported_arch.real_target_substrate_run);
    assert_eq!(unsupported_arch.real_target_concrete_arch, Some("banana64"));
    assert!(unsupported_arch.real_target_extraction_events_observed);
    assert!(!unsupported_arch.can_claim_real_target_substrate);
}

#[test]
fn profile_conformance_suite_reports_backend_failures() {
    let mut backend = UnsupportedConformanceBackend;
    let fixtures = conformance::ConformanceFixtures::default();

    let report = conformance::check_substrate_profile(
        &mut backend,
        SubstrateProfile::SemanticHarness,
        SubstrateCapabilitySet::semantic_harness(),
        &fixtures,
    );
    let failures = report.failures().map(|check| check.check).collect::<Vec<_>>();

    assert!(!report.ok);
    assert_eq!(
        failures,
        vec![
            "console_write_smoke",
            "timer_now_smoke",
            "timer_arm_smoke",
            "event_queue_fifo",
            "capability_denied_event"
        ]
    );
    assert!(report.compatibility.ok);
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

// ── ConformancePolicy regression tests ──────────────────────────────────────

#[test]
fn policy_required_missing_capability_is_rejected() {
    let mut backend = FullConformanceBackend::default();
    let fixtures = conformance::ConformanceFixtures::default();
    let mut policy = ConformancePolicy::for_profile(SubstrateProfile::SemanticHarness);
    // SemanticHarness does NOT require mmio, but policy addition does.
    policy.required.mmio = true;

    let report = conformance::check_substrate_profile_with_policy(
        &mut backend,
        SubstrateProfile::SemanticHarness,
        SubstrateCapabilitySet::semantic_harness(), // no mmio capability
        &policy,
        &fixtures,
    );

    assert!(!report.ok, "must reject when policy-required authority is missing");
    assert!(report.compatibility.missing_required.iter().any(|m| m.authority == "mmio"));
}

#[test]
fn policy_forbidden_present_capability_is_rejected() {
    let mut backend = FullConformanceBackend::default();
    let fixtures = conformance::ConformanceFixtures::default();
    let mut policy = ConformancePolicy::for_profile(SubstrateProfile::SemanticHarness);
    policy.forbidden.mmio = true;

    let report = conformance::check_substrate_profile_with_policy(
        &mut backend,
        SubstrateProfile::SemanticHarness,
        SubstrateCapabilitySet::host_validation(), // mmio capability present
        &policy,
        &fixtures,
    );

    assert!(!report.ok, "must reject when forbidden authority is present");
    assert!(report.compatibility.forbidden_present.iter().any(|p| p.authority == "mmio"));
}

#[test]
fn optional_authority_degradation_not_fatal_without_strict() {
    let mut backend = FullConformanceBackend::default();
    let fixtures = conformance::ConformanceFixtures::default();
    let mut policy = ConformancePolicy::for_profile(SubstrateProfile::SemanticHarness);
    policy.optional.snapshot = SnapshotRequirement::DeterministicReplay;
    policy.strict = false;

    let report = conformance::check_substrate_profile_with_policy(
        &mut backend,
        SubstrateProfile::SemanticHarness,
        SubstrateCapabilitySet::semantic_harness(), // no snapshot capability
        &policy,
        &fixtures,
    );

    // Compatibility should be ok (missing optional should not reject)
    assert!(report.compatibility.ok);
    // Report should not fail: optional + non-strict means degraded, not failed
    assert!(report.ok);
    assert!(
        report.compatibility.degraded_optional.iter().any(|m| m.authority == "snapshot"),
        "must report snapshot as degraded optional"
    );
}

#[test]
fn optional_authority_fails_when_strict() {
    let mut backend = FullConformanceBackend::default();
    let fixtures = conformance::ConformanceFixtures::default();
    let mut policy = ConformancePolicy::for_profile(SubstrateProfile::SemanticHarness);
    policy.optional.snapshot = SnapshotRequirement::DeterministicReplay;
    policy.strict = true;

    let report = conformance::check_substrate_profile_with_policy(
        &mut backend,
        SubstrateProfile::SemanticHarness,
        SubstrateCapabilitySet::semantic_harness(),
        &policy,
        &fixtures,
    );

    assert!(!report.ok, "must fail when optional+strict capability is missing");
    assert!(
        report.compatibility.missing_required.iter().any(|m| m.authority == "snapshot"),
        "strict optional missing must be treated as missing_required"
    );
}
