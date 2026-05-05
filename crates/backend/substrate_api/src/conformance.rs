use alloc::vec::Vec;

use crate::*;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConformanceError {
    pub check: &'static str,
    pub detail: &'static str,
}

impl ConformanceError {
    const fn new(check: &'static str, detail: &'static str) -> Self {
        Self { check, detail }
    }
}

pub type ConformanceResult = Result<(), ConformanceError>;

pub trait SubstrateConformanceBackend:
    ConsoleAuthority
    + TimerAuthority
    + EventQueueAuthority
    + GuestMemoryAuthority
    + DmwAuthority
    + ArtifactAuthority
    + CodePublisherAuthority
    + MmioAuthority
    + DmaAuthority
    + IrqAuthority
    + SnapshotAuthority
{
}

impl<T> SubstrateConformanceBackend for T where
    T: ConsoleAuthority
        + TimerAuthority
        + EventQueueAuthority
        + GuestMemoryAuthority
        + DmwAuthority
        + ArtifactAuthority
        + CodePublisherAuthority
        + MmioAuthority
        + DmaAuthority
        + IrqAuthority
        + SnapshotAuthority
{
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConformanceFixtures {
    pub artifact: ArtifactImageRef,
    pub code: CodeObjectRef,
    pub user_memory: UserMemoryHandle,
    pub user_ptr: u64,
    pub user_bytes: GuestBytes,
    pub wait_token: WaitTokenRef,
    pub mmio_region: MmioRegionRef,
    pub irq: IrqLine,
    pub dma_request: DmaAllocRequest,
}

impl Default for ConformanceFixtures {
    fn default() -> Self {
        Self {
            artifact: ArtifactImageRef::new(1, 1),
            code: CodeObjectRef::new(1, 1),
            user_memory: UserMemoryHandle::new(1, 1),
            user_ptr: 0x1000,
            user_bytes: alloc::vec![0x76, 0x49, 0x53, 0x41],
            wait_token: WaitTokenRef::new(1, 1),
            mmio_region: MmioRegionRef::new(1, 1),
            irq: IrqLine::new(1, 1),
            dma_request: DmaAllocRequest::new(1, 4096, 4096),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConformanceStatus {
    Passed,
    Failed,
    Skipped,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConformanceCheck {
    pub check: &'static str,
    pub required: bool,
    pub status: ConformanceStatus,
    pub detail: &'static str,
}

impl ConformanceCheck {
    const fn passed(check: &'static str, required: bool) -> Self {
        Self { check, required, status: ConformanceStatus::Passed, detail: "ok" }
    }

    const fn failed(check: &'static str, required: bool, detail: &'static str) -> Self {
        Self { check, required, status: ConformanceStatus::Failed, detail }
    }

    const fn skipped(check: &'static str) -> Self {
        Self {
            check,
            required: false,
            status: ConformanceStatus::Skipped,
            detail: "not required by profile",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SubstrateConformanceReport {
    pub profile: SubstrateProfile,
    pub capabilities: SubstrateCapabilitySet,
    pub compatibility: SubstrateCompatibilityReport,
    pub checks: Vec<ConformanceCheck>,
    pub ok: bool,
}

impl SubstrateConformanceReport {
    pub fn failures(&self) -> impl Iterator<Item = &ConformanceCheck> {
        self.checks.iter().filter(|check| check.status == ConformanceStatus::Failed)
    }
}

#[derive(Clone, Debug, Default)]
pub struct ConformancePolicy {
    pub required: AuthorityRequirementSet,
    pub optional: AuthorityRequirementSet,
    pub forbidden: AuthorityRequirementSet,
    pub strict: bool,
}

impl ConformancePolicy {
    pub fn for_profile(profile: SubstrateProfile) -> Self {
        Self {
            required: profile.requirements(),
            optional: AuthorityRequirementSet::default(),
            forbidden: AuthorityRequirementSet::default(),
            strict: false,
        }
    }
}

pub fn check_substrate_profile<B: SubstrateConformanceBackend>(
    backend: &mut B,
    profile: SubstrateProfile,
    capabilities: SubstrateCapabilitySet,
    fixtures: &ConformanceFixtures,
) -> SubstrateConformanceReport {
    check_substrate_profile_with_policy(
        backend,
        profile,
        capabilities,
        &ConformancePolicy::for_profile(profile),
        fixtures,
    )
}

pub fn check_substrate_profile_with_policy<B: SubstrateConformanceBackend>(
    backend: &mut B,
    profile: SubstrateProfile,
    capabilities: SubstrateCapabilitySet,
    policy: &ConformancePolicy,
    fixtures: &ConformanceFixtures,
) -> SubstrateConformanceReport {
    let compatibility = capabilities.check_profile(profile);
    let requirements = profile.requirements();
    let mut checks = Vec::new();

    // required checks
    push_policy_check(
        &mut checks,
        "console_write_smoke",
        requirements.console,
        policy,
        || console_write_smoke(backend, b"vISA conformance"),
    );
    push_policy_check(&mut checks, "timer_now_smoke", requirements.timer, policy, || {
        timer_now_smoke(backend)
    });
    push_policy_check(
        &mut checks,
        "timer_arm_smoke",
        requirements.timer,
        policy,
        || timer_arm_smoke(backend, fixtures),
    );
    push_policy_check(&mut checks, "event_queue_fifo", requirements.event_queue, policy, || {
        event_queue_fifo_or_declared_order(backend)
    });
    push_policy_check(
        &mut checks,
        "capability_denied_event",
        requirements.event_queue,
        policy,
        || capability_denied_event_is_visible(backend),
    );
    push_policy_check(
        &mut checks,
        "guest_memory_copy_roundtrip",
        requirements.guest_memory,
        policy,
        || guest_memory_copy_roundtrip(backend, fixtures),
    );
    push_policy_check(
        &mut checks,
        "artifact_loading_smoke",
        requirements.artifact_loading,
        policy,
        || artifact_loading_smoke(backend, fixtures),
    );
    push_policy_check(
        &mut checks,
        "code_publish_smoke",
        !matches!(requirements.code_publish, CodePublishRequirement::None),
        policy,
        || code_publish_smoke(backend, fixtures),
    );
    push_policy_check(
        &mut checks,
        "dmw_window_smoke",
        !matches!(requirements.dmw, DmwRequirement::None),
        policy,
        || dmw_window_smoke(backend, fixtures),
    );
    push_policy_check(
        &mut checks,
        "mmio_read_write_smoke",
        requirements.mmio,
        policy,
        || mmio_read_write_smoke(backend, fixtures),
    );
    push_policy_check(
        &mut checks,
        "irq_ack_mask_unmask_smoke",
        requirements.irq,
        policy,
        || irq_ack_mask_unmask_smoke(backend, fixtures),
    );
    push_policy_check(
        &mut checks,
        "dma_alloc_free_smoke",
        !matches!(requirements.dma, DmaRequirement::None),
        policy,
        || dma_alloc_free_smoke(backend, fixtures),
    );
    push_policy_check(
        &mut checks,
        "snapshot_barrier_smoke",
        !matches!(requirements.snapshot, SnapshotRequirement::None),
        policy,
        || snapshot_barrier_smoke(backend),
    );

    // forbidden checks: only run when policy explicitly forbids an authority
    push_forbidden_check(
        &mut checks,
        "dmw_unsupported_is_reported",
        !matches!(policy.forbidden.dmw, DmwRequirement::None),
        || dmw_unsupported_is_reported(backend),
    );
    push_forbidden_check(
        &mut checks,
        "dma_unsupported_is_reported",
        !matches!(policy.forbidden.dma, DmaRequirement::None),
        || dma_unsupported_is_reported(backend),
    );

    let ok = compatibility.ok
        && checks
            .iter()
            .all(|check| check.status != ConformanceStatus::Failed);
    SubstrateConformanceReport { profile, capabilities, compatibility, checks, ok }
}

fn push_policy_check<F>(
    checks: &mut Vec<ConformanceCheck>,
    check: &'static str,
    in_profile: bool,
    _policy: &ConformancePolicy,
    mut run: F,
) where
    F: FnMut() -> ConformanceResult,
{
    if !in_profile {
        checks.push(ConformanceCheck::skipped(check));
        return;
    }
    match run() {
        Ok(()) => checks.push(ConformanceCheck::passed(check, true)),
        Err(error) => checks.push(ConformanceCheck::failed(error.check, true, error.detail)),
    }
}

fn push_forbidden_check<F>(
    checks: &mut Vec<ConformanceCheck>,
    check: &'static str,
    forbidden: bool,
    mut run: F,
) where
    F: FnMut() -> ConformanceResult,
{
    if !forbidden {
        checks.push(ConformanceCheck::skipped(check));
        return;
    }
    match run() {
        Ok(()) => checks.push(ConformanceCheck::passed(check, true)),
        Err(error) => checks.push(ConformanceCheck::failed(error.check, true, error.detail)),
    }
}

pub fn unsupported_is_reported<T>(
    check: &'static str,
    result: SubstrateResult<T>,
    authority: &'static str,
    operation: &'static str,
) -> ConformanceResult {
    match result {
        Err(SubstrateError::Unsupported {
            authority: actual_authority,
            operation: actual_operation,
        }) if actual_authority == authority && actual_operation == operation => Ok(()),
        Err(_) => Err(ConformanceError::new(check, "operation failed with the wrong error class")),
        Ok(_) => Err(ConformanceError::new(check, "operation unexpectedly succeeded")),
    }
}

pub fn console_write_smoke<A: ConsoleAuthority>(
    authority: &mut A,
    bytes: &[u8],
) -> ConformanceResult {
    match authority.console_write(bytes) {
        Ok(written) if written == bytes.len() => Ok(()),
        Ok(_) => Err(ConformanceError::new(
            "console_write_smoke",
            "console authority returned a partial write",
        )),
        Err(_) => Err(ConformanceError::new(
            "console_write_smoke",
            "console authority rejected a basic write",
        )),
    }
}

pub fn timer_now_smoke<A: TimerAuthority>(authority: &A) -> ConformanceResult {
    authority
        .now()
        .map(|_| ())
        .map_err(|_| ConformanceError::new("timer_now_smoke", "timer authority rejected now()"))
}

pub fn event_queue_fifo_or_declared_order<Q: EventQueueAuthority>(
    queue: &mut Q,
) -> ConformanceResult {
    let first = SubstrateEvent::unsupported("DmaAuthority", "dma_alloc", None);
    let second = SubstrateEvent::unsupported("IrqAuthority", "irq_ack", None);
    queue
        .push_event(first.clone())
        .map_err(|_| ConformanceError::new("event_queue_fifo", "first push failed"))?;
    queue
        .push_event(second.clone())
        .map_err(|_| ConformanceError::new("event_queue_fifo", "second push failed"))?;

    if queue.pop_event() != Some(first) {
        return Err(ConformanceError::new("event_queue_fifo", "first event did not pop first"));
    }
    if queue.pop_event() != Some(second) {
        return Err(ConformanceError::new("event_queue_fifo", "second event did not pop second"));
    }
    Ok(())
}

pub fn capability_denied_event_is_visible<Q: EventQueueAuthority>(
    queue: &mut Q,
) -> ConformanceResult {
    let event = SubstrateEvent::CapabilityDenied {
        authority: "DmaAuthority",
        operation: "dma_alloc",
        requester: Some(SubstrateRequester::new("driver.fake_net")),
        capability: Some(CapabilityHandle::new(7, 2)),
    };
    queue
        .push_event(event.clone())
        .map_err(|_| ConformanceError::new("capability_denied_event", "event push failed"))?;
    match queue.pop_event() {
        Some(actual) if actual == event => Ok(()),
        Some(_) => {
            Err(ConformanceError::new("capability_denied_event", "event payload changed in queue"))
        }
        None => {
            Err(ConformanceError::new("capability_denied_event", "event queue returned no event"))
        }
    }
}

pub fn guest_memory_copy_roundtrip<A: GuestMemoryAuthority>(
    authority: &mut A,
    fixtures: &ConformanceFixtures,
) -> ConformanceResult {
    authority
        .copyout(fixtures.user_memory, fixtures.user_ptr, &fixtures.user_bytes)
        .map_err(|_| ConformanceError::new("guest_memory_copy_roundtrip", "copyout failed"))?;
    match authority.copyin(fixtures.user_memory, fixtures.user_ptr, fixtures.user_bytes.len()) {
        Ok(bytes) if bytes == fixtures.user_bytes => Ok(()),
        Ok(_) => Err(ConformanceError::new(
            "guest_memory_copy_roundtrip",
            "copyin returned different bytes",
        )),
        Err(_) => Err(ConformanceError::new("guest_memory_copy_roundtrip", "copyin failed")),
    }
}

pub fn artifact_loading_smoke<A: ArtifactAuthority>(
    authority: &mut A,
    fixtures: &ConformanceFixtures,
) -> ConformanceResult {
    authority
        .load_artifact_image(fixtures.artifact)
        .map_err(|_| ConformanceError::new("artifact_loading_smoke", "artifact load failed"))
}

pub fn code_publish_smoke<A: CodePublisherAuthority>(
    authority: &mut A,
    fixtures: &ConformanceFixtures,
) -> ConformanceResult {
    match authority.publish_code(fixtures.artifact, fixtures.code) {
        Ok(code) if code.is_valid() => Ok(()),
        Ok(_) => {
            Err(ConformanceError::new("code_publish_smoke", "published code handle is invalid"))
        }
        Err(_) => Err(ConformanceError::new("code_publish_smoke", "code publish failed")),
    }
}

pub fn dmw_window_smoke<A: DmwAuthority>(
    authority: &mut A,
    fixtures: &ConformanceFixtures,
) -> ConformanceResult {
    let lease = authority
        .map_user_window(
            fixtures.user_memory,
            fixtures.user_ptr,
            fixtures.user_bytes.len(),
            WindowPerms::READ_WRITE,
        )
        .map_err(|_| ConformanceError::new("dmw_window_smoke", "map_user_window failed"))?;
    if !lease.is_valid() {
        return Err(ConformanceError::new("dmw_window_smoke", "window lease is invalid"));
    }
    authority
        .unmap_user_window(lease)
        .map_err(|_| ConformanceError::new("dmw_window_smoke", "unmap_user_window failed"))
}

pub fn mmio_read_write_smoke<A: MmioAuthority>(
    authority: &mut A,
    fixtures: &ConformanceFixtures,
) -> ConformanceResult {
    const TEST_VALUE: u32 = 0xa5a5_5a5a;
    authority
        .mmio_write32(fixtures.mmio_region, 0, TEST_VALUE)
        .map_err(|_| ConformanceError::new("mmio_read_write_smoke", "mmio_write32 failed"))?;
    match authority.mmio_read32(fixtures.mmio_region, 0) {
        Ok(value) if value == TEST_VALUE => Ok(()),
        Ok(_) => Err(ConformanceError::new(
            "mmio_read_write_smoke",
            "mmio_read32 returned a different value than what was written",
        )),
        Err(_) => Err(ConformanceError::new("mmio_read_write_smoke", "mmio_read32 failed")),
    }
}

pub fn timer_arm_smoke<A: TimerAuthority>(
    authority: &mut A,
    fixtures: &ConformanceFixtures,
) -> ConformanceResult {
    authority
        .arm_timer(VirtualTime::from_ticks(100), fixtures.wait_token)
        .map_err(|_| ConformanceError::new("timer_arm_smoke", "arm_timer rejected a basic arm"))
}

pub fn irq_ack_mask_unmask_smoke<A: IrqAuthority>(
    authority: &mut A,
    fixtures: &ConformanceFixtures,
) -> ConformanceResult {
    authority
        .irq_mask(fixtures.irq)
        .map_err(|_| ConformanceError::new("irq_ack_mask_unmask_smoke", "irq_mask failed"))?;
    authority
        .irq_ack(fixtures.irq)
        .map_err(|_| ConformanceError::new("irq_ack_mask_unmask_smoke", "irq_ack failed"))?;
    authority
        .irq_unmask(fixtures.irq)
        .map_err(|_| ConformanceError::new("irq_ack_mask_unmask_smoke", "irq_unmask failed"))
}

pub fn dma_alloc_free_smoke<A: DmaAuthority>(
    authority: &mut A,
    fixtures: &ConformanceFixtures,
) -> ConformanceResult {
    let capability = authority
        .dma_alloc(fixtures.dma_request)
        .map_err(|_| ConformanceError::new("dma_alloc_free_smoke", "dma_alloc failed"))?;
    if !capability.is_valid() {
        return Err(ConformanceError::new("dma_alloc_free_smoke", "dma capability is invalid"));
    }
    authority
        .dma_free(capability)
        .map_err(|_| ConformanceError::new("dma_alloc_free_smoke", "dma_free failed"))
}

pub fn snapshot_barrier_smoke<A: SnapshotAuthority>(authority: &mut A) -> ConformanceResult {
    let barrier = authority
        .enter_snapshot_barrier()
        .map_err(|_| ConformanceError::new("snapshot_barrier_smoke", "enter barrier failed"))?;
    if !barrier.is_valid() {
        return Err(ConformanceError::new(
            "snapshot_barrier_smoke",
            "snapshot barrier handle is invalid",
        ));
    }
    authority
        .exit_snapshot_barrier(barrier)
        .map_err(|_| ConformanceError::new("snapshot_barrier_smoke", "exit barrier failed"))
}

pub fn dmw_unsupported_is_reported<A: DmwAuthority>(authority: &mut A) -> ConformanceResult {
    unsupported_is_reported(
        "dmw_unsupported",
        authority.map_user_window(UserMemoryHandle::new(1, 1), 0x1000, 16, WindowPerms::READ),
        "DmwAuthority",
        "map_user_window",
    )
}

pub fn dma_unsupported_is_reported<A: DmaAuthority>(authority: &mut A) -> ConformanceResult {
    unsupported_is_reported(
        "dma_unsupported",
        authority.dma_alloc(DmaAllocRequest::new(1, 4096, 4096)),
        "DmaAuthority",
        "dma_alloc",
    )
}

#[macro_export]
macro_rules! conformance_test_suite {
    ($backend_factory:expr) => {
        use $crate::conformance::{
            check_substrate_profile, ConformanceFixtures, SubstrateConformanceReport,
        };
        use $crate::SubstrateCapabilitySet;
        use visa_profile::SubstrateProfile;

        fn assert_report_ok(report: &SubstrateConformanceReport, profile_name: &str) {
            if !report.ok {
                panic!(
                    "Profile {} conformance failed: {:#?}",
                    profile_name,
                    report.failures().collect::<Vec<_>>()
                );
            }
        }

        #[test]
        fn conformance_profile_0_semantic_harness() {
            let mut backend = ($backend_factory)();
            let fixtures = ConformanceFixtures::default();
            let report = check_substrate_profile(
                &mut backend,
                SubstrateProfile::SemanticHarness,
                SubstrateCapabilitySet::for_profile(SubstrateProfile::SemanticHarness),
                &fixtures,
            );
            assert_report_ok(&report, "SemanticHarness");
        }

        #[test]
        fn conformance_profile_1_minimal_bare_metal() {
            let mut backend = ($backend_factory)();
            let fixtures = ConformanceFixtures::default();
            let report = check_substrate_profile(
                &mut backend,
                SubstrateProfile::MinimalBareMetal,
                SubstrateCapabilitySet::for_profile(SubstrateProfile::MinimalBareMetal),
                &fixtures,
            );
            assert_report_ok(&report, "MinimalBareMetal");
        }

        #[test]
        fn conformance_profile_2_guest_frontend() {
            let mut backend = ($backend_factory)();
            let fixtures = ConformanceFixtures::default();
            let report = check_substrate_profile(
                &mut backend,
                SubstrateProfile::GuestFrontend,
                SubstrateCapabilitySet::for_profile(SubstrateProfile::GuestFrontend),
                &fixtures,
            );
            assert_report_ok(&report, "GuestFrontend");
        }

        #[test]
        fn conformance_profile_3_device_capable() {
            let mut backend = ($backend_factory)();
            let fixtures = ConformanceFixtures::default();
            let report = check_substrate_profile(
                &mut backend,
                SubstrateProfile::DeviceCapable,
                SubstrateCapabilitySet::for_profile(SubstrateProfile::DeviceCapable),
                &fixtures,
            );
            assert_report_ok(&report, "DeviceCapable");
        }

        #[test]
        fn conformance_profile_4_snapshot_replay_capable() {
            let mut backend = ($backend_factory)();
            let fixtures = ConformanceFixtures::default();
            let report = check_substrate_profile(
                &mut backend,
                SubstrateProfile::SnapshotReplayCapable,
                SubstrateCapabilitySet::for_profile(SubstrateProfile::SnapshotReplayCapable),
                &fixtures,
            );
            assert_report_ok(&report, "SnapshotReplayCapable");
        }
    };
}
