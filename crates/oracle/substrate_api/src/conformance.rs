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
    + PageTableAuthority
    + ArtifactAuthority
    + CodePublisherAuthority
    + MmioAuthority
    + DmaAuthority
    + IrqAuthority
    + PacketDeviceBackend
    + SnapshotAuthority
{
}

impl<T> SubstrateConformanceBackend for T where
    T: ConsoleAuthority
        + TimerAuthority
        + EventQueueAuthority
        + GuestMemoryAuthority
        + DmwAuthority
        + PageTableAuthority
        + ArtifactAuthority
        + CodePublisherAuthority
        + MmioAuthority
        + DmaAuthority
        + IrqAuthority
        + PacketDeviceBackend
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
    pub page_va: u64,
    pub page_copy_len: usize,
    pub mmio_region: MmioRegionRef,
    pub irq: IrqLine,
    pub dma_request: DmaAllocRequest,
    pub packet_mac: [u8; 6],
    pub packet_frame: GuestBytes,
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
            page_va: 0x4000,
            page_copy_len: 64,
            mmio_region: MmioRegionRef::new(1, 1),
            irq: IrqLine::new(1, 1),
            dma_request: DmaAllocRequest::new(1, 4096, 4096),
            packet_mac: [0x02, 0x56, 0x4d, 0x4f, 0x53, 0x01],
            packet_frame: alloc::vec![
                0xff, 0xff, 0xff, 0xff, 0xff, 0xff, // dst
                0x02, 0x56, 0x4d, 0x4f, 0x53, 0x01, // src
                0x08, 0x00, // ethertype IPv4
                0x45, 0x00, 0x00, 0x2e, 0x00, 0x01, 0x00, 0x00, 0x40, 0x11, 0, 0, 192, 0, 2, 1,
                192, 0, 2, 2, // compact IPv4/UDP fixture payload
                0, 7, 0, 7, 0, 10, 0, 0, b'v', b'm',
            ],
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

    pub fn evidence_summary<C>(&self, context: C) -> SubstrateConformanceEvidence
    where
        C: Into<ConformanceEvidenceContext>,
    {
        let context = context.into();
        let required_checks = self.checks.iter().filter(|check| check.required).count();
        let passed_required = self
            .checks
            .iter()
            .filter(|check| check.required && check.status == ConformanceStatus::Passed)
            .count();
        let failed_checks =
            self.checks.iter().filter(|check| check.status == ConformanceStatus::Failed).count();
        let skipped_optional = self
            .checks
            .iter()
            .filter(|check| !check.required && check.status == ConformanceStatus::Skipped)
            .count();
        let strongest_profile = SubstrateProfile::strongest_satisfied_by(self.capabilities);
        let can_claim_profile =
            self.ok && self.compatibility.ok && passed_required == required_checks;
        let can_claim_real_target_substrate =
            can_claim_profile && context.real_target.can_claim_real_target_substrate();
        SubstrateConformanceEvidence {
            profile: self.profile,
            strongest_profile,
            total_checks: self.checks.len(),
            required_checks,
            passed_required,
            failed_checks,
            skipped_optional,
            can_claim_profile,
            real_target_substrate_run: context.real_target.executed_on_real_target,
            real_target_concrete_arch: context.real_target.concrete_arch,
            real_target_extraction_events_observed: context.real_target.extraction_events_observed,
            real_target_extraction_event_count: context.real_target.extraction_event_count,
            can_claim_real_target_substrate,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ConformanceEvidenceContext {
    pub real_target: RealTargetConformanceContext,
}

impl ConformanceEvidenceContext {
    pub const fn host_side() -> Self {
        Self { real_target: RealTargetConformanceContext::none() }
    }

    pub const fn real_target(
        concrete_arch: &'static str,
        extraction_events_observed: bool,
    ) -> Self {
        let extraction_event_count = if extraction_events_observed { 1 } else { 0 };
        Self::real_target_with_extraction_event_count(concrete_arch, extraction_event_count)
    }

    pub const fn real_target_with_extraction_event_count(
        concrete_arch: &'static str,
        extraction_event_count: usize,
    ) -> Self {
        Self {
            real_target: RealTargetConformanceContext::verified(
                concrete_arch,
                extraction_event_count,
            ),
        }
    }
}

impl Default for ConformanceEvidenceContext {
    fn default() -> Self {
        Self::host_side()
    }
}

impl From<bool> for ConformanceEvidenceContext {
    fn from(real_target_substrate_run: bool) -> Self {
        Self {
            real_target: RealTargetConformanceContext {
                executed_on_real_target: real_target_substrate_run,
                concrete_arch: None,
                extraction_events_observed: false,
                extraction_event_count: 0,
            },
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RealTargetConformanceContext {
    pub executed_on_real_target: bool,
    pub concrete_arch: Option<&'static str>,
    pub extraction_events_observed: bool,
    pub extraction_event_count: usize,
}

impl RealTargetConformanceContext {
    pub const fn none() -> Self {
        Self {
            executed_on_real_target: false,
            concrete_arch: None,
            extraction_events_observed: false,
            extraction_event_count: 0,
        }
    }

    pub const fn verified(concrete_arch: &'static str, extraction_event_count: usize) -> Self {
        Self {
            executed_on_real_target: true,
            concrete_arch: Some(concrete_arch),
            extraction_events_observed: extraction_event_count > 0,
            extraction_event_count,
        }
    }

    fn can_claim_real_target_substrate(&self) -> bool {
        self.executed_on_real_target
            && self.extraction_events_observed
            && matches!(self.concrete_arch, Some(arch) if is_supported_real_target_arch(arch))
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SubstrateConformanceEvidence {
    pub profile: SubstrateProfile,
    pub strongest_profile: Option<SubstrateProfile>,
    pub total_checks: usize,
    pub required_checks: usize,
    pub passed_required: usize,
    pub failed_checks: usize,
    pub skipped_optional: usize,
    pub can_claim_profile: bool,
    pub real_target_substrate_run: bool,
    pub real_target_concrete_arch: Option<&'static str>,
    pub real_target_extraction_events_observed: bool,
    pub real_target_extraction_event_count: usize,
    pub can_claim_real_target_substrate: bool,
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
    let compatibility = SubstrateAuthorityRequirements {
        required: if policy.strict {
            profile.requirements().merged_with(policy.required).merged_with(policy.optional)
        } else {
            profile.requirements().merged_with(policy.required)
        },
        optional: if policy.strict { AuthorityRequirementSet::default() } else { policy.optional },
        forbidden: policy.forbidden,
    }
    .check(capabilities);
    let req = profile.requirements();
    let mut checks = Vec::new();

    push_policy_check(
        &mut checks,
        "console_write_smoke",
        policy,
        req.console,
        policy.required.console,
        policy.optional.console,
        || console_write_smoke(backend, b"vISA conformance"),
    );
    push_policy_check(
        &mut checks,
        "timer_now_smoke",
        policy,
        req.timer,
        policy.required.timer,
        policy.optional.timer,
        || timer_now_smoke(backend),
    );
    push_policy_check(
        &mut checks,
        "timer_arm_smoke",
        policy,
        req.timer,
        policy.required.timer,
        policy.optional.timer,
        || timer_arm_smoke(backend, fixtures),
    );
    push_policy_check(
        &mut checks,
        "event_queue_fifo",
        policy,
        req.event_queue,
        policy.required.event_queue,
        policy.optional.event_queue,
        || event_queue_fifo_or_declared_order(backend),
    );
    push_policy_check(
        &mut checks,
        "capability_denied_event",
        policy,
        req.event_queue,
        policy.required.event_queue,
        policy.optional.event_queue,
        || capability_denied_event_is_visible(backend),
    );
    push_policy_check(
        &mut checks,
        "guest_memory_copy_roundtrip",
        policy,
        req.guest_memory,
        policy.required.guest_memory,
        policy.optional.guest_memory,
        || guest_memory_copy_roundtrip(backend, fixtures),
    );
    push_policy_check(
        &mut checks,
        "artifact_loading_smoke",
        policy,
        req.artifact_loading,
        policy.required.artifact_loading,
        policy.optional.artifact_loading,
        || artifact_loading_smoke(backend, fixtures),
    );
    push_policy_check(
        &mut checks,
        "code_publish_smoke",
        policy,
        !matches!(req.code_publish, CodePublishRequirement::None),
        !matches!(policy.required.code_publish, CodePublishRequirement::None),
        !matches!(policy.optional.code_publish, CodePublishRequirement::None),
        || code_publish_smoke(backend, fixtures),
    );
    push_policy_check(
        &mut checks,
        "dmw_window_smoke",
        policy,
        !matches!(req.dmw, DmwRequirement::None),
        !matches!(policy.required.dmw, DmwRequirement::None),
        !matches!(policy.optional.dmw, DmwRequirement::None),
        || dmw_window_smoke(backend, fixtures),
    );
    push_policy_check(
        &mut checks,
        "page_table_map_protect_copy_unmap_smoke",
        policy,
        req.page_table,
        policy.required.page_table,
        policy.optional.page_table,
        || page_table_map_protect_copy_unmap_smoke(backend, fixtures),
    );
    push_policy_check(
        &mut checks,
        "mmio_read_write_smoke",
        policy,
        req.mmio,
        policy.required.mmio,
        policy.optional.mmio,
        || mmio_read_write_smoke(backend, fixtures),
    );
    push_policy_check(
        &mut checks,
        "irq_ack_mask_unmask_smoke",
        policy,
        req.irq,
        policy.required.irq,
        policy.optional.irq,
        || irq_ack_mask_unmask_smoke(backend, fixtures),
    );
    push_policy_check(
        &mut checks,
        "dma_alloc_free_smoke",
        policy,
        !matches!(req.dma, DmaRequirement::None),
        !matches!(policy.required.dma, DmaRequirement::None),
        !matches!(policy.optional.dma, DmaRequirement::None),
        || dma_alloc_free_smoke(backend, fixtures),
    );
    push_policy_check(
        &mut checks,
        "packet_device_tx_poll_smoke",
        policy,
        req.packet_device,
        policy.required.packet_device,
        policy.optional.packet_device,
        || packet_device_tx_poll_smoke(backend, fixtures),
    );
    push_policy_check(
        &mut checks,
        "snapshot_barrier_smoke",
        policy,
        !matches!(req.snapshot, SnapshotRequirement::None),
        !matches!(policy.required.snapshot, SnapshotRequirement::None),
        !matches!(policy.optional.snapshot, SnapshotRequirement::None),
        || snapshot_barrier_smoke(backend),
    );

    // forbidden: run each authority if declared in policy.forbidden
    for check in forbidden_policy_checks(backend, policy) {
        checks.push(check);
    }

    let ok = compatibility.ok && checks.iter().all(|c| c.status != ConformanceStatus::Failed);
    SubstrateConformanceReport { profile, capabilities, compatibility, checks, ok }
}

// Collect forbidden checks based on policy.forbidden fields.
fn forbidden_policy_checks<B: SubstrateConformanceBackend>(
    backend: &mut B,
    policy: &ConformancePolicy,
) -> Vec<ConformanceCheck> {
    let mut out = Vec::new();
    let f = &policy.forbidden;

    let mut try_forbidden =
        |name: &'static str, gate: bool, run: fn(&mut B) -> ConformanceResult| {
            if !gate {
                out.push(ConformanceCheck::skipped(name));
                return;
            }
            match run(backend) {
                Ok(()) => out.push(ConformanceCheck::passed(name, true)),
                Err(e) => out.push(ConformanceCheck::failed(e.check, true, e.detail)),
            }
        };

    try_forbidden(
        "dmw_unsupported_is_reported",
        !matches!(f.dmw, DmwRequirement::None),
        dmw_unsupported_is_reported,
    );
    try_forbidden("page_table_unsupported_is_reported", f.page_table, |b| {
        page_table_unsupported_is_reported(b)
    });
    try_forbidden(
        "dma_unsupported_is_reported",
        !matches!(f.dma, DmaRequirement::None),
        dma_unsupported_is_reported,
    );
    try_forbidden("packet_device_unsupported_is_reported", f.packet_device, |b| {
        packet_device_unsupported_is_reported(b)
    });
    try_forbidden("console_unsupported_is_reported", f.console, |b| {
        unsupported_is_reported(
            "console_unsupported",
            b.console_write(b"test"),
            "ConsoleAuthority",
            "console_write",
        )
    });
    try_forbidden("timer_unsupported_is_reported", f.timer, |b| {
        unsupported_is_reported("timer_unsupported", b.now().map(|_| ()), "TimerAuthority", "now")
    });
    try_forbidden("event_queue_unsupported_is_reported", f.event_queue, |b| {
        unsupported_is_reported(
            "event_queue_unsupported",
            b.push_event(SubstrateEvent::unsupported("test", "test", None)),
            "EventQueueAuthority",
            "push_event",
        )
    });
    try_forbidden("guest_memory_unsupported_is_reported", f.guest_memory, |b| {
        unsupported_is_reported(
            "guest_memory_unsupported",
            b.copyout(UserMemoryHandle::new(1, 1), 0, &[]),
            "GuestMemoryAuthority",
            "copyout",
        )
    });
    try_forbidden("artifact_loading_unsupported_is_reported", f.artifact_loading, |b| {
        unsupported_is_reported(
            "artifact_loading_unsupported",
            b.load_artifact_image(ArtifactImageRef::new(1, 1)),
            "ArtifactAuthority",
            "load_artifact_image",
        )
    });
    try_forbidden(
        "code_publish_unsupported_is_reported",
        !matches!(f.code_publish, CodePublishRequirement::None),
        |b| {
            unsupported_is_reported(
                "code_publish_unsupported",
                b.publish_code(ArtifactImageRef::new(1, 1), CodeObjectRef::new(1, 1)).map(|_| ()),
                "CodePublisherAuthority",
                "publish_code",
            )
        },
    );
    try_forbidden("mmio_unsupported_is_reported", f.mmio, |b| {
        unsupported_is_reported(
            "mmio_unsupported",
            b.mmio_read32(MmioRegionRef::new(1, 1), 0).map(|_| ()),
            "MmioAuthority",
            "mmio_read32",
        )
    });
    try_forbidden("irq_unsupported_is_reported", f.irq, |b| {
        unsupported_is_reported(
            "irq_unsupported",
            b.irq_ack(IrqLine::new(1, 1)),
            "IrqAuthority",
            "irq_ack",
        )
    });
    try_forbidden(
        "snapshot_unsupported_is_reported",
        !matches!(f.snapshot, SnapshotRequirement::None),
        |b| {
            unsupported_is_reported(
                "snapshot_unsupported",
                b.enter_snapshot_barrier().map(|_| ()),
                "SnapshotAuthority",
                "enter_snapshot_barrier",
            )
        },
    );

    out
}

fn push_policy_check<F>(
    checks: &mut Vec<ConformanceCheck>,
    check: &'static str,
    policy: &ConformancePolicy,
    required_by_profile: bool,
    required_by_policy: bool,
    optional_by_policy: bool,
    mut run: F,
) where
    F: FnMut() -> ConformanceResult,
{
    let is_required = required_by_profile || required_by_policy;
    let is_optional = optional_by_policy && !is_required;
    if !is_required && !is_optional {
        checks.push(ConformanceCheck::skipped(check));
        return;
    }
    match run() {
        Ok(()) => checks.push(ConformanceCheck::passed(check, is_required)),
        Err(error) => {
            if is_optional && !policy.strict {
                checks.push(ConformanceCheck {
                    check: error.check,
                    required: false,
                    status: ConformanceStatus::Skipped,
                    detail: "optional authority degraded",
                });
            } else {
                checks.push(ConformanceCheck::failed(error.check, is_required, error.detail));
            }
        }
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

pub fn page_table_map_protect_copy_unmap_smoke<A: PageTableAuthority>(
    authority: &mut A,
    fixtures: &ConformanceFixtures,
) -> ConformanceResult {
    let src = authority
        .alloc_frame()
        .map_err(|_| ConformanceError::new("page_table_smoke", "source frame allocation failed"))?;
    if src == 0 {
        return Err(ConformanceError::new("page_table_smoke", "source frame is zero"));
    }
    let dst = authority.alloc_frame().map_err(|_| {
        ConformanceError::new("page_table_smoke", "destination frame allocation failed")
    })?;
    if dst == 0 || dst == src {
        return Err(ConformanceError::new(
            "page_table_smoke",
            "destination frame identity is invalid",
        ));
    }
    authority
        .map_page(fixtures.page_va, src, true, false)
        .map_err(|_| ConformanceError::new("page_table_smoke", "map_page failed"))?;
    authority
        .protect_page(fixtures.page_va, false, false)
        .map_err(|_| ConformanceError::new("page_table_smoke", "protect_page failed"))?;
    authority
        .copy_frame(src, dst, fixtures.page_copy_len)
        .map_err(|_| ConformanceError::new("page_table_smoke", "copy_frame failed"))?;
    authority
        .flush_tlb(fixtures.page_va)
        .map_err(|_| ConformanceError::new("page_table_smoke", "flush_tlb failed"))?;
    authority
        .unmap_page(fixtures.page_va)
        .map_err(|_| ConformanceError::new("page_table_smoke", "unmap_page failed"))
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

pub fn packet_device_tx_poll_smoke<A: PacketDeviceBackend>(
    authority: &mut A,
    fixtures: &ConformanceFixtures,
) -> ConformanceResult {
    authority
        .init(fixtures.packet_mac)
        .map_err(|_| ConformanceError::new("packet_device_smoke", "packet device init failed"))?;
    if authority.mtu() == 0 || authority.mtu() > PacketFrameSlot::new().data.len() {
        return Err(ConformanceError::new("packet_device_smoke", "packet device MTU is invalid"));
    }
    authority
        .submit_tx(&fixtures.packet_frame)
        .map_err(|_| ConformanceError::new("packet_device_smoke", "packet TX failed"))?;
    let mut slots = [PacketFrameSlot::new(), PacketFrameSlot::new()];
    let count = authority
        .poll_rx(&mut slots)
        .map_err(|_| ConformanceError::new("packet_device_smoke", "packet RX poll failed"))?;
    if count > slots.len() {
        return Err(ConformanceError::new(
            "packet_device_smoke",
            "packet RX poll over-reported filled slots",
        ));
    }
    if slots.iter().take(count).any(|slot| usize::from(slot.len) > slot.data.len()) {
        return Err(ConformanceError::new(
            "packet_device_smoke",
            "packet RX slot length overflowed",
        ));
    }
    Ok(())
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

pub fn page_table_unsupported_is_reported<A: PageTableAuthority>(
    authority: &mut A,
) -> ConformanceResult {
    unsupported_is_reported(
        "page_table_unsupported",
        authority.alloc_frame(),
        "PageTableAuthority",
        "alloc_frame",
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

pub fn packet_device_unsupported_is_reported<A: PacketDeviceBackend>(
    authority: &mut A,
) -> ConformanceResult {
    unsupported_is_reported(
        "packet_device_unsupported",
        authority.init([0x02, 0x56, 0x4d, 0x4f, 0x53, 0x01]),
        "PacketDeviceBackend",
        "init",
    )
}

#[macro_export]
macro_rules! conformance_test_suite {
    ($backend_factory:expr) => {
        use visa_profile::SubstrateProfile;
        use $crate::{
            SubstrateCapabilitySet,
            conformance::{
                ConformanceFixtures, SubstrateConformanceReport, check_substrate_profile,
            },
        };

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
