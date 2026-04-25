use alloc::vec::Vec;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum DmwSupport {
    None,
    Logical,
    RealMmuWindow,
}

impl DmwSupport {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Logical => "logical",
            Self::RealMmuWindow => "real-mmu-window",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum DmaSupport {
    None,
    BounceBuffer,
    Mediated,
    IommuStrict,
}

impl DmaSupport {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::BounceBuffer => "bounce-buffer",
            Self::Mediated => "mediated",
            Self::IommuStrict => "iommu-strict",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum SnapshotSupport {
    None,
    BarrierOnly,
    CowPages,
    DeterministicReplay,
}

impl SnapshotSupport {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::BarrierOnly => "barrier-only",
            Self::CowPages => "cow-pages",
            Self::DeterministicReplay => "deterministic-replay",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum CodePublishSupport {
    None,
    MetadataOnly,
    RuntimeOnly,
    NativeWx,
}

impl CodePublishSupport {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::MetadataOnly => "metadata-only",
            Self::RuntimeOnly => "runtime-only",
            Self::NativeWx => "native-wx",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SubstrateCapabilitySet {
    pub console: bool,
    pub timer: bool,
    pub event_queue: bool,
    pub guest_memory: bool,
    pub artifact_loading: bool,
    pub dmw: DmwSupport,
    pub mmio: bool,
    pub irq: bool,
    pub dma: DmaSupport,
    pub snapshot: SnapshotSupport,
    pub code_publish: CodePublishSupport,
}

impl SubstrateCapabilitySet {
    pub const fn empty() -> Self {
        Self {
            console: false,
            timer: false,
            event_queue: false,
            guest_memory: false,
            artifact_loading: false,
            dmw: DmwSupport::None,
            mmio: false,
            irq: false,
            dma: DmaSupport::None,
            snapshot: SnapshotSupport::None,
            code_publish: CodePublishSupport::None,
        }
    }

    pub const fn semantic_harness() -> Self {
        Self {
            console: true,
            timer: true,
            event_queue: true,
            guest_memory: true,
            artifact_loading: false,
            dmw: DmwSupport::None,
            mmio: false,
            irq: false,
            dma: DmaSupport::None,
            snapshot: SnapshotSupport::None,
            code_publish: CodePublishSupport::None,
        }
    }

    pub const fn supports_profile(self, profile: SubstrateProfile) -> bool {
        profile.requirements().is_satisfied_by(self)
    }

    pub fn check_profile(self, profile: SubstrateProfile) -> SubstrateCompatibilityReport {
        SubstrateAuthorityRequirements {
            required: profile.requirements(),
            optional: AuthorityRequirementSet::default(),
            forbidden: AuthorityRequirementSet::default(),
        }
        .check(self)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SubstrateProfile {
    SemanticHarness,
    MinimalBareMetal,
    GuestFrontend,
    DeviceCapable,
    SnapshotReplayCapable,
}

impl SubstrateProfile {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::SemanticHarness => "semantic-harness",
            Self::MinimalBareMetal => "minimal-bare-metal",
            Self::GuestFrontend => "guest-frontend",
            Self::DeviceCapable => "device-capable",
            Self::SnapshotReplayCapable => "snapshot-replay-capable",
        }
    }

    pub const fn requirements(self) -> AuthorityRequirementSet {
        match self {
            Self::SemanticHarness => AuthorityRequirementSet {
                console: true,
                timer: true,
                event_queue: true,
                guest_memory: true,
                artifact_loading: false,
                dmw: DmwRequirement::None,
                mmio: false,
                irq: false,
                dma: DmaRequirement::None,
                snapshot: SnapshotRequirement::None,
                code_publish: CodePublishRequirement::None,
            },
            Self::MinimalBareMetal => AuthorityRequirementSet {
                console: true,
                timer: true,
                event_queue: true,
                guest_memory: false,
                artifact_loading: true,
                dmw: DmwRequirement::None,
                mmio: false,
                irq: false,
                dma: DmaRequirement::None,
                snapshot: SnapshotRequirement::None,
                code_publish: CodePublishRequirement::MetadataOnly,
            },
            Self::GuestFrontend => AuthorityRequirementSet {
                console: true,
                timer: true,
                event_queue: true,
                guest_memory: true,
                artifact_loading: true,
                dmw: DmwRequirement::LogicalOrBetter,
                mmio: false,
                irq: false,
                dma: DmaRequirement::None,
                snapshot: SnapshotRequirement::None,
                code_publish: CodePublishRequirement::MetadataOnly,
            },
            Self::DeviceCapable => AuthorityRequirementSet {
                console: true,
                timer: true,
                event_queue: true,
                guest_memory: true,
                artifact_loading: true,
                dmw: DmwRequirement::LogicalOrBetter,
                mmio: true,
                irq: true,
                dma: DmaRequirement::MediatedOrBetter,
                snapshot: SnapshotRequirement::None,
                code_publish: CodePublishRequirement::MetadataOnly,
            },
            Self::SnapshotReplayCapable => AuthorityRequirementSet {
                console: true,
                timer: true,
                event_queue: true,
                guest_memory: true,
                artifact_loading: true,
                dmw: DmwRequirement::LogicalOrBetter,
                mmio: false,
                irq: false,
                dma: DmaRequirement::None,
                snapshot: SnapshotRequirement::DeterministicReplay,
                code_publish: CodePublishRequirement::MetadataOnly,
            },
        }
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct AuthorityRequirementSet {
    pub console: bool,
    pub timer: bool,
    pub event_queue: bool,
    pub guest_memory: bool,
    pub artifact_loading: bool,
    pub dmw: DmwRequirement,
    pub mmio: bool,
    pub irq: bool,
    pub dma: DmaRequirement,
    pub snapshot: SnapshotRequirement,
    pub code_publish: CodePublishRequirement,
}

impl AuthorityRequirementSet {
    pub const fn is_satisfied_by(self, capabilities: SubstrateCapabilitySet) -> bool {
        (!self.console || capabilities.console)
            && (!self.timer || capabilities.timer)
            && (!self.event_queue || capabilities.event_queue)
            && (!self.guest_memory || capabilities.guest_memory)
            && (!self.artifact_loading || capabilities.artifact_loading)
            && self.dmw.is_satisfied_by(capabilities.dmw)
            && (!self.mmio || capabilities.mmio)
            && (!self.irq || capabilities.irq)
            && self.dma.is_satisfied_by(capabilities.dma)
            && self.snapshot.is_satisfied_by(capabilities.snapshot)
            && self.code_publish.is_satisfied_by(capabilities.code_publish)
    }

    pub const fn any_present(self, capabilities: SubstrateCapabilitySet) -> bool {
        (self.console && capabilities.console)
            || (self.timer && capabilities.timer)
            || (self.event_queue && capabilities.event_queue)
            || (self.guest_memory && capabilities.guest_memory)
            || (self.artifact_loading && capabilities.artifact_loading)
            || self.dmw.is_present_in(capabilities.dmw)
            || (self.mmio && capabilities.mmio)
            || (self.irq && capabilities.irq)
            || self.dma.is_present_in(capabilities.dma)
            || self.snapshot.is_present_in(capabilities.snapshot)
            || self.code_publish.is_present_in(capabilities.code_publish)
    }

    fn missing(self, capabilities: SubstrateCapabilitySet) -> Vec<AuthorityMismatch> {
        let mut out = Vec::new();
        push_bool_missing(&mut out, "console", self.console, capabilities.console);
        push_bool_missing(&mut out, "timer", self.timer, capabilities.timer);
        push_bool_missing(
            &mut out,
            "event-queue",
            self.event_queue,
            capabilities.event_queue,
        );
        push_bool_missing(
            &mut out,
            "guest-memory",
            self.guest_memory,
            capabilities.guest_memory,
        );
        push_bool_missing(
            &mut out,
            "artifact-loading",
            self.artifact_loading,
            capabilities.artifact_loading,
        );
        if !self.dmw.is_satisfied_by(capabilities.dmw) {
            out.push(AuthorityMismatch::new(
                "dmw",
                self.dmw.as_str(),
                capabilities.dmw.as_str(),
            ));
        }
        push_bool_missing(&mut out, "mmio", self.mmio, capabilities.mmio);
        push_bool_missing(&mut out, "irq", self.irq, capabilities.irq);
        if !self.dma.is_satisfied_by(capabilities.dma) {
            out.push(AuthorityMismatch::new(
                "dma",
                self.dma.as_str(),
                capabilities.dma.as_str(),
            ));
        }
        if !self.snapshot.is_satisfied_by(capabilities.snapshot) {
            out.push(AuthorityMismatch::new(
                "snapshot",
                self.snapshot.as_str(),
                capabilities.snapshot.as_str(),
            ));
        }
        if !self.code_publish.is_satisfied_by(capabilities.code_publish) {
            out.push(AuthorityMismatch::new(
                "code-publish",
                self.code_publish.as_str(),
                capabilities.code_publish.as_str(),
            ));
        }
        out
    }

    fn present(self, capabilities: SubstrateCapabilitySet) -> Vec<AuthorityPresent> {
        let mut out = Vec::new();
        push_bool_present(&mut out, "console", self.console, capabilities.console);
        push_bool_present(&mut out, "timer", self.timer, capabilities.timer);
        push_bool_present(
            &mut out,
            "event-queue",
            self.event_queue,
            capabilities.event_queue,
        );
        push_bool_present(
            &mut out,
            "guest-memory",
            self.guest_memory,
            capabilities.guest_memory,
        );
        push_bool_present(
            &mut out,
            "artifact-loading",
            self.artifact_loading,
            capabilities.artifact_loading,
        );
        if self.dmw.is_present_in(capabilities.dmw) {
            out.push(AuthorityPresent::new("dmw", capabilities.dmw.as_str()));
        }
        push_bool_present(&mut out, "mmio", self.mmio, capabilities.mmio);
        push_bool_present(&mut out, "irq", self.irq, capabilities.irq);
        if self.dma.is_present_in(capabilities.dma) {
            out.push(AuthorityPresent::new("dma", capabilities.dma.as_str()));
        }
        if self.snapshot.is_present_in(capabilities.snapshot) {
            out.push(AuthorityPresent::new(
                "snapshot",
                capabilities.snapshot.as_str(),
            ));
        }
        if self.code_publish.is_present_in(capabilities.code_publish) {
            out.push(AuthorityPresent::new(
                "code-publish",
                capabilities.code_publish.as_str(),
            ));
        }
        out
    }
}

fn push_bool_missing(
    out: &mut Vec<AuthorityMismatch>,
    authority: &'static str,
    required: bool,
    actual: bool,
) {
    if required && !actual {
        out.push(AuthorityMismatch::new(authority, "true", "false"));
    }
}

fn push_bool_present(
    out: &mut Vec<AuthorityPresent>,
    authority: &'static str,
    forbidden: bool,
    actual: bool,
) {
    if forbidden && actual {
        out.push(AuthorityPresent::new(authority, "true"));
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum DmwRequirement {
    #[default]
    None,
    Any,
    LogicalOrBetter,
    RealMmuWindow,
}

impl DmwRequirement {
    pub const fn is_satisfied_by(self, support: DmwSupport) -> bool {
        match self {
            Self::None => true,
            Self::Any => !matches!(support, DmwSupport::None),
            Self::LogicalOrBetter => {
                matches!(support, DmwSupport::Logical | DmwSupport::RealMmuWindow)
            }
            Self::RealMmuWindow => matches!(support, DmwSupport::RealMmuWindow),
        }
    }

    pub const fn is_present_in(self, support: DmwSupport) -> bool {
        !matches!(self, Self::None) && !matches!(support, DmwSupport::None)
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Any => "any",
            Self::LogicalOrBetter => "logical-or-better",
            Self::RealMmuWindow => "real-mmu-window",
        }
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum DmaRequirement {
    #[default]
    None,
    Any,
    BounceBufferOrBetter,
    MediatedOrBetter,
    IommuStrict,
}

impl DmaRequirement {
    pub const fn is_satisfied_by(self, support: DmaSupport) -> bool {
        match self {
            Self::None => true,
            Self::Any => !matches!(support, DmaSupport::None),
            Self::BounceBufferOrBetter => matches!(
                support,
                DmaSupport::BounceBuffer | DmaSupport::Mediated | DmaSupport::IommuStrict
            ),
            Self::MediatedOrBetter => {
                matches!(support, DmaSupport::Mediated | DmaSupport::IommuStrict)
            }
            Self::IommuStrict => matches!(support, DmaSupport::IommuStrict),
        }
    }

    pub const fn is_present_in(self, support: DmaSupport) -> bool {
        !matches!(self, Self::None) && !matches!(support, DmaSupport::None)
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Any => "any",
            Self::BounceBufferOrBetter => "bounce-buffer-or-better",
            Self::MediatedOrBetter => "mediated-or-better",
            Self::IommuStrict => "iommu-strict",
        }
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum SnapshotRequirement {
    #[default]
    None,
    Any,
    BarrierOnlyOrBetter,
    CowPagesOrBetter,
    DeterministicReplay,
}

impl SnapshotRequirement {
    pub const fn is_satisfied_by(self, support: SnapshotSupport) -> bool {
        match self {
            Self::None => true,
            Self::Any => !matches!(support, SnapshotSupport::None),
            Self::BarrierOnlyOrBetter => matches!(
                support,
                SnapshotSupport::BarrierOnly
                    | SnapshotSupport::CowPages
                    | SnapshotSupport::DeterministicReplay
            ),
            Self::CowPagesOrBetter => {
                matches!(
                    support,
                    SnapshotSupport::CowPages | SnapshotSupport::DeterministicReplay
                )
            }
            Self::DeterministicReplay => matches!(support, SnapshotSupport::DeterministicReplay),
        }
    }

    pub const fn is_present_in(self, support: SnapshotSupport) -> bool {
        !matches!(self, Self::None) && !matches!(support, SnapshotSupport::None)
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Any => "any",
            Self::BarrierOnlyOrBetter => "barrier-only-or-better",
            Self::CowPagesOrBetter => "cow-pages-or-better",
            Self::DeterministicReplay => "deterministic-replay",
        }
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum CodePublishRequirement {
    #[default]
    None,
    Any,
    MetadataOnly,
    RuntimeOnly,
    NativeWx,
}

impl CodePublishRequirement {
    pub const fn is_satisfied_by(self, support: CodePublishSupport) -> bool {
        match self {
            Self::None => true,
            Self::Any => !matches!(support, CodePublishSupport::None),
            Self::MetadataOnly => matches!(
                support,
                CodePublishSupport::MetadataOnly
                    | CodePublishSupport::RuntimeOnly
                    | CodePublishSupport::NativeWx
            ),
            Self::RuntimeOnly => {
                matches!(
                    support,
                    CodePublishSupport::RuntimeOnly | CodePublishSupport::NativeWx
                )
            }
            Self::NativeWx => matches!(support, CodePublishSupport::NativeWx),
        }
    }

    pub const fn is_present_in(self, support: CodePublishSupport) -> bool {
        !matches!(self, Self::None) && !matches!(support, CodePublishSupport::None)
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Any => "any",
            Self::MetadataOnly => "metadata-only",
            Self::RuntimeOnly => "runtime-only",
            Self::NativeWx => "native-wx",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SubstrateAuthorityRequirements {
    pub required: AuthorityRequirementSet,
    pub optional: AuthorityRequirementSet,
    pub forbidden: AuthorityRequirementSet,
}

impl SubstrateAuthorityRequirements {
    pub fn check(&self, capabilities: SubstrateCapabilitySet) -> SubstrateCompatibilityReport {
        let missing_required = self.required.missing(capabilities);
        let degraded_optional = self.optional.missing(capabilities);
        let forbidden_present = self.forbidden.present(capabilities);
        SubstrateCompatibilityReport {
            ok: missing_required.is_empty() && forbidden_present.is_empty(),
            missing_required,
            degraded_optional,
            forbidden_present,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SubstrateCompatibilityReport {
    pub ok: bool,
    pub missing_required: Vec<AuthorityMismatch>,
    pub degraded_optional: Vec<AuthorityMismatch>,
    pub forbidden_present: Vec<AuthorityPresent>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthorityMismatch {
    pub authority: &'static str,
    pub required: &'static str,
    pub actual: &'static str,
}

impl AuthorityMismatch {
    pub const fn new(
        authority: &'static str,
        required: &'static str,
        actual: &'static str,
    ) -> Self {
        Self {
            authority,
            required,
            actual,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthorityPresent {
    pub authority: &'static str,
    pub actual: &'static str,
}

impl AuthorityPresent {
    pub const fn new(authority: &'static str, actual: &'static str) -> Self {
        Self { authority, actual }
    }
}
