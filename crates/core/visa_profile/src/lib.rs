//! Stable Semantic Virtual ISA profile types and compatibility matrix.
//!
//! Profiles describe what a target can enforce before artifacts load and what
//! an artifact requires, optionally uses, or forbids. They are vISA feature sets,
//! not OS labels and not frontend interface names.

#![no_std]

extern crate alloc;

use alloc::{string::String, vec::Vec};

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

    pub const fn for_profile(profile: SubstrateProfile) -> Self {
        match profile {
            SubstrateProfile::SemanticHarness => Self::semantic_harness(),
            SubstrateProfile::MinimalBareMetal => Self {
                console: true,
                timer: true,
                event_queue: true,
                guest_memory: false,
                artifact_loading: true,
                dmw: DmwSupport::None,
                mmio: false,
                irq: false,
                dma: DmaSupport::None,
                snapshot: SnapshotSupport::None,
                code_publish: CodePublishSupport::MetadataOnly,
            },
            SubstrateProfile::GuestFrontend => Self {
                console: true,
                timer: true,
                event_queue: true,
                guest_memory: true,
                artifact_loading: true,
                dmw: DmwSupport::Logical,
                mmio: false,
                irq: false,
                dma: DmaSupport::None,
                snapshot: SnapshotSupport::None,
                code_publish: CodePublishSupport::MetadataOnly,
            },
            SubstrateProfile::DeviceCapable => Self {
                console: true,
                timer: true,
                event_queue: true,
                guest_memory: true,
                artifact_loading: true,
                dmw: DmwSupport::Logical,
                mmio: true,
                irq: true,
                dma: DmaSupport::Mediated,
                snapshot: SnapshotSupport::None,
                code_publish: CodePublishSupport::MetadataOnly,
            },
            SubstrateProfile::SnapshotReplayCapable => Self {
                console: true,
                timer: true,
                event_queue: true,
                guest_memory: true,
                artifact_loading: true,
                dmw: DmwSupport::Logical,
                mmio: true,
                irq: true,
                dma: DmaSupport::Mediated,
                snapshot: SnapshotSupport::DeterministicReplay,
                code_publish: CodePublishSupport::MetadataOnly,
            },
        }
    }

    pub const fn host_validation() -> Self {
        Self {
            console: true,
            timer: true,
            event_queue: true,
            guest_memory: true,
            artifact_loading: true,
            dmw: DmwSupport::Logical,
            mmio: true,
            irq: true,
            dma: DmaSupport::Mediated,
            snapshot: SnapshotSupport::DeterministicReplay,
            code_publish: CodePublishSupport::MetadataOnly,
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
    pub const ALL_ASCENDING: [Self; 5] = [
        Self::SemanticHarness,
        Self::MinimalBareMetal,
        Self::GuestFrontend,
        Self::DeviceCapable,
        Self::SnapshotReplayCapable,
    ];

    pub const fn parse(value: &str) -> Option<Self> {
        match value.as_bytes() {
            b"semantic-harness" => Some(Self::SemanticHarness),
            b"reference-harness" => Some(Self::SemanticHarness),
            b"minimal-bare-metal" => Some(Self::MinimalBareMetal),
            b"console-timer-event" => Some(Self::MinimalBareMetal),
            b"guest-frontend" => Some(Self::GuestFrontend),
            b"guest-memory-logical-dmw" => Some(Self::GuestFrontend),
            b"device-capable" => Some(Self::DeviceCapable),
            b"snapshot-replay-capable" => Some(Self::SnapshotReplayCapable),
            _ => None,
        }
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::SemanticHarness => "semantic-harness",
            Self::MinimalBareMetal => "minimal-bare-metal",
            Self::GuestFrontend => "guest-frontend",
            Self::DeviceCapable => "device-capable",
            Self::SnapshotReplayCapable => "snapshot-replay-capable",
        }
    }

    pub const fn canonical_id(self) -> &'static str {
        match self {
            Self::SemanticHarness => "reference-harness",
            Self::MinimalBareMetal => "console-timer-event",
            Self::GuestFrontend => "guest-memory-logical-dmw",
            Self::DeviceCapable => "device-capable",
            Self::SnapshotReplayCapable => "snapshot-replay-capable",
        }
    }

    pub const fn profile_number(self) -> u8 {
        match self {
            Self::SemanticHarness => 0,
            Self::MinimalBareMetal => 1,
            Self::GuestFrontend => 2,
            Self::DeviceCapable => 3,
            Self::SnapshotReplayCapable => 4,
        }
    }

    pub const fn satisfies(self, required: Self) -> bool {
        self.profile_number() >= required.profile_number()
    }

    pub fn strongest_satisfied_by(capabilities: SubstrateCapabilitySet) -> Option<Self> {
        Self::ALL_ASCENDING
            .iter()
            .rev()
            .copied()
            .find(|profile| capabilities.supports_profile(*profile))
    }

    pub const fn requirements(self) -> AuthorityRequirementSet {
        match self {
            Self::SemanticHarness => AuthorityRequirementSet {
                console: true,
                timer: true,
                event_queue: true,
                guest_memory: false,
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
                mmio: true,
                irq: true,
                dma: DmaRequirement::MediatedOrBetter,
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
    pub fn from_tokens<'a>(
        tokens: impl IntoIterator<Item = &'a str>,
    ) -> Result<Self, AuthorityRequirementParseError> {
        let mut requirements = Self::default();
        for token in tokens {
            requirements.add_token(token)?;
        }
        Ok(requirements)
    }

    pub fn add_token(&mut self, token: &str) -> Result<(), AuthorityRequirementParseError> {
        match token {
            "console" => self.console = true,
            "timer" => self.timer = true,
            "event-queue" => self.event_queue = true,
            "guest-memory" => self.guest_memory = true,
            "artifact-loading" => self.artifact_loading = true,
            "mmio" => self.mmio = true,
            "irq" => self.irq = true,
            _ => {
                let Some((authority, requirement)) = token.split_once(':') else {
                    return Err(AuthorityRequirementParseError::unknown(token));
                };
                match authority {
                    "dmw" => self.dmw = parse_dmw_requirement(token, requirement)?,
                    "dma" => self.dma = parse_dma_requirement(token, requirement)?,
                    "snapshot" => self.snapshot = parse_snapshot_requirement(token, requirement)?,
                    "code-publish" => {
                        self.code_publish = parse_code_publish_requirement(token, requirement)?
                    }
                    _ => return Err(AuthorityRequirementParseError::unknown(token)),
                }
            }
        }
        Ok(())
    }

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

    pub fn merged_with(self, other: Self) -> Self {
        Self {
            console: self.console || other.console,
            timer: self.timer || other.timer,
            event_queue: self.event_queue || other.event_queue,
            guest_memory: self.guest_memory || other.guest_memory,
            artifact_loading: self.artifact_loading || other.artifact_loading,
            dmw: core::cmp::max(self.dmw, other.dmw),
            mmio: self.mmio || other.mmio,
            irq: self.irq || other.irq,
            dma: core::cmp::max(self.dma, other.dma),
            snapshot: core::cmp::max(self.snapshot, other.snapshot),
            code_publish: core::cmp::max(self.code_publish, other.code_publish),
        }
    }

    fn missing(self, capabilities: SubstrateCapabilitySet) -> Vec<AuthorityMismatch> {
        let mut out = Vec::new();
        push_bool_missing(&mut out, "console", self.console, capabilities.console);
        push_bool_missing(&mut out, "timer", self.timer, capabilities.timer);
        push_bool_missing(&mut out, "event-queue", self.event_queue, capabilities.event_queue);
        push_bool_missing(&mut out, "guest-memory", self.guest_memory, capabilities.guest_memory);
        push_bool_missing(
            &mut out,
            "artifact-loading",
            self.artifact_loading,
            capabilities.artifact_loading,
        );
        if !self.dmw.is_satisfied_by(capabilities.dmw) {
            out.push(AuthorityMismatch::new("dmw", self.dmw.as_str(), capabilities.dmw.as_str()));
        }
        push_bool_missing(&mut out, "mmio", self.mmio, capabilities.mmio);
        push_bool_missing(&mut out, "irq", self.irq, capabilities.irq);
        if !self.dma.is_satisfied_by(capabilities.dma) {
            out.push(AuthorityMismatch::new("dma", self.dma.as_str(), capabilities.dma.as_str()));
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
        push_bool_present(&mut out, "event-queue", self.event_queue, capabilities.event_queue);
        push_bool_present(&mut out, "guest-memory", self.guest_memory, capabilities.guest_memory);
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
            out.push(AuthorityPresent::new("snapshot", capabilities.snapshot.as_str()));
        }
        if self.code_publish.is_present_in(capabilities.code_publish) {
            out.push(AuthorityPresent::new("code-publish", capabilities.code_publish.as_str()));
        }
        out
    }
}

fn parse_dmw_requirement(
    token: &str,
    requirement: &str,
) -> Result<DmwRequirement, AuthorityRequirementParseError> {
    match requirement {
        "any" => Ok(DmwRequirement::Any),
        "logical-or-better" => Ok(DmwRequirement::LogicalOrBetter),
        "real-mmu-window" => Ok(DmwRequirement::RealMmuWindow),
        "none" => Ok(DmwRequirement::None),
        _ => Err(AuthorityRequirementParseError::unknown(token)),
    }
}

fn parse_dma_requirement(
    token: &str,
    requirement: &str,
) -> Result<DmaRequirement, AuthorityRequirementParseError> {
    match requirement {
        "any" => Ok(DmaRequirement::Any),
        "bounce-buffer-or-better" => Ok(DmaRequirement::BounceBufferOrBetter),
        "mediated-or-better" => Ok(DmaRequirement::MediatedOrBetter),
        "iommu-strict" => Ok(DmaRequirement::IommuStrict),
        "none" => Ok(DmaRequirement::None),
        _ => Err(AuthorityRequirementParseError::unknown(token)),
    }
}

fn parse_snapshot_requirement(
    token: &str,
    requirement: &str,
) -> Result<SnapshotRequirement, AuthorityRequirementParseError> {
    match requirement {
        "any" => Ok(SnapshotRequirement::Any),
        "barrier-only-or-better" => Ok(SnapshotRequirement::BarrierOnlyOrBetter),
        "cow-pages-or-better" => Ok(SnapshotRequirement::CowPagesOrBetter),
        "deterministic-replay" => Ok(SnapshotRequirement::DeterministicReplay),
        "none" => Ok(SnapshotRequirement::None),
        _ => Err(AuthorityRequirementParseError::unknown(token)),
    }
}

fn parse_code_publish_requirement(
    token: &str,
    requirement: &str,
) -> Result<CodePublishRequirement, AuthorityRequirementParseError> {
    match requirement {
        "any" => Ok(CodePublishRequirement::Any),
        "metadata-only" => Ok(CodePublishRequirement::MetadataOnly),
        "runtime-only" => Ok(CodePublishRequirement::RuntimeOnly),
        "native-wx" => Ok(CodePublishRequirement::NativeWx),
        "none" => Ok(CodePublishRequirement::None),
        _ => Err(AuthorityRequirementParseError::unknown(token)),
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthorityRequirementParseError {
    pub token: String,
    pub reason: &'static str,
}

impl AuthorityRequirementParseError {
    pub fn unknown(token: &str) -> Self {
        Self { token: token.into(), reason: "unknown authority requirement" }
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

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord)]
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

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord)]
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

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord)]
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
                matches!(support, SnapshotSupport::CowPages | SnapshotSupport::DeterministicReplay)
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

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord)]
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
                matches!(support, CodePublishSupport::RuntimeOnly | CodePublishSupport::NativeWx)
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
        Self { authority, required, actual }
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

pub type VisaProfileLevel = SubstrateProfile;
pub type VisaCapabilitySet = SubstrateCapabilitySet;
pub type VisaAuthorityRequirements = SubstrateAuthorityRequirements;
pub type VisaRequirementSet = SubstrateAuthorityRequirements;
pub type ProfileCompatibilityReport = SubstrateCompatibilityReport;

pub fn check_profile_compatibility(
    required_profile: VisaProfileLevel,
    required_authorities: AuthorityRequirementSet,
    optional_authorities: AuthorityRequirementSet,
    forbidden_authorities: AuthorityRequirementSet,
    enforced_capabilities: VisaCapabilitySet,
) -> ProfileCompatibilityReport {
    VisaRequirementSet {
        required: required_profile.requirements().merged_with(required_authorities),
        optional: optional_authorities,
        forbidden: forbidden_authorities,
    }
    .check(enforced_capabilities)
}

#[cfg(test)]
mod tests {
    use alloc::vec;

    use super::*;

    #[test]
    fn canonical_and_legacy_profile_ids_parse() {
        assert_eq!(
            VisaProfileLevel::parse("reference-harness"),
            Some(VisaProfileLevel::SemanticHarness)
        );
        assert_eq!(
            VisaProfileLevel::parse("semantic-harness"),
            Some(VisaProfileLevel::SemanticHarness)
        );
        assert_eq!(
            VisaProfileLevel::parse("console-timer-event"),
            Some(VisaProfileLevel::MinimalBareMetal)
        );
        assert_eq!(
            VisaProfileLevel::parse("guest-memory-logical-dmw"),
            Some(VisaProfileLevel::GuestFrontend)
        );
        assert_eq!(VisaProfileLevel::DeviceCapable.canonical_id(), "device-capable");
    }

    #[test]
    fn profile_levels_are_linear_for_load_compatibility() {
        let profiles = [
            VisaProfileLevel::SemanticHarness,
            VisaProfileLevel::MinimalBareMetal,
            VisaProfileLevel::GuestFrontend,
            VisaProfileLevel::DeviceCapable,
            VisaProfileLevel::SnapshotReplayCapable,
        ];
        for (required_index, required) in profiles.iter().copied().enumerate() {
            for (enforced_index, enforced) in profiles.iter().copied().enumerate() {
                assert_eq!(enforced.satisfies(required), enforced_index >= required_index);
                assert_eq!(
                    VisaCapabilitySet::for_profile(enforced).supports_profile(required),
                    enforced_index >= required_index
                );
            }
        }
    }

    #[test]
    fn optional_missing_degrades_without_rejecting() {
        let report = check_profile_compatibility(
            VisaProfileLevel::SemanticHarness,
            AuthorityRequirementSet::default(),
            AuthorityRequirementSet {
                snapshot: SnapshotRequirement::DeterministicReplay,
                ..Default::default()
            },
            AuthorityRequirementSet::default(),
            VisaCapabilitySet::semantic_harness(),
        );

        assert!(report.ok);
        assert_eq!(
            report.degraded_optional,
            vec![AuthorityMismatch::new("snapshot", "deterministic-replay", "none")]
        );
    }

    #[test]
    fn forbidden_present_rejects() {
        let report = check_profile_compatibility(
            VisaProfileLevel::SemanticHarness,
            AuthorityRequirementSet::default(),
            AuthorityRequirementSet::default(),
            AuthorityRequirementSet { mmio: true, ..Default::default() },
            VisaCapabilitySet::host_validation(),
        );

        assert!(!report.ok);
        assert_eq!(report.forbidden_present, vec![AuthorityPresent::new("mmio", "true")]);
    }
}
