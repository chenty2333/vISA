use super::*;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ActivationEntry {
    Symbol(String),
    Hostcall(u32),
}

impl ActivationEntry {
    pub fn summary(&self) -> String {
        match self {
            Self::Symbol(symbol) => format!("symbol:{symbol}"),
            Self::Hostcall(hostcall) => format!("hostcall:{hostcall}"),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ActivationState {
    Running,
    Pending,
    Trapped,
    Returned,
    Dropped,
}

impl ActivationState {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Running => "running",
            Self::Pending => "pending",
            Self::Trapped => "trapped",
            Self::Returned => "returned",
            Self::Dropped => "dropped",
        }
    }
}

#[repr(u16)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HostcallReturnTag {
    Ok = 0,
    Errno = 1,
    Pending = 2,
    Trap = 3,
    KillStore = 4,
    RestartSyscall = 5,
    BadAbi = 6,
}

impl HostcallReturnTag {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Ok => "ok",
            Self::Errno => "errno",
            Self::Pending => "pending",
            Self::Trap => "trap",
            Self::KillStore => "kill-store",
            Self::RestartSyscall => "restart-syscall",
            Self::BadAbi => "bad-abi",
        }
    }

    pub const fn as_u16(self) -> u16 {
        self as u16
    }

    pub const fn from_u16(value: u16) -> Option<Self> {
        match value {
            0 => Some(Self::Ok),
            1 => Some(Self::Errno),
            2 => Some(Self::Pending),
            3 => Some(Self::Trap),
            4 => Some(Self::KillStore),
            5 => Some(Self::RestartSyscall),
            6 => Some(Self::BadAbi),
            _ => None,
        }
    }
}

#[repr(u16)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RecordMode {
    Deterministic = 0,
    RecordInput = 1,
    RecordOutput = 2,
    RecordInputOutput = 3,
    ForbiddenDuringReplay = 4,
}

impl RecordMode {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Deterministic => "deterministic",
            Self::RecordInput => "record-input",
            Self::RecordOutput => "record-output",
            Self::RecordInputOutput => "record-input-output",
            Self::ForbiddenDuringReplay => "forbidden-during-replay",
        }
    }

    pub const fn as_u16(self) -> u16 {
        self as u16
    }

    pub const fn from_u16(value: u16) -> Option<Self> {
        match value {
            0 => Some(Self::Deterministic),
            1 => Some(Self::RecordInput),
            2 => Some(Self::RecordOutput),
            3 => Some(Self::RecordInputOutput),
            4 => Some(Self::ForbiddenDuringReplay),
            _ => None,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ActivationRecord {
    pub id: ActivationId,
    pub store: StoreId,
    pub store_generation: Generation,
    pub code_object: CodeObjectId,
    pub code_generation: Generation,
    pub artifact: TargetArtifactId,
    pub entry: ActivationEntry,
    pub generation: Generation,
    pub state: ActivationState,
    pub start_event: EventId,
    pub exit_event: Option<EventId>,
    pub active_dmw_leases: u32,
    pub blocked_wait: Option<WaitId>,
    pub trap: Option<TargetTrapId>,
    pub return_tag: Option<HostcallReturnTag>,
}

impl ActivationRecord {
    pub fn summary(&self) -> String {
        let exit =
            self.exit_event.map(|event| event.to_string()).unwrap_or_else(|| "none".to_string());
        let wait =
            self.blocked_wait.map(|wait| wait.to_string()).unwrap_or_else(|| "none".to_string());
        let trap = self.trap.map(|trap| trap.to_string()).unwrap_or_else(|| "none".to_string());
        let return_tag = self.return_tag.map(|tag| tag.as_str()).unwrap_or("none");
        format!(
            "activation id={} store={} store_generation={} code={} code_generation={} artifact={} entry={} state={} generation={} start={} exit={} dmw_leases={} wait={} trap={} return={}",
            self.id,
            self.store,
            self.store_generation,
            self.code_object,
            self.code_generation,
            self.artifact,
            self.entry.summary(),
            self.state.as_str(),
            self.generation,
            self.start_event,
            exit,
            self.active_dmw_leases,
            wait,
            trap,
            return_tag
        )
    }
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct WireObjectRef {
    pub id: u64,
    pub generation: u64,
}

impl WireObjectRef {
    pub const NULL: Self = Self { id: 0, generation: 0 };

    pub const fn new(id: u64, generation: u64) -> Self {
        Self { id, generation }
    }
}

#[repr(transparent)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ArtifactRefV1(pub WireObjectRef);

#[repr(transparent)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct CodeObjectRefV1(pub WireObjectRef);

#[repr(transparent)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct StoreRefV1(pub WireObjectRef);

#[repr(transparent)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ActivationRefV1(pub WireObjectRef);

#[repr(transparent)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct TrapRefV1(pub WireObjectRef);

#[repr(transparent)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct WaitTokenRefV1(pub WireObjectRef);

#[repr(transparent)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct CapabilityRefV1(pub WireObjectRef);

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ExecutorCapabilityHandleV1 {
    pub owner_store: StoreRefV1,
    pub slot: u32,
    pub slot_generation: u32,
    pub tag: u64,
    pub rights_mask: u64,
    pub object_class: u16,
    pub reserved: [u16; 3],
}

#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ExecutorHostcallFrameV1 {
    pub magic: u32,
    pub abi_version: u16,
    pub frame_size: u16,
    pub flags: u32,
    pub record_mode: u16,
    pub ret_tag: u16,
    pub activation: ActivationRefV1,
    pub store: StoreRefV1,
    pub code_object: CodeObjectRefV1,
    pub artifact: ArtifactRefV1,
    pub hostcall_number: u32,
    pub cap_arg_count: u16,
    pub reserved0: u16,
    pub hostcall_seq: u64,
    pub caller_offset: u64,
    pub args: [u64; 6],
    pub cap_args: [ExecutorCapabilityHandleV1; 4],
    pub ret0: u64,
    pub ret1: u64,
    pub trap_out: TrapRefV1,
    pub wait_token_out: WaitTokenRefV1,
}

impl ExecutorHostcallFrameV1 {
    pub const MAGIC: u32 = 0x564d_4843;
    pub const ABI_VERSION: u16 = 1;
    pub const FRAME_SIZE: u16 = core::mem::size_of::<Self>() as u16;
    pub const CAP_ARG_CAPACITY: usize = 4;

    pub const fn activation_id(&self) -> ActivationId {
        self.activation.0.id
    }

    pub const fn activation_generation(&self) -> Generation {
        self.activation.0.generation
    }

    pub const fn store_id(&self) -> StoreId {
        self.store.0.id
    }

    pub const fn store_generation(&self) -> Generation {
        self.store.0.generation
    }

    pub const fn code_object_id(&self) -> CodeObjectId {
        self.code_object.0.id
    }

    pub const fn code_generation(&self) -> Generation {
        self.code_object.0.generation
    }

    pub const fn artifact_id(&self) -> TargetArtifactId {
        self.artifact.0.id
    }

    pub const fn artifact_generation(&self) -> Generation {
        self.artifact.0.generation
    }
}

impl Default for ExecutorHostcallFrameV1 {
    fn default() -> Self {
        Self {
            magic: Self::MAGIC,
            abi_version: Self::ABI_VERSION,
            frame_size: Self::FRAME_SIZE,
            flags: 0,
            record_mode: RecordMode::Deterministic.as_u16(),
            ret_tag: HostcallReturnTag::Ok.as_u16(),
            activation: ActivationRefV1(WireObjectRef::NULL),
            store: StoreRefV1(WireObjectRef::NULL),
            code_object: CodeObjectRefV1(WireObjectRef::NULL),
            artifact: ArtifactRefV1(WireObjectRef::NULL),
            hostcall_number: 0,
            cap_arg_count: 0,
            reserved0: 0,
            hostcall_seq: 0,
            caller_offset: 0,
            args: [0; 6],
            cap_args: [ExecutorCapabilityHandleV1::default(); 4],
            ret0: 0,
            ret1: 0,
            trap_out: TrapRefV1(WireObjectRef::NULL),
            wait_token_out: WaitTokenRefV1(WireObjectRef::NULL),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TargetTrapClass {
    GuestTrap,
    SupervisorStoreTrap,
    CapabilityTrap,
    WindowTrap,
    HostcallTrap,
    CodeObjectTrap,
    SubstrateFault,
}

impl TargetTrapClass {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::GuestTrap => "guest-trap",
            Self::SupervisorStoreTrap => "supervisor-store-trap",
            Self::CapabilityTrap => "capability-trap",
            Self::WindowTrap => "window-trap",
            Self::HostcallTrap => "hostcall-trap",
            Self::CodeObjectTrap => "code-object-trap",
            Self::SubstrateFault => "substrate-fault",
        }
    }

    pub const fn legacy_trap(self) -> TrapClass {
        match self {
            Self::GuestTrap => TrapClass::GuestIllegalInstruction,
            Self::SupervisorStoreTrap => TrapClass::ServiceTrap,
            Self::CapabilityTrap => TrapClass::CapabilityDenied,
            Self::WindowTrap => TrapClass::WindowViolationTrap,
            Self::HostcallTrap => TrapClass::ServiceTrap,
            Self::CodeObjectTrap => TrapClass::WasmBoundsTrap,
            Self::SubstrateFault => TrapClass::SubstrateFault,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SimdTrapClassification {
    UnsupportedTargetProfile,
    IllegalInstruction,
    RequirementMissing,
}

impl SimdTrapClassification {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::UnsupportedTargetProfile => "unsupported-target-profile",
            Self::IllegalInstruction => "illegal-instruction",
            Self::RequirementMissing => "requirement-missing",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SimdTrapAttribution {
    pub classification: SimdTrapClassification,
    pub required_abi: String,
    pub min_vector_register_count: u16,
    pub min_vector_register_bits: u16,
    pub target_feature_set: Option<ContractObjectRef>,
    pub code_requirement_status: CodeObjectSimdRequirementStatus,
    pub note: String,
}

impl SimdTrapAttribution {
    pub(super) fn from_code(kind: TrapKindV1, code: Option<&CodeObject>) -> Option<Self> {
        let classification = match kind {
            TrapKindV1::SimdUnsupported => SimdTrapClassification::UnsupportedTargetProfile,
            TrapKindV1::SimdIllegalInstruction => SimdTrapClassification::IllegalInstruction,
            _ => return None,
        };
        let Some(code) = code else {
            return Some(Self {
                classification: SimdTrapClassification::RequirementMissing,
                required_abi: String::new(),
                min_vector_register_count: 0,
                min_vector_register_bits: 0,
                target_feature_set: None,
                code_requirement_status: CodeObjectSimdRequirementStatus::MissingDeclaration,
                note: "SIMD trap had no code object attribution".to_string(),
            });
        };
        if !code.simd_requirement.uses_simd || !code.simd_requirement.declared {
            return Some(Self {
                classification: SimdTrapClassification::RequirementMissing,
                required_abi: code.simd_requirement.required_abi.clone(),
                min_vector_register_count: code.simd_requirement.min_vector_register_count,
                min_vector_register_bits: code.simd_requirement.min_vector_register_bits,
                target_feature_set: code.simd_requirement.target_feature_set,
                code_requirement_status: code.simd_requirement.status,
                note: "SIMD trap was raised for code without a declared SIMD requirement"
                    .to_string(),
            });
        }
        Some(Self {
            classification,
            required_abi: code.simd_requirement.required_abi.clone(),
            min_vector_register_count: code.simd_requirement.min_vector_register_count,
            min_vector_register_bits: code.simd_requirement.min_vector_register_bits,
            target_feature_set: code.simd_requirement.target_feature_set,
            code_requirement_status: code.simd_requirement.status,
            note: "SIMD trap is attributed through the CodeObject SIMD requirement".to_string(),
        })
    }
}

pub(super) fn trap_class_for_attribution(kind: TrapKindV1) -> TargetTrapClass {
    match kind {
        TrapKindV1::CapabilityDenied => TargetTrapClass::CapabilityTrap,
        TrapKindV1::WindowViolation => TargetTrapClass::WindowTrap,
        TrapKindV1::HostcallFault => TargetTrapClass::HostcallTrap,
        TrapKindV1::UnknownCodeFault | TrapKindV1::SubstrateFault => {
            TargetTrapClass::SubstrateFault
        }
        TrapKindV1::UnknownCodeTrap | TrapKindV1::StaleCodeExecutionFault => {
            TargetTrapClass::CodeObjectTrap
        }
        TrapKindV1::SimdUnsupported | TrapKindV1::SimdIllegalInstruction => {
            TargetTrapClass::CodeObjectTrap
        }
        TrapKindV1::WasmBounds
        | TrapKindV1::WasmUnreachable
        | TrapKindV1::BadIndirectCall
        | TrapKindV1::IntegerDivByZero
        | TrapKindV1::StackOverflow => TargetTrapClass::GuestTrap,
    }
}

pub(super) fn trap_attribution_status(attribution: Option<TrapAttributionV1>) -> &'static str {
    match attribution.map(|attribution| attribution.trap_kind) {
        None => "synthetic",
        Some(TrapKindV1::UnknownCodeFault | TrapKindV1::SubstrateFault) => "trap-map-unknown-pc",
        Some(TrapKindV1::UnknownCodeTrap) => "trap-map-missing-entry",
        Some(TrapKindV1::StaleCodeExecutionFault) => "trap-map-stale-code",
        Some(_) => "trap-map-attributed",
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TargetTrapRecord {
    pub id: TargetTrapId,
    pub generation: Generation,
    pub class: TargetTrapClass,
    pub store: Option<StoreId>,
    pub store_generation: Option<Generation>,
    pub activation: Option<ActivationId>,
    pub activation_generation: Option<Generation>,
    pub code_object: Option<CodeObjectId>,
    pub code_generation: Option<Generation>,
    pub artifact: Option<TargetArtifactId>,
    pub artifact_generation: Option<Generation>,
    pub offset: Option<u64>,
    pub target_pc: Option<u64>,
    pub trap_kind: Option<String>,
    pub function_index: Option<u32>,
    pub wasm_offset: Option<u64>,
    pub debug_symbol: Option<u32>,
    pub classification_status: Option<String>,
    pub attribution_status: String,
    pub simd_attribution: Option<SimdTrapAttribution>,
    pub hostcall: Option<String>,
    pub fault_policy: String,
    pub effect: FailureEffect,
    pub detail: String,
}

impl TargetTrapRecord {
    pub fn summary(&self) -> String {
        let store = self.store.map(|store| store.to_string()).unwrap_or_else(|| "none".to_string());
        let activation = self
            .activation
            .map(|activation| activation.to_string())
            .unwrap_or_else(|| "none".to_string());
        let store_generation = self
            .store_generation
            .map(|generation| generation.to_string())
            .unwrap_or_else(|| "none".to_string());
        let activation_generation = self
            .activation_generation
            .map(|generation| generation.to_string())
            .unwrap_or_else(|| "none".to_string());
        let code =
            self.code_object.map(|code| code.to_string()).unwrap_or_else(|| "none".to_string());
        let artifact = self
            .artifact
            .map(|artifact| artifact.to_string())
            .unwrap_or_else(|| "none".to_string());
        let code_generation = self
            .code_generation
            .map(|generation| generation.to_string())
            .unwrap_or_else(|| "none".to_string());
        let artifact_generation = self
            .artifact_generation
            .map(|generation| generation.to_string())
            .unwrap_or_else(|| "none".to_string());
        let offset =
            self.offset.map(|offset| format!("{offset:#x}")).unwrap_or_else(|| "none".to_string());
        let hostcall = self.hostcall.as_deref().unwrap_or("none");
        format!(
            "trap id={} generation={} class={} store={} store_generation={} activation={} activation_generation={} code={} code_generation={} artifact={} artifact_generation={} offset={} attribution={} hostcall={} policy={} effect={} detail={}",
            self.id,
            self.generation,
            self.class.as_str(),
            store,
            store_generation,
            activation,
            activation_generation,
            code,
            code_generation,
            artifact,
            artifact_generation,
            offset,
            self.attribution_status,
            hostcall,
            self.fault_policy,
            self.effect.summary(),
            self.detail
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CapabilityHandleArg {
    pub id: CapabilityId,
    pub object: String,
    pub object_ref: Option<AuthorityObjectRef>,
    pub generation: Generation,
    pub owner_store: Option<StoreId>,
    pub owner_store_generation: Option<Generation>,
    pub handle_slot: u32,
    pub handle_generation: u32,
    pub handle_tag: u64,
    pub class_hint: Option<CapabilityClass>,
    pub rights_mask: u64,
    pub rights: Vec<String>,
}

impl CapabilityHandleArg {
    pub fn new(
        id: CapabilityId,
        object: &str,
        generation: Generation,
        rights_mask: u64,
        rights: &[&str],
    ) -> Self {
        let class = CapabilityClass::from_object(object);
        Self {
            id,
            object: object.to_string(),
            object_ref: Some(AuthorityObjectRef::from_label(class, object)),
            generation,
            owner_store: None,
            owner_store_generation: None,
            handle_slot: 0,
            handle_generation: 0,
            handle_tag: 0,
            class_hint: Some(class),
            rights_mask,
            rights: rights.iter().map(|right| (*right).to_string()).collect(),
        }
    }

    pub fn capability_handle(&self) -> Option<CapabilityHandle> {
        Some(CapabilityHandle::new(
            self.owner_store?,
            self.owner_store_generation?,
            self.handle_slot,
            self.handle_generation,
            self.handle_tag,
            self.rights.clone(),
            self.class_hint?,
        ))
    }

    pub fn from_record(record: &CapabilityRecord, rights_mask: u64, rights: &[&str]) -> Self {
        Self {
            id: record.id,
            object: record.debug_object_label.clone(),
            object_ref: record.object_ref,
            generation: record.generation,
            owner_store: record.owner_store,
            owner_store_generation: record.owner_store_generation,
            handle_slot: record.handle_slot,
            handle_generation: record.handle_generation,
            handle_tag: record.handle_tag,
            class_hint: Some(record.class),
            rights_mask,
            rights: rights.iter().map(|right| (*right).to_string()).collect(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HostcallFrame {
    pub abi_version: String,
    pub frame_size: u16,
    pub flags: u32,
    pub activation: ActivationId,
    pub activation_generation: Generation,
    pub store: StoreId,
    pub store_generation: Generation,
    pub code_object: CodeObjectId,
    pub code_generation: Generation,
    pub artifact: TargetArtifactId,
    pub artifact_generation: Generation,
    pub hostcall_number: u32,
    pub hostcall_seq: u64,
    pub caller_offset: u64,
    pub subject: String,
    pub object: String,
    pub operation: String,
    pub generation: Generation,
    pub args: [u64; 6],
    pub cap_args: Vec<CapabilityHandleArg>,
    pub record_mode: RecordMode,
    pub ret_tag: HostcallReturnTag,
    pub ret0: u64,
    pub ret1: u64,
    pub trap_out: Option<TargetTrapId>,
    pub trap_generation_out: Option<Generation>,
    pub wait_token_out: Option<WaitId>,
    pub wait_token_generation_out: Option<Generation>,
}

impl HostcallFrame {
    pub const ABI_VERSION: &'static str = "vmos-target-hostcall-frame-v1";
    pub const FRAME_SIZE: u16 = ExecutorHostcallFrameV1::FRAME_SIZE;

    pub fn new(
        activation: ActivationId,
        store: StoreId,
        hostcall_number: u32,
        subject: &str,
        object: &str,
        operation: &str,
        generation: Generation,
    ) -> Self {
        Self {
            abi_version: Self::ABI_VERSION.to_string(),
            frame_size: Self::FRAME_SIZE,
            flags: 0,
            activation,
            activation_generation: 1,
            store,
            store_generation: 0,
            code_object: 0,
            code_generation: 0,
            artifact: 0,
            artifact_generation: 0,
            hostcall_number,
            hostcall_seq: 1,
            caller_offset: 0,
            subject: subject.to_string(),
            object: object.to_string(),
            operation: operation.to_string(),
            generation,
            args: [0; 6],
            cap_args: Vec::new(),
            record_mode: RecordMode::Deterministic,
            ret_tag: HostcallReturnTag::Ok,
            ret0: 0,
            ret1: 0,
            trap_out: None,
            trap_generation_out: None,
            wait_token_out: None,
            wait_token_generation_out: None,
        }
    }

    pub fn new_bound(
        activation: ActivationId,
        store: &StoreRecord,
        code: &CodeObject,
        hostcall_number: u32,
        object: &str,
        operation: &str,
        generation: Generation,
    ) -> Self {
        let mut frame = Self::new(
            activation,
            store.id,
            hostcall_number,
            &code.package,
            object,
            operation,
            generation,
        );
        frame.store_generation = store.generation;
        frame.code_object = code.id;
        frame.code_generation = code.generation;
        frame.artifact = code.artifact_id;
        frame.artifact_generation = TARGET_ARTIFACT_GENERATION_V1;
        frame
    }

    pub fn with_args(mut self, args: [u64; 6]) -> Self {
        self.args = args;
        self
    }

    pub fn with_hostcall_seq(mut self, hostcall_seq: u64) -> Self {
        self.hostcall_seq = hostcall_seq;
        self
    }

    pub fn with_caller_offset(mut self, caller_offset: u64) -> Self {
        self.caller_offset = caller_offset;
        self
    }

    pub fn with_record_mode(mut self, record_mode: RecordMode) -> Self {
        self.record_mode = record_mode;
        self
    }

    pub fn with_cap_args(mut self, cap_args: Vec<CapabilityHandleArg>) -> Self {
        self.cap_args = cap_args;
        self
    }

    pub fn to_wire_frame(&self) -> ExecutorHostcallFrameV1 {
        let mut frame = ExecutorHostcallFrameV1 {
            flags: self.flags,
            record_mode: self.record_mode.as_u16(),
            ret_tag: self.ret_tag.as_u16(),
            activation: ActivationRefV1(WireObjectRef::new(
                self.activation,
                self.activation_generation,
            )),
            store: StoreRefV1(WireObjectRef::new(self.store, self.store_generation)),
            code_object: CodeObjectRefV1(WireObjectRef::new(
                self.code_object,
                self.code_generation,
            )),
            artifact: ArtifactRefV1(WireObjectRef::new(self.artifact, self.artifact_generation)),
            hostcall_number: self.hostcall_number,
            hostcall_seq: self.hostcall_seq,
            caller_offset: self.caller_offset,
            args: self.args,
            ret0: self.ret0,
            ret1: self.ret1,
            trap_out: self.trap_out.map_or(TrapRefV1(WireObjectRef::NULL), |trap| {
                TrapRefV1(WireObjectRef::new(trap, self.trap_generation_out.unwrap_or(1)))
            }),
            wait_token_out: self.wait_token_out.map_or(
                WaitTokenRefV1(WireObjectRef::NULL),
                |wait| {
                    WaitTokenRefV1(WireObjectRef::new(
                        wait,
                        self.wait_token_generation_out.unwrap_or(1),
                    ))
                },
            ),
            ..ExecutorHostcallFrameV1::default()
        };
        frame.cap_arg_count =
            self.cap_args.len().min(ExecutorHostcallFrameV1::CAP_ARG_CAPACITY) as u16;
        for (slot, arg) in
            self.cap_args.iter().take(ExecutorHostcallFrameV1::CAP_ARG_CAPACITY).enumerate()
        {
            frame.cap_args[slot] = ExecutorCapabilityHandleV1 {
                owner_store: StoreRefV1(WireObjectRef::new(
                    arg.owner_store.unwrap_or(0),
                    arg.owner_store_generation.unwrap_or(0),
                )),
                slot: arg.handle_slot,
                slot_generation: arg.handle_generation,
                tag: arg.handle_tag,
                rights_mask: arg.rights_mask,
                object_class: CapabilityClass::from_object(&arg.object).as_u16(),
                reserved: [0; 3],
            };
        }
        frame
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HostcallTraceRecord {
    pub id: HostcallTraceId,
    pub generation: Generation,
    pub abi_version: String,
    pub frame_size: u16,
    pub flags: u32,
    pub activation: ActivationId,
    pub activation_generation: Generation,
    pub store: StoreId,
    pub store_generation: Generation,
    pub code_object: CodeObjectId,
    pub code_generation: Generation,
    pub artifact: TargetArtifactId,
    pub artifact_generation: Generation,
    pub hostcall_number: u32,
    pub hostcall_seq: u64,
    pub caller_offset: u64,
    pub name: String,
    pub category: HostcallCategory,
    pub subject: String,
    pub subject_source: String,
    pub object: String,
    pub operation: String,
    pub args: [u64; 6],
    pub cap_args: Vec<CapabilityHandleArg>,
    pub record_mode: RecordMode,
    pub allowed: bool,
    pub gate_status: String,
    pub result: String,
    pub denial_reason: Option<String>,
    pub ret_tag: HostcallReturnTag,
    pub ret0: u64,
    pub ret1: u64,
    pub trap_out: Option<TargetTrapId>,
    pub trap_generation_out: Option<Generation>,
    pub wait_token_out: Option<WaitId>,
    pub wait_token_generation_out: Option<Generation>,
}

impl HostcallTraceRecord {
    pub const SUBJECT_SOURCE_ACTIVE_STATE: &'static str = "active-store-activation-code-object";

    pub fn gate_status_for(
        allowed: bool,
        ret_tag: HostcallReturnTag,
        trap_out: Option<TargetTrapId>,
    ) -> &'static str {
        if allowed {
            "exit"
        } else if ret_tag == HostcallReturnTag::Trap {
            "denied"
        } else if trap_out.is_some() {
            "trap"
        } else {
            "denied"
        }
    }

    pub fn summary(&self) -> String {
        format!(
            "hostcall id={} generation={} abi={} frame_size={} seq={} caller_offset={} record_mode={} activation={} activation_generation={} store={} store_generation={} code={} code_generation={} artifact={} artifact_generation={} number={} name={} category={} subject={} source={} object={} op={} gate={} allowed={} result={} ret={}",
            self.id,
            self.generation,
            self.abi_version,
            self.frame_size,
            self.hostcall_seq,
            self.caller_offset,
            self.record_mode.as_str(),
            self.activation,
            self.activation_generation,
            self.store,
            self.store_generation,
            self.code_object,
            self.code_generation,
            self.artifact,
            self.artifact_generation,
            self.hostcall_number,
            self.name,
            self.category.as_str(),
            self.subject,
            self.subject_source,
            self.object,
            self.operation,
            self.gate_status,
            self.allowed,
            self.result,
            self.ret_tag.as_str()
        )
    }
}
