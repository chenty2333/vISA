#![no_std]

pub struct WasmModuleSpec {
    pub package: &'static str,
    pub artifact_name: &'static str,
    pub role: StoreRole,
    pub fault_policy: FaultPolicy,
    pub capabilities: &'static [CapabilitySpec],
    pub expected_exports: &'static [&'static str],
}

pub struct UserBinarySpec {
    pub package: &'static str,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StoreRole {
    Personality,
    CoreService,
    Driver,
    FrontendGuest,
}

impl StoreRole {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Personality => "personality",
            Self::CoreService => "service",
            Self::Driver => "driver",
            Self::FrontendGuest => "frontend_guest",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FaultPolicy {
    Restartable,
    KillOnTrap,
}

impl FaultPolicy {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Restartable => "restartable",
            Self::KillOnTrap => "kill-on-trap",
        }
    }
}

pub struct CapabilitySpec {
    pub name: &'static str,
    pub rights: &'static [&'static str],
    pub lifetime: &'static str,
}

const NO_CAPABILITIES: &[CapabilitySpec] = &[];
const CONSOLE_CAPABILITIES: &[CapabilitySpec] = &[CapabilitySpec {
    name: "console.write",
    rights: &["write"],
    lifetime: "activation",
}];
const TIMER_CAPABILITIES: &[CapabilitySpec] = &[CapabilitySpec {
    name: "timer.sleep",
    rights: &["arm", "cancel"],
    lifetime: "wait-token",
}];
const DEVFS_CAPABILITIES: &[CapabilitySpec] = &[CapabilitySpec {
    name: "device.pulse",
    rights: &["read", "poll"],
    lifetime: "store",
}];

pub const SUPERVISOR_WASM_MODULES: &[WasmModuleSpec] = &[
    WasmModuleSpec {
        package: "console_service",
        artifact_name: "driver_console",
        role: StoreRole::Driver,
        fault_policy: FaultPolicy::Restartable,
        capabilities: CONSOLE_CAPABILITIES,
        expected_exports: &["memory", "buffer_ptr", "buffer_capacity", "commit_write"],
    },
    WasmModuleSpec {
        package: "devfs_service",
        artifact_name: "devfs",
        role: StoreRole::CoreService,
        fault_policy: FaultPolicy::Restartable,
        capabilities: DEVFS_CAPABILITIES,
        expected_exports: &[
            "memory",
            "request_ptr",
            "request_capacity",
            "response_ptr",
            "response_capacity",
            "node_kind",
            "lookup",
            "list_dir",
            "read_device",
            "write_device",
        ],
    },
    WasmModuleSpec {
        package: "epoll_service",
        artifact_name: "epoll",
        role: StoreRole::CoreService,
        fault_policy: FaultPolicy::Restartable,
        capabilities: NO_CAPABILITIES,
        expected_exports: &[
            "memory",
            "request_ptr",
            "request_capacity",
            "response_ptr",
            "response_capacity",
            "create",
            "ctl",
            "collect_ready",
            "arm_wait",
            "notify_ready",
            "restart_key",
            "cancel_wait",
        ],
    },
    WasmModuleSpec {
        package: "futex_service",
        artifact_name: "futex",
        role: StoreRole::CoreService,
        fault_policy: FaultPolicy::Restartable,
        capabilities: NO_CAPABILITIES,
        expected_exports: &[
            "memory",
            "request_ptr",
            "request_capacity",
            "response_ptr",
            "response_capacity",
            "register_wait",
            "wake",
            "cancel_wait",
        ],
    },
    WasmModuleSpec {
        package: "linux_syscall",
        artifact_name: "linux_personality",
        role: StoreRole::Personality,
        fault_policy: FaultPolicy::KillOnTrap,
        capabilities: TIMER_CAPABILITIES,
        expected_exports: &[
            "memory",
            "dispatch",
            "resume_wait",
            "cancel_wait",
            "restart_wait",
            "arg_buffer_ptr",
            "arg_buffer_capacity",
            "result_buffer_ptr",
            "result_buffer_capacity",
            "plan_arg",
            "dispatch_sleep_ms",
            "dispatch_futex_raw",
            "encode_uname",
            "encode_dirents64",
            "encode_epoll_events",
        ],
    },
    WasmModuleSpec {
        package: "procfs_service",
        artifact_name: "procfs",
        role: StoreRole::CoreService,
        fault_policy: FaultPolicy::Restartable,
        capabilities: NO_CAPABILITIES,
        expected_exports: &[
            "memory",
            "request_ptr",
            "request_capacity",
            "response_ptr",
            "response_capacity",
            "node_kind",
            "lookup",
            "read_file",
            "list_dir",
            "read_link",
        ],
    },
    WasmModuleSpec {
        package: "vfs_service",
        artifact_name: "vfs",
        role: StoreRole::CoreService,
        fault_policy: FaultPolicy::Restartable,
        capabilities: NO_CAPABILITIES,
        expected_exports: &[
            "memory",
            "request_ptr",
            "request_capacity",
            "response_ptr",
            "response_capacity",
            "route_kind",
            "node_kind",
            "lookup",
            "read_file",
            "list_dir",
            "read_link",
        ],
    },
    WasmModuleSpec {
        package: "wasm_app",
        artifact_name: "wasm_app_frontend",
        role: StoreRole::FrontendGuest,
        fault_policy: FaultPolicy::KillOnTrap,
        capabilities: CONSOLE_CAPABILITIES,
        expected_exports: &["memory", "run"],
    },
];

pub const USER_BINARIES: &[UserBinarySpec] = &[UserBinarySpec {
    package: "linux_user_demo",
}];

pub fn find_wasm_module(package: &str) -> Option<&'static WasmModuleSpec> {
    SUPERVISOR_WASM_MODULES
        .iter()
        .find(|module| module.package == package)
}
