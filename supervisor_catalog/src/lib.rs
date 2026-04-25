#![no_std]

pub const SUPERVISOR_CONTRACT_VERSION: &str = "vmos-supervisor-contract-v2";
pub const SUPERVISOR_WORLD: &str = "wasm-supervisor-world-v1";
pub const MACHINE_ABI_VERSION: &str = "vmos-machine-abi-v0";
pub const SUPERVISOR_ABI_VERSION: &str = "vmos-supervisor-abi-v0";
pub const WASM_FEATURE_PROFILE: &str = "wasm32-core-mvp-single-memory";
pub const DMW_LAYOUT: &str = "logical-activation-leases-v0";
pub const LINUX_ABI_PROFILE: &str = "linux-x86_64-demo-socket-v0";
pub const ARTIFACT_SIGNATURE_PROFILE: &str = "prototype-self-signed-sha256";
pub const SUPERVISOR_COMPILER_ENGINE: &str = "wasmtime";
pub const SUPERVISOR_EXECUTION_MODE: &str = "precompiled-core-module";
pub const SUPERVISOR_ARTIFACT_FORMAT: &str = "cwasm";
pub const RUNTIME_ONLY_EXECUTOR_ABI: &str = "vmos-runtime-only-executor-v0";
pub const SEMANTIC_CONTRACT_SCHEMA_VERSION: &str = "semantic-contract-v0.1";
pub const COMPONENT_MODEL_VERSION: &str = "wasm-core-module-v0";
pub const WASI_PROFILE_NONE: &str = "none";
pub const HOSTCALL_ABI_VERSION: &str = "vmos-target-hostcall-frame-v1";
pub const CAPABILITY_ABI_VERSION: &str = "vmos-capability-handle-v1";
pub const WIT_PACKAGE_VERSION: &str = "semantic:vmos@0.1";

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

pub struct StoreBlueprint {
    pub package: &'static str,
    pub role: StoreRole,
    pub fault_policy: FaultPolicy,
    pub capabilities: &'static [CapabilitySpec],
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

#[derive(Clone, Copy)]
pub struct ModuleInterfaceSpec {
    pub required_wasi_worlds: &'static [&'static str],
    pub optional_wasi_worlds: &'static [&'static str],
    pub custom_wit_worlds: &'static [&'static str],
    pub wit_package_versions: &'static [&'static str],
    pub component_model_version: &'static str,
    pub wasi_profile: &'static str,
    pub hostcall_abi_version: &'static str,
    pub capability_abi_version: &'static str,
    pub semantic_contract_version: &'static str,
    pub substrate_profile_required: &'static str,
    pub substrate_required: &'static [&'static str],
    pub substrate_optional: &'static [&'static str],
    pub substrate_forbidden: &'static [&'static str],
}

const NO_INTERFACES: &[&str] = &[];
const VMOS_WIT_PACKAGE: &[&str] = &[WIT_PACKAGE_VERSION];
const SUPERVISOR_WIT: &[&str] = &["semantic:supervisor"];
const DRIVER_WIT: &[&str] = &["semantic:driverkit", "semantic:machine"];
const MACHINE_WIT: &[&str] = &["semantic:machine"];
const SNAPSHOT_WIT: &[&str] = &["semantic:snapshot", "semantic:debug"];
const DEBUG_WIT: &[&str] = &["semantic:debug"];

const SEMANTIC_HARNESS_AUTHORITIES: &[&str] = &["console", "timer", "event-queue", "guest-memory"];
const GUEST_FRONTEND_AUTHORITIES: &[&str] = &[
    "console",
    "timer",
    "event-queue",
    "guest-memory",
    "artifact-loading",
    "dmw:logical-or-better",
    "code-publish:metadata-only",
];
const DEVICE_AUTHORITIES: &[&str] = &[
    "console",
    "timer",
    "event-queue",
    "guest-memory",
    "artifact-loading",
    "dmw:logical-or-better",
    "mmio",
    "irq",
    "dma:mediated-or-better",
    "code-publish:metadata-only",
];
const SNAPSHOT_AUTHORITIES: &[&str] = &[
    "console",
    "timer",
    "event-queue",
    "guest-memory",
    "artifact-loading",
    "dmw:logical-or-better",
    "snapshot:deterministic-replay",
    "code-publish:metadata-only",
];
const DIRECT_DEVICE_FORBIDDEN: &[&str] = &["direct-dma", "raw-mmio", "raw-irq"];

const fn interface_spec(
    custom_wit_worlds: &'static [&'static str],
    substrate_profile_required: &'static str,
    substrate_required: &'static [&'static str],
    substrate_optional: &'static [&'static str],
    substrate_forbidden: &'static [&'static str],
) -> ModuleInterfaceSpec {
    ModuleInterfaceSpec {
        required_wasi_worlds: NO_INTERFACES,
        optional_wasi_worlds: NO_INTERFACES,
        custom_wit_worlds,
        wit_package_versions: VMOS_WIT_PACKAGE,
        component_model_version: COMPONENT_MODEL_VERSION,
        wasi_profile: WASI_PROFILE_NONE,
        hostcall_abi_version: HOSTCALL_ABI_VERSION,
        capability_abi_version: CAPABILITY_ABI_VERSION,
        semantic_contract_version: SEMANTIC_CONTRACT_SCHEMA_VERSION,
        substrate_profile_required,
        substrate_required,
        substrate_optional,
        substrate_forbidden,
    }
}

pub fn module_interface_spec(module: &WasmModuleSpec) -> ModuleInterfaceSpec {
    match module.package {
        "driver_virtio_net" => interface_spec(
            DRIVER_WIT,
            "device-capable",
            DEVICE_AUTHORITIES,
            NO_INTERFACES,
            NO_INTERFACES,
        ),
        "linux_syscall" => interface_spec(
            MACHINE_WIT,
            "guest-frontend",
            GUEST_FRONTEND_AUTHORITIES,
            NO_INTERFACES,
            DIRECT_DEVICE_FORBIDDEN,
        ),
        "replay_snapshot" => interface_spec(
            SNAPSHOT_WIT,
            "snapshot-replay-capable",
            SNAPSHOT_AUTHORITIES,
            NO_INTERFACES,
            DIRECT_DEVICE_FORBIDDEN,
        ),
        "wasm_app" => interface_spec(
            DEBUG_WIT,
            "semantic-harness",
            SEMANTIC_HARNESS_AUTHORITIES,
            NO_INTERFACES,
            DIRECT_DEVICE_FORBIDDEN,
        ),
        _ => interface_spec(
            SUPERVISOR_WIT,
            "semantic-harness",
            SEMANTIC_HARNESS_AUTHORITIES,
            NO_INTERFACES,
            DIRECT_DEVICE_FORBIDDEN,
        ),
    }
}

const CONSOLE_CAPABILITIES: &[CapabilitySpec] = &[CapabilitySpec {
    name: "console.write",
    rights: &["write"],
    lifetime: "activation",
}];
const LINUX_CAPABILITIES: &[CapabilitySpec] = &[
    CapabilitySpec {
        name: "timer.sleep",
        rights: &["arm", "cancel"],
        lifetime: "wait-token",
    },
    CapabilitySpec {
        name: "console.write",
        rights: &["write"],
        lifetime: "activation",
    },
    CapabilitySpec {
        name: "fd.table",
        rights: &["close"],
        lifetime: "task",
    },
    CapabilitySpec {
        name: "linux.socket",
        rights: &[
            "socket",
            "bind",
            "connect",
            "listen",
            "accept",
            "send",
            "recv",
            "poll",
            "close",
            "setsockopt",
            "getsockopt",
            "fcntl",
        ],
        lifetime: "task",
    },
];
const DEVFS_CAPABILITIES: &[CapabilitySpec] = &[CapabilitySpec {
    name: "device.pulse",
    rights: &["read", "poll"],
    lifetime: "store",
}];
const EPOLL_CAPABILITIES: &[CapabilitySpec] = &[CapabilitySpec {
    name: "epoll.instance",
    rights: &["create", "ctl", "wait", "notify", "restart", "cancel"],
    lifetime: "store",
}];
const FUTEX_CAPABILITIES: &[CapabilitySpec] = &[CapabilitySpec {
    name: "futex.waitset",
    rights: &["wait", "wake", "cancel"],
    lifetime: "store",
}];
const PROCFS_CAPABILITIES: &[CapabilitySpec] = &[CapabilitySpec {
    name: "procfs.tree",
    rights: &["lookup", "read", "list", "readlink"],
    lifetime: "store",
}];
const VFS_CAPABILITIES: &[CapabilitySpec] = &[CapabilitySpec {
    name: "vfs.namespace",
    rights: &["lookup", "read", "list", "readlink"],
    lifetime: "store",
}];
const DRIVER_VIRTIO_NET_CAPABILITIES: &[CapabilitySpec] = &[
    CapabilitySpec {
        name: "packet-device.net0",
        rights: &["rx", "tx", "poll", "irq", "dma"],
        lifetime: "store",
    },
    CapabilitySpec {
        name: "dma.pool.net0",
        rights: &["submit", "complete", "cancel"],
        lifetime: "store",
    },
    CapabilitySpec {
        name: "irq.net0",
        rights: &["ack", "mask", "unmask"],
        lifetime: "store",
    },
    CapabilitySpec {
        name: "mmio.virtio-net0",
        rights: &["read", "write"],
        lifetime: "store",
    },
    CapabilitySpec {
        name: "virtqueue.net0",
        rights: &["read", "write", "kick"],
        lifetime: "store",
    },
];
const NET_CORE_CAPABILITIES: &[CapabilitySpec] = &[
    CapabilitySpec {
        name: "packet-device.net0",
        rights: &["rx", "tx", "poll"],
        lifetime: "store",
    },
    CapabilitySpec {
        name: "net.interface",
        rights: &["attach", "up", "down", "rx", "tx"],
        lifetime: "store",
    },
    CapabilitySpec {
        name: "net.socket",
        rights: &[
            "create",
            "bind",
            "connect",
            "listen",
            "accept",
            "send",
            "recv",
            "poll",
            "close",
            "setsockopt",
            "getsockopt",
        ],
        lifetime: "task",
    },
];
const LINUX_SOCKET_CAPABILITIES: &[CapabilitySpec] = &[
    CapabilitySpec {
        name: "linux.socket",
        rights: &[
            "socket",
            "bind",
            "connect",
            "listen",
            "accept",
            "send",
            "recv",
            "poll",
            "close",
            "setsockopt",
            "getsockopt",
            "fcntl",
        ],
        lifetime: "task",
    },
    CapabilitySpec {
        name: "net.socket",
        rights: &["create", "send", "recv", "poll", "close"],
        lifetime: "task",
    },
];
const REPLAY_SNAPSHOT_CAPABILITIES: &[CapabilitySpec] = &[CapabilitySpec {
    name: "snapshot.barrier",
    rights: &["enter", "validate", "replay"],
    lifetime: "activation",
}];

pub const NETWORK_STORE_BLUEPRINTS: &[StoreBlueprint] = &[
    StoreBlueprint {
        package: "driver_virtio_net",
        role: StoreRole::Driver,
        fault_policy: FaultPolicy::Restartable,
        capabilities: DRIVER_VIRTIO_NET_CAPABILITIES,
    },
    StoreBlueprint {
        package: "net_core",
        role: StoreRole::CoreService,
        fault_policy: FaultPolicy::Restartable,
        capabilities: NET_CORE_CAPABILITIES,
    },
    StoreBlueprint {
        package: "linux_socket_service",
        role: StoreRole::CoreService,
        fault_policy: FaultPolicy::Restartable,
        capabilities: LINUX_SOCKET_CAPABILITIES,
    },
];

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
        capabilities: EPOLL_CAPABILITIES,
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
        capabilities: FUTEX_CAPABILITIES,
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
        package: "driver_virtio_net",
        artifact_name: "driver_virtio_net",
        role: StoreRole::Driver,
        fault_policy: FaultPolicy::Restartable,
        capabilities: DRIVER_VIRTIO_NET_CAPABILITIES,
        expected_exports: &[
            "memory",
            "request_ptr",
            "request_capacity",
            "response_ptr",
            "response_capacity",
            "network_contract_version",
            "packet_mtu",
            "packet_rx_queue_depth",
            "packet_tx_queue_depth",
            "reset_sequence",
            "submit_tx_frame",
            "poll_device",
            "event_len",
            "dequeue_rx_frame",
            "pending_rx_frames",
        ],
    },
    WasmModuleSpec {
        package: "net_core",
        artifact_name: "net_core",
        role: StoreRole::CoreService,
        fault_policy: FaultPolicy::Restartable,
        capabilities: NET_CORE_CAPABILITIES,
        expected_exports: &[
            "memory",
            "request_ptr",
            "request_capacity",
            "response_ptr",
            "response_capacity",
            "network_contract_version",
            "packet_mtu",
            "packet_rx_queue_depth",
            "packet_tx_queue_depth",
            "create_socket",
            "close_socket",
            "ready_key",
            "poll_socket",
            "send_socket",
            "take_tx_frame",
            "recv_socket",
            "deliver_packet_frame",
            "socket_count",
            "queued_rx_bytes",
        ],
    },
    WasmModuleSpec {
        package: "linux_socket_service",
        artifact_name: "linux_socket",
        role: StoreRole::CoreService,
        fault_policy: FaultPolicy::Restartable,
        capabilities: LINUX_SOCKET_CAPABILITIES,
        expected_exports: &[
            "memory",
            "request_ptr",
            "request_capacity",
            "response_ptr",
            "response_capacity",
            "network_contract_version",
            "register_socket",
            "close_socket",
            "bind_socket",
            "connect_socket",
            "listen_socket",
            "accept_socket",
            "send_socket",
            "recv_socket",
            "setsockopt",
            "getsockopt",
            "fcntl",
            "socket_count",
        ],
    },
    WasmModuleSpec {
        package: "linux_syscall",
        artifact_name: "linux_personality",
        role: StoreRole::Personality,
        fault_policy: FaultPolicy::KillOnTrap,
        capabilities: LINUX_CAPABILITIES,
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
        capabilities: PROCFS_CAPABILITIES,
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
        capabilities: VFS_CAPABILITIES,
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
        package: "replay_snapshot",
        artifact_name: "replay_snapshot",
        role: StoreRole::CoreService,
        fault_policy: FaultPolicy::Restartable,
        capabilities: REPLAY_SNAPSHOT_CAPABILITIES,
        expected_exports: &[
            "memory",
            "request_ptr",
            "request_capacity",
            "response_ptr",
            "response_capacity",
            "validate_barrier",
            "replay_until",
            "last_replay_cursor",
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

pub fn module_dependencies(spec: &WasmModuleSpec) -> &'static [&'static str] {
    match spec.package {
        "net_core" => &["driver_virtio_net"],
        "linux_socket_service" => &["net_core"],
        "linux_syscall" => &[
            "vfs_service",
            "procfs_service",
            "devfs_service",
            "epoll_service",
            "futex_service",
            "linux_socket_service",
        ],
        "wasm_app" => &["console_service"],
        _ => &[],
    }
}

pub fn catalog_contract_fingerprint() -> u64 {
    let mut hash = ContractHasher::new();
    hash.write_str(SUPERVISOR_CONTRACT_VERSION);
    hash.write_str(SUPERVISOR_WORLD);
    hash.write_str(MACHINE_ABI_VERSION);
    hash.write_str(SUPERVISOR_ABI_VERSION);
    hash.write_str(WASM_FEATURE_PROFILE);
    hash.write_str(DMW_LAYOUT);
    hash.write_str(LINUX_ABI_PROFILE);
    hash.write_str(ARTIFACT_SIGNATURE_PROFILE);
    hash.write_str(SUPERVISOR_COMPILER_ENGINE);
    hash.write_str(SUPERVISOR_EXECUTION_MODE);
    hash.write_str(SUPERVISOR_ARTIFACT_FORMAT);
    hash.write_str(RUNTIME_ONLY_EXECUTOR_ABI);
    for module in SUPERVISOR_WASM_MODULES {
        hash_module_contract(&mut hash, module);
    }
    hash.finish()
}

pub fn package_set_fingerprint() -> u64 {
    let mut hash = ContractHasher::new();
    hash.write_str(SUPERVISOR_CONTRACT_VERSION);
    for module in SUPERVISOR_WASM_MODULES {
        hash.write_str(module.package);
    }
    hash.finish()
}

pub fn module_contract_fingerprint(spec: &WasmModuleSpec) -> u64 {
    let mut hash = ContractHasher::new();
    hash_module_contract(&mut hash, spec);
    hash.finish()
}

fn hash_module_contract(hash: &mut ContractHasher, module: &WasmModuleSpec) {
    hash.write_str(module.package);
    hash.write_str(module.artifact_name);
    hash.write_str(module.role.as_str());
    hash.write_str(module.fault_policy.as_str());
    for export in module.expected_exports {
        hash.write_str("export");
        hash.write_str(export);
    }
    for dependency in module_dependencies(module) {
        hash.write_str("dependency");
        hash.write_str(dependency);
    }
    for capability in module.capabilities {
        hash.write_str("capability");
        hash.write_str(capability.name);
        hash.write_str(capability.lifetime);
        for right in capability.rights {
            hash.write_str("right");
            hash.write_str(right);
        }
    }
    let interfaces = module_interface_spec(module);
    hash.write_str("component-model");
    hash.write_str(interfaces.component_model_version);
    hash.write_str("wasi-profile");
    hash.write_str(interfaces.wasi_profile);
    hash.write_str("hostcall-abi");
    hash.write_str(interfaces.hostcall_abi_version);
    hash.write_str("capability-abi");
    hash.write_str(interfaces.capability_abi_version);
    hash.write_str("semantic-contract");
    hash.write_str(interfaces.semantic_contract_version);
    hash.write_str("substrate-profile");
    hash.write_str(interfaces.substrate_profile_required);
    for entry in interfaces.required_wasi_worlds {
        hash.write_str("required-wasi");
        hash.write_str(entry);
    }
    for entry in interfaces.optional_wasi_worlds {
        hash.write_str("optional-wasi");
        hash.write_str(entry);
    }
    for entry in interfaces.custom_wit_worlds {
        hash.write_str("custom-wit");
        hash.write_str(entry);
    }
    for entry in interfaces.wit_package_versions {
        hash.write_str("wit-package");
        hash.write_str(entry);
    }
    for entry in interfaces.substrate_required {
        hash.write_str("substrate-required");
        hash.write_str(entry);
    }
    for entry in interfaces.substrate_optional {
        hash.write_str("substrate-optional");
        hash.write_str(entry);
    }
    for entry in interfaces.substrate_forbidden {
        hash.write_str("substrate-forbidden");
        hash.write_str(entry);
    }
}

struct ContractHasher {
    value: u64,
}

impl ContractHasher {
    const fn new() -> Self {
        Self {
            value: 0xcbf29ce484222325,
        }
    }

    fn write_str(&mut self, value: &str) {
        for byte in value.as_bytes() {
            self.value ^= *byte as u64;
            self.value = self.value.wrapping_mul(0x100000001b3);
        }
        self.write_separator();
    }

    fn write_separator(&mut self) {
        self.value ^= 0xff;
        self.value = self.value.wrapping_mul(0x100000001b3);
    }

    const fn finish(self) -> u64 {
        self.value
    }
}
