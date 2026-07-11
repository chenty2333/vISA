use visa_profile::SubstrateProfile;

use crate::types::{Boundary, CapabilityDomain, ClaimKind, Personality, TestSpec};

pub fn full_catalog() -> Vec<TestSpec> {
    let mut specs = Vec::new();
    specs.extend(visa_core_catalog());
    specs.extend(substrate_profile_catalog());
    specs.extend(linux_ltp_catalog());
    specs.extend(wasi_personality_catalog());
    specs.extend(performance_catalog());
    specs
}

pub fn visa_core_catalog() -> Vec<TestSpec> {
    vec![
        spec(SpecDef {
            id: "visa.artifact.load",
            title: "artifact image load validates package identity, profile gate, code object publish, and manifest binding",
            claim: ClaimKind::VisaSemanticConformance,
            minimum_boundary: Boundary::PortableArtifactExecution,
            required_profile: Some(SubstrateProfile::MinimalBareMetal),
            personality: Some(Personality::VisaNative),
            domains: &[
                CapabilityDomain::Artifact,
                CapabilityDomain::Activation,
                CapabilityDomain::Hostcall,
            ],
            runner: "cargo test -p visa_runtime runtime_loads_artifact_publishes_code_and_starts_activation",
            proves: &[
                "TargetArtifactImage -> CodeObject -> Store -> Activation path is executable",
            ],
            does_not_prove: &["Linux syscall compatibility", "real target substrate execution"],
        }),
        spec(SpecDef {
            id: "visa.capability.hostcall",
            title: "hostcall execution consumes live capability records and records denied or unsupported paths",
            claim: ClaimKind::VisaSemanticConformance,
            minimum_boundary: Boundary::PortableArtifactExecution,
            required_profile: Some(SubstrateProfile::DeviceCapable),
            personality: Some(Personality::VisaNative),
            domains: &[
                CapabilityDomain::Capability,
                CapabilityDomain::Hostcall,
                CapabilityDomain::Mmio,
            ],
            runner: "cargo test -p contract_validate external_audit_rejects_portable_execution_with_unbacked_hostcall_capability",
            proves: &[
                "hostcall claims require live capability evidence when the operation is capability-gated",
            ],
            does_not_prove: &["hardware MMIO correctness outside the substrate trait boundary"],
        }),
        spec(SpecDef {
            id: "visa.wait.trap.cleanup",
            title: "wait, trap, and cleanup records preserve object identity, generation, tombstone, and edge-mode invariants",
            claim: ClaimKind::VisaSemanticConformance,
            minimum_boundary: Boundary::SemanticModel,
            required_profile: None,
            personality: Some(Personality::VisaNative),
            domains: &[CapabilityDomain::Wait, CapabilityDomain::Trap, CapabilityDomain::Cleanup],
            runner: "cargo test -p semantic_core contract_graph",
            proves: &[
                "semantic graph validator rejects dangling or generation-mismatched lifecycle edges",
            ],
            does_not_prove: &["runtime performance", "Linux personality behavior"],
        }),
        spec(SpecDef {
            id: "visa.snapshot.restore",
            title: "portable snapshot subset can be restored across profile changes without restoring host-specific state",
            claim: ClaimKind::VisaSemanticConformance,
            minimum_boundary: Boundary::PortableArtifactExecution,
            required_profile: Some(SubstrateProfile::SnapshotReplayCapable),
            personality: Some(Personality::VisaNative),
            domains: &[
                CapabilityDomain::Snapshot,
                CapabilityDomain::Artifact,
                CapabilityDomain::Capability,
            ],
            runner: "cargo test -p visa_runtime portable_state_survives_profile_change",
            proves: &["portable state survives profile-change restore with stable identity"],
            does_not_prove: &["product-grade live migration latency", "device binding continuity"],
        }),
        spec(SpecDef {
            id: "visa.native.full-hostcall-abi",
            title: "vISA-native Wasm artifact drives the full typed hostcall ABI without Linux or WASI personality semantics",
            claim: ClaimKind::VisaSemanticConformance,
            minimum_boundary: Boundary::PortableArtifactExecution,
            required_profile: Some(SubstrateProfile::SnapshotReplayCapable),
            personality: Some(Personality::VisaNative),
            domains: &[
                CapabilityDomain::Artifact,
                CapabilityDomain::Activation,
                CapabilityDomain::Hostcall,
                CapabilityDomain::Capability,
                CapabilityDomain::Memory,
                CapabilityDomain::Mmio,
                CapabilityDomain::Dma,
                CapabilityDomain::Irq,
                CapabilityDomain::Snapshot,
                CapabilityDomain::Timer,
            ],
            runner: "cargo test -p visa_wasmtime run_executes_native_visa_full_substrate_hostcall_abi",
            proves: &[
                "a non-Linux vISA-native artifact exercises typed console, timer, memory, DMW, MMIO, DMA, IRQ, and snapshot hostcalls through the Wasmtime adapter",
            ],
            does_not_prove: &["Linux personality compatibility", "real target substrate execution"],
        }),
    ]
}

pub fn substrate_profile_catalog() -> Vec<TestSpec> {
    vec![
        substrate_spec(
            "substrate.p0.semantic.harness",
            "Profile 0 semantic harness console, timer, event, and guest memory conformance",
            SubstrateProfile::SemanticHarness,
            &[
                CapabilityDomain::Timer,
                CapabilityDomain::Event,
                CapabilityDomain::Hostcall,
                CapabilityDomain::Memory,
            ],
            "cargo test -p substrate_api profile_conformance_suite_passes_snapshot_replay_backend",
        ),
        substrate_spec(
            "substrate.p1.console.timer.event",
            "Profile 1 console, timer, and event queue conformance",
            SubstrateProfile::MinimalBareMetal,
            &[CapabilityDomain::Timer, CapabilityDomain::Event, CapabilityDomain::Hostcall],
            "cargo test -p substrate_api profile_conformance_suite_passes_snapshot_replay_backend",
        ),
        substrate_spec(
            "substrate.p2.memory.dmw",
            "Profile 2 guest memory and DMW conformance",
            SubstrateProfile::GuestFrontend,
            &[CapabilityDomain::Memory, CapabilityDomain::Hostcall],
            "cargo test -p substrate_api guest_memory",
        ),
        substrate_spec(
            "substrate.p3.mmio.dma.irq",
            "Profile 3 MMIO, DMA, and IRQ conformance",
            SubstrateProfile::DeviceCapable,
            &[CapabilityDomain::Mmio, CapabilityDomain::Dma, CapabilityDomain::Irq],
            "cargo test -p substrate_api mmio_read_write_smoke",
        ),
        substrate_spec(
            "substrate.p4.snapshot.replay",
            "Profile 4 snapshot barrier and replay conformance",
            SubstrateProfile::SnapshotReplayCapable,
            &[CapabilityDomain::Snapshot],
            "cargo test -p substrate_api profile_conformance_suite_passes_snapshot_replay_backend",
        ),
        spec(SpecDef {
            id: "substrate.virtio.block.net.skeleton",
            title: "virtio block and network backend skeleton configuration evidence",
            claim: ClaimKind::SubstrateProfileConformance,
            minimum_boundary: Boundary::SemanticModel,
            required_profile: Some(SubstrateProfile::DeviceCapable),
            personality: None,
            domains: &[
                CapabilityDomain::Virtio,
                CapabilityDomain::Block,
                CapabilityDomain::Network,
            ],
            runner: "cargo test -p substrate_virtio",
            proves: &[
                "virtio skeleton backend evidence rejects malformed queue, IRQ, and feature negotiation state",
            ],
            does_not_prove: &["real device DMA correctness", "Linux driver compatibility"],
        }),
    ]
}

pub fn linux_ltp_catalog() -> Vec<TestSpec> {
    vec![
        ltp_spec(
            "linux-ltp.fs.basic",
            "LTP filesystem subset for open, read, write, stat, rename, unlink, and directory behavior",
            SubstrateProfile::GuestFrontend,
            &[CapabilityDomain::FileSystem, CapabilityDomain::Block],
            "ltp/runltp -f fs",
        ),
        ltp_spec(
            "linux-ltp.mm.mapping",
            "LTP memory-management subset for mmap, brk, mprotect, page fault, and VMA behavior",
            SubstrateProfile::GuestFrontend,
            &[CapabilityDomain::Memory],
            "ltp/runltp -f mm",
        ),
        ltp_spec(
            "linux-ltp.ipc.futex",
            "LTP IPC/futex subset for wait and wake semantics exposed through the Linux personality",
            SubstrateProfile::GuestFrontend,
            &[CapabilityDomain::Wait, CapabilityDomain::Event],
            "ltp/runltp -f ipc",
        ),
        ltp_spec(
            "linux-ltp.sched.timers",
            "LTP scheduler and timers subset for preemption, sleep, clock, and timer behavior",
            SubstrateProfile::MinimalBareMetal,
            &[CapabilityDomain::Scheduler, CapabilityDomain::Timer],
            "ltp/runltp -f sched,timers",
        ),
        ltp_spec(
            "linux-ltp.syscalls.core",
            "LTP core syscall subset for Linux personality ABI coverage",
            SubstrateProfile::GuestFrontend,
            &[CapabilityDomain::Activation, CapabilityDomain::Memory, CapabilityDomain::FileSystem],
            "ltp/runltp -f syscalls",
        ),
        ltp_spec(
            "linux-ltp.net.socket",
            "LTP network/socket subset for Linux personality socket behavior backed by vISA network records",
            SubstrateProfile::DeviceCapable,
            &[CapabilityDomain::Network],
            "ltp/runltp -f net.ipv4,net.tcp_cmds",
        ),
    ]
}

pub fn wasi_personality_catalog() -> Vec<TestSpec> {
    vec![spec(SpecDef {
        id: "wasi.console.timer",
        title: "minimal WASI personality console and timer behavior over vISA hostcalls",
        claim: ClaimKind::PersonalityCompatibility,
        minimum_boundary: Boundary::PortableArtifactExecution,
        required_profile: Some(SubstrateProfile::MinimalBareMetal),
        personality: Some(Personality::Wasi),
        domains: &[CapabilityDomain::Hostcall, CapabilityDomain::Timer],
        runner: "cargo test -p visa_runtime visa_native_personality_runs_without_linux_or_wasi_frontend",
        proves: &["non-Linux personality can use the vISA runtime path"],
        does_not_prove: &["Linux personality compatibility", "WASI filesystem or socket coverage"],
    })]
}

pub fn performance_catalog() -> Vec<TestSpec> {
    vec![
        perf_spec(
            "bench.hostcall.latency",
            "hostcall dispatch latency through visa_runtime and visa_wasmtime",
            Boundary::PortableArtifactExecution,
            &[CapabilityDomain::Hostcall],
            "cargo bench -p visa-bench",
        ),
        perf_spec(
            "bench.activation.start",
            "artifact load and activation start latency",
            Boundary::PortableArtifactExecution,
            &[CapabilityDomain::Artifact, CapabilityDomain::Activation],
            "cargo bench -p visa-bench",
        ),
        perf_spec(
            "bench.block.network",
            "block request and packet path throughput",
            Boundary::SemanticModel,
            &[CapabilityDomain::Block, CapabilityDomain::Network],
            "cargo bench -p visa-bench",
        ),
        perf_spec(
            "bench.snapshot.restore",
            "portable snapshot subset and restore cost",
            Boundary::PortableArtifactExecution,
            &[CapabilityDomain::Snapshot],
            "cargo bench -p visa-bench",
        ),
        perf_spec(
            "bench.scheduler.preemption",
            "scheduler preemption, decision, and activation resume mutation latency",
            Boundary::SemanticModel,
            &[CapabilityDomain::Scheduler, CapabilityDomain::Activation],
            "cargo bench -p visa-bench",
        ),
        perf_spec(
            "bench.simd.context",
            "SIMD vector state record mutation latency",
            Boundary::SemanticModel,
            &[CapabilityDomain::Simd],
            "cargo bench -p visa-bench",
        ),
        perf_spec(
            "bench.simd.speedup",
            "SIMD benchmark record mutation latency",
            Boundary::SemanticModel,
            &[CapabilityDomain::Simd],
            "cargo bench -p visa-bench",
        ),
        perf_spec(
            "bench.display.framebuffer",
            "framebuffer display record mutation latency",
            Boundary::SemanticModel,
            &[CapabilityDomain::Display],
            "cargo bench -p visa-bench",
        ),
    ]
}

fn substrate_spec(
    id: &str,
    title: &str,
    profile: SubstrateProfile,
    domains: &[CapabilityDomain],
    runner: &str,
) -> TestSpec {
    spec(SpecDef {
        id,
        title,
        claim: ClaimKind::SubstrateProfileConformance,
        minimum_boundary: Boundary::SemanticModel,
        required_profile: Some(profile),
        personality: None,
        domains,
        runner,
        proves: &["reported substrate authority behavior matches the selected profile contract"],
        does_not_prove: &[
            "Linux personality compatibility",
            "performance",
            "real target execution unless run with real target extraction evidence",
        ],
    })
}

fn ltp_spec(
    id: &str,
    title: &str,
    profile: SubstrateProfile,
    domains: &[CapabilityDomain],
    runner: &str,
) -> TestSpec {
    spec(SpecDef {
        id,
        title,
        claim: ClaimKind::PersonalityCompatibility,
        minimum_boundary: Boundary::PortableArtifactExecution,
        required_profile: Some(profile),
        personality: Some(Personality::Linux),
        domains,
        runner,
        proves: &["Linux personality compatibility for the named LTP subset"],
        does_not_prove: &[
            "vISA semantic completeness",
            "substrate profile conformance",
            "real target substrate execution unless the report boundary is real-target-substrate",
        ],
    })
}

fn perf_spec(
    id: &str,
    title: &str,
    minimum_boundary: Boundary,
    domains: &[CapabilityDomain],
    runner: &str,
) -> TestSpec {
    spec(SpecDef {
        id,
        title,
        claim: ClaimKind::PerformanceBenchmark,
        minimum_boundary,
        required_profile: None,
        personality: None,
        domains,
        runner,
        proves: &[
            "performance measurement for the named path under the observed evidence boundary",
        ],
        does_not_prove: &[
            "conformance",
            "correctness beyond the separately reported pass/fail suite",
        ],
    })
}

struct SpecDef<'a> {
    id: &'a str,
    title: &'a str,
    claim: ClaimKind,
    minimum_boundary: Boundary,
    required_profile: Option<SubstrateProfile>,
    personality: Option<Personality>,
    domains: &'a [CapabilityDomain],
    runner: &'a str,
    proves: &'a [&'a str],
    does_not_prove: &'a [&'a str],
}

fn spec(def: SpecDef<'_>) -> TestSpec {
    TestSpec {
        id: def.id.to_string(),
        title: def.title.to_string(),
        claim: def.claim,
        minimum_boundary: def.minimum_boundary,
        required_profile: def.required_profile.map(|profile| profile.as_str().to_string()),
        personality: def.personality,
        domains: def.domains.to_vec(),
        runner: def.runner.to_string(),
        proves: def.proves.iter().map(|item| item.to_string()).collect(),
        does_not_prove: def.does_not_prove.iter().map(|item| item.to_string()).collect(),
    }
}
