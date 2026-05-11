use std::collections::{BTreeMap, BTreeSet};

use contract_core::EvidenceBoundaryLevel;
use serde::{Deserialize, Serialize};
use visa_profile::SubstrateProfile;

pub const REPORT_SCHEMA_VERSION: &str = "vmos-conformance-report-v0.1";

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ClaimKind {
    VisaSemanticConformance,
    SubstrateProfileConformance,
    PersonalityCompatibility,
    PerformanceBenchmark,
}

impl ClaimKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::VisaSemanticConformance => "visa-semantic-conformance",
            Self::SubstrateProfileConformance => "substrate-profile-conformance",
            Self::PersonalityCompatibility => "personality-compatibility",
            Self::PerformanceBenchmark => "performance-benchmark",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Boundary {
    SemanticModel,
    ReferenceService,
    ReferenceAotHarness,
    PortableArtifactExecution,
    RealTargetSubstrate,
}

impl Boundary {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::SemanticModel => "semantic-model",
            Self::ReferenceService => "reference-service",
            Self::ReferenceAotHarness => "reference-aot-harness",
            Self::PortableArtifactExecution => "portable-artifact-execution",
            Self::RealTargetSubstrate => "real-target-substrate",
        }
    }

    pub const fn level(self) -> EvidenceBoundaryLevel {
        match self {
            Self::SemanticModel => EvidenceBoundaryLevel::SemanticModel,
            Self::ReferenceService => EvidenceBoundaryLevel::ReferenceService,
            Self::ReferenceAotHarness => EvidenceBoundaryLevel::ReferenceAotHarness,
            Self::PortableArtifactExecution => EvidenceBoundaryLevel::PortableArtifactExecution,
            Self::RealTargetSubstrate => EvidenceBoundaryLevel::RealTargetSubstrate,
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "semantic-model" => Some(Self::SemanticModel),
            "reference-service" => Some(Self::ReferenceService),
            "reference-aot-harness" => Some(Self::ReferenceAotHarness),
            "portable-artifact-execution" => Some(Self::PortableArtifactExecution),
            "real-target-substrate" => Some(Self::RealTargetSubstrate),
            _ => None,
        }
    }

    pub fn can_claim(self, claimed: Self) -> bool {
        self.level().can_claim(claimed.level())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Personality {
    VisaNative,
    Linux,
    Wasi,
    Debugger,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CapabilityDomain {
    Artifact,
    Activation,
    Capability,
    Wait,
    Trap,
    Cleanup,
    Snapshot,
    FileSystem,
    Memory,
    Mmio,
    Dma,
    Irq,
    Block,
    Network,
    Scheduler,
    Timer,
    Event,
    Virtio,
    Hostcall,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Outcome {
    Pass,
    Fail,
    Skip,
    NotRun,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TestSpec {
    pub id: String,
    pub title: String,
    pub claim: ClaimKind,
    pub minimum_boundary: Boundary,
    pub required_profile: Option<String>,
    pub personality: Option<Personality>,
    pub domains: Vec<CapabilityDomain>,
    pub runner: String,
    pub proves: Vec<String>,
    pub does_not_prove: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct TestResult {
    pub spec_id: String,
    pub outcome: Outcome,
    pub observed_boundary: Boundary,
    pub observed_profile: Option<String>,
    pub evidence: String,
    pub remaining_uncertainty: String,
    #[serde(default)]
    pub metrics: BTreeMap<String, f64>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ConformanceReport {
    pub schema_version: String,
    pub suite_id: String,
    pub target: String,
    pub generated_by: String,
    pub results: Vec<TestResult>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValidationFinding {
    pub code: String,
    pub detail: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValidationReport {
    pub ok: bool,
    pub findings: Vec<ValidationFinding>,
}

impl ValidationReport {
    fn new(findings: Vec<ValidationFinding>) -> Self {
        Self { ok: findings.is_empty(), findings }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReportLoadError {
    pub code: String,
    pub detail: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReportGateResult {
    pub ok: bool,
    pub load_error: Option<ReportLoadError>,
    pub validation: Option<ValidationReport>,
    pub outcome_findings: Vec<ValidationFinding>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum LtpSubset {
    FsBasic,
    MmMapping,
    IpcFutex,
    SchedTimers,
    SyscallsCore,
    NetSocket,
}

impl LtpSubset {
    pub const ALL: [Self; 6] = [
        Self::FsBasic,
        Self::MmMapping,
        Self::IpcFutex,
        Self::SchedTimers,
        Self::SyscallsCore,
        Self::NetSocket,
    ];

    pub const fn spec_id(self) -> &'static str {
        match self {
            Self::FsBasic => "linux-ltp.fs.basic",
            Self::MmMapping => "linux-ltp.mm.mapping",
            Self::IpcFutex => "linux-ltp.ipc.futex",
            Self::SchedTimers => "linux-ltp.sched.timers",
            Self::SyscallsCore => "linux-ltp.syscalls.core",
            Self::NetSocket => "linux-ltp.net.socket",
        }
    }

    pub const fn scenario_arg(self) -> &'static str {
        match self {
            Self::FsBasic => "fs",
            Self::MmMapping => "mm",
            Self::IpcFutex => "ipc",
            Self::SchedTimers => "sched,timers",
            Self::SyscallsCore => "syscalls",
            Self::NetSocket => "net.ipv4,net.tcp_cmds",
        }
    }

    pub fn from_spec_id(spec_id: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|subset| subset.spec_id() == spec_id)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LtpInvocation {
    pub runltp: String,
    pub output_dir: String,
    pub subsets: Vec<LtpSubset>,
}

impl LtpInvocation {
    pub fn default_plan(output_dir: impl Into<String>) -> Self {
        Self {
            runltp: "runltp".to_string(),
            output_dir: output_dir.into(),
            subsets: LtpSubset::ALL.to_vec(),
        }
    }

    pub fn command_for(&self, subset: LtpSubset) -> Vec<String> {
        let output_dir = self.output_dir.trim_end_matches('/');
        vec![
            self.runltp.clone(),
            "-f".to_string(),
            subset.scenario_arg().to_string(),
            "-o".to_string(),
            format!("{output_dir}/{}.log", subset.spec_id()),
        ]
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LtpCaseResult {
    pub case_id: String,
    pub outcome: Outcome,
    pub raw_status: String,
    pub detail: String,
}

pub fn parse_ltp_results(text: &str) -> Vec<LtpCaseResult> {
    text.lines().filter_map(parse_ltp_result_line).collect()
}

pub fn parse_ltp_result_line(line: &str) -> Option<LtpCaseResult> {
    let trimmed = line.trim();
    if trimmed.is_empty() {
        return None;
    }
    let mut case_id = trimmed.split_whitespace().next()?.trim_end_matches(':').to_string();
    let (raw_status, outcome) = trimmed.split_whitespace().find_map(|token| {
        normalize_ltp_status(token).map(|outcome| (token.to_string(), outcome))
    })?;
    if matches!(case_id.as_str(), "PASS" | "FAIL" | "TPASS" | "TFAIL" | "SKIP" | "CONF") {
        case_id = "unknown".to_string();
    }
    Some(LtpCaseResult { case_id, outcome, raw_status, detail: trimmed.to_string() })
}

pub fn ltp_subset_result(
    spec: &TestSpec,
    cases: &[LtpCaseResult],
    observed_boundary: Boundary,
    observed_profile: Option<String>,
) -> TestResult {
    let passed = cases.iter().filter(|case| case.outcome == Outcome::Pass).count();
    let failed = cases.iter().filter(|case| case.outcome == Outcome::Fail).count();
    let skipped = cases.iter().filter(|case| case.outcome == Outcome::Skip).count();
    let outcome = if failed > 0 {
        Outcome::Fail
    } else if passed > 0 {
        Outcome::Pass
    } else if skipped > 0 {
        Outcome::Skip
    } else {
        Outcome::NotRun
    };
    let mut metrics = BTreeMap::new();
    metrics.insert("ltp_cases_passed".to_string(), passed as f64);
    metrics.insert("ltp_cases_failed".to_string(), failed as f64);
    metrics.insert("ltp_cases_skipped".to_string(), skipped as f64);
    TestResult {
        spec_id: spec.id.clone(),
        outcome,
        observed_boundary,
        observed_profile,
        evidence: format!(
            "LTP subset {} parsed {} cases: {passed} passed, {failed} failed, {skipped} skipped",
            spec.id,
            cases.len()
        ),
        remaining_uncertainty: "LTP compatibility does not prove vISA semantic completeness, substrate profile conformance, or real target substrate execution unless separately claimed with matching evidence".to_string(),
        metrics,
    }
}

pub fn ltp_report_from_subset_logs<'a>(
    target: impl Into<String>,
    generated_by: impl Into<String>,
    observed_boundary: Boundary,
    observed_profile_override: Option<String>,
    logs: impl IntoIterator<Item = (LtpSubset, &'a str)>,
) -> ConformanceReport {
    let logs = logs.into_iter().collect::<BTreeMap<_, _>>();
    let results = linux_ltp_catalog()
        .into_iter()
        .map(|spec| {
            let subset = LtpSubset::from_spec_id(&spec.id).expect("linux_ltp_catalog id mismatch");
            let observed_profile =
                observed_profile_override.clone().or_else(|| spec.required_profile.clone());
            match logs.get(&subset) {
                Some(text) => {
                    let cases = parse_ltp_results(text);
                    ltp_subset_result(&spec, &cases, observed_boundary, observed_profile)
                }
                None => TestResult {
                    spec_id: spec.id,
                    outcome: Outcome::NotRun,
                    observed_boundary,
                    observed_profile,
                    evidence: "LTP subset log was not provided".to_string(),
                    remaining_uncertainty:
                        "subset was not executed or the runner did not collect its log".to_string(),
                    metrics: BTreeMap::new(),
                },
            }
        })
        .collect();
    ConformanceReport {
        schema_version: REPORT_SCHEMA_VERSION.to_string(),
        suite_id: "vmos-linux-ltp-personality-compatibility".to_string(),
        target: target.into(),
        generated_by: generated_by.into(),
        results,
    }
}

fn normalize_ltp_status(token: &str) -> Option<Outcome> {
    let status = token.trim_matches(|ch: char| !ch.is_ascii_alphanumeric()).to_ascii_uppercase();
    match status.as_str() {
        "PASS" | "TPASS" => Some(Outcome::Pass),
        "FAIL" | "TFAIL" | "BROK" | "TBROK" => Some(Outcome::Fail),
        "CONF" | "TCONF" | "NA" | "SKIP" | "TSKIP" => Some(Outcome::Skip),
        _ => None,
    }
}

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
            runner: "cargo test -p vms_runtime runtime_loads_artifact_publishes_code_and_starts_activation",
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
            runner: "cargo test -p vms_runtime portable_state_survives_profile_change",
            proves: &["portable state survives profile-change restore with stable identity"],
            does_not_prove: &["product-grade live migration latency", "device binding continuity"],
        }),
    ]
}

pub fn substrate_profile_catalog() -> Vec<TestSpec> {
    vec![
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
        runner: "cargo test -p vms_runtime visa_native_personality_runs_without_linux_or_wasi_frontend",
        proves: &["non-Linux personality can use the vISA runtime path"],
        does_not_prove: &["Linux personality compatibility", "WASI filesystem or socket coverage"],
    })]
}

pub fn performance_catalog() -> Vec<TestSpec> {
    vec![
        perf_spec(
            "bench.hostcall.latency",
            "hostcall dispatch latency through vms_runtime and vms_wasmtime",
            &[CapabilityDomain::Hostcall],
            "cargo bench -p vmos-bench",
        ),
        perf_spec(
            "bench.activation.start",
            "artifact load and activation start latency",
            &[CapabilityDomain::Artifact, CapabilityDomain::Activation],
            "cargo bench -p vmos-bench",
        ),
        perf_spec(
            "bench.block.network",
            "block request and packet path throughput",
            &[CapabilityDomain::Block, CapabilityDomain::Network],
            "cargo bench -p vmos-bench",
        ),
        perf_spec(
            "bench.snapshot.restore",
            "portable snapshot subset and restore cost",
            &[CapabilityDomain::Snapshot],
            "cargo bench -p vmos-bench",
        ),
    ]
}

pub fn validate_catalog(specs: &[TestSpec]) -> ValidationReport {
    let mut findings = Vec::new();
    let mut ids = BTreeSet::new();
    for spec in specs {
        if !ids.insert(spec.id.as_str()) {
            findings.push(finding("duplicate-spec-id", format!("duplicate spec id {}", spec.id)));
        }
        validate_spec(spec, &mut findings);
    }
    ValidationReport::new(findings)
}

pub fn validate_report(report: &ConformanceReport, catalog: &[TestSpec]) -> ValidationReport {
    let mut findings = Vec::new();
    if report.schema_version != REPORT_SCHEMA_VERSION {
        findings.push(finding(
            "unsupported-report-schema",
            format!("unsupported schema {}", report.schema_version),
        ));
    }
    if report.results.is_empty() {
        findings.push(finding("empty-report", "report contains no results"));
    }
    let spec_by_id =
        catalog.iter().map(|spec| (spec.id.as_str(), spec)).collect::<BTreeMap<_, _>>();
    let mut result_ids = BTreeSet::new();
    for result in &report.results {
        if !result_ids.insert(result.spec_id.as_str()) {
            findings.push(finding(
                "duplicate-result-spec-id",
                format!("duplicate result for spec id {}", result.spec_id),
            ));
        }
        let Some(spec) = spec_by_id.get(result.spec_id.as_str()) else {
            findings
                .push(finding("unknown-spec-id", format!("unknown spec id {}", result.spec_id)));
            continue;
        };
        if !result.observed_boundary.can_claim(spec.minimum_boundary) {
            findings.push(finding(
                "insufficient-evidence-boundary",
                format!(
                    "{} observed {} but requires {}",
                    result.spec_id,
                    result.observed_boundary.as_str(),
                    spec.minimum_boundary.as_str()
                ),
            ));
        }
        if let Some(profile) = &result.observed_profile
            && SubstrateProfile::parse(profile).is_none()
        {
            findings.push(finding(
                "unknown-observed-profile",
                format!("{} observed unknown profile {}", result.spec_id, profile),
            ));
        }
        if matches!(result.outcome, Outcome::Pass | Outcome::Fail) {
            if result.evidence.trim().is_empty() {
                findings.push(finding(
                    "missing-evidence",
                    format!("{} has no evidence text", result.spec_id),
                ));
            }
            if result.remaining_uncertainty.trim().is_empty() {
                findings.push(finding(
                    "missing-remaining-uncertainty",
                    format!("{} has no remaining uncertainty text", result.spec_id),
                ));
            }
            if spec.claim == ClaimKind::PerformanceBenchmark && result.metrics.is_empty() {
                findings.push(finding(
                    "missing-performance-metrics",
                    format!("{} is a performance result without metrics", result.spec_id),
                ));
            }
        }
    }
    validate_suite_coverage(report, &result_ids, catalog, &mut findings);
    ValidationReport::new(findings)
}

pub fn parse_report_json(bytes: &[u8]) -> Result<ConformanceReport, ReportLoadError> {
    serde_json::from_slice(bytes).map_err(|error| ReportLoadError {
        code: "invalid-report-json".to_string(),
        detail: error.to_string(),
    })
}

pub fn gate_report_json(bytes: &[u8], catalog: &[TestSpec]) -> ReportGateResult {
    match parse_report_json(bytes) {
        Ok(report) => {
            let validation = validate_report(&report, catalog);
            let outcome_findings = report_outcome_findings(&report);
            ReportGateResult {
                ok: validation.ok && outcome_findings.is_empty(),
                load_error: None,
                validation: Some(validation),
                outcome_findings,
            }
        }
        Err(error) => ReportGateResult {
            ok: false,
            load_error: Some(error),
            validation: None,
            outcome_findings: Vec::new(),
        },
    }
}

pub fn report_outcome_findings(report: &ConformanceReport) -> Vec<ValidationFinding> {
    let mut findings = Vec::new();
    for result in &report.results {
        let code = match result.outcome {
            Outcome::Pass => continue,
            Outcome::Fail => "result-failed",
            Outcome::Skip => "result-skipped",
            Outcome::NotRun => "result-not-run",
        };
        findings.push(finding(
            code,
            format!("{} reported outcome {:?}", result.spec_id, result.outcome),
        ));
    }
    findings
}

fn validate_suite_coverage(
    report: &ConformanceReport,
    result_ids: &BTreeSet<&str>,
    catalog: &[TestSpec],
    findings: &mut Vec<ValidationFinding>,
) {
    let required_ids: Vec<String> = match report.suite_id.as_str() {
        "vmos-layered-conformance" => catalog.iter().map(|spec| spec.id.clone()).collect(),
        "vmos-linux-ltp-personality-compatibility" => {
            linux_ltp_catalog().into_iter().map(|spec| spec.id).collect()
        }
        "vmos-performance-benchmark" => {
            performance_catalog().into_iter().map(|spec| spec.id).collect()
        }
        suite_id => {
            findings.push(finding("unknown-suite-id", format!("unknown suite id {suite_id}")));
            return;
        }
    };
    for spec_id in required_ids {
        if !result_ids.contains(spec_id.as_str()) {
            findings.push(finding(
                "missing-suite-result",
                format!("{} omits required result {}", report.suite_id, spec_id),
            ));
        }
    }
}

pub fn sample_report(catalog: &[TestSpec]) -> ConformanceReport {
    ConformanceReport {
        schema_version: REPORT_SCHEMA_VERSION.to_string(),
        suite_id: "vmos-layered-conformance".to_string(),
        target: "catalog-only".to_string(),
        generated_by: "vmos-conformance sample-report".to_string(),
        results: catalog
            .iter()
            .map(|spec| TestResult {
                spec_id: spec.id.clone(),
                outcome: Outcome::NotRun,
                observed_boundary: spec.minimum_boundary,
                observed_profile: spec.required_profile.clone(),
                evidence: "catalog entry not executed".to_string(),
                remaining_uncertainty: "no executable result has been collected".to_string(),
                metrics: BTreeMap::new(),
            })
            .collect(),
    }
}

pub fn sample_ltp_report() -> ConformanceReport {
    let catalog = linux_ltp_catalog();
    ConformanceReport {
        schema_version: REPORT_SCHEMA_VERSION.to_string(),
        suite_id: "vmos-linux-ltp-personality-compatibility".to_string(),
        target: "ltp-parser-sample".to_string(),
        generated_by: "vmos-conformance sample-ltp-report".to_string(),
        results: catalog
            .iter()
            .map(|spec| {
                let cases = [
                    LtpCaseResult {
                        case_id: format!("{}_smoke_01", spec.id.replace('.', "_")),
                        outcome: Outcome::Pass,
                        raw_status: "TPASS".to_string(),
                        detail: "sample LTP case passed".to_string(),
                    },
                    LtpCaseResult {
                        case_id: format!("{}_smoke_02", spec.id.replace('.', "_")),
                        outcome: Outcome::Skip,
                        raw_status: "TCONF".to_string(),
                        detail: "sample LTP case skipped by configuration".to_string(),
                    },
                ];
                ltp_subset_result(
                    spec,
                    &cases,
                    Boundary::PortableArtifactExecution,
                    spec.required_profile.clone(),
                )
            })
            .collect(),
    }
}

pub fn sample_performance_report() -> ConformanceReport {
    ConformanceReport {
        schema_version: REPORT_SCHEMA_VERSION.to_string(),
        suite_id: "vmos-performance-benchmark".to_string(),
        target: "performance-parser-sample".to_string(),
        generated_by: "vmos-conformance sample-performance-report".to_string(),
        results: performance_catalog()
            .into_iter()
            .map(|spec| {
                let mut metrics = BTreeMap::new();
                metrics.insert("sample_value".to_string(), 1.0);
                TestResult {
                    spec_id: spec.id,
                    outcome: Outcome::Pass,
                    observed_boundary: spec.minimum_boundary,
                    observed_profile: spec.required_profile,
                    evidence: "synthetic performance metric recorded".to_string(),
                    remaining_uncertainty:
                        "sample report validates schema only; it is not a real benchmark run"
                            .to_string(),
                    metrics,
                }
            })
            .collect(),
    }
}

fn validate_spec(spec: &TestSpec, findings: &mut Vec<ValidationFinding>) {
    if spec.id.trim().is_empty() {
        findings.push(finding("empty-spec-id", "spec id is empty"));
    }
    if spec.runner.trim().is_empty() {
        findings.push(finding("empty-runner", format!("{} has no runner", spec.id)));
    }
    if let Some(profile) = &spec.required_profile
        && SubstrateProfile::parse(profile).is_none()
    {
        findings.push(finding(
            "unknown-required-profile",
            format!("{} requires unknown profile {}", spec.id, profile),
        ));
    }
    if spec.claim == ClaimKind::PersonalityCompatibility && spec.personality.is_none() {
        findings.push(finding(
            "personality-claim-missing-personality",
            format!("{} is a personality claim without a personality", spec.id),
        ));
    }
    if spec.id.starts_with("linux-ltp.") {
        if spec.claim != ClaimKind::PersonalityCompatibility
            || spec.personality != Some(Personality::Linux)
        {
            findings.push(finding(
                "ltp-boundary-misclassified",
                format!("{} must be Linux personality compatibility", spec.id),
            ));
        }
        if !spec.does_not_prove.iter().any(|item| item.contains("vISA semantic completeness")) {
            findings.push(finding(
                "ltp-missing-non-proof",
                format!(
                    "{} must state that LTP does not prove vISA semantic completeness",
                    spec.id
                ),
            ));
        }
    }
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

fn perf_spec(id: &str, title: &str, domains: &[CapabilityDomain], runner: &str) -> TestSpec {
    spec(SpecDef {
        id,
        title,
        claim: ClaimKind::PerformanceBenchmark,
        minimum_boundary: Boundary::PortableArtifactExecution,
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

fn finding(code: &str, detail: impl Into<String>) -> ValidationFinding {
    ValidationFinding { code: code.to_string(), detail: detail.into() }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn full_catalog_is_valid_and_has_unique_ids() {
        let catalog = full_catalog();
        let report = validate_catalog(&catalog);
        assert!(report.ok, "{:#?}", report.findings);
        assert!(catalog.len() >= 15);
    }

    #[test]
    fn ltp_specs_are_linux_personality_compatibility_not_visa_conformance() {
        for spec in linux_ltp_catalog() {
            assert_eq!(spec.claim, ClaimKind::PersonalityCompatibility);
            assert_eq!(spec.personality, Some(Personality::Linux));
            assert!(
                spec.does_not_prove.iter().any(|item| item.contains("vISA semantic completeness"))
            );
            assert_ne!(spec.claim, ClaimKind::VisaSemanticConformance);
        }
    }

    #[test]
    fn sample_report_validates_against_full_catalog() {
        let catalog = full_catalog();
        let report = sample_report(&catalog);
        let validation = validate_report(&report, &catalog);
        assert!(validation.ok, "{:#?}", validation.findings);
    }

    #[test]
    fn report_rejects_unknown_spec_id() {
        let catalog = full_catalog();
        let mut report = sample_report(&catalog);
        report.results[0].spec_id = "missing.spec".to_string();

        let validation = validate_report(&report, &catalog);
        assert!(!validation.ok);
        assert!(validation.findings.iter().any(|finding| finding.code == "unknown-spec-id"));
    }

    #[test]
    fn report_rejects_unknown_suite_id() {
        let catalog = linux_ltp_catalog();
        let mut report = sample_ltp_report();
        report.suite_id = "custom-suite".to_string();

        let validation = validate_report(&report, &catalog);
        assert!(!validation.ok);
        assert!(validation.findings.iter().any(|finding| finding.code == "unknown-suite-id"));
    }

    #[test]
    fn report_rejects_missing_suite_results() {
        let catalog = linux_ltp_catalog();
        let spec = catalog.iter().find(|spec| spec.id == LtpSubset::FsBasic.spec_id()).unwrap();
        let report = ConformanceReport {
            schema_version: REPORT_SCHEMA_VERSION.to_string(),
            suite_id: "vmos-linux-ltp-personality-compatibility".to_string(),
            target: "unit-test".to_string(),
            generated_by: "unit-test".to_string(),
            results: vec![TestResult {
                spec_id: spec.id.clone(),
                outcome: Outcome::Pass,
                observed_boundary: spec.minimum_boundary,
                observed_profile: spec.required_profile.clone(),
                evidence: "only one passing LTP subset was reported".to_string(),
                remaining_uncertainty: "other LTP subsets were omitted".to_string(),
                metrics: BTreeMap::new(),
            }],
        };

        let validation = validate_report(&report, &catalog);
        assert!(!validation.ok);
        assert!(validation.findings.iter().any(|finding| finding.code == "missing-suite-result"));
    }

    #[test]
    fn report_rejects_empty_result_set() {
        let report = ConformanceReport {
            schema_version: REPORT_SCHEMA_VERSION.to_string(),
            suite_id: "test".to_string(),
            target: "test".to_string(),
            generated_by: "unit-test".to_string(),
            results: Vec::new(),
        };

        let validation = validate_report(&report, &full_catalog());
        assert!(!validation.ok);
        assert!(validation.findings.iter().any(|finding| finding.code == "empty-report"));
    }

    #[test]
    fn report_rejects_duplicate_result_ids() {
        let catalog = full_catalog();
        let spec = catalog.iter().find(|spec| spec.id == "visa.artifact.load").unwrap();
        let mut report = sample_report(&catalog);
        report.results = vec![
            TestResult {
                spec_id: spec.id.clone(),
                outcome: Outcome::NotRun,
                observed_boundary: spec.minimum_boundary,
                observed_profile: spec.required_profile.clone(),
                evidence: "not run".to_string(),
                remaining_uncertainty: "duplicate test fixture".to_string(),
                metrics: BTreeMap::new(),
            },
            TestResult {
                spec_id: spec.id.clone(),
                outcome: Outcome::NotRun,
                observed_boundary: spec.minimum_boundary,
                observed_profile: spec.required_profile.clone(),
                evidence: "not run".to_string(),
                remaining_uncertainty: "duplicate test fixture".to_string(),
                metrics: BTreeMap::new(),
            },
        ];

        let validation = validate_report(&report, &catalog);
        assert!(!validation.ok);
        assert!(
            validation.findings.iter().any(|finding| finding.code == "duplicate-result-spec-id")
        );
    }

    #[test]
    fn report_rejects_insufficient_boundary() {
        let catalog = full_catalog();
        let mut report = sample_report(&catalog);
        let ltp = catalog.iter().find(|spec| spec.id == "linux-ltp.fs.basic").unwrap();
        report.results = vec![TestResult {
            spec_id: ltp.id.clone(),
            outcome: Outcome::Pass,
            observed_boundary: Boundary::SemanticModel,
            observed_profile: ltp.required_profile.clone(),
            evidence: "LTP fs subset passed in a semantic-only harness".to_string(),
            remaining_uncertainty: "portable artifact execution was not observed".to_string(),
            metrics: BTreeMap::new(),
        }];

        let validation = validate_report(&report, &catalog);
        assert!(!validation.ok);
        assert!(
            validation
                .findings
                .iter()
                .any(|finding| finding.code == "insufficient-evidence-boundary")
        );
    }

    #[test]
    fn passing_results_must_record_confidence_and_risk() {
        let catalog = full_catalog();
        let spec = catalog.iter().find(|spec| spec.id == "visa.artifact.load").unwrap();
        let report = ConformanceReport {
            schema_version: REPORT_SCHEMA_VERSION.to_string(),
            suite_id: "test".to_string(),
            target: "test".to_string(),
            generated_by: "unit-test".to_string(),
            results: vec![TestResult {
                spec_id: spec.id.clone(),
                outcome: Outcome::Pass,
                observed_boundary: spec.minimum_boundary,
                observed_profile: spec.required_profile.clone(),
                evidence: String::new(),
                remaining_uncertainty: String::new(),
                metrics: BTreeMap::new(),
            }],
        };

        let validation = validate_report(&report, &catalog);
        assert!(!validation.ok);
        assert!(validation.findings.iter().any(|finding| finding.code == "missing-evidence"));
        assert!(
            validation
                .findings
                .iter()
                .any(|finding| finding.code == "missing-remaining-uncertainty")
        );
    }

    #[test]
    fn gate_report_json_accepts_all_pass_sample_report() {
        let catalog = linux_ltp_catalog();
        let sample = sample_ltp_report();
        let bytes = serde_json::to_vec(&sample).unwrap();
        let gate = gate_report_json(&bytes, &catalog);

        assert!(gate.ok, "{gate:#?}");
        assert!(gate.load_error.is_none());
        assert!(gate.validation.unwrap().ok);
        assert!(gate.outcome_findings.is_empty());
    }

    #[test]
    fn gate_report_json_rejects_not_run_or_failed_outcomes() {
        let catalog = full_catalog();
        let sample = sample_report(&catalog);
        let bytes = serde_json::to_vec(&sample).unwrap();
        let gate = gate_report_json(&bytes, &catalog);

        assert!(!gate.ok);
        assert!(gate.validation.unwrap().ok);
        assert!(gate.outcome_findings.iter().any(|finding| finding.code == "result-not-run"));
    }

    #[test]
    fn performance_report_requires_metrics_for_pass_or_fail_results() {
        let catalog = performance_catalog();
        let report = ConformanceReport {
            schema_version: REPORT_SCHEMA_VERSION.to_string(),
            suite_id: "vmos-performance-benchmark".to_string(),
            target: "unit-test".to_string(),
            generated_by: "unit-test".to_string(),
            results: catalog
                .iter()
                .map(|spec| TestResult {
                    spec_id: spec.id.clone(),
                    outcome: Outcome::Pass,
                    observed_boundary: spec.minimum_boundary,
                    observed_profile: spec.required_profile.clone(),
                    evidence: "benchmark completed".to_string(),
                    remaining_uncertainty: "metrics were accidentally omitted".to_string(),
                    metrics: BTreeMap::new(),
                })
                .collect(),
        };

        let validation = validate_report(&report, &catalog);
        assert!(!validation.ok);
        assert!(
            validation.findings.iter().any(|finding| finding.code == "missing-performance-metrics")
        );
    }

    #[test]
    fn sample_performance_report_validates_and_gates() {
        let catalog = performance_catalog();
        let report = sample_performance_report();
        let validation = validate_report(&report, &catalog);
        let gate = gate_report_json(&serde_json::to_vec(&report).unwrap(), &catalog);

        assert!(validation.ok, "{:#?}", validation.findings);
        assert!(gate.ok, "{gate:#?}");
        assert!(report.results.iter().all(|result| !result.metrics.is_empty()));
    }

    #[test]
    fn gate_report_json_rejects_malformed_json() {
        let gate = gate_report_json(b"{not-json", &full_catalog());

        assert!(!gate.ok);
        assert_eq!(gate.load_error.unwrap().code, "invalid-report-json");
        assert!(gate.validation.is_none());
        assert!(gate.outcome_findings.is_empty());
    }

    #[test]
    fn ltp_invocation_maps_subsets_to_runltp_commands() {
        let plan = LtpInvocation::default_plan("target/ltp");

        assert_eq!(plan.subsets, LtpSubset::ALL);
        assert_eq!(
            plan.command_for(LtpSubset::FsBasic),
            vec![
                "runltp".to_string(),
                "-f".to_string(),
                "fs".to_string(),
                "-o".to_string(),
                "target/ltp/linux-ltp.fs.basic.log".to_string(),
            ]
        );
        assert_eq!(
            plan.command_for(LtpSubset::NetSocket),
            vec![
                "runltp".to_string(),
                "-f".to_string(),
                "net.ipv4,net.tcp_cmds".to_string(),
                "-o".to_string(),
                "target/ltp/linux-ltp.net.socket.log".to_string(),
            ]
        );
    }

    #[test]
    fn ltp_parser_maps_common_status_lines() {
        let cases = parse_ltp_results(
            r#"
open01 1 TPASS : open succeeded
rename01 1 TFAIL : rename failed
mmap01 1 TCONF : unsupported configuration
"#,
        );

        assert_eq!(cases.len(), 3);
        assert_eq!(cases[0].case_id, "open01");
        assert_eq!(cases[0].outcome, Outcome::Pass);
        assert_eq!(cases[1].outcome, Outcome::Fail);
        assert_eq!(cases[2].outcome, Outcome::Skip);
    }

    #[test]
    fn ltp_subset_result_uses_failures_as_compatibility_failure() {
        let spec = linux_ltp_catalog()
            .into_iter()
            .find(|spec| spec.id == LtpSubset::FsBasic.spec_id())
            .unwrap();
        let cases = parse_ltp_results(
            r#"
open01 1 TPASS : open succeeded
rename01 1 TFAIL : rename failed
"#,
        );
        let result = ltp_subset_result(
            &spec,
            &cases,
            Boundary::PortableArtifactExecution,
            spec.required_profile.clone(),
        );

        assert_eq!(result.outcome, Outcome::Fail);
        assert_eq!(result.metrics["ltp_cases_passed"], 1.0);
        assert_eq!(result.metrics["ltp_cases_failed"], 1.0);
        assert!(result.remaining_uncertainty.contains("vISA semantic completeness"));
    }

    #[test]
    fn ltp_report_from_subset_logs_marks_missing_subsets_not_run() {
        let report = ltp_report_from_subset_logs(
            "unit-test",
            "unit-test",
            Boundary::PortableArtifactExecution,
            None,
            [(LtpSubset::FsBasic, "open01 1 TPASS : open succeeded")],
        );

        let validation = validate_report(&report, &linux_ltp_catalog());
        assert!(validation.ok, "{:#?}", validation.findings);
        assert_eq!(report.results.len(), LtpSubset::ALL.len());
        assert_eq!(report.results[0].spec_id, LtpSubset::FsBasic.spec_id());
        assert_eq!(report.results[0].outcome, Outcome::Pass);
        assert!(
            report.results.iter().filter(|result| result.outcome == Outcome::NotRun).count() >= 1
        );
    }

    #[test]
    fn ltp_report_from_subset_logs_preserves_failures_and_profile_override() {
        let report = ltp_report_from_subset_logs(
            "unit-test",
            "unit-test",
            Boundary::RealTargetSubstrate,
            Some("snapshot-replay-capable".to_string()),
            [(
                LtpSubset::NetSocket,
                "socket01 1 TPASS : socket opened\nsocket02 1 TFAIL : connect failed",
            )],
        );

        let socket = report
            .results
            .iter()
            .find(|result| result.spec_id == LtpSubset::NetSocket.spec_id())
            .unwrap();
        assert_eq!(socket.outcome, Outcome::Fail);
        assert_eq!(socket.observed_boundary, Boundary::RealTargetSubstrate);
        assert_eq!(socket.observed_profile.as_deref(), Some("snapshot-replay-capable"));
        assert_eq!(socket.metrics["ltp_cases_failed"], 1.0);
        assert!(validate_report(&report, &linux_ltp_catalog()).ok);
    }

    #[test]
    fn sample_ltp_report_validates_against_ltp_catalog() {
        let catalog = linux_ltp_catalog();
        let report = sample_ltp_report();
        let validation = validate_report(&report, &catalog);

        assert!(validation.ok, "{:#?}", validation.findings);
        assert!(report.results.iter().all(|result| {
            result.observed_boundary == Boundary::PortableArtifactExecution
                && matches!(result.outcome, Outcome::Pass)
        }));
    }
}
