use std::collections::BTreeMap;

use contract_core::EvidenceBoundaryLevel;
use serde::{Deserialize, Serialize};

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
    #[serde(default)]
    pub evidence_artifacts: Vec<EvidenceArtifact>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvidenceArtifact {
    pub kind: EvidenceArtifactKind,
    pub uri: String,
    pub sha256: String,
    pub description: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum EvidenceArtifactKind {
    ContractGraphSnapshot,
    SubstrateExtractionTrace,
    DeviceTrace,
    SerialLog,
    BenchmarkRawOutput,
    LtpRawLog,
}

impl EvidenceArtifactKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ContractGraphSnapshot => "contract-graph-snapshot",
            Self::SubstrateExtractionTrace => "substrate-extraction-trace",
            Self::DeviceTrace => "device-trace",
            Self::SerialLog => "serial-log",
            Self::BenchmarkRawOutput => "benchmark-raw-output",
            Self::LtpRawLog => "ltp-raw-log",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "contract-graph-snapshot" => Some(Self::ContractGraphSnapshot),
            "substrate-extraction-trace" => Some(Self::SubstrateExtractionTrace),
            "device-trace" => Some(Self::DeviceTrace),
            "serial-log" => Some(Self::SerialLog),
            "benchmark-raw-output" => Some(Self::BenchmarkRawOutput),
            "ltp-raw-log" => Some(Self::LtpRawLog),
            _ => None,
        }
    }
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
    pub(crate) fn new(findings: Vec<ValidationFinding>) -> Self {
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
