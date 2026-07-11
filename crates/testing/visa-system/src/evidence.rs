use std::{
    collections::BTreeSet,
    fmt,
    fs::{self, OpenOptions},
    io::{Read, Write},
    path::{Component, Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};

use contract_core::{Digest, Identity, LeaseEpoch};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use visa_conformance::{
    STAGE1_CAPABILITY_ID, STAGE1_EVIDENCE_SCHEMA_VERSION, STAGE1_SEMANTIC_TRACE_SCHEMA_VERSION,
    Stage1ArtifactReference, Stage1AuthorityEvidence, Stage1BindingReceiptReference,
    Stage1CaseArtifacts, Stage1CaseEvidence, Stage1CaseOutcome, Stage1Claim, Stage1EvidenceBundle,
    Stage1EvidenceKind, Stage1ExecutionEnvironment, Stage1ExpectedOwnership, Stage1FaultSchedule,
    Stage1OwnershipStatus, Stage1PerformanceMetric, Stage1PerformanceObservation,
    Stage1PerformanceUnit, Stage1Provenance, Stage1ProvenanceArtifactReference,
    Stage1ProvenanceArtifacts, Stage1ResourceKind, Stage1ResourceProfile,
    Stage1SemanticTraceArtifact, Stage1StateEvidence, Stage1TraceRole, required_stage1_case_ids,
    stage1_case_definition, stage1_expected_ownership, validate_stage1_evidence_artifacts,
    validate_stage1_evidence_bundle,
};
use visa_runtime::canonical_digest;

use crate::fixture::FixtureSpec;

pub const EVIDENCE_BUNDLE_FILE: &str = "stage1-evidence.json";
const CASE_MANIFEST_SCHEMA: &str = "visa-system-case-artifacts-v1";
static NEXT_TEMP_FILE: AtomicU64 = AtomicU64::new(1);

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceContext {
    pub bundle_id: String,
    pub started_at_unix_ms: u64,
    pub finished_at_unix_ms: u64,
    pub environment: Stage1ExecutionEnvironment,
    pub component_digest: Digest,
    pub profile_digest: Digest,
    pub config_digest: Digest,
    pub policy_digest: Digest,
    pub source_digest: Digest,
    pub toolchain_digest: Digest,
    pub provenance_files: EvidenceProvenanceFiles,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceProvenanceFiles {
    pub component: PathBuf,
    pub profile: PathBuf,
    pub source_manifest: PathBuf,
    pub toolchain: PathBuf,
    pub build_source_manifest: PathBuf,
    pub build_toolchain: PathBuf,
    pub executable: PathBuf,
    pub matrix_manifest: PathBuf,
}

impl EvidenceContext {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        bundle_id: impl Into<String>,
        started_at_unix_ms: u64,
        finished_at_unix_ms: u64,
        mut environment: Stage1ExecutionEnvironment,
        component_digest: Digest,
        profile_digest: Digest,
        config_digest: Digest,
        policy_digest: Digest,
        source_digest: Digest,
        toolchain_digest: Digest,
        provenance_files: EvidenceProvenanceFiles,
    ) -> Self {
        environment.authority_enforcement.policy_sha256 = digest_hex(policy_digest);
        Self {
            bundle_id: bundle_id.into(),
            started_at_unix_ms,
            finished_at_unix_ms,
            environment,
            component_digest,
            profile_digest,
            config_digest,
            policy_digest,
            source_digest,
            toolchain_digest,
            provenance_files,
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn from_fixture(
        bundle_id: impl Into<String>,
        started_at_unix_ms: u64,
        finished_at_unix_ms: u64,
        mut environment: Stage1ExecutionEnvironment,
        fixture: &FixtureSpec,
        source_digest: Digest,
        toolchain_digest: Digest,
        provenance_files: EvidenceProvenanceFiles,
    ) -> Result<Self, EvidenceError> {
        let config_digest = fixture.config_digest().map_err(|error| {
            EvidenceError::invalid(format!("cannot digest fixture config: {error}"))
        })?;
        let policy_digest = fixture.policy_digest().map_err(|error| {
            EvidenceError::invalid(format!("cannot digest fixture policy: {error}"))
        })?;
        let timer_digest = canonical_digest(&fixture.profile.timer)
            .map_err(|_| EvidenceError::invalid("cannot digest timer profile"))?;
        let key_value_digest = canonical_digest(&fixture.profile.key_value)
            .map_err(|_| EvidenceError::invalid("cannot digest key-value profile"))?;
        let profile_version =
            format!("{}.{}", fixture.profile.version.major, fixture.profile.version.minor);

        environment.resource_profiles = vec![
            Stage1ResourceProfile {
                resource: Stage1ResourceKind::PausedDurationTimer,
                profile_id: "paused-duration-monotonic-timer".to_owned(),
                version: profile_version.clone(),
                profile_sha256: digest_hex(timer_digest),
            },
            Stage1ResourceProfile {
                resource: Stage1ResourceKind::DurableKeyValue,
                profile_id: "durable-versioned-kv".to_owned(),
                version: profile_version,
                profile_sha256: digest_hex(key_value_digest),
            },
        ];

        Ok(Self::new(
            bundle_id,
            started_at_unix_ms,
            finished_at_unix_ms,
            environment,
            fixture.component_digest,
            fixture.profile_digest,
            config_digest,
            policy_digest,
            source_digest,
            toolchain_digest,
            provenance_files,
        ))
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CaseAuthorityRecord {
    pub source_authority_root: Digest,
    pub destination_authority_root: Digest,
    pub source_lease_epoch: LeaseEpoch,
    pub destination_lease_epoch: Option<LeaseEpoch>,
    pub fencing_epoch: LeaseEpoch,
    pub ownership: Stage1OwnershipStatus,
    pub source_fenced: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BindingReceiptArtifact {
    pub receipt_id: Identity,
    pub bytes: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PerformanceMeasurement {
    pub metric: Stage1PerformanceMetric,
    pub samples: Vec<u64>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CaseExecutionRecord {
    pub case_id: String,
    pub case_config_digest: Digest,
    pub case_policy_digest: Digest,
    pub execution_id: Identity,
    pub handoff_id: Identity,
    pub snapshot_id: Identity,
    pub outcome: Stage1CaseOutcome,
    pub exit_status: i32,
    pub fault_schedule: Stage1FaultSchedule,
    pub authority: CaseAuthorityRecord,
    pub snapshot_bytes: Option<Vec<u8>>,
    pub semantic_traces: Vec<Stage1SemanticTraceArtifact>,
    pub timer_binding_receipt: Option<BindingReceiptArtifact>,
    pub key_value_binding_receipt: Option<BindingReceiptArtifact>,
    pub raw_source_json: Vec<u8>,
    pub raw_destination_json: Vec<u8>,
    pub raw_assertions_json: Vec<u8>,
    pub state_digest: Digest,
    pub replay_state_digest: Digest,
    pub performance: Vec<PerformanceMeasurement>,
}

pub struct EvidenceWriter {
    artifact_root: PathBuf,
}

impl EvidenceWriter {
    pub fn new(artifact_root: impl Into<PathBuf>) -> Self {
        Self { artifact_root: artifact_root.into() }
    }

    pub fn artifact_root(&self) -> &Path {
        &self.artifact_root
    }

    pub fn bundle_path(&self) -> PathBuf {
        self.artifact_root.join(EVIDENCE_BUNDLE_FILE)
    }

    pub fn manifest_set_sha256(&self) -> Result<String, EvidenceError> {
        let mut digest = Sha256::new();
        for case_id in required_stage1_case_ids() {
            let path = self.manifest_path(case_id);
            let bytes = fs::read(&path).map_err(|error| EvidenceError::io(&path, error))?;
            digest.update((case_id.len() as u64).to_be_bytes());
            digest.update(case_id.as_bytes());
            digest.update((bytes.len() as u64).to_be_bytes());
            digest.update(bytes);
        }
        Ok(format!("{:x}", digest.finalize()))
    }

    pub fn bundle_sha256(&self) -> Result<String, EvidenceError> {
        sha256_file(&self.bundle_path())
    }

    pub fn append_case_assertion(
        &self,
        case_id: &str,
        name: &str,
        detail: serde_json::Value,
    ) -> Result<(), EvidenceError> {
        if name.trim().is_empty() {
            return Err(EvidenceError::invalid("assertion name is empty"));
        }
        let mut manifest = self.read_manifest(case_id)?;
        let assertion = manifest
            .raw_execution
            .iter_mut()
            .find(|artifact| artifact.uri.ends_with("/raw/assertions.jsonl"))
            .ok_or_else(|| {
                EvidenceError::invalid(format!("case {case_id} has no raw assertions artifact"))
            })?;
        self.verify_artifact(assertion)?;
        let path = self.artifact_root.join(&assertion.uri);
        let mut bytes = fs::read(&path).map_err(|error| EvidenceError::io(&path, error))?;
        if !bytes.is_empty() && !bytes.ends_with(b"\n") {
            return Err(EvidenceError::invalid(format!(
                "case {case_id} assertions artifact is not newline terminated"
            )));
        }
        for line in bytes.split(|byte| *byte == b'\n').filter(|line| !line.is_empty()) {
            let value: serde_json::Value = serde_json::from_slice(line)
                .map_err(|error| EvidenceError::json("raw assertion", error))?;
            if value.get("name").and_then(serde_json::Value::as_str) == Some(name) {
                return Err(EvidenceError::conflict(format!(
                    "case {case_id} already contains assertion {name}"
                )));
            }
        }
        let observation = serde_json::json!({
            "name": name,
            "detail": detail,
            "case_config_digest": digest_from_hex(&manifest.case_config_sha256)?,
            "case_policy_digest": digest_from_hex(&manifest.case_policy_sha256)?,
        });
        serde_json::to_writer(&mut bytes, &observation)
            .map_err(|error| EvidenceError::json("raw assertion", error))?;
        bytes.push(b'\n');
        atomic_replace(&path, &bytes)?;
        assertion.sha256 = sha256_hex(&bytes);

        let manifest_path = self.manifest_path(case_id);
        let mut manifest_bytes = serde_json::to_vec_pretty(&manifest)
            .map_err(|error| EvidenceError::json("case manifest", error))?;
        manifest_bytes.push(b'\n');
        atomic_replace(&manifest_path, &manifest_bytes)
    }

    pub fn write(
        &self,
        context: &EvidenceContext,
        records: &[CaseExecutionRecord],
    ) -> Result<Stage1EvidenceBundle, EvidenceError> {
        self.write_records(context, records)?;
        self.regenerate(context)
    }

    pub fn write_prepublication(
        &self,
        context: &EvidenceContext,
        records: &[CaseExecutionRecord],
    ) -> Result<Stage1EvidenceBundle, EvidenceError> {
        self.write_records(context, records)?;
        self.regenerate_prepublication(context)
    }

    fn write_records(
        &self,
        context: &EvidenceContext,
        records: &[CaseExecutionRecord],
    ) -> Result<(), EvidenceError> {
        validate_context(context)?;
        validate_record_set(records)?;
        fs::create_dir_all(&self.artifact_root)
            .map_err(|error| EvidenceError::io(&self.artifact_root, error))?;
        for record in records {
            self.write_case(context, record)?;
        }
        Ok(())
    }

    pub fn regenerate(
        &self,
        context: &EvidenceContext,
    ) -> Result<Stage1EvidenceBundle, EvidenceError> {
        self.regenerate_inner(context, false)
    }

    pub fn regenerate_prepublication(
        &self,
        context: &EvidenceContext,
    ) -> Result<Stage1EvidenceBundle, EvidenceError> {
        self.regenerate_inner(context, true)
    }

    fn regenerate_inner(
        &self,
        context: &EvidenceContext,
        allow_pending_report_observation: bool,
    ) -> Result<Stage1EvidenceBundle, EvidenceError> {
        validate_context(context)?;
        let provenance_artifacts = self.provenance_artifacts(context)?;
        let mut cases = Vec::new();
        let mut performance_observations = Vec::new();
        for case_id in required_stage1_case_ids() {
            let manifest = self.read_manifest(case_id)?;
            validate_manifest_context(&manifest, context, case_id)?;
            let (case, observations) = self.case_from_manifest(context, manifest)?;
            cases.push(case);
            performance_observations.extend(observations);
        }

        let bundle = Stage1EvidenceBundle {
            schema_version: STAGE1_EVIDENCE_SCHEMA_VERSION.to_owned(),
            capability_id: STAGE1_CAPABILITY_ID.to_owned(),
            bundle_id: context.bundle_id.clone(),
            evidence_kind: Stage1EvidenceKind::Execution,
            claims: vec![Stage1Claim::CooperativeStatefulComponentHandoff],
            started_at_unix_ms: context.started_at_unix_ms,
            finished_at_unix_ms: context.finished_at_unix_ms,
            environment: context.environment.clone(),
            provenance: Stage1Provenance {
                component_sha256: digest_hex(context.component_digest),
                profile_sha256: digest_hex(context.profile_digest),
                config_sha256: digest_hex(context.config_digest),
                source_sha256: digest_hex(context.source_digest),
                toolchain_sha256: digest_hex(context.toolchain_digest),
                executable_sha256: provenance_artifacts.executable.sha256.clone(),
                artifacts: provenance_artifacts,
            },
            cases,
            performance_observations,
        };

        let structural = validate_stage1_evidence_bundle(&bundle);
        if !structural.ok {
            return Err(EvidenceError::validation("bundle", &structural.findings));
        }
        let mut artifacts = validate_stage1_evidence_artifacts(&bundle, &self.artifact_root);
        if allow_pending_report_observation {
            let pending = artifacts
                .findings
                .iter()
                .filter(|finding| finding.code == "missing-stage1-report-regeneration-assertion")
                .count();
            artifacts
                .findings
                .retain(|finding| finding.code != "missing-stage1-report-regeneration-assertion");
            artifacts.ok = artifacts.findings.is_empty();
            if pending != 1 {
                return Err(EvidenceError::invalid(format!(
                    "pre-publication evidence had {pending} pending report observations, expected one"
                )));
            }
        }
        if !artifacts.ok {
            return Err(EvidenceError::validation("artifacts", &artifacts.findings));
        }

        let mut bytes = serde_json::to_vec_pretty(&bundle)
            .map_err(|error| EvidenceError::json("bundle", error))?;
        bytes.push(b'\n');
        atomic_replace(&self.bundle_path(), &bytes)?;
        Ok(bundle)
    }

    fn write_case(
        &self,
        context: &EvidenceContext,
        record: &CaseExecutionRecord,
    ) -> Result<(), EvidenceError> {
        validate_record(record)?;
        let prefix = PathBuf::from("cases").join(&record.case_id);
        let snapshot = record
            .snapshot_bytes
            .as_deref()
            .map(|bytes| self.write_payload(prefix.join("snapshot.bin"), bytes))
            .transpose()?;
        let semantic_traces = record
            .semantic_traces
            .iter()
            .map(|trace| {
                let role = match trace.role {
                    Stage1TraceRole::Source => "source",
                    Stage1TraceRole::Destination => "destination",
                };
                let mut bytes = serde_json::to_vec_pretty(trace)
                    .map_err(|error| EvidenceError::json("semantic trace", error))?;
                bytes.push(b'\n');
                self.write_payload(prefix.join(format!("semantic-{role}.json")), &bytes)
            })
            .collect::<Result<Vec<_>, EvidenceError>>()?;

        let mut binding_receipts = Vec::new();
        if let Some(receipt) = &record.timer_binding_receipt {
            binding_receipts.push(StoredBindingReceipt {
                resource: Stage1ResourceKind::PausedDurationTimer,
                receipt_id: identity_hex(receipt.receipt_id),
                artifact: self.write_payload(prefix.join("receipts/timer.json"), &receipt.bytes)?,
            });
        }
        if let Some(receipt) = &record.key_value_binding_receipt {
            binding_receipts.push(StoredBindingReceipt {
                resource: Stage1ResourceKind::DurableKeyValue,
                receipt_id: identity_hex(receipt.receipt_id),
                artifact: self
                    .write_payload(prefix.join("receipts/key-value.json"), &receipt.bytes)?,
            });
        }

        let mut raw_execution = vec![
            self.write_payload(prefix.join("raw/source.jsonl"), &record.raw_source_json)?,
            self.write_payload(prefix.join("raw/destination.jsonl"), &record.raw_destination_json)?,
            self.write_payload(prefix.join("raw/assertions.jsonl"), &record.raw_assertions_json)?,
        ];
        let performance = if record.performance.is_empty() {
            None
        } else {
            let mut bytes = serde_json::to_vec_pretty(&record.performance)
                .map_err(|error| EvidenceError::json("performance", error))?;
            bytes.push(b'\n');
            let artifact = self.write_payload(prefix.join("raw/performance.json"), &bytes)?;
            raw_execution.push(artifact.clone());
            Some(StoredPerformance { measurements: record.performance.clone(), artifact })
        };

        let manifest = StoredCaseManifest {
            schema_version: CASE_MANIFEST_SCHEMA.to_owned(),
            bundle_id: context.bundle_id.clone(),
            component_sha256: digest_hex(context.component_digest),
            profile_sha256: digest_hex(context.profile_digest),
            case_id: record.case_id.clone(),
            case_config_sha256: digest_hex(record.case_config_digest),
            case_policy_sha256: digest_hex(record.case_policy_digest),
            execution_id: identity_hex(record.execution_id),
            handoff_id: identity_hex(record.handoff_id),
            snapshot_id: identity_hex(record.snapshot_id),
            outcome: record.outcome,
            exit_status: record.exit_status,
            fault_schedule: record.fault_schedule.clone(),
            authority: Stage1AuthorityEvidence {
                enforcement_policy_sha256: digest_hex(context.policy_digest),
                source_authority_root_sha256: digest_hex(record.authority.source_authority_root),
                destination_authority_root_sha256: digest_hex(
                    record.authority.destination_authority_root,
                ),
                source_lease_epoch: record.authority.source_lease_epoch.0,
                destination_lease_epoch: record
                    .authority
                    .destination_lease_epoch
                    .map(|epoch| epoch.0),
                fencing_epoch: record.authority.fencing_epoch.0,
                ownership: record.authority.ownership,
                source_fenced: record.authority.source_fenced,
            },
            state_sha256: digest_hex(record.state_digest),
            replay_state_sha256: digest_hex(record.replay_state_digest),
            snapshot,
            semantic_traces,
            binding_receipts,
            raw_execution,
            performance,
        };
        let mut manifest_bytes = serde_json::to_vec_pretty(&manifest)
            .map_err(|error| EvidenceError::json("case manifest", error))?;
        manifest_bytes.push(b'\n');
        atomic_replace(&self.manifest_path(&record.case_id), &manifest_bytes)
    }

    fn write_payload(
        &self,
        relative_path: PathBuf,
        bytes: &[u8],
    ) -> Result<StoredArtifact, EvidenceError> {
        if !safe_relative_path(&relative_path) {
            return Err(EvidenceError::invalid(format!(
                "unsafe artifact path {}",
                relative_path.display()
            )));
        }
        let path = self.artifact_root.join(&relative_path);
        if path.exists() {
            let existing = fs::read(&path).map_err(|error| EvidenceError::io(&path, error))?;
            if existing != bytes {
                return Err(EvidenceError::conflict(format!(
                    "artifact {} already exists with different content",
                    relative_path.display()
                )));
            }
        } else {
            atomic_replace(&path, bytes)?;
        }
        Ok(StoredArtifact { uri: path_to_uri(&relative_path)?, sha256: sha256_hex(bytes) })
    }

    fn read_manifest(&self, case_id: &str) -> Result<StoredCaseManifest, EvidenceError> {
        let path = self.manifest_path(case_id);
        let bytes = fs::read(&path).map_err(|error| EvidenceError::io(&path, error))?;
        serde_json::from_slice(&bytes).map_err(|error| EvidenceError::json(path.display(), error))
    }

    fn manifest_path(&self, case_id: &str) -> PathBuf {
        self.artifact_root.join("cases").join(case_id).join("manifest.json")
    }

    fn case_from_manifest(
        &self,
        context: &EvidenceContext,
        manifest: StoredCaseManifest,
    ) -> Result<(Stage1CaseEvidence, Vec<Stage1PerformanceObservation>), EvidenceError> {
        let case_id = manifest.case_id.clone();
        let execution_id = manifest.execution_id.clone();
        let handoff_id = manifest.handoff_id.clone();
        let snapshot_id = manifest.snapshot_id.clone();
        let reference =
            |artifact: StoredArtifact| -> Result<Stage1ArtifactReference, EvidenceError> {
                self.verify_artifact(&artifact)?;
                Ok(Stage1ArtifactReference {
                    uri: artifact.uri,
                    sha256: artifact.sha256,
                    bundle_id: context.bundle_id.clone(),
                    case_id: case_id.clone(),
                    execution_id: execution_id.clone(),
                    handoff_id: handoff_id.clone(),
                    snapshot_id: snapshot_id.clone(),
                    component_sha256: digest_hex(context.component_digest),
                    profile_sha256: digest_hex(context.profile_digest),
                })
            };

        let snapshot = manifest.snapshot.map(&reference).transpose()?;
        let semantic_traces = manifest
            .semantic_traces
            .into_iter()
            .map(reference)
            .collect::<Result<Vec<_>, EvidenceError>>()?;
        let binding_receipts = manifest
            .binding_receipts
            .into_iter()
            .map(|receipt| {
                Ok(Stage1BindingReceiptReference {
                    resource: receipt.resource,
                    receipt_id: receipt.receipt_id,
                    artifact: reference(receipt.artifact)?,
                })
            })
            .collect::<Result<Vec<_>, EvidenceError>>()?;
        let raw_execution = manifest
            .raw_execution
            .into_iter()
            .map(reference)
            .collect::<Result<Vec<_>, EvidenceError>>()?;
        let performance_observations = manifest
            .performance
            .map(|performance| {
                self.verify_artifact(&performance.artifact)?;
                Ok(performance
                    .measurements
                    .into_iter()
                    .map(|measurement| Stage1PerformanceObservation {
                        metric: measurement.metric,
                        unit: performance_unit(measurement.metric),
                        samples: measurement.samples,
                        execution_id: execution_id.clone(),
                        raw_artifact_sha256: performance.artifact.sha256.clone(),
                    })
                    .collect::<Vec<_>>())
            })
            .transpose()?
            .unwrap_or_default();

        let state = Stage1StateEvidence {
            state_sha256: manifest.state_sha256,
            replay_state_sha256: manifest.replay_state_sha256,
            snapshot_sha256: snapshot.as_ref().map(|artifact| artifact.sha256.clone()),
            trace_sha256s: semantic_traces.iter().map(|artifact| artifact.sha256.clone()).collect(),
        };
        Ok((
            Stage1CaseEvidence {
                case_id: manifest.case_id,
                execution_id: manifest.execution_id,
                handoff_id: manifest.handoff_id,
                snapshot_id: manifest.snapshot_id,
                case_config_sha256: manifest.case_config_sha256,
                case_policy_sha256: manifest.case_policy_sha256,
                outcome: manifest.outcome,
                exit_status: manifest.exit_status,
                fault_schedule: manifest.fault_schedule,
                authority: manifest.authority,
                artifacts: Stage1CaseArtifacts {
                    snapshot,
                    semantic_traces,
                    binding_receipts,
                    raw_execution,
                },
                state,
            },
            performance_observations,
        ))
    }

    fn verify_artifact(&self, artifact: &StoredArtifact) -> Result<(), EvidenceError> {
        let relative = Path::new(&artifact.uri);
        if !safe_relative_path(relative) {
            return Err(EvidenceError::invalid(format!(
                "unsafe stored artifact path {}",
                artifact.uri
            )));
        }
        let root = self
            .artifact_root
            .canonicalize()
            .map_err(|error| EvidenceError::io(&self.artifact_root, error))?;
        let path = self.artifact_root.join(relative);
        let resolved = path.canonicalize().map_err(|error| EvidenceError::io(&path, error))?;
        if !resolved.starts_with(&root) || !resolved.is_file() {
            return Err(EvidenceError::invalid(format!(
                "artifact {} is not a regular file under the artifact root",
                artifact.uri
            )));
        }
        let observed = sha256_file(&resolved)?;
        if observed != artifact.sha256 {
            return Err(EvidenceError::conflict(format!(
                "artifact {} digest is {observed}, expected {}",
                artifact.uri, artifact.sha256
            )));
        }
        Ok(())
    }

    fn provenance_artifacts(
        &self,
        context: &EvidenceContext,
    ) -> Result<Stage1ProvenanceArtifacts, EvidenceError> {
        let files = &context.provenance_files;
        Ok(Stage1ProvenanceArtifacts {
            component: self.provenance_reference(&files.component)?,
            profile: self.provenance_reference(&files.profile)?,
            source_manifest: self.provenance_reference(&files.source_manifest)?,
            toolchain: self.provenance_reference(&files.toolchain)?,
            build_source_manifest: self.provenance_reference(&files.build_source_manifest)?,
            build_toolchain: self.provenance_reference(&files.build_toolchain)?,
            executable: self.provenance_reference(&files.executable)?,
            matrix_manifest: self.provenance_reference(&files.matrix_manifest)?,
        })
    }

    fn provenance_reference(
        &self,
        path: &Path,
    ) -> Result<Stage1ProvenanceArtifactReference, EvidenceError> {
        let root = self
            .artifact_root
            .canonicalize()
            .map_err(|error| EvidenceError::io(&self.artifact_root, error))?;
        let candidate =
            if path.is_absolute() { path.to_path_buf() } else { self.artifact_root.join(path) };
        let resolved =
            candidate.canonicalize().map_err(|error| EvidenceError::io(&candidate, error))?;
        if !resolved.starts_with(&root) || !resolved.is_file() {
            return Err(EvidenceError::invalid(format!(
                "provenance artifact {} is not a regular file under the artifact root",
                candidate.display()
            )));
        }
        let relative = resolved.strip_prefix(&root).map_err(|_| {
            EvidenceError::invalid(format!(
                "provenance artifact {} escaped the artifact root",
                candidate.display()
            ))
        })?;
        Ok(Stage1ProvenanceArtifactReference {
            uri: path_to_uri(relative)?,
            sha256: sha256_file(&resolved)?,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredArtifact {
    uri: String,
    sha256: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredBindingReceipt {
    resource: Stage1ResourceKind,
    receipt_id: String,
    artifact: StoredArtifact,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredPerformance {
    measurements: Vec<PerformanceMeasurement>,
    artifact: StoredArtifact,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredCaseManifest {
    schema_version: String,
    bundle_id: String,
    component_sha256: String,
    profile_sha256: String,
    case_id: String,
    case_config_sha256: String,
    case_policy_sha256: String,
    execution_id: String,
    handoff_id: String,
    snapshot_id: String,
    outcome: Stage1CaseOutcome,
    exit_status: i32,
    fault_schedule: Stage1FaultSchedule,
    authority: Stage1AuthorityEvidence,
    state_sha256: String,
    replay_state_sha256: String,
    snapshot: Option<StoredArtifact>,
    semantic_traces: Vec<StoredArtifact>,
    binding_receipts: Vec<StoredBindingReceipt>,
    raw_execution: Vec<StoredArtifact>,
    performance: Option<StoredPerformance>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceErrorKind {
    Io,
    Json,
    InvalidInput,
    Conflict,
    Validation,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceError {
    pub kind: EvidenceErrorKind,
    pub message: String,
}

impl EvidenceError {
    fn io(path: &Path, error: std::io::Error) -> Self {
        Self { kind: EvidenceErrorKind::Io, message: format!("{}: {error}", path.display()) }
    }

    fn json(label: impl fmt::Display, error: serde_json::Error) -> Self {
        Self { kind: EvidenceErrorKind::Json, message: format!("{label}: {error}") }
    }

    fn invalid(message: impl Into<String>) -> Self {
        Self { kind: EvidenceErrorKind::InvalidInput, message: message.into() }
    }

    fn conflict(message: impl Into<String>) -> Self {
        Self { kind: EvidenceErrorKind::Conflict, message: message.into() }
    }

    fn validation(label: &str, findings: &[visa_conformance::Stage1ValidationFinding]) -> Self {
        Self {
            kind: EvidenceErrorKind::Validation,
            message: format!("{label} validation failed: {findings:?}"),
        }
    }
}

impl fmt::Display for EvidenceError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl std::error::Error for EvidenceError {}

pub fn sha256_digest(bytes: &[u8]) -> Digest {
    Digest::from_bytes(Sha256::digest(bytes).into())
}

fn validate_context(context: &EvidenceContext) -> Result<(), EvidenceError> {
    if context.bundle_id.trim().is_empty() {
        return Err(EvidenceError::invalid("bundle_id is empty"));
    }
    if context.started_at_unix_ms == 0
        || context.finished_at_unix_ms == 0
        || context.finished_at_unix_ms < context.started_at_unix_ms
    {
        return Err(EvidenceError::invalid("bundle timestamps are zero or unordered"));
    }
    if context.environment.authority_enforcement.policy_sha256 != digest_hex(context.policy_digest)
    {
        return Err(EvidenceError::invalid(
            "environment authority policy digest does not match the evidence context",
        ));
    }
    Ok(())
}

fn validate_record_set(records: &[CaseExecutionRecord]) -> Result<(), EvidenceError> {
    let mut cases = BTreeSet::new();
    let mut executions = BTreeSet::new();
    let mut handoffs = BTreeSet::new();
    let mut snapshots = BTreeSet::new();
    for record in records {
        validate_record(record)?;
        if !cases.insert(record.case_id.as_str()) {
            return Err(EvidenceError::invalid(format!("duplicate case {}", record.case_id)));
        }
        for (label, inserted) in [
            ("execution", executions.insert(record.execution_id)),
            ("handoff", handoffs.insert(record.handoff_id)),
            ("snapshot", snapshots.insert(record.snapshot_id)),
        ] {
            if !inserted {
                return Err(EvidenceError::invalid(format!(
                    "duplicate {label} identity in {}",
                    record.case_id
                )));
            }
        }
    }
    for required in required_stage1_case_ids() {
        if !cases.contains(required) {
            return Err(EvidenceError::invalid(format!("missing required case {required}")));
        }
    }
    Ok(())
}

fn validate_record(record: &CaseExecutionRecord) -> Result<(), EvidenceError> {
    let definition = stage1_case_definition(&record.case_id)
        .ok_or_else(|| EvidenceError::invalid(format!("unknown case {}", record.case_id)))?;
    if !definition.allowed_outcomes.contains(&record.outcome) {
        return Err(EvidenceError::invalid(format!(
            "outcome {:?} is not allowed for {}",
            record.outcome, record.case_id
        )));
    }
    for (label, identity) in [
        ("execution", record.execution_id),
        ("handoff", record.handoff_id),
        ("snapshot", record.snapshot_id),
    ] {
        if identity.is_zero() {
            return Err(EvidenceError::invalid(format!(
                "{} has a zero {label} identity",
                record.case_id
            )));
        }
    }
    if record.semantic_traces.is_empty() {
        return Err(EvidenceError::invalid(format!(
            "{} has no semantic journal trace",
            record.case_id
        )));
    }
    let mut trace_roles = BTreeSet::new();
    let mut claimed_final = 0_usize;
    for trace in &record.semantic_traces {
        if trace.schema_version != STAGE1_SEMANTIC_TRACE_SCHEMA_VERSION {
            return Err(EvidenceError::invalid(format!(
                "{} has unsupported semantic trace schema {}",
                record.case_id, trace.schema_version
            )));
        }
        if !trace_roles.insert(trace.role) {
            return Err(EvidenceError::invalid(format!(
                "{} has duplicate {:?} semantic traces",
                record.case_id, trace.role
            )));
        }
        claimed_final += usize::from(trace.claimed_final);
    }
    if claimed_final != 1 {
        return Err(EvidenceError::invalid(format!(
            "{} must identify exactly one claimed final semantic trace",
            record.case_id
        )));
    }
    for (label, bytes) in [
        ("source", record.raw_source_json.as_slice()),
        ("destination", record.raw_destination_json.as_slice()),
        ("assertions", record.raw_assertions_json.as_slice()),
    ] {
        validate_json_or_json_lines(bytes).map_err(|error| {
            EvidenceError::json(format_args!("{}.raw_{label}", record.case_id), error)
        })?;
    }
    if stage1_expected_ownership(record.outcome) != Stage1ExpectedOwnership::SourceRetained
        && (record.snapshot_bytes.is_none()
            || record.timer_binding_receipt.is_none()
            || record.key_value_binding_receipt.is_none())
    {
        return Err(EvidenceError::invalid(format!(
            "{} committed without snapshot and both binding receipts",
            record.case_id
        )));
    }
    validate_performance(record)
}

fn validate_json_or_json_lines(bytes: &[u8]) -> Result<(), serde_json::Error> {
    if serde_json::from_slice::<serde_json::Value>(bytes).is_ok() {
        return Ok(());
    }
    let mut lines = bytes.split(|byte| *byte == b'\n').filter(|line| !line.is_empty());
    let Some(first) = lines.next() else {
        return serde_json::from_slice::<serde_json::Value>(bytes).map(|_| ());
    };
    serde_json::from_slice::<serde_json::Value>(first)?;
    for line in lines {
        serde_json::from_slice::<serde_json::Value>(line)?;
    }
    Ok(())
}

fn validate_performance(record: &CaseExecutionRecord) -> Result<(), EvidenceError> {
    if record.case_id != "performance-observations" {
        if !record.performance.is_empty() {
            return Err(EvidenceError::invalid(format!(
                "{} contains performance samples outside the performance case",
                record.case_id
            )));
        }
        return Ok(());
    }
    let mut metrics = BTreeSet::new();
    for measurement in &record.performance {
        if !metrics.insert(measurement.metric) || measurement.samples.is_empty() {
            return Err(EvidenceError::invalid(
                "performance metrics must be unique and contain raw samples",
            ));
        }
        if measurement.metric == Stage1PerformanceMetric::SnapshotSize
            && measurement.samples.contains(&0)
        {
            return Err(EvidenceError::invalid("snapshot size samples must be non-zero"));
        }
    }
    for required in [
        Stage1PerformanceMetric::SteadyStateCost,
        Stage1PerformanceMetric::SnapshotSize,
        Stage1PerformanceMetric::HandoffInterruption,
    ] {
        if !metrics.contains(&required) {
            return Err(EvidenceError::invalid(format!(
                "performance case is missing {required:?} samples"
            )));
        }
    }
    Ok(())
}

fn validate_manifest_context(
    manifest: &StoredCaseManifest,
    context: &EvidenceContext,
    expected_case: &str,
) -> Result<(), EvidenceError> {
    let component = digest_hex(context.component_digest);
    let profile = digest_hex(context.profile_digest);
    let expected = [
        ("schema", CASE_MANIFEST_SCHEMA, manifest.schema_version.as_str()),
        ("bundle", context.bundle_id.as_str(), manifest.bundle_id.as_str()),
        ("case", expected_case, manifest.case_id.as_str()),
        ("component", component.as_str(), manifest.component_sha256.as_str()),
        ("profile", profile.as_str(), manifest.profile_sha256.as_str()),
    ];
    for (label, expected, observed) in expected {
        if expected != observed {
            return Err(EvidenceError::conflict(format!(
                "case manifest {label} is {observed:?}, expected {expected:?}"
            )));
        }
    }
    if manifest.authority.enforcement_policy_sha256 != digest_hex(context.policy_digest) {
        return Err(EvidenceError::conflict(format!(
            "case {} policy digest does not match the evidence context",
            manifest.case_id
        )));
    }
    Ok(())
}

fn performance_unit(metric: Stage1PerformanceMetric) -> Stage1PerformanceUnit {
    match metric {
        Stage1PerformanceMetric::SteadyStateCost | Stage1PerformanceMetric::HandoffInterruption => {
            Stage1PerformanceUnit::Nanoseconds
        }
        Stage1PerformanceMetric::SnapshotSize => Stage1PerformanceUnit::Bytes,
    }
}

fn atomic_replace(path: &Path, bytes: &[u8]) -> Result<(), EvidenceError> {
    let parent = path
        .parent()
        .ok_or_else(|| EvidenceError::invalid(format!("{} has no parent", path.display())))?;
    fs::create_dir_all(parent).map_err(|error| EvidenceError::io(parent, error))?;
    let sequence = NEXT_TEMP_FILE.fetch_add(1, Ordering::Relaxed);
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| EvidenceError::invalid(format!("invalid output path {}", path.display())))?;
    let temporary = parent.join(format!(".{file_name}.tmp-{}-{sequence}", std::process::id()));
    let result = (|| {
        let mut file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&temporary)
            .map_err(|error| EvidenceError::io(&temporary, error))?;
        file.write_all(bytes).map_err(|error| EvidenceError::io(&temporary, error))?;
        file.sync_all().map_err(|error| EvidenceError::io(&temporary, error))?;
        fs::rename(&temporary, path).map_err(|error| EvidenceError::io(path, error))
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

fn sha256_file(path: &Path) -> Result<String, EvidenceError> {
    let mut file = fs::File::open(path).map_err(|error| EvidenceError::io(path, error))?;
    let mut digest = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = file.read(&mut buffer).map_err(|error| EvidenceError::io(path, error))?;
        if read == 0 {
            break;
        }
        digest.update(&buffer[..read]);
    }
    Ok(format!("{:x}", digest.finalize()))
}

fn sha256_hex(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn digest_hex(digest: Digest) -> String {
    bytes_hex(&digest.0)
}

fn digest_from_hex(value: &str) -> Result<Digest, EvidenceError> {
    if value.len() != 64 {
        return Err(EvidenceError::invalid("digest is not 64 hexadecimal characters"));
    }
    let mut bytes = [0_u8; 32];
    let (pairs, remainder) = value.as_bytes().as_chunks::<2>();
    debug_assert!(remainder.is_empty());
    for (index, pair) in pairs.iter().enumerate() {
        bytes[index] = (hex_nibble(pair[0])? << 4) | hex_nibble(pair[1])?;
    }
    Ok(Digest::from_bytes(bytes))
}

fn hex_nibble(byte: u8) -> Result<u8, EvidenceError> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        _ => Err(EvidenceError::invalid("digest contains a non-hexadecimal character")),
    }
}

fn identity_hex(identity: Identity) -> String {
    bytes_hex(&identity.0)
}

fn bytes_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(char::from(HEX[usize::from(byte >> 4)]));
        encoded.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    encoded
}

fn safe_relative_path(path: &Path) -> bool {
    !path.as_os_str().is_empty()
        && !path.is_absolute()
        && path.components().all(|component| matches!(component, Component::Normal(_)))
}

fn path_to_uri(path: &Path) -> Result<String, EvidenceError> {
    if !safe_relative_path(path) {
        return Err(EvidenceError::invalid(format!("unsafe relative path {}", path.display())));
    }
    let mut parts = Vec::new();
    for component in path.components() {
        let Component::Normal(part) = component else {
            return Err(EvidenceError::invalid(format!("unsafe path {}", path.display())));
        };
        parts.push(
            part.to_str().ok_or_else(|| EvidenceError::invalid("artifact path is not UTF-8"))?,
        );
    }
    Ok(parts.join("/"))
}

#[cfg(test)]
mod tests {
    use std::{
        path::Path,
        time::{SystemTime, UNIX_EPOCH},
    };

    use visa_conformance::{
        STAGE1_CASE_DEFINITIONS, Stage1AuthorityEnforcementIdentity, Stage1CaseClass,
        Stage1FaultInjection, Stage1IsaIdentity, Stage1ProviderIdentity, Stage1VersionedIdentity,
    };

    use super::*;
    use crate::fixture::{FixtureSpec, derive_identity};

    struct TestRoot(PathBuf);

    impl TestRoot {
        fn new() -> Self {
            let nonce = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
            Self(
                std::env::temp_dir()
                    .join(format!("visa-system-evidence-{}-{nonce}", std::process::id())),
            )
        }

        fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for TestRoot {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn writes_typed_case_artifacts_and_detects_payload_tampering() {
        let root = TestRoot::new();
        let baseline = FixtureSpec::new("evidence-verification").unwrap();
        let records = records();
        let context = EvidenceContext::from_fixture(
            "stage1-test-bundle",
            1_000,
            2_000,
            environment(),
            &baseline,
            sha256_digest(b"visa-system-source"),
            sha256_digest(b"rustc-test-toolchain"),
            EvidenceProvenanceFiles {
                component: PathBuf::from("provenance/component.wasm"),
                profile: PathBuf::from("provenance/profile.json"),
                source_manifest: PathBuf::from("provenance/source-manifest.json"),
                toolchain: PathBuf::from("provenance/toolchain.txt"),
                build_source_manifest: PathBuf::from("provenance/build-source-manifest.json"),
                build_toolchain: PathBuf::from("provenance/build-toolchain.txt"),
                executable: PathBuf::from("provenance/visa-system-executable"),
                matrix_manifest: PathBuf::from("provenance/matrix.json"),
            },
        )
        .unwrap();
        let writer = EvidenceWriter::new(root.path());

        writer.write_case(&context, &records[0]).unwrap();
        let first_manifest = writer.read_manifest(&records[0].case_id).unwrap();
        let (first, observations) = writer.case_from_manifest(&context, first_manifest).unwrap();
        assert!(observations.is_empty());
        let trace = &first.artifacts.semantic_traces[0];
        assert_eq!(sha256_file(&root.path().join(&trace.uri)).unwrap(), trace.sha256);
        assert_eq!(trace.bundle_id, context.bundle_id);
        assert_eq!(trace.case_id, first.case_id);
        assert_eq!(trace.execution_id, first.execution_id);
        assert_eq!(trace.handoff_id, first.handoff_id);
        assert_eq!(trace.snapshot_id, first.snapshot_id);
        let first_manifest = writer.read_manifest(&first.case_id).unwrap();
        assert_eq!(first_manifest.case_config_sha256, digest_hex(records[0].case_config_digest));
        assert_eq!(first_manifest.case_policy_sha256, digest_hex(records[0].case_policy_digest));
        assert_eq!(
            fs::read(root.path().join(&first.artifacts.raw_execution[0].uri)).unwrap(),
            records[0].raw_source_json
        );

        fs::write(root.path().join(&trace.uri), b"tampered").unwrap();
        let manifest = writer.read_manifest(&first.case_id).unwrap();
        let error = writer.case_from_manifest(&context, manifest).unwrap_err();
        assert_eq!(error.kind, EvidenceErrorKind::Conflict);
    }

    fn records() -> Vec<CaseExecutionRecord> {
        STAGE1_CASE_DEFINITIONS
            .iter()
            .map(|definition| {
                let fixture = FixtureSpec::new(definition.id).unwrap();
                let outcome = definition.allowed_outcomes[0];
                let committed =
                    stage1_expected_ownership(outcome) != Stage1ExpectedOwnership::SourceRetained;
                let state_digest = canonical_digest(&fixture.source_state).unwrap();
                let raw_transcript = |role: &str| {
                    format!(
                        "{{\"case_id\":\"{}\",\"role\":\"{role}\",\"pid\":100}}\n\
                         {{\"request_id\":\"{}-{role}-1\",\"status\":\"observed\"}}\n",
                        definition.id, definition.id
                    )
                    .into_bytes()
                };
                let receipt = |role: &str| {
                    serde_json::to_vec(&serde_json::json!({
                        "case_id": definition.id,
                        "role": role,
                        "observed": true
                    }))
                    .unwrap()
                };
                CaseExecutionRecord {
                    case_id: definition.id.to_owned(),
                    case_config_digest: fixture.config_digest().unwrap(),
                    case_policy_digest: fixture.policy_digest().unwrap(),
                    execution_id: derive_identity(definition.id, "execution"),
                    handoff_id: fixture.ids.handoff,
                    snapshot_id: fixture.ids.snapshot,
                    outcome,
                    exit_status: 0,
                    fault_schedule: Stage1FaultSchedule {
                        schedule_id: if definition.class == Stage1CaseClass::FailureRecovery {
                            format!("inject-{}", definition.id)
                        } else {
                            "none".to_owned()
                        },
                        injections: if definition.class == Stage1CaseClass::FailureRecovery {
                            vec![Stage1FaultInjection {
                                transition: definition.id.to_owned(),
                                action: "inject-required-condition".to_owned(),
                            }]
                        } else {
                            Vec::new()
                        },
                    },
                    authority: authority(outcome, &fixture),
                    snapshot_bytes: committed
                        .then(|| format!("snapshot:{}", definition.id).into_bytes()),
                    semantic_traces: vec![Stage1SemanticTraceArtifact {
                        schema_version: STAGE1_SEMANTIC_TRACE_SCHEMA_VERSION.to_owned(),
                        role: Stage1TraceRole::Source,
                        scope: visa_conformance::Stage1JournalScope {
                            node: fixture.config_digest_input.source_scope.node,
                            component: fixture.config_digest_input.source_scope.component,
                        },
                        base_cursor: contract_core::JournalPosition::ORIGIN,
                        base_state: fixture.source_state.clone(),
                        entries: Vec::new(),
                        final_state: fixture.source_state.clone(),
                        claimed_final: true,
                    }],
                    timer_binding_receipt: committed.then(|| BindingReceiptArtifact {
                        receipt_id: derive_identity(definition.id, "timer-receipt"),
                        bytes: receipt("timer-receipt"),
                    }),
                    key_value_binding_receipt: committed.then(|| BindingReceiptArtifact {
                        receipt_id: derive_identity(definition.id, "key-value-receipt"),
                        bytes: receipt("key-value-receipt"),
                    }),
                    raw_source_json: raw_transcript("source"),
                    raw_destination_json: raw_transcript("destination"),
                    raw_assertions_json: receipt("assertions"),
                    state_digest,
                    replay_state_digest: state_digest,
                    performance: if definition.id == "performance-observations" {
                        vec![
                            PerformanceMeasurement {
                                metric: Stage1PerformanceMetric::SteadyStateCost,
                                samples: vec![100, 110],
                            },
                            PerformanceMeasurement {
                                metric: Stage1PerformanceMetric::SnapshotSize,
                                samples: vec![4096],
                            },
                            PerformanceMeasurement {
                                metric: Stage1PerformanceMetric::HandoffInterruption,
                                samples: vec![1_000_000],
                            },
                        ]
                    } else {
                        Vec::new()
                    },
                }
            })
            .collect()
    }

    fn authority(outcome: Stage1CaseOutcome, fixture: &FixtureSpec) -> CaseAuthorityRecord {
        let source = canonical_digest(&fixture.policy_digest_input.source_roots).unwrap();
        let destination = canonical_digest(&[
            fixture.handoff_authority,
            fixture.timer_authority,
            fixture.key_value_authority,
        ])
        .unwrap();
        match stage1_expected_ownership(outcome) {
            Stage1ExpectedOwnership::SourceRetained => CaseAuthorityRecord {
                source_authority_root: source,
                destination_authority_root: destination,
                source_lease_epoch: LeaseEpoch(1),
                destination_lease_epoch: None,
                fencing_epoch: LeaseEpoch(1),
                ownership: Stage1OwnershipStatus::SourceActive,
                source_fenced: false,
            },
            Stage1ExpectedOwnership::DestinationCommitted => CaseAuthorityRecord {
                source_authority_root: source,
                destination_authority_root: destination,
                source_lease_epoch: LeaseEpoch(1),
                destination_lease_epoch: Some(LeaseEpoch(2)),
                fencing_epoch: LeaseEpoch(2),
                ownership: Stage1OwnershipStatus::DestinationActive,
                source_fenced: true,
            },
            Stage1ExpectedOwnership::DestinationRecoveryRequired => CaseAuthorityRecord {
                source_authority_root: source,
                destination_authority_root: destination,
                source_lease_epoch: LeaseEpoch(1),
                destination_lease_epoch: Some(LeaseEpoch(2)),
                fencing_epoch: LeaseEpoch(2),
                ownership: Stage1OwnershipStatus::DestinationRecoveryRequired,
                source_fenced: true,
            },
        }
    }

    fn environment() -> Stage1ExecutionEnvironment {
        let versioned = |name: &str, version: &str| Stage1VersionedIdentity {
            name: name.to_owned(),
            version: version.to_owned(),
        };
        Stage1ExecutionEnvironment {
            carrier: versioned("wasm-component-model", "0.1"),
            source_runtime: versioned("wasmtime", "43.0.2"),
            destination_runtime: versioned("wasmtime", "43.0.2"),
            source_isa: Stage1IsaIdentity {
                architecture: std::env::consts::ARCH.to_owned(),
                abi: std::env::consts::OS.to_owned(),
            },
            destination_isa: Stage1IsaIdentity {
                architecture: std::env::consts::ARCH.to_owned(),
                abi: std::env::consts::OS.to_owned(),
            },
            substrate: versioned("isolated-host-process", "1"),
            provider: Stage1ProviderIdentity {
                implementation: versioned("sqlite", "3"),
                durable: true,
                mock: false,
            },
            authority_enforcement: Stage1AuthorityEnforcementIdentity {
                implementation: versioned("visa-authority-and-lease", "1"),
                policy_sha256: String::new(),
            },
            resource_profiles: Vec::new(),
        }
    }
}
