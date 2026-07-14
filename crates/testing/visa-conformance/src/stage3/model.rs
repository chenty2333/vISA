use serde::{Deserialize, Serialize};

pub const STAGE3A_EVIDENCE_FILE: &str = "stage3a-evidence.json";
pub const STAGE3B_EVIDENCE_FILE: &str = "stage3b-evidence.json";
pub const STAGE3A_EVIDENCE_SCHEMA_VERSION: &str = "visa-stage3a-evidence-v1";
pub const STAGE3B_EVIDENCE_SCHEMA_VERSION: &str = "visa-stage3b-evidence-v1";
pub const STAGE3A_CLAIM_ID: &str = "bounded-regular-file-continuity";
pub const STAGE3B_CLAIM_ID: &str = "bounded-logical-request-continuity";
pub const STAGE3_INCOMPLETE_MARKER_FILE: &str = "stage3-incomplete";
pub const STAGE3_INCOMPLETE_MARKER_CONTENT: &[u8] = b"stage3 evidence publication incomplete\n";

// Updated only by an explicit registry review. The verifier also recomputes
// the current catalog and requires it to match this lock.
pub const STAGE3A_ACCEPTED_REGISTRY_SHA256: &str =
    "3f7d41d91eaedb2db87ec4f2be54eae7e47ac82bebd6e5cff8816ff205edcd71";
pub const STAGE3B_ACCEPTED_REGISTRY_SHA256: &str =
    "eedb87e7a99aa3a67ccabad521f7066d5dae78952f771a189cd1592f759607e3";

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Stage3Profile {
    RegularFile,
    LogicalRequest,
}

impl Stage3Profile {
    pub const fn schema_version(self) -> &'static str {
        match self {
            Self::RegularFile => STAGE3A_EVIDENCE_SCHEMA_VERSION,
            Self::LogicalRequest => STAGE3B_EVIDENCE_SCHEMA_VERSION,
        }
    }

    pub const fn claim_id(self) -> &'static str {
        match self {
            Self::RegularFile => STAGE3A_CLAIM_ID,
            Self::LogicalRequest => STAGE3B_CLAIM_ID,
        }
    }

    pub const fn accepted_registry_sha256(self) -> &'static str {
        match self {
            Self::RegularFile => STAGE3A_ACCEPTED_REGISTRY_SHA256,
            Self::LogicalRequest => STAGE3B_ACCEPTED_REGISTRY_SHA256,
        }
    }

    pub const fn evidence_file(self) -> &'static str {
        match self {
            Self::RegularFile => STAGE3A_EVIDENCE_FILE,
            Self::LogicalRequest => STAGE3B_EVIDENCE_FILE,
        }
    }

    pub const fn cases(self) -> &'static [Stage3CaseDefinition] {
        match self {
            Self::RegularFile => STAGE3A_CASE_DEFINITIONS,
            Self::LogicalRequest => STAGE3B_CASE_DEFINITIONS,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Stage3CaseDefinition {
    pub id: &'static str,
    pub terminal: Stage3CaseTerminal,
    pub required_assertions: &'static [&'static str],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Stage3CaseTerminal {
    HandoffCommitted,
    HandoffBlocked,
    ProfileRejected,
}

pub const STAGE3A_CASE_DEFINITIONS: &[Stage3CaseDefinition] = &[
    Stage3CaseDefinition {
        id: "read-write-offset",
        terminal: Stage3CaseTerminal::HandoffCommitted,
        required_assertions: &[
            "transient_observe_retried",
            "bytes_preserved",
            "logical_offset_preserved",
            "write_once",
        ],
    },
    Stage3CaseDefinition {
        id: "append-continuity",
        terminal: Stage3CaseTerminal::HandoffCommitted,
        required_assertions: &["append_once", "size_preserved", "digest_preserved"],
    },
    Stage3CaseDefinition {
        id: "truncate-version",
        terminal: Stage3CaseTerminal::HandoffCommitted,
        required_assertions: &["size_preserved", "version_advanced", "digest_preserved"],
    },
    Stage3CaseDefinition {
        id: "rename-object-identity",
        terminal: Stage3CaseTerminal::HandoffCommitted,
        required_assertions: &[
            "path_rebound",
            "object_identity_preserved",
            "existing_target_preserved",
            "old_path_absent",
        ],
    },
    Stage3CaseDefinition {
        id: "replacement-rejected",
        terminal: Stage3CaseTerminal::ProfileRejected,
        required_assertions: &["replacement_detected", "same_content_not_accepted"],
    },
    Stage3CaseDefinition {
        id: "external-mutation-rejected",
        terminal: Stage3CaseTerminal::ProfileRejected,
        required_assertions: &["version_conflict_detected", "canonical_state_unchanged"],
    },
    Stage3CaseDefinition {
        id: "lock-conflict",
        terminal: Stage3CaseTerminal::HandoffCommitted,
        required_assertions: &[
            "exclusive_lock_enforced",
            "lock_not_snapshotted_live",
            "reacquired",
        ],
    },
    Stage3CaseDefinition {
        id: "durability-reconciled",
        terminal: Stage3CaseTerminal::HandoffCommitted,
        required_assertions: &["durability_met", "lost_ack_reconciled", "mutation_not_repeated"],
    },
    Stage3CaseDefinition {
        id: "stale-source-fenced",
        terminal: Stage3CaseTerminal::HandoffCommitted,
        required_assertions: &[
            "destination_epoch_advanced",
            "source_write_denied",
            "destination_write_succeeded",
        ],
    },
    Stage3CaseDefinition {
        id: "cleanup-idempotent",
        terminal: Stage3CaseTerminal::HandoffCommitted,
        required_assertions: &["cleanup_repeated", "operation_truth_retained"],
    },
    Stage3CaseDefinition {
        id: "indeterminate-write-blocks-handoff",
        terminal: Stage3CaseTerminal::HandoffBlocked,
        required_assertions: &["unknown_outcome_recorded", "freeze_rejected", "no_lease_transfer"],
    },
    Stage3CaseDefinition {
        id: "destination-reauthorization-denied",
        terminal: Stage3CaseTerminal::HandoffBlocked,
        required_assertions: &[
            "destination_policy_denied",
            "binding_not_published",
            "source_lease_retained",
        ],
    },
];

pub const STAGE3B_CASE_DEFINITIONS: &[Stage3CaseDefinition] = &[
    Stage3CaseDefinition {
        id: "completed-before-freeze",
        terminal: Stage3CaseTerminal::HandoffCommitted,
        required_assertions: &["response_preserved", "completion_not_replayed"],
    },
    Stage3CaseDefinition {
        id: "pending-before-send",
        terminal: Stage3CaseTerminal::HandoffCommitted,
        required_assertions: &["pending_state_preserved", "send_after_restore"],
    },
    Stage3CaseDefinition {
        id: "lost-ack-deduplicated",
        terminal: Stage3CaseTerminal::HandoffCommitted,
        required_assertions: &["operation_id_preserved", "request_applied_once", "ack_reconciled"],
    },
    Stage3CaseDefinition {
        id: "unknown-completion-reconciled",
        terminal: Stage3CaseTerminal::HandoffCommitted,
        required_assertions: &[
            "unknown_state_preserved",
            "provider_truth_queried",
            "no_unsafe_replay",
        ],
    },
    Stage3CaseDefinition {
        id: "partial-response-resumed",
        terminal: Stage3CaseTerminal::HandoffCommitted,
        required_assertions: &[
            "transient_observe_retried",
            "cursor_preserved",
            "bytes_not_duplicated",
            "response_digest_matched",
        ],
    },
    Stage3CaseDefinition {
        id: "timeout",
        terminal: Stage3CaseTerminal::HandoffCommitted,
        required_assertions: &[
            "read_timeout_became_unknown",
            "late_completion_reconciled",
            "request_not_replayed",
        ],
    },
    Stage3CaseDefinition {
        id: "cancel-completion-race",
        terminal: Stage3CaseTerminal::HandoffCommitted,
        required_assertions: &["single_terminal_outcome", "race_reconciled"],
    },
    Stage3CaseDefinition {
        id: "peer-mismatch",
        terminal: Stage3CaseTerminal::ProfileRejected,
        required_assertions: &["peer_identity_checked", "request_not_sent"],
    },
    Stage3CaseDefinition {
        id: "credential-reacquired",
        terminal: Stage3CaseTerminal::HandoffCommitted,
        required_assertions: &[
            "credential_reference_preserved",
            "credential_bytes_absent",
            "destination_credential_used",
        ],
    },
    Stage3CaseDefinition {
        id: "credential-denied",
        terminal: Stage3CaseTerminal::ProfileRejected,
        required_assertions: &["credential_denial_preserved", "secret_not_exposed"],
    },
    Stage3CaseDefinition {
        id: "non-idempotent-unknown-blocked",
        terminal: Stage3CaseTerminal::HandoffBlocked,
        required_assertions: &["unsafe_replay_rejected", "request_not_repeated"],
    },
    Stage3CaseDefinition {
        id: "raw-live-tcp-rejected",
        terminal: Stage3CaseTerminal::ProfileRejected,
        required_assertions: &["unsupported_transport_explicit", "socket_state_absent"],
    },
    Stage3CaseDefinition {
        id: "stale-source-fenced",
        terminal: Stage3CaseTerminal::HandoffCommitted,
        required_assertions: &[
            "destination_epoch_advanced",
            "source_request_denied",
            "destination_request_succeeded",
        ],
    },
    Stage3CaseDefinition {
        id: "cleanup-idempotent",
        terminal: Stage3CaseTerminal::HandoffCommitted,
        required_assertions: &["cleanup_repeated", "dedup_truth_retained"],
    },
];

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Stage3ArtifactReference {
    pub uri: String,
    pub sha256: String,
    pub size: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Stage3RuntimeIdentity {
    pub implementation: String,
    pub implementation_version: String,
    pub engine: String,
    pub engine_version: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Stage3RuntimeScope {
    pub source: Stage3RuntimeIdentity,
    pub destination: Stage3RuntimeIdentity,
    pub host_os: String,
    pub source_isa: String,
    pub destination_isa: String,
    pub substrate: String,
    pub execution_boundary: String,
    pub independent_runtime_coverage: bool,
    pub unsupported_runtime_implementations: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Stage3Assertion {
    pub name: String,
    pub passed: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Stage3CaseEvidence {
    pub case_id: String,
    pub terminal: Stage3CaseTerminal,
    pub passed: bool,
    pub assertions: Vec<Stage3Assertion>,
    pub canonical_before_sha256: String,
    pub canonical_after_sha256: String,
    pub source_epoch: u64,
    pub destination_epoch: Option<u64>,
    pub profile_operations: Vec<String>,
    pub artifacts: Vec<Stage3ArtifactReference>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Stage3EvidenceBundle {
    pub schema_version: String,
    pub profile: Stage3Profile,
    pub claim_id: String,
    pub bundle_id: String,
    pub started_at_unix_ms: u64,
    pub finished_at_unix_ms: u64,
    pub registry_sha256: String,
    pub component: Stage3ArtifactReference,
    pub wit_world: Stage3ArtifactReference,
    pub profile_manifest: Stage3ArtifactReference,
    pub configuration: Stage3ArtifactReference,
    pub runtime: Stage3RuntimeScope,
    pub cases: Vec<Stage3CaseEvidence>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Stage3ValidationFinding {
    pub code: String,
    pub detail: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Stage3ValidationReport {
    pub ok: bool,
    pub findings: Vec<Stage3ValidationFinding>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Stage3EvidenceLoadError {
    pub code: String,
    pub detail: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Stage3EvidenceGateResult {
    pub ok: bool,
    pub load_error: Option<Stage3EvidenceLoadError>,
    pub validation: Option<Stage3ValidationReport>,
}
