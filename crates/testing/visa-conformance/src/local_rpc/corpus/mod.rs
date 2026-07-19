mod agent_control;
mod fixtures;
mod model;
mod nexus_adapter;
mod ownership;

use std::{
    fs,
    path::{Path, PathBuf},
};

pub use model::{GoldenCase, GoldenCorpus, NegativeCase, TypeCoverage, WireDirection};
use serde_json_canonicalizer::to_vec as to_jcs_vec;
use sha2::{Digest as _, Sha256};

pub const AGENT_CONTROL_CORPUS_PATH: &str =
    "schemas/local-rpc/visa-agent-control-v1.golden-corpus.json";
pub const OWNERSHIP_CORPUS_PATH: &str =
    "schemas/local-rpc/visa-ownership-local-v1.golden-corpus.json";
pub const NEXUS_ADAPTER_CORPUS_PATH: &str =
    "schemas/local-rpc/visa-nexus-adapter-local-v1.golden-corpus.json";
pub const MAX_GOLDEN_CORPUS_BYTES: usize = 4 * 1024 * 1024;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GeneratedGoldenCorpus {
    pub path: &'static str,
    pub corpus_id: String,
    pub bytes: Vec<u8>,
    pub sha256: String,
}

#[derive(Debug)]
pub enum GoldenCorpusError {
    Json(serde_json::Error),
    Io { path: PathBuf, source: std::io::Error },
    TooLarge { corpus_id: String },
    NonCanonical { corpus_id: String },
    ContentDrift { corpus_id: String },
    Contract(String),
}

impl std::fmt::Display for GoldenCorpusError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Json(source) => write!(formatter, "golden-corpus JSON is invalid: {source}"),
            Self::Io { path, source } => {
                write!(formatter, "cannot access golden corpus {}: {source}", path.display())
            }
            Self::TooLarge { corpus_id } => {
                write!(formatter, "{corpus_id} exceeds the golden-corpus input limit")
            }
            Self::NonCanonical { corpus_id } => {
                write!(formatter, "{corpus_id} is not exact RFC 8785 JCS bytes")
            }
            Self::ContentDrift { corpus_id } => {
                write!(formatter, "{corpus_id} differs from its Rust-constructed corpus")
            }
            Self::Contract(detail) => formatter.write_str(detail),
        }
    }
}

impl std::error::Error for GoldenCorpusError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Json(source) => Some(source),
            Self::Io { source, .. } => Some(source),
            Self::TooLarge { .. }
            | Self::NonCanonical { .. }
            | Self::ContentDrift { .. }
            | Self::Contract(_) => None,
        }
    }
}

impl From<serde_json::Error> for GoldenCorpusError {
    fn from(source: serde_json::Error) -> Self {
        Self::Json(source)
    }
}

pub fn generated_golden_corpora() -> Result<Vec<GeneratedGoldenCorpus>, GoldenCorpusError> {
    [
        (AGENT_CONTROL_CORPUS_PATH, agent_control::build()?),
        (OWNERSHIP_CORPUS_PATH, ownership::build()?),
        (NEXUS_ADAPTER_CORPUS_PATH, nexus_adapter::build()?),
    ]
    .into_iter()
    .map(|(path, corpus)| generate(path, corpus))
    .collect()
}

pub fn verify_golden_corpus_bytes(
    bytes: &[u8],
    expected: &GoldenCorpus,
) -> Result<(), GoldenCorpusError> {
    if bytes.len() > MAX_GOLDEN_CORPUS_BYTES {
        return Err(GoldenCorpusError::TooLarge { corpus_id: expected.corpus_id.clone() });
    }
    let parsed: GoldenCorpus = serde_json::from_slice(bytes)?;
    if &parsed != expected {
        return Err(GoldenCorpusError::ContentDrift { corpus_id: expected.corpus_id.clone() });
    }
    if to_jcs_vec(&parsed)? != bytes {
        return Err(GoldenCorpusError::NonCanonical { corpus_id: expected.corpus_id.clone() });
    }
    Ok(())
}

pub fn verify_checked_in_golden_corpora(root: &Path) -> Result<(), GoldenCorpusError> {
    for generated in generated_golden_corpora()? {
        let path = root.join(generated.path);
        let bytes = fs::read(&path)
            .map_err(|source| GoldenCorpusError::Io { path: path.clone(), source })?;
        let expected = corpus_for_path(generated.path)?;
        verify_golden_corpus_bytes(&bytes, &expected)?;
        if bytes != generated.bytes {
            return Err(GoldenCorpusError::ContentDrift { corpus_id: generated.corpus_id });
        }
    }
    verify_executable_negative_contracts()
}

pub fn write_golden_corpora(root: &Path) -> Result<Vec<GeneratedGoldenCorpus>, GoldenCorpusError> {
    let generated = generated_golden_corpora()?;
    for artifact in &generated {
        let path = root.join(artifact.path);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)
                .map_err(|source| GoldenCorpusError::Io { path: parent.to_path_buf(), source })?;
        }
        fs::write(&path, &artifact.bytes)
            .map_err(|source| GoldenCorpusError::Io { path, source })?;
    }
    Ok(generated)
}

pub fn verify_executable_negative_contracts() -> Result<(), GoldenCorpusError> {
    verify_receipt_carrier_contracts()?;
    agent_control::verify_negative_contracts()?;
    ownership::verify_negative_contracts()?;
    nexus_adapter::verify_negative_contracts()
}

fn verify_receipt_carrier_contracts() -> Result<(), GoldenCorpusError> {
    use visa_local_rpc::{
        WireValidation,
        common::{ReceiptKindWire, WireValidationError},
    };

    for (index, kind) in fixtures::all_receipt_kinds().into_iter().enumerate() {
        let artifact = fixtures::receipt(kind, 50_000 + index as u128);
        artifact.validate().map_err(|error| {
            GoldenCorpusError::Contract(format!(
                "self-consistent {kind:?} receipt carrier failed validation: {error:?}"
            ))
        })?;

        let mut digest_mismatch = artifact.clone();
        digest_mismatch.reference.digest = fixtures::digest("wrong-receipt-reference");
        if digest_mismatch.validate() != Err(WireValidationError::InvalidDigest) {
            return Err(GoldenCorpusError::Contract(format!(
                "{kind:?} receipt carrier accepted a reference/payload digest mismatch"
            )));
        }

        let substitute = match kind {
            ReceiptKindWire::PrepareIntent => ReceiptKindWire::VisaFreeze,
            _ => ReceiptKindWire::PrepareIntent,
        };
        let mut schema_substitution = artifact.clone();
        schema_substitution.payload.schema = substitute.payload_schema();
        if schema_substitution.validate() != Err(WireValidationError::UnsupportedVersion) {
            return Err(GoldenCorpusError::Contract(format!(
                "{kind:?} receipt carrier accepted another kind's payload schema"
            )));
        }

        let mut kind_substitution = artifact;
        kind_substitution.reference.kind = substitute;
        if kind_substitution.validate() != Err(WireValidationError::UnsupportedVersion) {
            return Err(GoldenCorpusError::Contract(format!(
                "{kind:?} receipt carrier accepted a substituted reference kind"
            )));
        }
    }
    Ok(())
}

fn corpus_for_path(path: &str) -> Result<GoldenCorpus, GoldenCorpusError> {
    match path {
        AGENT_CONTROL_CORPUS_PATH => agent_control::build(),
        OWNERSHIP_CORPUS_PATH => ownership::build(),
        NEXUS_ADAPTER_CORPUS_PATH => nexus_adapter::build(),
        _ => Err(GoldenCorpusError::Contract(format!("unknown local RPC corpus path: {path}"))),
    }
}

fn generate(
    path: &'static str,
    corpus: GoldenCorpus,
) -> Result<GeneratedGoldenCorpus, GoldenCorpusError> {
    corpus.validate()?;
    let bytes = to_jcs_vec(&corpus)?;
    if bytes.len() > MAX_GOLDEN_CORPUS_BYTES {
        return Err(GoldenCorpusError::TooLarge { corpus_id: corpus.corpus_id });
    }
    let sha256 = hex_digest(&bytes);
    Ok(GeneratedGoldenCorpus { path, corpus_id: corpus.corpus_id, bytes, sha256 })
}

fn hex_digest(bytes: &[u8]) -> String {
    use core::fmt::Write as _;

    let digest = Sha256::digest(bytes);
    let mut output = String::with_capacity(digest.len() * 2);
    for byte in digest {
        write!(&mut output, "{byte:02x}").expect("writing to String is infallible");
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_corpora_are_independent_canonical_and_executable() {
        let corpora = generated_golden_corpora().expect("corpus generation must succeed");
        assert_eq!(corpora.len(), 3);
        let mut paths = std::collections::BTreeSet::new();
        let mut ids = std::collections::BTreeSet::new();
        let mut digests = std::collections::BTreeSet::new();
        for generated in corpora {
            assert!(paths.insert(generated.path));
            assert!(ids.insert(generated.corpus_id));
            assert!(digests.insert(generated.sha256));
            let expected = corpus_for_path(generated.path).expect("known corpus path");
            verify_golden_corpus_bytes(&generated.bytes, &expected)
                .expect("generated corpus must verify");
        }
        verify_executable_negative_contracts().expect("negative contracts must execute");
    }

    #[test]
    fn neutral_joint_wire_tags_shapes_and_receipt_digest_remain_exact() {
        use contract_core::{EntityRef, Generation, Identity, LeaseEpoch, NodeIdentity};
        use joint_handoff_core::{
            JointHandoffKey, JointProtocolVersion, ReceiptKind, ReceiptRef, receipt_digest,
        };
        use visa_local_rpc::common::{
            ContinuityUnitId, EntityRefWire, HandoffId, IssuerId, IssuerKeyId, IssuerLogId,
            JointHandoffKeyWire, NodeId, ReceiptKindWire, ReceiptRefWire, ServiceIncarnation,
            Sha256Digest, joint_receipt_digest,
        };

        let pairs = [
            (ReceiptKindWire::PrepareIntent, ReceiptKind::PrepareIntent),
            (ReceiptKindWire::VisaFreeze, ReceiptKind::VisaFreeze),
            (ReceiptKindWire::NexusFreeze, ReceiptKind::NexusFreeze),
            (ReceiptKindWire::DestinationPrepared, ReceiptKind::DestinationPrepared),
            (ReceiptKindWire::OwnershipPrepared, ReceiptKind::OwnershipPrepared),
            (ReceiptKindWire::OwnershipAbort, ReceiptKind::OwnershipAbort),
            (ReceiptKindWire::OwnershipCommit, ReceiptKind::OwnershipCommit),
            (ReceiptKindWire::NexusThaw, ReceiptKind::NexusThaw),
            (ReceiptKindWire::ClosureProgress, ReceiptKind::ClosureProgress),
            (ReceiptKindWire::Closure, ReceiptKind::Closure),
            (ReceiptKindWire::RetainedTombstone, ReceiptKind::RetainedTombstone),
            (ReceiptKindWire::VisaSourceFence, ReceiptKind::VisaSourceFence),
            (ReceiptKindWire::VisaSourceResume, ReceiptKind::VisaSourceResume),
            (ReceiptKindWire::VisaDestinationActivation, ReceiptKind::VisaDestinationActivation),
        ];
        let receipt_value = b"typed-neutral-receipt-parity-vector".as_slice();
        let receipt_bytes = postcard::to_allocvec(receipt_value).unwrap();
        for (local, neutral) in pairs {
            assert_eq!(
                postcard::to_allocvec(&local).unwrap(),
                postcard::to_allocvec(&neutral).unwrap()
            );
            assert_eq!(local.neutral_tag(), postcard::to_allocvec(&neutral).unwrap()[0]);
            assert_eq!(
                joint_receipt_digest(local, &receipt_bytes).0,
                receipt_digest(neutral, receipt_value).unwrap().0
            );
        }

        let local_key = JointHandoffKeyWire {
            continuity_unit: EntityRefWire {
                identity: ContinuityUnitId::from_u128(1),
                generation: 2,
            },
            handoff: HandoffId::from_u128(3),
            source: NodeId::from_u128(4),
            destination: NodeId::from_u128(5),
            expected_epoch: 6,
            next_epoch: 7,
        };
        let neutral_key = JointHandoffKey {
            continuity_unit: EntityRef::new(Identity::from_u128(1), Generation(2)),
            handoff: Identity::from_u128(3),
            source: NodeIdentity::new(Identity::from_u128(4)),
            destination: NodeIdentity::new(Identity::from_u128(5)),
            expected_epoch: LeaseEpoch(6),
            next_epoch: LeaseEpoch(7),
        };
        assert_eq!(
            postcard::to_allocvec(&local_key).unwrap(),
            postcard::to_allocvec(&neutral_key).unwrap()
        );

        let local_reference = ReceiptRefWire {
            protocol_major: 1,
            protocol_minor: 0,
            kind: ReceiptKindWire::OwnershipCommit,
            handoff: HandoffId::from_u128(8),
            issuer: IssuerId::from_u128(9),
            issuer_incarnation: ServiceIncarnation::from_u128(10),
            key_id: IssuerKeyId::from_u128(11),
            log_id: IssuerLogId::from_u128(12),
            sequence: 13,
            digest: Sha256Digest::of(b"reference"),
        };
        let neutral_reference = ReceiptRef {
            version: JointProtocolVersion::new(1, 0),
            kind: ReceiptKind::OwnershipCommit,
            handoff: Identity::from_u128(8),
            issuer: Identity::from_u128(9),
            issuer_incarnation: Identity::from_u128(10),
            key_id: Identity::from_u128(11),
            log_id: Identity::from_u128(12),
            sequence: 13,
            digest: contract_core::Digest::from_bytes(local_reference.digest.0),
        };
        assert_eq!(
            postcard::to_allocvec(&local_reference).unwrap(),
            postcard::to_allocvec(&neutral_reference).unwrap()
        );
    }
}
