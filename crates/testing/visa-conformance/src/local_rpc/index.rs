use std::{
    fs,
    path::{Path, PathBuf},
};

use serde::{Deserialize, Serialize};
use serde_json_canonicalizer::to_vec as to_jcs_vec;
use sha2::{Digest as _, Sha256};

use super::{
    GeneratedGoldenCorpus, GeneratedOwnedSchema, GoldenCorpusError, OwnedSchemaError,
    generated_golden_corpora, generated_owned_schemas,
};

pub const LOCAL_RPC_INDEX_PATH: &str = "schemas/local-rpc/index.json";
pub const LOCAL_RPC_INDEX_SCHEMA: &str = "visa.local-rpc-artifact-index.v1";
pub const MAX_LOCAL_RPC_INDEX_BYTES: usize = 1024 * 1024;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LocalRpcArtifactIndex {
    pub schema: String,
    pub status: String,
    pub product_version: String,
    pub canonical_encoding: String,
    pub schema_reflection: String,
    pub canonical_json: String,
    pub artifacts: Vec<LocalRpcArtifactEntry>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LocalRpcArtifactEntry {
    pub artifact_id: String,
    pub kind: String,
    pub rpc_schema: String,
    pub path: String,
    pub byte_length: u32,
    pub sha256: String,
    pub readiness_id: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GeneratedLocalRpcIndex {
    pub bytes: Vec<u8>,
    pub sha256: String,
}

#[derive(Debug)]
pub enum LocalRpcIndexError {
    Schema(OwnedSchemaError),
    Corpus(GoldenCorpusError),
    Json(serde_json::Error),
    Io { path: PathBuf, source: std::io::Error },
    TooLarge,
    ContentDrift,
    Invalid(String),
}

impl std::fmt::Display for LocalRpcIndexError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Schema(source) => write!(formatter, "cannot generate owned schemas: {source}"),
            Self::Corpus(source) => write!(formatter, "cannot generate golden corpora: {source}"),
            Self::Json(source) => write!(formatter, "local RPC index JSON is invalid: {source}"),
            Self::Io { path, source } => {
                write!(formatter, "cannot access local RPC index {}: {source}", path.display())
            }
            Self::TooLarge => formatter.write_str("local RPC index exceeds its input limit"),
            Self::ContentDrift => {
                formatter.write_str("local RPC index is noncanonical or differs from its inputs")
            }
            Self::Invalid(detail) => formatter.write_str(detail),
        }
    }
}

impl std::error::Error for LocalRpcIndexError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Schema(source) => Some(source),
            Self::Corpus(source) => Some(source),
            Self::Json(source) => Some(source),
            Self::Io { source, .. } => Some(source),
            Self::TooLarge | Self::ContentDrift | Self::Invalid(_) => None,
        }
    }
}

impl From<OwnedSchemaError> for LocalRpcIndexError {
    fn from(source: OwnedSchemaError) -> Self {
        Self::Schema(source)
    }
}

impl From<GoldenCorpusError> for LocalRpcIndexError {
    fn from(source: GoldenCorpusError) -> Self {
        Self::Corpus(source)
    }
}

impl From<serde_json::Error> for LocalRpcIndexError {
    fn from(source: serde_json::Error) -> Self {
        Self::Json(source)
    }
}

pub fn generated_local_rpc_index() -> Result<GeneratedLocalRpcIndex, LocalRpcIndexError> {
    let schemas = generated_owned_schemas()?;
    let corpora = generated_golden_corpora()?;
    let index = build_index(&schemas, &corpora)?;
    let bytes = to_jcs_vec(&index)?;
    if bytes.len() > MAX_LOCAL_RPC_INDEX_BYTES {
        return Err(LocalRpcIndexError::TooLarge);
    }
    Ok(GeneratedLocalRpcIndex { sha256: hex_digest(&bytes), bytes })
}

pub fn verify_checked_in_local_rpc_index(root: &Path) -> Result<(), LocalRpcIndexError> {
    let expected = generated_local_rpc_index()?;
    let path = root.join(LOCAL_RPC_INDEX_PATH);
    let bytes = fs::read(&path).map_err(|source| LocalRpcIndexError::Io { path, source })?;
    if bytes.len() > MAX_LOCAL_RPC_INDEX_BYTES {
        return Err(LocalRpcIndexError::TooLarge);
    }
    let parsed: LocalRpcArtifactIndex = serde_json::from_slice(&bytes)?;
    let canonical = to_jcs_vec(&parsed)?;
    if canonical != bytes || bytes != expected.bytes {
        return Err(LocalRpcIndexError::ContentDrift);
    }
    Ok(())
}

pub fn write_local_rpc_index(root: &Path) -> Result<GeneratedLocalRpcIndex, LocalRpcIndexError> {
    let generated = generated_local_rpc_index()?;
    let path = root.join(LOCAL_RPC_INDEX_PATH);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .map_err(|source| LocalRpcIndexError::Io { path: parent.to_path_buf(), source })?;
    }
    fs::write(&path, &generated.bytes).map_err(|source| LocalRpcIndexError::Io { path, source })?;
    Ok(generated)
}

fn build_index(
    schemas: &[GeneratedOwnedSchema],
    corpora: &[GeneratedGoldenCorpus],
) -> Result<LocalRpcArtifactIndex, LocalRpcIndexError> {
    let mut artifacts = Vec::with_capacity(schemas.len() + corpora.len());
    for schema in schemas {
        let (rpc_schema, readiness_id) = identity(&schema.artifact_id)?;
        artifacts.push(LocalRpcArtifactEntry {
            artifact_id: schema.artifact_id.clone(),
            kind: "owned-schema".to_owned(),
            rpc_schema: rpc_schema.to_owned(),
            path: schema.path.to_owned(),
            byte_length: u32::try_from(schema.bytes.len())
                .map_err(|_| LocalRpcIndexError::TooLarge)?,
            sha256: schema.sha256.clone(),
            readiness_id: readiness_id.to_owned(),
        });
    }
    for corpus in corpora {
        let (rpc_schema, readiness_id) = identity(&corpus.corpus_id)?;
        artifacts.push(LocalRpcArtifactEntry {
            artifact_id: corpus.corpus_id.clone(),
            kind: "golden-corpus".to_owned(),
            rpc_schema: rpc_schema.to_owned(),
            path: corpus.path.to_owned(),
            byte_length: u32::try_from(corpus.bytes.len())
                .map_err(|_| LocalRpcIndexError::TooLarge)?,
            sha256: corpus.sha256.clone(),
            readiness_id: readiness_id.to_owned(),
        });
    }
    artifacts.sort_by(|left, right| left.artifact_id.cmp(&right.artifact_id));
    if artifacts.len() != 6 {
        return Err(LocalRpcIndexError::Invalid(
            "local RPC index must contain exactly six independent artifacts".to_owned(),
        ));
    }
    let unique_paths: std::collections::BTreeSet<_> =
        artifacts.iter().map(|entry| &entry.path).collect();
    let unique_ids: std::collections::BTreeSet<_> =
        artifacts.iter().map(|entry| &entry.artifact_id).collect();
    if unique_paths.len() != artifacts.len() || unique_ids.len() != artifacts.len() {
        return Err(LocalRpcIndexError::Invalid(
            "local RPC index paths and IDs must be unique".to_owned(),
        ));
    }

    Ok(LocalRpcArtifactIndex {
        schema: LOCAL_RPC_INDEX_SCHEMA.to_owned(),
        status: "development-wire-contract-not-rpc-readiness-or-release-evidence".to_owned(),
        product_version: "0.1.0".to_owned(),
        canonical_encoding: "postcard-1.1.3".to_owned(),
        schema_reflection: "postcard-schema-0.2.5-owned-json".to_owned(),
        canonical_json: "rfc8785-jcs-via-serde_json_canonicalizer-0.3.2".to_owned(),
        artifacts,
    })
}

fn identity(artifact_id: &str) -> Result<(&'static str, &'static str), LocalRpcIndexError> {
    if artifact_id.starts_with("visa.agent.control.") {
        Ok(("visa.agent.control.v1", "cli-agent-rpc-v1"))
    } else if artifact_id.starts_with("visa.ownership.local.") {
        Ok(("visa.ownership.local.v1", "agent-ownership-rpc-v1"))
    } else if artifact_id.starts_with("visa.nexus-adapter.local.") {
        Ok(("visa.nexus-adapter.local.v1", "agent-nexus-rpc-v1"))
    } else {
        Err(LocalRpcIndexError::Invalid(format!("unknown local RPC artifact ID: {artifact_id}")))
    }
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
    fn index_binds_exactly_two_artifacts_per_independent_family() {
        let generated = generated_local_rpc_index().expect("index generation must succeed");
        let index: LocalRpcArtifactIndex =
            serde_json::from_slice(&generated.bytes).expect("index must parse");
        assert_eq!(index.artifacts.len(), 6);
        for readiness_id in ["cli-agent-rpc-v1", "agent-ownership-rpc-v1", "agent-nexus-rpc-v1"] {
            assert_eq!(
                index.artifacts.iter().filter(|entry| entry.readiness_id == readiness_id).count(),
                2
            );
        }
        assert_eq!(to_jcs_vec(&index).expect("index must canonicalize"), generated.bytes);
    }
}
