use std::{
    fs,
    path::{Path, PathBuf},
};

use serde_json_canonicalizer::to_vec as to_jcs_vec;
use sha2::{Digest as _, Sha256};
use visa_local_rpc::schema::{
    OwnedSchemaArtifact, agent_control_artifact, nexus_adapter_artifact, ownership_artifact,
};

pub const AGENT_CONTROL_SCHEMA_PATH: &str =
    "schemas/local-rpc/visa-agent-control-v1.owned-schema.json";
pub const OWNERSHIP_SCHEMA_PATH: &str =
    "schemas/local-rpc/visa-ownership-local-v1.owned-schema.json";
pub const NEXUS_ADAPTER_SCHEMA_PATH: &str =
    "schemas/local-rpc/visa-nexus-adapter-local-v1.owned-schema.json";
pub const MAX_OWNED_SCHEMA_BYTES: usize = 1024 * 1024;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GeneratedOwnedSchema {
    pub path: &'static str,
    pub artifact_id: String,
    pub bytes: Vec<u8>,
    pub sha256: String,
}

#[derive(Debug)]
pub enum OwnedSchemaError {
    Json(serde_json::Error),
    Io { path: PathBuf, source: std::io::Error },
    NonCanonical { artifact_id: String },
    TooLarge { artifact_id: String },
    ContentDrift { artifact_id: String },
}

impl std::fmt::Display for OwnedSchemaError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Json(source) => write!(formatter, "owned-schema JSON is invalid: {source}"),
            Self::Io { path, source } => {
                write!(formatter, "cannot access owned-schema {}: {source}", path.display())
            }
            Self::NonCanonical { artifact_id } => {
                write!(formatter, "{artifact_id} is not exact RFC 8785 JCS bytes")
            }
            Self::TooLarge { artifact_id } => {
                write!(formatter, "{artifact_id} exceeds the owned-schema input limit")
            }
            Self::ContentDrift { artifact_id } => {
                write!(formatter, "{artifact_id} differs from its Rust-owned schema")
            }
        }
    }
}

impl std::error::Error for OwnedSchemaError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Json(source) => Some(source),
            Self::Io { source, .. } => Some(source),
            Self::NonCanonical { .. } | Self::TooLarge { .. } | Self::ContentDrift { .. } => None,
        }
    }
}

impl From<serde_json::Error> for OwnedSchemaError {
    fn from(source: serde_json::Error) -> Self {
        Self::Json(source)
    }
}

pub fn generated_owned_schemas() -> Result<Vec<GeneratedOwnedSchema>, OwnedSchemaError> {
    [
        (AGENT_CONTROL_SCHEMA_PATH, agent_control_artifact()),
        (OWNERSHIP_SCHEMA_PATH, ownership_artifact()),
        (NEXUS_ADAPTER_SCHEMA_PATH, nexus_adapter_artifact()),
    ]
    .into_iter()
    .map(|(path, artifact)| generate(path, artifact))
    .collect()
}

pub fn verify_owned_schema_bytes(
    bytes: &[u8],
    expected: &OwnedSchemaArtifact,
) -> Result<(), OwnedSchemaError> {
    if bytes.len() > MAX_OWNED_SCHEMA_BYTES {
        return Err(OwnedSchemaError::TooLarge { artifact_id: expected.artifact_id.clone() });
    }
    let parsed: OwnedSchemaArtifact = serde_json::from_slice(bytes)?;
    if &parsed != expected {
        return Err(OwnedSchemaError::ContentDrift { artifact_id: expected.artifact_id.clone() });
    }
    if to_jcs_vec(&parsed)? != bytes {
        return Err(OwnedSchemaError::NonCanonical { artifact_id: expected.artifact_id.clone() });
    }
    Ok(())
}

pub fn verify_checked_in_owned_schemas(root: &Path) -> Result<(), OwnedSchemaError> {
    for generated in generated_owned_schemas()? {
        let path = root.join(generated.path);
        let bytes = fs::read(&path)
            .map_err(|source| OwnedSchemaError::Io { path: path.clone(), source })?;
        let expected = artifact_for_path(generated.path);
        verify_owned_schema_bytes(&bytes, &expected)?;
        if bytes != generated.bytes {
            return Err(OwnedSchemaError::ContentDrift { artifact_id: generated.artifact_id });
        }
    }
    Ok(())
}

pub fn write_owned_schemas(root: &Path) -> Result<Vec<GeneratedOwnedSchema>, OwnedSchemaError> {
    let generated = generated_owned_schemas()?;
    for artifact in &generated {
        let path = root.join(artifact.path);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)
                .map_err(|source| OwnedSchemaError::Io { path: parent.to_path_buf(), source })?;
        }
        fs::write(&path, &artifact.bytes)
            .map_err(|source| OwnedSchemaError::Io { path, source })?;
    }
    Ok(generated)
}

fn generate(
    path: &'static str,
    artifact: OwnedSchemaArtifact,
) -> Result<GeneratedOwnedSchema, OwnedSchemaError> {
    let bytes = to_jcs_vec(&artifact)?;
    let sha256 = hex_digest(&bytes);
    Ok(GeneratedOwnedSchema { path, artifact_id: artifact.artifact_id, bytes, sha256 })
}

fn artifact_for_path(path: &str) -> OwnedSchemaArtifact {
    match path {
        AGENT_CONTROL_SCHEMA_PATH => agent_control_artifact(),
        OWNERSHIP_SCHEMA_PATH => ownership_artifact(),
        NEXUS_ADAPTER_SCHEMA_PATH => nexus_adapter_artifact(),
        _ => unreachable!("only frozen owned-schema paths are generated"),
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
    fn generated_owned_schemas_are_independent_and_canonical() {
        let schemas = generated_owned_schemas().expect("schema generation must succeed");
        assert_eq!(schemas.len(), 3);
        let mut paths = std::collections::BTreeSet::new();
        let mut ids = std::collections::BTreeSet::new();
        let mut digests = std::collections::BTreeSet::new();
        for generated in schemas {
            assert!(paths.insert(generated.path));
            assert!(ids.insert(generated.artifact_id));
            assert!(digests.insert(generated.sha256));
            let expected = artifact_for_path(generated.path);
            verify_owned_schema_bytes(&generated.bytes, &expected)
                .expect("generated schema must verify");
        }
    }

    #[test]
    fn duplicate_unknown_trailing_and_noncanonical_json_are_rejected() {
        let expected = agent_control_artifact();
        let canonical = to_jcs_vec(&expected).expect("JCS serialization must succeed");

        let mut duplicate = canonical.clone();
        duplicate.splice(1..1, b"\"schema\":\"duplicate\",".iter().copied());
        assert!(verify_owned_schema_bytes(&duplicate, &expected).is_err());

        let mut unknown = canonical.clone();
        unknown.splice(1..1, b"\"unexpected\":true,".iter().copied());
        assert!(verify_owned_schema_bytes(&unknown, &expected).is_err());

        let mut trailing = canonical.clone();
        trailing.extend_from_slice(b"\n");
        assert!(verify_owned_schema_bytes(&trailing, &expected).is_err());

        let value: serde_json::Value =
            serde_json::from_slice(&canonical).expect("canonical JSON must parse");
        let pretty = serde_json::to_vec_pretty(&value).expect("pretty JSON must serialize");
        assert!(verify_owned_schema_bytes(&pretty, &expected).is_err());

        let oversized = vec![b' '; MAX_OWNED_SCHEMA_BYTES + 1];
        assert!(matches!(
            verify_owned_schema_bytes(&oversized, &expected),
            Err(OwnedSchemaError::TooLarge { .. })
        ));
    }

    #[test]
    fn jcs_matches_rfc_8785_examples_used_by_the_artifact_profile() {
        let numbers: serde_json::Value =
            serde_json::from_str(r#"[333333333.33333329,1E30,4.50,2e-3,1e-27]"#)
                .expect("RFC number example must parse");
        let example = serde_json::json!({
            "numbers": numbers,
            "string": "€$\u{000f}\nA'B\"\\\\\"/",
            "literals": [null, true, false]
        });
        assert_eq!(
            to_jcs_vec(&example).expect("RFC example must canonicalize"),
            r#"{"literals":[null,true,false],"numbers":[333333333.3333333,1e+30,4.5,0.002,1e-27],"string":"€$\u000f\nA'B\"\\\\\"/"}"#.as_bytes()
        );

        let sorting = serde_json::json!({
            "€": "Euro Sign",
            "\r": "Carriage Return",
            "דּ": "Hebrew Letter Dalet With Dagesh",
            "1": "One",
            "😀": "Emoji: Grinning Face",
            "\u{0080}": "Control",
            "ö": "Latin Small Letter O With Diaeresis"
        });
        assert_eq!(
            to_jcs_vec(&sorting).expect("RFC sorting example must canonicalize"),
            "{\"\\r\":\"Carriage Return\",\"1\":\"One\",\"\u{0080}\":\"Control\",\"ö\":\"Latin Small Letter O With Diaeresis\",\"€\":\"Euro Sign\",\"😀\":\"Emoji: Grinning Face\",\"דּ\":\"Hebrew Letter Dalet With Dagesh\"}".as_bytes()
        );
    }

    #[test]
    fn schema_artifacts_use_only_safe_json_numbers_and_allowed_wire_types() {
        for artifact in [agent_control_artifact(), ownership_artifact(), nexus_adapter_artifact()] {
            let value = serde_json::to_value(&artifact).expect("typed artifact must serialize");
            assert_safe_schema_value(&value);
        }
    }

    fn assert_safe_schema_value(value: &serde_json::Value) {
        const MAX_SAFE_INTEGER: u64 = 9_007_199_254_740_991;

        match value {
            serde_json::Value::Null | serde_json::Value::Bool(_) => {}
            serde_json::Value::Number(number) => {
                let unsigned = number
                    .as_u64()
                    .expect("owned-schema metadata numbers must be unsigned integers");
                assert!(unsigned <= MAX_SAFE_INTEGER);
            }
            serde_json::Value::String(string) => {
                assert!(!matches!(string.as_str(), "F32" | "F64" | "HashMap" | "HashSet"));
            }
            serde_json::Value::Array(values) => {
                for value in values {
                    assert_safe_schema_value(value);
                }
            }
            serde_json::Value::Object(values) => {
                for value in values.values() {
                    assert_safe_schema_value(value);
                }
            }
        }
    }
}
