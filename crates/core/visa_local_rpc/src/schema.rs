//! Complete owned-schema roots for each independent local RPC family.
//!
//! This module deliberately has no aggregate "all local RPCs" artifact. Each
//! producer function returns one self-identifying artifact whose roots contain
//! only the selected family's concrete request, response, semantic error, and
//! replay types.

use postcard_schema::{Schema, schema::owned::OwnedNamedType};
use serde::{Deserialize, Serialize};

use crate::{agent_control, codec::CANONICAL_ENCODING, nexus_adapter, ownership};

pub const ARTIFACT_SCHEMA: &str = "visa.postcard-owned-schema-artifact.v1";
pub const ARTIFACT_FORMAT: &str = "postcard-schema-owned-json.v1";
pub const POSTCARD_SCHEMA_VERSION: &str = "0.2.5";
pub const CANONICAL_JSON: &str = "rfc8785-jcs-utf8-no-duplicate-keys-no-trailing-bytes";
pub const DIGEST_ALGORITHM: &str = "sha-256";
pub const DIGEST_SCOPE: &str = "entire-artifact-exact-bytes-not-postcard-schema-fnv-key";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OwnedSchemaArtifact {
    pub schema: String,
    pub format: String,
    pub artifact_id: String,
    pub rpc_schema: String,
    pub protocol_major: u16,
    pub protocol_minor: u16,
    pub family_id_hex: String,
    pub canonical_encoding: String,
    pub canonical_json: String,
    pub postcard_schema_version: String,
    pub digest_algorithm: String,
    pub digest_scope: String,
    pub golden_corpus_id: String,
    pub namespaces: SchemaNamespaces,
    pub roots: OwnedSchemaRoots,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SchemaNamespaces {
    pub request: String,
    pub response: String,
    pub error: String,
    pub replay: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OwnedSchemaRoots {
    pub request: OwnedNamedType,
    pub response: OwnedNamedType,
    pub rejection: OwnedNamedType,
    pub unknown: OwnedNamedType,
    pub replay: OwnedNamedType,
}

pub fn agent_control_artifact() -> OwnedSchemaArtifact {
    build_artifact(
        ArtifactIdentity {
            artifact_id: agent_control::OWNED_SCHEMA_ARTIFACT_ID,
            rpc_schema: agent_control::SCHEMA,
            family_id: agent_control::FAMILY_ID,
            golden_corpus_id: agent_control::GOLDEN_CORPUS_ID,
            request_namespace: agent_control::REQUEST_NAMESPACE,
            response_namespace: agent_control::RESPONSE_NAMESPACE,
            error_namespace: agent_control::ERROR_NAMESPACE,
            replay_namespace: agent_control::REPLAY_NAMESPACE,
        },
        OwnedSchemaRoots {
            request: owned::<agent_control::Request>(),
            response: owned::<agent_control::Response>(),
            rejection: owned::<agent_control::Rejection>(),
            unknown: owned::<agent_control::Unknown>(),
            replay: owned::<agent_control::ReplayRecord>(),
        },
    )
}

pub fn ownership_artifact() -> OwnedSchemaArtifact {
    build_artifact(
        ArtifactIdentity {
            artifact_id: ownership::OWNED_SCHEMA_ARTIFACT_ID,
            rpc_schema: ownership::SCHEMA,
            family_id: ownership::FAMILY_ID,
            golden_corpus_id: ownership::GOLDEN_CORPUS_ID,
            request_namespace: ownership::REQUEST_NAMESPACE,
            response_namespace: ownership::RESPONSE_NAMESPACE,
            error_namespace: ownership::ERROR_NAMESPACE,
            replay_namespace: ownership::REPLAY_NAMESPACE,
        },
        OwnedSchemaRoots {
            request: owned::<ownership::Request>(),
            response: owned::<ownership::Response>(),
            rejection: owned::<ownership::Rejection>(),
            unknown: owned::<ownership::Unknown>(),
            replay: owned::<ownership::ReplayRecord>(),
        },
    )
}

pub fn nexus_adapter_artifact() -> OwnedSchemaArtifact {
    build_artifact(
        ArtifactIdentity {
            artifact_id: nexus_adapter::OWNED_SCHEMA_ARTIFACT_ID,
            rpc_schema: nexus_adapter::SCHEMA,
            family_id: nexus_adapter::FAMILY_ID,
            golden_corpus_id: nexus_adapter::GOLDEN_CORPUS_ID,
            request_namespace: nexus_adapter::REQUEST_NAMESPACE,
            response_namespace: nexus_adapter::RESPONSE_NAMESPACE,
            error_namespace: nexus_adapter::ERROR_NAMESPACE,
            replay_namespace: nexus_adapter::REPLAY_NAMESPACE,
        },
        OwnedSchemaRoots {
            request: owned::<nexus_adapter::Request>(),
            response: owned::<nexus_adapter::Response>(),
            rejection: owned::<nexus_adapter::Rejection>(),
            unknown: owned::<nexus_adapter::Unknown>(),
            replay: owned::<nexus_adapter::ReplayRecord>(),
        },
    )
}

struct ArtifactIdentity {
    artifact_id: &'static str,
    rpc_schema: &'static str,
    family_id: [u8; 16],
    golden_corpus_id: &'static str,
    request_namespace: &'static str,
    response_namespace: &'static str,
    error_namespace: &'static str,
    replay_namespace: &'static str,
}

fn build_artifact(identity: ArtifactIdentity, roots: OwnedSchemaRoots) -> OwnedSchemaArtifact {
    OwnedSchemaArtifact {
        schema: ARTIFACT_SCHEMA.to_owned(),
        format: ARTIFACT_FORMAT.to_owned(),
        artifact_id: identity.artifact_id.to_owned(),
        rpc_schema: identity.rpc_schema.to_owned(),
        protocol_major: 1,
        protocol_minor: 0,
        family_id_hex: hex_bytes(identity.family_id),
        canonical_encoding: CANONICAL_ENCODING.to_owned(),
        canonical_json: CANONICAL_JSON.to_owned(),
        postcard_schema_version: POSTCARD_SCHEMA_VERSION.to_owned(),
        digest_algorithm: DIGEST_ALGORITHM.to_owned(),
        digest_scope: DIGEST_SCOPE.to_owned(),
        golden_corpus_id: identity.golden_corpus_id.to_owned(),
        namespaces: SchemaNamespaces {
            request: identity.request_namespace.to_owned(),
            response: identity.response_namespace.to_owned(),
            error: identity.error_namespace.to_owned(),
            replay: identity.replay_namespace.to_owned(),
        },
        roots,
    }
}

fn owned<T: Schema>() -> OwnedNamedType {
    T::SCHEMA.into()
}

fn hex_bytes(bytes: [u8; 16]) -> String {
    use core::fmt::Write as _;

    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        write!(&mut output, "{byte:02x}").expect("writing to String is infallible");
    }
    output
}
