use alloc::format;
use alloc::string::String;

use super::*;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ArtifactVerificationState {
    Planned,
    ManifestBound,
    ManifestVerified,
    HostValidated,
    Rejected,
}

impl ArtifactVerificationState {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Planned => "planned",
            Self::ManifestBound => "manifest-bound",
            Self::ManifestVerified => "manifest-verified",
            Self::HostValidated => "host-validated",
            Self::Rejected => "rejected",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ArtifactVerificationRecord {
    pub id: ArtifactId,
    pub package: String,
    pub artifact_name: String,
    pub manifest_binding_hash: String,
    pub artifact_hash: String,
    pub abi_fingerprint: String,
    pub signature_profile: String,
    pub signer: String,
    pub state: ArtifactVerificationState,
    pub blocked_by: Option<String>,
    pub generation: Generation,
}

impl ArtifactVerificationRecord {
    pub fn summary(&self) -> String {
        let blocked_by = self
            .blocked_by
            .as_ref()
            .map(String::as_str)
            .unwrap_or("none");
        format!(
            "artifact {} name={} state={} binding={} artifact_hash={} abi={} signature={} signer={} blocked={} generation={}",
            self.package,
            self.artifact_name,
            self.state.as_str(),
            self.manifest_binding_hash,
            self.artifact_hash,
            self.abi_fingerprint,
            self.signature_profile,
            self.signer,
            blocked_by,
            self.generation
        )
    }
}
