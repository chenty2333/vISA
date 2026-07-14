use std::{
    fs::File,
    io::{self, Read},
    path::Path,
};

use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use crate::{build_info, protocol::PROTOCOL_VERSION};

pub const TARGET_HELLO_SCHEMA_VERSION: &str = "visa-stage4-target-hello-v1";
pub const TARGET_NONCE_HEX_LENGTH: usize = 64;

#[cfg(target_env = "gnu")]
const TARGET_ENV: &str = "gnu";
#[cfg(target_env = "musl")]
const TARGET_ENV: &str = "musl";
#[cfg(target_env = "msvc")]
const TARGET_ENV: &str = "msvc";
#[cfg(target_env = "sgx")]
const TARGET_ENV: &str = "sgx";
#[cfg(not(any(target_env = "gnu", target_env = "musl", target_env = "msvc", target_env = "sgx")))]
const TARGET_ENV: &str = "none";

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TargetEndianness {
    Little,
    Big,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TargetHelloV1 {
    pub schema_version: String,
    pub nonce: String,
    pub target_triple: String,
    pub architecture: String,
    pub os: String,
    pub abi: String,
    pub endianness: TargetEndianness,
    pub pointer_width_bits: u16,
    pub executable_sha256: String,
    pub executable_size: u64,
    pub build_source_sha256: String,
    pub build_toolchain_sha256: String,
    pub worker_protocol_version: u64,
}

#[derive(Debug)]
pub struct TargetHelloError {
    detail: String,
}

impl TargetHelloError {
    fn new(detail: impl Into<String>) -> Self {
        Self { detail: detail.into() }
    }
}

impl std::fmt::Display for TargetHelloError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.detail)
    }
}

impl std::error::Error for TargetHelloError {}

pub fn observe_target(nonce: &str) -> Result<TargetHelloV1, TargetHelloError> {
    validate_target_nonce(nonce)?;
    let executable = std::env::current_exe().map_err(|source| {
        TargetHelloError::new(format!("cannot resolve current target executable: {source}"))
    })?;
    let (executable_sha256, executable_size) = hash_regular_file(&executable)?;
    let pointer_width_bits = u16::try_from(usize::BITS).map_err(|_| {
        TargetHelloError::new(format!("target pointer width {} does not fit u16", usize::BITS))
    })?;
    let hello = TargetHelloV1 {
        schema_version: TARGET_HELLO_SCHEMA_VERSION.to_owned(),
        nonce: nonce.to_owned(),
        target_triple: build_info::TARGET_TRIPLE.to_owned(),
        architecture: std::env::consts::ARCH.to_owned(),
        os: std::env::consts::OS.to_owned(),
        abi: format!("{}-{TARGET_ENV}", std::env::consts::OS),
        endianness: if cfg!(target_endian = "little") {
            TargetEndianness::Little
        } else {
            TargetEndianness::Big
        },
        pointer_width_bits,
        executable_sha256,
        executable_size,
        build_source_sha256: build_info::SOURCE_SHA256.to_owned(),
        build_toolchain_sha256: build_info::TOOLCHAIN_SHA256.to_owned(),
        worker_protocol_version: PROTOCOL_VERSION,
    };
    hello.validate_for_nonce(nonce)?;
    Ok(hello)
}

impl TargetHelloV1 {
    pub fn validate_for_nonce(&self, expected_nonce: &str) -> Result<(), TargetHelloError> {
        validate_target_nonce(expected_nonce)?;
        validate_target_nonce(&self.nonce)?;
        if self.schema_version != TARGET_HELLO_SCHEMA_VERSION {
            return Err(TargetHelloError::new(format!(
                "target hello schema {:?} does not equal {TARGET_HELLO_SCHEMA_VERSION:?}",
                self.schema_version
            )));
        }
        if self.nonce != expected_nonce {
            return Err(TargetHelloError::new("target hello nonce does not match the challenge"));
        }
        for (label, value) in [
            ("target_triple", self.target_triple.as_str()),
            ("architecture", self.architecture.as_str()),
            ("os", self.os.as_str()),
            ("abi", self.abi.as_str()),
        ] {
            if value.is_empty() || value.chars().any(char::is_whitespace) {
                return Err(TargetHelloError::new(format!(
                    "target hello {label} must be nonempty and contain no whitespace"
                )));
            }
        }
        if !matches!(self.pointer_width_bits, 32 | 64) {
            return Err(TargetHelloError::new(format!(
                "unsupported target pointer width {}",
                self.pointer_width_bits
            )));
        }
        for (label, digest) in [
            ("executable_sha256", self.executable_sha256.as_str()),
            ("build_source_sha256", self.build_source_sha256.as_str()),
            ("build_toolchain_sha256", self.build_toolchain_sha256.as_str()),
        ] {
            if !is_lower_sha256(digest) {
                return Err(TargetHelloError::new(format!(
                    "target hello {label} is not a lowercase SHA-256 digest"
                )));
            }
        }
        if self.executable_size == 0 {
            return Err(TargetHelloError::new("target executable size must be positive"));
        }
        if self.worker_protocol_version != PROTOCOL_VERSION {
            return Err(TargetHelloError::new(format!(
                "target worker protocol version {} does not equal {PROTOCOL_VERSION}",
                self.worker_protocol_version
            )));
        }
        Ok(())
    }
}

pub fn validate_target_nonce(nonce: &str) -> Result<(), TargetHelloError> {
    if nonce.len() != TARGET_NONCE_HEX_LENGTH
        || !nonce.bytes().all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(TargetHelloError::new(format!(
            "target hello nonce must be exactly {TARGET_NONCE_HEX_LENGTH} lowercase hexadecimal characters"
        )));
    }
    Ok(())
}

fn hash_regular_file(path: &Path) -> Result<(String, u64), TargetHelloError> {
    let mut file = File::open(path).map_err(|source| {
        TargetHelloError::new(format!("cannot open target executable {}: {source}", path.display()))
    })?;
    let before = file.metadata().map_err(|source| {
        TargetHelloError::new(format!(
            "cannot inspect target executable {}: {source}",
            path.display()
        ))
    })?;
    if !before.is_file() || before.len() == 0 {
        return Err(TargetHelloError::new(format!(
            "target executable is not a nonempty regular file: {}",
            path.display()
        )));
    }
    let mut digest = Sha256::new();
    let mut observed = 0_u64;
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = match file.read(&mut buffer) {
            Ok(read) => read,
            Err(source) if source.kind() == io::ErrorKind::Interrupted => continue,
            Err(source) => {
                return Err(TargetHelloError::new(format!(
                    "cannot hash target executable {}: {source}",
                    path.display()
                )));
            }
        };
        if read == 0 {
            break;
        }
        observed = observed
            .checked_add(u64::try_from(read).unwrap_or(u64::MAX))
            .ok_or_else(|| TargetHelloError::new("target executable size overflow"))?;
        digest.update(&buffer[..read]);
    }
    let after = file.metadata().map_err(|source| {
        TargetHelloError::new(format!(
            "cannot reinspect target executable {}: {source}",
            path.display()
        ))
    })?;
    if before.len() != after.len() || observed != before.len() {
        return Err(TargetHelloError::new(format!(
            "target executable changed while hashing: {}",
            path.display()
        )));
    }
    Ok((format!("{:x}", digest.finalize()), observed))
}

fn is_lower_sha256(value: &str) -> bool {
    value.len() == 64
        && value.bytes().all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

#[cfg(test)]
mod tests {
    use sha2::{Digest as _, Sha256};

    use super::*;

    const NONCE: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    #[test]
    fn native_target_hello_is_nonce_bound_and_hashes_the_current_executable() {
        let hello = observe_target(NONCE).unwrap();
        let executable = std::env::current_exe().unwrap();
        let bytes = std::fs::read(executable).unwrap();

        assert_eq!(hello.nonce, NONCE);
        assert_eq!(hello.target_triple, build_info::TARGET_TRIPLE);
        assert_eq!(hello.architecture, std::env::consts::ARCH);
        assert_eq!(hello.executable_sha256, format!("{:x}", Sha256::digest(&bytes)));
        assert_eq!(hello.executable_size, bytes.len() as u64);
        hello.validate_for_nonce(NONCE).unwrap();
    }

    #[test]
    fn nonce_and_unknown_hello_fields_are_rejected() {
        assert!(validate_target_nonce("short").is_err());
        assert!(validate_target_nonce(&"A".repeat(64)).is_err());

        let hello = observe_target(NONCE).unwrap();
        assert!(hello.validate_for_nonce(&"f".repeat(64)).is_err());
        let mut value = serde_json::to_value(hello).unwrap();
        value["unexpected"] = serde_json::Value::Bool(true);
        assert!(serde_json::from_value::<TargetHelloV1>(value).is_err());
    }
}
