//! Unix-socket transport for sharing one real `SqliteProvider` transaction
//! domain between workers on different execution hosts.
//!
//! The service does not implement a second provider. Each connection owns one
//! `SqliteProvider` session, while sessions carrying different journal scopes
//! may open the same server-local database identifier. All journal, lease,
//! authority, binding, and key-value transactions therefore remain in the
//! existing SQLite implementation.

mod client;
mod server;
mod wire;

use std::{
    fmt,
    os::unix::ffi::{OsStrExt, OsStringExt},
    path::{Component, Path, PathBuf},
};

pub use client::{NetworkProvider, ProviderRpcError, probe};
pub use server::{ProviderRpcServerError, ProviderServer};

pub const PROVIDER_RPC_SCHEMA_VERSION: &str = "visa-provider-rpc-v1";
const DATABASE_ID_HEX_BYTES: usize = 64;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProviderLocator {
    socket_path: PathBuf,
    database_id: String,
    canonical: String,
}

impl ProviderLocator {
    pub const PREFIX: &'static str = "visa-provider+unix-v1:";

    pub fn new(
        socket_path: impl AsRef<Path>,
        database_id: impl Into<String>,
    ) -> Result<Self, ProviderLocatorError> {
        let socket_path = socket_path.as_ref();
        validate_socket_path(socket_path)?;
        let database_id = database_id.into();
        validate_database_id(&database_id)?;
        let socket_hex = encode_hex(socket_path.as_os_str().as_bytes());
        let canonical = format!("{}{socket_hex}:{database_id}", Self::PREFIX);
        Ok(Self { socket_path: socket_path.to_path_buf(), database_id, canonical })
    }

    pub fn parse(value: &str) -> Result<Self, ProviderLocatorError> {
        let remainder =
            value.strip_prefix(Self::PREFIX).ok_or(ProviderLocatorError::WrongScheme)?;
        let (socket_hex, database_id) =
            remainder.split_once(':').ok_or(ProviderLocatorError::MissingDatabaseId)?;
        let socket_bytes = decode_hex(socket_hex).ok_or(ProviderLocatorError::InvalidSocketPath)?;
        let socket_path = PathBuf::from(std::ffi::OsString::from_vec(socket_bytes));
        let parsed = Self::new(socket_path, database_id)?;
        if parsed.as_str() != value {
            return Err(ProviderLocatorError::NonCanonical);
        }
        Ok(parsed)
    }

    pub fn socket_path(&self) -> &Path {
        &self.socket_path
    }

    pub fn database_id(&self) -> &str {
        &self.database_id
    }

    pub fn as_str(&self) -> &str {
        &self.canonical
    }
}

impl fmt::Display for ProviderLocator {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.canonical)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProviderLocatorError {
    WrongScheme,
    MissingDatabaseId,
    InvalidSocketPath,
    InvalidDatabaseId,
    NonCanonical,
}

impl fmt::Display for ProviderLocatorError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::WrongScheme => "provider locator has the wrong scheme",
            Self::MissingDatabaseId => "provider locator has no database_id",
            Self::InvalidSocketPath => "provider locator has an invalid Unix socket path",
            Self::InvalidDatabaseId => "provider locator has an invalid database_id",
            Self::NonCanonical => "provider locator is not canonically encoded",
        })
    }
}

impl std::error::Error for ProviderLocatorError {}

fn validate_socket_path(path: &Path) -> Result<(), ProviderLocatorError> {
    if !path.is_absolute()
        || path.as_os_str().is_empty()
        || path.as_os_str().as_bytes().contains(&0)
        || path
            .components()
            .any(|component| matches!(component, Component::CurDir | Component::ParentDir))
    {
        return Err(ProviderLocatorError::InvalidSocketPath);
    }
    Ok(())
}

pub(crate) fn validate_database_id(value: &str) -> Result<(), ProviderLocatorError> {
    if value.len() != DATABASE_ID_HEX_BYTES
        || value.bytes().any(|byte| !(byte.is_ascii_digit() || matches!(byte, b'a'..=b'f')))
    {
        return Err(ProviderLocatorError::InvalidDatabaseId);
    }
    Ok(())
}

fn encode_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(char::from(HEX[usize::from(byte >> 4)]));
        encoded.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    encoded
}

fn decode_hex(value: &str) -> Option<Vec<u8>> {
    if value.is_empty() || !value.len().is_multiple_of(2) {
        return None;
    }
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let high = decode_hex_nibble(pair[0])?;
            let low = decode_hex_nibble(pair[1])?;
            Some((high << 4) | low)
        })
        .collect()
}

const fn decode_hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests;
