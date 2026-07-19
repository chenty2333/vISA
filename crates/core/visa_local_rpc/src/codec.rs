use postcard_schema::Schema;
use serde::{Serialize, de::DeserializeOwned};
use sha2::{Digest as _, Sha256};

use crate::common::{Sha256Digest, WireValidation, WireValidationError};

pub const CANONICAL_ENCODING: &str = "postcard-1.1.3";
pub const MAX_INNER_REQUEST_BYTES: usize = 1_048_576;
pub const MAX_INNER_RESPONSE_BYTES: usize = 1_048_576;
pub const MAX_REPLAY_RECORD_BYTES: usize =
    MAX_INNER_REQUEST_BYTES + MAX_INNER_RESPONSE_BYTES + 4_096;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EncodeError {
    Invalid(WireValidationError),
    Codec,
    TooLarge,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DecodeError {
    TooLarge,
    Codec,
    TrailingBytes,
    NonCanonical,
    Invalid(WireValidationError),
}

pub(crate) fn canonical_request_bytes<T>(value: &T) -> Result<Vec<u8>, EncodeError>
where
    T: Serialize + Schema + WireValidation,
{
    canonical_bytes_with_limit(value, MAX_INNER_REQUEST_BYTES)
}

pub(crate) fn canonical_response_bytes<T>(value: &T) -> Result<Vec<u8>, EncodeError>
where
    T: Serialize + Schema + WireValidation,
{
    canonical_bytes_with_limit(value, MAX_INNER_RESPONSE_BYTES)
}

pub(crate) fn decode_canonical_request<T>(bytes: &[u8]) -> Result<T, DecodeError>
where
    T: DeserializeOwned + Serialize + Schema + WireValidation,
{
    decode_canonical_with_limit(bytes, MAX_INNER_REQUEST_BYTES)
}

pub(crate) fn decode_canonical_response<T>(bytes: &[u8]) -> Result<T, DecodeError>
where
    T: DeserializeOwned + Serialize + Schema + WireValidation,
{
    decode_canonical_with_limit(bytes, MAX_INNER_RESPONSE_BYTES)
}

pub(crate) fn canonical_replay_bytes<T>(value: &T) -> Result<Vec<u8>, EncodeError>
where
    T: Serialize + Schema + WireValidation,
{
    canonical_bytes_with_limit(value, MAX_REPLAY_RECORD_BYTES)
}

pub(crate) fn decode_canonical_replay<T>(bytes: &[u8]) -> Result<T, DecodeError>
where
    T: DeserializeOwned + Serialize + Schema + WireValidation,
{
    decode_canonical_with_limit(bytes, MAX_REPLAY_RECORD_BYTES)
}

pub(crate) fn request_digest<T>(domain: &[u8], value: &T) -> Result<Sha256Digest, EncodeError>
where
    T: Serialize + Schema + WireValidation,
{
    let bytes = canonical_request_bytes(value)?;
    Ok(domain_digest(domain, &bytes))
}

pub(crate) fn response_digest<T>(domain: &[u8], value: &T) -> Result<Sha256Digest, EncodeError>
where
    T: Serialize + Schema + WireValidation,
{
    let bytes = canonical_response_bytes(value)?;
    Ok(domain_digest(domain, &bytes))
}

pub(crate) fn domain_digest(domain: &[u8], canonical_bytes: &[u8]) -> Sha256Digest {
    let mut digest = Sha256::new();
    digest.update(domain);
    digest.update((canonical_bytes.len() as u64).to_be_bytes());
    digest.update(canonical_bytes);
    Sha256Digest(digest.finalize().into())
}

fn canonical_bytes_with_limit<T>(value: &T, limit: usize) -> Result<Vec<u8>, EncodeError>
where
    T: Serialize + WireValidation,
{
    value.validate().map_err(EncodeError::Invalid)?;
    let bytes = postcard::to_allocvec(value).map_err(|_| EncodeError::Codec)?;
    if bytes.len() > limit {
        return Err(EncodeError::TooLarge);
    }
    Ok(bytes)
}

fn decode_canonical_with_limit<T>(bytes: &[u8], limit: usize) -> Result<T, DecodeError>
where
    T: DeserializeOwned + Serialize + WireValidation,
{
    if bytes.len() > limit {
        return Err(DecodeError::TooLarge);
    }
    let (value, remaining) =
        postcard::take_from_bytes::<T>(bytes).map_err(|_| DecodeError::Codec)?;
    if !remaining.is_empty() {
        return Err(DecodeError::TrailingBytes);
    }
    let reencoded = postcard::to_allocvec(&value).map_err(|_| DecodeError::Codec)?;
    if reencoded != bytes {
        return Err(DecodeError::NonCanonical);
    }
    value.validate().map_err(DecodeError::Invalid)?;
    Ok(value)
}
