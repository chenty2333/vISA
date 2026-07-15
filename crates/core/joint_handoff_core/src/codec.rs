use alloc::vec::Vec;

use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use crate::{Digest, ReceiptKind, ReceiptRequest, ReceiptRequestBinding, ReceiptRequestParameters};

pub const JOINT_CANONICAL_ENCODING: &str = "postcard-1.1.3";
pub const JOINT_DIGEST_ALGORITHM: &str = "sha-256";

const RECEIPT_DOMAIN: &[u8] = b"vISA/joint-handoff/receipt/v1\0";
const REQUEST_PARAMETERS_DOMAIN: &[u8] = b"vISA/joint-handoff/request-parameters/v1\0";
const REQUEST_BINDING_DOMAIN: &[u8] = b"vISA/joint-handoff/request-binding/v1\0";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EncodeError;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DecodeError {
    Codec,
    TrailingBytes,
}

pub fn canonical_bytes<T>(value: &T) -> Result<Vec<u8>, EncodeError>
where
    T: Serialize + ?Sized,
{
    postcard::to_allocvec(value).map_err(|_| EncodeError)
}

pub fn canonical_from_bytes<'de, T>(bytes: &'de [u8]) -> Result<T, DecodeError>
where
    T: Deserialize<'de>,
{
    let (value, remaining) = postcard::take_from_bytes(bytes).map_err(|_| DecodeError::Codec)?;
    if remaining.is_empty() { Ok(value) } else { Err(DecodeError::TrailingBytes) }
}

pub fn canonical_digest<T>(value: &T) -> Result<Digest, EncodeError>
where
    T: Serialize + ?Sized,
{
    let encoded = canonical_bytes(value)?;
    Ok(Digest::from_bytes(Sha256::digest(encoded).into()))
}

pub fn receipt_digest<T>(kind: ReceiptKind, value: &T) -> Result<Digest, EncodeError>
where
    T: Serialize + ?Sized,
{
    let encoded = canonical_bytes(value)?;
    let length = u64::try_from(encoded.len()).map_err(|_| EncodeError)?;
    let mut digest = Sha256::new();
    digest.update(RECEIPT_DOMAIN);
    digest.update([kind as u8]);
    digest.update(length.to_be_bytes());
    digest.update(encoded);
    Ok(Digest::from_bytes(digest.finalize().into()))
}

pub fn receipt_request_parameters_digest(
    value: &ReceiptRequestParameters,
) -> Result<Digest, EncodeError> {
    domain_digest(REQUEST_PARAMETERS_DOMAIN, value)
}

pub fn receipt_request_binding(
    request: &ReceiptRequest,
) -> Result<ReceiptRequestBinding, EncodeError> {
    Ok(ReceiptRequestBinding {
        version: request.version,
        kind: request.kind,
        key: request.key,
        operation: request.operation,
        expected_state_sequence: request.expected_state_sequence,
        expected_previous_receipt_digest: request.expected_previous_receipt_digest,
        parameters_digest: receipt_request_parameters_digest(&request.parameters)?,
    })
}

pub fn receipt_request_digest(request: &ReceiptRequest) -> Result<Digest, EncodeError> {
    domain_digest(REQUEST_BINDING_DOMAIN, &receipt_request_binding(request)?)
}

fn domain_digest<T>(domain: &[u8], value: &T) -> Result<Digest, EncodeError>
where
    T: Serialize + ?Sized,
{
    let encoded = canonical_bytes(value)?;
    let length = u64::try_from(encoded.len()).map_err(|_| EncodeError)?;
    let mut digest = Sha256::new();
    digest.update(domain);
    digest.update(length.to_be_bytes());
    digest.update(encoded);
    Ok(Digest::from_bytes(digest.finalize().into()))
}
