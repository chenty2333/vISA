use alloc::vec::Vec;

use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use crate::{CanonicalState, Digest, SnapshotBody};

pub const CANONICAL_ENCODING: &str = "postcard-1.1.3";
pub const DIGEST_ALGORITHM: &str = "sha-256";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EncodeError;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DecodeError;

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
    postcard::from_bytes(bytes).map_err(|_| DecodeError)
}

pub fn canonical_digest<T>(value: &T) -> Result<Digest, EncodeError>
where
    T: Serialize + ?Sized,
{
    let encoded = canonical_bytes(value)?;
    let mut hasher = Sha256::new();
    hasher.update(encoded);
    Ok(Digest::from_bytes(hasher.finalize().into()))
}

pub fn state_digest(state: &CanonicalState) -> Result<Digest, EncodeError> {
    canonical_digest(state)
}

pub fn snapshot_integrity(body: &SnapshotBody) -> Result<Digest, EncodeError> {
    canonical_digest(body)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Generation, Identity};

    #[test]
    fn canonical_codec_round_trips_and_hashes_the_encoded_bytes() {
        let value = (Identity::from_u128(7), Generation(3));
        let bytes = canonical_bytes(&value).expect("contract value encodes");

        assert_eq!(
            canonical_from_bytes::<(Identity, Generation)>(&bytes).expect("contract value decodes"),
            value
        );
        assert_eq!(
            canonical_digest(&value).expect("contract value hashes"),
            Digest::from_bytes(Sha256::digest(bytes).into())
        );
    }
}
