use std::io::{self, Write};

use contract_core::Digest;
use visa_component_adapter::{AdapterError, component_digest};

pub const EXECUTION_CARRIER: &str = "owned-component-profile-stdin-frame-v2";

const FRAME_MAGIC: &[u8; 8] = b"VISAWCG2";
const MAX_COMPONENT_BYTES: usize = 64 * 1024 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub(crate) enum WacogoProfile {
    CooperativeHandoff = 1,
    RegularFile = 2,
}

impl WacogoProfile {
    pub(crate) const fn id(self) -> &'static str {
        match self {
            Self::CooperativeHandoff => "cooperative-handoff-v1",
            Self::RegularFile => "regular-file-v1",
        }
    }
}

/// Exact Component bytes owned by a runtime-bound prepared process.
#[derive(Clone, Debug)]
pub(crate) struct PreparedComponentBytes {
    bytes: Vec<u8>,
    digest: Digest,
    profile: WacogoProfile,
}

impl PreparedComponentBytes {
    pub(crate) fn capture(
        bytes: &[u8],
        expected: Digest,
        profile: WacogoProfile,
    ) -> Result<Self, AdapterError> {
        if bytes.len() > MAX_COMPONENT_BYTES {
            return Err(AdapterError::InvalidComponent(format!(
                "wacogo Component exceeds the carrier limit of {MAX_COMPONENT_BYTES} bytes"
            )));
        }
        let digest = component_digest(bytes);
        if digest != expected {
            return Err(AdapterError::ComponentDigestMismatch { expected, actual: digest });
        }
        Ok(Self { bytes: bytes.to_vec(), digest, profile })
    }

    pub(crate) const fn digest(&self) -> Digest {
        self.digest
    }

    pub(crate) fn digest_hex(&self) -> String {
        hex::encode(self.digest.0)
    }

    pub(crate) const fn profile(&self) -> WacogoProfile {
        self.profile
    }

    pub(crate) fn validate(&self) -> Result<(), AdapterError> {
        if self.bytes.len() > MAX_COMPONENT_BYTES || component_digest(&self.bytes) != self.digest {
            return Err(AdapterError::InvalidComponent(
                "prepared wacogo Component no longer matches its captured byte identity".into(),
            ));
        }
        Ok(())
    }

    pub(crate) fn write_frame(&self, writer: &mut impl Write) -> io::Result<()> {
        self.validate().map_err(io::Error::other)?;
        writer.write_all(FRAME_MAGIC)?;
        writer.write_all(&[self.profile as u8])?;
        writer.write_all(
            &u64::try_from(self.bytes.len())
                .map_err(|_| io::Error::other("Component length does not fit u64"))?
                .to_be_bytes(),
        )?;
        writer.write_all(&self.digest.0)?;
        writer.write_all(&self.bytes)?;
        writer.flush()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn carrier_is_versioned_bounded_and_binds_the_exact_bytes() {
        let bytes = b"\0asm\r\0\x01\0";
        let digest = component_digest(bytes);
        let prepared =
            PreparedComponentBytes::capture(bytes, digest, WacogoProfile::RegularFile).unwrap();
        let mut frame = Vec::new();
        prepared.write_frame(&mut frame).unwrap();

        assert_eq!(&frame[..8], FRAME_MAGIC);
        assert_eq!(frame[8], WacogoProfile::RegularFile as u8);
        assert_eq!(u64::from_be_bytes(frame[9..17].try_into().unwrap()), bytes.len() as u64);
        assert_eq!(&frame[17..49], &digest.0);
        assert_eq!(&frame[49..], bytes);
    }

    #[test]
    fn capture_rejects_a_different_expected_digest() {
        let error = PreparedComponentBytes::capture(
            b"component",
            Digest::ZERO,
            WacogoProfile::CooperativeHandoff,
        )
        .unwrap_err();
        assert_eq!(
            error.kind(),
            visa_component_adapter::AdapterFailureKind::ComponentDigestMismatch
        );
    }
}
