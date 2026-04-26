#[repr(u16)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SignatureSchemeV1 {
    UnsignedResearch = 1,
    DevEd25519 = 2,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DevKeyRecordV1 {
    pub public_key: [u8; 32],
}

#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SignatureRecordV1 {
    pub scheme: SignatureSchemeV1,
    pub flags: u16,
    pub public_key_len: u16,
    pub signature_len: u16,
    pub public_key: [u8; 32],
    pub signature: [u8; 64],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SignatureStatusV1 {
    pub scheme: SignatureSchemeV1,
    pub shape_valid: bool,
    pub signature_enforced: bool,
    pub signature_verified: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SignatureShapeError {
    UnsignedResearchCarriesSignatureBytes,
    DevEd25519PublicKeyLength,
    DevEd25519SignatureLength,
}

impl SignatureRecordV1 {
    pub const fn unsigned_research() -> Self {
        Self {
            scheme: SignatureSchemeV1::UnsignedResearch,
            flags: 0,
            public_key_len: 0,
            signature_len: 0,
            public_key: [0; 32],
            signature: [0; 64],
        }
    }

    pub const fn dev_ed25519(public_key: [u8; 32], signature: [u8; 64]) -> Self {
        Self {
            scheme: SignatureSchemeV1::DevEd25519,
            flags: 0,
            public_key_len: 32,
            signature_len: 64,
            public_key,
            signature,
        }
    }

    pub const fn dev_key(&self) -> Option<DevKeyRecordV1> {
        match self.scheme {
            SignatureSchemeV1::DevEd25519
                if self.public_key_len == 32 && self.signature_len == 64 =>
            {
                Some(DevKeyRecordV1 {
                    public_key: self.public_key,
                })
            }
            _ => None,
        }
    }

    pub const fn validate_shape(&self) -> Result<SignatureStatusV1, SignatureShapeError> {
        match self.scheme {
            SignatureSchemeV1::UnsignedResearch => {
                if self.public_key_len != 0 || self.signature_len != 0 {
                    return Err(SignatureShapeError::UnsignedResearchCarriesSignatureBytes);
                }
                Ok(SignatureStatusV1 {
                    scheme: self.scheme,
                    shape_valid: true,
                    signature_enforced: false,
                    signature_verified: false,
                })
            }
            SignatureSchemeV1::DevEd25519 => {
                if self.public_key_len != 32 {
                    return Err(SignatureShapeError::DevEd25519PublicKeyLength);
                }
                if self.signature_len != 64 {
                    return Err(SignatureShapeError::DevEd25519SignatureLength);
                }
                Ok(SignatureStatusV1 {
                    scheme: self.scheme,
                    shape_valid: true,
                    signature_enforced: true,
                    signature_verified: false,
                })
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signature_unsigned_research_is_not_reported_as_verified() {
        let status = SignatureRecordV1::unsigned_research()
            .validate_shape()
            .expect("unsigned-research signature shape");

        assert_eq!(status.scheme, SignatureSchemeV1::UnsignedResearch);
        assert!(status.shape_valid);
        assert!(!status.signature_enforced);
        assert!(!status.signature_verified);
    }

    #[test]
    fn signature_dev_ed25519_fixed_lengths() {
        let record = SignatureRecordV1::dev_ed25519([7; 32], [9; 64]);
        let status = record.validate_shape().expect("dev-ed25519 shape");

        assert_eq!(record.public_key_len, 32);
        assert_eq!(record.signature_len, 64);
        assert_eq!(record.dev_key().expect("dev key").public_key, [7; 32]);
        assert!(status.signature_enforced);
        assert!(!status.signature_verified);
    }
}
