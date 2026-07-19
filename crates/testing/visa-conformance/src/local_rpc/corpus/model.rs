use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use super::GoldenCorpusError;

pub const CORPUS_SCHEMA: &str = "visa.local-rpc-golden-corpus.v1";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GoldenCorpus {
    pub schema: String,
    pub corpus_id: String,
    pub rpc_schema: String,
    pub family_id_hex: String,
    pub canonical_encoding: String,
    pub construction: String,
    pub cases: Vec<GoldenCase>,
    pub negative_cases: Vec<NegativeCase>,
    pub coverage: Vec<TypeCoverage>,
}

impl GoldenCorpus {
    pub fn validate(&self) -> Result<(), GoldenCorpusError> {
        if self.schema != CORPUS_SCHEMA
            || self.corpus_id.is_empty()
            || self.rpc_schema.is_empty()
            || self.family_id_hex.len() != 32
            || self.canonical_encoding != "postcard-1.1.3"
            || self.construction != "rust-constructed-no-canonical-byte-source-literals"
            || self.cases.is_empty()
            || self.negative_cases.is_empty()
            || self.coverage.is_empty()
        {
            return Err(GoldenCorpusError::Contract(format!(
                "{} corpus header is invalid",
                self.corpus_id
            )));
        }
        let mut ids = BTreeSet::new();
        for case in &self.cases {
            if !ids.insert(case.case_id.as_str()) {
                return Err(GoldenCorpusError::Contract(format!(
                    "{} repeats case ID {}",
                    self.corpus_id, case.case_id
                )));
            }
            case.validate()?;
        }
        for case in &self.negative_cases {
            if !ids.insert(case.case_id.as_str()) {
                return Err(GoldenCorpusError::Contract(format!(
                    "{} repeats case ID {}",
                    self.corpus_id, case.case_id
                )));
            }
            case.validate()?;
        }
        for coverage in &self.coverage {
            coverage.validate()?;
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum WireDirection {
    Request,
    Response,
    Replay,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GoldenCase {
    pub case_id: String,
    pub direction: WireDirection,
    pub semantic_variant: String,
    pub byte_length: u32,
    pub bytes_hex: String,
    pub sha256: String,
}

impl GoldenCase {
    fn validate(&self) -> Result<(), GoldenCorpusError> {
        let bytes = decode_hex(&self.bytes_hex)?;
        if self.case_id.is_empty()
            || self.semantic_variant.is_empty()
            || usize::try_from(self.byte_length).ok() != Some(bytes.len())
            || self.sha256 != hex_digest(&bytes)
        {
            return Err(GoldenCorpusError::Contract(format!(
                "golden case {} is internally inconsistent",
                self.case_id
            )));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NegativeCase {
    pub case_id: String,
    pub mutation: String,
    pub target: String,
    pub expected_rejection: String,
    pub byte_length: u32,
    pub bytes_hex: Option<String>,
    pub sha256: String,
}

impl NegativeCase {
    fn validate(&self) -> Result<(), GoldenCorpusError> {
        if self.case_id.is_empty()
            || self.mutation.is_empty()
            || self.target.is_empty()
            || self.expected_rejection.is_empty()
            || self.sha256.len() != 64
        {
            return Err(GoldenCorpusError::Contract(format!(
                "negative case {} is incomplete",
                self.case_id
            )));
        }
        if let Some(bytes_hex) = &self.bytes_hex {
            let bytes = decode_hex(bytes_hex)?;
            if usize::try_from(self.byte_length).ok() != Some(bytes.len())
                || self.sha256 != hex_digest(&bytes)
            {
                return Err(GoldenCorpusError::Contract(format!(
                    "negative case {} is internally inconsistent",
                    self.case_id
                )));
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TypeCoverage {
    pub type_name: String,
    pub variants: Vec<String>,
}

impl TypeCoverage {
    fn validate(&self) -> Result<(), GoldenCorpusError> {
        if self.type_name.is_empty() || self.variants.is_empty() {
            return Err(GoldenCorpusError::Contract("type coverage entry is empty".to_owned()));
        }
        let variants: BTreeSet<_> = self.variants.iter().collect();
        if variants.len() != self.variants.len() {
            return Err(GoldenCorpusError::Contract(format!(
                "{} repeats a covered variant",
                self.type_name
            )));
        }
        Ok(())
    }
}

pub struct CorpusBuilder {
    corpus_id: &'static str,
    rpc_schema: &'static str,
    family_id: [u8; 16],
    cases: Vec<GoldenCase>,
    negative_cases: Vec<NegativeCase>,
    coverage: BTreeMap<String, BTreeSet<String>>,
}

impl CorpusBuilder {
    pub fn new(corpus_id: &'static str, rpc_schema: &'static str, family_id: [u8; 16]) -> Self {
        Self {
            corpus_id,
            rpc_schema,
            family_id,
            cases: Vec::new(),
            negative_cases: Vec::new(),
            coverage: BTreeMap::new(),
        }
    }

    pub fn push(
        &mut self,
        case_id: impl Into<String>,
        direction: WireDirection,
        semantic_variant: impl Into<String>,
        bytes: Vec<u8>,
        coverage: &[(&str, &str)],
    ) {
        for (type_name, variant) in coverage {
            self.coverage.entry((*type_name).to_owned()).or_default().insert((*variant).to_owned());
        }
        self.cases.push(golden_case(case_id, direction, semantic_variant, bytes));
    }

    #[allow(clippy::too_many_arguments)]
    pub fn push_negative(
        &mut self,
        case_id: impl Into<String>,
        mutation: impl Into<String>,
        target: impl Into<String>,
        expected_rejection: impl Into<String>,
        bytes: Option<Vec<u8>>,
        byte_length: usize,
        sha256: String,
    ) {
        self.negative_cases.push(NegativeCase {
            case_id: case_id.into(),
            mutation: mutation.into(),
            target: target.into(),
            expected_rejection: expected_rejection.into(),
            byte_length: u32::try_from(byte_length).expect("local RPC case length fits u32"),
            bytes_hex: bytes.as_ref().map(|value| encode_hex(value)),
            sha256,
        });
    }

    pub fn finish(self) -> Result<GoldenCorpus, GoldenCorpusError> {
        let corpus = GoldenCorpus {
            schema: CORPUS_SCHEMA.to_owned(),
            corpus_id: self.corpus_id.to_owned(),
            rpc_schema: self.rpc_schema.to_owned(),
            family_id_hex: encode_hex(&self.family_id),
            canonical_encoding: "postcard-1.1.3".to_owned(),
            construction: "rust-constructed-no-canonical-byte-source-literals".to_owned(),
            cases: self.cases,
            negative_cases: self.negative_cases,
            coverage: self
                .coverage
                .into_iter()
                .map(|(type_name, variants)| TypeCoverage {
                    type_name,
                    variants: variants.into_iter().collect(),
                })
                .collect(),
        };
        corpus.validate()?;
        Ok(corpus)
    }
}

pub fn encode_hex(bytes: &[u8]) -> String {
    use core::fmt::Write as _;

    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        write!(&mut output, "{byte:02x}").expect("writing to String is infallible");
    }
    output
}

pub fn hex_digest(bytes: &[u8]) -> String {
    encode_hex(&Sha256::digest(bytes))
}

fn golden_case(
    case_id: impl Into<String>,
    direction: WireDirection,
    semantic_variant: impl Into<String>,
    bytes: Vec<u8>,
) -> GoldenCase {
    GoldenCase {
        case_id: case_id.into(),
        direction,
        semantic_variant: semantic_variant.into(),
        byte_length: u32::try_from(bytes.len()).expect("local RPC case length fits u32"),
        bytes_hex: encode_hex(&bytes),
        sha256: hex_digest(&bytes),
    }
}

fn decode_hex(value: &str) -> Result<Vec<u8>, GoldenCorpusError> {
    if !value.len().is_multiple_of(2) || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(GoldenCorpusError::Contract(
            "corpus contains invalid hexadecimal bytes".to_owned(),
        ));
    }
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let pair = std::str::from_utf8(pair).expect("ASCII hex is UTF-8");
            u8::from_str_radix(pair, 16).map_err(|_| {
                GoldenCorpusError::Contract("corpus contains invalid hexadecimal bytes".to_owned())
            })
        })
        .collect()
}
