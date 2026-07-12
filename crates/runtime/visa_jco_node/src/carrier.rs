use std::io::{self, Write};

use contract_core::Digest;
use sha2::{Digest as _, Sha256};
use visa_component_adapter::AdapterError;

pub(crate) const EXECUTION_CARRIER: &str = "owned-bytes-stdin-frame-v1";

const FRAME_MAGIC: &[u8; 8] = b"VISAJCO1";
const ENTRYPOINT_KIND: u8 = 1;
const CORE_MODULE_KIND: u8 = 2;
const MAX_FILES: usize = 64;
const MAX_NAME_BYTES: usize = 1024;
const MAX_FILE_BYTES: usize = 64 * 1024 * 1024;
const MAX_TOTAL_BYTES: usize = 256 * 1024 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum GraphFileKind {
    Entrypoint,
    CoreModule,
}

impl GraphFileKind {
    const fn wire_value(self) -> u8 {
        match self {
            Self::Entrypoint => ENTRYPOINT_KIND,
            Self::CoreModule => CORE_MODULE_KIND,
        }
    }
}

#[derive(Clone, Debug)]
pub(crate) struct PreparedGraphFile {
    name: String,
    bytes: Vec<u8>,
    digest: Digest,
    kind: GraphFileKind,
}

impl PreparedGraphFile {
    pub(crate) fn name(&self) -> &str {
        &self.name
    }

    pub(crate) fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub(crate) const fn digest(&self) -> Digest {
        self.digest
    }

    pub(crate) const fn kind(&self) -> GraphFileKind {
        self.kind
    }
}

/// One path-free Jco output graph owned by a prepared adapter value.
///
/// The publisher's pathnames never enter this value. The same owned bytes are
/// used for the prepared manifest, graph digest, preflight, and the bounded
/// startup frame consumed by Node.
#[derive(Clone, Debug)]
pub(crate) struct PreparedExecutionGraph {
    files: Vec<PreparedGraphFile>,
    generated_digest: Digest,
    total_bytes: usize,
}

impl PreparedExecutionGraph {
    pub(crate) fn new(
        entrypoint_name: String,
        entrypoint_bytes: Vec<u8>,
        core_modules: Vec<(String, Vec<u8>)>,
    ) -> Result<Self, AdapterError> {
        if core_modules.is_empty() {
            return Err(invalid_graph("Jco did not emit any core WebAssembly modules"));
        }
        let file_count = core_modules.len().checked_add(1).ok_or_else(|| {
            invalid_graph("Jco generated artifact count overflowed the carrier limit")
        })?;
        if file_count > MAX_FILES {
            return Err(invalid_graph(format!(
                "Jco generated {file_count} artifacts, exceeding the carrier limit of {MAX_FILES}"
            )));
        }

        let mut files = Vec::with_capacity(file_count);
        files.push(graph_file(entrypoint_name, entrypoint_bytes, GraphFileKind::Entrypoint)?);
        for (name, bytes) in core_modules {
            files.push(graph_file(name, bytes, GraphFileKind::CoreModule)?);
        }
        files.sort_by(|left, right| left.name.cmp(&right.name));
        for pair in files.windows(2) {
            if pair[0].name == pair[1].name {
                return Err(invalid_graph(format!(
                    "Jco generated duplicate artifact path {}",
                    pair[0].name
                )));
            }
        }

        let total_bytes = files.iter().try_fold(0_usize, |total, file| {
            total
                .checked_add(file.bytes.len())
                .filter(|total| *total <= MAX_TOTAL_BYTES)
                .ok_or_else(|| {
                    invalid_graph(format!(
                        "Jco generated artifact bytes exceed the carrier limit of {MAX_TOTAL_BYTES}"
                    ))
                })
        })?;
        let generated_digest = generated_graph_digest(&files);
        let graph = Self { files, generated_digest, total_bytes };
        graph.validate()?;
        Ok(graph)
    }

    pub(crate) fn files(&self) -> &[PreparedGraphFile] {
        &self.files
    }

    pub(crate) fn entrypoint(&self) -> &PreparedGraphFile {
        self.files
            .iter()
            .find(|file| file.kind == GraphFileKind::Entrypoint)
            .expect("validated prepared graph has one entrypoint")
    }

    pub(crate) const fn generated_digest(&self) -> Digest {
        self.generated_digest
    }

    pub(crate) fn generated_digest_hex(&self) -> String {
        hex(&self.generated_digest.0)
    }

    pub(crate) fn core_module_digests(&self) -> Vec<Digest> {
        self.files
            .iter()
            .filter(|file| file.kind == GraphFileKind::CoreModule)
            .map(|file| file.digest)
            .collect()
    }

    pub(crate) fn validate(&self) -> Result<(), AdapterError> {
        if self.files.is_empty() || self.files.len() > MAX_FILES {
            return Err(invalid_graph("prepared Jco graph has an invalid artifact count"));
        }
        let mut entrypoints = 0_usize;
        let mut cores = 0_usize;
        let mut total = 0_usize;
        let mut previous = None;
        for file in &self.files {
            validate_file(file)?;
            if previous.is_some_and(|previous: &str| previous >= file.name.as_str()) {
                return Err(invalid_graph(
                    "prepared Jco graph artifact names are not strictly sorted",
                ));
            }
            previous = Some(&file.name);
            match file.kind {
                GraphFileKind::Entrypoint => entrypoints += 1,
                GraphFileKind::CoreModule => cores += 1,
            }
            total = total
                .checked_add(file.bytes.len())
                .filter(|total| *total <= MAX_TOTAL_BYTES)
                .ok_or_else(|| {
                invalid_graph("prepared Jco graph exceeds the carrier byte limit")
            })?;
        }
        if entrypoints != 1 || cores == 0 {
            return Err(invalid_graph(format!(
                "prepared Jco graph requires one entrypoint and at least one core module, found {entrypoints} and {cores}"
            )));
        }
        if total != self.total_bytes || generated_graph_digest(&self.files) != self.generated_digest
        {
            return Err(invalid_graph(
                "prepared Jco graph no longer matches its captured byte identity",
            ));
        }
        Ok(())
    }

    /// Write the versioned startup frame without materializing a second copy.
    pub(crate) fn write_frame(&self, writer: &mut impl Write) -> io::Result<()> {
        self.validate().map_err(io::Error::other)?;
        writer.write_all(FRAME_MAGIC)?;
        writer.write_all(
            &u32::try_from(self.files.len())
                .map_err(|_| io::Error::other("carrier artifact count does not fit u32"))?
                .to_be_bytes(),
        )?;
        for file in &self.files {
            writer.write_all(&[file.kind.wire_value()])?;
            writer.write_all(
                &u32::try_from(file.name.len())
                    .map_err(|_| io::Error::other("carrier artifact name does not fit u32"))?
                    .to_be_bytes(),
            )?;
            writer.write_all(
                &u64::try_from(file.bytes.len())
                    .map_err(|_| io::Error::other("carrier artifact length does not fit u64"))?
                    .to_be_bytes(),
            )?;
            writer.write_all(&file.digest.0)?;
            writer.write_all(file.name.as_bytes())?;
        }
        for file in &self.files {
            writer.write_all(&file.bytes)?;
        }
        writer.flush()
    }
}

fn graph_file(
    name: String,
    bytes: Vec<u8>,
    kind: GraphFileKind,
) -> Result<PreparedGraphFile, AdapterError> {
    let file = PreparedGraphFile { digest: hash(&bytes), name, bytes, kind };
    validate_file(&file)?;
    Ok(file)
}

fn validate_file(file: &PreparedGraphFile) -> Result<(), AdapterError> {
    if file.name.is_empty() || file.name.len() > MAX_NAME_BYTES || !file.name.is_ascii() {
        return Err(invalid_graph(format!(
            "Jco generated an invalid carrier artifact name {:?}",
            file.name
        )));
    }
    if file.bytes.len() > MAX_FILE_BYTES {
        return Err(invalid_graph(format!(
            "Jco generated artifact {} exceeds the carrier per-file limit of {MAX_FILE_BYTES}",
            file.name
        )));
    }
    if hash(&file.bytes) != file.digest {
        return Err(invalid_graph(format!(
            "Jco generated artifact {} no longer matches its captured digest",
            file.name
        )));
    }
    Ok(())
}

fn generated_graph_digest(files: &[PreparedGraphFile]) -> Digest {
    let mut hasher = Sha256::new();
    for file in files {
        hasher.update((file.name.len() as u64).to_be_bytes());
        hasher.update(file.name.as_bytes());
        hasher.update((file.bytes.len() as u64).to_be_bytes());
        hasher.update(&file.bytes);
    }
    Digest::from_bytes(hasher.finalize().into())
}

fn hash(bytes: &[u8]) -> Digest {
    Digest::from_bytes(Sha256::digest(bytes).into())
}

fn hex(bytes: &[u8]) -> String {
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write as _;
        write!(&mut encoded, "{byte:02x}").expect("writing to a String cannot fail");
    }
    encoded
}

fn invalid_graph(message: impl Into<String>) -> AdapterError {
    AdapterError::InvalidComponent(format!(
        "invalid prepared Jco execution graph: {}",
        message.into()
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn graph_owns_exact_bytes_and_writes_a_stable_bounded_frame() {
        let mut publisher_entry = b"export function instantiate() {}\n".to_vec();
        let mut publisher_core = b"\0asm\x01\0\0\0".to_vec();
        let graph = PreparedExecutionGraph::new(
            "handoff-component.component.js".into(),
            publisher_entry.clone(),
            vec![("handoff-component.component.core.wasm".into(), publisher_core.clone())],
        )
        .unwrap();
        let digest = graph.generated_digest();
        let mut first = Vec::new();
        graph.write_frame(&mut first).unwrap();

        publisher_entry.fill(b'x');
        publisher_core.fill(b'y');

        let mut second = Vec::new();
        graph.write_frame(&mut second).unwrap();
        assert_eq!(first, second);
        assert_eq!(graph.generated_digest(), digest);
        assert!(!first.windows(8).any(|window| window == b"xxxxxxxx"));
    }

    #[test]
    fn graph_requires_one_entrypoint_and_at_least_one_core_module() {
        assert!(
            PreparedExecutionGraph::new("entry.js".into(), b"export {}".to_vec(), vec![]).is_err()
        );
    }

    #[test]
    fn graph_rejects_duplicate_and_oversized_names() {
        let duplicate = PreparedExecutionGraph::new(
            "same".into(),
            b"export {}".to_vec(),
            vec![("same".into(), b"\0asm\x01\0\0\0".to_vec())],
        );
        assert!(duplicate.is_err());
        let oversized = "x".repeat(MAX_NAME_BYTES + 1);
        assert!(
            PreparedExecutionGraph::new(
                oversized,
                b"export {}".to_vec(),
                vec![("core.wasm".into(), b"\0asm\x01\0\0\0".to_vec())],
            )
            .is_err()
        );
    }
}
