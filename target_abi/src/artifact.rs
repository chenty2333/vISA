use core::convert::TryFrom;

#[cfg(feature = "hash")]
use sha2::{Digest, Sha256};

pub const TARGET_ARTIFACT_MAGIC: [u8; 8] = *b"SEMAOS\0\x01";
pub const TARGET_ARTIFACT_HEADER_LEN: usize = 128;
pub const TARGET_SECTION_HEADER_LEN: usize = 64;
pub const TARGET_ARTIFACT_SCHEMA_MAJOR: u16 = 1;
pub const IMAGE_HASH_OFFSET: usize = 88;
pub const IMAGE_HASH_LEN: usize = 32;
pub const SECTION_HASH_OFFSET: usize = 28;

const HEADER_LEN_OFF: usize = 8;
const IMAGE_LEN_OFF: usize = 16;
const SCHEMA_MAJOR_OFF: usize = 24;
const SCHEMA_MINOR_OFF: usize = 26;
const TARGET_ARCH_OFF: usize = 28;
const TARGET_ABI_OFF: usize = 30;
const ENDIAN_OFF: usize = 32;
const POINTER_WIDTH_OFF: usize = 33;
const ARTIFACT_KIND_OFF: usize = 34;
const CODE_FORMAT_OFF: usize = 36;
const SECTION_COUNT_OFF: usize = 40;
const SECTION_TABLE_OFF_OFF: usize = 48;
const MANIFEST_HASH_OFF: usize = 56;
const FLAGS_OFF: usize = 120;

const SECTION_KIND_OFF: usize = 0;
const SECTION_FLAGS_OFF: usize = 4;
const SECTION_OFFSET_OFF: usize = 8;
const SECTION_LEN_OFF: usize = 16;
const SECTION_ALIGN_OFF: usize = 24;

const REQUIRED_SECTIONS: [SectionKindV1; 7] = [
    SectionKindV1::Manifest,
    SectionKindV1::CodeObject,
    SectionKindV1::HostcallImportTable,
    SectionKindV1::TrapMap,
    SectionKindV1::PcRangeTable,
    SectionKindV1::ProfileRequirements,
    SectionKindV1::Signature,
];

#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TargetArtifactHeaderV1 {
    pub magic: [u8; 8],
    pub header_len: u32,
    pub image_len: u64,
    pub schema_major: u16,
    pub schema_minor: u16,
    pub target_arch: u16,
    pub target_abi: u16,
    pub endian: u8,
    pub pointer_width: u8,
    pub artifact_kind: u16,
    pub code_format: u16,
    pub section_count: u32,
    pub section_table_off: u64,
    pub manifest_hash: [u8; 32],
    pub image_hash: [u8; 32],
    pub flags: u64,
}

impl TargetArtifactHeaderV1 {
    pub const WIRE_LEN: usize = TARGET_ARTIFACT_HEADER_LEN;

    pub const fn fake_riscv64(section_count: u32, image_len: u64) -> Self {
        Self {
            magic: TARGET_ARTIFACT_MAGIC,
            header_len: TARGET_ARTIFACT_HEADER_LEN as u32,
            image_len,
            schema_major: TARGET_ARTIFACT_SCHEMA_MAJOR,
            schema_minor: 0,
            target_arch: TargetArchCodeV1::Riscv64 as u16,
            target_abi: TargetAbiCodeV1::Baremetal as u16,
            endian: 1,
            pointer_width: 64,
            artifact_kind: ArtifactKindCodeV1::Supervisor as u16,
            code_format: CodeFormatCodeV1::Fake as u16,
            section_count,
            section_table_off: TARGET_ARTIFACT_HEADER_LEN as u64,
            manifest_hash: [0; 32],
            image_hash: [0; 32],
            flags: 0,
        }
    }

    pub fn parse(bytes: &[u8]) -> Result<Self, TargetArtifactError> {
        if bytes.len() < TARGET_ARTIFACT_HEADER_LEN {
            return Err(TargetArtifactError::ImageTooSmall);
        }

        let mut magic = [0; 8];
        magic.copy_from_slice(&bytes[..8]);

        let mut manifest_hash = [0; 32];
        manifest_hash.copy_from_slice(&bytes[MANIFEST_HASH_OFF..MANIFEST_HASH_OFF + 32]);

        let mut image_hash = [0; 32];
        image_hash.copy_from_slice(&bytes[IMAGE_HASH_OFFSET..IMAGE_HASH_OFFSET + 32]);

        Ok(Self {
            magic,
            header_len: read_u32(bytes, HEADER_LEN_OFF)?,
            image_len: read_u64(bytes, IMAGE_LEN_OFF)?,
            schema_major: read_u16(bytes, SCHEMA_MAJOR_OFF)?,
            schema_minor: read_u16(bytes, SCHEMA_MINOR_OFF)?,
            target_arch: read_u16(bytes, TARGET_ARCH_OFF)?,
            target_abi: read_u16(bytes, TARGET_ABI_OFF)?,
            endian: bytes[ENDIAN_OFF],
            pointer_width: bytes[POINTER_WIDTH_OFF],
            artifact_kind: read_u16(bytes, ARTIFACT_KIND_OFF)?,
            code_format: read_u16(bytes, CODE_FORMAT_OFF)?,
            section_count: read_u32(bytes, SECTION_COUNT_OFF)?,
            section_table_off: read_u64(bytes, SECTION_TABLE_OFF_OFF)?,
            manifest_hash,
            image_hash,
            flags: read_u64(bytes, FLAGS_OFF)?,
        })
    }

    pub fn write_to(&self, out: &mut [u8]) -> Result<(), TargetArtifactError> {
        if out.len() < TARGET_ARTIFACT_HEADER_LEN {
            return Err(TargetArtifactError::ImageTooSmall);
        }
        out[..TARGET_ARTIFACT_HEADER_LEN].fill(0);
        out[..8].copy_from_slice(&self.magic);
        write_u32(out, HEADER_LEN_OFF, self.header_len)?;
        write_u64(out, IMAGE_LEN_OFF, self.image_len)?;
        write_u16(out, SCHEMA_MAJOR_OFF, self.schema_major)?;
        write_u16(out, SCHEMA_MINOR_OFF, self.schema_minor)?;
        write_u16(out, TARGET_ARCH_OFF, self.target_arch)?;
        write_u16(out, TARGET_ABI_OFF, self.target_abi)?;
        out[ENDIAN_OFF] = self.endian;
        out[POINTER_WIDTH_OFF] = self.pointer_width;
        write_u16(out, ARTIFACT_KIND_OFF, self.artifact_kind)?;
        write_u16(out, CODE_FORMAT_OFF, self.code_format)?;
        write_u32(out, SECTION_COUNT_OFF, self.section_count)?;
        write_u64(out, SECTION_TABLE_OFF_OFF, self.section_table_off)?;
        out[MANIFEST_HASH_OFF..MANIFEST_HASH_OFF + 32].copy_from_slice(&self.manifest_hash);
        out[IMAGE_HASH_OFFSET..IMAGE_HASH_OFFSET + 32].copy_from_slice(&self.image_hash);
        write_u64(out, FLAGS_OFF, self.flags)?;
        Ok(())
    }
}

#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TargetSectionHeaderV1 {
    pub kind: SectionKindV1,
    pub flags: u32,
    pub offset: u64,
    pub len: u64,
    pub align: u32,
    pub hash: [u8; 32],
}

impl TargetSectionHeaderV1 {
    pub const WIRE_LEN: usize = TARGET_SECTION_HEADER_LEN;

    pub const fn new(kind: SectionKindV1, offset: u64, len: u64, align: u32) -> Self {
        Self {
            kind,
            flags: 0,
            offset,
            len,
            align,
            hash: [0; 32],
        }
    }

    pub fn parse(bytes: &[u8]) -> Result<Self, TargetArtifactError> {
        if bytes.len() < TARGET_SECTION_HEADER_LEN {
            return Err(TargetArtifactError::SectionTableOutOfBounds);
        }
        let kind = SectionKindV1::try_from(read_u32(bytes, SECTION_KIND_OFF)?)?;
        let mut hash = [0; 32];
        hash.copy_from_slice(&bytes[SECTION_HASH_OFFSET..SECTION_HASH_OFFSET + 32]);
        Ok(Self {
            kind,
            flags: read_u32(bytes, SECTION_FLAGS_OFF)?,
            offset: read_u64(bytes, SECTION_OFFSET_OFF)?,
            len: read_u64(bytes, SECTION_LEN_OFF)?,
            align: read_u32(bytes, SECTION_ALIGN_OFF)?,
            hash,
        })
    }

    pub fn write_to(&self, out: &mut [u8]) -> Result<(), TargetArtifactError> {
        if out.len() < TARGET_SECTION_HEADER_LEN {
            return Err(TargetArtifactError::SectionTableOutOfBounds);
        }
        out[..TARGET_SECTION_HEADER_LEN].fill(0);
        write_u32(out, SECTION_KIND_OFF, self.kind as u32)?;
        write_u32(out, SECTION_FLAGS_OFF, self.flags)?;
        write_u64(out, SECTION_OFFSET_OFF, self.offset)?;
        write_u64(out, SECTION_LEN_OFF, self.len)?;
        write_u32(out, SECTION_ALIGN_OFF, self.align)?;
        out[SECTION_HASH_OFFSET..SECTION_HASH_OFFSET + 32].copy_from_slice(&self.hash);
        Ok(())
    }
}

#[repr(u32)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SectionKindV1 {
    Manifest = 1,
    ContractMetadata = 2,
    CodeObject = 3,
    Relocation = 4,
    HostcallImportTable = 5,
    TrapMap = 6,
    PcRangeTable = 7,
    MemoryLayout = 8,
    ProfileRequirements = 9,
    DebugLite = 10,
    Signature = 11,
}

impl TryFrom<u32> for SectionKindV1 {
    type Error = TargetArtifactError;

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::Manifest),
            2 => Ok(Self::ContractMetadata),
            3 => Ok(Self::CodeObject),
            4 => Ok(Self::Relocation),
            5 => Ok(Self::HostcallImportTable),
            6 => Ok(Self::TrapMap),
            7 => Ok(Self::PcRangeTable),
            8 => Ok(Self::MemoryLayout),
            9 => Ok(Self::ProfileRequirements),
            10 => Ok(Self::DebugLite),
            11 => Ok(Self::Signature),
            _ => Err(TargetArtifactError::UnknownSectionKind),
        }
    }
}

#[repr(u16)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TargetArchCodeV1 {
    Riscv64 = 1,
    X86_64 = 2,
    Aarch64 = 3,
}

#[repr(u16)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TargetAbiCodeV1 {
    None = 0,
    Baremetal = 1,
    Custom = 2,
}

#[repr(u16)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ArtifactKindCodeV1 {
    Supervisor = 1,
    Service = 2,
    Driver = 3,
    App = 4,
}

#[repr(u16)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CodeFormatCodeV1 {
    WasmtimeSerialized = 1,
    NativeAot = 2,
    Pulley = 3,
    Fake = 4,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TargetArtifactError {
    ImageTooSmall,
    BadMagic,
    UnsupportedSchema,
    BadHeaderLength,
    ImageLengthMismatch,
    SectionTableOutOfBounds,
    UnknownSectionKind,
    SectionOutOfBounds,
    BadSectionAlignment,
    DuplicateRequiredSection(SectionKindV1),
    MissingRequiredSection(SectionKindV1),
    HashUnavailable,
    HashMismatch,
    ManifestHashMismatch,
    SectionHashMismatch(SectionKindV1),
}

#[derive(Debug, PartialEq, Eq)]
pub struct TargetArtifactImage<'a> {
    bytes: &'a [u8],
    header: TargetArtifactHeaderV1,
}

impl<'a> TargetArtifactImage<'a> {
    pub fn parse(bytes: &'a [u8]) -> Result<Self, TargetArtifactError> {
        let header = TargetArtifactHeaderV1::parse(bytes)?;
        let image = Self { bytes, header };
        image.validate()?;
        Ok(image)
    }

    pub const fn bytes(&self) -> &'a [u8] {
        self.bytes
    }

    pub const fn header(&self) -> &TargetArtifactHeaderV1 {
        &self.header
    }

    pub fn sections(&self) -> SectionIter<'a> {
        SectionIter {
            bytes: self.bytes,
            next_offset: self.header.section_table_off as usize,
            remaining: self.header.section_count,
        }
    }

    pub fn section(&self, kind: SectionKindV1) -> Option<TargetSectionHeaderV1> {
        self.sections()
            .flatten()
            .find(|section| section.kind == kind)
    }

    fn validate(&self) -> Result<(), TargetArtifactError> {
        validate_header(self.bytes, &self.header)?;
        let mut required_seen: u16 = 0;
        let mut manifest_section = None;

        for section in self.sections() {
            let section = section?;
            validate_section(self.bytes, &section)?;
            if let Some(bit) = required_section_bit(section.kind) {
                if required_seen & bit != 0 {
                    return Err(TargetArtifactError::DuplicateRequiredSection(section.kind));
                }
                required_seen |= bit;
            }
            if section.kind == SectionKindV1::Manifest {
                manifest_section = Some(section);
            }
            verify_section_payload_hash(self.bytes, &section)?;
        }

        for required in REQUIRED_SECTIONS {
            let Some(bit) = required_section_bit(required) else {
                return Err(TargetArtifactError::MissingRequiredSection(required));
            };
            if required_seen & bit == 0 {
                return Err(TargetArtifactError::MissingRequiredSection(required));
            }
        }

        let manifest_section = manifest_section.ok_or(
            TargetArtifactError::MissingRequiredSection(SectionKindV1::Manifest),
        )?;
        verify_manifest_hash(self.bytes, &self.header, &manifest_section)?;
        verify_canonical_zero_field_image_hash(self.bytes)?;
        Ok(())
    }
}

pub struct SectionIter<'a> {
    bytes: &'a [u8],
    next_offset: usize,
    remaining: u32,
}

impl Iterator for SectionIter<'_> {
    type Item = Result<TargetSectionHeaderV1, TargetArtifactError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.remaining == 0 {
            return None;
        }
        let end = match self.next_offset.checked_add(TARGET_SECTION_HEADER_LEN) {
            Some(end) => end,
            None => return Some(Err(TargetArtifactError::SectionTableOutOfBounds)),
        };
        if end > self.bytes.len() {
            return Some(Err(TargetArtifactError::SectionTableOutOfBounds));
        }
        let section = TargetSectionHeaderV1::parse(&self.bytes[self.next_offset..end]);
        self.next_offset = end;
        self.remaining -= 1;
        Some(section)
    }
}

pub fn canonical_zero_field_image_hash(bytes: &[u8]) -> Result<[u8; 32], TargetArtifactError> {
    let header = TargetArtifactHeaderV1::parse(bytes)?;
    validate_header(bytes, &header)?;

    let mut signature_payload = None;
    let mut signature_section_hash = None;
    let table_off = header.section_table_off as usize;
    for index in 0..header.section_count as usize {
        let section_off = checked_add(
            table_off,
            checked_mul(
                index,
                TARGET_SECTION_HEADER_LEN,
                TargetArtifactError::SectionTableOutOfBounds,
            )?,
            TargetArtifactError::SectionTableOutOfBounds,
        )?;
        let section_end = checked_add(
            section_off,
            TARGET_SECTION_HEADER_LEN,
            TargetArtifactError::SectionTableOutOfBounds,
        )?;
        if section_end > bytes.len() {
            return Err(TargetArtifactError::SectionTableOutOfBounds);
        }
        let section = TargetSectionHeaderV1::parse(&bytes[section_off..section_end])?;
        validate_section(bytes, &section)?;
        if section.kind == SectionKindV1::Signature {
            signature_section_hash = Some((
                section_off + SECTION_HASH_OFFSET,
                section_off + SECTION_HASH_OFFSET + IMAGE_HASH_LEN,
            ));
            signature_payload = Some((
                section.offset as usize,
                checked_add(
                    section.offset as usize,
                    section.len as usize,
                    TargetArtifactError::SectionOutOfBounds,
                )?,
            ));
        }
    }

    #[cfg(not(feature = "hash"))]
    {
        let _ = signature_payload;
        let _ = signature_section_hash;
        return Err(TargetArtifactError::HashUnavailable);
    }

    #[cfg(feature = "hash")]
    {
        let mut hasher = Sha256::new();
        for (index, byte) in bytes.iter().copied().enumerate() {
            let in_image_hash =
                (IMAGE_HASH_OFFSET..IMAGE_HASH_OFFSET + IMAGE_HASH_LEN).contains(&index);
            let in_signature_hash = signature_section_hash
                .map(|(start, end)| (start..end).contains(&index))
                .unwrap_or(false);
            let in_signature_payload = signature_payload
                .map(|(start, end)| (start..end).contains(&index))
                .unwrap_or(false);

            if in_image_hash || in_signature_hash || in_signature_payload {
                hasher.update([0]);
            } else {
                hasher.update([byte]);
            }
        }

        let digest = hasher.finalize();
        let mut out = [0; 32];
        out.copy_from_slice(&digest);
        Ok(out)
    }
}

pub fn verify_canonical_zero_field_image_hash(
    bytes: &[u8],
) -> Result<[u8; 32], TargetArtifactError> {
    let header = TargetArtifactHeaderV1::parse(bytes)?;
    let actual = canonical_zero_field_image_hash(bytes)?;
    if actual != header.image_hash {
        return Err(TargetArtifactError::HashMismatch);
    }
    Ok(actual)
}

fn validate_header(
    bytes: &[u8],
    header: &TargetArtifactHeaderV1,
) -> Result<(), TargetArtifactError> {
    if header.magic != TARGET_ARTIFACT_MAGIC {
        return Err(TargetArtifactError::BadMagic);
    }
    if header.schema_major != TARGET_ARTIFACT_SCHEMA_MAJOR {
        return Err(TargetArtifactError::UnsupportedSchema);
    }
    if header.header_len as usize != TARGET_ARTIFACT_HEADER_LEN {
        return Err(TargetArtifactError::BadHeaderLength);
    }
    if header.image_len as usize != bytes.len() {
        return Err(TargetArtifactError::ImageLengthMismatch);
    }
    let table_off = usize::try_from(header.section_table_off)
        .map_err(|_| TargetArtifactError::SectionTableOutOfBounds)?;
    if table_off < TARGET_ARTIFACT_HEADER_LEN {
        return Err(TargetArtifactError::SectionTableOutOfBounds);
    }
    let table_len = checked_mul(
        header.section_count as usize,
        TARGET_SECTION_HEADER_LEN,
        TargetArtifactError::SectionTableOutOfBounds,
    )?;
    let table_end = checked_add(
        table_off,
        table_len,
        TargetArtifactError::SectionTableOutOfBounds,
    )?;
    if table_end > bytes.len() {
        return Err(TargetArtifactError::SectionTableOutOfBounds);
    }
    Ok(())
}

fn validate_section(
    bytes: &[u8],
    section: &TargetSectionHeaderV1,
) -> Result<(), TargetArtifactError> {
    let offset =
        usize::try_from(section.offset).map_err(|_| TargetArtifactError::SectionOutOfBounds)?;
    let len = usize::try_from(section.len).map_err(|_| TargetArtifactError::SectionOutOfBounds)?;
    let end = checked_add(offset, len, TargetArtifactError::SectionOutOfBounds)?;
    if end > bytes.len() {
        return Err(TargetArtifactError::SectionOutOfBounds);
    }
    if section.align != 0 {
        if !section.align.is_power_of_two() {
            return Err(TargetArtifactError::BadSectionAlignment);
        }
        if offset % section.align as usize != 0 {
            return Err(TargetArtifactError::BadSectionAlignment);
        }
    }
    Ok(())
}

fn section_payload<'a>(
    bytes: &'a [u8],
    section: &TargetSectionHeaderV1,
) -> Result<&'a [u8], TargetArtifactError> {
    let offset =
        usize::try_from(section.offset).map_err(|_| TargetArtifactError::SectionOutOfBounds)?;
    let len = usize::try_from(section.len).map_err(|_| TargetArtifactError::SectionOutOfBounds)?;
    let end = checked_add(offset, len, TargetArtifactError::SectionOutOfBounds)?;
    bytes
        .get(offset..end)
        .ok_or(TargetArtifactError::SectionOutOfBounds)
}

fn verify_section_payload_hash(
    bytes: &[u8],
    section: &TargetSectionHeaderV1,
) -> Result<(), TargetArtifactError> {
    let payload = section_payload(bytes, section)?;
    #[cfg(not(feature = "hash"))]
    {
        let _ = payload;
        return Err(TargetArtifactError::HashUnavailable);
    }

    #[cfg(feature = "hash")]
    {
        let digest: [u8; 32] = Sha256::digest(payload).into();
        if digest != section.hash {
            return Err(TargetArtifactError::SectionHashMismatch(section.kind));
        }
        Ok(())
    }
}

fn verify_manifest_hash(
    bytes: &[u8],
    header: &TargetArtifactHeaderV1,
    section: &TargetSectionHeaderV1,
) -> Result<(), TargetArtifactError> {
    let payload = section_payload(bytes, section)?;
    #[cfg(not(feature = "hash"))]
    {
        let _ = header;
        let _ = payload;
        return Err(TargetArtifactError::HashUnavailable);
    }

    #[cfg(feature = "hash")]
    {
        let digest: [u8; 32] = Sha256::digest(payload).into();
        if digest != header.manifest_hash {
            return Err(TargetArtifactError::ManifestHashMismatch);
        }
        Ok(())
    }
}

fn required_section_bit(kind: SectionKindV1) -> Option<u16> {
    REQUIRED_SECTIONS
        .iter()
        .position(|required| *required == kind)
        .map(|index| 1u16 << index)
}

fn read_u16(bytes: &[u8], offset: usize) -> Result<u16, TargetArtifactError> {
    let end = checked_add(offset, 2, TargetArtifactError::ImageTooSmall)?;
    let slice = bytes
        .get(offset..end)
        .ok_or(TargetArtifactError::ImageTooSmall)?;
    Ok(u16::from_le_bytes([slice[0], slice[1]]))
}

fn read_u32(bytes: &[u8], offset: usize) -> Result<u32, TargetArtifactError> {
    let end = checked_add(offset, 4, TargetArtifactError::ImageTooSmall)?;
    let slice = bytes
        .get(offset..end)
        .ok_or(TargetArtifactError::ImageTooSmall)?;
    Ok(u32::from_le_bytes([slice[0], slice[1], slice[2], slice[3]]))
}

fn read_u64(bytes: &[u8], offset: usize) -> Result<u64, TargetArtifactError> {
    let end = checked_add(offset, 8, TargetArtifactError::ImageTooSmall)?;
    let slice = bytes
        .get(offset..end)
        .ok_or(TargetArtifactError::ImageTooSmall)?;
    Ok(u64::from_le_bytes([
        slice[0], slice[1], slice[2], slice[3], slice[4], slice[5], slice[6], slice[7],
    ]))
}

fn write_u16(bytes: &mut [u8], offset: usize, value: u16) -> Result<(), TargetArtifactError> {
    let end = checked_add(offset, 2, TargetArtifactError::ImageTooSmall)?;
    let slice = bytes
        .get_mut(offset..end)
        .ok_or(TargetArtifactError::ImageTooSmall)?;
    slice.copy_from_slice(&value.to_le_bytes());
    Ok(())
}

fn write_u32(bytes: &mut [u8], offset: usize, value: u32) -> Result<(), TargetArtifactError> {
    let end = checked_add(offset, 4, TargetArtifactError::ImageTooSmall)?;
    let slice = bytes
        .get_mut(offset..end)
        .ok_or(TargetArtifactError::ImageTooSmall)?;
    slice.copy_from_slice(&value.to_le_bytes());
    Ok(())
}

fn write_u64(bytes: &mut [u8], offset: usize, value: u64) -> Result<(), TargetArtifactError> {
    let end = checked_add(offset, 8, TargetArtifactError::ImageTooSmall)?;
    let slice = bytes
        .get_mut(offset..end)
        .ok_or(TargetArtifactError::ImageTooSmall)?;
    slice.copy_from_slice(&value.to_le_bytes());
    Ok(())
}

fn checked_add(
    left: usize,
    right: usize,
    error: TargetArtifactError,
) -> Result<usize, TargetArtifactError> {
    left.checked_add(right).ok_or(error)
}

fn checked_mul(
    left: usize,
    right: usize,
    error: TargetArtifactError,
) -> Result<usize, TargetArtifactError> {
    left.checked_mul(right).ok_or(error)
}

#[cfg(all(test, feature = "hash"))]
mod tests {
    use super::*;

    const REQUIRED_PAYLOAD_LEN: usize = 16;

    #[test]
    fn target_artifact_wire_layout_sizes_are_fixed() {
        assert_eq!(
            core::mem::size_of::<TargetArtifactHeaderV1>(),
            TARGET_ARTIFACT_HEADER_LEN
        );
        assert_eq!(
            core::mem::size_of::<TargetSectionHeaderV1>(),
            TARGET_SECTION_HEADER_LEN
        );
    }

    #[test]
    fn parse_fake_target_artifact_envelope() {
        let image = fake_image(&REQUIRED_SECTIONS);
        let parsed = TargetArtifactImage::parse(&image).expect("fake image parses");

        assert_eq!(parsed.header().magic, TARGET_ARTIFACT_MAGIC);
        assert_eq!(parsed.header().schema_major, 1);
        assert_eq!(
            parsed.header().section_count,
            REQUIRED_SECTIONS.len() as u32
        );
        assert!(parsed.section(SectionKindV1::CodeObject).is_some());
        assert!(parsed.section(SectionKindV1::Signature).is_some());
    }

    #[test]
    fn reject_bad_artifact_magic() {
        let mut image = fake_image(&REQUIRED_SECTIONS);
        image[0] = b'X';

        assert_eq!(
            TargetArtifactImage::parse(&image),
            Err(TargetArtifactError::BadMagic)
        );
    }

    #[test]
    fn reject_section_out_of_bounds() {
        let mut image = fake_image(&REQUIRED_SECTIONS);
        let first_section = TARGET_ARTIFACT_HEADER_LEN;
        let bad_offset = image.len() as u64 + 8;
        write_u64(&mut image, first_section + SECTION_OFFSET_OFF, bad_offset)
            .expect("write bad section offset");

        assert_eq!(
            TargetArtifactImage::parse(&image),
            Err(TargetArtifactError::SectionOutOfBounds)
        );
    }

    #[test]
    fn reject_missing_required_sections() {
        let kinds = [
            SectionKindV1::Manifest,
            SectionKindV1::CodeObject,
            SectionKindV1::HostcallImportTable,
            SectionKindV1::TrapMap,
            SectionKindV1::PcRangeTable,
            SectionKindV1::ProfileRequirements,
        ];
        let image = fake_image(&kinds);

        assert_eq!(
            TargetArtifactImage::parse(&image),
            Err(TargetArtifactError::MissingRequiredSection(
                SectionKindV1::Signature
            ))
        );
    }

    #[test]
    fn canonical_zero_field_hash_stable() {
        let mut image = fake_image(&REQUIRED_SECTIONS);
        let original = canonical_zero_field_image_hash(&image).expect("hash");

        image[IMAGE_HASH_OFFSET..IMAGE_HASH_OFFSET + IMAGE_HASH_LEN].copy_from_slice(&[0xa5; 32]);
        let rewritten = canonical_zero_field_image_hash(&image).expect("hash ignores image_hash");

        assert_eq!(original, rewritten);
    }

    #[test]
    fn reject_section_hash_mismatch() {
        let mut image = fake_image(&REQUIRED_SECTIONS);
        let (start, _) = section_payload_range(&image, SectionKindV1::CodeObject);
        image[start] ^= 0x5a;
        refresh_image_hash(&mut image);

        assert_eq!(
            TargetArtifactImage::parse(&image),
            Err(TargetArtifactError::SectionHashMismatch(
                SectionKindV1::CodeObject
            ))
        );
    }

    #[test]
    fn reject_manifest_hash_mismatch() {
        let mut image = fake_image(&REQUIRED_SECTIONS);
        image[MANIFEST_HASH_OFF] ^= 0xa5;
        refresh_image_hash(&mut image);

        assert_eq!(
            TargetArtifactImage::parse(&image),
            Err(TargetArtifactError::ManifestHashMismatch)
        );
    }

    #[test]
    fn signature_payload_change_requires_signature_section_hash() {
        let mut image = fake_image(&REQUIRED_SECTIONS);
        let (start, _) = section_payload_range(&image, SectionKindV1::Signature);
        image[start] ^= 0x5a;
        refresh_image_hash(&mut image);

        assert_eq!(
            TargetArtifactImage::parse(&image),
            Err(TargetArtifactError::SectionHashMismatch(
                SectionKindV1::Signature
            ))
        );
    }

    #[test]
    fn reject_duplicate_required_sections() {
        let kinds = [
            SectionKindV1::Manifest,
            SectionKindV1::Manifest,
            SectionKindV1::CodeObject,
            SectionKindV1::HostcallImportTable,
            SectionKindV1::TrapMap,
            SectionKindV1::PcRangeTable,
            SectionKindV1::ProfileRequirements,
            SectionKindV1::Signature,
        ];
        let image = fake_image(&kinds);

        assert_eq!(
            TargetArtifactImage::parse(&image),
            Err(TargetArtifactError::DuplicateRequiredSection(
                SectionKindV1::Manifest
            ))
        );
    }

    fn fake_image(kinds: &[SectionKindV1]) -> Vec<u8> {
        let section_table_len = kinds.len() * TARGET_SECTION_HEADER_LEN;
        let payload_base = TARGET_ARTIFACT_HEADER_LEN + section_table_len;
        let image_len = payload_base + kinds.len() * REQUIRED_PAYLOAD_LEN;
        let mut image = vec![0; image_len];

        let header = TargetArtifactHeaderV1::fake_riscv64(kinds.len() as u32, image_len as u64);
        header.write_to(&mut image).expect("write header");

        for (index, kind) in kinds.iter().copied().enumerate() {
            let offset = payload_base + index * REQUIRED_PAYLOAD_LEN;
            image[offset..offset + REQUIRED_PAYLOAD_LEN].fill(kind as u32 as u8);

            let mut section =
                TargetSectionHeaderV1::new(kind, offset as u64, REQUIRED_PAYLOAD_LEN as u64, 1);
            section.hash = Sha256::digest(&image[offset..offset + REQUIRED_PAYLOAD_LEN]).into();
            let section_off = TARGET_ARTIFACT_HEADER_LEN + index * TARGET_SECTION_HEADER_LEN;
            section
                .write_to(&mut image[section_off..section_off + TARGET_SECTION_HEADER_LEN])
                .expect("write section");
        }

        let mut header = TargetArtifactHeaderV1::parse(&image).expect("header");
        if let Some((manifest_start, manifest_end)) =
            optional_section_payload_range(&image, SectionKindV1::Manifest)
        {
            header.manifest_hash = Sha256::digest(&image[manifest_start..manifest_end]).into();
            header.write_to(&mut image).expect("write manifest hash");
        }
        refresh_image_hash(&mut image);
        image
    }

    fn section_payload_range(image: &[u8], kind: SectionKindV1) -> (usize, usize) {
        optional_section_payload_range(image, kind).expect("section payload")
    }

    fn optional_section_payload_range(image: &[u8], kind: SectionKindV1) -> Option<(usize, usize)> {
        let header = TargetArtifactHeaderV1::parse(image).expect("header");
        for index in 0..header.section_count as usize {
            let section_off = TARGET_ARTIFACT_HEADER_LEN + index * TARGET_SECTION_HEADER_LEN;
            let section = TargetSectionHeaderV1::parse(
                &image[section_off..section_off + TARGET_SECTION_HEADER_LEN],
            )
            .expect("section");
            if section.kind == kind {
                let start = section.offset as usize;
                return Some((start, start + section.len as usize));
            }
        }
        None
    }

    fn refresh_image_hash(image: &mut [u8]) {
        image[IMAGE_HASH_OFFSET..IMAGE_HASH_OFFSET + IMAGE_HASH_LEN].fill(0);
        let hash = canonical_zero_field_image_hash(image).expect("canonical image hash");
        image[IMAGE_HASH_OFFSET..IMAGE_HASH_OFFSET + IMAGE_HASH_LEN].copy_from_slice(&hash);
    }
}
