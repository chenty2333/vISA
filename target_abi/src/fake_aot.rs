use core::convert::TryFrom;

pub const FAKE_AOT_MAGIC: [u8; 8] = *b"FAKEAOT1";
pub const FAKE_AOT_VERSION_MAJOR: u16 = 1;
pub const FAKE_AOT_VERSION_MINOR: u16 = 0;
pub const FAKE_AOT_CODE_ALIGN: u32 = 4096;
pub const FAKE_AOT_DEFAULT_CODE_LEN: usize = 4096;
pub const FAKE_AOT_DEFAULT_PC_RANGE_TABLE_BYTES: usize = 16;
pub const FAKE_AOT_DEFAULT_TRAP_MAP_BYTES: usize = 16;
pub const FAKE_AOT_DEFAULT_DEBUG_LITE_BYTES: usize = 64;
pub const FAKE_AOT_DEFAULT_BLOB_LEN: usize = FAKE_AOT_CODE_ALIGN as usize
    + FAKE_AOT_DEFAULT_CODE_LEN
    + FAKE_AOT_DEFAULT_PC_RANGE_TABLE_BYTES
    + FAKE_AOT_DEFAULT_TRAP_MAP_BYTES
    + FAKE_AOT_DEFAULT_DEBUG_LITE_BYTES;

pub const RV64_ENTRY_RETURN_OK_OFFSET: u64 = 0x0000;
pub const RV64_ENTRY_HOSTCALL_TAIL_OFFSET: u64 = 0x0010;
pub const RV64_ENTRY_TRAP_EBREAK_OFFSET: u64 = 0x0020;

pub const RV64_ENTRY_RETURN_OK_BYTES: [u8; 8] = [0x13, 0x05, 0x00, 0x00, 0x67, 0x80, 0x00, 0x00];
pub const RV64_ENTRY_HOSTCALL_TAIL_BYTES: [u8; 4] = [0x67, 0x80, 0x05, 0x00];
pub const RV64_ENTRY_TRAP_EBREAK_BYTES: [u8; 4] = [0x73, 0x00, 0x10, 0x00];

pub const FAKE_AOT_ENTRY_RETURN_OK_NAME_OFF: u32 = 0;
pub const FAKE_AOT_ENTRY_HOSTCALL_TAIL_NAME_OFF: u32 = 16;
pub const FAKE_AOT_ENTRY_TRAP_EBREAK_NAME_OFF: u32 = 36;
pub const FAKE_AOT_HOSTCALL_DEMO_ID: u32 = 1;
pub const FAKE_AOT_HOSTCALL_FRAME_LAYOUT_VERSION: u16 = 1;
pub const FAKE_AOT_HOSTCALL_ARG_COUNT: u16 = 2;
pub const FAKE_AOT_HOSTCALL_RET_COUNT: u16 = 1;
pub const FAKE_AOT_TRAP_KIND_EBREAK: u16 = 1;

#[cfg(test)]
const FAKE_AOT_DEBUG_NAMES: &[u8] = b"entry_return_ok\0entry_hostcall_tail\0entry_trap_ebreak\0";

const HEADER_LEN_OFF: usize = 8;
const BLOB_LEN_OFF: usize = 16;
const VERSION_MAJOR_OFF: usize = 24;
const VERSION_MINOR_OFF: usize = 26;
const TARGET_ARCH_OFF: usize = 28;
const ENDIAN_OFF: usize = 30;
const POINTER_WIDTH_OFF: usize = 31;
const FLAGS_OFF: usize = 32;
const ENTRY_TABLE_OFF_OFF: usize = 40;
const ENTRY_TABLE_LEN_OFF: usize = 48;
const HOSTCALL_STUB_TABLE_OFF_OFF: usize = 56;
const HOSTCALL_STUB_TABLE_LEN_OFF: usize = 64;
const TRAP_STUB_TABLE_OFF_OFF: usize = 72;
const TRAP_STUB_TABLE_LEN_OFF: usize = 80;
const CODE_OFF_OFF: usize = 88;
const CODE_LEN_OFF: usize = 96;
const CODE_ALIGN_OFF: usize = 104;
const PC_RANGE_TABLE_OFF_OFF: usize = 112;
const PC_RANGE_TABLE_LEN_OFF: usize = 120;
const TRAP_MAP_OFF_OFF: usize = 128;
const TRAP_MAP_LEN_OFF: usize = 136;
const DEBUG_LITE_OFF_OFF: usize = 144;
const DEBUG_LITE_LEN_OFF: usize = 152;
const RESERVED_OFF: usize = 156;

const ENTRY_NAME_OFF_OFF: usize = 0;
const ENTRY_KIND_OFF: usize = 4;
const ENTRY_FLAGS_OFF: usize = 6;
const ENTRY_CODE_OFFSET_OFF: usize = 8;

const HOSTCALL_ID_OFF: usize = 0;
const HOSTCALL_STUB_CODE_OFFSET_OFF: usize = 8;
const HOSTCALL_FRAME_LAYOUT_VERSION_OFF: usize = 16;
const HOSTCALL_ARG_COUNT_OFF: usize = 18;
const HOSTCALL_RET_COUNT_OFF: usize = 20;

const TRAP_KIND_OFF: usize = 0;
const TRAP_STUB_CODE_OFFSET_OFF: usize = 8;
const TRAP_EXPECTED_OFFSET_OFF: usize = 16;

#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FakeAotHeaderV1 {
    pub magic: [u8; 8],
    pub header_len: u32,
    pub blob_len: u64,
    pub version_major: u16,
    pub version_minor: u16,
    pub target_arch: u16,
    pub endian: u8,
    pub pointer_width: u8,
    pub flags: u32,
    pub entry_table_off: u64,
    pub entry_table_len: u32,
    pub hostcall_stub_table_off: u64,
    pub hostcall_stub_table_len: u32,
    pub trap_stub_table_off: u64,
    pub trap_stub_table_len: u32,
    pub code_off: u64,
    pub code_len: u64,
    pub code_align: u32,
    pub pc_range_table_off: u64,
    pub pc_range_table_len: u32,
    pub trap_map_off: u64,
    pub trap_map_len: u32,
    pub debug_lite_off: u64,
    pub debug_lite_len: u32,
    pub reserved: [u8; 32],
}

impl FakeAotHeaderV1 {
    pub const WIRE_LEN: usize = core::mem::size_of::<Self>();

    pub const fn default_riscv64(blob_len: u64) -> Self {
        let entry_off = Self::WIRE_LEN as u64;
        let hostcall_off = entry_off + FakeAotEntryV1::WIRE_LEN as u64 * 3;
        let trap_off = hostcall_off + FakeHostcallStubV1::WIRE_LEN as u64;
        let code_off =
            align_up_u64(trap_off + FakeTrapStubV1::WIRE_LEN as u64, FAKE_AOT_CODE_ALIGN as u64);
        let pc_range_off = code_off + FAKE_AOT_DEFAULT_CODE_LEN as u64;
        let trap_map_off = pc_range_off + FAKE_AOT_DEFAULT_PC_RANGE_TABLE_BYTES as u64;
        let debug_lite_off = trap_map_off + FAKE_AOT_DEFAULT_TRAP_MAP_BYTES as u64;
        Self {
            magic: FAKE_AOT_MAGIC,
            header_len: Self::WIRE_LEN as u32,
            blob_len,
            version_major: FAKE_AOT_VERSION_MAJOR,
            version_minor: FAKE_AOT_VERSION_MINOR,
            target_arch: 1,
            endian: 1,
            pointer_width: 64,
            flags: 0,
            entry_table_off: entry_off,
            entry_table_len: 3,
            hostcall_stub_table_off: hostcall_off,
            hostcall_stub_table_len: 1,
            trap_stub_table_off: trap_off,
            trap_stub_table_len: 1,
            code_off,
            code_len: FAKE_AOT_DEFAULT_CODE_LEN as u64,
            code_align: FAKE_AOT_CODE_ALIGN,
            pc_range_table_off: pc_range_off,
            pc_range_table_len: 1,
            trap_map_off,
            trap_map_len: 1,
            debug_lite_off,
            debug_lite_len: FAKE_AOT_DEFAULT_DEBUG_LITE_BYTES as u32,
            reserved: [0; 32],
        }
    }

    pub fn parse(bytes: &[u8]) -> Result<Self, FakeAotError> {
        if bytes.len() < Self::WIRE_LEN {
            return Err(FakeAotError::BlobTooSmall);
        }
        let mut magic = [0; 8];
        magic.copy_from_slice(&bytes[..8]);
        let mut reserved = [0; 32];
        reserved.copy_from_slice(&bytes[RESERVED_OFF..RESERVED_OFF + 32]);
        Ok(Self {
            magic,
            header_len: read_u32(bytes, HEADER_LEN_OFF)?,
            blob_len: read_u64(bytes, BLOB_LEN_OFF)?,
            version_major: read_u16(bytes, VERSION_MAJOR_OFF)?,
            version_minor: read_u16(bytes, VERSION_MINOR_OFF)?,
            target_arch: read_u16(bytes, TARGET_ARCH_OFF)?,
            endian: bytes[ENDIAN_OFF],
            pointer_width: bytes[POINTER_WIDTH_OFF],
            flags: read_u32(bytes, FLAGS_OFF)?,
            entry_table_off: read_u64(bytes, ENTRY_TABLE_OFF_OFF)?,
            entry_table_len: read_u32(bytes, ENTRY_TABLE_LEN_OFF)?,
            hostcall_stub_table_off: read_u64(bytes, HOSTCALL_STUB_TABLE_OFF_OFF)?,
            hostcall_stub_table_len: read_u32(bytes, HOSTCALL_STUB_TABLE_LEN_OFF)?,
            trap_stub_table_off: read_u64(bytes, TRAP_STUB_TABLE_OFF_OFF)?,
            trap_stub_table_len: read_u32(bytes, TRAP_STUB_TABLE_LEN_OFF)?,
            code_off: read_u64(bytes, CODE_OFF_OFF)?,
            code_len: read_u64(bytes, CODE_LEN_OFF)?,
            code_align: read_u32(bytes, CODE_ALIGN_OFF)?,
            pc_range_table_off: read_u64(bytes, PC_RANGE_TABLE_OFF_OFF)?,
            pc_range_table_len: read_u32(bytes, PC_RANGE_TABLE_LEN_OFF)?,
            trap_map_off: read_u64(bytes, TRAP_MAP_OFF_OFF)?,
            trap_map_len: read_u32(bytes, TRAP_MAP_LEN_OFF)?,
            debug_lite_off: read_u64(bytes, DEBUG_LITE_OFF_OFF)?,
            debug_lite_len: read_u32(bytes, DEBUG_LITE_LEN_OFF)?,
            reserved,
        })
    }

    pub fn write_to(&self, out: &mut [u8]) -> Result<(), FakeAotError> {
        if out.len() < Self::WIRE_LEN {
            return Err(FakeAotError::BlobTooSmall);
        }
        out[..Self::WIRE_LEN].fill(0);
        out[..8].copy_from_slice(&self.magic);
        write_u32(out, HEADER_LEN_OFF, self.header_len)?;
        write_u64(out, BLOB_LEN_OFF, self.blob_len)?;
        write_u16(out, VERSION_MAJOR_OFF, self.version_major)?;
        write_u16(out, VERSION_MINOR_OFF, self.version_minor)?;
        write_u16(out, TARGET_ARCH_OFF, self.target_arch)?;
        out[ENDIAN_OFF] = self.endian;
        out[POINTER_WIDTH_OFF] = self.pointer_width;
        write_u32(out, FLAGS_OFF, self.flags)?;
        write_u64(out, ENTRY_TABLE_OFF_OFF, self.entry_table_off)?;
        write_u32(out, ENTRY_TABLE_LEN_OFF, self.entry_table_len)?;
        write_u64(out, HOSTCALL_STUB_TABLE_OFF_OFF, self.hostcall_stub_table_off)?;
        write_u32(out, HOSTCALL_STUB_TABLE_LEN_OFF, self.hostcall_stub_table_len)?;
        write_u64(out, TRAP_STUB_TABLE_OFF_OFF, self.trap_stub_table_off)?;
        write_u32(out, TRAP_STUB_TABLE_LEN_OFF, self.trap_stub_table_len)?;
        write_u64(out, CODE_OFF_OFF, self.code_off)?;
        write_u64(out, CODE_LEN_OFF, self.code_len)?;
        write_u32(out, CODE_ALIGN_OFF, self.code_align)?;
        write_u64(out, PC_RANGE_TABLE_OFF_OFF, self.pc_range_table_off)?;
        write_u32(out, PC_RANGE_TABLE_LEN_OFF, self.pc_range_table_len)?;
        write_u64(out, TRAP_MAP_OFF_OFF, self.trap_map_off)?;
        write_u32(out, TRAP_MAP_LEN_OFF, self.trap_map_len)?;
        write_u64(out, DEBUG_LITE_OFF_OFF, self.debug_lite_off)?;
        write_u32(out, DEBUG_LITE_LEN_OFF, self.debug_lite_len)?;
        out[RESERVED_OFF..RESERVED_OFF + 32].copy_from_slice(&self.reserved);
        Ok(())
    }
}

#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FakeAotEntryV1 {
    pub name_off: u32,
    pub kind: FakeAotEntryKindV1,
    pub flags: u16,
    pub code_offset: u64,
}

impl FakeAotEntryV1 {
    pub const WIRE_LEN: usize = core::mem::size_of::<Self>();

    pub fn parse(bytes: &[u8]) -> Result<Self, FakeAotError> {
        if bytes.len() < Self::WIRE_LEN {
            return Err(FakeAotError::TableOutOfBounds);
        }
        Ok(Self {
            name_off: read_u32(bytes, ENTRY_NAME_OFF_OFF)?,
            kind: parse_entry_kind(read_u16(bytes, ENTRY_KIND_OFF)?)?,
            flags: read_u16(bytes, ENTRY_FLAGS_OFF)?,
            code_offset: read_u64(bytes, ENTRY_CODE_OFFSET_OFF)?,
        })
    }

    pub fn write_to(&self, out: &mut [u8]) -> Result<(), FakeAotError> {
        if out.len() < Self::WIRE_LEN {
            return Err(FakeAotError::TableOutOfBounds);
        }
        out[..Self::WIRE_LEN].fill(0);
        write_u32(out, ENTRY_NAME_OFF_OFF, self.name_off)?;
        write_u16(out, ENTRY_KIND_OFF, self.kind as u16)?;
        write_u16(out, ENTRY_FLAGS_OFF, self.flags)?;
        write_u64(out, ENTRY_CODE_OFFSET_OFF, self.code_offset)?;
        Ok(())
    }
}

#[repr(u16)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FakeAotEntryKindV1 {
    Init = 1,
    Call = 2,
    TrapDemo = 3,
    HostcallDemo = 4,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FakeHostcallStubV1 {
    pub hostcall_id: u32,
    pub stub_code_offset: u64,
    pub frame_layout_version: u16,
    pub arg_count: u16,
    pub ret_count: u16,
}

impl FakeHostcallStubV1 {
    pub const WIRE_LEN: usize = core::mem::size_of::<Self>();

    pub fn parse(bytes: &[u8]) -> Result<Self, FakeAotError> {
        if bytes.len() < Self::WIRE_LEN {
            return Err(FakeAotError::TableOutOfBounds);
        }
        Ok(Self {
            hostcall_id: read_u32(bytes, HOSTCALL_ID_OFF)?,
            stub_code_offset: read_u64(bytes, HOSTCALL_STUB_CODE_OFFSET_OFF)?,
            frame_layout_version: read_u16(bytes, HOSTCALL_FRAME_LAYOUT_VERSION_OFF)?,
            arg_count: read_u16(bytes, HOSTCALL_ARG_COUNT_OFF)?,
            ret_count: read_u16(bytes, HOSTCALL_RET_COUNT_OFF)?,
        })
    }

    pub fn write_to(&self, out: &mut [u8]) -> Result<(), FakeAotError> {
        if out.len() < Self::WIRE_LEN {
            return Err(FakeAotError::TableOutOfBounds);
        }
        out[..Self::WIRE_LEN].fill(0);
        write_u32(out, HOSTCALL_ID_OFF, self.hostcall_id)?;
        write_u64(out, HOSTCALL_STUB_CODE_OFFSET_OFF, self.stub_code_offset)?;
        write_u16(out, HOSTCALL_FRAME_LAYOUT_VERSION_OFF, self.frame_layout_version)?;
        write_u16(out, HOSTCALL_ARG_COUNT_OFF, self.arg_count)?;
        write_u16(out, HOSTCALL_RET_COUNT_OFF, self.ret_count)?;
        Ok(())
    }
}

#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FakeTrapStubV1 {
    pub trap_kind: u16,
    pub stub_code_offset: u64,
    pub expected_trap_offset: u64,
}

impl FakeTrapStubV1 {
    pub const WIRE_LEN: usize = core::mem::size_of::<Self>();

    pub fn parse(bytes: &[u8]) -> Result<Self, FakeAotError> {
        if bytes.len() < Self::WIRE_LEN {
            return Err(FakeAotError::TableOutOfBounds);
        }
        Ok(Self {
            trap_kind: read_u16(bytes, TRAP_KIND_OFF)?,
            stub_code_offset: read_u64(bytes, TRAP_STUB_CODE_OFFSET_OFF)?,
            expected_trap_offset: read_u64(bytes, TRAP_EXPECTED_OFFSET_OFF)?,
        })
    }

    pub fn write_to(&self, out: &mut [u8]) -> Result<(), FakeAotError> {
        if out.len() < Self::WIRE_LEN {
            return Err(FakeAotError::TableOutOfBounds);
        }
        out[..Self::WIRE_LEN].fill(0);
        write_u16(out, TRAP_KIND_OFF, self.trap_kind)?;
        write_u64(out, TRAP_STUB_CODE_OFFSET_OFF, self.stub_code_offset)?;
        write_u64(out, TRAP_EXPECTED_OFFSET_OFF, self.expected_trap_offset)?;
        Ok(())
    }
}

#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FakePatchEntryV1 {
    pub kind: FakePatchKindV1,
    pub target_section: FakeAotSectionKindV1,
    pub target_offset: u64,
    pub width: u16,
    pub symbol_kind: u16,
    pub symbol_index: u32,
    pub addend: i64,
}

#[repr(u16)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FakePatchKindV1 {
    None = 0,
    U64LeAbs = 1,
    U32LeAbs = 2,
    Riscv64AuipcJalrPair = 100,
    Riscv64Hi20Lo12 = 101,
    Riscv64Call = 102,
}

#[repr(u16)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FakeAotSectionKindV1 {
    EntryTable = 1,
    HostcallStubTable = 2,
    TrapStubTable = 3,
    CodeBytes = 4,
    PcRangeTable = 5,
    TrapMap = 6,
    DebugLite = 7,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RelocationEntryV1 {
    pub target_section: FakeAotSectionKindV1,
    pub reloc_kind: RelocationKindV1,
    pub flags: u16,
    pub reserved: u16,
    pub offset: u64,
    pub import_id: u32,
    pub symbol_index: u32,
    pub addend: i64,
}

#[repr(u16)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RelocationKindV1 {
    Abs64 = 1,
    Abs32 = 2,
    PcRel32 = 3,
    RiscvCallPlt = 100,
    RiscvPcrelHi20 = 101,
    RiscvPcrelLo12I = 102,
    RiscvPcrelLo12S = 103,
    RiscvHi20 = 104,
    RiscvLo12I = 105,
    RiscvLo12S = 106,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ArtifactRelocationUnsupportedEventV1 {
    pub event_kind: &'static str,
    pub reason: &'static str,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FakeAotError {
    BlobTooSmall,
    BadMagic,
    UnsupportedVersion,
    BadHeaderLength,
    BlobLengthMismatch,
    BadTarget,
    TableOutOfBounds,
    CodeSectionNotPageAligned,
    CodeSectionOutOfBounds,
    MissingRequiredStub(&'static str),
    MissingRequiredTable(&'static str),
    BadTableEntry(&'static str),
    PatchOutOfBounds,
    PatchSectionMismatch,
    BadPatchWidth,
    CodePatchRejected,
    UnsupportedRelocation(ArtifactRelocationUnsupportedEventV1),
}

pub struct FakeAotBlob<'a> {
    bytes: &'a [u8],
    header: FakeAotHeaderV1,
}

impl<'a> FakeAotBlob<'a> {
    pub fn parse(bytes: &'a [u8]) -> Result<Self, FakeAotError> {
        let header = FakeAotHeaderV1::parse(bytes)?;
        let blob = Self { bytes, header };
        blob.validate()?;
        Ok(blob)
    }

    pub const fn header(&self) -> &FakeAotHeaderV1 {
        &self.header
    }

    pub fn code_bytes(&self) -> &'a [u8] {
        let start = self.header.code_off as usize;
        let end = start + self.header.code_len as usize;
        &self.bytes[start..end]
    }

    fn validate(&self) -> Result<(), FakeAotError> {
        let header = &self.header;
        if header.magic != FAKE_AOT_MAGIC {
            return Err(FakeAotError::BadMagic);
        }
        if header.header_len as usize != FakeAotHeaderV1::WIRE_LEN {
            return Err(FakeAotError::BadHeaderLength);
        }
        if header.blob_len as usize != self.bytes.len() {
            return Err(FakeAotError::BlobLengthMismatch);
        }
        if header.version_major != FAKE_AOT_VERSION_MAJOR {
            return Err(FakeAotError::UnsupportedVersion);
        }
        if header.target_arch != 1 || header.endian != 1 || header.pointer_width != 64 {
            return Err(FakeAotError::BadTarget);
        }
        require_table(header.entry_table_len, "EntryTable")?;
        require_table(header.hostcall_stub_table_len, "HostcallStubTable")?;
        require_table(header.trap_stub_table_len, "TrapStubTable")?;
        require_table(header.pc_range_table_len, "PcRangeTable")?;
        require_table(header.trap_map_len, "TrapMap")?;
        require_bytes(header.debug_lite_len, "DebugLite")?;
        validate_table(
            self.bytes,
            header.entry_table_off,
            header.entry_table_len as usize,
            FakeAotEntryV1::WIRE_LEN,
        )?;
        validate_table(
            self.bytes,
            header.hostcall_stub_table_off,
            header.hostcall_stub_table_len as usize,
            FakeHostcallStubV1::WIRE_LEN,
        )?;
        validate_table(
            self.bytes,
            header.trap_stub_table_off,
            header.trap_stub_table_len as usize,
            FakeTrapStubV1::WIRE_LEN,
        )?;
        validate_table(
            self.bytes,
            header.pc_range_table_off,
            header.pc_range_table_len as usize,
            16,
        )?;
        validate_table(self.bytes, header.trap_map_off, header.trap_map_len as usize, 16)?;
        validate_region(self.bytes, header.debug_lite_off, header.debug_lite_len as usize, 1)?;
        require_entry_table_stub(
            self.bytes,
            header,
            "entry_return_ok",
            FakeAotEntryKindV1::Call,
            RV64_ENTRY_RETURN_OK_OFFSET,
        )?;
        require_entry_table_stub(
            self.bytes,
            header,
            "entry_hostcall_tail",
            FakeAotEntryKindV1::HostcallDemo,
            RV64_ENTRY_HOSTCALL_TAIL_OFFSET,
        )?;
        require_entry_table_stub(
            self.bytes,
            header,
            "entry_trap_ebreak",
            FakeAotEntryKindV1::TrapDemo,
            RV64_ENTRY_TRAP_EBREAK_OFFSET,
        )?;
        require_hostcall_stub_table(self.bytes, header)?;
        require_trap_stub_table(self.bytes, header)?;
        if header.code_align != FAKE_AOT_CODE_ALIGN
            || !header.code_off.is_multiple_of(FAKE_AOT_CODE_ALIGN as u64)
        {
            return Err(FakeAotError::CodeSectionNotPageAligned);
        }
        if !header.code_len.is_multiple_of(16) {
            return Err(FakeAotError::CodeSectionOutOfBounds);
        }
        let code_start = header.code_off as usize;
        let code_end = checked_add(
            code_start,
            header.code_len as usize,
            FakeAotError::CodeSectionOutOfBounds,
        )?;
        if code_end > self.bytes.len() {
            return Err(FakeAotError::CodeSectionOutOfBounds);
        }
        let code = &self.bytes[code_start..code_end];
        require_stub(
            code,
            RV64_ENTRY_RETURN_OK_OFFSET as usize,
            &RV64_ENTRY_RETURN_OK_BYTES,
            "entry_return_ok",
        )?;
        require_stub(
            code,
            RV64_ENTRY_HOSTCALL_TAIL_OFFSET as usize,
            &RV64_ENTRY_HOSTCALL_TAIL_BYTES,
            "entry_hostcall_tail",
        )?;
        require_stub(
            code,
            RV64_ENTRY_TRAP_EBREAK_OFFSET as usize,
            &RV64_ENTRY_TRAP_EBREAK_BYTES,
            "entry_trap_ebreak",
        )?;
        Ok(())
    }
}

pub fn apply_fake_patch(
    section: FakeAotSectionKindV1,
    bytes: &mut [u8],
    patch: FakePatchEntryV1,
    value: u64,
) -> Result<(), FakeAotError> {
    if section == FakeAotSectionKindV1::CodeBytes
        || patch.target_section == FakeAotSectionKindV1::CodeBytes
    {
        return Err(FakeAotError::CodePatchRejected);
    }
    if section != patch.target_section {
        return Err(FakeAotError::PatchSectionMismatch);
    }
    let offset = patch.target_offset as usize;
    match patch.kind {
        FakePatchKindV1::U64LeAbs => {
            if patch.width != 8 {
                return Err(FakeAotError::BadPatchWidth);
            }
            let end = checked_add(offset, 8, FakeAotError::PatchOutOfBounds)?;
            let out = bytes.get_mut(offset..end).ok_or(FakeAotError::PatchOutOfBounds)?;
            out.copy_from_slice(&value.to_le_bytes());
            Ok(())
        }
        FakePatchKindV1::U32LeAbs => {
            if patch.width != 4 {
                return Err(FakeAotError::BadPatchWidth);
            }
            let end = checked_add(offset, 4, FakeAotError::PatchOutOfBounds)?;
            let out = bytes.get_mut(offset..end).ok_or(FakeAotError::PatchOutOfBounds)?;
            out.copy_from_slice(&(value as u32).to_le_bytes());
            Ok(())
        }
        FakePatchKindV1::None
        | FakePatchKindV1::Riscv64AuipcJalrPair
        | FakePatchKindV1::Riscv64Hi20Lo12
        | FakePatchKindV1::Riscv64Call => {
            Err(unsupported_relocation("unsupported fake AOT patch kind"))
        }
    }
}

pub fn validate_real_aot_relocation(relocation: RelocationEntryV1) -> Result<(), FakeAotError> {
    match relocation.reloc_kind {
        RelocationKindV1::Abs64 | RelocationKindV1::Abs32 => {
            if relocation.target_section == FakeAotSectionKindV1::CodeBytes {
                Err(FakeAotError::CodePatchRejected)
            } else {
                Ok(())
            }
        }
        RelocationKindV1::PcRel32
        | RelocationKindV1::RiscvCallPlt
        | RelocationKindV1::RiscvPcrelHi20
        | RelocationKindV1::RiscvPcrelLo12I
        | RelocationKindV1::RiscvPcrelLo12S
        | RelocationKindV1::RiscvHi20
        | RelocationKindV1::RiscvLo12I
        | RelocationKindV1::RiscvLo12S => {
            Err(unsupported_relocation("unsupported real AOT relocation kind"))
        }
    }
}

fn unsupported_relocation(reason: &'static str) -> FakeAotError {
    FakeAotError::UnsupportedRelocation(ArtifactRelocationUnsupportedEventV1 {
        event_kind: "ArtifactRelocationUnsupported",
        reason,
    })
}

fn require_stub(
    code: &[u8],
    offset: usize,
    expected: &[u8],
    name: &'static str,
) -> Result<(), FakeAotError> {
    let end = checked_add(offset, expected.len(), FakeAotError::MissingRequiredStub(name))?;
    match code.get(offset..end) {
        Some(actual) if actual == expected => Ok(()),
        _ => Err(FakeAotError::MissingRequiredStub(name)),
    }
}

fn require_table(count: u32, name: &'static str) -> Result<(), FakeAotError> {
    if count == 0 { Err(FakeAotError::MissingRequiredTable(name)) } else { Ok(()) }
}

fn require_bytes(len: u32, name: &'static str) -> Result<(), FakeAotError> {
    if len == 0 { Err(FakeAotError::MissingRequiredTable(name)) } else { Ok(()) }
}

fn validate_table(
    bytes: &[u8],
    offset: u64,
    count: usize,
    entry_len: usize,
) -> Result<(), FakeAotError> {
    validate_region(bytes, offset, count, entry_len)?;
    Ok(())
}

fn validate_region(
    bytes: &[u8],
    offset: u64,
    count: usize,
    entry_len: usize,
) -> Result<(), FakeAotError> {
    if !offset.is_multiple_of(8) {
        return Err(FakeAotError::TableOutOfBounds);
    }
    let start = usize::try_from(offset).map_err(|_| FakeAotError::TableOutOfBounds)?;
    let len = count.checked_mul(entry_len).ok_or(FakeAotError::TableOutOfBounds)?;
    let end = checked_add(start, len, FakeAotError::TableOutOfBounds)?;
    if end > bytes.len() {
        return Err(FakeAotError::TableOutOfBounds);
    }
    Ok(())
}

fn require_entry_table_stub(
    bytes: &[u8],
    header: &FakeAotHeaderV1,
    name: &'static str,
    kind: FakeAotEntryKindV1,
    code_offset: u64,
) -> Result<(), FakeAotError> {
    for index in 0..header.entry_table_len as usize {
        let entry = parse_table_entry::<FakeAotEntryV1>(
            bytes,
            header.entry_table_off,
            index,
            FakeAotEntryV1::WIRE_LEN,
            FakeAotEntryV1::parse,
        )?;
        if entry.kind == kind
            && entry.code_offset == code_offset
            && debug_name_matches(bytes, header, entry.name_off, name.as_bytes())?
        {
            return Ok(());
        }
    }
    Err(FakeAotError::MissingRequiredStub(name))
}

fn require_hostcall_stub_table(bytes: &[u8], header: &FakeAotHeaderV1) -> Result<(), FakeAotError> {
    for index in 0..header.hostcall_stub_table_len as usize {
        let stub = parse_table_entry::<FakeHostcallStubV1>(
            bytes,
            header.hostcall_stub_table_off,
            index,
            FakeHostcallStubV1::WIRE_LEN,
            FakeHostcallStubV1::parse,
        )?;
        if stub.hostcall_id == FAKE_AOT_HOSTCALL_DEMO_ID
            && stub.stub_code_offset == RV64_ENTRY_HOSTCALL_TAIL_OFFSET
            && stub.frame_layout_version == FAKE_AOT_HOSTCALL_FRAME_LAYOUT_VERSION
            && stub.arg_count == FAKE_AOT_HOSTCALL_ARG_COUNT
            && stub.ret_count == FAKE_AOT_HOSTCALL_RET_COUNT
        {
            return Ok(());
        }
    }
    Err(FakeAotError::MissingRequiredStub("entry_hostcall_tail"))
}

fn require_trap_stub_table(bytes: &[u8], header: &FakeAotHeaderV1) -> Result<(), FakeAotError> {
    for index in 0..header.trap_stub_table_len as usize {
        let stub = parse_table_entry::<FakeTrapStubV1>(
            bytes,
            header.trap_stub_table_off,
            index,
            FakeTrapStubV1::WIRE_LEN,
            FakeTrapStubV1::parse,
        )?;
        if stub.trap_kind == FAKE_AOT_TRAP_KIND_EBREAK
            && stub.stub_code_offset == RV64_ENTRY_TRAP_EBREAK_OFFSET
            && stub.expected_trap_offset == RV64_ENTRY_TRAP_EBREAK_OFFSET
        {
            return Ok(());
        }
    }
    Err(FakeAotError::MissingRequiredStub("entry_trap_ebreak"))
}

fn parse_table_entry<T>(
    bytes: &[u8],
    table_off: u64,
    index: usize,
    entry_len: usize,
    parse: fn(&[u8]) -> Result<T, FakeAotError>,
) -> Result<T, FakeAotError> {
    let table_start = usize::try_from(table_off).map_err(|_| FakeAotError::TableOutOfBounds)?;
    let entry_off = checked_add(
        table_start,
        index.checked_mul(entry_len).ok_or(FakeAotError::TableOutOfBounds)?,
        FakeAotError::TableOutOfBounds,
    )?;
    let entry_end = checked_add(entry_off, entry_len, FakeAotError::TableOutOfBounds)?;
    let entry = bytes.get(entry_off..entry_end).ok_or(FakeAotError::TableOutOfBounds)?;
    parse(entry)
}

fn debug_name_matches(
    bytes: &[u8],
    header: &FakeAotHeaderV1,
    name_off: u32,
    expected: &[u8],
) -> Result<bool, FakeAotError> {
    let debug_start =
        usize::try_from(header.debug_lite_off).map_err(|_| FakeAotError::TableOutOfBounds)?;
    let debug_len = header.debug_lite_len as usize;
    let debug_end = checked_add(debug_start, debug_len, FakeAotError::TableOutOfBounds)?;
    let name_start = checked_add(debug_start, name_off as usize, FakeAotError::TableOutOfBounds)?;
    let name_end = checked_add(name_start, expected.len(), FakeAotError::TableOutOfBounds)?;
    let nul = checked_add(name_end, 1, FakeAotError::TableOutOfBounds)?;
    if nul > debug_end {
        return Ok(false);
    }
    Ok(bytes.get(name_start..name_end) == Some(expected) && bytes.get(name_end) == Some(&0))
}

fn parse_entry_kind(value: u16) -> Result<FakeAotEntryKindV1, FakeAotError> {
    match value {
        1 => Ok(FakeAotEntryKindV1::Init),
        2 => Ok(FakeAotEntryKindV1::Call),
        3 => Ok(FakeAotEntryKindV1::TrapDemo),
        4 => Ok(FakeAotEntryKindV1::HostcallDemo),
        _ => Err(FakeAotError::BadTableEntry("EntryTable")),
    }
}

const fn align_up_u64(value: u64, align: u64) -> u64 {
    value.div_ceil(align) * align
}

fn read_u16(bytes: &[u8], offset: usize) -> Result<u16, FakeAotError> {
    let end = checked_add(offset, 2, FakeAotError::BlobTooSmall)?;
    let slice = bytes.get(offset..end).ok_or(FakeAotError::BlobTooSmall)?;
    Ok(u16::from_le_bytes([slice[0], slice[1]]))
}

fn read_u32(bytes: &[u8], offset: usize) -> Result<u32, FakeAotError> {
    let end = checked_add(offset, 4, FakeAotError::BlobTooSmall)?;
    let slice = bytes.get(offset..end).ok_or(FakeAotError::BlobTooSmall)?;
    Ok(u32::from_le_bytes([slice[0], slice[1], slice[2], slice[3]]))
}

fn read_u64(bytes: &[u8], offset: usize) -> Result<u64, FakeAotError> {
    let end = checked_add(offset, 8, FakeAotError::BlobTooSmall)?;
    let slice = bytes.get(offset..end).ok_or(FakeAotError::BlobTooSmall)?;
    Ok(u64::from_le_bytes([
        slice[0], slice[1], slice[2], slice[3], slice[4], slice[5], slice[6], slice[7],
    ]))
}

fn write_u16(bytes: &mut [u8], offset: usize, value: u16) -> Result<(), FakeAotError> {
    let end = checked_add(offset, 2, FakeAotError::BlobTooSmall)?;
    let slice = bytes.get_mut(offset..end).ok_or(FakeAotError::BlobTooSmall)?;
    slice.copy_from_slice(&value.to_le_bytes());
    Ok(())
}

fn write_u32(bytes: &mut [u8], offset: usize, value: u32) -> Result<(), FakeAotError> {
    let end = checked_add(offset, 4, FakeAotError::BlobTooSmall)?;
    let slice = bytes.get_mut(offset..end).ok_or(FakeAotError::BlobTooSmall)?;
    slice.copy_from_slice(&value.to_le_bytes());
    Ok(())
}

fn write_u64(bytes: &mut [u8], offset: usize, value: u64) -> Result<(), FakeAotError> {
    let end = checked_add(offset, 8, FakeAotError::BlobTooSmall)?;
    let slice = bytes.get_mut(offset..end).ok_or(FakeAotError::BlobTooSmall)?;
    slice.copy_from_slice(&value.to_le_bytes());
    Ok(())
}

fn checked_add(left: usize, right: usize, error: FakeAotError) -> Result<usize, FakeAotError> {
    left.checked_add(right).ok_or(error)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rv64_stub_return_ok_exact_bytes() {
        assert_eq!(RV64_ENTRY_RETURN_OK_BYTES, [0x13, 0x05, 0x00, 0x00, 0x67, 0x80, 0x00, 0x00]);
    }

    #[test]
    fn rv64_stub_hostcall_tail_exact_bytes() {
        assert_eq!(RV64_ENTRY_HOSTCALL_TAIL_BYTES, [0x67, 0x80, 0x05, 0x00]);
    }

    #[test]
    fn rv64_stub_ebreak_exact_bytes() {
        assert_eq!(RV64_ENTRY_TRAP_EBREAK_BYTES, [0x73, 0x00, 0x10, 0x00]);
    }

    #[test]
    fn fake_aot_code_section_page_aligned() {
        let bytes = default_blob();
        let blob = FakeAotBlob::parse(&bytes).expect("default fake AOT parses");

        assert_eq!(blob.header().code_align, FAKE_AOT_CODE_ALIGN);
        assert!(blob.header().code_off.is_multiple_of(FAKE_AOT_CODE_ALIGN as u64));
    }

    #[test]
    fn fake_aot_wire_layout_sizes_are_stable() {
        assert_eq!(FakeAotHeaderV1::WIRE_LEN, 192);
        assert_eq!(FakeAotEntryV1::WIRE_LEN, 16);
        assert_eq!(FakeHostcallStubV1::WIRE_LEN, 24);
        assert_eq!(FakeTrapStubV1::WIRE_LEN, 24);
        assert_eq!(core::mem::size_of::<FakePatchEntryV1>(), 32);
        assert_eq!(core::mem::size_of::<RelocationEntryV1>(), 32);
    }

    #[test]
    fn fake_aot_contains_required_stubs() {
        let bytes = default_blob();
        let blob = FakeAotBlob::parse(&bytes).expect("default fake AOT parses");
        let code = blob.code_bytes();

        assert_eq!(
            &code[RV64_ENTRY_RETURN_OK_OFFSET as usize
                ..RV64_ENTRY_RETURN_OK_OFFSET as usize + RV64_ENTRY_RETURN_OK_BYTES.len()],
            RV64_ENTRY_RETURN_OK_BYTES
        );
        assert_eq!(
            &code[RV64_ENTRY_HOSTCALL_TAIL_OFFSET as usize
                ..RV64_ENTRY_HOSTCALL_TAIL_OFFSET as usize + RV64_ENTRY_HOSTCALL_TAIL_BYTES.len()],
            RV64_ENTRY_HOSTCALL_TAIL_BYTES
        );
        assert_eq!(
            &code[RV64_ENTRY_TRAP_EBREAK_OFFSET as usize
                ..RV64_ENTRY_TRAP_EBREAK_OFFSET as usize + RV64_ENTRY_TRAP_EBREAK_BYTES.len()],
            RV64_ENTRY_TRAP_EBREAK_BYTES
        );
    }

    #[test]
    fn fake_aot_entry_table_names_required_stubs() {
        let bytes = default_blob();
        let header = FakeAotHeaderV1::parse(&bytes).expect("header");
        let entry = FakeAotEntryV1::parse(
            table_entry(&bytes, header.entry_table_off, 1, FakeAotEntryV1::WIRE_LEN)
                .expect("entry"),
        )
        .expect("entry");

        assert_eq!(entry.name_off, FAKE_AOT_ENTRY_HOSTCALL_TAIL_NAME_OFF);
        assert_eq!(entry.kind, FakeAotEntryKindV1::HostcallDemo);
        assert_eq!(entry.code_offset, RV64_ENTRY_HOSTCALL_TAIL_OFFSET);
    }

    #[test]
    fn fake_aot_rejects_zero_filled_required_tables() {
        let mut bytes = default_blob();
        let header = FakeAotHeaderV1::parse(&bytes).expect("header");
        table_entry_mut(&mut bytes, header.entry_table_off, 0, FakeAotEntryV1::WIRE_LEN)
            .expect("entry")
            .fill(0);

        assert_eq!(
            FakeAotBlob::parse(&bytes).err(),
            Some(FakeAotError::BadTableEntry("EntryTable"))
        );
    }

    #[test]
    fn fake_aot_rejects_missing_hostcall_stub_metadata() {
        let mut bytes = default_blob();
        let header = FakeAotHeaderV1::parse(&bytes).expect("header");
        table_entry_mut(
            &mut bytes,
            header.hostcall_stub_table_off,
            0,
            FakeHostcallStubV1::WIRE_LEN,
        )
        .expect("hostcall")
        .fill(0);

        assert_eq!(
            FakeAotBlob::parse(&bytes).err(),
            Some(FakeAotError::MissingRequiredStub("entry_hostcall_tail"))
        );
    }

    #[test]
    fn fake_aot_rejects_missing_trap_stub_metadata() {
        let mut bytes = default_blob();
        let header = FakeAotHeaderV1::parse(&bytes).expect("header");
        table_entry_mut(&mut bytes, header.trap_stub_table_off, 0, FakeTrapStubV1::WIRE_LEN)
            .expect("trap")
            .fill(0);

        assert_eq!(
            FakeAotBlob::parse(&bytes).err(),
            Some(FakeAotError::MissingRequiredStub("entry_trap_ebreak"))
        );
    }

    #[test]
    fn fake_aot_default_layout_places_metadata_after_code() {
        let bytes = default_blob();
        let blob = FakeAotBlob::parse(&bytes).expect("default fake AOT parses");
        let header = blob.header();

        assert!(header.entry_table_off < header.hostcall_stub_table_off);
        assert!(header.hostcall_stub_table_off < header.trap_stub_table_off);
        assert!(header.trap_stub_table_off < header.code_off);
        assert_eq!(header.pc_range_table_off, header.code_off + FAKE_AOT_DEFAULT_CODE_LEN as u64);
        assert_eq!(
            header.trap_map_off,
            header.pc_range_table_off + FAKE_AOT_DEFAULT_PC_RANGE_TABLE_BYTES as u64
        );
        assert_eq!(
            header.debug_lite_off,
            header.trap_map_off + FAKE_AOT_DEFAULT_TRAP_MAP_BYTES as u64
        );
    }

    #[test]
    fn fake_aot_rejects_missing_required_tables() {
        let mut bytes = default_blob();
        let mut header = FakeAotHeaderV1::parse(&bytes).expect("header");
        header.trap_map_len = 0;
        header.write_to(&mut bytes).expect("header");

        assert_eq!(
            FakeAotBlob::parse(&bytes).err(),
            Some(FakeAotError::MissingRequiredTable("TrapMap"))
        );
    }

    #[test]
    fn fake_aot_rejects_code_patch_in_default_profile() {
        let mut code = [0; 64];
        let patch = FakePatchEntryV1 {
            kind: FakePatchKindV1::U64LeAbs,
            target_section: FakeAotSectionKindV1::CodeBytes,
            target_offset: 0,
            width: 8,
            symbol_kind: 0,
            symbol_index: 0,
            addend: 0,
        };

        assert_eq!(
            apply_fake_patch(FakeAotSectionKindV1::CodeBytes, &mut code, patch, 0xfeed),
            Err(FakeAotError::CodePatchRejected)
        );
    }

    #[test]
    fn fake_aot_data_patch_writes_little_endian_non_code_section() {
        let mut debug = [0; 16];
        let patch = FakePatchEntryV1 {
            kind: FakePatchKindV1::U32LeAbs,
            target_section: FakeAotSectionKindV1::DebugLite,
            target_offset: 4,
            width: 4,
            symbol_kind: 0,
            symbol_index: 0,
            addend: 0,
        };

        apply_fake_patch(FakeAotSectionKindV1::DebugLite, &mut debug, patch, 0x1122_3344)
            .expect("data patch");
        assert_eq!(&debug[4..8], &[0x44, 0x33, 0x22, 0x11]);
    }

    #[test]
    fn real_aot_rejects_unsupported_riscv_relocation() {
        let relocation = RelocationEntryV1 {
            target_section: FakeAotSectionKindV1::CodeBytes,
            reloc_kind: RelocationKindV1::RiscvPcrelHi20,
            flags: 0,
            reserved: 0,
            offset: 0,
            import_id: 1,
            symbol_index: 0,
            addend: 0,
        };

        assert_eq!(
            validate_real_aot_relocation(relocation),
            Err(FakeAotError::UnsupportedRelocation(ArtifactRelocationUnsupportedEventV1 {
                event_kind: "ArtifactRelocationUnsupported",
                reason: "unsupported real AOT relocation kind"
            }))
        );
    }

    fn default_blob() -> Vec<u8> {
        let blob_len = FAKE_AOT_DEFAULT_BLOB_LEN;
        let mut blob = vec![0; blob_len];
        let header = FakeAotHeaderV1::default_riscv64(blob_len as u64);
        header.write_to(&mut blob).expect("header");
        write_default_tables(&mut blob, &header);
        let code = &mut blob[header.code_off as usize..header.code_off as usize + 0x30];
        code[RV64_ENTRY_RETURN_OK_OFFSET as usize
            ..RV64_ENTRY_RETURN_OK_OFFSET as usize + RV64_ENTRY_RETURN_OK_BYTES.len()]
            .copy_from_slice(&RV64_ENTRY_RETURN_OK_BYTES);
        code[RV64_ENTRY_HOSTCALL_TAIL_OFFSET as usize
            ..RV64_ENTRY_HOSTCALL_TAIL_OFFSET as usize + RV64_ENTRY_HOSTCALL_TAIL_BYTES.len()]
            .copy_from_slice(&RV64_ENTRY_HOSTCALL_TAIL_BYTES);
        code[RV64_ENTRY_TRAP_EBREAK_OFFSET as usize
            ..RV64_ENTRY_TRAP_EBREAK_OFFSET as usize + RV64_ENTRY_TRAP_EBREAK_BYTES.len()]
            .copy_from_slice(&RV64_ENTRY_TRAP_EBREAK_BYTES);
        blob
    }

    fn write_default_tables(blob: &mut [u8], header: &FakeAotHeaderV1) {
        let entries = [
            FakeAotEntryV1 {
                name_off: FAKE_AOT_ENTRY_RETURN_OK_NAME_OFF,
                kind: FakeAotEntryKindV1::Call,
                flags: 0,
                code_offset: RV64_ENTRY_RETURN_OK_OFFSET,
            },
            FakeAotEntryV1 {
                name_off: FAKE_AOT_ENTRY_HOSTCALL_TAIL_NAME_OFF,
                kind: FakeAotEntryKindV1::HostcallDemo,
                flags: 0,
                code_offset: RV64_ENTRY_HOSTCALL_TAIL_OFFSET,
            },
            FakeAotEntryV1 {
                name_off: FAKE_AOT_ENTRY_TRAP_EBREAK_NAME_OFF,
                kind: FakeAotEntryKindV1::TrapDemo,
                flags: 0,
                code_offset: RV64_ENTRY_TRAP_EBREAK_OFFSET,
            },
        ];
        for (index, entry) in entries.iter().enumerate() {
            entry
                .write_to(
                    table_entry_mut(blob, header.entry_table_off, index, FakeAotEntryV1::WIRE_LEN)
                        .expect("entry"),
                )
                .expect("entry write");
        }

        FakeHostcallStubV1 {
            hostcall_id: FAKE_AOT_HOSTCALL_DEMO_ID,
            stub_code_offset: RV64_ENTRY_HOSTCALL_TAIL_OFFSET,
            frame_layout_version: FAKE_AOT_HOSTCALL_FRAME_LAYOUT_VERSION,
            arg_count: FAKE_AOT_HOSTCALL_ARG_COUNT,
            ret_count: FAKE_AOT_HOSTCALL_RET_COUNT,
        }
        .write_to(
            table_entry_mut(blob, header.hostcall_stub_table_off, 0, FakeHostcallStubV1::WIRE_LEN)
                .expect("hostcall"),
        )
        .expect("hostcall write");

        FakeTrapStubV1 {
            trap_kind: FAKE_AOT_TRAP_KIND_EBREAK,
            stub_code_offset: RV64_ENTRY_TRAP_EBREAK_OFFSET,
            expected_trap_offset: RV64_ENTRY_TRAP_EBREAK_OFFSET,
        }
        .write_to(
            table_entry_mut(blob, header.trap_stub_table_off, 0, FakeTrapStubV1::WIRE_LEN)
                .expect("trap"),
        )
        .expect("trap write");

        let debug_start = header.debug_lite_off as usize;
        let debug = &mut blob[debug_start..debug_start + FAKE_AOT_DEBUG_NAMES.len()];
        debug.copy_from_slice(FAKE_AOT_DEBUG_NAMES);
    }

    fn table_entry(bytes: &[u8], table_off: u64, index: usize, entry_len: usize) -> Option<&[u8]> {
        let start = table_off as usize + index * entry_len;
        bytes.get(start..start + entry_len)
    }

    fn table_entry_mut(
        bytes: &mut [u8],
        table_off: u64,
        index: usize,
        entry_len: usize,
    ) -> Option<&mut [u8]> {
        let start = table_off as usize + index * entry_len;
        bytes.get_mut(start..start + entry_len)
    }
}
