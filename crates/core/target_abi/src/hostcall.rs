pub const HOSTCALL_FRAME_MAGIC: u32 = u32::from_le_bytes(*b"HCF1");
pub const HOSTCALL_FRAME_VERSION: u16 = 1;
pub const HOSTCALL_FRAME_ARG_CAPACITY: usize = 8;
pub const HOSTCALL_FRAME_RET_CAPACITY: usize = 4;
pub const FAKE_HOSTCALL_TRAMPOLINE_REGISTER_A0: &str = "a0";
pub const FAKE_HOSTCALL_TRAMPOLINE_REGISTER_A1: &str = "a1";
pub const OBJECT_KIND_CAPABILITY_V1: u16 = 3;
pub const OBJECT_KIND_STORE_V1: u16 = 6;
pub const OBJECT_KIND_ACTIVATION_V1: u16 = 8;
pub const OBJECT_KIND_CODE_OBJECT_V1: u16 = 10;

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ObjectRefRaw {
    pub kind: u16,
    pub reserved: u16,
    pub id: u64,
    pub generation: u64,
}

impl ObjectRefRaw {
    pub const NULL: Self = Self { kind: 0, reserved: 0, id: 0, generation: 0 };

    pub const WIRE_LEN: usize = core::mem::size_of::<Self>();

    pub const fn new(kind: u16, id: u64, generation: u64) -> Self {
        Self { kind, reserved: 0, id, generation }
    }

    pub const fn is_null(self) -> bool {
        self.id == 0 && self.generation == 0
    }
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct CapabilityHandleRaw {
    pub slot: u32,
    pub generation: u32,
    pub tag: u64,
    pub rights_hint: u64,
    pub class_hint: u16,
    pub reserved: [u16; 3],
}

impl CapabilityHandleRaw {
    pub const WIRE_LEN: usize = core::mem::size_of::<Self>();

    pub const fn new(
        slot: u32,
        generation: u32,
        tag: u64,
        rights_hint: u64,
        class_hint: u16,
    ) -> Self {
        Self { slot, generation, tag, rights_hint, class_hint, reserved: [0; 3] }
    }
}

#[repr(u32)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HostcallStatusV1 {
    Ok = 0,
    Pending = 1,
    Denied = 2,
    Unsupported = 3,
    Trap = 4,
    InvalidFrame = 5,
    GenerationMismatch = 6,
}

impl HostcallStatusV1 {
    pub const fn from_u32(value: u32) -> Option<Self> {
        match value {
            0 => Some(Self::Ok),
            1 => Some(Self::Pending),
            2 => Some(Self::Denied),
            3 => Some(Self::Unsupported),
            4 => Some(Self::Trap),
            5 => Some(Self::InvalidFrame),
            6 => Some(Self::GenerationMismatch),
            _ => None,
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HostcallFrameV1 {
    pub magic: u32,
    pub version: u16,
    pub frame_len: u16,
    pub call_id: u32,
    pub flags: u32,
    pub caller_store: ObjectRefRaw,
    pub caller_activation: ObjectRefRaw,
    pub caller_code: ObjectRefRaw,
    pub capability: ObjectRefRaw,
    pub arg_count: u16,
    pub ret_count: u16,
    pub args: [u64; HOSTCALL_FRAME_ARG_CAPACITY],
    pub rets: [u64; HOSTCALL_FRAME_RET_CAPACITY],
    pub status: u32,
    pub errno_or_reason: u32,
    pub event_epoch: u64,
    pub scratch_ptr: u64,
    pub scratch_len: u64,
}

impl HostcallFrameV1 {
    pub const WIRE_LEN: usize = core::mem::size_of::<Self>();

    pub const fn new(call_id: u32) -> Self {
        Self {
            magic: HOSTCALL_FRAME_MAGIC,
            version: HOSTCALL_FRAME_VERSION,
            frame_len: Self::WIRE_LEN as u16,
            call_id,
            flags: 0,
            caller_store: ObjectRefRaw::NULL,
            caller_activation: ObjectRefRaw::NULL,
            caller_code: ObjectRefRaw::NULL,
            capability: ObjectRefRaw::NULL,
            arg_count: 0,
            ret_count: 0,
            args: [0; HOSTCALL_FRAME_ARG_CAPACITY],
            rets: [0; HOSTCALL_FRAME_RET_CAPACITY],
            status: HostcallStatusV1::Ok as u32,
            errno_or_reason: 0,
            event_epoch: 0,
            scratch_ptr: 0,
            scratch_len: 0,
        }
    }

    pub fn validate_basic(&self) -> Result<(), HostcallFrameError> {
        if self.magic != HOSTCALL_FRAME_MAGIC {
            return Err(HostcallFrameError::BadMagic);
        }
        if self.version != HOSTCALL_FRAME_VERSION {
            return Err(HostcallFrameError::BadVersion);
        }
        if usize::from(self.frame_len) < Self::WIRE_LEN {
            return Err(HostcallFrameError::BadFrameLength);
        }
        if usize::from(self.arg_count) > HOSTCALL_FRAME_ARG_CAPACITY {
            return Err(HostcallFrameError::TooManyArgs);
        }
        if usize::from(self.ret_count) > HOSTCALL_FRAME_RET_CAPACITY {
            return Err(HostcallFrameError::TooManyRets);
        }
        if HostcallStatusV1::from_u32(self.status).is_none() {
            return Err(HostcallFrameError::BadStatus);
        }
        Ok(())
    }

    pub fn write_to(&self, out: &mut [u8]) -> Result<(), HostcallFrameError> {
        if out.len() < Self::WIRE_LEN {
            return Err(HostcallFrameError::BufferTooSmall);
        }
        out[..Self::WIRE_LEN].fill(0);
        write_u32(out, 0, self.magic)?;
        write_u16(out, 4, self.version)?;
        write_u16(out, 6, self.frame_len)?;
        write_u32(out, 8, self.call_id)?;
        write_u32(out, 12, self.flags)?;
        write_object(out, 16, self.caller_store)?;
        write_object(out, 40, self.caller_activation)?;
        write_object(out, 64, self.caller_code)?;
        write_object(out, 88, self.capability)?;
        write_u16(out, 112, self.arg_count)?;
        write_u16(out, 114, self.ret_count)?;
        let mut offset = 120;
        for value in self.args {
            write_u64(out, offset, value)?;
            offset += 8;
        }
        for value in self.rets {
            write_u64(out, offset, value)?;
            offset += 8;
        }
        write_u32(out, 216, self.status)?;
        write_u32(out, 220, self.errno_or_reason)?;
        write_u64(out, 224, self.event_epoch)?;
        write_u64(out, 232, self.scratch_ptr)?;
        write_u64(out, 240, self.scratch_len)?;
        Ok(())
    }

    pub fn parse(bytes: &[u8]) -> Result<Self, HostcallFrameError> {
        if bytes.len() < Self::WIRE_LEN {
            return Err(HostcallFrameError::BufferTooSmall);
        }
        let mut args = [0; HOSTCALL_FRAME_ARG_CAPACITY];
        let mut rets = [0; HOSTCALL_FRAME_RET_CAPACITY];
        let mut offset = 120;
        for arg in &mut args {
            *arg = read_u64(bytes, offset)?;
            offset += 8;
        }
        for ret in &mut rets {
            *ret = read_u64(bytes, offset)?;
            offset += 8;
        }
        Ok(Self {
            magic: read_u32(bytes, 0)?,
            version: read_u16(bytes, 4)?,
            frame_len: read_u16(bytes, 6)?,
            call_id: read_u32(bytes, 8)?,
            flags: read_u32(bytes, 12)?,
            caller_store: read_object(bytes, 16)?,
            caller_activation: read_object(bytes, 40)?,
            caller_code: read_object(bytes, 64)?,
            capability: read_object(bytes, 88)?,
            arg_count: read_u16(bytes, 112)?,
            ret_count: read_u16(bytes, 114)?,
            args,
            rets,
            status: read_u32(bytes, 216)?,
            errno_or_reason: read_u32(bytes, 220)?,
            event_epoch: read_u64(bytes, 224)?,
            scratch_ptr: read_u64(bytes, 232)?,
            scratch_len: read_u64(bytes, 240)?,
        })
    }
}

impl Default for HostcallFrameV1 {
    fn default() -> Self {
        Self::new(0)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HostcallFrameError {
    BufferTooSmall,
    BadMagic,
    BadVersion,
    BadFrameLength,
    TooManyArgs,
    TooManyRets,
    BadStatus,
    NullFramePointer,
    UnalignedFramePointer,
    FrameOutsideScratch,
    CallerStoreMismatch,
    CallerActivationMismatch,
    CallerCodeMismatch,
}

impl HostcallFrameError {
    pub const fn status(self) -> HostcallStatusV1 {
        match self {
            Self::CallerStoreMismatch
            | Self::CallerActivationMismatch
            | Self::CallerCodeMismatch => HostcallStatusV1::GenerationMismatch,
            Self::BadMagic
            | Self::BadVersion
            | Self::BadFrameLength
            | Self::TooManyArgs
            | Self::TooManyRets
            | Self::BadStatus
            | Self::NullFramePointer
            | Self::UnalignedFramePointer
            | Self::FrameOutsideScratch
            | Self::BufferTooSmall => HostcallStatusV1::InvalidFrame,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ActivationScratchRegion {
    pub base: u64,
    pub len: u64,
    pub alignment: u64,
}

impl ActivationScratchRegion {
    pub const fn new(base: u64, len: u64, alignment: u64) -> Self {
        Self { base, len, alignment }
    }

    pub fn contains_frame(&self, frame_ptr: u64, frame_len: u16) -> bool {
        let len = u64::from(frame_len);
        let Some(end) = frame_ptr.checked_add(len) else {
            return false;
        };
        let Some(region_end) = self.base.checked_add(self.len) else {
            return false;
        };
        frame_ptr >= self.base && end <= region_end
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ActiveHostcallIdentity {
    pub store: ObjectRefRaw,
    pub activation: ObjectRefRaw,
    pub code: ObjectRefRaw,
}

pub fn validate_trampoline_frame(
    frame: &HostcallFrameV1,
    frame_ptr: u64,
    scratch: ActivationScratchRegion,
    identity: ActiveHostcallIdentity,
) -> Result<(), HostcallFrameError> {
    if frame_ptr == 0 {
        return Err(HostcallFrameError::NullFramePointer);
    }
    if !frame_ptr.is_multiple_of(scratch.alignment.max(1)) {
        return Err(HostcallFrameError::UnalignedFramePointer);
    }
    frame.validate_basic()?;
    if !scratch.contains_frame(frame_ptr, frame.frame_len) {
        return Err(HostcallFrameError::FrameOutsideScratch);
    }
    if frame.caller_store != identity.store {
        return Err(HostcallFrameError::CallerStoreMismatch);
    }
    if frame.caller_activation != identity.activation {
        return Err(HostcallFrameError::CallerActivationMismatch);
    }
    if frame.caller_code != identity.code {
        return Err(HostcallFrameError::CallerCodeMismatch);
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FakeHostcallTailInvocation {
    pub a0_frame_ptr: u64,
    pub a1_trampoline_ptr: u64,
    pub original_ra: u64,
    pub returned_ra: u64,
}

impl FakeHostcallTailInvocation {
    pub const fn new(a0_frame_ptr: u64, a1_trampoline_ptr: u64, original_ra: u64) -> Self {
        Self { a0_frame_ptr, a1_trampoline_ptr, original_ra, returned_ra: original_ra }
    }

    pub const fn uses_a0_frame_ptr(self, expected_frame_ptr: u64) -> bool {
        self.a0_frame_ptr == expected_frame_ptr
    }

    pub const fn preserves_original_ra(self) -> bool {
        self.returned_ra == self.original_ra
    }
}

fn read_u16(bytes: &[u8], offset: usize) -> Result<u16, HostcallFrameError> {
    let end = checked_add(offset, 2)?;
    let slice = bytes.get(offset..end).ok_or(HostcallFrameError::BufferTooSmall)?;
    Ok(u16::from_le_bytes([slice[0], slice[1]]))
}

fn read_u32(bytes: &[u8], offset: usize) -> Result<u32, HostcallFrameError> {
    let end = checked_add(offset, 4)?;
    let slice = bytes.get(offset..end).ok_or(HostcallFrameError::BufferTooSmall)?;
    Ok(u32::from_le_bytes([slice[0], slice[1], slice[2], slice[3]]))
}

fn read_u64(bytes: &[u8], offset: usize) -> Result<u64, HostcallFrameError> {
    let end = checked_add(offset, 8)?;
    let slice = bytes.get(offset..end).ok_or(HostcallFrameError::BufferTooSmall)?;
    Ok(u64::from_le_bytes([
        slice[0], slice[1], slice[2], slice[3], slice[4], slice[5], slice[6], slice[7],
    ]))
}

fn read_object(bytes: &[u8], offset: usize) -> Result<ObjectRefRaw, HostcallFrameError> {
    Ok(ObjectRefRaw {
        kind: read_u16(bytes, offset)?,
        reserved: read_u16(bytes, offset + 2)?,
        id: read_u64(bytes, offset + 8)?,
        generation: read_u64(bytes, offset + 16)?,
    })
}

fn write_u16(bytes: &mut [u8], offset: usize, value: u16) -> Result<(), HostcallFrameError> {
    let end = checked_add(offset, 2)?;
    let out = bytes.get_mut(offset..end).ok_or(HostcallFrameError::BufferTooSmall)?;
    out.copy_from_slice(&value.to_le_bytes());
    Ok(())
}

fn write_u32(bytes: &mut [u8], offset: usize, value: u32) -> Result<(), HostcallFrameError> {
    let end = checked_add(offset, 4)?;
    let out = bytes.get_mut(offset..end).ok_or(HostcallFrameError::BufferTooSmall)?;
    out.copy_from_slice(&value.to_le_bytes());
    Ok(())
}

fn write_u64(bytes: &mut [u8], offset: usize, value: u64) -> Result<(), HostcallFrameError> {
    let end = checked_add(offset, 8)?;
    let out = bytes.get_mut(offset..end).ok_or(HostcallFrameError::BufferTooSmall)?;
    out.copy_from_slice(&value.to_le_bytes());
    Ok(())
}

fn write_object(
    bytes: &mut [u8],
    offset: usize,
    object: ObjectRefRaw,
) -> Result<(), HostcallFrameError> {
    write_u16(bytes, offset, object.kind)?;
    write_u16(bytes, offset + 2, object.reserved)?;
    write_u64(bytes, offset + 8, object.id)?;
    write_u64(bytes, offset + 16, object.generation)?;
    Ok(())
}

fn checked_add(left: usize, right: usize) -> Result<usize, HostcallFrameError> {
    left.checked_add(right).ok_or(HostcallFrameError::BufferTooSmall)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::RV64_ENTRY_HOSTCALL_TAIL_BYTES;

    #[test]
    fn hostcall_frame_v1_roundtrip() {
        let mut frame = frame();
        frame.args[0] = 0xfeed;
        frame.rets[0] = 0xbeef;
        frame.status = HostcallStatusV1::Pending as u32;
        frame.errno_or_reason = 7;
        frame.scratch_ptr = 0x1000;
        frame.scratch_len = 0x100;
        let mut bytes = [0; HostcallFrameV1::WIRE_LEN];

        frame.write_to(&mut bytes).expect("write frame");
        let parsed = HostcallFrameV1::parse(&bytes).expect("parse frame");

        assert_eq!(parsed, frame);
        assert_eq!(parsed.validate_basic(), Ok(()));
    }

    #[test]
    fn hostcall_trampoline_rejects_frame_outside_activation_scratch() {
        let frame = frame();
        let scratch = ActivationScratchRegion::new(0x1000, 0x100, 8);

        assert_eq!(
            validate_trampoline_frame(&frame, 0x2000, scratch, identity())
                .map_err(|error| error.status()),
            Err(HostcallStatusV1::InvalidFrame)
        );
    }

    #[test]
    fn caller_refs_mismatch_executor_identity_rejects() {
        let mut frame = frame();
        frame.caller_code = ObjectRefRaw::new(OBJECT_KIND_CODE_OBJECT_V1, 99, 1);

        assert_eq!(
            validate_trampoline_frame(
                &frame,
                0x1000,
                ActivationScratchRegion::new(0x1000, 0x400, 8),
                identity(),
            ),
            Err(HostcallFrameError::CallerCodeMismatch)
        );
        assert_eq!(
            HostcallFrameError::CallerCodeMismatch.status(),
            HostcallStatusV1::GenerationMismatch
        );
    }

    #[test]
    fn denied_and_unsupported_are_trace_visible_statuses() {
        assert_eq!(
            HostcallStatusV1::from_u32(HostcallStatusV1::Denied as u32),
            Some(HostcallStatusV1::Denied)
        );
        assert_eq!(
            HostcallStatusV1::from_u32(HostcallStatusV1::Unsupported as u32),
            Some(HostcallStatusV1::Unsupported)
        );
    }

    #[test]
    fn fake_aot_hostcall_uses_a0_frame_ptr() {
        let invocation = FakeHostcallTailInvocation::new(0x1000, 0x8000, 0x55aa);

        assert!(invocation.uses_a0_frame_ptr(0x1000));
        assert_eq!(FAKE_HOSTCALL_TRAMPOLINE_REGISTER_A0, "a0");
        assert_eq!(FAKE_HOSTCALL_TRAMPOLINE_REGISTER_A1, "a1");
        assert_eq!(RV64_ENTRY_HOSTCALL_TAIL_BYTES, [0x67, 0x80, 0x05, 0x00]);
    }

    #[test]
    fn hostcall_tail_preserves_original_ra_semantics() {
        let invocation = FakeHostcallTailInvocation::new(0x1000, 0x8000, 0x55aa);

        assert!(invocation.preserves_original_ra());
        assert_ne!(invocation.a1_trampoline_ptr, 0);
    }

    fn frame() -> HostcallFrameV1 {
        let mut frame = HostcallFrameV1::new(42);
        frame.caller_store = ObjectRefRaw::new(OBJECT_KIND_STORE_V1, 1, 3);
        frame.caller_activation = ObjectRefRaw::new(OBJECT_KIND_ACTIVATION_V1, 2, 5);
        frame.caller_code = ObjectRefRaw::new(OBJECT_KIND_CODE_OBJECT_V1, 3, 7);
        frame.capability = ObjectRefRaw::new(OBJECT_KIND_CAPABILITY_V1, 4, 9);
        frame.arg_count = 1;
        frame.ret_count = 1;
        frame
    }

    fn identity() -> ActiveHostcallIdentity {
        ActiveHostcallIdentity {
            store: ObjectRefRaw::new(OBJECT_KIND_STORE_V1, 1, 3),
            activation: ObjectRefRaw::new(OBJECT_KIND_ACTIVATION_V1, 2, 5),
            code: ObjectRefRaw::new(OBJECT_KIND_CODE_OBJECT_V1, 3, 7),
        }
    }
}
