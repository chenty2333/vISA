use core::fmt::{self, Write};
use core::str;

pub const OSCTL_JSONL_FRAME_SCHEMA: &str = "osctl-jsonl-frame-v1";
pub const OSCTL_CURSOR_SCHEMA: &str = "osctl-cursor-v1";
pub const OSCTL_JSONL_NORMAL_MAX_LINE: usize = 16 * 1024;
pub const OSCTL_JSONL_HARD_MAX_LINE: usize = 64 * 1024;
pub const OSCTL_JSONL_PANIC_MAX_LINE: usize = 4 * 1024;

pub const PANIC_RING_MAGIC: [u8; 8] = *b"PANICR1\0";
pub const PANIC_RING_SIZE: usize = 64 * 1024;
pub const PANIC_RING_ALIGN: usize = 4096;
pub const PANIC_RECORD_MAX_LEN: usize = 4096;
pub const PANIC_RING_SLOT_COUNT: usize = PANIC_RING_SIZE / PANIC_RECORD_MAX_LEN;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ControlPlaneError {
    BufferTooSmall,
    InvalidUtf8,
    InvalidCursor,
    InvalidCursorVersion,
    InvalidCursorField,
    InvalidCursorInteger,
    InvalidCursorStream,
    NewlineInFrame,
    FrameExceedsHardLimit,
    PanicRecordMissing,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OsctlStreamV1 {
    EventLog,
    View,
    PanicRing,
    TargetProfile,
}

impl OsctlStreamV1 {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::EventLog => "event-log",
            Self::View => "view",
            Self::PanicRing => "panic-ring",
            Self::TargetProfile => "target-profile",
        }
    }

    pub fn parse(value: &str) -> Result<Self, ControlPlaneError> {
        if !value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-' || byte == b'_'
        }) {
            return Err(ControlPlaneError::InvalidCursorStream);
        }
        match value {
            "event-log" => Ok(Self::EventLog),
            "view" => Ok(Self::View),
            "panic-ring" => Ok(Self::PanicRing),
            "target-profile" => Ok(Self::TargetProfile),
            _ => Err(ControlPlaneError::InvalidCursorStream),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OsctlCursorV1 {
    pub epoch: u64,
    pub stream: OsctlStreamV1,
    pub seq: u64,
    pub event: u64,
    pub view: u64,
}

impl OsctlCursorV1 {
    pub const fn new(epoch: u64, stream: OsctlStreamV1, seq: u64, event: u64, view: u64) -> Self {
        Self {
            epoch,
            stream,
            seq,
            event,
            view,
        }
    }

    pub fn parse_cli(value: &str) -> Result<Self, ControlPlaneError> {
        let mut parts = value.split(':');
        if parts.next() != Some("v1") {
            return Err(ControlPlaneError::InvalidCursorVersion);
        }
        let epoch = parse_field(parts.next(), "e")?;
        let stream = parse_stream_field(parts.next(), "s")?;
        let seq = parse_field(parts.next(), "q")?;
        let event = parse_field(parts.next(), "ev")?;
        let view = parse_field(parts.next(), "v")?;
        if parts.next().is_some() {
            return Err(ControlPlaneError::InvalidCursorField);
        }
        Ok(Self::new(epoch, stream, seq, event, view))
    }

    pub fn write_cli(&self, out: &mut [u8]) -> Result<usize, ControlPlaneError> {
        let mut writer = SliceWriter::new(out);
        write!(
            writer,
            "v1:e={}:s={}:q={}:ev={}:v={}",
            self.epoch,
            self.stream.as_str(),
            self.seq,
            self.event,
            self.view
        )
        .map_err(|_| ControlPlaneError::BufferTooSmall)?;
        Ok(writer.len())
    }

    pub fn write_json<W: Write>(&self, writer: &mut W) -> fmt::Result {
        write!(
            writer,
            "{{\"schema\":\"{}\",\"epoch\":{},\"stream\":\"{}\",\"seq\":{},\"event\":{},\"view\":{}}}",
            OSCTL_CURSOR_SCHEMA,
            self.epoch,
            self.stream.as_str(),
            self.seq,
            self.event,
            self.view
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct JsonlFrameRefV1<'a> {
    pub seq: u64,
    pub epoch: u64,
    pub kind: &'a str,
    pub cursor: OsctlCursorV1,
    pub flags: &'a [&'a str],
    pub payload_json: &'a [u8],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct JsonlWriteOutcome {
    pub bytes_written: usize,
    pub cursor_advanced: bool,
    pub truncated: bool,
}

pub fn write_jsonl_frame(
    frame: JsonlFrameRefV1<'_>,
    out: &mut [u8],
    normal_limit: usize,
) -> Result<JsonlWriteOutcome, ControlPlaneError> {
    validate_json_atom(frame.kind.as_bytes())?;
    for flag in frame.flags {
        validate_json_atom(flag.as_bytes())?;
    }
    validate_payload(frame.payload_json)?;

    let mut counter = CountingWriter::default();
    write_jsonl_frame_inner(&mut counter, frame).map_err(|_| ControlPlaneError::BufferTooSmall)?;
    let estimated_len = counter.len;
    if estimated_len > OSCTL_JSONL_HARD_MAX_LINE {
        return Err(ControlPlaneError::FrameExceedsHardLimit);
    }
    if estimated_len > normal_limit {
        let mut writer = SliceWriter::new(out);
        write_truncated_frame(
            &mut writer,
            frame.seq,
            frame.kind,
            estimated_len,
            normal_limit,
        )
        .map_err(|_| ControlPlaneError::BufferTooSmall)?;
        return Ok(JsonlWriteOutcome {
            bytes_written: writer.len(),
            cursor_advanced: false,
            truncated: true,
        });
    }

    let mut writer = SliceWriter::new(out);
    write_jsonl_frame_inner(&mut writer, frame).map_err(|_| ControlPlaneError::BufferTooSmall)?;
    Ok(JsonlWriteOutcome {
        bytes_written: writer.len(),
        cursor_advanced: true,
        truncated: false,
    })
}

#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PanicRingHeaderV1 {
    pub magic: [u8; 8],
    pub version: u16,
    pub header_len: u16,
    pub capacity: u32,
    pub max_record_len: u32,
    pub write_seq: u64,
    pub oldest_seq: u64,
    pub record_count: u32,
    pub lost_count: u64,
    pub write_off: u32,
    pub flags: u32,
}

impl PanicRingHeaderV1 {
    pub const fn new() -> Self {
        Self {
            magic: PANIC_RING_MAGIC,
            version: 1,
            header_len: core::mem::size_of::<Self>() as u16,
            capacity: PANIC_RING_SIZE as u32,
            max_record_len: PANIC_RECORD_MAX_LEN as u32,
            write_seq: 0,
            oldest_seq: 1,
            record_count: 0,
            lost_count: 0,
            write_off: 0,
            flags: 0,
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PanicRecordHeaderV1 {
    pub seq: u64,
    pub kind: u16,
    pub flags: u16,
    pub len: u32,
    pub crc32: u32,
    pub committed: u32,
}

#[repr(u16)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PanicRecordKindV1 {
    PanicRecord = 1,
    LastTrap = 2,
    LastHostcallFrameSummary = 3,
    LastCodeObjectRef = 4,
    LastStoreRef = 5,
    LastActivationRef = 6,
    ContractPanicSummary = 7,
    TruncatedPanicRecord = 0xffff,
}

impl PanicRecordKindV1 {
    pub const fn schema(self) -> &'static str {
        match self {
            Self::PanicRecord => "panic-record-v1",
            Self::LastTrap => "last-trap-v1",
            Self::LastHostcallFrameSummary => "last-hostcall-frame-summary-v1",
            Self::LastCodeObjectRef => "last-code-object-ref-v1",
            Self::LastStoreRef => "last-store-ref-v1",
            Self::LastActivationRef => "last-activation-ref-v1",
            Self::ContractPanicSummary => "contract-panic-summary-v1",
            Self::TruncatedPanicRecord => "truncated-panic-record-v1",
        }
    }

    pub const fn from_u16(value: u16) -> Option<Self> {
        match value {
            1 => Some(Self::PanicRecord),
            2 => Some(Self::LastTrap),
            3 => Some(Self::LastHostcallFrameSummary),
            4 => Some(Self::LastCodeObjectRef),
            5 => Some(Self::LastStoreRef),
            6 => Some(Self::LastActivationRef),
            7 => Some(Self::ContractPanicSummary),
            0xffff => Some(Self::TruncatedPanicRecord),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PanicWriteOutcome {
    pub seq: u64,
    pub truncated: bool,
    pub overwritten: bool,
    pub lost_count: u64,
}

#[derive(Clone, Copy)]
struct PanicRecordSlotV1 {
    header: PanicRecordHeaderV1,
    payload: [u8; PANIC_RECORD_MAX_LEN],
}

impl PanicRecordSlotV1 {
    const EMPTY: Self = Self {
        header: PanicRecordHeaderV1 {
            seq: 0,
            kind: 0,
            flags: 0,
            len: 0,
            crc32: 0,
            committed: 0,
        },
        payload: [0; PANIC_RECORD_MAX_LEN],
    };
}

pub struct PanicRingV1 {
    header: PanicRingHeaderV1,
    slots: [PanicRecordSlotV1; PANIC_RING_SLOT_COUNT],
}

impl PanicRingV1 {
    pub const fn new() -> Self {
        Self {
            header: PanicRingHeaderV1::new(),
            slots: [PanicRecordSlotV1::EMPTY; PANIC_RING_SLOT_COUNT],
        }
    }

    pub const fn header(&self) -> &PanicRingHeaderV1 {
        &self.header
    }

    pub fn push_record(
        &mut self,
        kind: PanicRecordKindV1,
        payload_json: &[u8],
    ) -> Result<PanicWriteOutcome, ControlPlaneError> {
        let mut truncated_payload = [0u8; 128];
        let (kind, payload, truncated) = if payload_json.len() > PANIC_RECORD_MAX_LEN {
            let len = {
                let mut writer = SliceWriter::new(&mut truncated_payload);
                write!(
                    writer,
                    "{{\"original_len\":{},\"limit\":{}}}",
                    payload_json.len(),
                    PANIC_RECORD_MAX_LEN
                )
                .map_err(|_| ControlPlaneError::BufferTooSmall)?;
                writer.len()
            };
            (
                PanicRecordKindV1::TruncatedPanicRecord,
                &truncated_payload[..len],
                true,
            )
        } else {
            validate_payload(payload_json)?;
            (kind, payload_json, false)
        };

        let seq = self.header.write_seq + 1;
        let slot_index = ((seq - 1) as usize) % PANIC_RING_SLOT_COUNT;
        let overwritten = self.header.record_count as usize == PANIC_RING_SLOT_COUNT;
        if overwritten {
            self.header.lost_count += 1;
            self.header.oldest_seq += 1;
        } else {
            self.header.record_count += 1;
            if self.header.record_count == 1 {
                self.header.oldest_seq = seq;
            }
        }

        let slot = &mut self.slots[slot_index];
        slot.header = PanicRecordHeaderV1 {
            seq,
            kind: kind as u16,
            flags: 0,
            len: payload.len() as u32,
            crc32: crc32(payload),
            committed: 0,
        };
        slot.payload.fill(0);
        slot.payload[..payload.len()].copy_from_slice(payload);
        slot.header.committed = 1;

        self.header.write_seq = seq;
        self.header.write_off = (slot_index * PANIC_RECORD_MAX_LEN) as u32;
        Ok(PanicWriteOutcome {
            seq,
            truncated,
            overwritten,
            lost_count: self.header.lost_count,
        })
    }

    pub fn dump_jsonl(&self, out: &mut [u8]) -> Result<usize, ControlPlaneError> {
        let mut writer = SliceWriter::new(out);
        let newest = self.header.write_seq;
        write!(
            writer,
            "{{\"schema\":\"panic-ring-begin-v1\",\"oldest_seq\":{},\"newest_seq\":{},\"lost_count\":{}}}\n",
            self.header.oldest_seq, newest, self.header.lost_count
        )
        .map_err(|_| ControlPlaneError::BufferTooSmall)?;

        for index in 0..self.header.record_count {
            let seq = self.header.oldest_seq + u64::from(index);
            let slot_index = ((seq - 1) as usize) % PANIC_RING_SLOT_COUNT;
            let slot = &self.slots[slot_index];
            let valid_len = slot.header.len as usize <= PANIC_RECORD_MAX_LEN;
            let payload = if valid_len {
                &slot.payload[..slot.header.len as usize]
            } else {
                &[]
            };
            let valid = slot.header.seq == seq
                && slot.header.committed == 1
                && valid_len
                && slot.header.crc32 == crc32(payload);
            if !valid {
                write!(
                    writer,
                    "{{\"schema\":\"panic-ring-corrupt-record-v1\",\"seq\":{seq}}}\n"
                )
                .map_err(|_| ControlPlaneError::BufferTooSmall)?;
                continue;
            }
            let kind = PanicRecordKindV1::from_u16(slot.header.kind)
                .ok_or(ControlPlaneError::PanicRecordMissing)?;
            let payload = str::from_utf8(payload).map_err(|_| ControlPlaneError::InvalidUtf8)?;
            write!(
                writer,
                "{{\"schema\":\"{}\",\"seq\":{},\"payload\":{}}}\n",
                kind.schema(),
                seq,
                payload
            )
            .map_err(|_| ControlPlaneError::BufferTooSmall)?;
        }
        writer
            .write_str("{\"schema\":\"panic-ring-end-v1\"}\n")
            .map_err(|_| ControlPlaneError::BufferTooSmall)?;
        Ok(writer.len())
    }

    pub fn corrupt_record_for_test(
        &mut self,
        seq: u64,
        committed: u32,
        crc32_value: u32,
    ) -> Result<(), ControlPlaneError> {
        let slot_index = ((seq - 1) as usize) % PANIC_RING_SLOT_COUNT;
        let slot = self
            .slots
            .get_mut(slot_index)
            .ok_or(ControlPlaneError::PanicRecordMissing)?;
        if slot.header.seq != seq {
            return Err(ControlPlaneError::PanicRecordMissing);
        }
        slot.header.committed = committed;
        slot.header.crc32 = crc32_value;
        Ok(())
    }
}

impl Default for PanicRingV1 {
    fn default() -> Self {
        Self::new()
    }
}

fn write_jsonl_frame_inner<W: Write>(writer: &mut W, frame: JsonlFrameRefV1<'_>) -> fmt::Result {
    write!(
        writer,
        "{{\"schema\":\"{}\",\"seq\":{},\"epoch\":{},\"kind\":\"{}\",\"cursor\":",
        OSCTL_JSONL_FRAME_SCHEMA, frame.seq, frame.epoch, frame.kind
    )?;
    frame.cursor.write_json(writer)?;
    writer.write_str(",\"flags\":[")?;
    for (index, flag) in frame.flags.iter().enumerate() {
        if index != 0 {
            writer.write_char(',')?;
        }
        write!(writer, "\"{flag}\"")?;
    }
    writer.write_str("],\"payload\":")?;
    let payload = str::from_utf8(frame.payload_json).map_err(|_| fmt::Error)?;
    writer.write_str(payload)?;
    writer.write_str("}\n")
}

fn write_truncated_frame<W: Write>(
    writer: &mut W,
    seq: u64,
    original_kind: &str,
    original_estimated_len: usize,
    limit: usize,
) -> fmt::Result {
    write!(
        writer,
        "{{\"schema\":\"{}\",\"seq\":{},\"kind\":\"truncated-frame-v1\",\"reason\":\"line_too_long\",\"original_kind\":\"{}\",\"original_estimated_len\":{},\"limit\":{}}}\n",
        OSCTL_JSONL_FRAME_SCHEMA, seq, original_kind, original_estimated_len, limit
    )
}

fn parse_field(value: Option<&str>, name: &str) -> Result<u64, ControlPlaneError> {
    let value = value.ok_or(ControlPlaneError::InvalidCursor)?;
    let Some(raw) = value
        .strip_prefix(name)
        .and_then(|rest| rest.strip_prefix('='))
    else {
        return Err(ControlPlaneError::InvalidCursorField);
    };
    parse_decimal_u64(raw)
}

fn parse_stream_field(value: Option<&str>, name: &str) -> Result<OsctlStreamV1, ControlPlaneError> {
    let value = value.ok_or(ControlPlaneError::InvalidCursor)?;
    let Some(raw) = value
        .strip_prefix(name)
        .and_then(|rest| rest.strip_prefix('='))
    else {
        return Err(ControlPlaneError::InvalidCursorField);
    };
    OsctlStreamV1::parse(raw)
}

fn parse_decimal_u64(value: &str) -> Result<u64, ControlPlaneError> {
    if value.is_empty() {
        return Err(ControlPlaneError::InvalidCursorInteger);
    }
    if value.len() > 1 && value.as_bytes()[0] == b'0' {
        return Err(ControlPlaneError::InvalidCursorInteger);
    }
    let mut out = 0u64;
    for byte in value.bytes() {
        if !byte.is_ascii_digit() {
            return Err(ControlPlaneError::InvalidCursorInteger);
        }
        out = out
            .checked_mul(10)
            .and_then(|value| value.checked_add(u64::from(byte - b'0')))
            .ok_or(ControlPlaneError::InvalidCursorInteger)?;
    }
    Ok(out)
}

fn validate_json_atom(bytes: &[u8]) -> Result<(), ControlPlaneError> {
    if bytes
        .iter()
        .any(|byte| *byte == b'\n' || *byte == b'\r' || *byte == b'"')
    {
        return Err(ControlPlaneError::NewlineInFrame);
    }
    Ok(())
}

fn validate_payload(bytes: &[u8]) -> Result<(), ControlPlaneError> {
    str::from_utf8(bytes).map_err(|_| ControlPlaneError::InvalidUtf8)?;
    if bytes.iter().any(|byte| *byte == b'\n' || *byte == b'\r') {
        return Err(ControlPlaneError::NewlineInFrame);
    }
    Ok(())
}

#[derive(Default)]
struct CountingWriter {
    len: usize,
}

impl Write for CountingWriter {
    fn write_str(&mut self, value: &str) -> fmt::Result {
        self.len += value.len();
        Ok(())
    }
}

struct SliceWriter<'a> {
    out: &'a mut [u8],
    len: usize,
}

impl<'a> SliceWriter<'a> {
    fn new(out: &'a mut [u8]) -> Self {
        Self { out, len: 0 }
    }

    const fn len(&self) -> usize {
        self.len
    }
}

impl Write for SliceWriter<'_> {
    fn write_str(&mut self, value: &str) -> fmt::Result {
        let bytes = value.as_bytes();
        let end = self.len.checked_add(bytes.len()).ok_or(fmt::Error)?;
        let Some(out) = self.out.get_mut(self.len..end) else {
            return Err(fmt::Error);
        };
        out.copy_from_slice(bytes);
        self.len = end;
        Ok(())
    }
}

fn crc32(bytes: &[u8]) -> u32 {
    let mut crc = 0xffff_ffffu32;
    for byte in bytes {
        crc ^= u32::from(*byte);
        for _ in 0..8 {
            let mask = 0u32.wrapping_sub(crc & 1);
            crc = (crc >> 1) ^ (0xedb8_8320 & mask);
        }
    }
    !crc
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn panic_ring_headers_match_default_profile() {
        let header = PanicRingHeaderV1::new();

        assert_eq!(header.magic, PANIC_RING_MAGIC);
        assert_eq!(header.version, 1);
        assert_eq!(header.capacity, 64 * 1024);
        assert_eq!(header.max_record_len, 4 * 1024);
        assert_eq!(PANIC_RING_ALIGN, 4096);
        assert_eq!(
            core::mem::size_of::<PanicRecordHeaderV1>(),
            core::mem::size_of::<u64>()
                + 2 * core::mem::size_of::<u16>()
                + 3 * core::mem::size_of::<u32>()
        );
    }

    #[test]
    fn qemu_jsonl_frame_one_line_only() {
        let cursor = OsctlCursorV1::new(17, OsctlStreamV1::EventLog, 42, 900, 12);
        let frame = JsonlFrameRefV1 {
            seq: 42,
            epoch: 17,
            kind: "store-view-v1",
            cursor,
            flags: &[],
            payload_json: br#"{"id":1,"state":"running"}"#,
        };
        let mut out = [0u8; 512];

        let result =
            write_jsonl_frame(frame, &mut out, OSCTL_JSONL_NORMAL_MAX_LINE).expect("write");
        let line = core::str::from_utf8(&out[..result.bytes_written]).unwrap();

        assert!(result.cursor_advanced);
        assert!(!result.truncated);
        assert!(line.starts_with(r#"{"schema":"osctl-jsonl-frame-v1""#));
        assert!(line.ends_with('\n'));
        assert_eq!(
            line.as_bytes()
                .iter()
                .filter(|byte| **byte == b'\n')
                .count(),
            1
        );
    }

    #[test]
    fn jsonl_cursor_object_to_cli_roundtrip() {
        let cursor = OsctlCursorV1::new(17, OsctlStreamV1::EventLog, 42, 900, 12);
        let mut out = [0u8; 64];

        let len = cursor.write_cli(&mut out).expect("cursor cli");
        let cli = core::str::from_utf8(&out[..len]).unwrap();
        let parsed = OsctlCursorV1::parse_cli(cli).expect("parse cli");

        assert_eq!(cli, "v1:e=17:s=event-log:q=42:ev=900:v=12");
        assert_eq!(parsed, cursor);
        assert!(OsctlCursorV1::parse_cli("v1:e=017:s=event-log:q=42:ev=900:v=12").is_err());
        assert!(OsctlCursorV1::parse_cli("v1:s=event-log:e=17:q=42:ev=900:v=12").is_err());
    }

    #[test]
    fn jsonl_truncated_frame_does_not_advance_cursor() {
        let cursor = OsctlCursorV1::new(17, OsctlStreamV1::EventLog, 42, 900, 12);
        let frame = JsonlFrameRefV1 {
            seq: 43,
            epoch: 17,
            kind: "event-log-view-v1",
            cursor,
            flags: &[],
            payload_json:
                br#"{"message":"this payload is intentionally longer than the small test limit"}"#,
        };
        let mut out = [0u8; 512];

        let result = write_jsonl_frame(frame, &mut out, 64).expect("truncated frame");
        let line = core::str::from_utf8(&out[..result.bytes_written]).unwrap();

        assert!(!result.cursor_advanced);
        assert!(result.truncated);
        assert!(line.contains(r#""kind":"truncated-frame-v1""#));
        assert!(line.contains(r#""original_kind":"event-log-view-v1""#));
        assert_eq!(
            line.as_bytes()
                .iter()
                .filter(|byte| **byte == b'\n')
                .count(),
            1
        );
    }

    #[test]
    fn panic_ring_64k_overwrites_oldest() {
        let mut ring = PanicRingV1::new();
        let mut payload = [b' '; PANIC_RECORD_MAX_LEN];
        payload[0] = b'{';
        payload[1] = b'}';

        for _ in 0..=PANIC_RING_SLOT_COUNT {
            ring.push_record(PanicRecordKindV1::PanicRecord, &payload)
                .expect("panic record");
        }

        assert_eq!(ring.header().capacity, PANIC_RING_SIZE as u32);
        assert_eq!(ring.header().max_record_len, PANIC_RECORD_MAX_LEN as u32);
        assert_eq!(ring.header().record_count as usize, PANIC_RING_SLOT_COUNT);
        assert_eq!(ring.header().lost_count, 1);
        assert_eq!(ring.header().oldest_seq, 2);
    }

    #[test]
    fn panic_ring_overwrites_oldest_and_counts_lost() {
        let mut ring = PanicRingV1::new();
        let payload = br#"{"cpu":0,"pc":"0x80200000","reason":"substrate_panic"}"#;

        for _ in 0..(PANIC_RING_SLOT_COUNT + 3) {
            ring.push_record(PanicRecordKindV1::PanicRecord, payload)
                .expect("panic record");
        }

        assert_eq!(ring.header().record_count as usize, PANIC_RING_SLOT_COUNT);
        assert_eq!(ring.header().lost_count, 3);
        assert_eq!(ring.header().oldest_seq, 4);
    }

    #[test]
    fn panic_ring_truncates_oversized_record() {
        let mut ring = PanicRingV1::new();
        let payload = [b'a'; PANIC_RECORD_MAX_LEN + 1];

        let result = ring
            .push_record(PanicRecordKindV1::PanicRecord, &payload)
            .expect("truncated panic");

        assert!(result.truncated);
        assert_eq!(ring.header().write_seq, 1);
        let mut out = [0u8; 1024];
        let len = ring.dump_jsonl(&mut out).expect("dump ring");
        let dump = core::str::from_utf8(&out[..len]).unwrap();
        assert!(dump.contains("truncated-panic-record-v1"));
        assert!(dump.contains(r#""original_len":4097"#));
    }

    #[test]
    fn jsonl_panic_record_fits_panic_limit() {
        let mut ring = PanicRingV1::new();
        ring.push_record(
            PanicRecordKindV1::PanicRecord,
            br#"{"cpu":0,"pc":"0x80201234","reason":"substrate_panic"}"#,
        )
        .expect("panic record");
        let mut out = [0u8; OSCTL_JSONL_PANIC_MAX_LINE];

        let len = ring.dump_jsonl(&mut out).expect("dump panic ring");
        let dump = core::str::from_utf8(&out[..len]).unwrap();

        for line in dump.lines() {
            assert!(line.len() < OSCTL_JSONL_PANIC_MAX_LINE);
        }
        assert!(dump.contains("panic-record-v1"));
    }

    #[test]
    fn panic_ring_skips_corrupt_record_and_reports_frame() {
        let mut ring = PanicRingV1::new();
        let bad_crc = ring
            .push_record(PanicRecordKindV1::PanicRecord, br#"{"reason":"panic"}"#)
            .expect("panic record");
        let uncommitted = ring
            .push_record(PanicRecordKindV1::PanicRecord, br#"{"reason":"panic2"}"#)
            .expect("panic record");
        ring.corrupt_record_for_test(bad_crc.seq, 1, 0)
            .expect("corrupt record");
        ring.corrupt_record_for_test(uncommitted.seq, 0, 0)
            .expect("corrupt record");
        let mut out = [0u8; 512];

        let len = ring.dump_jsonl(&mut out).expect("dump panic ring");
        let dump = core::str::from_utf8(&out[..len]).unwrap();

        assert_eq!(dump.matches("panic-ring-corrupt-record-v1").count(), 2);
        assert!(dump.contains("panic-ring-end-v1"));
    }
}
