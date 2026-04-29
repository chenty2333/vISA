use crate::ObjectRefRaw;

#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PcRangeEntryV1 {
    pub code_object: ObjectRefRaw,
    pub rx_base: u64,
    pub rx_len: u64,
    pub code_offset_base: u64,
    pub flags: u32,
}

impl PcRangeEntryV1 {
    pub const WIRE_LEN: usize = core::mem::size_of::<Self>();

    pub const fn new(
        code_object: ObjectRefRaw,
        rx_base: u64,
        rx_len: u64,
        code_offset_base: u64,
        flags: u32,
    ) -> Self {
        Self { code_object, rx_base, rx_len, code_offset_base, flags }
    }

    pub fn contains(self, pc: u64) -> bool {
        let Some(end) = self.rx_base.checked_add(self.rx_len) else {
            return false;
        };
        pc >= self.rx_base && pc < end
    }

    pub fn code_offset(self, pc: u64) -> Option<u64> {
        self.contains(pc).then_some(pc - self.rx_base + self.code_offset_base)
    }
}

#[repr(u16)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TrapKindV1 {
    WasmBounds = 1,
    WasmUnreachable = 2,
    BadIndirectCall = 3,
    IntegerDivByZero = 4,
    StackOverflow = 5,
    HostcallFault = 6,
    CapabilityDenied = 7,
    WindowViolation = 8,
    UnknownCodeTrap = 9,
    SubstrateFault = 10,
    UnknownCodeFault = 11,
    StaleCodeExecutionFault = 12,
    SimdUnsupported = 13,
    SimdIllegalInstruction = 14,
}

impl TrapKindV1 {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::WasmBounds => "wasm-bounds",
            Self::WasmUnreachable => "wasm-unreachable",
            Self::BadIndirectCall => "bad-indirect-call",
            Self::IntegerDivByZero => "integer-div-by-zero",
            Self::StackOverflow => "stack-overflow",
            Self::HostcallFault => "hostcall-fault",
            Self::CapabilityDenied => "capability-denied",
            Self::WindowViolation => "window-violation",
            Self::UnknownCodeTrap => "unknown-code-trap",
            Self::SubstrateFault => "substrate-fault",
            Self::UnknownCodeFault => "unknown-code-fault",
            Self::StaleCodeExecutionFault => "stale-code-execution-fault",
            Self::SimdUnsupported => "simd-unsupported",
            Self::SimdIllegalInstruction => "simd-illegal-instruction",
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TrapMapEntryV1 {
    pub code_object: ObjectRefRaw,
    pub code_offset_start: u64,
    pub code_offset_end: u64,
    pub trap_kind: TrapKindV1,
    pub function_index: u32,
    pub wasm_offset: u64,
    pub debug_symbol: u32,
}

impl TrapMapEntryV1 {
    pub const WIRE_LEN: usize = core::mem::size_of::<Self>();

    pub const fn new(
        code_object: ObjectRefRaw,
        code_offset_start: u64,
        code_offset_end: u64,
        trap_kind: TrapKindV1,
        function_index: u32,
        wasm_offset: u64,
        debug_symbol: u32,
    ) -> Self {
        Self {
            code_object,
            code_offset_start,
            code_offset_end,
            trap_kind,
            function_index,
            wasm_offset,
            debug_symbol,
        }
    }

    pub fn covers(self, code_object: ObjectRefRaw, code_offset: u64) -> bool {
        self.code_object == code_object
            && code_offset >= self.code_offset_start
            && code_offset < self.code_offset_end
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CodeRangeStateV1 {
    Live,
    Retired,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PcRangeRuntimeEntryV1 {
    pub range: PcRangeEntryV1,
    pub state: CodeRangeStateV1,
}

impl PcRangeRuntimeEntryV1 {
    pub const fn live(range: PcRangeEntryV1) -> Self {
        Self { range, state: CodeRangeStateV1::Live }
    }

    pub const fn retired(range: PcRangeEntryV1) -> Self {
        Self { range, state: CodeRangeStateV1::Retired }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TrapAttributionV1 {
    pub code_object: Option<ObjectRefRaw>,
    pub pc: u64,
    pub code_offset: Option<u64>,
    pub trap_kind: TrapKindV1,
    pub function_index: Option<u32>,
    pub wasm_offset: Option<u64>,
    pub debug_symbol: Option<u32>,
}

pub fn classify_trap_pc(
    pc: u64,
    ranges: &[PcRangeRuntimeEntryV1],
    trap_map: &[TrapMapEntryV1],
) -> TrapAttributionV1 {
    let Some(range) = ranges.iter().find(|entry| entry.range.contains(pc)).copied() else {
        return TrapAttributionV1 {
            code_object: None,
            pc,
            code_offset: None,
            trap_kind: TrapKindV1::UnknownCodeFault,
            function_index: None,
            wasm_offset: None,
            debug_symbol: None,
        };
    };
    let code_offset = range.range.code_offset(pc).expect("contains(pc) already validated offset");
    if range.state == CodeRangeStateV1::Retired {
        return TrapAttributionV1 {
            code_object: Some(range.range.code_object),
            pc,
            code_offset: Some(code_offset),
            trap_kind: TrapKindV1::StaleCodeExecutionFault,
            function_index: None,
            wasm_offset: None,
            debug_symbol: None,
        };
    }
    let Some(entry) =
        trap_map.iter().find(|entry| entry.covers(range.range.code_object, code_offset)).copied()
    else {
        return TrapAttributionV1 {
            code_object: Some(range.range.code_object),
            pc,
            code_offset: Some(code_offset),
            trap_kind: TrapKindV1::UnknownCodeTrap,
            function_index: None,
            wasm_offset: None,
            debug_symbol: None,
        };
    };
    TrapAttributionV1 {
        code_object: Some(range.range.code_object),
        pc,
        code_offset: Some(code_offset),
        trap_kind: entry.trap_kind,
        function_index: Some(entry.function_index),
        wasm_offset: Some(entry.wasm_offset),
        debug_symbol: Some(entry.debug_symbol),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{OBJECT_KIND_CODE_OBJECT_V1, RV64_ENTRY_TRAP_EBREAK_OFFSET};

    #[test]
    fn trap_pc_maps_to_codeobject_offset() {
        let code = ObjectRefRaw::new(OBJECT_KIND_CODE_OBJECT_V1, 7, 3);
        let range = PcRangeEntryV1::new(code, 0x8000, 0x1000, 0, 0);

        let attribution = classify_trap_pc(
            0x8020,
            &[PcRangeRuntimeEntryV1::live(range)],
            &[trap_entry(code, RV64_ENTRY_TRAP_EBREAK_OFFSET)],
        );

        assert_eq!(attribution.code_object, Some(code));
        assert_eq!(attribution.code_offset, Some(0x20));
    }

    #[test]
    fn fake_aot_ebreak_trap_maps_to_code_offset() {
        let code = ObjectRefRaw::new(OBJECT_KIND_CODE_OBJECT_V1, 7, 3);
        let range = PcRangeEntryV1::new(code, 0x8000, 0x1000, 0, 0);

        let attribution = classify_trap_pc(
            0x8000 + RV64_ENTRY_TRAP_EBREAK_OFFSET,
            &[PcRangeRuntimeEntryV1::live(range)],
            &[trap_entry(code, RV64_ENTRY_TRAP_EBREAK_OFFSET)],
        );

        assert_eq!(
            attribution.trap_kind,
            TrapKindV1::WasmUnreachable,
            "fake ebreak is classified through TrapMap, not by raw PC alone"
        );
        assert_eq!(attribution.code_offset, Some(RV64_ENTRY_TRAP_EBREAK_OFFSET));
    }

    #[test]
    fn unknown_pc_creates_unknown_code_fault() {
        let code = ObjectRefRaw::new(OBJECT_KIND_CODE_OBJECT_V1, 7, 3);
        let range = PcRangeEntryV1::new(code, 0x8000, 0x100, 0, 0);

        let attribution = classify_trap_pc(
            0x9000,
            &[PcRangeRuntimeEntryV1::live(range)],
            &[trap_entry(code, RV64_ENTRY_TRAP_EBREAK_OFFSET)],
        );

        assert_eq!(attribution.code_object, None);
        assert_eq!(attribution.trap_kind, TrapKindV1::UnknownCodeFault);
    }

    #[test]
    fn retired_code_execution_is_stale_code_fault() {
        let code = ObjectRefRaw::new(OBJECT_KIND_CODE_OBJECT_V1, 7, 3);
        let range = PcRangeEntryV1::new(code, 0x8000, 0x100, 0, 0);

        let attribution = classify_trap_pc(
            0x8020,
            &[PcRangeRuntimeEntryV1::retired(range)],
            &[trap_entry(code, RV64_ENTRY_TRAP_EBREAK_OFFSET)],
        );

        assert_eq!(attribution.code_object, Some(code));
        assert_eq!(attribution.code_offset, Some(0x20));
        assert_eq!(attribution.trap_kind, TrapKindV1::StaleCodeExecutionFault);
    }

    fn trap_entry(code: ObjectRefRaw, offset: u64) -> TrapMapEntryV1 {
        TrapMapEntryV1::new(code, offset, offset + 4, TrapKindV1::WasmUnreachable, 2, 0x44, 3)
    }
}
