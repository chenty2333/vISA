#[repr(u16)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TargetArchV1 {
    Riscv64 = 1,
    X86_64 = 2,
    Aarch64 = 3,
}

#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EndianV1 {
    Little = 1,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CodePublishProfileV1 {
    pub supported: bool,
    pub wx: bool,
    pub icache_sync: bool,
    pub remote_icache_sync: bool,
}

impl CodePublishProfileV1 {
    pub const fn single_hart_aot_rx_pages() -> Self {
        Self {
            supported: true,
            wx: true,
            icache_sync: true,
            remote_icache_sync: false,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DmwProfileV1 {
    None,
    Logical,
    RealMmuWindow {
        slot_count: u16,
        slot_size: u64,
        per_core: bool,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DmaProfileV1 {
    None,
    BounceBuffer,
    Mediated,
    IommuStrict,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TargetSubstrateProfileV1 {
    pub schema: u16,
    pub target_arch: TargetArchV1,
    pub pointer_width: u8,
    pub endian: EndianV1,
    pub code_publish: CodePublishProfileV1,
    pub memory_protection: bool,
    pub dmw: DmwProfileV1,
    pub dma: DmaProfileV1,
    pub mmio_authority: bool,
    pub irq_authority: bool,
    pub timer_authority: bool,
    pub event_queue: bool,
    pub log_sink: bool,
    pub panic_ring_bytes: u32,
    pub osctl_jsonl: bool,
    pub host_to_target_osctl: bool,
}

impl TargetSubstrateProfileV1 {
    pub const SCHEMA_V1: u16 = 1;
    pub const PANIC_RING_BYTES_DEFAULT: u32 = 64 * 1024;

    pub const fn default_research() -> Self {
        Self {
            schema: Self::SCHEMA_V1,
            target_arch: TargetArchV1::Riscv64,
            pointer_width: 64,
            endian: EndianV1::Little,
            code_publish: CodePublishProfileV1::single_hart_aot_rx_pages(),
            memory_protection: true,
            dmw: DmwProfileV1::Logical,
            dma: DmaProfileV1::BounceBuffer,
            mmio_authority: false,
            irq_authority: false,
            timer_authority: true,
            event_queue: true,
            log_sink: true,
            panic_ring_bytes: Self::PANIC_RING_BYTES_DEFAULT,
            osctl_jsonl: true,
            host_to_target_osctl: false,
        }
    }
}

impl Default for TargetSubstrateProfileV1 {
    fn default() -> Self {
        Self::default_research()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_profile_covers_research_target_fields() {
        let profile = TargetSubstrateProfileV1::default_research();

        assert_eq!(profile.schema, TargetSubstrateProfileV1::SCHEMA_V1);
        assert_eq!(profile.target_arch, TargetArchV1::Riscv64);
        assert_eq!(profile.pointer_width, 64);
        assert_eq!(profile.endian, EndianV1::Little);
        assert!(profile.code_publish.wx);
        assert!(profile.code_publish.icache_sync);
        assert!(!profile.code_publish.remote_icache_sync);
        assert_eq!(profile.dmw, DmwProfileV1::Logical);
        assert_eq!(profile.dma, DmaProfileV1::BounceBuffer);
        assert_eq!(profile.panic_ring_bytes, 64 * 1024);
        assert!(profile.osctl_jsonl);
        assert!(!profile.host_to_target_osctl);
    }
}
