use visa_profile::{
    CodePublishSupport, DmaSupport, DmwSupport, SnapshotSupport, VisaCapabilitySet,
    VisaProfileLevel,
};

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
        Self { supported: true, wx: true, icache_sync: true, remote_icache_sync: false }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DmwProfileV1 {
    None,
    Logical,
    RealMmuWindow { slot_count: u16, slot_size: u64, per_core: bool },
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

    pub const fn to_visa_capabilities(self) -> VisaCapabilitySet {
        VisaCapabilitySet {
            console: self.log_sink,
            timer: self.timer_authority,
            event_queue: self.event_queue,
            guest_memory: self.memory_protection,
            artifact_loading: self.code_publish.supported,
            dmw: match self.dmw {
                DmwProfileV1::None => DmwSupport::None,
                DmwProfileV1::Logical => DmwSupport::Logical,
                DmwProfileV1::RealMmuWindow { .. } => DmwSupport::RealMmuWindow,
            },
            mmio: self.mmio_authority,
            irq: self.irq_authority,
            dma: match self.dma {
                DmaProfileV1::None => DmaSupport::None,
                DmaProfileV1::BounceBuffer => DmaSupport::BounceBuffer,
                DmaProfileV1::Mediated => DmaSupport::Mediated,
                DmaProfileV1::IommuStrict => DmaSupport::IommuStrict,
            },
            snapshot: SnapshotSupport::None,
            code_publish: if !self.code_publish.supported {
                CodePublishSupport::None
            } else if self.code_publish.wx {
                CodePublishSupport::NativeWx
            } else {
                CodePublishSupport::RuntimeOnly
            },
        }
    }

    pub const fn enforced_visa_profile(self) -> Option<VisaProfileLevel> {
        let capabilities = self.to_visa_capabilities();
        if capabilities.supports_profile(VisaProfileLevel::SnapshotReplayCapable) {
            Some(VisaProfileLevel::SnapshotReplayCapable)
        } else if capabilities.supports_profile(VisaProfileLevel::DeviceCapable) {
            Some(VisaProfileLevel::DeviceCapable)
        } else if capabilities.supports_profile(VisaProfileLevel::GuestFrontend) {
            Some(VisaProfileLevel::GuestFrontend)
        } else if capabilities.supports_profile(VisaProfileLevel::MinimalBareMetal) {
            Some(VisaProfileLevel::MinimalBareMetal)
        } else if capabilities.supports_profile(VisaProfileLevel::SemanticHarness) {
            Some(VisaProfileLevel::SemanticHarness)
        } else {
            None
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

    #[test]
    fn default_profile_maps_to_visa_capabilities() {
        let profile = TargetSubstrateProfileV1::default_research();
        let capabilities = profile.to_visa_capabilities();

        assert!(capabilities.supports_profile(VisaProfileLevel::GuestFrontend));
        assert!(!capabilities.supports_profile(VisaProfileLevel::DeviceCapable));
        assert_eq!(profile.enforced_visa_profile(), Some(VisaProfileLevel::GuestFrontend));
    }
}
