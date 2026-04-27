pub const VIRTIO_BLK_BACKEND_PROVIDER: &str = "substrate_virtio";
pub const VIRTIO_BLK_BACKEND_PROFILE: &str = "virtio-blk-backend-skeleton-v1";
pub const VIRTIO_BLK_BACKEND_MODEL: &str = "virtio-blk";

pub const VIRTIO_BLK_F_BLK_SIZE: u64 = 1 << 6;
pub const VIRTIO_BLK_F_FLUSH: u64 = 1 << 9;
pub const VIRTIO_BLK_SKELETON_FEATURES: u64 = VIRTIO_BLK_F_BLK_SIZE | VIRTIO_BLK_F_FLUSH;
pub const VIRTIO_BLK_REQUEST_QUEUE_INDEX: u16 = 0;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VirtioBlkBackendConfig {
    pub sector_size: u32,
    pub sector_count: u64,
    pub read_only: bool,
    pub max_transfer_sectors: u32,
    pub device_features: u64,
    pub driver_features: u64,
    pub negotiated_features: u64,
    pub request_queue_index: u16,
    pub queue_size: u16,
    pub irq_vector: u16,
}

impl VirtioBlkBackendConfig {
    pub const fn blk0() -> Self {
        Self {
            sector_size: 512,
            sector_count: 4096,
            read_only: false,
            max_transfer_sectors: 128,
            device_features: VIRTIO_BLK_SKELETON_FEATURES,
            driver_features: VIRTIO_BLK_F_BLK_SIZE,
            negotiated_features: VIRTIO_BLK_F_BLK_SIZE,
            request_queue_index: VIRTIO_BLK_REQUEST_QUEUE_INDEX,
            queue_size: 8,
            irq_vector: 6,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VirtioBlkBackendState {
    SkeletonReady,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VirtioBlkBackendEvidence {
    pub provider: &'static str,
    pub profile: &'static str,
    pub model: &'static str,
    pub state: VirtioBlkBackendState,
    pub config: VirtioBlkBackendConfig,
}

pub struct VirtioBlkBackendSkeleton {
    config: VirtioBlkBackendConfig,
}

impl VirtioBlkBackendSkeleton {
    pub const fn new(config: VirtioBlkBackendConfig) -> Self {
        Self { config }
    }

    pub const fn config(&self) -> VirtioBlkBackendConfig {
        self.config
    }

    pub fn evidence(&self) -> Result<VirtioBlkBackendEvidence, &'static str> {
        validate_config(self.config)?;
        Ok(VirtioBlkBackendEvidence {
            provider: VIRTIO_BLK_BACKEND_PROVIDER,
            profile: VIRTIO_BLK_BACKEND_PROFILE,
            model: VIRTIO_BLK_BACKEND_MODEL,
            state: VirtioBlkBackendState::SkeletonReady,
            config: self.config,
        })
    }
}

impl Default for VirtioBlkBackendSkeleton {
    fn default() -> Self {
        Self::new(VirtioBlkBackendConfig::blk0())
    }
}

pub fn validate_config(config: VirtioBlkBackendConfig) -> Result<(), &'static str> {
    if config.sector_size < 512 || !config.sector_size.is_power_of_two() {
        return Err("virtio block backend sector size is unsupported");
    }
    if config.sector_count == 0 {
        return Err("virtio block backend sector count is zero");
    }
    if config.max_transfer_sectors == 0 {
        return Err("virtio block backend max transfer is zero");
    }
    if config.queue_size == 0 {
        return Err("virtio block backend queue size is zero");
    }
    if config.irq_vector == 0 {
        return Err("virtio block backend irq vector is zero");
    }
    if config.negotiated_features & !config.device_features != 0 {
        return Err("virtio block backend negotiated features exceed device features");
    }
    if config.negotiated_features & !config.driver_features != 0 {
        return Err("virtio block backend negotiated features exceed driver features");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn virtio_block_skeleton_reports_stable_profile_evidence() {
        let backend = VirtioBlkBackendSkeleton::default();
        let evidence = backend.evidence().unwrap();
        assert_eq!(evidence.provider, "substrate_virtio");
        assert_eq!(evidence.profile, "virtio-blk-backend-skeleton-v1");
        assert_eq!(evidence.model, "virtio-blk");
        assert_eq!(evidence.config.sector_size, 512);
        assert_eq!(evidence.config.sector_count, 4096);
        assert_eq!(evidence.config.request_queue_index, 0);
        assert_eq!(evidence.config.negotiated_features, VIRTIO_BLK_F_BLK_SIZE);
    }

    #[test]
    fn virtio_block_skeleton_rejects_invalid_geometry_queue_and_features() {
        let mut config = VirtioBlkBackendConfig::blk0();
        config.sector_size = 511;
        assert_eq!(
            validate_config(config),
            Err("virtio block backend sector size is unsupported")
        );

        config = VirtioBlkBackendConfig::blk0();
        config.sector_count = 0;
        assert_eq!(
            validate_config(config),
            Err("virtio block backend sector count is zero")
        );

        config = VirtioBlkBackendConfig::blk0();
        config.queue_size = 0;
        assert_eq!(
            validate_config(config),
            Err("virtio block backend queue size is zero")
        );

        config = VirtioBlkBackendConfig::blk0();
        config.negotiated_features = VIRTIO_BLK_F_FLUSH;
        assert_eq!(
            validate_config(config),
            Err("virtio block backend negotiated features exceed driver features")
        );

        config = VirtioBlkBackendConfig::blk0();
        config.negotiated_features = 1 << 63;
        assert_eq!(
            validate_config(config),
            Err("virtio block backend negotiated features exceed device features")
        );
    }
}
