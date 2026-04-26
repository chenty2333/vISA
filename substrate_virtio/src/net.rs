pub const VIRTIO_NET_BACKEND_PROVIDER: &str = "substrate_virtio";
pub const VIRTIO_NET_BACKEND_PROFILE: &str = "virtio-net-backend-skeleton-v1";
pub const VIRTIO_NET_BACKEND_MODEL: &str = "virtio-net";

pub const VIRTIO_NET_F_MAC: u64 = 1 << 5;
pub const VIRTIO_NET_F_STATUS: u64 = 1 << 16;
pub const VIRTIO_NET_SKELETON_FEATURES: u64 = VIRTIO_NET_F_MAC | VIRTIO_NET_F_STATUS;
pub const VIRTIO_NET_RX_QUEUE_INDEX: u16 = 0;
pub const VIRTIO_NET_TX_QUEUE_INDEX: u16 = 1;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VirtioNetBackendConfig {
    pub device_features: u64,
    pub driver_features: u64,
    pub negotiated_features: u64,
    pub rx_queue_index: u16,
    pub tx_queue_index: u16,
    pub queue_size: u16,
    pub irq_vector: u16,
}

impl VirtioNetBackendConfig {
    pub const fn net0() -> Self {
        Self {
            device_features: VIRTIO_NET_SKELETON_FEATURES,
            driver_features: VIRTIO_NET_F_MAC,
            negotiated_features: VIRTIO_NET_F_MAC,
            rx_queue_index: VIRTIO_NET_RX_QUEUE_INDEX,
            tx_queue_index: VIRTIO_NET_TX_QUEUE_INDEX,
            queue_size: 4,
            irq_vector: 5,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VirtioNetBackendState {
    SkeletonReady,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VirtioNetBackendEvidence {
    pub provider: &'static str,
    pub profile: &'static str,
    pub model: &'static str,
    pub state: VirtioNetBackendState,
    pub config: VirtioNetBackendConfig,
}

pub struct VirtioNetBackendSkeleton {
    config: VirtioNetBackendConfig,
}

impl VirtioNetBackendSkeleton {
    pub const fn new(config: VirtioNetBackendConfig) -> Self {
        Self { config }
    }

    pub const fn config(&self) -> VirtioNetBackendConfig {
        self.config
    }

    pub fn evidence(&self) -> Result<VirtioNetBackendEvidence, &'static str> {
        validate_config(self.config)?;
        Ok(VirtioNetBackendEvidence {
            provider: VIRTIO_NET_BACKEND_PROVIDER,
            profile: VIRTIO_NET_BACKEND_PROFILE,
            model: VIRTIO_NET_BACKEND_MODEL,
            state: VirtioNetBackendState::SkeletonReady,
            config: self.config,
        })
    }
}

impl Default for VirtioNetBackendSkeleton {
    fn default() -> Self {
        Self::new(VirtioNetBackendConfig::net0())
    }
}

pub fn validate_config(config: VirtioNetBackendConfig) -> Result<(), &'static str> {
    if config.queue_size == 0 {
        return Err("virtio net backend queue size is zero");
    }
    if config.rx_queue_index == config.tx_queue_index {
        return Err("virtio net backend rx and tx queues must be distinct");
    }
    if config.negotiated_features & !config.device_features != 0 {
        return Err("virtio net backend negotiated features exceed device features");
    }
    if config.negotiated_features & !config.driver_features != 0 {
        return Err("virtio net backend negotiated features exceed driver features");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn virtio_net_skeleton_reports_stable_profile_evidence() {
        let backend = VirtioNetBackendSkeleton::default();
        let evidence = backend.evidence().unwrap();
        assert_eq!(evidence.provider, "substrate_virtio");
        assert_eq!(evidence.profile, "virtio-net-backend-skeleton-v1");
        assert_eq!(evidence.model, "virtio-net");
        assert_eq!(evidence.config.rx_queue_index, 0);
        assert_eq!(evidence.config.tx_queue_index, 1);
        assert_eq!(evidence.config.negotiated_features, VIRTIO_NET_F_MAC);
    }

    #[test]
    fn virtio_net_skeleton_rejects_invalid_queue_and_feature_negotiation() {
        let mut config = VirtioNetBackendConfig::net0();
        config.queue_size = 0;
        assert_eq!(
            validate_config(config),
            Err("virtio net backend queue size is zero")
        );

        config = VirtioNetBackendConfig::net0();
        config.tx_queue_index = config.rx_queue_index;
        assert_eq!(
            validate_config(config),
            Err("virtio net backend rx and tx queues must be distinct")
        );

        config = VirtioNetBackendConfig::net0();
        config.negotiated_features = VIRTIO_NET_F_STATUS;
        assert_eq!(
            validate_config(config),
            Err("virtio net backend negotiated features exceed driver features")
        );

        config = VirtioNetBackendConfig::net0();
        config.negotiated_features = 1 << 63;
        assert_eq!(
            validate_config(config),
            Err("virtio net backend negotiated features exceed device features")
        );
    }
}
