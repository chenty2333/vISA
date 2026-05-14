pub const VIRTIO_NET_BACKEND_PROVIDER: &str = "substrate_virtio";
pub const VIRTIO_NET_BACKEND_PROFILE: &str = "virtio-net-backend-skeleton-v1";
pub const VIRTIO_NET_BACKEND_MODEL: &str = "virtio-net";

pub const VIRTIO_NET_F_MAC: u64 = 1 << 5;
pub const VIRTIO_NET_F_STATUS: u64 = 1 << 16;
pub const VIRTIO_NET_SKELETON_FEATURES: u64 = VIRTIO_NET_F_MAC | VIRTIO_NET_F_STATUS;
pub const VIRTIO_NET_RX_QUEUE_INDEX: u16 = 0;
pub const VIRTIO_NET_TX_QUEUE_INDEX: u16 = 1;

#[cfg(all(feature = "host-tap", not(target_os = "linux")))]
compile_error!("substrate_virtio host-tap feature requires Linux /dev/net/tun");

#[cfg(all(feature = "host-tap", target_os = "linux"))]
mod host_tap {
    use std::{
        fs::{File, OpenOptions},
        io::{ErrorKind, Read, Write},
        os::fd::AsRawFd,
    };

    use substrate_api::{PacketDeviceBackend, PacketFrameSlot, SubstrateError, SubstrateResult};

    const IFNAMSIZ: usize = 16;
    const IFREQ_SIZE: usize = 40;
    const TUNSETIFF: libc::c_ulong = 0x4004_54ca;
    const IFF_TAP: i16 = 0x0002;
    const IFF_NO_PI: i16 = 0x1000;
    const DEFAULT_MTU: usize = 1500;
    const MAX_TAP_FRAME_LEN: usize = 1518;

    pub struct HostTapPacketDeviceBackend {
        file: File,
        mtu: usize,
        mac: Option<[u8; 6]>,
    }

    impl HostTapPacketDeviceBackend {
        pub fn open(name: &str) -> SubstrateResult<Self> {
            let mut ifreq = tap_ifreq(name)?;
            let file = OpenOptions::new()
                .read(true)
                .write(true)
                .open("/dev/net/tun")
                .map_err(|_| tap_fault("open /dev/net/tun"))?;
            let fd = file.as_raw_fd();
            let rc = unsafe { libc::ioctl(fd, TUNSETIFF, ifreq.as_mut_ptr()) };
            if rc < 0 {
                return Err(tap_fault("ioctl TUNSETIFF"));
            }
            set_nonblocking(fd)?;
            Ok(Self { file, mtu: DEFAULT_MTU, mac: None })
        }

        pub fn configured_mac(&self) -> Option<[u8; 6]> {
            self.mac
        }
    }

    impl PacketDeviceBackend for HostTapPacketDeviceBackend {
        fn init(&mut self, mac: [u8; 6]) -> SubstrateResult<()> {
            self.mac = Some(mac);
            Ok(())
        }

        fn submit_tx(&mut self, frame: &[u8]) -> SubstrateResult<()> {
            validate_tap_frame_len(frame.len())?;
            self.file.write_all(frame).map_err(|_| tap_fault("write tap frame"))
        }

        fn poll_rx(&mut self, out: &mut [PacketFrameSlot]) -> SubstrateResult<usize> {
            let mut count = 0usize;
            for slot in out {
                match self.file.read(&mut slot.data) {
                    Ok(0) => break,
                    Ok(len) => {
                        slot.len =
                            u16::try_from(len).map_err(|_| SubstrateError::ContractViolation {
                                detail: "tap frame slot length overflow",
                            })?;
                        count += 1;
                    }
                    Err(err) if err.kind() == ErrorKind::WouldBlock => break,
                    Err(_) => return Err(tap_fault("read tap frame")),
                }
            }
            Ok(count)
        }

        fn mtu(&self) -> usize {
            self.mtu
        }
    }

    fn tap_ifreq(name: &str) -> SubstrateResult<[u8; IFREQ_SIZE]> {
        let bytes = name.as_bytes();
        if bytes.is_empty() || bytes.len() >= IFNAMSIZ || bytes.contains(&0) {
            return Err(SubstrateError::ContractViolation { detail: "invalid tap interface name" });
        }

        let mut ifreq = [0u8; IFREQ_SIZE];
        ifreq[..bytes.len()].copy_from_slice(bytes);
        let flags = (IFF_TAP | IFF_NO_PI).to_ne_bytes();
        ifreq[IFNAMSIZ..IFNAMSIZ + flags.len()].copy_from_slice(&flags);
        Ok(ifreq)
    }

    fn validate_tap_frame_len(len: usize) -> SubstrateResult<()> {
        if len > MAX_TAP_FRAME_LEN {
            return Err(SubstrateError::ContractViolation {
                detail: "tap ethernet frame exceeds supported length",
            });
        }
        Ok(())
    }

    fn set_nonblocking(fd: libc::c_int) -> SubstrateResult<()> {
        let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
        if flags < 0 {
            return Err(tap_fault("fcntl F_GETFL"));
        }
        let rc = unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) };
        if rc < 0 {
            return Err(tap_fault("fcntl F_SETFL O_NONBLOCK"));
        }
        Ok(())
    }

    fn tap_fault(detail: &'static str) -> SubstrateError {
        SubstrateError::HardwareFault { authority: "HostTapPacketDeviceBackend", detail }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn tap_ifreq_rejects_names_the_kernel_cannot_represent() {
            assert!(tap_ifreq("").is_err());
            assert!(tap_ifreq("0123456789abcdef").is_err());
            assert!(tap_ifreq("bad\0tap").is_err());
        }

        #[test]
        fn tap_ifreq_encodes_tap_no_pi_flags() {
            let ifreq = tap_ifreq("vmos0").unwrap();
            assert_eq!(&ifreq[..5], b"vmos0");
            let flags = i16::from_ne_bytes([ifreq[IFNAMSIZ], ifreq[IFNAMSIZ + 1]]);
            assert_eq!(flags, IFF_TAP | IFF_NO_PI);
        }

        #[test]
        fn tap_tx_limit_allows_full_ethernet_frames_not_just_ip_mtu() {
            assert!(validate_tap_frame_len(DEFAULT_MTU).is_ok());
            assert!(validate_tap_frame_len(DEFAULT_MTU + 14).is_ok());
            assert!(validate_tap_frame_len(MAX_TAP_FRAME_LEN).is_ok());
            assert!(validate_tap_frame_len(MAX_TAP_FRAME_LEN + 1).is_err());
        }
    }
}

#[cfg(all(feature = "host-tap", target_os = "linux"))]
pub use host_tap::HostTapPacketDeviceBackend;

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
    if !config.queue_size.is_power_of_two() {
        return Err("virtio net backend queue size is not a power of two");
    }
    if config.irq_vector == 0 {
        return Err("virtio net backend irq vector is zero");
    }
    if config.rx_queue_index == config.tx_queue_index {
        return Err("virtio net backend rx and tx queues must be distinct");
    }
    if config.rx_queue_index != VIRTIO_NET_RX_QUEUE_INDEX
        || config.tx_queue_index != VIRTIO_NET_TX_QUEUE_INDEX
    {
        return Err("virtio net backend queue indices are unsupported");
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
        assert_eq!(validate_config(config), Err("virtio net backend queue size is zero"));

        config = VirtioNetBackendConfig::net0();
        config.queue_size = 3;
        assert_eq!(
            validate_config(config),
            Err("virtio net backend queue size is not a power of two")
        );

        config = VirtioNetBackendConfig::net0();
        config.irq_vector = 0;
        assert_eq!(validate_config(config), Err("virtio net backend irq vector is zero"));

        config = VirtioNetBackendConfig::net0();
        config.tx_queue_index = config.rx_queue_index;
        assert_eq!(
            validate_config(config),
            Err("virtio net backend rx and tx queues must be distinct")
        );

        config = VirtioNetBackendConfig::net0();
        config.rx_queue_index = 2;
        config.tx_queue_index = 3;
        assert_eq!(
            validate_config(config),
            Err("virtio net backend queue indices are unsupported")
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
