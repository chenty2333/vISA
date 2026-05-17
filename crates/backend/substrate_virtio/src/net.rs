use alloc::vec::Vec;

use substrate_api::{PacketDeviceBackend, PacketFrameSlot, SubstrateError, SubstrateResult};

pub const VIRTIO_NET_BACKEND_PROVIDER: &str = "substrate_virtio";
pub const VIRTIO_NET_BACKEND_PROFILE: &str = "virtio-net-backend-skeleton-v1";
pub const VIRTIO_NET_QUEUE_BACKEND_PROFILE: &str = "virtio-net-in-memory-queue-v1";
pub const VIRTIO_NET_BACKEND_MODEL: &str = "virtio-net";

pub const VIRTIO_NET_F_MAC: u64 = 1 << 5;
pub const VIRTIO_NET_F_STATUS: u64 = 1 << 16;
pub const VIRTIO_NET_SKELETON_FEATURES: u64 = VIRTIO_NET_F_MAC | VIRTIO_NET_F_STATUS;
pub const VIRTIO_NET_RX_QUEUE_INDEX: u16 = 0;
pub const VIRTIO_NET_TX_QUEUE_INDEX: u16 = 1;
const ETHERNET_HEADER_LEN: usize = 14;
const VLAN_HEADER_LEN: usize = 4;
const DEFAULT_MTU: usize = 1500;
const MAX_ETHERNET_FRAME_LEN: usize = DEFAULT_MTU + ETHERNET_HEADER_LEN + VLAN_HEADER_LEN;

#[cfg(all(feature = "host-tap", not(target_os = "linux")))]
compile_error!("substrate_virtio host-tap feature requires Linux /dev/net/tun");

#[cfg(all(feature = "host-tap", target_os = "linux"))]
mod host_tap {
    use std::{
        fs::{File, OpenOptions},
        io::{ErrorKind, Read, Write},
        os::fd::AsRawFd,
        string::String,
    };

    use substrate_api::{PacketDeviceBackend, PacketFrameSlot, SubstrateError, SubstrateResult};

    const IFNAMSIZ: usize = 16;
    const IFREQ_SIZE: usize = 40;
    const TUNSETIFF: libc::c_ulong = 0x4004_54ca;
    const SIOCGIFFLAGS: libc::c_ulong = 0x8913;
    const SIOCSIFFLAGS: libc::c_ulong = 0x8914;
    const SIOCSIFMTU: libc::c_ulong = 0x8922;
    const SIOCSIFHWADDR: libc::c_ulong = 0x8924;
    const NETDEV_IFF_UP: i16 = 0x0001;
    const IFF_TAP: i16 = 0x0002;
    const IFF_NO_PI: i16 = 0x1000;
    const ARPHRD_ETHER: u16 = 1;
    const DEFAULT_MTU: usize = 1500;
    const MAX_TAP_FRAME_LEN: usize = 1518;

    pub struct HostTapPacketDeviceBackend {
        name: String,
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
            let actual_name = tap_ifreq_name(&ifreq)?;
            set_nonblocking(fd)?;
            Ok(Self { name: actual_name, file, mtu: DEFAULT_MTU, mac: None })
        }

        pub fn configured_mac(&self) -> Option<[u8; 6]> {
            self.mac
        }
    }

    impl PacketDeviceBackend for HostTapPacketDeviceBackend {
        fn init(&mut self, mac: [u8; 6]) -> SubstrateResult<()> {
            set_tap_mac(&self.name, mac)?;
            set_tap_mtu(&self.name, DEFAULT_MTU)?;
            set_tap_up(&self.name)?;
            self.mtu = DEFAULT_MTU;
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
        let mut ifreq = tap_name_ifreq(name)?;
        let flags = (IFF_TAP | IFF_NO_PI).to_ne_bytes();
        ifreq[IFNAMSIZ..IFNAMSIZ + flags.len()].copy_from_slice(&flags);
        Ok(ifreq)
    }

    fn tap_name_ifreq(name: &str) -> SubstrateResult<[u8; IFREQ_SIZE]> {
        let bytes = name.as_bytes();
        if bytes.is_empty() || bytes.len() >= IFNAMSIZ || bytes.contains(&0) {
            return Err(SubstrateError::ContractViolation { detail: "invalid tap interface name" });
        }

        let mut ifreq = [0u8; IFREQ_SIZE];
        write_ifreq_name(&mut ifreq, bytes);
        Ok(ifreq)
    }

    fn tap_hwaddr_ifreq(name: &str, mac: [u8; 6]) -> SubstrateResult<[u8; IFREQ_SIZE]> {
        let mut ifreq = tap_name_ifreq(name)?;
        ifreq[IFNAMSIZ..IFNAMSIZ + 2].copy_from_slice(&ARPHRD_ETHER.to_ne_bytes());
        ifreq[IFNAMSIZ + 2..IFNAMSIZ + 8].copy_from_slice(&mac);
        Ok(ifreq)
    }

    fn tap_mtu_ifreq(name: &str, mtu: usize) -> SubstrateResult<[u8; IFREQ_SIZE]> {
        let mtu = i32::try_from(mtu)
            .map_err(|_| SubstrateError::ContractViolation { detail: "invalid tap mtu" })?;
        let mut ifreq = tap_name_ifreq(name)?;
        ifreq[IFNAMSIZ..IFNAMSIZ + 4].copy_from_slice(&mtu.to_ne_bytes());
        Ok(ifreq)
    }

    fn write_ifreq_name(ifreq: &mut [u8; IFREQ_SIZE], name: &[u8]) {
        ifreq[..name.len()].copy_from_slice(name);
    }

    fn read_ifreq_flags(ifreq: &[u8; IFREQ_SIZE]) -> i16 {
        i16::from_ne_bytes([ifreq[IFNAMSIZ], ifreq[IFNAMSIZ + 1]])
    }

    fn write_ifreq_flags(ifreq: &mut [u8; IFREQ_SIZE], flags: i16) {
        ifreq[IFNAMSIZ..IFNAMSIZ + 2].copy_from_slice(&flags.to_ne_bytes());
    }

    fn tap_ifreq_name(ifreq: &[u8; IFREQ_SIZE]) -> SubstrateResult<String> {
        let len = ifreq[..IFNAMSIZ].iter().position(|byte| *byte == 0).unwrap_or(IFNAMSIZ);
        let name = core::str::from_utf8(&ifreq[..len]).map_err(|_| {
            SubstrateError::ContractViolation { detail: "invalid tap interface name" }
        })?;
        if name.is_empty() {
            return Err(SubstrateError::ContractViolation { detail: "invalid tap interface name" });
        }
        Ok(String::from(name))
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

    fn set_tap_mac(name: &str, mac: [u8; 6]) -> SubstrateResult<()> {
        let mut ifreq = tap_hwaddr_ifreq(name, mac)?;
        with_control_socket(|fd| ioctl_ifreq(fd, SIOCSIFHWADDR, &mut ifreq, "ioctl SIOCSIFHWADDR"))
    }

    fn set_tap_mtu(name: &str, mtu: usize) -> SubstrateResult<()> {
        let mut ifreq = tap_mtu_ifreq(name, mtu)?;
        with_control_socket(|fd| ioctl_ifreq(fd, SIOCSIFMTU, &mut ifreq, "ioctl SIOCSIFMTU"))
    }

    fn set_tap_up(name: &str) -> SubstrateResult<()> {
        let mut ifreq = tap_name_ifreq(name)?;
        with_control_socket(|fd| {
            ioctl_ifreq(fd, SIOCGIFFLAGS, &mut ifreq, "ioctl SIOCGIFFLAGS")?;
            let flags = read_ifreq_flags(&ifreq) | NETDEV_IFF_UP;
            write_ifreq_flags(&mut ifreq, flags);
            ioctl_ifreq(fd, SIOCSIFFLAGS, &mut ifreq, "ioctl SIOCSIFFLAGS")
        })
    }

    fn with_control_socket<T>(
        action: impl FnOnce(libc::c_int) -> SubstrateResult<T>,
    ) -> SubstrateResult<T> {
        let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0) };
        if fd < 0 {
            return Err(tap_fault("socket AF_INET SOCK_DGRAM"));
        }

        let result = action(fd);
        let close_rc = unsafe { libc::close(fd) };
        if result.is_ok() && close_rc < 0 {
            return Err(tap_fault("close tap control socket"));
        }
        result
    }

    fn ioctl_ifreq(
        fd: libc::c_int,
        request: libc::c_ulong,
        ifreq: &mut [u8; IFREQ_SIZE],
        detail: &'static str,
    ) -> SubstrateResult<()> {
        let rc = unsafe { libc::ioctl(fd, request, ifreq.as_mut_ptr()) };
        if rc < 0 {
            return Err(tap_fault(detail));
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
        fn tap_hwaddr_ifreq_encodes_ethernet_mac() {
            let ifreq = tap_hwaddr_ifreq("vmos0", [2, 0, 0, 0, 0, 1]).unwrap();
            assert_eq!(&ifreq[..5], b"vmos0");
            let family = u16::from_ne_bytes([ifreq[IFNAMSIZ], ifreq[IFNAMSIZ + 1]]);
            assert_eq!(family, ARPHRD_ETHER);
            assert_eq!(&ifreq[IFNAMSIZ + 2..IFNAMSIZ + 8], &[2, 0, 0, 0, 0, 1]);
        }

        #[test]
        fn tap_mtu_ifreq_encodes_requested_mtu() {
            let ifreq = tap_mtu_ifreq("vmos0", 1500).unwrap();
            assert_eq!(&ifreq[..5], b"vmos0");
            let mtu = i32::from_ne_bytes([
                ifreq[IFNAMSIZ],
                ifreq[IFNAMSIZ + 1],
                ifreq[IFNAMSIZ + 2],
                ifreq[IFNAMSIZ + 3],
            ]);
            assert_eq!(mtu, 1500);
        }

        #[test]
        fn tap_flags_helpers_preserve_existing_flags_when_marking_up() {
            let mut ifreq = tap_name_ifreq("vmos0").unwrap();
            write_ifreq_flags(&mut ifreq, 0x0040);
            let flags = read_ifreq_flags(&ifreq) | NETDEV_IFF_UP;
            write_ifreq_flags(&mut ifreq, flags);
            assert_eq!(read_ifreq_flags(&ifreq), 0x0041);
        }

        #[test]
        fn tap_ifreq_name_reads_kernel_returned_name() {
            let mut ifreq = [0u8; IFREQ_SIZE];
            ifreq[..5].copy_from_slice(b"tap42");
            assert_eq!(tap_ifreq_name(&ifreq).unwrap(), "tap42");
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

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VirtioNetQueueBackendEvidence {
    pub provider: &'static str,
    pub profile: &'static str,
    pub model: &'static str,
    pub config: VirtioNetBackendConfig,
    pub initialized: bool,
    pub mac: Option<[u8; 6]>,
    pub rx_queue_len: usize,
    pub tx_queue_len: usize,
}

/// Bounded in-memory packet backend for virtio-net queue semantics.
///
/// This models the queue handoff boundary that a real virtio-net transport must
/// provide without claiming host TAP or hardware evidence.
pub struct InMemoryVirtioNetBackend {
    config: VirtioNetBackendConfig,
    initialized: bool,
    mac: Option<[u8; 6]>,
    rx_queue: Vec<Vec<u8>>,
    tx_queue: Vec<Vec<u8>>,
}

impl InMemoryVirtioNetBackend {
    pub const fn new(config: VirtioNetBackendConfig) -> Self {
        Self { config, initialized: false, mac: None, rx_queue: Vec::new(), tx_queue: Vec::new() }
    }

    pub const fn config(&self) -> VirtioNetBackendConfig {
        self.config
    }

    pub fn evidence(&self) -> VirtioNetQueueBackendEvidence {
        VirtioNetQueueBackendEvidence {
            provider: VIRTIO_NET_BACKEND_PROVIDER,
            profile: VIRTIO_NET_QUEUE_BACKEND_PROFILE,
            model: VIRTIO_NET_BACKEND_MODEL,
            config: self.config,
            initialized: self.initialized,
            mac: self.mac,
            rx_queue_len: self.rx_queue.len(),
            tx_queue_len: self.tx_queue.len(),
        }
    }

    pub fn inject_rx_frame(&mut self, frame: &[u8]) -> SubstrateResult<()> {
        self.ensure_initialized()?;
        validate_frame_len(frame.len())?;
        self.ensure_rx_capacity()?;
        self.rx_queue.push(frame.to_vec());
        Ok(())
    }

    pub fn take_tx_frame(&mut self) -> Option<Vec<u8>> {
        if self.tx_queue.is_empty() { None } else { Some(self.tx_queue.remove(0)) }
    }

    pub fn pending_rx_frames(&self) -> usize {
        self.rx_queue.len()
    }

    pub fn pending_tx_frames(&self) -> usize {
        self.tx_queue.len()
    }

    fn queue_capacity(&self) -> usize {
        usize::from(self.config.queue_size)
    }

    fn ensure_initialized(&self) -> SubstrateResult<()> {
        if self.initialized {
            Ok(())
        } else {
            Err(SubstrateError::InvalidObject { object: "virtio-net-backend" })
        }
    }

    fn ensure_rx_capacity(&self) -> SubstrateResult<()> {
        if self.rx_queue.len() < self.queue_capacity() {
            Ok(())
        } else {
            Err(SubstrateError::ContractViolation { detail: "virtio net rx queue is full" })
        }
    }

    fn ensure_tx_capacity(&self) -> SubstrateResult<()> {
        if self.tx_queue.len() < self.queue_capacity() {
            Ok(())
        } else {
            Err(SubstrateError::ContractViolation { detail: "virtio net tx queue is full" })
        }
    }
}

impl Default for InMemoryVirtioNetBackend {
    fn default() -> Self {
        Self::new(VirtioNetBackendConfig::net0())
    }
}

impl PacketDeviceBackend for InMemoryVirtioNetBackend {
    fn init(&mut self, mac: [u8; 6]) -> SubstrateResult<()> {
        validate_config(self.config)
            .map_err(|detail| SubstrateError::ContractViolation { detail })?;
        self.mac = Some(mac);
        self.initialized = true;
        self.rx_queue.clear();
        self.tx_queue.clear();
        Ok(())
    }

    fn submit_tx(&mut self, frame: &[u8]) -> SubstrateResult<()> {
        self.ensure_initialized()?;
        validate_frame_len(frame.len())?;
        self.ensure_tx_capacity()?;
        self.tx_queue.push(frame.to_vec());
        Ok(())
    }

    fn poll_rx(&mut self, out: &mut [PacketFrameSlot]) -> SubstrateResult<usize> {
        self.ensure_initialized()?;
        let count = core::cmp::min(out.len(), self.rx_queue.len());
        for slot in out.iter_mut().take(count) {
            let frame = self.rx_queue.remove(0);
            slot.data[..frame.len()].copy_from_slice(&frame);
            slot.len = u16::try_from(frame.len()).map_err(|_| {
                SubstrateError::ContractViolation { detail: "virtio net rx frame length overflow" }
            })?;
        }
        Ok(count)
    }

    fn mtu(&self) -> usize {
        DEFAULT_MTU
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

fn validate_frame_len(len: usize) -> SubstrateResult<()> {
    if len == 0 {
        return Err(SubstrateError::ContractViolation { detail: "virtio net frame is empty" });
    }
    if len > MAX_ETHERNET_FRAME_LEN {
        return Err(SubstrateError::ContractViolation {
            detail: "virtio net frame exceeds supported ethernet length",
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use substrate_api::{
        PacketDeviceBackend,
        conformance::{ConformanceFixtures, packet_device_tx_poll_smoke},
    };

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

    #[test]
    fn in_memory_virtio_net_backend_passes_packet_device_smoke() {
        let mut backend = InMemoryVirtioNetBackend::default();
        let fixtures = ConformanceFixtures::default();

        packet_device_tx_poll_smoke(&mut backend, &fixtures).unwrap();

        let evidence = backend.evidence();
        assert_eq!(evidence.provider, VIRTIO_NET_BACKEND_PROVIDER);
        assert_eq!(evidence.profile, VIRTIO_NET_QUEUE_BACKEND_PROFILE);
        assert!(evidence.initialized);
        assert_eq!(evidence.mac, Some(fixtures.packet_mac));
        assert_eq!(evidence.tx_queue_len, 1);
    }

    #[test]
    fn in_memory_virtio_net_backend_moves_bounded_tx_and_rx_frames() {
        let mut backend = InMemoryVirtioNetBackend::default();
        let tx = [0x12u8; 64];
        let rx = [0x34u8; 96];

        backend.init([2, 0x56, 0x4d, 0x4f, 0x53, 1]).unwrap();
        backend.submit_tx(&tx).unwrap();
        assert_eq!(backend.pending_tx_frames(), 1);
        assert_eq!(backend.take_tx_frame().unwrap().as_slice(), &tx);
        assert_eq!(backend.pending_tx_frames(), 0);

        backend.inject_rx_frame(&rx).unwrap();
        let mut slots = [PacketFrameSlot::new(), PacketFrameSlot::new()];
        assert_eq!(backend.poll_rx(&mut slots).unwrap(), 1);
        assert_eq!(slots[0].len, rx.len() as u16);
        assert_eq!(&slots[0].data[..rx.len()], &rx);
        assert_eq!(backend.pending_rx_frames(), 0);
    }

    #[test]
    fn in_memory_virtio_net_backend_reinit_clears_old_queue_state() {
        let mut backend = InMemoryVirtioNetBackend::default();
        let frame = [0x66u8; 64];

        backend.init([2, 0x56, 0x4d, 0x4f, 0x53, 1]).unwrap();
        backend.submit_tx(&frame).unwrap();
        backend.inject_rx_frame(&frame).unwrap();
        assert_eq!(backend.pending_tx_frames(), 1);
        assert_eq!(backend.pending_rx_frames(), 1);

        backend.init([2, 0x56, 0x4d, 0x4f, 0x53, 2]).unwrap();
        let evidence = backend.evidence();
        assert_eq!(evidence.mac, Some([2, 0x56, 0x4d, 0x4f, 0x53, 2]));
        assert_eq!(evidence.tx_queue_len, 0);
        assert_eq!(evidence.rx_queue_len, 0);
    }

    #[test]
    fn in_memory_virtio_net_backend_enforces_init_frame_and_queue_contracts() {
        let mut backend = InMemoryVirtioNetBackend::default();
        assert_eq!(
            backend.submit_tx(&[0u8; 64]),
            Err(SubstrateError::InvalidObject { object: "virtio-net-backend" })
        );

        backend.init([2, 0x56, 0x4d, 0x4f, 0x53, 1]).unwrap();
        assert_eq!(
            backend.submit_tx(&[]),
            Err(SubstrateError::ContractViolation { detail: "virtio net frame is empty" })
        );
        assert_eq!(
            backend.submit_tx(&[0u8; MAX_ETHERNET_FRAME_LEN + 1]),
            Err(SubstrateError::ContractViolation {
                detail: "virtio net frame exceeds supported ethernet length"
            })
        );

        let frame = [0x55u8; 64];
        for _ in 0..backend.config().queue_size {
            backend.inject_rx_frame(&frame).unwrap();
        }
        assert_eq!(
            backend.inject_rx_frame(&frame),
            Err(SubstrateError::ContractViolation { detail: "virtio net rx queue is full" })
        );
        assert_eq!(backend.pending_rx_frames(), usize::from(backend.config().queue_size));
    }
}
