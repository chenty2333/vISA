#![no_std]

extern crate alloc;

#[cfg(test)]
extern crate std;

use alloc::{vec, vec::Vec};

use service_core::net_contract::{
    PacketDeviceContract, VIRTIO_NET0_CONTRACT, validate_packet_device_contract,
};
use smoltcp::{
    iface::{Config, Interface, PollResult, SocketSet},
    phy::{Device, DeviceCapabilities, Loopback, Medium, RxToken, TxToken},
    time::Instant,
    wire::{EthernetAddress, HardwareAddress, IpAddress, IpCidr, Ipv4Address, Ipv4Cidr},
};

pub const SMOLTCP_ADAPTER_IMPLEMENTATION: &str = "smoltcp";
pub const SMOLTCP_ADAPTER_VERSION: &str = "0.13.0";
pub const SMOLTCP_ADAPTER_PROFILE: &str = "smoltcp-0.13.0-ethernet-ipv4-tcp-v1";
pub const SMOLTCP_ADAPTER_MEDIUM: &str = "ethernet";
pub const DEFAULT_IPV4_ADDR: [u8; 4] = [10, 0, 2, 15];
pub const DEFAULT_IPV4_PREFIX_LEN: u8 = 24;
pub const DEFAULT_SOCKET_CAPACITY: u16 = 0;
pub const ETHERNET_HEADER_LEN: usize = 14;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SmoltcpAdapterConfig {
    pub contract: PacketDeviceContract,
    pub ipv4_addr: [u8; 4],
    pub ipv4_prefix_len: u8,
    pub random_seed: u64,
    pub socket_capacity: u16,
}

impl SmoltcpAdapterConfig {
    pub const fn default_vmos() -> Self {
        Self {
            contract: VIRTIO_NET0_CONTRACT,
            ipv4_addr: DEFAULT_IPV4_ADDR,
            ipv4_prefix_len: DEFAULT_IPV4_PREFIX_LEN,
            random_seed: 0x766d_6f73_6e65_7430,
            socket_capacity: DEFAULT_SOCKET_CAPACITY,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SmoltcpAdapterEvidence {
    pub implementation: &'static str,
    pub version: &'static str,
    pub profile: &'static str,
    pub medium: &'static str,
    pub hardware_addr: [u8; 6],
    pub ipv4_addr: [u8; 4],
    pub ipv4_prefix_len: u8,
    pub mtu: u32,
    pub rx_queue_depth: u32,
    pub tx_queue_depth: u32,
    pub max_payload_len: u32,
    pub socket_capacity: u16,
    pub poll_result: &'static str,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SmoltcpPollEvidence {
    pub poll_result: &'static str,
    pub rx_frames_before: usize,
    pub rx_frames_after: usize,
    pub tx_frames_before: usize,
    pub tx_frames_after: usize,
}

pub struct SmoltcpPacketStack {
    iface: Interface,
    sockets: SocketSet<'static>,
    device: PacketQueueDevice,
}

impl SmoltcpPacketStack {
    pub fn new(config: SmoltcpAdapterConfig) -> Result<Self, &'static str> {
        validate_adapter_config(config)?;

        let mut device = PacketQueueDevice::new(
            config.contract.mtu as usize + ETHERNET_HEADER_LEN,
            config.contract.rx_queue_depth as usize,
            config.contract.tx_queue_depth as usize,
        );
        let mut iface_config =
            Config::new(HardwareAddress::Ethernet(EthernetAddress(config.contract.mac)));
        iface_config.random_seed = config.random_seed;
        let mut iface = Interface::new(iface_config, &mut device, Instant::from_millis(0));
        install_ipv4_addr(&mut iface, config.ipv4_addr, config.ipv4_prefix_len)?;

        Ok(Self { iface, sockets: SocketSet::new(Vec::new()), device })
    }

    pub fn enqueue_rx_frame(&mut self, frame: &[u8]) -> Result<(), &'static str> {
        self.device.enqueue_rx_frame(frame)
    }

    pub fn take_tx_frame(&mut self) -> Option<Vec<u8>> {
        self.device.take_tx_frame()
    }

    pub fn pending_rx_frames(&self) -> usize {
        self.device.pending_rx_frames()
    }

    pub fn pending_tx_frames(&self) -> usize {
        self.device.pending_tx_frames()
    }

    pub fn poll(&mut self, now_ms: i64) -> SmoltcpPollEvidence {
        let rx_frames_before = self.device.pending_rx_frames();
        let tx_frames_before = self.device.pending_tx_frames();
        let poll_result =
            self.iface.poll(Instant::from_millis(now_ms), &mut self.device, &mut self.sockets);
        SmoltcpPollEvidence {
            poll_result: poll_result_name(poll_result),
            rx_frames_before,
            rx_frames_after: self.device.pending_rx_frames(),
            tx_frames_before,
            tx_frames_after: self.device.pending_tx_frames(),
        }
    }
}

pub fn build_smoltcp_adapter_evidence(
    config: SmoltcpAdapterConfig,
) -> Result<SmoltcpAdapterEvidence, &'static str> {
    validate_adapter_config(config)?;

    let mut device = Loopback::new(Medium::Ethernet);
    let mut iface_config =
        Config::new(HardwareAddress::Ethernet(EthernetAddress(config.contract.mac)));
    iface_config.random_seed = config.random_seed;
    let mut iface = Interface::new(iface_config, &mut device, Instant::from_millis(0));
    install_ipv4_addr(&mut iface, config.ipv4_addr, config.ipv4_prefix_len)?;

    let mut sockets = SocketSet::new(Vec::new());
    let poll_result = iface.poll(Instant::from_millis(0), &mut device, &mut sockets);

    Ok(SmoltcpAdapterEvidence {
        implementation: SMOLTCP_ADAPTER_IMPLEMENTATION,
        version: SMOLTCP_ADAPTER_VERSION,
        profile: SMOLTCP_ADAPTER_PROFILE,
        medium: SMOLTCP_ADAPTER_MEDIUM,
        hardware_addr: config.contract.mac,
        ipv4_addr: config.ipv4_addr,
        ipv4_prefix_len: config.ipv4_prefix_len,
        mtu: config.contract.mtu,
        rx_queue_depth: config.contract.rx_queue_depth,
        tx_queue_depth: config.contract.tx_queue_depth,
        max_payload_len: config.contract.max_payload_len,
        socket_capacity: config.socket_capacity,
        poll_result: poll_result_name(poll_result),
    })
}

pub struct PacketQueueDevice {
    rx_queue: Vec<Vec<u8>>,
    tx_queue: Vec<Vec<u8>>,
    max_frame_len: usize,
    rx_queue_depth: usize,
    tx_queue_depth: usize,
}

impl PacketQueueDevice {
    pub fn new(max_frame_len: usize, rx_queue_depth: usize, tx_queue_depth: usize) -> Self {
        Self {
            rx_queue: Vec::new(),
            tx_queue: Vec::new(),
            max_frame_len,
            rx_queue_depth,
            tx_queue_depth,
        }
    }

    pub fn enqueue_rx_frame(&mut self, frame: &[u8]) -> Result<(), &'static str> {
        if frame.len() > self.max_frame_len {
            return Err("packet queue rx frame exceeds device max frame length");
        }
        if self.rx_queue.len() >= self.rx_queue_depth {
            return Err("packet queue rx queue is full");
        }
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
}

impl Device for PacketQueueDevice {
    type RxToken<'a>
        = QueueRxToken
    where
        Self: 'a;
    type TxToken<'a>
        = QueueTxToken<'a>
    where
        Self: 'a;

    fn receive(&mut self, _timestamp: Instant) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        if self.rx_queue.is_empty() {
            return None;
        }
        let frame = self.rx_queue.remove(0);
        Some((
            QueueRxToken { frame },
            QueueTxToken {
                tx_queue: &mut self.tx_queue,
                max_frame_len: self.max_frame_len,
                tx_queue_depth: self.tx_queue_depth,
            },
        ))
    }

    fn transmit(&mut self, _timestamp: Instant) -> Option<Self::TxToken<'_>> {
        Some(QueueTxToken {
            tx_queue: &mut self.tx_queue,
            max_frame_len: self.max_frame_len,
            tx_queue_depth: self.tx_queue_depth,
        })
    }

    fn capabilities(&self) -> DeviceCapabilities {
        let mut capabilities = DeviceCapabilities::default();
        capabilities.medium = Medium::Ethernet;
        capabilities.max_transmission_unit = self.max_frame_len;
        capabilities.max_burst_size = Some(self.rx_queue_depth.max(self.tx_queue_depth));
        capabilities
    }
}

pub struct QueueRxToken {
    frame: Vec<u8>,
}

impl RxToken for QueueRxToken {
    fn consume<R, F>(self, f: F) -> R
    where
        F: FnOnce(&[u8]) -> R,
    {
        f(&self.frame)
    }
}

pub struct QueueTxToken<'a> {
    tx_queue: &'a mut Vec<Vec<u8>>,
    max_frame_len: usize,
    tx_queue_depth: usize,
}

impl TxToken for QueueTxToken<'_> {
    fn consume<R, F>(self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        if len > self.max_frame_len || self.tx_queue.len() >= self.tx_queue_depth {
            let mut frame = Vec::new();
            return f(&mut frame);
        }
        let mut frame = vec![0; len];
        let result = f(&mut frame);
        self.tx_queue.push(frame);
        result
    }
}

fn validate_adapter_config(config: SmoltcpAdapterConfig) -> Result<(), &'static str> {
    if !validate_packet_device_contract(config.contract) {
        return Err("smoltcp adapter packet device contract mismatch");
    }
    if config.ipv4_prefix_len == 0 || config.ipv4_prefix_len > 32 {
        return Err("smoltcp adapter ipv4 prefix is invalid");
    }
    Ok(())
}

fn install_ipv4_addr(
    iface: &mut Interface,
    ipv4_addr: [u8; 4],
    ipv4_prefix_len: u8,
) -> Result<(), &'static str> {
    let ipv4_addr = Ipv4Address::new(ipv4_addr[0], ipv4_addr[1], ipv4_addr[2], ipv4_addr[3]);
    let mut installed_addr = false;
    iface.update_ip_addrs(|addrs| {
        let cidr = IpCidr::Ipv4(Ipv4Cidr::new(ipv4_addr, ipv4_prefix_len));
        installed_addr = addrs.push(cidr).is_ok();
    });
    if !installed_addr {
        return Err("smoltcp adapter failed to install ipv4 cidr");
    }
    if !iface.has_ip_addr(IpAddress::Ipv4(ipv4_addr)) {
        return Err("smoltcp adapter failed to install ipv4 address");
    }
    Ok(())
}

const fn poll_result_name(result: PollResult) -> &'static str {
    match result {
        PollResult::None => "none",
        PollResult::SocketStateChanged => "socket-state-changed",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn smoltcp_adapter_builds_ethernet_ipv4_tcp_profile() {
        let evidence = build_smoltcp_adapter_evidence(SmoltcpAdapterConfig::default_vmos())
            .expect("smoltcp adapter evidence");

        assert_eq!(evidence.implementation, "smoltcp");
        assert_eq!(evidence.version, "0.13.0");
        assert_eq!(evidence.profile, SMOLTCP_ADAPTER_PROFILE);
        assert_eq!(evidence.medium, "ethernet");
        assert_eq!(evidence.hardware_addr, VIRTIO_NET0_CONTRACT.mac);
        assert_eq!(evidence.ipv4_addr, DEFAULT_IPV4_ADDR);
        assert_eq!(evidence.ipv4_prefix_len, DEFAULT_IPV4_PREFIX_LEN);
        assert_eq!(evidence.mtu, VIRTIO_NET0_CONTRACT.mtu);
        assert_eq!(evidence.socket_capacity, 0);
        assert_eq!(evidence.poll_result, "none");
    }

    #[test]
    fn smoltcp_adapter_rejects_contract_and_prefix_mismatch() {
        let mut config = SmoltcpAdapterConfig::default_vmos();
        config.contract.mtu += 1;
        assert_eq!(
            build_smoltcp_adapter_evidence(config),
            Err("smoltcp adapter packet device contract mismatch")
        );

        let mut config = SmoltcpAdapterConfig::default_vmos();
        config.ipv4_prefix_len = 0;
        assert_eq!(
            build_smoltcp_adapter_evidence(config),
            Err("smoltcp adapter ipv4 prefix is invalid")
        );
    }

    #[test]
    fn packet_stack_pumps_arp_request_through_smoltcp_device() {
        let mut stack =
            SmoltcpPacketStack::new(SmoltcpAdapterConfig::default_vmos()).expect("packet stack");
        let remote_mac = [0x02, 0, 0, 0, 0, 2];
        let request =
            arp_request(remote_mac, [10, 0, 2, 2], VIRTIO_NET0_CONTRACT.mac, DEFAULT_IPV4_ADDR);

        stack.enqueue_rx_frame(&request).expect("enqueue arp request");
        let poll = stack.poll(1);
        assert_eq!(poll.rx_frames_before, 1);
        assert_eq!(poll.rx_frames_after, 0);
        assert_eq!(poll.tx_frames_after, 1);

        let reply = stack.take_tx_frame().expect("smoltcp generated arp reply");
        assert_eq!(&reply[0..6], &remote_mac);
        assert_eq!(&reply[6..12], &VIRTIO_NET0_CONTRACT.mac);
        assert_eq!(&reply[12..14], &[0x08, 0x06]);
        assert_eq!(&reply[20..22], &[0x00, 0x02]);
        assert_eq!(&reply[22..28], &VIRTIO_NET0_CONTRACT.mac);
        assert_eq!(&reply[28..32], &DEFAULT_IPV4_ADDR);
    }

    #[test]
    fn packet_queue_device_drops_oversized_or_overflow_tx_without_allocating_frame() {
        let mut device = PacketQueueDevice::new(4, 1, 1);
        let token = device.transmit(Instant::from_millis(0)).expect("tx token");
        token.consume(8, |frame| assert!(frame.is_empty()));
        assert_eq!(device.pending_tx_frames(), 0);

        let token = device.transmit(Instant::from_millis(0)).expect("tx token");
        token.consume(4, |frame| frame.copy_from_slice(b"ping"));
        assert_eq!(device.pending_tx_frames(), 1);
        let token = device.transmit(Instant::from_millis(0)).expect("tx token");
        token.consume(4, |frame| assert!(frame.is_empty()));
        assert_eq!(device.pending_tx_frames(), 1);
    }

    fn arp_request(
        sender_mac: [u8; 6],
        sender_ip: [u8; 4],
        target_mac: [u8; 6],
        target_ip: [u8; 4],
    ) -> [u8; 42] {
        let mut frame = [0u8; 42];
        frame[0..6].copy_from_slice(&[0xff; 6]);
        frame[6..12].copy_from_slice(&sender_mac);
        frame[12..14].copy_from_slice(&[0x08, 0x06]);
        frame[14..16].copy_from_slice(&[0x00, 0x01]);
        frame[16..18].copy_from_slice(&[0x08, 0x00]);
        frame[18] = 6;
        frame[19] = 4;
        frame[20..22].copy_from_slice(&[0x00, 0x01]);
        frame[22..28].copy_from_slice(&sender_mac);
        frame[28..32].copy_from_slice(&sender_ip);
        frame[32..38].copy_from_slice(&target_mac);
        frame[38..42].copy_from_slice(&target_ip);
        frame
    }
}
