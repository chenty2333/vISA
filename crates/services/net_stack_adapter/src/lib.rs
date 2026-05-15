#![no_std]

extern crate alloc;

#[cfg(test)]
extern crate std;

use alloc::{vec, vec::Vec};

use service_core::net_contract::{
    PacketDeviceContract, VIRTIO_NET0_CONTRACT, validate_packet_device_contract,
};
use smoltcp::{
    iface::{Config, Interface, PollResult, SocketHandle, SocketSet},
    phy::{Device, DeviceCapabilities, Loopback, Medium, RxToken, TxToken},
    socket::tcp,
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
pub const DEFAULT_TCP_BUFFER_LEN: usize = 4096;
pub const DEFAULT_EPHEMERAL_PORT_BASE: u16 = 49152;

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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TcpSocketSnapshot {
    pub socket_id: u32,
    pub state: &'static str,
    pub can_send: bool,
    pub can_recv: bool,
    pub may_send: bool,
    pub may_recv: bool,
    pub local_port: u16,
    pub remote_port: u16,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct TcpSocketMapping {
    socket_id: u32,
    handle: SocketHandle,
}

pub struct SmoltcpPacketStack {
    iface: Interface,
    sockets: SocketSet<'static>,
    device: PacketQueueDevice,
    tcp_sockets: Vec<TcpSocketMapping>,
    next_tcp_socket_id: u32,
    next_ephemeral_port: u16,
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

        Ok(Self {
            iface,
            sockets: SocketSet::new(Vec::new()),
            device,
            tcp_sockets: Vec::new(),
            next_tcp_socket_id: 1,
            next_ephemeral_port: DEFAULT_EPHEMERAL_PORT_BASE,
        })
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

    pub fn create_tcp_socket(&mut self) -> Result<u32, &'static str> {
        let socket_id = self.next_tcp_socket_id;
        let next_socket_id =
            self.next_tcp_socket_id.checked_add(1).ok_or("smoltcp tcp socket id exhausted")?;
        let rx_buffer = tcp::SocketBuffer::new(vec![0; DEFAULT_TCP_BUFFER_LEN]);
        let tx_buffer = tcp::SocketBuffer::new(vec![0; DEFAULT_TCP_BUFFER_LEN]);
        let socket = tcp::Socket::new(rx_buffer, tx_buffer);
        let handle = self.sockets.add(socket);
        self.next_tcp_socket_id = next_socket_id;
        self.tcp_sockets.push(TcpSocketMapping { socket_id, handle });
        Ok(socket_id)
    }

    pub fn close_tcp_socket(&mut self, socket_id: u32) -> Result<(), &'static str> {
        let index = self.tcp_socket_index(socket_id)?;
        let handle = self.tcp_sockets.remove(index).handle;
        let _ = self.sockets.remove(handle);
        Ok(())
    }

    pub fn listen_tcp(&mut self, socket_id: u32, local_port: u16) -> Result<(), &'static str> {
        let handle = self.tcp_socket_handle(socket_id)?;
        self.sockets
            .get_mut::<tcp::Socket>(handle)
            .listen(local_port)
            .map_err(|_| "smoltcp tcp listen failed")
    }

    pub fn connect_tcp_ipv4(
        &mut self,
        socket_id: u32,
        remote_addr: [u8; 4],
        remote_port: u16,
    ) -> Result<u16, &'static str> {
        if remote_port == 0 {
            return Err("smoltcp tcp remote port is zero");
        }
        let handle = self.tcp_socket_handle(socket_id)?;
        let local_port = self.allocate_ephemeral_port()?;
        let remote_addr = IpAddress::Ipv4(Ipv4Address::new(
            remote_addr[0],
            remote_addr[1],
            remote_addr[2],
            remote_addr[3],
        ));
        self.sockets
            .get_mut::<tcp::Socket>(handle)
            .connect(self.iface.context(), (remote_addr, remote_port), local_port)
            .map_err(|_| "smoltcp tcp connect failed")?;
        Ok(local_port)
    }

    pub fn send_tcp(&mut self, socket_id: u32, bytes: &[u8]) -> Result<usize, &'static str> {
        let handle = self.tcp_socket_handle(socket_id)?;
        self.sockets
            .get_mut::<tcp::Socket>(handle)
            .send_slice(bytes)
            .map_err(|_| "smoltcp tcp send failed")
    }

    pub fn recv_tcp(&mut self, socket_id: u32, out: &mut [u8]) -> Result<usize, &'static str> {
        let handle = self.tcp_socket_handle(socket_id)?;
        self.sockets
            .get_mut::<tcp::Socket>(handle)
            .recv_slice(out)
            .map_err(|_| "smoltcp tcp recv failed")
    }

    pub fn tcp_snapshot(&self, socket_id: u32) -> Result<TcpSocketSnapshot, &'static str> {
        let handle = self.tcp_socket_handle(socket_id)?;
        let socket = self.sockets.get::<tcp::Socket>(handle);
        let local_port = socket
            .local_endpoint()
            .map(|endpoint| endpoint.port)
            .unwrap_or_else(|| socket.listen_endpoint().port);
        let remote_port = socket.remote_endpoint().map(|endpoint| endpoint.port).unwrap_or(0);
        Ok(TcpSocketSnapshot {
            socket_id,
            state: tcp_state_name(socket.state()),
            can_send: socket.can_send(),
            can_recv: socket.can_recv(),
            may_send: socket.may_send(),
            may_recv: socket.may_recv(),
            local_port,
            remote_port,
        })
    }

    fn tcp_socket_index(&self, socket_id: u32) -> Result<usize, &'static str> {
        self.tcp_sockets
            .iter()
            .position(|mapping| mapping.socket_id == socket_id)
            .ok_or("smoltcp tcp socket not found")
    }

    fn tcp_socket_handle(&self, socket_id: u32) -> Result<SocketHandle, &'static str> {
        Ok(self.tcp_sockets[self.tcp_socket_index(socket_id)?].handle)
    }

    fn allocate_ephemeral_port(&mut self) -> Result<u16, &'static str> {
        let port = self.next_ephemeral_port;
        self.next_ephemeral_port =
            self.next_ephemeral_port.checked_add(1).ok_or("smoltcp ephemeral port exhausted")?;
        Ok(port)
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

const fn tcp_state_name(state: tcp::State) -> &'static str {
    match state {
        tcp::State::Closed => "closed",
        tcp::State::Listen => "listen",
        tcp::State::SynSent => "syn-sent",
        tcp::State::SynReceived => "syn-received",
        tcp::State::Established => "established",
        tcp::State::FinWait1 => "fin-wait-1",
        tcp::State::FinWait2 => "fin-wait-2",
        tcp::State::CloseWait => "close-wait",
        tcp::State::Closing => "closing",
        tcp::State::LastAck => "last-ack",
        tcp::State::TimeWait => "time-wait",
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
    fn tcp_connect_resolves_arp_and_emits_syn_frame() {
        let mut stack =
            SmoltcpPacketStack::new(SmoltcpAdapterConfig::default_vmos()).expect("packet stack");
        let socket = stack.create_tcp_socket().expect("tcp socket");
        let remote_mac = [0x02, 0, 0, 0, 0, 2];
        let remote_ip = [10, 0, 2, 2];

        let local_port = stack.connect_tcp_ipv4(socket, remote_ip, 80).expect("connect tcp");
        assert_eq!(local_port, DEFAULT_EPHEMERAL_PORT_BASE);
        let snapshot = stack.tcp_snapshot(socket).expect("tcp snapshot");
        assert_eq!(snapshot.state, "syn-sent");
        assert_eq!(snapshot.local_port, DEFAULT_EPHEMERAL_PORT_BASE);
        assert_eq!(snapshot.remote_port, 80);

        let arp_poll = stack.poll(1);
        assert_eq!(arp_poll.tx_frames_after, 1);
        let arp = stack.take_tx_frame().expect("arp request");
        assert_eq!(&arp[0..6], &[0xff; 6]);
        assert_eq!(&arp[6..12], &VIRTIO_NET0_CONTRACT.mac);
        assert_eq!(&arp[12..14], &[0x08, 0x06]);
        assert_eq!(&arp[20..22], &[0x00, 0x01]);
        assert_eq!(&arp[38..42], &remote_ip);

        let reply = arp_reply(remote_mac, remote_ip, VIRTIO_NET0_CONTRACT.mac, DEFAULT_IPV4_ADDR);
        stack.enqueue_rx_frame(&reply).expect("enqueue arp reply");
        let syn_poll = stack.poll(2);
        assert_eq!(syn_poll.rx_frames_after, 0);
        assert_eq!(syn_poll.tx_frames_after, 1);

        let syn = stack.take_tx_frame().expect("tcp syn");
        assert_eq!(&syn[0..6], &remote_mac);
        assert_eq!(&syn[6..12], &VIRTIO_NET0_CONTRACT.mac);
        assert_eq!(&syn[12..14], &[0x08, 0x00]);
        assert_eq!(&syn[26..30], &DEFAULT_IPV4_ADDR);
        assert_eq!(&syn[30..34], &remote_ip);
        assert_eq!(syn[23], 0x06);
        assert_eq!(u16::from_be_bytes([syn[34], syn[35]]), local_port);
        assert_eq!(u16::from_be_bytes([syn[36], syn[37]]), 80);
        assert_eq!(syn[47] & 0x02, 0x02);
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

    fn arp_reply(
        sender_mac: [u8; 6],
        sender_ip: [u8; 4],
        target_mac: [u8; 6],
        target_ip: [u8; 4],
    ) -> [u8; 42] {
        let mut frame = [0u8; 42];
        frame[0..6].copy_from_slice(&target_mac);
        frame[6..12].copy_from_slice(&sender_mac);
        frame[12..14].copy_from_slice(&[0x08, 0x06]);
        frame[14..16].copy_from_slice(&[0x00, 0x01]);
        frame[16..18].copy_from_slice(&[0x08, 0x00]);
        frame[18] = 6;
        frame[19] = 4;
        frame[20..22].copy_from_slice(&[0x00, 0x02]);
        frame[22..28].copy_from_slice(&sender_mac);
        frame[28..32].copy_from_slice(&sender_ip);
        frame[32..38].copy_from_slice(&target_mac);
        frame[38..42].copy_from_slice(&target_ip);
        frame
    }
}
