#![no_std]

extern crate alloc;

#[cfg(test)]
extern crate std;

use alloc::{vec, vec::Vec};

use service_core::{
    driver::{DriverNetEventKind, DriverVirtioNetState, RAW_RX_QUEUE_DEPTH, RESPONSE_CAPACITY},
    net_contract::{PacketDeviceContract, VIRTIO_NET0_CONTRACT, validate_packet_device_contract},
};
use smoltcp::{
    iface::{Config, Interface, PollResult, SocketHandle, SocketSet},
    phy::{Device, DeviceCapabilities, Loopback, Medium, RxToken, TxToken},
    socket::tcp,
    time::Instant,
    wire::{EthernetAddress, HardwareAddress, IpAddress, IpCidr, Ipv4Address, Ipv4Cidr},
};
use substrate_api::{PacketDeviceBackend, PacketFrameSlot, SubstrateError, SubstrateResult};

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
pub const BACKEND_RX_BATCH: usize = 8;
pub const DRIVER_BACKEND_RX_BATCH: usize = RAW_RX_QUEUE_DEPTH;
pub const DRIVER_RX_EVENT_SEQUENCE_LEN: usize = 5;
pub const STACK_DRIVER_EVENT_LIMIT: usize = DRIVER_BACKEND_RX_BATCH * DRIVER_RX_EVENT_SEQUENCE_LEN;
pub const STACK_DRIVER_BACKEND_PUMP_LIMIT: usize = 64;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SmoltcpAdapterConfig {
    pub contract: PacketDeviceContract,
    pub ipv4_addr: [u8; 4],
    pub ipv4_prefix_len: u8,
    pub random_seed: u64,
    pub socket_capacity: u16,
}

impl SmoltcpAdapterConfig {
    pub const fn default_visa() -> Self {
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

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BackendPumpEvidence {
    pub rx_frames_delivered: usize,
    pub tx_frames_submitted: usize,
    pub poll: SmoltcpPollEvidence,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DriverBackendPumpEvidence {
    pub rx_frames_delivered: usize,
    pub tx_frames_submitted: usize,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StackDriverBackendPumpEvidence {
    pub backend_rx_frames_delivered_to_driver: usize,
    pub driver_rx_frames_delivered_to_stack: usize,
    pub stack_poll: SmoltcpPollEvidence,
    pub stack_tx_frames_submitted_to_driver: usize,
    pub driver_tx_frames_submitted_to_backend: usize,
}

impl StackDriverBackendPumpEvidence {
    pub fn made_progress(&self) -> bool {
        self.backend_rx_frames_delivered_to_driver != 0
            || self.driver_rx_frames_delivered_to_stack != 0
            || self.stack_poll.poll_result != "none"
            || self.stack_poll.rx_frames_before != self.stack_poll.rx_frames_after
            || self.stack_poll.tx_frames_before != self.stack_poll.tx_frames_after
            || self.stack_tx_frames_submitted_to_driver != 0
            || self.driver_tx_frames_submitted_to_backend != 0
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct StackDriverBackendPumpTotals {
    pub steps: usize,
    pub quiesced: bool,
    pub backend_rx_frames_delivered_to_driver: usize,
    pub driver_rx_frames_delivered_to_stack: usize,
    pub stack_tx_frames_submitted_to_driver: usize,
    pub driver_tx_frames_submitted_to_backend: usize,
}

impl StackDriverBackendPumpTotals {
    fn add(&mut self, pump: &StackDriverBackendPumpEvidence) {
        self.steps = self.steps.saturating_add(1);
        self.backend_rx_frames_delivered_to_driver = self
            .backend_rx_frames_delivered_to_driver
            .saturating_add(pump.backend_rx_frames_delivered_to_driver);
        self.driver_rx_frames_delivered_to_stack = self
            .driver_rx_frames_delivered_to_stack
            .saturating_add(pump.driver_rx_frames_delivered_to_stack);
        self.stack_tx_frames_submitted_to_driver = self
            .stack_tx_frames_submitted_to_driver
            .saturating_add(pump.stack_tx_frames_submitted_to_driver);
        self.driver_tx_frames_submitted_to_backend = self
            .driver_tx_frames_submitted_to_backend
            .saturating_add(pump.driver_tx_frames_submitted_to_backend);
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TcpSocketSnapshot {
    pub socket_id: u32,
    pub state: &'static str,
    pub can_send: bool,
    pub can_recv: bool,
    pub may_send: bool,
    pub may_recv: bool,
    pub recv_capacity: usize,
    pub recv_queue: usize,
    pub send_capacity: usize,
    pub send_queue: usize,
    pub local_ipv4: [u8; 4],
    pub local_port: u16,
    pub remote_ipv4: [u8; 4],
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
    contract: PacketDeviceContract,
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
            contract: config.contract,
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

    pub fn init_backend<B: PacketDeviceBackend>(&self, backend: &mut B) -> SubstrateResult<()> {
        backend.init(self.contract.mac)?;
        if backend.mtu() < self.contract.mtu as usize {
            return Err(SubstrateError::ContractViolation {
                detail: "packet backend mtu is smaller than smoltcp contract mtu",
            });
        }
        Ok(())
    }

    pub fn pump_backend<B: PacketDeviceBackend>(
        &mut self,
        backend: &mut B,
        now_ms: i64,
    ) -> SubstrateResult<BackendPumpEvidence> {
        let mut rx_slots: [PacketFrameSlot; BACKEND_RX_BATCH] =
            core::array::from_fn(|_| PacketFrameSlot::new());
        let rx_frames = backend.poll_rx(&mut rx_slots)?;
        if rx_frames > rx_slots.len() {
            return Err(SubstrateError::ContractViolation {
                detail: "packet backend returned more rx frames than provided slots",
            });
        }
        for slot in rx_slots.iter().take(rx_frames) {
            let len = slot.len as usize;
            if len > slot.data.len() {
                return Err(SubstrateError::ContractViolation {
                    detail: "packet backend returned an invalid frame slot length",
                });
            }
            self.enqueue_rx_frame(&slot.data[..len]).map_err(|_| {
                SubstrateError::ContractViolation {
                    detail: "packet backend delivered frame rejected by smoltcp queue",
                }
            })?;
        }

        let poll = self.poll(now_ms);
        let mut tx_frames = 0usize;
        while let Some(frame) = self.take_tx_frame() {
            backend.submit_tx(&frame)?;
            tx_frames += 1;
        }

        Ok(BackendPumpEvidence {
            rx_frames_delivered: rx_frames,
            tx_frames_submitted: tx_frames,
            poll,
        })
    }

    pub fn create_tcp_socket(&mut self) -> Result<u32, &'static str> {
        self.create_tcp_socket_with_buffer_capacity(DEFAULT_TCP_BUFFER_LEN, DEFAULT_TCP_BUFFER_LEN)
    }

    pub fn create_tcp_socket_with_recv_capacity(
        &mut self,
        recv_capacity: usize,
    ) -> Result<u32, &'static str> {
        self.create_tcp_socket_with_buffer_capacity(recv_capacity, DEFAULT_TCP_BUFFER_LEN)
    }

    pub fn create_tcp_socket_with_buffer_capacity(
        &mut self,
        recv_capacity: usize,
        send_capacity: usize,
    ) -> Result<u32, &'static str> {
        let socket_id = self.next_tcp_socket_id;
        let next_socket_id =
            self.next_tcp_socket_id.checked_add(1).ok_or("smoltcp tcp socket id exhausted")?;
        let rx_buffer = tcp::SocketBuffer::new(vec![0; bounded_tcp_buffer_len(recv_capacity)]);
        let tx_buffer = tcp::SocketBuffer::new(vec![0; bounded_tcp_buffer_len(send_capacity)]);
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

    pub fn close_tcp_send(&mut self, socket_id: u32) -> Result<(), &'static str> {
        let handle = self.tcp_socket_handle(socket_id)?;
        self.sockets.get_mut::<tcp::Socket>(handle).close();
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

    pub fn peek_tcp(&mut self, socket_id: u32, out: &mut [u8]) -> Result<usize, &'static str> {
        let handle = self.tcp_socket_handle(socket_id)?;
        self.sockets
            .get_mut::<tcp::Socket>(handle)
            .peek_slice(out)
            .map_err(|_| "smoltcp tcp peek failed")
    }

    pub fn tcp_snapshot(&self, socket_id: u32) -> Result<TcpSocketSnapshot, &'static str> {
        let handle = self.tcp_socket_handle(socket_id)?;
        let socket = self.sockets.get::<tcp::Socket>(handle);
        let local_endpoint = socket.local_endpoint();
        let remote_endpoint = socket.remote_endpoint();
        let listen_endpoint = socket.listen_endpoint();
        let local_ipv4 = local_endpoint
            .map(|endpoint| ipv4_bytes(endpoint.addr))
            .or_else(|| listen_endpoint.addr.map(ipv4_bytes))
            .unwrap_or([0; 4]);
        let local_port =
            local_endpoint.map(|endpoint| endpoint.port).unwrap_or(listen_endpoint.port);
        let remote_ipv4 =
            remote_endpoint.map(|endpoint| ipv4_bytes(endpoint.addr)).unwrap_or([0; 4]);
        let remote_port = remote_endpoint.map(|endpoint| endpoint.port).unwrap_or(0);
        Ok(TcpSocketSnapshot {
            socket_id,
            state: tcp_state_name(socket.state()),
            can_send: socket.can_send(),
            can_recv: socket.can_recv(),
            may_send: socket.may_send(),
            may_recv: socket.may_recv(),
            recv_capacity: socket.recv_capacity(),
            recv_queue: socket.recv_queue(),
            send_capacity: socket.send_capacity(),
            send_queue: socket.send_queue(),
            local_ipv4,
            local_port,
            remote_ipv4,
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

pub fn pump_driver_backend<B: PacketDeviceBackend>(
    driver: &mut DriverVirtioNetState,
    backend: &mut B,
    now_ticks: u64,
) -> SubstrateResult<DriverBackendPumpEvidence> {
    let mut rx_slots: [PacketFrameSlot; DRIVER_BACKEND_RX_BATCH] =
        core::array::from_fn(|_| PacketFrameSlot::new());
    let rx_frames = backend.poll_rx(&mut rx_slots)?;
    if rx_frames > rx_slots.len() {
        return Err(SubstrateError::ContractViolation {
            detail: "packet backend returned more rx frames than provided slots",
        });
    }
    let mut rx_frames_delivered = 0usize;
    for slot in rx_slots.iter().take(rx_frames) {
        let len = slot.len as usize;
        if len > slot.data.len() {
            return Err(SubstrateError::ContractViolation {
                detail: "packet backend returned an invalid frame slot length",
            });
        }
        driver.deliver_rx_frame(now_ticks, &slot.data[..len]).map_err(driver_errno_to_substrate)?;
        rx_frames_delivered += 1;
    }

    let mut tx_frames_submitted = 0usize;
    loop {
        let mut frame = [0u8; RESPONSE_CAPACITY];
        let len = driver.take_tx_frame(&mut frame).map_err(driver_errno_to_substrate)?;
        if len == 0 {
            break;
        }
        backend.submit_tx(&frame[..len as usize])?;
        tx_frames_submitted += 1;
    }

    Ok(DriverBackendPumpEvidence { rx_frames_delivered, tx_frames_submitted })
}

pub fn pump_stack_driver_backend<B: PacketDeviceBackend>(
    stack: &mut SmoltcpPacketStack,
    driver: &mut DriverVirtioNetState,
    backend: &mut B,
    now_ms: i64,
    now_ticks: u64,
) -> SubstrateResult<StackDriverBackendPumpEvidence> {
    let inbound_driver_pump = pump_driver_backend(driver, backend, now_ticks)?;
    let driver_rx_frames_delivered_to_stack = pump_driver_rx_to_stack(stack, driver, now_ticks)?;
    let stack_poll = stack.poll(now_ms);

    let mut stack_tx_frames_submitted_to_driver = 0usize;
    while let Some(frame) = stack.take_tx_frame() {
        driver.submit_tx_frame(now_ticks, &frame).map_err(driver_errno_to_substrate)?;
        stack_tx_frames_submitted_to_driver += 1;
    }

    let outbound_driver_pump = pump_driver_backend(driver, backend, now_ticks)?;
    Ok(StackDriverBackendPumpEvidence {
        backend_rx_frames_delivered_to_driver: inbound_driver_pump
            .rx_frames_delivered
            .saturating_add(outbound_driver_pump.rx_frames_delivered),
        driver_rx_frames_delivered_to_stack,
        stack_poll,
        stack_tx_frames_submitted_to_driver,
        driver_tx_frames_submitted_to_backend: inbound_driver_pump
            .tx_frames_submitted
            .saturating_add(outbound_driver_pump.tx_frames_submitted),
    })
}

pub fn pump_stack_driver_backend_until_quiescent<B: PacketDeviceBackend>(
    stack: &mut SmoltcpPacketStack,
    driver: &mut DriverVirtioNetState,
    backend: &mut B,
    now_ms: i64,
    now_ticks: u64,
    max_steps: usize,
) -> SubstrateResult<StackDriverBackendPumpTotals> {
    if max_steps == 0 || max_steps > STACK_DRIVER_BACKEND_PUMP_LIMIT {
        return Err(SubstrateError::ContractViolation {
            detail: "stack driver backend pump limit is outside supported bounds",
        });
    }

    let mut totals = StackDriverBackendPumpTotals::default();
    for step in 0..max_steps {
        let step_ms = now_ms.saturating_add(step as i64);
        let step_ticks = now_ticks.saturating_add(step as u64);
        let pump = pump_stack_driver_backend(stack, driver, backend, step_ms, step_ticks)?;
        let made_progress = pump.made_progress();
        totals.add(&pump);
        if !made_progress {
            totals.quiesced = true;
            break;
        }
    }
    Ok(totals)
}

fn pump_driver_rx_to_stack(
    stack: &mut SmoltcpPacketStack,
    driver: &mut DriverVirtioNetState,
    now_ticks: u64,
) -> SubstrateResult<usize> {
    let mut delivered = 0usize;
    for _ in 0..STACK_DRIVER_EVENT_LIMIT {
        let event = driver.poll_device(now_ticks);
        match event.kind {
            DriverNetEventKind::None => break,
            DriverNetEventKind::PacketRx => {
                let mut frame = [0u8; RESPONSE_CAPACITY];
                let len = driver.dequeue_rx_frame(&mut frame).map_err(driver_errno_to_substrate)?;
                if len == 0 {
                    continue;
                }
                let len = len as usize;
                stack.enqueue_rx_frame(&frame[..len]).map_err(|_| {
                    SubstrateError::ContractViolation {
                        detail: "driver delivered frame rejected by smoltcp queue",
                    }
                })?;
                delivered += 1;
            }
            DriverNetEventKind::Irq
            | DriverNetEventKind::DmaSubmitted
            | DriverNetEventKind::DmaCompleted
            | DriverNetEventKind::DriverCompletion => {}
        }
    }
    Ok(delivered)
}

fn driver_errno_to_substrate(errno: i32) -> SubstrateError {
    match errno {
        visa_abi::ERR_EAGAIN => {
            SubstrateError::ContractViolation { detail: "driver packet queue is full" }
        }
        visa_abi::ERR_EINVAL => {
            SubstrateError::ContractViolation { detail: "driver rejected invalid packet frame" }
        }
        visa_abi::ERR_EIO => {
            SubstrateError::ContractViolation { detail: "driver packet buffer contract violation" }
        }
        _ => SubstrateError::HardwareFault {
            authority: "DriverVirtioNetState",
            detail: "driver returned unexpected packet errno",
        },
    }
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

fn ipv4_bytes(addr: IpAddress) -> [u8; 4] {
    #[allow(unreachable_patterns)]
    match addr {
        IpAddress::Ipv4(addr) => addr.octets(),
        _ => [0; 4],
    }
}

fn bounded_tcp_buffer_len(len: usize) -> usize {
    len.clamp(1, DEFAULT_TCP_BUFFER_LEN)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn smoltcp_adapter_builds_ethernet_ipv4_tcp_profile() {
        let evidence = build_smoltcp_adapter_evidence(SmoltcpAdapterConfig::default_visa())
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
        let mut config = SmoltcpAdapterConfig::default_visa();
        config.contract.mtu += 1;
        assert_eq!(
            build_smoltcp_adapter_evidence(config),
            Err("smoltcp adapter packet device contract mismatch")
        );

        let mut config = SmoltcpAdapterConfig::default_visa();
        config.ipv4_prefix_len = 0;
        assert_eq!(
            build_smoltcp_adapter_evidence(config),
            Err("smoltcp adapter ipv4 prefix is invalid")
        );
    }

    #[test]
    fn tcp_socket_recv_capacity_is_bounded_at_creation() {
        let mut stack =
            SmoltcpPacketStack::new(SmoltcpAdapterConfig::default_visa()).expect("packet stack");

        let socket = stack.create_tcp_socket_with_buffer_capacity(2048, 1024).expect("tcp socket");
        let snapshot = stack.tcp_snapshot(socket).expect("tcp snapshot");
        assert_eq!(snapshot.recv_capacity, 2048);
        assert_eq!(snapshot.recv_queue, 0);
        assert_eq!(snapshot.send_capacity, 1024);
        assert_eq!(snapshot.send_queue, 0);

        let socket = stack
            .create_tcp_socket_with_buffer_capacity(
                DEFAULT_TCP_BUFFER_LEN * 4,
                DEFAULT_TCP_BUFFER_LEN * 4,
            )
            .expect("bounded tcp socket");
        let snapshot = stack.tcp_snapshot(socket).expect("bounded tcp snapshot");
        assert_eq!(snapshot.recv_capacity, DEFAULT_TCP_BUFFER_LEN);
        assert_eq!(snapshot.send_capacity, DEFAULT_TCP_BUFFER_LEN);
    }

    #[test]
    fn packet_stack_pumps_arp_request_through_smoltcp_device() {
        let mut stack =
            SmoltcpPacketStack::new(SmoltcpAdapterConfig::default_visa()).expect("packet stack");
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
    fn packet_backend_pump_bridges_raw_frames_into_smoltcp() {
        let mut stack =
            SmoltcpPacketStack::new(SmoltcpAdapterConfig::default_visa()).expect("packet stack");
        let remote_mac = [0x02, 0, 0, 0, 0, 2];
        let request =
            arp_request(remote_mac, [10, 0, 2, 2], VIRTIO_NET0_CONTRACT.mac, DEFAULT_IPV4_ADDR);
        let mut backend = InMemoryPacketBackend::new();
        backend.rx.push(request.to_vec());

        stack.init_backend(&mut backend).expect("init backend");
        assert_eq!(backend.init_mac, Some(VIRTIO_NET0_CONTRACT.mac));
        let evidence = stack.pump_backend(&mut backend, 1).expect("pump backend");

        assert_eq!(evidence.rx_frames_delivered, 1);
        assert_eq!(evidence.poll.rx_frames_before, 1);
        assert_eq!(evidence.poll.rx_frames_after, 0);
        assert_eq!(evidence.tx_frames_submitted, 1);
        assert_eq!(backend.tx.len(), 1);
        let reply = &backend.tx[0];
        assert_eq!(&reply[0..6], &remote_mac);
        assert_eq!(&reply[6..12], &VIRTIO_NET0_CONTRACT.mac);
        assert_eq!(&reply[12..14], &[0x08, 0x06]);
        assert_eq!(&reply[20..22], &[0x00, 0x02]);
    }

    #[test]
    fn driver_backend_pump_moves_rx_and_tx_frames() {
        let mut driver = DriverVirtioNetState::new();
        let remote_mac = [0x02, 0, 0, 0, 0, 2];
        let rx =
            arp_request(remote_mac, [10, 0, 2, 2], VIRTIO_NET0_CONTRACT.mac, DEFAULT_IPV4_ADDR);
        let mut tx = [0u8; 42];
        tx[..6].copy_from_slice(&remote_mac);
        tx[6..12].copy_from_slice(&VIRTIO_NET0_CONTRACT.mac);
        tx[12..14].copy_from_slice(&[0x08, 0x06]);

        assert_eq!(driver.submit_tx_frame(3, &tx).unwrap(), tx.len() as u32);
        let mut backend = InMemoryPacketBackend::new();
        backend.rx.push(rx.to_vec());

        let evidence = pump_driver_backend(&mut driver, &mut backend, 7).expect("pump driver");
        assert_eq!(evidence.rx_frames_delivered, 1);
        assert_eq!(evidence.tx_frames_submitted, 1);
        assert_eq!(backend.tx.len(), 1);
        assert_eq!(&backend.tx[0], &tx);
        assert_eq!(driver.pending_rx_frames(), 1);
        assert_eq!(driver.pending_tx_frames(), 0);

        for _ in 0..5 {
            driver.poll_device(7);
        }
        let mut out = [0u8; RESPONSE_CAPACITY];
        let len = driver.dequeue_rx_frame(&mut out).unwrap();
        assert_eq!(len, rx.len() as u32);
        assert_eq!(&out[..rx.len()], &rx);
    }

    #[test]
    fn driver_backend_pump_rejects_overreported_rx_count() {
        let mut driver = DriverVirtioNetState::new();
        let mut backend = OverreportingPacketBackend;

        assert_eq!(
            pump_driver_backend(&mut driver, &mut backend, 1),
            Err(SubstrateError::ContractViolation {
                detail: "packet backend returned more rx frames than provided slots",
            })
        );

        let mut stack =
            SmoltcpPacketStack::new(SmoltcpAdapterConfig::default_visa()).expect("packet stack");
        assert_eq!(
            stack.pump_backend(&mut backend, 1),
            Err(SubstrateError::ContractViolation {
                detail: "packet backend returned more rx frames than provided slots",
            })
        );
    }

    #[test]
    fn stack_driver_backend_pump_moves_frames_across_full_runtime_boundary() {
        let mut stack =
            SmoltcpPacketStack::new(SmoltcpAdapterConfig::default_visa()).expect("packet stack");
        let mut driver = DriverVirtioNetState::new();
        let remote_mac = [0x02, 0, 0, 0, 0, 2];
        let request =
            arp_request(remote_mac, [10, 0, 2, 2], VIRTIO_NET0_CONTRACT.mac, DEFAULT_IPV4_ADDR);
        let mut backend = InMemoryPacketBackend::new();
        backend.rx.push(request.to_vec());

        stack.init_backend(&mut backend).expect("init backend");
        let evidence = pump_stack_driver_backend(&mut stack, &mut driver, &mut backend, 1, 1)
            .expect("pump full stack/driver/backend loop");

        assert_eq!(evidence.backend_rx_frames_delivered_to_driver, 1);
        assert_eq!(evidence.driver_rx_frames_delivered_to_stack, 1);
        assert_eq!(evidence.stack_poll.rx_frames_before, 1);
        assert_eq!(evidence.stack_poll.rx_frames_after, 0);
        assert_eq!(evidence.stack_tx_frames_submitted_to_driver, 1);
        assert_eq!(evidence.driver_tx_frames_submitted_to_backend, 1);
        assert_eq!(backend.tx.len(), 1);
        let reply = &backend.tx[0];
        assert_eq!(&reply[0..6], &remote_mac);
        assert_eq!(&reply[6..12], &VIRTIO_NET0_CONTRACT.mac);
        assert_eq!(&reply[12..14], &[0x08, 0x06]);
        assert_eq!(&reply[20..22], &[0x00, 0x02]);
        assert_eq!(driver.pending_rx_frames(), 0);
        assert_eq!(driver.pending_tx_frames(), 0);
    }

    #[test]
    fn stack_driver_backend_pump_drains_rearmed_driver_rx_queue() {
        let mut stack =
            SmoltcpPacketStack::new(SmoltcpAdapterConfig::default_visa()).expect("packet stack");
        let mut driver = DriverVirtioNetState::new();
        let mut backend = InMemoryPacketBackend::new();
        for index in 0..RAW_RX_QUEUE_DEPTH {
            let remote_mac = [0x02, 0, 0, 0, 0, index as u8 + 2];
            let remote_ip = [10, 0, 2, index as u8 + 2];
            backend.rx.push(
                arp_request(remote_mac, remote_ip, VIRTIO_NET0_CONTRACT.mac, DEFAULT_IPV4_ADDR)
                    .to_vec(),
            );
        }

        stack.init_backend(&mut backend).expect("init backend");
        let evidence = pump_stack_driver_backend(&mut stack, &mut driver, &mut backend, 1, 1)
            .expect("pump full rx queue");

        assert_eq!(evidence.backend_rx_frames_delivered_to_driver, RAW_RX_QUEUE_DEPTH);
        assert_eq!(evidence.driver_rx_frames_delivered_to_stack, RAW_RX_QUEUE_DEPTH);
        assert_eq!(evidence.stack_poll.rx_frames_before, RAW_RX_QUEUE_DEPTH);
        assert_eq!(evidence.stack_poll.rx_frames_after, 0);
        assert_eq!(evidence.stack_tx_frames_submitted_to_driver, RAW_RX_QUEUE_DEPTH);
        assert_eq!(evidence.driver_tx_frames_submitted_to_backend, RAW_RX_QUEUE_DEPTH);
        assert_eq!(backend.tx.len(), RAW_RX_QUEUE_DEPTH);
        assert_eq!(driver.pending_rx_frames(), 0);
        assert_eq!(driver.pending_tx_frames(), 0);
    }

    #[test]
    fn stack_driver_backend_pump_until_quiescent_drains_multiple_backend_batches() {
        let mut stack =
            SmoltcpPacketStack::new(SmoltcpAdapterConfig::default_visa()).expect("packet stack");
        let mut driver = DriverVirtioNetState::new();
        let mut backend = InMemoryPacketBackend::new();
        let frame_count = DRIVER_BACKEND_RX_BATCH * 2;
        for index in 0..frame_count {
            let remote_mac = [0x02, 0, 0, 0, 0, index as u8 + 2];
            let remote_ip = [10, 0, 2, index as u8 + 2];
            backend.rx.push(
                arp_request(remote_mac, remote_ip, VIRTIO_NET0_CONTRACT.mac, DEFAULT_IPV4_ADDR)
                    .to_vec(),
            );
        }

        stack.init_backend(&mut backend).expect("init backend");
        let totals = pump_stack_driver_backend_until_quiescent(
            &mut stack,
            &mut driver,
            &mut backend,
            1,
            1,
            STACK_DRIVER_BACKEND_PUMP_LIMIT,
        )
        .expect("pump until quiescent");

        assert!(totals.quiesced);
        assert!(totals.steps > 1);
        assert_eq!(totals.backend_rx_frames_delivered_to_driver, frame_count);
        assert_eq!(totals.driver_rx_frames_delivered_to_stack, frame_count);
        assert_eq!(totals.stack_tx_frames_submitted_to_driver, frame_count);
        assert_eq!(totals.driver_tx_frames_submitted_to_backend, frame_count);
        assert_eq!(backend.rx.len(), 0);
        assert_eq!(backend.tx.len(), frame_count);
        assert_eq!(driver.pending_rx_frames(), 0);
        assert_eq!(driver.pending_tx_frames(), 0);
    }

    #[test]
    fn stack_driver_backend_pump_until_quiescent_reports_saturation() {
        let mut stack =
            SmoltcpPacketStack::new(SmoltcpAdapterConfig::default_visa()).expect("packet stack");
        let mut driver = DriverVirtioNetState::new();
        let mut backend = InMemoryPacketBackend::new();
        let frame_count = DRIVER_BACKEND_RX_BATCH * 2;
        for index in 0..frame_count {
            let remote_mac = [0x02, 0, 0, 0, 0, index as u8 + 2];
            let remote_ip = [10, 0, 2, index as u8 + 2];
            backend.rx.push(
                arp_request(remote_mac, remote_ip, VIRTIO_NET0_CONTRACT.mac, DEFAULT_IPV4_ADDR)
                    .to_vec(),
            );
        }

        stack.init_backend(&mut backend).expect("init backend");
        let totals = pump_stack_driver_backend_until_quiescent(
            &mut stack,
            &mut driver,
            &mut backend,
            1,
            1,
            1,
        )
        .expect("single bounded pump step");

        assert!(!totals.quiesced);
        assert_eq!(totals.steps, 1);
        assert_eq!(totals.backend_rx_frames_delivered_to_driver, frame_count);
        assert_eq!(totals.driver_rx_frames_delivered_to_stack, DRIVER_BACKEND_RX_BATCH);
        assert_eq!(backend.rx.len(), 0);
        assert_eq!(driver.pending_rx_frames(), DRIVER_BACKEND_RX_BATCH as u32);
        assert_eq!(driver.pending_tx_frames(), 0);
    }

    #[test]
    fn stack_driver_backend_pump_until_quiescent_rejects_invalid_limit() {
        let mut stack =
            SmoltcpPacketStack::new(SmoltcpAdapterConfig::default_visa()).expect("packet stack");
        let mut driver = DriverVirtioNetState::new();
        let mut backend = InMemoryPacketBackend::new();

        assert_eq!(
            pump_stack_driver_backend_until_quiescent(
                &mut stack,
                &mut driver,
                &mut backend,
                1,
                1,
                0,
            ),
            Err(SubstrateError::ContractViolation {
                detail: "stack driver backend pump limit is outside supported bounds",
            })
        );
        assert_eq!(
            pump_stack_driver_backend_until_quiescent(
                &mut stack,
                &mut driver,
                &mut backend,
                1,
                1,
                STACK_DRIVER_BACKEND_PUMP_LIMIT + 1,
            ),
            Err(SubstrateError::ContractViolation {
                detail: "stack driver backend pump limit is outside supported bounds",
            })
        );
    }

    #[test]
    fn tcp_connect_resolves_arp_and_emits_syn_frame() {
        let mut stack =
            SmoltcpPacketStack::new(SmoltcpAdapterConfig::default_visa()).expect("packet stack");
        let socket = stack.create_tcp_socket().expect("tcp socket");
        let remote_mac = [0x02, 0, 0, 0, 0, 2];
        let remote_ip = [10, 0, 2, 2];

        let local_port = stack.connect_tcp_ipv4(socket, remote_ip, 80).expect("connect tcp");
        assert_eq!(local_port, DEFAULT_EPHEMERAL_PORT_BASE);
        let snapshot = stack.tcp_snapshot(socket).expect("tcp snapshot");
        assert_eq!(snapshot.state, "syn-sent");
        assert_eq!(snapshot.local_ipv4, DEFAULT_IPV4_ADDR);
        assert_eq!(snapshot.local_port, DEFAULT_EPHEMERAL_PORT_BASE);
        assert_eq!(snapshot.remote_ipv4, remote_ip);
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
    fn tcp_connect_reaches_established_after_syn_ack() {
        let mut stack =
            SmoltcpPacketStack::new(SmoltcpAdapterConfig::default_visa()).expect("packet stack");
        let socket = stack.create_tcp_socket().expect("tcp socket");
        let remote_mac = [0x02, 0, 0, 0, 0, 2];
        let remote_ip = [10, 0, 2, 2];

        stack.connect_tcp_ipv4(socket, remote_ip, 80).expect("connect tcp");
        let _ = stack.poll(1);
        let _arp = stack.take_tx_frame().expect("arp request");

        let reply = arp_reply(remote_mac, remote_ip, VIRTIO_NET0_CONTRACT.mac, DEFAULT_IPV4_ADDR);
        stack.enqueue_rx_frame(&reply).expect("enqueue arp reply");
        let _ = stack.poll(2);
        let syn = stack.take_tx_frame().expect("tcp syn");
        assert_eq!(syn[47] & 0x02, 0x02);

        let syn_ack = tcp_syn_ack_for_syn(&syn, remote_mac, 0x1234_5678);
        stack.enqueue_rx_frame(&syn_ack).expect("enqueue syn ack");
        let poll = stack.poll(3);
        assert_eq!(poll.rx_frames_after, 0);

        let snapshot = stack.tcp_snapshot(socket).expect("tcp snapshot");
        assert_eq!(snapshot.state, "established");
        assert_eq!(snapshot.local_ipv4, DEFAULT_IPV4_ADDR);
        assert_eq!(snapshot.remote_ipv4, remote_ip);
        assert!(snapshot.can_send);
        assert!(snapshot.may_recv);

        let ack = stack.take_tx_frame().expect("final tcp ack");
        assert_eq!(ack[47] & 0x10, 0x10);
    }

    #[test]
    fn tcp_remote_fin_marks_receive_half_closed() {
        let mut stack =
            SmoltcpPacketStack::new(SmoltcpAdapterConfig::default_visa()).expect("packet stack");
        let socket = stack.create_tcp_socket().expect("tcp socket");
        let remote_mac = [0x02, 0, 0, 0, 0, 2];
        let remote_ip = [10, 0, 2, 2];

        stack.connect_tcp_ipv4(socket, remote_ip, 80).expect("connect tcp");
        let _ = stack.poll(1);
        let _arp = stack.take_tx_frame().expect("arp request");

        let reply = arp_reply(remote_mac, remote_ip, VIRTIO_NET0_CONTRACT.mac, DEFAULT_IPV4_ADDR);
        stack.enqueue_rx_frame(&reply).expect("enqueue arp reply");
        let _ = stack.poll(2);
        let syn = stack.take_tx_frame().expect("tcp syn");

        let syn_ack = tcp_syn_ack_for_syn(&syn, remote_mac, 0x1234_5678);
        stack.enqueue_rx_frame(&syn_ack).expect("enqueue syn ack");
        let _ = stack.poll(3);
        let ack = stack.take_tx_frame().expect("final tcp ack");
        assert_eq!(ack[47] & 0x10, 0x10);

        let fin = tcp_fin_for_syn_ack(&syn_ack);
        stack.enqueue_rx_frame(&fin).expect("enqueue remote fin");
        let _ = stack.poll(4);

        let snapshot = stack.tcp_snapshot(socket).expect("close-wait snapshot");
        assert_eq!(snapshot.state, "close-wait");
        assert!(!snapshot.can_recv);
        assert!(!snapshot.may_recv);
        assert!(snapshot.can_send);
        let fin_ack = stack.take_tx_frame().expect("fin ack");
        assert_eq!(fin_ack[47] & 0x10, 0x10);
    }

    #[test]
    fn tcp_listen_reaches_established_after_remote_handshake() {
        let mut stack =
            SmoltcpPacketStack::new(SmoltcpAdapterConfig::default_visa()).expect("packet stack");
        let socket = stack.create_tcp_socket().expect("tcp socket");
        let remote_mac = [0x02, 0, 0, 0, 0, 2];
        let remote_ip = [10, 0, 2, 2];
        let remote_port = 40_000;
        let local_port = 8080;
        let remote_seq = 0x0102_0304;

        stack.listen_tcp(socket, local_port).expect("listen tcp");
        assert_eq!(stack.tcp_snapshot(socket).expect("listen snapshot").state, "listen");

        let syn = tcp_syn_to_listener(remote_mac, remote_ip, remote_port, local_port, remote_seq);
        stack.enqueue_rx_frame(&syn).expect("enqueue remote syn");
        let arp_poll = stack.poll(1);
        assert_eq!(arp_poll.rx_frames_after, 0);
        assert_eq!(arp_poll.tx_frames_after, 1);
        let arp = stack.take_tx_frame().expect("arp request");
        assert_eq!(&arp[0..6], &[0xff; 6]);
        assert_eq!(&arp[6..12], &VIRTIO_NET0_CONTRACT.mac);
        assert_eq!(&arp[38..42], &remote_ip);

        let reply = arp_reply(remote_mac, remote_ip, VIRTIO_NET0_CONTRACT.mac, DEFAULT_IPV4_ADDR);
        stack.enqueue_rx_frame(&reply).expect("enqueue arp reply");
        let syn_ack_poll = stack.poll(2);
        assert_eq!(syn_ack_poll.rx_frames_after, 0);
        assert_eq!(syn_ack_poll.tx_frames_after, 1);
        let syn_ack = stack.take_tx_frame().expect("server syn ack");
        assert_eq!(syn_ack[47] & 0x12, 0x12);

        let ack = tcp_ack_for_syn_ack(&syn_ack);
        stack.enqueue_rx_frame(&ack).expect("enqueue remote ack");
        let established_poll = stack.poll(3);
        assert_eq!(established_poll.rx_frames_after, 0);

        let snapshot = stack.tcp_snapshot(socket).expect("established snapshot");
        assert_eq!(snapshot.state, "established");
        assert_eq!(snapshot.local_ipv4, DEFAULT_IPV4_ADDR);
        assert_eq!(snapshot.local_port, local_port);
        assert_eq!(snapshot.remote_ipv4, remote_ip);
        assert_eq!(snapshot.remote_port, remote_port);
        assert!(snapshot.can_send);
        assert!(snapshot.may_recv);
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

    struct InMemoryPacketBackend {
        init_mac: Option<[u8; 6]>,
        rx: Vec<Vec<u8>>,
        tx: Vec<Vec<u8>>,
        mtu: usize,
    }

    impl InMemoryPacketBackend {
        fn new() -> Self {
            Self { init_mac: None, rx: Vec::new(), tx: Vec::new(), mtu: 1500 }
        }
    }

    impl PacketDeviceBackend for InMemoryPacketBackend {
        fn init(&mut self, mac: [u8; 6]) -> SubstrateResult<()> {
            self.init_mac = Some(mac);
            Ok(())
        }

        fn submit_tx(&mut self, frame: &[u8]) -> SubstrateResult<()> {
            self.tx.push(frame.to_vec());
            Ok(())
        }

        fn poll_rx(&mut self, out: &mut [PacketFrameSlot]) -> SubstrateResult<usize> {
            let count = self.rx.len().min(out.len());
            for slot in out.iter_mut().take(count) {
                let frame = self.rx.remove(0);
                if frame.len() > slot.data.len() {
                    return Err(SubstrateError::ContractViolation {
                        detail: "test packet frame exceeds slot capacity",
                    });
                }
                slot.len =
                    u16::try_from(frame.len()).map_err(|_| SubstrateError::ContractViolation {
                        detail: "test packet frame length overflow",
                    })?;
                slot.data[..frame.len()].copy_from_slice(&frame);
            }
            Ok(count)
        }

        fn mtu(&self) -> usize {
            self.mtu
        }
    }

    struct OverreportingPacketBackend;

    impl PacketDeviceBackend for OverreportingPacketBackend {
        fn poll_rx(&mut self, out: &mut [PacketFrameSlot]) -> SubstrateResult<usize> {
            Ok(out.len() + 1)
        }
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

    fn tcp_syn_ack_for_syn(syn: &[u8], server_mac: [u8; 6], server_seq: u32) -> Vec<u8> {
        let syn_ip_start = ETHERNET_HEADER_LEN;
        let syn_ihl = ((syn[syn_ip_start] & 0x0f) as usize) * 4;
        let syn_tcp_start = syn_ip_start + syn_ihl;
        let client_mac: [u8; 6] = syn[6..12].try_into().expect("client mac");
        let client_ip: [u8; 4] = syn[26..30].try_into().expect("client ip");
        let server_ip: [u8; 4] = syn[30..34].try_into().expect("server ip");
        let client_port = u16::from_be_bytes([syn[syn_tcp_start], syn[syn_tcp_start + 1]]);
        let server_port = u16::from_be_bytes([syn[syn_tcp_start + 2], syn[syn_tcp_start + 3]]);
        let client_seq = u32::from_be_bytes([
            syn[syn_tcp_start + 4],
            syn[syn_tcp_start + 5],
            syn[syn_tcp_start + 6],
            syn[syn_tcp_start + 7],
        ]);

        let mut frame = vec![0u8; ETHERNET_HEADER_LEN + 20 + 20];
        frame[0..6].copy_from_slice(&client_mac);
        frame[6..12].copy_from_slice(&server_mac);
        frame[12..14].copy_from_slice(&[0x08, 0x00]);

        let ip_start = ETHERNET_HEADER_LEN;
        frame[ip_start] = 0x45;
        frame[ip_start + 2..ip_start + 4].copy_from_slice(&(40u16).to_be_bytes());
        frame[ip_start + 6..ip_start + 8].copy_from_slice(&0x4000u16.to_be_bytes());
        frame[ip_start + 8] = 64;
        frame[ip_start + 9] = 6;
        frame[ip_start + 12..ip_start + 16].copy_from_slice(&server_ip);
        frame[ip_start + 16..ip_start + 20].copy_from_slice(&client_ip);
        let ip_checksum = internet_checksum(&frame[ip_start..ip_start + 20]);
        frame[ip_start + 10..ip_start + 12].copy_from_slice(&ip_checksum.to_be_bytes());

        let tcp_start = ip_start + 20;
        frame[tcp_start..tcp_start + 2].copy_from_slice(&server_port.to_be_bytes());
        frame[tcp_start + 2..tcp_start + 4].copy_from_slice(&client_port.to_be_bytes());
        frame[tcp_start + 4..tcp_start + 8].copy_from_slice(&server_seq.to_be_bytes());
        frame[tcp_start + 8..tcp_start + 12]
            .copy_from_slice(&client_seq.wrapping_add(1).to_be_bytes());
        frame[tcp_start + 12] = 5 << 4;
        frame[tcp_start + 13] = 0x12;
        frame[tcp_start + 14..tcp_start + 16].copy_from_slice(&64240u16.to_be_bytes());
        let tcp_checksum = tcp_ipv4_checksum(&server_ip, &client_ip, &frame[tcp_start..]);
        frame[tcp_start + 16..tcp_start + 18].copy_from_slice(&tcp_checksum.to_be_bytes());
        frame
    }

    fn tcp_syn_to_listener(
        remote_mac: [u8; 6],
        remote_ip: [u8; 4],
        remote_port: u16,
        local_port: u16,
        remote_seq: u32,
    ) -> Vec<u8> {
        let mut frame = vec![0u8; ETHERNET_HEADER_LEN + 20 + 20];
        frame[0..6].copy_from_slice(&VIRTIO_NET0_CONTRACT.mac);
        frame[6..12].copy_from_slice(&remote_mac);
        frame[12..14].copy_from_slice(&[0x08, 0x00]);

        let ip_start = ETHERNET_HEADER_LEN;
        frame[ip_start] = 0x45;
        frame[ip_start + 2..ip_start + 4].copy_from_slice(&(40u16).to_be_bytes());
        frame[ip_start + 6..ip_start + 8].copy_from_slice(&0x4000u16.to_be_bytes());
        frame[ip_start + 8] = 64;
        frame[ip_start + 9] = 6;
        frame[ip_start + 12..ip_start + 16].copy_from_slice(&remote_ip);
        frame[ip_start + 16..ip_start + 20].copy_from_slice(&DEFAULT_IPV4_ADDR);
        let ip_checksum = internet_checksum(&frame[ip_start..ip_start + 20]);
        frame[ip_start + 10..ip_start + 12].copy_from_slice(&ip_checksum.to_be_bytes());

        let tcp_start = ip_start + 20;
        frame[tcp_start..tcp_start + 2].copy_from_slice(&remote_port.to_be_bytes());
        frame[tcp_start + 2..tcp_start + 4].copy_from_slice(&local_port.to_be_bytes());
        frame[tcp_start + 4..tcp_start + 8].copy_from_slice(&remote_seq.to_be_bytes());
        frame[tcp_start + 12] = 5 << 4;
        frame[tcp_start + 13] = 0x02;
        frame[tcp_start + 14..tcp_start + 16].copy_from_slice(&64240u16.to_be_bytes());
        let tcp_checksum = tcp_ipv4_checksum(&remote_ip, &DEFAULT_IPV4_ADDR, &frame[tcp_start..]);
        frame[tcp_start + 16..tcp_start + 18].copy_from_slice(&tcp_checksum.to_be_bytes());
        frame
    }

    fn tcp_ack_for_syn_ack(syn_ack: &[u8]) -> Vec<u8> {
        let syn_ack_ip_start = ETHERNET_HEADER_LEN;
        let syn_ack_ihl = ((syn_ack[syn_ack_ip_start] & 0x0f) as usize) * 4;
        let syn_ack_tcp_start = syn_ack_ip_start + syn_ack_ihl;
        let server_mac: [u8; 6] = syn_ack[6..12].try_into().expect("server mac");
        let client_mac: [u8; 6] = syn_ack[0..6].try_into().expect("client mac");
        let server_ip: [u8; 4] = syn_ack[26..30].try_into().expect("server ip");
        let client_ip: [u8; 4] = syn_ack[30..34].try_into().expect("client ip");
        let server_port =
            u16::from_be_bytes([syn_ack[syn_ack_tcp_start], syn_ack[syn_ack_tcp_start + 1]]);
        let client_port =
            u16::from_be_bytes([syn_ack[syn_ack_tcp_start + 2], syn_ack[syn_ack_tcp_start + 3]]);
        let server_seq = u32::from_be_bytes([
            syn_ack[syn_ack_tcp_start + 4],
            syn_ack[syn_ack_tcp_start + 5],
            syn_ack[syn_ack_tcp_start + 6],
            syn_ack[syn_ack_tcp_start + 7],
        ]);
        let client_seq = u32::from_be_bytes([
            syn_ack[syn_ack_tcp_start + 8],
            syn_ack[syn_ack_tcp_start + 9],
            syn_ack[syn_ack_tcp_start + 10],
            syn_ack[syn_ack_tcp_start + 11],
        ]);

        let mut frame = vec![0u8; ETHERNET_HEADER_LEN + 20 + 20];
        frame[0..6].copy_from_slice(&server_mac);
        frame[6..12].copy_from_slice(&client_mac);
        frame[12..14].copy_from_slice(&[0x08, 0x00]);

        let ip_start = ETHERNET_HEADER_LEN;
        frame[ip_start] = 0x45;
        frame[ip_start + 2..ip_start + 4].copy_from_slice(&(40u16).to_be_bytes());
        frame[ip_start + 6..ip_start + 8].copy_from_slice(&0x4000u16.to_be_bytes());
        frame[ip_start + 8] = 64;
        frame[ip_start + 9] = 6;
        frame[ip_start + 12..ip_start + 16].copy_from_slice(&client_ip);
        frame[ip_start + 16..ip_start + 20].copy_from_slice(&server_ip);
        let ip_checksum = internet_checksum(&frame[ip_start..ip_start + 20]);
        frame[ip_start + 10..ip_start + 12].copy_from_slice(&ip_checksum.to_be_bytes());

        let tcp_start = ip_start + 20;
        frame[tcp_start..tcp_start + 2].copy_from_slice(&client_port.to_be_bytes());
        frame[tcp_start + 2..tcp_start + 4].copy_from_slice(&server_port.to_be_bytes());
        frame[tcp_start + 4..tcp_start + 8].copy_from_slice(&client_seq.to_be_bytes());
        frame[tcp_start + 8..tcp_start + 12]
            .copy_from_slice(&server_seq.wrapping_add(1).to_be_bytes());
        frame[tcp_start + 12] = 5 << 4;
        frame[tcp_start + 13] = 0x10;
        frame[tcp_start + 14..tcp_start + 16].copy_from_slice(&64240u16.to_be_bytes());
        let tcp_checksum = tcp_ipv4_checksum(&client_ip, &server_ip, &frame[tcp_start..]);
        frame[tcp_start + 16..tcp_start + 18].copy_from_slice(&tcp_checksum.to_be_bytes());
        frame
    }

    fn tcp_fin_for_syn_ack(syn_ack: &[u8]) -> Vec<u8> {
        let syn_ack_ip_start = ETHERNET_HEADER_LEN;
        let syn_ack_ihl = ((syn_ack[syn_ack_ip_start] & 0x0f) as usize) * 4;
        let syn_ack_tcp_start = syn_ack_ip_start + syn_ack_ihl;
        let client_mac: [u8; 6] = syn_ack[0..6].try_into().expect("client mac");
        let server_mac: [u8; 6] = syn_ack[6..12].try_into().expect("server mac");
        let server_ip: [u8; 4] = syn_ack[26..30].try_into().expect("server ip");
        let client_ip: [u8; 4] = syn_ack[30..34].try_into().expect("client ip");
        let server_port =
            u16::from_be_bytes([syn_ack[syn_ack_tcp_start], syn_ack[syn_ack_tcp_start + 1]]);
        let client_port =
            u16::from_be_bytes([syn_ack[syn_ack_tcp_start + 2], syn_ack[syn_ack_tcp_start + 3]]);
        let server_seq = u32::from_be_bytes([
            syn_ack[syn_ack_tcp_start + 4],
            syn_ack[syn_ack_tcp_start + 5],
            syn_ack[syn_ack_tcp_start + 6],
            syn_ack[syn_ack_tcp_start + 7],
        ]);
        let client_seq = u32::from_be_bytes([
            syn_ack[syn_ack_tcp_start + 8],
            syn_ack[syn_ack_tcp_start + 9],
            syn_ack[syn_ack_tcp_start + 10],
            syn_ack[syn_ack_tcp_start + 11],
        ]);

        let mut frame = vec![0u8; ETHERNET_HEADER_LEN + 20 + 20];
        frame[0..6].copy_from_slice(&client_mac);
        frame[6..12].copy_from_slice(&server_mac);
        frame[12..14].copy_from_slice(&[0x08, 0x00]);

        let ip_start = ETHERNET_HEADER_LEN;
        frame[ip_start] = 0x45;
        frame[ip_start + 2..ip_start + 4].copy_from_slice(&(40u16).to_be_bytes());
        frame[ip_start + 6..ip_start + 8].copy_from_slice(&0x4000u16.to_be_bytes());
        frame[ip_start + 8] = 64;
        frame[ip_start + 9] = 6;
        frame[ip_start + 12..ip_start + 16].copy_from_slice(&server_ip);
        frame[ip_start + 16..ip_start + 20].copy_from_slice(&client_ip);
        let ip_checksum = internet_checksum(&frame[ip_start..ip_start + 20]);
        frame[ip_start + 10..ip_start + 12].copy_from_slice(&ip_checksum.to_be_bytes());

        let tcp_start = ip_start + 20;
        frame[tcp_start..tcp_start + 2].copy_from_slice(&server_port.to_be_bytes());
        frame[tcp_start + 2..tcp_start + 4].copy_from_slice(&client_port.to_be_bytes());
        frame[tcp_start + 4..tcp_start + 8]
            .copy_from_slice(&server_seq.wrapping_add(1).to_be_bytes());
        frame[tcp_start + 8..tcp_start + 12].copy_from_slice(&client_seq.to_be_bytes());
        frame[tcp_start + 12] = 5 << 4;
        frame[tcp_start + 13] = 0x11;
        frame[tcp_start + 14..tcp_start + 16].copy_from_slice(&64240u16.to_be_bytes());
        let tcp_checksum = tcp_ipv4_checksum(&server_ip, &client_ip, &frame[tcp_start..]);
        frame[tcp_start + 16..tcp_start + 18].copy_from_slice(&tcp_checksum.to_be_bytes());
        frame
    }

    fn tcp_ipv4_checksum(src_ip: &[u8; 4], dst_ip: &[u8; 4], tcp_segment: &[u8]) -> u16 {
        let mut checksum_input = Vec::with_capacity(12 + tcp_segment.len());
        checksum_input.extend_from_slice(src_ip);
        checksum_input.extend_from_slice(dst_ip);
        checksum_input.push(0);
        checksum_input.push(6);
        checksum_input.extend_from_slice(&(tcp_segment.len() as u16).to_be_bytes());
        checksum_input.extend_from_slice(tcp_segment);
        internet_checksum(&checksum_input)
    }

    fn internet_checksum(bytes: &[u8]) -> u16 {
        let mut sum = 0u32;
        for chunk in bytes.chunks(2) {
            let word = if chunk.len() == 2 {
                u16::from_be_bytes([chunk[0], chunk[1]]) as u32
            } else {
                (chunk[0] as u32) << 8
            };
            sum = sum.wrapping_add(word);
        }
        while (sum >> 16) != 0 {
            sum = (sum & 0xffff) + (sum >> 16);
        }
        !(sum as u16)
    }
}
