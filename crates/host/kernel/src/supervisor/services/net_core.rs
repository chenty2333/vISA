use alloc::vec::Vec;

use service_core::net_contract::{
    NETWORK_CONTRACT_ABI_VERSION, VIRTIO_NET0_MTU, VIRTIO_NET0_RX_QUEUE_DEPTH,
    VIRTIO_NET0_TX_QUEUE_DEPTH,
};

use super::super::{
    engine::{BufferedModule, SupervisorEngine, WasmFn, expect_len, expect_ok},
    types::ServiceCallError,
};

const NET_CORE_WASM: &[u8] = include_bytes!(env!("VISA_NET_CORE_WASM"));

pub(crate) struct NetCoreService {
    io: BufferedModule,
    create_socket: WasmFn<(u32, u32, u32), i32>,
    close_socket: WasmFn<u32, i32>,
    ready_key: WasmFn<u32, u64>,
    poll_socket: WasmFn<u32, u32>,
    set_recv_capacity: WasmFn<(u32, u32), i32>,
    send_socket: WasmFn<(u32, u32), i32>,
    take_tx_frame: WasmFn<u32, i32>,
    recv_socket: WasmFn<(u32, u32), i32>,
    peek_socket: WasmFn<(u32, u32), i32>,
    deliver_packet_frame: WasmFn<u32, i64>,
    socket_count: WasmFn<(), u32>,
    queued_rx_bytes: WasmFn<(), u32>,
}

impl NetCoreService {
    pub(crate) fn new(engine: &SupervisorEngine) -> Result<Self, &'static str> {
        let io =
            BufferedModule::instantiate(engine, NET_CORE_WASM, "failed to instantiate net_core")?;
        let create_socket = io.bind("create_socket", "missing net_core create_socket export")?;
        let close_socket = io.bind("close_socket", "missing net_core close_socket export")?;
        let ready_key = io.bind("ready_key", "missing net_core ready_key export")?;
        let poll_socket = io.bind("poll_socket", "missing net_core poll_socket export")?;
        let set_recv_capacity =
            io.bind("set_recv_capacity", "missing net_core set_recv_capacity export")?;
        let send_socket = io.bind("send_socket", "missing net_core send_socket export")?;
        let take_tx_frame = io.bind("take_tx_frame", "missing net_core take_tx_frame export")?;
        let recv_socket = io.bind("recv_socket", "missing net_core recv_socket export")?;
        let peek_socket = io.bind("peek_socket", "missing net_core peek_socket export")?;
        let deliver_packet_frame =
            io.bind("deliver_packet_frame", "missing net_core deliver_packet_frame export")?;
        let socket_count = io.bind("socket_count", "missing net_core socket_count export")?;
        let queued_rx_bytes =
            io.bind("queued_rx_bytes", "missing net_core queued_rx_bytes export")?;
        let network_contract_version: WasmFn<(), u32> = io
            .bind("network_contract_version", "missing net_core network_contract_version export")?;
        let packet_mtu: WasmFn<(), u32> =
            io.bind("packet_mtu", "missing net_core packet_mtu export")?;
        let packet_rx_queue_depth: WasmFn<(), u32> =
            io.bind("packet_rx_queue_depth", "missing net_core packet_rx_queue_depth export")?;
        let packet_tx_queue_depth: WasmFn<(), u32> =
            io.bind("packet_tx_queue_depth", "missing net_core packet_tx_queue_depth export")?;

        let mut service = Self {
            io,
            create_socket,
            close_socket,
            ready_key,
            poll_socket,
            set_recv_capacity,
            send_socket,
            take_tx_frame,
            recv_socket,
            peek_socket,
            deliver_packet_frame,
            socket_count,
            queued_rx_bytes,
        };
        validate_network_contract(
            &mut service.io,
            &network_contract_version,
            &packet_mtu,
            &packet_rx_queue_depth,
            &packet_tx_queue_depth,
        )?;
        Ok(service)
    }

    pub(crate) fn create_socket(
        &mut self,
        domain: u32,
        ty: u32,
        protocol: u32,
    ) -> Result<u32, ServiceCallError> {
        expect_len(
            self.io
                .call(&self.create_socket, (domain, ty, protocol), "net_core trapped")
                .map_err(ServiceCallError::Trap)?,
        )
    }

    pub(crate) fn close_socket(&mut self, socket_id: u32) -> Result<(), ServiceCallError> {
        expect_ok(
            self.io
                .call(&self.close_socket, socket_id, "net_core trapped")
                .map_err(ServiceCallError::Trap)?,
        )
    }

    pub(crate) fn ready_key(&mut self, socket_id: u32) -> Result<u64, ServiceCallError> {
        let key = self
            .io
            .call(&self.ready_key, socket_id, "net_core trapped")
            .map_err(ServiceCallError::Trap)?;
        if key == 0 { Err(ServiceCallError::Errno(visa_abi::ERR_EBADF)) } else { Ok(key) }
    }

    pub(crate) fn poll_socket(&mut self, socket_id: u32) -> Result<u32, ServiceCallError> {
        let events = self
            .io
            .call(&self.poll_socket, socket_id, "net_core trapped")
            .map_err(ServiceCallError::Trap)?;
        Ok(events)
    }

    pub(crate) fn set_recv_capacity(
        &mut self,
        socket_id: u32,
        capacity: u32,
    ) -> Result<(), ServiceCallError> {
        expect_ok(
            self.io
                .call(&self.set_recv_capacity, (socket_id, capacity), "net_core trapped")
                .map_err(ServiceCallError::Trap)?,
        )
    }

    pub(crate) fn send_socket(
        &mut self,
        socket_id: u32,
        bytes: &[u8],
    ) -> Result<u32, ServiceCallError> {
        let len = self.io.write_request(bytes).map_err(ServiceCallError::Invalid)?;
        expect_len(
            self.io
                .call(&self.send_socket, (socket_id, len), "net_core trapped")
                .map_err(ServiceCallError::Trap)?,
        )
    }

    pub(crate) fn recv_socket(
        &mut self,
        socket_id: u32,
        count: u32,
    ) -> Result<Vec<u8>, ServiceCallError> {
        let len = expect_len(
            self.io
                .call(&self.recv_socket, (socket_id, count), "net_core trapped")
                .map_err(ServiceCallError::Trap)?,
        )?;
        self.io.read_response(len).map_err(ServiceCallError::Invalid)
    }

    pub(crate) fn peek_socket(
        &mut self,
        socket_id: u32,
        count: u32,
    ) -> Result<Vec<u8>, ServiceCallError> {
        let len = expect_len(
            self.io
                .call(&self.peek_socket, (socket_id, count), "net_core trapped")
                .map_err(ServiceCallError::Trap)?,
        )?;
        self.io.read_response(len).map_err(ServiceCallError::Invalid)
    }

    pub(crate) fn take_tx_frame(&mut self, socket_id: u32) -> Result<Vec<u8>, ServiceCallError> {
        let len = expect_len(
            self.io
                .call(&self.take_tx_frame, socket_id, "net_core trapped")
                .map_err(ServiceCallError::Trap)?,
        )?;
        self.io.read_response(len).map_err(ServiceCallError::Invalid)
    }

    pub(crate) fn deliver_packet_frame(
        &mut self,
        frame: &[u8],
    ) -> Result<Option<u64>, ServiceCallError> {
        let len = self.io.write_request(frame).map_err(ServiceCallError::Invalid)?;
        let raw = self
            .io
            .call(&self.deliver_packet_frame, len, "net_core trapped")
            .map_err(ServiceCallError::Trap)?;
        if raw < 0 {
            return Err(ServiceCallError::Errno((-raw) as i32));
        }
        if raw == 0 { Ok(None) } else { Ok(Some(raw as u64)) }
    }

    pub(crate) fn socket_count(&mut self) -> Result<u32, ServiceCallError> {
        self.io.call(&self.socket_count, (), "net_core trapped").map_err(ServiceCallError::Trap)
    }

    pub(crate) fn queued_rx_bytes(&mut self) -> Result<u32, ServiceCallError> {
        self.io.call(&self.queued_rx_bytes, (), "net_core trapped").map_err(ServiceCallError::Trap)
    }
}

fn validate_network_contract(
    io: &mut BufferedModule,
    version_fn: &WasmFn<(), u32>,
    mtu_fn: &WasmFn<(), u32>,
    rx_depth_fn: &WasmFn<(), u32>,
    tx_depth_fn: &WasmFn<(), u32>,
) -> Result<(), &'static str> {
    let version = io.call(version_fn, (), "net_core network contract version trapped")?;
    let mtu = io.call(mtu_fn, (), "net_core packet_mtu trapped")?;
    let rx_depth = io.call(rx_depth_fn, (), "net_core rx depth trapped")?;
    let tx_depth = io.call(tx_depth_fn, (), "net_core tx depth trapped")?;
    if version != NETWORK_CONTRACT_ABI_VERSION
        || mtu != VIRTIO_NET0_MTU
        || rx_depth != VIRTIO_NET0_RX_QUEUE_DEPTH
        || tx_depth != VIRTIO_NET0_TX_QUEUE_DEPTH
    {
        return Err("net_core network contract mismatch");
    }
    Ok(())
}
