use alloc::vec::Vec;

use service_core::{
    net_contract::{
        NETWORK_CONTRACT_ABI_VERSION, VIRTIO_NET0_MTU, VIRTIO_NET0_RX_QUEUE_DEPTH,
        VIRTIO_NET0_TX_QUEUE_DEPTH,
    },
    packet::decode_frame,
};

use super::super::{
    engine::{BufferedModule, SupervisorEngine, WasmFn},
    types::ServiceCallError,
};

const DRIVER_VIRTIO_NET_WASM: &[u8] = include_bytes!(env!("VMOS_DRIVER_VIRTIO_NET_WASM"));

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum DriverNetEventKind {
    None,
    Irq,
    DmaSubmitted,
    DmaCompleted,
    DriverCompletion,
    PacketRx,
}

pub(crate) struct DriverNetEvent {
    pub(crate) kind: DriverNetEventKind,
    pub(crate) len: u32,
    pub(crate) frame: Vec<u8>,
}

pub(crate) struct DriverVirtioNetService {
    io: BufferedModule,
    reset_sequence: WasmFn<u64, ()>,
    submit_tx_frame: WasmFn<(u64, u32), i32>,
    poll_device: WasmFn<u64, u32>,
    event_len: WasmFn<(), u32>,
    dequeue_rx_frame: WasmFn<(), i32>,
}

impl DriverVirtioNetService {
    pub(crate) fn new(engine: &SupervisorEngine) -> Result<Self, &'static str> {
        let io = BufferedModule::instantiate(
            engine,
            DRIVER_VIRTIO_NET_WASM,
            "failed to instantiate driver_virtio_net",
        )?;
        let reset_sequence =
            io.bind("reset_sequence", "missing driver_virtio_net reset_sequence export")?;
        let submit_tx_frame =
            io.bind("submit_tx_frame", "missing driver_virtio_net submit_tx_frame export")?;
        let poll_device = io.bind("poll_device", "missing driver_virtio_net poll_device export")?;
        let event_len = io.bind("event_len", "missing driver_virtio_net event_len export")?;
        let dequeue_rx_frame =
            io.bind("dequeue_rx_frame", "missing driver_virtio_net dequeue_rx_frame export")?;
        let network_contract_version: WasmFn<(), u32> = io.bind(
            "network_contract_version",
            "missing driver_virtio_net network_contract_version export",
        )?;
        let packet_mtu: WasmFn<(), u32> =
            io.bind("packet_mtu", "missing driver_virtio_net packet_mtu export")?;
        let packet_rx_queue_depth: WasmFn<(), u32> = io.bind(
            "packet_rx_queue_depth",
            "missing driver_virtio_net packet_rx_queue_depth export",
        )?;
        let packet_tx_queue_depth: WasmFn<(), u32> = io.bind(
            "packet_tx_queue_depth",
            "missing driver_virtio_net packet_tx_queue_depth export",
        )?;

        let mut service =
            Self { io, reset_sequence, submit_tx_frame, poll_device, event_len, dequeue_rx_frame };
        validate_network_contract(
            &mut service.io,
            &network_contract_version,
            &packet_mtu,
            &packet_rx_queue_depth,
            &packet_tx_queue_depth,
            "driver_virtio_net",
        )?;
        Ok(service)
    }

    pub(crate) fn reset_sequence(&mut self, now_ticks: u64) -> Result<(), ServiceCallError> {
        self.io
            .call(&self.reset_sequence, now_ticks, "driver_virtio_net trapped")
            .map_err(ServiceCallError::Trap)
    }

    pub(crate) fn submit_tx_frame(
        &mut self,
        now_ticks: u64,
        frame: &[u8],
    ) -> Result<u32, ServiceCallError> {
        let len = self.io.write_request(frame).map_err(ServiceCallError::Invalid)?;
        let submitted = self
            .io
            .call(&self.submit_tx_frame, (now_ticks, len), "driver_virtio_net trapped")
            .map_err(ServiceCallError::Trap)?;
        if submitted < 0 { Err(ServiceCallError::Errno(-submitted)) } else { Ok(submitted as u32) }
    }

    pub(crate) fn poll_device(
        &mut self,
        now_ticks: u64,
    ) -> Result<DriverNetEvent, ServiceCallError> {
        let raw = self
            .io
            .call(&self.poll_device, now_ticks, "driver_virtio_net trapped")
            .map_err(ServiceCallError::Trap)?;
        let len = self
            .io
            .call(&self.event_len, (), "driver_virtio_net trapped")
            .map_err(ServiceCallError::Trap)?;
        let kind = match raw {
            0 => DriverNetEventKind::None,
            1 => DriverNetEventKind::Irq,
            2 => DriverNetEventKind::DmaSubmitted,
            3 => DriverNetEventKind::DmaCompleted,
            4 => DriverNetEventKind::DriverCompletion,
            5 => DriverNetEventKind::PacketRx,
            _ => {
                return Err(ServiceCallError::Invalid(
                    "driver_virtio_net returned an invalid event kind",
                ));
            }
        };
        let (frame, payload_len) = if kind == DriverNetEventKind::PacketRx {
            let frame_len = self
                .io
                .call(&self.dequeue_rx_frame, (), "driver_virtio_net trapped")
                .map_err(ServiceCallError::Trap)?;
            if frame_len < 0 {
                return Err(ServiceCallError::Errno(-frame_len));
            }
            let frame =
                self.io.read_response(frame_len as u32).map_err(ServiceCallError::Invalid)?;
            let payload_len = decode_frame(&frame)
                .map(|(meta, _)| meta.payload_len)
                .map_err(|_| ServiceCallError::Invalid("driver returned an invalid frame"))?;
            (frame, payload_len)
        } else {
            (Vec::new(), len)
        };
        Ok(DriverNetEvent { kind, len: payload_len, frame })
    }
}

fn validate_network_contract(
    io: &mut BufferedModule,
    version_fn: &WasmFn<(), u32>,
    mtu_fn: &WasmFn<(), u32>,
    rx_depth_fn: &WasmFn<(), u32>,
    tx_depth_fn: &WasmFn<(), u32>,
    label: &'static str,
) -> Result<(), &'static str> {
    let version = io.call(version_fn, (), "network contract version trapped")?;
    let mtu = io.call(mtu_fn, (), "network packet_mtu trapped")?;
    let rx_depth = io.call(rx_depth_fn, (), "network rx depth trapped")?;
    let tx_depth = io.call(tx_depth_fn, (), "network tx depth trapped")?;
    if version != NETWORK_CONTRACT_ABI_VERSION
        || mtu != VIRTIO_NET0_MTU
        || rx_depth != VIRTIO_NET0_RX_QUEUE_DEPTH
        || tx_depth != VIRTIO_NET0_TX_QUEUE_DEPTH
    {
        crate::kwarn!("{} exported an incompatible network contract", label);
        return Err("network contract mismatch");
    }
    Ok(())
}
