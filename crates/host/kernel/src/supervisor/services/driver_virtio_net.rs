use alloc::vec::Vec;

use service_core::{
    net_contract::{
        NETWORK_CONTRACT_ABI_VERSION, VIRTIO_NET0_MTU, VIRTIO_NET0_RX_QUEUE_DEPTH,
        VIRTIO_NET0_TX_QUEUE_DEPTH,
    },
    packet::decode_frame,
};

use super::super::{
    engine::{BufferedModule, SupervisorEngine, WasmFn, expect_len},
    types::ServiceCallError,
};

const DRIVER_VIRTIO_NET_WASM: &[u8] = include_bytes!(env!("VISA_DRIVER_VIRTIO_NET_WASM"));
const ETHERNET_HEADER_LEN: usize = 14;

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
    deliver_rx_frame: WasmFn<(u64, u32), i32>,
    poll_device: WasmFn<u64, u32>,
    event_len: WasmFn<(), u32>,
    dequeue_rx_frame: WasmFn<(), i32>,
    take_tx_frame: WasmFn<(), i32>,
    pending_rx_frames: WasmFn<(), u32>,
    pending_tx_frames: WasmFn<(), u32>,
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
        let deliver_rx_frame =
            io.bind("deliver_rx_frame", "missing driver_virtio_net deliver_rx_frame export")?;
        let poll_device = io.bind("poll_device", "missing driver_virtio_net poll_device export")?;
        let event_len = io.bind("event_len", "missing driver_virtio_net event_len export")?;
        let dequeue_rx_frame =
            io.bind("dequeue_rx_frame", "missing driver_virtio_net dequeue_rx_frame export")?;
        let take_tx_frame =
            io.bind("take_tx_frame", "missing driver_virtio_net take_tx_frame export")?;
        let pending_rx_frames =
            io.bind("pending_rx_frames", "missing driver_virtio_net pending_rx_frames export")?;
        let pending_tx_frames =
            io.bind("pending_tx_frames", "missing driver_virtio_net pending_tx_frames export")?;
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

        let mut service = Self {
            io,
            reset_sequence,
            submit_tx_frame,
            deliver_rx_frame,
            poll_device,
            event_len,
            dequeue_rx_frame,
            take_tx_frame,
            pending_rx_frames,
            pending_tx_frames,
        };
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

    pub(crate) fn deliver_rx_frame(
        &mut self,
        now_ticks: u64,
        frame: &[u8],
    ) -> Result<u32, ServiceCallError> {
        let len = self.io.write_request(frame).map_err(ServiceCallError::Invalid)?;
        let delivered = self
            .io
            .call(&self.deliver_rx_frame, (now_ticks, len), "driver_virtio_net trapped")
            .map_err(ServiceCallError::Trap)?;
        expect_len(delivered)
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
            let payload_len = driver_rx_len(&frame)?;
            (frame, payload_len)
        } else {
            (Vec::new(), len)
        };
        Ok(DriverNetEvent { kind, len: payload_len, frame })
    }

    pub(crate) fn take_tx_frame(&mut self) -> Result<Option<Vec<u8>>, ServiceCallError> {
        let len = self
            .io
            .call(&self.take_tx_frame, (), "driver_virtio_net trapped")
            .map_err(ServiceCallError::Trap)?;
        let len = expect_len(len)?;
        if len == 0 {
            return Ok(None);
        }
        let frame = self.io.read_response(len).map_err(ServiceCallError::Invalid)?;
        Ok(Some(frame))
    }

    pub(crate) fn pending_rx_frames(&mut self) -> Result<u32, ServiceCallError> {
        self.io
            .call(&self.pending_rx_frames, (), "driver_virtio_net trapped")
            .map_err(ServiceCallError::Trap)
    }

    pub(crate) fn pending_tx_frames(&mut self) -> Result<u32, ServiceCallError> {
        self.io
            .call(&self.pending_tx_frames, (), "driver_virtio_net trapped")
            .map_err(ServiceCallError::Trap)
    }
}

fn driver_rx_len(frame: &[u8]) -> Result<u32, ServiceCallError> {
    if let Ok((meta, _)) = decode_frame(frame) {
        return Ok(meta.payload_len);
    }
    if frame.len() >= ETHERNET_HEADER_LEN {
        return u32::try_from(frame.len())
            .map_err(|_| ServiceCallError::Invalid("driver returned an oversized raw frame"));
    }
    Err(ServiceCallError::Invalid("driver returned an invalid frame"))
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
