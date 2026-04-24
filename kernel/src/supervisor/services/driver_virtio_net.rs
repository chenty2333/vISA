use alloc::vec::Vec;

use super::super::engine::{BufferedModule, SupervisorEngine, WasmFn};
use super::super::types::ServiceCallError;

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
    pub(crate) packet: Vec<u8>,
}

pub(crate) struct DriverVirtioNetService {
    io: BufferedModule,
    reset_sequence: WasmFn<u64, ()>,
    poll_device: WasmFn<u64, u32>,
    event_len: WasmFn<(), u32>,
    consume_packet: WasmFn<(), ()>,
}

impl DriverVirtioNetService {
    pub(crate) fn new(engine: &SupervisorEngine) -> Result<Self, &'static str> {
        let io = BufferedModule::instantiate(
            engine,
            DRIVER_VIRTIO_NET_WASM,
            "failed to instantiate driver_virtio_net",
        )?;
        let reset_sequence = io.bind(
            "reset_sequence",
            "missing driver_virtio_net reset_sequence export",
        )?;
        let poll_device = io.bind(
            "poll_device",
            "missing driver_virtio_net poll_device export",
        )?;
        let event_len = io.bind("event_len", "missing driver_virtio_net event_len export")?;
        let consume_packet = io.bind(
            "consume_packet",
            "missing driver_virtio_net consume_packet export",
        )?;

        Ok(Self {
            io,
            reset_sequence,
            poll_device,
            event_len,
            consume_packet,
        })
    }

    pub(crate) fn reset_sequence(&mut self, now_ticks: u64) -> Result<(), ServiceCallError> {
        self.io
            .call(&self.reset_sequence, now_ticks, "driver_virtio_net trapped")
            .map_err(ServiceCallError::Trap)
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
        let packet = if kind == DriverNetEventKind::PacketRx {
            self.io
                .read_response(len)
                .map_err(ServiceCallError::Invalid)?
        } else {
            Vec::new()
        };
        if kind == DriverNetEventKind::PacketRx {
            self.io
                .call(&self.consume_packet, (), "driver_virtio_net trapped")
                .map_err(ServiceCallError::Trap)?;
        }
        Ok(DriverNetEvent { kind, len, packet })
    }
}
