use alloc::vec::Vec;

use semantic_core::{ResourceHandle, ResourceKind, SemanticGraph};

use crate::interrupts;

const NET_READY_KEY: u64 = 0x6e65_7430_7278;
const FIRST_RX_DELAY_MS: u32 = 7;
const NEXT_RX_DELAY_MS: u32 = 20;
const DEMO_PACKET_LEN: usize = 64;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum NetEvent {
    DeviceIrq {
        irq: ResourceHandle,
        device: ResourceHandle,
    },
    DmaSubmitted {
        buffer: ResourceHandle,
        device: ResourceHandle,
        len: usize,
    },
    DmaCompleted {
        buffer: ResourceHandle,
        device: ResourceHandle,
        len: usize,
    },
    DriverCompletion {
        device: ResourceHandle,
    },
    PacketReceived {
        interface: ResourceHandle,
        ready_key: u64,
        len: usize,
    },
}

pub(crate) struct FakePacketDevice {
    next_tick: u64,
    ready: bool,
    next_socket_id: u64,
    device: ResourceHandle,
    interface: ResourceHandle,
    irq: ResourceHandle,
    dma_buffer: ResourceHandle,
}

impl FakePacketDevice {
    pub(crate) fn new(now_ticks: u64, semantic: &mut SemanticGraph) -> Self {
        let device =
            semantic.register_resource(ResourceKind::PacketDevice, None, "packet-device:net0");
        let interface =
            semantic.register_resource(ResourceKind::NetInterface, None, "net-interface:net0");
        let irq = semantic.register_resource(ResourceKind::IrqLine, None, "irq:net0");
        let dma_buffer = semantic.register_resource(ResourceKind::DmaBuffer, None, "dma:net0-rx");
        semantic.record_net_interface_state_changed(interface, true);

        Self {
            next_tick: now_ticks + ms_to_ticks(FIRST_RX_DELAY_MS),
            ready: false,
            next_socket_id: 1,
            device: semantic
                .resource_handle(device)
                .expect("fresh packet device should have a resource handle"),
            interface: semantic
                .resource_handle(interface)
                .expect("fresh net interface should have a resource handle"),
            irq: semantic
                .resource_handle(irq)
                .expect("fresh irq line should have a resource handle"),
            dma_buffer: semantic
                .resource_handle(dma_buffer)
                .expect("fresh dma buffer should have a resource handle"),
        }
    }

    pub(crate) fn reset_sequence(&mut self, now_ticks: u64) {
        self.next_tick = now_ticks + ms_to_ticks(FIRST_RX_DELAY_MS);
        self.ready = false;
    }

    pub(crate) fn allocate_socket_id(&mut self) -> u64 {
        let socket = self.next_socket_id;
        self.next_socket_id += 1;
        socket
    }

    pub(crate) fn ready_key(&self) -> u64 {
        NET_READY_KEY
    }

    pub(crate) fn is_ready_key(&self, ready_key: u64) -> bool {
        self.ready && ready_key == NET_READY_KEY
    }

    pub(crate) fn collect_events(&mut self, now_ticks: u64, out: &mut Vec<NetEvent>) {
        if self.ready || now_ticks < self.next_tick {
            return;
        }

        self.ready = true;
        self.next_tick = now_ticks + ms_to_ticks(NEXT_RX_DELAY_MS);
        out.push(NetEvent::DeviceIrq {
            irq: self.irq,
            device: self.device,
        });
        out.push(NetEvent::DmaSubmitted {
            buffer: self.dma_buffer,
            device: self.device,
            len: DEMO_PACKET_LEN,
        });
        out.push(NetEvent::DmaCompleted {
            buffer: self.dma_buffer,
            device: self.device,
            len: DEMO_PACKET_LEN,
        });
        out.push(NetEvent::DriverCompletion {
            device: self.device,
        });
        out.push(NetEvent::PacketReceived {
            interface: self.interface,
            ready_key: NET_READY_KEY,
            len: DEMO_PACKET_LEN,
        });
    }
}

fn ms_to_ticks(delay_ms: u32) -> u64 {
    let scaled = delay_ms as u64 * interrupts::TIMER_HZ as u64;
    scaled.div_ceil(1_000).max(1)
}
