use super::*;

impl SemanticGraph {
    pub fn record_packet_received(
        &mut self,
        interface: ResourceId,
        socket: Option<ResourceId>,
        ready_key: u64,
        len: usize,
    ) {
        self.event_log.push("net", EventKind::PacketReceived { interface, socket, ready_key, len });
    }
    pub fn record_packet_transmitted(
        &mut self,
        interface: ResourceId,
        socket: Option<ResourceId>,
        ready_key: u64,
        len: usize,
    ) {
        self.event_log
            .push("net", EventKind::PacketTransmitted { interface, socket, ready_key, len });
    }
    pub fn record_net_interface_state_changed(&mut self, interface: ResourceId, up: bool) {
        self.event_log.push("net", EventKind::NetInterfaceStateChanged { interface, up });
    }
    pub fn record_socket_state_changed(&mut self, socket: ResourceId, state: &str) {
        self.event_log
            .push("net", EventKind::SocketStateChanged { socket, state: state.to_string() });
    }
    pub fn record_device_irq_delivered(
        &mut self,
        irq: ResourceId,
        device: ResourceId,
        cause: &str,
    ) {
        self.event_log.push(
            "device",
            EventKind::DeviceIrqDelivered { irq, device, cause: cause.to_string() },
        );
    }
    pub fn record_driver_completion(&mut self, device: ResourceId, operation: &str) {
        self.event_log.push(
            "driver",
            EventKind::DriverCompletion { device, operation: operation.to_string() },
        );
    }
    pub fn record_dma_submitted(&mut self, buffer: ResourceId, device: ResourceId, len: usize) {
        self.event_log.push("dma", EventKind::DmaSubmitted { buffer, device, len });
    }
    pub fn record_dma_completed(&mut self, buffer: ResourceId, device: ResourceId, len: usize) {
        self.event_log.push("dma", EventKind::DmaCompleted { buffer, device, len });
    }
}
