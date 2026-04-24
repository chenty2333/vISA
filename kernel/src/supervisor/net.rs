use semantic_core::{ResourceHandle, ResourceKind, SemanticGraph};

pub(crate) struct NetworkPlane {
    pub(crate) device: ResourceHandle,
    pub(crate) interface: ResourceHandle,
    pub(crate) irq: ResourceHandle,
    pub(crate) dma_buffer: ResourceHandle,
    pub(crate) mmio_region: ResourceHandle,
    pub(crate) virtio_queue: ResourceHandle,
}

impl NetworkPlane {
    pub(crate) fn new(semantic: &mut SemanticGraph) -> Self {
        let device =
            semantic.register_resource(ResourceKind::PacketDevice, None, "packet-device:net0");
        let interface =
            semantic.register_resource(ResourceKind::NetInterface, None, "net-interface:net0");
        let irq = semantic.register_resource(ResourceKind::IrqLine, None, "irq:net0");
        let dma_buffer = semantic.register_resource(ResourceKind::DmaBuffer, None, "dma:net0-rx");
        let mmio_region =
            semantic.register_resource(ResourceKind::MmioRegion, None, "mmio:virtio-net0");
        let virtio_queue =
            semantic.register_resource(ResourceKind::VirtioQueue, None, "virtqueue:net0-rx");
        semantic.record_net_interface_state_changed(interface, true);

        Self {
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
            mmio_region: semantic
                .resource_handle(mmio_region)
                .expect("fresh mmio region should have a resource handle"),
            virtio_queue: semantic
                .resource_handle(virtio_queue)
                .expect("fresh virtio queue should have a resource handle"),
        }
    }
}
