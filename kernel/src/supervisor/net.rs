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
        let driver_store = semantic.store_id("driver_virtio_net");
        let device = semantic.register_resource_for_store(
            ResourceKind::PacketDevice,
            None,
            driver_store,
            "packet-device:net0",
        );
        let interface =
            semantic.register_resource(ResourceKind::NetInterface, None, "net-interface:net0");
        let irq = semantic.register_resource_for_store(
            ResourceKind::IrqLine,
            None,
            driver_store,
            "irq:net0",
        );
        let dma_buffer = semantic.register_resource_for_store(
            ResourceKind::DmaBuffer,
            None,
            driver_store,
            "dma:net0-rx",
        );
        let mmio_region = semantic.register_resource_for_store(
            ResourceKind::MmioRegion,
            None,
            driver_store,
            "mmio:virtio-net0",
        );
        let virtio_queue = semantic.register_resource_for_store(
            ResourceKind::VirtioQueue,
            None,
            driver_store,
            "virtqueue:net0-rx",
        );
        semantic.bind_authority_resource(
            irq,
            "driver_virtio_net",
            "irq.net0",
            &["ack", "mask", "unmask"],
            "store",
        );
        semantic.bind_authority_resource(
            dma_buffer,
            "driver_virtio_net",
            "dma.pool.net0",
            &["submit", "complete", "cancel"],
            "store",
        );
        semantic.bind_authority_resource(
            mmio_region,
            "driver_virtio_net",
            "mmio.virtio-net0",
            &["read", "write"],
            "store",
        );
        semantic.bind_authority_resource(
            virtio_queue,
            "driver_virtio_net",
            "virtqueue.net0",
            &["read", "write", "kick"],
            "store",
        );
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

    pub(crate) fn rebind_driver_authority(
        &mut self,
        semantic: &mut SemanticGraph,
    ) -> Result<(), &'static str> {
        let driver_store = semantic.store_id("driver_virtio_net");
        let device = semantic.register_resource_for_store(
            ResourceKind::PacketDevice,
            None,
            driver_store,
            "packet-device:net0",
        );
        let irq = semantic.register_resource_for_store(
            ResourceKind::IrqLine,
            None,
            driver_store,
            "irq:net0",
        );
        let dma_buffer = semantic.register_resource_for_store(
            ResourceKind::DmaBuffer,
            None,
            driver_store,
            "dma:net0-rx",
        );
        let mmio_region = semantic.register_resource_for_store(
            ResourceKind::MmioRegion,
            None,
            driver_store,
            "mmio:virtio-net0",
        );
        let virtio_queue = semantic.register_resource_for_store(
            ResourceKind::VirtioQueue,
            None,
            driver_store,
            "virtqueue:net0-rx",
        );
        semantic.bind_authority_resource(
            irq,
            "driver_virtio_net",
            "irq.net0",
            &["ack", "mask", "unmask"],
            "store",
        );
        semantic.bind_authority_resource(
            dma_buffer,
            "driver_virtio_net",
            "dma.pool.net0",
            &["submit", "complete", "cancel"],
            "store",
        );
        semantic.bind_authority_resource(
            mmio_region,
            "driver_virtio_net",
            "mmio.virtio-net0",
            &["read", "write"],
            "store",
        );
        semantic.bind_authority_resource(
            virtio_queue,
            "driver_virtio_net",
            "virtqueue.net0",
            &["read", "write", "kick"],
            "store",
        );
        self.device = resource_handle(semantic, device)?;
        self.irq = resource_handle(semantic, irq)?;
        self.dma_buffer = resource_handle(semantic, dma_buffer)?;
        self.mmio_region = resource_handle(semantic, mmio_region)?;
        self.virtio_queue = resource_handle(semantic, virtio_queue)?;
        semantic.record_net_interface_state_changed(self.interface.id, true);
        Ok(())
    }
}

fn resource_handle(
    semantic: &SemanticGraph,
    resource: semantic_core::ResourceId,
) -> Result<ResourceHandle, &'static str> {
    semantic
        .resource_handle(resource)
        .ok_or("fresh network resource did not publish a handle")
}
