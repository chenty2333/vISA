use semantic_core::{ResourceHandle, ResourceId, ResourceKind, SemanticGraph, StoreId};

use super::authority::{AuthorityPlane, SubstrateAuthorityClass, SubstrateAuthoritySpec};

const DEFAULT_DRIVER_PACKAGE: &str = "driver_virtio_net";

pub(crate) struct NetworkPlane {
    pub(crate) device: ResourceHandle,
    pub(crate) interface: ResourceHandle,
    pub(crate) irq: ResourceHandle,
    pub(crate) dma_buffer: ResourceHandle,
    pub(crate) mmio_region: ResourceHandle,
    pub(crate) virtio_queue: ResourceHandle,
}

impl NetworkPlane {
    pub(crate) fn new(
        authority: &AuthorityPlane,
        semantic: &mut SemanticGraph,
    ) -> Result<Self, &'static str> {
        let driver_store = semantic.store_id(DEFAULT_DRIVER_PACKAGE);
        let device = bind_network_authority(
            authority,
            semantic,
            DEFAULT_DRIVER_PACKAGE,
            driver_store,
            SubstrateAuthorityClass::PacketDevice,
            "packet-device:net0",
            "packet-device.net0",
            &["rx", "tx", "poll", "irq", "dma"],
        )?;
        let interface =
            semantic.register_resource(ResourceKind::NetInterface, None, "net-interface:net0");
        let irq = bind_network_authority(
            authority,
            semantic,
            DEFAULT_DRIVER_PACKAGE,
            driver_store,
            SubstrateAuthorityClass::IrqLine,
            "irq:net0",
            "irq.net0",
            &["ack", "mask", "unmask"],
        )?;
        let dma_buffer = bind_network_authority(
            authority,
            semantic,
            DEFAULT_DRIVER_PACKAGE,
            driver_store,
            SubstrateAuthorityClass::DmaBuffer,
            "dma:net0-rx",
            "dma.pool.net0",
            &["submit", "complete", "cancel"],
        )?;
        let mmio_region = bind_network_authority(
            authority,
            semantic,
            DEFAULT_DRIVER_PACKAGE,
            driver_store,
            SubstrateAuthorityClass::MmioRegion,
            "mmio:virtio-net0",
            "mmio.virtio-net0",
            &["read", "write"],
        )?;
        let virtio_queue = bind_network_authority(
            authority,
            semantic,
            DEFAULT_DRIVER_PACKAGE,
            driver_store,
            SubstrateAuthorityClass::VirtioQueue,
            "virtqueue:net0-rx",
            "virtqueue.net0",
            &["read", "write", "kick"],
        )?;
        let interface = resource_handle(semantic, interface)?;
        semantic.record_net_interface_state_changed(interface.id, true);

        Ok(Self {
            device,
            interface,
            irq,
            dma_buffer,
            mmio_region,
            virtio_queue,
        })
    }

    pub(crate) fn bind_driver_resources(
        &mut self,
        authority: &AuthorityPlane,
        semantic: &mut SemanticGraph,
        driver_store: StoreId,
        driver_package: &'static str,
    ) -> Result<(), &'static str> {
        self.device = bind_network_authority(
            authority,
            semantic,
            driver_package,
            Some(driver_store),
            SubstrateAuthorityClass::PacketDevice,
            "packet-device:net0",
            "packet-device.net0",
            &["rx", "tx", "poll", "irq", "dma"],
        )?;
        self.irq = bind_network_authority(
            authority,
            semantic,
            driver_package,
            Some(driver_store),
            SubstrateAuthorityClass::IrqLine,
            "irq:net0",
            "irq.net0",
            &["ack", "mask", "unmask"],
        )?;
        self.dma_buffer = bind_network_authority(
            authority,
            semantic,
            driver_package,
            Some(driver_store),
            SubstrateAuthorityClass::DmaBuffer,
            "dma:net0-rx",
            "dma.pool.net0",
            &["submit", "complete", "cancel"],
        )?;
        self.mmio_region = bind_network_authority(
            authority,
            semantic,
            driver_package,
            Some(driver_store),
            SubstrateAuthorityClass::MmioRegion,
            "mmio:virtio-net0",
            "mmio.virtio-net0",
            &["read", "write"],
        )?;
        self.virtio_queue = bind_network_authority(
            authority,
            semantic,
            driver_package,
            Some(driver_store),
            SubstrateAuthorityClass::VirtioQueue,
            "virtqueue:net0-rx",
            "virtqueue.net0",
            &["read", "write", "kick"],
        )?;
        semantic.record_net_interface_state_changed(self.interface.id, true);
        Ok(())
    }
}

fn bind_network_authority(
    authority: &AuthorityPlane,
    semantic: &mut SemanticGraph,
    subject: &'static str,
    owner_store: Option<StoreId>,
    class: SubstrateAuthorityClass,
    label: &'static str,
    object: &'static str,
    operations: &'static [&'static str],
) -> Result<ResourceHandle, &'static str> {
    Ok(authority
        .bind_substrate_authority(
            semantic,
            SubstrateAuthoritySpec {
                class,
                subject,
                object,
                operations,
                lifetime: "store",
                label,
                owner_store,
            },
        )?
        .handle)
}

fn resource_handle(
    semantic: &SemanticGraph,
    resource: ResourceId,
) -> Result<ResourceHandle, &'static str> {
    semantic
        .resource_handle(resource)
        .ok_or("fresh network resource did not publish a handle")
}
