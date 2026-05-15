use semantic_core::{ResourceHandle, ResourceId, ResourceKind, SemanticGraph, StoreId};
use service_core::net_contract::PROTO_TCP;
use vmos_abi::{
    AF_INET, ERR_EAGAIN, ERR_EALREADY, ERR_EINPROGRESS, ERR_EISCONN, ERR_ENOTCONN, ERR_EOPNOTSUPP,
    SOCK_STREAM,
};

use super::{
    authority::{AuthorityPlane, SubstrateAuthorityClass, SubstrateAuthoritySpec},
    linux::LinuxCallResult,
    runtime::PrototypeRuntime,
    services::DriverNetEventKind,
    types::ServiceCallError,
};
use crate::interrupts;

const DEFAULT_DRIVER_PACKAGE: &str = "driver_virtio_net";
const NET_STACK_DRIVER_EVENT_LIMIT: usize = 8;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum NetStackSocketMode {
    Idle,
    TcpConnectInProgress,
    TcpEstablished,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct NetStackSocketBinding {
    pub(crate) socket_id: u32,
    pub(crate) stack_socket_id: u32,
    pub(crate) mode: NetStackSocketMode,
    pub(crate) remote_ipv4: [u8; 4],
    pub(crate) remote_port: u16,
}

impl NetStackSocketBinding {
    pub(crate) const fn new(socket_id: u32, stack_socket_id: u32) -> Self {
        Self {
            socket_id,
            stack_socket_id,
            mode: NetStackSocketMode::Idle,
            remote_ipv4: [0; 4],
            remote_port: 0,
        }
    }
}

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

        Ok(Self { device, interface, irq, dma_buffer, mmio_region, virtio_queue })
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
    semantic.resource_handle(resource).ok_or("fresh network resource did not publish a handle")
}

impl<'engine> PrototypeRuntime<'engine> {
    pub(super) fn create_net_stack_socket_if_supported(
        &mut self,
        socket_id: u32,
        domain: u32,
        ty: u32,
        protocol: u32,
    ) -> Result<(), ServiceCallError> {
        if !is_smoltcp_tcp_socket(domain, ty, protocol) {
            return Ok(());
        }
        if self.net_stack_socket_index(socket_id).is_some() {
            return Ok(());
        }

        let stack_socket_id =
            self.net_stack.create_tcp_socket().map_err(ServiceCallError::Invalid)?;
        self.net_stack_sockets.push(NetStackSocketBinding::new(socket_id, stack_socket_id));
        Ok(())
    }

    pub(super) fn close_net_stack_socket(&mut self, socket_id: u32) {
        let Some(index) = self.net_stack_socket_index(socket_id) else {
            return;
        };
        let binding = self.net_stack_sockets.remove(index);
        if let Err(err) = self.net_stack.close_tcp_socket(binding.stack_socket_id) {
            crate::kwarn!("smoltcp close socket {}: {}", socket_id, err);
        }
    }

    pub(super) fn connect_net_stack_tcp(
        &mut self,
        socket_id: u32,
        ready_key: u64,
        socket_resource: ResourceHandle,
        remote_ipv4: [u8; 4],
        remote_port: u16,
    ) -> Result<LinuxCallResult, &'static str> {
        let Some(index) = self.net_stack_socket_index(socket_id) else {
            return Ok(LinuxCallResult::Ret(-(ERR_EOPNOTSUPP as i64)));
        };
        if remote_port == 0 {
            return Ok(LinuxCallResult::Ret(-(ERR_EOPNOTSUPP as i64)));
        }

        match self.net_stack_sockets[index].mode {
            NetStackSocketMode::Idle => {}
            NetStackSocketMode::TcpConnectInProgress => {
                self.poll_net_stack_socket(socket_id, ready_key, Some(socket_resource.id));
                self.refresh_net_stack_socket_state(index, ready_key, socket_resource);
                if self.net_stack_sockets[index].mode == NetStackSocketMode::TcpEstablished {
                    return Ok(LinuxCallResult::Ret(-(ERR_EISCONN as i64)));
                }
                return Ok(LinuxCallResult::Ret(-(ERR_EALREADY as i64)));
            }
            NetStackSocketMode::TcpEstablished => {
                return Ok(LinuxCallResult::Ret(-(ERR_EISCONN as i64)));
            }
        }

        let stack_socket_id = self.net_stack_sockets[index].stack_socket_id;
        if let Err(err) = self.net_stack.connect_tcp_ipv4(stack_socket_id, remote_ipv4, remote_port)
        {
            crate::kwarn!("smoltcp connect socket {}: {}", socket_id, err);
            return Ok(LinuxCallResult::Ret(-(ERR_EAGAIN as i64)));
        }
        self.net_stack_sockets[index].mode = NetStackSocketMode::TcpConnectInProgress;
        self.net_stack_sockets[index].remote_ipv4 = remote_ipv4;
        self.net_stack_sockets[index].remote_port = remote_port;
        self.semantic.record_socket_state_changed(socket_resource.id, "syn-sent");
        self.poll_net_stack_socket(socket_id, ready_key, Some(socket_resource.id));
        Ok(LinuxCallResult::Ret(-(ERR_EINPROGRESS as i64)))
    }

    pub(super) fn net_stack_send_socket(
        &mut self,
        socket_id: u32,
        ready_key: u64,
        socket_resource: ResourceHandle,
        bytes: &[u8],
    ) -> Result<Option<LinuxCallResult>, &'static str> {
        let Some(index) = self.net_stack_socket_index(socket_id) else {
            return Ok(None);
        };
        if self.net_stack_sockets[index].mode == NetStackSocketMode::Idle {
            return Ok(None);
        }

        self.poll_net_stack_socket(socket_id, ready_key, Some(socket_resource.id));
        self.refresh_net_stack_socket_state(index, ready_key, socket_resource);
        let stack_socket_id = self.net_stack_sockets[index].stack_socket_id;
        let snapshot = match self.net_stack.tcp_snapshot(stack_socket_id) {
            Ok(snapshot) => snapshot,
            Err(err) => {
                crate::kwarn!("smoltcp send snapshot socket {}: {}", socket_id, err);
                return Ok(Some(LinuxCallResult::Ret(-(ERR_ENOTCONN as i64))));
            }
        };
        if !snapshot.can_send {
            let errno = if snapshot.may_send { ERR_EAGAIN } else { ERR_ENOTCONN };
            return Ok(Some(LinuxCallResult::Ret(-(errno as i64))));
        }

        let count = match self.net_stack.send_tcp(stack_socket_id, bytes) {
            Ok(count) => count,
            Err(err) => {
                crate::kwarn!("smoltcp send socket {}: {}", socket_id, err);
                return Ok(Some(LinuxCallResult::Ret(-(ERR_EAGAIN as i64))));
            }
        };
        self.poll_net_stack_socket(socket_id, ready_key, Some(socket_resource.id));
        Ok(Some(LinuxCallResult::Ret(count as i64)))
    }

    pub(super) fn net_stack_recv_socket(
        &mut self,
        socket_id: u32,
        ready_key: u64,
        socket_resource: ResourceHandle,
        count: u32,
    ) -> Result<Option<LinuxCallResult>, &'static str> {
        let Some(index) = self.net_stack_socket_index(socket_id) else {
            return Ok(None);
        };
        if self.net_stack_sockets[index].mode == NetStackSocketMode::Idle {
            return Ok(None);
        }

        self.poll_net_stack_socket(socket_id, ready_key, Some(socket_resource.id));
        self.refresh_net_stack_socket_state(index, ready_key, socket_resource);
        let stack_socket_id = self.net_stack_sockets[index].stack_socket_id;
        let snapshot = match self.net_stack.tcp_snapshot(stack_socket_id) {
            Ok(snapshot) => snapshot,
            Err(err) => {
                crate::kwarn!("smoltcp recv snapshot socket {}: {}", socket_id, err);
                return Ok(Some(LinuxCallResult::Ret(-(ERR_ENOTCONN as i64))));
            }
        };
        if !snapshot.can_recv {
            let errno = if snapshot.may_recv { ERR_EAGAIN } else { ERR_ENOTCONN };
            return Ok(Some(LinuxCallResult::Ret(-(errno as i64))));
        }

        let mut out = alloc::vec![0; count as usize];
        let len = match self.net_stack.recv_tcp(stack_socket_id, &mut out) {
            Ok(len) => len,
            Err(err) => {
                crate::kwarn!("smoltcp recv socket {}: {}", socket_id, err);
                return Ok(Some(LinuxCallResult::Ret(-(ERR_EAGAIN as i64))));
            }
        };
        out.truncate(len);
        Ok(Some(LinuxCallResult::Bytes(out)))
    }

    pub(super) fn net_stack_socket_readable(
        &mut self,
        socket_id: u32,
        ready_key: u64,
        socket_resource: ResourceHandle,
    ) -> Option<bool> {
        let index = self.net_stack_socket_index(socket_id)?;
        if self.net_stack_sockets[index].mode == NetStackSocketMode::Idle {
            return None;
        }
        self.poll_net_stack_socket(socket_id, ready_key, Some(socket_resource.id));
        let index = self.net_stack_socket_index(socket_id)?;
        self.refresh_net_stack_socket_state(index, ready_key, socket_resource);
        let stack_socket_id = self.net_stack_sockets[index].stack_socket_id;
        self.net_stack.tcp_snapshot(stack_socket_id).ok().map(|snapshot| snapshot.can_recv)
    }

    pub(super) fn has_net_stack_socket(&self, socket_id: u32) -> bool {
        self.net_stack_socket_index(socket_id).is_some()
    }

    fn net_stack_socket_index(&self, socket_id: u32) -> Option<usize> {
        self.net_stack_sockets.iter().position(|binding| binding.socket_id == socket_id)
    }

    fn poll_net_stack_socket(
        &mut self,
        _socket_id: u32,
        ready_key: u64,
        socket_resource: Option<ResourceId>,
    ) {
        let now_ticks = interrupts::tick_count();
        let now_ms = net_stack_now_ms();
        self.poll_net_stack_driver_events(now_ticks);
        let _ = self.net_stack.poll(now_ms);
        while let Some(frame) = self.net_stack.take_tx_frame() {
            match self.net_driver.submit_tx_frame(now_ticks, &frame) {
                Ok(submitted) if submitted > 0 => {
                    self.semantic.record_packet_queued_for_transmit(
                        self.net.interface.id,
                        socket_resource,
                        ready_key,
                        frame.len(),
                    );
                }
                Ok(_) => {
                    crate::kwarn!("driver_virtio_net ignored smoltcp tx frame");
                }
                Err(ServiceCallError::Trap(reason)) => {
                    crate::kwarn!("driver_virtio_net submit smoltcp tx: {}", reason);
                }
                Err(ServiceCallError::Invalid(err)) => {
                    crate::kwarn!("driver_virtio_net submit smoltcp tx: {}", err);
                }
                Err(ServiceCallError::Errno(errno)) => {
                    crate::kwarn!("driver_virtio_net submit smoltcp tx errno={}", errno);
                }
            }
        }
    }

    fn poll_net_stack_driver_events(&mut self, now_ticks: u64) {
        for _ in 0..NET_STACK_DRIVER_EVENT_LIMIT {
            let event = match self.net_driver.poll_device(now_ticks) {
                Ok(event) => event,
                Err(ServiceCallError::Trap(reason)) => {
                    crate::kwarn!("driver_virtio_net poll for smoltcp: {}", reason);
                    break;
                }
                Err(ServiceCallError::Invalid(err)) => {
                    crate::kwarn!("driver_virtio_net poll for smoltcp: {}", err);
                    break;
                }
                Err(ServiceCallError::Errno(errno)) => {
                    crate::kwarn!("driver_virtio_net poll for smoltcp errno={}", errno);
                    break;
                }
            };
            match event.kind {
                DriverNetEventKind::None => break,
                DriverNetEventKind::Irq => self.semantic.record_device_irq_delivered(
                    self.net.irq.id,
                    self.net.device.id,
                    "virtio-net-rx",
                ),
                DriverNetEventKind::DmaSubmitted => self.semantic.record_dma_submitted(
                    self.net.dma_buffer.id,
                    self.net.device.id,
                    event.len as usize,
                ),
                DriverNetEventKind::DmaCompleted => self.semantic.record_dma_completed(
                    self.net.dma_buffer.id,
                    self.net.device.id,
                    event.len as usize,
                ),
                DriverNetEventKind::DriverCompletion => {
                    self.semantic.record_driver_completion(self.net.device.id, "virtio-net-rx")
                }
                DriverNetEventKind::PacketRx => {
                    self.semantic.record_packet_received(
                        self.net.interface.id,
                        None,
                        0,
                        event.frame.len(),
                    );
                    if let Err(err) = self.net_stack.enqueue_rx_frame(&event.frame) {
                        crate::kwarn!("smoltcp enqueue driver rx frame: {}", err);
                    }
                }
            }
        }
    }

    fn refresh_net_stack_socket_state(
        &mut self,
        index: usize,
        ready_key: u64,
        socket_resource: ResourceHandle,
    ) {
        let stack_socket_id = self.net_stack_sockets[index].stack_socket_id;
        let Ok(snapshot) = self.net_stack.tcp_snapshot(stack_socket_id) else {
            return;
        };
        if snapshot.state == "established"
            && self.net_stack_sockets[index].mode != NetStackSocketMode::TcpEstablished
        {
            self.net_stack_sockets[index].mode = NetStackSocketMode::TcpEstablished;
            self.semantic.record_socket_state_changed(socket_resource.id, "connected");
            self.notify_ready_key(ready_key, "smoltcp socket ready");
        }
    }
}

fn is_smoltcp_tcp_socket(domain: u32, ty: u32, protocol: u32) -> bool {
    domain == AF_INET && ty == SOCK_STREAM && (protocol == 0 || protocol == PROTO_TCP as u32)
}

fn net_stack_now_ms() -> i64 {
    let hz = interrupts::TIMER_HZ.max(1) as u64;
    let ms = interrupts::tick_count().saturating_mul(1000) / hz;
    ms.min(i64::MAX as u64) as i64
}
