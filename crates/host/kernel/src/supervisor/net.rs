use net_stack_adapter::DEFAULT_IPV4_ADDR;
use semantic_core::{ResourceHandle, ResourceId, ResourceKind, SemanticGraph, StoreId};
use service_core::{
    net_contract::PROTO_TCP,
    packet::{PROTO_DEMO_TCP, decode_frame},
};
use vmos_abi::{
    AF_INET, ERR_EAGAIN, ERR_EALREADY, ERR_EINPROGRESS, ERR_EINVAL, ERR_EISCONN, ERR_ENOTCONN,
    ERR_EOPNOTSUPP, SOCK_STREAM,
};

use super::{
    authority::{AuthorityPlane, SubstrateAuthorityClass, SubstrateAuthoritySpec},
    linux::LinuxCallResult,
    runtime::PrototypeRuntime,
    services::DriverNetEventKind,
    types::{FdResource, ServiceCallError},
};
use crate::interrupts;

const DEFAULT_DRIVER_PACKAGE: &str = "driver_virtio_net";
const NET_STACK_DRIVER_EVENT_LIMIT: usize = 8;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Ipv4SocketEndpoint {
    pub(crate) addr: [u8; 4],
    pub(crate) port: u16,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum NetStackSocketMode {
    Idle,
    TcpListening,
    TcpListenEstablished,
    TcpConnectInProgress,
    TcpEstablished,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct NetStackSocketBinding {
    pub(crate) socket_id: u32,
    pub(crate) stack_socket_id: u32,
    pub(crate) mode: NetStackSocketMode,
    pub(crate) local_ipv4: [u8; 4],
    pub(crate) local_port: u16,
    pub(crate) remote_ipv4: [u8; 4],
    pub(crate) remote_port: u16,
}

impl NetStackSocketBinding {
    pub(crate) const fn new(socket_id: u32, stack_socket_id: u32) -> Self {
        Self {
            socket_id,
            stack_socket_id,
            mode: NetStackSocketMode::Idle,
            local_ipv4: [0; 4],
            local_port: 0,
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
            NetStackSocketMode::TcpListening | NetStackSocketMode::TcpListenEstablished => {
                return Ok(LinuxCallResult::Ret(-(ERR_EOPNOTSUPP as i64)));
            }
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
        let local_port =
            match self.net_stack.connect_tcp_ipv4(stack_socket_id, remote_ipv4, remote_port) {
                Ok(port) => port,
                Err(err) => {
                    crate::kwarn!("smoltcp connect socket {}: {}", socket_id, err);
                    return Ok(LinuxCallResult::Ret(-(ERR_EAGAIN as i64)));
                }
            };
        self.net_stack_sockets[index].mode = NetStackSocketMode::TcpConnectInProgress;
        self.net_stack_sockets[index].local_ipv4 = DEFAULT_IPV4_ADDR;
        self.net_stack_sockets[index].local_port = local_port;
        self.net_stack_sockets[index].remote_ipv4 = remote_ipv4;
        self.net_stack_sockets[index].remote_port = remote_port;
        self.semantic.record_socket_state_changed(socket_resource.id, "syn-sent");
        self.poll_net_stack_socket(socket_id, ready_key, Some(socket_resource.id));
        let Some(index) = self.net_stack_socket_index(socket_id) else {
            return Ok(LinuxCallResult::Ret(-(ERR_EAGAIN as i64)));
        };
        self.refresh_net_stack_socket_state(index, ready_key, socket_resource);
        if self.net_stack_sockets[index].mode == NetStackSocketMode::TcpEstablished {
            return Ok(LinuxCallResult::Ret(0));
        }
        Ok(LinuxCallResult::Ret(-(ERR_EINPROGRESS as i64)))
    }

    pub(super) fn bind_net_stack_tcp(
        &mut self,
        socket_id: u32,
        local_ipv4: [u8; 4],
        local_port: u16,
    ) -> Result<Option<LinuxCallResult>, &'static str> {
        let Some(index) = self.net_stack_socket_index(socket_id) else {
            return Ok(None);
        };
        match self.net_stack_sockets[index].mode {
            NetStackSocketMode::Idle => {
                if local_ipv4 != [0; 4] && local_ipv4 != DEFAULT_IPV4_ADDR {
                    return Ok(Some(LinuxCallResult::Ret(-(ERR_EINVAL as i64))));
                }
                self.net_stack_sockets[index].local_ipv4 = local_ipv4;
                self.net_stack_sockets[index].local_port = local_port;
                Ok(None)
            }
            NetStackSocketMode::TcpListening
            | NetStackSocketMode::TcpListenEstablished
            | NetStackSocketMode::TcpConnectInProgress
            | NetStackSocketMode::TcpEstablished => {
                Ok(Some(LinuxCallResult::Ret(-(ERR_EINVAL as i64))))
            }
        }
    }

    pub(super) fn listen_net_stack_tcp(
        &mut self,
        socket_id: u32,
        ready_key: u64,
        socket_resource: ResourceHandle,
    ) -> Result<Option<LinuxCallResult>, &'static str> {
        let Some(index) = self.net_stack_socket_index(socket_id) else {
            return Ok(None);
        };
        if self.net_stack_sockets[index].local_port == 0 {
            return Ok(None);
        }
        match self.net_stack_sockets[index].mode {
            NetStackSocketMode::Idle => {}
            NetStackSocketMode::TcpListening | NetStackSocketMode::TcpListenEstablished => {
                return Ok(Some(LinuxCallResult::Ret(0)));
            }
            NetStackSocketMode::TcpConnectInProgress | NetStackSocketMode::TcpEstablished => {
                return Ok(Some(LinuxCallResult::Ret(-(ERR_EISCONN as i64))));
            }
        }

        let stack_socket_id = self.net_stack_sockets[index].stack_socket_id;
        let local_port = self.net_stack_sockets[index].local_port;
        if let Err(err) = self.net_stack.listen_tcp(stack_socket_id, local_port) {
            crate::kwarn!("smoltcp listen socket {}: {}", socket_id, err);
            return Ok(Some(LinuxCallResult::Ret(-(ERR_EAGAIN as i64))));
        }
        self.net_stack_sockets[index].mode = NetStackSocketMode::TcpListening;
        self.semantic.record_socket_state_changed(socket_resource.id, "listen");
        self.poll_net_stack_socket(socket_id, ready_key, Some(socket_resource.id));
        Ok(Some(LinuxCallResult::Ret(0)))
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

    pub(super) fn net_stack_socket_writable(
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
        self.net_stack.tcp_snapshot(stack_socket_id).ok().map(|snapshot| snapshot.can_send)
    }

    pub(super) fn net_stack_socket_connected(
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
        Some(self.net_stack_sockets[index].mode == NetStackSocketMode::TcpEstablished)
    }

    pub(super) fn net_stack_socket_accept_ready(
        &mut self,
        socket_id: u32,
        ready_key: u64,
        socket_resource: ResourceHandle,
    ) -> Option<bool> {
        let index = self.net_stack_socket_index(socket_id)?;
        if !matches!(
            self.net_stack_sockets[index].mode,
            NetStackSocketMode::TcpListening | NetStackSocketMode::TcpListenEstablished
        ) {
            return None;
        }
        self.poll_net_stack_socket(socket_id, ready_key, Some(socket_resource.id));
        let index = self.net_stack_socket_index(socket_id)?;
        self.refresh_net_stack_socket_state(index, ready_key, socket_resource);
        Some(self.net_stack_sockets[index].mode == NetStackSocketMode::TcpListenEstablished)
    }

    pub(super) fn accept_net_stack_tcp(
        &mut self,
        listen_socket_id: u32,
        listen_ready_key: u64,
        listen_resource: ResourceHandle,
        accepted_socket_id: u32,
        _accepted_ready_key: u64,
    ) -> Result<Option<LinuxCallResult>, &'static str> {
        let Some(index) = self.net_stack_socket_index(listen_socket_id) else {
            return Ok(None);
        };
        if !matches!(
            self.net_stack_sockets[index].mode,
            NetStackSocketMode::TcpListening | NetStackSocketMode::TcpListenEstablished
        ) {
            return Ok(None);
        }
        self.poll_net_stack_socket(listen_socket_id, listen_ready_key, Some(listen_resource.id));
        let Some(index) = self.net_stack_socket_index(listen_socket_id) else {
            return Ok(Some(LinuxCallResult::Ret(-(ERR_EAGAIN as i64))));
        };
        self.refresh_net_stack_socket_state(index, listen_ready_key, listen_resource);
        if self.net_stack_sockets[index].mode != NetStackSocketMode::TcpListenEstablished {
            return Ok(None);
        }

        let old_stack_socket_id = self.net_stack_sockets[index].stack_socket_id;
        let local_port = self.net_stack_sockets[index].local_port;
        let accepted_snapshot = self
            .net_stack
            .tcp_snapshot(old_stack_socket_id)
            .map_err(|_| "smoltcp accepted socket snapshot failed")?;
        let new_listener_stack_socket_id =
            self.net_stack.create_tcp_socket().map_err(|_| "smoltcp listener socket exhausted")?;
        if let Err(err) = self.net_stack.listen_tcp(new_listener_stack_socket_id, local_port) {
            if let Err(close_err) = self.net_stack.close_tcp_socket(new_listener_stack_socket_id) {
                crate::kwarn!(
                    "smoltcp cleanup socket {} after relisten failure: {}",
                    new_listener_stack_socket_id,
                    close_err
                );
            }
            crate::kwarn!("smoltcp relisten socket {}: {}", listen_socket_id, err);
            return Ok(Some(LinuxCallResult::Ret(-(ERR_EAGAIN as i64))));
        }

        self.net_stack_sockets[index].stack_socket_id = new_listener_stack_socket_id;
        self.net_stack_sockets[index].mode = NetStackSocketMode::TcpListening;
        self.net_stack_sockets[index].remote_ipv4 = [0; 4];
        self.net_stack_sockets[index].remote_port = 0;
        self.net_stack_sockets.push(NetStackSocketBinding {
            socket_id: accepted_socket_id,
            stack_socket_id: old_stack_socket_id,
            mode: NetStackSocketMode::TcpEstablished,
            local_ipv4: accepted_snapshot.local_ipv4,
            local_port: accepted_snapshot.local_port,
            remote_ipv4: accepted_snapshot.remote_ipv4,
            remote_port: accepted_snapshot.remote_port,
        });
        Ok(Some(LinuxCallResult::Ret(0)))
    }

    pub(crate) fn net_stack_socket_ipv4_endpoint(
        &self,
        socket_id: u32,
        peer: bool,
    ) -> Option<Ipv4SocketEndpoint> {
        let binding = self.net_stack_sockets.get(self.net_stack_socket_index(socket_id)?)?;
        if peer {
            if binding.mode != NetStackSocketMode::TcpEstablished || binding.remote_port == 0 {
                return None;
            }
            return Some(Ipv4SocketEndpoint {
                addr: binding.remote_ipv4,
                port: binding.remote_port,
            });
        }
        if binding.local_port == 0 {
            return None;
        }
        Some(Ipv4SocketEndpoint { addr: binding.local_ipv4, port: binding.local_port })
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
        self.poll_network_driver_events();
        self.poll_active_net_stack(socket_resource, ready_key);
    }

    pub(super) fn pump_network_runtime(&mut self) {
        self.poll_network_driver_events();
        self.poll_active_net_stack(None, 0);
    }

    pub(super) fn poll_network_driver_events(&mut self) {
        let now_ticks = interrupts::tick_count();
        for _ in 0..NET_STACK_DRIVER_EVENT_LIMIT {
            let event = match self.net_driver.poll_device(now_ticks) {
                Ok(event) => event,
                Err(ServiceCallError::Trap(reason)) => {
                    crate::kwarn!("driver_virtio_net poll: {}", reason);
                    break;
                }
                Err(ServiceCallError::Invalid(err)) => {
                    crate::kwarn!("driver_virtio_net poll: {}", err);
                    break;
                }
                Err(ServiceCallError::Errno(errno)) => {
                    crate::kwarn!("driver_virtio_net poll errno={}", errno);
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
                    self.deliver_network_driver_rx_frame(&event.frame, event.len as usize)
                }
            }
        }
    }

    fn deliver_network_driver_rx_frame(&mut self, frame: &[u8], reported_len: usize) {
        if self.driver_rx_frame_targets_net_stack(frame) {
            self.semantic.record_packet_received(self.net.interface.id, None, 0, frame.len());
            if let Err(err) = self.net_stack.enqueue_rx_frame(frame) {
                crate::kwarn!("smoltcp enqueue driver rx frame: {}", err);
                return;
            }
            self.poll_active_net_stack(None, 0);
            return;
        }

        match self.net_core.deliver_packet_frame(frame) {
            Ok(Some(ready_key)) => {
                let socket = self.socket_resource_for_ready_key(ready_key).map(|handle| handle.id);
                self.semantic.record_packet_received(
                    self.net.interface.id,
                    socket,
                    ready_key,
                    reported_len,
                );
                self.notify_ready_key(ready_key, "epoll net ready notification");
            }
            Ok(None) => {
                self.semantic.record_packet_received(self.net.interface.id, None, 0, reported_len);
            }
            Err(ServiceCallError::Trap(reason)) => {
                crate::kwarn!("net_core deliver_packet_frame: {}", reason);
            }
            Err(ServiceCallError::Invalid(err)) => {
                crate::kwarn!("net_core deliver_packet_frame: {}", err);
            }
            Err(ServiceCallError::Errno(errno)) => {
                crate::kwarn!("net_core deliver_packet_frame errno={}", errno);
            }
        }
    }

    fn driver_rx_frame_targets_net_stack(&self, frame: &[u8]) -> bool {
        self.has_active_net_stack_socket()
            && is_raw_ipv4_or_arp_ethernet_frame(frame)
            && !is_modeled_packet_frame(frame)
    }

    fn has_active_net_stack_socket(&self) -> bool {
        self.net_stack_sockets.iter().any(|binding| binding.mode != NetStackSocketMode::Idle)
    }

    fn poll_active_net_stack(&mut self, socket_resource: Option<ResourceId>, ready_key: u64) {
        if !self.has_active_net_stack_socket() {
            return;
        }
        let _ = self.net_stack.poll(net_stack_now_ms());
        self.refresh_active_net_stack_sockets();
        self.flush_net_stack_tx_frames(socket_resource, ready_key);
    }

    fn refresh_active_net_stack_sockets(&mut self) {
        let mut index = 0usize;
        while index < self.net_stack_sockets.len() {
            if self.net_stack_sockets[index].mode != NetStackSocketMode::Idle {
                let socket_id = self.net_stack_sockets[index].socket_id;
                if let Some((ready_key, handle)) =
                    self.socket_ready_snapshot_for_socket_id(socket_id)
                {
                    self.refresh_net_stack_socket_state(index, ready_key, handle);
                }
            }
            index += 1;
        }
    }

    fn socket_ready_snapshot_for_socket_id(&self, socket_id: u32) -> Option<(u64, ResourceHandle)> {
        for (fd, entry) in self.fd_table.iter().enumerate() {
            let Some(entry) = entry else {
                continue;
            };
            let FdResource::Socket { socket_id: candidate, ready_key } = &entry.resource else {
                continue;
            };
            if *candidate as u32 != socket_id {
                continue;
            }
            let handle = self.fd_handles.get(fd).copied().flatten()?;
            return Some((*ready_key, handle));
        }
        None
    }

    fn flush_net_stack_tx_frames(&mut self, socket_resource: Option<ResourceId>, ready_key: u64) {
        while let Some(frame) = self.net_stack.take_tx_frame() {
            match self.net_driver.submit_tx_frame(interrupts::tick_count(), &frame) {
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
            && self.net_stack_sockets[index].mode == NetStackSocketMode::TcpConnectInProgress
        {
            self.net_stack_sockets[index].mode = NetStackSocketMode::TcpEstablished;
            self.semantic.record_socket_state_changed(socket_resource.id, "connected");
            self.notify_ready_key(ready_key, "smoltcp socket ready");
        }
        if snapshot.state == "established"
            && self.net_stack_sockets[index].mode == NetStackSocketMode::TcpListening
        {
            self.net_stack_sockets[index].mode = NetStackSocketMode::TcpListenEstablished;
            self.semantic.record_socket_state_changed(socket_resource.id, "accept-ready");
            self.notify_ready_key(ready_key, "smoltcp listener ready");
        }
    }
}

fn is_smoltcp_tcp_socket(domain: u32, ty: u32, protocol: u32) -> bool {
    domain == AF_INET && ty == SOCK_STREAM && (protocol == 0 || protocol == PROTO_TCP as u32)
}

fn is_raw_ipv4_or_arp_ethernet_frame(frame: &[u8]) -> bool {
    if frame.len() < 14 {
        return false;
    }
    matches!(u16::from_be_bytes([frame[12], frame[13]]), 0x0800 | 0x0806)
}

fn is_modeled_packet_frame(frame: &[u8]) -> bool {
    matches!(decode_frame(frame), Ok((meta, _)) if meta.protocol == PROTO_DEMO_TCP)
}

fn net_stack_now_ms() -> i64 {
    let hz = interrupts::TIMER_HZ.max(1) as u64;
    let ms = interrupts::tick_count().saturating_mul(1000) / hz;
    ms.min(i64::MAX as u64) as i64
}
