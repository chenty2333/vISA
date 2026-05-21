use alloc::vec::Vec;

use net_stack_adapter::{DEFAULT_IPV4_ADDR, TcpSocketSnapshot};
use semantic_core::{ResourceHandle, ResourceId, ResourceKind, SemanticGraph, StoreId};
use service_core::{
    net_contract::PROTO_TCP,
    packet::{PROTO_DEMO_TCP, decode_frame},
};
use substrate_api::{PacketDeviceBackend, PacketFrameSlot};
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
const NETWORK_RUNTIME_PUMP_LIMIT: usize = 16;
const REFERENCE_PACKET_BACKEND_RX_BATCH: usize = 4;
const MAX_NET_STACK_PENDING_ACCEPTS: usize = 16;

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

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct NetStackSocketBinding {
    pub(crate) socket_id: u32,
    pub(crate) stack_socket_id: u32,
    pub(crate) mode: NetStackSocketMode,
    pub(crate) listen_backlog: u32,
    pub(crate) local_ipv4: [u8; 4],
    pub(crate) local_port: u16,
    pub(crate) remote_ipv4: [u8; 4],
    pub(crate) remote_port: u16,
    pub(crate) pending_accepts: Vec<NetStackPendingAccept>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct NetStackPendingAccept {
    pub(crate) stack_socket_id: u32,
    pub(crate) local_ipv4: [u8; 4],
    pub(crate) local_port: u16,
    pub(crate) remote_ipv4: [u8; 4],
    pub(crate) remote_port: u16,
}

impl NetStackSocketBinding {
    pub(crate) fn new(socket_id: u32, stack_socket_id: u32) -> Self {
        Self {
            socket_id,
            stack_socket_id,
            mode: NetStackSocketMode::Idle,
            listen_backlog: 0,
            local_ipv4: [0; 4],
            local_port: 0,
            remote_ipv4: [0; 4],
            remote_port: 0,
            pending_accepts: Vec::new(),
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
        for pending in binding.pending_accepts {
            if let Err(err) = self.net_stack.close_tcp_socket(pending.stack_socket_id) {
                crate::kwarn!(
                    "smoltcp close pending accepted socket {}: {}",
                    pending.stack_socket_id,
                    err
                );
            }
        }
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
        backlog: u32,
        ready_key: u64,
        socket_resource: ResourceHandle,
    ) -> Result<Option<LinuxCallResult>, &'static str> {
        let Some(index) = self.net_stack_socket_index(socket_id) else {
            return Ok(None);
        };
        if self.net_stack_sockets[index].local_port == 0 {
            return Ok(None);
        }
        let listen_backlog = normalize_net_stack_backlog(backlog);
        match self.net_stack_sockets[index].mode {
            NetStackSocketMode::Idle => {}
            NetStackSocketMode::TcpListening | NetStackSocketMode::TcpListenEstablished => {
                self.net_stack_sockets[index].listen_backlog = listen_backlog;
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
        self.net_stack_sockets[index].listen_backlog = listen_backlog;
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
            if tcp_read_half_closed(&snapshot) {
                return Ok(Some(LinuxCallResult::Bytes(Vec::new())));
            }
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
        self.net_stack
            .tcp_snapshot(stack_socket_id)
            .ok()
            .map(|snapshot| snapshot.can_recv || tcp_read_half_closed(&snapshot))
    }

    pub(super) fn net_stack_socket_read_half_closed(
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
        self.net_stack
            .tcp_snapshot(stack_socket_id)
            .ok()
            .map(|snapshot| tcp_read_half_closed(&snapshot))
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
        Some(
            !self.net_stack_sockets[index].pending_accepts.is_empty()
                || self.net_stack_sockets[index].mode == NetStackSocketMode::TcpListenEstablished,
        )
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
        if let Some(pending) = dequeue_net_stack_pending_accept(&mut self.net_stack_sockets[index])
        {
            self.net_stack_sockets.push(NetStackSocketBinding {
                socket_id: accepted_socket_id,
                stack_socket_id: pending.stack_socket_id,
                mode: NetStackSocketMode::TcpEstablished,
                listen_backlog: 0,
                local_ipv4: pending.local_ipv4,
                local_port: pending.local_port,
                remote_ipv4: pending.remote_ipv4,
                remote_port: pending.remote_port,
                pending_accepts: Vec::new(),
            });
            return Ok(Some(LinuxCallResult::Ret(0)));
        }
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
            listen_backlog: 0,
            local_ipv4: accepted_snapshot.local_ipv4,
            local_port: accepted_snapshot.local_port,
            remote_ipv4: accepted_snapshot.remote_ipv4,
            remote_port: accepted_snapshot.remote_port,
            pending_accepts: Vec::new(),
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
        self.pump_network_runtime_scoped(socket_resource, ready_key);
    }

    pub(super) fn pump_network_runtime(&mut self) {
        self.pump_network_runtime_scoped(None, 0);
    }

    fn pump_network_runtime_scoped(&mut self, socket_resource: Option<ResourceId>, ready_key: u64) {
        for _ in 0..NETWORK_RUNTIME_PUMP_LIMIT {
            if !self.pump_network_runtime_once(socket_resource, ready_key) {
                break;
            }
        }
    }

    fn pump_network_runtime_once(
        &mut self,
        socket_resource: Option<ResourceId>,
        ready_key: u64,
    ) -> bool {
        let mut progressed = false;
        progressed |= self.pump_reference_packet_backend_rx() != 0;
        progressed |= self.poll_network_driver_events() != 0;
        progressed |= self.poll_active_net_stack(socket_resource, ready_key);
        progressed |= self.pump_reference_packet_backend_tx(socket_resource, ready_key) != 0;
        progressed
    }

    fn pump_reference_packet_backend_rx(&mut self) -> usize {
        match self.net_driver.pending_rx_frames() {
            Ok(0) => {}
            Ok(_) => return 0,
            Err(err) => {
                self.warn_driver_service_error("driver_virtio_net pending rx", err);
                return 0;
            }
        }
        let mut slots: [PacketFrameSlot; REFERENCE_PACKET_BACKEND_RX_BATCH] =
            core::array::from_fn(|_| PacketFrameSlot::new());
        let frames = match self.reference_packet_backend.poll_rx(&mut slots) {
            Ok(frames) => frames,
            Err(err) => {
                crate::kwarn!("reference packet backend rx poll: {}", err);
                return 0;
            }
        };
        if frames > slots.len() {
            crate::kwarn!("reference packet backend overreported rx frames");
            return 0;
        }
        let mut delivered = 0usize;
        let now_ticks = interrupts::tick_count();
        for slot in slots.iter().take(frames) {
            let len = slot.len as usize;
            if len > slot.data.len() {
                crate::kwarn!("reference packet backend returned oversized rx frame");
                continue;
            }
            if let Err(err) = self.net_driver.deliver_rx_frame(now_ticks, &slot.data[..len]) {
                self.warn_driver_service_error("driver_virtio_net backend rx", err);
            } else {
                delivered += 1;
            }
        }
        delivered
    }

    fn pump_reference_packet_backend_tx(
        &mut self,
        socket_resource: Option<ResourceId>,
        ready_key: u64,
    ) -> usize {
        let mut submitted_count = 0usize;
        loop {
            let frame = match self.net_driver.take_tx_frame() {
                Ok(Some(frame)) => frame,
                Ok(None) => break,
                Err(err) => {
                    self.warn_driver_service_error("driver_virtio_net backend tx", err);
                    break;
                }
            };
            match self.reference_packet_backend.submit_tx(&frame) {
                Ok(()) => {
                    self.semantic.record_packet_transmitted(
                        self.net.interface.id,
                        socket_resource,
                        ready_key,
                        frame.len(),
                    );
                    match self.reference_packet_backend.take_tx_frame() {
                        Some(completed) if completed.as_slice() == frame.as_slice() => {}
                        Some(_) => {
                            crate::kwarn!("reference packet backend consumed unexpected tx frame");
                        }
                        None => {
                            crate::kwarn!("reference packet backend lost submitted tx frame");
                        }
                    }
                    submitted_count += 1;
                }
                Err(err) => {
                    crate::kwarn!("reference packet backend tx submit: {}", err);
                    if let Err(requeue_err) =
                        self.net_driver.submit_tx_frame(interrupts::tick_count(), &frame)
                    {
                        self.warn_driver_service_error(
                            "driver_virtio_net backend tx requeue",
                            requeue_err,
                        );
                    }
                    break;
                }
            }
        }
        submitted_count
    }

    fn warn_driver_service_error(&self, context: &str, err: ServiceCallError) {
        match err {
            ServiceCallError::Trap(reason) => crate::kwarn!("{}: {}", context, reason),
            ServiceCallError::Invalid(reason) => crate::kwarn!("{}: {}", context, reason),
            ServiceCallError::Errno(errno) => crate::kwarn!("{} errno={}", context, errno),
        }
    }

    pub(super) fn poll_network_driver_events(&mut self) -> usize {
        let now_ticks = interrupts::tick_count();
        let mut events = 0usize;
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
            if event.kind == DriverNetEventKind::None {
                break;
            }
            events += 1;
            match event.kind {
                DriverNetEventKind::None => unreachable!(),
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
        events
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

    fn poll_active_net_stack(
        &mut self,
        socket_resource: Option<ResourceId>,
        ready_key: u64,
    ) -> bool {
        if !self.has_active_net_stack_socket() {
            return false;
        }
        let poll = self.net_stack.poll(net_stack_now_ms());
        let progressed = poll.poll_result != "none"
            || poll.rx_frames_before != poll.rx_frames_after
            || poll.tx_frames_before != poll.tx_frames_after;
        self.refresh_active_net_stack_sockets();
        self.flush_net_stack_tx_frames(socket_resource, ready_key) != 0 || progressed
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

    fn flush_net_stack_tx_frames(
        &mut self,
        socket_resource: Option<ResourceId>,
        ready_key: u64,
    ) -> usize {
        let mut submitted_count = 0usize;
        while let Some(frame) = self.net_stack.take_tx_frame() {
            match self.net_driver.submit_tx_frame(interrupts::tick_count(), &frame) {
                Ok(submitted) if submitted > 0 => {
                    self.semantic.record_packet_queued_for_transmit(
                        self.net.interface.id,
                        socket_resource,
                        ready_key,
                        frame.len(),
                    );
                    submitted_count += 1;
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
        submitted_count
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
            if self.queue_established_listener_socket(index, &snapshot, ready_key, socket_resource)
            {
                return;
            }
            self.net_stack_sockets[index].mode = NetStackSocketMode::TcpListenEstablished;
            self.semantic.record_socket_state_changed(socket_resource.id, "accept-ready");
            self.notify_ready_key(ready_key, "smoltcp listener ready");
        }
    }

    fn queue_established_listener_socket(
        &mut self,
        index: usize,
        snapshot: &net_stack_adapter::TcpSocketSnapshot,
        ready_key: u64,
        socket_resource: ResourceHandle,
    ) -> bool {
        let backlog = self.net_stack_sockets[index].listen_backlog.max(1) as usize;
        if self.net_stack_sockets[index].pending_accepts.len() >= backlog {
            return false;
        }

        let old_stack_socket_id = self.net_stack_sockets[index].stack_socket_id;
        let local_port = self.net_stack_sockets[index].local_port;
        let Ok(new_listener_stack_socket_id) = self.net_stack.create_tcp_socket() else {
            crate::kwarn!("smoltcp listener socket exhausted while queueing accept");
            return false;
        };
        if let Err(err) = self.net_stack.listen_tcp(new_listener_stack_socket_id, local_port) {
            if let Err(close_err) = self.net_stack.close_tcp_socket(new_listener_stack_socket_id) {
                crate::kwarn!(
                    "smoltcp cleanup socket {} after queue relisten failure: {}",
                    new_listener_stack_socket_id,
                    close_err
                );
            }
            crate::kwarn!("smoltcp relisten socket after accept-ready: {}", err);
            return false;
        }

        self.net_stack_sockets[index].pending_accepts.push(NetStackPendingAccept {
            stack_socket_id: old_stack_socket_id,
            local_ipv4: snapshot.local_ipv4,
            local_port: snapshot.local_port,
            remote_ipv4: snapshot.remote_ipv4,
            remote_port: snapshot.remote_port,
        });
        self.net_stack_sockets[index].stack_socket_id = new_listener_stack_socket_id;
        self.net_stack_sockets[index].mode = NetStackSocketMode::TcpListening;
        self.net_stack_sockets[index].remote_ipv4 = [0; 4];
        self.net_stack_sockets[index].remote_port = 0;
        self.semantic.record_socket_state_changed(socket_resource.id, "accept-ready");
        self.notify_ready_key(ready_key, "smoltcp listener ready");
        true
    }
}

fn is_smoltcp_tcp_socket(domain: u32, ty: u32, protocol: u32) -> bool {
    domain == AF_INET && ty == SOCK_STREAM && (protocol == 0 || protocol == PROTO_TCP as u32)
}

fn tcp_read_half_closed(snapshot: &TcpSocketSnapshot) -> bool {
    snapshot.state == "close-wait"
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

fn normalize_net_stack_backlog(backlog: u32) -> u32 {
    backlog.max(1).min(MAX_NET_STACK_PENDING_ACCEPTS as u32)
}

fn dequeue_net_stack_pending_accept(
    binding: &mut NetStackSocketBinding,
) -> Option<NetStackPendingAccept> {
    if binding.pending_accepts.is_empty() {
        return None;
    }
    Some(binding.pending_accepts.remove(0))
}

fn net_stack_now_ms() -> i64 {
    let hz = interrupts::TIMER_HZ.max(1) as u64;
    let ms = interrupts::tick_count().saturating_mul(1000) / hz;
    ms.min(i64::MAX as u64) as i64
}

#[cfg(test)]
mod tests {
    use alloc::vec::Vec;
    use std::sync::{Mutex, MutexGuard};

    use vmos_abi::{
        AF_INET, ERR_EINTR, SOCK_STREAM, SYS_ACCEPT, SYS_ACCEPT4, SYS_BIND, SYS_CONNECT,
        SYS_LISTEN, SYS_READ, SYS_SOCKET, SYS_WRITE, SyscallContext,
    };

    use super::{LinuxCallResult, PrototypeRuntime};
    use crate::supervisor::{engine::RuntimeOnlyExecutor, types::SigAction};

    const REMOTE_MAC: [u8; 6] = [0x02, 0x00, 0x00, 0x00, 0x00, 0x02];
    const REMOTE_IPV4: [u8; 4] = [10, 0, 2, 2];
    const VMOS_IPV4: [u8; 4] = [10, 0, 2, 15];
    const ARP_FRAME_LEN: usize = 42;
    const ETHERNET_HEADER_LEN: usize = 14;
    const SOCK_CLOEXEC: u64 = 0o2000000;
    const SOCK_NONBLOCK: u64 = 0o0004000;
    const FD_CLOEXEC: u32 = 1;
    const O_NONBLOCK: u32 = 0o4000;
    static TEST_LOCK: Mutex<()> = Mutex::new(());

    fn test_runtime() -> PrototypeRuntime<'static> {
        let engine = Box::leak(Box::new(RuntimeOnlyExecutor::default()));
        PrototypeRuntime::new(engine).expect("test runtime")
    }

    fn test_guard() -> MutexGuard<'static, ()> {
        TEST_LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    fn expect_ret(result: LinuxCallResult) -> i64 {
        match result {
            LinuxCallResult::Ret(ret) => ret,
            other => panic!("expected integer return, got {other:?}"),
        }
    }

    fn expect_bytes(result: LinuxCallResult) -> Vec<u8> {
        match result {
            LinuxCallResult::Bytes(bytes) => bytes,
            other => panic!("expected bytes return, got {other:?}"),
        }
    }

    fn dispatch_ret(
        runtime: &mut PrototypeRuntime<'_>,
        label: &'static str,
        nr: u64,
        args: [u64; 6],
    ) -> i64 {
        let result = runtime
            .dispatch_linux_syscall(label, SyscallContext::new(nr, args))
            .expect("linux syscall dispatch");
        expect_ret(result)
    }

    fn dispatch_bytes(
        runtime: &mut PrototypeRuntime<'_>,
        label: &'static str,
        nr: u64,
        args: [u64; 6],
    ) -> Vec<u8> {
        let result = runtime
            .dispatch_linux_syscall(label, SyscallContext::new(nr, args))
            .expect("linux syscall dispatch");
        expect_bytes(result)
    }

    fn write_fd(runtime: &mut PrototypeRuntime<'_>, fd: i64, bytes: &[u8]) -> i64 {
        let (ptr, len) = runtime.write_linux_arg_bytes(bytes).expect("write buffer");
        dispatch_ret(runtime, "test_write", SYS_WRITE, [fd as u64, ptr as u64, len as u64, 0, 0, 0])
    }

    fn arp_request() -> [u8; ARP_FRAME_LEN] {
        let mut frame = [0u8; ARP_FRAME_LEN];
        frame[0..6].copy_from_slice(&[0xff; 6]);
        frame[6..12].copy_from_slice(&REMOTE_MAC);
        frame[12..14].copy_from_slice(&[0x08, 0x06]);
        frame[14..16].copy_from_slice(&[0x00, 0x01]);
        frame[16..18].copy_from_slice(&[0x08, 0x00]);
        frame[18] = 0x06;
        frame[19] = 0x04;
        frame[20..22].copy_from_slice(&[0x00, 0x01]);
        frame[22..28].copy_from_slice(&REMOTE_MAC);
        frame[28..32].copy_from_slice(&REMOTE_IPV4);
        frame[32..38].copy_from_slice(&[0; 6]);
        frame[38..42].copy_from_slice(&VMOS_IPV4);
        frame
    }

    fn arp_reply(
        sender_mac: [u8; 6],
        sender_ip: [u8; 4],
        target_mac: [u8; 6],
        target_ip: [u8; 4],
    ) -> [u8; ARP_FRAME_LEN] {
        let mut frame = [0u8; ARP_FRAME_LEN];
        frame[0..6].copy_from_slice(&target_mac);
        frame[6..12].copy_from_slice(&sender_mac);
        frame[12..14].copy_from_slice(&[0x08, 0x06]);
        frame[14..16].copy_from_slice(&[0x00, 0x01]);
        frame[16..18].copy_from_slice(&[0x08, 0x00]);
        frame[18] = 6;
        frame[19] = 4;
        frame[20..22].copy_from_slice(&[0x00, 0x02]);
        frame[22..28].copy_from_slice(&sender_mac);
        frame[28..32].copy_from_slice(&sender_ip);
        frame[32..38].copy_from_slice(&target_mac);
        frame[38..42].copy_from_slice(&target_ip);
        frame
    }

    fn tcp_syn_to_listener(remote_port: u16, local_port: u16, remote_seq: u32) -> Vec<u8> {
        let mut frame = alloc::vec![0u8; ETHERNET_HEADER_LEN + 20 + 20];
        frame[0..6].copy_from_slice(&service_core::net_contract::VIRTIO_NET0_CONTRACT.mac);
        frame[6..12].copy_from_slice(&REMOTE_MAC);
        frame[12..14].copy_from_slice(&[0x08, 0x00]);

        let ip_start = ETHERNET_HEADER_LEN;
        frame[ip_start] = 0x45;
        frame[ip_start + 2..ip_start + 4].copy_from_slice(&(40u16).to_be_bytes());
        frame[ip_start + 6..ip_start + 8].copy_from_slice(&0x4000u16.to_be_bytes());
        frame[ip_start + 8] = 64;
        frame[ip_start + 9] = 6;
        frame[ip_start + 12..ip_start + 16].copy_from_slice(&REMOTE_IPV4);
        frame[ip_start + 16..ip_start + 20].copy_from_slice(&VMOS_IPV4);
        let ip_checksum = internet_checksum(&frame[ip_start..ip_start + 20]);
        frame[ip_start + 10..ip_start + 12].copy_from_slice(&ip_checksum.to_be_bytes());

        let tcp_start = ip_start + 20;
        frame[tcp_start..tcp_start + 2].copy_from_slice(&remote_port.to_be_bytes());
        frame[tcp_start + 2..tcp_start + 4].copy_from_slice(&local_port.to_be_bytes());
        frame[tcp_start + 4..tcp_start + 8].copy_from_slice(&remote_seq.to_be_bytes());
        frame[tcp_start + 12] = 5 << 4;
        frame[tcp_start + 13] = 0x02;
        frame[tcp_start + 14..tcp_start + 16].copy_from_slice(&64240u16.to_be_bytes());
        let tcp_checksum = tcp_ipv4_checksum(&REMOTE_IPV4, &VMOS_IPV4, &frame[tcp_start..]);
        frame[tcp_start + 16..tcp_start + 18].copy_from_slice(&tcp_checksum.to_be_bytes());
        frame
    }

    fn tcp_syn_ack_for_syn(syn: &[u8], server_mac: [u8; 6], server_seq: u32) -> Vec<u8> {
        let syn_ip_start = ETHERNET_HEADER_LEN;
        let syn_ihl = ((syn[syn_ip_start] & 0x0f) as usize) * 4;
        let syn_tcp_start = syn_ip_start + syn_ihl;
        let client_mac: [u8; 6] = syn[6..12].try_into().expect("client mac");
        let client_ip: [u8; 4] = syn[26..30].try_into().expect("client ip");
        let server_ip: [u8; 4] = syn[30..34].try_into().expect("server ip");
        let client_port = u16::from_be_bytes([syn[syn_tcp_start], syn[syn_tcp_start + 1]]);
        let server_port = u16::from_be_bytes([syn[syn_tcp_start + 2], syn[syn_tcp_start + 3]]);
        let client_seq = u32::from_be_bytes([
            syn[syn_tcp_start + 4],
            syn[syn_tcp_start + 5],
            syn[syn_tcp_start + 6],
            syn[syn_tcp_start + 7],
        ]);

        let mut frame = alloc::vec![0u8; ETHERNET_HEADER_LEN + 20 + 20];
        frame[0..6].copy_from_slice(&client_mac);
        frame[6..12].copy_from_slice(&server_mac);
        frame[12..14].copy_from_slice(&[0x08, 0x00]);

        let ip_start = ETHERNET_HEADER_LEN;
        frame[ip_start] = 0x45;
        frame[ip_start + 2..ip_start + 4].copy_from_slice(&(40u16).to_be_bytes());
        frame[ip_start + 6..ip_start + 8].copy_from_slice(&0x4000u16.to_be_bytes());
        frame[ip_start + 8] = 64;
        frame[ip_start + 9] = 6;
        frame[ip_start + 12..ip_start + 16].copy_from_slice(&server_ip);
        frame[ip_start + 16..ip_start + 20].copy_from_slice(&client_ip);
        let ip_checksum = internet_checksum(&frame[ip_start..ip_start + 20]);
        frame[ip_start + 10..ip_start + 12].copy_from_slice(&ip_checksum.to_be_bytes());

        let tcp_start = ip_start + 20;
        frame[tcp_start..tcp_start + 2].copy_from_slice(&server_port.to_be_bytes());
        frame[tcp_start + 2..tcp_start + 4].copy_from_slice(&client_port.to_be_bytes());
        frame[tcp_start + 4..tcp_start + 8].copy_from_slice(&server_seq.to_be_bytes());
        frame[tcp_start + 8..tcp_start + 12]
            .copy_from_slice(&client_seq.wrapping_add(1).to_be_bytes());
        frame[tcp_start + 12] = 5 << 4;
        frame[tcp_start + 13] = 0x12;
        frame[tcp_start + 14..tcp_start + 16].copy_from_slice(&64240u16.to_be_bytes());
        let tcp_checksum = tcp_ipv4_checksum(&server_ip, &client_ip, &frame[tcp_start..]);
        frame[tcp_start + 16..tcp_start + 18].copy_from_slice(&tcp_checksum.to_be_bytes());
        frame
    }

    fn tcp_ack_for_syn_ack(syn_ack: &[u8]) -> Vec<u8> {
        let syn_ack_ip_start = ETHERNET_HEADER_LEN;
        let syn_ack_ihl = ((syn_ack[syn_ack_ip_start] & 0x0f) as usize) * 4;
        let syn_ack_tcp_start = syn_ack_ip_start + syn_ack_ihl;
        let server_mac: [u8; 6] = syn_ack[6..12].try_into().expect("server mac");
        let client_mac: [u8; 6] = syn_ack[0..6].try_into().expect("client mac");
        let server_ip: [u8; 4] = syn_ack[26..30].try_into().expect("server ip");
        let client_ip: [u8; 4] = syn_ack[30..34].try_into().expect("client ip");
        let server_port =
            u16::from_be_bytes([syn_ack[syn_ack_tcp_start], syn_ack[syn_ack_tcp_start + 1]]);
        let client_port =
            u16::from_be_bytes([syn_ack[syn_ack_tcp_start + 2], syn_ack[syn_ack_tcp_start + 3]]);
        let server_seq = u32::from_be_bytes([
            syn_ack[syn_ack_tcp_start + 4],
            syn_ack[syn_ack_tcp_start + 5],
            syn_ack[syn_ack_tcp_start + 6],
            syn_ack[syn_ack_tcp_start + 7],
        ]);
        let client_seq = u32::from_be_bytes([
            syn_ack[syn_ack_tcp_start + 8],
            syn_ack[syn_ack_tcp_start + 9],
            syn_ack[syn_ack_tcp_start + 10],
            syn_ack[syn_ack_tcp_start + 11],
        ]);

        let mut frame = alloc::vec![0u8; ETHERNET_HEADER_LEN + 20 + 20];
        frame[0..6].copy_from_slice(&server_mac);
        frame[6..12].copy_from_slice(&client_mac);
        frame[12..14].copy_from_slice(&[0x08, 0x00]);

        let ip_start = ETHERNET_HEADER_LEN;
        frame[ip_start] = 0x45;
        frame[ip_start + 2..ip_start + 4].copy_from_slice(&(40u16).to_be_bytes());
        frame[ip_start + 6..ip_start + 8].copy_from_slice(&0x4000u16.to_be_bytes());
        frame[ip_start + 8] = 64;
        frame[ip_start + 9] = 6;
        frame[ip_start + 12..ip_start + 16].copy_from_slice(&client_ip);
        frame[ip_start + 16..ip_start + 20].copy_from_slice(&server_ip);
        let ip_checksum = internet_checksum(&frame[ip_start..ip_start + 20]);
        frame[ip_start + 10..ip_start + 12].copy_from_slice(&ip_checksum.to_be_bytes());

        let tcp_start = ip_start + 20;
        frame[tcp_start..tcp_start + 2].copy_from_slice(&client_port.to_be_bytes());
        frame[tcp_start + 2..tcp_start + 4].copy_from_slice(&server_port.to_be_bytes());
        frame[tcp_start + 4..tcp_start + 8].copy_from_slice(&client_seq.to_be_bytes());
        frame[tcp_start + 8..tcp_start + 12]
            .copy_from_slice(&server_seq.wrapping_add(1).to_be_bytes());
        frame[tcp_start + 12] = 5 << 4;
        frame[tcp_start + 13] = 0x10;
        frame[tcp_start + 14..tcp_start + 16].copy_from_slice(&64240u16.to_be_bytes());
        let tcp_checksum = tcp_ipv4_checksum(&client_ip, &server_ip, &frame[tcp_start..]);
        frame[tcp_start + 16..tcp_start + 18].copy_from_slice(&tcp_checksum.to_be_bytes());
        frame
    }

    fn tcp_data_for_syn_ack(syn_ack: &[u8], payload: &[u8]) -> Vec<u8> {
        let syn_ack_ip_start = ETHERNET_HEADER_LEN;
        let syn_ack_ihl = ((syn_ack[syn_ack_ip_start] & 0x0f) as usize) * 4;
        let syn_ack_tcp_start = syn_ack_ip_start + syn_ack_ihl;
        let server_mac: [u8; 6] = syn_ack[6..12].try_into().expect("server mac");
        let client_mac: [u8; 6] = syn_ack[0..6].try_into().expect("client mac");
        let server_ip: [u8; 4] = syn_ack[26..30].try_into().expect("server ip");
        let client_ip: [u8; 4] = syn_ack[30..34].try_into().expect("client ip");
        let server_port =
            u16::from_be_bytes([syn_ack[syn_ack_tcp_start], syn_ack[syn_ack_tcp_start + 1]]);
        let client_port =
            u16::from_be_bytes([syn_ack[syn_ack_tcp_start + 2], syn_ack[syn_ack_tcp_start + 3]]);
        let server_seq = u32::from_be_bytes([
            syn_ack[syn_ack_tcp_start + 4],
            syn_ack[syn_ack_tcp_start + 5],
            syn_ack[syn_ack_tcp_start + 6],
            syn_ack[syn_ack_tcp_start + 7],
        ]);
        let client_seq = u32::from_be_bytes([
            syn_ack[syn_ack_tcp_start + 8],
            syn_ack[syn_ack_tcp_start + 9],
            syn_ack[syn_ack_tcp_start + 10],
            syn_ack[syn_ack_tcp_start + 11],
        ]);

        let ip_payload_len = 20usize + payload.len();
        let mut frame = alloc::vec![0u8; ETHERNET_HEADER_LEN + 20 + ip_payload_len];
        frame[0..6].copy_from_slice(&server_mac);
        frame[6..12].copy_from_slice(&client_mac);
        frame[12..14].copy_from_slice(&[0x08, 0x00]);

        let ip_start = ETHERNET_HEADER_LEN;
        frame[ip_start] = 0x45;
        frame[ip_start + 2..ip_start + 4]
            .copy_from_slice(&((20 + ip_payload_len) as u16).to_be_bytes());
        frame[ip_start + 6..ip_start + 8].copy_from_slice(&0x4000u16.to_be_bytes());
        frame[ip_start + 8] = 64;
        frame[ip_start + 9] = 6;
        frame[ip_start + 12..ip_start + 16].copy_from_slice(&client_ip);
        frame[ip_start + 16..ip_start + 20].copy_from_slice(&server_ip);
        let ip_checksum = internet_checksum(&frame[ip_start..ip_start + 20]);
        frame[ip_start + 10..ip_start + 12].copy_from_slice(&ip_checksum.to_be_bytes());

        let tcp_start = ip_start + 20;
        frame[tcp_start..tcp_start + 2].copy_from_slice(&client_port.to_be_bytes());
        frame[tcp_start + 2..tcp_start + 4].copy_from_slice(&server_port.to_be_bytes());
        frame[tcp_start + 4..tcp_start + 8].copy_from_slice(&client_seq.to_be_bytes());
        frame[tcp_start + 8..tcp_start + 12]
            .copy_from_slice(&server_seq.wrapping_add(1).to_be_bytes());
        frame[tcp_start + 12] = 5 << 4;
        frame[tcp_start + 13] = 0x18;
        frame[tcp_start + 14..tcp_start + 16].copy_from_slice(&64240u16.to_be_bytes());
        frame[tcp_start + 20..tcp_start + 20 + payload.len()].copy_from_slice(payload);
        let tcp_checksum = tcp_ipv4_checksum(&client_ip, &server_ip, &frame[tcp_start..]);
        frame[tcp_start + 16..tcp_start + 18].copy_from_slice(&tcp_checksum.to_be_bytes());
        frame
    }

    fn tcp_server_data_for_syn_ack(syn_ack: &[u8], payload: &[u8]) -> Vec<u8> {
        let syn_ack_ip_start = ETHERNET_HEADER_LEN;
        let syn_ack_ihl = ((syn_ack[syn_ack_ip_start] & 0x0f) as usize) * 4;
        let syn_ack_tcp_start = syn_ack_ip_start + syn_ack_ihl;
        let client_mac: [u8; 6] = syn_ack[0..6].try_into().expect("client mac");
        let server_mac: [u8; 6] = syn_ack[6..12].try_into().expect("server mac");
        let server_ip: [u8; 4] = syn_ack[26..30].try_into().expect("server ip");
        let client_ip: [u8; 4] = syn_ack[30..34].try_into().expect("client ip");
        let server_port =
            u16::from_be_bytes([syn_ack[syn_ack_tcp_start], syn_ack[syn_ack_tcp_start + 1]]);
        let client_port =
            u16::from_be_bytes([syn_ack[syn_ack_tcp_start + 2], syn_ack[syn_ack_tcp_start + 3]]);
        let server_seq = u32::from_be_bytes([
            syn_ack[syn_ack_tcp_start + 4],
            syn_ack[syn_ack_tcp_start + 5],
            syn_ack[syn_ack_tcp_start + 6],
            syn_ack[syn_ack_tcp_start + 7],
        ]);
        let client_seq = u32::from_be_bytes([
            syn_ack[syn_ack_tcp_start + 8],
            syn_ack[syn_ack_tcp_start + 9],
            syn_ack[syn_ack_tcp_start + 10],
            syn_ack[syn_ack_tcp_start + 11],
        ]);

        let ip_payload_len = 20usize + payload.len();
        let mut frame = alloc::vec![0u8; ETHERNET_HEADER_LEN + 20 + ip_payload_len];
        frame[0..6].copy_from_slice(&client_mac);
        frame[6..12].copy_from_slice(&server_mac);
        frame[12..14].copy_from_slice(&[0x08, 0x00]);

        let ip_start = ETHERNET_HEADER_LEN;
        frame[ip_start] = 0x45;
        frame[ip_start + 2..ip_start + 4]
            .copy_from_slice(&((20 + ip_payload_len) as u16).to_be_bytes());
        frame[ip_start + 6..ip_start + 8].copy_from_slice(&0x4000u16.to_be_bytes());
        frame[ip_start + 8] = 64;
        frame[ip_start + 9] = 6;
        frame[ip_start + 12..ip_start + 16].copy_from_slice(&server_ip);
        frame[ip_start + 16..ip_start + 20].copy_from_slice(&client_ip);
        let ip_checksum = internet_checksum(&frame[ip_start..ip_start + 20]);
        frame[ip_start + 10..ip_start + 12].copy_from_slice(&ip_checksum.to_be_bytes());

        let tcp_start = ip_start + 20;
        frame[tcp_start..tcp_start + 2].copy_from_slice(&server_port.to_be_bytes());
        frame[tcp_start + 2..tcp_start + 4].copy_from_slice(&client_port.to_be_bytes());
        frame[tcp_start + 4..tcp_start + 8]
            .copy_from_slice(&server_seq.wrapping_add(1).to_be_bytes());
        frame[tcp_start + 8..tcp_start + 12].copy_from_slice(&client_seq.to_be_bytes());
        frame[tcp_start + 12] = 5 << 4;
        frame[tcp_start + 13] = 0x18;
        frame[tcp_start + 14..tcp_start + 16].copy_from_slice(&64240u16.to_be_bytes());
        frame[tcp_start + 20..tcp_start + 20 + payload.len()].copy_from_slice(payload);
        let tcp_checksum = tcp_ipv4_checksum(&server_ip, &client_ip, &frame[tcp_start..]);
        frame[tcp_start + 16..tcp_start + 18].copy_from_slice(&tcp_checksum.to_be_bytes());
        frame
    }

    fn tcp_ipv4_checksum(src_ip: &[u8; 4], dst_ip: &[u8; 4], tcp_segment: &[u8]) -> u16 {
        let mut checksum_input = Vec::with_capacity(12 + tcp_segment.len());
        checksum_input.extend_from_slice(src_ip);
        checksum_input.extend_from_slice(dst_ip);
        checksum_input.push(0);
        checksum_input.push(6);
        checksum_input.extend_from_slice(&(tcp_segment.len() as u16).to_be_bytes());
        checksum_input.extend_from_slice(tcp_segment);
        internet_checksum(&checksum_input)
    }

    fn internet_checksum(bytes: &[u8]) -> u16 {
        let mut sum = 0u32;
        for chunk in bytes.chunks(2) {
            let word = if chunk.len() == 2 {
                u16::from_be_bytes([chunk[0], chunk[1]]) as u32
            } else {
                (chunk[0] as u32) << 8
            };
            sum = sum.wrapping_add(word);
        }
        while (sum >> 16) != 0 {
            sum = (sum & 0xffff) + (sum >> 16);
        }
        !(sum as u16)
    }

    fn take_driver_tx(runtime: &mut PrototypeRuntime<'_>) -> Vec<u8> {
        runtime.net_driver.take_tx_frame().expect("driver tx service").expect("driver tx frame")
    }

    fn is_remote_arp_request(frame: &[u8]) -> bool {
        frame.len() == ARP_FRAME_LEN
            && &frame[0..6] == &[0xff; 6]
            && &frame[12..14] == &[0x08, 0x06]
            && &frame[38..42] == &REMOTE_IPV4
    }

    fn accept_sockaddr_buffer() -> [u8; 20] {
        let mut buffer = [0u8; 20];
        buffer[16..20].copy_from_slice(&16u32.to_le_bytes());
        buffer
    }

    fn assert_sockaddr_in(bytes: &[u8], addr: [u8; 4], port: u16) {
        assert_eq!(u16::from_le_bytes(bytes[0..2].try_into().unwrap()), AF_INET as u16);
        assert_eq!(u16::from_be_bytes(bytes[2..4].try_into().unwrap()), port);
        assert_eq!(&bytes[4..8], &addr);
    }

    fn drive_reference_backend_tcp_handshake(
        runtime: &mut PrototypeRuntime<'_>,
        local_port: u16,
        remote_port: u16,
        remote_seq: u32,
    ) -> Vec<u8> {
        let syn = tcp_syn_to_listener(remote_port, local_port, remote_seq);
        runtime.reference_packet_backend.inject_rx_frame(&syn).expect("inject tcp syn");
        runtime.pump_reference_packet_backend_rx();
        runtime.poll_network_driver_events();

        let first_tx = take_driver_tx(runtime);
        let syn_ack = if is_remote_arp_request(&first_tx) {
            let arp_reply = arp_reply(
                REMOTE_MAC,
                REMOTE_IPV4,
                service_core::net_contract::VIRTIO_NET0_CONTRACT.mac,
                VMOS_IPV4,
            );
            runtime.net_driver.deliver_rx_frame(0, &arp_reply).expect("deliver arp reply");
            runtime.poll_network_driver_events();
            take_driver_tx(runtime)
        } else {
            first_tx
        };
        assert_eq!(syn_ack[47] & 0x12, 0x12);

        let ack = tcp_ack_for_syn_ack(&syn_ack);
        runtime.net_driver.deliver_rx_frame(0, &ack).expect("deliver final ack");
        runtime.poll_network_driver_events();
        syn_ack
    }

    fn drive_reference_backend_tcp_connect(
        runtime: &mut PrototypeRuntime<'_>,
        token: super::super::types::WaitToken,
        remote_port: u16,
        server_seq: u32,
    ) -> Vec<u8> {
        let arp_reply = arp_reply(
            REMOTE_MAC,
            REMOTE_IPV4,
            service_core::net_contract::VIRTIO_NET0_CONTRACT.mac,
            VMOS_IPV4,
        );
        runtime.reference_packet_backend.inject_rx_frame(&arp_reply).expect("inject arp reply");
        runtime.pump_network_runtime();

        let syn = runtime
            .reference_packet_backend
            .last_tx_frame()
            .expect("connect emitted tcp syn")
            .to_vec();
        assert_eq!(syn[47] & 0x02, 0x02);
        assert_eq!(u16::from_be_bytes([syn[36], syn[37]]), remote_port);

        let syn_ack = tcp_syn_ack_for_syn(&syn, REMOTE_MAC, server_seq);
        runtime.reference_packet_backend.inject_rx_frame(&syn_ack).expect("inject syn ack");
        let connected =
            expect_ret(runtime.block_on_wait("test_connect_resume", token).expect("connect wait"));
        assert_eq!(connected, 0);
        syn_ack
    }

    fn event_log_contains(runtime: &PrototypeRuntime<'_>, needle: &str) -> bool {
        runtime
            .semantic
            .event_log()
            .events()
            .iter()
            .any(|event| event.kind.summary().contains(needle))
    }

    fn event_log_count(runtime: &PrototypeRuntime<'_>, needle: &str) -> usize {
        runtime
            .semantic
            .event_log()
            .events()
            .iter()
            .filter(|event| event.kind.summary().contains(needle))
            .count()
    }

    #[test]
    fn kernel_reference_backend_rx_reaches_smoltcp_and_records_tx_completion() {
        let _guard = test_guard();
        let mut runtime = test_runtime();

        let fd = dispatch_ret(
            &mut runtime,
            "test_socket",
            SYS_SOCKET,
            [AF_INET as u64, SOCK_STREAM as u64, 0, 0, 0, 0],
        );
        assert!(fd >= 0);

        let local_port = 8080u64;
        assert_eq!(
            dispatch_ret(
                &mut runtime,
                "test_bind",
                SYS_BIND,
                [fd as u64, 0, 16, AF_INET as u64, 0, local_port],
            ),
            0
        );
        assert_eq!(
            dispatch_ret(&mut runtime, "test_listen", SYS_LISTEN, [fd as u64, 1, 0, 0, 0, 0]),
            0
        );

        let request = arp_request();
        runtime
            .reference_packet_backend
            .inject_rx_frame(&request)
            .expect("inject backend rx frame");
        runtime.pump_network_runtime();

        assert_eq!(runtime.reference_packet_backend.pending_rx_frames(), 0);
        assert_eq!(runtime.reference_packet_backend.pending_tx_frames(), 0);
        assert_eq!(runtime.net_driver.pending_rx_frames().expect("driver rx"), 0);
        assert_eq!(runtime.net_driver.pending_tx_frames().expect("driver tx"), 0);
        assert!(event_log_contains(&runtime, "PacketReceived"));
        assert!(event_log_contains(&runtime, "PacketTransmitted"));
    }

    #[test]
    fn network_runtime_pump_drains_batched_backend_rx_frames() {
        let _guard = test_guard();
        let mut runtime = test_runtime();

        let fd = dispatch_ret(
            &mut runtime,
            "test_socket",
            SYS_SOCKET,
            [AF_INET as u64, SOCK_STREAM as u64, 0, 0, 0, 0],
        );
        assert!(fd >= 0);

        let local_port = 8081u64;
        assert_eq!(
            dispatch_ret(
                &mut runtime,
                "test_bind",
                SYS_BIND,
                [fd as u64, 0, 16, AF_INET as u64, 0, local_port],
            ),
            0
        );
        assert_eq!(
            dispatch_ret(&mut runtime, "test_listen", SYS_LISTEN, [fd as u64, 1, 0, 0, 0, 0]),
            0
        );

        let request = arp_request();
        runtime
            .reference_packet_backend
            .inject_rx_frame(&request)
            .expect("inject first backend rx frame");
        runtime
            .reference_packet_backend
            .inject_rx_frame(&request)
            .expect("inject second backend rx frame");
        runtime.pump_network_runtime();

        assert_eq!(runtime.reference_packet_backend.pending_rx_frames(), 0);
        assert_eq!(runtime.reference_packet_backend.pending_tx_frames(), 0);
        assert_eq!(runtime.net_driver.pending_rx_frames().expect("driver rx"), 0);
        assert_eq!(runtime.net_driver.pending_tx_frames().expect("driver tx"), 0);
        assert!(event_log_count(&runtime, "PacketReceived") >= 2);
        assert!(event_log_count(&runtime, "PacketTransmitted") >= 2);
    }

    #[test]
    fn reference_backend_tcp_handshake_drives_accept_fd_with_peer_metadata() {
        let _guard = test_guard();
        let mut runtime = test_runtime();

        let listener_fd = dispatch_ret(
            &mut runtime,
            "test_socket",
            SYS_SOCKET,
            [AF_INET as u64, SOCK_STREAM as u64, 0, 0, 0, 0],
        );
        assert!(listener_fd >= 0);
        let local_port = 18080u16;
        let local_ipv4 = u32::from_be_bytes(VMOS_IPV4);
        assert_eq!(
            dispatch_ret(
                &mut runtime,
                "test_bind",
                SYS_BIND,
                [listener_fd as u64, 0, 16, AF_INET as u64, local_ipv4 as u64, local_port as u64],
            ),
            0
        );
        assert_eq!(
            dispatch_ret(
                &mut runtime,
                "test_listen",
                SYS_LISTEN,
                [listener_fd as u64, 1, 0, 0, 0, 0,],
            ),
            0
        );

        let remote_port = 40_000u16;
        drive_reference_backend_tcp_handshake(&mut runtime, local_port, remote_port, 0x0102_0304);
        let (addr_ptr, _) =
            runtime.linux.write_arg_bytes(&accept_sockaddr_buffer()).expect("accept buffer");
        let len_ptr = addr_ptr + 16;

        let accepted_fd = dispatch_ret(
            &mut runtime,
            "test_accept",
            SYS_ACCEPT,
            [listener_fd as u64, addr_ptr as u64, len_ptr as u64, 0, 0, 0],
        );
        assert!(accepted_fd >= 0);
        let written = runtime.linux.read_bytes(addr_ptr, 20).expect("accept writeback");
        assert_sockaddr_in(&written[..16], REMOTE_IPV4, remote_port);
        assert_eq!(u32::from_le_bytes(written[16..20].try_into().unwrap()), 16);
        let peer = runtime
            .socket_ipv4_endpoint(accepted_fd as u32, true)
            .expect("accepted peer endpoint")
            .expect("accepted peer");
        assert_eq!(peer.addr, REMOTE_IPV4);
        assert_eq!(peer.port, remote_port);
        assert!(event_log_contains(&runtime, "PacketReceived"));
        assert!(event_log_contains(&runtime, "accept-ready"));
    }

    #[test]
    fn packet_backed_accept_dequeues_two_established_connections_fifo() {
        let _guard = test_guard();
        let mut runtime = test_runtime();

        let listener_fd = dispatch_ret(
            &mut runtime,
            "test_socket",
            SYS_SOCKET,
            [AF_INET as u64, SOCK_STREAM as u64, 0, 0, 0, 0],
        );
        assert!(listener_fd >= 0);
        let local_port = 18083u16;
        let local_ipv4 = u32::from_be_bytes(VMOS_IPV4);
        assert_eq!(
            dispatch_ret(
                &mut runtime,
                "test_bind",
                SYS_BIND,
                [listener_fd as u64, 0, 16, AF_INET as u64, local_ipv4 as u64, local_port as u64],
            ),
            0
        );
        assert_eq!(
            dispatch_ret(
                &mut runtime,
                "test_listen",
                SYS_LISTEN,
                [listener_fd as u64, 2, 0, 0, 0, 0],
            ),
            0
        );

        let first_remote_port = 40_003u16;
        let second_remote_port = 40_004u16;
        drive_reference_backend_tcp_handshake(
            &mut runtime,
            local_port,
            first_remote_port,
            0x1112_1314,
        );
        drive_reference_backend_tcp_handshake(
            &mut runtime,
            local_port,
            second_remote_port,
            0x2122_2324,
        );

        let (addr_ptr, _) =
            runtime.linux.write_arg_bytes(&accept_sockaddr_buffer()).expect("accept buffer");
        let len_ptr = addr_ptr + 16;

        let first_fd = dispatch_ret(
            &mut runtime,
            "test_accept_first",
            SYS_ACCEPT,
            [listener_fd as u64, addr_ptr as u64, len_ptr as u64, 0, 0, 0],
        );
        assert!(first_fd >= 0);
        let first_written = runtime.linux.read_bytes(addr_ptr, 20).expect("first writeback");
        assert_sockaddr_in(&first_written[..16], REMOTE_IPV4, first_remote_port);
        assert_eq!(u32::from_le_bytes(first_written[16..20].try_into().unwrap()), 16);

        let second_fd = dispatch_ret(
            &mut runtime,
            "test_accept_second",
            SYS_ACCEPT,
            [listener_fd as u64, addr_ptr as u64, len_ptr as u64, 0, 0, 0],
        );
        assert!(second_fd >= 0);
        assert_ne!(first_fd, second_fd);
        let second_written = runtime.linux.read_bytes(addr_ptr, 20).expect("second writeback");
        assert_sockaddr_in(&second_written[..16], REMOTE_IPV4, second_remote_port);
        assert_eq!(u32::from_le_bytes(second_written[16..20].try_into().unwrap()), 16);
    }

    #[test]
    fn packet_backed_accept4_applies_fd_flags_and_peer_writeback() {
        let _guard = test_guard();
        let mut runtime = test_runtime();

        let listener_fd = dispatch_ret(
            &mut runtime,
            "test_socket",
            SYS_SOCKET,
            [AF_INET as u64, SOCK_STREAM as u64, 0, 0, 0, 0],
        );
        assert!(listener_fd >= 0);
        let local_port = 18084u16;
        let local_ipv4 = u32::from_be_bytes(VMOS_IPV4);
        assert_eq!(
            dispatch_ret(
                &mut runtime,
                "test_bind",
                SYS_BIND,
                [listener_fd as u64, 0, 16, AF_INET as u64, local_ipv4 as u64, local_port as u64],
            ),
            0
        );
        assert_eq!(
            dispatch_ret(
                &mut runtime,
                "test_listen",
                SYS_LISTEN,
                [listener_fd as u64, 1, 0, 0, 0, 0],
            ),
            0
        );

        let remote_port = 40_005u16;
        drive_reference_backend_tcp_handshake(&mut runtime, local_port, remote_port, 0x3132_3334);

        let (addr_ptr, _) =
            runtime.linux.write_arg_bytes(&accept_sockaddr_buffer()).expect("accept buffer");
        let len_ptr = addr_ptr + 16;
        let accepted_fd = dispatch_ret(
            &mut runtime,
            "test_accept4",
            SYS_ACCEPT4,
            [
                listener_fd as u64,
                addr_ptr as u64,
                len_ptr as u64,
                SOCK_CLOEXEC | SOCK_NONBLOCK,
                0,
                0,
            ],
        );
        assert!(accepted_fd >= 0);
        let accepted_fd = accepted_fd as u32;

        assert_eq!(
            runtime.fd_flags(accepted_fd).expect("accepted fd flags") & FD_CLOEXEC,
            FD_CLOEXEC
        );
        assert_eq!(
            runtime.file_status_flags(accepted_fd).expect("accepted status flags") & O_NONBLOCK,
            O_NONBLOCK
        );

        let written = runtime.linux.read_bytes(addr_ptr, 20).expect("accept4 writeback");
        assert_sockaddr_in(&written[..16], REMOTE_IPV4, remote_port);
        assert_eq!(u32::from_le_bytes(written[16..20].try_into().unwrap()), 16);
    }

    #[test]
    fn packet_backed_accepted_socket_reads_and_writes_tcp_payload() {
        let _guard = test_guard();
        let mut runtime = test_runtime();

        let listener_fd = dispatch_ret(
            &mut runtime,
            "test_socket",
            SYS_SOCKET,
            [AF_INET as u64, SOCK_STREAM as u64, 0, 0, 0, 0],
        );
        assert!(listener_fd >= 0);
        let local_port = 18085u16;
        let local_ipv4 = u32::from_be_bytes(VMOS_IPV4);
        assert_eq!(
            dispatch_ret(
                &mut runtime,
                "test_bind",
                SYS_BIND,
                [listener_fd as u64, 0, 16, AF_INET as u64, local_ipv4 as u64, local_port as u64],
            ),
            0
        );
        assert_eq!(
            dispatch_ret(
                &mut runtime,
                "test_listen",
                SYS_LISTEN,
                [listener_fd as u64, 1, 0, 0, 0, 0],
            ),
            0
        );

        let remote_port = 40_006u16;
        let syn_ack = drive_reference_backend_tcp_handshake(
            &mut runtime,
            local_port,
            remote_port,
            0x4142_4344,
        );
        let accepted_fd = dispatch_ret(
            &mut runtime,
            "test_accept",
            SYS_ACCEPT,
            [listener_fd as u64, 0, 0, 0, 0, 0],
        );
        assert!(accepted_fd >= 0);

        let payload = b"hello from packet tcp";
        let data = tcp_data_for_syn_ack(&syn_ack, payload);
        runtime.reference_packet_backend.inject_rx_frame(&data).expect("inject tcp payload");
        runtime.pump_network_runtime();

        let read = dispatch_bytes(
            &mut runtime,
            "test_read_payload",
            SYS_READ,
            [accepted_fd as u64, 0, payload.len() as u64, 0, 0, 0],
        );
        assert_eq!(read, payload);
        assert_eq!(runtime.reference_packet_backend.pending_rx_frames(), 0);
        assert_eq!(runtime.net_driver.pending_rx_frames().expect("driver rx"), 0);
        assert!(event_log_contains(&runtime, "PacketReceived"));

        let reply = b"hello back from vmos";
        assert_eq!(write_fd(&mut runtime, accepted_fd, reply), reply.len() as i64);
        let last_tx = runtime
            .reference_packet_backend
            .last_tx_frame()
            .expect("accepted socket write emitted tcp frame");
        assert_eq!(&last_tx[last_tx.len() - reply.len()..], reply);
        assert_eq!(last_tx[47] & 0x18, 0x18);
        assert!(event_log_contains(&runtime, "PacketTransmitted"));
    }

    #[test]
    fn packet_backed_connect_socket_reads_and_writes_tcp_payload() {
        let _guard = test_guard();
        let mut runtime = test_runtime();

        let fd = dispatch_ret(
            &mut runtime,
            "test_socket",
            SYS_SOCKET,
            [AF_INET as u64, SOCK_STREAM as u64, 0, 0, 0, 0],
        );
        assert!(fd >= 0);
        let remote_port = 18086u16;
        let remote_ipv4 = u32::from_be_bytes(REMOTE_IPV4);
        let pending = runtime
            .dispatch_linux_syscall_raw(
                "test_connect",
                SyscallContext::new(
                    SYS_CONNECT,
                    [fd as u64, 0, 16, AF_INET as u64, remote_ipv4 as u64, remote_port as u64],
                ),
            )
            .expect("connect dispatch");
        let token = match pending {
            LinuxCallResult::Pending(token) => token,
            other => panic!("expected pending connect, got {other:?}"),
        };

        let first_tx =
            runtime.reference_packet_backend.last_tx_frame().expect("connect emitted arp request");
        assert!(is_remote_arp_request(first_tx));

        let syn_ack =
            drive_reference_backend_tcp_connect(&mut runtime, token, remote_port, 0x5152_5354);
        let payload = b"server payload over connect";
        let data = tcp_server_data_for_syn_ack(&syn_ack, payload);
        runtime.reference_packet_backend.inject_rx_frame(&data).expect("inject tcp payload");
        runtime.pump_network_runtime();

        let read = dispatch_bytes(
            &mut runtime,
            "test_read_connected_payload",
            SYS_READ,
            [fd as u64, 0, payload.len() as u64, 0, 0, 0],
        );
        assert_eq!(read, payload);

        let reply = b"client reply over connect";
        assert_eq!(write_fd(&mut runtime, fd, reply), reply.len() as i64);
        let last_tx = runtime
            .reference_packet_backend
            .last_tx_frame()
            .expect("connected socket write emitted tcp frame");
        assert_eq!(&last_tx[last_tx.len() - reply.len()..], reply);
        assert_eq!(last_tx[47] & 0x18, 0x18);
        assert!(event_log_contains(&runtime, "connected"));
        assert!(event_log_contains(&runtime, "PacketReceived"));
        assert!(event_log_contains(&runtime, "PacketTransmitted"));
    }

    #[test]
    fn generic_blocking_accept_preserves_sockaddr_writeback_on_resume() {
        let _guard = test_guard();
        let mut runtime = test_runtime();

        let listener_fd = dispatch_ret(
            &mut runtime,
            "test_socket",
            SYS_SOCKET,
            [AF_INET as u64, SOCK_STREAM as u64, 0, 0, 0, 0],
        );
        assert!(listener_fd >= 0);
        let local_port = 18081u16;
        let local_ipv4 = u32::from_be_bytes(VMOS_IPV4);
        assert_eq!(
            dispatch_ret(
                &mut runtime,
                "test_bind",
                SYS_BIND,
                [listener_fd as u64, 0, 16, AF_INET as u64, local_ipv4 as u64, local_port as u64],
            ),
            0
        );
        assert_eq!(
            dispatch_ret(
                &mut runtime,
                "test_listen",
                SYS_LISTEN,
                [listener_fd as u64, 1, 0, 0, 0, 0],
            ),
            0
        );

        let (addr_ptr, _) =
            runtime.linux.write_arg_bytes(&accept_sockaddr_buffer()).expect("accept buffer");
        let len_ptr = addr_ptr + 16;
        let pending = runtime
            .dispatch_linux_syscall_raw(
                "test_accept",
                SyscallContext::new(
                    SYS_ACCEPT,
                    [listener_fd as u64, addr_ptr as u64, len_ptr as u64, 0, 0, 0],
                ),
            )
            .expect("accept dispatch");
        let token = match pending {
            LinuxCallResult::Pending(token) => token,
            other => panic!("expected pending accept, got {other:?}"),
        };

        let remote_port = 40_001u16;
        drive_reference_backend_tcp_handshake(&mut runtime, local_port, remote_port, 0x0506_0708);
        let accepted_fd =
            expect_ret(runtime.block_on_wait("test_accept_resume", token).expect("resume accept"));

        assert!(accepted_fd >= 0);
        let written = runtime.linux.read_bytes(addr_ptr, 20).expect("accept writeback");
        assert_sockaddr_in(&written[..16], REMOTE_IPV4, remote_port);
        assert_eq!(u32::from_le_bytes(written[16..20].try_into().unwrap()), 16);
    }

    #[test]
    fn generic_blocking_accept_signal_interrupt_leaves_listener_retryable() {
        let _guard = test_guard();
        let mut runtime = test_runtime();

        let listener_fd = dispatch_ret(
            &mut runtime,
            "test_socket",
            SYS_SOCKET,
            [AF_INET as u64, SOCK_STREAM as u64, 0, 0, 0, 0],
        );
        assert!(listener_fd >= 0);
        let local_port = 18082u16;
        let local_ipv4 = u32::from_be_bytes(VMOS_IPV4);
        assert_eq!(
            dispatch_ret(
                &mut runtime,
                "test_bind",
                SYS_BIND,
                [listener_fd as u64, 0, 16, AF_INET as u64, local_ipv4 as u64, local_port as u64],
            ),
            0
        );
        assert_eq!(
            dispatch_ret(
                &mut runtime,
                "test_listen",
                SYS_LISTEN,
                [listener_fd as u64, 1, 0, 0, 0, 0],
            ),
            0
        );

        let (addr_ptr, _) =
            runtime.linux.write_arg_bytes(&accept_sockaddr_buffer()).expect("accept buffer");
        let len_ptr = addr_ptr + 16;
        let pending = runtime
            .dispatch_linux_syscall_raw(
                "test_accept",
                SyscallContext::new(
                    SYS_ACCEPT,
                    [listener_fd as u64, addr_ptr as u64, len_ptr as u64, 0, 0, 0],
                ),
            )
            .expect("accept dispatch");
        let token = match pending {
            LinuxCallResult::Pending(token) => token,
            other => panic!("expected pending accept, got {other:?}"),
        };

        let pid = runtime.current_pid();
        let tid = runtime.current_tid();
        assert!(runtime.set_sigaction(
            pid,
            10,
            SigAction { handler: 0x4000, flags: 0, restorer: 0x5000, mask: 0 }
        ));
        runtime.queue_signal_to_thread(tid, 10, 0, pid, 0);
        let interrupted =
            expect_ret(runtime.block_on_wait("test_accept_signal", token).expect("interrupt"));
        assert_eq!(interrupted, -(ERR_EINTR as i64));
        assert_eq!(
            runtime.linux.read_bytes(addr_ptr, 20).expect("accept buffer"),
            accept_sockaddr_buffer()
        );
        let delivered = runtime.take_pending_user_handler_signal(tid).expect("signal delivery");
        assert_eq!(delivered.signal.signo, 10);

        let remote_port = 40_002u16;
        drive_reference_backend_tcp_handshake(&mut runtime, local_port, remote_port, 0x090a_0b0c);
        let accepted_fd = dispatch_ret(
            &mut runtime,
            "test_accept_retry",
            SYS_ACCEPT,
            [listener_fd as u64, addr_ptr as u64, len_ptr as u64, 0, 0, 0],
        );

        assert!(accepted_fd >= 0);
        let written = runtime.linux.read_bytes(addr_ptr, 20).expect("accept writeback");
        assert_sockaddr_in(&written[..16], REMOTE_IPV4, remote_port);
        assert_eq!(u32::from_le_bytes(written[16..20].try_into().unwrap()), 16);
    }
}
