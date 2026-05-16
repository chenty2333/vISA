use vmos_abi::{
    AF_INET, ERR_EAGAIN, ERR_EALREADY, ERR_EINPROGRESS, ERR_EINVAL, ERR_EMFILE, ERR_ENOSYS,
    ERR_EPERM, PlanKind, SOCK_STREAM,
};

use super::{
    linux::{LinuxCallResult, LinuxPlan},
    runtime::PrototypeRuntime,
    types::{FdEntry, FdResource, ServiceCallError},
    wait::WaitRegistration,
};
use crate::interrupts;

const SOCK_CLOEXEC: u32 = 0o2000000;
const SOCK_NONBLOCK: u32 = 0o0004000;
const FD_CLOEXEC: u32 = 1;
const O_NONBLOCK: u32 = 0o4000;

impl<'engine> PrototypeRuntime<'engine> {
    pub(super) fn plan_socket(&mut self, plan: LinuxPlan) -> Result<LinuxCallResult, &'static str> {
        if self.require_capability("linux_syscall", "linux.socket", "socket").is_err()
            || self.require_capability("net_core", "net.socket", "create").is_err()
        {
            return Ok(LinuxCallResult::Ret(-(ERR_EPERM as i64)));
        }
        let domain = u32::try_from(plan.args[0]).map_err(|_| "socket domain overflowed")?;
        let raw_ty = u32::try_from(plan.args[1]).map_err(|_| "socket type overflowed")?;
        let socket_flags = raw_ty & (SOCK_CLOEXEC | SOCK_NONBLOCK);
        let ty = raw_ty & !(SOCK_CLOEXEC | SOCK_NONBLOCK);
        let protocol = u32::try_from(plan.args[2]).map_err(|_| "socket protocol overflowed")?;
        if !self.can_allocate_fds(1) {
            return Ok(LinuxCallResult::Ret(-(vmos_abi::ERR_EMFILE as i64)));
        }
        let socket_id = match self.net_core.create_socket(domain, ty, protocol) {
            Ok(socket_id) => socket_id,
            Err(ServiceCallError::Errno(errno)) => {
                return Ok(LinuxCallResult::Ret(-(errno as i64)));
            }
            Err(ServiceCallError::Trap(reason)) => {
                crate::kwarn!("net_core create_socket: {}", reason);
                return Err("net_core trapped during socket");
            }
            Err(ServiceCallError::Invalid(err)) => return Err(err),
        };
        let ready_key = match self.net_core.ready_key(socket_id) {
            Ok(key) => key,
            Err(ServiceCallError::Errno(errno)) => {
                let _ = self.net_core.close_socket(socket_id);
                return Ok(LinuxCallResult::Ret(-(errno as i64)));
            }
            Err(ServiceCallError::Trap(reason)) => {
                let _ = self.net_core.close_socket(socket_id);
                crate::kwarn!("net_core ready_key: {}", reason);
                return Err("net_core trapped while creating socket");
            }
            Err(ServiceCallError::Invalid(err)) => {
                let _ = self.net_core.close_socket(socket_id);
                return Err(err);
            }
        };
        if let Err(err) = self.create_net_stack_socket_if_supported(socket_id, domain, ty, protocol)
        {
            let _ = self.net_core.close_socket(socket_id);
            return match err {
                ServiceCallError::Errno(errno) => Ok(LinuxCallResult::Ret(-(errno as i64))),
                ServiceCallError::Trap(reason) => {
                    crate::kwarn!("smoltcp create socket: {}", reason);
                    Err("smoltcp trapped during socket")
                }
                ServiceCallError::Invalid(err) => Err(err),
            };
        };
        match self.linux_socket.register_socket(socket_id, domain, ty, protocol, ready_key) {
            Ok(()) => {}
            Err(ServiceCallError::Errno(errno)) => {
                self.close_net_stack_socket(socket_id);
                let _ = self.net_core.close_socket(socket_id);
                return Ok(LinuxCallResult::Ret(-(errno as i64)));
            }
            Err(ServiceCallError::Trap(reason)) => {
                self.close_net_stack_socket(socket_id);
                let _ = self.net_core.close_socket(socket_id);
                crate::kwarn!("linux_socket register_socket: {}", reason);
                return Err("linux_socket_service trapped during socket");
            }
            Err(ServiceCallError::Invalid(err)) => {
                self.close_net_stack_socket(socket_id);
                let _ = self.net_core.close_socket(socket_id);
                return Err(err);
            }
        }

        let fd = match self.alloc_fd(FdEntry {
            resource: FdResource::Socket { socket_id: socket_id as u64, ready_key },
            cursor: 0,
            fd_flags: if socket_flags & SOCK_CLOEXEC != 0 { FD_CLOEXEC } else { 0 },
            status_flags: if socket_flags & SOCK_NONBLOCK != 0 { O_NONBLOCK } else { 0 },
            cursor_group: None,
        }) {
            Ok(fd) => fd,
            Err(errno) => {
                let _ = self.linux_socket.close_socket(socket_id);
                self.close_net_stack_socket(socket_id);
                let _ = self.net_core.close_socket(socket_id);
                return Ok(LinuxCallResult::Ret(-(errno as i64)));
            }
        };
        if let Some(handle) = self.fd_handle(fd) {
            self.semantic.record_socket_state_changed(handle.id, "open");
        }
        Ok(LinuxCallResult::Ret(fd as i64))
    }
    pub(super) fn plan_socket_state(
        &mut self,
        plan: LinuxPlan,
        state: &'static str,
    ) -> Result<LinuxCallResult, &'static str> {
        let operation = match plan.kind {
            PlanKind::Bind => "bind",
            PlanKind::Listen => "listen",
            PlanKind::Connect => "connect",
            _ => "socket-state",
        };
        if self.require_capability("linux_syscall", "linux.socket", operation).is_err() {
            return Ok(LinuxCallResult::Ret(-(ERR_EPERM as i64)));
        }

        let fd = u32::try_from(plan.args[0]).map_err(|_| "socket fd overflowed")?;
        let (socket_id, ready_key, handle) = match self.socket_fd_snapshot(fd) {
            Ok(snapshot) => snapshot,
            Err(ServiceCallError::Errno(errno)) => {
                return Ok(LinuxCallResult::Ret(-(errno as i64)));
            }
            Err(ServiceCallError::Trap(reason)) => {
                crate::kwarn!("socket snapshot: {}", reason);
                return Err("socket snapshot trapped");
            }
            Err(ServiceCallError::Invalid(err)) => return Err(err),
        };
        if matches!(plan.kind, PlanKind::Connect) {
            let family = u32::try_from(plan.args[3]).map_err(|_| "connect family overflowed")?;
            let remote_ipv4 =
                u32::try_from(plan.args[4]).map_err(|_| "connect ipv4 overflowed")?.to_be_bytes();
            let remote_port = u16::try_from(plan.args[5]).map_err(|_| "connect port overflowed")?;
            if family == AF_INET && remote_port != 0 && self.has_net_stack_socket(socket_id) {
                let result = self.connect_net_stack_tcp(
                    socket_id,
                    ready_key,
                    handle,
                    remote_ipv4,
                    remote_port,
                )?;
                let should_wait = matches!(
                    result,
                    LinuxCallResult::Ret(ret)
                        if ret == -(ERR_EINPROGRESS as i64) || ret == -(ERR_EALREADY as i64)
                );
                if !should_wait {
                    return Ok(result);
                }
                let status_flags = match self.file_status_flags(fd) {
                    Ok(flags) => flags,
                    Err(errno) => return Ok(LinuxCallResult::Ret(-(errno as i64))),
                };
                if status_flags & O_NONBLOCK != 0 {
                    return Ok(result);
                }
                let token = self.waits.register(
                    self.scheduler.current_task(),
                    WaitRegistration::SocketConnect { fd },
                    interrupts::tick_count(),
                    interrupts::TIMER_HZ,
                );
                self.record_wait_token(token);
                return Ok(LinuxCallResult::Pending(token));
            }
        }
        let result = match plan.kind {
            PlanKind::Bind => {
                let addr_len =
                    u32::try_from(plan.args[2]).map_err(|_| "bind addr_len overflowed")?;
                let family = u32::try_from(plan.args[3]).map_err(|_| "bind family overflowed")?;
                let local_ipv4 = u32::try_from(plan.args[4]).map_err(|_| "bind ipv4 overflowed")?;
                let local_port = u32::try_from(plan.args[5]).map_err(|_| "bind port overflowed")?;
                if family == AF_INET && self.has_net_stack_socket(socket_id) {
                    let local_ipv4 = local_ipv4.to_be_bytes();
                    let local_port =
                        u16::try_from(local_port).map_err(|_| "bind port overflowed")?;
                    if let Some(result) =
                        self.bind_net_stack_tcp(socket_id, local_ipv4, local_port)?
                    {
                        return Ok(result);
                    }
                }
                self.linux_socket.bind_socket(socket_id, addr_len, family, local_ipv4, local_port)
            }
            PlanKind::Listen => {
                let backlog =
                    u32::try_from(plan.args[1]).map_err(|_| "listen backlog overflowed")?;
                if let Some(result) = self.listen_net_stack_tcp(socket_id, ready_key, handle)? {
                    if matches!(result, LinuxCallResult::Ret(0)) {
                        match self.linux_socket.listen_socket(socket_id, backlog) {
                            Ok(()) | Err(ServiceCallError::Errno(vmos_abi::ERR_EOPNOTSUPP)) => {}
                            Err(ServiceCallError::Errno(errno)) => {
                                return Ok(LinuxCallResult::Ret(-(errno as i64)));
                            }
                            Err(ServiceCallError::Trap(reason)) => {
                                crate::kwarn!("linux_socket listen: {}", reason);
                                return Err(
                                    "linux_socket_service trapped during socket state change",
                                );
                            }
                            Err(ServiceCallError::Invalid(err)) => return Err(err),
                        }
                    }
                    return Ok(result);
                }
                self.linux_socket.listen_socket(socket_id, backlog)
            }
            PlanKind::Connect => {
                let addr_len =
                    u32::try_from(plan.args[2]).map_err(|_| "connect addr_len overflowed")?;
                let family =
                    u32::try_from(plan.args[3]).map_err(|_| "connect family overflowed")?;
                let remote_ipv4 =
                    u32::try_from(plan.args[4]).map_err(|_| "connect ipv4 overflowed")?;
                let remote_port =
                    u32::try_from(plan.args[5]).map_err(|_| "connect port overflowed")?;
                self.linux_socket.connect_socket(
                    socket_id,
                    addr_len,
                    family,
                    remote_ipv4,
                    remote_port,
                )
            }
            _ => Ok(()),
        };
        match result {
            Ok(()) => {
                self.semantic.record_socket_state_changed(handle.id, state);
                if matches!(plan.kind, PlanKind::Connect) {
                    match self.linux_socket.accept_ready_key_for_client(socket_id) {
                        Ok(Some(ready_key)) => {
                            self.notify_ready_key(ready_key, "socket accept readiness");
                            self.drain_event_queue();
                        }
                        Ok(None) | Err(ServiceCallError::Errno(_)) => {}
                        Err(ServiceCallError::Trap(reason)) => {
                            crate::kwarn!("linux_socket accept ready key: {}", reason);
                        }
                        Err(ServiceCallError::Invalid(err)) => {
                            crate::kwarn!("linux_socket accept ready key: {}", err);
                        }
                    }
                }
                Ok(LinuxCallResult::Ret(0))
            }
            Err(ServiceCallError::Errno(errno)) => Ok(LinuxCallResult::Ret(-(errno as i64))),
            Err(ServiceCallError::Trap(reason)) => {
                crate::kwarn!("linux_socket {}: {}", operation, reason);
                Err("linux_socket_service trapped during socket state change")
            }
            Err(ServiceCallError::Invalid(err)) => Err(err),
        }
    }
    pub(super) fn plan_accept(&mut self, plan: LinuxPlan) -> Result<LinuxCallResult, &'static str> {
        if self.require_capability("linux_syscall", "linux.socket", "accept").is_err()
            || self.require_capability("net_core", "net.socket", "create").is_err()
        {
            return Ok(LinuxCallResult::Ret(-(ERR_EPERM as i64)));
        }
        let fd = u32::try_from(plan.args[0]).map_err(|_| "accept fd overflowed")?;
        let flags = u32::try_from(plan.args[3]).map_err(|_| "accept flags overflowed")?;
        if flags & !(SOCK_CLOEXEC | SOCK_NONBLOCK) != 0 {
            return Ok(LinuxCallResult::Ret(-(ERR_EINVAL as i64)));
        }
        let result = self.try_accept_fd(fd, flags)?;
        if !matches!(result, LinuxCallResult::Ret(ret) if ret == -(ERR_EAGAIN as i64)) {
            return Ok(result);
        }
        let status_flags = match self.file_status_flags(fd) {
            Ok(flags) => flags,
            Err(errno) => return Ok(LinuxCallResult::Ret(-(errno as i64))),
        };
        if status_flags & O_NONBLOCK != 0 {
            return Ok(result);
        }
        let token = self.waits.register(
            self.scheduler.current_task(),
            WaitRegistration::SocketAccept { fd, flags },
            interrupts::tick_count(),
            interrupts::TIMER_HZ,
        );
        self.record_wait_token(token);
        Ok(LinuxCallResult::Pending(token))
    }

    pub(super) fn try_accept_fd(
        &mut self,
        fd: u32,
        flags: u32,
    ) -> Result<LinuxCallResult, &'static str> {
        if !self.can_allocate_fds(1) {
            return Ok(LinuxCallResult::Ret(-(ERR_EMFILE as i64)));
        }
        let (listen_socket_id, listen_ready_key, listen_handle) = match self.socket_fd_snapshot(fd)
        {
            Ok(snapshot) => snapshot,
            Err(ServiceCallError::Errno(errno)) => {
                return Ok(LinuxCallResult::Ret(-(errno as i64)));
            }
            Err(ServiceCallError::Trap(reason)) => {
                crate::kwarn!("accept socket snapshot: {}", reason);
                return Err("socket snapshot trapped during accept");
            }
            Err(ServiceCallError::Invalid(err)) => return Err(err),
        };
        let accepted_socket_id = match self.net_core.create_socket(AF_INET, SOCK_STREAM, 0) {
            Ok(socket_id) => socket_id,
            Err(ServiceCallError::Errno(errno)) => {
                return Ok(LinuxCallResult::Ret(-(errno as i64)));
            }
            Err(ServiceCallError::Trap(reason)) => {
                crate::kwarn!("net_core accept create_socket: {}", reason);
                return Err("net_core trapped during accept");
            }
            Err(ServiceCallError::Invalid(err)) => return Err(err),
        };
        let accepted_ready_key = match self.net_core.ready_key(accepted_socket_id) {
            Ok(key) => key,
            Err(ServiceCallError::Errno(errno)) => {
                let _ = self.net_core.close_socket(accepted_socket_id);
                return Ok(LinuxCallResult::Ret(-(errno as i64)));
            }
            Err(ServiceCallError::Trap(reason)) => {
                let _ = self.net_core.close_socket(accepted_socket_id);
                crate::kwarn!("net_core accept ready_key: {}", reason);
                return Err("net_core trapped during accept");
            }
            Err(ServiceCallError::Invalid(err)) => {
                let _ = self.net_core.close_socket(accepted_socket_id);
                return Err(err);
            }
        };
        if let Some(result) = self.accept_net_stack_tcp(
            listen_socket_id,
            listen_ready_key,
            listen_handle,
            accepted_socket_id,
            accepted_ready_key,
        )? {
            return self.finish_net_stack_accept_fd(
                accepted_socket_id,
                accepted_ready_key,
                flags,
                listen_handle,
                result,
            );
        }
        match self.linux_socket.accept_socket(
            listen_socket_id,
            accepted_socket_id,
            accepted_ready_key,
        ) {
            Ok(_) => {}
            Err(ServiceCallError::Errno(errno)) => {
                let _ = self.net_core.close_socket(accepted_socket_id);
                return Ok(LinuxCallResult::Ret(-(errno as i64)));
            }
            Err(ServiceCallError::Trap(reason)) => {
                let _ = self.net_core.close_socket(accepted_socket_id);
                crate::kwarn!("linux_socket accept: {}", reason);
                return Err("linux_socket_service trapped during accept");
            }
            Err(ServiceCallError::Invalid(err)) => {
                let _ = self.net_core.close_socket(accepted_socket_id);
                return Err(err);
            }
        }
        let fd_flags = if flags & SOCK_CLOEXEC != 0 { FD_CLOEXEC } else { 0 };
        let status_flags = if flags & SOCK_NONBLOCK != 0 { O_NONBLOCK } else { 0 };
        let accepted_fd = match self.alloc_fd(FdEntry {
            resource: FdResource::Socket {
                socket_id: accepted_socket_id as u64,
                ready_key: accepted_ready_key,
            },
            cursor: 0,
            fd_flags,
            status_flags,
            cursor_group: None,
        }) {
            Ok(fd) => fd,
            Err(errno) => {
                let _ = self.linux_socket.close_socket(accepted_socket_id);
                let _ = self.net_core.close_socket(accepted_socket_id);
                return Ok(LinuxCallResult::Ret(-(errno as i64)));
            }
        };
        self.semantic.record_socket_state_changed(listen_handle.id, "accept");
        if let Some(handle) = self.fd_handle(accepted_fd) {
            self.semantic.record_socket_state_changed(handle.id, "connected");
        }
        Ok(LinuxCallResult::Ret(accepted_fd as i64))
    }

    fn finish_net_stack_accept_fd(
        &mut self,
        accepted_socket_id: u32,
        accepted_ready_key: u64,
        flags: u32,
        listen_handle: semantic_core::ResourceHandle,
        accept_result: LinuxCallResult,
    ) -> Result<LinuxCallResult, &'static str> {
        if !matches!(accept_result, LinuxCallResult::Ret(0)) {
            let _ = self.net_core.close_socket(accepted_socket_id);
            return Ok(accept_result);
        }
        match self.linux_socket.register_connected_socket(
            accepted_socket_id,
            AF_INET,
            SOCK_STREAM,
            0,
            accepted_ready_key,
        ) {
            Ok(()) => {}
            Err(ServiceCallError::Errno(errno)) => {
                self.close_net_stack_socket(accepted_socket_id);
                let _ = self.net_core.close_socket(accepted_socket_id);
                return Ok(LinuxCallResult::Ret(-(errno as i64)));
            }
            Err(ServiceCallError::Trap(reason)) => {
                self.close_net_stack_socket(accepted_socket_id);
                let _ = self.net_core.close_socket(accepted_socket_id);
                crate::kwarn!("linux_socket register accepted socket: {}", reason);
                return Err("linux_socket_service trapped during smoltcp accept");
            }
            Err(ServiceCallError::Invalid(err)) => {
                self.close_net_stack_socket(accepted_socket_id);
                let _ = self.net_core.close_socket(accepted_socket_id);
                return Err(err);
            }
        }
        let fd_flags = if flags & SOCK_CLOEXEC != 0 { FD_CLOEXEC } else { 0 };
        let status_flags = if flags & SOCK_NONBLOCK != 0 { O_NONBLOCK } else { 0 };
        let accepted_fd = match self.alloc_fd(FdEntry {
            resource: FdResource::Socket {
                socket_id: accepted_socket_id as u64,
                ready_key: accepted_ready_key,
            },
            cursor: 0,
            fd_flags,
            status_flags,
            cursor_group: None,
        }) {
            Ok(fd) => fd,
            Err(errno) => {
                self.close_net_stack_socket(accepted_socket_id);
                let _ = self.linux_socket.close_socket(accepted_socket_id);
                let _ = self.net_core.close_socket(accepted_socket_id);
                return Ok(LinuxCallResult::Ret(-(errno as i64)));
            }
        };
        self.semantic.record_socket_state_changed(listen_handle.id, "accept");
        if let Some(handle) = self.fd_handle(accepted_fd) {
            self.semantic.record_socket_state_changed(handle.id, "connected");
        }
        Ok(LinuxCallResult::Ret(accepted_fd as i64))
    }
    pub(super) fn plan_sendto(&mut self, plan: LinuxPlan) -> Result<LinuxCallResult, &'static str> {
        if self.require_capability("linux_syscall", "linux.socket", "send").is_err()
            || self.require_capability("net_core", "net.socket", "send").is_err()
        {
            return Ok(LinuxCallResult::Ret(-(ERR_EPERM as i64)));
        }

        let fd = u32::try_from(plan.args[0]).map_err(|_| "sendto fd overflowed")?;
        let ptr = u32::try_from(plan.args[1]).map_err(|_| "sendto ptr overflowed")?;
        let len = u32::try_from(plan.args[2]).map_err(|_| "sendto len overflowed")?;
        let bytes = self.linux.read_bytes(ptr, len)?;
        let (socket_id, ready_key, handle) = match self.socket_fd_snapshot(fd) {
            Ok(snapshot) => snapshot,
            Err(ServiceCallError::Errno(errno)) => {
                return Ok(LinuxCallResult::Ret(-(errno as i64)));
            }
            Err(ServiceCallError::Trap(reason)) => {
                crate::kwarn!("sendto socket snapshot: {}", reason);
                return Err("socket snapshot trapped during sendto");
            }
            Err(ServiceCallError::Invalid(err)) => return Err(err),
        };
        if let Some(result) = self.net_stack_send_socket(socket_id, ready_key, handle, &bytes)? {
            return Ok(result);
        }
        match self.linux_socket.send_socket(socket_id, len) {
            Ok(_) => {}
            Err(ServiceCallError::Errno(errno)) => {
                return Ok(LinuxCallResult::Ret(-(errno as i64)));
            }
            Err(ServiceCallError::Trap(reason)) => {
                crate::kwarn!("linux_socket send: {}", reason);
                return Err("linux_socket_service trapped during sendto");
            }
            Err(ServiceCallError::Invalid(err)) => return Err(err),
        }
        match self.net_core.send_socket(socket_id, &bytes) {
            Ok(count) => {
                let frame = match self.net_core.take_tx_frame(socket_id) {
                    Ok(frame) => frame,
                    Err(ServiceCallError::Errno(errno)) => {
                        return Ok(LinuxCallResult::Ret(-(errno as i64)));
                    }
                    Err(ServiceCallError::Trap(reason)) => {
                        crate::kwarn!("net_core take_tx_frame: {}", reason);
                        return Err("net_core trapped while preparing send frame");
                    }
                    Err(ServiceCallError::Invalid(err)) => return Err(err),
                };
                match self.net_driver.submit_tx_frame(interrupts::tick_count(), &frame) {
                    Ok(_) => {}
                    Err(ServiceCallError::Errno(errno)) => {
                        return Ok(LinuxCallResult::Ret(-(errno as i64)));
                    }
                    Err(ServiceCallError::Trap(reason)) => {
                        crate::kwarn!("driver_virtio_net submit_tx_frame: {}", reason);
                        return Err("driver_virtio_net trapped while submitting tx frame");
                    }
                    Err(ServiceCallError::Invalid(err)) => return Err(err),
                }
                self.semantic.record_packet_queued_for_transmit(
                    self.net.interface.id,
                    Some(handle.id),
                    ready_key,
                    count as usize,
                );
                Ok(LinuxCallResult::Ret(count as i64))
            }
            Err(ServiceCallError::Errno(errno)) => Ok(LinuxCallResult::Ret(-(errno as i64))),
            Err(ServiceCallError::Trap(reason)) => {
                crate::kwarn!("net_core send_socket: {}", reason);
                Err("net_core trapped during sendto")
            }
            Err(ServiceCallError::Invalid(err)) => Err(err),
        }
    }
    pub(super) fn plan_recvfrom(
        &mut self,
        plan: LinuxPlan,
    ) -> Result<LinuxCallResult, &'static str> {
        if self.require_capability("linux_syscall", "linux.socket", "recv").is_err()
            || self.require_capability("net_core", "net.socket", "recv").is_err()
        {
            return Ok(LinuxCallResult::Ret(-(ERR_EPERM as i64)));
        }

        let fd = u32::try_from(plan.args[0]).map_err(|_| "recvfrom fd overflowed")?;
        let count = u32::try_from(plan.args[2]).map_err(|_| "recvfrom count overflowed")?;
        let (socket_id, ready_key, handle) = match self.socket_fd_snapshot(fd) {
            Ok(snapshot) => snapshot,
            Err(ServiceCallError::Errno(errno)) => {
                return Ok(LinuxCallResult::Ret(-(errno as i64)));
            }
            Err(ServiceCallError::Trap(reason)) => {
                crate::kwarn!("recvfrom socket snapshot: {}", reason);
                return Err("socket snapshot trapped during recvfrom");
            }
            Err(ServiceCallError::Invalid(err)) => return Err(err),
        };
        if let Some(result) = self.net_stack_recv_socket(socket_id, ready_key, handle, count)? {
            return Ok(result);
        }
        match self.net_core.recv_socket(socket_id, count) {
            Ok(bytes) => {
                let _ = self.linux_socket.recv_socket(socket_id, bytes.len() as u32);
                Ok(LinuxCallResult::Bytes(bytes))
            }
            Err(ServiceCallError::Errno(errno)) => Ok(LinuxCallResult::Ret(-(errno as i64))),
            Err(ServiceCallError::Trap(reason)) => {
                crate::kwarn!("net_core recv_socket: {}", reason);
                Err("net_core trapped during recvfrom")
            }
            Err(ServiceCallError::Invalid(err)) => Err(err),
        }
    }
    pub(super) fn plan_setsockopt(
        &mut self,
        plan: LinuxPlan,
    ) -> Result<LinuxCallResult, &'static str> {
        if self.require_capability("linux_syscall", "linux.socket", "setsockopt").is_err() {
            return Ok(LinuxCallResult::Ret(-(ERR_EPERM as i64)));
        }
        let fd = u32::try_from(plan.args[0]).map_err(|_| "setsockopt fd overflowed")?;
        let level = u32::try_from(plan.args[1]).map_err(|_| "setsockopt level overflowed")?;
        let optname = u32::try_from(plan.args[2]).map_err(|_| "setsockopt optname overflowed")?;
        let optlen = u32::try_from(plan.args[4]).map_err(|_| "setsockopt optlen overflowed")?;
        let (socket_id, _, _) = match self.socket_fd_snapshot(fd) {
            Ok(snapshot) => snapshot,
            Err(ServiceCallError::Errno(errno)) => {
                return Ok(LinuxCallResult::Ret(-(errno as i64)));
            }
            Err(ServiceCallError::Trap(reason)) => {
                crate::kwarn!("setsockopt socket snapshot: {}", reason);
                return Err("socket snapshot trapped during setsockopt");
            }
            Err(ServiceCallError::Invalid(err)) => return Err(err),
        };
        match self.linux_socket.setsockopt(socket_id, level, optname, optlen) {
            Ok(()) => Ok(LinuxCallResult::Ret(0)),
            Err(ServiceCallError::Errno(errno)) => Ok(LinuxCallResult::Ret(-(errno as i64))),
            Err(ServiceCallError::Trap(reason)) => {
                crate::kwarn!("linux_socket setsockopt: {}", reason);
                Err("linux_socket_service trapped during setsockopt")
            }
            Err(ServiceCallError::Invalid(err)) => Err(err),
        }
    }
    pub(super) fn plan_getsockopt(
        &mut self,
        plan: LinuxPlan,
    ) -> Result<LinuxCallResult, &'static str> {
        if self.require_capability("linux_syscall", "linux.socket", "getsockopt").is_err() {
            return Ok(LinuxCallResult::Ret(-(ERR_EPERM as i64)));
        }
        let fd = u32::try_from(plan.args[0]).map_err(|_| "getsockopt fd overflowed")?;
        let level = u32::try_from(plan.args[1]).map_err(|_| "getsockopt level overflowed")?;
        let optname = u32::try_from(plan.args[2]).map_err(|_| "getsockopt optname overflowed")?;
        let (socket_id, _, _) = match self.socket_fd_snapshot(fd) {
            Ok(snapshot) => snapshot,
            Err(ServiceCallError::Errno(errno)) => {
                return Ok(LinuxCallResult::Ret(-(errno as i64)));
            }
            Err(ServiceCallError::Trap(reason)) => {
                crate::kwarn!("getsockopt socket snapshot: {}", reason);
                return Err("socket snapshot trapped during getsockopt");
            }
            Err(ServiceCallError::Invalid(err)) => return Err(err),
        };
        match self.linux_socket.getsockopt(socket_id, level, optname) {
            Ok(value) => Ok(LinuxCallResult::Ret(value as i64)),
            Err(ServiceCallError::Errno(errno)) => Ok(LinuxCallResult::Ret(-(errno as i64))),
            Err(ServiceCallError::Trap(reason)) => {
                crate::kwarn!("linux_socket getsockopt: {}", reason);
                Err("linux_socket_service trapped during getsockopt")
            }
            Err(ServiceCallError::Invalid(err)) => Err(err),
        }
    }
    pub(super) fn plan_fcntl(&mut self, plan: LinuxPlan) -> Result<LinuxCallResult, &'static str> {
        const F_DUPFD: u32 = 0;
        const F_GETFD: u32 = 1;
        const F_SETFD: u32 = 2;
        const F_GETFL: u32 = 3;
        const F_SETFL: u32 = 4;
        const F_GETLK: u32 = 5;
        const F_SETLK: u32 = 6;
        const F_SETLKW: u32 = 7;
        const F_DUPFD_CLOEXEC: u32 = 1030;
        const F_SETPIPE_SZ: u32 = 1031;
        const F_GETPIPE_SZ: u32 = 1032;
        const FD_CLOEXEC: u32 = 1;

        if self.require_capability("linux_syscall", "linux.socket", "fcntl").is_err() {
            return Ok(LinuxCallResult::Ret(-(ERR_EPERM as i64)));
        }
        let fd = u32::try_from(plan.args[0]).map_err(|_| "fcntl fd overflowed")?;
        match self.validate_fd_handle(fd) {
            Ok(()) => {}
            Err(ServiceCallError::Errno(errno)) => {
                return Ok(LinuxCallResult::Ret(-(errno as i64)));
            }
            Err(ServiceCallError::Trap(reason)) => {
                crate::kwarn!("fcntl fd validation: {}", reason);
                return Err("fcntl fd validation trapped");
            }
            Err(ServiceCallError::Invalid(err)) => return Err(err),
        }
        let cmd = u32::try_from(plan.args[1]).map_err(|_| "fcntl cmd overflowed")?;
        let arg = plan.args[2];
        let ret = match cmd {
            F_DUPFD => {
                self.dup_fd_from(fd, u32::try_from(arg).map_err(|_| "fcntl arg overflowed")?)
            }
            F_DUPFD_CLOEXEC => {
                let min_fd = u32::try_from(arg).map_err(|_| "fcntl arg overflowed")?;
                self.dup_fd_from(fd, min_fd).and_then(|new_fd| {
                    self.set_fd_flags(new_fd, FD_CLOEXEC)?;
                    Ok(new_fd)
                })
            }
            F_GETFD => self.fd_flags(fd),
            F_SETFD => self.set_fd_flags(fd, (arg as u32) & FD_CLOEXEC).map(|()| 0),
            F_GETFL => self.file_status_flags(fd),
            F_SETFL => self.set_file_status_flags(fd, arg as u32).map(|()| 0),
            F_SETPIPE_SZ => {
                let requested = usize::try_from(arg).map_err(|_| "fcntl pipe size overflowed")?;
                self.set_pipe_capacity(fd, requested)
                    .and_then(|size| u32::try_from(size).map_err(|_| ERR_EINVAL))
            }
            F_GETPIPE_SZ => {
                self.pipe_capacity(fd).and_then(|size| u32::try_from(size).map_err(|_| ERR_EINVAL))
            }
            F_GETLK | F_SETLK | F_SETLKW => Err(ERR_ENOSYS),
            _ => Err(ERR_ENOSYS),
        };
        match ret {
            Ok(value) => Ok(LinuxCallResult::Ret(value as i64)),
            Err(errno) => Ok(LinuxCallResult::Ret(-(errno as i64))),
        }
    }
}
