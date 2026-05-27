use alloc::vec::Vec;

use vmos_abi::{
    AF_INET, ERR_EAGAIN, ERR_EALREADY, ERR_EBADF, ERR_EFAULT, ERR_EINPROGRESS, ERR_EINVAL,
    ERR_EMFILE, ERR_ENOSYS, ERR_ENOTCONN, ERR_EPERM, ERR_EPIPE, PlanKind, SO_ERROR, SO_RCVBUF,
    SO_SNDBUF, SOCK_STREAM, SOL_SOCKET,
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
const MSG_PEEK: u32 = 0x02;
const MSG_DONTWAIT: u32 = 0x40;
const MSG_NOSIGNAL: u32 = 0x4000;
const SIGPIPE: u8 = 13;

fn call_would_block(result: &LinuxCallResult) -> bool {
    matches!(result, LinuxCallResult::Ret(ret) if *ret == -(ERR_EAGAIN as i64))
}

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
                self.cleanup_net_core_socket(socket_id, "socket ready_key rollback");
                return Ok(LinuxCallResult::Ret(-(errno as i64)));
            }
            Err(ServiceCallError::Trap(reason)) => {
                self.cleanup_net_core_socket(socket_id, "socket ready_key trap rollback");
                crate::kwarn!("net_core ready_key: {}", reason);
                return Err("net_core trapped while creating socket");
            }
            Err(ServiceCallError::Invalid(err)) => {
                self.cleanup_net_core_socket(socket_id, "socket ready_key invalid rollback");
                return Err(err);
            }
        };
        if let Err(err) = self.create_net_stack_socket_if_supported(socket_id, domain, ty, protocol)
        {
            self.cleanup_net_core_socket(socket_id, "socket smoltcp rollback");
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
                self.cleanup_net_core_socket(socket_id, "socket register rollback");
                return Ok(LinuxCallResult::Ret(-(errno as i64)));
            }
            Err(ServiceCallError::Trap(reason)) => {
                self.close_net_stack_socket(socket_id);
                self.cleanup_net_core_socket(socket_id, "socket register trap rollback");
                crate::kwarn!("linux_socket register_socket: {}", reason);
                return Err("linux_socket_service trapped during socket");
            }
            Err(ServiceCallError::Invalid(err)) => {
                self.close_net_stack_socket(socket_id);
                self.cleanup_net_core_socket(socket_id, "socket register invalid rollback");
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
                self.cleanup_linux_socket(socket_id, "socket fd rollback");
                self.close_net_stack_socket(socket_id);
                self.cleanup_net_core_socket(socket_id, "socket fd rollback");
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
                let backlog = linux_listen_backlog_arg(plan.args[1]);
                if let Some(result) =
                    self.listen_net_stack_tcp(socket_id, backlog, ready_key, handle)?
                {
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

    pub(super) fn retry_socket_connect_wait(
        &mut self,
        fd: u32,
    ) -> Result<LinuxCallResult, &'static str> {
        let (socket_id, ready_key, handle) = match self.socket_fd_snapshot(fd) {
            Ok(snapshot) => snapshot,
            Err(ServiceCallError::Errno(errno)) => {
                return Ok(LinuxCallResult::Ret(-(errno as i64)));
            }
            Err(ServiceCallError::Trap(reason)) => {
                crate::kwarn!("socket connect retry snapshot: {}", reason);
                return Err("socket snapshot trapped during connect retry");
            }
            Err(ServiceCallError::Invalid(err)) => return Err(err),
        };
        let connected =
            self.net_stack_socket_connected(socket_id, ready_key, handle).unwrap_or(false);
        if let Some(errno) = self.take_net_stack_socket_error(socket_id) {
            return Ok(LinuxCallResult::Ret(-(errno as i64)));
        }
        if connected {
            Ok(LinuxCallResult::Ret(0))
        } else {
            Ok(LinuxCallResult::Ret(-(ERR_EALREADY as i64)))
        }
    }

    pub(super) fn plan_shutdown(
        &mut self,
        plan: LinuxPlan,
    ) -> Result<LinuxCallResult, &'static str> {
        if self.require_capability("linux_syscall", "linux.socket", "shutdown").is_err()
            || self.require_capability("net_core", "net.socket", "shutdown").is_err()
        {
            return Ok(LinuxCallResult::Ret(-(ERR_EPERM as i64)));
        }
        let fd = u32::try_from(plan.args[0]).map_err(|_| "shutdown fd overflowed")?;
        let how = u32::try_from(plan.args[1]).map_err(|_| "shutdown how overflowed")?;
        let (socket_id, ready_key, handle) = match self.socket_fd_snapshot(fd) {
            Ok(snapshot) => snapshot,
            Err(ServiceCallError::Errno(errno)) => {
                return Ok(LinuxCallResult::Ret(-(errno as i64)));
            }
            Err(ServiceCallError::Trap(reason)) => {
                crate::kwarn!("shutdown socket snapshot: {}", reason);
                return Err("socket snapshot trapped during shutdown");
            }
            Err(ServiceCallError::Invalid(err)) => return Err(err),
        };
        if let Some(result) = self.shutdown_net_stack_socket(socket_id, ready_key, handle, how)? {
            if matches!(result, LinuxCallResult::Ret(0)) {
                match self.linux_socket.shutdown_socket(socket_id, how) {
                    Ok(()) | Err(ServiceCallError::Errno(ERR_ENOTCONN)) => {}
                    Err(ServiceCallError::Errno(errno)) => {
                        return Ok(LinuxCallResult::Ret(-(errno as i64)));
                    }
                    Err(ServiceCallError::Trap(reason)) => {
                        crate::kwarn!("linux_socket shutdown: {}", reason);
                        return Err("linux_socket_service trapped during shutdown");
                    }
                    Err(ServiceCallError::Invalid(err)) => return Err(err),
                }
            }
            return Ok(result);
        }
        match self.linux_socket.shutdown_socket(socket_id, how) {
            Ok(()) => {
                self.semantic.record_socket_state_changed(handle.id, "shutdown");
                Ok(LinuxCallResult::Ret(0))
            }
            Err(ServiceCallError::Errno(errno)) => Ok(LinuxCallResult::Ret(-(errno as i64))),
            Err(ServiceCallError::Trap(reason)) => {
                crate::kwarn!("linux_socket shutdown: {}", reason);
                Err("linux_socket_service trapped during shutdown")
            }
            Err(ServiceCallError::Invalid(err)) => Err(err),
        }
    }

    pub(super) fn plan_accept(
        &mut self,
        plan: LinuxPlan,
        label: &str,
    ) -> Result<LinuxCallResult, &'static str> {
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
        let (addr_ptr, addr_len_ptr, write_addr) =
            match self.generic_accept_sockaddr_writeback(label, plan.args[1], plan.args[2]) {
                Ok(writeback) => writeback,
                Err(errno) => return Ok(LinuxCallResult::Ret(-(errno as i64))),
            };
        let result = self.try_accept_fd_with_sockaddr_writeback(
            fd,
            flags,
            addr_ptr,
            addr_len_ptr,
            write_addr,
        )?;
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
            WaitRegistration::SocketAccept { fd, flags, addr_ptr, addr_len_ptr, write_addr },
            interrupts::tick_count(),
            interrupts::TIMER_HZ,
        );
        self.record_wait_token(token);
        Ok(LinuxCallResult::Pending(token))
    }

    pub(super) fn try_accept_fd_with_sockaddr_writeback(
        &mut self,
        fd: u32,
        flags: u32,
        addr_ptr: u32,
        addr_len_ptr: u32,
        write_addr: bool,
    ) -> Result<LinuxCallResult, &'static str> {
        let result = self.try_accept_fd_raw(fd, flags)?;
        self.finish_accept_sockaddr_writeback(result, addr_ptr, addr_len_ptr, write_addr)
    }

    fn try_accept_fd_raw(&mut self, fd: u32, flags: u32) -> Result<LinuxCallResult, &'static str> {
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
                self.cleanup_net_core_socket(accepted_socket_id, "accept ready_key rollback");
                return Ok(LinuxCallResult::Ret(-(errno as i64)));
            }
            Err(ServiceCallError::Trap(reason)) => {
                self.cleanup_net_core_socket(accepted_socket_id, "accept ready_key trap rollback");
                crate::kwarn!("net_core accept ready_key: {}", reason);
                return Err("net_core trapped during accept");
            }
            Err(ServiceCallError::Invalid(err)) => {
                self.cleanup_net_core_socket(
                    accepted_socket_id,
                    "accept ready_key invalid rollback",
                );
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
                listen_socket_id,
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
                self.cleanup_net_core_socket(accepted_socket_id, "accept service rollback");
                return Ok(LinuxCallResult::Ret(-(errno as i64)));
            }
            Err(ServiceCallError::Trap(reason)) => {
                self.cleanup_net_core_socket(accepted_socket_id, "accept service trap rollback");
                crate::kwarn!("linux_socket accept: {}", reason);
                return Err("linux_socket_service trapped during accept");
            }
            Err(ServiceCallError::Invalid(err)) => {
                self.cleanup_net_core_socket(accepted_socket_id, "accept service invalid rollback");
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
                self.cleanup_linux_socket(accepted_socket_id, "accept fd rollback");
                self.cleanup_net_core_socket(accepted_socket_id, "accept fd rollback");
                return Ok(LinuxCallResult::Ret(-(errno as i64)));
            }
        };
        self.semantic.record_socket_state_changed(listen_handle.id, "accept");
        if let Some(handle) = self.fd_handle(accepted_fd) {
            self.semantic.record_socket_state_changed(handle.id, "connected");
        }
        Ok(LinuxCallResult::Ret(accepted_fd as i64))
    }

    fn generic_accept_sockaddr_writeback(
        &mut self,
        label: &str,
        addr_raw: u64,
        addr_len_raw: u64,
    ) -> Result<(u32, u32, bool), i32> {
        if label.starts_with("ring3_") || (addr_raw == 0 && addr_len_raw == 0) {
            return Ok((0, 0, false));
        }
        if addr_raw == 0 || addr_len_raw == 0 {
            return Err(ERR_EINVAL);
        }
        let addr_ptr = u32::try_from(addr_raw).map_err(|_| ERR_EFAULT)?;
        let addr_len_ptr = u32::try_from(addr_len_raw).map_err(|_| ERR_EFAULT)?;
        let len_bytes = self.linux.read_bytes(addr_len_ptr, 4).map_err(|_| ERR_EFAULT)?;
        let addr_len = u32::from_le_bytes(len_bytes.as_slice().try_into().map_err(|_| ERR_EFAULT)?);
        if !(16..=128).contains(&addr_len) {
            return Err(ERR_EINVAL);
        }
        self.linux.read_bytes(addr_ptr, addr_len).map_err(|_| ERR_EFAULT)?;
        Ok((addr_ptr, addr_len_ptr, true))
    }

    fn finish_accept_sockaddr_writeback(
        &mut self,
        result: LinuxCallResult,
        addr_ptr: u32,
        addr_len_ptr: u32,
        write_addr: bool,
    ) -> Result<LinuxCallResult, &'static str> {
        if !write_addr {
            return Ok(result);
        }
        let accepted_fd = match result {
            LinuxCallResult::Ret(fd) if fd >= 0 => {
                u32::try_from(fd).map_err(|_| "accept fd overflowed during writeback")?
            }
            other => return Ok(other),
        };
        match self.write_generic_socket_peer_sockaddr(accepted_fd, addr_ptr, addr_len_ptr) {
            Ok(()) => Ok(LinuxCallResult::Ret(accepted_fd as i64)),
            Err(errno) => {
                self.close_accept_writeback_fd(accepted_fd);
                Ok(LinuxCallResult::Ret(-(errno as i64)))
            }
        }
    }

    pub(super) fn write_generic_socket_peer_sockaddr(
        &mut self,
        fd: u32,
        addr_ptr: u32,
        addr_len_ptr: u32,
    ) -> Result<(), i32> {
        let endpoint = self
            .socket_ipv4_endpoint(fd, true)?
            .unwrap_or(super::net::Ipv4SocketEndpoint { addr: [0; 4], port: 0 });
        self.write_generic_sockaddr_in(addr_ptr, addr_len_ptr, endpoint)
    }

    fn write_generic_sockaddr_in(
        &mut self,
        addr_ptr: u32,
        addr_len_ptr: u32,
        endpoint: super::net::Ipv4SocketEndpoint,
    ) -> Result<(), i32> {
        if addr_ptr == 0 || addr_len_ptr == 0 {
            return Err(ERR_EFAULT);
        }
        let len_bytes = self.linux.read_bytes(addr_len_ptr, 4).map_err(|_| ERR_EFAULT)?;
        let addr_len = u32::from_le_bytes(len_bytes.as_slice().try_into().map_err(|_| ERR_EFAULT)?);
        if addr_len < 16 {
            return Err(ERR_EINVAL);
        }
        let mut sockaddr = [0u8; 16];
        sockaddr[..2].copy_from_slice(&(AF_INET as u16).to_le_bytes());
        sockaddr[2..4].copy_from_slice(&endpoint.port.to_be_bytes());
        sockaddr[4..8].copy_from_slice(&endpoint.addr);
        self.linux.write_bytes(addr_ptr, &sockaddr).map_err(|_| ERR_EFAULT)?;
        self.linux.write_bytes(addr_len_ptr, &16u32.to_le_bytes()).map_err(|_| ERR_EFAULT)
    }

    pub(super) fn plan_getsockname(
        &mut self,
        plan: LinuxPlan,
    ) -> Result<LinuxCallResult, &'static str> {
        if self.require_capability("linux_syscall", "linux.socket", "getsockname").is_err() {
            return Ok(LinuxCallResult::Ret(-(ERR_EPERM as i64)));
        }
        let fd = match u32::try_from(plan.args[0]) {
            Ok(fd) => fd,
            Err(_) => return Ok(LinuxCallResult::Ret(-(ERR_EBADF as i64))),
        };
        let endpoint = match self.socket_ipv4_endpoint(fd, false) {
            Ok(endpoint) => {
                endpoint.unwrap_or(super::net::Ipv4SocketEndpoint { addr: [0; 4], port: 0 })
            }
            Err(errno) => return Ok(LinuxCallResult::Ret(-(errno as i64))),
        };
        let addr_ptr = match u32::try_from(plan.args[1]) {
            Ok(ptr) => ptr,
            Err(_) => return Ok(LinuxCallResult::Ret(-(ERR_EFAULT as i64))),
        };
        let addr_len_ptr = match u32::try_from(plan.args[2]) {
            Ok(ptr) => ptr,
            Err(_) => return Ok(LinuxCallResult::Ret(-(ERR_EFAULT as i64))),
        };
        match self.write_generic_sockaddr_in(addr_ptr, addr_len_ptr, endpoint) {
            Ok(()) => Ok(LinuxCallResult::Ret(0)),
            Err(errno) => Ok(LinuxCallResult::Ret(-(errno as i64))),
        }
    }

    pub(super) fn plan_getpeername(
        &mut self,
        plan: LinuxPlan,
    ) -> Result<LinuxCallResult, &'static str> {
        if self.require_capability("linux_syscall", "linux.socket", "getpeername").is_err() {
            return Ok(LinuxCallResult::Ret(-(ERR_EPERM as i64)));
        }
        let fd = match u32::try_from(plan.args[0]) {
            Ok(fd) => fd,
            Err(_) => return Ok(LinuxCallResult::Ret(-(ERR_EBADF as i64))),
        };
        let endpoint = match self.socket_ipv4_endpoint(fd, true) {
            Ok(Some(endpoint)) => endpoint,
            Ok(None) => return Ok(LinuxCallResult::Ret(-(ERR_ENOTCONN as i64))),
            Err(errno) => return Ok(LinuxCallResult::Ret(-(errno as i64))),
        };
        let addr_ptr = match u32::try_from(plan.args[1]) {
            Ok(ptr) => ptr,
            Err(_) => return Ok(LinuxCallResult::Ret(-(ERR_EFAULT as i64))),
        };
        let addr_len_ptr = match u32::try_from(plan.args[2]) {
            Ok(ptr) => ptr,
            Err(_) => return Ok(LinuxCallResult::Ret(-(ERR_EFAULT as i64))),
        };
        match self.write_generic_sockaddr_in(addr_ptr, addr_len_ptr, endpoint) {
            Ok(()) => Ok(LinuxCallResult::Ret(0)),
            Err(errno) => Ok(LinuxCallResult::Ret(-(errno as i64))),
        }
    }

    fn finish_net_stack_accept_fd(
        &mut self,
        listen_socket_id: u32,
        accepted_socket_id: u32,
        accepted_ready_key: u64,
        flags: u32,
        listen_handle: semantic_core::ResourceHandle,
        accept_result: LinuxCallResult,
    ) -> Result<LinuxCallResult, &'static str> {
        if !matches!(accept_result, LinuxCallResult::Ret(0)) {
            self.cleanup_net_core_socket(accepted_socket_id, "smoltcp accept nonready rollback");
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
                self.cleanup_net_core_socket(
                    accepted_socket_id,
                    "smoltcp accept register rollback",
                );
                return Ok(LinuxCallResult::Ret(-(errno as i64)));
            }
            Err(ServiceCallError::Trap(reason)) => {
                self.close_net_stack_socket(accepted_socket_id);
                self.cleanup_net_core_socket(
                    accepted_socket_id,
                    "smoltcp accept register trap rollback",
                );
                crate::kwarn!("linux_socket register accepted socket: {}", reason);
                return Err("linux_socket_service trapped during smoltcp accept");
            }
            Err(ServiceCallError::Invalid(err)) => {
                self.close_net_stack_socket(accepted_socket_id);
                self.cleanup_net_core_socket(
                    accepted_socket_id,
                    "smoltcp accept register invalid rollback",
                );
                return Err(err);
            }
        }
        if let Err(err) =
            self.inherit_net_stack_accept_socket_buffers(listen_socket_id, accepted_socket_id)
        {
            self.close_net_stack_socket(accepted_socket_id);
            self.cleanup_linux_socket(accepted_socket_id, "smoltcp accept option rollback");
            self.cleanup_net_core_socket(accepted_socket_id, "smoltcp accept option rollback");
            return match err {
                ServiceCallError::Errno(errno) => Ok(LinuxCallResult::Ret(-(errno as i64))),
                ServiceCallError::Trap(reason) => {
                    crate::kwarn!("linux_socket inherit accepted buffers: {}", reason);
                    Err("linux_socket_service trapped during smoltcp accept option inheritance")
                }
                ServiceCallError::Invalid(err) => Err(err),
            };
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
                self.cleanup_linux_socket(accepted_socket_id, "smoltcp accept fd rollback");
                self.cleanup_net_core_socket(accepted_socket_id, "smoltcp accept fd rollback");
                return Ok(LinuxCallResult::Ret(-(errno as i64)));
            }
        };
        self.semantic.record_socket_state_changed(listen_handle.id, "accept");
        if let Some(handle) = self.fd_handle(accepted_fd) {
            self.semantic.record_socket_state_changed(handle.id, "connected");
        }
        Ok(LinuxCallResult::Ret(accepted_fd as i64))
    }

    fn inherit_net_stack_accept_socket_buffers(
        &mut self,
        listen_socket_id: u32,
        accepted_socket_id: u32,
    ) -> Result<(), ServiceCallError> {
        for optname in [SO_RCVBUF, SO_SNDBUF] {
            let reported = self.linux_socket.getsockopt(listen_socket_id, SOL_SOCKET, optname)?;
            self.linux_socket.setsockopt(
                accepted_socket_id,
                SOL_SOCKET,
                optname,
                4,
                reported / 2,
            )?;
        }
        Ok(())
    }

    pub(super) fn plan_sendto(&mut self, plan: LinuxPlan) -> Result<LinuxCallResult, &'static str> {
        if let Err(result) = self.require_socket_send_capability() {
            return Ok(result);
        }
        let fd = u32::try_from(plan.args[0]).map_err(|_| "sendto fd overflowed")?;
        let ptr = u32::try_from(plan.args[1]).map_err(|_| "sendto ptr overflowed")?;
        let len = u32::try_from(plan.args[2]).map_err(|_| "sendto len overflowed")?;
        let flags = plan.args[3] as u32;
        self.send_socket_arg_bytes_from_fd_authorized(fd, ptr, len, flags)
    }

    fn send_socket_arg_bytes_from_fd_authorized(
        &mut self,
        fd: u32,
        ptr: u32,
        len: u32,
        flags: u32,
    ) -> Result<LinuxCallResult, &'static str> {
        let bytes = self.linux.read_bytes(ptr, len)?;
        let result = self.try_sendto_fd(fd, len, &bytes)?;
        if matches!(result, LinuxCallResult::Ret(ret) if ret == -(ERR_EPIPE as i64))
            && flags & MSG_NOSIGNAL == 0
        {
            self.queue_sigpipe_for_current_thread();
        }
        if !call_would_block(&result) {
            return Ok(result);
        }

        let status_flags = match self.file_status_flags(fd) {
            Ok(flags) => flags,
            Err(errno) => return Ok(LinuxCallResult::Ret(-(errno as i64))),
        };
        if status_flags & O_NONBLOCK != 0 || flags & MSG_DONTWAIT != 0 {
            return Ok(result);
        }

        let token = self.waits.register(
            self.scheduler.current_task(),
            WaitRegistration::SocketSend { fd, ptr, len, flags },
            interrupts::tick_count(),
            interrupts::TIMER_HZ,
        );
        self.record_wait_token(token);
        Ok(LinuxCallResult::Pending(token))
    }

    pub(super) fn retry_socket_send_wait(
        &mut self,
        fd: u32,
        ptr: u32,
        len: u32,
        flags: u32,
    ) -> Result<LinuxCallResult, &'static str> {
        let bytes = self.linux.read_bytes(ptr, len)?;
        let result = self.try_sendto_fd(fd, len, &bytes)?;
        if matches!(result, LinuxCallResult::Ret(ret) if ret == -(ERR_EPIPE as i64))
            && flags & MSG_NOSIGNAL == 0
        {
            self.queue_sigpipe_for_current_thread();
        }
        Ok(result)
    }

    pub(super) fn send_socket_bytes_from_fd_authorized(
        &mut self,
        fd: u32,
        bytes: &[u8],
        flags: u32,
    ) -> Result<LinuxCallResult, &'static str> {
        let len = u32::try_from(bytes.len()).map_err(|_| "sendto len overflowed")?;
        let result = self.try_sendto_fd(fd, len, bytes)?;
        if matches!(result, LinuxCallResult::Ret(ret) if ret == -(ERR_EPIPE as i64))
            && flags & MSG_NOSIGNAL == 0
        {
            self.queue_sigpipe_for_current_thread();
        }
        if !call_would_block(&result) {
            return Ok(result);
        }

        let status_flags = match self.file_status_flags(fd) {
            Ok(flags) => flags,
            Err(errno) => return Ok(LinuxCallResult::Ret(-(errno as i64))),
        };
        if status_flags & O_NONBLOCK != 0 || flags & MSG_DONTWAIT != 0 {
            return Ok(result);
        }

        let (ptr, copied_len) = self.linux.write_arg_bytes(bytes)?;
        let token = self.waits.register(
            self.scheduler.current_task(),
            WaitRegistration::SocketSend { fd, ptr, len: copied_len, flags },
            interrupts::tick_count(),
            interrupts::TIMER_HZ,
        );
        self.record_wait_token(token);
        Ok(LinuxCallResult::Pending(token))
    }

    fn queue_sigpipe_for_current_thread(&mut self) {
        self.queue_signal_to_thread(self.current_tid(), SIGPIPE, 0, self.current_pid(), 0);
    }

    pub(super) fn require_socket_send_capability(&mut self) -> Result<(), LinuxCallResult> {
        if self.require_capability("linux_syscall", "linux.socket", "send").is_err()
            || self.require_capability("net_core", "net.socket", "send").is_err()
        {
            Err(LinuxCallResult::Ret(-(ERR_EPERM as i64)))
        } else {
            Ok(())
        }
    }

    fn try_sendto_fd(
        &mut self,
        fd: u32,
        len: u32,
        bytes: &[u8],
    ) -> Result<LinuxCallResult, &'static str> {
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
        label: &str,
    ) -> Result<LinuxCallResult, &'static str> {
        if let Err(result) = self.require_socket_recv_capability() {
            return Ok(result);
        }
        let fd = u32::try_from(plan.args[0]).map_err(|_| "recvfrom fd overflowed")?;
        let count = u32::try_from(plan.args[2]).map_err(|_| "recvfrom count overflowed")?;
        let flags = plan.args[3] as u32;
        let (addr_ptr, addr_len_ptr, write_addr) =
            match self.generic_recvfrom_sockaddr_writeback(label, plan.args[4], plan.args[5]) {
                Ok(writeback) => writeback,
                Err(errno) => return Ok(LinuxCallResult::Ret(-(errno as i64))),
            };
        self.recvfrom_socket_bytes_from_fd_authorized(
            fd,
            count,
            flags,
            addr_ptr,
            addr_len_ptr,
            write_addr,
        )
    }

    fn recvfrom_socket_bytes_from_fd_authorized(
        &mut self,
        fd: u32,
        count: u32,
        flags: u32,
        addr_ptr: u32,
        addr_len_ptr: u32,
        write_addr: bool,
    ) -> Result<LinuxCallResult, &'static str> {
        let result = self.try_recvfrom_fd(fd, count, flags)?;
        match self.socket_recv_wait_allowed(fd, flags, &result) {
            Ok(false) => self.finish_recvfrom_sockaddr_writeback(
                result,
                fd,
                addr_ptr,
                addr_len_ptr,
                write_addr,
            ),
            Ok(true) => {
                let token = self.waits.register(
                    self.scheduler.current_task(),
                    WaitRegistration::SocketRecv {
                        fd,
                        count,
                        flags,
                        addr_ptr,
                        addr_len_ptr,
                        write_addr,
                    },
                    interrupts::tick_count(),
                    interrupts::TIMER_HZ,
                );
                self.record_wait_token(token);
                Ok(LinuxCallResult::Pending(token))
            }
            Err(error_result) => Ok(error_result),
        }
    }

    pub(super) fn retry_socket_recv_wait(
        &mut self,
        fd: u32,
        count: u32,
        flags: u32,
        addr_ptr: u32,
        addr_len_ptr: u32,
        write_addr: bool,
    ) -> Result<LinuxCallResult, &'static str> {
        let result = self.try_recvfrom_fd(fd, count, flags)?;
        self.finish_recvfrom_sockaddr_writeback(result, fd, addr_ptr, addr_len_ptr, write_addr)
    }

    pub(super) fn require_socket_recv_capability(&mut self) -> Result<(), LinuxCallResult> {
        if self.require_capability("linux_syscall", "linux.socket", "recv").is_err()
            || self.require_capability("net_core", "net.socket", "recv").is_err()
        {
            Err(LinuxCallResult::Ret(-(ERR_EPERM as i64)))
        } else {
            Ok(())
        }
    }

    pub(super) fn socket_recv_wait_allowed(
        &self,
        fd: u32,
        flags: u32,
        result: &LinuxCallResult,
    ) -> Result<bool, LinuxCallResult> {
        if !call_would_block(result) {
            return Ok(false);
        }
        let status_flags = match self.file_status_flags(fd) {
            Ok(flags) => flags,
            Err(errno) => return Err(LinuxCallResult::Ret(-(errno as i64))),
        };
        Ok(status_flags & O_NONBLOCK == 0 && flags & MSG_DONTWAIT == 0)
    }

    pub(super) fn try_recvfrom_fd(
        &mut self,
        fd: u32,
        count: u32,
        flags: u32,
    ) -> Result<LinuxCallResult, &'static str> {
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
        let peek = flags & MSG_PEEK != 0;
        if let Some(result) =
            self.net_stack_recv_socket(socket_id, ready_key, handle, count, peek)?
        {
            return Ok(result);
        }
        match self.linux_socket.recv_socket(socket_id, count) {
            Ok(0) => return Ok(LinuxCallResult::Bytes(Vec::new())),
            Ok(_) => {}
            Err(ServiceCallError::Errno(errno)) => {
                return Ok(LinuxCallResult::Ret(-(errno as i64)));
            }
            Err(ServiceCallError::Trap(reason)) => {
                crate::kwarn!("linux_socket recv precheck: {}", reason);
                return Err("linux_socket_service trapped during recv precheck");
            }
            Err(ServiceCallError::Invalid(err)) => return Err(err),
        }
        let net_core_result = if peek {
            self.net_core.peek_socket(socket_id, count)
        } else {
            self.net_core.recv_socket(socket_id, count)
        };
        match net_core_result {
            Ok(bytes) => {
                if !peek {
                    match self.linux_socket.recv_socket(socket_id, bytes.len() as u32) {
                        Ok(_) => {}
                        Err(ServiceCallError::Errno(errno)) => {
                            crate::kwarn!(
                                "linux_socket recv bookkeeping socket {} failed errno={}",
                                socket_id,
                                errno
                            );
                        }
                        Err(ServiceCallError::Trap(reason)) => {
                            crate::kwarn!(
                                "linux_socket recv bookkeeping socket {}: {}",
                                socket_id,
                                reason
                            );
                        }
                        Err(ServiceCallError::Invalid(err)) => {
                            crate::kwarn!(
                                "linux_socket recv bookkeeping socket {}: {}",
                                socket_id,
                                err
                            );
                        }
                    }
                }
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

    fn generic_recvfrom_sockaddr_writeback(
        &mut self,
        label: &str,
        addr_raw: u64,
        addr_len_raw: u64,
    ) -> Result<(u32, u32, bool), i32> {
        if label.starts_with("ring3_") || addr_raw == 0 {
            return Ok((0, 0, false));
        }
        if addr_len_raw == 0 {
            return Err(ERR_EFAULT);
        }
        let addr_ptr = u32::try_from(addr_raw).map_err(|_| ERR_EFAULT)?;
        let addr_len_ptr = u32::try_from(addr_len_raw).map_err(|_| ERR_EFAULT)?;
        let len_bytes = self.linux.read_bytes(addr_len_ptr, 4).map_err(|_| ERR_EFAULT)?;
        let addr_len = u32::from_le_bytes(len_bytes.as_slice().try_into().map_err(|_| ERR_EFAULT)?);
        if addr_len < 16 {
            return Err(ERR_EINVAL);
        }
        self.linux.read_bytes(addr_ptr, 16).map_err(|_| ERR_EFAULT)?;
        Ok((addr_ptr, addr_len_ptr, true))
    }

    fn finish_recvfrom_sockaddr_writeback(
        &mut self,
        result: LinuxCallResult,
        fd: u32,
        addr_ptr: u32,
        addr_len_ptr: u32,
        write_addr: bool,
    ) -> Result<LinuxCallResult, &'static str> {
        if !write_addr {
            return Ok(result);
        }
        match result {
            LinuxCallResult::Bytes(bytes) => {
                match self.write_generic_socket_peer_sockaddr(fd, addr_ptr, addr_len_ptr) {
                    Ok(()) => Ok(LinuxCallResult::Bytes(bytes)),
                    Err(errno) => Ok(LinuxCallResult::Ret(-(errno as i64))),
                }
            }
            other => Ok(other),
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
        let value = u32::try_from(plan.args[5]).map_err(|_| "setsockopt value overflowed")?;
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
        match self.linux_socket.setsockopt(socket_id, level, optname, optlen, value) {
            Ok(()) => {
                if level == SOL_SOCKET && matches!(optname, SO_RCVBUF | SO_SNDBUF) {
                    let capacity = match self.linux_socket.getsockopt(socket_id, level, optname) {
                        Ok(capacity) => capacity,
                        Err(ServiceCallError::Errno(errno)) => {
                            return Ok(LinuxCallResult::Ret(-(errno as i64)));
                        }
                        Err(ServiceCallError::Trap(reason)) => {
                            crate::kwarn!("linux_socket getsockopt after buffer opt: {}", reason);
                            return Err("linux_socket_service trapped during socket buffer sync");
                        }
                        Err(ServiceCallError::Invalid(err)) => return Err(err),
                    };
                    if optname == SO_RCVBUF {
                        match self.net_core.set_recv_capacity(socket_id, capacity) {
                            Ok(()) => {}
                            Err(ServiceCallError::Errno(errno)) => {
                                return Ok(LinuxCallResult::Ret(-(errno as i64)));
                            }
                            Err(ServiceCallError::Trap(reason)) => {
                                crate::kwarn!("net_core set_recv_capacity: {}", reason);
                                return Err("net_core trapped during SO_RCVBUF sync");
                            }
                            Err(ServiceCallError::Invalid(err)) => return Err(err),
                        }
                        match self.set_net_stack_recv_capacity(socket_id, capacity) {
                            Ok(()) => {}
                            Err(ServiceCallError::Errno(errno)) => {
                                return Ok(LinuxCallResult::Ret(-(errno as i64)));
                            }
                            Err(ServiceCallError::Trap(reason)) => {
                                crate::kwarn!("net_stack set_recv_capacity: {}", reason);
                                return Err("net_stack trapped during SO_RCVBUF sync");
                            }
                            Err(ServiceCallError::Invalid(err)) => return Err(err),
                        }
                    } else {
                        match self.set_net_stack_send_capacity(socket_id, capacity) {
                            Ok(()) => {}
                            Err(ServiceCallError::Errno(errno)) => {
                                return Ok(LinuxCallResult::Ret(-(errno as i64)));
                            }
                            Err(ServiceCallError::Trap(reason)) => {
                                crate::kwarn!("net_stack set_send_capacity: {}", reason);
                                return Err("net_stack trapped during SO_SNDBUF sync");
                            }
                            Err(ServiceCallError::Invalid(err)) => return Err(err),
                        }
                    }
                }
                Ok(LinuxCallResult::Ret(0))
            }
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
        let optval_ptr =
            u32::try_from(plan.args[3]).map_err(|_| "getsockopt optval pointer overflowed")?;
        let optlen_ptr =
            u32::try_from(plan.args[4]).map_err(|_| "getsockopt optlen pointer overflowed")?;
        match self.linux_socket.getsockopt(socket_id, level, optname) {
            Ok(value) => {
                let value = if level == SOL_SOCKET && optname == SO_ERROR {
                    self.take_net_stack_socket_error(socket_id).unwrap_or(value as i32) as u32
                } else {
                    value
                };
                self.write_getsockopt_u32(optval_ptr, optlen_ptr, value)
            }
            Err(ServiceCallError::Errno(errno)) => Ok(LinuxCallResult::Ret(-(errno as i64))),
            Err(ServiceCallError::Trap(reason)) => {
                crate::kwarn!("linux_socket getsockopt: {}", reason);
                Err("linux_socket_service trapped during getsockopt")
            }
            Err(ServiceCallError::Invalid(err)) => Err(err),
        }
    }

    fn write_getsockopt_u32(
        &mut self,
        optval_ptr: u32,
        optlen_ptr: u32,
        value: u32,
    ) -> Result<LinuxCallResult, &'static str> {
        const SOCKOPT_U32_LEN: u32 = 4;

        let optlen = match self.linux.read_bytes(optlen_ptr, SOCKOPT_U32_LEN) {
            Ok(bytes) => u32::from_le_bytes(
                bytes.as_slice().try_into().map_err(|_| "getsockopt optlen read was short")?,
            ),
            Err(err) => {
                crate::kwarn!("getsockopt optlen readback: {}", err);
                return Ok(LinuxCallResult::Ret(-(ERR_EFAULT as i64)));
            }
        };
        if optlen < SOCKOPT_U32_LEN {
            return Ok(LinuxCallResult::Ret(-(ERR_EINVAL as i64)));
        }
        if self.linux.write_bytes(optval_ptr, &value.to_le_bytes()).is_err()
            || self.linux.write_bytes(optlen_ptr, &SOCKOPT_U32_LEN.to_le_bytes()).is_err()
        {
            return Ok(LinuxCallResult::Ret(-(ERR_EFAULT as i64)));
        }
        Ok(LinuxCallResult::Ret(0))
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
        let fd = match u32::try_from(plan.args[0]) {
            Ok(fd) => fd,
            Err(_) => return Ok(LinuxCallResult::Ret(-(ERR_EBADF as i64))),
        };
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
        let cmd = match u32::try_from(plan.args[1]) {
            Ok(cmd) => cmd,
            Err(_) => return Ok(LinuxCallResult::Ret(-(ERR_EINVAL as i64))),
        };
        let arg = plan.args[2];
        let ret = match cmd {
            F_DUPFD => {
                let min_fd = match u32::try_from(arg) {
                    Ok(min_fd) => min_fd,
                    Err(_) => return Ok(LinuxCallResult::Ret(-(ERR_EINVAL as i64))),
                };
                self.dup_fd_from(fd, min_fd)
            }
            F_DUPFD_CLOEXEC => {
                let min_fd = match u32::try_from(arg) {
                    Ok(min_fd) => min_fd,
                    Err(_) => return Ok(LinuxCallResult::Ret(-(ERR_EINVAL as i64))),
                };
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

    pub(super) fn plan_fcntl_setlk(
        &mut self,
        plan: LinuxPlan,
    ) -> Result<LinuxCallResult, &'static str> {
        const F_SETLK: u32 = 6;
        const F_SETLKW: u32 = 7;

        if self.require_capability("linux_syscall", "vfs.file-lock", "fcntl-setlk").is_err() {
            return Ok(LinuxCallResult::Ret(-(ERR_EPERM as i64)));
        }
        let fd = match u32::try_from(plan.args[0]) {
            Ok(fd) => fd,
            Err(_) => return Ok(LinuxCallResult::Ret(-(ERR_EBADF as i64))),
        };
        match self.validate_fd_handle(fd) {
            Ok(()) => {}
            Err(ServiceCallError::Errno(errno)) => {
                return Ok(LinuxCallResult::Ret(-(errno as i64)));
            }
            Err(ServiceCallError::Trap(reason)) => {
                crate::kwarn!("fcntl setlk fd validation: {}", reason);
                return Err("fcntl setlk fd validation trapped");
            }
            Err(ServiceCallError::Invalid(err)) => return Err(err),
        }

        let cmd = match u32::try_from(plan.args[1]) {
            Ok(cmd) => cmd,
            Err(_) => return Ok(LinuxCallResult::Ret(-(ERR_EINVAL as i64))),
        };
        let lock_type = plan.args[2] as i16;
        let whence = plan.args[3] as i16;
        let start = plan.args[4] as i64;
        let len = plan.args[5] as i64;
        let owner = self.current_pid();
        let ret = match cmd {
            F_SETLK => self.fcntl_setlk_fd(fd, owner, lock_type, whence, start, len),
            F_SETLKW => self.fcntl_setlkw_fd(fd, owner, lock_type, whence, start, len),
            _ => Err(ERR_EINVAL),
        };

        match ret {
            Ok(()) => Ok(LinuxCallResult::Ret(0)),
            Err(errno) => Ok(LinuxCallResult::Ret(-(errno as i64))),
        }
    }

    pub(super) fn plan_fcntl_getlk(
        &mut self,
        plan: LinuxPlan,
    ) -> Result<LinuxCallResult, &'static str> {
        const F_RDLCK: i16 = 0;
        const F_WRLCK: i16 = 1;
        const F_UNLCK: i16 = 2;

        if self.require_capability("linux_syscall", "vfs.file-lock", "fcntl-getlk").is_err() {
            return Ok(LinuxCallResult::Ret(-(ERR_EPERM as i64)));
        }
        let fd = match u32::try_from(plan.args[0]) {
            Ok(fd) => fd,
            Err(_) => return Ok(LinuxCallResult::Ret(-(ERR_EBADF as i64))),
        };
        match self.validate_fd_handle(fd) {
            Ok(()) => {}
            Err(ServiceCallError::Errno(errno)) => {
                return Ok(LinuxCallResult::Ret(-(errno as i64)));
            }
            Err(ServiceCallError::Trap(reason)) => {
                crate::kwarn!("fcntl getlk fd validation: {}", reason);
                return Err("fcntl getlk fd validation trapped");
            }
            Err(ServiceCallError::Invalid(err)) => return Err(err),
        }

        let out_ptr = match u32::try_from(plan.args[1]) {
            Ok(out_ptr) => out_ptr,
            Err(_) => return Ok(LinuxCallResult::Ret(-(ERR_EFAULT as i64))),
        };
        let lock_type = plan.args[2] as i16;
        let whence = plan.args[3] as i16;
        let start = plan.args[4] as i64;
        let len = plan.args[5] as i64;
        let owner = self.current_pid();
        let encoded = match self.fcntl_getlk_fd(fd, owner, lock_type, whence, start, len) {
            Ok(Some((write, pid, lock_start, lock_len))) => {
                encode_flock(if write { F_WRLCK } else { F_RDLCK }, 0, lock_start, lock_len, pid)
            }
            Ok(None) => encode_flock(F_UNLCK, whence, start, len, 0),
            Err(errno) => return Ok(LinuxCallResult::Ret(-(errno as i64))),
        };
        match self.linux.write_bytes(out_ptr, &encoded) {
            Ok(()) => Ok(LinuxCallResult::Ret(0)),
            Err(err) => {
                crate::kwarn!("fcntl getlk writeback: {}", err);
                Ok(LinuxCallResult::Ret(-(ERR_EFAULT as i64)))
            }
        }
    }

    pub(super) fn plan_flock(&mut self, plan: LinuxPlan) -> Result<LinuxCallResult, &'static str> {
        if self.require_capability("linux_syscall", "vfs.file-lock", "flock").is_err() {
            return Ok(LinuxCallResult::Ret(-(ERR_EPERM as i64)));
        }
        let fd = match u32::try_from(plan.args[0]) {
            Ok(fd) => fd,
            Err(_) => return Ok(LinuxCallResult::Ret(-(ERR_EBADF as i64))),
        };
        let operation = match u32::try_from(plan.args[1]) {
            Ok(operation) => operation,
            Err(_) => return Ok(LinuxCallResult::Ret(-(ERR_EINVAL as i64))),
        };
        match self.flock_fd(fd, operation) {
            Ok(()) => Ok(LinuxCallResult::Ret(0)),
            Err(errno) => Ok(LinuxCallResult::Ret(-(errno as i64))),
        }
    }

    fn cleanup_linux_socket(&mut self, socket_id: u32, context: &'static str) {
        if let Err(err) = self.linux_socket.close_socket(socket_id) {
            log_cleanup_error(context, err);
        }
    }

    fn cleanup_net_core_socket(&mut self, socket_id: u32, context: &'static str) {
        if let Err(err) = self.net_core.close_socket(socket_id) {
            log_cleanup_error(context, err);
        }
    }

    fn close_accept_writeback_fd(&mut self, accepted_fd: u32) {
        if let Err(errno) = self.close_fd_number(accepted_fd)
            && errno != ERR_EBADF
        {
            crate::kwarn!("accept writeback fd cleanup returned errno {}", errno);
        }
    }
}

fn linux_listen_backlog_arg(raw: u64) -> u32 {
    let backlog = raw as i32;
    if backlog < 0 { u32::MAX } else { backlog as u32 }
}

#[cfg(test)]
mod tests {
    use alloc::{boxed::Box, vec, vec::Vec};

    use service_core::packet::{
        PACKET_FRAME_CAPACITY, PACKET_PAYLOAD_CAPACITY, PacketFrameMeta, encode_frame,
    };
    use vmos_abi::{
        AF_INET, ERR_EAGAIN, ERR_EBADF, ERR_EFAULT, ERR_EINVAL, ERR_ENOTCONN, ERR_ENOTSOCK,
        ERR_EPIPE, NodeKind, PlanKind, SO_KEEPALIVE, SO_RCVBUF, SO_SNDBUF, SOCK_STREAM, SOL_SOCKET,
        SYS_GETPEERNAME, SYS_GETSOCKNAME, SYS_GETSOCKOPT, SYS_RECVFROM, SYS_RECVMSG, SYS_SENDTO,
        SYS_SETSOCKOPT, SYS_SHUTDOWN, SYS_SOCKET, ServiceRoute, SyscallContext,
    };

    use super::{
        LinuxCallResult, LinuxPlan, MSG_NOSIGNAL, MSG_PEEK, SIGPIPE, linux_listen_backlog_arg,
    };
    use crate::supervisor::{
        engine::RuntimeOnlyExecutor,
        runtime::PrototypeRuntime,
        types::{FdEntry, FdResource, ServiceCallError},
    };

    fn test_runtime() -> PrototypeRuntime<'static> {
        let engine = Box::leak(Box::new(RuntimeOnlyExecutor::default()));
        PrototypeRuntime::new(engine).expect("test runtime")
    }

    fn open_vfs_file(runtime: &mut PrototypeRuntime<'_>, path: &[u8]) -> u32 {
        runtime.vfs.create_file(path, 0o600, 0, 0).expect("create dynamic file");
        let vfs_node_id = runtime.vfs.node_id_for_path(path);
        runtime
            .alloc_fd(FdEntry {
                resource: FdResource::ServiceNode {
                    route: ServiceRoute::Vfs,
                    node: NodeKind::File,
                    path: path.to_vec(),
                    vfs_node_id,
                },
                cursor: 0,
                fd_flags: 0,
                status_flags: 0,
                cursor_group: None,
            })
            .expect("install vfs fd")
    }

    fn create_legacy_socket_fd(runtime: &mut PrototypeRuntime<'_>) -> (u32, u32) {
        let socket_id =
            runtime.net_core.create_socket(AF_INET, SOCK_STREAM, 0).expect("legacy socket");
        let ready_key = runtime.net_core.ready_key(socket_id).expect("legacy socket ready key");
        runtime
            .linux_socket
            .register_socket(socket_id, AF_INET, SOCK_STREAM, 0, ready_key)
            .expect("legacy linux socket registration");
        let fd = runtime
            .alloc_fd(FdEntry {
                resource: FdResource::Socket { socket_id: socket_id as u64, ready_key },
                cursor: 0,
                fd_flags: 0,
                status_flags: 0,
                cursor_group: None,
            })
            .expect("legacy socket fd");
        (fd, socket_id)
    }

    fn create_connected_legacy_socket_fd(runtime: &mut PrototypeRuntime<'_>) -> (u32, u32) {
        let socket_id =
            runtime.net_core.create_socket(AF_INET, SOCK_STREAM, 0).expect("legacy socket");
        let ready_key = runtime.net_core.ready_key(socket_id).expect("legacy socket ready key");
        runtime
            .linux_socket
            .register_connected_socket(socket_id, AF_INET, SOCK_STREAM, 0, ready_key)
            .expect("connected linux socket registration");
        let fd = runtime
            .alloc_fd(FdEntry {
                resource: FdResource::Socket { socket_id: socket_id as u64, ready_key },
                cursor: 0,
                fd_flags: 0,
                status_flags: 0,
                cursor_group: None,
            })
            .expect("connected socket fd");
        (fd, socket_id)
    }

    fn create_accepted_legacy_socket_fd(runtime: &mut PrototypeRuntime<'_>) -> u32 {
        let (_, listener_socket_id) = create_legacy_socket_fd(runtime);
        let (_, client_socket_id) = create_legacy_socket_fd(runtime);
        let listener_ipv4 = u32::from_be_bytes([127, 0, 0, 1]);
        let client_ipv4 = u32::from_be_bytes([127, 0, 0, 2]);

        runtime
            .linux_socket
            .bind_socket(listener_socket_id, 16, AF_INET, listener_ipv4, 8080)
            .expect("bind listener");
        runtime.linux_socket.listen_socket(listener_socket_id, 2).expect("listen socket");
        runtime
            .linux_socket
            .bind_socket(client_socket_id, 16, AF_INET, client_ipv4, 9090)
            .expect("bind client");
        runtime
            .linux_socket
            .connect_socket(client_socket_id, 16, AF_INET, listener_ipv4, 8080)
            .expect("connect client");

        let accepted_socket_id =
            runtime.net_core.create_socket(AF_INET, SOCK_STREAM, 0).expect("accepted socket");
        let accepted_ready_key =
            runtime.net_core.ready_key(accepted_socket_id).expect("accepted ready key");
        runtime
            .linux_socket
            .accept_socket(listener_socket_id, accepted_socket_id, accepted_ready_key)
            .expect("accept socket");
        runtime
            .alloc_fd(FdEntry {
                resource: FdResource::Socket {
                    socket_id: accepted_socket_id as u64,
                    ready_key: accepted_ready_key,
                },
                cursor: 0,
                fd_flags: 0,
                status_flags: 0,
                cursor_group: None,
            })
            .expect("accepted socket fd")
    }

    fn deliver_legacy_socket_payload(
        runtime: &mut PrototypeRuntime<'_>,
        socket_id: u32,
        payload: &[u8],
    ) {
        runtime.net_core.send_socket(socket_id, b"prime").expect("prime socket endpoints");
        let meta = PacketFrameMeta::demo_http_response(1, payload.len());
        let mut frame = [0u8; PACKET_FRAME_CAPACITY];
        let frame_len = encode_frame(meta, payload, &mut frame).expect("encode rx frame");
        runtime.net_core.deliver_packet_frame(&frame[..frame_len]).expect("deliver socket rx");
    }

    fn fcntl_plan(fd: u64, cmd: u64, arg: u64) -> LinuxPlan {
        LinuxPlan { kind: PlanKind::Fcntl, args: [fd, cmd, arg, 0, 0, 0] }
    }

    fn fcntl_setlk_plan(
        fd: u64,
        cmd: u64,
        lock_type: i16,
        whence: i16,
        start: i64,
        len: i64,
    ) -> LinuxPlan {
        LinuxPlan {
            kind: PlanKind::FcntlSetlk,
            args: [
                fd,
                cmd,
                lock_type as i64 as u64,
                whence as i64 as u64,
                start as u64,
                len as u64,
            ],
        }
    }

    fn fcntl_getlk_plan(
        fd: u64,
        out_ptr: u64,
        lock_type: i16,
        whence: i16,
        start: i64,
        len: i64,
    ) -> LinuxPlan {
        LinuxPlan {
            kind: PlanKind::FcntlGetlk,
            args: [
                fd,
                out_ptr,
                lock_type as i64 as u64,
                whence as i64 as u64,
                start as u64,
                len as u64,
            ],
        }
    }

    fn flock_plan(fd: u64, operation: u64) -> LinuxPlan {
        LinuxPlan { kind: PlanKind::Flock, args: [fd, operation, 0, 0, 0, 0] }
    }

    fn socket_plan() -> LinuxPlan {
        LinuxPlan { kind: PlanKind::Socket, args: [AF_INET as u64, SOCK_STREAM as u64, 0, 0, 0, 0] }
    }

    fn ret_errno(result: Result<LinuxCallResult, &'static str>) -> i64 {
        match result.expect("plan should return a Linux result") {
            LinuxCallResult::Ret(ret) => ret,
            other => panic!("unexpected Linux result: {other:?}"),
        }
    }

    fn expect_bytes(result: Result<LinuxCallResult, &'static str>) -> Vec<u8> {
        match result.expect("plan should return a Linux result") {
            LinuxCallResult::Bytes(bytes) => bytes,
            other => panic!("unexpected Linux result: {other:?}"),
        }
    }

    fn write_u32_at(bytes: &mut [u8], offset: usize, value: u32) {
        bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }

    fn write_u64_at(bytes: &mut [u8], offset: usize, value: u64) {
        bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
    }

    fn sockaddr_writeback_buffer(runtime: &mut PrototypeRuntime<'_>, len: u32) -> (u32, u32) {
        let mut raw = vec![0u8; 20];
        write_u32_at(&mut raw, 16, len);
        let (base, _) = runtime.linux.write_arg_bytes(&raw).expect("sockaddr writeback buffer");
        (base, base + 16)
    }

    fn assert_sockaddr_in(
        runtime: &mut PrototypeRuntime<'_>,
        addr_ptr: u32,
        len_ptr: u32,
        addr: [u8; 4],
        port: u16,
    ) {
        let sockaddr = runtime.linux.read_bytes(addr_ptr, 16).expect("sockaddr");
        assert_eq!(u16::from_le_bytes(sockaddr[..2].try_into().unwrap()), AF_INET as u16);
        assert_eq!(u16::from_be_bytes(sockaddr[2..4].try_into().unwrap()), port);
        assert_eq!(&sockaddr[4..8], &addr);
        assert_eq!(runtime.linux.read_bytes(len_ptr, 4).expect("socklen"), 16u32.to_le_bytes());
    }

    fn generic_setsockopt_u32(
        runtime: &mut PrototypeRuntime<'_>,
        fd: u32,
        optname: u32,
        value: u32,
    ) -> i64 {
        let (opt_ptr, _) =
            runtime.linux.write_arg_bytes(&value.to_le_bytes()).expect("setsockopt buffer");
        ret_errno(runtime.dispatch_linux_syscall(
            "test_setsockopt_u32",
            SyscallContext::new(
                SYS_SETSOCKOPT,
                [fd as u64, SOL_SOCKET as u64, optname as u64, opt_ptr as u64, 4, 0],
            ),
        ))
    }

    fn generic_getsockopt_u32(runtime: &mut PrototypeRuntime<'_>, fd: u32, optname: u32) -> u32 {
        let (opt_ptr, _) = runtime.linux.write_arg_bytes(&[0; 8]).expect("getsockopt buffer");
        runtime.linux.write_bytes(opt_ptr + 4, &4u32.to_le_bytes()).expect("getsockopt len");
        assert_eq!(
            ret_errno(runtime.dispatch_linux_syscall(
                "test_getsockopt_u32",
                SyscallContext::new(
                    SYS_GETSOCKOPT,
                    [
                        fd as u64,
                        SOL_SOCKET as u64,
                        optname as u64,
                        opt_ptr as u64,
                        (opt_ptr + 4) as u64,
                        0,
                    ],
                ),
            )),
            0
        );
        let bytes = runtime.linux.read_bytes(opt_ptr, 8).expect("getsockopt output");
        assert_eq!(u32::from_le_bytes(bytes[4..8].try_into().unwrap()), 4);
        u32::from_le_bytes(bytes[..4].try_into().unwrap())
    }

    #[test]
    fn listen_backlog_arg_uses_linux_i32_shape_before_internal_clamp() {
        assert_eq!(linux_listen_backlog_arg(0), 0);
        assert_eq!(linux_listen_backlog_arg(1), 1);
        assert_eq!(linux_listen_backlog_arg(i32::MAX as u64), i32::MAX as u32);
        assert_eq!(linux_listen_backlog_arg(u64::MAX), u32::MAX);
        assert_eq!(linux_listen_backlog_arg(u32::MAX as u64), u32::MAX);
        assert_eq!(linux_listen_backlog_arg(1u64 << 32), 0);
    }

    #[test]
    fn generic_fcntl_bad_fd_shape_returns_ebadf() {
        let mut runtime = test_runtime();

        assert_eq!(ret_errno(runtime.plan_fcntl(fcntl_plan(u64::MAX, 1, 0))), -(ERR_EBADF as i64));
    }

    #[test]
    fn generic_fcntl_dupfd_bad_min_shape_returns_einval() {
        const F_DUPFD: u64 = 0;
        const F_DUPFD_CLOEXEC: u64 = 1030;

        let mut runtime = test_runtime();
        let fd = open_vfs_file(&mut runtime, b"/tmp/generic-fcntl-dupfd-shape") as u64;

        assert_eq!(
            ret_errno(runtime.plan_fcntl(fcntl_plan(fd, F_DUPFD, u64::MAX))),
            -(ERR_EINVAL as i64)
        );
        assert_eq!(
            ret_errno(runtime.plan_fcntl(fcntl_plan(fd, F_DUPFD_CLOEXEC, u64::MAX))),
            -(ERR_EINVAL as i64)
        );
    }

    #[test]
    fn generic_fcntl_lock_bad_shapes_return_linux_errno() {
        const F_SETLK: u64 = 6;
        const F_RDLCK: i16 = 0;
        const F_WRLCK: i16 = 1;
        const SEEK_SET: i16 = 0;

        let mut runtime = test_runtime();
        let fd = open_vfs_file(&mut runtime, b"/tmp/generic-fcntl-lock-bad-shapes") as u64;
        let (out_ptr, _) = runtime.linux.write_arg_bytes(&[0u8; 32]).expect("flock output");

        assert_eq!(
            ret_errno(runtime.plan_fcntl_setlk(fcntl_setlk_plan(
                u64::MAX,
                F_SETLK,
                F_WRLCK,
                SEEK_SET,
                0,
                1,
            ))),
            -(ERR_EBADF as i64)
        );
        assert_eq!(
            ret_errno(runtime.plan_fcntl_setlk(fcntl_setlk_plan(
                fd,
                u64::MAX,
                F_WRLCK,
                SEEK_SET,
                0,
                1,
            ))),
            -(ERR_EINVAL as i64)
        );
        assert_eq!(
            ret_errno(runtime.plan_fcntl_getlk(fcntl_getlk_plan(
                u64::MAX,
                out_ptr as u64,
                F_RDLCK,
                SEEK_SET,
                0,
                1,
            ))),
            -(ERR_EBADF as i64)
        );
        assert_eq!(
            ret_errno(runtime.plan_fcntl_getlk(fcntl_getlk_plan(
                fd,
                u64::MAX,
                F_RDLCK,
                SEEK_SET,
                0,
                1,
            ))),
            -(ERR_EFAULT as i64)
        );
    }

    #[test]
    fn generic_flock_bad_shapes_return_linux_errno() {
        const LOCK_SH: u64 = 1;

        let mut runtime = test_runtime();
        let fd = open_vfs_file(&mut runtime, b"/tmp/generic-flock-bad-shapes") as u64;

        assert_eq!(
            ret_errno(runtime.plan_flock(flock_plan(u64::MAX, LOCK_SH))),
            -(ERR_EBADF as i64)
        );
        assert_eq!(ret_errno(runtime.plan_flock(flock_plan(fd, u64::MAX))), -(ERR_EINVAL as i64));
    }

    #[test]
    fn generic_fcntl_getlk_writes_conflict_and_reports_bad_output_as_efault() {
        const F_GETLK: u64 = 5;
        const F_RDLCK: i16 = 0;
        const F_WRLCK: i16 = 1;
        const SEEK_SET: i16 = 0;

        let mut runtime = test_runtime();
        let fd = open_vfs_file(&mut runtime, b"/tmp/generic-fcntl-getlk-writeback");

        runtime
            .fcntl_setlk_fd(fd, 100, F_RDLCK, SEEK_SET, 16, 8)
            .expect("seed conflicting read lock");
        let (out_ptr, _) = runtime.linux.write_arg_bytes(&[0u8; 32]).expect("flock output");

        assert_eq!(
            ret_errno(runtime.plan_fcntl_getlk(LinuxPlan {
                kind: PlanKind::FcntlGetlk,
                args: [fd as u64, out_ptr as u64, F_WRLCK as u64, SEEK_SET as u64, 0, 64],
            })),
            0
        );
        let out = runtime.linux.read_bytes(out_ptr, 32).expect("flock writeback");
        assert_eq!(i16::from_le_bytes(out[0..2].try_into().unwrap()), F_RDLCK);
        assert_eq!(i16::from_le_bytes(out[2..4].try_into().unwrap()), SEEK_SET);
        assert_eq!(i64::from_le_bytes(out[8..16].try_into().unwrap()), 16);
        assert_eq!(i64::from_le_bytes(out[16..24].try_into().unwrap()), 8);
        assert_eq!(i32::from_le_bytes(out[24..28].try_into().unwrap()), 100);

        assert_eq!(
            ret_errno(runtime.plan_fcntl_getlk(LinuxPlan {
                kind: PlanKind::FcntlGetlk,
                args: [fd as u64, u32::MAX as u64, F_WRLCK as u64, SEEK_SET as u64, 0, 64],
            })),
            -(ERR_EFAULT as i64)
        );
    }

    #[test]
    fn generic_accept_writeback_failure_closes_accepted_fd() {
        let mut runtime = test_runtime();
        let accepted_fd = ret_errno(runtime.plan_socket(socket_plan()));
        assert!(accepted_fd >= 0);
        let accepted_fd = accepted_fd as u32;

        assert_eq!(
            ret_errno(runtime.finish_accept_sockaddr_writeback(
                LinuxCallResult::Ret(accepted_fd as i64),
                0,
                0,
                true,
            )),
            -(ERR_EFAULT as i64)
        );
        assert_eq!(runtime.file_status_flags(accepted_fd), Err(ERR_EBADF));
    }

    #[test]
    fn generic_shutdown_requires_connected_socket() {
        let mut runtime = test_runtime();
        let (fd, _) = create_legacy_socket_fd(&mut runtime);

        assert_eq!(
            ret_errno(runtime.dispatch_linux_syscall(
                "test_shutdown_unconnected",
                SyscallContext::new(SYS_SHUTDOWN, [fd as u64, 2, 0, 0, 0, 0]),
            )),
            -(ERR_ENOTCONN as i64)
        );
    }

    #[test]
    fn generic_shutdown_read_returns_eof_with_queued_payload() {
        let mut runtime = test_runtime();
        let (fd, socket_id) = create_connected_legacy_socket_fd(&mut runtime);
        let payload = b"queued payload before shutdown";
        deliver_legacy_socket_payload(&mut runtime, socket_id, payload);

        assert_eq!(
            ret_errno(runtime.dispatch_linux_syscall(
                "test_shutdown_rd",
                SyscallContext::new(SYS_SHUTDOWN, [fd as u64, 0, 0, 0, 0, 0]),
            )),
            0
        );
        let bytes = expect_bytes(runtime.dispatch_linux_syscall(
            "test_recvfrom_after_shutdown_rd",
            SyscallContext::new(SYS_RECVFROM, [fd as u64, 0, payload.len() as u64, 0, 0, 0]),
        ));
        assert!(bytes.is_empty());
    }

    #[test]
    fn generic_shutdown_write_returns_epipe_and_queues_sigpipe_unless_suppressed() {
        let mut runtime = test_runtime();
        let (fd, _) = create_connected_legacy_socket_fd(&mut runtime);
        let (ptr, _) = runtime.linux.write_arg_bytes(b"payload").expect("send buffer");

        assert_eq!(
            ret_errno(runtime.dispatch_linux_syscall(
                "test_shutdown_wr",
                SyscallContext::new(SYS_SHUTDOWN, [fd as u64, 1, 0, 0, 0, 0]),
            )),
            0
        );
        assert_eq!(
            ret_errno(runtime.dispatch_linux_syscall(
                "test_sendto_after_shutdown_wr",
                SyscallContext::new(SYS_SENDTO, [fd as u64, ptr as u64, 7, 0, 0, 0]),
            )),
            -(ERR_EPIPE as i64)
        );
        let tid = runtime.current_tid();
        let pending = &runtime.query_thread(tid).expect("current thread").pending_signals;
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].signo, SIGPIPE);

        assert_eq!(
            ret_errno(runtime.dispatch_linux_syscall(
                "test_sendto_after_shutdown_wr_nosignal",
                SyscallContext::new(
                    SYS_SENDTO,
                    [fd as u64, ptr as u64, 7, MSG_NOSIGNAL as u64, 0, 0],
                ),
            )),
            -(ERR_EPIPE as i64)
        );
        let pending = &runtime.query_thread(tid).expect("current thread").pending_signals;
        assert_eq!(pending.len(), 1);
    }

    #[test]
    fn generic_keepalive_setsockopt_round_trips_through_arg_buffer() {
        let mut runtime = test_runtime();
        let fd = ret_errno(runtime.dispatch_linux_syscall(
            "test_socket_for_keepalive",
            SyscallContext::new(SYS_SOCKET, [AF_INET as u64, SOCK_STREAM as u64, 0, 0, 0, 0]),
        ));
        assert!(fd >= 0);
        let fd = fd as u32;

        assert_eq!(generic_getsockopt_u32(&mut runtime, fd, SO_KEEPALIVE), 0);
        assert_eq!(generic_setsockopt_u32(&mut runtime, fd, SO_KEEPALIVE, 1), 0);
        assert_eq!(generic_getsockopt_u32(&mut runtime, fd, SO_KEEPALIVE), 1);
        assert_eq!(generic_setsockopt_u32(&mut runtime, fd, SO_KEEPALIVE, 0), 0);
        assert_eq!(generic_getsockopt_u32(&mut runtime, fd, SO_KEEPALIVE), 0);
    }

    #[test]
    fn generic_socket_buffers_round_trip_through_arg_buffer() {
        let mut runtime = test_runtime();
        let fd = ret_errno(runtime.dispatch_linux_syscall(
            "test_socket_for_buffers",
            SyscallContext::new(SYS_SOCKET, [AF_INET as u64, SOCK_STREAM as u64, 0, 0, 0, 0]),
        ));
        assert!(fd >= 0);
        let fd = fd as u32;

        assert_eq!(generic_getsockopt_u32(&mut runtime, fd, SO_SNDBUF), 212_992);
        assert_eq!(generic_getsockopt_u32(&mut runtime, fd, SO_RCVBUF), 212_992);
        assert_eq!(generic_setsockopt_u32(&mut runtime, fd, SO_SNDBUF, 4096), 0);
        assert_eq!(generic_setsockopt_u32(&mut runtime, fd, SO_RCVBUF, 1), 0);
        assert_eq!(generic_getsockopt_u32(&mut runtime, fd, SO_SNDBUF), 8192);
        assert_eq!(generic_getsockopt_u32(&mut runtime, fd, SO_RCVBUF), 2048);
    }

    #[test]
    fn generic_so_rcvbuf_limits_modeled_receive_queue() {
        let mut runtime = test_runtime();
        let (fd, socket_id) = create_legacy_socket_fd(&mut runtime);
        let payload = [b'r'; PACKET_PAYLOAD_CAPACITY];

        assert_eq!(generic_setsockopt_u32(&mut runtime, fd, SO_RCVBUF, 1), 0);
        assert_eq!(generic_getsockopt_u32(&mut runtime, fd, SO_RCVBUF), 2048);

        for _ in 0..4 {
            deliver_legacy_socket_payload(&mut runtime, socket_id, &payload);
        }

        let meta = PacketFrameMeta::demo_http_response(5, payload.len());
        let mut frame = [0u8; PACKET_FRAME_CAPACITY];
        let frame_len = encode_frame(meta, &payload, &mut frame).expect("encode overflow frame");
        assert!(matches!(
            runtime.net_core.deliver_packet_frame(&frame[..frame_len]),
            Err(ServiceCallError::Errno(ERR_EAGAIN))
        ));

        let bytes = expect_bytes(runtime.dispatch_linux_syscall(
            "test_recvfrom_rcvbuf_capacity",
            SyscallContext::new(SYS_RECVFROM, [fd as u64, 0, 2048, 0, 0, 0]),
        ));
        assert_eq!(bytes.len(), 2048);
        assert!(bytes.iter().all(|byte| *byte == b'r'));
    }

    #[test]
    fn generic_getsockname_and_getpeername_write_accepted_legacy_endpoints() {
        let mut runtime = test_runtime();
        let fd = create_accepted_legacy_socket_fd(&mut runtime);

        let (addr_ptr, len_ptr) = sockaddr_writeback_buffer(&mut runtime, 16);
        assert_eq!(
            ret_errno(runtime.dispatch_linux_syscall(
                "test_getsockname_accepted",
                SyscallContext::new(
                    SYS_GETSOCKNAME,
                    [fd as u64, addr_ptr as u64, len_ptr as u64, 0, 0, 0],
                ),
            )),
            0
        );
        assert_sockaddr_in(&mut runtime, addr_ptr, len_ptr, [127, 0, 0, 1], 8080);

        let (addr_ptr, len_ptr) = sockaddr_writeback_buffer(&mut runtime, 16);
        assert_eq!(
            ret_errno(runtime.dispatch_linux_syscall(
                "test_getpeername_accepted",
                SyscallContext::new(
                    SYS_GETPEERNAME,
                    [fd as u64, addr_ptr as u64, len_ptr as u64, 0, 0, 0],
                ),
            )),
            0
        );
        assert_sockaddr_in(&mut runtime, addr_ptr, len_ptr, [127, 0, 0, 2], 9090);
    }

    #[test]
    fn generic_getsockname_unbound_socket_writes_zero_endpoint() {
        let mut runtime = test_runtime();
        let (fd, _) = create_legacy_socket_fd(&mut runtime);
        let (addr_ptr, len_ptr) = sockaddr_writeback_buffer(&mut runtime, 16);

        assert_eq!(
            ret_errno(runtime.dispatch_linux_syscall(
                "test_getsockname_unbound",
                SyscallContext::new(
                    SYS_GETSOCKNAME,
                    [fd as u64, addr_ptr as u64, len_ptr as u64, 0, 0, 0],
                ),
            )),
            0
        );
        assert_sockaddr_in(&mut runtime, addr_ptr, len_ptr, [0, 0, 0, 0], 0);
    }

    #[test]
    fn generic_getpeername_requires_connected_peer() {
        let mut runtime = test_runtime();
        let (fd, _) = create_legacy_socket_fd(&mut runtime);
        let (addr_ptr, len_ptr) = sockaddr_writeback_buffer(&mut runtime, 16);

        assert_eq!(
            ret_errno(runtime.dispatch_linux_syscall(
                "test_getpeername_unconnected",
                SyscallContext::new(
                    SYS_GETPEERNAME,
                    [fd as u64, addr_ptr as u64, len_ptr as u64, 0, 0, 0],
                ),
            )),
            -(ERR_ENOTCONN as i64)
        );
    }

    #[test]
    fn generic_socket_name_writeback_validates_fd_type_and_socklen() {
        let mut runtime = test_runtime();
        let vfs_fd = open_vfs_file(&mut runtime, b"/tmp/generic-socket-name-nonsocket");
        let (addr_ptr, len_ptr) = sockaddr_writeback_buffer(&mut runtime, 16);

        assert_eq!(
            ret_errno(runtime.dispatch_linux_syscall(
                "test_getsockname_bad_fd_shape",
                SyscallContext::new(
                    SYS_GETSOCKNAME,
                    [u64::MAX, addr_ptr as u64, len_ptr as u64, 0, 0, 0],
                ),
            )),
            -(ERR_EBADF as i64)
        );
        assert_eq!(
            ret_errno(runtime.dispatch_linux_syscall(
                "test_getsockname_nonsocket",
                SyscallContext::new(
                    SYS_GETSOCKNAME,
                    [vfs_fd as u64, addr_ptr as u64, len_ptr as u64, 0, 0, 0],
                ),
            )),
            -(ERR_ENOTSOCK as i64)
        );

        let fd = create_accepted_legacy_socket_fd(&mut runtime);
        let (addr_ptr, len_ptr) = sockaddr_writeback_buffer(&mut runtime, 15);
        assert_eq!(
            ret_errno(runtime.dispatch_linux_syscall(
                "test_getpeername_short_socklen",
                SyscallContext::new(
                    SYS_GETPEERNAME,
                    [fd as u64, addr_ptr as u64, len_ptr as u64, 0, 0, 0],
                ),
            )),
            -(ERR_EINVAL as i64)
        );
    }

    #[test]
    fn generic_recvfrom_prevalidates_sockaddr_before_consuming_payload() {
        let mut runtime = test_runtime();
        let (fd, socket_id) = create_legacy_socket_fd(&mut runtime);
        let payload = b"queued payload";
        deliver_legacy_socket_payload(&mut runtime, socket_id, payload);

        let (len_ptr, _) = runtime.linux.write_arg_bytes(&16u32.to_le_bytes()).expect("addrlen");
        let invalid_addr_ptr = len_ptr + 64;
        assert_eq!(
            ret_errno(runtime.dispatch_linux_syscall(
                "test_recvfrom_bad_sockaddr",
                SyscallContext::new(
                    SYS_RECVFROM,
                    [
                        fd as u64,
                        0,
                        payload.len() as u64,
                        0,
                        invalid_addr_ptr as u64,
                        len_ptr as u64
                    ],
                ),
            )),
            -(ERR_EFAULT as i64)
        );

        let bytes = expect_bytes(runtime.dispatch_linux_syscall(
            "test_recvfrom_retry",
            SyscallContext::new(SYS_RECVFROM, [fd as u64, 0, payload.len() as u64, 0, 0, 0]),
        ));
        assert_eq!(bytes, payload);
    }

    #[test]
    fn generic_recvfrom_msg_peek_preserves_payload_for_later_recv() {
        let mut runtime = test_runtime();
        let (fd, socket_id) = create_legacy_socket_fd(&mut runtime);
        let payload = b"queued peek payload";
        deliver_legacy_socket_payload(&mut runtime, socket_id, payload);

        let peek = expect_bytes(runtime.dispatch_linux_syscall(
            "test_recvfrom_peek",
            SyscallContext::new(SYS_RECVFROM, [fd as u64, 0, 6, MSG_PEEK as u64, 0, 0]),
        ));
        assert_eq!(peek, &payload[..6]);

        let first = expect_bytes(runtime.dispatch_linux_syscall(
            "test_recvfrom_after_peek_first",
            SyscallContext::new(SYS_RECVFROM, [fd as u64, 0, 6, 0, 0, 0]),
        ));
        assert_eq!(first, &payload[..6]);

        let rest = expect_bytes(runtime.dispatch_linux_syscall(
            "test_recvfrom_after_peek_rest",
            SyscallContext::new(SYS_RECVFROM, [fd as u64, 0, payload.len() as u64, 0, 0, 0]),
        ));
        assert_eq!(rest, &payload[6..]);
    }

    #[test]
    fn generic_recvfrom_reads_multiple_delivered_frames_in_order() {
        let mut runtime = test_runtime();
        let (fd, socket_id) = create_legacy_socket_fd(&mut runtime);
        deliver_legacy_socket_payload(&mut runtime, socket_id, b"first ");
        deliver_legacy_socket_payload(&mut runtime, socket_id, b"second");

        let bytes = expect_bytes(runtime.dispatch_linux_syscall(
            "test_recvfrom_two_deliveries",
            SyscallContext::new(SYS_RECVFROM, [fd as u64, 0, 12, 0, 0, 0]),
        ));
        assert_eq!(bytes, b"first second");
    }

    #[test]
    fn generic_recvmsg_prevalidates_name_before_consuming_payload_and_writes_peer() {
        let mut runtime = test_runtime();
        let (fd, socket_id) = create_legacy_socket_fd(&mut runtime);
        let payload = b"queued recvmsg payload";
        deliver_legacy_socket_payload(&mut runtime, socket_id, payload);

        const MSGHDR_SIZE: usize = 56;
        const IOVEC_SIZE: usize = 16;
        let buffer_len = MSGHDR_SIZE + IOVEC_SIZE + 16 + payload.len();
        let (base, _) =
            runtime.linux.write_arg_bytes(&vec![0u8; buffer_len]).expect("recvmsg buffer");
        let msg_ptr = base;
        let iov_ptr = base + MSGHDR_SIZE as u32;
        let name_ptr = iov_ptr + IOVEC_SIZE as u32;
        let data_ptr = name_ptr + 16;
        let invalid_name_ptr = base + buffer_len as u32 + 64;

        let mut raw = vec![0u8; buffer_len];
        write_u64_at(&mut raw, 0, invalid_name_ptr as u64);
        write_u32_at(&mut raw, 8, 16);
        write_u64_at(&mut raw, 16, iov_ptr as u64);
        write_u64_at(&mut raw, 24, 1);
        write_u64_at(&mut raw, 40, 0);
        write_u32_at(&mut raw, 48, 0x66);
        write_u64_at(&mut raw, MSGHDR_SIZE, data_ptr as u64);
        write_u64_at(&mut raw, MSGHDR_SIZE + 8, payload.len() as u64);
        runtime.linux.write_arg_bytes(&raw).expect("bad recvmsg msghdr");

        assert_eq!(
            ret_errno(runtime.dispatch_linux_syscall(
                "test_recvmsg_bad_name",
                SyscallContext::new(SYS_RECVMSG, [fd as u64, msg_ptr as u64, 0, 0, 0, 0]),
            )),
            -(ERR_EFAULT as i64)
        );

        write_u64_at(&mut raw, 0, name_ptr as u64);
        runtime.linux.write_arg_bytes(&raw).expect("valid recvmsg msghdr");
        assert_eq!(
            ret_errno(runtime.dispatch_linux_syscall(
                "test_recvmsg_retry",
                SyscallContext::new(SYS_RECVMSG, [fd as u64, msg_ptr as u64, 0, 0, 0, 0]),
            )),
            payload.len() as i64
        );
        assert_eq!(runtime.linux.read_bytes(data_ptr, payload.len() as u32).unwrap(), payload);
        let name = runtime.linux.read_bytes(name_ptr, 16).expect("recvmsg name");
        assert_eq!(u16::from_le_bytes(name[..2].try_into().unwrap()), AF_INET as u16);
        assert_eq!(runtime.linux.read_bytes(msg_ptr + 8, 4).expect("namelen"), 16u32.to_le_bytes());
        assert_eq!(
            runtime.linux.read_bytes(msg_ptr + 40, 8).expect("controllen"),
            0u64.to_le_bytes()
        );
        assert_eq!(runtime.linux.read_bytes(msg_ptr + 48, 4).expect("flags"), 0u32.to_le_bytes());
    }
}

fn log_cleanup_error(context: &'static str, err: ServiceCallError) {
    match err {
        ServiceCallError::Errno(ERR_EBADF) => {}
        ServiceCallError::Errno(errno) => {
            crate::kwarn!("{} cleanup returned errno {}", context, errno)
        }
        ServiceCallError::Trap(reason) => crate::kwarn!("{} cleanup trapped: {}", context, reason),
        ServiceCallError::Invalid(err) => crate::kwarn!("{} cleanup invalid: {}", context, err),
    }
}

fn encode_flock(lock_type: i16, whence: i16, start: i64, len: i64, pid: u32) -> [u8; 32] {
    let mut encoded = [0u8; 32];
    encoded[0..2].copy_from_slice(&lock_type.to_le_bytes());
    encoded[2..4].copy_from_slice(&whence.to_le_bytes());
    encoded[8..16].copy_from_slice(&start.to_le_bytes());
    encoded[16..24].copy_from_slice(&len.to_le_bytes());
    encoded[24..28].copy_from_slice(&(pid as i32).to_le_bytes());
    encoded
}
