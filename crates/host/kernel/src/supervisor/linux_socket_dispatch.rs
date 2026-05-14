use vmos_abi::{ERR_EOPNOTSUPP, ERR_EPERM, PlanKind};

use super::{
    linux::{LinuxCallResult, LinuxPlan},
    runtime::PrototypeRuntime,
    types::{FdEntry, FdResource, ServiceCallError},
};
use crate::interrupts;

impl<'engine> PrototypeRuntime<'engine> {
    pub(crate) fn note_synthetic_listener(&mut self, _backlog: u64) {
        self.synthetic_listener_connects = self.synthetic_listener_connects.saturating_add(1);
    }

    pub(crate) fn consume_synthetic_listener_connect(&mut self) -> bool {
        if self.synthetic_listener_connects == 0 {
            return false;
        }
        self.synthetic_listener_connects -= 1;
        true
    }

    pub(super) fn plan_socket(&mut self, plan: LinuxPlan) -> Result<LinuxCallResult, &'static str> {
        if self.require_capability("linux_syscall", "linux.socket", "socket").is_err()
            || self.require_capability("net_core", "net.socket", "create").is_err()
        {
            return Ok(LinuxCallResult::Ret(-(ERR_EPERM as i64)));
        }
        let domain = u32::try_from(plan.args[0]).map_err(|_| "socket domain overflowed")?;
        let ty = u32::try_from(plan.args[1]).map_err(|_| "socket type overflowed")?;
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
                return Ok(LinuxCallResult::Ret(-(errno as i64)));
            }
            Err(ServiceCallError::Trap(reason)) => {
                crate::kwarn!("net_core ready_key: {}", reason);
                return Err("net_core trapped while creating socket");
            }
            Err(ServiceCallError::Invalid(err)) => return Err(err),
        };
        match self.linux_socket.register_socket(socket_id, domain, ty, protocol, ready_key) {
            Ok(()) => {}
            Err(ServiceCallError::Errno(errno)) => {
                return Ok(LinuxCallResult::Ret(-(errno as i64)));
            }
            Err(ServiceCallError::Trap(reason)) => {
                crate::kwarn!("linux_socket register_socket: {}", reason);
                return Err("linux_socket_service trapped during socket");
            }
            Err(ServiceCallError::Invalid(err)) => return Err(err),
        }

        let fd = match self.alloc_fd(FdEntry {
            resource: FdResource::Socket { socket_id: socket_id as u64, ready_key },
            cursor: 0,
            fd_flags: 0,
            status_flags: 0,
            cursor_group: None,
        }) {
            Ok(fd) => fd,
            Err(errno) => return Ok(LinuxCallResult::Ret(-(errno as i64))),
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
        let (socket_id, _, handle) = match self.socket_fd_snapshot(fd) {
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
        let result = match plan.kind {
            PlanKind::Bind => {
                let addr_len =
                    u32::try_from(plan.args[2]).map_err(|_| "bind addr_len overflowed")?;
                self.linux_socket.bind_socket(socket_id, addr_len)
            }
            PlanKind::Listen => {
                let backlog =
                    u32::try_from(plan.args[1]).map_err(|_| "listen backlog overflowed")?;
                self.linux_socket.listen_socket(socket_id, backlog)
            }
            PlanKind::Connect => {
                let addr_len =
                    u32::try_from(plan.args[2]).map_err(|_| "connect addr_len overflowed")?;
                self.linux_socket.connect_socket(socket_id, addr_len)
            }
            _ => Ok(()),
        };
        match result {
            Ok(()) => {
                self.semantic.record_socket_state_changed(handle.id, state);
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
        if self.require_capability("linux_syscall", "linux.socket", "accept").is_err() {
            return Ok(LinuxCallResult::Ret(-(ERR_EPERM as i64)));
        }
        let fd = u32::try_from(plan.args[0]).map_err(|_| "accept fd overflowed")?;
        let (socket_id, _, _) = match self.socket_fd_snapshot(fd) {
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
        match self.linux_socket.accept_socket(socket_id) {
            Ok(_) => Ok(LinuxCallResult::Ret(-(ERR_EOPNOTSUPP as i64))),
            Err(ServiceCallError::Errno(errno)) => Ok(LinuxCallResult::Ret(-(errno as i64))),
            Err(ServiceCallError::Trap(reason)) => {
                crate::kwarn!("linux_socket accept: {}", reason);
                Err("linux_socket_service trapped during accept")
            }
            Err(ServiceCallError::Invalid(err)) => Err(err),
        }
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
                self.semantic.record_packet_transmitted(
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
        let (socket_id, _, _) = match self.socket_fd_snapshot(fd) {
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
        if let Ok((socket_id, _, _)) = self.socket_fd_snapshot(fd) {
            return match self.linux_socket.fcntl(socket_id, cmd, arg) {
                Ok(value) => Ok(LinuxCallResult::Ret(value as i64)),
                Err(ServiceCallError::Errno(errno)) => Ok(LinuxCallResult::Ret(-(errno as i64))),
                Err(ServiceCallError::Trap(reason)) => {
                    crate::kwarn!("linux_socket fcntl: {}", reason);
                    Err("linux_socket_service trapped during fcntl")
                }
                Err(ServiceCallError::Invalid(err)) => Err(err),
            };
        }
        Ok(LinuxCallResult::Ret(0))
    }
}
