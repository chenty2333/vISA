use semantic_core::FailureEffect;
use vmos_abi::ERR_EPERM;

use super::{
    linux::{LinuxCallResult, LinuxPlan},
    runtime::PrototypeRuntime,
    types::{FdEntry, FdResource, ServiceCallError},
    wait::WaitRegistration,
};
use crate::interrupts;

impl<'engine> PrototypeRuntime<'engine> {
    pub(super) fn plan_epoll_create1(
        &mut self,
        plan: LinuxPlan,
    ) -> Result<LinuxCallResult, &'static str> {
        if self.require_capability("epoll_service", "epoll.instance", "create").is_err() {
            return Ok(LinuxCallResult::Ret(-(ERR_EPERM as i64)));
        }
        let flags = u32::try_from(plan.args[0]).map_err(|_| "epoll_create1 flags overflowed")?;
        if !self.can_allocate_fds(1) {
            return Ok(LinuxCallResult::Ret(-(vmos_abi::ERR_EMFILE as i64)));
        }
        match self.epoll.create(flags) {
            Ok(epoll_id) => {
                let fd = match self.alloc_fd(FdEntry {
                    resource: FdResource::EpollInstance { epoll_id },
                    cursor: 0,
                    fd_flags: 0,
                    status_flags: 0,
                    cursor_group: None,
                }) {
                    Ok(fd) => fd,
                    Err(errno) => return Ok(LinuxCallResult::Ret(-(errno as i64))),
                };
                Ok(LinuxCallResult::Ret(fd as i64))
            }
            Err(ServiceCallError::Errno(errno)) => Ok(LinuxCallResult::Ret(-(errno as i64))),
            Err(ServiceCallError::Trap(reason)) => {
                crate::kwarn!("epoll_create1: {}", reason);
                Err("epoll_service trapped during epoll_create1")
            }
            Err(ServiceCallError::Invalid(err)) => Err(err),
        }
    }
    pub(super) fn plan_epoll_ctl(
        &mut self,
        plan: LinuxPlan,
    ) -> Result<LinuxCallResult, &'static str> {
        if self.require_capability("epoll_service", "epoll.instance", "ctl").is_err() {
            return Ok(LinuxCallResult::Ret(-(ERR_EPERM as i64)));
        }
        let epfd = u32::try_from(plan.args[0]).map_err(|_| "epoll_ctl epfd overflowed")?;
        let op = u32::try_from(plan.args[1]).map_err(|_| "epoll_ctl op overflowed")?;
        let fd = u32::try_from(plan.args[2]).map_err(|_| "epoll_ctl fd overflowed")?;
        let events = u32::try_from(plan.args[3]).map_err(|_| "epoll_ctl events overflowed")?;
        let data = plan.args[4];
        let epoll_id = match self.epoll_id_from_fd(epfd) {
            Ok(epoll_id) => epoll_id,
            Err(ServiceCallError::Errno(errno)) => {
                return Ok(LinuxCallResult::Ret(-(errno as i64)));
            }
            Err(ServiceCallError::Trap(reason)) => {
                crate::kwarn!("epoll_ctl epfd validation: {}", reason);
                return Err("epoll_ctl epfd validation trapped");
            }
            Err(ServiceCallError::Invalid(err)) => return Err(err),
        };
        let ready_key = match self.fd_ready_key(fd) {
            Ok(ready_key) => ready_key,
            Err(ServiceCallError::Errno(errno)) => {
                return Ok(LinuxCallResult::Ret(-(errno as i64)));
            }
            Err(ServiceCallError::Trap(reason)) => {
                crate::kwarn!("epoll_ctl fd validation: {}", reason);
                return Err("epoll_ctl fd validation trapped");
            }
            Err(ServiceCallError::Invalid(err)) => return Err(err),
        };
        match self.epoll.ctl(epoll_id, op, ready_key, events, data) {
            Ok(()) => {
                if self.pulse.is_ready_key(ready_key)
                    || self.socket_ready_key_matches_events(ready_key, events)
                    || self.pipe_ready_key_matches_events(ready_key, events)
                    || self.socketpair_ready_key_matches_events(ready_key, events)
                    || self.eventfd_ready_key_matches_events(ready_key, events)
                {
                    let _ = self.epoll.notify_ready(ready_key);
                }
                Ok(LinuxCallResult::Ret(0))
            }
            Err(ServiceCallError::Errno(errno)) => Ok(LinuxCallResult::Ret(-(errno as i64))),
            Err(ServiceCallError::Trap(reason)) => {
                crate::kwarn!("epoll_ctl: {}", reason);
                Err("epoll_service trapped during epoll_ctl")
            }
            Err(ServiceCallError::Invalid(err)) => Err(err),
        }
    }
    pub(super) fn plan_epoll_wait(
        &mut self,
        plan: LinuxPlan,
    ) -> Result<LinuxCallResult, &'static str> {
        if self.require_capability("epoll_service", "epoll.instance", "wait").is_err() {
            return Ok(LinuxCallResult::Ret(-(ERR_EPERM as i64)));
        }
        let epfd = u32::try_from(plan.args[0]).map_err(|_| "epoll_wait epfd overflowed")?;
        let max_events =
            u32::try_from(plan.args[1]).map_err(|_| "epoll_wait max_events overflowed")?;
        let timeout_ms = if plan.args[2] == u64::MAX {
            None
        } else {
            Some(u32::try_from(plan.args[2]).map_err(|_| "epoll_wait timeout overflowed")?)
        };
        let resume_cookie =
            u32::try_from(plan.args[3]).map_err(|_| "epoll_wait resume cookie overflowed")?;
        let epoll_id =
            self.epoll_id_from_fd(epfd).map_err(|_| "epoll_wait targeted an invalid epoll fd")?;

        self.pump_async_sources();
        let ready = match self.epoll.collect_ready(epoll_id, max_events) {
            Ok(bytes) => bytes,
            Err(ServiceCallError::Errno(errno)) => {
                return Ok(LinuxCallResult::Ret(-(errno as i64)));
            }
            Err(ServiceCallError::Trap(reason)) => {
                crate::kwarn!("epoll_wait collect_ready: {}", reason);
                return Err("epoll_service trapped during epoll_wait");
            }
            Err(ServiceCallError::Invalid(err)) => return Err(err),
        };
        if !ready.is_empty() {
            return self.encode_epoll_ready(&ready, max_events);
        }
        if timeout_ms == Some(0) {
            return Ok(LinuxCallResult::Ret(0));
        }

        let token = self.waits.register(
            self.scheduler.current_task(),
            WaitRegistration::Epoll { epoll_id, max_events, timeout_ms, resume_cookie },
            interrupts::tick_count(),
            interrupts::TIMER_HZ,
        );
        match self.epoll.arm_wait(epoll_id, token.id) {
            Ok(()) => {
                self.record_wait_token(token);
                Ok(LinuxCallResult::Pending(token))
            }
            Err(ServiceCallError::Errno(errno)) => {
                self.semantic.record_wait_cancelled(token.id, errno);
                self.semantic.record_failure_effect(FailureEffect::CancelWaitToken {
                    wait: token.id,
                    errno,
                });
                Ok(LinuxCallResult::Ret(-(errno as i64)))
            }
            Err(ServiceCallError::Trap(reason)) => {
                crate::kwarn!("epoll_wait arm_wait: {}", reason);
                self.record_service_trap("epoll_service", reason);
                Err("epoll_service trapped during epoll_wait")
            }
            Err(ServiceCallError::Invalid(err)) => Err(err),
        }
    }
    pub(super) fn plan_epoll_ready(
        &mut self,
        plan: LinuxPlan,
    ) -> Result<LinuxCallResult, &'static str> {
        if self.require_capability("epoll_service", "epoll.instance", "wait").is_err() {
            return Ok(LinuxCallResult::Ret(-(ERR_EPERM as i64)));
        }
        let epoll_id =
            u32::try_from(plan.args[0]).map_err(|_| "epoll_ready epoll id overflowed")?;
        let max_events =
            u32::try_from(plan.args[1]).map_err(|_| "epoll_ready max_events overflowed")?;
        let ready = match self.epoll.collect_ready(epoll_id, max_events) {
            Ok(bytes) => bytes,
            Err(ServiceCallError::Errno(errno)) => {
                return Ok(LinuxCallResult::Ret(-(errno as i64)));
            }
            Err(ServiceCallError::Trap(reason)) => {
                crate::kwarn!("epoll_ready: {}", reason);
                return Err("epoll_service trapped during epoll ready");
            }
            Err(ServiceCallError::Invalid(err)) => return Err(err),
        };
        if ready.is_empty() {
            return Ok(LinuxCallResult::Ret(0));
        }
        self.encode_epoll_ready(&ready, max_events)
    }
    pub(super) fn collect_epoll_ready(
        &mut self,
        epoll_id: u32,
        max_events: u32,
    ) -> Result<LinuxCallResult, &'static str> {
        let ready = match self.epoll.collect_ready(epoll_id, max_events) {
            Ok(bytes) => bytes,
            Err(ServiceCallError::Errno(errno)) => {
                return Ok(LinuxCallResult::Ret(-(errno as i64)));
            }
            Err(ServiceCallError::Trap(reason)) => {
                crate::kwarn!("epoll collect_ready: {}", reason);
                return Err("epoll_service trapped while collecting ready events");
            }
            Err(ServiceCallError::Invalid(err)) => return Err(err),
        };
        if ready.is_empty() {
            return Ok(LinuxCallResult::Ret(0));
        }
        self.encode_epoll_ready(&ready, max_events)
    }
    pub(super) fn encode_epoll_ready(
        &mut self,
        records: &[u8],
        max_events: u32,
    ) -> Result<LinuxCallResult, &'static str> {
        let bytes = self.linux.encode_epoll_events(records, max_events)?;
        Ok(LinuxCallResult::Bytes(bytes))
    }
}
