use alloc::{vec, vec::Vec};

use semantic_core::{FailureEffect, TaskState};
use vmos_abi::{ERR_EFAULT, ERR_EPERM};

use super::{
    events::Event,
    linux::{LinuxCallResult, LinuxPlan},
    pulse::PulseEvent,
    runtime::PrototypeRuntime,
    services::DriverNetEventKind,
    types::{ServiceCallError, WaitRestartClass, WaitToken},
    wait::{WaitOutcome, WaitRegistration, WaitSource},
};
use crate::interrupts;

impl<'engine> PrototypeRuntime<'engine> {
    pub(super) fn plan_sleep(&mut self, plan: LinuxPlan) -> Result<LinuxCallResult, &'static str> {
        if self.require_capability("linux_syscall", "timer.sleep", "arm").is_err() {
            return Ok(LinuxCallResult::Ret(-(ERR_EPERM as i64)));
        }
        let resume_cookie =
            u32::try_from(plan.args[0]).map_err(|_| "sleep resume cookie overflowed")?;
        let delay_ms = u32::try_from(plan.args[1]).map_err(|_| "sleep delay overflowed")?;
        let token = self.waits.register(
            self.scheduler.current_task(),
            WaitRegistration::Timer { delay_ms, resume_cookie },
            interrupts::tick_count(),
            interrupts::TIMER_HZ,
        );
        self.record_wait_token(token);
        Ok(LinuxCallResult::Pending(token))
    }
    pub(super) fn plan_futex_wait(
        &mut self,
        plan: LinuxPlan,
    ) -> Result<LinuxCallResult, &'static str> {
        self.plan_futex_wait_common(plan, u32::MAX)
    }

    pub(super) fn plan_futex_wait_bitset(
        &mut self,
        plan: LinuxPlan,
    ) -> Result<LinuxCallResult, &'static str> {
        let bitset = u32::try_from(plan.args[3]).map_err(|_| "futex bitset overflowed")?;
        if bitset == 0 {
            return Ok(LinuxCallResult::Ret(-(vmos_abi::ERR_EINVAL as i64)));
        }
        self.plan_futex_wait_common(plan, bitset)
    }

    fn plan_futex_wait_common(
        &mut self,
        plan: LinuxPlan,
        bitset: u32,
    ) -> Result<LinuxCallResult, &'static str> {
        if self.require_capability("futex_service", "futex.waitset", "wait").is_err() {
            return Ok(LinuxCallResult::Ret(-(ERR_EPERM as i64)));
        }
        let key = plan.args[0];
        let timeout_ms = if plan.args[1] == u64::MAX {
            None
        } else {
            Some(u32::try_from(plan.args[1]).map_err(|_| "futex timeout overflowed")?)
        };
        let resume_cookie =
            u32::try_from(plan.args[2]).map_err(|_| "futex resume cookie overflowed")?;
        let token = self.waits.register(
            self.scheduler.current_task(),
            WaitRegistration::Futex { timeout_ms, resume_cookie },
            interrupts::tick_count(),
            interrupts::TIMER_HZ,
        );

        let registered = if bitset == u32::MAX {
            self.futex.register_wait(key, token.id)
        } else {
            self.futex.register_wait_bitset(key, token.id, bitset)
        };
        match registered {
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
                crate::kwarn!("futex_wait: {}", reason);
                self.record_service_trap("futex_service", reason);
                Err("futex_service trapped during futex wait")
            }
            Err(ServiceCallError::Invalid(err)) => Err(err),
        }
    }

    pub(super) fn plan_futex_wake(
        &mut self,
        plan: LinuxPlan,
    ) -> Result<LinuxCallResult, &'static str> {
        self.plan_futex_wake_common(plan, u32::MAX)
    }

    pub(super) fn plan_futex_wake_bitset(
        &mut self,
        plan: LinuxPlan,
    ) -> Result<LinuxCallResult, &'static str> {
        let bitset = u32::try_from(plan.args[2]).map_err(|_| "futex bitset overflowed")?;
        if bitset == 0 {
            return Ok(LinuxCallResult::Ret(-(vmos_abi::ERR_EINVAL as i64)));
        }
        self.plan_futex_wake_common(plan, bitset)
    }

    fn plan_futex_wake_common(
        &mut self,
        plan: LinuxPlan,
        bitset: u32,
    ) -> Result<LinuxCallResult, &'static str> {
        if self.require_capability("futex_service", "futex.waitset", "wake").is_err() {
            return Ok(LinuxCallResult::Ret(-(ERR_EPERM as i64)));
        }
        let key = plan.args[0];
        let count = u32::try_from(plan.args[1]).map_err(|_| "futex wake count overflowed")?;
        let woken = if bitset == u32::MAX {
            self.futex.wake(key, count)
        } else {
            self.futex.wake_bitset(key, count, bitset)
        };
        match woken {
            Ok(wait_ids) => {
                for wait_id in &wait_ids {
                    self.scheduler.push_event(Event::WaitReady(*wait_id));
                }
                self.drain_event_queue();
                Ok(LinuxCallResult::Ret(wait_ids.len() as i64))
            }
            Err(ServiceCallError::Errno(errno)) => Ok(LinuxCallResult::Ret(-(errno as i64))),
            Err(ServiceCallError::Trap(reason)) => {
                crate::kwarn!("futex_wake: {}", reason);
                Err("futex_service trapped during futex wake")
            }
            Err(ServiceCallError::Invalid(err)) => Err(err),
        }
    }
    pub(super) fn block_on_wait(
        &mut self,
        label: &str,
        token: WaitToken,
    ) -> Result<LinuxCallResult, &'static str> {
        self.validate_wait_token(token)
            .map_err(|_| "wait token generation check failed before blocking")?;
        if let Err(err) = crate::substrate::dmw::assert_quiescent() {
            self.semantic.record_failure_effect(FailureEffect::CompleteWithErrno(ERR_EFAULT));
            return Err(err);
        }
        loop {
            self.pump_async_sources();

            if let Some(resolution) = self.waits.take_resolution(token) {
                if !matches!(resolution.outcome, WaitOutcome::Restart(_)) {
                    self.validate_wait_token(token)
                        .map_err(|_| "wait token generation check failed before resume")?;
                }
                self.semantic.set_task_state(token.owner_task, TaskState::Running);
                return match resolution.outcome {
                    WaitOutcome::Ready => match resolution.source {
                        WaitSource::Epoll { epoll_id, max_events } => {
                            let _ = self.linux.resume_wait(resolution.resume_cookie)?;
                            self.collect_epoll_ready(epoll_id, max_events)
                        }
                        _ => {
                            let resumed = self.linux.resume_wait(resolution.resume_cookie)?;
                            self.execute_linux_step("linux_resume", resumed)
                        }
                    },
                    WaitOutcome::Cancelled(errno) => {
                        self.semantic.record_failure_effect(FailureEffect::CancelWaitToken {
                            wait: token.id,
                            errno,
                        });
                        match token.kind {
                            super::types::WaitKind::Futex => {
                                match self.futex.cancel_wait(token.id) {
                                    Ok(()) | Err(ServiceCallError::Errno(_)) => {}
                                    Err(ServiceCallError::Trap(reason)) => {
                                        crate::kwarn!("futex cancel: {}", reason);
                                    }
                                    Err(ServiceCallError::Invalid(err)) => {
                                        crate::kwarn!("futex cancel: {}", err);
                                    }
                                }
                            }
                            super::types::WaitKind::Epoll => {
                                match self.epoll.cancel_wait(token.id) {
                                    Ok(()) | Err(ServiceCallError::Errno(_)) => {}
                                    Err(ServiceCallError::Trap(reason)) => {
                                        crate::kwarn!("epoll cancel: {}", reason);
                                    }
                                    Err(ServiceCallError::Invalid(err)) => {
                                        crate::kwarn!("epoll cancel: {}", err);
                                    }
                                }
                            }
                            super::types::WaitKind::Timer => {}
                        }
                        let cancelled = self.linux.cancel_wait(resolution.resume_cookie, errno)?;
                        self.execute_linux_step("linux_cancel", cancelled)
                    }
                    WaitOutcome::Restart(class) => {
                        self.restart_count += 1;
                        crate::kinfo!("{} restarted as {:?}", label, class);
                        self.semantic.record_failure_effect(FailureEffect::RestartSyscall {
                            wait: Some(token.id),
                        });
                        let restarted = self.linux.restart_wait(resolution.resume_cookie, class)?;
                        Ok(match self.execute_linux_step("linux_restart", restarted)? {
                            LinuxCallResult::Pending(next) => self.block_on_wait(label, next),
                            ready => Ok(ready),
                        }?)
                    }
                };
            }

            interrupts::wait_for_interrupt();
        }
    }
    pub(super) fn drain_event_queue(&mut self) {
        while let Some(event) = self.scheduler.pop_event() {
            self.record_scheduler_event(event);
            self.waits.apply_event(event);
        }
    }
    pub(super) fn pump_async_sources(&mut self) {
        let mut due_events = vec![];
        self.waits.collect_due_events(interrupts::tick_count(), &mut due_events);
        for event in due_events {
            self.scheduler.push_event(event);
        }

        let mut pulse_events = Vec::new();
        self.pulse.collect_events(interrupts::tick_count(), &mut pulse_events);
        for event in pulse_events {
            match event {
                PulseEvent::Ready(ready_key) => match self.epoll.notify_ready(ready_key) {
                    Ok(wait_ids) => {
                        for wait_id in wait_ids {
                            self.scheduler.push_event(Event::WaitReady(wait_id));
                        }
                    }
                    Err(ServiceCallError::Trap(reason)) => {
                        crate::kwarn!("epoll ready notification: {}", reason);
                    }
                    Err(ServiceCallError::Invalid(err)) => {
                        crate::kwarn!("epoll ready notification: {}", err);
                    }
                    Err(ServiceCallError::Errno(errno)) => {
                        crate::kwarn!("epoll ready notification errno={}", errno);
                    }
                },
                PulseEvent::Restart(ready_key) => match self.epoll.restart_key(ready_key) {
                    Ok(wait_ids) => {
                        for wait_id in wait_ids {
                            self.scheduler.push_event(Event::WaitRestart(
                                wait_id,
                                WaitRestartClass::DriverRestart,
                            ));
                        }
                    }
                    Err(ServiceCallError::Trap(reason)) => {
                        crate::kwarn!("epoll restart notification: {}", reason);
                    }
                    Err(ServiceCallError::Invalid(err)) => {
                        crate::kwarn!("epoll restart notification: {}", err);
                    }
                    Err(ServiceCallError::Errno(errno)) => {
                        crate::kwarn!("epoll restart notification errno={}", errno);
                    }
                },
            }
        }

        let now_ticks = interrupts::tick_count();
        for _ in 0..8 {
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
                    match self.net_core.deliver_packet_frame(&event.frame) {
                        Ok(Some(ready_key)) => {
                            let socket = self
                                .socket_resource_for_ready_key(ready_key)
                                .map(|handle| handle.id);
                            self.semantic.record_packet_received(
                                self.net.interface.id,
                                socket,
                                ready_key,
                                event.len as usize,
                            );
                            self.notify_ready_key(ready_key, "epoll net ready notification");
                        }
                        Ok(None) => {
                            self.semantic.record_packet_received(
                                self.net.interface.id,
                                None,
                                0,
                                event.len as usize,
                            );
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
            }
        }
        self.drain_event_queue();
    }
}
