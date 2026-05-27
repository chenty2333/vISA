use alloc::{vec, vec::Vec};

use semantic_core::FailureEffect;
use vmos_abi::{
    ERR_EAGAIN, ERR_EDEADLK, ERR_EFAULT, ERR_EINTR, ERR_EINVAL, ERR_EPERM, ERR_ETIMEDOUT,
    FUTEX_OWNER_DIED, FUTEX_PI_TIMEOUT_MONOTONIC, FUTEX_PI_TIMEOUT_NONE, FUTEX_PI_TIMEOUT_REALTIME,
    FUTEX_TID_MASK, FUTEX_WAITERS,
};

use super::{
    events::Event,
    linux::{LinuxCallResult, LinuxPlan},
    pulse::PulseEvent,
    runtime::PrototypeRuntime,
    types::{ServiceCallError, WaitRestartClass, WaitToken},
    wait::{WaitOutcome, WaitRegistration, WaitSource},
};
use crate::interrupts;

const GENERIC_TIMESPEC_SIZE: usize = 16;

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

    pub(super) fn plan_pause(&mut self, _plan: LinuxPlan) -> Result<LinuxCallResult, &'static str> {
        let token = self.waits.register(
            self.scheduler.current_task(),
            WaitRegistration::Signal,
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

    pub(super) fn plan_futex_wait_requeue_pi(
        &mut self,
        plan: LinuxPlan,
    ) -> Result<LinuxCallResult, &'static str> {
        self.plan_futex_wait_common_with_mode(plan, u32::MAX, true)
    }

    fn plan_futex_wait_common(
        &mut self,
        plan: LinuxPlan,
        bitset: u32,
    ) -> Result<LinuxCallResult, &'static str> {
        self.plan_futex_wait_common_with_mode(plan, bitset, false)
    }

    fn plan_futex_wait_common_with_mode(
        &mut self,
        plan: LinuxPlan,
        bitset: u32,
        requeue_pi: bool,
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
            WaitRegistration::Futex { timeout_ms, resume_cookie, pi: requeue_pi },
            interrupts::tick_count(),
            interrupts::TIMER_HZ,
        );
        let wait_priority = self.current_task_priority();

        let registered = if requeue_pi {
            self.futex.register_wait_requeue_pi(key, token.id, wait_priority)
        } else if bitset == u32::MAX {
            self.futex.register_wait_with_priority(key, token.id, wait_priority)
        } else {
            self.futex.register_wait_bitset_with_priority(key, token.id, bitset, wait_priority)
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

    pub(super) fn plan_futex_requeue(
        &mut self,
        plan: LinuxPlan,
    ) -> Result<LinuxCallResult, &'static str> {
        if self.require_capability("futex_service", "futex.waitset", "requeue").is_err() {
            return Ok(LinuxCallResult::Ret(-(ERR_EPERM as i64)));
        }
        let src_key = plan.args[0];
        let requeue_count =
            u32::try_from(plan.args[1]).map_err(|_| "futex requeue count overflowed")?;
        let dst_key = plan.args[2];
        let wake_count = u32::try_from(plan.args[3]).map_err(|_| "futex wake count overflowed")?;
        match self.futex.requeue(src_key, requeue_count, dst_key, wake_count) {
            Ok((total, wait_ids)) => {
                for wait_id in &wait_ids {
                    self.scheduler.push_event(Event::WaitReady(*wait_id));
                }
                self.drain_event_queue();
                Ok(LinuxCallResult::Ret(total as i64))
            }
            Err(ServiceCallError::Errno(errno)) => Ok(LinuxCallResult::Ret(-(errno as i64))),
            Err(ServiceCallError::Trap(reason)) => {
                crate::kwarn!("futex_requeue: {}", reason);
                Err("futex_service trapped during futex requeue")
            }
            Err(ServiceCallError::Invalid(err)) => Err(err),
        }
    }

    pub(super) fn plan_futex_lock_pi(
        &mut self,
        plan: LinuxPlan,
    ) -> Result<LinuxCallResult, &'static str> {
        let key = plan.args[0];
        let try_only = plan.args[2] != 0;
        let timeout_ms =
            match self.generic_futex_pi_timeout_ms(plan.args[3], plan.args[4], plan.args[5]) {
                Ok(timeout_ms) => timeout_ms,
                Err(errno) => return Ok(LinuxCallResult::Ret(-(errno as i64))),
            };
        let tid = self.current_tid() & FUTEX_TID_MASK;
        let word = match self.read_generic_futex_word(key) {
            Ok(word) => word,
            Err(errno) => return Ok(LinuxCallResult::Ret(-(errno as i64))),
        };
        let owner = word & FUTEX_TID_MASK;

        if owner == 0 {
            return self.write_generic_futex_word_ret(key, futex_pi_owner_word(word, tid));
        }
        if owner == tid {
            return Ok(LinuxCallResult::Ret(-(ERR_EDEADLK as i64)));
        }
        if try_only {
            return Ok(LinuxCallResult::Ret(-(ERR_EAGAIN as i64)));
        }
        if timeout_ms == Some(0) {
            return Ok(LinuxCallResult::Ret(-(ERR_ETIMEDOUT as i64)));
        }
        if self.require_capability("futex_service", "futex.waitset", "wait").is_err() {
            return Ok(LinuxCallResult::Ret(-(ERR_EPERM as i64)));
        }

        let wait_word = futex_pi_wait_word(word);
        if wait_word != word {
            let result = self.write_generic_futex_word_ret(key, wait_word)?;
            if let LinuxCallResult::Ret(ret) = result
                && ret < 0
            {
                return Ok(LinuxCallResult::Ret(ret));
            }
        }
        let owner_task = self.task_id_for_tid(owner);
        let wait_priority = self.current_task_priority();
        if let Some(owner_task) = owner_task {
            self.register_futex_pi_boost(owner_task, key, wait_priority);
        }

        let token = self.waits.register(
            self.scheduler.current_task(),
            WaitRegistration::Futex { timeout_ms, resume_cookie: 0, pi: true },
            interrupts::tick_count(),
            interrupts::TIMER_HZ,
        );
        match self.futex.register_wait_pi(key, token.id, wait_priority) {
            Ok(()) => self.record_wait_token(token),
            Err(ServiceCallError::Errno(errno)) => {
                self.restore_generic_futex_wait_word_if_unwaited(key, word, wait_word);
                if let Some(owner_task) = owner_task {
                    self.refresh_futex_pi_boost(owner_task, key);
                }
                self.semantic.record_wait_cancelled(token.id, errno);
                self.semantic.record_failure_effect(FailureEffect::CancelWaitToken {
                    wait: token.id,
                    errno,
                });
                return Ok(LinuxCallResult::Ret(-(errno as i64)));
            }
            Err(ServiceCallError::Trap(reason)) => {
                self.restore_generic_futex_wait_word_if_unwaited(key, word, wait_word);
                crate::kwarn!("futex_lock_pi: {}", reason);
                return Err("futex_service trapped during futex pi lock");
            }
            Err(ServiceCallError::Invalid(err)) => {
                self.restore_generic_futex_wait_word_if_unwaited(key, word, wait_word);
                return Err(err);
            }
        }

        match self.block_on_wait("generic_futex_lock_pi", token)? {
            LinuxCallResult::Ret(0) => {
                let current_word = match self.read_generic_futex_word(key) {
                    Ok(word) => word,
                    Err(errno) => return Ok(LinuxCallResult::Ret(-(errno as i64))),
                };
                let next_word = futex_pi_owner_word(current_word, tid);
                let result = self.write_generic_futex_word_ret(key, next_word)?;
                self.adopt_futex_pi_after_wait(key, owner_task);
                Ok(result)
            }
            LinuxCallResult::Ret(ret) => {
                self.restore_generic_futex_wait_word_if_unwaited(key, word, wait_word);
                if let Some(owner_task) = owner_task {
                    self.refresh_futex_pi_boost(owner_task, key);
                }
                Ok(LinuxCallResult::Ret(ret))
            }
            _ => {
                self.restore_generic_futex_wait_word_if_unwaited(key, word, wait_word);
                Ok(LinuxCallResult::Ret(-(ERR_EINVAL as i64)))
            }
        }
    }

    pub(super) fn plan_futex_unlock_pi(
        &mut self,
        plan: LinuxPlan,
    ) -> Result<LinuxCallResult, &'static str> {
        let key = plan.args[0];
        let tid = self.current_tid() & FUTEX_TID_MASK;
        let word = match self.read_generic_futex_word(key) {
            Ok(word) => word,
            Err(errno) => return Ok(LinuxCallResult::Ret(-(errno as i64))),
        };
        let owner = word & FUTEX_TID_MASK;
        if owner != tid {
            return Ok(LinuxCallResult::Ret(-(ERR_EPERM as i64)));
        }
        let owner_task = self.current_task_id();
        if word & FUTEX_WAITERS != 0 {
            match self.prepare_futex_pi_handoff(key) {
                Ok(Some(handoff)) => {
                    let next_word = futex_pi_handoff_word(
                        word,
                        handoff.next_owner_tid & FUTEX_TID_MASK,
                        handoff.has_more_waiters,
                    );
                    let result = self.write_generic_futex_word_ret(key, next_word)?;
                    if matches!(result, LinuxCallResult::Ret(0)) {
                        match self.complete_futex_pi_handoff(key, owner_task, handoff) {
                            Ok(()) => return Ok(result),
                            Err(ServiceCallError::Errno(errno)) => {
                                return Ok(LinuxCallResult::Ret(-(errno as i64)));
                            }
                            Err(ServiceCallError::Trap(reason)) => {
                                crate::kwarn!("futex_unlock_pi handoff: {}", reason);
                                return Err("futex_service trapped during futex pi unlock");
                            }
                            Err(ServiceCallError::Invalid(err)) => return Err(err),
                        }
                    }
                    return Ok(result);
                }
                Ok(None) => {
                    let result =
                        self.write_generic_futex_word_ret(key, futex_pi_unlock_empty_word(word))?;
                    self.release_futex_pi_boost(owner_task, key);
                    return Ok(result);
                }
                Err(ServiceCallError::Errno(errno)) => {
                    return Ok(LinuxCallResult::Ret(-(errno as i64)));
                }
                Err(ServiceCallError::Trap(reason)) => {
                    crate::kwarn!("futex_unlock_pi prepare handoff: {}", reason);
                    return Err("futex_service trapped during futex pi unlock");
                }
                Err(ServiceCallError::Invalid(err)) => return Err(err),
            }
        }
        let result = self.write_generic_futex_word_ret(key, 0)?;
        self.release_futex_pi_boost(owner_task, key);
        Ok(result)
    }

    fn read_generic_futex_word(&mut self, ptr: u64) -> Result<u32, i32> {
        if ptr & 0x3 != 0 {
            return Err(ERR_EINVAL);
        }
        let ptr = u32::try_from(ptr).map_err(|_| ERR_EFAULT)?;
        let bytes = self.linux.read_bytes(ptr, 4).map_err(|_| ERR_EFAULT)?;
        Ok(u32::from_le_bytes(bytes[..4].try_into().map_err(|_| ERR_EFAULT)?))
    }

    fn write_generic_futex_word_ret(
        &mut self,
        ptr: u64,
        value: u32,
    ) -> Result<LinuxCallResult, &'static str> {
        if ptr & 0x3 != 0 {
            return Ok(LinuxCallResult::Ret(-(ERR_EINVAL as i64)));
        }
        let ptr = match u32::try_from(ptr) {
            Ok(ptr) => ptr,
            Err(_) => return Ok(LinuxCallResult::Ret(-(ERR_EFAULT as i64))),
        };
        match self.linux.write_bytes(ptr, &value.to_le_bytes()) {
            Ok(()) => Ok(LinuxCallResult::Ret(0)),
            Err(_) => Ok(LinuxCallResult::Ret(-(ERR_EFAULT as i64))),
        }
    }

    fn generic_futex_pi_timeout_ms(
        &mut self,
        timeout_ptr: u64,
        timeout_len: u64,
        timeout_clock: u64,
    ) -> Result<Option<u32>, i32> {
        if timeout_clock == FUTEX_PI_TIMEOUT_NONE {
            return Ok(None);
        }
        if timeout_ptr == 0 || timeout_len != GENERIC_TIMESPEC_SIZE as u64 {
            return Err(ERR_EINVAL);
        }
        let ptr = u32::try_from(timeout_ptr).map_err(|_| ERR_EFAULT)?;
        let bytes =
            self.linux.read_bytes(ptr, GENERIC_TIMESPEC_SIZE as u32).map_err(|_| ERR_EFAULT)?;
        let sec = i64::from_le_bytes(bytes[0..8].try_into().map_err(|_| ERR_EINVAL)?);
        let nsec = i64::from_le_bytes(bytes[8..16].try_into().map_err(|_| ERR_EINVAL)?);
        if sec < 0 || !(0..1_000_000_000).contains(&nsec) {
            return Err(ERR_EINVAL);
        }
        let target_ns = (sec as u64).saturating_mul(1_000_000_000).saturating_add(nsec as u64);
        let tick = interrupts::tick_count();
        let timer_hz = interrupts::TIMER_HZ as u64;
        let now_ns = match timeout_clock {
            FUTEX_PI_TIMEOUT_REALTIME => self.runtime_realtime_now_ns(tick, timer_hz),
            FUTEX_PI_TIMEOUT_MONOTONIC => 1_000_000_000u64
                .saturating_add(tick.saturating_mul(1_000_000_000) / timer_hz.max(1)),
            _ => return Err(ERR_EINVAL),
        };
        let delay_ms =
            target_ns.saturating_sub(now_ns).div_ceil(1_000_000).min(u32::MAX as u64) as u32;
        Ok(Some(delay_ms))
    }

    fn restore_generic_futex_wait_word_if_unwaited(
        &mut self,
        key: u64,
        original_word: u32,
        wait_word: u32,
    ) {
        let Ok(waiters) = self.futex.pi_waiter_count(key) else {
            crate::kwarn!("generic futex pi restore skipped after pi-waiter-count failure");
            return;
        };
        if waiters != 0 {
            return;
        }
        let Ok(current_word) = self.read_generic_futex_word(key) else {
            crate::kwarn!("generic futex pi restore skipped after word read failure");
            return;
        };
        if current_word != wait_word {
            return;
        }
        match self.write_generic_futex_word_ret(key, original_word) {
            Ok(LinuxCallResult::Ret(0)) => {}
            Ok(LinuxCallResult::Ret(errno)) => {
                crate::kwarn!("generic futex pi restore write returned {}", errno);
            }
            Ok(other) => {
                crate::kwarn!("generic futex pi restore returned unexpected {:?}", other);
            }
            Err(err) => {
                crate::kwarn!("generic futex pi restore failed: {}", err);
            }
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
            let mut connect_ready = false;
            if let Some(WaitSource::SocketConnect { fd }) = self.waits.pending_source(token)
                && self.socket_connect_fd_is_ready(fd)
            {
                self.scheduler.push_event(Event::WaitReady(token.id));
                self.drain_event_queue();
                connect_ready = true;
            }
            if !connect_ready {
                self.pump_async_sources();
            }
            if let Some(WaitSource::SocketAccept { fd, .. }) = self.waits.pending_source(token)
                && self.socket_accept_fd_is_ready(fd)
            {
                self.scheduler.push_event(Event::WaitReady(token.id));
                self.drain_event_queue();
            }
            if let Some(WaitSource::SocketSend { fd, .. }) = self.waits.pending_source(token)
                && self.socket_send_fd_is_ready(fd)
            {
                self.scheduler.push_event(Event::WaitReady(token.id));
                self.drain_event_queue();
            }
            if let Some(source) = self.waits.pending_source(token) {
                let fd = match source {
                    WaitSource::SocketRecv { fd, .. }
                    | WaitSource::SocketReadv { fd, .. }
                    | WaitSource::SocketRecvMsg { fd, .. } => Some(fd),
                    _ => None,
                };
                if let Some(fd) = fd
                    && self.socket_recv_fd_is_ready(fd)
                {
                    self.scheduler.push_event(Event::WaitReady(token.id));
                    self.drain_event_queue();
                }
            }
            if let Some(WaitSource::FileLock { fd, owner, lock_type, whence, start, len }) =
                self.waits.pending_source(token)
                && self.file_lock_wait_is_ready(fd, owner, lock_type, whence, start, len)
            {
                self.scheduler.push_event(Event::WaitReady(token.id));
                self.drain_event_queue();
            }
            if let Some(WaitSource::Flock { fd, owner, exclusive }) =
                self.waits.pending_source(token)
                && self.flock_wait_is_ready(fd, owner, exclusive)
            {
                self.scheduler.push_event(Event::WaitReady(token.id));
                self.drain_event_queue();
            }
            if let Some(WaitSource::ChildExit { caller_pid, selector }) =
                self.waits.pending_source(token)
                && self.wait4_child_is_ready(caller_pid, selector)
            {
                self.scheduler.push_event(Event::WaitReady(token.id));
                self.drain_event_queue();
            }
            if let Some(WaitSource::FdSet { read_bits, write_bits, error_bits, nfds }) =
                self.waits.pending_source(token)
                && self.fdset_wait_is_ready(read_bits, write_bits, error_bits, nfds)
            {
                self.scheduler.push_event(Event::WaitReady(token.id));
                self.drain_event_queue();
            }
            if let Some(WaitSource::SignalSet { wait_set }) = self.waits.pending_source(token)
                && self.has_pending_signal_matching_set_for_task(token.owner_task, wait_set)
            {
                self.scheduler.push_event(Event::WaitReady(token.id));
                self.drain_event_queue();
            }
            if self.waits.is_pending(token)
                && self.has_unblocked_pending_signal_for_task(token.owner_task)
            {
                self.scheduler.push_event(Event::WaitCancelled(token.id, ERR_EINTR));
                self.drain_event_queue();
            }

            if let Some(resolution) = self.waits.take_resolution(token) {
                if !matches!(resolution.outcome, WaitOutcome::Restart(_)) {
                    self.validate_wait_token(token)
                        .map_err(|_| "wait token generation check failed before resume")?;
                }
                self.record_wait_owner_running(token.owner_task);
                return match resolution.outcome {
                    WaitOutcome::Ready => match resolution.source {
                        WaitSource::Epoll { epoll_id, max_events } => {
                            let _ = self.linux.resume_wait(resolution.resume_cookie)?;
                            self.collect_epoll_ready(epoll_id, max_events)
                        }
                        WaitSource::SocketConnect { fd } => self.retry_socket_connect_wait(fd),
                        WaitSource::SocketAccept {
                            fd,
                            flags,
                            addr_ptr,
                            addr_len_ptr,
                            write_addr,
                        } => self.try_accept_fd_with_sockaddr_writeback(
                            fd,
                            flags,
                            addr_ptr,
                            addr_len_ptr,
                            write_addr,
                        ),
                        WaitSource::SocketSend { fd, ptr, len, flags } => {
                            self.retry_socket_send_wait(fd, ptr, len, flags)
                        }
                        WaitSource::SocketRecv {
                            fd,
                            count,
                            flags,
                            addr_ptr,
                            addr_len_ptr,
                            write_addr,
                        } => self.retry_socket_recv_wait(
                            fd,
                            count,
                            flags,
                            addr_ptr,
                            addr_len_ptr,
                            write_addr,
                        ),
                        WaitSource::SocketReadv { fd, iov_ptr, iovcnt } => {
                            self.retry_socket_readv_wait(fd, iov_ptr, iovcnt)
                        }
                        WaitSource::SocketRecvMsg { fd, msg_ptr, flags } => {
                            self.retry_socket_recvmsg_wait(fd, msg_ptr, flags)
                        }
                        WaitSource::SeccompUserNotif { notification_id } => {
                            let completion = self
                                .take_seccomp_notification_response(notification_id)
                                .map_err(|_| "seccomp user notification missing response")?;
                            Ok(match completion.response {
                                super::types::SeccompNotificationResponse::Return(ret) => {
                                    LinuxCallResult::Ret(ret)
                                }
                                super::types::SeccompNotificationResponse::Continue => {
                                    LinuxCallResult::SeccompContinue {
                                        syscall: completion.syscall,
                                        args: completion.args,
                                    }
                                }
                            })
                        }
                        WaitSource::SeccompTrace { trace_id } => {
                            let completion = self
                                .take_seccomp_trace_response(trace_id)
                                .map_err(|_| "seccomp trace missing response")?;
                            Ok(match completion.response {
                                super::types::SeccompTraceResponse::Return(ret) => {
                                    LinuxCallResult::Ret(ret)
                                }
                                super::types::SeccompTraceResponse::Continue => {
                                    LinuxCallResult::SeccompContinue {
                                        syscall: completion.syscall,
                                        args: completion.args,
                                    }
                                }
                            })
                        }
                        WaitSource::FileLock { .. } => Ok(LinuxCallResult::Ret(0)),
                        WaitSource::Flock { .. } => Ok(LinuxCallResult::Ret(0)),
                        WaitSource::ChildExit { .. } => Ok(LinuxCallResult::Ret(0)),
                        WaitSource::FdSet { .. } => Ok(LinuxCallResult::Ret(0)),
                        WaitSource::Signal => Ok(LinuxCallResult::Ret(0)),
                        WaitSource::SignalSet { .. } => Ok(LinuxCallResult::Ret(0)),
                        WaitSource::Futex { .. } if resolution.resume_cookie == 0 => {
                            Ok(LinuxCallResult::Ret(0))
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
                        if let WaitSource::SeccompUserNotif { notification_id } = resolution.source
                        {
                            self.cancel_seccomp_notification(notification_id);
                        }
                        if let WaitSource::SeccompTrace { trace_id } = resolution.source {
                            self.cancel_seccomp_trace_event(trace_id);
                        }
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
                            super::types::WaitKind::SocketConnect => {}
                            super::types::WaitKind::SocketAccept => {}
                            super::types::WaitKind::SeccompUserNotif => {}
                            super::types::WaitKind::SeccompTrace => {}
                            super::types::WaitKind::FileLock => {}
                            super::types::WaitKind::Flock => {}
                            super::types::WaitKind::ChildExit => {}
                            super::types::WaitKind::FdReadable => {}
                            super::types::WaitKind::FdWritable => {}
                            super::types::WaitKind::Signal => {}
                        }
                        let manual_futex_wait =
                            matches!(resolution.source, WaitSource::Futex { .. })
                                && resolution.resume_cookie == 0;
                        if manual_futex_wait
                            || matches!(
                                resolution.source,
                                WaitSource::SocketConnect { .. }
                                    | WaitSource::SocketAccept { .. }
                                    | WaitSource::SocketSend { .. }
                                    | WaitSource::SocketRecv { .. }
                                    | WaitSource::SocketReadv { .. }
                                    | WaitSource::SocketRecvMsg { .. }
                                    | WaitSource::SeccompUserNotif { .. }
                                    | WaitSource::SeccompTrace { .. }
                                    | WaitSource::FileLock { .. }
                                    | WaitSource::Flock { .. }
                                    | WaitSource::ChildExit { .. }
                                    | WaitSource::FdSet { .. }
                                    | WaitSource::Signal
                                    | WaitSource::SignalSet { .. }
                            )
                        {
                            return Ok(LinuxCallResult::Ret(-(errno as i64)));
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
                        if matches!(resolution.source, WaitSource::Futex { .. })
                            && resolution.resume_cookie == 0
                        {
                            return Ok(LinuxCallResult::Ret(-(ERR_EINTR as i64)));
                        }
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
        const MAX_DRAINED_EVENTS_PER_CALL: usize = 4096;

        let mut events = Vec::new();
        let mut drained = 0usize;
        loop {
            if events.is_empty() {
                self.scheduler.drain_events(&mut events);
                if events.is_empty() {
                    break;
                }
            }
            if drained >= MAX_DRAINED_EVENTS_PER_CALL {
                self.scheduler.prepend_events(&mut events);
                crate::kwarn!("scheduler event drain stopped after {} events", drained);
                break;
            }
            let index = self.highest_priority_event_index(&events);
            let event = events.remove(index);
            self.record_scheduler_event(event);
            self.waits.apply_event(event);
            drained += 1;
        }
    }

    fn highest_priority_event_index(&self, events: &[Event]) -> usize {
        let mut selected = 0usize;
        let mut selected_priority = 0u32;
        for (index, event) in events.iter().copied().enumerate() {
            let priority = self.event_owner_priority(event);
            if index == 0 || priority > selected_priority {
                selected = index;
                selected_priority = priority;
            }
        }
        selected
    }

    fn event_owner_priority(&self, event: Event) -> u32 {
        let wait_id = match event {
            Event::WaitReady(wait_id)
            | Event::WaitCancelled(wait_id, _)
            | Event::WaitRestart(wait_id, _) => wait_id,
        };
        self.waits.owner_task_for_wait_id(wait_id).map(|task| self.task_priority(task)).unwrap_or(0)
    }

    pub(super) fn pump_async_sources(&mut self) {
        let mut due_events = vec![];
        self.waits.collect_due_events(interrupts::tick_count(), &mut due_events);
        for event in due_events {
            self.scheduler.push_event(event);
        }

        let mut timerfd_ready_keys = Vec::new();
        self.collect_timerfd_ready_keys(&mut timerfd_ready_keys);
        for ready_key in timerfd_ready_keys {
            match self.epoll.notify_ready(ready_key) {
                Ok(wait_ids) => {
                    for wait_id in wait_ids {
                        self.scheduler.push_event(Event::WaitReady(wait_id));
                    }
                }
                Err(ServiceCallError::Trap(reason)) => {
                    crate::kwarn!("timerfd ready notification: {}", reason);
                }
                Err(ServiceCallError::Invalid(err)) => {
                    crate::kwarn!("timerfd ready notification: {}", err);
                }
                Err(ServiceCallError::Errno(errno)) => {
                    crate::kwarn!("timerfd ready notification errno={}", errno);
                }
            }
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

        self.pump_network_runtime();
        self.drain_event_queue();
    }
}

fn futex_pi_owner_word(word: u32, tid: u32) -> u32 {
    (word & (FUTEX_OWNER_DIED | FUTEX_WAITERS)) | (tid & FUTEX_TID_MASK)
}

fn futex_pi_wait_word(word: u32) -> u32 {
    word | FUTEX_WAITERS
}

fn futex_pi_handoff_word(word: u32, tid: u32, has_more_waiters: bool) -> u32 {
    let mut next = (word & FUTEX_OWNER_DIED) | (tid & FUTEX_TID_MASK);
    if has_more_waiters {
        next |= FUTEX_WAITERS;
    }
    next
}

fn futex_pi_unlock_empty_word(word: u32) -> u32 {
    word & FUTEX_OWNER_DIED
}

#[cfg(test)]
mod tests {
    use alloc::boxed::Box;

    use vmos_abi::{
        ERR_EAGAIN, ERR_EDEADLK, ERR_EINTR, ERR_EINVAL, ERR_ETIMEDOUT, FUTEX_LOCK_PI,
        FUTEX_LOCK_PI2, FUTEX_TID_MASK, FUTEX_TRYLOCK_PI, FUTEX_UNLOCK_PI, SYS_FUTEX, SYS_PAUSE,
        SyscallContext,
    };

    use super::*;
    use crate::supervisor::{
        engine::RuntimeOnlyExecutor, runtime::PrototypeRuntime, types::WaitKind,
    };

    fn test_runtime() -> PrototypeRuntime<'static> {
        let engine = Box::leak(Box::new(RuntimeOnlyExecutor::default()));
        PrototypeRuntime::new(engine).expect("test runtime")
    }

    fn expect_ret(result: LinuxCallResult) -> i64 {
        match result {
            LinuxCallResult::Ret(ret) => ret,
            other => panic!("expected Ret, got {other:?}"),
        }
    }

    fn read_word(runtime: &mut PrototypeRuntime<'_>, ptr: u32) -> u32 {
        let bytes = runtime.linux.read_bytes(ptr, 4).expect("futex word bytes");
        u32::from_le_bytes(bytes.try_into().expect("word len"))
    }

    #[test]
    fn generic_pause_registers_signal_wait_and_resumes_eintr() {
        let mut runtime = test_runtime();
        let pause = runtime
            .dispatch_linux_syscall_raw("test_pause", SyscallContext::new(SYS_PAUSE, [0; 6]))
            .expect("pause dispatch");
        let token = match pause {
            LinuxCallResult::Pending(token) => token,
            other => panic!("expected pending pause wait, got {other:?}"),
        };
        assert_eq!(token.kind, WaitKind::Signal);

        runtime.scheduler.push_event(Event::WaitCancelled(token.id, ERR_EINTR));
        runtime.drain_event_queue();
        let resolution = runtime.waits.take_resolution(token).expect("pause resolution");
        assert_eq!(resolution.source, WaitSource::Signal);
        assert_eq!(resolution.outcome, WaitOutcome::Cancelled(ERR_EINTR));
    }

    #[test]
    fn generic_futex_pi_lock_unlock_updates_arg_buffer_word() {
        let mut runtime = test_runtime();
        let (ptr, _) = runtime.write_linux_arg_bytes(&0u32.to_le_bytes()).expect("futex word");

        let lock = runtime
            .dispatch_linux_syscall(
                "test_futex_lock_pi",
                SyscallContext::new(SYS_FUTEX, [ptr as u64, FUTEX_LOCK_PI as u64, 0, 0, 0, 0]),
            )
            .expect("lock dispatch");
        assert_eq!(expect_ret(lock), 0);
        assert_eq!(read_word(&mut runtime, ptr) & FUTEX_TID_MASK, runtime.current_tid());

        let relock = runtime
            .dispatch_linux_syscall(
                "test_futex_lock_pi_deadlock",
                SyscallContext::new(SYS_FUTEX, [ptr as u64, FUTEX_LOCK_PI as u64, 0, 0, 0, 0]),
            )
            .expect("relock dispatch");
        assert_eq!(expect_ret(relock), -(ERR_EDEADLK as i64));

        let unlock = runtime
            .dispatch_linux_syscall(
                "test_futex_unlock_pi",
                SyscallContext::new(SYS_FUTEX, [ptr as u64, FUTEX_UNLOCK_PI as u64, 0, 0, 0, 0]),
            )
            .expect("unlock dispatch");
        assert_eq!(expect_ret(unlock), 0);
        assert_eq!(read_word(&mut runtime, ptr), 0);
    }

    #[test]
    fn generic_futex_trylock_pi_reports_busy_owner() {
        let mut runtime = test_runtime();
        let (ptr, _) = runtime.write_linux_arg_bytes(&99u32.to_le_bytes()).expect("futex word");

        let trylock = runtime
            .dispatch_linux_syscall(
                "test_futex_trylock_pi",
                SyscallContext::new(SYS_FUTEX, [ptr as u64, FUTEX_TRYLOCK_PI as u64, 0, 0, 0, 0]),
            )
            .expect("trylock dispatch");
        assert_eq!(expect_ret(trylock), -(ERR_EAGAIN as i64));
        assert_eq!(read_word(&mut runtime, ptr), 99);
    }

    #[test]
    fn generic_futex_lock_pi2_timeout_restores_waiters_word() {
        let mut runtime = test_runtime();
        let mut args = [0u8; 24];
        args[0..4].copy_from_slice(&99u32.to_le_bytes());
        args[8..16].copy_from_slice(&0i64.to_le_bytes());
        args[16..24].copy_from_slice(&0i64.to_le_bytes());
        let (ptr, _) = runtime.write_linux_arg_bytes(&args).expect("futex args");
        let timeout_ptr = ptr + 8;

        let timed = runtime
            .dispatch_linux_syscall(
                "test_futex_lock_pi2_timeout",
                SyscallContext::new(
                    SYS_FUTEX,
                    [ptr as u64, FUTEX_LOCK_PI2 as u64, 0, timeout_ptr as u64, 16, 0],
                ),
            )
            .expect("timed lock dispatch");
        assert_eq!(expect_ret(timed), -(ERR_ETIMEDOUT as i64));
        assert_eq!(read_word(&mut runtime, ptr), 99);

        let malformed = runtime
            .dispatch_linux_syscall(
                "test_futex_lock_pi2_bad_timeout_len",
                SyscallContext::new(
                    SYS_FUTEX,
                    [ptr as u64, FUTEX_LOCK_PI2 as u64, 0, timeout_ptr as u64, 0, 0],
                ),
            )
            .expect("malformed timeout dispatch");
        assert_eq!(expect_ret(malformed), -(ERR_EINVAL as i64));
        assert_eq!(read_word(&mut runtime, ptr), 99);
    }
}
