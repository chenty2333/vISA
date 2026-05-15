use alloc::vec::Vec;

use vmos_abi::ERR_ETIMEDOUT;

use super::{
    events::Event,
    types::{TaskId, WaitKind, WaitRestartClass, WaitToken},
};

#[derive(Clone, Copy, Debug)]
pub(crate) enum WaitRegistration {
    Timer { delay_ms: u32, resume_cookie: u32 },
    Futex { timeout_ms: Option<u32>, resume_cookie: u32 },
    Epoll { epoll_id: u32, max_events: u32, timeout_ms: Option<u32>, resume_cookie: u32 },
    SocketAccept { fd: u32, flags: u32 },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum WaitOutcome {
    Ready,
    Cancelled(i32),
    Restart(WaitRestartClass),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct WaitResolution {
    pub(crate) outcome: WaitOutcome,
    pub(crate) resume_cookie: u32,
    pub(crate) source: WaitSource,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum WaitState {
    Pending,
    Ready,
    Cancelled(i32),
    Restart(WaitRestartClass),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum WaitSource {
    Timer,
    Futex,
    Epoll { epoll_id: u32, max_events: u32 },
    SocketAccept { fd: u32, flags: u32 },
}

#[derive(Clone, Copy, Debug)]
struct WaitRecord {
    token: WaitToken,
    source: WaitSource,
    resume_cookie: u32,
    deadline_tick: Option<u64>,
    state: WaitState,
}

pub(crate) struct WaitRegistry {
    next_id: u64,
    records: Vec<Option<WaitRecord>>,
}

impl WaitRegistry {
    pub(crate) fn new() -> Self {
        Self { next_id: 1, records: Vec::new() }
    }

    pub(crate) fn register(
        &mut self,
        owner_task: TaskId,
        registration: WaitRegistration,
        now_ticks: u64,
        timer_hz: u32,
    ) -> WaitToken {
        let (kind, source, resume_cookie, deadline_tick) = match registration {
            WaitRegistration::Timer { delay_ms, resume_cookie } => (
                WaitKind::Timer,
                WaitSource::Timer,
                resume_cookie,
                Some(now_ticks.saturating_add(ms_to_ticks(delay_ms, timer_hz))),
            ),
            WaitRegistration::Futex { timeout_ms, resume_cookie } => (
                WaitKind::Futex,
                WaitSource::Futex,
                resume_cookie,
                timeout_ms
                    .map(|delay_ms| now_ticks.saturating_add(ms_to_ticks(delay_ms, timer_hz))),
            ),
            WaitRegistration::Epoll { epoll_id, max_events, timeout_ms, resume_cookie } => (
                WaitKind::Epoll,
                WaitSource::Epoll { epoll_id, max_events },
                resume_cookie,
                timeout_ms
                    .map(|delay_ms| now_ticks.saturating_add(ms_to_ticks(delay_ms, timer_hz))),
            ),
            WaitRegistration::SocketAccept { fd, flags } => {
                (WaitKind::SocketAccept, WaitSource::SocketAccept { fd, flags }, 0, None)
            }
        };

        let token = WaitToken { id: self.next_id, owner_task, kind, generation: self.next_id };
        self.next_id += 1;

        let record =
            WaitRecord { token, source, resume_cookie, deadline_tick, state: WaitState::Pending };

        for slot in &mut self.records {
            if slot.is_none() {
                *slot = Some(record);
                return token;
            }
        }

        self.records.push(Some(record));
        token
    }

    pub(crate) fn collect_due_events(&self, now_ticks: u64, events: &mut Vec<Event>) {
        for record in self.records.iter().flatten() {
            if record.state != WaitState::Pending {
                continue;
            }

            let Some(deadline_tick) = record.deadline_tick else {
                continue;
            };
            if now_ticks < deadline_tick {
                continue;
            }

            match record.source {
                WaitSource::Timer => events.push(Event::WaitReady(record.token.id)),
                WaitSource::Futex => {
                    events.push(Event::WaitCancelled(record.token.id, ERR_ETIMEDOUT))
                }
                WaitSource::Epoll { .. } => events.push(Event::WaitReady(record.token.id)),
                WaitSource::SocketAccept { .. } => {}
            }
        }
    }

    pub(crate) fn apply_event(&mut self, event: Event) {
        match event {
            Event::WaitReady(id) => self.mark_ready(id),
            Event::WaitCancelled(id, errno) => self.mark_cancelled(id, errno),
            Event::WaitRestart(id, class) => self.mark_restart(id, class),
        }
    }

    pub(crate) fn take_resolution(&mut self, token: WaitToken) -> Option<WaitResolution> {
        let index = self
            .records
            .iter()
            .position(|slot| slot.as_ref().is_some_and(|record| record.token == token))?;
        let record = self.records[index].take()?;
        match record.state {
            WaitState::Pending => {
                self.records[index] = Some(record);
                None
            }
            WaitState::Ready => Some(WaitResolution {
                outcome: WaitOutcome::Ready,
                resume_cookie: record.resume_cookie,
                source: record.source,
            }),
            WaitState::Cancelled(errno) => Some(WaitResolution {
                outcome: WaitOutcome::Cancelled(errno),
                resume_cookie: record.resume_cookie,
                source: record.source,
            }),
            WaitState::Restart(class) => Some(WaitResolution {
                outcome: WaitOutcome::Restart(class),
                resume_cookie: record.resume_cookie,
                source: record.source,
            }),
        }
    }

    pub(crate) fn is_pending(&self, token: WaitToken) -> bool {
        self.records
            .iter()
            .flatten()
            .find(|record| record.token == token)
            .is_some_and(|record| record.state == WaitState::Pending)
    }

    pub(crate) fn pending_source(&self, token: WaitToken) -> Option<WaitSource> {
        self.records
            .iter()
            .flatten()
            .find(|record| record.token == token && record.state == WaitState::Pending)
            .map(|record| record.source)
    }

    fn mark_ready(&mut self, token_id: u64) {
        if let Some(record) = self.find_mut(token_id) {
            record.state = WaitState::Ready;
        }
    }

    fn mark_cancelled(&mut self, token_id: u64, errno: i32) {
        if let Some(record) = self.find_mut(token_id) {
            record.state = WaitState::Cancelled(errno);
        }
    }

    fn mark_restart(&mut self, token_id: u64, class: WaitRestartClass) {
        if let Some(record) = self.find_mut(token_id) {
            record.state = WaitState::Restart(class);
        }
    }

    fn find_mut(&mut self, token_id: u64) -> Option<&mut WaitRecord> {
        self.records.iter_mut().flatten().find(|record| record.token.id == token_id)
    }
}

fn ms_to_ticks(delay_ms: u32, timer_hz: u32) -> u64 {
    let scaled = delay_ms as u64 * timer_hz as u64;
    scaled.div_ceil(1_000).max(1)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn restart_resolution_is_consumed_by_original_wait_token() {
        let mut registry = WaitRegistry::new();
        let token = registry.register(
            7,
            WaitRegistration::Epoll {
                epoll_id: 3,
                max_events: 4,
                timeout_ms: None,
                resume_cookie: 99,
            },
            0,
            100,
        );

        registry.apply_event(Event::WaitRestart(token.id, WaitRestartClass::DriverRestart));

        assert_eq!(
            registry.take_resolution(token),
            Some(WaitResolution {
                outcome: WaitOutcome::Restart(WaitRestartClass::DriverRestart),
                resume_cookie: 99,
                source: WaitSource::Epoll { epoll_id: 3, max_events: 4 },
            })
        );
        assert_eq!(registry.take_resolution(token), None);
    }

    #[test]
    fn is_pending_distinguishes_ready_waits_before_resolution_is_taken() {
        let mut registry = WaitRegistry::new();
        let token = registry.register(
            7,
            WaitRegistration::Futex { timeout_ms: None, resume_cookie: 11 },
            0,
            100,
        );

        assert!(registry.is_pending(token));
        registry.apply_event(Event::WaitReady(token.id));
        assert!(!registry.is_pending(token));
    }

    #[test]
    fn socket_accept_registration_carries_fd_and_flags() {
        let mut registry = WaitRegistry::new();
        let token = registry.register(
            7,
            WaitRegistration::SocketAccept { fd: 4, flags: 0o2000000 },
            0,
            100,
        );

        assert_eq!(token.kind, WaitKind::SocketAccept);
        assert_eq!(
            registry.pending_source(token),
            Some(WaitSource::SocketAccept { fd: 4, flags: 0o2000000 })
        );

        registry.apply_event(Event::WaitReady(token.id));
        assert_eq!(
            registry.take_resolution(token),
            Some(WaitResolution {
                outcome: WaitOutcome::Ready,
                resume_cookie: 0,
                source: WaitSource::SocketAccept { fd: 4, flags: 0o2000000 },
            })
        );
    }
}
