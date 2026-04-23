use alloc::vec::Vec;

use vmos_abi::ERR_ETIMEDOUT;

use super::events::Event;
use super::types::{TaskId, WaitKind, WaitToken};

#[derive(Clone, Copy, Debug)]
pub(crate) enum WaitRegistration {
    Timer {
        delay_ms: u32,
        resume_cookie: u32,
    },
    Futex {
        timeout_ms: Option<u32>,
        resume_cookie: u32,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum WaitOutcome {
    Ready,
    Cancelled(i32),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct WaitResolution {
    pub(crate) outcome: WaitOutcome,
    pub(crate) resume_cookie: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum WaitState {
    Pending,
    Ready,
    Cancelled(i32),
}

#[derive(Clone, Copy, Debug)]
enum WaitSource {
    Timer,
    Futex,
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
        Self {
            next_id: 1,
            records: Vec::new(),
        }
    }

    pub(crate) fn register(
        &mut self,
        owner_task: TaskId,
        registration: WaitRegistration,
        now_ticks: u64,
        timer_hz: u32,
    ) -> WaitToken {
        let (kind, source, resume_cookie, deadline_tick) = match registration {
            WaitRegistration::Timer {
                delay_ms,
                resume_cookie,
            } => (
                WaitKind::Timer,
                WaitSource::Timer,
                resume_cookie,
                Some(now_ticks.saturating_add(ms_to_ticks(delay_ms, timer_hz))),
            ),
            WaitRegistration::Futex {
                timeout_ms,
                resume_cookie,
            } => (
                WaitKind::Futex,
                WaitSource::Futex,
                resume_cookie,
                timeout_ms
                    .map(|delay_ms| now_ticks.saturating_add(ms_to_ticks(delay_ms, timer_hz))),
            ),
        };

        let token = WaitToken {
            id: self.next_id,
            owner_task,
            kind,
            generation: self.next_id,
        };
        self.next_id += 1;

        let record = WaitRecord {
            token,
            source,
            resume_cookie,
            deadline_tick,
            state: WaitState::Pending,
        };

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
            }
        }
    }

    pub(crate) fn apply_event(&mut self, event: Event) {
        match event {
            Event::WaitReady(id) => self.mark_ready(id),
            Event::WaitCancelled(id, errno) => self.mark_cancelled(id, errno),
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
            }),
            WaitState::Cancelled(errno) => Some(WaitResolution {
                outcome: WaitOutcome::Cancelled(errno),
                resume_cookie: record.resume_cookie,
            }),
        }
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

    fn find_mut(&mut self, token_id: u64) -> Option<&mut WaitRecord> {
        self.records
            .iter_mut()
            .flatten()
            .find(|record| record.token.id == token_id)
    }
}

fn ms_to_ticks(delay_ms: u32, timer_hz: u32) -> u64 {
    let scaled = delay_ms as u64 * timer_hz as u64;
    scaled.div_ceil(1_000).max(1)
}
