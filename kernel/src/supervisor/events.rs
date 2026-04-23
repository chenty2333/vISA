use alloc::collections::VecDeque;

use super::types::WaitRestartClass;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Event {
    WaitReady(u64),
    WaitCancelled(u64, i32),
    WaitRestart(u64, WaitRestartClass),
}

pub(crate) struct EventQueue {
    events: VecDeque<Event>,
}

impl EventQueue {
    pub(crate) fn new() -> Self {
        Self {
            events: VecDeque::new(),
        }
    }

    pub(crate) fn push(&mut self, event: Event) {
        self.events.push_back(event);
    }

    pub(crate) fn pop(&mut self) -> Option<Event> {
        self.events.pop_front()
    }
}
