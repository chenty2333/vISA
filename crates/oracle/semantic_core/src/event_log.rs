use alloc::{
    format,
    string::{String, ToString},
    vec::Vec,
};

use super::*;

mod kind;
mod summary;

pub use kind::EventKind;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EventRecord {
    pub id: EventId,
    pub epoch: u64,
    pub source: String,
    pub causal_parent: Option<EventId>,
    pub kind: EventKind,
}

impl EventRecord {
    pub fn summary(&self) -> String {
        format!("#{} epoch={} source={} {}", self.id, self.epoch, self.source, self.kind.summary())
    }
}

#[derive(Clone, Debug)]
pub struct EventLog {
    next_id: EventId,
    epoch: u64,
    runtime_mode: RuntimeMode,
    pub(crate) events: Vec<EventRecord>,
}

impl EventLog {
    pub const fn new() -> Self {
        Self { next_id: 1, epoch: 0, runtime_mode: RuntimeMode::Research, events: Vec::new() }
    }

    pub const fn with_runtime_mode(runtime_mode: RuntimeMode) -> Self {
        Self { next_id: 1, epoch: 0, runtime_mode, events: Vec::new() }
    }

    pub const fn runtime_mode(&self) -> RuntimeMode {
        self.runtime_mode
    }

    pub fn push(&mut self, source: &str, kind: EventKind) -> EventId {
        let id = self.next_id;
        self.next_id += 1;
        self.epoch += 1;
        self.events.push(EventRecord {
            id,
            epoch: self.epoch,
            source: source.to_string(),
            causal_parent: None,
            kind,
        });
        id
    }

    pub fn len(&self) -> usize {
        self.events.len()
    }

    pub fn cursor(&self) -> EventId {
        self.next_id.saturating_sub(1)
    }

    pub fn is_empty(&self) -> bool {
        self.events.is_empty()
    }

    pub fn events(&self) -> &[EventRecord] {
        &self.events
    }

    pub fn tail(&self, count: usize) -> &[EventRecord] {
        let start = self.events.len().saturating_sub(count);
        &self.events[start..]
    }
}

impl Default for EventLog {
    fn default() -> Self {
        Self::new()
    }
}
