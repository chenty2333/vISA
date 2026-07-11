use alloc::{
    string::{String, ToString},
    vec::Vec,
};

use super::*;

mod apply;
mod envelope;
mod kind;
mod preflight;

pub use kind::SemanticCommand;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CommandEnvelope {
    pub command_id: CommandId,
    pub issuer: String,
    pub expected_epoch: Option<u64>,
    pub command: SemanticCommand,
}

impl CommandEnvelope {
    pub fn new(command_id: CommandId, issuer: &str, command: SemanticCommand) -> Self {
        Self { command_id, issuer: issuer.to_string(), expected_epoch: None, command }
    }

    pub fn with_expected_epoch(mut self, expected_epoch: u64) -> Self {
        self.expected_epoch = Some(expected_epoch);
        self
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CommandStatus {
    Applied,
    Noop,
    Rejected,
}

impl CommandStatus {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Applied => "applied",
            Self::Noop => "noop",
            Self::Rejected => "rejected",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CommandEffect {
    pub kind: String,
    pub target: Option<ContractObjectRef>,
}

impl CommandEffect {
    pub fn new(kind: &str, target: Option<ContractObjectRef>) -> Self {
        Self { kind: kind.to_string(), target }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CommandResult {
    pub command_id: CommandId,
    pub issuer: String,
    pub command: &'static str,
    pub status: CommandStatus,
    pub events: Vec<EventId>,
    pub effects: Vec<CommandEffect>,
    pub violations: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CommandOutcome {
    pub command: &'static str,
    pub event_count_before: usize,
    pub event_count_after: usize,
    pub changed: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CommandError {
    PreconditionFailed(String),
}

impl CommandError {
    pub fn precondition(detail: &str) -> Self {
        Self::PreconditionFailed(detail.to_string())
    }
}
