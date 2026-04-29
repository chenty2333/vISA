use alloc::vec::Vec;

use super::*;

impl SemanticGraph {
    pub fn apply_envelope(&mut self, envelope: CommandEnvelope) -> CommandResult {
        let command_name = envelope.command.name();
        let result = if envelope.command_id == 0 {
            rejected_command_result(
                envelope.command_id,
                envelope.issuer,
                command_name,
                "command id=0 is invalid",
            )
        } else if let Some(expected_epoch) = envelope.expected_epoch {
            let actual_epoch = self.event_count() as u64;
            if expected_epoch != actual_epoch {
                rejected_command_result(
                    envelope.command_id,
                    envelope.issuer,
                    command_name,
                    "expected epoch mismatch",
                )
            } else {
                self.apply_envelope_prechecked(envelope, command_name)
            }
        } else {
            self.apply_envelope_prechecked(envelope, command_name)
        };
        self.command_results.push(result.clone());
        result
    }

    fn apply_envelope_prechecked(
        &mut self,
        envelope: CommandEnvelope,
        command_name: &'static str,
    ) -> CommandResult {
        match self.apply(envelope.command) {
            Ok(outcome) => CommandResult {
                command_id: envelope.command_id,
                issuer: envelope.issuer,
                command: outcome.command,
                status: if outcome.changed { CommandStatus::Applied } else { CommandStatus::Noop },
                events: event_refs_between(outcome.event_count_before, outcome.event_count_after),
                effects: command_effects(&outcome),
                violations: Vec::new(),
            },
            Err(CommandError::PreconditionFailed(detail)) => CommandResult {
                command_id: envelope.command_id,
                issuer: envelope.issuer,
                command: command_name,
                status: CommandStatus::Rejected,
                events: Vec::new(),
                effects: Vec::new(),
                violations: {
                    let mut violations = Vec::new();
                    violations.push(detail);
                    violations
                },
            },
        }
    }

    pub fn apply(&mut self, command: SemanticCommand) -> Result<CommandOutcome, CommandError> {
        self.preflight_command(&command)?;
        let event_count_before = self.event_count();
        let command_name = command.name();
        let changed = self.apply_prechecked_command(command);
        Ok(CommandOutcome {
            command: command_name,
            event_count_before,
            event_count_after: self.event_count(),
            changed,
        })
    }
}

fn rejected_command_result(
    command_id: CommandId,
    issuer: String,
    command: &'static str,
    detail: &str,
) -> CommandResult {
    CommandResult {
        command_id,
        issuer,
        command,
        status: CommandStatus::Rejected,
        events: Vec::new(),
        effects: Vec::new(),
        violations: {
            let mut violations = Vec::new();
            violations.push(detail.to_string());
            violations
        },
    }
}

fn event_refs_between(before: usize, after: usize) -> Vec<EventId> {
    ((before + 1)..=after).map(|event| event as EventId).collect()
}

fn command_effects(outcome: &CommandOutcome) -> Vec<CommandEffect> {
    if !outcome.changed {
        return Vec::new();
    }
    let mut effects = Vec::new();
    effects.push(CommandEffect::new(outcome.command, None));
    effects
}
