use visa_conformance::{
    STAGE1_SEMANTIC_TRACE_SCHEMA_VERSION, Stage1ExpectedOwnership, Stage1JournalScope,
    Stage1SemanticTraceArtifact, Stage1TraceRole,
};

use super::{
    RunnerError,
    harness::{
        ArchivedTranscript, AssertionObservation, CaseHarness, DumpData, RawTranscriptLine,
        SnapshotTransfer,
    },
};
use crate::{evidence::BindingReceiptArtifact, fixture::FixtureSpec};

pub(super) fn snapshot_envelope(
    harness: &CaseHarness,
) -> Result<contract_core::SnapshotEnvelope, RunnerError> {
    harness.snapshot.as_ref().and_then(|transfer| transfer.envelope.clone()).ok_or_else(|| {
        RunnerError::Assertion {
            case_id: harness.definition.id.to_owned(),
            detail: "case has no exported snapshot envelope".to_owned(),
        }
    })
}

pub(super) fn binding_for_claim(
    dump: &DumpData,
    claim: contract_core::EntityRef,
) -> Option<&contract_core::BindingReceipt> {
    dump.binding_receipts.iter().find(|receipt| receipt.claim == claim)
}

pub(super) fn receipt_artifact(
    dump: &DumpData,
    claim: contract_core::EntityRef,
) -> Result<Option<BindingReceiptArtifact>, RunnerError> {
    binding_for_claim(dump, claim)
        .map(|receipt| {
            Ok(BindingReceiptArtifact {
                receipt_id: receipt.binding.identity,
                bytes: serde_json::to_vec(receipt).map_err(|error| RunnerError::Json {
                    context: "encode binding receipt".to_owned(),
                    detail: error.to_string(),
                })?,
            })
        })
        .transpose()
}

pub(super) fn transcript_json_lines(
    transcripts: &[ArchivedTranscript],
) -> Result<Vec<u8>, RunnerError> {
    let mut bytes = Vec::new();
    for transcript in transcripts {
        for line in &transcript.lines {
            serde_json::to_writer(
                &mut bytes,
                &RawTranscriptLine {
                    worker: &transcript.label,
                    pid: transcript.pid,
                    sequence: line.sequence,
                    stream: line.stream,
                    line: &line.line,
                },
            )
            .map_err(|error| RunnerError::Json {
                context: "encode raw worker transcript".to_owned(),
                detail: error.to_string(),
            })?;
            bytes.push(b'\n');
        }
    }
    Ok(bytes)
}

pub(super) fn assertions_json_lines(
    assertions: &[AssertionObservation],
) -> Result<Vec<u8>, RunnerError> {
    let mut bytes = Vec::new();
    for assertion in assertions {
        serde_json::to_writer(&mut bytes, assertion).map_err(|error| RunnerError::Json {
            context: "encode raw case assertion".to_owned(),
            detail: error.to_string(),
        })?;
        bytes.push(b'\n');
    }
    Ok(bytes)
}

pub(super) fn semantic_traces(
    case_id: &str,
    fixture: &FixtureSpec,
    snapshot: Option<&SnapshotTransfer>,
    source_final: &DumpData,
    destination_base: Option<&DumpData>,
    destination_final: Option<&DumpData>,
    expected_ownership: Stage1ExpectedOwnership,
) -> Result<Vec<Stage1SemanticTraceArtifact>, RunnerError> {
    let source_claimed = expected_ownership == Stage1ExpectedOwnership::SourceRetained;
    let mut traces = vec![Stage1SemanticTraceArtifact {
        schema_version: STAGE1_SEMANTIC_TRACE_SCHEMA_VERSION.to_owned(),
        role: Stage1TraceRole::Source,
        scope: Stage1JournalScope {
            node: fixture.config_digest_input.source_scope.node,
            component: fixture.config_digest_input.source_scope.component,
        },
        base_cursor: contract_core::JournalPosition::ORIGIN,
        base_state: fixture.source_state.clone(),
        entries: source_final.journal.clone(),
        final_state: source_final.canonical_state.clone(),
        claimed_final: source_claimed,
    }];

    match (destination_base, destination_final) {
        (Some(base), Some(final_dump)) => {
            let base_cursor = snapshot
                .and_then(|transfer| transfer.envelope.as_ref())
                .map(|envelope| envelope.body.snapshot.journal_position)
                .ok_or_else(|| RunnerError::Assertion {
                    case_id: case_id.to_owned(),
                    detail: "destination trace has no snapshot cursor".to_owned(),
                })?;
            traces.push(Stage1SemanticTraceArtifact {
                schema_version: STAGE1_SEMANTIC_TRACE_SCHEMA_VERSION.to_owned(),
                role: Stage1TraceRole::Destination,
                scope: Stage1JournalScope {
                    node: fixture.config_digest_input.destination_scope.node,
                    component: fixture.config_digest_input.destination_scope.component,
                },
                base_cursor,
                base_state: base.canonical_state.clone(),
                entries: final_dump.journal.clone(),
                final_state: final_dump.canonical_state.clone(),
                claimed_final: !source_claimed,
            });
        }
        (None, None) if source_claimed => {}
        (Some(_), None) if source_claimed => {}
        (None, Some(_)) => {
            return Err(RunnerError::Assertion {
                case_id: case_id.to_owned(),
                detail: "destination trace has a final state but no pre-prepare base".to_owned(),
            });
        }
        _ => {
            return Err(RunnerError::Assertion {
                case_id: case_id.to_owned(),
                detail: "destination-owned outcome has no complete destination trace".to_owned(),
            });
        }
    }

    if traces.iter().filter(|trace| trace.claimed_final).count() != 1 {
        return Err(RunnerError::Assertion {
            case_id: case_id.to_owned(),
            detail: "semantic traces must identify exactly one claimed final branch".to_owned(),
        });
    }
    Ok(traces)
}
