//! Shared Stage 1 evidence-mutation library.
//!
//! The primitives here are used by two drivers: the in-crate defect-corpus
//! tests (`cfg(test)`) and the `visa-defect-corpus` binary behind the
//! `defect-corpus` feature. Nothing in this module is compiled into the
//! default-feature library.

use std::{
    fs,
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

use serde::de::DeserializeOwned;
use sha2::{Digest, Sha256};

use crate::stage1::*;

// Used only by the in-crate Stage 1 fixture, not by the shared corpus.
#[cfg(test)]
pub(crate) fn append_event(
    state: &mut contract_core::CanonicalState,
    position: &mut contract_core::JournalPosition,
    entries: &mut Vec<contract_core::JournalEntry>,
    event: contract_core::Event,
) {
    let input_state = contract_core::state_digest(state).unwrap();
    let next = semantic_core::apply(state, &event).unwrap().into_state();
    *position = position.next().unwrap();
    let output_state = contract_core::state_digest(&next).unwrap();
    entries.push(contract_core::JournalEntry {
        version: contract_core::CONTRACT_VERSION,
        position: *position,
        input_state,
        output_state,
        event,
    });
    *state = next;
}

pub(crate) fn mutate_embedded_protocol(
    lines: &mut [serde_json::Value],
    matches: impl Fn(&serde_json::Value) -> bool,
    mutate: impl FnOnce(&mut serde_json::Value),
) {
    let index = lines
        .iter()
        .position(|line| {
            line.get("line")
                .and_then(serde_json::Value::as_str)
                .and_then(|line| serde_json::from_str::<serde_json::Value>(line).ok())
                .is_some_and(|protocol| matches(&protocol))
        })
        .expect("matching embedded protocol line");
    let mut protocol = serde_json::from_str::<serde_json::Value>(
        lines[index].get("line").and_then(serde_json::Value::as_str).unwrap(),
    )
    .unwrap();
    mutate(&mut protocol);
    lines[index]["line"] = serde_json::Value::String(serde_json::to_string(&protocol).unwrap());
}

pub(crate) fn read_json<T: DeserializeOwned>(root: &Path, uri: &str) -> T {
    serde_json::from_slice(&fs::read(root.join(uri)).unwrap()).unwrap()
}

pub(crate) fn committed_case_index(bundle: &Stage1EvidenceBundle) -> usize {
    bundle.cases.iter().position(|case| case.case_id == "evidence-verification").unwrap()
}

// Used only by the in-crate Stage 1 fixture, not by the shared corpus.
#[cfg(test)]
pub(crate) fn rewrite_committed_trace(
    bundle: &mut Stage1EvidenceBundle,
    root: &Path,
    mutate: impl FnOnce(&mut Stage1SemanticTraceArtifact),
) {
    let case_index = committed_case_index(bundle);
    let trace_index = bundle.cases[case_index]
        .artifacts
        .semantic_traces
        .iter()
        .position(|reference| reference.uri.ends_with("destination.json"))
        .unwrap();
    let reference = bundle.cases[case_index].artifacts.semantic_traces[trace_index].clone();
    let mut trace = read_json::<Stage1SemanticTraceArtifact>(root, &reference.uri);
    mutate(&mut trace);

    let case = &mut bundle.cases[case_index];
    let reference = &mut case.artifacts.semantic_traces[trace_index];
    write_case_ref(root, reference, &serde_json::to_vec_pretty(&trace).unwrap());
    case.state.trace_sha256s =
        case.artifacts.semantic_traces.iter().map(|reference| reference.sha256.clone()).collect();
}

pub(crate) fn rewrite_timer_receipt(
    bundle: &mut Stage1EvidenceBundle,
    root: &Path,
    mutate: impl FnOnce(&mut contract_core::BindingReceipt),
) {
    let case_index = committed_case_index(bundle);
    let receipt_index = bundle.cases[case_index]
        .artifacts
        .binding_receipts
        .iter()
        .position(|reference| reference.resource == Stage1ResourceKind::PausedDurationTimer)
        .unwrap();
    let reference =
        bundle.cases[case_index].artifacts.binding_receipts[receipt_index].artifact.clone();
    let mut receipt = read_json::<contract_core::BindingReceipt>(root, &reference.uri);
    mutate(&mut receipt);
    write_case_ref(
        root,
        &mut bundle.cases[case_index].artifacts.binding_receipts[receipt_index].artifact,
        &serde_json::to_vec_pretty(&receipt).unwrap(),
    );
}

// Used only by the in-crate Stage 1 fixture, not by the shared corpus.
#[cfg(test)]
pub(crate) fn rewrite_source_trace(
    bundle: &mut Stage1EvidenceBundle,
    root: &Path,
    case_id: &str,
    mutate: impl FnOnce(&mut Stage1SemanticTraceArtifact),
) {
    let case_index = bundle.cases.iter().position(|case| case.case_id == case_id).unwrap();
    let trace_index = bundle.cases[case_index]
        .artifacts
        .semantic_traces
        .iter()
        .position(|reference| reference.uri.ends_with("source.json"))
        .unwrap();
    let reference = bundle.cases[case_index].artifacts.semantic_traces[trace_index].clone();
    let mut trace = read_json::<Stage1SemanticTraceArtifact>(root, &reference.uri);
    assert!(trace.claimed_final);
    mutate(&mut trace);
    let state_digest = contract_core::state_digest(&trace.final_state).unwrap();
    let source_authority_root =
        contract_core::canonical_digest(trace.final_state.authorities.as_slice()).unwrap();

    let case = &mut bundle.cases[case_index];
    write_case_ref(
        root,
        &mut case.artifacts.semantic_traces[trace_index],
        &serde_json::to_vec_pretty(&trace).unwrap(),
    );
    case.state.trace_sha256s =
        case.artifacts.semantic_traces.iter().map(|reference| reference.sha256.clone()).collect();
    case.state.state_sha256 = contract_hex(state_digest);
    case.state.replay_state_sha256 = contract_hex(state_digest);
    case.authority.source_authority_root_sha256 = contract_hex(source_authority_root);
}

// Used only by the in-crate Stage 1 fixture, not by the shared corpus.
#[cfg(test)]
pub(crate) fn rewrite_case_assertions(
    bundle: &mut Stage1EvidenceBundle,
    root: &Path,
    case_index: usize,
    mutate: impl FnOnce(&mut Vec<serde_json::Value>),
) {
    let raw_index = bundle.cases[case_index]
        .artifacts
        .raw_execution
        .iter()
        .position(|reference| reference.uri.ends_with("assertions.jsonl"))
        .unwrap();
    let uri = bundle.cases[case_index].artifacts.raw_execution[raw_index].uri.clone();
    let bytes = fs::read(root.join(uri)).unwrap();
    let mut assertions = bytes
        .split(|byte| *byte == b'\n')
        .filter(|line| !line.is_empty())
        .map(|line| serde_json::from_slice::<serde_json::Value>(line).unwrap())
        .collect::<Vec<_>>();
    mutate(&mut assertions);
    write_case_ref(
        root,
        &mut bundle.cases[case_index].artifacts.raw_execution[raw_index],
        &json_lines(&assertions),
    );
}

pub(crate) fn rewrite_raw_transcript(
    bundle: &mut Stage1EvidenceBundle,
    root: &Path,
    case_index: usize,
    file_name: &str,
    mutate: impl FnOnce(&mut Vec<serde_json::Value>),
) {
    let raw_index = bundle.cases[case_index]
        .artifacts
        .raw_execution
        .iter()
        .position(|reference| reference.uri.ends_with(file_name))
        .unwrap();
    let uri = bundle.cases[case_index].artifacts.raw_execution[raw_index].uri.clone();
    let bytes = fs::read(root.join(uri)).unwrap();
    let mut lines = bytes
        .split(|byte| *byte == b'\n')
        .filter(|line| !line.is_empty())
        .map(|line| serde_json::from_slice::<serde_json::Value>(line).unwrap())
        .collect::<Vec<_>>();
    mutate(&mut lines);
    write_case_ref(
        root,
        &mut bundle.cases[case_index].artifacts.raw_execution[raw_index],
        &json_lines(&lines),
    );
}

pub(crate) fn json_lines(values: &[serde_json::Value]) -> Vec<u8> {
    let mut bytes = Vec::new();
    for value in values {
        serde_json::to_writer(&mut bytes, value).unwrap();
        bytes.push(b'\n');
    }
    bytes
}

pub(crate) fn write_case_ref(root: &Path, artifact: &mut Stage1ArtifactReference, bytes: &[u8]) {
    let path = root.join(&artifact.uri);
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(&path, bytes).unwrap();
    artifact.sha256 = sha256(bytes);
}

// Used only by the in-crate Stage 1 fixture, not by the shared corpus.
#[cfg(test)]
pub(crate) fn write_provenance_ref(
    root: &Path,
    artifact: &mut Stage1ProvenanceArtifactReference,
    bytes: &[u8],
) {
    let path = root.join(&artifact.uri);
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(&path, bytes).unwrap();
    artifact.sha256 = sha256(bytes);
}

pub(crate) fn sha256(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

pub(crate) fn contract_hex(digest: contract_core::Digest) -> String {
    digest.0.iter().map(|byte| format!("{byte:02x}")).collect()
}

// Used only by the in-crate Stage 1 fixture, not by the shared corpus.
#[cfg(test)]
pub(crate) fn digest_from_hex(value: &str) -> contract_core::Digest {
    let mut bytes = [0_u8; 32];
    for (index, byte) in bytes.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&value[index * 2..index * 2 + 2], 16).unwrap();
    }
    contract_core::Digest::from_bytes(bytes)
}

// Used only by the in-crate Stage 1 fixture, not by the shared corpus.
#[cfg(test)]
pub(crate) fn identity_from_hex(value: &str) -> contract_core::Identity {
    let mut bytes = [0_u8; 16];
    for (index, byte) in bytes.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&value[index * 2..index * 2 + 2], 16).unwrap();
    }
    contract_core::Identity::from_bytes(bytes)
}

// Used only by the in-crate Stage 1 fixture, not by the shared corpus.
#[cfg(test)]
pub(crate) fn identity_hex(identity: contract_core::Identity) -> String {
    identity.0.iter().map(|byte| format!("{byte:02x}")).collect()
}

pub(crate) fn temp_dir(label: &str) -> PathBuf {
    let nonce = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
    std::env::temp_dir().join(format!("visa-stage1-{label}-{}-{nonce}", std::process::id()))
}

/// Stage 1 case identities the corpus targets.
pub(crate) const COMMITTED_CASE: &str = "evidence-verification";
pub(crate) const REVOCATION_CASE: &str = "required-capability-revoked";
pub(crate) const RETAINED_CASE: &str = "safe-point-unreachable";

/// Finding codes that only ever mean "the mutation was resealed incorrectly".
/// A corpus entry that produces one of these proves nothing about detection and
/// is reported as void rather than as a measurement.
pub(crate) const INTEGRITY_FAMILY_CODES: &[&str] = &[
    "stage1-artifact-digest-mismatch",
    "missing-stage1-captured-artifact",
    "missing-stage1-artifact-file",
    "invalid-stage1-digest",
    "invalid-stage1-snapshot-integrity",
    "inconsistent-stage1-snapshot-digest",
    "inconsistent-stage1-trace-digest",
    "inconsistent-stage1-state-replay-digest",
];

pub(crate) fn case_index_of(bundle: &Stage1EvidenceBundle, case_id: &str) -> usize {
    bundle.cases.iter().position(|case| case.case_id == case_id).unwrap()
}

pub(crate) fn trace_index_of(
    bundle: &Stage1EvidenceBundle,
    case_index: usize,
    file_name: &str,
) -> usize {
    bundle.cases[case_index]
        .artifacts
        .semantic_traces
        .iter()
        .position(|reference| reference.uri.ends_with(file_name))
        .unwrap()
}

pub(crate) fn read_trace(
    bundle: &Stage1EvidenceBundle,
    root: &Path,
    case_index: usize,
    file_name: &str,
) -> Stage1SemanticTraceArtifact {
    let index = trace_index_of(bundle, case_index, file_name);
    let uri = bundle.cases[case_index].artifacts.semantic_traces[index].uri.clone();
    read_json(root, &uri)
}

fn write_trace(
    bundle: &mut Stage1EvidenceBundle,
    root: &Path,
    case_index: usize,
    file_name: &str,
    trace: &Stage1SemanticTraceArtifact,
) {
    let index = trace_index_of(bundle, case_index, file_name);
    write_case_ref(
        root,
        &mut bundle.cases[case_index].artifacts.semantic_traces[index],
        &serde_json::to_vec_pretty(trace).unwrap(),
    );
}

/// How a mutated journal is re-derived before it is written back.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Rechain {
    /// Renumber positions from the base cursor and recompute every digest.
    Renumber,
    /// Keep the recorded positions and only recompute digests, so a deletion
    /// leaves a real journal gap for the replay gate to find.
    KeepPositions,
}

/// Re-derives journal positions, state digests, and the final state of a trace
/// from its base state and its event sequence.
///
/// An event the canonical core rejects is kept in the journal with a
/// self-consistent input digest, so the replay gate reports the rejection
/// instead of a digest mismatch that would mask it.
pub(crate) fn rechain_trace(trace: &mut Stage1SemanticTraceArtifact, mode: Rechain) {
    let mut state = trace.base_state.clone();
    let mut position = trace.base_cursor;
    let mut entries = Vec::new();
    for entry in std::mem::take(&mut trace.entries) {
        let input_state = contract_core::state_digest(&state).unwrap();
        let position_value = match mode {
            Rechain::Renumber => {
                position = position.next().unwrap();
                position
            }
            Rechain::KeepPositions => entry.position,
        };
        match semantic_core::apply(&state, &entry.event) {
            Ok(applied) => {
                let next = applied.into_state();
                entries.push(contract_core::JournalEntry {
                    version: contract_core::CONTRACT_VERSION,
                    position: position_value,
                    input_state,
                    output_state: contract_core::state_digest(&next).unwrap(),
                    event: entry.event,
                });
                state = next;
            }
            Err(_) => entries.push(contract_core::JournalEntry {
                version: contract_core::CONTRACT_VERSION,
                position: position_value,
                input_state,
                output_state: input_state,
                event: entry.event,
            }),
        }
    }
    trace.entries = entries;
    trace.final_state = state;
}

/// Restates the case-level digests and authority roots that the validator
/// expects a well-formed bundle to carry. Mutations that intend to break one of
/// these fields set it explicitly after calling this.
pub(crate) fn reseal_case_digests(
    bundle: &mut Stage1EvidenceBundle,
    root: &Path,
    case_index: usize,
) {
    let uris = bundle.cases[case_index]
        .artifacts
        .semantic_traces
        .iter()
        .map(|reference| reference.uri.clone())
        .collect::<Vec<_>>();
    let traces = uris
        .iter()
        .map(|uri| read_json::<Stage1SemanticTraceArtifact>(root, uri))
        .collect::<Vec<_>>();
    let source = traces.iter().find(|trace| trace.role == Stage1TraceRole::Source).unwrap();
    let destination = traces.iter().find(|trace| trace.role == Stage1TraceRole::Destination);
    let claimed = traces.iter().find(|trace| trace.claimed_final).unwrap();

    let source_root =
        contract_core::canonical_digest(source.final_state.authorities.as_slice()).unwrap();
    let empty: &[contract_core::AuthorityGrant] = &[];
    let destination_root = match stage1_expected_ownership(bundle.cases[case_index].outcome) {
        Stage1ExpectedOwnership::SourceRetained => contract_core::canonical_digest(empty).unwrap(),
        _ => {
            contract_core::canonical_digest(destination.unwrap().final_state.authorities.as_slice())
                .unwrap()
        }
    };
    let state_digest = contract_core::state_digest(&claimed.final_state).unwrap();

    let case = &mut bundle.cases[case_index];
    case.state.trace_sha256s =
        case.artifacts.semantic_traces.iter().map(|reference| reference.sha256.clone()).collect();
    case.state.state_sha256 = contract_hex(state_digest);
    case.state.replay_state_sha256 = contract_hex(state_digest);
    case.authority.source_authority_root_sha256 = contract_hex(source_root);
    case.authority.destination_authority_root_sha256 = contract_hex(destination_root);
}

/// Rewrites every worker dump in one raw transcript whose canonical state is
/// `before`, so raw observations keep matching a resealed canonical trace.
pub(crate) fn reseal_raw_dumps(
    bundle: &mut Stage1EvidenceBundle,
    root: &Path,
    case_index: usize,
    file_name: &str,
    before: &contract_core::CanonicalState,
    after: &contract_core::CanonicalState,
) {
    if before == after {
        return;
    }
    let before_value = serde_json::to_value(before).unwrap();
    let after_value = serde_json::to_value(after).unwrap();
    let after_digest = serde_json::to_value(contract_core::state_digest(after).unwrap()).unwrap();
    let mut grants = after.authorities.clone();
    if let Some(prepared) = &after.prepared_destination {
        grants.extend(prepared.authorities.clone());
    }
    let after_grants = serde_json::to_value(&grants).unwrap();
    let after_portable = serde_json::to_value(&after.portable_state).unwrap();
    rewrite_raw_transcript(bundle, root, case_index, file_name, |lines| {
        for line in lines.iter_mut() {
            let Some(text) = line.get("line").and_then(serde_json::Value::as_str) else {
                continue;
            };
            let Ok(mut protocol) = serde_json::from_str::<serde_json::Value>(text) else {
                continue;
            };
            let Some(result) = protocol.pointer_mut("/outcome/result") else { continue };
            if result.get("kind").and_then(serde_json::Value::as_str) != Some("dump")
                || result.get("canonical_state") != Some(&before_value)
            {
                continue;
            }
            result["canonical_state"] = after_value.clone();
            result["state_digest"] = after_digest.clone();
            result["authority_grants"] = after_grants.clone();
            result["portable_component_state"] = after_portable.clone();
            line["line"] = serde_json::Value::String(serde_json::to_string(&protocol).unwrap());
        }
    });
}

/// Applies `mutate` to a case's destination trace, then reseals the journal,
/// the case digests, and the destination raw dumps.
pub(crate) fn mutate_destination_trace(
    bundle: &mut Stage1EvidenceBundle,
    root: &Path,
    case_id: &str,
    mode: Rechain,
    resync_raw: bool,
    mutate: impl FnOnce(&mut Stage1SemanticTraceArtifact),
) {
    let case_index = case_index_of(bundle, case_id);
    let mut trace = read_trace(bundle, root, case_index, "destination.json");
    let before = trace.final_state.clone();
    mutate(&mut trace);
    rechain_trace(&mut trace, mode);
    let after = trace.final_state.clone();
    write_trace(bundle, root, case_index, "destination.json", &trace);
    if resync_raw {
        reseal_raw_dumps(bundle, root, case_index, "destination.jsonl", &before, &after);
    }
    reseal_case_digests(bundle, root, case_index);
}

/// Applies `mutate` to a case's source trace and reseals the whole downstream
/// chain: the exported snapshot, the destination trace that restores from it,
/// the case digests, and both raw transcripts.
pub(crate) fn mutate_source_trace_chain(
    bundle: &mut Stage1EvidenceBundle,
    root: &Path,
    case_id: &str,
    mode: Rechain,
    mutate: impl FnOnce(&mut Stage1SemanticTraceArtifact),
) {
    let case_index = case_index_of(bundle, case_id);
    let mut source = read_trace(bundle, root, case_index, "source.json");
    let source_before = source.final_state.clone();
    mutate(&mut source);
    rechain_trace(&mut source, mode);
    let source_after = source.final_state.clone();
    write_trace(bundle, root, case_index, "source.json", &source);

    if bundle.cases[case_index].artifacts.snapshot.is_some() {
        let cursor = source
            .entries
            .iter()
            .find_map(|entry| match &entry.event.kind {
                contract_core::EventKind::SnapshotExported { snapshot } => Some(snapshot.clone()),
                _ => None,
            })
            .expect("exported snapshot record");
        let prefix = source
            .entries
            .iter()
            .take_while(|entry| entry.position.0 <= cursor.journal_position.0)
            .cloned()
            .collect::<Vec<_>>();
        let projected =
            semantic_core::replay_from(&source.base_state, source.base_cursor, &prefix, |state| {
                contract_core::state_digest(state).unwrap_or(contract_core::Digest::ZERO)
            })
            .expect("snapshot prefix replays");
        let body = projected.snapshot_body().expect("exported state projects a snapshot body");
        let envelope = contract_core::SnapshotEnvelope {
            version: contract_core::CONTRACT_VERSION,
            integrity: contract_core::snapshot_integrity(&body).unwrap(),
            body,
        };
        let reference = bundle.cases[case_index].artifacts.snapshot.as_mut().unwrap();
        write_case_ref(root, reference, &serde_json::to_vec(&envelope).unwrap());
        bundle.cases[case_index].state.snapshot_sha256 = Some(reference.sha256.clone());

        if bundle.cases[case_index].artifacts.semantic_traces.len() > 1 {
            let mut destination = read_trace(bundle, root, case_index, "destination.json");
            let destination_base_before = destination.base_state.clone();
            let destination_before = destination.final_state.clone();
            destination.base_state = semantic_core::restore(
                &envelope,
                envelope.integrity,
                envelope.body.component_digest,
                envelope.body.profile_digest,
                envelope.body.profile_version,
                &[],
                destination.scope.node,
            )
            .expect("resealed snapshot restores");
            rechain_trace(&mut destination, Rechain::Renumber);
            let destination_after = destination.final_state.clone();
            write_trace(bundle, root, case_index, "destination.json", &destination);
            reseal_raw_dumps(
                bundle,
                root,
                case_index,
                "destination.jsonl",
                &destination_base_before,
                &destination.base_state,
            );
            reseal_raw_dumps(
                bundle,
                root,
                case_index,
                "destination.jsonl",
                &destination_before,
                &destination_after,
            );
        }
    }

    reseal_raw_dumps(bundle, root, case_index, "source.jsonl", &source_before, &source_after);
    reseal_case_digests(bundle, root, case_index);
}

/// Rewrites the `prepared` payload carried by a destination trace's
/// `DestinationPrepared` event.
pub(crate) fn mutate_prepared_destination(
    trace: &mut Stage1SemanticTraceArtifact,
    mutate: impl FnOnce(&mut contract_core::PreparedDestination),
) {
    for entry in &mut trace.entries {
        if let contract_core::EventKind::DestinationPrepared { prepared } = &mut entry.event.kind {
            mutate(prepared);
            return;
        }
    }
    panic!("destination trace carries a DestinationPrepared event");
}

pub(crate) fn drop_entry(
    trace: &mut Stage1SemanticTraceArtifact,
    matches: impl Fn(&contract_core::EventKind) -> bool,
) {
    let index = trace.entries.iter().position(|entry| matches(&entry.event.kind)).unwrap();
    trace.entries.remove(index);
}

pub(crate) fn narrow(
    rights: contract_core::Rights,
    removed: contract_core::Rights,
) -> contract_core::Rights {
    contract_core::Rights::from_bits(rights.bits() & !removed.bits()).unwrap()
}

pub(crate) fn push_event(
    trace: &mut Stage1SemanticTraceArtifact,
    identity: u128,
    kind: contract_core::EventKind,
) {
    trace.entries.push(contract_core::JournalEntry {
        version: contract_core::CONTRACT_VERSION,
        position: contract_core::JournalPosition::ORIGIN,
        input_state: contract_core::Digest::ZERO,
        output_state: contract_core::Digest::ZERO,
        event: contract_core::Event::new(contract_core::Identity::from_u128(identity), kind),
    });
}

/// The eight defect classes the corpus covers.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, serde::Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum DefectClass {
    StaleGeneration,
    LostCancellation,
    DuplicateClose,
    IncorrectErrorMapping,
    LateProfileChecks,
    MissingSourceFencing,
    SilentAuthorityDowngrade,
    OmittedEvents,
}

impl DefectClass {
    pub const ALL: &'static [Self] = &[
        Self::StaleGeneration,
        Self::LostCancellation,
        Self::DuplicateClose,
        Self::IncorrectErrorMapping,
        Self::LateProfileChecks,
        Self::MissingSourceFencing,
        Self::SilentAuthorityDowngrade,
        Self::OmittedEvents,
    ];
}

/// The semantic role of one resealed mutation in the corpus.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum MutationDisposition {
    /// An observable semantic defect that the verifier must reject.
    SemanticDefect,
    /// A mutation absorbed by the specified idempotent semantics.
    BenignEquivalent,
    /// A deliberate verifier boundary recorded outside scored denominators.
    BoundaryCase,
}

/// What the corpus predicts the Stage 1 verifier will say about one entry.
#[derive(Clone, Copy, Debug, serde::Serialize)]
pub struct Expectation {
    /// `true` means the defect is predicted to survive verification.
    pub ok: bool,
    /// Codes that must appear when `ok` is `false`.
    pub codes: &'static [&'static str],
}

/// One injected defect: a named mutation plus its predicted verdict.
#[derive(Clone, Copy)]
pub struct DefectCase {
    pub id: &'static str,
    pub class: DefectClass,
    pub case_id: &'static str,
    pub mutation: &'static str,
    pub disposition: MutationDisposition,
    pub expectation: Expectation,
    pub apply: fn(&mut Stage1EvidenceBundle, &Path),
}

const fn detected(codes: &'static [&'static str]) -> Expectation {
    Expectation { ok: false, codes }
}

const UNDETECTED: Expectation = Expectation { ok: true, codes: &[] };

pub fn defect_corpus() -> &'static [DefectCase] {
    DEFECT_CORPUS
}

const DEFECT_CORPUS: &[DefectCase] = &[
    DefectCase {
        id: "A1a-stale-activation-epoch",
        class: DefectClass::StaleGeneration,
        case_id: COMMITTED_CASE,
        mutation: "append a destination Activated event carrying the superseded source lease epoch",
        disposition: MutationDisposition::SemanticDefect,
        expectation: detected(&["invalid-stage1-semantic-replay"]),
        apply: a1a_stale_activation_epoch,
    },
    DefectCase {
        id: "A1b-revoked-tombstone-generation-reset",
        class: DefectClass::StaleGeneration,
        case_id: REVOCATION_CASE,
        mutation: "reset the revoked authority to its initial generation so no tombstone advances",
        disposition: MutationDisposition::SemanticDefect,
        expectation: detected(&["missing-stage1-revoked-authority-tombstone"]),
        apply: a1b_revoked_tombstone_generation_reset,
    },
    DefectCase {
        id: "A1c-stale-source-authority-root",
        class: DefectClass::StaleGeneration,
        case_id: COMMITTED_CASE,
        mutation: "publish the pre-handoff authority root instead of the final one",
        disposition: MutationDisposition::SemanticDefect,
        expectation: detected(&["inconsistent-stage1-source-authority-root"]),
        apply: a1c_stale_source_authority_root,
    },
    DefectCase {
        id: "A2a-timer-completion-after-commit",
        class: DefectClass::LostCancellation,
        case_id: COMMITTED_CASE,
        mutation: "append a timer completion after the handoff commit, as if a cancel was lost",
        disposition: MutationDisposition::SemanticDefect,
        expectation: detected(&["invalid-stage1-semantic-replay"]),
        apply: a2a_timer_completion_after_commit,
    },
    DefectCase {
        id: "A2b-freeze-disposition-rewritten",
        class: DefectClass::LostCancellation,
        case_id: COMMITTED_CASE,
        mutation: "rewrite the frozen timer disposition and reseal the whole chain",
        disposition: MutationDisposition::SemanticDefect,
        expectation: detected(&["inconsistent-stage1-timer-intent"]),
        apply: a2b_freeze_disposition_rewritten,
    },
    DefectCase {
        id: "A2c-supplemental-round-trip-erased",
        class: DefectClass::LostCancellation,
        case_id: COMMITTED_CASE,
        mutation: "erase the supplemental fault round-trip from the source transcript",
        disposition: MutationDisposition::SemanticDefect,
        expectation: detected(&["incomplete-stage1-supplemental-fault-evidence"]),
        apply: a2c_supplemental_round_trip_erased,
    },
    DefectCase {
        id: "A3a-commit-event-duplicated",
        class: DefectClass::DuplicateClose,
        case_id: COMMITTED_CASE,
        mutation: "duplicate the commit journal entry and renumber the journal",
        disposition: MutationDisposition::BenignEquivalent,
        expectation: UNDETECTED,
        apply: a3a_commit_event_duplicated,
    },
    DefectCase {
        id: "A3b-resume-event-duplicated",
        class: DefectClass::DuplicateClose,
        case_id: COMMITTED_CASE,
        mutation: "duplicate the destination resume entry and renumber the journal",
        disposition: MutationDisposition::BenignEquivalent,
        expectation: UNDETECTED,
        apply: a3b_resume_event_duplicated,
    },
    DefectCase {
        id: "A3c-transcript-dump-round-trip-duplicated",
        class: DefectClass::DuplicateClose,
        case_id: COMMITTED_CASE,
        mutation: "append a duplicate dump round-trip under a fresh request id",
        disposition: MutationDisposition::BenignEquivalent,
        expectation: UNDETECTED,
        apply: a3c_transcript_dump_round_trip_duplicated,
    },
    DefectCase {
        id: "A4a-revocation-provider-kind-remapped",
        class: DefectClass::IncorrectErrorMapping,
        case_id: REVOCATION_CASE,
        mutation: "remap the observed provider rejection from Revoked to Conflict",
        disposition: MutationDisposition::SemanticDefect,
        expectation: detected(&["missing-stage1-revocation-provider-observation"]),
        apply: a4a_revocation_provider_kind_remapped,
    },
    DefectCase {
        id: "A4b-revocation-error-family-remapped",
        class: DefectClass::IncorrectErrorMapping,
        case_id: REVOCATION_CASE,
        mutation: "report the revocation rejection as an adapter error instead of a provider error",
        disposition: MutationDisposition::SemanticDefect,
        expectation: detected(&["missing-stage1-revocation-provider-observation"]),
        apply: a4b_revocation_error_family_remapped,
    },
    DefectCase {
        id: "A4c-revocation-retryable-flag-flipped",
        class: DefectClass::IncorrectErrorMapping,
        case_id: REVOCATION_CASE,
        mutation: "mark the non-retryable revocation rejection as retryable",
        disposition: MutationDisposition::SemanticDefect,
        expectation: detected(&["missing-stage1-revocation-provider-observation"]),
        apply: a4c_revocation_retryable_flag_flipped,
    },
    DefectCase {
        id: "A5a-rejection-destination-authority-root",
        class: DefectClass::LateProfileChecks,
        case_id: RETAINED_CASE,
        mutation: "publish a non-empty destination authority root for a rejected handoff",
        disposition: MutationDisposition::SemanticDefect,
        expectation: detected(&["inconsistent-stage1-destination-authority-root"]),
        apply: a5a_rejection_destination_authority_root,
    },
    DefectCase {
        id: "A5b-prepare-after-commit",
        class: DefectClass::LateProfileChecks,
        case_id: COMMITTED_CASE,
        mutation: "move destination preparation after the commit entry",
        disposition: MutationDisposition::SemanticDefect,
        expectation: detected(&["invalid-stage1-semantic-replay"]),
        apply: a5b_prepare_after_commit,
    },
    DefectCase {
        id: "A5c-profile-digest-drift",
        class: DefectClass::LateProfileChecks,
        case_id: COMMITTED_CASE,
        mutation: "bind the canonical trace to a profile digest the bundle never declares",
        disposition: MutationDisposition::SemanticDefect,
        expectation: detected(&["inconsistent-stage1-trace-provenance"]),
        apply: a5c_profile_digest_drift,
    },
    DefectCase {
        id: "A6a-source-fenced-flag-cleared",
        class: DefectClass::MissingSourceFencing,
        case_id: COMMITTED_CASE,
        mutation: "clear the source-fenced flag on a committed handoff",
        disposition: MutationDisposition::SemanticDefect,
        expectation: detected(&["inconsistent-stage1-ownership-evidence"]),
        apply: a6a_source_fenced_flag_cleared,
    },
    DefectCase {
        id: "A6b-lease-epoch-not-monotonic",
        class: DefectClass::MissingSourceFencing,
        case_id: COMMITTED_CASE,
        mutation: "reuse the source lease epoch as the destination lease epoch",
        disposition: MutationDisposition::SemanticDefect,
        expectation: detected(&["inconsistent-stage1-ownership-evidence"]),
        apply: a6b_lease_epoch_not_monotonic,
    },
    DefectCase {
        id: "A6c-post-export-source-resume",
        class: DefectClass::MissingSourceFencing,
        case_id: REVOCATION_CASE,
        mutation: "resume the source after snapshot export without refencing",
        disposition: MutationDisposition::SemanticDefect,
        expectation: detected(&["invalid-stage1-semantic-replay"]),
        apply: a6c_post_export_source_resume,
    },
    DefectCase {
        id: "A6d-extra-worker-stderr-observation",
        class: DefectClass::MissingSourceFencing,
        case_id: COMMITTED_CASE,
        mutation: "append an unclaimed worker stderr observation to the source transcript",
        disposition: MutationDisposition::SemanticDefect,
        expectation: detected(&["unexpected-stage1-worker-stderr"]),
        apply: a6d_extra_worker_stderr_observation,
    },
    DefectCase {
        id: "A7a-receipt-rights-narrowed",
        class: DefectClass::SilentAuthorityDowngrade,
        case_id: COMMITTED_CASE,
        mutation: "narrow the exposed rights recorded on the timer binding receipt",
        disposition: MutationDisposition::SemanticDefect,
        expectation: detected(&["inconsistent-stage1-binding-receipt-content"]),
        apply: a7a_receipt_rights_narrowed,
    },
    DefectCase {
        id: "A7b-prepared-rights-narrowed",
        class: DefectClass::SilentAuthorityDowngrade,
        case_id: COMMITTED_CASE,
        mutation: "narrow the prepared destination timer grant below the claimed rights",
        disposition: MutationDisposition::SemanticDefect,
        expectation: detected(&["excess-stage1-destination-authority"]),
        apply: a7b_prepared_rights_narrowed,
    },
    DefectCase {
        id: "A7c-prepared-grant-added",
        class: DefectClass::SilentAuthorityDowngrade,
        case_id: COMMITTED_CASE,
        mutation: "add a fourth grant to the prepared destination authority set",
        disposition: MutationDisposition::SemanticDefect,
        expectation: detected(&["excess-stage1-destination-authority"]),
        apply: a7c_prepared_grant_added,
    },
    DefectCase {
        id: "A7d-resource-profile-digest-restated",
        class: DefectClass::SilentAuthorityDowngrade,
        case_id: COMMITTED_CASE,
        mutation: "restate the declared timer resource profile digest consistently",
        disposition: MutationDisposition::BoundaryCase,
        expectation: UNDETECTED,
        apply: a7d_resource_profile_digest_restated,
    },
    DefectCase {
        id: "A8a-entry-dropped-without-renumbering",
        class: DefectClass::OmittedEvents,
        case_id: COMMITTED_CASE,
        mutation: "drop the effect-prepared entry and keep the recorded positions",
        disposition: MutationDisposition::SemanticDefect,
        expectation: detected(&["invalid-stage1-semantic-replay"]),
        apply: a8a_entry_dropped_without_renumbering,
    },
    DefectCase {
        id: "A8b-entry-dropped-without-raw-resync",
        class: DefectClass::OmittedEvents,
        case_id: COMMITTED_CASE,
        mutation: "drop the destination resume entry without resyncing the raw dump",
        disposition: MutationDisposition::SemanticDefect,
        expectation: detected(&["missing-stage1-final-state-observation"]),
        apply: a8b_entry_dropped_without_raw_resync,
    },
    DefectCase {
        id: "A8c-entry-dropped-and-fully-resealed",
        class: DefectClass::OmittedEvents,
        case_id: COMMITTED_CASE,
        mutation: "drop the destination resume entry and reseal the journal and raw dump",
        disposition: MutationDisposition::SemanticDefect,
        expectation: detected(&["inconsistent-stage1-final-ownership-trace"]),
        apply: a8c_entry_dropped_and_fully_resealed,
    },
];

fn a1a_stale_activation_epoch(bundle: &mut Stage1EvidenceBundle, root: &Path) {
    mutate_destination_trace(bundle, root, COMMITTED_CASE, Rechain::Renumber, true, |trace| {
        push_event(
            trace,
            0x5741_0001,
            contract_core::EventKind::Activated { lease_epoch: contract_core::LeaseEpoch(7) },
        );
    });
}

fn a1b_revoked_tombstone_generation_reset(bundle: &mut Stage1EvidenceBundle, root: &Path) {
    mutate_source_trace_chain(bundle, root, REVOCATION_CASE, Rechain::Renumber, |trace| {
        for state in [&mut trace.base_state, &mut trace.final_state] {
            for grant in &mut state.authorities {
                if grant.status == contract_core::AuthorityStatus::Revoked {
                    grant.authority.generation = contract_core::Generation::INITIAL;
                }
            }
        }
    });
}

fn a1c_stale_source_authority_root(bundle: &mut Stage1EvidenceBundle, root: &Path) {
    let case_index = case_index_of(bundle, COMMITTED_CASE);
    let trace = read_trace(bundle, root, case_index, "source.json");
    let mut authorities = trace.final_state.authorities.clone();
    authorities[1].authority.generation = contract_core::Generation(1);
    bundle.cases[case_index].authority.source_authority_root_sha256 =
        contract_hex(contract_core::canonical_digest(authorities.as_slice()).unwrap());
}

fn a2a_timer_completion_after_commit(bundle: &mut Stage1EvidenceBundle, root: &Path) {
    let case_index = case_index_of(bundle, COMMITTED_CASE);
    let timer =
        read_trace(bundle, root, case_index, "source.json").final_state.timer.claim.resource;
    mutate_destination_trace(bundle, root, COMMITTED_CASE, Rechain::Renumber, true, |trace| {
        push_event(
            trace,
            0x5742_0001,
            contract_core::EventKind::TimerCompleted {
                timer,
                arm_operation: contract_core::Identity::from_u128(0x5742_0002),
                evidence: contract_core::EvidenceRef {
                    identity: contract_core::Identity::from_u128(0x5742_0003),
                    kind: contract_core::EvidenceKind::EffectOutcome,
                    digest: contract_core::Digest::from_bytes(
                        Sha256::digest(0x5742_0003_u128.to_be_bytes()).into(),
                    ),
                },
            },
        );
    });
}

fn a2b_freeze_disposition_rewritten(bundle: &mut Stage1EvidenceBundle, root: &Path) {
    mutate_source_trace_chain(bundle, root, COMMITTED_CASE, Rechain::Renumber, |trace| {
        for entry in &mut trace.entries {
            if let contract_core::EventKind::Frozen { timer, .. } = &mut entry.event.kind {
                *timer = contract_core::TimerDisposition::Completed;
            }
        }
    });
}

fn a2c_supplemental_round_trip_erased(bundle: &mut Stage1EvidenceBundle, root: &Path) {
    let case_index = case_index_of(bundle, COMMITTED_CASE);
    rewrite_raw_transcript(bundle, root, case_index, "source.jsonl", |lines| {
        lines.retain(|line| {
            !line
                .get("worker")
                .and_then(serde_json::Value::as_str)
                .is_some_and(|worker| worker.contains("supplemental"))
        });
    });
}

fn a3a_commit_event_duplicated(bundle: &mut Stage1EvidenceBundle, root: &Path) {
    duplicate_entry(bundle, root, |kind| {
        matches!(kind, contract_core::EventKind::HandoffCommitted { .. })
    });
}

fn a3b_resume_event_duplicated(bundle: &mut Stage1EvidenceBundle, root: &Path) {
    duplicate_entry(bundle, root, |kind| {
        matches!(kind, contract_core::EventKind::DestinationResumed)
    });
}

fn duplicate_entry(
    bundle: &mut Stage1EvidenceBundle,
    root: &Path,
    matches: fn(&contract_core::EventKind) -> bool,
) {
    mutate_destination_trace(bundle, root, COMMITTED_CASE, Rechain::Renumber, true, |trace| {
        let index = trace.entries.iter().position(|entry| matches(&entry.event.kind)).unwrap();
        let duplicate = trace.entries[index].clone();
        trace.entries.insert(index + 1, duplicate);
    });
}

fn a3c_transcript_dump_round_trip_duplicated(bundle: &mut Stage1EvidenceBundle, root: &Path) {
    let case_index = case_index_of(bundle, COMMITTED_CASE);
    rewrite_raw_transcript(bundle, root, case_index, "destination.jsonl", |lines| {
        let next_sequence = lines
            .iter()
            .filter_map(|line| line.get("sequence").and_then(serde_json::Value::as_u64))
            .max()
            .unwrap();
        let mut duplicated = Vec::new();
        for (offset, index) in [2_usize, 3].into_iter().enumerate() {
            let mut line = lines[index].clone();
            line["sequence"] =
                serde_json::Value::from(next_sequence + 1 + u64::try_from(offset).unwrap());
            let mut protocol = serde_json::from_str::<serde_json::Value>(
                line.get("line").and_then(serde_json::Value::as_str).unwrap(),
            )
            .unwrap();
            let id = protocol["id"].as_str().unwrap().replace("000002", "000009");
            protocol["id"] = serde_json::Value::String(id);
            line["line"] = serde_json::Value::String(serde_json::to_string(&protocol).unwrap());
            duplicated.push(line);
        }
        lines.extend(duplicated);
    });
}

fn a4a_revocation_provider_kind_remapped(bundle: &mut Stage1EvidenceBundle, root: &Path) {
    remap_revocation_error(bundle, root, |error| {
        error["provider_kind"] = serde_json::Value::String("Conflict".to_owned());
    });
}

fn a4b_revocation_error_family_remapped(bundle: &mut Stage1EvidenceBundle, root: &Path) {
    remap_revocation_error(bundle, root, |error| {
        error["code"] = serde_json::Value::String("adapter".to_owned());
        error["provider_kind"] = serde_json::Value::Null;
        error["adapter_kind"] = serde_json::Value::String("incompatible_profile".to_owned());
    });
}

fn a4c_revocation_retryable_flag_flipped(bundle: &mut Stage1EvidenceBundle, root: &Path) {
    remap_revocation_error(bundle, root, |error| {
        error["retryable"] = serde_json::Value::Bool(true);
    });
}

fn remap_revocation_error(
    bundle: &mut Stage1EvidenceBundle,
    root: &Path,
    mutate: fn(&mut serde_json::Value),
) {
    let case_index = case_index_of(bundle, REVOCATION_CASE);
    rewrite_raw_transcript(bundle, root, case_index, "destination.jsonl", |lines| {
        mutate_embedded_protocol(
            lines,
            |protocol| protocol.pointer("/outcome/error").is_some(),
            |protocol| mutate(protocol.pointer_mut("/outcome/error").unwrap()),
        );
    });
}

fn a5a_rejection_destination_authority_root(bundle: &mut Stage1EvidenceBundle, root: &Path) {
    let case_index = case_index_of(bundle, RETAINED_CASE);
    let trace = read_trace(bundle, root, case_index, "source.json");
    bundle.cases[case_index].authority.destination_authority_root_sha256 = contract_hex(
        contract_core::canonical_digest(trace.final_state.authorities.as_slice()).unwrap(),
    );
}

fn a5b_prepare_after_commit(bundle: &mut Stage1EvidenceBundle, root: &Path) {
    mutate_destination_trace(bundle, root, COMMITTED_CASE, Rechain::Renumber, true, |trace| {
        let index = trace
            .entries
            .iter()
            .position(|entry| {
                matches!(entry.event.kind, contract_core::EventKind::DestinationPrepared { .. })
            })
            .unwrap();
        let prepared = trace.entries.remove(index);
        let commit = trace
            .entries
            .iter()
            .position(|entry| {
                matches!(entry.event.kind, contract_core::EventKind::HandoffCommitted { .. })
            })
            .unwrap();
        trace.entries.insert(commit + 1, prepared);
    });
}

fn a5c_profile_digest_drift(bundle: &mut Stage1EvidenceBundle, root: &Path) {
    let drifted =
        contract_core::Digest::from_bytes(Sha256::digest(b"stage1-drifted-profile").into());
    mutate_source_trace_chain(bundle, root, COMMITTED_CASE, Rechain::Renumber, move |trace| {
        trace.base_state.profile_digest = drifted;
        trace.final_state.profile_digest = drifted;
    });
}

fn a6a_source_fenced_flag_cleared(bundle: &mut Stage1EvidenceBundle, _root: &Path) {
    let case_index = case_index_of(bundle, COMMITTED_CASE);
    bundle.cases[case_index].authority.source_fenced = false;
}

fn a6b_lease_epoch_not_monotonic(bundle: &mut Stage1EvidenceBundle, _root: &Path) {
    let case_index = case_index_of(bundle, COMMITTED_CASE);
    let authority = &mut bundle.cases[case_index].authority;
    authority.destination_lease_epoch = Some(authority.source_lease_epoch);
}

fn a6c_post_export_source_resume(bundle: &mut Stage1EvidenceBundle, root: &Path) {
    mutate_source_trace_chain(bundle, root, REVOCATION_CASE, Rechain::Renumber, |trace| {
        push_event(trace, 0x5746_0001, contract_core::EventKind::SourceResumed);
    });
}

fn a6d_extra_worker_stderr_observation(bundle: &mut Stage1EvidenceBundle, root: &Path) {
    let case_index = case_index_of(bundle, COMMITTED_CASE);
    let worker = format!("{COMMITTED_CASE}-source");
    rewrite_raw_transcript(bundle, root, case_index, "source.jsonl", |lines| {
        let next_sequence = lines
            .iter()
            .filter(|line| line.get("worker").and_then(serde_json::Value::as_str) == Some(&worker))
            .filter_map(|line| line.get("sequence").and_then(serde_json::Value::as_u64))
            .max()
            .unwrap();
        lines.push(serde_json::json!({
            "worker": worker,
            "pid": 100,
            "sequence": next_sequence + 1,
            "stream": "worker_stderr",
            "line": "stale key-value write probe rejected",
        }));
    });
}

fn a7a_receipt_rights_narrowed(bundle: &mut Stage1EvidenceBundle, root: &Path) {
    rewrite_timer_receipt(bundle, root, |receipt| {
        receipt.exposed_rights = narrow(receipt.exposed_rights, contract_core::Rights::REBIND);
    });
}

fn a7b_prepared_rights_narrowed(bundle: &mut Stage1EvidenceBundle, root: &Path) {
    mutate_destination_trace(bundle, root, COMMITTED_CASE, Rechain::Renumber, true, |trace| {
        mutate_prepared_destination(trace, |prepared| {
            let grant = &mut prepared.authorities[1];
            grant.rights = narrow(grant.rights, contract_core::Rights::TIMER_CANCEL);
        });
    });
}

fn a7c_prepared_grant_added(bundle: &mut Stage1EvidenceBundle, root: &Path) {
    mutate_destination_trace(bundle, root, COMMITTED_CASE, Rechain::Renumber, true, |trace| {
        mutate_prepared_destination(trace, |prepared| {
            let mut extra = prepared.authorities[1].clone();
            extra.authority =
                contract_core::EntityRef::initial(contract_core::Identity::from_u128(0x5747_0001));
            extra.resource =
                contract_core::EntityRef::initial(contract_core::Identity::from_u128(0x5747_0002));
            prepared.authorities.push(extra);
        });
    });
}

fn a7d_resource_profile_digest_restated(bundle: &mut Stage1EvidenceBundle, _root: &Path) {
    let restated = format!("{:x}", Sha256::digest(b"stage1-restated-timer-resource-profile"));
    bundle.environment.resource_profiles[0].profile_sha256 = restated;
}

fn a8a_entry_dropped_without_renumbering(bundle: &mut Stage1EvidenceBundle, root: &Path) {
    mutate_destination_trace(bundle, root, COMMITTED_CASE, Rechain::KeepPositions, true, |trace| {
        drop_entry(trace, |kind| matches!(kind, contract_core::EventKind::EffectPrepared { .. }));
    });
}

fn a8b_entry_dropped_without_raw_resync(bundle: &mut Stage1EvidenceBundle, root: &Path) {
    mutate_destination_trace(bundle, root, COMMITTED_CASE, Rechain::Renumber, false, |trace| {
        drop_entry(trace, |kind| matches!(kind, contract_core::EventKind::DestinationResumed));
    });
}

fn a8c_entry_dropped_and_fully_resealed(bundle: &mut Stage1EvidenceBundle, root: &Path) {
    mutate_destination_trace(bundle, root, COMMITTED_CASE, Rechain::Renumber, true, |trace| {
        drop_entry(trace, |kind| matches!(kind, contract_core::EventKind::DestinationResumed));
    });
}
