use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

pub const EFFECT_CLOSURE_FAULT_MATRIX_V1_SCHEMA: &str =
    "visa.effect-closure-provider-fault-matrix.v1";
pub const EFFECT_CLOSURE_FAULT_MATRIX_V2_SCHEMA: &str =
    "visa.effect-closure-provider-fault-matrix.v2";
/// Historical schema alias retained for consumers of the 2.0 contract.
pub const EFFECT_CLOSURE_FAULT_MATRIX_SCHEMA: &str = EFFECT_CLOSURE_FAULT_MATRIX_V1_SCHEMA;
pub const RECORDED_NATIVE_EFFECT_REPLAY_SCHEMA: &str = "visa.recorded-native-effect-replay.v1";

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum EffectClosureContractExpectation {
    Accepted,
    Applied,
    ExactReplay,
    Absent,
    Authorized,
    Denied,
    PermitConsumed,
    RejectedStaleSelector,
    RejectedConflict,
    RejectedInvalidTransition,
    ObservedCommitted,
    ObservedGuestReturnedDispatch,
    ObservedGuestFailedDispatch,
    ObservedOutcomeRecorded,
    ObservedCompleted,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EffectClosureFaultCase {
    pub case_id: &'static str,
    pub expectation: EffectClosureContractExpectation,
}

pub const EFFECT_CLOSURE_PROVIDER_FAULT_MATRIX_V1: &[EffectClosureFaultCase] = &[
    case("descriptor", EffectClosureContractExpectation::Accepted),
    case("query-absent", EffectClosureContractExpectation::Absent),
    case("stale-selector", EffectClosureContractExpectation::RejectedStaleSelector),
    case("initial-admission", EffectClosureContractExpectation::Applied),
    case("query-committed", EffectClosureContractExpectation::ObservedCommitted),
    case("permit-exact-effect", EffectClosureContractExpectation::Authorized),
    case("permit-other-provider", EffectClosureContractExpectation::Denied),
    case("permit-mutated-effect", EffectClosureContractExpectation::Denied),
    case("dispatch-other-provider", EffectClosureContractExpectation::Denied),
    case("dispatch-mutated-effect", EffectClosureContractExpectation::Denied),
    case("exact-admission-replay", EffectClosureContractExpectation::ExactReplay),
    case("alias-publication-id", EffectClosureContractExpectation::RejectedConflict),
    case("mutated-same-operation-lane", EffectClosureContractExpectation::RejectedConflict),
    case("mutated-same-idempotency-lane", EffectClosureContractExpectation::RejectedConflict),
    case("idempotency-key", EffectClosureContractExpectation::RejectedConflict),
    case("request-digest", EffectClosureContractExpectation::RejectedConflict),
    case("kind", EffectClosureContractExpectation::RejectedConflict),
    case("subject", EffectClosureContractExpectation::RejectedConflict),
    case("resource", EffectClosureContractExpectation::RejectedConflict),
    case("authority", EffectClosureContractExpectation::RejectedConflict),
    case("causal-parent", EffectClosureContractExpectation::RejectedConflict),
    case("conflicting-registration", EffectClosureContractExpectation::RejectedConflict),
    case("conflicting-commit", EffectClosureContractExpectation::RejectedInvalidTransition),
    case("complete-before-outcome", EffectClosureContractExpectation::RejectedInvalidTransition),
    case("outcome-before-dispatch", EffectClosureContractExpectation::RejectedInvalidTransition),
    case("dispatch-gate-consumes-permit", EffectClosureContractExpectation::PermitConsumed),
    case("duplicate-dispatch", EffectClosureContractExpectation::RejectedInvalidTransition),
    case("record-outcome", EffectClosureContractExpectation::Applied),
    case("query-outcome-recorded", EffectClosureContractExpectation::ObservedOutcomeRecorded),
    case("replay-outcome", EffectClosureContractExpectation::ExactReplay),
    case("conflicting-outcome", EffectClosureContractExpectation::RejectedConflict),
    case("complete", EffectClosureContractExpectation::Applied),
    case("query-completed", EffectClosureContractExpectation::ObservedCompleted),
    case("replay-complete", EffectClosureContractExpectation::ExactReplay),
    case("conflicting-complete", EffectClosureContractExpectation::RejectedConflict),
    case("failed-dispatch", EffectClosureContractExpectation::PermitConsumed),
    case(
        "failed-dispatch-canonical-outcome",
        EffectClosureContractExpectation::RejectedInvalidTransition,
    ),
    case("query-failed-dispatch", EffectClosureContractExpectation::ObservedCommitted),
];

/// Historical 2.0 matrix alias. It must never be reinterpreted in place.
pub const EFFECT_CLOSURE_PROVIDER_FAULT_MATRIX: &[EffectClosureFaultCase] =
    EFFECT_CLOSURE_PROVIDER_FAULT_MATRIX_V1;

/// Protocol-2.1 contract, including terminal finish replay and a canonical
/// outcome after either guest terminal result.
pub const EFFECT_CLOSURE_PROVIDER_FAULT_MATRIX_V2: &[EffectClosureFaultCase] = &[
    case("descriptor", EffectClosureContractExpectation::Accepted),
    case("query-absent", EffectClosureContractExpectation::Absent),
    case("stale-selector", EffectClosureContractExpectation::RejectedStaleSelector),
    case("initial-admission", EffectClosureContractExpectation::Applied),
    case("query-committed", EffectClosureContractExpectation::ObservedCommitted),
    case("permit-exact-effect", EffectClosureContractExpectation::Authorized),
    case("permit-other-provider", EffectClosureContractExpectation::Denied),
    case("permit-mutated-effect", EffectClosureContractExpectation::Denied),
    case("dispatch-other-provider", EffectClosureContractExpectation::Denied),
    case("dispatch-mutated-effect", EffectClosureContractExpectation::Denied),
    case("exact-admission-replay", EffectClosureContractExpectation::ExactReplay),
    case("alias-publication-id", EffectClosureContractExpectation::RejectedConflict),
    case("mutated-same-operation-lane", EffectClosureContractExpectation::RejectedConflict),
    case("mutated-same-idempotency-lane", EffectClosureContractExpectation::RejectedConflict),
    case("idempotency-key", EffectClosureContractExpectation::RejectedConflict),
    case("request-digest", EffectClosureContractExpectation::RejectedConflict),
    case("kind", EffectClosureContractExpectation::RejectedConflict),
    case("subject", EffectClosureContractExpectation::RejectedConflict),
    case("resource", EffectClosureContractExpectation::RejectedConflict),
    case("authority", EffectClosureContractExpectation::RejectedConflict),
    case("causal-parent", EffectClosureContractExpectation::RejectedConflict),
    case("conflicting-registration", EffectClosureContractExpectation::RejectedConflict),
    case("conflicting-commit", EffectClosureContractExpectation::RejectedInvalidTransition),
    case("complete-before-outcome", EffectClosureContractExpectation::RejectedInvalidTransition),
    case("outcome-before-dispatch", EffectClosureContractExpectation::RejectedInvalidTransition),
    case("dispatch-gate-consumes-permit", EffectClosureContractExpectation::PermitConsumed),
    case("finish-applied-simulated-reply-loss", EffectClosureContractExpectation::Applied),
    case("finish-conflicting-replay", EffectClosureContractExpectation::RejectedConflict),
    case("finish-exact-replay", EffectClosureContractExpectation::ExactReplay),
    case(
        "query-terminal-dispatch",
        EffectClosureContractExpectation::ObservedGuestReturnedDispatch,
    ),
    case("duplicate-dispatch", EffectClosureContractExpectation::RejectedInvalidTransition),
    case("record-outcome", EffectClosureContractExpectation::Applied),
    case("query-outcome-recorded", EffectClosureContractExpectation::ObservedOutcomeRecorded),
    case("replay-outcome", EffectClosureContractExpectation::ExactReplay),
    case("conflicting-outcome", EffectClosureContractExpectation::RejectedConflict),
    case("complete", EffectClosureContractExpectation::Applied),
    case("query-completed", EffectClosureContractExpectation::ObservedCompleted),
    case("replay-complete", EffectClosureContractExpectation::ExactReplay),
    case("conflicting-complete", EffectClosureContractExpectation::RejectedConflict),
    case("failed-dispatch", EffectClosureContractExpectation::PermitConsumed),
    case("failed-finish-applied-simulated-reply-loss", EffectClosureContractExpectation::Applied),
    case("failed-finish-conflicting-replay", EffectClosureContractExpectation::RejectedConflict),
    case("failed-finish-exact-replay", EffectClosureContractExpectation::ExactReplay),
    case(
        "query-failed-terminal-dispatch",
        EffectClosureContractExpectation::ObservedGuestFailedDispatch,
    ),
    case("failed-dispatch-canonical-outcome", EffectClosureContractExpectation::Applied),
    case("failed-dispatch-outcome-replay", EffectClosureContractExpectation::ExactReplay),
    case("failed-dispatch-outcome-conflict", EffectClosureContractExpectation::RejectedConflict),
    case("query-failed-dispatch", EffectClosureContractExpectation::ObservedOutcomeRecorded),
];

const fn case(
    case_id: &'static str,
    expectation: EffectClosureContractExpectation,
) -> EffectClosureFaultCase {
    EffectClosureFaultCase { case_id, expectation }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EffectClosureProviderContractReport {
    observations: Vec<EffectClosureFaultCase>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EffectClosureProviderContractV2Report {
    observations: Vec<EffectClosureFaultCase>,
}

impl EffectClosureProviderContractV2Report {
    pub fn new(observations: Vec<EffectClosureFaultCase>) -> Result<Self, String> {
        validate_effect_closure_contract_v2_observations(&observations)?;
        Ok(Self { observations })
    }

    pub fn observations(&self) -> &[EffectClosureFaultCase] {
        &self.observations
    }
}

impl EffectClosureProviderContractReport {
    pub fn new(observations: Vec<EffectClosureFaultCase>) -> Result<Self, String> {
        validate_effect_closure_contract_observations(&observations)?;
        Ok(Self { observations })
    }

    pub fn observations(&self) -> &[EffectClosureFaultCase] {
        &self.observations
    }
}

pub fn validate_effect_closure_contract_observations(
    observations: &[EffectClosureFaultCase],
) -> Result<(), String> {
    if observations == EFFECT_CLOSURE_PROVIDER_FAULT_MATRIX {
        return Ok(());
    }
    let mismatch = observations
        .iter()
        .zip(EFFECT_CLOSURE_PROVIDER_FAULT_MATRIX)
        .position(|(actual, expected)| actual != expected)
        .unwrap_or_else(|| observations.len().min(EFFECT_CLOSURE_PROVIDER_FAULT_MATRIX.len()));
    Err(format!(
        "effect-closure fault matrix drifted at index {mismatch}: expected {:?}, observed {:?}",
        EFFECT_CLOSURE_PROVIDER_FAULT_MATRIX.get(mismatch),
        observations.get(mismatch)
    ))
}

pub fn validate_effect_closure_contract_v2_observations(
    observations: &[EffectClosureFaultCase],
) -> Result<(), String> {
    validate_effect_closure_contract_observations_against(
        observations,
        EFFECT_CLOSURE_PROVIDER_FAULT_MATRIX_V2,
        "effect-closure v2 fault matrix",
    )
}

fn validate_effect_closure_contract_observations_against(
    observations: &[EffectClosureFaultCase],
    expected: &[EffectClosureFaultCase],
    label: &str,
) -> Result<(), String> {
    if observations == expected {
        return Ok(());
    }
    let mismatch = observations
        .iter()
        .zip(expected)
        .position(|(actual, expected)| actual != expected)
        .unwrap_or_else(|| observations.len().min(expected.len()));
    Err(format!(
        "{label} drifted at index {mismatch}: expected {:?}, observed {:?}",
        expected.get(mismatch),
        observations.get(mismatch)
    ))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RecordedNativeEffectOperation {
    Initialize,
    Register,
    Prepare,
    Commit,
    Complete,
}

pub const RECORDED_NATIVE_EFFECT_OPERATIONS: &[RecordedNativeEffectOperation] = &[
    RecordedNativeEffectOperation::Initialize,
    RecordedNativeEffectOperation::Register,
    RecordedNativeEffectOperation::Prepare,
    RecordedNativeEffectOperation::Commit,
    RecordedNativeEffectOperation::Complete,
];

/// Provider-neutral projection of one accepted native exchange.
///
/// Request and response bytes stay opaque. The provider adapter is responsible
/// for classifying the operation; this crate checks only framing, issuance
/// binding, chain continuity, and exact replay. It does not import or interpret
/// any Nexus wire structure.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecordedNativeEffectExchange {
    pub operation: RecordedNativeEffectOperation,
    pub request_id: u64,
    pub request_jsonl: String,
    pub response_jsonl: String,
    pub receipt_sequence: u64,
    pub request_sha256: String,
    pub previous_receipt_sha256: Option<String>,
    pub receipt_sha256: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecordedNativeExactReplay {
    pub request_id: u64,
    pub original_response_jsonl: String,
    pub replay_response_jsonl: String,
    pub accepted_chain_length_before: usize,
    pub accepted_chain_length_after: usize,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecordedNativeEffectReplay {
    pub schema: String,
    pub exchanges: Vec<RecordedNativeEffectExchange>,
    pub exact_replay: RecordedNativeExactReplay,
}

pub fn validate_recorded_native_effect_replay(
    replay: &RecordedNativeEffectReplay,
) -> Result<(), String> {
    if replay.schema != RECORDED_NATIVE_EFFECT_REPLAY_SCHEMA {
        return Err("recorded native effect replay used the wrong schema".to_owned());
    }
    if replay.exchanges.len() != RECORDED_NATIVE_EFFECT_OPERATIONS.len() {
        return Err("recorded native effect replay changed the fixed lifecycle length".to_owned());
    }

    let mut previous_receipt = None;
    for (index, (exchange, expected_operation)) in
        replay.exchanges.iter().zip(RECORDED_NATIVE_EFFECT_OPERATIONS).enumerate()
    {
        let expected_sequence =
            u64::try_from(index).map_err(|error| error.to_string())?.saturating_add(1);
        if exchange.operation != *expected_operation {
            return Err(format!("recorded native operation drifted at index {index}"));
        }
        if exchange.request_id != expected_sequence
            || exchange.receipt_sequence != expected_sequence
        {
            return Err(format!("recorded native sequence drifted at index {index}"));
        }
        validate_jsonl(&exchange.request_jsonl, "request")?;
        validate_jsonl(&exchange.response_jsonl, "response")?;
        let request = exchange
            .request_jsonl
            .strip_suffix('\n')
            .ok_or_else(|| "recorded native request omitted LF".to_owned())?;
        if exchange.request_sha256 != sha256_hex(request.as_bytes()) {
            return Err(format!("recorded native request digest drifted at index {index}"));
        }
        if exchange.previous_receipt_sha256 != previous_receipt {
            return Err(format!("recorded native receipt parent drifted at index {index}"));
        }
        if !lower_hex_256(&exchange.receipt_sha256) {
            return Err(format!("recorded native receipt digest was malformed at index {index}"));
        }
        previous_receipt = Some(exchange.receipt_sha256.clone());
    }

    let exact = &replay.exact_replay;
    let last = replay
        .exchanges
        .last()
        .ok_or_else(|| "recorded native replay omitted its accepted chain".to_owned())?;
    if exact.request_id != last.request_id
        || exact.original_response_jsonl != last.response_jsonl
        || exact.replay_response_jsonl != exact.original_response_jsonl
        || exact.accepted_chain_length_before != replay.exchanges.len()
        || exact.accepted_chain_length_after != replay.exchanges.len()
    {
        return Err("recorded native exact replay changed bytes or accepted chain state".to_owned());
    }
    Ok(())
}

fn validate_jsonl(value: &str, label: &str) -> Result<(), String> {
    if !value.ends_with('\n')
        || value.ends_with("\r\n")
        || value[..value.len().saturating_sub(1)].contains('\n')
    {
        return Err(format!("recorded native {label} was not one LF-delimited frame"));
    }
    let frame =
        value.strip_suffix('\n').ok_or_else(|| format!("recorded native {label} omitted LF"))?;
    let decoded = serde_json::from_str::<serde_json::Value>(frame)
        .map_err(|error| format!("recorded native {label} was not valid JSON: {error}"))?;
    if !decoded.is_object() {
        return Err(format!("recorded native {label} was not one JSON object"));
    }
    Ok(())
}

fn lower_hex_256(value: &str) -> bool {
    value.len() == 64
        && value.bytes().all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut encoded = String::with_capacity(64);
    for byte in digest {
        use core::fmt::Write as _;
        write!(&mut encoded, "{byte:02x}").expect("writing to String cannot fail");
    }
    encoded
}

#[cfg(test)]
mod tests {
    use super::*;

    fn exchange(
        index: usize,
        operation: RecordedNativeEffectOperation,
    ) -> RecordedNativeEffectExchange {
        let request_id = u64::try_from(index).unwrap() + 1;
        let request_jsonl = format!("{{\"request\":{request_id}}}\n");
        let response_jsonl = format!("{{\"response\":{request_id}}}\n");
        RecordedNativeEffectExchange {
            operation,
            request_id,
            request_sha256: sha256_hex(request_jsonl.strip_suffix('\n').unwrap().as_bytes()),
            request_jsonl,
            response_jsonl,
            receipt_sequence: request_id,
            previous_receipt_sha256: (index != 0).then(|| format!("{:064x}", index)),
            receipt_sha256: format!("{:064x}", index + 1),
        }
    }

    fn replay() -> RecordedNativeEffectReplay {
        let exchanges = RECORDED_NATIVE_EFFECT_OPERATIONS
            .iter()
            .copied()
            .enumerate()
            .map(|(index, operation)| exchange(index, operation))
            .collect::<Vec<_>>();
        let last = exchanges.last().unwrap();
        RecordedNativeEffectReplay {
            schema: RECORDED_NATIVE_EFFECT_REPLAY_SCHEMA.to_owned(),
            exact_replay: RecordedNativeExactReplay {
                request_id: last.request_id,
                original_response_jsonl: last.response_jsonl.clone(),
                replay_response_jsonl: last.response_jsonl.clone(),
                accepted_chain_length_before: exchanges.len(),
                accepted_chain_length_after: exchanges.len(),
            },
            exchanges,
        }
    }

    #[test]
    fn fixed_fault_matrix_has_stable_unique_case_ids() {
        assert_eq!(EFFECT_CLOSURE_PROVIDER_FAULT_MATRIX.len(), 38);
        for (index, case) in EFFECT_CLOSURE_PROVIDER_FAULT_MATRIX.iter().enumerate() {
            assert!(!case.case_id.is_empty());
            assert!(
                !EFFECT_CLOSURE_PROVIDER_FAULT_MATRIX[..index]
                    .iter()
                    .any(|earlier| earlier.case_id == case.case_id)
            );
        }
        validate_effect_closure_contract_observations(EFFECT_CLOSURE_PROVIDER_FAULT_MATRIX)
            .unwrap();

        assert_eq!(EFFECT_CLOSURE_PROVIDER_FAULT_MATRIX_V2.len(), 48);
        for (index, case) in EFFECT_CLOSURE_PROVIDER_FAULT_MATRIX_V2.iter().enumerate() {
            assert!(!case.case_id.is_empty());
            assert!(
                !EFFECT_CLOSURE_PROVIDER_FAULT_MATRIX_V2[..index]
                    .iter()
                    .any(|earlier| earlier.case_id == case.case_id)
            );
        }
        validate_effect_closure_contract_v2_observations(EFFECT_CLOSURE_PROVIDER_FAULT_MATRIX_V2)
            .unwrap();
        assert_eq!(
            EFFECT_CLOSURE_PROVIDER_FAULT_MATRIX[36].expectation,
            EffectClosureContractExpectation::RejectedInvalidTransition
        );
        assert_eq!(
            EFFECT_CLOSURE_PROVIDER_FAULT_MATRIX_V2[44].expectation,
            EffectClosureContractExpectation::Applied
        );
    }

    #[test]
    fn opaque_recorded_native_replay_validates_without_provider_wire_types() {
        validate_recorded_native_effect_replay(&replay()).unwrap();
    }

    #[test]
    fn recorded_native_replay_rejects_digest_chain_and_byte_mutations() {
        let mut mutated = replay();
        mutated.exchanges[1].request_jsonl.insert(1, ' ');
        assert!(validate_recorded_native_effect_replay(&mutated).is_err());

        let mut mutated = replay();
        mutated.exchanges[2].previous_receipt_sha256 = Some("f".repeat(64));
        assert!(validate_recorded_native_effect_replay(&mutated).is_err());

        let mut mutated = replay();
        mutated.exact_replay.replay_response_jsonl.push(' ');
        assert!(validate_recorded_native_effect_replay(&mutated).is_err());

        let mut mutated = replay();
        mutated.exact_replay.accepted_chain_length_after += 1;
        assert!(validate_recorded_native_effect_replay(&mutated).is_err());

        let mut mutated = replay();
        mutated.exchanges[0].response_jsonl = "not-json\n".to_owned();
        assert!(validate_recorded_native_effect_replay(&mutated).is_err());

        let mut mutated = replay();
        mutated.exchanges[0].response_jsonl = "[]\n".to_owned();
        assert!(validate_recorded_native_effect_replay(&mutated).is_err());
    }
}
