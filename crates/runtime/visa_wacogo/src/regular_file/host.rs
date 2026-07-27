use std::collections::BTreeMap;

use contract_core::{CanonicalState, ProfileAccess};
use serde_json::{Value, json};
use visa_component_adapter::{
    AdapterProvider, ProfileBinding, ProfileCallResult, ProfileFailure, ResourceBindingError,
    profile_execute, profile_observe,
};
use visa_profile::{
    FileLockState, REGULAR_FILE_EXTENSION_ID, RegularFileOperation, RegularFileResult,
    RegularFileState, decode_regular_file_result, encode_regular_file_operation,
    regular_file_state,
};
use visa_runtime::Coordinator;

use super::state::{durability_name, parse_durability};
use crate::{
    error::protocol_error,
    protocol::{HostCall, HostCallOperation, ResourceKind, WireError},
    state::{decode_canonical_hex, parse_canonical_u64},
};

pub(super) struct RegularFileHostState<P> {
    coordinator: Coordinator<P>,
    files: BTreeMap<u64, ProfileBinding>,
    next_resource: u64,
}

impl<P> RegularFileHostState<P>
where
    P: AdapterProvider,
{
    pub(super) fn new(coordinator: Coordinator<P>) -> Self {
        Self { coordinator, files: BTreeMap::new(), next_resource: 1 }
    }

    pub(super) fn coordinator(&self) -> &Coordinator<P> {
        &self.coordinator
    }

    pub(super) fn coordinator_mut(&mut self) -> &mut Coordinator<P> {
        &mut self.coordinator
    }

    pub(super) fn into_coordinator(self) -> Coordinator<P> {
        self.coordinator
    }

    pub(super) fn fresh_file(&mut self) -> Result<u64, ResourceBindingError> {
        if !self.files.is_empty() {
            return Err(ResourceBindingError::LiveResources);
        }
        let binding =
            ProfileBinding::for_state(self.coordinator.state(), REGULAR_FILE_EXTENSION_ID)
                .map_err(ResourceBindingError::from)?;
        let id = self.next_resource;
        if id == 0 {
            return Err(ResourceBindingError::ResourceTable);
        }
        self.next_resource = id.checked_add(1).ok_or(ResourceBindingError::ResourceTable)?;
        self.files.insert(id, binding);
        Ok(id)
    }

    pub(super) fn resource_count(&self) -> usize {
        self.files.len()
    }

    pub(super) fn resources_are_empty(&self) -> bool {
        self.files.is_empty()
    }

    pub(super) fn handle(&mut self, call: HostCall) -> Result<Value, WireError> {
        match call.operation {
            HostCallOperation::FileRead(args) => {
                let binding = self.binding(call.resource)?;
                let operation = RegularFileOperation::Read { max_bytes: args.max_bytes };
                let payload = encode_regular_file_operation(&operation)
                    .map_err(|_| protocol_error("invalid-argument", "cannot encode file.read"))?;
                let result = profile_observe(&mut self.coordinator, &binding, payload)
                    .map_err(file_wire_error)?;
                let decoded = decode_regular_file_result(&result.payload).map_err(|_| {
                    protocol_error("invalid-provider-result", "cannot decode file.read result")
                })?;
                let RegularFileResult::Read { bytes, .. } = decoded else {
                    return Err(protocol_error(
                        "invalid-provider-result",
                        "file.read returned a non-read result",
                    ));
                };
                let state = canonical_regular_file(self.coordinator.state()).map_err(|_| {
                    protocol_error("invalid-canonical-profile", "regular-file state is invalid")
                })?;
                Ok(json!({
                    "observation": observation(&result, &state)?,
                    "bytesHex": hex::encode(bytes),
                }))
            }
            HostCallOperation::FileWrite(args) => self.execute(
                call.resource,
                args.idempotency_key,
                RegularFileOperation::Write {
                    bytes: decode_bytes(&args.bytes_hex)?,
                    durability: parse_durability(&args.durability).map_err(adapter_to_protocol)?,
                },
                ProfileAccess::Write,
                ExpectedResult::Mutated,
            ),
            HostCallOperation::FileAppend(args) => self.execute(
                call.resource,
                args.idempotency_key,
                RegularFileOperation::Append {
                    bytes: decode_bytes(&args.bytes_hex)?,
                    durability: parse_durability(&args.durability).map_err(adapter_to_protocol)?,
                },
                ProfileAccess::Write,
                ExpectedResult::Mutated,
            ),
            HostCallOperation::FileTruncate(args) => self.execute(
                call.resource,
                args.idempotency_key,
                RegularFileOperation::Truncate {
                    size: canonical_u64(&args.size, "size")?,
                    durability: parse_durability(&args.durability).map_err(adapter_to_protocol)?,
                },
                ProfileAccess::Write,
                ExpectedResult::Mutated,
            ),
            HostCallOperation::FileRename(args) => self.execute(
                call.resource,
                args.idempotency_key,
                RegularFileOperation::Rename { relative_path: args.relative_path.into_bytes() },
                ProfileAccess::Write,
                ExpectedResult::Renamed,
            ),
            HostCallOperation::FileSync(args) => self.execute(
                call.resource,
                args.idempotency_key,
                RegularFileOperation::Sync {
                    durability: parse_durability(&args.durability).map_err(adapter_to_protocol)?,
                },
                ProfileAccess::Control,
                ExpectedResult::Synced,
            ),
            HostCallOperation::FileAcquireLock(args) => self.execute(
                call.resource,
                args.idempotency_key,
                RegularFileOperation::AcquireLock,
                ProfileAccess::Control,
                ExpectedResult::Locked,
            ),
            HostCallOperation::FileReleaseLock(args) => self.execute(
                call.resource,
                args.idempotency_key,
                RegularFileOperation::ReleaseLock,
                ProfileAccess::Control,
                ExpectedResult::Unlocked,
            ),
            HostCallOperation::ResourceDispose(args) => {
                if args.kind != ResourceKind::File {
                    return Err(protocol_error(
                        "profile-hostcall-mismatch",
                        "non-file resource disposal reached a regular-file host state",
                    ));
                }
                if self.files.remove(&call.resource).is_none() {
                    return Err(protocol_error(
                        "unknown-resource",
                        format!("file resource {} was already disposed", call.resource),
                    ));
                }
                Ok(Value::Null)
            }
            HostCallOperation::KvRead(_)
            | HostCallOperation::KvConditionalPut(_)
            | HostCallOperation::TimerArm(_)
            | HostCallOperation::TimerCancel(_) => Err(protocol_error(
                "profile-hostcall-mismatch",
                "cooperative-handoff hostcall reached a regular-file host state",
            )),
        }
    }

    fn binding(&self, resource: u64) -> Result<ProfileBinding, WireError> {
        self.files.get(&resource).cloned().ok_or_else(|| {
            protocol_error("unknown-resource", format!("unknown file resource {resource}"))
        })
    }

    fn execute(
        &mut self,
        resource: u64,
        idempotency_key: String,
        operation: RegularFileOperation,
        access: ProfileAccess,
        expected: ExpectedResult,
    ) -> Result<Value, WireError> {
        if idempotency_key.is_empty() {
            return Err(protocol_error(
                "invalid-argument",
                "file mutation requires a non-empty idempotency key",
            ));
        }
        let binding = self.binding(resource)?;
        let payload = encode_regular_file_operation(&operation)
            .map_err(|_| protocol_error("invalid-argument", "cannot encode file operation"))?;
        let result = profile_execute(
            &mut self.coordinator,
            &binding,
            access,
            idempotency_key.as_bytes(),
            payload,
        )
        .map_err(file_wire_error)?;
        let decoded = decode_regular_file_result(&result.payload).map_err(|_| {
            protocol_error("invalid-provider-result", "cannot decode file operation result")
        })?;
        let matches = matches!(
            (expected, decoded),
            (ExpectedResult::Mutated, RegularFileResult::Mutated { .. })
                | (ExpectedResult::Renamed, RegularFileResult::Renamed { .. })
                | (ExpectedResult::Synced, RegularFileResult::Synced { .. })
                | (ExpectedResult::Locked, RegularFileResult::Lock { state: FileLockState::Held })
                | (
                    ExpectedResult::Unlocked,
                    RegularFileResult::Lock { state: FileLockState::Unlocked }
                )
        );
        if !matches {
            return Err(protocol_error(
                "invalid-provider-result",
                "file operation returned an unexpected result variant",
            ));
        }
        let state = canonical_regular_file(self.coordinator.state()).map_err(|_| {
            protocol_error("invalid-canonical-profile", "regular-file state is invalid")
        })?;
        observation(&result, &state)
    }
}

#[derive(Clone, Copy)]
enum ExpectedResult {
    Mutated,
    Renamed,
    Synced,
    Locked,
    Unlocked,
}

fn observation(call: &ProfileCallResult, state: &RegularFileState) -> Result<Value, WireError> {
    if state.last_operation != Some(call.operation) {
        return Err(protocol_error(
            "invalid-provider-result",
            "canonical regular-file operation does not match provider result",
        ));
    }
    Ok(json!({
        "operationId": call.operation_id,
        "logicalOffset": state.logical_offset.to_string(),
        "version": state.version.to_string(),
        "size": state.size.to_string(),
        "contentDigestHex": hex::encode(state.content_digest.0),
        "durableThrough": durability_name(state.durable_through),
    }))
}

pub(super) fn canonical_regular_file(state: &CanonicalState) -> Result<RegularFileState, ()> {
    let mut matching =
        state.extensions.iter().filter(|extension| extension.id == REGULAR_FILE_EXTENSION_ID);
    let extension = matching.next().ok_or(())?;
    if matching.next().is_some() {
        return Err(());
    }
    regular_file_state(extension).map_err(|_| ())
}

fn decode_bytes(value: &str) -> Result<Vec<u8>, WireError> {
    decode_canonical_hex(value).map_err(|detail| {
        protocol_error("invalid-argument", format!("bytesHex is invalid: {detail}"))
    })
}

fn canonical_u64(value: &str, name: &str) -> Result<u64, WireError> {
    parse_canonical_u64(value).ok_or_else(|| {
        protocol_error("invalid-argument", format!("{name} must be canonical u64 text"))
    })
}

fn adapter_to_protocol(error: visa_component_adapter::RegularFileAdapterError) -> WireError {
    protocol_error("invalid-argument", error.to_string())
}

fn file_wire_error(error: ProfileFailure) -> WireError {
    let (kind, detail) = match error {
        ProfileFailure::Denied => ("denied", None),
        ProfileFailure::Conflict => ("conflict", None),
        ProfileFailure::StaleBinding => ("stale-binding", None),
        ProfileFailure::Invalid | ProfileFailure::Unsupported => ("unsupported", None),
        ProfileFailure::Indeterminate(operation) => ("indeterminate", Some(operation)),
        ProfileFailure::Cancelled | ProfileFailure::Unavailable => ("unavailable", None),
    };
    WireError { domain: "file".into(), kind: kind.into(), detail }
}
