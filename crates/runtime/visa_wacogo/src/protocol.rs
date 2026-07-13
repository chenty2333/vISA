use serde::{Deserialize, Deserializer, Serialize};
use serde_json::Value;

pub(crate) const PROTOCOL_VERSION: u32 = 1;
pub(crate) const MAX_JSONL_MESSAGE_BYTES: usize = 1024 * 1024;

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct RuntimeReport {
    pub implementation: String,
    pub implementation_version: String,
    pub engine: String,
    pub engine_version: String,
    pub wacogo_version: String,
    pub wacogo_revision: String,
    pub patchset_sha256: String,
    pub patched_tree_sha256: String,
    pub wazero_version: String,
    pub go_version: String,
    pub target: String,
    pub main_module: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct CommandRequest<'a> {
    #[serde(rename = "type")]
    pub message_type: &'static str,
    pub protocol: u32,
    pub id: u64,
    pub op: &'a str,
    pub args: Value,
}

#[derive(Debug, Deserialize)]
#[serde(
    tag = "type",
    rename_all = "kebab-case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub(crate) enum Envelope {
    Prepared {
        protocol: u32,
        component_sha256: String,
        guest_instantiated: bool,
        live_resources: usize,
        runtime: RuntimeReport,
    },
    StartupError {
        protocol: u32,
        ok: bool,
        error: WireError,
        live_resources: usize,
    },
    Hostcall {
        protocol: u32,
        id: u64,
        command_id: u64,
        resource: u64,
        #[serde(flatten)]
        operation: HostCallOperation,
    },
    Response {
        protocol: u32,
        id: u64,
        ok: bool,
        #[serde(default)]
        result: FieldPresence<Value>,
        #[serde(default)]
        error: FieldPresence<WireError>,
        live_resources: usize,
    },
    Settled {
        protocol: u32,
        id: u64,
    },
}

impl Envelope {
    pub(crate) const fn protocol(&self) -> u32 {
        match self {
            Self::Prepared { protocol, .. }
            | Self::StartupError { protocol, .. }
            | Self::Hostcall { protocol, .. }
            | Self::Response { protocol, .. }
            | Self::Settled { protocol, .. } => *protocol,
        }
    }

    pub(crate) const fn kind(&self) -> &'static str {
        match self {
            Self::Prepared { .. } => "prepared",
            Self::StartupError { .. } => "startup-error",
            Self::Hostcall { .. } => "hostcall",
            Self::Response { .. } => "response",
            Self::Settled { .. } => "settled",
        }
    }
}

#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) enum FieldPresence<T> {
    #[default]
    Missing,
    Present(T),
}

impl<'de, T> Deserialize<'de> for FieldPresence<T>
where
    T: Deserialize<'de>,
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        T::deserialize(deserializer).map(Self::Present)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct WireError {
    pub domain: String,
    pub kind: String,
    #[serde(
        default,
        deserialize_with = "deserialize_optional_non_null_string",
        skip_serializing_if = "Option::is_none"
    )]
    pub detail: Option<String>,
}

fn deserialize_optional_non_null_string<'de, D>(deserializer: D) -> Result<Option<String>, D::Error>
where
    D: Deserializer<'de>,
{
    String::deserialize(deserializer).map(Some)
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct HostResponse {
    #[serde(rename = "type")]
    pub message_type: &'static str,
    pub protocol: u32,
    pub id: u64,
    pub ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<WireError>,
}

pub(crate) struct HostCall {
    pub id: u64,
    pub resource: u64,
    pub operation: HostCallOperation,
}

#[derive(Debug, Deserialize)]
#[serde(tag = "op", content = "args")]
pub(crate) enum HostCallOperation {
    #[serde(rename = "kv.read")]
    KvRead(KvReadArgs),
    #[serde(rename = "kv.conditional-put")]
    KvConditionalPut(KvConditionalPutArgs),
    #[serde(rename = "timer.arm")]
    TimerArm(TimerArmArgs),
    #[serde(rename = "timer.cancel")]
    TimerCancel(TimerCancelArgs),
    #[serde(rename = "resource.dispose")]
    ResourceDispose(ResourceDisposeArgs),
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct KvReadArgs {
    pub key: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct KvConditionalPutArgs {
    pub idempotency_key: String,
    pub key: String,
    pub expected_version: NullableU64Text,
    pub value_hex: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct TimerArmArgs {
    pub idempotency_key: String,
    pub duration_ns: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct TimerCancelArgs {
    pub operation_id: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct ResourceDisposeArgs {
    pub kind: ResourceKind,
}

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum ResourceKind {
    Kv,
    Timer,
}

#[derive(Debug, Deserialize)]
#[serde(transparent)]
pub(crate) struct NullableU64Text(pub Option<String>);

#[derive(Debug)]
pub(crate) struct CommandReply {
    pub result: Result<Value, visa_component_adapter::AdapterError>,
    pub live_resources: usize,
}
