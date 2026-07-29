pub mod canonical;

mod record;

use std::path::Path;

pub use record::{merge_carrier_probe, record_observation};
use visa_regular_file_observation::{RegularFileCase, RouteMode};

pub const WANCO_REVISION: &str = "3c2e400dda5ce51d78333223f6fcbde08e6b198a";
const READ_WRITE_WORKLOAD: &[u8] = include_bytes!("../guest/regular_file_workload.wat");
const APPEND_WORKLOAD: &[u8] = include_bytes!("../guest/append_continuity_workload.wat");

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CarrierProbeCase {
    ReadWriteOffset,
    AppendContinuity,
}

impl CarrierProbeCase {
    pub fn parse(value: &str) -> Result<Self, String> {
        match value {
            "read-write-offset" => Ok(Self::ReadWriteOffset),
            "append-continuity" => Ok(Self::AppendContinuity),
            other => Err(format!("unknown carrier probe case {other:?}")),
        }
    }

    pub(crate) const fn wire(self) -> RegularFileCase {
        match self {
            Self::ReadWriteOffset => RegularFileCase::ReadWriteOffset,
            Self::AppendContinuity => RegularFileCase::AppendContinuity,
        }
    }

    pub(crate) const fn name(self) -> &'static str {
        match self {
            Self::ReadWriteOffset => "read-write-offset",
            Self::AppendContinuity => "append-continuity",
        }
    }

    pub(crate) const fn workload(self) -> &'static [u8] {
        match self {
            Self::ReadWriteOffset => READ_WRITE_WORKLOAD,
            Self::AppendContinuity => APPEND_WORKLOAD,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CarrierRoute {
    Uninterrupted,
    CarrierOnly,
    VisaPlusCarrier,
}

impl CarrierRoute {
    pub fn parse(value: &str) -> Result<Self, String> {
        match value {
            "uninterrupted" => Ok(Self::Uninterrupted),
            "carrier-only" => Ok(Self::CarrierOnly),
            "visa-plus-carrier" => Ok(Self::VisaPlusCarrier),
            other => Err(format!(
                "unknown canonical Wanco route {other:?}; expected uninterrupted, carrier-only, or visa-plus-carrier"
            )),
        }
    }

    pub const fn wire_mode(self) -> RouteMode {
        match self {
            Self::Uninterrupted => RouteMode::UninterruptedControl,
            Self::CarrierOnly => RouteMode::CarrierOnly,
            Self::VisaPlusCarrier => RouteMode::VisaPlusCarrier,
        }
    }

    pub const fn needs_checkpoint(self) -> bool {
        matches!(self, Self::CarrierOnly | Self::VisaPlusCarrier)
    }

    pub const fn needs_destination_receipt(self) -> bool {
        matches!(self, Self::VisaPlusCarrier)
    }

    pub const fn has_destination(self) -> bool {
        !matches!(self, Self::Uninterrupted)
    }

    pub const fn name(self) -> &'static str {
        match self {
            Self::Uninterrupted => "uninterrupted",
            Self::CarrierOnly => "carrier-only",
            Self::VisaPlusCarrier => "visa-plus-carrier",
        }
    }
}

#[derive(Debug)]
pub struct RecordInput<'a> {
    pub case: CarrierProbeCase,
    pub route: CarrierRoute,
    pub artifact_root: &'a Path,
    pub source_events: &'a Path,
    pub destination_events: Option<&'a Path>,
    pub source_stdout: &'a Path,
    pub destination_stdout: Option<&'a Path>,
    pub source_status: &'a Path,
    pub destination_status: Option<&'a Path>,
    pub source_receipt: &'a Path,
    pub destination_receipt: Option<&'a Path>,
    pub subject_file: &'a Path,
    pub checkpoint: Option<&'a Path>,
    pub output: &'a Path,
}
