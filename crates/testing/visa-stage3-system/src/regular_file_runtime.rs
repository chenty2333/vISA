use serde::{Deserialize, Serialize};
use substrate_host::SqliteProvider;
use visa_component_adapter::{
    PortableRegularFileState, RegularFileAdapterError, RegularFileCallResult, RuntimeIdentity,
};
use visa_profile::RegularFileOperation;
use visa_runtime::Coordinator;
use visa_wacogo::WacogoRegularFileAdapter;
use visa_wasmtime::RegularFileAdapter;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RegularFileRuntimeKind {
    Wasmtime,
    SourceLockedWacogo,
}

impl RegularFileRuntimeKind {
    pub const fn matrix_name(self) -> &'static str {
        match self {
            Self::Wasmtime => "wasmtime",
            Self::SourceLockedWacogo => "source-locked-wacogo",
        }
    }

    pub const fn implementation(self) -> &'static str {
        match self {
            Self::Wasmtime => "visa_wasmtime_stage3a",
            Self::SourceLockedWacogo => "visa_wacogo",
        }
    }

    const fn cell_name(self) -> &'static str {
        match self {
            Self::Wasmtime => "wasmtime",
            Self::SourceLockedWacogo => "wacogo",
        }
    }

    pub fn runtime_identity(self) -> RuntimeIdentity {
        match self {
            Self::Wasmtime => RegularFileAdapter::<SqliteProvider>::runtime_identity_static(),
            Self::SourceLockedWacogo => {
                WacogoRegularFileAdapter::<SqliteProvider>::runtime_identity_static()
            }
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RegularFileRuntimePair {
    pub source: RegularFileRuntimeKind,
    pub destination: RegularFileRuntimeKind,
}

impl RegularFileRuntimePair {
    pub const WASMTIME_BASELINE: Self = Self {
        source: RegularFileRuntimeKind::Wasmtime,
        destination: RegularFileRuntimeKind::Wasmtime,
    };

    pub const FOUR_DIRECTIONS: [Self; 4] = [
        Self {
            source: RegularFileRuntimeKind::SourceLockedWacogo,
            destination: RegularFileRuntimeKind::SourceLockedWacogo,
        },
        Self {
            source: RegularFileRuntimeKind::SourceLockedWacogo,
            destination: RegularFileRuntimeKind::Wasmtime,
        },
        Self {
            source: RegularFileRuntimeKind::Wasmtime,
            destination: RegularFileRuntimeKind::SourceLockedWacogo,
        },
        Self::WASMTIME_BASELINE,
    ];

    pub fn cell_id(self) -> String {
        format!(
            "s3a.cross.{}-to-{}.regular-file",
            self.source.cell_name(),
            self.destination.cell_name()
        )
    }

    pub fn artifact_directory(self) -> String {
        format!("{}-to-{}", self.source.cell_name(), self.destination.cell_name())
    }

    pub const fn handoff_topology(self) -> &'static str {
        match (self.source, self.destination) {
            (RegularFileRuntimeKind::Wasmtime, RegularFileRuntimeKind::Wasmtime) => {
                "in-process-distinct-stores"
            }
            (
                RegularFileRuntimeKind::SourceLockedWacogo,
                RegularFileRuntimeKind::SourceLockedWacogo,
            ) => "runner-with-dual-sidecars",
            (RegularFileRuntimeKind::SourceLockedWacogo, RegularFileRuntimeKind::Wasmtime) => {
                "runner-with-source-sidecar"
            }
            (RegularFileRuntimeKind::Wasmtime, RegularFileRuntimeKind::SourceLockedWacogo) => {
                "runner-with-destination-sidecar"
            }
        }
    }

    pub const fn execution_boundary(self) -> &'static str {
        match (self.source, self.destination) {
            (RegularFileRuntimeKind::Wasmtime, RegularFileRuntimeKind::Wasmtime) => {
                "same-process-distinct-wasmtime-store-and-provider-instance"
            }
            (
                RegularFileRuntimeKind::SourceLockedWacogo,
                RegularFileRuntimeKind::SourceLockedWacogo,
            ) => {
                "runner-with-distinct-source-and-destination-wacogo-sidecars-and-provider-instances"
            }
            (RegularFileRuntimeKind::SourceLockedWacogo, RegularFileRuntimeKind::Wasmtime) => {
                "runner-with-source-wacogo-sidecar-and-destination-wasmtime-store"
            }
            (RegularFileRuntimeKind::Wasmtime, RegularFileRuntimeKind::SourceLockedWacogo) => {
                "runner-with-source-wasmtime-store-and-destination-wacogo-sidecar"
            }
        }
    }
}

pub enum MatrixRegularFileAdapter {
    Wasmtime(Box<RegularFileAdapter<SqliteProvider>>),
    Wacogo(Box<WacogoRegularFileAdapter<SqliteProvider>>),
}

impl MatrixRegularFileAdapter {
    pub fn instantiate(
        kind: RegularFileRuntimeKind,
        component_bytes: &[u8],
        coordinator: Coordinator<SqliteProvider>,
    ) -> Result<Self, RegularFileAdapterError> {
        match kind {
            RegularFileRuntimeKind::Wasmtime => {
                RegularFileAdapter::instantiate(component_bytes, coordinator)
                    .map(Box::new)
                    .map(Self::Wasmtime)
            }
            RegularFileRuntimeKind::SourceLockedWacogo => {
                WacogoRegularFileAdapter::instantiate(component_bytes, coordinator)
                    .map(Box::new)
                    .map(Self::Wacogo)
            }
        }
    }

    pub fn runtime_identity(&self) -> RuntimeIdentity {
        match self {
            Self::Wasmtime(adapter) => adapter.runtime_identity(),
            Self::Wacogo(adapter) => adapter.runtime_identity(),
        }
    }

    pub fn coordinator(&self) -> &Coordinator<SqliteProvider> {
        match self {
            Self::Wasmtime(adapter) => adapter.coordinator(),
            Self::Wacogo(adapter) => adapter.coordinator(),
        }
    }

    pub fn coordinator_mut(&mut self) -> &mut Coordinator<SqliteProvider> {
        match self {
            Self::Wasmtime(adapter) => adapter.coordinator_mut(),
            Self::Wacogo(adapter) => adapter.coordinator_mut(),
        }
    }

    pub fn activate(&mut self, session_id: String) -> Result<(), RegularFileAdapterError> {
        match self {
            Self::Wasmtime(adapter) => adapter.activate(session_id),
            Self::Wacogo(adapter) => adapter.activate(session_id),
        }
    }

    pub fn execute(
        &mut self,
        operation: RegularFileOperation,
        idempotency_key: Option<&str>,
    ) -> Result<RegularFileCallResult, RegularFileAdapterError> {
        match self {
            Self::Wasmtime(adapter) => adapter.execute(operation, idempotency_key),
            Self::Wacogo(adapter) => adapter.execute(operation, idempotency_key),
        }
    }

    pub fn freeze(&mut self) -> Result<PortableRegularFileState, RegularFileAdapterError> {
        match self {
            Self::Wasmtime(adapter) => adapter.freeze(),
            Self::Wacogo(adapter) => adapter.freeze(),
        }
    }

    pub fn thaw(
        &mut self,
        state: &PortableRegularFileState,
    ) -> Result<(), RegularFileAdapterError> {
        match self {
            Self::Wasmtime(adapter) => adapter.thaw(state),
            Self::Wacogo(adapter) => adapter.thaw(state),
        }
    }

    pub fn restore(
        &mut self,
        state: &PortableRegularFileState,
    ) -> Result<(), RegularFileAdapterError> {
        match self {
            Self::Wasmtime(adapter) => adapter.restore(state),
            Self::Wacogo(adapter) => adapter.restore(state),
        }
    }

    pub fn shutdown(&mut self) -> Result<(), RegularFileAdapterError> {
        match self {
            Self::Wasmtime(_) => Ok(()),
            Self::Wacogo(adapter) => adapter.shutdown(),
        }
    }
}
