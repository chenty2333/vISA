use alloc::format;
use alloc::string::{String, ToString};

use super::*;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StoreActivationHandle {
    pub store: StoreId,
    pub generation: Generation,
}

impl StoreActivationHandle {
    pub const fn new(store: StoreId, generation: Generation) -> Self {
        Self { store, generation }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CodePublishState {
    NotPublished,
    Published,
    Dropped,
}

impl CodePublishState {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NotPublished => "not-published",
            Self::Published => "published",
            Self::Dropped => "dropped",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MemoryLayoutState {
    Planned,
    Verified,
    Dropped,
}

impl MemoryLayoutState {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Planned => "planned",
            Self::Verified => "verified",
            Self::Dropped => "dropped",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HostcallLinkState {
    NotLinked,
    Linked,
    Dropped,
}

impl HostcallLinkState {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NotLinked => "not-linked",
            Self::Linked => "linked",
            Self::Dropped => "dropped",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TrapSurfaceState {
    ContractDeclared,
    Linked,
    Dropped,
}

impl TrapSurfaceState {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ContractDeclared => "contract-declared",
            Self::Linked => "linked",
            Self::Dropped => "dropped",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EntrypointState {
    NotRunnable,
    Runnable,
    Dropped,
}

impl EntrypointState {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NotRunnable => "not-runnable",
            Self::Runnable => "runnable",
            Self::Dropped => "dropped",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StoreActivationRecord {
    pub id: StoreActivationId,
    pub store: StoreId,
    pub package: String,
    pub manifest_binding_hash: String,
    pub code_hash: String,
    pub code_publish_state: CodePublishState,
    pub memory_layout_state: MemoryLayoutState,
    pub hostcall_table_state: HostcallLinkState,
    pub trap_surface_state: TrapSurfaceState,
    pub entrypoint_state: EntrypointState,
    pub blocked_by: Option<String>,
    pub generation: Generation,
}

impl StoreActivationRecord {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        id: StoreActivationId,
        store: StoreId,
        package: &str,
        manifest_binding_hash: &str,
        code_hash: &str,
        code_publish_state: CodePublishState,
        memory_layout_state: MemoryLayoutState,
        hostcall_table_state: HostcallLinkState,
        trap_surface_state: TrapSurfaceState,
        entrypoint_state: EntrypointState,
        blocked_by: Option<&str>,
    ) -> Self {
        Self {
            id,
            store,
            package: package.to_string(),
            manifest_binding_hash: manifest_binding_hash.to_string(),
            code_hash: code_hash.to_string(),
            code_publish_state,
            memory_layout_state,
            hostcall_table_state,
            trap_surface_state,
            entrypoint_state,
            blocked_by: blocked_by.map(|value| value.to_string()),
            generation: 1,
        }
    }

    pub fn summary(&self) -> String {
        let blocked_by = self
            .blocked_by
            .as_ref()
            .map(String::as_str)
            .unwrap_or("none");
        format!(
            "store-activation store={} package={} binding={} code_hash={} code={} memory={} hostcalls={} traps={} entry={} blocked={} generation={}",
            self.store,
            self.package,
            self.manifest_binding_hash,
            self.code_hash,
            self.code_publish_state.as_str(),
            self.memory_layout_state.as_str(),
            self.hostcall_table_state.as_str(),
            self.trap_surface_state.as_str(),
            self.entrypoint_state.as_str(),
            blocked_by,
            self.generation
        )
    }
}
