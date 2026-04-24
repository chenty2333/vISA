use super::contract::ArtifactFormat;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ExecutorInstanceHandle {
    pub(crate) id: u64,
    pub(crate) generation: u64,
}

impl ExecutorInstanceHandle {
    pub(crate) const fn planned(id: u64) -> Self {
        Self { id, generation: 1 }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ExecutorStoreState {
    Planned,
    ArtifactVerified,
    CodePublished,
    HostcallsLinked,
    Runnable,
    Draining,
    Dropped,
    Rebound,
    Faulted,
}

impl ExecutorStoreState {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Planned => "planned",
            Self::ArtifactVerified => "artifact-verified",
            Self::CodePublished => "code-published",
            Self::HostcallsLinked => "hostcalls-linked",
            Self::Runnable => "runnable",
            Self::Draining => "draining",
            Self::Dropped => "dropped",
            Self::Rebound => "rebound",
            Self::Faulted => "faulted",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ExecutorTableState {
    Planned,
    NotLinked,
    Bound,
}

impl ExecutorTableState {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Planned => "planned",
            Self::NotLinked => "not-linked",
            Self::Bound => "bound",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ExecutorTrapSurfaceState {
    Planned,
    ContractDeclared,
    Linked,
}

impl ExecutorTrapSurfaceState {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Planned => "planned",
            Self::ContractDeclared => "contract-declared",
            Self::Linked => "linked",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ExecutorMemoryLayout {
    pub(crate) dmw_layout: &'static str,
    pub(crate) max_memory_pages: u32,
    pub(crate) max_table_elements: u32,
    pub(crate) publish_policy: &'static str,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ExecutorHostcallTable {
    pub(crate) abi: &'static str,
    pub(crate) state: ExecutorTableState,
    pub(crate) max_hostcalls_per_activation: u32,
    pub(crate) expected_export_count: usize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ExecutorTrapSurface {
    pub(crate) state: ExecutorTrapSurfaceState,
    pub(crate) guest_trap: &'static str,
    pub(crate) supervisor_trap: &'static str,
    pub(crate) substrate_fault: &'static str,
}

impl ExecutorTrapSurface {
    pub(crate) const fn runtime_only_v1() -> Self {
        Self {
            state: ExecutorTrapSurfaceState::ContractDeclared,
            guest_trap: "guest-trap->frontend-personality",
            supervisor_trap: "supervisor-trap->store-fault-domain",
            substrate_fault: "substrate-fault->machine-fault",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ExecutorTransitionError {
    InvalidStoreTransition {
        from: ExecutorStoreState,
        to: ExecutorStoreState,
    },
    HostcallTableNotLinked,
    TrapSurfaceNotLinked,
}

impl ExecutorTransitionError {
    pub(crate) const fn message(self) -> &'static str {
        match self {
            Self::InvalidStoreTransition { .. } => "invalid executor store state transition",
            Self::HostcallTableNotLinked => "executor hostcall table is not linked",
            Self::TrapSurfaceNotLinked => "executor trap surface is not linked",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ExecutorTransitionReport {
    pub(crate) from: ExecutorStoreState,
    pub(crate) to: ExecutorStoreState,
    pub(crate) blocked_by: Option<&'static str>,
    pub(crate) hostcall_table: ExecutorTableState,
    pub(crate) trap_surface: ExecutorTrapSurfaceState,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ExecutorRuntimeState {
    pub(crate) store: ExecutorStoreState,
    pub(crate) hostcall_table: ExecutorHostcallTable,
    pub(crate) trap_surface: ExecutorTrapSurface,
    pub(crate) blocked_by: Option<&'static str>,
}

impl ExecutorRuntimeState {
    pub(crate) fn publish_code(
        &mut self,
    ) -> Result<ExecutorTransitionReport, ExecutorTransitionError> {
        self.transition_to(
            ExecutorStoreState::CodePublished,
            Some("hostcall-table-not-linked"),
        )
    }

    pub(crate) fn link_hostcalls(
        &mut self,
    ) -> Result<ExecutorTransitionReport, ExecutorTransitionError> {
        self.transition_to(
            ExecutorStoreState::HostcallsLinked,
            Some("store-entry-not-runnable"),
        )?;
        self.hostcall_table.state = ExecutorTableState::Bound;
        self.trap_surface.state = ExecutorTrapSurfaceState::Linked;
        self.blocked_by = Some("store-entry-not-runnable");
        Ok(self.report(ExecutorStoreState::CodePublished))
    }

    pub(crate) fn mark_runnable(
        &mut self,
    ) -> Result<ExecutorTransitionReport, ExecutorTransitionError> {
        if self.hostcall_table.state != ExecutorTableState::Bound {
            return Err(ExecutorTransitionError::HostcallTableNotLinked);
        }
        if self.trap_surface.state != ExecutorTrapSurfaceState::Linked {
            return Err(ExecutorTransitionError::TrapSurfaceNotLinked);
        }
        self.transition_to(ExecutorStoreState::Runnable, None)
    }

    pub(crate) fn begin_draining(
        &mut self,
    ) -> Result<ExecutorTransitionReport, ExecutorTransitionError> {
        self.transition_to(ExecutorStoreState::Draining, Some("store-draining"))
    }

    pub(crate) fn mark_dropped(
        &mut self,
    ) -> Result<ExecutorTransitionReport, ExecutorTransitionError> {
        self.transition_to(ExecutorStoreState::Dropped, None)
    }

    pub(crate) fn mark_rebound(
        &mut self,
    ) -> Result<ExecutorTransitionReport, ExecutorTransitionError> {
        self.hostcall_table.state = ExecutorTableState::NotLinked;
        self.trap_surface.state = ExecutorTrapSurfaceState::ContractDeclared;
        self.transition_to(ExecutorStoreState::Rebound, Some("code-publish-not-linked"))
    }

    pub(crate) fn mark_faulted(
        &mut self,
    ) -> Result<ExecutorTransitionReport, ExecutorTransitionError> {
        self.transition_to(ExecutorStoreState::Faulted, None)
    }

    fn transition_to(
        &mut self,
        to: ExecutorStoreState,
        blocked_by: Option<&'static str>,
    ) -> Result<ExecutorTransitionReport, ExecutorTransitionError> {
        let from = self.store;
        if !valid_store_transition(from, to) {
            return Err(ExecutorTransitionError::InvalidStoreTransition { from, to });
        }
        self.store = to;
        self.blocked_by = blocked_by;
        Ok(self.report(from))
    }

    const fn report(&self, from: ExecutorStoreState) -> ExecutorTransitionReport {
        ExecutorTransitionReport {
            from,
            to: self.store,
            blocked_by: self.blocked_by,
            hostcall_table: self.hostcall_table.state,
            trap_surface: self.trap_surface.state,
        }
    }
}

const fn valid_store_transition(from: ExecutorStoreState, to: ExecutorStoreState) -> bool {
    use ExecutorStoreState as State;
    matches!(
        (from, to),
        (State::Planned, State::ArtifactVerified)
            | (State::ArtifactVerified, State::CodePublished)
            | (State::ArtifactVerified, State::Draining)
            | (State::CodePublished, State::HostcallsLinked)
            | (State::CodePublished, State::Draining)
            | (State::HostcallsLinked, State::Runnable)
            | (State::HostcallsLinked, State::Draining)
            | (State::Runnable, State::Draining)
            | (State::Draining, State::Dropped)
            | (State::Draining, State::Faulted)
            | (State::Dropped, State::Rebound)
            | (State::Dropped, State::Faulted)
            | (State::Rebound, State::ArtifactVerified)
            | (State::Rebound, State::Draining)
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use supervisor_catalog::RUNTIME_ONLY_EXECUTOR_ABI;

    fn runtime_state(state: ExecutorStoreState) -> ExecutorRuntimeState {
        ExecutorRuntimeState {
            store: state,
            hostcall_table: ExecutorHostcallTable {
                abi: RUNTIME_ONLY_EXECUTOR_ABI,
                state: ExecutorTableState::NotLinked,
                max_hostcalls_per_activation: 64,
                expected_export_count: 4,
            },
            trap_surface: ExecutorTrapSurface::runtime_only_v1(),
            blocked_by: Some("code-publish-not-linked"),
        }
    }

    #[test]
    fn executor_runtime_requires_publish_and_hostcall_link_before_runnable() {
        let mut runtime = runtime_state(ExecutorStoreState::ArtifactVerified);

        assert_eq!(
            runtime.mark_runnable(),
            Err(ExecutorTransitionError::HostcallTableNotLinked)
        );
        let published = runtime.publish_code().expect("code publish transition");
        assert_eq!(published.from, ExecutorStoreState::ArtifactVerified);
        assert_eq!(published.to, ExecutorStoreState::CodePublished);
        assert_eq!(published.blocked_by, Some("hostcall-table-not-linked"));
        assert_eq!(published.hostcall_table, ExecutorTableState::NotLinked);

        let linked = runtime
            .link_hostcalls()
            .expect("hostcall table link transition");
        assert_eq!(linked.from, ExecutorStoreState::CodePublished);
        assert_eq!(linked.to, ExecutorStoreState::HostcallsLinked);
        assert_eq!(linked.hostcall_table, ExecutorTableState::Bound);
        assert_eq!(linked.trap_surface, ExecutorTrapSurfaceState::Linked);

        let runnable = runtime.mark_runnable().expect("runnable transition");
        assert_eq!(runnable.from, ExecutorStoreState::HostcallsLinked);
        assert_eq!(runnable.to, ExecutorStoreState::Runnable);
        assert_eq!(runnable.blocked_by, None);
    }

    #[test]
    fn executor_recovery_cycle_resets_linked_surfaces() {
        let mut runtime = runtime_state(ExecutorStoreState::ArtifactVerified);

        assert_eq!(
            runtime.begin_draining().expect("draining").to,
            ExecutorStoreState::Draining
        );
        assert_eq!(
            runtime.mark_dropped().expect("dropped").to,
            ExecutorStoreState::Dropped
        );
        let rebound = runtime.mark_rebound().expect("rebound");
        assert_eq!(rebound.from, ExecutorStoreState::Dropped);
        assert_eq!(rebound.to, ExecutorStoreState::Rebound);
        assert_eq!(runtime.hostcall_table.state, ExecutorTableState::NotLinked);
        assert_eq!(
            runtime.trap_surface.state,
            ExecutorTrapSurfaceState::ContractDeclared
        );
        assert_eq!(runtime.blocked_by, Some("code-publish-not-linked"));
        assert_eq!(
            runtime.mark_dropped(),
            Err(ExecutorTransitionError::InvalidStoreTransition {
                from: ExecutorStoreState::Rebound,
                to: ExecutorStoreState::Dropped,
            })
        );
    }
}
