#![no_std]

extern crate alloc;
#[cfg(test)]
extern crate std;

use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

pub type TaskId = u32;
pub type ResourceId = u64;
pub type CapabilityId = u64;
pub type FaultDomainId = u64;
pub type EventId = u64;
pub type WaitId = u64;
pub type Generation = u64;
pub type SnapshotBarrierId = u64;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FrontendKind {
    Supervisor,
    LinuxElf,
    WasmApp,
    FutureRuntime,
}

impl FrontendKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Supervisor => "supervisor",
            Self::LinuxElf => "linux-elf",
            Self::WasmApp => "wasm-app",
            Self::FutureRuntime => "future-runtime",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TaskState {
    Runnable,
    Running,
    Pending,
    Cancelled,
    Faulted,
    Exited,
    SnapshotFrozen,
}

impl TaskState {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Runnable => "runnable",
            Self::Running => "running",
            Self::Pending => "pending",
            Self::Cancelled => "cancelled",
            Self::Faulted => "faulted",
            Self::Exited => "exited",
            Self::SnapshotFrozen => "snapshot-frozen",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ResourceKind {
    Fd,
    Timer,
    Futex,
    Epoll,
    Device,
    GuestMemory,
    WindowLease,
    ServiceStore,
}

impl ResourceKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Fd => "fd",
            Self::Timer => "timer",
            Self::Futex => "futex",
            Self::Epoll => "epoll",
            Self::Device => "device",
            Self::GuestMemory => "guest-memory",
            Self::WindowLease => "window-lease",
            Self::ServiceStore => "service-store",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SemanticWaitKind {
    Timer,
    Futex,
    Epoll,
    FdReadable,
    FdWritable,
    DriverCompletion,
    Signal,
    ChildExit,
}

impl SemanticWaitKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Timer => "timer",
            Self::Futex => "futex",
            Self::Epoll => "epoll",
            Self::FdReadable => "fd-readable",
            Self::FdWritable => "fd-writable",
            Self::DriverCompletion => "driver-completion",
            Self::Signal => "signal",
            Self::ChildExit => "child-exit",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WaitState {
    Pending,
    Ready,
    Cancelled,
    Restarted,
}

impl WaitState {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Ready => "ready",
            Self::Cancelled => "cancelled",
            Self::Restarted => "restarted",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FaultDomainState {
    Created,
    Initializing,
    Running,
    Degraded,
    Draining,
    Restarting,
    Dead,
}

impl FaultDomainState {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Created => "created",
            Self::Initializing => "initializing",
            Self::Running => "running",
            Self::Degraded => "degraded",
            Self::Draining => "draining",
            Self::Restarting => "restarting",
            Self::Dead => "dead",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CanonicalGuestIsa {
    Riscv64,
    Wasm32,
    None,
}

impl CanonicalGuestIsa {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Riscv64 => "riscv64",
            Self::Wasm32 => "wasm32",
            Self::None => "none",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OperationSet {
    operations: Vec<String>,
}

impl OperationSet {
    pub fn from_static(operations: &[&str]) -> Self {
        Self {
            operations: operations.iter().map(|op| (*op).to_string()).collect(),
        }
    }

    pub fn contains_all(&self, requested: &[&str]) -> bool {
        requested
            .iter()
            .all(|requested| self.operations.iter().any(|op| op == requested))
    }

    pub fn contains(&self, requested: &str) -> bool {
        self.operations.iter().any(|op| op == requested)
    }

    pub fn as_slice(&self) -> &[String] {
        &self.operations
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CapabilityRecord {
    pub id: CapabilityId,
    pub subject: String,
    pub object: String,
    pub operations: OperationSet,
    pub lifetime: String,
    pub generation: Generation,
    pub revoked: bool,
}

#[derive(Clone, Debug)]
pub struct CapabilityLedger {
    next_id: CapabilityId,
    records: Vec<CapabilityRecord>,
}

impl CapabilityLedger {
    pub const fn new() -> Self {
        Self {
            next_id: 1,
            records: Vec::new(),
        }
    }

    pub fn grant(
        &mut self,
        subject: &str,
        object: &str,
        operations: &[&str],
        lifetime: &str,
    ) -> CapabilityId {
        if let Some(record) = self
            .records
            .iter_mut()
            .find(|record| record.subject == subject && record.object == object)
        {
            record.operations = OperationSet::from_static(operations);
            record.lifetime = lifetime.to_string();
            record.generation += 1;
            record.revoked = false;
            return record.id;
        }

        let id = self.next_id;
        self.next_id += 1;
        self.records.push(CapabilityRecord {
            id,
            subject: subject.to_string(),
            object: object.to_string(),
            operations: OperationSet::from_static(operations),
            lifetime: lifetime.to_string(),
            generation: 1,
            revoked: false,
        });
        id
    }

    pub fn delegate(
        &mut self,
        parent_id: CapabilityId,
        subject: &str,
        lifetime: &str,
    ) -> Option<CapabilityId> {
        let parent = self.active(parent_id)?.clone();
        let operations = parent
            .operations
            .as_slice()
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>();
        Some(self.grant(subject, &parent.object, &operations, lifetime))
    }

    pub fn attenuate(
        &mut self,
        parent_id: CapabilityId,
        subject: &str,
        operations: &[&str],
        lifetime: &str,
    ) -> Option<CapabilityId> {
        let parent = self.active(parent_id)?.clone();
        if !parent.operations.contains_all(operations) {
            return None;
        }
        Some(self.grant(subject, &parent.object, operations, lifetime))
    }

    pub fn revoke(&mut self, id: CapabilityId) -> bool {
        let Some(record) = self.records.iter_mut().find(|record| record.id == id) else {
            return false;
        };
        record.revoked = true;
        record.generation += 1;
        true
    }

    pub fn revoke_by_subject_object(
        &mut self,
        subject: &str,
        object: &str,
    ) -> Option<CapabilityId> {
        let record = self
            .records
            .iter_mut()
            .find(|record| record.subject == subject && record.object == object)?;
        record.revoked = true;
        record.generation += 1;
        Some(record.id)
    }

    pub fn revoke_subject(&mut self, subject: &str) -> usize {
        let mut revoked = 0;
        for record in &mut self.records {
            if record.subject == subject && !record.revoked {
                record.revoked = true;
                record.generation += 1;
                revoked += 1;
            }
        }
        revoked
    }

    pub fn active(&self, id: CapabilityId) -> Option<&CapabilityRecord> {
        self.records
            .iter()
            .find(|record| record.id == id && !record.revoked)
    }

    pub fn check(
        &self,
        subject: &str,
        object: &str,
        operation: &str,
    ) -> Result<&CapabilityRecord, CapabilityDenyReason> {
        let Some(record) = self
            .records
            .iter()
            .find(|record| record.subject == subject && record.object == object)
        else {
            return Err(CapabilityDenyReason::Missing);
        };
        if record.revoked {
            return Err(CapabilityDenyReason::Revoked);
        }
        if !record.operations.contains(operation) {
            return Err(CapabilityDenyReason::OperationDenied);
        }
        Ok(record)
    }

    pub fn generation_of(&self, subject: &str, object: &str) -> Option<Generation> {
        self.records
            .iter()
            .find(|record| record.subject == subject && record.object == object)
            .map(|record| record.generation)
    }

    pub fn records(&self) -> &[CapabilityRecord] {
        &self.records
    }

    pub fn active_count(&self) -> usize {
        self.records.iter().filter(|record| !record.revoked).count()
    }
}

impl Default for CapabilityLedger {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CapabilityDenyReason {
    Missing,
    Revoked,
    OperationDenied,
    GenerationMismatch,
}

impl CapabilityDenyReason {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Missing => "missing",
            Self::Revoked => "revoked",
            Self::OperationDenied => "operation-denied",
            Self::GenerationMismatch => "generation-mismatch",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HostcallClass {
    PureQuery,
    ImmediatePrivilegedOp,
    AsyncOp,
}

impl HostcallClass {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::PureQuery => "pure-query",
            Self::ImmediatePrivilegedOp => "immediate-privileged-op",
            Self::AsyncOp => "async-op",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TaskRecord {
    pub id: TaskId,
    pub label: String,
    pub frontend: FrontendKind,
    pub state: TaskState,
    pub fault_domain: Option<FaultDomainId>,
    pub pending_wait: Option<WaitId>,
    pub generation: Generation,
    pub resources: Vec<ResourceId>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResourceRecord {
    pub id: ResourceId,
    pub label: String,
    pub kind: ResourceKind,
    pub owner_task: Option<TaskId>,
    pub generation: Generation,
    pub live: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WaitRecord {
    pub id: WaitId,
    pub owner_task: TaskId,
    pub kind: SemanticWaitKind,
    pub generation: Generation,
    pub state: WaitState,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FaultDomainRecord {
    pub id: FaultDomainId,
    pub name: String,
    pub role: String,
    pub state: FaultDomainState,
    pub generation: Generation,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FailureEffect {
    CompleteWithErrno(i32),
    RetryTransparent,
    RestartSyscall { wait: Option<WaitId> },
    CancelWaitToken { wait: WaitId, errno: i32 },
    MarkResourceDead(ResourceId),
    KillTask(TaskId),
    RebootFaultDomain(FaultDomainId),
}

impl FailureEffect {
    pub fn summary(self) -> String {
        match self {
            Self::CompleteWithErrno(errno) => format!("complete-with-errno({errno})"),
            Self::RetryTransparent => "retry-transparent".to_string(),
            Self::RestartSyscall { wait: Some(wait) } => format!("restart-syscall(wait={wait})"),
            Self::RestartSyscall { wait: None } => "restart-syscall".to_string(),
            Self::CancelWaitToken { wait, errno } => {
                format!("cancel-wait-token(wait={wait}, errno={errno})")
            }
            Self::MarkResourceDead(resource) => format!("mark-resource-dead({resource})"),
            Self::KillTask(task) => format!("kill-task({task})"),
            Self::RebootFaultDomain(domain) => format!("reboot-fault-domain({domain})"),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EventKind {
    TaskCreated {
        task: TaskId,
        frontend: FrontendKind,
    },
    TaskStateChanged {
        task: TaskId,
        from: TaskState,
        to: TaskState,
    },
    ResourceCreated {
        resource: ResourceId,
        kind: ResourceKind,
        generation: Generation,
    },
    ResourceClosed {
        resource: ResourceId,
        generation: Generation,
    },
    WaitCreated {
        wait: WaitId,
        task: TaskId,
        kind: SemanticWaitKind,
        generation: Generation,
    },
    WaitResolved {
        wait: WaitId,
        reason: String,
    },
    WaitCancelled {
        wait: WaitId,
        errno: i32,
    },
    WaitRestarted {
        wait: WaitId,
        class: String,
    },
    CapabilityGranted {
        cap: CapabilityId,
    },
    CapabilityRevoked {
        cap: CapabilityId,
    },
    CapabilityUsed {
        cap: CapabilityId,
        subject: String,
        object: String,
        operation: String,
        generation: Generation,
    },
    CapabilityDenied {
        subject: String,
        object: String,
        operation: String,
        reason: CapabilityDenyReason,
    },
    CapabilityGenerationMismatch {
        subject: String,
        object: String,
        operation: String,
        expected: Generation,
        actual: Option<Generation>,
    },
    HostcallEntered {
        label: String,
        class: HostcallClass,
        subject: String,
        object: String,
        operation: String,
    },
    FaultDomainRegistered {
        domain: FaultDomainId,
    },
    DriverTrap {
        domain: Option<FaultDomainId>,
        trap: String,
    },
    FaultDomainRestarted {
        domain: FaultDomainId,
    },
    WindowLeaseCreated {
        lease: ResourceId,
        generation: Generation,
    },
    WindowLeaseDestroyed {
        lease: ResourceId,
        generation: Generation,
    },
    SnapshotBarrierEnter {
        barrier: u64,
    },
    SnapshotBarrierExit {
        barrier: u64,
    },
    FastPathPlanInstalled {
        plan: u64,
    },
    FastPathPlanInvalidated {
        plan: u64,
    },
    FailureEffect {
        effect: FailureEffect,
    },
}

impl EventKind {
    pub fn summary(&self) -> String {
        match self {
            Self::TaskCreated { task, frontend } => {
                format!("TaskCreated task={task} frontend={}", frontend.as_str())
            }
            Self::TaskStateChanged { task, from, to } => {
                format!(
                    "TaskStateChanged task={task} {}->{}",
                    from.as_str(),
                    to.as_str()
                )
            }
            Self::ResourceCreated {
                resource,
                kind,
                generation,
            } => format!(
                "ResourceCreated resource={resource} kind={} generation={generation}",
                kind.as_str()
            ),
            Self::ResourceClosed {
                resource,
                generation,
            } => format!("ResourceClosed resource={resource} generation={generation}"),
            Self::WaitCreated {
                wait,
                task,
                kind,
                generation,
            } => format!(
                "WaitCreated wait={wait} task={task} kind={} generation={generation}",
                kind.as_str()
            ),
            Self::WaitResolved { wait, reason } => {
                format!("WaitResolved wait={wait} reason={reason}")
            }
            Self::WaitCancelled { wait, errno } => {
                format!("WaitCancelled wait={wait} errno={errno}")
            }
            Self::WaitRestarted { wait, class } => {
                format!("WaitRestarted wait={wait} class={class}")
            }
            Self::CapabilityGranted { cap } => format!("CapabilityGranted cap={cap}"),
            Self::CapabilityRevoked { cap } => format!("CapabilityRevoked cap={cap}"),
            Self::CapabilityUsed {
                cap,
                subject,
                object,
                operation,
                generation,
            } => format!(
                "CapabilityUsed cap={cap} subject={subject} object={object} op={operation} generation={generation}"
            ),
            Self::CapabilityDenied {
                subject,
                object,
                operation,
                reason,
            } => format!(
                "CapabilityDenied subject={subject} object={object} op={operation} reason={}",
                reason.as_str()
            ),
            Self::CapabilityGenerationMismatch {
                subject,
                object,
                operation,
                expected,
                actual,
            } => match actual {
                Some(actual) => format!(
                    "CapabilityGenerationMismatch subject={subject} object={object} op={operation} expected={expected} actual={actual}"
                ),
                None => format!(
                    "CapabilityGenerationMismatch subject={subject} object={object} op={operation} expected={expected} actual=missing"
                ),
            },
            Self::HostcallEntered {
                label,
                class,
                subject,
                object,
                operation,
            } => format!(
                "HostcallEntered label={label} class={} subject={subject} object={object} op={operation}",
                class.as_str()
            ),
            Self::FaultDomainRegistered { domain } => {
                format!("FaultDomainRegistered domain={domain}")
            }
            Self::DriverTrap { domain, trap } => match domain {
                Some(domain) => format!("DriverTrap domain={domain} trap={trap}"),
                None => format!("DriverTrap trap={trap}"),
            },
            Self::FaultDomainRestarted { domain } => {
                format!("FaultDomainRestarted domain={domain}")
            }
            Self::WindowLeaseCreated { lease, generation } => {
                format!("WindowLeaseCreated lease={lease} generation={generation}")
            }
            Self::WindowLeaseDestroyed { lease, generation } => {
                format!("WindowLeaseDestroyed lease={lease} generation={generation}")
            }
            Self::SnapshotBarrierEnter { barrier } => {
                format!("SnapshotBarrierEnter barrier={barrier}")
            }
            Self::SnapshotBarrierExit { barrier } => {
                format!("SnapshotBarrierExit barrier={barrier}")
            }
            Self::FastPathPlanInstalled { plan } => {
                format!("FastPathPlanInstalled plan={plan}")
            }
            Self::FastPathPlanInvalidated { plan } => {
                format!("FastPathPlanInvalidated plan={plan}")
            }
            Self::FailureEffect { effect } => {
                format!("FailureEffect {}", effect.summary())
            }
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EventRecord {
    pub id: EventId,
    pub epoch: u64,
    pub source: String,
    pub causal_parent: Option<EventId>,
    pub kind: EventKind,
}

impl EventRecord {
    pub fn summary(&self) -> String {
        format!(
            "#{} epoch={} source={} {}",
            self.id,
            self.epoch,
            self.source,
            self.kind.summary()
        )
    }
}

#[derive(Clone, Debug)]
pub struct EventLog {
    next_id: EventId,
    epoch: u64,
    events: Vec<EventRecord>,
}

impl EventLog {
    pub const fn new() -> Self {
        Self {
            next_id: 1,
            epoch: 0,
            events: Vec::new(),
        }
    }

    pub fn push(&mut self, source: &str, kind: EventKind) -> EventId {
        let id = self.next_id;
        self.next_id += 1;
        self.epoch += 1;
        self.events.push(EventRecord {
            id,
            epoch: self.epoch,
            source: source.to_string(),
            causal_parent: None,
            kind,
        });
        id
    }

    pub fn len(&self) -> usize {
        self.events.len()
    }

    pub fn cursor(&self) -> EventId {
        self.next_id.saturating_sub(1)
    }

    pub fn is_empty(&self) -> bool {
        self.events.is_empty()
    }

    pub fn tail(&self, count: usize) -> &[EventRecord] {
        let start = self.events.len().saturating_sub(count);
        &self.events[start..]
    }
}

impl Default for EventLog {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Clone, Debug)]
pub struct SemanticGraph {
    tasks: Vec<TaskRecord>,
    resources: Vec<ResourceRecord>,
    waits: Vec<WaitRecord>,
    fault_domains: Vec<FaultDomainRecord>,
    capabilities: CapabilityLedger,
    event_log: EventLog,
    next_resource_id: ResourceId,
    next_fault_domain_id: FaultDomainId,
}

impl SemanticGraph {
    pub fn new() -> Self {
        Self {
            tasks: Vec::new(),
            resources: Vec::new(),
            waits: Vec::new(),
            fault_domains: Vec::new(),
            capabilities: CapabilityLedger::new(),
            event_log: EventLog::new(),
            next_resource_id: 1,
            next_fault_domain_id: 1,
        }
    }

    pub fn ensure_task(&mut self, id: TaskId, frontend: FrontendKind, label: &str) {
        if let Some(task) = self.tasks.iter_mut().find(|task| task.id == id) {
            task.frontend = frontend;
            task.label = label.to_string();
            return;
        }

        self.tasks.push(TaskRecord {
            id,
            label: label.to_string(),
            frontend,
            state: TaskState::Runnable,
            fault_domain: None,
            pending_wait: None,
            generation: 1,
            resources: Vec::new(),
        });
        self.event_log
            .push("semantic", EventKind::TaskCreated { task: id, frontend });
    }

    pub fn set_task_state(&mut self, id: TaskId, state: TaskState) {
        let Some(task) = self.tasks.iter_mut().find(|task| task.id == id) else {
            return;
        };
        let from = task.state;
        if from == state {
            return;
        }
        task.state = state;
        task.generation += 1;
        if state != TaskState::Pending {
            task.pending_wait = None;
        }
        self.event_log.push(
            "scheduler",
            EventKind::TaskStateChanged {
                task: id,
                from,
                to: state,
            },
        );
    }

    pub fn register_resource(
        &mut self,
        kind: ResourceKind,
        owner_task: Option<TaskId>,
        label: &str,
    ) -> ResourceId {
        let id = self.next_resource_id;
        self.next_resource_id += 1;
        self.resources.push(ResourceRecord {
            id,
            label: label.to_string(),
            kind,
            owner_task,
            generation: 1,
            live: true,
        });
        if let Some(owner_task) = owner_task
            && let Some(task) = self.tasks.iter_mut().find(|task| task.id == owner_task)
        {
            task.resources.push(id);
        }
        self.event_log.push(
            "resource",
            EventKind::ResourceCreated {
                resource: id,
                kind,
                generation: 1,
            },
        );
        id
    }

    pub fn close_resource(&mut self, id: ResourceId) {
        let Some(resource) = self.resources.iter_mut().find(|resource| resource.id == id) else {
            return;
        };
        if !resource.live {
            return;
        }
        resource.live = false;
        resource.generation += 1;
        self.event_log.push(
            "resource",
            EventKind::ResourceClosed {
                resource: id,
                generation: resource.generation,
            },
        );
    }

    pub fn record_window_lease_created(
        &mut self,
        owner_task: Option<TaskId>,
        label: &str,
        generation: Generation,
    ) -> ResourceId {
        let lease = self.register_resource(ResourceKind::WindowLease, owner_task, label);
        self.event_log
            .push("dmw", EventKind::WindowLeaseCreated { lease, generation });
        lease
    }

    pub fn record_window_lease_destroyed(&mut self, lease: ResourceId, generation: Generation) {
        self.close_resource(lease);
        self.event_log
            .push("dmw", EventKind::WindowLeaseDestroyed { lease, generation });
    }

    pub fn register_fault_domain(&mut self, name: &str, role: &str) -> FaultDomainId {
        if let Some(domain) = self.fault_domains.iter().find(|domain| domain.name == name) {
            return domain.id;
        }

        let id = self.next_fault_domain_id;
        self.next_fault_domain_id += 1;
        self.fault_domains.push(FaultDomainRecord {
            id,
            name: name.to_string(),
            role: role.to_string(),
            state: FaultDomainState::Running,
            generation: 1,
        });
        self.event_log.push(
            "fault-domain",
            EventKind::FaultDomainRegistered { domain: id },
        );
        id
    }

    pub fn fault_domain_id(&self, name: &str) -> Option<FaultDomainId> {
        self.fault_domains
            .iter()
            .find(|domain| domain.name == name)
            .map(|domain| domain.id)
    }

    pub fn set_fault_domain_state(&mut self, id: FaultDomainId, state: FaultDomainState) {
        let Some(domain) = self.fault_domains.iter_mut().find(|domain| domain.id == id) else {
            return;
        };
        if domain.state == state {
            return;
        }
        domain.state = state;
        domain.generation += 1;
        if state == FaultDomainState::Running {
            self.event_log.push(
                "fault-domain",
                EventKind::FaultDomainRestarted { domain: id },
            );
        }
    }

    pub fn record_driver_trap(&mut self, domain: Option<FaultDomainId>, trap: &str) {
        self.event_log.push(
            "trap",
            EventKind::DriverTrap {
                domain,
                trap: trap.to_string(),
            },
        );
    }

    pub fn grant_capability(
        &mut self,
        subject: &str,
        object: &str,
        operations: &[&str],
        lifetime: &str,
    ) -> CapabilityId {
        let cap = self
            .capabilities
            .grant(subject, object, operations, lifetime);
        self.event_log
            .push("capability", EventKind::CapabilityGranted { cap });
        cap
    }

    pub fn revoke_capability(&mut self, cap: CapabilityId) -> bool {
        if !self.capabilities.revoke(cap) {
            return false;
        }
        self.event_log
            .push("capability", EventKind::CapabilityRevoked { cap });
        true
    }

    pub fn revoke_capability_by_subject_object(
        &mut self,
        subject: &str,
        object: &str,
    ) -> Option<CapabilityId> {
        let cap = self
            .capabilities
            .revoke_by_subject_object(subject, object)?;
        self.event_log
            .push("capability", EventKind::CapabilityRevoked { cap });
        Some(cap)
    }

    pub fn check_capability(
        &mut self,
        subject: &str,
        object: &str,
        operation: &str,
    ) -> Result<CapabilityId, CapabilityDenyReason> {
        match self.capabilities.check(subject, object, operation) {
            Ok(record) => {
                let cap = record.id;
                let generation = record.generation;
                self.event_log.push(
                    "capability",
                    EventKind::CapabilityUsed {
                        cap,
                        subject: subject.to_string(),
                        object: object.to_string(),
                        operation: operation.to_string(),
                        generation,
                    },
                );
                Ok(cap)
            }
            Err(reason) => {
                self.event_log.push(
                    "capability",
                    EventKind::CapabilityDenied {
                        subject: subject.to_string(),
                        object: object.to_string(),
                        operation: operation.to_string(),
                        reason,
                    },
                );
                Err(reason)
            }
        }
    }

    pub fn check_capability_generation(
        &mut self,
        subject: &str,
        object: &str,
        operation: &str,
        expected_generation: Generation,
    ) -> Result<CapabilityId, CapabilityDenyReason> {
        let actual_generation = self.capabilities.generation_of(subject, object);
        let record = match self.capabilities.check(subject, object, operation) {
            Ok(record) => record,
            Err(reason) => {
                self.event_log.push(
                    "capability",
                    EventKind::CapabilityDenied {
                        subject: subject.to_string(),
                        object: object.to_string(),
                        operation: operation.to_string(),
                        reason,
                    },
                );
                return Err(reason);
            }
        };
        if record.generation != expected_generation {
            self.event_log.push(
                "capability",
                EventKind::CapabilityGenerationMismatch {
                    subject: subject.to_string(),
                    object: object.to_string(),
                    operation: operation.to_string(),
                    expected: expected_generation,
                    actual: actual_generation,
                },
            );
            return Err(CapabilityDenyReason::GenerationMismatch);
        }
        let cap = record.id;
        let generation = record.generation;
        self.event_log.push(
            "capability",
            EventKind::CapabilityUsed {
                cap,
                subject: subject.to_string(),
                object: object.to_string(),
                operation: operation.to_string(),
                generation,
            },
        );
        Ok(cap)
    }

    pub fn capability_generation(&self, subject: &str, object: &str) -> Option<Generation> {
        self.capabilities.generation_of(subject, object)
    }

    pub fn record_hostcall(
        &mut self,
        label: &str,
        class: HostcallClass,
        subject: &str,
        object: &str,
        operation: &str,
    ) {
        self.event_log.push(
            "hostcall",
            EventKind::HostcallEntered {
                label: label.to_string(),
                class,
                subject: subject.to_string(),
                object: object.to_string(),
                operation: operation.to_string(),
            },
        );
    }

    pub fn record_wait_created(
        &mut self,
        wait: WaitId,
        owner_task: TaskId,
        kind: SemanticWaitKind,
        generation: Generation,
    ) {
        if let Some(record) = self.waits.iter_mut().find(|record| record.id == wait) {
            record.state = WaitState::Pending;
            record.generation = generation;
        } else {
            self.waits.push(WaitRecord {
                id: wait,
                owner_task,
                kind,
                generation,
                state: WaitState::Pending,
            });
        }
        if let Some(task) = self.tasks.iter_mut().find(|task| task.id == owner_task) {
            task.pending_wait = Some(wait);
        }
        self.set_task_state(owner_task, TaskState::Pending);
        self.event_log.push(
            "wait",
            EventKind::WaitCreated {
                wait,
                task: owner_task,
                kind,
                generation,
            },
        );
    }

    pub fn record_wait_resolved(&mut self, wait: WaitId, reason: &str) {
        if let Some(record) = self.waits.iter_mut().find(|record| record.id == wait) {
            record.state = WaitState::Ready;
        }
        self.event_log.push(
            "wait",
            EventKind::WaitResolved {
                wait,
                reason: reason.to_string(),
            },
        );
    }

    pub fn record_wait_cancelled(&mut self, wait: WaitId, errno: i32) {
        if let Some(record) = self.waits.iter_mut().find(|record| record.id == wait) {
            record.state = WaitState::Cancelled;
        }
        self.event_log
            .push("wait", EventKind::WaitCancelled { wait, errno });
    }

    pub fn record_wait_restarted(&mut self, wait: WaitId, class: &str) {
        if let Some(record) = self.waits.iter_mut().find(|record| record.id == wait) {
            record.state = WaitState::Restarted;
        }
        self.event_log.push(
            "wait",
            EventKind::WaitRestarted {
                wait,
                class: class.to_string(),
            },
        );
    }

    pub fn record_failure_effect(&mut self, effect: FailureEffect) {
        self.event_log
            .push("failure", EventKind::FailureEffect { effect });
    }

    pub fn record_snapshot_barrier_enter(&mut self, barrier: SnapshotBarrierId) {
        self.event_log
            .push("snapshot", EventKind::SnapshotBarrierEnter { barrier });
    }

    pub fn record_snapshot_barrier_exit(&mut self, barrier: SnapshotBarrierId) {
        self.event_log
            .push("snapshot", EventKind::SnapshotBarrierExit { barrier });
    }

    pub fn migration_package(
        &self,
        package_id: &str,
        source_host_arch: &str,
        target_host_arch_hint: &str,
        required_artifact_profile: ArtifactProfile,
        guest: GuestStateSnapshot,
        substrate_boundary: SubstrateBoundarySnapshot,
        barrier_id: SnapshotBarrierId,
        dmw_quiescent: bool,
    ) -> MigrationPackage {
        MigrationPackage {
            schema_version: 1,
            package_id: package_id.to_string(),
            source_host_arch: source_host_arch.to_string(),
            target_host_arch_hint: target_host_arch_hint.to_string(),
            required_artifact_profile,
            guest,
            substrate_boundary: substrate_boundary.clone(),
            semantic: SemanticSnapshot {
                barrier: SnapshotBarrierSnapshot {
                    id: barrier_id,
                    event_log_cursor: self.event_log.cursor(),
                    pending_wait_count: self.pending_wait_count(),
                    live_resource_count: self.live_resource_count(),
                    active_dmw_lease_count: substrate_boundary.active_dmw_lease_count,
                    dmw_quiescent,
                },
                tasks: self.tasks.clone(),
                resources: self.resources.clone(),
                waits: self.waits.clone(),
                fault_domains: self.fault_domains.clone(),
                capabilities: self.capabilities.records().to_vec(),
            },
        }
    }

    pub fn task_count(&self) -> usize {
        self.tasks.len()
    }

    pub fn resource_count(&self) -> usize {
        self.resources.len()
    }

    pub fn wait_count(&self) -> usize {
        self.waits.len()
    }

    pub fn fault_domain_count(&self) -> usize {
        self.fault_domains.len()
    }

    pub fn capability_count(&self) -> usize {
        self.capabilities.active_count()
    }

    pub fn event_count(&self) -> usize {
        self.event_log.len()
    }

    pub fn pending_wait_count(&self) -> usize {
        self.waits
            .iter()
            .filter(|wait| wait.state == WaitState::Pending)
            .count()
    }

    pub fn live_resource_count(&self) -> usize {
        self.resources
            .iter()
            .filter(|resource| resource.live)
            .count()
    }

    pub fn capabilities(&self) -> &CapabilityLedger {
        &self.capabilities
    }

    pub fn event_log(&self) -> &EventLog {
        &self.event_log
    }

    pub fn event_log_tail(&self, count: usize) -> &[EventRecord] {
        self.event_log.tail(count)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ArtifactProfile {
    pub artifact_profile: String,
    pub target_arch: String,
    pub machine_abi_version: String,
    pub supervisor_abi_version: String,
    pub wasm_feature_profile: String,
    pub memory64: bool,
    pub multi_memory: bool,
    pub dmw_layout: String,
    pub compiler_engine: String,
    pub compiler_execution_mode: String,
    pub artifact_format: String,
}

impl ArtifactProfile {
    pub fn summary(&self) -> String {
        format!(
            "artifact_profile={} target_arch={} machine_abi={} supervisor_abi={} wasm_profile={} dmw_layout={} engine={} mode={} format={}",
            self.artifact_profile,
            self.target_arch,
            self.machine_abi_version,
            self.supervisor_abi_version,
            self.wasm_feature_profile,
            self.dmw_layout,
            self.compiler_engine,
            self.compiler_execution_mode,
            self.artifact_format
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GuestStateSnapshot {
    pub canonical_isa: CanonicalGuestIsa,
    pub register_count: u32,
    pub memory_page_count: u64,
    pub vma_count: u32,
    pub signal_queue_count: u32,
    pub note: String,
}

impl GuestStateSnapshot {
    pub fn riscv64_placeholder() -> Self {
        Self {
            canonical_isa: CanonicalGuestIsa::Riscv64,
            register_count: 33,
            memory_page_count: 0,
            vma_count: 0,
            signal_queue_count: 0,
            note: "placeholder canonical guest state; real VM state is not implemented in prototype v0"
                .to_string(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SubstrateBoundarySnapshot {
    pub timer_epoch: u64,
    pub pending_irq_causes: u32,
    pub pending_dma_completions: u32,
    pub active_dmw_lease_count: u32,
    pub native_state_policy: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SnapshotBarrierSnapshot {
    pub id: SnapshotBarrierId,
    pub event_log_cursor: EventId,
    pub pending_wait_count: usize,
    pub live_resource_count: usize,
    pub active_dmw_lease_count: u32,
    pub dmw_quiescent: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SemanticSnapshot {
    pub barrier: SnapshotBarrierSnapshot,
    pub tasks: Vec<TaskRecord>,
    pub resources: Vec<ResourceRecord>,
    pub waits: Vec<WaitRecord>,
    pub fault_domains: Vec<FaultDomainRecord>,
    pub capabilities: Vec<CapabilityRecord>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MigrationPackage {
    pub schema_version: u32,
    pub package_id: String,
    pub source_host_arch: String,
    pub target_host_arch_hint: String,
    pub required_artifact_profile: ArtifactProfile,
    pub guest: GuestStateSnapshot,
    pub substrate_boundary: SubstrateBoundarySnapshot,
    pub semantic: SemanticSnapshot,
}

impl MigrationPackage {
    pub fn validate_portability(&self) -> Result<(), MigrationValidationError> {
        if self.schema_version != 1 {
            return Err(MigrationValidationError::UnsupportedSchema);
        }
        if self.semantic.barrier.active_dmw_lease_count != 0 || !self.semantic.barrier.dmw_quiescent
        {
            return Err(MigrationValidationError::ActiveDmwLease);
        }
        if self.substrate_boundary.pending_dma_completions != 0 {
            return Err(MigrationValidationError::InFlightDma);
        }
        if self.guest.canonical_isa != CanonicalGuestIsa::Riscv64 {
            return Err(MigrationValidationError::UnsupportedGuestIsa);
        }
        Ok(())
    }

    pub fn summary_lines(&self) -> Vec<String> {
        let mut lines = Vec::new();
        lines.push(format!(
            "migration package: id={} source_host={} target_hint={} guest_isa={}",
            self.package_id,
            self.source_host_arch,
            self.target_host_arch_hint,
            self.guest.canonical_isa.as_str()
        ));
        lines.push(format!(
            "snapshot barrier: id={} cursor={} pending_waits={} live_resources={} active_dmw_leases={}",
            self.semantic.barrier.id,
            self.semantic.barrier.event_log_cursor,
            self.semantic.barrier.pending_wait_count,
            self.semantic.barrier.live_resource_count,
            self.semantic.barrier.active_dmw_lease_count
        ));
        lines.push(format!(
            "semantic roots: tasks={} resources={} waits={} capabilities={} fault_domains={}",
            self.semantic.tasks.len(),
            self.semantic.resources.len(),
            self.semantic.waits.len(),
            self.semantic.capabilities.len(),
            self.semantic.fault_domains.len()
        ));
        lines.push(format!(
            "required artifacts: {}",
            self.required_artifact_profile.summary()
        ));
        lines.push(
            "not migrated: raw pointers, native stacks, active DMW leases, DMA mappings, MMIO mappings, IRQ registrations, translated code cache"
                .to_string(),
        );
        lines
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MigrationValidationError {
    UnsupportedSchema,
    ActiveDmwLease,
    InFlightDma,
    UnsupportedGuestIsa,
}

impl Default for SemanticGraph {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn capability_attenuation_cannot_expand_rights() {
        let mut ledger = CapabilityLedger::new();
        let parent = ledger.grant("driver", "mmio-bar0", &["read"], "store");

        assert!(
            ledger
                .attenuate(parent, "helper", &["read"], "activation")
                .is_some()
        );
        assert!(
            ledger
                .attenuate(parent, "helper", &["write"], "activation")
                .is_none()
        );
    }

    #[test]
    fn capability_check_records_denial_and_generation_mismatch() {
        let mut graph = SemanticGraph::new();
        let generation = {
            graph.grant_capability("linux_syscall", "timer.sleep", &["arm"], "wait-token");
            graph
                .capability_generation("linux_syscall", "timer.sleep")
                .expect("capability generation")
        };

        assert!(
            graph
                .check_capability("linux_syscall", "timer.sleep", "arm")
                .is_ok()
        );
        graph.revoke_capability_by_subject_object("linux_syscall", "timer.sleep");
        assert_eq!(
            graph.check_capability("linux_syscall", "timer.sleep", "arm"),
            Err(CapabilityDenyReason::Revoked)
        );
        graph.grant_capability("linux_syscall", "timer.sleep", &["arm"], "wait-token");
        assert_eq!(
            graph.check_capability_generation("linux_syscall", "timer.sleep", "arm", generation),
            Err(CapabilityDenyReason::GenerationMismatch)
        );
    }

    #[test]
    fn wait_flow_is_recorded_in_event_log() {
        let mut graph = SemanticGraph::new();
        graph.ensure_task(7, FrontendKind::LinuxElf, "guest");
        graph.set_task_state(7, TaskState::Running);

        graph.record_wait_created(11, 7, SemanticWaitKind::Futex, 1);
        graph.record_wait_resolved(11, "ready");

        assert_eq!(graph.wait_count(), 1);
        assert_eq!(
            graph.event_log_tail(1)[0].kind.summary(),
            "WaitResolved wait=11 reason=ready"
        );
    }

    #[test]
    fn migration_package_rejects_active_dmw_leases() {
        let mut graph = SemanticGraph::new();
        graph.ensure_task(1, FrontendKind::Supervisor, "bootstrap");
        graph.record_snapshot_barrier_enter(1);
        graph.record_snapshot_barrier_exit(1);

        let package = graph.migration_package(
            "test",
            "x86_64",
            "aarch64",
            test_artifact_profile(),
            GuestStateSnapshot::riscv64_placeholder(),
            SubstrateBoundarySnapshot {
                timer_epoch: 0,
                pending_irq_causes: 0,
                pending_dma_completions: 0,
                active_dmw_lease_count: 1,
                native_state_policy: "rebuild".to_string(),
            },
            1,
            false,
        );

        assert_eq!(
            package.validate_portability(),
            Err(MigrationValidationError::ActiveDmwLease)
        );
    }

    fn test_artifact_profile() -> ArtifactProfile {
        ArtifactProfile {
            artifact_profile: "test".to_string(),
            target_arch: "target-native".to_string(),
            machine_abi_version: "machine".to_string(),
            supervisor_abi_version: "supervisor".to_string(),
            wasm_feature_profile: "wasm32".to_string(),
            memory64: false,
            multi_memory: false,
            dmw_layout: "dmw".to_string(),
            compiler_engine: "wasmtime".to_string(),
            compiler_execution_mode: "precompiled-core-module".to_string(),
            artifact_format: "cwasm".to_string(),
        }
    }
}
