use visa_core::{ContinuationId, LineageId, LineagePoint, OperationId};

use crate::WorkflowRecord;

/// Durable storage must compare the full expected record and lineage head in
/// the same transaction that writes a committed successor.
pub trait RecordStore {
    type Error;

    fn create(&mut self, record: WorkflowRecord, lineage: LineageCreate)
    -> Result<(), Self::Error>;
    fn load(&self, continuation: &ContinuationId) -> Result<Option<WorkflowRecord>, Self::Error>;
    fn cas(
        &mut self,
        expected: &WorkflowRecord,
        next: WorkflowRecord,
        lineage: Option<LineageUpdate>,
    ) -> Result<(), Self::Error>;
    fn unfinished(&self) -> Result<alloc::vec::Vec<ContinuationId>, Self::Error>;
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LineageCreate {
    pub parent: LineagePoint,
    pub active_continuation: ContinuationId,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LineageUpdate {
    pub lineage: LineageId,
    pub expected_head: LineagePoint,
    pub successor: LineagePoint,
    pub expected_active: ContinuationId,
    pub next_active: Option<ContinuationId>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RecoveryReference {
    pub continuation: ContinuationId,
    pub operation: OperationId,
}
