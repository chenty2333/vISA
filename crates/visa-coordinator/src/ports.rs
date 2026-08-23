use visa_core::{
    AbortPreparationReceipt, ActivationPermitReceipt, AuthorityCommitReceipt,
    BindingPreparationReceipt, DestinationRestoreReceipt, RetirementReceipt,
    RuntimeActivationReceipt, RuntimePreparationReceipt, SourceRestorationReceipt,
};

use crate::{Action, CapturedSnapshot, Observation};

/// Runtime operations are all explicit and queryable. Associated preparation
/// state stays in the runtime; only its exact receipt reaches durable storage.
pub trait RuntimePort {
    type Error;

    fn capture(&mut self, action: &Action) -> Observation<CapturedSnapshot, Self::Error>;
    fn query_capture(&mut self, action: &Action) -> Observation<CapturedSnapshot, Self::Error>;
    fn prepare_destination(
        &mut self,
        action: &Action,
    ) -> Observation<RuntimePreparationReceipt, Self::Error>;
    fn query_prepare_destination(
        &mut self,
        action: &Action,
    ) -> Observation<RuntimePreparationReceipt, Self::Error>;
    fn restore_source(
        &mut self,
        action: &Action,
    ) -> Observation<SourceRestorationReceipt, Self::Error>;
    fn query_restore_source(
        &mut self,
        action: &Action,
    ) -> Observation<SourceRestorationReceipt, Self::Error>;
    fn restore_destination(
        &mut self,
        action: &Action,
    ) -> Observation<DestinationRestoreReceipt, Self::Error>;
    fn query_restore_destination(
        &mut self,
        action: &Action,
    ) -> Observation<DestinationRestoreReceipt, Self::Error>;
    fn activate(&mut self, action: &Action) -> Observation<RuntimeActivationReceipt, Self::Error>;
    fn query_activate(
        &mut self,
        action: &Action,
    ) -> Observation<RuntimeActivationReceipt, Self::Error>;
    fn retire(&mut self, action: &Action) -> Observation<RetirementReceipt, Self::Error>;
    fn query_retire(&mut self, action: &Action) -> Observation<RetirementReceipt, Self::Error>;
}

/// This authority alone prepares bindings, fences the source, and discards an
/// uncommitted destination preparation.
pub trait AuthorityPort {
    type Error;

    fn prepare_bindings(
        &mut self,
        action: &Action,
    ) -> Observation<BindingPreparationReceipt, Self::Error>;
    fn query_prepare_bindings(
        &mut self,
        action: &Action,
    ) -> Observation<BindingPreparationReceipt, Self::Error>;
    fn commit_fence(&mut self, action: &Action)
    -> Observation<AuthorityCommitReceipt, Self::Error>;
    fn query_commit_fence(
        &mut self,
        action: &Action,
    ) -> Observation<AuthorityCommitReceipt, Self::Error>;
    fn permit_activation(
        &mut self,
        action: &Action,
    ) -> Observation<ActivationPermitReceipt, Self::Error>;
    fn query_permit_activation(
        &mut self,
        action: &Action,
    ) -> Observation<ActivationPermitReceipt, Self::Error>;
    fn abort_bindings(
        &mut self,
        action: &Action,
    ) -> Observation<AbortPreparationReceipt, Self::Error>;
    fn query_abort_bindings(
        &mut self,
        action: &Action,
    ) -> Observation<AbortPreparationReceipt, Self::Error>;
}
