use semantic_core::{FailureEffect, StoreId, StoreState, TransactionId, TrapClass};
use vmos_abi::ERR_EIO;

use super::fault::classify_service_trap;
use super::runtime::PrototypeRuntime;
use super::services::{DriverVirtioNetService, ProcfsService};
use super::types::ServiceCallError;

impl<'engine> PrototypeRuntime<'engine> {
    pub(crate) fn begin_semantic_transaction(
        &mut self,
        label: &str,
        store: Option<StoreId>,
    ) -> TransactionId {
        self.semantic
            .begin_transaction(label, store, Some(self.scheduler.current_task()))
    }

    pub(crate) fn commit_semantic_transaction(&mut self, transaction: TransactionId) {
        self.semantic.commit_transaction(transaction);
    }

    pub(crate) fn rollback_semantic_transaction(
        &mut self,
        transaction: TransactionId,
        reason: &str,
    ) {
        self.semantic.rollback_transaction(transaction, reason);
    }

    pub(crate) fn execute_failure_effect(&mut self, effect: FailureEffect) {
        match effect {
            FailureEffect::MarkResourceDead(resource) => self.semantic.mark_resource_dead(resource),
            FailureEffect::KillTask(task) => {
                self.semantic
                    .set_task_state(task, semantic_core::TaskState::Faulted);
                self.semantic.record_failure_effect(effect);
            }
            _ => self.semantic.record_failure_effect(effect),
        }
    }

    pub(crate) fn execute_failure_plan(&mut self, effects: &[FailureEffect]) {
        for effect in effects {
            self.execute_failure_effect(*effect);
        }
    }

    pub(crate) fn recover_procfs_store_after_trap(
        &mut self,
        detail: &str,
    ) -> Result<(), ServiceCallError> {
        let fault = classify_service_trap("procfs_service", detail);
        let store = self.begin_store_micro_reboot(
            "procfs_service",
            "fault-domain.procfs_service",
            fault.trap,
            detail,
        )?;
        if !fault.recoverable {
            self.execute_failure_effect(FailureEffect::CompleteWithErrno(fault.errno));
            return Err(ServiceCallError::Errno(fault.errno));
        }

        let _ = self.procfs.take();
        self.drop_store_instance(store);
        self.procfs = Some(ProcfsService::new(self.engine).map_err(|_| {
            self.execute_failure_effect(FailureEffect::CompleteWithErrno(ERR_EIO));
            ServiceCallError::Errno(ERR_EIO)
        })?);
        self.rebind_store_instance(store)
            .map_err(ServiceCallError::Invalid)?;
        self.finish_store_micro_reboot(store);
        Ok(())
    }

    pub(crate) fn micro_reboot_net_driver(&mut self, detail: &str) -> Result<(), ServiceCallError> {
        let store = self.begin_store_micro_reboot(
            "driver_virtio_net",
            "fault-domain.driver_virtio_net",
            TrapClass::DriverTrap,
            detail,
        )?;
        self.drop_store_instance(store);
        self.net_driver = DriverVirtioNetService::new(self.engine).map_err(|_| {
            self.execute_failure_effect(FailureEffect::CompleteWithErrno(ERR_EIO));
            ServiceCallError::Errno(ERR_EIO)
        })?;
        self.rebind_store_instance(store)
            .map_err(ServiceCallError::Invalid)?;
        self.net
            .rebind_driver_authority(&mut self.semantic)
            .map_err(ServiceCallError::Invalid)?;
        self.net_driver
            .reset_sequence(crate::interrupts::tick_count())?;
        self.finish_store_micro_reboot(store);
        Ok(())
    }

    fn begin_store_micro_reboot(
        &mut self,
        package: &str,
        capability_object: &str,
        trap: TrapClass,
        detail: &str,
    ) -> Result<StoreId, ServiceCallError> {
        self.require_capability("fault_manager", capability_object, "restart")
            .map_err(|_| ServiceCallError::Errno(vmos_abi::ERR_EPERM))?;
        let store = self
            .store_id(package)
            .ok_or(ServiceCallError::Invalid("store was not registered"))?;
        let domain = self.semantic.fault_domain_id(package);
        self.record_store_trap(store, trap, detail);
        self.set_store_state(store, StoreState::Draining);
        self.set_store_state(store, StoreState::Restarting);

        if let Some(domain) = domain {
            self.execute_failure_plan(&[
                FailureEffect::RebootFaultDomain(domain),
                FailureEffect::RetryTransparent,
            ]);
        } else {
            self.execute_failure_effect(FailureEffect::RetryTransparent);
        }

        Ok(store)
    }

    fn finish_store_micro_reboot(&mut self, store: StoreId) {
        self.set_store_state(store, StoreState::Running);
    }
}
