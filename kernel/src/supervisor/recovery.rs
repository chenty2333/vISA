use semantic_core::{FailureEffect, StoreId, StoreState, TransactionId};
use vmos_abi::ERR_EIO;

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
        self.require_capability("fault_manager", "fault-domain.procfs_service", "restart")
            .map_err(|_| ServiceCallError::Errno(vmos_abi::ERR_EPERM))?;
        let store = self
            .store_id("procfs_service")
            .ok_or(ServiceCallError::Invalid("procfs store was not registered"))?;
        let fault = self
            .record_service_trap("procfs_service", detail)
            .ok_or(ServiceCallError::Invalid("procfs store was not registered"))?;
        let domain = self.semantic.fault_domain_id("procfs_service");

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
        self.set_store_state(store, StoreState::Running);
        Ok(())
    }

    pub(crate) fn micro_reboot_net_driver(&mut self, detail: &str) -> Result<(), ServiceCallError> {
        self.require_capability("fault_manager", "fault-domain.driver_virtio_net", "restart")
            .map_err(|_| ServiceCallError::Errno(vmos_abi::ERR_EPERM))?;
        let store = self
            .store_id("driver_virtio_net")
            .ok_or(ServiceCallError::Invalid(
                "driver_virtio_net store was not registered",
            ))?;
        let domain = self.semantic.fault_domain_id("driver_virtio_net");
        self.record_store_trap(store, semantic_core::TrapClass::DriverTrap, detail);
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
        self.set_store_state(store, StoreState::Running);
        Ok(())
    }
}
