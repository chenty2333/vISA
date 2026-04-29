use semantic_core::{StoreDropReport, StoreId, StoreRebindReport, TrapClass};

use super::{
    authority_rebind::{StoreAuthorityRebindRequest, plan_store_authority_rebind},
    fault::{ClassifiedFault, classify_service_trap},
    runtime::PrototypeRuntime,
};

impl<'engine> PrototypeRuntime<'engine> {
    pub(crate) fn store_lifecycle_line(&self, package: &str) -> Option<alloc::string::String> {
        self.store_manager.lifecycle_line(&self.semantic, package)
    }

    pub(crate) fn store_id(&self, package: &str) -> Option<StoreId> {
        self.store_manager.store_id(package).or_else(|| self.semantic.store_id(package))
    }

    pub(crate) fn drop_store_instance(
        &mut self,
        store: StoreId,
    ) -> Result<StoreDropReport, &'static str> {
        self.store_manager.drop_instance(&mut self.semantic, store)
    }

    pub(crate) fn rebind_store_instance(
        &mut self,
        store: StoreId,
    ) -> Result<StoreRebindReport, &'static str> {
        self.store_manager.rebind_instance(&mut self.semantic, store)
    }

    pub(crate) fn rebind_store_authorities(
        &mut self,
        report: StoreRebindReport,
    ) -> Result<(), &'static str> {
        let Some(request) = plan_store_authority_rebind(&self.store_manager, report) else {
            return Ok(());
        };
        match request {
            StoreAuthorityRebindRequest::NetworkDriver { store, package } => {
                self.net.bind_driver_resources(&self.authority, &mut self.semantic, store, package)
            }
        }
    }

    pub(crate) fn try_publish_store_code(&mut self, package: &str) -> Result<(), &'static str> {
        let store = self.store_id(package).ok_or("store was not registered in store manager")?;
        let result = self
            .store_manager
            .try_publish_code(&mut self.semantic, store)
            .map_err(|error| error.message());
        super::boundary::publish_code_published_boundary(
            &mut self.semantic,
            self.executor_plan.profile.runtime_executor_abi,
        );
        result
    }

    pub(crate) fn try_link_store_hostcalls(&mut self, package: &str) -> Result<(), &'static str> {
        let store = self.store_id(package).ok_or("store was not registered in store manager")?;
        let result = self
            .store_manager
            .try_link_hostcalls(&mut self.semantic, store)
            .map_err(|error| error.message());
        super::boundary::publish_hostcalls_linked_boundary(
            &mut self.semantic,
            self.executor_plan.profile.runtime_executor_abi,
        );
        result
    }

    pub(crate) fn try_mark_store_runnable(&mut self, package: &str) -> Result<(), &'static str> {
        let store = self.store_id(package).ok_or("store was not registered in store manager")?;
        let result = self
            .store_manager
            .try_mark_runnable(&mut self.semantic, store)
            .map_err(|error| error.message());
        super::boundary::publish_runnable_blocked_boundary(
            &mut self.semantic,
            self.executor_plan.profile.runtime_executor_abi,
        );
        result
    }

    pub(crate) fn record_service_trap(
        &mut self,
        package: &str,
        detail: &str,
    ) -> Option<ClassifiedFault> {
        let fault = classify_service_trap(package, detail);
        let store = self.store_id(package)?;
        self.record_store_trap(store, fault.trap, detail).ok()?;
        Some(fault)
    }

    pub(crate) fn record_store_trap(
        &mut self,
        store: StoreId,
        trap: TrapClass,
        detail: &str,
    ) -> Result<(), &'static str> {
        self.store_manager.record_trap(&mut self.semantic, store, trap, detail)
    }
}
