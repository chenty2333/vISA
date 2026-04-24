use semantic_core::{StoreDropReport, StoreId, StoreRebindReport, TrapClass};

use super::fault::{ClassifiedFault, classify_service_trap};
use super::runtime::PrototypeRuntime;

impl<'engine> PrototypeRuntime<'engine> {
    pub(crate) fn store_lifecycle_line(&self, package: &str) -> Option<alloc::string::String> {
        self.store_manager.lifecycle_line(&self.semantic, package)
    }

    pub(crate) fn store_id(&self, package: &str) -> Option<StoreId> {
        self.store_manager
            .store_id(package)
            .or_else(|| self.semantic.store_id(package))
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
        self.store_manager
            .rebind_instance(&mut self.semantic, store)
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
        self.store_manager
            .record_trap(&mut self.semantic, store, trap, detail)
    }
}
