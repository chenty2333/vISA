use semantic_core::{StoreId, StoreState, TrapClass};

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

    pub(crate) fn set_store_state(&mut self, store: StoreId, state: StoreState) {
        self.semantic.set_store_state(store, state);
        self.store_manager.set_state(store, state, &self.semantic);
    }

    pub(crate) fn drop_store_instance(&mut self, store: StoreId) {
        self.semantic.drop_store_instance(store);
        self.store_manager.mark_dropped(store, &self.semantic);
    }

    pub(crate) fn rebind_store_instance(&mut self, store: StoreId) -> Result<(), &'static str> {
        self.semantic
            .rebind_store_instance(store)
            .map(|_| ())
            .ok_or("store to rebind was not present")?;
        self.store_manager.mark_rebound(store, &self.semantic);
        Ok(())
    }

    pub(crate) fn record_service_trap(
        &mut self,
        package: &str,
        detail: &str,
    ) -> Option<ClassifiedFault> {
        let fault = classify_service_trap(package, detail);
        let store = self.store_id(package)?;
        self.record_store_trap(store, fault.trap, detail);
        Some(fault)
    }

    pub(crate) fn record_store_trap(&mut self, store: StoreId, trap: TrapClass, detail: &str) {
        self.semantic.record_store_trap_class(store, trap, detail);
        self.store_manager.record_trap(store, trap);
    }
}
