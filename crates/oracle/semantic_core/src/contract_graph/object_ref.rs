use super::*;

impl VerifiedArtifact {
    pub const fn object_ref(&self) -> ContractObjectRef {
        ContractObjectRef::new(ContractObjectKind::Artifact, self.artifact_id, self.generation)
    }
}

impl CodeObject {
    pub const fn object_ref(&self) -> ContractObjectRef {
        ContractObjectRef::new(ContractObjectKind::CodeObject, self.id, self.generation)
    }
}

impl StoreRecord {
    pub const fn object_ref(&self) -> ContractObjectRef {
        ContractObjectRef::new(ContractObjectKind::Store, self.id, self.generation)
    }
}

impl ActivationRecord {
    pub const fn object_ref(&self) -> ContractObjectRef {
        ContractObjectRef::new(ContractObjectKind::Activation, self.id, self.generation)
    }
}

impl TargetTrapRecord {
    pub const fn object_ref(&self) -> ContractObjectRef {
        ContractObjectRef::new(ContractObjectKind::Trap, self.id, self.generation)
    }
}

impl HostcallTraceRecord {
    pub const fn object_ref(&self) -> ContractObjectRef {
        ContractObjectRef::new(ContractObjectKind::Hostcall, self.id, self.generation)
    }
}

impl CapabilityRecord {
    pub const fn object_ref(&self) -> ContractObjectRef {
        ContractObjectRef::new(ContractObjectKind::Capability, self.id, self.generation)
    }
}

impl FaultCleanupTransaction {
    pub const fn object_ref(&self) -> ContractObjectRef {
        ContractObjectRef::new(ContractObjectKind::CleanupTransaction, self.id, self.generation)
    }
}
