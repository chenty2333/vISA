use super::*;

impl SemanticGraph {
    pub fn record_guest_memory_manager(&mut self, memory: &GuestMemoryManager) -> bool {
        self.restore_guest_memory_records(
            memory.address_spaces(),
            memory.regions(),
            memory.pages(),
            memory.fault_history(),
            memory.operations(),
        )
    }

    pub fn restore_guest_memory_records(
        &mut self,
        address_spaces: &[GuestAddressSpaceRecord],
        regions: &[VmaRegionRecord],
        pages: &[PageObjectRecord],
        faults: &[GuestMemoryFaultRecord],
        operations: &[GuestMemoryOperationRecord],
    ) -> bool {
        if !self.domains.memory.guest_address_spaces.is_empty()
            || !self.domains.memory.vma_regions.is_empty()
            || !self.domains.memory.page_objects.is_empty()
            || !self.domains.memory.guest_memory_faults.is_empty()
            || !self.domains.memory.guest_memory_operations.is_empty()
        {
            return false;
        }
        if !guest_memory_records_are_valid(address_spaces, regions, pages, faults, operations) {
            return false;
        }
        self.domains.memory.guest_address_spaces = address_spaces.to_vec();
        self.domains.memory.vma_regions = regions.to_vec();
        self.domains.memory.page_objects = pages.to_vec();
        self.domains.memory.guest_memory_faults = faults.to_vec();
        self.domains.memory.guest_memory_operations = operations.to_vec();
        true
    }

    pub fn guest_address_spaces(&self) -> &[GuestAddressSpaceRecord] {
        &self.domains.memory.guest_address_spaces
    }

    pub fn guest_address_space_count(&self) -> usize {
        self.domains.memory.guest_address_spaces.len()
    }

    pub fn vma_regions(&self) -> &[VmaRegionRecord] {
        &self.domains.memory.vma_regions
    }

    pub fn vma_region_count(&self) -> usize {
        self.domains.memory.vma_regions.len()
    }

    pub fn page_objects(&self) -> &[PageObjectRecord] {
        &self.domains.memory.page_objects
    }

    pub fn page_object_count(&self) -> usize {
        self.domains.memory.page_objects.len()
    }

    pub fn guest_memory_faults(&self) -> &[GuestMemoryFaultRecord] {
        &self.domains.memory.guest_memory_faults
    }

    pub fn guest_memory_fault_count(&self) -> usize {
        self.domains.memory.guest_memory_faults.len()
    }

    pub fn guest_memory_operations(&self) -> &[GuestMemoryOperationRecord] {
        &self.domains.memory.guest_memory_operations
    }

    pub fn guest_memory_operation_count(&self) -> usize {
        self.domains.memory.guest_memory_operations.len()
    }

    pub fn check_guest_memory_invariants(&self) -> Result<(), SemanticInvariantError> {
        if guest_memory_records_are_valid(
            &self.domains.memory.guest_address_spaces,
            &self.domains.memory.vma_regions,
            &self.domains.memory.page_objects,
            &self.domains.memory.guest_memory_faults,
            &self.domains.memory.guest_memory_operations,
        ) {
            Ok(())
        } else {
            Err(SemanticInvariantError::InvalidGuestMemory)
        }
    }
}

fn guest_memory_records_are_valid(
    address_spaces: &[GuestAddressSpaceRecord],
    regions: &[VmaRegionRecord],
    pages: &[PageObjectRecord],
    faults: &[GuestMemoryFaultRecord],
    operations: &[GuestMemoryOperationRecord],
) -> bool {
    ids_are_unique(address_spaces, |record| record.aspace.id())
        && ids_are_unique(regions, |record| record.region.id())
        && ids_are_unique(pages, |record| record.page.id())
        && ids_are_unique(faults, |record| record.id)
        && ids_are_unique(operations, |record| record.operation_ref.id())
        && address_spaces.iter().all(|record| {
            record.aspace.id() != 0
                && record.generation != 0
                && record.aspace.generation() == record.generation
                && record.owner.id != 0
                && record.owner.generation != 0
                && record.vma_generation != 0
                && record.page_map_generation != 0
                && record.root_region.is_none_or(|region| contains_region_ref(regions, region))
        })
        && regions.iter().all(|record| {
            record.region.id() != 0
                && record.generation != 0
                && record.region.generation() == record.generation
                && record.range.len != 0
                && contains_aspace_ref(address_spaces, record.aspace)
                && contains_page_ref(pages, record.backing)
        })
        && pages.iter().all(|record| {
            record.page.id() != 0
                && record.generation != 0
                && record.page.generation() == record.generation
                && record.dirty_generation != 0
        })
        && faults.iter().all(|record| {
            record.id != 0
                && record.generation != 0
                && contains_page_ref(pages, record.page)
                && !record.reason.is_empty()
        })
        && operations.iter().all(|record| {
            record.operation_ref.id() != 0
                && record.generation != 0
                && record.operation_ref.generation() == record.generation
                && contains_aspace_ref(address_spaces, record.aspace)
                && !record.reason.is_empty()
                && operation_refs_are_valid(record, regions, pages)
        })
}

fn ids_are_unique<T>(records: &[T], mut id_of: impl FnMut(&T) -> u64) -> bool {
    records.iter().enumerate().all(|(idx, record)| {
        let id = id_of(record);
        id != 0 && records.iter().skip(idx + 1).all(|other| id_of(other) != id)
    })
}

fn contains_aspace_ref(
    records: &[GuestAddressSpaceRecord],
    reference: GuestAddressSpaceRef,
) -> bool {
    records.iter().any(|record| record.aspace == reference)
}

fn contains_region_ref(records: &[VmaRegionRecord], reference: VmaRegionRef) -> bool {
    records.iter().any(|record| record.region == reference)
}

fn contains_page_ref(records: &[PageObjectRecord], reference: PageObjectRef) -> bool {
    records.iter().any(|record| record.page == reference)
}

fn contains_region_id(records: &[VmaRegionRecord], reference: VmaRegionRef) -> bool {
    records.iter().any(|record| record.region.id() == reference.id())
}

fn contains_page_id(records: &[PageObjectRecord], reference: PageObjectRef) -> bool {
    records.iter().any(|record| record.page.id() == reference.id())
}

fn operation_refs_are_valid(
    operation: &GuestMemoryOperationRecord,
    regions: &[VmaRegionRecord],
    pages: &[PageObjectRecord],
) -> bool {
    let before_refs_valid =
        operation.region_before.is_none_or(|region| contains_region_id(regions, region))
            && operation.page_before.is_none_or(|page| contains_page_id(pages, page));
    let after_refs_valid =
        operation.region_after.is_none_or(|region| contains_region_ref(regions, region))
            && operation.page_after.is_none_or(|page| contains_page_ref(pages, page));
    if !before_refs_valid || !after_refs_valid {
        return false;
    }

    match operation.operation {
        GuestMemoryOperationKind::Mmap => {
            operation.range.len != 0
                && operation.region_before.is_none()
                && operation.region_after.is_some()
                && operation.page_after.is_some()
                && operation.perms_after.is_some()
        }
        GuestMemoryOperationKind::Munmap => {
            operation.range.len != 0
                && operation.region_before.is_some()
                && operation.region_after.is_some()
                && operation.perms_before.is_some()
        }
        GuestMemoryOperationKind::Mprotect => {
            operation.range.len != 0
                && operation.region_before.is_some()
                && operation.region_after.is_some()
                && operation.perms_before.is_some()
                && operation.perms_after.is_some()
        }
        GuestMemoryOperationKind::Brk => operation.brk_after.is_some(),
    }
}
