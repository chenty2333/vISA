use alloc::vec::Vec;

use semantic_core::{
    CowState, GuestAddressSpaceRef, GuestMemoryManager, GuestPerms, GuestVaRange, PageBacking,
    VmaFlags, VmaRegionRef,
};

const PAGE_SIZE: u64 = 4096;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct GuestMemoryProjectionSpec {
    start: u64,
    end: u64,
    readable: bool,
    writable: bool,
    executable: bool,
}

impl GuestMemoryProjectionSpec {
    const fn new(start: u64, end: u64, readable: bool, writable: bool, executable: bool) -> Self {
        Self { start, end, readable, writable, executable }
    }

    fn from_range(
        start: u64,
        len: u64,
        readable: bool,
        writable: bool,
        executable: bool,
    ) -> Option<Self> {
        let end = start.checked_add(len)?;
        Some(Self::new(start, end, readable, writable, executable))
    }

    const fn perms(self) -> GuestPerms {
        GuestPerms::from_rwx(self.readable, self.writable, self.executable)
    }
}

#[derive(Clone, Debug)]
struct GuestMemoryProjectionRecord {
    spec: GuestMemoryProjectionSpec,
    region: VmaRegionRef,
}

#[derive(Debug)]
pub(crate) struct GuestMemoryProjection {
    memory: GuestMemoryManager,
    aspace: GuestAddressSpaceRef,
    regions: Vec<GuestMemoryProjectionRecord>,
}

impl GuestMemoryProjection {
    pub(crate) fn new(memory: GuestMemoryManager, aspace: GuestAddressSpaceRef) -> Self {
        Self { memory, aspace, regions: Vec::new() }
    }

    pub(crate) fn record_region(
        &mut self,
        start: u64,
        len: u64,
        readable: bool,
        writable: bool,
        executable: bool,
    ) {
        let Some(spec) =
            GuestMemoryProjectionSpec::from_range(start, len, readable, writable, executable)
        else {
            return;
        };
        self.replace_range(start, len, Some(spec));
    }

    pub(crate) fn remove_region(&mut self, start: u64, len: u64) {
        self.replace_range(start, len, None);
    }

    pub(crate) fn aspace(&self) -> GuestAddressSpaceRef {
        self.aspace
    }

    #[cfg(test)]
    fn region_specs(&self) -> Vec<GuestMemoryProjectionSpec> {
        self.regions.iter().map(|region| region.spec).collect()
    }

    fn replace_range(
        &mut self,
        start: u64,
        len: u64,
        replacement: Option<GuestMemoryProjectionSpec>,
    ) {
        if len == 0 || start & (PAGE_SIZE - 1) != 0 || len & (PAGE_SIZE - 1) != 0 {
            return;
        }
        let Some(end) = start.checked_add(len) else {
            return;
        };

        let mut next_specs = Vec::with_capacity(self.regions.len().saturating_add(1));
        for record in &self.regions {
            let spec = record.spec;
            if spec.end <= start || spec.start >= end {
                next_specs.push(spec);
                continue;
            }
            if spec.start < start {
                next_specs.push(GuestMemoryProjectionSpec::new(
                    spec.start,
                    start,
                    spec.readable,
                    spec.writable,
                    spec.executable,
                ));
            }
            if spec.end > end {
                next_specs.push(GuestMemoryProjectionSpec::new(
                    end,
                    spec.end,
                    spec.readable,
                    spec.writable,
                    spec.executable,
                ));
            }
        }
        if let Some(spec) = replacement {
            next_specs.push(spec);
        }
        self.rebuild_regions(normalize_region_specs(next_specs));
    }

    fn rebuild_regions(&mut self, next_specs: Vec<GuestMemoryProjectionSpec>) {
        let mut next_memory = self.memory.clone();
        for record in &self.regions {
            if next_memory.unmap_region(record.region).is_err() {
                crate::kwarn!("guest memory projection failed to unmap a stale region");
                return;
            }
        }

        let mut next_regions = Vec::with_capacity(next_specs.len());
        for spec in next_specs {
            let page = next_memory.create_page(PageBacking::Anonymous, CowState::None);
            let Ok(region) = next_memory.map_region(
                self.aspace,
                GuestVaRange::new(spec.start, spec.end - spec.start),
                spec.perms(),
                VmaFlags::anonymous(),
                page,
            ) else {
                crate::kwarn!(
                    "guest memory projection failed to map region start=0x{:x} end=0x{:x}",
                    spec.start,
                    spec.end
                );
                return;
            };
            next_regions.push(GuestMemoryProjectionRecord { spec, region });
        }

        self.memory = next_memory;
        self.regions = next_regions;
    }
}

fn normalize_region_specs(
    mut specs: Vec<GuestMemoryProjectionSpec>,
) -> Vec<GuestMemoryProjectionSpec> {
    specs.sort_by_key(|spec| (spec.start, spec.end));
    let mut merged: Vec<GuestMemoryProjectionSpec> = Vec::with_capacity(specs.len());
    for spec in specs {
        if spec.start >= spec.end {
            continue;
        }
        if let Some(last) = merged.last_mut()
            && last.readable == spec.readable
            && last.writable == spec.writable
            && last.executable == spec.executable
            && last.end >= spec.start
        {
            last.end = last.end.max(spec.end);
            continue;
        }
        merged.push(spec);
    }
    merged
}

#[cfg(test)]
mod tests {
    use semantic_core::{ContractObjectKind, ContractObjectRef};

    use super::*;

    #[test]
    fn region_projection_replays_and_splits_overlaps() {
        let owner = ContractObjectRef::new(ContractObjectKind::Store, 7, 1);
        let mut memory = GuestMemoryManager::new();
        let aspace = memory.create_address_space(owner);
        let mut projection = GuestMemoryProjection::new(memory, aspace);

        projection.record_region(0x1000, 0x3000, true, true, false);
        projection.record_region(0x2000, 0x2000, true, false, false);

        assert_eq!(projection.region_specs().len(), 2);
        assert_eq!(projection.region_specs()[0].start, 0x1000);
        assert_eq!(projection.region_specs()[0].end, 0x2000);
        assert!(projection.region_specs()[0].writable);
        assert_eq!(projection.region_specs()[1].start, 0x2000);
        assert_eq!(projection.region_specs()[1].end, 0x4000);
        assert!(!projection.region_specs()[1].writable);

        let rebuilt = projection
            .memory
            .rebuild_substrate_mappings(projection.aspace())
            .expect("rebuild substrate mappings");
        assert_eq!(rebuilt.len(), 2);
    }

    #[test]
    fn region_projection_removes_ranges() {
        let owner = ContractObjectRef::new(ContractObjectKind::Store, 8, 1);
        let mut memory = GuestMemoryManager::new();
        let aspace = memory.create_address_space(owner);
        let mut projection = GuestMemoryProjection::new(memory, aspace);

        projection.record_region(0x1000, 0x2000, true, true, false);
        projection.remove_region(0x2000, 0x1000);

        assert_eq!(projection.region_specs().len(), 1);
        assert_eq!(projection.region_specs()[0].start, 0x1000);
        assert_eq!(projection.region_specs()[0].end, 0x2000);

        projection.remove_region(0x1000, 0x2000);
        assert!(projection.region_specs().is_empty());
        let rebuilt = projection
            .memory
            .rebuild_substrate_mappings(projection.aspace())
            .expect("rebuild substrate mappings");
        assert!(rebuilt.is_empty());
    }
}
