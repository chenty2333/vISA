use alloc::{
    string::{String, ToString},
    vec,
    vec::Vec,
};

use super::*;

/// Result of classifying a page fault — semantic policy, not substrate execution.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PageFaultResolution {
    /// A COW page was written — must copy the physical page and update PTEs
    CowCopy { page: PageObjectRef },
    /// A valid mapped page needs its physical frame installed (demand paging)
    DemandMapping { page: PageObjectRef },
    /// No VMA found at this address — SIGSEGV
    NoMapping,
    /// Protection violation (write to read-only, execute to NX) — SIGSEGV
    ProtectionViolation,
}

pub type GuestAddressSpaceId = u64;
pub type VmaRegionId = u64;
pub type PageObjectId = u64;
pub type GuestVa = u64;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GuestAddressSpaceRef(pub ContractObjectRef);

impl GuestAddressSpaceRef {
    pub const fn new(id: GuestAddressSpaceId, generation: Generation) -> Self {
        Self(ContractObjectRef::new(ContractObjectKind::GuestAddressSpace, id, generation))
    }

    pub const fn id(self) -> GuestAddressSpaceId {
        self.0.id
    }

    pub const fn generation(self) -> Generation {
        self.0.generation
    }

    pub const fn object_ref(self) -> ContractObjectRef {
        self.0
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VmaRegionRef(pub ContractObjectRef);

impl VmaRegionRef {
    pub const fn new(id: VmaRegionId, generation: Generation) -> Self {
        Self(ContractObjectRef::new(ContractObjectKind::VmaRegion, id, generation))
    }

    pub const fn id(self) -> VmaRegionId {
        self.0.id
    }

    pub const fn generation(self) -> Generation {
        self.0.generation
    }

    pub const fn object_ref(self) -> ContractObjectRef {
        self.0
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PageObjectRef(pub ContractObjectRef);

impl PageObjectRef {
    pub const fn new(id: PageObjectId, generation: Generation) -> Self {
        Self(ContractObjectRef::new(ContractObjectKind::PageObject, id, generation))
    }

    pub const fn id(self) -> PageObjectId {
        self.0.id
    }

    pub const fn generation(self) -> Generation {
        self.0.generation
    }

    pub const fn object_ref(self) -> ContractObjectRef {
        self.0
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AddressSpaceState {
    Live,
    Frozen,
    Dead,
}

impl AddressSpaceState {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Live => "live",
            Self::Frozen => "frozen",
            Self::Dead => "dead",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VmaState {
    Mapped,
    Unmapped,
}

impl VmaState {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Mapped => "mapped",
            Self::Unmapped => "unmapped",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PageObjectState {
    Live,
    Frozen,
    Dead,
}

impl PageObjectState {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Live => "live",
            Self::Frozen => "frozen",
            Self::Dead => "dead",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GuestVaRange {
    pub start: GuestVa,
    pub len: u64,
}

impl GuestVaRange {
    pub const fn new(start: GuestVa, len: u64) -> Self {
        Self { start, len }
    }

    pub fn contains_range(self, start: GuestVa, len: u64) -> bool {
        let Some(end) = start.checked_add(len) else {
            return false;
        };
        let Some(range_end) = self.start.checked_add(self.len) else {
            return false;
        };
        start >= self.start && end <= range_end
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GuestPerms {
    bits: u8,
}

impl GuestPerms {
    pub const READ: Self = Self { bits: 0b001 };
    pub const WRITE: Self = Self { bits: 0b010 };
    pub const EXEC: Self = Self { bits: 0b100 };
    pub const READ_WRITE: Self = Self { bits: 0b011 };
    pub const READ_EXECUTE: Self = Self { bits: 0b101 };

    pub const fn contains(self, required: Self) -> bool {
        self.bits & required.bits == required.bits
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VmaFlags {
    pub cow: bool,
    pub shared: bool,
    pub device: bool,
}

impl VmaFlags {
    pub const fn anonymous() -> Self {
        Self { cow: false, shared: false, device: false }
    }

    pub const fn cow() -> Self {
        Self { cow: true, shared: false, device: false }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PageBacking {
    Anonymous,
    FileBacked,
    CowChild,
    SharedMemory,
    DeviceMemory,
    ZeroPage,
    External,
}

impl PageBacking {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Anonymous => "anonymous",
            Self::FileBacked => "file-backed",
            Self::CowChild => "cow-child",
            Self::SharedMemory => "shared-memory",
            Self::DeviceMemory => "device-memory",
            Self::ZeroPage => "zero-page",
            Self::External => "external",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CowState {
    None,
    Shared,
    Broken,
}

impl CowState {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Shared => "shared",
            Self::Broken => "broken",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GuestAddressSpaceRecord {
    pub aspace: GuestAddressSpaceRef,
    pub owner: ContractObjectRef,
    pub generation: Generation,
    pub state: AddressSpaceState,
    pub root_region: Option<VmaRegionRef>,
    pub vma_generation: Generation,
    pub page_map_generation: Generation,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VmaRegionRecord {
    pub region: VmaRegionRef,
    pub aspace: GuestAddressSpaceRef,
    pub range: GuestVaRange,
    pub perms: GuestPerms,
    pub flags: VmaFlags,
    pub backing: PageObjectRef,
    pub generation: Generation,
    pub state: VmaState,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PageObjectRecord {
    pub page: PageObjectRef,
    pub backing: PageBacking,
    pub cow: CowState,
    pub dirty_generation: Generation,
    pub generation: Generation,
    pub state: PageObjectState,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UserBufferFastPath {
    pub aspace: GuestAddressSpaceRef,
    pub region: VmaRegionRef,
    pub start_va: GuestVa,
    pub len: u64,
    pub pages: Vec<PageObjectRef>,
    pub perms: GuestPerms,
    pub cap_generation: Generation,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FrozenPageGeneration {
    pub page: PageObjectRef,
    pub dirty_generation: Generation,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SnapshotBarrierReport {
    pub released_dmw_leases: u32,
    pub frozen_pages: Vec<FrozenPageGeneration>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GuestMemoryFaultRecord {
    pub page: PageObjectRef,
    pub reason: String,
    pub historical: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SubstrateMappingRecord {
    pub aspace: GuestAddressSpaceRef,
    pub region: VmaRegionRef,
    pub page: PageObjectRef,
    pub source: &'static str,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GuestMemoryError {
    AddressSpaceMissing,
    VmaMissing,
    PageMissing,
    GenerationMismatch,
    PermissionDenied,
    BadCapability,
    SnapshotBarrierActive,
    ActiveDmwLease,
    PendingCleanup,
    VmaUnmapped,
    PageDead,
}

impl GuestMemoryError {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::AddressSpaceMissing => "address-space-missing",
            Self::VmaMissing => "vma-missing",
            Self::PageMissing => "page-missing",
            Self::GenerationMismatch => "generation-mismatch",
            Self::PermissionDenied => "permission-denied",
            Self::BadCapability => "bad-capability",
            Self::SnapshotBarrierActive => "snapshot-barrier-active",
            Self::ActiveDmwLease => "active-dmw-lease",
            Self::PendingCleanup => "pending-cleanup",
            Self::VmaUnmapped => "vma-unmapped",
            Self::PageDead => "page-dead",
        }
    }
}

#[derive(Clone, Debug)]
pub struct GuestMemoryManager {
    next_aspace: GuestAddressSpaceId,
    next_region: VmaRegionId,
    next_page: PageObjectId,
    aspaces: Vec<GuestAddressSpaceRecord>,
    regions: Vec<VmaRegionRecord>,
    pages: Vec<PageObjectRecord>,
    fault_history: Vec<GuestMemoryFaultRecord>,
    active_dmw_leases: u32,
    snapshot_barrier_active: bool,
    pending_cleanup_stores: Vec<ContractObjectRef>,
}

impl GuestMemoryManager {
    pub const fn new() -> Self {
        Self {
            next_aspace: 1,
            next_region: 1,
            next_page: 1,
            aspaces: Vec::new(),
            regions: Vec::new(),
            pages: Vec::new(),
            fault_history: Vec::new(),
            active_dmw_leases: 0,
            snapshot_barrier_active: false,
            pending_cleanup_stores: Vec::new(),
        }
    }

    pub fn create_address_space(&mut self, owner: ContractObjectRef) -> GuestAddressSpaceRef {
        let aspace = GuestAddressSpaceRef::new(self.next_aspace, 1);
        self.next_aspace += 1;
        self.aspaces.push(GuestAddressSpaceRecord {
            aspace,
            owner,
            generation: aspace.generation(),
            state: AddressSpaceState::Live,
            root_region: None,
            vma_generation: 1,
            page_map_generation: 1,
        });
        aspace
    }

    pub fn create_page(&mut self, backing: PageBacking, cow: CowState) -> PageObjectRef {
        let page = PageObjectRef::new(self.next_page, 1);
        self.next_page += 1;
        self.pages.push(PageObjectRecord {
            page,
            backing,
            cow,
            dirty_generation: 1,
            generation: page.generation(),
            state: PageObjectState::Live,
        });
        page
    }

    /// Find the VMA region containing a virtual address in the given address space.
    pub fn find_region(&self, aspace: GuestAddressSpaceRef, va: GuestVa) -> Option<&VmaRegionRecord> {
        self.regions.iter()
            .filter(|r| r.aspace == aspace && r.state == VmaState::Mapped)
            .find(|r| r.range.contains_range(va, 1))
    }

    /// Classify a page fault into resolution strategy.
    /// This is semantic policy — the substrate executes it.
    pub fn classify_fault(
        &self,
        vma: &VmaRegionRecord,
        _va: GuestVa,
        write: bool,
    ) -> PageFaultResolution {
        if write && vma.flags.cow {
            PageFaultResolution::CowCopy { page: vma.backing }
        } else if write && !vma.perms.contains(GuestPerms::WRITE) {
            PageFaultResolution::ProtectionViolation
        } else if !vma.perms.contains(GuestPerms::READ) {
            PageFaultResolution::ProtectionViolation
        } else {
            PageFaultResolution::DemandMapping { page: vma.backing }
        }
    }

    /// Find a free virtual address range of at least `len` bytes, near `hint`.
    pub fn find_gap(&self, aspace: GuestAddressSpaceRef, len: u64, hint: u64) -> Option<u64> {
        let mut region_bounds: Vec<(u64, u64)> = self.regions.iter()
            .filter(|r| r.aspace == aspace && r.state == VmaState::Mapped)
            .map(|r| {
                let end = r.range.start.checked_add(r.range.len).unwrap_or(u64::MAX);
                (r.range.start, end)
            })
            .collect();
        region_bounds.sort_by_key(|(start, _)| *start);

        if region_bounds.is_empty() {
            return Some(hint.max(0x1000));
        }

        if !region_bounds.iter().any(|(s, e)| hint < *e && (hint + len) > *s) {
            return Some(hint);
        }

        let mut cursor = 0x1000u64;
        for (start, end) in region_bounds {
            if cursor + len <= start {
                return Some(cursor);
            }
            cursor = cursor.max(end);
        }
        Some(cursor)
    }

    pub fn map_region(
        &mut self,
        aspace: GuestAddressSpaceRef,
        range: GuestVaRange,
        perms: GuestPerms,
        flags: VmaFlags,
        page: PageObjectRef,
    ) -> Result<VmaRegionRef, GuestMemoryError> {
        self.aspace_exact(aspace)?;
        self.page_exact(page)?;
        let region = VmaRegionRef::new(self.next_region, 1);
        self.next_region += 1;
        self.regions.push(VmaRegionRecord {
            region,
            aspace,
            range,
            perms,
            flags,
            backing: page,
            generation: region.generation(),
            state: VmaState::Mapped,
        });
        let aspace_record = self.aspace_exact_mut(aspace)?;
        aspace_record.root_region.get_or_insert(region);
        aspace_record.vma_generation += 1;
        aspace_record.page_map_generation += 1;
        Ok(region)
    }

    pub fn build_user_buffer_fast_path(
        &self,
        aspace: GuestAddressSpaceRef,
        region: VmaRegionRef,
        start_va: GuestVa,
        len: u64,
        cap_generation: Generation,
    ) -> Result<UserBufferFastPath, GuestMemoryError> {
        let region_record = self.region_exact(region)?;
        if region_record.aspace != aspace {
            return Err(GuestMemoryError::GenerationMismatch);
        }
        if !region_record.range.contains_range(start_va, len) {
            return Err(GuestMemoryError::PermissionDenied);
        }
        Ok(UserBufferFastPath {
            aspace,
            region,
            start_va,
            len,
            pages: vec![region_record.backing],
            perms: region_record.perms,
            cap_generation,
        })
    }

    pub fn validate_fast_path(
        &self,
        fast_path: &UserBufferFastPath,
        required_perm: GuestPerms,
        subject: &str,
        authority: AuthorityObjectRef,
        handle: &CapabilityHandle,
        ledger: &CapabilityLedger,
    ) -> Result<(), GuestMemoryError> {
        let aspace = self.aspace_exact(fast_path.aspace)?;
        if self.snapshot_barrier_active {
            return Err(GuestMemoryError::SnapshotBarrierActive);
        }
        if self.pending_cleanup_stores.contains(&aspace.owner) {
            return Err(GuestMemoryError::PendingCleanup);
        }
        let region = self.region_exact(fast_path.region)?;
        if region.aspace != fast_path.aspace {
            return Err(GuestMemoryError::GenerationMismatch);
        }
        if region.state != VmaState::Mapped {
            return Err(GuestMemoryError::VmaUnmapped);
        }
        if !region.perms.contains(required_perm) || !fast_path.perms.contains(required_perm) {
            return Err(GuestMemoryError::PermissionDenied);
        }
        for page in &fast_path.pages {
            let page = self.page_exact(*page)?;
            if page.state == PageObjectState::Dead {
                return Err(GuestMemoryError::PageDead);
            }
        }
        let record = ledger
            .check_authority(subject, authority, permission_operation(required_perm), Some(handle))
            .map_err(|_| GuestMemoryError::BadCapability)?;
        if record.generation != fast_path.cap_generation {
            return Err(GuestMemoryError::GenerationMismatch);
        }
        Ok(())
    }

    pub fn validate_dmw_map(
        &self,
        aspace: GuestAddressSpaceRef,
        region: VmaRegionRef,
        page: PageObjectRef,
    ) -> Result<(), GuestMemoryError> {
        self.aspace_exact(aspace)?;
        let region_record = self.region_exact(region)?;
        if region_record.aspace != aspace || region_record.backing != page {
            return Err(GuestMemoryError::GenerationMismatch);
        }
        if region_record.state != VmaState::Mapped {
            return Err(GuestMemoryError::VmaUnmapped);
        }
        let page_record = self.page_exact(page)?;
        if page_record.state == PageObjectState::Dead {
            return Err(GuestMemoryError::PageDead);
        }
        Ok(())
    }

    pub fn copyin(
        &self,
        fast_path: &UserBufferFastPath,
        subject: &str,
        authority: AuthorityObjectRef,
        handle: &CapabilityHandle,
        ledger: &CapabilityLedger,
    ) -> Result<(), GuestMemoryError> {
        self.validate_fast_path(fast_path, GuestPerms::READ, subject, authority, handle, ledger)
    }

    pub fn copyout(
        &self,
        fast_path: &UserBufferFastPath,
        subject: &str,
        authority: AuthorityObjectRef,
        handle: &CapabilityHandle,
        ledger: &CapabilityLedger,
    ) -> Result<(), GuestMemoryError> {
        self.validate_fast_path(fast_path, GuestPerms::WRITE, subject, authority, handle, ledger)
    }

    pub fn unmap_region(&mut self, region: VmaRegionRef) -> Result<(), GuestMemoryError> {
        let index = self.region_index(region)?;
        let aspace = self.regions[index].aspace;
        self.regions[index].state = VmaState::Unmapped;
        self.regions[index].generation += 1;
        self.regions[index].region = VmaRegionRef::new(region.id(), self.regions[index].generation);
        let aspace = self.aspace_exact_mut(aspace)?;
        aspace.vma_generation += 1;
        aspace.page_map_generation += 1;
        Ok(())
    }

    pub fn cow_break(&mut self, page: PageObjectRef) -> Result<(), GuestMemoryError> {
        let new_page = {
            let page = self.page_exact_mut(page)?;
            page.cow = CowState::Broken;
            page.dirty_generation += 1;
            page.generation += 1;
            page.page = PageObjectRef::new(page.page.id(), page.generation);
            page.page
        };
        for region in &mut self.regions {
            if region.backing == page {
                region.backing = new_page;
            }
        }
        for aspace in &mut self.aspaces {
            aspace.page_map_generation += 1;
        }
        Ok(())
    }

    pub fn retire_page(&mut self, page: PageObjectRef) -> Result<(), GuestMemoryError> {
        let page = self.page_exact_mut(page)?;
        page.state = PageObjectState::Dead;
        page.generation += 1;
        page.page = PageObjectRef::new(page.page.id(), page.generation);
        Ok(())
    }

    pub fn record_page_fault(&mut self, page: PageObjectRef, reason: &str) {
        self.fault_history.push(GuestMemoryFaultRecord {
            page,
            reason: reason.to_string(),
            historical: true,
        });
    }

    pub fn open_dmw_lease(&mut self) {
        self.active_dmw_leases += 1;
    }

    pub fn close_dmw_lease(&mut self) {
        if self.active_dmw_leases != 0 {
            self.active_dmw_leases -= 1;
        }
    }

    pub const fn active_dmw_leases(&self) -> u32 {
        self.active_dmw_leases
    }

    pub fn begin_cleanup_for_store(&mut self, store: ContractObjectRef) {
        if !self.pending_cleanup_stores.contains(&store) {
            self.pending_cleanup_stores.push(store);
        }
    }

    pub fn snapshot_barrier(&mut self) -> Result<SnapshotBarrierReport, GuestMemoryError> {
        if self.active_dmw_leases != 0 {
            return Err(GuestMemoryError::ActiveDmwLease);
        }
        self.snapshot_barrier_active = true;
        let mut frozen_pages = Vec::new();
        for page in &mut self.pages {
            page.state = PageObjectState::Frozen;
            frozen_pages.push(FrozenPageGeneration {
                page: page.page,
                dirty_generation: page.dirty_generation,
            });
        }
        for aspace in &mut self.aspaces {
            aspace.state = AddressSpaceState::Frozen;
        }
        Ok(SnapshotBarrierReport { released_dmw_leases: 0, frozen_pages })
    }

    pub fn rebuild_substrate_mappings(
        &self,
        aspace: GuestAddressSpaceRef,
    ) -> Result<Vec<SubstrateMappingRecord>, GuestMemoryError> {
        self.aspace_exact(aspace)?;
        let mut rebuilt = Vec::new();
        for region in self
            .regions
            .iter()
            .filter(|region| region.aspace == aspace && region.state == VmaState::Mapped)
        {
            self.page_exact(region.backing)?;
            rebuilt.push(SubstrateMappingRecord {
                aspace,
                region: region.region,
                page: region.backing,
                source: "rebuilt-from-semantic-guest-memory",
            });
        }
        Ok(rebuilt)
    }

    pub fn fault_history(&self) -> &[GuestMemoryFaultRecord] {
        &self.fault_history
    }

    fn aspace_exact(
        &self,
        aspace: GuestAddressSpaceRef,
    ) -> Result<&GuestAddressSpaceRecord, GuestMemoryError> {
        self.aspaces
            .iter()
            .find(|record| record.aspace.id() == aspace.id())
            .ok_or(GuestMemoryError::AddressSpaceMissing)
            .and_then(|record| {
                if record.aspace == aspace && record.generation == aspace.generation() {
                    Ok(record)
                } else {
                    Err(GuestMemoryError::GenerationMismatch)
                }
            })
    }

    fn aspace_exact_mut(
        &mut self,
        aspace: GuestAddressSpaceRef,
    ) -> Result<&mut GuestAddressSpaceRecord, GuestMemoryError> {
        self.aspaces
            .iter_mut()
            .find(|record| record.aspace.id() == aspace.id())
            .ok_or(GuestMemoryError::AddressSpaceMissing)
            .and_then(|record| {
                if record.aspace == aspace && record.generation == aspace.generation() {
                    Ok(record)
                } else {
                    Err(GuestMemoryError::GenerationMismatch)
                }
            })
    }

    fn region_exact(&self, region: VmaRegionRef) -> Result<&VmaRegionRecord, GuestMemoryError> {
        self.regions
            .iter()
            .find(|record| record.region.id() == region.id())
            .ok_or(GuestMemoryError::VmaMissing)
            .and_then(|record| {
                if record.region == region && record.generation == region.generation() {
                    Ok(record)
                } else {
                    Err(GuestMemoryError::GenerationMismatch)
                }
            })
    }

    fn region_index(&self, region: VmaRegionRef) -> Result<usize, GuestMemoryError> {
        self.regions
            .iter()
            .position(|record| record.region.id() == region.id())
            .ok_or(GuestMemoryError::VmaMissing)
            .and_then(|index| {
                if self.regions[index].region == region
                    && self.regions[index].generation == region.generation()
                {
                    Ok(index)
                } else {
                    Err(GuestMemoryError::GenerationMismatch)
                }
            })
    }

    fn page_exact(&self, page: PageObjectRef) -> Result<&PageObjectRecord, GuestMemoryError> {
        self.pages
            .iter()
            .find(|record| record.page.id() == page.id())
            .ok_or(GuestMemoryError::PageMissing)
            .and_then(|record| {
                if record.page == page && record.generation == page.generation() {
                    Ok(record)
                } else {
                    Err(GuestMemoryError::GenerationMismatch)
                }
            })
    }

    fn page_exact_mut(
        &mut self,
        page: PageObjectRef,
    ) -> Result<&mut PageObjectRecord, GuestMemoryError> {
        self.pages
            .iter_mut()
            .find(|record| record.page.id() == page.id())
            .ok_or(GuestMemoryError::PageMissing)
            .and_then(|record| {
                if record.page == page && record.generation == page.generation() {
                    Ok(record)
                } else {
                    Err(GuestMemoryError::GenerationMismatch)
                }
            })
    }
}

impl Default for GuestMemoryManager {
    fn default() -> Self {
        Self::new()
    }
}

fn permission_operation(permission: GuestPerms) -> &'static str {
    if permission.contains(GuestPerms::WRITE) {
        "write"
    } else if permission.contains(GuestPerms::EXEC) {
        "execute"
    } else {
        "read"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SUBJECT: &str = "linux_syscall";

    struct Harness {
        memory: GuestMemoryManager,
        ledger: CapabilityLedger,
        store: ContractObjectRef,
        aspace: GuestAddressSpaceRef,
        region: VmaRegionRef,
        page: PageObjectRef,
        authority: AuthorityObjectRef,
        handle: CapabilityHandle,
        cap_generation: Generation,
    }

    impl Harness {
        fn new() -> Self {
            let mut memory = GuestMemoryManager::new();
            let store = ContractObjectRef::new(ContractObjectKind::Store, 7, 3);
            let aspace = memory.create_address_space(store);
            let page = memory.create_page(PageBacking::Anonymous, CowState::None);
            let region = memory
                .map_region(
                    aspace,
                    GuestVaRange::new(0x4000, 0x2000),
                    GuestPerms::READ_WRITE,
                    VmaFlags::anonymous(),
                    page,
                )
                .expect("map region");
            let authority = AuthorityObjectRef::internal(
                CapabilityClass::GuestMemoryAccess,
                aspace.object_ref(),
            );
            let mut ledger = CapabilityLedger::new();
            let cap = ledger
                .grant_with_authority_ref(
                    SUBJECT,
                    "guest-memory.aspace",
                    authority,
                    &["read", "write"],
                    "store",
                    Some(store.id),
                    Some(store.generation),
                    None,
                    "guest-memory-test",
                    true,
                )
                .expect("grant guest-memory cap");
            let record = ledger.record(cap).expect("cap record");
            let handle = record
                .store_local_handle(vec!["read".to_string(), "write".to_string()])
                .expect("store local handle");
            let cap_generation = record.generation;
            Self { memory, ledger, store, aspace, region, page, authority, handle, cap_generation }
        }

        fn fast_path(&self) -> UserBufferFastPath {
            self.memory
                .build_user_buffer_fast_path(
                    self.aspace,
                    self.region,
                    0x4000,
                    0x1000,
                    self.cap_generation,
                )
                .expect("fast path")
        }
    }

    #[test]
    fn guest_aspace_generation_mismatch_rejects_fast_path() {
        let h = Harness::new();
        let mut fast_path = h.fast_path();
        fast_path.aspace = GuestAddressSpaceRef::new(h.aspace.id(), h.aspace.generation() + 1);

        assert_eq!(
            h.memory.copyin(&fast_path, SUBJECT, h.authority, &h.handle, &h.ledger),
            Err(GuestMemoryError::GenerationMismatch)
        );
    }

    #[test]
    fn vma_generation_mismatch_rejects_dmw_map() {
        let h = Harness::new();
        let stale_region = VmaRegionRef::new(h.region.id(), h.region.generation() + 1);

        assert_eq!(
            h.memory.validate_dmw_map(h.aspace, stale_region, h.page),
            Err(GuestMemoryError::GenerationMismatch)
        );
    }

    #[test]
    fn page_object_generation_mismatch_rejects_copyin() {
        let h = Harness::new();
        let mut fast_path = h.fast_path();
        fast_path.pages[0] = PageObjectRef::new(h.page.id(), h.page.generation() + 1);

        assert_eq!(
            h.memory.copyin(&fast_path, SUBJECT, h.authority, &h.handle, &h.ledger),
            Err(GuestMemoryError::GenerationMismatch)
        );
    }

    #[test]
    fn forged_global_object_id_does_not_authorize_capability() {
        let h = Harness::new();
        let mut forged = h.handle.clone();
        forged.slot = h.aspace.id() as u32;
        forged.generation = h.aspace.generation() as u32;
        forged.tag = 0;

        assert_eq!(
            h.memory.copyin(&h.fast_path(), SUBJECT, h.authority, &forged, &h.ledger),
            Err(GuestMemoryError::BadCapability)
        );
    }

    #[test]
    fn store_local_capability_slot_generation_mismatch_denies() {
        let h = Harness::new();
        let mut stale = h.handle.clone();
        stale.generation += 1;

        assert_eq!(
            h.memory.copyin(&h.fast_path(), SUBJECT, h.authority, &stale, &h.ledger),
            Err(GuestMemoryError::BadCapability)
        );
    }

    #[test]
    fn capability_tag_mismatch_denies() {
        let h = Harness::new();
        let mut forged = h.handle.clone();
        forged.tag ^= 0x55aa;

        assert_eq!(
            h.memory.copyin(&h.fast_path(), SUBJECT, h.authority, &forged, &h.ledger),
            Err(GuestMemoryError::BadCapability)
        );
    }

    #[test]
    fn vma_unmap_invalidates_user_buffer_fast_path() {
        let mut h = Harness::new();
        let fast_path = h.fast_path();
        h.memory.unmap_region(h.region).expect("unmap");

        assert_eq!(
            h.memory.copyin(&fast_path, SUBJECT, h.authority, &h.handle, &h.ledger),
            Err(GuestMemoryError::GenerationMismatch)
        );
    }

    #[test]
    fn cow_break_invalidates_page_object_fast_path() {
        let mut h = Harness::new();
        let fast_path = h.fast_path();
        h.memory.cow_break(h.page).expect("cow break");

        assert_eq!(
            h.memory.copyin(&fast_path, SUBJECT, h.authority, &h.handle, &h.ledger),
            Err(GuestMemoryError::GenerationMismatch)
        );
    }

    #[test]
    fn guest_memory_convergence_copyout_cow_and_lease_boundaries_are_generation_safe() {
        let mut h = Harness::new();
        let fast_path = h.fast_path();

        assert_eq!(
            h.memory.copyout(&fast_path, SUBJECT, h.authority, &h.handle, &h.ledger),
            Ok(())
        );
        h.memory.open_dmw_lease();
        assert_eq!(h.memory.snapshot_barrier(), Err(GuestMemoryError::ActiveDmwLease));
        assert_eq!(h.memory.active_dmw_leases(), 1);
        h.memory.close_dmw_lease();
        assert_eq!(h.memory.active_dmw_leases(), 0);

        h.memory.cow_break(h.page).expect("cow break");
        assert_eq!(
            h.memory.copyout(&fast_path, SUBJECT, h.authority, &h.handle, &h.ledger),
            Err(GuestMemoryError::GenerationMismatch)
        );
        let mappings = h.memory.rebuild_substrate_mappings(h.aspace).expect("rebuild after cow");
        assert_eq!(mappings.len(), 1);
        assert_eq!(mappings[0].page.id(), h.page.id());
        assert_eq!(mappings[0].page.generation(), h.page.generation() + 1);

        let fresh = h
            .memory
            .build_user_buffer_fast_path(h.aspace, h.region, 0x4000, 0x1000, h.cap_generation)
            .expect("fresh fast path");
        assert_eq!(fresh.pages[0], mappings[0].page);
        assert_eq!(h.memory.copyout(&fresh, SUBJECT, h.authority, &h.handle, &h.ledger), Ok(()));

        let report = h.memory.snapshot_barrier().expect("snapshot barrier");
        assert_eq!(report.released_dmw_leases, 0);
        assert_eq!(report.frozen_pages[0].page, mappings[0].page);
        assert_eq!(
            h.memory.copyout(&fresh, SUBJECT, h.authority, &h.handle, &h.ledger),
            Err(GuestMemoryError::SnapshotBarrierActive)
        );
    }

    #[test]
    fn copyout_requires_write_permission_in_cached_fast_path() {
        let h = Harness::new();
        let mut fast_path = h.fast_path();
        fast_path.perms = GuestPerms::READ;

        assert_eq!(
            h.memory.copyout(&fast_path, SUBJECT, h.authority, &h.handle, &h.ledger),
            Err(GuestMemoryError::PermissionDenied)
        );
    }

    #[test]
    fn snapshot_barrier_rejects_active_dmw_leases() {
        let mut h = Harness::new();
        h.memory.open_dmw_lease();
        h.memory.open_dmw_lease();

        assert_eq!(h.memory.snapshot_barrier(), Err(GuestMemoryError::ActiveDmwLease));
        assert_eq!(h.memory.active_dmw_leases(), 2);
    }

    #[test]
    fn snapshot_barrier_freezes_page_object_generations() {
        let mut h = Harness::new();
        let report = h.memory.snapshot_barrier().expect("snapshot barrier");

        assert_eq!(report.frozen_pages.len(), 1);
        assert_eq!(report.released_dmw_leases, 0);
        assert_eq!(report.frozen_pages[0].page, h.page);
        assert_eq!(report.frozen_pages[0].dirty_generation, 1);
        assert_eq!(
            h.memory.copyin(&h.fast_path(), SUBJECT, h.authority, &h.handle, &h.ledger),
            Err(GuestMemoryError::SnapshotBarrierActive)
        );
    }

    #[test]
    fn pending_cleanup_rejects_user_buffer_fast_path() {
        let mut h = Harness::new();
        let fast_path = h.fast_path();
        h.memory.begin_cleanup_for_store(h.store);

        assert_eq!(
            h.memory.copyin(&fast_path, SUBJECT, h.authority, &h.handle, &h.ledger),
            Err(GuestMemoryError::PendingCleanup)
        );
    }

    #[test]
    fn trap_history_preserves_dead_page_object_generation() {
        let mut h = Harness::new();
        h.memory.record_page_fault(h.page, "copyin-efault");
        h.memory.retire_page(h.page).expect("retire page");

        assert_eq!(h.memory.fault_history()[0].page, h.page);
        assert!(h.memory.fault_history()[0].historical);
    }

    #[test]
    fn substrate_mapping_rebuilt_from_semantic_guest_memory() {
        let h = Harness::new();

        let mappings = h.memory.rebuild_substrate_mappings(h.aspace).expect("rebuild mappings");

        assert_eq!(mappings.len(), 1);
        assert_eq!(mappings[0].aspace, h.aspace);
        assert_eq!(mappings[0].region, h.region);
        assert_eq!(mappings[0].page, h.page);
        assert_eq!(mappings[0].source, "rebuilt-from-semantic-guest-memory");
    }
}
