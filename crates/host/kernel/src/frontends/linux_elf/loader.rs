use alloc::{vec, vec::Vec};
use core::slice;

use bootloader_api::BootInfo;
use substrate_api::{PageTableAuthority, SubstrateError, SubstrateResult};
use x86_64::{
    PhysAddr, VirtAddr,
    registers::control::Cr3,
    structures::paging::{
        FrameAllocator, Mapper, OffsetPageTable, Page, PageTable, PageTableFlags, PhysFrame,
        Size4KiB,
        mapper::{FlagUpdateError, MapToError, UnmapError},
    },
};
use xmas_elf::{ElfFile, header::Type as ElfType, program::Type as ProgramType};

use super::context::{
    LoadedUserImage, UserFrameAllocator, UserPageBacking, UserPageMapping, UserRegion,
};
use crate::supervisor::{linux_user_resource_bytes_for_path, types::DEFAULT_RLIMIT_STACK_BYTES};

const LIVE_PAGE_TABLE_AUTHORITY: &str = "LiveUserPageTableAuthority";
const PAGE_SIZE: usize = 4096;
const USER_STACK_PAGES: usize = 2048;
const USER_STACK_TOP: u64 = 0x0000_0000_7000_0000;
const USER_STACK_BYTES: u64 = (USER_STACK_PAGES * PAGE_SIZE) as u64;
const USER_PIE_BASE: u64 = 0x0000_0000_4000_0000;
const USER_INTERP_BASE: u64 = 0x0000_0000_5000_0000;
pub(crate) const USER_MMAP_BASE: u64 = 0x0000_0000_6000_0000;
pub(crate) const USER_MMAP_PAGES: usize = 4096;
pub(crate) const USER_MMAP_END: u64 = USER_MMAP_BASE + (USER_MMAP_PAGES * PAGE_SIZE) as u64;
pub(crate) const USER_BRK_BASE: u64 = USER_MMAP_BASE;
pub(crate) const USER_BRK_END: u64 = USER_BRK_BASE + 0x0020_0000;
pub(crate) const USER_MMAP_ALLOC_BASE: u64 = USER_BRK_END;
const AT_NULL: u64 = 0;
const AT_PHDR: u64 = 3;
const AT_PHENT: u64 = 4;
const AT_PHNUM: u64 = 5;
const AT_PAGESZ: u64 = 6;
const AT_BASE: u64 = 7;
const AT_FLAGS: u64 = 8;
const AT_ENTRY: u64 = 9;
const AT_UID: u64 = 11;
const AT_EUID: u64 = 12;
const AT_GID: u64 = 13;
const AT_EGID: u64 = 14;
const AT_PLATFORM: u64 = 15;
const AT_CLKTCK: u64 = 17;
const AT_SECURE: u64 = 23;
const AT_RANDOM: u64 = 25;
const AT_EXECFN: u64 = 31;
const ELF_INTERPRETER_PATH_MAX: usize = 4096;

#[repr(align(8))]
struct AlignedElf<const N: usize>([u8; N]);

struct AlignedElfBuffer {
    words: Vec<u64>,
    len: usize,
}

impl AlignedElfBuffer {
    fn copy_from(bytes: &[u8]) -> Self {
        let mut words = vec![0u64; bytes.len().div_ceil(core::mem::size_of::<u64>())];
        let ptr = words.as_mut_ptr().cast::<u8>();
        unsafe {
            core::ptr::copy_nonoverlapping(bytes.as_ptr(), ptr, bytes.len());
        }
        Self { words, len: bytes.len() }
    }

    fn as_bytes(&self) -> &[u8] {
        unsafe { slice::from_raw_parts(self.words.as_ptr().cast::<u8>(), self.len) }
    }
}

static LINUX_USER_DEMO_ELF: AlignedElf<{ include_bytes!(env!("VMOS_LINUX_USER_DEMO_ELF")).len() }> =
    AlignedElf(*include_bytes!(env!("VMOS_LINUX_USER_DEMO_ELF")));

pub(crate) struct PreparedUserImage {
    pub(crate) entry: u64,
    pub(crate) stack_top: u64,
    pub(crate) regions: Vec<UserRegion>,
    pub(crate) page_mappings: Vec<UserPageMapping>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ExecStackCredentials {
    pub(crate) uid: u32,
    pub(crate) euid: u32,
    pub(crate) gid: u32,
    pub(crate) egid: u32,
    pub(crate) secure: bool,
}

impl ExecStackCredentials {
    fn root() -> Self {
        Self { uid: 0, euid: 0, gid: 0, egid: 0, secure: false }
    }
}

impl PreparedUserImage {
    pub(crate) fn release_frames(self, frame_allocator: &mut UserFrameAllocator) {
        release_prepared_page_mappings(frame_allocator, &self.page_mappings);
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct UserPageSwitchError {
    message: &'static str,
    next_mappings_cleaned: bool,
}

impl UserPageSwitchError {
    fn new(message: &'static str) -> Self {
        Self { message, next_mappings_cleaned: true }
    }

    fn with_next_cleanup(message: &'static str, next_mappings_cleaned: bool) -> Self {
        Self { message, next_mappings_cleaned }
    }

    pub(crate) fn message(self) -> &'static str {
        self.message
    }

    pub(crate) fn next_mappings_cleaned(self) -> bool {
        self.next_mappings_cleaned
    }
}

pub(crate) fn demo_program_host_path() -> &'static str {
    env!("VMOS_LINUX_USER_DEMO_ELF")
}

pub(crate) fn user_page_flags(prot: u64) -> PageTableFlags {
    const PROT_WRITE: u64 = 0x2;
    const PROT_EXEC: u64 = 0x4;

    let mut flags = PageTableFlags::PRESENT | PageTableFlags::USER_ACCESSIBLE;
    if prot & PROT_WRITE != 0 {
        flags |= PageTableFlags::WRITABLE;
    }
    if prot & PROT_EXEC == 0 {
        flags |= PageTableFlags::NO_EXECUTE;
    }
    flags
}

fn prot_is_none(prot: u64) -> bool {
    prot & 0x7 == 0
}

fn prot_allows_write(prot: u64) -> bool {
    prot & 0x2 != 0
}

struct LiveUserPageTableAuthority<'a, 'mapper> {
    mapper: &'a mut OffsetPageTable<'mapper>,
    frame_allocator: &'a mut UserFrameAllocator,
    phys_offset: VirtAddr,
}

impl PageTableAuthority for LiveUserPageTableAuthority<'_, '_> {
    fn alloc_frame(&mut self) -> SubstrateResult<u64> {
        self.frame_allocator.allocate_frame().map(|frame| frame.start_address().as_u64()).ok_or(
            SubstrateError::HardwareFault {
                authority: LIVE_PAGE_TABLE_AUTHORITY,
                detail: "out of usable frames",
            },
        )
    }

    fn map_page(
        &mut self,
        va: u64,
        phys: u64,
        writable: bool,
        executable: bool,
    ) -> SubstrateResult<()> {
        validate_page_aligned(va, "page")?;
        validate_page_aligned(phys, "page-frame")?;
        let page = Page::<Size4KiB>::containing_address(VirtAddr::new(va));
        let frame = PhysFrame::containing_address(PhysAddr::new(phys));
        let flags = page_flags_from_attrs(writable, executable);
        match unsafe { self.mapper.map_to(page, frame, flags, self.frame_allocator) } {
            Ok(flush) => {
                flush.flush();
                Ok(())
            }
            Err(MapToError::PageAlreadyMapped(_)) => {
                Err(SubstrateError::ContractViolation { detail: "virtual page already mapped" })
            }
            Err(MapToError::ParentEntryHugePage) => Err(SubstrateError::HardwareFault {
                authority: LIVE_PAGE_TABLE_AUTHORITY,
                detail: "page parent entry is a huge page",
            }),
            Err(MapToError::FrameAllocationFailed) => Err(SubstrateError::HardwareFault {
                authority: LIVE_PAGE_TABLE_AUTHORITY,
                detail: "page table frame allocation failed",
            }),
        }
    }

    fn unmap_page(&mut self, va: u64) -> SubstrateResult<()> {
        validate_page_aligned(va, "page")?;
        let page = Page::<Size4KiB>::containing_address(VirtAddr::new(va));
        match self.mapper.unmap(page) {
            Ok((_frame, flush)) => {
                flush.flush();
                Ok(())
            }
            Err(UnmapError::PageNotMapped) => {
                Err(SubstrateError::InvalidObject { object: "page-mapping" })
            }
            Err(UnmapError::ParentEntryHugePage) => Err(SubstrateError::HardwareFault {
                authority: LIVE_PAGE_TABLE_AUTHORITY,
                detail: "page parent entry is a huge page",
            }),
            Err(UnmapError::InvalidFrameAddress(_)) => Err(SubstrateError::HardwareFault {
                authority: LIVE_PAGE_TABLE_AUTHORITY,
                detail: "page has an invalid frame address",
            }),
        }
    }

    fn protect_page(&mut self, va: u64, writable: bool, executable: bool) -> SubstrateResult<()> {
        validate_page_aligned(va, "page")?;
        let page = Page::<Size4KiB>::containing_address(VirtAddr::new(va));
        let flags = page_flags_from_attrs(writable, executable);
        match unsafe { self.mapper.update_flags(page, flags) } {
            Ok(flush) => {
                flush.flush();
                Ok(())
            }
            Err(FlagUpdateError::PageNotMapped) => {
                Err(SubstrateError::InvalidObject { object: "page-mapping" })
            }
            Err(FlagUpdateError::ParentEntryHugePage) => Err(SubstrateError::HardwareFault {
                authority: LIVE_PAGE_TABLE_AUTHORITY,
                detail: "page parent entry is a huge page",
            }),
        }
    }

    fn copy_frame(&mut self, src_phys: u64, dst_phys: u64, len: usize) -> SubstrateResult<()> {
        validate_page_aligned(src_phys, "page-frame")?;
        validate_page_aligned(dst_phys, "page-frame")?;
        if len > PAGE_SIZE {
            return Err(SubstrateError::ContractViolation {
                detail: "page frame copy exceeds frame size",
            });
        }
        if len == 0 || src_phys == dst_phys {
            return Ok(());
        }
        let src_frame = PhysFrame::containing_address(PhysAddr::new(src_phys));
        let dst_frame = PhysFrame::containing_address(PhysAddr::new(dst_phys));
        let bytes = frame_bytes(src_frame, self.phys_offset)[..len].to_vec();
        frame_bytes(dst_frame, self.phys_offset)[..len].copy_from_slice(&bytes);
        Ok(())
    }

    fn flush_tlb(&mut self, va: u64) -> SubstrateResult<()> {
        validate_page_aligned(va, "page")?;
        x86_64::instructions::tlb::flush(VirtAddr::new(va));
        Ok(())
    }
}

fn validate_page_aligned(value: u64, object: &'static str) -> SubstrateResult<()> {
    if value == 0 || value % PAGE_SIZE as u64 != 0 {
        Err(SubstrateError::InvalidObject { object })
    } else {
        Ok(())
    }
}

fn page_flags_from_attrs(writable: bool, executable: bool) -> PageTableFlags {
    let mut flags = PageTableFlags::PRESENT | PageTableFlags::USER_ACCESSIBLE;
    if writable {
        flags |= PageTableFlags::WRITABLE;
    }
    if !executable {
        flags |= PageTableFlags::NO_EXECUTE;
    }
    flags
}

fn page_attrs_from_flags(flags: PageTableFlags) -> (bool, bool) {
    (flags.contains(PageTableFlags::WRITABLE), !flags.contains(PageTableFlags::NO_EXECUTE))
}

fn map_page_table_error(err: SubstrateError) -> &'static str {
    match err {
        SubstrateError::InvalidObject { object: "page-mapping" } => "user page is not mapped",
        SubstrateError::InvalidObject { object: "page" } => "user page range is not page aligned",
        SubstrateError::InvalidObject { object: "page-frame" } => {
            "user page has an invalid frame address"
        }
        SubstrateError::ContractViolation { detail } => detail,
        SubstrateError::HardwareFault { detail, .. } => detail,
        _ => "page table authority operation failed",
    }
}

fn is_page_not_mapped(err: &SubstrateError) -> bool {
    matches!(err, SubstrateError::InvalidObject { object: "page-mapping" })
}

pub(crate) fn protect_user_page_range(
    physical_memory_offset: u64,
    page_mappings: &mut Vec<UserPageMapping>,
    frame_allocator: &mut UserFrameAllocator,
    start: u64,
    len: u64,
    prot: u64,
) -> Result<(), &'static str> {
    let phys_offset = VirtAddr::new(physical_memory_offset);
    let level_4 = unsafe { active_level_4_table(phys_offset) };
    let mut mapper = unsafe { OffsetPageTable::new(level_4, phys_offset) };
    let mut authority =
        LiveUserPageTableAuthority { mapper: &mut mapper, frame_allocator, phys_offset };
    let flags = user_page_flags(prot);
    for page_addr in user_page_iter(start, len)? {
        if prot_is_none(prot) {
            if let Some(mapping) = user_page_mapping_mut(page_mappings, page_addr)
                && mapping.present
            {
                match authority.unmap_page(page_addr) {
                    Ok(()) => {
                        mapping.present = false;
                    }
                    Err(err) if is_page_not_mapped(&err) => mapping.present = false,
                    Err(err) => {
                        return Err(map_page_table_error(err));
                    }
                }
            }
            continue;
        }

        if let Some(mapping) = user_page_mapping_mut(page_mappings, page_addr) {
            if mapping.cow && prot_allows_write(prot) {
                break_user_cow_page_with_authority(&mut authority, page_addr, mapping, flags)?;
                continue;
            }
            let mapping_flags = user_page_flags_for_mapping(prot, mapping);
            if !mapping.present {
                if mapping.backing.is_file_backed() {
                    continue;
                }
                remap_user_page(&mut authority, page_addr, mapping, mapping_flags)?;
                continue;
            }
            let (writable, executable) = page_attrs_from_flags(mapping_flags);
            match authority.protect_page(page_addr, writable, executable) {
                Ok(()) => {}
                Err(err) if is_page_not_mapped(&err) => {
                    mapping.present = false;
                    remap_user_page(&mut authority, page_addr, mapping, mapping_flags)?;
                }
                Err(err) => {
                    return Err(map_page_table_error(err));
                }
            }
        } else {
            map_new_user_page(&mut authority, page_mappings, page_addr, flags)?;
        }
    }
    Ok(())
}

pub(crate) fn invalidate_user_page_mapping(
    physical_memory_offset: u64,
    page_mappings: &mut [UserPageMapping],
    frame_allocator: &mut UserFrameAllocator,
    page_addr: u64,
) -> Result<(), &'static str> {
    let Some(index) = page_mappings.iter().position(|mapping| mapping.va == page_addr) else {
        return Ok(());
    };

    if page_mappings[index].present {
        let phys_offset = VirtAddr::new(physical_memory_offset);
        let level_4 = unsafe { active_level_4_table(phys_offset) };
        let mut mapper = unsafe { OffsetPageTable::new(level_4, phys_offset) };
        let mut authority =
            LiveUserPageTableAuthority { mapper: &mut mapper, frame_allocator, phys_offset };
        match authority.unmap_page(page_addr) {
            Ok(()) => {}
            Err(err) if is_page_not_mapped(&err) => {}
            Err(err) => return Err(map_page_table_error(err)),
        }
    }

    let mapping = &mut page_mappings[index];
    if mapping.owned && mapping.frame_start != 0 {
        frame_allocator
            .deallocate_frame(PhysFrame::containing_address(PhysAddr::new(mapping.frame_start)));
    }
    mapping.frame_start = 0;
    mapping.present = false;
    mapping.owned = false;
    mapping.cow = false;
    Ok(())
}

pub(crate) fn prefault_user_page_range(
    physical_memory_offset: u64,
    page_mappings: &mut Vec<UserPageMapping>,
    frame_allocator: &mut UserFrameAllocator,
    start: u64,
    len: u64,
    prot: u64,
    write: bool,
) -> Result<(), &'static str> {
    if prot_is_none(prot) {
        return Err("user page range is not accessible");
    }
    let phys_offset = VirtAddr::new(physical_memory_offset);
    let level_4 = unsafe { active_level_4_table(phys_offset) };
    let mut mapper = unsafe { OffsetPageTable::new(level_4, phys_offset) };
    let mut authority =
        LiveUserPageTableAuthority { mapper: &mut mapper, frame_allocator, phys_offset };
    let flags = user_page_flags(prot);
    for page_addr in user_page_iter(start, len)? {
        if let Some(mapping) = user_page_mapping_mut(page_mappings, page_addr) {
            if write && mapping.cow {
                break_user_cow_page_with_authority(&mut authority, page_addr, mapping, flags)?;
                continue;
            }
            if mapping.present {
                if write {
                    let (writable, executable) = page_attrs_from_flags(flags);
                    match authority.protect_page(page_addr, writable, executable) {
                        Ok(()) => {}
                        Err(err) if is_page_not_mapped(&err) => {
                            mapping.present = false;
                            remap_user_page(&mut authority, page_addr, mapping, flags)?;
                        }
                        Err(err) => return Err(map_page_table_error(err)),
                    }
                }
                continue;
            }
            let mapping_flags = user_page_flags_for_mapping(prot, mapping);
            remap_user_page(&mut authority, page_addr, mapping, mapping_flags)?;
        } else {
            map_new_user_page(&mut authority, page_mappings, page_addr, flags)?;
        }
    }
    Ok(())
}

pub(crate) fn unmap_user_page_range(
    physical_memory_offset: u64,
    page_mappings: &mut Vec<UserPageMapping>,
    frame_allocator: &mut UserFrameAllocator,
    start: u64,
    len: u64,
) -> Result<(), &'static str> {
    let end = start.checked_add(len).ok_or("user page range overflowed")?;
    let phys_offset = VirtAddr::new(physical_memory_offset);
    let level_4 = unsafe { active_level_4_table(phys_offset) };
    let mut mapper = unsafe { OffsetPageTable::new(level_4, phys_offset) };
    {
        let mut authority =
            LiveUserPageTableAuthority { mapper: &mut mapper, frame_allocator, phys_offset };
        for page_addr in user_page_iter(start, len)? {
            match authority.unmap_page(page_addr) {
                Ok(()) => {}
                Err(err) if is_page_not_mapped(&err) => {}
                Err(err) => {
                    return Err(map_page_table_error(err));
                }
            }
        }
    }
    let mut retained = Vec::new();
    for mapping in page_mappings.drain(..) {
        if mapping.va >= start && mapping.va < end {
            if mapping.owned && mapping.frame_start != 0 {
                frame_allocator.deallocate_frame(PhysFrame::containing_address(PhysAddr::new(
                    mapping.frame_start,
                )));
            }
        } else {
            retained.push(mapping);
        }
    }
    *page_mappings = retained;
    Ok(())
}

pub(crate) fn clone_user_page_mappings(
    page_mappings: &[UserPageMapping],
) -> Result<Vec<UserPageMapping>, &'static str> {
    let mut cloned = Vec::with_capacity(page_mappings.len());
    for mapping in page_mappings {
        cloned.push(UserPageMapping {
            va: mapping.va,
            frame_start: mapping.frame_start,
            present: mapping.present,
            owned: false,
            cow: mapping.frame_start != 0 && !mapping.backing.is_file_shared(),
            backing: mapping.backing.clone(),
        });
    }
    Ok(cloned)
}

pub(crate) fn switch_user_page_mappings(
    physical_memory_offset: u64,
    current_mappings: &[UserPageMapping],
    current_regions: &[UserRegion],
    next_mappings: &[UserPageMapping],
    next_regions: &[UserRegion],
    frame_allocator: &mut UserFrameAllocator,
    reclaim_current: bool,
) -> Result<(), UserPageSwitchError> {
    let phys_offset = VirtAddr::new(physical_memory_offset);
    let level_4 = unsafe { active_level_4_table(phys_offset) };
    let mut mapper = unsafe { OffsetPageTable::new(level_4, phys_offset) };
    let mut authority =
        LiveUserPageTableAuthority { mapper: &mut mapper, frame_allocator, phys_offset };

    for mapping in next_mappings.iter().filter(|mapping| mapping.present) {
        if user_page_region_prot(next_regions, mapping.va).is_none() {
            return Err(UserPageSwitchError::new("next user page has no region"));
        }
    }
    for mapping in current_mappings.iter().filter(|mapping| mapping.present) {
        if user_page_region_prot(current_regions, mapping.va).is_none() {
            return Err(UserPageSwitchError::new("current user page has no region"));
        }
    }

    let mut unmapped_current = Vec::new();
    for mapping in current_mappings.iter().filter(|mapping| mapping.present) {
        match authority.unmap_page(mapping.va) {
            Ok(()) => {
                unmapped_current.push(mapping.va);
            }
            Err(err) if is_page_not_mapped(&err) => {
                unmapped_current.push(mapping.va);
            }
            Err(err) => {
                let rollback_err = remap_user_page_mappings(
                    &mut authority,
                    current_mappings,
                    current_regions,
                    &unmapped_current,
                )
                .err();
                if let Some(rollback_err) = rollback_err {
                    crate::kwarn!("user page switch rollback failed: {}", rollback_err);
                }
                return Err(UserPageSwitchError::new(map_page_table_error(err)));
            }
        }
    }

    let mut mapped_next = Vec::new();
    for mapping in next_mappings.iter().filter(|mapping| mapping.present) {
        let prot = user_page_region_prot(next_regions, mapping.va)
            .ok_or_else(|| UserPageSwitchError::new("next user page has no region"))?;
        let flags = user_page_flags_for_mapping(prot, mapping);
        let (writable, executable) = page_attrs_from_flags(flags);
        if let Err(err) = authority.map_page(mapping.va, mapping.frame_start, writable, executable)
        {
            let switch_err = map_page_table_error(err);
            let next_mappings_cleaned =
                unmap_user_page_mappings(&mut authority, &mapped_next).is_ok();
            let rollback_err = remap_user_page_mappings(
                &mut authority,
                current_mappings,
                current_regions,
                &unmapped_current,
            )
            .err();
            if let Some(rollback_err) = rollback_err {
                crate::kwarn!("user page switch rollback failed: {}", rollback_err);
            }
            return Err(UserPageSwitchError::with_next_cleanup(switch_err, next_mappings_cleaned));
        }
        mapped_next.push(mapping.va);
    }

    if reclaim_current {
        for mapping in current_mappings {
            if mapping.owned && mapping.frame_start != 0 {
                authority.frame_allocator.deallocate_frame(PhysFrame::containing_address(
                    PhysAddr::new(mapping.frame_start),
                ));
            }
        }
    }
    Ok(())
}

fn remap_user_page_mappings(
    authority: &mut LiveUserPageTableAuthority<'_, '_>,
    mappings: &[UserPageMapping],
    regions: &[UserRegion],
    mapped_pages: &[u64],
) -> Result<(), &'static str> {
    for mapping in mappings.iter().filter(|mapping| {
        mapping.present && mapped_pages.iter().any(|page_addr| *page_addr == mapping.va)
    }) {
        let prot = user_page_region_prot(regions, mapping.va).ok_or("user page has no region")?;
        let flags = user_page_flags_for_mapping(prot, mapping);
        let (writable, executable) = page_attrs_from_flags(flags);
        authority
            .map_page(mapping.va, mapping.frame_start, writable, executable)
            .map_err(map_page_table_error)?;
    }
    Ok(())
}

fn unmap_user_page_mappings(
    authority: &mut LiveUserPageTableAuthority<'_, '_>,
    mapped_pages: &[u64],
) -> Result<(), &'static str> {
    let mut first_error = None;
    for page_addr in mapped_pages {
        match authority.unmap_page(*page_addr) {
            Ok(()) | Err(SubstrateError::InvalidObject { object: "page-mapping" }) => {}
            Err(err) => {
                let err = map_page_table_error(err);
                crate::kwarn!("user page switch cleanup failed: {}", err);
                if first_error.is_none() {
                    first_error = Some(err);
                }
            }
        }
    }
    if let Some(err) = first_error { Err(err) } else { Ok(()) }
}

pub(crate) fn cow_break_user_page(
    physical_memory_offset: u64,
    page_mappings: &mut [UserPageMapping],
    frame_allocator: &mut UserFrameAllocator,
    page_addr: u64,
    prot: u64,
) -> Result<(), &'static str> {
    let phys_offset = VirtAddr::new(physical_memory_offset);
    let level_4 = unsafe { active_level_4_table(phys_offset) };
    let mut mapper = unsafe { OffsetPageTable::new(level_4, phys_offset) };
    let mut authority =
        LiveUserPageTableAuthority { mapper: &mut mapper, frame_allocator, phys_offset };
    let mapping = user_page_mapping_mut(page_mappings, page_addr).ok_or("missing COW page")?;
    let flags = user_page_flags(prot);
    break_user_cow_page_with_authority(&mut authority, page_addr, mapping, flags)
}

pub(crate) fn discard_user_page_range(
    physical_memory_offset: u64,
    page_mappings: &mut Vec<UserPageMapping>,
    frame_allocator: &mut UserFrameAllocator,
    start: u64,
    len: u64,
) -> Result<(), &'static str> {
    discard_user_page_range_with_policy(
        physical_memory_offset,
        page_mappings,
        frame_allocator,
        start,
        len,
        DiscardPolicy::Discardable,
    )
}

pub(crate) fn discard_zero_user_page_range(
    physical_memory_offset: u64,
    page_mappings: &mut Vec<UserPageMapping>,
    frame_allocator: &mut UserFrameAllocator,
    start: u64,
    len: u64,
) -> Result<(), &'static str> {
    discard_user_page_range_with_policy(
        physical_memory_offset,
        page_mappings,
        frame_allocator,
        start,
        len,
        DiscardPolicy::ZeroFillOnly,
    )
}

enum DiscardPolicy {
    Discardable,
    ZeroFillOnly,
}

fn discard_user_page_range_with_policy(
    physical_memory_offset: u64,
    page_mappings: &mut Vec<UserPageMapping>,
    frame_allocator: &mut UserFrameAllocator,
    start: u64,
    len: u64,
    policy: DiscardPolicy,
) -> Result<(), &'static str> {
    let end = start.checked_add(len).ok_or("user page range overflowed")?;
    for mapping in page_mappings.iter().filter(|mapping| mapping.va >= start && mapping.va < end) {
        match (&policy, &mapping.backing) {
            (DiscardPolicy::Discardable, backing) if backing.is_discardable() => {}
            (DiscardPolicy::ZeroFillOnly, UserPageBacking::ZeroFill) => {}
            (DiscardPolicy::ZeroFillOnly, _) => {
                return Err("user page range has non-zero-fill backing");
            }
            (DiscardPolicy::Discardable, _) => {
                return Err("user page range has non-discardable backing");
            }
        }
    }

    let phys_offset = VirtAddr::new(physical_memory_offset);
    let level_4 = unsafe { active_level_4_table(phys_offset) };
    let mut mapper = unsafe { OffsetPageTable::new(level_4, phys_offset) };
    {
        let mut authority =
            LiveUserPageTableAuthority { mapper: &mut mapper, frame_allocator, phys_offset };
        for mapping in page_mappings
            .iter()
            .filter(|mapping| mapping.va >= start && mapping.va < end && mapping.present)
        {
            match authority.unmap_page(mapping.va) {
                Ok(()) => {}
                Err(err) if is_page_not_mapped(&err) => {}
                Err(err) => return Err(map_page_table_error(err)),
            }
        }
    }

    let mut retained = Vec::new();
    for mut mapping in page_mappings.drain(..) {
        if mapping.va >= start && mapping.va < end {
            if mapping.owned && mapping.frame_start != 0 {
                frame_allocator.deallocate_frame(PhysFrame::containing_address(PhysAddr::new(
                    mapping.frame_start,
                )));
            }
            if matches!(&mapping.backing, UserPageBacking::FilePrivate { .. }) {
                mapping.frame_start = 0;
                mapping.present = false;
                mapping.owned = false;
                mapping.cow = false;
                retained.push(mapping);
            }
        } else {
            retained.push(mapping);
        }
    }
    *page_mappings = retained;
    Ok(())
}

fn break_user_cow_page_with_authority(
    authority: &mut LiveUserPageTableAuthority<'_, '_>,
    page_addr: u64,
    mapping: &mut UserPageMapping,
    flags: PageTableFlags,
) -> Result<(), &'static str> {
    if !mapping.cow {
        return Err("user page is not COW");
    }

    let old_frame_start = mapping.frame_start;
    if old_frame_start == 0 {
        return Err("COW page has no physical frame");
    }
    let old_present = mapping.present;
    let old_owned = mapping.owned;
    let old_cow = mapping.cow;
    let new_frame = authority.alloc_frame().map_err(map_page_table_error)?;
    authority.copy_frame(old_frame_start, new_frame, PAGE_SIZE).map_err(map_page_table_error)?;

    if old_present {
        match authority.unmap_page(page_addr) {
            Ok(()) => {}
            Err(err) if is_page_not_mapped(&err) => {}
            Err(err) => {
                authority
                    .frame_allocator
                    .deallocate_frame(PhysFrame::containing_address(PhysAddr::new(new_frame)));
                return Err(map_page_table_error(err));
            }
        }
    }

    mapping.frame_start = new_frame;
    mapping.present = false;
    mapping.owned = true;
    mapping.cow = false;
    if let Err(err) = remap_user_page(authority, page_addr, mapping, flags) {
        authority
            .frame_allocator
            .deallocate_frame(PhysFrame::containing_address(PhysAddr::new(new_frame)));
        mapping.frame_start = old_frame_start;
        mapping.present = false;
        mapping.owned = old_owned;
        mapping.cow = old_cow;
        return Err(err);
    }
    Ok(())
}

fn user_page_flags_for_mapping(prot: u64, mapping: &UserPageMapping) -> PageTableFlags {
    let mut flags = user_page_flags(prot);
    if mapping.cow {
        flags.remove(PageTableFlags::WRITABLE);
    }
    flags
}

fn user_page_region_prot(regions: &[UserRegion], page: u64) -> Option<u64> {
    let region = regions.iter().rev().find(|region| {
        page >= region.start
            && page < region.end
            && (region.readable || region.writable || region.executable)
    })?;
    let mut prot = 0;
    if region.readable || region.writable {
        prot |= 0x1;
    }
    if region.writable {
        prot |= 0x2;
    }
    if region.executable {
        prot |= 0x4;
    }
    Some(prot)
}

fn user_page_mapping_mut(
    page_mappings: &mut [UserPageMapping],
    page_addr: u64,
) -> Option<&mut UserPageMapping> {
    page_mappings.iter_mut().find(|mapping| mapping.va == page_addr)
}

fn remap_user_page(
    authority: &mut LiveUserPageTableAuthority<'_, '_>,
    page_addr: u64,
    mapping: &mut UserPageMapping,
    flags: PageTableFlags,
) -> Result<(), &'static str> {
    let allocated = materialize_user_page_frame(authority, mapping)?;
    let (writable, executable) = page_attrs_from_flags(flags);
    match authority.map_page(page_addr, mapping.frame_start, writable, executable) {
        Ok(()) => {
            mapping.present = true;
            Ok(())
        }
        Err(SubstrateError::ContractViolation { detail: "virtual page already mapped" }) => {
            if allocated {
                discard_materialized_user_page_frame(authority, mapping);
                return Err("virtual page already mapped while materializing discarded page");
            }
            mapping.present = true;
            match authority.protect_page(page_addr, writable, executable) {
                Ok(()) => Ok(()),
                Err(err) => Err(map_page_table_error(err)),
            }
        }
        Err(err) => {
            if allocated {
                discard_materialized_user_page_frame(authority, mapping);
            }
            Err(map_page_table_error(err))
        }
    }
}

fn materialize_user_page_frame(
    authority: &mut LiveUserPageTableAuthority<'_, '_>,
    mapping: &mut UserPageMapping,
) -> Result<bool, &'static str> {
    if mapping.backing.is_invalid_file_page() {
        return Err("file-backed user page is beyond EOF");
    }
    if mapping.frame_start != 0 {
        return Ok(false);
    }

    let frame_start = authority.alloc_frame().map_err(map_page_table_error)?;
    let frame = PhysFrame::containing_address(PhysAddr::new(frame_start));
    let dest = frame_bytes(frame, authority.phys_offset);
    match &mapping.backing {
        UserPageBacking::ZeroFill => dest.fill(0),
        UserPageBacking::FilePrivate { bytes, valid } => {
            if !valid {
                authority.frame_allocator.deallocate_frame(frame);
                return Err("file-backed user page is beyond EOF");
            }
            dest.fill(0);
            let copy_len = core::cmp::min(bytes.len(), PAGE_SIZE);
            dest[..copy_len].copy_from_slice(&bytes[..copy_len]);
        }
        UserPageBacking::FileShared { bytes, valid, .. } => {
            if !valid {
                authority.frame_allocator.deallocate_frame(frame);
                return Err("file-backed user page is beyond EOF");
            }
            dest.fill(0);
            let copy_len = core::cmp::min(bytes.len(), PAGE_SIZE);
            dest[..copy_len].copy_from_slice(&bytes[..copy_len]);
        }
        UserPageBacking::Preserve => {
            authority.frame_allocator.deallocate_frame(frame);
            return Err("preserved user page lost its physical frame");
        }
    }
    mapping.frame_start = frame_start;
    mapping.owned = true;
    mapping.cow = false;
    Ok(true)
}

fn discard_materialized_user_page_frame(
    authority: &mut LiveUserPageTableAuthority<'_, '_>,
    mapping: &mut UserPageMapping,
) {
    if mapping.frame_start != 0 {
        authority
            .frame_allocator
            .deallocate_frame(PhysFrame::containing_address(PhysAddr::new(mapping.frame_start)));
    }
    mapping.frame_start = 0;
    mapping.present = false;
    mapping.owned = false;
    mapping.cow = false;
}

fn map_new_user_page(
    authority: &mut LiveUserPageTableAuthority<'_, '_>,
    page_mappings: &mut Vec<UserPageMapping>,
    page_addr: u64,
    flags: PageTableFlags,
) -> Result<(), &'static str> {
    let frame_start = authority.alloc_frame().map_err(map_page_table_error)?;
    let (writable, executable) = page_attrs_from_flags(flags);
    match authority.map_page(page_addr, frame_start, writable, executable) {
        Ok(()) => {
            frame_bytes(
                PhysFrame::containing_address(PhysAddr::new(frame_start)),
                authority.phys_offset,
            )
            .fill(0);
            page_mappings.push(UserPageMapping {
                va: page_addr,
                frame_start,
                present: true,
                owned: true,
                cow: false,
                backing: UserPageBacking::ZeroFill,
            });
            Ok(())
        }
        Err(err) => {
            authority
                .frame_allocator
                .deallocate_frame(PhysFrame::containing_address(PhysAddr::new(frame_start)));
            Err(map_page_table_error(err))
        }
    }
}

pub(crate) fn load_demo_program(
    boot_info: &'static BootInfo,
) -> Result<LoadedUserImage, &'static str> {
    load_user_program(boot_info, &LINUX_USER_DEMO_ELF.0)
}

pub(crate) fn user_elf_interpreter_path(bytes: &[u8]) -> Result<Option<Vec<u8>>, &'static str> {
    let aligned = AlignedElfBuffer::copy_from(bytes);
    let elf = ElfFile::new(aligned.as_bytes()).map_err(|_| "user ELF was invalid")?;
    let mut interpreter = None;
    for ph in elf.program_iter() {
        if ph.get_type() != Ok(ProgramType::Interp) {
            continue;
        }
        if interpreter.is_some() {
            return Err("user ELF has multiple interpreters");
        }
        let file_start =
            usize::try_from(ph.offset()).map_err(|_| "user ELF interpreter offset overflowed")?;
        let file_size =
            usize::try_from(ph.file_size()).map_err(|_| "user ELF interpreter size overflowed")?;
        if file_size == 0 || file_size > ELF_INTERPRETER_PATH_MAX {
            return Err("user ELF interpreter path invalid");
        }
        let file_end =
            file_start.checked_add(file_size).ok_or("user ELF interpreter range overflowed")?;
        let raw = bytes.get(file_start..file_end).ok_or("user ELF interpreter outside image")?;
        let nul =
            raw.iter().position(|byte| *byte == 0).ok_or("user ELF interpreter path invalid")?;
        let path = &raw[..nul];
        if path.is_empty() || path[0] != b'/' {
            return Err("user ELF interpreter path invalid");
        }
        interpreter = Some(path.to_vec());
    }
    Ok(interpreter)
}

pub(crate) fn prepare_user_program(
    physical_memory_offset: u64,
    frame_allocator: &mut UserFrameAllocator,
    bytes: &[u8],
    interpreter: Option<&[u8]>,
    argv: &[Vec<u8>],
    envp: &[Vec<u8>],
    execfn: &[u8],
    stack_limit: u64,
    stack_credentials: ExecStackCredentials,
) -> Result<PreparedUserImage, &'static str> {
    let phys_offset = VirtAddr::new(physical_memory_offset);
    let aligned = AlignedElfBuffer::copy_from(bytes);
    let elf = ElfFile::new(aligned.as_bytes()).map_err(|_| "user ELF was invalid")?;
    let mut regions = Vec::new();
    let mut page_mappings = Vec::new();

    let result = prepare_user_program_inner(
        phys_offset,
        frame_allocator,
        bytes,
        &elf,
        interpreter,
        argv,
        envp,
        execfn,
        stack_limit,
        stack_credentials,
        &mut regions,
        &mut page_mappings,
    );
    match result {
        Ok((entry, stack_top)) => {
            Ok(PreparedUserImage { entry, stack_top, regions, page_mappings })
        }
        Err(err) => {
            release_prepared_page_mappings(frame_allocator, &page_mappings);
            Err(err)
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn prepare_user_program_inner(
    phys_offset: VirtAddr,
    frame_allocator: &mut UserFrameAllocator,
    bytes: &[u8],
    elf: &ElfFile<'_>,
    interpreter: Option<&[u8]>,
    argv: &[Vec<u8>],
    envp: &[Vec<u8>],
    execfn: &[u8],
    stack_limit: u64,
    stack_credentials: ExecStackCredentials,
    regions: &mut Vec<UserRegion>,
    page_mappings: &mut Vec<UserPageMapping>,
) -> Result<(u64, u64), &'static str> {
    let main_interpreter = user_elf_interpreter_path(bytes)?;
    match (main_interpreter.is_some(), interpreter.is_some()) {
        (true, false) => return Err("user ELF interpreter missing"),
        (false, true) => return Err("user ELF interpreter provided for static image"),
        _ => {}
    }

    let main_load_bias = elf_load_bias(elf, USER_PIE_BASE)?;
    prepare_user_load_segments(
        frame_allocator,
        page_mappings,
        phys_offset,
        bytes,
        elf,
        main_load_bias,
        regions,
    )?;

    let main_entry = biased_addr(elf.header.pt2.entry_point(), main_load_bias)?;
    let (entry, at_base) = if let Some(interpreter_bytes) = interpreter {
        let aligned_interpreter = AlignedElfBuffer::copy_from(interpreter_bytes);
        let interpreter_elf = ElfFile::new(aligned_interpreter.as_bytes())
            .map_err(|_| "user ELF interpreter invalid")?;
        if user_elf_interpreter_path(interpreter_bytes)?.is_some() {
            return Err("user ELF interpreter nested");
        }
        let interpreter_load_bias = elf_interpreter_load_bias(&interpreter_elf)?;
        prepare_user_load_segments(
            frame_allocator,
            page_mappings,
            phys_offset,
            interpreter_bytes,
            &interpreter_elf,
            interpreter_load_bias,
            regions,
        )?;
        (
            biased_addr(interpreter_elf.header.pt2.entry_point(), interpreter_load_bias)?,
            interpreter_load_bias,
        )
    } else {
        (main_entry, 0)
    };

    let stack_pages = stack_pages_for_rlimit(stack_limit)?;
    let stack_base = stack_base_for_pages(stack_pages);
    let initial_stack = build_exec_stack(
        elf,
        main_load_bias,
        at_base,
        main_entry,
        argv,
        envp,
        execfn,
        stack_credentials,
    )?;
    prepare_user_stack(frame_allocator, page_mappings, phys_offset, &initial_stack, stack_pages)?;
    regions.push(UserRegion {
        start: stack_base,
        end: USER_STACK_TOP,
        readable: true,
        writable: true,
        executable: false,
        dont_fork: false,
        wipe_on_fork: false,
    });

    Ok((entry, initial_stack.stack_pointer))
}

#[allow(clippy::too_many_arguments)]
fn prepare_user_load_segments(
    frame_allocator: &mut UserFrameAllocator,
    page_mappings: &mut Vec<UserPageMapping>,
    phys_offset: VirtAddr,
    bytes: &[u8],
    elf: &ElfFile<'_>,
    load_bias: u64,
    regions: &mut Vec<UserRegion>,
) -> Result<(), &'static str> {
    for ph in elf.program_iter() {
        if ph.get_type() != Ok(ProgramType::Load) {
            continue;
        }

        let virt_start = biased_addr(ph.virtual_addr(), load_bias)?;
        let virt_end =
            virt_start.checked_add(ph.mem_size()).ok_or("user ELF segment overflowed")?;
        let file_start = usize::try_from(ph.offset()).map_err(|_| "user ELF offset overflowed")?;
        let file_size =
            usize::try_from(ph.file_size()).map_err(|_| "user ELF file size overflowed")?;
        if ph.file_size() > ph.mem_size() {
            return Err("user ELF segment file exceeds memory size");
        }
        let file_end = file_start.checked_add(file_size).ok_or("user ELF file range overflowed")?;
        let segment_bytes =
            bytes.get(file_start..file_end).ok_or("user ELF referenced bytes outside the image")?;

        prepare_user_pages(
            frame_allocator,
            page_mappings,
            phys_offset,
            virt_start,
            virt_end,
            segment_bytes,
        )?;

        regions.push(UserRegion {
            start: virt_start & !(PAGE_SIZE as u64 - 1),
            end: align_up(virt_end as usize, PAGE_SIZE) as u64,
            readable: ph.flags().is_read(),
            writable: ph.flags().is_write(),
            executable: ph.flags().is_execute(),
            dont_fork: false,
            wipe_on_fork: false,
        });
    }
    Ok(())
}

fn load_user_program(
    boot_info: &'static BootInfo,
    bytes: &[u8],
) -> Result<LoadedUserImage, &'static str> {
    let physical_memory_offset = boot_info
        .physical_memory_offset
        .as_ref()
        .copied()
        .ok_or("bootloader did not provide physical_memory_offset")?;
    let mut frame_allocator = UserFrameAllocator::new(&boot_info.memory_regions);

    let interpreter_path = user_elf_interpreter_path(bytes)?;
    let interpreter_bytes = interpreter_path
        .as_deref()
        .map(|path| {
            linux_user_resource_bytes_for_path(path).ok_or("initial user ELF interpreter missing")
        })
        .transpose()?;
    let argv = vec![b"/bin/vmos-ltp".to_vec()];
    let envp = vec![
        b"KCONFIG_SKIP_CHECK=1".to_vec(),
        b"LTP_DEV=/dev/loop0".to_vec(),
        b"LTP_SINGLE_FS_TYPE=tmpfs".to_vec(),
    ];
    let image = prepare_user_program(
        physical_memory_offset,
        &mut frame_allocator,
        bytes,
        interpreter_bytes,
        &argv,
        &envp,
        b"/bin/vmos-ltp",
        DEFAULT_RLIMIT_STACK_BYTES,
        ExecStackCredentials::root(),
    )?;
    if let Err(err) = switch_user_page_mappings(
        physical_memory_offset,
        &[],
        &[],
        &image.page_mappings,
        &image.regions,
        &mut frame_allocator,
        false,
    ) {
        image.release_frames(&mut frame_allocator);
        crate::kwarn!("initial user page-table switch failed: {}", err.message());
        return Err("failed to map initial user image");
    }

    Ok(LoadedUserImage {
        entry: image.entry,
        stack_top: image.stack_top,
        regions: image.regions,
        page_mappings: image.page_mappings,
        frame_allocator,
    })
}

fn prepare_user_pages(
    frame_allocator: &mut UserFrameAllocator,
    page_mappings: &mut Vec<UserPageMapping>,
    phys_offset: VirtAddr,
    virt_start: u64,
    virt_end: u64,
    file_bytes: &[u8],
) -> Result<(), &'static str> {
    let page_start = virt_start & !(PAGE_SIZE as u64 - 1);
    let page_end = align_up(virt_end as usize, PAGE_SIZE) as u64;

    for page_addr in (page_start..page_end).step_by(PAGE_SIZE) {
        let frame =
            frame_allocator.allocate_frame().ok_or("out of usable frames for user image")?;
        page_mappings.push(UserPageMapping {
            va: page_addr,
            frame_start: frame.start_address().as_u64(),
            present: true,
            owned: true,
            cow: false,
            backing: UserPageBacking::Preserve,
        });

        let dest = frame_bytes(frame, phys_offset);
        dest.fill(0);

        let copy_start = core::cmp::max(page_addr, virt_start);
        let copy_end =
            core::cmp::min(page_addr + PAGE_SIZE as u64, virt_start + file_bytes.len() as u64);
        if copy_start < copy_end {
            let file_offset = (copy_start - virt_start) as usize;
            let page_offset = (copy_start - page_addr) as usize;
            let copy_len = (copy_end - copy_start) as usize;
            dest[page_offset..page_offset + copy_len]
                .copy_from_slice(&file_bytes[file_offset..file_offset + copy_len]);
        }
    }

    Ok(())
}

fn prepare_user_stack(
    frame_allocator: &mut UserFrameAllocator,
    page_mappings: &mut Vec<UserPageMapping>,
    phys_offset: VirtAddr,
    initial_stack: &InitialStack,
    stack_pages: usize,
) -> Result<(), &'static str> {
    let stack_base = stack_base_for_pages(stack_pages);
    for index in 0..stack_pages {
        let addr = stack_base + (index * PAGE_SIZE) as u64;
        let frame =
            frame_allocator.allocate_frame().ok_or("out of usable frames for user stack")?;
        page_mappings.push(UserPageMapping {
            va: addr,
            frame_start: frame.start_address().as_u64(),
            present: true,
            owned: true,
            cow: false,
            backing: UserPageBacking::ZeroFill,
        });
        let dest = frame_bytes(frame, phys_offset);
        dest.fill(0);
        if addr == initial_stack.page_base {
            dest.copy_from_slice(&initial_stack.page_bytes);
        }
    }

    Ok(())
}

fn stack_pages_for_rlimit(limit: u64) -> Result<usize, &'static str> {
    let bounded = limit.min(USER_STACK_BYTES);
    let pages = bounded / PAGE_SIZE as u64;
    if pages == 0 {
        return Err("initial stack exceeded rlimit");
    }
    usize::try_from(pages).map_err(|_| "initial stack exceeded rlimit")
}

fn stack_base_for_pages(pages: usize) -> u64 {
    USER_STACK_TOP - (pages * PAGE_SIZE) as u64
}

fn release_prepared_page_mappings(
    frame_allocator: &mut UserFrameAllocator,
    page_mappings: &[UserPageMapping],
) {
    for mapping in page_mappings.iter().filter(|mapping| mapping.owned && mapping.frame_start != 0)
    {
        frame_allocator
            .deallocate_frame(PhysFrame::containing_address(PhysAddr::new(mapping.frame_start)));
    }
}

struct InitialStack {
    page_base: u64,
    page_bytes: Vec<u8>,
    stack_pointer: u64,
}

#[allow(clippy::too_many_arguments)]
fn build_exec_stack(
    elf: &ElfFile<'_>,
    load_bias: u64,
    at_base: u64,
    at_entry: u64,
    argv: &[Vec<u8>],
    envp: &[Vec<u8>],
    execfn: &[u8],
    stack_credentials: ExecStackCredentials,
) -> Result<InitialStack, &'static str> {
    let argv_refs: Vec<&[u8]> = argv.iter().map(Vec::as_slice).collect();
    let envp_refs: Vec<&[u8]> = envp.iter().map(Vec::as_slice).collect();
    build_initial_stack_slices(
        elf,
        load_bias,
        at_base,
        at_entry,
        &argv_refs,
        &envp_refs,
        execfn,
        stack_credentials,
    )
}

#[allow(clippy::too_many_arguments)]
fn build_initial_stack_slices(
    elf: &ElfFile<'_>,
    load_bias: u64,
    at_base: u64,
    at_entry: u64,
    argv: &[&[u8]],
    envp: &[&[u8]],
    execfn_bytes: &[u8],
    stack_credentials: ExecStackCredentials,
) -> Result<InitialStack, &'static str> {
    let page_base = USER_STACK_TOP - PAGE_SIZE as u64;
    let mut page_bytes = vec![0; PAGE_SIZE];
    let mut cursor = USER_STACK_TOP;

    let execfn = push_c_string(&mut page_bytes, page_base, &mut cursor, execfn_bytes)?;
    let platform = push_c_string(&mut page_bytes, page_base, &mut cursor, b"x86_64")?;
    let random = push_bytes(&mut page_bytes, page_base, &mut cursor, b"vmos-ltp-random!")?;
    let mut argv_ptrs = Vec::with_capacity(argv.len());
    for arg in argv.iter().rev() {
        argv_ptrs.push(push_c_string(&mut page_bytes, page_base, &mut cursor, arg)?);
    }
    argv_ptrs.reverse();
    let mut envp_ptrs = Vec::with_capacity(envp.len());
    for env in envp.iter().rev() {
        envp_ptrs.push(push_c_string(&mut page_bytes, page_base, &mut cursor, env)?);
    }
    envp_ptrs.reverse();
    cursor &= !15;

    let auxv = [
        (AT_PHDR, program_header_vaddr(elf, load_bias)?),
        (AT_PHENT, elf.header.pt2.ph_entry_size() as u64),
        (AT_PHNUM, elf.header.pt2.ph_count() as u64),
        (AT_PAGESZ, PAGE_SIZE as u64),
        (AT_BASE, at_base),
        (AT_FLAGS, 0),
        (AT_ENTRY, at_entry),
        (AT_UID, stack_credentials.uid as u64),
        (AT_EUID, stack_credentials.euid as u64),
        (AT_GID, stack_credentials.gid as u64),
        (AT_EGID, stack_credentials.egid as u64),
        (AT_CLKTCK, 100),
        (AT_SECURE, u64::from(stack_credentials.secure)),
        (AT_RANDOM, random),
        (AT_EXECFN, execfn),
        (AT_PLATFORM, platform),
        (AT_NULL, 0),
    ];

    let mut values =
        Vec::with_capacity(1 + argv_ptrs.len() + 1 + envp_ptrs.len() + 1 + auxv.len() * 2);
    values.push(argv_ptrs.len() as u64);
    values.extend(argv_ptrs);
    values.push(0);
    values.extend(envp_ptrs);
    values.push(0);
    for (kind, value) in auxv {
        values.push(kind);
        values.push(value);
    }

    let values_len = (values.len() * core::mem::size_of::<u64>()) as u64;
    cursor = cursor.checked_sub(values_len).ok_or("initial stack underflowed")?;
    cursor &= !15;
    write_u64_values(&mut page_bytes, page_base, cursor, &values)?;

    Ok(InitialStack { page_base, page_bytes, stack_pointer: cursor })
}

fn program_header_vaddr(elf: &ElfFile<'_>, load_bias: u64) -> Result<u64, &'static str> {
    let ph_offset = elf.header.pt2.ph_offset();
    let ph_size =
        (elf.header.pt2.ph_entry_size() as u64).saturating_mul(elf.header.pt2.ph_count() as u64);
    for ph in elf.program_iter() {
        if ph.get_type() != Ok(ProgramType::Load) {
            continue;
        }
        let start = ph.offset();
        let end = start.checked_add(ph.file_size()).ok_or("user ELF segment overflowed")?;
        if ph_offset >= start && ph_offset.saturating_add(ph_size) <= end {
            let phdr = ph
                .virtual_addr()
                .checked_add(ph_offset - start)
                .ok_or("user ELF program header table overflowed")?;
            return biased_addr(phdr, load_bias);
        }
    }
    Err("user ELF program header table is not mapped")
}

fn elf_load_bias(elf: &ElfFile<'_>, dyn_base: u64) -> Result<u64, &'static str> {
    match elf.header.pt2.type_().as_type() {
        ElfType::Executable => Ok(0),
        ElfType::SharedObject => Ok(dyn_base),
        _ => Err("user ELF type unsupported"),
    }
}

fn elf_interpreter_load_bias(elf: &ElfFile<'_>) -> Result<u64, &'static str> {
    match elf.header.pt2.type_().as_type() {
        ElfType::SharedObject => Ok(USER_INTERP_BASE),
        _ => Err("user ELF interpreter type unsupported"),
    }
}

fn biased_addr(addr: u64, load_bias: u64) -> Result<u64, &'static str> {
    addr.checked_add(load_bias).ok_or("user ELF address overflowed")
}

fn push_bytes(
    page: &mut [u8],
    page_base: u64,
    cursor: &mut u64,
    bytes: &[u8],
) -> Result<u64, &'static str> {
    *cursor = cursor.checked_sub(bytes.len() as u64).ok_or("initial stack underflowed")?;
    let offset = cursor.checked_sub(page_base).ok_or("initial stack exceeded one page")? as usize;
    let end = offset.checked_add(bytes.len()).ok_or("initial stack overflowed")?;
    let dest = page.get_mut(offset..end).ok_or("initial stack exceeded one page")?;
    dest.copy_from_slice(bytes);
    Ok(*cursor)
}

fn push_c_string(
    page: &mut [u8],
    page_base: u64,
    cursor: &mut u64,
    bytes: &[u8],
) -> Result<u64, &'static str> {
    if bytes.contains(&0) {
        return Err("initial stack string contains nul");
    }
    let start = cursor.checked_sub(1).ok_or("initial stack underflowed")?;
    *cursor = start;
    let offset = cursor.checked_sub(page_base).ok_or("initial stack exceeded one page")? as usize;
    *page.get_mut(offset).ok_or("initial stack exceeded one page")? = 0;
    push_bytes(page, page_base, cursor, bytes)
}

fn write_u64_values(
    page: &mut [u8],
    page_base: u64,
    start: u64,
    values: &[u64],
) -> Result<(), &'static str> {
    let offset = start.checked_sub(page_base).ok_or("initial stack exceeded one page")? as usize;
    let byte_len =
        values.len().checked_mul(core::mem::size_of::<u64>()).ok_or("initial stack overflowed")?;
    let dest = page.get_mut(offset..offset + byte_len).ok_or("initial stack exceeded one page")?;
    for (index, value) in values.iter().copied().enumerate() {
        let start = index * core::mem::size_of::<u64>();
        dest[start..start + core::mem::size_of::<u64>()].copy_from_slice(&value.to_le_bytes());
    }
    Ok(())
}

fn frame_bytes(frame: PhysFrame, phys_offset: VirtAddr) -> &'static mut [u8] {
    let virt = phys_offset + frame.start_address().as_u64();
    unsafe { slice::from_raw_parts_mut(virt.as_mut_ptr::<u8>(), PAGE_SIZE) }
}

pub(crate) fn copy_user_page_bytes(
    physical_memory_offset: u64,
    mapping: &UserPageMapping,
    out: &mut [u8],
) -> Result<(), &'static str> {
    if out.len() < PAGE_SIZE {
        return Err("destination buffer is smaller than one user page");
    }
    if mapping.frame_start == 0 {
        return Err("user page has no materialized frame");
    }
    let phys_offset = VirtAddr::new(physical_memory_offset);
    let frame = PhysFrame::containing_address(PhysAddr::new(mapping.frame_start));
    out[..PAGE_SIZE].copy_from_slice(frame_bytes(frame, phys_offset));
    Ok(())
}

pub(crate) fn fill_user_page_frame(
    physical_memory_offset: u64,
    frame_start: u64,
    value: u8,
) -> Result<(), &'static str> {
    if frame_start == 0 {
        return Ok(());
    }
    let phys_offset = VirtAddr::new(physical_memory_offset);
    let frame = PhysFrame::containing_address(PhysAddr::new(frame_start));
    frame_bytes(frame, phys_offset).fill(value);
    Ok(())
}

pub(crate) fn fill_user_page_frame_range(
    physical_memory_offset: u64,
    frame_start: u64,
    start: usize,
    len: usize,
    value: u8,
) -> Result<(), &'static str> {
    if frame_start == 0 || len == 0 {
        return Ok(());
    }
    let end = start.checked_add(len).ok_or("user page fill range overflowed")?;
    if end > PAGE_SIZE {
        return Err("user page fill range exceeds frame size");
    }
    let phys_offset = VirtAddr::new(physical_memory_offset);
    let frame = PhysFrame::containing_address(PhysAddr::new(frame_start));
    frame_bytes(frame, phys_offset)[start..end].fill(value);
    Ok(())
}

unsafe fn active_level_4_table(phys_offset: VirtAddr) -> &'static mut PageTable {
    let (frame, _) = Cr3::read();
    let virt = phys_offset + frame.start_address().as_u64();
    unsafe { &mut *virt.as_mut_ptr() }
}

fn align_up(value: usize, align: usize) -> usize {
    (value + align - 1) & !(align - 1)
}

fn user_page_iter(start: u64, len: u64) -> Result<impl Iterator<Item = u64>, &'static str> {
    let end = start.checked_add(len).ok_or("user page range overflowed")?;
    if start & (PAGE_SIZE as u64 - 1) != 0 || end & (PAGE_SIZE as u64 - 1) != 0 {
        return Err("user page range is not page aligned");
    }
    Ok((start..end).step_by(PAGE_SIZE))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stack_pages_for_rlimit_bounds_fixed_stack_region() {
        assert_eq!(stack_pages_for_rlimit(u64::MAX), Ok(USER_STACK_PAGES));
        assert_eq!(
            stack_pages_for_rlimit(USER_STACK_BYTES + PAGE_SIZE as u64),
            Ok(USER_STACK_PAGES)
        );
        assert_eq!(stack_pages_for_rlimit(PAGE_SIZE as u64 * 2), Ok(2));
        assert_eq!(stack_base_for_pages(2), USER_STACK_TOP - PAGE_SIZE as u64 * 2);
    }

    #[test]
    fn stack_pages_for_rlimit_rejects_subpage_stack() {
        assert_eq!(stack_pages_for_rlimit(0), Err("initial stack exceeded rlimit"));
        assert_eq!(
            stack_pages_for_rlimit(PAGE_SIZE as u64 - 1),
            Err("initial stack exceeded rlimit")
        );
    }

    #[test]
    fn clone_user_page_mappings_marks_private_frames_cow() {
        let mappings = [UserPageMapping {
            va: 0x4000,
            frame_start: 0x20_000,
            present: true,
            owned: true,
            cow: false,
            backing: UserPageBacking::ZeroFill,
        }];

        let cloned = clone_user_page_mappings(&mappings).expect("clone mappings");

        assert_eq!(cloned.len(), 1);
        assert_eq!(cloned[0].frame_start, 0x20_000);
        assert!(!cloned[0].owned);
        assert!(cloned[0].cow);
    }

    #[test]
    fn clone_user_page_mappings_keeps_file_shared_frames_shared() {
        let mappings = [UserPageMapping {
            va: 0x8000,
            frame_start: 0x24_000,
            present: true,
            owned: true,
            cow: false,
            backing: UserPageBacking::FileShared {
                vfs_node_id: 7,
                path: b"/tmp/shared".to_vec(),
                offset: 0,
                bytes: vec![1, 2, 3],
                valid: true,
            },
        }];

        let cloned = clone_user_page_mappings(&mappings).expect("clone mappings");

        assert_eq!(cloned.len(), 1);
        assert_eq!(cloned[0].frame_start, 0x24_000);
        assert!(!cloned[0].owned);
        assert!(!cloned[0].cow);
    }
}
