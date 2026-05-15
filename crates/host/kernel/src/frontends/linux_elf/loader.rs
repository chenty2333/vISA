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
use xmas_elf::{ElfFile, program::Type as ProgramType};

use super::context::{LoadedUserImage, UserFrameAllocator, UserPageMapping, UserRegion};

const LIVE_PAGE_TABLE_AUTHORITY: &str = "LiveUserPageTableAuthority";
const PAGE_SIZE: usize = 4096;
const USER_STACK_PAGES: usize = 2048;
const USER_STACK_TOP: u64 = 0x0000_0000_7000_0000;
const USER_STACK_BASE: u64 = USER_STACK_TOP - (USER_STACK_PAGES * PAGE_SIZE) as u64;
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

#[repr(align(8))]
struct AlignedElf<const N: usize>([u8; N]);

static LINUX_USER_DEMO_ELF: AlignedElf<{ include_bytes!(env!("VMOS_LINUX_USER_DEMO_ELF")).len() }> =
    AlignedElf(*include_bytes!(env!("VMOS_LINUX_USER_DEMO_ELF")));

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
            if mapping.owned {
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
            cow: true,
        });
    }
    Ok(cloned)
}

pub(crate) fn switch_user_page_mappings(
    physical_memory_offset: u64,
    current_mappings: &[UserPageMapping],
    next_mappings: &[UserPageMapping],
    next_regions: &[UserRegion],
    frame_allocator: &mut UserFrameAllocator,
    reclaim_current: bool,
) -> Result<(), &'static str> {
    let phys_offset = VirtAddr::new(physical_memory_offset);
    let level_4 = unsafe { active_level_4_table(phys_offset) };
    let mut mapper = unsafe { OffsetPageTable::new(level_4, phys_offset) };
    let mut authority =
        LiveUserPageTableAuthority { mapper: &mut mapper, frame_allocator, phys_offset };

    for mapping in next_mappings.iter().filter(|mapping| mapping.present) {
        if user_page_region_prot(next_regions, mapping.va).is_none() {
            return Err("forked user page has no region");
        }
    }

    for mapping in current_mappings.iter().filter(|mapping| mapping.present) {
        match authority.unmap_page(mapping.va) {
            Ok(()) => {}
            Err(err) if is_page_not_mapped(&err) => {}
            Err(err) => {
                return Err(map_page_table_error(err));
            }
        }
    }
    if reclaim_current {
        for mapping in current_mappings {
            if mapping.owned {
                authority.frame_allocator.deallocate_frame(PhysFrame::containing_address(
                    PhysAddr::new(mapping.frame_start),
                ));
            }
        }
    }

    for mapping in next_mappings.iter().filter(|mapping| mapping.present) {
        let prot = user_page_region_prot(next_regions, mapping.va)
            .ok_or("forked user page has no region")?;
        let flags = user_page_flags_for_mapping(prot, mapping);
        let (writable, executable) = page_attrs_from_flags(flags);
        authority
            .map_page(mapping.va, mapping.frame_start, writable, executable)
            .map_err(map_page_table_error)?;
    }
    Ok(())
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
    let (writable, executable) = page_attrs_from_flags(flags);
    match authority.map_page(page_addr, mapping.frame_start, writable, executable) {
        Ok(()) => {
            mapping.present = true;
            Ok(())
        }
        Err(SubstrateError::ContractViolation { detail: "virtual page already mapped" }) => {
            mapping.present = true;
            match authority.protect_page(page_addr, writable, executable) {
                Ok(()) => Ok(()),
                Err(err) => Err(map_page_table_error(err)),
            }
        }
        Err(err) => Err(map_page_table_error(err)),
    }
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

fn load_user_program(
    boot_info: &'static BootInfo,
    bytes: &[u8],
) -> Result<LoadedUserImage, &'static str> {
    let phys_offset = boot_info
        .physical_memory_offset
        .as_ref()
        .copied()
        .ok_or("bootloader did not provide physical_memory_offset")?;
    let phys_offset = VirtAddr::new(phys_offset);

    let elf = ElfFile::new(bytes).map_err(|_| "user ELF was invalid")?;
    let level_4 = unsafe { active_level_4_table(phys_offset) };
    let mut mapper = unsafe { OffsetPageTable::new(level_4, phys_offset) };
    let mut frame_allocator = UserFrameAllocator::new(&boot_info.memory_regions);
    let mut regions = Vec::new();
    let mut page_mappings = Vec::new();

    for ph in elf.program_iter() {
        if ph.get_type() != Ok(ProgramType::Load) {
            continue;
        }

        let virt_start = ph.virtual_addr();
        let virt_end =
            virt_start.checked_add(ph.mem_size()).ok_or("user ELF segment overflowed")?;
        let file_start = usize::try_from(ph.offset()).map_err(|_| "user ELF offset overflowed")?;
        let file_size =
            usize::try_from(ph.file_size()).map_err(|_| "user ELF file size overflowed")?;
        let file_end = file_start.checked_add(file_size).ok_or("user ELF file range overflowed")?;
        let segment_bytes =
            bytes.get(file_start..file_end).ok_or("user ELF referenced bytes outside the image")?;

        let mut flags = PageTableFlags::PRESENT | PageTableFlags::USER_ACCESSIBLE;
        if ph.flags().is_write() {
            flags |= PageTableFlags::WRITABLE;
        }
        if !ph.flags().is_execute() {
            flags |= PageTableFlags::NO_EXECUTE;
        }

        map_user_pages(
            &mut mapper,
            &mut frame_allocator,
            &mut page_mappings,
            phys_offset,
            virt_start,
            virt_end,
            segment_bytes,
            flags,
        )?;

        regions.push(UserRegion {
            start: virt_start & !(PAGE_SIZE as u64 - 1),
            end: align_up(virt_end as usize, PAGE_SIZE) as u64,
            readable: ph.flags().is_read(),
            writable: ph.flags().is_write(),
            executable: ph.flags().is_execute(),
        });
    }

    let initial_stack = build_initial_stack(&elf)?;
    map_user_stack(
        &mut mapper,
        &mut frame_allocator,
        &mut page_mappings,
        phys_offset,
        &initial_stack,
    )?;
    regions.push(UserRegion {
        start: USER_STACK_BASE,
        end: USER_STACK_TOP,
        readable: true,
        writable: true,
        executable: false,
    });

    Ok(LoadedUserImage {
        entry: elf.header.pt2.entry_point(),
        stack_top: initial_stack.stack_pointer,
        regions,
        page_mappings,
        frame_allocator,
    })
}

fn map_user_pages(
    mapper: &mut OffsetPageTable<'_>,
    frame_allocator: &mut UserFrameAllocator,
    page_mappings: &mut Vec<UserPageMapping>,
    phys_offset: VirtAddr,
    virt_start: u64,
    virt_end: u64,
    file_bytes: &[u8],
    flags: PageTableFlags,
) -> Result<(), &'static str> {
    let page_start = virt_start & !(PAGE_SIZE as u64 - 1);
    let page_end = align_up(virt_end as usize, PAGE_SIZE) as u64;

    for page_addr in (page_start..page_end).step_by(PAGE_SIZE) {
        let frame =
            frame_allocator.allocate_frame().ok_or("out of usable frames for user image")?;
        let page = Page::<Size4KiB>::containing_address(VirtAddr::new(page_addr));
        unsafe {
            mapper
                .map_to(page, frame, flags, frame_allocator)
                .map_err(|_| "failed to map user ELF page")?
                .flush();
        }
        page_mappings.push(UserPageMapping {
            va: page_addr,
            frame_start: frame.start_address().as_u64(),
            present: true,
            owned: true,
            cow: false,
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

fn map_user_stack(
    mapper: &mut OffsetPageTable<'_>,
    frame_allocator: &mut UserFrameAllocator,
    page_mappings: &mut Vec<UserPageMapping>,
    phys_offset: VirtAddr,
    initial_stack: &InitialStack,
) -> Result<(), &'static str> {
    let flags = PageTableFlags::PRESENT
        | PageTableFlags::WRITABLE
        | PageTableFlags::USER_ACCESSIBLE
        | PageTableFlags::NO_EXECUTE;

    for index in 0..USER_STACK_PAGES {
        let addr = USER_STACK_BASE + (index * PAGE_SIZE) as u64;
        let frame =
            frame_allocator.allocate_frame().ok_or("out of usable frames for user stack")?;
        let page = Page::<Size4KiB>::containing_address(VirtAddr::new(addr));
        unsafe {
            mapper
                .map_to(page, frame, flags, frame_allocator)
                .map_err(|_| "failed to map user stack page")?
                .flush();
        }
        page_mappings.push(UserPageMapping {
            va: addr,
            frame_start: frame.start_address().as_u64(),
            present: true,
            owned: true,
            cow: false,
        });
        let dest = frame_bytes(frame, phys_offset);
        dest.fill(0);
        if addr == initial_stack.page_base {
            dest.copy_from_slice(&initial_stack.page_bytes);
        }
    }

    Ok(())
}

struct InitialStack {
    page_base: u64,
    page_bytes: Vec<u8>,
    stack_pointer: u64,
}

fn build_initial_stack(elf: &ElfFile<'_>) -> Result<InitialStack, &'static str> {
    let page_base = USER_STACK_TOP - PAGE_SIZE as u64;
    let mut page_bytes = vec![0; PAGE_SIZE];
    let mut cursor = USER_STACK_TOP;

    let execfn = push_bytes(&mut page_bytes, page_base, &mut cursor, b"/bin/vmos-ltp\0")?;
    let platform = push_bytes(&mut page_bytes, page_base, &mut cursor, b"x86_64\0")?;
    let random = push_bytes(&mut page_bytes, page_base, &mut cursor, b"vmos-ltp-random!")?;
    let kconfig_skip =
        push_bytes(&mut page_bytes, page_base, &mut cursor, b"KCONFIG_SKIP_CHECK=1\0")?;
    let ltp_dev = push_bytes(&mut page_bytes, page_base, &mut cursor, b"LTP_DEV=/dev/loop0\0")?;
    let ltp_single_fs =
        push_bytes(&mut page_bytes, page_base, &mut cursor, b"LTP_SINGLE_FS_TYPE=tmpfs\0")?;
    cursor &= !15;

    let entry = elf.header.pt2.entry_point();
    let auxv = [
        (AT_PHDR, program_header_vaddr(elf)?),
        (AT_PHENT, elf.header.pt2.ph_entry_size() as u64),
        (AT_PHNUM, elf.header.pt2.ph_count() as u64),
        (AT_PAGESZ, PAGE_SIZE as u64),
        (AT_BASE, 0),
        (AT_FLAGS, 0),
        (AT_ENTRY, entry),
        (AT_UID, 0),
        (AT_EUID, 0),
        (AT_GID, 0),
        (AT_EGID, 0),
        (AT_CLKTCK, 100),
        (AT_SECURE, 0),
        (AT_RANDOM, random),
        (AT_EXECFN, execfn),
        (AT_PLATFORM, platform),
        (AT_NULL, 0),
    ];

    let mut values = Vec::with_capacity(1 + 2 + 1 + auxv.len() * 2);
    values.push(1);
    values.push(execfn);
    values.push(0);
    values.push(kconfig_skip);
    values.push(ltp_dev);
    values.push(ltp_single_fs);
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

fn program_header_vaddr(elf: &ElfFile<'_>) -> Result<u64, &'static str> {
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
            return Ok(ph.virtual_addr() + (ph_offset - start));
        }
    }
    Err("user ELF program header table is not mapped")
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
