use alloc::{vec, vec::Vec};
use core::slice;

use bootloader_api::BootInfo;
use x86_64::{
    VirtAddr,
    registers::control::Cr3,
    structures::paging::{
        FrameAllocator, Mapper, OffsetPageTable, Page, PageTable, PageTableFlags, PhysFrame,
        Size4KiB,
    },
};
use xmas_elf::{ElfFile, program::Type as ProgramType};

use super::context::{LoadedUserImage, UserRegion};

const PAGE_SIZE: usize = 4096;
const USER_STACK_PAGES: usize = 4;
const USER_STACK_BASE: u64 = 0x0000_0000_7000_0000;
const USER_STACK_TOP: u64 = USER_STACK_BASE + (USER_STACK_PAGES * PAGE_SIZE) as u64;
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

pub(crate) fn load_demo_program(boot_info: &BootInfo) -> Result<LoadedUserImage, &'static str> {
    load_user_program(boot_info, &LINUX_USER_DEMO_ELF.0)
}

fn load_user_program(boot_info: &BootInfo, bytes: &[u8]) -> Result<LoadedUserImage, &'static str> {
    let phys_offset = boot_info
        .physical_memory_offset
        .as_ref()
        .copied()
        .ok_or("bootloader did not provide physical_memory_offset")?;
    let phys_offset = VirtAddr::new(phys_offset);

    let elf = ElfFile::new(bytes).map_err(|_| "user ELF was invalid")?;
    let level_4 = unsafe { active_level_4_table(phys_offset) };
    let mut mapper = unsafe { OffsetPageTable::new(level_4, phys_offset) };
    let mut frame_allocator = BootInfoFrameAllocator::new(&boot_info.memory_regions);
    let mut regions = Vec::new();

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
            phys_offset,
            virt_start,
            virt_end,
            segment_bytes,
            flags,
        )?;

        regions.push(UserRegion {
            start: virt_start,
            end: align_up(virt_end as usize, PAGE_SIZE) as u64,
            writable: ph.flags().is_write(),
        });
    }

    let anon_flags = PageTableFlags::PRESENT
        | PageTableFlags::WRITABLE
        | PageTableFlags::USER_ACCESSIBLE
        | PageTableFlags::NO_EXECUTE;
    map_user_pages(
        &mut mapper,
        &mut frame_allocator,
        phys_offset,
        USER_MMAP_BASE,
        USER_MMAP_END,
        &[],
        anon_flags,
    )?;
    regions.push(UserRegion { start: USER_MMAP_BASE, end: USER_MMAP_END, writable: true });

    let initial_stack = build_initial_stack(&elf)?;
    map_user_stack(&mut mapper, &mut frame_allocator, phys_offset, &initial_stack)?;
    regions.push(UserRegion { start: USER_STACK_BASE, end: USER_STACK_TOP, writable: true });

    Ok(LoadedUserImage {
        entry: elf.header.pt2.entry_point(),
        stack_top: initial_stack.stack_pointer,
        regions,
    })
}

fn map_user_pages(
    mapper: &mut OffsetPageTable<'_>,
    frame_allocator: &mut BootInfoFrameAllocator<'_>,
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
    frame_allocator: &mut BootInfoFrameAllocator<'_>,
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

struct BootInfoFrameAllocator<'a> {
    memory_regions: &'a [bootloader_api::info::MemoryRegion],
    next: usize,
}

impl<'a> BootInfoFrameAllocator<'a> {
    fn new(memory_regions: &'a [bootloader_api::info::MemoryRegion]) -> Self {
        Self { memory_regions, next: 0 }
    }

    fn usable_frames(&self) -> impl Iterator<Item = PhysFrame> + '_ {
        self.memory_regions
            .iter()
            .filter(|region| region.kind == bootloader_api::info::MemoryRegionKind::Usable)
            .flat_map(|region| (region.start..region.end).step_by(PAGE_SIZE))
            .map(|addr| PhysFrame::containing_address(x86_64::PhysAddr::new(addr)))
    }
}

unsafe impl FrameAllocator<Size4KiB> for BootInfoFrameAllocator<'_> {
    fn allocate_frame(&mut self) -> Option<PhysFrame> {
        let frame = self.usable_frames().nth(self.next);
        self.next += 1;
        frame
    }
}

fn align_up(value: usize, align: usize) -> usize {
    (value + align - 1) & !(align - 1)
}
