use alloc::vec::Vec;
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

    map_user_stack(&mut mapper, &mut frame_allocator, phys_offset)?;
    regions.push(UserRegion { start: USER_STACK_BASE, end: USER_STACK_TOP, writable: true });

    Ok(LoadedUserImage { entry: elf.header.pt2.entry_point(), stack_top: USER_STACK_TOP, regions })
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
        frame_bytes(frame, phys_offset).fill(0);
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
