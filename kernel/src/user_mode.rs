use core::arch::{asm, global_asm};
use core::ptr::addr_of_mut;
use core::slice;
use core::sync::atomic::{AtomicUsize, Ordering};

use bootloader_api::BootInfo;
use spin::Lazy;
use x86_64::VirtAddr;
use x86_64::instructions::segmentation::{CS, SS, Segment};
use x86_64::instructions::tables::load_tss;
use x86_64::registers::control::Cr3;
use x86_64::registers::model_specific::{Efer, EferFlags, LStar, SFMask, Star};
use x86_64::registers::rflags::RFlags;
use x86_64::structures::gdt::{Descriptor, GlobalDescriptorTable, SegmentSelector};
use x86_64::structures::paging::{
    FrameAllocator, Mapper, OffsetPageTable, Page, PageTable, PageTableFlags, PhysFrame, Size4KiB,
    Translate,
};
use x86_64::structures::tss::TaskStateSegment;

use crate::qemu;
use crate::serial;
use crate::serial_println;
use vmos_abi::{SYS_EXIT, SYS_WRITE};

const PAGE_SIZE: usize = 4096;
const KERNEL_SYSCALL_STACK_SIZE: usize = PAGE_SIZE * 4;
const USER_CODE_ADDR: u64 = 0x0000_0004_0000_0000;
const USER_DATA_ADDR: u64 = USER_CODE_ADDR + PAGE_SIZE as u64;
const USER_STACK_ADDR: u64 = USER_DATA_ADDR + PAGE_SIZE as u64;
const USER_STACK_TOP: u64 = USER_STACK_ADDR + PAGE_SIZE as u64;
const USER_MESSAGE: &[u8] = b"ring3 frontend: hello via syscall/sysret\n";

static USER_PHASE: AtomicUsize = AtomicUsize::new(0);

#[repr(C, align(4096))]
struct PageStorage([u8; PAGE_SIZE]);

#[repr(C, align(16))]
struct StackStorage([u8; KERNEL_SYSCALL_STACK_SIZE]);

static mut USER_CODE_PAGE: PageStorage = PageStorage([0; PAGE_SIZE]);
static mut USER_DATA_PAGE: PageStorage = PageStorage([0; PAGE_SIZE]);
static mut USER_STACK_PAGE: PageStorage = PageStorage([0; PAGE_SIZE]);
static mut KERNEL_SYSCALL_STACK: StackStorage = StackStorage([0; KERNEL_SYSCALL_STACK_SIZE]);

static TSS: Lazy<TaskStateSegment> = Lazy::new(|| {
    let mut tss = TaskStateSegment::new();
    let stack_top = VirtAddr::from_ptr(unsafe { addr_of_mut!(KERNEL_SYSCALL_STACK.0) })
        + KERNEL_SYSCALL_STACK_SIZE as u64;
    tss.privilege_stack_table[0] = stack_top;
    tss
});

static GDT: Lazy<(GlobalDescriptorTable, Selectors)> = Lazy::new(|| {
    let mut gdt = GlobalDescriptorTable::new();
    let kernel_code = gdt.append(Descriptor::kernel_code_segment());
    let kernel_data = gdt.append(Descriptor::kernel_data_segment());
    let user_data = gdt.append(Descriptor::user_data_segment());
    let user_code = gdt.append(Descriptor::user_code_segment());
    let tss = gdt.append(Descriptor::tss_segment(&TSS));

    (
        gdt,
        Selectors {
            kernel_code,
            kernel_data,
            user_code,
            user_data,
            tss,
        },
    )
});

global_asm!(
    r#"
    .global vmos_syscall_entry
vmos_syscall_entry:
    push r11
    push rcx
    push rax
    push rdi
    push rsi
    push rdx
    push r10
    push r8
    push r9
    sub rsp, 8
    lea rdi, [rsp + 8]
    call {handler}
    add rsp, 8
    pop r9
    pop r8
    pop r10
    pop rdx
    pop rsi
    pop rdi
    pop rax
    pop rcx
    pop r11
    sysretq
    "#,
    handler = sym syscall_dispatch_from_asm,
);

unsafe extern "C" {
    fn vmos_syscall_entry();
}

#[derive(Clone, Copy)]
struct Selectors {
    kernel_code: SegmentSelector,
    kernel_data: SegmentSelector,
    user_code: SegmentSelector,
    user_data: SegmentSelector,
    tss: SegmentSelector,
}

#[repr(C)]
struct SyscallFrame {
    r9: u64,
    r8: u64,
    r10: u64,
    rdx: u64,
    rsi: u64,
    rdi: u64,
    rax: u64,
    rcx: u64,
    r11: u64,
}

pub fn init() {
    let (gdt, selectors) = &*GDT;
    gdt.load();
    unsafe {
        CS::set_reg(selectors.kernel_code);
        SS::set_reg(selectors.kernel_data);
        load_tss(selectors.tss);
    }

    let mut efer = Efer::read();
    efer.insert(EferFlags::SYSTEM_CALL_EXTENSIONS);
    unsafe {
        Efer::write(efer);
    }

    Star::write(
        selectors.user_code,
        selectors.user_data,
        selectors.kernel_code,
        selectors.kernel_data,
    )
    .expect("GDT selectors must satisfy STAR layout");
    LStar::write(VirtAddr::from_ptr(vmos_syscall_entry as *const ()));
    SFMask::write(RFlags::INTERRUPT_FLAG);
}

pub fn run_demo(boot_info: &BootInfo) -> Result<(), &'static str> {
    serial_println!("== ring3 syscall/sysret demo ==");
    USER_PHASE.store(0, Ordering::Release);
    prepare_user_pages();
    map_user_pages(boot_info)?;
    crate::kinfo!("entering ring3 demo");
    enter_user_mode();
}

extern "C" fn syscall_dispatch_from_asm(frame: *mut SyscallFrame) {
    let frame = unsafe { &mut *frame };
    match frame.rax {
        SYS_WRITE => handle_write(frame),
        SYS_EXIT => handle_exit(frame),
        nr => panic!("unexpected ring3 syscall {}", nr),
    }
}

fn handle_write(frame: &mut SyscallFrame) {
    let phase = USER_PHASE.fetch_add(1, Ordering::AcqRel);
    if phase != 0 {
        panic!("ring3 write syscall arrived in unexpected phase {}", phase);
    }

    let bytes = user_slice(frame.rdi, frame.rsi).expect("ring3 write passed invalid user slice");
    serial::write_bytes(bytes);
    frame.rax = bytes.len() as u64;
    crate::kinfo!("ring3 write returned via sysret");
}

fn handle_exit(frame: &SyscallFrame) -> ! {
    let phase = USER_PHASE.fetch_add(1, Ordering::AcqRel);
    if phase != 1 {
        panic!("ring3 exit syscall arrived in unexpected phase {}", phase);
    }
    if frame.rdi != 0 {
        panic!("ring3 exit returned unexpected status {}", frame.rdi);
    }

    crate::kinfo!("ring3 exit trapped into kernel");
    serial_println!("vmos: demo completed");
    qemu::exit_success();
    crate::ktrace!("entered halt loop after qemu exit");
    loop {
        x86_64::instructions::hlt();
    }
}

fn user_slice(ptr: u64, len: u64) -> Result<&'static [u8], &'static str> {
    let start = ptr;
    let end = start.checked_add(len).ok_or("ring3 buffer overflowed")?;
    let page_start = USER_DATA_ADDR;
    let page_end = USER_DATA_ADDR + PAGE_SIZE as u64;
    if start < page_start || end > page_end {
        return Err("ring3 buffer escaped mapped user page");
    }

    let ptr = start as *const u8;
    Ok(unsafe { slice::from_raw_parts(ptr, len as usize) })
}

fn prepare_user_pages() {
    let code = build_user_program();

    unsafe {
        let code_page = addr_of_mut!(USER_CODE_PAGE.0) as *mut u8;
        core::ptr::write_bytes(code_page, 0xcc, PAGE_SIZE);
        core::ptr::copy_nonoverlapping(code.as_ptr(), code_page, code.len());

        let data_page = addr_of_mut!(USER_DATA_PAGE.0) as *mut u8;
        core::ptr::write_bytes(data_page, 0, PAGE_SIZE);
        core::ptr::copy_nonoverlapping(USER_MESSAGE.as_ptr(), data_page, USER_MESSAGE.len());

        let stack_page = addr_of_mut!(USER_STACK_PAGE.0) as *mut u8;
        core::ptr::write_bytes(stack_page, 0, PAGE_SIZE);
    }
}

fn build_user_program() -> [u8; 38] {
    let mut bytes = [0u8; 38];
    let mut offset = 0;

    emit_mov_imm32(&mut bytes, &mut offset, 0xb8, SYS_WRITE as u32);
    emit_mov_imm64(&mut bytes, &mut offset, 0xbf, USER_DATA_ADDR);
    emit_mov_imm64(&mut bytes, &mut offset, 0xbe, USER_MESSAGE.len() as u64);
    emit_syscall(&mut bytes, &mut offset);

    emit_mov_imm32(&mut bytes, &mut offset, 0xb8, SYS_EXIT as u32);
    bytes[offset] = 0x31;
    bytes[offset + 1] = 0xff;
    offset += 2;
    emit_syscall(&mut bytes, &mut offset);
    bytes[offset] = 0x0f;
    bytes[offset + 1] = 0x0b;

    bytes
}

fn emit_mov_imm32(code: &mut [u8], offset: &mut usize, opcode: u8, value: u32) {
    code[*offset] = opcode;
    *offset += 1;
    code[*offset..*offset + 4].copy_from_slice(&value.to_le_bytes());
    *offset += 4;
}

fn emit_mov_imm64(code: &mut [u8], offset: &mut usize, opcode: u8, value: u64) {
    code[*offset] = 0x48;
    code[*offset + 1] = opcode;
    *offset += 2;
    code[*offset..*offset + 8].copy_from_slice(&value.to_le_bytes());
    *offset += 8;
}

fn emit_syscall(code: &mut [u8], offset: &mut usize) {
    code[*offset] = 0x0f;
    code[*offset + 1] = 0x05;
    *offset += 2;
}

fn map_user_pages(boot_info: &BootInfo) -> Result<(), &'static str> {
    let phys_offset = boot_info
        .physical_memory_offset
        .as_ref()
        .copied()
        .ok_or("bootloader did not provide physical_memory_offset")?;
    let phys_offset = VirtAddr::new(phys_offset);

    let level_4 = unsafe { active_level_4_table(phys_offset) };
    let mut mapper = unsafe { OffsetPageTable::new(level_4, phys_offset) };
    let mut frame_allocator = BootInfoFrameAllocator::new(&boot_info.memory_regions);

    map_alias(
        &mut mapper,
        &mut frame_allocator,
        VirtAddr::new(USER_CODE_ADDR),
        VirtAddr::from_ptr(unsafe { addr_of_mut!(USER_CODE_PAGE.0) }),
        PageTableFlags::PRESENT | PageTableFlags::USER_ACCESSIBLE,
    )?;
    map_alias(
        &mut mapper,
        &mut frame_allocator,
        VirtAddr::new(USER_DATA_ADDR),
        VirtAddr::from_ptr(unsafe { addr_of_mut!(USER_DATA_PAGE.0) }),
        PageTableFlags::PRESENT | PageTableFlags::USER_ACCESSIBLE | PageTableFlags::NO_EXECUTE,
    )?;
    map_alias(
        &mut mapper,
        &mut frame_allocator,
        VirtAddr::new(USER_STACK_ADDR),
        VirtAddr::from_ptr(unsafe { addr_of_mut!(USER_STACK_PAGE.0) }),
        PageTableFlags::PRESENT
            | PageTableFlags::WRITABLE
            | PageTableFlags::USER_ACCESSIBLE
            | PageTableFlags::NO_EXECUTE,
    )?;

    Ok(())
}

fn map_alias(
    mapper: &mut OffsetPageTable<'_>,
    frame_allocator: &mut BootInfoFrameAllocator<'_>,
    user_addr: VirtAddr,
    backing_addr: VirtAddr,
    flags: PageTableFlags,
) -> Result<(), &'static str> {
    let page = Page::<Size4KiB>::containing_address(user_addr);
    let backing_phys = mapper
        .translate_addr(backing_addr)
        .ok_or("backing page was not mapped")?;
    let frame = PhysFrame::<Size4KiB>::containing_address(backing_phys);

    unsafe {
        mapper
            .map_to(page, frame, flags, frame_allocator)
            .map_err(|_| "failed to map user page")?
            .flush();
    }
    Ok(())
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
        Self {
            memory_regions,
            next: 0,
        }
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

fn enter_user_mode() -> ! {
    let selectors = &GDT.1;
    let user_code = selectors.user_code.0 as u64;
    let user_data = selectors.user_data.0 as u64;

    unsafe {
        asm!(
            "push {user_data}",
            "push {user_stack}",
            "pushfq",
            "pop rax",
            "or rax, {interrupt_flag}",
            "push rax",
            "push {user_code}",
            "push {user_entry}",
            "iretq",
            user_data = in(reg) user_data,
            user_stack = in(reg) USER_STACK_TOP,
            interrupt_flag = const 0x200u64,
            user_code = in(reg) user_code,
            user_entry = in(reg) USER_CODE_ADDR,
            options(noreturn),
        );
    }
}
