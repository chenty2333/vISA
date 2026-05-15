use core::sync::atomic::{AtomicU64, Ordering};

use pic8259::ChainedPics;
use spin::{Lazy, Mutex};
use x86_64::{
    instructions::{interrupts, port::Port},
    structures::idt::{InterruptDescriptorTable, InterruptStackFrame, PageFaultErrorCode},
};

const PIC_1_OFFSET: u8 = 32;
const PIC_2_OFFSET: u8 = PIC_1_OFFSET + 8;
const PIT_INPUT_HZ: u32 = 1_193_182;
pub const TIMER_HZ: u32 = 1_000;

static TICKS: AtomicU64 = AtomicU64::new(0);

static IDT: Lazy<InterruptDescriptorTable> = Lazy::new(|| {
    let mut idt = InterruptDescriptorTable::new();
    idt.breakpoint.set_handler_fn(breakpoint_handler);
    idt.page_fault.set_handler_fn(page_fault_handler);
    idt.general_protection_fault.set_handler_fn(general_protection_fault_handler);
    idt[InterruptIndex::Timer.as_u8()].set_handler_fn(timer_interrupt_handler);
    idt
});

static PICS: Mutex<ChainedPics> =
    Mutex::new(unsafe { ChainedPics::new(PIC_1_OFFSET, PIC_2_OFFSET) });

#[derive(Clone, Copy)]
#[repr(u8)]
enum InterruptIndex {
    Timer = PIC_1_OFFSET,
}

impl InterruptIndex {
    const fn as_u8(self) -> u8 {
        self as u8
    }
}

pub fn init() {
    interrupts::disable();
    IDT.load();

    unsafe {
        let mut pics = PICS.lock();
        pics.initialize();
        pics.write_masks(0b1111_1110, 0xff);
    }

    init_pit_timer(TIMER_HZ);
    interrupts::enable();
}

pub fn wait_for_interrupt() {
    interrupts::disable();
    interrupts::enable_and_hlt();
}

pub fn tick_count() -> u64 {
    TICKS.load(Ordering::Acquire)
}

fn init_pit_timer(frequency_hz: u32) {
    let divisor = (PIT_INPUT_HZ / frequency_hz.max(1)).clamp(1, u16::MAX as u32) as u16;
    unsafe {
        let mut command = Port::<u8>::new(0x43);
        let mut channel0 = Port::<u8>::new(0x40);
        command.write(0x36);
        channel0.write((divisor & 0x00ff) as u8);
        channel0.write((divisor >> 8) as u8);
    }
}

extern "x86-interrupt" fn breakpoint_handler(stack_frame: InterruptStackFrame) {
    crate::kwarn!("breakpoint exception: {stack_frame:#?}");
}

extern "x86-interrupt" fn page_fault_handler(
    stack_frame: InterruptStackFrame,
    error_code: x86_64::structures::idt::PageFaultErrorCode,
) {
    let accessed = x86_64::registers::control::Cr2::read_raw();
    let user_mode = error_code.contains(PageFaultErrorCode::USER_MODE);
    let protection = error_code.contains(PageFaultErrorCode::PROTECTION_VIOLATION);
    let write = error_code.contains(PageFaultErrorCode::CAUSED_BY_WRITE);
    let instruction_fetch = error_code.contains(PageFaultErrorCode::INSTRUCTION_FETCH);
    if user_mode
        && !protection
        && crate::frontends::linux_elf::try_handle_user_page_fault(
            accessed,
            write,
            instruction_fetch,
        )
    {
        crate::kdebug!("page fault demand-mapped va={:#018x}", accessed);
        return;
    }
    crate::kwarn!(
        "page fault va={:#018x} error={:?} ip={:#018x}\n{:#?}",
        accessed,
        error_code,
        stack_frame.instruction_pointer,
        stack_frame,
    );
    // SIGSEGV: invalid memory access → exit current process
    crate::kinfo!("page fault: exiting with SIGSEGV");
    crate::frontends::linux_elf::handle_user_fault(11); // SIGSEGV
    loop {
        x86_64::instructions::hlt();
    }
}

extern "x86-interrupt" fn general_protection_fault_handler(
    stack_frame: InterruptStackFrame,
    error_code: u64,
) {
    panic!("general protection fault (code={error_code:#x})\n{stack_frame:#?}");
}

extern "x86-interrupt" fn timer_interrupt_handler(_stack_frame: InterruptStackFrame) {
    TICKS.fetch_add(1, Ordering::Release);
    unsafe {
        PICS.lock().notify_end_of_interrupt(InterruptIndex::Timer.as_u8());
    }
}
