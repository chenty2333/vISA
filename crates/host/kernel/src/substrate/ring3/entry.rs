use core::{
    arch::{asm, global_asm},
    ptr::addr_of,
};

use spin::Lazy;
use x86_64::{
    VirtAddr,
    instructions::{
        segmentation::{CS, SS, Segment},
        tables::load_tss,
    },
    registers::{
        model_specific::{Efer, EferFlags, FsBase, LStar, SFMask, Star},
        rflags::RFlags,
    },
    structures::{
        gdt::{Descriptor, GlobalDescriptorTable, SegmentSelector},
        tss::TaskStateSegment,
    },
};

const PAGE_SIZE: usize = 4096;
// Wasm service dispatch can consume a non-trivial amount of stack while we are
// inside the ring3 syscall fast path. Keep this comfortably larger than a bare
// trap stack to avoid silent corruption on multi-service lookups.
const KERNEL_SYSCALL_STACK_SIZE: usize = PAGE_SIZE * 16;

pub(crate) type SyscallHandler = extern "C" fn(*mut SyscallFrame);

#[derive(Clone, Copy)]
#[repr(C)]
pub(crate) struct SyscallFrame {
    pub(crate) r9: u64,
    pub(crate) r8: u64,
    pub(crate) r10: u64,
    pub(crate) rdx: u64,
    pub(crate) rsi: u64,
    pub(crate) rdi: u64,
    pub(crate) rax: u64,
    pub(crate) rcx: u64,
    pub(crate) r11: u64,
}

#[derive(Clone, Copy)]
pub(crate) struct UserReturnContext {
    pub(crate) frame: SyscallFrame,
    pub(crate) rsp: u64,
    pub(crate) fs_base: u64,
}

#[derive(Clone, Copy)]
struct Selectors {
    kernel_code: SegmentSelector,
    kernel_data: SegmentSelector,
    user_code: SegmentSelector,
    user_data: SegmentSelector,
    tss: SegmentSelector,
}

#[repr(C, align(16))]
struct StackStorage([u8; KERNEL_SYSCALL_STACK_SIZE]);

static mut KERNEL_SYSCALL_STACK: StackStorage = StackStorage([0; KERNEL_SYSCALL_STACK_SIZE]);
static mut SAVED_USER_RSP: u64 = 0;
static mut ACTIVE_SYSCALL_HANDLER: Option<SyscallHandler> = None;

static TSS: Lazy<TaskStateSegment> = Lazy::new(|| {
    let mut tss = TaskStateSegment::new();
    let stack_top = VirtAddr::from_ptr(unsafe { addr_of!(KERNEL_SYSCALL_STACK.0).cast::<u8>() })
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

    (gdt, Selectors { kernel_code, kernel_data, user_code, user_data, tss })
});

global_asm!(
    r#"
    .global vmos_syscall_entry
vmos_syscall_entry:
    mov [rip + {saved_user_rsp}], rsp
    lea rsp, [rip + {syscall_stack}]
    add rsp, {stack_size}
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
    mov rsp, [rip + {saved_user_rsp}]
    sysretq
    "#,
    handler = sym syscall_dispatch_trampoline,
    saved_user_rsp = sym SAVED_USER_RSP,
    syscall_stack = sym KERNEL_SYSCALL_STACK,
    stack_size = const KERNEL_SYSCALL_STACK_SIZE,
);

unsafe extern "C" {
    fn vmos_syscall_entry();
}

extern "C" fn syscall_dispatch_trampoline(frame: *mut SyscallFrame) {
    let handler = unsafe {
        ACTIVE_SYSCALL_HANDLER.expect("ring3 syscall handler was not installed before init")
    };
    handler(frame);
}

pub(crate) fn init(handler: SyscallHandler) {
    unsafe {
        ACTIVE_SYSCALL_HANDLER = Some(handler);
    }

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

pub(crate) fn capture_user_return(frame: &SyscallFrame) -> UserReturnContext {
    UserReturnContext {
        frame: *frame,
        rsp: unsafe { SAVED_USER_RSP },
        fs_base: FsBase::read().as_u64(),
    }
}

pub(crate) fn install_user_return(frame: &mut SyscallFrame, context: UserReturnContext) {
    *frame = context.frame;
    FsBase::write(VirtAddr::new(context.fs_base));
    unsafe {
        SAVED_USER_RSP = context.rsp;
    }
}

pub(crate) fn enter_user_mode(entry: u64, stack_top: u64) -> ! {
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
            "xor edx, edx",
            "iretq",
            user_data = in(reg) user_data,
            user_stack = in(reg) stack_top,
            interrupt_flag = const 0x200u64,
            user_code = in(reg) user_code,
            user_entry = in(reg) entry,
            options(noreturn),
        );
    }
}
