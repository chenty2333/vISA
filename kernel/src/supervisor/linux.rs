use alloc::vec::Vec;

use super::engine::{ModuleInstance, SupervisorEngine, WasmFn};
use super::types::{WaitRestartClass, WaitToken};
use vmos_abi::{PackedStep, PlanKind, SyscallContext};

const LINUX_SYSCALL_WASM: &[u8] = include_bytes!(env!("VMOS_LINUX_SYSCALL_WASM"));

#[derive(Debug)]
pub(crate) enum LinuxCallResult {
    Ret(i64),
    Bytes(Vec<u8>),
    Pending(WaitToken),
    Exit(i32),
}

#[derive(Clone, Copy, Debug)]
pub(super) struct LinuxPlan {
    pub(super) kind: PlanKind,
    pub(super) args: [u64; 6],
}

pub(super) struct LinuxFrontend {
    module: ModuleInstance,
    arg_buffer_ptr: u32,
    arg_buffer_capacity: u32,
    result_buffer_ptr: u32,
    result_buffer_capacity: u32,
    dispatch: WasmFn<(u64, u64, u64, u64, u64, u64, u64), u64>,
    dispatch_sleep_ms: WasmFn<u64, u64>,
    dispatch_futex_raw: WasmFn<(u64, u64, u64, u64, u64), u64>,
    resume_wait: WasmFn<u32, u64>,
    cancel_wait: WasmFn<(u32, i32), u64>,
    restart_wait: WasmFn<(u32, u32), u64>,
    plan_arg: WasmFn<u32, u64>,
    encode_uname: WasmFn<(u32, u32), i32>,
    encode_dirents64: WasmFn<(u32, u32, u32), i32>,
    encode_epoll_events: WasmFn<(u32, u32, u32), i32>,
}

impl LinuxFrontend {
    pub(super) fn new(engine: &SupervisorEngine) -> Result<Self, &'static str> {
        let mut module = ModuleInstance::instantiate(
            engine,
            LINUX_SYSCALL_WASM,
            "failed to instantiate linux_syscall",
        )?;
        let arg_buffer_ptr = module.export_u32(
            "arg_buffer_ptr",
            "missing linux arg_buffer_ptr export",
            "failed to fetch linux arg buffer ptr",
        )?;
        let arg_buffer_capacity = module.export_u32(
            "arg_buffer_capacity",
            "missing linux arg_buffer_capacity export",
            "failed to fetch linux arg buffer capacity",
        )?;
        let result_buffer_ptr = module.export_u32(
            "result_buffer_ptr",
            "missing linux result_buffer_ptr export",
            "failed to fetch linux result buffer ptr",
        )?;
        let result_buffer_capacity = module.export_u32(
            "result_buffer_capacity",
            "missing linux result_buffer_capacity export",
            "failed to fetch linux result buffer capacity",
        )?;
        let dispatch = module.bind("dispatch", "missing linux dispatch export")?;
        let dispatch_sleep_ms = module.bind(
            "dispatch_sleep_ms",
            "missing linux dispatch_sleep_ms export",
        )?;
        let dispatch_futex_raw = module.bind(
            "dispatch_futex_raw",
            "missing linux dispatch_futex_raw export",
        )?;
        let resume_wait = module.bind("resume_wait", "missing linux resume_wait export")?;
        let cancel_wait = module.bind("cancel_wait", "missing linux cancel_wait export")?;
        let restart_wait = module.bind("restart_wait", "missing linux restart_wait export")?;
        let plan_arg = module.bind("plan_arg", "missing linux plan_arg export")?;
        let encode_uname = module.bind("encode_uname", "missing linux encode_uname export")?;
        let encode_dirents64 =
            module.bind("encode_dirents64", "missing linux encode_dirents64 export")?;
        let encode_epoll_events = module.bind(
            "encode_epoll_events",
            "missing linux encode_epoll_events export",
        )?;

        Ok(Self {
            module,
            arg_buffer_ptr,
            arg_buffer_capacity,
            result_buffer_ptr,
            result_buffer_capacity,
            dispatch,
            dispatch_sleep_ms,
            dispatch_futex_raw,
            resume_wait,
            cancel_wait,
            restart_wait,
            plan_arg,
            encode_uname,
            encode_dirents64,
            encode_epoll_events,
        })
    }

    pub(super) fn dispatch(&mut self, ctx: SyscallContext) -> Result<u64, &'static str> {
        self.module.call(
            &self.dispatch,
            (
                ctx.nr,
                ctx.args[0],
                ctx.args[1],
                ctx.args[2],
                ctx.args[3],
                ctx.args[4],
                ctx.args[5],
            ),
            "linux_syscall dispatch trapped",
        )
    }

    pub(super) fn resume_wait(&mut self, token: u32) -> Result<u64, &'static str> {
        self.module
            .call(&self.resume_wait, token, "linux_syscall resume trapped")
    }

    pub(super) fn cancel_wait(&mut self, token: u32, errno: i32) -> Result<u64, &'static str> {
        self.module.call(
            &self.cancel_wait,
            (token, errno),
            "linux_syscall cancel trapped",
        )
    }

    pub(super) fn restart_wait(
        &mut self,
        token: u32,
        class: WaitRestartClass,
    ) -> Result<u64, &'static str> {
        self.module.call(
            &self.restart_wait,
            (token, class as u32),
            "linux_syscall restart trapped",
        )
    }

    pub(super) fn dispatch_sleep_ms(&mut self, delay_ms: u64) -> Result<u64, &'static str> {
        self.module.call(
            &self.dispatch_sleep_ms,
            delay_ms,
            "linux_syscall dispatch_sleep_ms trapped",
        )
    }

    pub(super) fn dispatch_futex_raw(
        &mut self,
        key: u64,
        op: u64,
        val: u64,
        timeout_ms: u64,
        current_word: u64,
    ) -> Result<u64, &'static str> {
        self.module.call(
            &self.dispatch_futex_raw,
            (key, op, val, timeout_ms, current_word),
            "linux_syscall dispatch_futex_raw trapped",
        )
    }

    pub(super) fn write_arg_bytes(&mut self, bytes: &[u8]) -> Result<(u32, u32), &'static str> {
        if bytes.len() > self.arg_buffer_capacity as usize {
            return Err("linux arg buffer overflowed");
        }

        self.module.write_memory(
            self.arg_buffer_ptr,
            bytes,
            "failed to write linux arg buffer",
        )?;
        Ok((self.arg_buffer_ptr, bytes.len() as u32))
    }

    pub(super) fn read_bytes(&mut self, ptr: u32, len: u32) -> Result<Vec<u8>, &'static str> {
        self.module
            .read_memory(ptr, len, "failed to read linux linear memory")
    }

    pub(super) fn encode_uname(&mut self, release: &[u8]) -> Result<Vec<u8>, &'static str> {
        let (ptr, len) = self.write_arg_bytes(release)?;
        let out_len = self.module.call(
            &self.encode_uname,
            (ptr, len),
            "linux_syscall encode_uname trapped",
        )?;
        self.read_result_bytes(u32::try_from(out_len).map_err(|_| "linux uname was too large")?)
    }

    pub(super) fn encode_dirents64(
        &mut self,
        records: &[u8],
        max_len: u32,
    ) -> Result<Vec<u8>, &'static str> {
        let (ptr, len) = self.write_arg_bytes(records)?;
        let out_len = self.module.call(
            &self.encode_dirents64,
            (ptr, len, max_len),
            "linux_syscall encode_dirents64 trapped",
        )?;
        self.read_result_bytes(
            u32::try_from(out_len).map_err(|_| "linux dirent output was too large")?,
        )
    }

    pub(super) fn encode_epoll_events(
        &mut self,
        records: &[u8],
        max_events: u32,
    ) -> Result<Vec<u8>, &'static str> {
        let (ptr, len) = self.write_arg_bytes(records)?;
        let out_len = self.module.call(
            &self.encode_epoll_events,
            (ptr, len, max_events),
            "linux_syscall encode_epoll_events trapped",
        )?;
        self.read_result_bytes(
            u32::try_from(out_len).map_err(|_| "linux epoll output was too large")?,
        )
    }

    pub(super) fn current_plan(&mut self, kind: PlanKind) -> Result<LinuxPlan, &'static str> {
        let mut args = [0u64; 6];
        for (idx, slot) in args.iter_mut().enumerate() {
            *slot =
                self.module
                    .call(&self.plan_arg, idx as u32, "failed to read linux plan arg")?;
        }

        Ok(LinuxPlan { kind, args })
    }

    #[allow(dead_code)]
    pub(super) fn decode_step(raw: u64) -> vmos_abi::DecodedStep {
        PackedStep::decode(raw)
    }

    fn read_result_bytes(&mut self, len: u32) -> Result<Vec<u8>, &'static str> {
        if len > self.result_buffer_capacity {
            return Err("linux result buffer overflowed");
        }
        self.module.read_memory(
            self.result_buffer_ptr,
            len,
            "failed to read linux result buffer",
        )
    }
}
