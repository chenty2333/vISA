use alloc::vec::Vec;

use wasmi::{Engine, Linker, Memory, Store, TypedFunc};

use super::types::{WaitRestartClass, WaitToken};
use super::wasm::{get_memory, load_module, read_memory};
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

pub(super) struct LinuxFrontend<'engine> {
    store: Store<()>,
    memory: Memory,
    arg_buffer_ptr: u32,
    arg_buffer_capacity: u32,
    result_buffer_ptr: u32,
    result_buffer_capacity: u32,
    dispatch: TypedFunc<(u64, u64, u64, u64, u64, u64, u64), u64>,
    dispatch_sleep_ms: TypedFunc<u64, u64>,
    dispatch_futex_raw: TypedFunc<(u64, u64, u64, u64, u64), u64>,
    resume_wait: TypedFunc<u32, u64>,
    cancel_wait: TypedFunc<(u32, i32), u64>,
    restart_wait: TypedFunc<(u32, u32), u64>,
    plan_arg: TypedFunc<u32, u64>,
    encode_uname: TypedFunc<(u32, u32), i32>,
    encode_dirents64: TypedFunc<(u32, u32, u32), i32>,
    encode_epoll_events: TypedFunc<(u32, u32, u32), i32>,
    _engine: &'engine Engine,
}

impl<'engine> LinuxFrontend<'engine> {
    pub(super) fn new(engine: &'engine Engine) -> Result<Self, &'static str> {
        let module = load_module(engine, LINUX_SYSCALL_WASM)?;
        let mut store = Store::new(engine, ());
        let linker = Linker::new(engine);
        let instance = linker
            .instantiate_and_start(&mut store, &module)
            .map_err(|_| "failed to instantiate linux_syscall")?;
        let memory = get_memory(&mut store, &instance)?;
        let arg_buffer_ptr = instance
            .get_typed_func::<(), u32>(&store, "arg_buffer_ptr")
            .map_err(|_| "missing linux arg_buffer_ptr export")?
            .call(&mut store, ())
            .map_err(|_| "failed to fetch linux arg buffer ptr")?;
        let arg_buffer_capacity = instance
            .get_typed_func::<(), u32>(&store, "arg_buffer_capacity")
            .map_err(|_| "missing linux arg_buffer_capacity export")?
            .call(&mut store, ())
            .map_err(|_| "failed to fetch linux arg buffer capacity")?;
        let result_buffer_ptr = instance
            .get_typed_func::<(), u32>(&store, "result_buffer_ptr")
            .map_err(|_| "missing linux result_buffer_ptr export")?
            .call(&mut store, ())
            .map_err(|_| "failed to fetch linux result buffer ptr")?;
        let result_buffer_capacity = instance
            .get_typed_func::<(), u32>(&store, "result_buffer_capacity")
            .map_err(|_| "missing linux result_buffer_capacity export")?
            .call(&mut store, ())
            .map_err(|_| "failed to fetch linux result buffer capacity")?;
        let dispatch = instance
            .get_typed_func::<(u64, u64, u64, u64, u64, u64, u64), u64>(&store, "dispatch")
            .map_err(|_| "missing linux dispatch export")?;
        let dispatch_sleep_ms = instance
            .get_typed_func::<u64, u64>(&store, "dispatch_sleep_ms")
            .map_err(|_| "missing linux dispatch_sleep_ms export")?;
        let dispatch_futex_raw = instance
            .get_typed_func::<(u64, u64, u64, u64, u64), u64>(&store, "dispatch_futex_raw")
            .map_err(|_| "missing linux dispatch_futex_raw export")?;
        let resume_wait = instance
            .get_typed_func::<u32, u64>(&store, "resume_wait")
            .map_err(|_| "missing linux resume_wait export")?;
        let cancel_wait = instance
            .get_typed_func::<(u32, i32), u64>(&store, "cancel_wait")
            .map_err(|_| "missing linux cancel_wait export")?;
        let restart_wait = instance
            .get_typed_func::<(u32, u32), u64>(&store, "restart_wait")
            .map_err(|_| "missing linux restart_wait export")?;
        let plan_arg = instance
            .get_typed_func::<u32, u64>(&store, "plan_arg")
            .map_err(|_| "missing linux plan_arg export")?;
        let encode_uname = instance
            .get_typed_func::<(u32, u32), i32>(&store, "encode_uname")
            .map_err(|_| "missing linux encode_uname export")?;
        let encode_dirents64 = instance
            .get_typed_func::<(u32, u32, u32), i32>(&store, "encode_dirents64")
            .map_err(|_| "missing linux encode_dirents64 export")?;
        let encode_epoll_events = instance
            .get_typed_func::<(u32, u32, u32), i32>(&store, "encode_epoll_events")
            .map_err(|_| "missing linux encode_epoll_events export")?;

        Ok(Self {
            store,
            memory,
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
            _engine: engine,
        })
    }

    pub(super) fn dispatch(&mut self, ctx: SyscallContext) -> Result<u64, &'static str> {
        self.dispatch
            .call(
                &mut self.store,
                (
                    ctx.nr,
                    ctx.args[0],
                    ctx.args[1],
                    ctx.args[2],
                    ctx.args[3],
                    ctx.args[4],
                    ctx.args[5],
                ),
            )
            .map_err(|_| "linux_syscall dispatch trapped")
    }

    pub(super) fn resume_wait(&mut self, token: u32) -> Result<u64, &'static str> {
        self.resume_wait
            .call(&mut self.store, token)
            .map_err(|_| "linux_syscall resume trapped")
    }

    pub(super) fn cancel_wait(&mut self, token: u32, errno: i32) -> Result<u64, &'static str> {
        self.cancel_wait
            .call(&mut self.store, (token, errno))
            .map_err(|_| "linux_syscall cancel trapped")
    }

    pub(super) fn restart_wait(
        &mut self,
        token: u32,
        class: WaitRestartClass,
    ) -> Result<u64, &'static str> {
        self.restart_wait
            .call(&mut self.store, (token, class as u32))
            .map_err(|_| "linux_syscall restart trapped")
    }

    pub(super) fn dispatch_sleep_ms(&mut self, delay_ms: u64) -> Result<u64, &'static str> {
        self.dispatch_sleep_ms
            .call(&mut self.store, delay_ms)
            .map_err(|_| "linux_syscall dispatch_sleep_ms trapped")
    }

    pub(super) fn dispatch_futex_raw(
        &mut self,
        key: u64,
        op: u64,
        val: u64,
        timeout_ms: u64,
        current_word: u64,
    ) -> Result<u64, &'static str> {
        self.dispatch_futex_raw
            .call(&mut self.store, (key, op, val, timeout_ms, current_word))
            .map_err(|_| "linux_syscall dispatch_futex_raw trapped")
    }

    pub(super) fn write_arg_bytes(&mut self, bytes: &[u8]) -> Result<(u32, u32), &'static str> {
        if bytes.len() > self.arg_buffer_capacity as usize {
            return Err("linux arg buffer overflowed");
        }

        self.memory
            .write(&mut self.store, self.arg_buffer_ptr as usize, bytes)
            .map_err(|_| "failed to write linux arg buffer")?;
        Ok((self.arg_buffer_ptr, bytes.len() as u32))
    }

    pub(super) fn read_bytes(&mut self, ptr: u32, len: u32) -> Result<Vec<u8>, &'static str> {
        read_memory(&self.memory, &self.store, ptr, len)
    }

    pub(super) fn encode_uname(&mut self, release: &[u8]) -> Result<Vec<u8>, &'static str> {
        let (ptr, len) = self.write_arg_bytes(release)?;
        let out_len = self
            .encode_uname
            .call(&mut self.store, (ptr, len))
            .map_err(|_| "linux_syscall encode_uname trapped")?;
        self.read_result_bytes(u32::try_from(out_len).map_err(|_| "linux uname was too large")?)
    }

    pub(super) fn encode_dirents64(
        &mut self,
        records: &[u8],
        max_len: u32,
    ) -> Result<Vec<u8>, &'static str> {
        let (ptr, len) = self.write_arg_bytes(records)?;
        let out_len = self
            .encode_dirents64
            .call(&mut self.store, (ptr, len, max_len))
            .map_err(|_| "linux_syscall encode_dirents64 trapped")?;
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
        let out_len = self
            .encode_epoll_events
            .call(&mut self.store, (ptr, len, max_events))
            .map_err(|_| "linux_syscall encode_epoll_events trapped")?;
        self.read_result_bytes(
            u32::try_from(out_len).map_err(|_| "linux epoll output was too large")?,
        )
    }

    pub(super) fn current_plan(&mut self, kind: PlanKind) -> Result<LinuxPlan, &'static str> {
        let mut args = [0u64; 6];
        for (idx, slot) in args.iter_mut().enumerate() {
            *slot = self
                .plan_arg
                .call(&mut self.store, idx as u32)
                .map_err(|_| "failed to read linux plan arg")?;
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
        read_memory(&self.memory, &self.store, self.result_buffer_ptr, len)
    }
}
