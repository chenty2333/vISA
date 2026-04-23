use alloc::vec::Vec;

use wasmi::{Engine, Linker, Memory, Store, TypedFunc};

use super::wasm::{get_memory, load_module, read_memory};
use vmos_abi::{PackedStep, PlanKind, SyscallContext};

const LINUX_SYSCALL_WASM: &[u8] = include_bytes!(env!("VMOS_LINUX_SYSCALL_WASM"));

#[derive(Debug)]
pub(crate) enum LinuxCallResult {
    Ret(i64),
    Bytes(Vec<u8>),
    Pending { token: u32, delay_ms: u32 },
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
    dispatch: TypedFunc<(u64, u64, u64, u64, u64, u64, u64), u64>,
    resume_wait: TypedFunc<u32, u64>,
    plan_arg: TypedFunc<u32, u64>,
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
        let dispatch = instance
            .get_typed_func::<(u64, u64, u64, u64, u64, u64, u64), u64>(&store, "dispatch")
            .map_err(|_| "missing linux dispatch export")?;
        let resume_wait = instance
            .get_typed_func::<u32, u64>(&store, "resume_wait")
            .map_err(|_| "missing linux resume_wait export")?;
        let plan_arg = instance
            .get_typed_func::<u32, u64>(&store, "plan_arg")
            .map_err(|_| "missing linux plan_arg export")?;

        Ok(Self {
            store,
            memory,
            arg_buffer_ptr,
            arg_buffer_capacity,
            dispatch,
            resume_wait,
            plan_arg,
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
}
