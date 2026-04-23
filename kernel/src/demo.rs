use alloc::vec;
use alloc::vec::Vec;

use wasmi::{Engine, Error, Extern, Instance, Linker, Memory, Module, Store, TypedFunc};

use crate::interrupts;
use crate::serial;
use crate::serial_println;
use vmos_abi::{
    DecodedStep, MSG_FAULT_RECOVERY, MSG_LINUX_WRITE, PackedStep, SYS_NANOSLEEP, SYS_WRITE,
    StepTag, SyscallContext,
};

const CONSOLE_SERVICE_WASM: &[u8] = include_bytes!(env!("VMOS_CONSOLE_SERVICE_WASM"));
const LINUX_SYSCALL_WASM: &[u8] = include_bytes!(env!("VMOS_LINUX_SYSCALL_WASM"));
const WASM_APP_WASM: &[u8] = include_bytes!(env!("VMOS_WASM_APP_WASM"));

pub fn run() -> Result<(), &'static str> {
    let engine = Engine::default();
    crate::kdebug!("wasmi engine ready");
    let mut runtime = DemoRuntime::new(&engine)?;
    crate::kdebug!("runtime ready");

    runtime.run_wasm_frontend()?;
    crate::kdebug!("wasm frontend done");
    runtime.run_linux_write_demo()?;
    crate::kdebug!("linux write done");
    runtime.run_sleep_demo()?;
    crate::kdebug!("sleep demo done");
    runtime.run_fault_recovery_demo()?;
    crate::kdebug!("fault recovery done");

    Ok(())
}

struct DemoRuntime<'engine> {
    console: ConsoleService<'engine>,
    linux: LinuxFrontend<'engine>,
    app: WasmApp<'engine>,
}

impl<'engine> DemoRuntime<'engine> {
    fn new(engine: &'engine Engine) -> Result<Self, &'static str> {
        Ok(Self {
            console: ConsoleService::new(engine)?,
            linux: LinuxFrontend::new(engine)?,
            app: WasmApp::new(engine)?,
        })
    }

    fn run_wasm_frontend(&mut self) -> Result<(), &'static str> {
        serial_println!("== wasm frontend demo ==");
        let step = self.app.run()?;
        self.handle_step("wasm_app", StepSource::WasmApp, step, false)?;
        Ok(())
    }

    fn run_linux_write_demo(&mut self) -> Result<(), &'static str> {
        serial_println!("== linux write demo ==");
        let (ptr, len) = self.linux.demo_message(MSG_LINUX_WRITE)?;
        let ctx = SyscallContext::new(SYS_WRITE, [1, ptr as u64, len as u64, 0, 0, 0]);
        let step = self.linux.dispatch(ctx)?;
        self.handle_step("linux_write", StepSource::LinuxFrontend, step, false)?;
        Ok(())
    }

    fn run_sleep_demo(&mut self) -> Result<(), &'static str> {
        serial_println!("== explicit suspend/resume demo ==");
        let ctx = SyscallContext::new(SYS_NANOSLEEP, [25, 0, 0, 0, 0, 0]);
        let step = self.linux.dispatch(ctx)?;
        let decoded = self.decode_step(step);
        if decoded.tag != StepTag::Pending {
            return Err("sleep path did not enter pending state");
        }

        crate::kinfo!(
            "linux_syscall returned Pending(token={}, delay_hint={}ms)",
            decoded.aux,
            decoded.value
        );
        crate::kinfo!("waiting for timer wakeup");
        interrupts::sleep_ms(decoded.value as u32);

        let resume = self.linux.resume_wait(decoded.aux)?;
        self.handle_step("linux_resume", StepSource::LinuxFrontend, resume, false)?;
        crate::kinfo!("nanosleep completed with explicit resume");
        Ok(())
    }

    fn run_fault_recovery_demo(&mut self) -> Result<(), &'static str> {
        serial_println!("== local recovery demo ==");
        let (ptr, len) = self.linux.demo_message(MSG_FAULT_RECOVERY)?;
        let ctx = SyscallContext::new(SYS_WRITE, [1, ptr as u64, len as u64, 0, 0, 0]);
        let step = self.linux.dispatch(ctx)?;
        let bytes = self.console_write_bytes(StepSource::LinuxFrontend, step)?;
        match self.console.write_bytes(&bytes, true) {
            Ok(()) => return Err("fault injection unexpectedly succeeded"),
            Err(_) => {
                crate::kinfo!("console_service trapped; recreating service store");
                self.console = ConsoleService::new(self.console.engine)?;
            }
        }

        self.console.write_bytes(&bytes, false)?;
        crate::kinfo!("console_service recovered locally");
        Ok(())
    }

    fn handle_step(
        &mut self,
        label: &str,
        source: StepSource,
        step: u64,
        inject_fault: bool,
    ) -> Result<(), &'static str> {
        let decoded = self.decode_step(step);
        match decoded.tag {
            StepTag::Ready => {
                crate::kdebug!("{}: Ready({})", label, decoded.value);
                Ok(())
            }
            StepTag::ConsoleWrite => {
                let len = decoded.value as u32;
                crate::kdebug!(
                    "{}: ConsoleWrite(ptr=0x{:x}, len={})",
                    label,
                    decoded.aux,
                    len
                );
                let bytes = self.console_write_bytes(source, step)?;
                self.console.write_bytes(&bytes, inject_fault)
            }
            StepTag::Pending => Err("unexpected pending step"),
            StepTag::Exit => {
                crate::kdebug!("{}: Exit({})", label, decoded.value);
                Ok(())
            }
            StepTag::Error => Err("wasm module returned an error step"),
        }
    }

    fn decode_step(&self, raw: u64) -> DecodedStep {
        PackedStep::decode(raw)
    }

    fn console_write_bytes(
        &mut self,
        source: StepSource,
        step: u64,
    ) -> Result<Vec<u8>, &'static str> {
        let decoded = self.decode_step(step);
        if decoded.tag != StepTag::ConsoleWrite {
            return Err("step was not a console write");
        }

        let len = u32::try_from(decoded.value).map_err(|_| "console write length was negative")?;
        match source {
            StepSource::WasmApp => self.app.read_bytes(decoded.aux, len),
            StepSource::LinuxFrontend => self.linux.read_bytes(decoded.aux, len),
        }
    }
}

#[derive(Clone, Copy)]
enum StepSource {
    WasmApp,
    LinuxFrontend,
}

struct ConsoleService<'engine> {
    engine: &'engine Engine,
    store: Store<()>,
    memory: Memory,
    buffer_ptr: u32,
    buffer_capacity: u32,
    commit_write: TypedFunc<(u32, u32), i32>,
}

impl<'engine> ConsoleService<'engine> {
    fn new(engine: &'engine Engine) -> Result<Self, &'static str> {
        let module = load_module(engine, CONSOLE_SERVICE_WASM)?;
        let mut store = Store::new(engine, ());
        let linker = Linker::new(engine);
        let instance = linker
            .instantiate_and_start(&mut store, &module)
            .map_err(|_| "failed to instantiate console_service")?;
        let memory = get_memory(&mut store, &instance)?;
        let buffer_ptr = instance
            .get_typed_func::<(), u32>(&store, "buffer_ptr")
            .map_err(|_| "missing buffer_ptr export")?
            .call(&mut store, ())
            .map_err(|_| "failed to fetch console buffer ptr")?;
        let buffer_capacity = instance
            .get_typed_func::<(), u32>(&store, "buffer_capacity")
            .map_err(|_| "missing buffer_capacity export")?
            .call(&mut store, ())
            .map_err(|_| "failed to fetch console buffer capacity")?;
        let commit_write = instance
            .get_typed_func::<(u32, u32), i32>(&store, "commit_write")
            .map_err(|_| "missing commit_write export")?;

        Ok(Self {
            engine,
            store,
            memory,
            buffer_ptr,
            buffer_capacity,
            commit_write,
        })
    }

    fn write_bytes(&mut self, bytes: &[u8], inject_fault: bool) -> Result<(), &'static str> {
        if bytes.len() > self.buffer_capacity as usize {
            return Err("console_service buffer too small");
        }

        self.memory
            .write(&mut self.store, self.buffer_ptr as usize, bytes)
            .map_err(|_| "failed to write console_service buffer")?;
        let inject = if inject_fault { 1 } else { 0 };
        let rc = self
            .commit_write
            .call(&mut self.store, (bytes.len() as u32, inject))
            .map_err(|_| "console_service trapped")?;
        if rc != 0 {
            return Err("console_service rejected message");
        }

        let echoed = self.read_buffer(bytes.len() as u32)?;
        serial::write_bytes(&echoed);
        Ok(())
    }

    fn read_buffer(&mut self, len: u32) -> Result<Vec<u8>, &'static str> {
        let mut buffer = vec![0_u8; len as usize];
        self.memory
            .read(&self.store, self.buffer_ptr as usize, &mut buffer)
            .map_err(|_| "failed to read console_service memory")?;
        Ok(buffer)
    }
}

struct LinuxFrontend<'engine> {
    store: Store<()>,
    memory: Memory,
    dispatch: TypedFunc<(u64, u64, u64, u64, u64, u64, u64), u64>,
    resume_wait: TypedFunc<u32, u64>,
    demo_message_ptr: TypedFunc<u32, u32>,
    demo_message_len: TypedFunc<u32, u32>,
    _engine: &'engine Engine,
}

impl<'engine> LinuxFrontend<'engine> {
    fn new(engine: &'engine Engine) -> Result<Self, &'static str> {
        let module = load_module(engine, LINUX_SYSCALL_WASM)?;
        let mut store = Store::new(engine, ());
        let linker = Linker::new(engine);
        let instance = linker
            .instantiate_and_start(&mut store, &module)
            .map_err(|_| "failed to instantiate linux_syscall")?;
        let memory = get_memory(&mut store, &instance)?;
        let dispatch = instance
            .get_typed_func::<(u64, u64, u64, u64, u64, u64, u64), u64>(&store, "dispatch")
            .map_err(|_| "missing dispatch export")?;
        let resume_wait = instance
            .get_typed_func::<u32, u64>(&store, "resume_wait")
            .map_err(|_| "missing resume_wait export")?;
        let demo_message_ptr = instance
            .get_typed_func::<u32, u32>(&store, "demo_message_ptr")
            .map_err(|_| "missing demo_message_ptr export")?;
        let demo_message_len = instance
            .get_typed_func::<u32, u32>(&store, "demo_message_len")
            .map_err(|_| "missing demo_message_len export")?;

        Ok(Self {
            store,
            memory,
            dispatch,
            resume_wait,
            demo_message_ptr,
            demo_message_len,
            _engine: engine,
        })
    }

    fn dispatch(&mut self, ctx: SyscallContext) -> Result<u64, &'static str> {
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

    fn resume_wait(&mut self, token: u32) -> Result<u64, &'static str> {
        self.resume_wait
            .call(&mut self.store, token)
            .map_err(|_| "linux_syscall resume trapped")
    }

    fn demo_message(&mut self, message_id: u32) -> Result<(u32, u32), &'static str> {
        let ptr = self
            .demo_message_ptr
            .call(&mut self.store, message_id)
            .map_err(|_| "failed to fetch linux demo ptr")?;
        let len = self
            .demo_message_len
            .call(&mut self.store, message_id)
            .map_err(|_| "failed to fetch linux demo len")?;
        if len == 0 {
            return Err("linux demo message was empty");
        }
        Ok((ptr, len))
    }

    fn read_bytes(&mut self, ptr: u32, len: u32) -> Result<Vec<u8>, &'static str> {
        read_memory(&self.memory, &self.store, ptr, len)
    }
}

struct WasmApp<'engine> {
    store: Store<()>,
    memory: Memory,
    run: TypedFunc<(), u64>,
    _engine: &'engine Engine,
}

impl<'engine> WasmApp<'engine> {
    fn new(engine: &'engine Engine) -> Result<Self, &'static str> {
        let module = load_module(engine, WASM_APP_WASM)?;
        let mut store = Store::new(engine, ());
        let linker = Linker::new(engine);
        let instance = linker
            .instantiate_and_start(&mut store, &module)
            .map_err(|_| "failed to instantiate wasm_app")?;
        let memory = get_memory(&mut store, &instance)?;
        let run = instance
            .get_typed_func::<(), u64>(&store, "run")
            .map_err(|_| "missing run export")?;

        Ok(Self {
            store,
            memory,
            run,
            _engine: engine,
        })
    }

    fn run(&mut self) -> Result<u64, &'static str> {
        self.run
            .call(&mut self.store, ())
            .map_err(|_| "wasm_app trapped")
    }

    fn read_bytes(&mut self, ptr: u32, len: u32) -> Result<Vec<u8>, &'static str> {
        read_memory(&self.memory, &self.store, ptr, len)
    }
}

fn load_module(engine: &Engine, bytes: &[u8]) -> Result<Module, &'static str> {
    Module::new(engine, bytes).map_err(map_wasmi_error)
}

fn get_memory(store: &mut Store<()>, instance: &Instance) -> Result<Memory, &'static str> {
    match instance.get_export(store, "memory") {
        Some(Extern::Memory(memory)) => Ok(memory),
        _ => Err("wasm module did not export linear memory"),
    }
}

fn read_memory(
    memory: &Memory,
    store: &Store<()>,
    ptr: u32,
    len: u32,
) -> Result<Vec<u8>, &'static str> {
    let mut buffer = vec![0_u8; len as usize];
    memory
        .read(store, ptr as usize, &mut buffer)
        .map_err(|_| "failed to read wasm linear memory")?;
    Ok(buffer)
}

fn map_wasmi_error(error: Error) -> &'static str {
    let _ = error;
    "wasmi returned an error"
}
