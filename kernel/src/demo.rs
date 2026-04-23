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
        self.handle_step("wasm_app", step, false)?;
        Ok(())
    }

    fn run_linux_write_demo(&mut self) -> Result<(), &'static str> {
        serial_println!("== linux write demo ==");
        let ctx = SyscallContext::new(SYS_WRITE, [1, MSG_LINUX_WRITE as u64, 0, 0, 0, 0]);
        let step = self.linux.dispatch(ctx)?;
        self.handle_step("linux_write", step, false)?;
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
        self.handle_step("linux_resume", resume, false)?;
        crate::kinfo!("nanosleep completed with explicit resume");
        Ok(())
    }

    fn run_fault_recovery_demo(&mut self) -> Result<(), &'static str> {
        serial_println!("== local recovery demo ==");
        let ctx = SyscallContext::new(SYS_WRITE, [1, MSG_FAULT_RECOVERY as u64, 0, 0, 0, 0]);
        let step = self.linux.dispatch(ctx)?;
        let decoded = self.decode_step(step);
        if decoded.tag != StepTag::ConsoleWrite {
            return Err("fault demo did not produce a console write action");
        }

        match self.console.write_message(decoded.aux, true) {
            Ok(()) => return Err("fault injection unexpectedly succeeded"),
            Err(_) => {
                crate::kinfo!("console_service trapped; recreating service store");
                self.console = ConsoleService::new(self.console.engine)?;
            }
        }

        self.console.write_message(decoded.aux, false)?;
        crate::kinfo!("console_service recovered locally");
        Ok(())
    }

    fn handle_step(
        &mut self,
        label: &str,
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
                crate::kdebug!(
                    "{}: ConsoleWrite(fd={}, message_id={})",
                    label,
                    decoded.value,
                    decoded.aux
                );
                self.console.write_message(decoded.aux, inject_fault)
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
}

struct ConsoleService<'engine> {
    engine: &'engine Engine,
    store: Store<()>,
    memory: Memory,
    write_message: TypedFunc<(u32, u32), i32>,
    message_ptr: TypedFunc<u32, u32>,
    message_len: TypedFunc<u32, u32>,
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
        let write_message = instance
            .get_typed_func::<(u32, u32), i32>(&store, "write_message")
            .map_err(|_| "missing write_message export")?;
        let message_ptr = instance
            .get_typed_func::<u32, u32>(&store, "message_ptr")
            .map_err(|_| "missing message_ptr export")?;
        let message_len = instance
            .get_typed_func::<u32, u32>(&store, "message_len")
            .map_err(|_| "missing message_len export")?;

        Ok(Self {
            engine,
            store,
            memory,
            write_message,
            message_ptr,
            message_len,
        })
    }

    fn write_message(&mut self, message_id: u32, inject_fault: bool) -> Result<(), &'static str> {
        let inject = if inject_fault { 1 } else { 0 };
        let rc = self
            .write_message
            .call(&mut self.store, (message_id, inject))
            .map_err(|_| "console_service trapped")?;
        if rc != 0 {
            return Err("console_service rejected message id");
        }

        let bytes = self.read_message(message_id)?;
        serial::write_bytes(&bytes);
        Ok(())
    }

    fn read_message(&mut self, message_id: u32) -> Result<Vec<u8>, &'static str> {
        let ptr = self
            .message_ptr
            .call(&mut self.store, message_id)
            .map_err(|_| "failed to fetch message_ptr")?;
        let len = self
            .message_len
            .call(&mut self.store, message_id)
            .map_err(|_| "failed to fetch message_len")?;
        let mut buffer = vec![0_u8; len as usize];
        self.memory
            .read(&self.store, ptr as usize, &mut buffer)
            .map_err(|_| "failed to read console_service memory")?;
        Ok(buffer)
    }
}

struct LinuxFrontend<'engine> {
    store: Store<()>,
    dispatch: TypedFunc<(u64, u64, u64, u64, u64, u64, u64), u64>,
    resume_wait: TypedFunc<u32, u64>,
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
        let dispatch = instance
            .get_typed_func::<(u64, u64, u64, u64, u64, u64, u64), u64>(&store, "dispatch")
            .map_err(|_| "missing dispatch export")?;
        let resume_wait = instance
            .get_typed_func::<u32, u64>(&store, "resume_wait")
            .map_err(|_| "missing resume_wait export")?;

        Ok(Self {
            store,
            dispatch,
            resume_wait,
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
}

struct WasmApp<'engine> {
    store: Store<()>,
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
        let run = instance
            .get_typed_func::<(), u64>(&store, "run")
            .map_err(|_| "missing run export")?;

        Ok(Self {
            store,
            run,
            _engine: engine,
        })
    }

    fn run(&mut self) -> Result<u64, &'static str> {
        self.run
            .call(&mut self.store, ())
            .map_err(|_| "wasm_app trapped")
    }
}

fn load_module(engine: &Engine, bytes: &[u8]) -> Result<Module, &'static str> {
    Module::new(engine, bytes).map_err(map_wasmi_error)
}

fn get_memory(store: &mut Store<()>, instance: &Instance) -> Result<Memory, &'static str> {
    match instance.get_export(store, "memory") {
        Some(Extern::Memory(memory)) => Ok(memory),
        _ => Err("console_service did not export linear memory"),
    }
}

fn map_wasmi_error(error: Error) -> &'static str {
    let _ = error;
    "wasmi returned an error"
}
