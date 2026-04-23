use std::env;
use std::error::Error;
use std::fs;
use std::path::PathBuf;
use std::process::{Child, Command, ExitStatus};
use std::thread;
use std::time::{Duration, Instant};

const QEMU_SUCCESS_EXIT_STATUS: i32 = 33;
const DEMO_SUCCESS_MARKER: &str = "vmos: demo completed";
const DEMO_FAILURE_MARKERS: [&str; 2] = ["vmos: demo failed:", "panic:"];
const QEMU_TIMEOUT: Duration = Duration::from_secs(30);

fn main() {
    if let Err(err) = run() {
        eprintln!("runner error: {err}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), Box<dyn Error>> {
    let config = RunConfig::parse(env::args().skip(1));

    let pid = std::process::id();
    let serial_log = env::temp_dir().join(format!("vmos-qemu-serial-{pid}.log"));
    let debug_log = env::temp_dir().join(format!("vmos-qemu-debug-{pid}.log"));
    let _ = fs::remove_file(&serial_log);
    let _ = fs::remove_file(&debug_log);

    let mut cmd = Command::new("qemu-system-x86_64");
    cmd.args([
        "-serial",
        &format!("file:{}", serial_log.display()),
        "-debugcon",
        &format!("file:{}", debug_log.display()),
        "-global",
        "isa-debugcon.iobase=0xe9",
        "-display",
        "none",
        "-no-reboot",
        "-no-shutdown",
        "-device",
        "isa-debug-exit,iobase=0xf4,iosize=0x04",
    ]);

    let uefi_image = env!("VMOS_UEFI_IMAGE");
    let code = pick_ovmf_code()?;
    let vars_template = pick_ovmf_vars()?;
    let vars_copy = copy_vars_template(&vars_template)?;

    cmd.args([
        "-drive",
        &format!("format=raw,file={uefi_image}"),
        "-drive",
        &format!("if=pflash,format=raw,readonly=on,file={}", code.display()),
        "-drive",
        &format!("if=pflash,format=raw,file={}", vars_copy.display()),
    ]);

    let mut child = cmd.args(&config.extra_args).spawn()?;
    wait_for_demo(&mut child, &serial_log, &debug_log, &config)
}

fn interpret_status(
    status: ExitStatus,
    serial_log: &PathBuf,
    debug_log: &PathBuf,
    config: &RunConfig,
) -> Result<(), Box<dyn Error>> {
    let serial = read_log(serial_log);
    match status.code() {
        Some(QEMU_SUCCESS_EXIT_STATUS) => {
            print_success_logs(&serial, &read_log(debug_log), config);
            Ok(())
        }
        Some(code) => Err(format!("qemu exited with status {code}").into()),
        None => Err("qemu terminated by signal".into()),
    }
}

fn pick_ovmf_code() -> Result<PathBuf, Box<dyn Error>> {
    for candidate in [
        "/usr/share/edk2/ovmf/OVMF_CODE.fd",
        "/usr/share/OVMF/OVMF_CODE.fd",
    ] {
        let path = PathBuf::from(candidate);
        if path.exists() {
            return Ok(path);
        }
    }

    Err("OVMF_CODE.fd not found".into())
}

fn pick_ovmf_vars() -> Result<PathBuf, Box<dyn Error>> {
    for candidate in [
        "/usr/share/edk2/ovmf/OVMF_VARS.fd",
        "/usr/share/OVMF/OVMF_VARS.fd",
    ] {
        let path = PathBuf::from(candidate);
        if path.exists() {
            return Ok(path);
        }
    }

    Err("OVMF_VARS.fd not found".into())
}

fn copy_vars_template(template: &PathBuf) -> Result<PathBuf, Box<dyn Error>> {
    let temp_dir = env::temp_dir();
    let pid = std::process::id();
    let vars_copy = temp_dir.join(format!("vmos-ovmf-vars-{pid}.fd"));
    fs::copy(template, &vars_copy)?;
    Ok(vars_copy)
}

fn wait_for_demo(
    child: &mut Child,
    serial_log: &PathBuf,
    debug_log: &PathBuf,
    config: &RunConfig,
) -> Result<(), Box<dyn Error>> {
    let deadline = Instant::now() + QEMU_TIMEOUT;

    loop {
        if let Some(status) = child.try_wait()? {
            return interpret_status(status, serial_log, debug_log, config);
        }

        let serial = read_log(serial_log);
        if serial.contains(DEMO_SUCCESS_MARKER) {
            let _ = child.kill();
            let _ = child.wait();
            print_success_logs(&serial, &read_log(debug_log), config);
            return Ok(());
        }

        if DEMO_FAILURE_MARKERS
            .iter()
            .any(|marker| serial.contains(marker))
        {
            let _ = child.kill();
            let _ = child.wait();
            let debug = read_log(debug_log);
            return Err(format!("guest reported failure\n{serial}\n{debug}").into());
        }

        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            let serial = read_log(serial_log);
            let debug = read_log(debug_log);
            return Err(
                format!("qemu timed out\nserial log:\n{serial}\ndebug log:\n{debug}").into(),
            );
        }

        thread::sleep(Duration::from_millis(100));
    }
}

fn read_log(path: &PathBuf) -> String {
    match fs::read(path) {
        Ok(bytes) => String::from_utf8_lossy(&bytes).into_owned(),
        Err(_) => String::new(),
    }
}

fn print_success_logs(serial: &str, debug: &str, config: &RunConfig) {
    if config.verbose {
        print_section("serial", &strip_ansi(serial));
        if !debug.is_empty() {
            print_section("debug", debug);
        }
        return;
    }

    print!("{}", sanitize_serial_output(serial));
}

fn sanitize_serial_output(serial: &str) -> String {
    let clean = strip_ansi(serial);
    let lines = clean.lines().collect::<Vec<_>>();
    let start = lines
        .iter()
        .position(|line| {
            let trimmed = line.trim();
            trimmed.starts_with("==") || trimmed.starts_with("vmos:")
        })
        .unwrap_or(0);

    let mut out = String::new();
    for line in lines.into_iter().skip(start) {
        let trimmed = line.trim_end();
        if trimmed.is_empty() {
            continue;
        }
        out.push_str(trimmed);
        out.push('\n');
    }
    out
}

fn strip_ansi(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    let bytes = input.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == 0x1b {
            i += 1;
            if i < bytes.len() && bytes[i] == b'[' {
                i += 1;
                while i < bytes.len() {
                    let ch = bytes[i];
                    i += 1;
                    if (0x40..=0x7e).contains(&ch) {
                        break;
                    }
                }
            }
            continue;
        }

        out.push(bytes[i] as char);
        i += 1;
    }
    out
}

fn print_section(name: &str, content: &str) {
    if content.is_empty() {
        return;
    }
    println!("--- {name} ---");
    print!("{content}");
    if !content.ends_with('\n') {
        println!();
    }
}

struct RunConfig {
    verbose: bool,
    extra_args: Vec<String>,
}

impl RunConfig {
    fn parse(args: impl IntoIterator<Item = String>) -> Self {
        let mut verbose = false;
        let mut extra_args = Vec::new();

        for arg in args {
            match arg.as_str() {
                "--verbose" => verbose = true,
                _ => extra_args.push(arg),
            }
        }

        Self {
            verbose,
            extra_args,
        }
    }
}
