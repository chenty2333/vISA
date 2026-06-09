use std::{
    env,
    error::Error,
    fs,
    path::PathBuf,
    process::{Child, Command, ExitStatus},
    thread,
    time::{Duration, Instant},
};

const QEMU_SUCCESS_EXIT_STATUS: i32 = 33;
const DEMO_SUCCESS_MARKER: &str = "visa: demo completed";
const DEMO_FAILURE_MARKERS: [&str; 2] = ["visa: demo failed:", "panic:"];
const QEMU_TIMEOUT: Duration = Duration::from_secs(30);

fn main() {
    if let Err(err) = run() {
        eprintln!("runner error: {err}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), Box<dyn Error>> {
    let config = RunConfig::parse(env::args().skip(1))?;

    let pid = std::process::id();
    let serial_log = env::temp_dir().join(format!("visa-qemu-serial-{pid}.log"));
    let debug_log = env::temp_dir().join(format!("visa-qemu-debug-{pid}.log"));
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

    let uefi_image = env!("VISA_UEFI_IMAGE");
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
    if serial_has_expected_user_status(&serial, config) {
        print_success_logs(&serial, &read_log(debug_log), config);
        return Ok(());
    }
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
    for candidate in ["/usr/share/edk2/ovmf/OVMF_CODE.fd", "/usr/share/OVMF/OVMF_CODE.fd"] {
        let path = PathBuf::from(candidate);
        if path.exists() {
            return Ok(path);
        }
    }

    Err("OVMF_CODE.fd not found".into())
}

fn pick_ovmf_vars() -> Result<PathBuf, Box<dyn Error>> {
    for candidate in ["/usr/share/edk2/ovmf/OVMF_VARS.fd", "/usr/share/OVMF/OVMF_VARS.fd"] {
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
    let vars_copy = temp_dir.join(format!("visa-ovmf-vars-{pid}.fd"));
    fs::copy(template, &vars_copy)?;
    Ok(vars_copy)
}

fn wait_for_demo(
    child: &mut Child,
    serial_log: &PathBuf,
    debug_log: &PathBuf,
    config: &RunConfig,
) -> Result<(), Box<dyn Error>> {
    let deadline = Instant::now() + config.qemu_timeout;

    loop {
        if let Some(status) = child.try_wait()? {
            return interpret_status(status, serial_log, debug_log, config);
        }

        let serial = read_log(serial_log);
        if serial_has_expected_user_status(&serial, config) {
            let _ = child.kill();
            let _ = child.wait();
            print_success_logs(&serial, &read_log(debug_log), config);
            return Ok(());
        }

        if serial.contains(DEMO_SUCCESS_MARKER) {
            let _ = child.kill();
            let _ = child.wait();
            print_success_logs(&serial, &read_log(debug_log), config);
            return Ok(());
        }

        if DEMO_FAILURE_MARKERS.iter().any(|marker| serial.contains(marker)) {
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
                format!("qemu timed out\nserial log:\n{serial}\ndebug log:\n{debug}").into()
            );
        }

        thread::sleep(Duration::from_millis(100));
    }
}

fn serial_has_expected_user_status(serial: &str, config: &RunConfig) -> bool {
    config.expected_user_status.is_some_and(|status| {
        serial.contains(&format!("visa: user ELF exited with status {status}"))
    })
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
            trimmed.starts_with("==") || trimmed.starts_with("visa:")
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
    qemu_timeout: Duration,
    expected_user_status: Option<i32>,
    extra_args: Vec<String>,
}

impl RunConfig {
    fn parse(args: impl IntoIterator<Item = String>) -> Result<Self, Box<dyn Error>> {
        let mut verbose = false;
        let mut extra_args = Vec::new();

        for arg in args {
            match arg.as_str() {
                "--verbose" => verbose = true,
                _ => extra_args.push(arg),
            }
        }

        Ok(Self {
            verbose,
            qemu_timeout: configured_qemu_timeout()?,
            expected_user_status: configured_expected_user_status()?,
            extra_args,
        })
    }
}

fn configured_expected_user_status() -> Result<Option<i32>, Box<dyn Error>> {
    for key in ["VISA_EXPECT_USER_STATUS", "VISA_EXPECT_USER_EXIT_STATUS"] {
        if let Ok(raw) = env::var(key) {
            let trimmed = raw.trim();
            if trimmed.is_empty() {
                return Ok(None);
            }
            let status =
                trimmed.parse::<i32>().map_err(|_| format!("invalid {key} value: {raw}"))?;
            return Ok(Some(status));
        }
    }
    Ok(None)
}

fn configured_qemu_timeout() -> Result<Duration, Box<dyn Error>> {
    for key in ["VISA_QEMU_TIMEOUT", "VISA_QEMU_TIMEOUT_SECS", "VISA_LTP_RUN_TIMEOUT"] {
        if let Ok(raw) = env::var(key) {
            return parse_timeout_duration(&raw)
                .ok_or_else(|| format!("invalid {key} value: {raw}").into());
        }
    }
    Ok(QEMU_TIMEOUT)
}

fn parse_timeout_duration(raw: &str) -> Option<Duration> {
    let value = raw.trim();
    if value.is_empty() {
        return None;
    }

    if let Some(ms) = value.strip_suffix("ms") {
        return ms.trim().parse::<u64>().ok().map(Duration::from_millis);
    }
    if let Some(seconds) = value.strip_suffix('s') {
        return seconds.trim().parse::<u64>().ok().map(Duration::from_secs);
    }
    if let Some(minutes) = value.strip_suffix('m') {
        return minutes
            .trim()
            .parse::<u64>()
            .ok()
            .map(|minutes| Duration::from_secs(minutes.saturating_mul(60)));
    }

    value.parse::<u64>().ok().map(Duration::from_secs)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config_with_expected_status(status: Option<i32>) -> RunConfig {
        RunConfig {
            verbose: false,
            qemu_timeout: Duration::from_secs(1),
            expected_user_status: status,
            extra_args: Vec::new(),
        }
    }

    #[test]
    fn expected_user_status_matches_linux_elf_exit_marker() {
        let config = config_with_expected_status(Some(135));

        assert!(serial_has_expected_user_status(
            "visa: user ELF exited with status 135\n",
            &config
        ));
        assert!(!serial_has_expected_user_status(
            "visa: user ELF exited with status 139\n",
            &config
        ));
    }

    #[test]
    fn expected_user_status_is_disabled_by_default() {
        let config = config_with_expected_status(None);

        assert!(!serial_has_expected_user_status(
            "visa: user ELF exited with status 135\n",
            &config
        ));
    }
}
