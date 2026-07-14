use std::{env, path::PathBuf, process::ExitCode};

fn main() -> ExitCode {
    let mut arguments = env::args_os();
    let program = arguments.next().unwrap_or_default();
    let command = arguments.next();
    let root = arguments.next();
    if arguments.next().is_some() || root.is_none() {
        eprintln!("usage: {} <stage3a|stage3b> <artifact-root>", PathBuf::from(program).display());
        return ExitCode::from(64);
    }
    let root = PathBuf::from(root.unwrap());
    let result = match command.as_deref().and_then(std::ffi::OsStr::to_str) {
        Some("stage3a") => visa_stage3_system::run_stage3a(&root),
        Some("stage3b") => visa_stage3_system::run_stage3b(&root),
        _ => Err("unknown Stage 3 command".to_owned()),
    };
    match result {
        Ok(path) => {
            println!("Stage 3 evidence bundle: {}", path.display());
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("Stage 3 runner failed: {error}");
            ExitCode::from(1)
        }
    }
}
