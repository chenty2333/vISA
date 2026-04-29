fn main() {
    if let Err(err) = target_executor::run() {
        eprintln!("target_executor error: {err}");
        std::process::exit(1);
    }
}
