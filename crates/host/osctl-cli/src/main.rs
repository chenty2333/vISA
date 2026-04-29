fn main() {
    if let Err(err) = osctl_cli::run() {
        eprintln!("osctl error: {err}");
        std::process::exit(1);
    }
}
