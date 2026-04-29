fn main() {
    if let Err(err) = osctl::run() {
        eprintln!("osctl error: {err}");
        std::process::exit(1);
    }
}
