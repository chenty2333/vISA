fn main() {
    if let Err(error) = visa_cli::run(std::env::args_os()) {
        eprintln!("visa: {error}");
        std::process::exit(error.exit_class().code().into());
    }
}
