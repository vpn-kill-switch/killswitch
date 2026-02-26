fn main() {
    if let Err(e) = built::write_built_file() {
        eprintln!("Failed to acquire build-time information: {e}");
        std::process::exit(1);
    }
}
