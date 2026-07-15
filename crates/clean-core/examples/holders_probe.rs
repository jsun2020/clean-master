//! Debug probe: print which running apps hold the given files open.
//! Usage: cargo run -p clean-core --example holders_probe -- <file...>

fn main() {
    let paths: Vec<String> = std::env::args().skip(1).collect();
    if paths.is_empty() {
        eprintln!("usage: holders_probe <file...>");
        std::process::exit(2);
    }
    let holders = clean_core::safety::in_use_by(&paths);
    if holders.is_empty() {
        println!("no holders detected");
    } else {
        println!("in use by: {}", holders.join(", "));
    }
}
