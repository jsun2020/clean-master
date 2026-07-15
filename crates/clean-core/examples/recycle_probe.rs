//! Debug probe: reproduce GUI apply failures. Deletes the given files via
//! trash::delete exactly like safety::recycle_files does - first from the
//! main thread, then from a spawned worker thread - printing exact errors.
//! Usage: cargo run -p clean-core --example recycle_probe -- <file1> [file2]

fn try_delete(tag: &str, path: &str) {
    let abs = std::path::absolute(path)
        .map(|p| p.display().to_string())
        .unwrap_or_else(|_| path.to_string());
    match trash::delete(&abs) {
        Ok(()) => println!("[{tag}] OK    {abs}"),
        Err(e) => println!("[{tag}] ERR   {abs}\n        {e:?}"),
    }
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.is_empty() {
        eprintln!("usage: recycle_probe <file1> [file2]");
        std::process::exit(2);
    }
    try_delete("main-thread", &args[0]);
    if let Some(second) = args.get(1).cloned() {
        std::thread::spawn(move || try_delete("worker-thread", &second))
            .join()
            .unwrap();
    }
}
