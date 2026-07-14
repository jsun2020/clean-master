// Debug helper: print Recycle Bin entries whose name contains the argument.
fn main() {
    let needle = std::env::args().nth(1).unwrap_or_default().to_lowercase();
    for item in trash::os_limited::list().expect("list trash") {
        if item.name.to_string_lossy().to_lowercase().contains(&needle) {
            println!(
                "name={:?} original_path={:?} exists={} time_deleted={}",
                item.name,
                item.original_path(),
                item.original_path().exists(),
                item.time_deleted
            );
        }
    }
}
