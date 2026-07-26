//! Smoke probe for the App Manager scan: prints installed-app counts and the
//! first few entries. Read-only; useful to sanity-check the registry / bundle
//! enumeration on a real machine. `cargo run -p clean-core --example list_apps`

use std::time::{SystemTime, UNIX_EPOCH};

fn main() {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    let apps = clean_core::appscan::scan_installed_apps(now, &|_| {});
    let flagged = apps.iter().filter(|a| !a.flags.is_empty()).count();
    let total: u64 = apps.iter().map(|a| a.size_bytes).sum();
    println!(
        "{} apps, {} flagged, {:.1} GiB known size",
        apps.len(),
        flagged,
        total as f64 / (1u64 << 30) as f64
    );
    for a in apps.iter().take(8) {
        println!(
            "  {:<40} {:>8.1} MiB  installed:{:<10} flags:{:?}",
            a.name.chars().take(40).collect::<String>(),
            a.size_bytes as f64 / (1u64 << 20) as f64,
            if a.install_date.is_empty() {
                "-"
            } else {
                &a.install_date
            },
            a.flags
        );
    }
}
