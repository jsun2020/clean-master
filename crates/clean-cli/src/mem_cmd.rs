//! `clean mem` - show physical-memory usage, and (with `--run`) trim working
//! sets / purge the standby list to free RAM, reporting the honest before /
//! after available memory.

use crate::fmt::human_bytes;
use clean_core::memory::{self, MemStatus};

fn print_status(s: &MemStatus) {
    println!("Memory:");
    println!("  Total:      {}", human_bytes(s.total_bytes));
    println!("  Available:  {}", human_bytes(s.avail_bytes));
    println!(
        "  Used:       {} ({}%)",
        human_bytes(s.used_bytes),
        s.percent_used
    );
}

/// `clean mem`
pub fn status() -> Result<(), String> {
    let s = memory::status();
    if s.total_bytes == 0 {
        return Err("could not read memory status (or not running on Windows)".into());
    }
    print_status(&s);
    println!("\nRun `clean mem --run` to free up memory (trim working sets).");
    Ok(())
}

/// `clean mem --run`
pub fn optimize() -> Result<(), String> {
    println!("Freeing memory (trimming process working sets)...");
    let out = memory::optimize().map_err(|e| e.to_string())?;
    println!(
        "  Before:  {} available",
        human_bytes(out.before.avail_bytes)
    );
    println!(
        "  After:   {} available",
        human_bytes(out.after.avail_bytes)
    );
    if out.freed_bytes >= 0 {
        println!("  Freed:   {}", human_bytes(out.freed_bytes as u64));
    } else {
        // Available RAM went down (other programs allocated during the run).
        // Report it honestly rather than hiding it behind a max(0, ..).
        println!("  Freed:   -{}", human_bytes((-out.freed_bytes) as u64));
    }
    println!(
        "  Trimmed {} of {} processes.",
        out.processes_trimmed, out.processes_total
    );
    if out.standby_purged {
        println!("  Standby list: purged.");
    } else if out.elevated {
        println!("  Standby list: not purged (unavailable).");
    } else {
        println!("  Standby list: skipped (needs administrator rights).");
    }
    println!(
        "\nNote: freed memory is temporary - Windows pages memory back in as programs need it. \
         This is a one-off trim, not a background optimizer."
    );
    Ok(())
}
