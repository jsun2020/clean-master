use crate::fmt::human_bytes;
use clean_core::dupes::{find_duplicates, DupeGroup, DupeOptions};
use clean_core::scanner::{ScanBackend, ScanOptions, WalkBackend};
use indicatif::{ProgressBar, ProgressStyle};
use std::path::PathBuf;
use std::time::Duration;

pub struct DupesArgs {
    pub path: PathBuf,
    pub min_size: u64,
    pub keep_priority: Vec<String>,
    pub top: usize,
}

pub fn find(args: &DupesArgs) -> Result<Vec<DupeGroup>, String> {
    let bar = ProgressBar::new_spinner();
    bar.set_style(ProgressStyle::with_template("{spinner} {msg}").expect("valid template"));
    bar.enable_steady_tick(Duration::from_millis(120));

    bar.set_message("scanning...");
    let outcome = WalkBackend
        .scan(&args.path, &ScanOptions::default(), &|seen| {
            bar.set_message(format!("scanning... {seen} entries"));
        })
        .map_err(|e| e.to_string())?;

    bar.set_message("hashing candidates (3-stage: size, head/tail, full BLAKE3)...");
    let opts = DupeOptions {
        min_size: args.min_size,
        keep_priority: args.keep_priority.clone(),
    };
    let groups = find_duplicates(&outcome.records, &opts);
    bar.finish_and_clear();
    Ok(groups)
}

/// Deletable copies across all groups. Guards: the suggested keeper must
/// still exist on disk (otherwise the whole group is skipped), and protected
/// system paths are excluded.
pub fn deletable_targets(groups: &[DupeGroup]) -> Vec<(String, u64)> {
    let mut targets = Vec::new();
    for g in groups {
        let keeper = &g.members[g.suggested_keep];
        if !std::path::Path::new(&keeper.path).is_file() {
            continue; // keeper vanished since scan: do not touch this group
        }
        for m in g.deletable() {
            if clean_core::safety::deletion_allowed(std::path::Path::new(&m.path), &[]) {
                targets.push((m.path.clone(), m.size));
            }
        }
    }
    targets
}

pub fn print_report(args: &DupesArgs, groups: &[DupeGroup], dry: bool) -> Result<(), String> {
    if groups.is_empty() {
        println!(
            "No duplicates >= {} found under {}.",
            human_bytes(args.min_size),
            args.path.display()
        );
        return Ok(());
    }

    let total_wasted: u64 = groups.iter().map(|g| g.wasted_bytes()).sum();
    let total_files: usize = groups.iter().map(|g| g.members.len() - 1).sum();

    for (i, g) in groups.iter().take(args.top).enumerate() {
        println!(
            "Group {} - {} each, {} wasted (content verified, BLAKE3 {})",
            i + 1,
            human_bytes(g.size),
            human_bytes(g.wasted_bytes()),
            &g.hash[..12]
        );
        for (idx, m) in g.members.iter().enumerate() {
            if idx == g.suggested_keep {
                println!("  KEEP    {}", m.path);
            } else {
                println!("  delete  {}", m.path);
            }
        }
        println!();
    }
    if groups.len() > args.top {
        println!("... and {} more groups (raise --top to see them).", groups.len() - args.top);
        println!();
    }
    println!(
        "{} duplicate groups, {} redundant files, {} reclaimable.",
        groups.len(),
        total_files,
        human_bytes(total_wasted)
    );
    if dry {
        println!("This was a DRY RUN. Nothing was deleted. Re-run with --apply to remove the redundant copies.");
    }
    println!("One copy of every group always survives.");
    Ok(())
}
