use crate::fmt::human_bytes;
use clean_core::rules::{self, RuleReport};
use comfy_table::{presets::UTF8_FULL_CONDENSED, Cell, CellAlignment, Table};
use std::time::{SystemTime, UNIX_EPOCH};

pub fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

pub fn collect_reports() -> Vec<RuleReport> {
    rules::evaluate_all(&rules::builtin_rules(), now_unix())
}

/// Report what would be (or is about to be) reclaimed, grouped by category.
/// Returns the deletable targets and the rule bases they are authorized under.
pub fn report(dry: bool) -> (Vec<(String, u64)>, Vec<std::path::PathBuf>) {
    if dry {
        println!("Scanning junk locations (dry run - nothing will be deleted)...");
    } else {
        println!("Scanning junk locations...");
    }
    let reports = collect_reports();

    let mut t = Table::new();
    t.load_preset(UTF8_FULL_CONDENSED);
    t.set_header(vec!["Category", "Rule", "Location", "Files", "Reclaimable"]);

    let mut total_files = 0usize;
    let mut total_bytes = 0u64;
    for r in &reports {
        if r.findings.is_empty() {
            continue;
        }
        total_files += r.findings.len();
        total_bytes += r.bytes;
        t.add_row(vec![
            Cell::new(r.rule.category.label()),
            Cell::new(&r.rule.id),
            Cell::new(&r.base),
            Cell::new(r.findings.len()).set_alignment(CellAlignment::Right),
            Cell::new(human_bytes(r.bytes)).set_alignment(CellAlignment::Right),
        ]);
    }

    if total_files == 0 {
        println!("No junk found in the known-safe locations. Nice and tidy.");
        return (Vec::new(), Vec::new());
    }
    println!("{t}");
    println!();
    println!(
        "Total reclaimable: {} across {} files.",
        human_bytes(total_bytes),
        total_files
    );
    if dry {
        println!("This was a DRY RUN. Nothing was deleted. Re-run with --apply to clean.");
        println!("Use `clean rules list` to see why each location is considered safe.");
    }

    let bases: Vec<std::path::PathBuf> = reports
        .iter()
        .map(|r| std::path::PathBuf::from(&r.base))
        .collect();
    let targets: Vec<(String, u64)> = reports
        .iter()
        .flat_map(|r| r.findings.iter())
        .map(|f| (f.record.path.clone(), f.record.size))
        .collect();
    (targets, bases)
}

/// `clean rules list`
pub fn list_rules() {
    let mut t = Table::new();
    t.load_preset(UTF8_FULL_CONDENSED);
    t.set_header(vec!["Rule", "Category", "Risk", "Min age", "Location", "Why it is safe"]);
    for rule in rules::builtin_rules() {
        let base = rules::expand_env(&rule.base).unwrap_or_else(|| rule.base.clone());
        t.add_row(vec![
            Cell::new(&rule.id),
            Cell::new(rule.category.label()),
            Cell::new(format!("{:?}", rule.risk)),
            Cell::new(format!("{}d", rule.min_age_days)),
            Cell::new(base),
            Cell::new(&rule.rationale),
        ]);
    }
    println!("{t}");
}
