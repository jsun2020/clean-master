use crate::error::CoreError;
use crate::scanner::{ScanBackend, ScanOptions, WalkBackend};
use crate::types::FileRecord;
use globset::{GlobBuilder, GlobSet, GlobSetBuilder};
use serde::{Deserialize, Serialize};
use std::path::Path;

/// Embedded rule packs. A rule ships only if its target is regenerable
/// (caches, temp, thumbnails) or debugging leftovers (dumps, reports).
const WINDOWS_PACK: &str = include_str!("../rules/windows.json");

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum JunkCategory {
    Temp,
    Cache,
    Logs,
    Dumps,
    UpdateLeftover,
}

impl JunkCategory {
    pub fn label(&self) -> &'static str {
        match self {
            JunkCategory::Temp => "Temporary files",
            JunkCategory::Cache => "Caches",
            JunkCategory::Logs => "Log files",
            JunkCategory::Dumps => "Crash dumps & error reports",
            JunkCategory::UpdateLeftover => "Update leftovers",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RiskTier {
    /// Regenerable or purely historical data. Only this tier is deletable in MVP.
    Safe,
    /// Reserved for V2 (e.g. old Downloads); never auto-applied.
    Moderate,
}

#[derive(Debug, Clone, Deserialize)]
pub struct JunkRule {
    pub id: String,
    pub category: JunkCategory,
    pub risk: RiskTier,
    pub rationale: String,
    /// Base directory containing %ENVVAR% placeholders. A rule can never
    /// match a path outside its expanded base.
    pub base: String,
    /// Globs relative to base (case-insensitive, `/` separators).
    pub include: Vec<String>,
    /// Files modified within the last N days are never flagged.
    #[serde(default)]
    pub min_age_days: u32,
}

#[derive(Debug, Deserialize)]
pub struct RulePack {
    pub pack: String,
    pub rules: Vec<JunkRule>,
}

#[derive(Debug, Clone)]
pub struct JunkFinding {
    pub record: FileRecord,
    pub rule_id: String,
    pub category: JunkCategory,
    pub risk: RiskTier,
}

pub fn builtin_rules() -> Vec<JunkRule> {
    let pack: RulePack =
        serde_json::from_str(WINDOWS_PACK).expect("embedded rule pack must parse");
    pack.rules
}

/// Expand %VAR% placeholders from the environment.
/// Returns None when a referenced variable is not set (rule is skipped).
pub fn expand_env(input: &str) -> Option<String> {
    let mut out = String::with_capacity(input.len());
    let mut rest = input;
    while let Some(start) = rest.find('%') {
        out.push_str(&rest[..start]);
        let after = &rest[start + 1..];
        let end = after.find('%')?;
        let var = &after[..end];
        out.push_str(&std::env::var(var).ok()?);
        rest = &after[end + 1..];
    }
    out.push_str(rest);
    Some(out)
}

fn build_include_set(rule: &JunkRule) -> Result<GlobSet, CoreError> {
    let mut builder = GlobSetBuilder::new();
    for pattern in &rule.include {
        let glob = GlobBuilder::new(pattern)
            .case_insensitive(true)
            .literal_separator(true)
            .build()
            .map_err(|e| CoreError::InvalidPattern {
                pattern: pattern.clone(),
                message: format!("rule {}: {e}", rule.id),
            })?;
        builder.add(glob);
    }
    builder.build().map_err(|e| CoreError::InvalidPattern {
        pattern: rule.include.join(", "),
        message: format!("rule {}: {e}", rule.id),
    })
}

/// Pure evaluation of one rule against already-scanned records under `base`.
/// Only files (never directories) are flagged; matching is on the path
/// relative to base; recently-modified files are excluded per rule.
pub fn evaluate_records(
    rule: &JunkRule,
    base: &Path,
    records: &[FileRecord],
    now_unix: i64,
) -> Result<Vec<JunkFinding>, CoreError> {
    let include = build_include_set(rule)?;
    let min_age_secs = rule.min_age_days as i64 * 86_400;
    let mut findings = Vec::new();
    for r in records {
        if r.is_dir {
            continue;
        }
        let path = Path::new(&r.path);
        let rel = match path.strip_prefix(base) {
            Ok(rel) => rel,
            Err(_) => continue, // outside base: never flag (safety invariant)
        };
        if !include.is_match(rel) {
            continue;
        }
        if now_unix - r.modified < min_age_secs {
            continue;
        }
        findings.push(JunkFinding {
            record: r.clone(),
            rule_id: rule.id.clone(),
            category: rule.category,
            risk: rule.risk,
        });
    }
    Ok(findings)
}

pub struct RuleReport {
    pub rule: JunkRule,
    pub base: String,
    pub findings: Vec<JunkFinding>,
    pub bytes: u64,
}

/// Scan each rule's base directory and evaluate. Missing bases (app not
/// installed) and unreadable subtrees are skipped silently by design.
pub fn evaluate_all(rules: &[JunkRule], now_unix: i64) -> Vec<RuleReport> {
    let mut reports = Vec::new();
    for rule in rules {
        let Some(base) = expand_env(&rule.base) else {
            continue;
        };
        let base_path = Path::new(&base);
        if !base_path.is_dir() {
            continue;
        }
        let Ok(outcome) = WalkBackend.scan(base_path, &ScanOptions::default(), &mut |_| {}) else {
            continue;
        };
        let Ok(findings) = evaluate_records(rule, base_path, &outcome.records, now_unix) else {
            continue;
        };
        let bytes = findings.iter().map(|f| f.record.size).sum();
        reports.push(RuleReport {
            rule: rule.clone(),
            base,
            findings,
            bytes,
        });
    }
    reports
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scanner::{ScanBackend, ScanOptions, WalkBackend};
    use std::fs;

    const NOW: i64 = 1_800_000_000;

    fn rule(include: &[&str], min_age_days: u32) -> JunkRule {
        JunkRule {
            id: "test.rule".into(),
            category: JunkCategory::Temp,
            risk: RiskTier::Safe,
            rationale: "test".into(),
            base: "unused".into(),
            include: include.iter().map(|s| s.to_string()).collect(),
            min_age_days,
        }
    }

    fn scan_records(root: &Path) -> Vec<FileRecord> {
        WalkBackend
            .scan(root, &ScanOptions::default(), &mut |_| {})
            .unwrap()
            .records
    }

    #[test]
    fn builtin_pack_parses_and_is_safe_tier_only() {
        let rules = builtin_rules();
        assert!(rules.len() >= 8);
        assert!(rules.iter().all(|r| r.risk == RiskTier::Safe));
        assert!(rules.iter().all(|r| !r.include.is_empty()));
    }

    #[test]
    fn matches_only_inside_base_and_pattern() {
        let dir = tempfile::tempdir().unwrap();
        let base = dir.path().join("profile");
        fs::create_dir_all(base.join("Cache").join("data")).unwrap();
        fs::create_dir_all(base.join("Documents")).unwrap();
        fs::write(base.join("Cache").join("data").join("f_0001"), vec![0u8; 100]).unwrap();
        fs::write(base.join("Documents").join("thesis.docx"), vec![0u8; 100]).unwrap();

        let records = scan_records(&base);
        // File modified "now" but min_age 0 allows it.
        let findings =
            evaluate_records(&rule(&["Cache/**"], 0), &base, &records, NOW + 10 * 86_400)
                .unwrap();
        assert_eq!(findings.len(), 1);
        assert!(findings[0].record.path.ends_with("f_0001"));
    }

    #[test]
    fn min_age_excludes_fresh_files() {
        let dir = tempfile::tempdir().unwrap();
        let base = dir.path();
        fs::write(base.join("fresh.tmp"), b"x").unwrap();
        let records = scan_records(base);
        let now = records[0].modified; // same second as file mtime
        let findings = evaluate_records(&rule(&["**"], 1), base, &records, now).unwrap();
        assert!(findings.is_empty());
        // 2 days later the same file is eligible
        let findings =
            evaluate_records(&rule(&["**"], 1), base, &records, now + 2 * 86_400).unwrap();
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn directories_are_never_flagged() {
        let dir = tempfile::tempdir().unwrap();
        fs::create_dir_all(dir.path().join("sub")).unwrap();
        fs::write(dir.path().join("sub").join("a.tmp"), b"x").unwrap();
        let records = scan_records(dir.path());
        let findings =
            evaluate_records(&rule(&["**"], 0), dir.path(), &records, NOW * 2).unwrap();
        assert!(findings.iter().all(|f| !f.record.is_dir));
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn records_outside_base_never_match() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("a.tmp"), b"x").unwrap();
        let records = scan_records(dir.path());
        // Evaluate against a DIFFERENT base: nothing may match.
        let other = dir.path().join("other-base");
        let findings = evaluate_records(&rule(&["**"], 0), &other, &records, NOW * 2).unwrap();
        assert!(findings.is_empty());
    }

    #[test]
    fn expand_env_replaces_variables() {
        std::env::set_var("CLEAN_TEST_VAR", "value123");
        assert_eq!(
            expand_env("pre\\%CLEAN_TEST_VAR%\\post").as_deref(),
            Some("pre\\value123\\post")
        );
        assert_eq!(expand_env("no vars here").as_deref(), Some("no vars here"));
        assert!(expand_env("%CLEAN_TEST_UNSET_VAR_XYZ%").is_none());
    }
}
