//! Installed-software discovery for the App Manager screen: list installed
//! programs with size / install date / a best-effort "last used" estimate,
//! and flag removal candidates (long unused, old install, known bundleware).
//!
//! Safety by construction: this module never deletes anything. On Windows the
//! caller launches the vendor's own `UninstallString` (exactly what Settings >
//! Apps does); on macOS the caller recycles the .app bundle through the
//! standard manifest/undo pipeline. Heuristics only ever produce *flags* -
//! removal is always the user's explicit per-app choice.

use std::path::Path;
use std::time::UNIX_EPOCH;

/// How an app is removed. The GUI re-derives this server-side by index;
/// nothing here is ever accepted from the webview.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AppRemoval {
    /// Windows: spawn this registry-provided command (vendor uninstaller).
    WindowsUninstall { uninstall_string: String },
    /// macOS: move this .app bundle to the Trash (undo-able).
    MacBundle { path: String },
}

#[derive(Debug, Clone)]
pub struct InstalledApp {
    pub name: String,
    pub version: String,
    pub publisher: String,
    /// "YYYY-MM-DD" or empty when the platform does not record it.
    pub install_date: String,
    /// 0 = unknown (never fabricated).
    pub size_bytes: u64,
    pub location: String,
    /// Unix seconds of the newest executable access/modify time in the
    /// install location; 0 = unknown. An estimate, labeled so in the UI.
    pub last_used_unix: i64,
    /// "unused" | "old" | "bundleware" (any subset, ordered).
    pub flags: Vec<String>,
    pub removal: AppRemoval,
}

// ------------------------------------------------------------ heuristics --

const SECS_PER_DAY: i64 = 86_400;
/// No launch evidence for this long -> "unused".
pub const UNUSED_AFTER_DAYS: i64 = 180;
/// Installed this long ago AND stale -> "old".
pub const OLD_INSTALL_DAYS: i64 = 365;
const OLD_STALE_USE_DAYS: i64 = 90;

/// Known bundleware / rider software, matched case-insensitively against
/// name + publisher. Deliberately short and unambiguous: a match is evidence
/// shown to the user, never an automatic action.
const BUNDLEWARE_PATTERNS: &[&str] = &[
    "2345",
    "hao123",
    "toolbar",
    "webadvisor",
    "web companion",
    "search protect",
    "wildtangent",
    "pc app store",
    "mcafee security scan",
    "driver updater",
];

pub fn is_bundleware(name: &str, publisher: &str) -> bool {
    let hay = format!("{} {}", name, publisher).to_lowercase();
    BUNDLEWARE_PATTERNS.iter().any(|p| hay.contains(p))
}

/// Registry entries that are OS patches, not applications.
pub fn is_update_entry(name: &str) -> bool {
    let n = name.trim();
    let lower = n.to_lowercase();
    (n.starts_with("KB") && n[2..].chars().take(4).all(|c| c.is_ascii_digit()) && n.len() > 4)
        || lower.starts_with("update for ")
        || lower.starts_with("security update for ")
        || lower.starts_with("hotfix for ")
}

/// "20230112" -> "2023-01-12". Anything malformed -> None.
pub fn parse_install_date(raw: &str) -> Option<String> {
    let d = raw.trim();
    if d.len() != 8 || !d.chars().all(|c| c.is_ascii_digit()) {
        return None;
    }
    Some(format!("{}-{}-{}", &d[..4], &d[4..6], &d[6..8]))
}

/// Days-from-civil (Howard Hinnant's algorithm) -> unix seconds at midnight.
pub fn install_date_unix(date_iso: &str) -> Option<i64> {
    let mut parts = date_iso.splitn(3, '-');
    let y: i64 = parts.next()?.parse().ok()?;
    let m: i64 = parts.next()?.parse().ok()?;
    let d: i64 = parts.next()?.parse().ok()?;
    if !(1..=12).contains(&m) || !(1..=31).contains(&d) {
        return None;
    }
    let yy = if m <= 2 { y - 1 } else { y };
    let era = if yy >= 0 { yy } else { yy - 399 } / 400;
    let yoe = yy - era * 400;
    let mp = if m > 2 { m - 3 } else { m + 9 };
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    Some((era * 146_097 + doe - 719_468) * SECS_PER_DAY)
}

/// Pure flag computation. `install_unix` / `last_used_unix`: None = unknown.
/// Unknown never *creates* a flag on its own - we only flag on evidence.
pub fn classify(
    now_unix: i64,
    install_unix: Option<i64>,
    last_used_unix: Option<i64>,
    bundleware: bool,
) -> Vec<String> {
    let mut flags = Vec::new();
    let stale_days = last_used_unix.map(|t| (now_unix - t) / SECS_PER_DAY);
    if let Some(days) = stale_days {
        if days > UNUSED_AFTER_DAYS {
            flags.push("unused".to_string());
        }
    }
    if let Some(inst) = install_unix {
        let old = (now_unix - inst) / SECS_PER_DAY > OLD_INSTALL_DAYS;
        // An old install only counts when usage is also stale (or unknown
        // usage, in which case the install date is the only evidence we have
        // AND it must be old; recently-used old installs are healthy apps).
        let stale = stale_days.map(|d| d > OLD_STALE_USE_DAYS).unwrap_or(true);
        if old && stale {
            flags.push("old".to_string());
        }
    }
    if bundleware {
        flags.push("bundleware".to_string());
    }
    flags
}

/// Newest access-or-modified time (unix secs) among top-level files in `dir`
/// whose extension matches `ext` (empty = any file). Bounded: one directory
/// read, no recursion, enumeration-cached metadata only (EDR-safe, LL-021).
pub fn newest_file_time_in(dir: &Path, ext: &str) -> Option<i64> {
    let entries = std::fs::read_dir(dir).ok()?;
    let mut newest: Option<i64> = None;
    for entry in entries.flatten().take(512) {
        let Ok(ft) = entry.file_type() else { continue };
        if !ft.is_file() {
            continue;
        }
        if !ext.is_empty() {
            let name = entry.file_name();
            let matches = Path::new(&name)
                .extension()
                .map(|e| e.eq_ignore_ascii_case(ext))
                .unwrap_or(false);
            if !matches {
                continue;
            }
        }
        let Ok(meta) = entry.metadata() else { continue };
        for t in [meta.accessed().ok(), meta.modified().ok()]
            .into_iter()
            .flatten()
        {
            if let Ok(d) = t.duration_since(UNIX_EPOCH) {
                let secs = d.as_secs() as i64;
                if newest.map(|n| secs > n).unwrap_or(true) {
                    newest = Some(secs);
                }
            }
        }
    }
    newest
}

// ------------------------------------------- macOS-style .app enumeration --
// Platform-neutral directory logic so it is unit-testable on any OS; the
// macOS scan entry point below feeds it the real /Applications directories.

/// One pass over `dir`: every `*.app` directory becomes an app entry
/// (unsized; the caller sizes in parallel).
pub fn app_bundles_in(dir: &Path) -> Vec<(String, String)> {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for entry in entries.flatten() {
        let Ok(ft) = entry.file_type() else { continue };
        if !ft.is_dir() || ft.is_symlink() {
            continue;
        }
        let name = entry.file_name().to_string_lossy().into_owned();
        if let Some(stem) = name.strip_suffix(".app") {
            if !stem.is_empty() {
                out.push((stem.to_string(), entry.path().display().to_string()));
            }
        }
    }
    out.sort();
    out
}

// ----------------------------------------------------------- Windows scan --

#[cfg(windows)]
mod win {
    use super::*;
    use winreg::enums::{HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE};
    use winreg::RegKey;

    const HIVES: &[(winreg::HKEY, &str)] = &[
        (
            HKEY_LOCAL_MACHINE,
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
        ),
        (
            HKEY_LOCAL_MACHINE,
            r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall",
        ),
        (
            HKEY_CURRENT_USER,
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
        ),
    ];

    pub fn scan(now_unix: i64, progress: &(dyn Fn(u64) + Sync)) -> Vec<InstalledApp> {
        let mut apps: Vec<InstalledApp> = Vec::new();
        let mut seen = 0u64;
        for (hive, path) in HIVES {
            let Ok(root) = RegKey::predef(*hive).open_subkey(path) else {
                continue;
            };
            for sub in root.enum_keys().flatten() {
                seen += 1;
                if seen.is_multiple_of(64) {
                    progress(seen);
                }
                let Ok(k) = root.open_subkey(&sub) else {
                    continue;
                };
                let name: String = k.get_value("DisplayName").unwrap_or_default();
                let name = name.trim().to_string();
                if name.is_empty() || is_update_entry(&name) {
                    continue;
                }
                if k.get_value::<u32, _>("SystemComponent").unwrap_or(0) == 1 {
                    continue;
                }
                let parent: String = k.get_value("ParentKeyName").unwrap_or_default();
                if !parent.trim().is_empty() {
                    continue;
                }
                let uninstall: String = k.get_value("UninstallString").unwrap_or_default();
                if uninstall.trim().is_empty() {
                    continue;
                }
                let publisher: String = k.get_value("Publisher").unwrap_or_default();
                let version: String = k.get_value("DisplayVersion").unwrap_or_default();
                let location: String = k.get_value("InstallLocation").unwrap_or_default();
                let raw_date: String = k.get_value("InstallDate").unwrap_or_default();
                let install_date = parse_install_date(&raw_date).unwrap_or_default();
                // EstimatedSize is stored in KB.
                let size_kb: u32 = k.get_value("EstimatedSize").unwrap_or(0);

                let last_used = if location.trim().is_empty() {
                    None
                } else {
                    newest_file_time_in(Path::new(location.trim()), "exe")
                };
                let flags = classify(
                    now_unix,
                    if install_date.is_empty() {
                        None
                    } else {
                        install_date_unix(&install_date)
                    },
                    last_used,
                    is_bundleware(&name, &publisher),
                );
                apps.push(InstalledApp {
                    name,
                    version,
                    publisher,
                    install_date,
                    size_bytes: size_kb as u64 * 1024,
                    location: location.trim().to_string(),
                    last_used_unix: last_used.unwrap_or(0),
                    flags,
                    removal: AppRemoval::WindowsUninstall {
                        uninstall_string: uninstall.trim().to_string(),
                    },
                });
            }
        }
        // The same product can appear in more than one hive view; keep the
        // richer entry (bigger size wins, then the one with a location).
        apps.sort_by(|a, b| {
            (a.name.to_lowercase(), &a.version)
                .cmp(&(b.name.to_lowercase(), &b.version))
                .then(b.size_bytes.cmp(&a.size_bytes))
                .then(b.location.len().cmp(&a.location.len()))
        });
        apps.dedup_by(|a, b| a.name.eq_ignore_ascii_case(&b.name) && a.version == b.version);
        apps
    }
}

// ------------------------------------------------------------- macOS scan --

#[cfg(target_os = "macos")]
mod mac {
    use super::*;
    use crate::scanner::{ScanBackend, ScanOptions, WalkBackend};
    use rayon::prelude::*;
    use std::path::PathBuf;

    fn bundle_size(path: &Path) -> u64 {
        match WalkBackend.scan(path, &ScanOptions::default(), &|_| {}) {
            Ok(o) => o.records.iter().filter(|r| !r.is_dir).map(|r| r.size).sum(),
            Err(_) => 0,
        }
    }

    pub fn scan(now_unix: i64, progress: &(dyn Fn(u64) + Sync)) -> Vec<InstalledApp> {
        let mut dirs = vec![PathBuf::from("/Applications")];
        if let Ok(home) = std::env::var("HOME") {
            dirs.push(PathBuf::from(home).join("Applications"));
        }
        let mut bundles = Vec::new();
        for d in &dirs {
            bundles.extend(app_bundles_in(d));
        }
        let mut count = 0u64;
        for _ in &bundles {
            count += 1;
            progress(count);
        }
        bundles
            .into_par_iter()
            .map(|(name, path)| {
                let p = Path::new(&path);
                // Launch evidence: newest time on the executable(s).
                let last_used = newest_file_time_in(&p.join("Contents").join("MacOS"), "");
                let flags = classify(now_unix, None, last_used, is_bundleware(&name, ""));
                InstalledApp {
                    name,
                    version: String::new(),
                    publisher: String::new(),
                    install_date: String::new(),
                    size_bytes: bundle_size(p),
                    location: path.clone(),
                    last_used_unix: last_used.unwrap_or(0),
                    flags,
                    removal: AppRemoval::MacBundle { path },
                }
            })
            .collect()
    }
}

// ------------------------------------------------------------ entry point --

/// Enumerate installed software, biggest first. Never deletes anything.
/// Empty on platforms without an implementation.
pub fn scan_installed_apps(now_unix: i64, progress: &(dyn Fn(u64) + Sync)) -> Vec<InstalledApp> {
    #[cfg(windows)]
    let mut apps = win::scan(now_unix, progress);
    #[cfg(target_os = "macos")]
    let mut apps = mac::scan(now_unix, progress);
    #[cfg(not(any(windows, target_os = "macos")))]
    let mut apps: Vec<InstalledApp> = {
        let _ = (now_unix, progress);
        Vec::new()
    };
    apps.sort_by(|a, b| {
        b.size_bytes
            .cmp(&a.size_bytes)
            .then_with(|| a.name.to_lowercase().cmp(&b.name.to_lowercase()))
    });
    apps
}

#[cfg(test)]
mod tests {
    use super::*;

    const DAY: i64 = 86_400;
    const NOW: i64 = 1_800_000_000; // fixed "now" for determinism

    #[test]
    fn install_date_parses_registry_format_only() {
        assert_eq!(
            parse_install_date("20230112").as_deref(),
            Some("2023-01-12")
        );
        assert_eq!(
            parse_install_date(" 20230112 ").as_deref(),
            Some("2023-01-12")
        );
        assert_eq!(parse_install_date("2023-01-12"), None);
        assert_eq!(parse_install_date("202301"), None);
        assert_eq!(parse_install_date(""), None);
    }

    #[test]
    fn install_date_unix_matches_known_epochs() {
        assert_eq!(install_date_unix("1970-01-01"), Some(0));
        assert_eq!(install_date_unix("2000-01-01"), Some(946_684_800));
        assert_eq!(install_date_unix("2023-13-01"), None);
    }

    #[test]
    fn unused_flag_needs_over_180_days() {
        let fresh = classify(NOW, None, Some(NOW - 179 * DAY), false);
        assert!(fresh.is_empty());
        let stale = classify(NOW, None, Some(NOW - 181 * DAY), false);
        assert_eq!(stale, vec!["unused"]);
    }

    #[test]
    fn old_flag_requires_old_install_and_stale_usage() {
        let install = Some(NOW - 400 * DAY);
        // Old install but actively used -> healthy, no flag.
        assert!(classify(NOW, install, Some(NOW - 10 * DAY), false).is_empty());
        // Old install, usage unknown -> "old" on install-date evidence.
        assert_eq!(classify(NOW, install, None, false), vec!["old"]);
        // Recent install -> nothing.
        assert!(classify(NOW, Some(NOW - 100 * DAY), None, false).is_empty());
    }

    #[test]
    fn unknown_everything_is_never_flagged() {
        assert!(classify(NOW, None, None, false).is_empty());
    }

    #[test]
    fn bundleware_patterns_match_name_or_publisher() {
        assert!(is_bundleware("2345 Pinyin Input", ""));
        assert!(is_bundleware("McAfee WebAdvisor", "McAfee LLC"));
        assert!(is_bundleware("Some Game Bar", "WildTangent"));
        assert!(!is_bundleware(
            "Visual Studio Code",
            "Microsoft Corporation"
        ));
        assert!(!is_bundleware("WPS Office", "Kingsoft"));
    }

    #[test]
    fn update_entries_are_recognized() {
        assert!(is_update_entry("KB2565063"));
        assert!(is_update_entry("Update for Microsoft Office"));
        assert!(is_update_entry("Security Update for Windows"));
        assert!(!is_update_entry("Krita 5.2"));
        assert!(!is_update_entry("KBar Media Player"));
    }

    #[test]
    fn app_bundles_found_by_suffix_only() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        std::fs::create_dir_all(root.join("Safari.app/Contents/MacOS")).unwrap();
        std::fs::write(root.join("Safari.app/Contents/MacOS/Safari"), b"x").unwrap();
        std::fs::create_dir_all(root.join("NotAnApp")).unwrap();
        std::fs::write(root.join("stray.app"), b"file not dir").unwrap();

        let found = app_bundles_in(root);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].0, "Safari");
        assert!(found[0].1.ends_with(".app"));
    }

    #[test]
    fn newest_file_time_filters_by_extension() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        std::fs::write(root.join("app.exe"), b"x").unwrap();
        std::fs::write(root.join("data.dat"), b"y").unwrap();
        assert!(newest_file_time_in(root, "exe").is_some());
        assert!(newest_file_time_in(root, "xyz").is_none());
        assert!(newest_file_time_in(&root.join("missing"), "exe").is_none());
    }
}
