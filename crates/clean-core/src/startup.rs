//! Startup (autostart) manager: list what runs at login and enable/disable
//! entries reversibly. Wopti-inspired, kept inside clean-cli's safety model.
//!
//! Disabling NEVER deletes the target program. A disabled entry is moved into
//! a CleanMaster-owned backup store (a registry key for Run values, a folder
//! for Startup-folder shortcuts); enabling moves it back to its exact origin,
//! preserving the original registry value type (`REG_SZ` / `REG_EXPAND_SZ`).
//!
//! Windows-only. On other platforms `list()` is empty and `set_enabled`
//! returns an error, so the crate still type-checks and links everywhere.

use crate::error::CoreError;
use serde::{Deserialize, Serialize};

/// Where an autostart entry lives. This is enough to locate it for
/// enable/disable and to decide whether admin rights are needed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StartupOrigin {
    /// `HKCU\...\CurrentVersion\Run`
    RunCurrentUser,
    /// `HKLM\...\CurrentVersion\Run` (admin to change)
    RunLocalMachine,
    /// `HKLM\...\WOW6432Node\...\Run` (admin to change)
    RunLocalMachineWow64,
    /// Per-user Startup folder
    FolderCurrentUser,
    /// All-users (common) Startup folder (admin to change)
    FolderCommon,
}

impl StartupOrigin {
    pub fn requires_admin(self) -> bool {
        matches!(
            self,
            StartupOrigin::RunLocalMachine
                | StartupOrigin::RunLocalMachineWow64
                | StartupOrigin::FolderCommon
        )
    }

    pub fn is_registry(self) -> bool {
        matches!(
            self,
            StartupOrigin::RunCurrentUser
                | StartupOrigin::RunLocalMachine
                | StartupOrigin::RunLocalMachineWow64
        )
    }

    pub fn label(self) -> &'static str {
        match self {
            StartupOrigin::RunCurrentUser => "HKCU\\...\\Run",
            StartupOrigin::RunLocalMachine => "HKLM\\...\\Run",
            StartupOrigin::RunLocalMachineWow64 => "HKLM\\...\\WOW6432Node\\...\\Run",
            StartupOrigin::FolderCurrentUser => "Startup folder (this user)",
            StartupOrigin::FolderCommon => "Startup folder (all users)",
        }
    }
}

/// A rough, HONEST estimate of how much an autostart entry slows login. It is
/// a keyword + file-size heuristic over the resolved target exe, NOT Task
/// Manager's measured boot time (Windows exposes no public API for that), so
/// it is always presented as an estimate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BootImpact {
    High,
    Medium,
    Low,
}

impl BootImpact {
    /// Stable lowercase id for CSS classes / i18n keys.
    pub fn id(self) -> &'static str {
        match self {
            BootImpact::High => "high",
            BootImpact::Medium => "medium",
            BootImpact::Low => "low",
        }
    }
}

/// One autostart entry, enabled or disabled.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StartupEntry {
    /// Registry value name, or the Startup-folder file name.
    pub name: String,
    /// The command line / target path that runs at login.
    pub command: String,
    pub origin: StartupOrigin,
    pub location_label: String,
    pub enabled: bool,
    /// True when changing this entry needs administrator rights (HKLM /
    /// all-users). Surface it; do not attempt and fail silently.
    pub requires_admin: bool,
    /// Estimated login-slowdown impact (see [`BootImpact`]).
    pub impact: BootImpact,
}

/// Substrings (matched on the target exe's file name, lowercased) that mark a
/// program as typically heavy at boot: updaters, cloud sync, and known-large
/// agents. Deliberately conservative - a hit only raises the estimate.
const HEAVY_KEYWORDS: &[&str] = &[
    "update",
    "updater",
    "sync",
    "onedrive",
    "dropbox",
    "googledrive",
    "teams",
    "steam",
    "epicgames",
    "adobe",
    "creativecloud",
    "acrotray",
    "docker",
    "nvcontainer",
    "spotify",
    "discord",
    "skype",
    "backup",
    "cloud",
    "mcafee",
    "norton",
];

const BIG_EXE_BYTES: u64 = 40 * 1024 * 1024;
const SMALL_EXE_BYTES: u64 = 2 * 1024 * 1024;

/// Pull the target executable path out of a Run command line. Handles a quoted
/// path, an unquoted path ending in `.exe`, and the plain first token. Returns
/// `None` for an empty command. Pure (no I/O), so it is unit-testable anywhere.
pub fn exe_path_of(command: &str) -> Option<String> {
    let c = command.trim();
    if c.is_empty() {
        return None;
    }
    if let Some(rest) = c.strip_prefix('"') {
        return Some(match rest.find('"') {
            Some(end) => rest[..end].to_string(),
            None => rest.to_string(),
        });
    }
    let lower = c.to_lowercase();
    if let Some(pos) = lower.find(".exe") {
        return Some(c[..pos + 4].to_string());
    }
    let end = c.find(char::is_whitespace).unwrap_or(c.len());
    Some(c[..end].to_string())
}

/// Classify an entry's boot impact from its command and (optionally) the size
/// of its resolved target exe. Pure, so the heuristic is unit-testable without
/// touching the registry or the filesystem.
///
/// A known-heavy keyword or a large binary reads as High; a small binary reads
/// as Low; everything else (including an unresolvable target) is Medium - the
/// honest "unknown / typical" bucket.
pub fn classify_impact(command: &str, exe_size: Option<u64>) -> BootImpact {
    let name = exe_path_of(command)
        .map(|p| p.rsplit(['\\', '/']).next().unwrap_or(&p).to_lowercase())
        .unwrap_or_default();
    if HEAVY_KEYWORDS.iter().any(|k| name.contains(k)) {
        return BootImpact::High;
    }
    match exe_size {
        Some(sz) if sz >= BIG_EXE_BYTES => BootImpact::High,
        Some(sz) if sz < SMALL_EXE_BYTES => BootImpact::Low,
        _ => BootImpact::Medium,
    }
}

// The JSON blob stored per disabled Run value inside the backup registry key.
#[cfg(windows)]
#[derive(Serialize, Deserialize)]
struct DisabledBlob {
    origin: StartupOrigin,
    name: String,
    command: String,
    /// Original value was REG_EXPAND_SZ (so it must be restored as such).
    expand: bool,
}

#[cfg(windows)]
fn backup_id(origin: StartupOrigin, name: &str) -> String {
    format!("{origin:?}|{name}")
}

// -------------------------------------------------------------- Windows --
#[cfg(windows)]
mod imp {
    use super::*;
    use winreg::enums::*;
    use winreg::{RegKey, RegValue};

    const RUN_SUBKEY: &str = r"Software\Microsoft\Windows\CurrentVersion\Run";
    const RUN_WOW_SUBKEY: &str = r"Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run";
    const BACKUP_SUBKEY: &str = r"Software\CleanMaster\DisabledStartup";

    fn origin_key(origin: StartupOrigin) -> Option<(RegKey, &'static str)> {
        match origin {
            StartupOrigin::RunCurrentUser => Some((RegKey::predef(HKEY_CURRENT_USER), RUN_SUBKEY)),
            StartupOrigin::RunLocalMachine => {
                Some((RegKey::predef(HKEY_LOCAL_MACHINE), RUN_SUBKEY))
            }
            StartupOrigin::RunLocalMachineWow64 => {
                Some((RegKey::predef(HKEY_LOCAL_MACHINE), RUN_WOW_SUBKEY))
            }
            _ => None,
        }
    }

    fn reg_value_to_string(v: &RegValue) -> Option<String> {
        // REG_SZ / REG_EXPAND_SZ hold UTF-16LE with a trailing NUL.
        if v.vtype != REG_SZ && v.vtype != REG_EXPAND_SZ {
            return None;
        }
        let units: Vec<u16> = v
            .bytes
            .as_chunks::<2>()
            .0
            .iter()
            .map(|c| u16::from_le_bytes(*c))
            .take_while(|&u| u != 0)
            .collect();
        Some(String::from_utf16_lossy(&units))
    }

    fn expand_sz_value(s: &str) -> RegValue {
        let bytes: Vec<u8> = s
            .encode_utf16()
            .chain(std::iter::once(0))
            .flat_map(|u| u.to_le_bytes())
            .collect();
        RegValue {
            bytes,
            vtype: REG_EXPAND_SZ,
        }
    }

    fn sz_value(s: &str) -> RegValue {
        let bytes: Vec<u8> = s
            .encode_utf16()
            .chain(std::iter::once(0))
            .flat_map(|u| u.to_le_bytes())
            .collect();
        RegValue {
            bytes,
            vtype: REG_SZ,
        }
    }

    fn startup_folder(origin: StartupOrigin) -> Option<std::path::PathBuf> {
        match origin {
            StartupOrigin::FolderCurrentUser => std::env::var("APPDATA").ok().map(|a| {
                std::path::PathBuf::from(a).join(r"Microsoft\Windows\Start Menu\Programs\Startup")
            }),
            StartupOrigin::FolderCommon => std::env::var("ProgramData").ok().map(|a| {
                std::path::PathBuf::from(a).join(r"Microsoft\Windows\Start Menu\Programs\Startup")
            }),
            _ => None,
        }
    }

    /// `%LOCALAPPDATA%\CleanMaster\DisabledStartup\{user|common}` - where a
    /// disabled Startup-folder shortcut is parked.
    fn disabled_folder(origin: StartupOrigin) -> Option<std::path::PathBuf> {
        let sub = match origin {
            StartupOrigin::FolderCurrentUser => "user",
            StartupOrigin::FolderCommon => "common",
            _ => return None,
        };
        std::env::var("LOCALAPPDATA").ok().map(|a| {
            std::path::PathBuf::from(a)
                .join("CleanMaster")
                .join("DisabledStartup")
                .join(sub)
        })
    }

    /// Resolve the target exe (expanding %VARS% in REG_EXPAND_SZ commands),
    /// stat it for a size, and classify the boot impact. A missing/unreadable
    /// target simply yields a size of `None` (-> Medium), never an error.
    fn impact_of(command: &str) -> BootImpact {
        let size = exe_path_of(command)
            .map(|p| crate::toolbox::expand_env(&p))
            .and_then(|p| std::fs::metadata(p).ok())
            .map(|m| m.len());
        classify_impact(command, size)
    }

    fn entry(origin: StartupOrigin, name: String, command: String, enabled: bool) -> StartupEntry {
        let impact = impact_of(&command);
        StartupEntry {
            name,
            command,
            origin,
            location_label: origin.label().to_string(),
            enabled,
            requires_admin: origin.requires_admin(),
            impact,
        }
    }

    fn list_registry(origin: StartupOrigin, out: &mut Vec<StartupEntry>) {
        let Some((root, sub)) = origin_key(origin) else {
            return;
        };
        let Ok(key) = root.open_subkey_with_flags(sub, KEY_READ) else {
            return;
        };
        for (name, val) in key.enum_values().filter_map(Result::ok) {
            if let Some(cmd) = reg_value_to_string(&val) {
                out.push(entry(origin, name, cmd, true));
            }
        }
    }

    fn list_folder(origin: StartupOrigin, out: &mut Vec<StartupEntry>) {
        let Some(dir) = startup_folder(origin) else {
            return;
        };
        let Ok(rd) = std::fs::read_dir(&dir) else {
            return;
        };
        for e in rd.filter_map(Result::ok) {
            let path = e.path();
            let name = e.file_name().to_string_lossy().into_owned();
            if name.eq_ignore_ascii_case("desktop.ini") || path.is_dir() {
                continue;
            }
            out.push(entry(origin, name, path.display().to_string(), true));
        }
    }

    fn list_disabled(out: &mut Vec<StartupEntry>) {
        // Disabled Run values live as JSON blobs in the backup registry key.
        if let Ok(key) =
            RegKey::predef(HKEY_CURRENT_USER).open_subkey_with_flags(BACKUP_SUBKEY, KEY_READ)
        {
            for (_id, val) in key.enum_values().filter_map(Result::ok) {
                if let Some(json) = reg_value_to_string(&val) {
                    if let Ok(blob) = serde_json::from_str::<DisabledBlob>(&json) {
                        out.push(entry(blob.origin, blob.name, blob.command, false));
                    }
                }
            }
        }
        // Disabled Startup-folder shortcuts live under the backup folder.
        for origin in [
            StartupOrigin::FolderCurrentUser,
            StartupOrigin::FolderCommon,
        ] {
            let Some(dir) = disabled_folder(origin) else {
                continue;
            };
            let Ok(rd) = std::fs::read_dir(&dir) else {
                continue;
            };
            for e in rd.filter_map(Result::ok) {
                let name = e.file_name().to_string_lossy().into_owned();
                out.push(entry(origin, name, e.path().display().to_string(), false));
            }
        }
    }

    pub fn list() -> Vec<StartupEntry> {
        let mut out = Vec::new();
        for origin in [
            StartupOrigin::RunCurrentUser,
            StartupOrigin::RunLocalMachine,
            StartupOrigin::RunLocalMachineWow64,
        ] {
            list_registry(origin, &mut out);
        }
        list_folder(StartupOrigin::FolderCurrentUser, &mut out);
        list_folder(StartupOrigin::FolderCommon, &mut out);
        list_disabled(&mut out);
        out.sort_by_key(|e| e.name.to_lowercase());
        out
    }

    fn io_err(path: String, e: std::io::Error) -> CoreError {
        CoreError::Io { path, source: e }
    }

    fn disable_registry(entry: &StartupEntry) -> Result<(), CoreError> {
        let (root, sub) = origin_key(entry.origin)
            .ok_or_else(|| CoreError::Session("not a registry startup entry".into()))?;
        let key = root
            .open_subkey_with_flags(sub, KEY_READ | KEY_SET_VALUE)
            .map_err(|e| io_err(format!("{sub} (needs admin for HKLM)"), e))?;
        let raw = key
            .get_raw_value(&entry.name)
            .map_err(|e| io_err(entry.name.clone(), e))?;
        let blob = DisabledBlob {
            origin: entry.origin,
            name: entry.name.clone(),
            command: reg_value_to_string(&raw).unwrap_or_else(|| entry.command.clone()),
            expand: raw.vtype == REG_EXPAND_SZ,
        };
        let (backup, _) = RegKey::predef(HKEY_CURRENT_USER)
            .create_subkey(BACKUP_SUBKEY)
            .map_err(|e| io_err(BACKUP_SUBKEY.into(), e))?;
        let json = serde_json::to_string(&blob)
            .map_err(|e| CoreError::Session(format!("serialize disabled entry: {e}")))?;
        backup
            .set_raw_value(backup_id(entry.origin, &entry.name), &sz_value(&json))
            .map_err(|e| io_err("backup value".into(), e))?;
        // Only remove from the live Run key AFTER the backup is safely written.
        key.delete_value(&entry.name)
            .map_err(|e| io_err(entry.name.clone(), e))?;
        Ok(())
    }

    fn enable_registry(entry: &StartupEntry) -> Result<(), CoreError> {
        let (root, sub) = origin_key(entry.origin)
            .ok_or_else(|| CoreError::Session("not a registry startup entry".into()))?;
        let backup = RegKey::predef(HKEY_CURRENT_USER)
            .open_subkey_with_flags(BACKUP_SUBKEY, KEY_READ | KEY_SET_VALUE)
            .map_err(|e| io_err(BACKUP_SUBKEY.into(), e))?;
        let id = backup_id(entry.origin, &entry.name);
        let raw = backup
            .get_raw_value(&id)
            .map_err(|e| io_err(id.clone(), e))?;
        let json = reg_value_to_string(&raw)
            .ok_or_else(|| CoreError::Session("corrupt backup entry".into()))?;
        let blob: DisabledBlob = serde_json::from_str(&json)
            .map_err(|e| CoreError::Session(format!("parse disabled entry: {e}")))?;
        let (key, _) = root
            .create_subkey(sub)
            .map_err(|e| io_err(format!("{sub} (needs admin for HKLM)"), e))?;
        let value = if blob.expand {
            expand_sz_value(&blob.command)
        } else {
            sz_value(&blob.command)
        };
        key.set_raw_value(&blob.name, &value)
            .map_err(|e| io_err(blob.name.clone(), e))?;
        backup.delete_value(&id).map_err(|e| io_err(id, e))?;
        Ok(())
    }

    fn disable_folder(entry: &StartupEntry) -> Result<(), CoreError> {
        let src = std::path::PathBuf::from(&entry.command);
        let dir = disabled_folder(entry.origin)
            .ok_or_else(|| CoreError::Session("no disabled-folder location".into()))?;
        std::fs::create_dir_all(&dir).map_err(|e| io_err(dir.display().to_string(), e))?;
        let dst = dir.join(&entry.name);
        move_file(&src, &dst)
    }

    fn enable_folder(entry: &StartupEntry) -> Result<(), CoreError> {
        let src = std::path::PathBuf::from(&entry.command);
        let dir = startup_folder(entry.origin)
            .ok_or_else(|| CoreError::Session("no startup-folder location".into()))?;
        std::fs::create_dir_all(&dir).map_err(|e| io_err(dir.display().to_string(), e))?;
        let dst = dir.join(&entry.name);
        move_file(&src, &dst)
    }

    fn move_file(src: &std::path::Path, dst: &std::path::Path) -> Result<(), CoreError> {
        // rename first (atomic, same volume); fall back to copy+remove across
        // volumes (%LOCALAPPDATA% and %APPDATA% can differ).
        if std::fs::rename(src, dst).is_ok() {
            return Ok(());
        }
        std::fs::copy(src, dst).map_err(|e| io_err(dst.display().to_string(), e))?;
        std::fs::remove_file(src).map_err(|e| io_err(src.display().to_string(), e))?;
        Ok(())
    }

    pub fn set_enabled(entry: &StartupEntry, enabled: bool) -> Result<(), CoreError> {
        if entry.enabled == enabled {
            return Ok(());
        }
        match (entry.origin.is_registry(), enabled) {
            (true, false) => disable_registry(entry),
            (true, true) => enable_registry(entry),
            (false, false) => disable_folder(entry),
            (false, true) => enable_folder(entry),
        }
    }

    // Test hooks: exercise the registry move mechanism against a scratch key
    // instead of the real Run key, so tests never touch the user's autostart.
    #[cfg(test)]
    pub(super) mod testhooks {
        use super::*;

        /// Disable/enable a value between a scratch "live" key and the backup
        /// key, using the same code paths' primitives.
        pub fn roundtrip(live_sub: &str, name: &str, command: &str, expand: bool) -> bool {
            let hkcu = RegKey::predef(HKEY_CURRENT_USER);
            let (live, _) = hkcu.create_subkey(live_sub).unwrap();
            let v = if expand {
                expand_sz_value(command)
            } else {
                sz_value(command)
            };
            live.set_raw_value(name, &v).unwrap();

            // --- disable: move live -> backup, faithfully preserving type ---
            let raw = live.get_raw_value(name).unwrap();
            let was_expand = raw.vtype == REG_EXPAND_SZ;
            assert_eq!(was_expand, expand);
            let blob = DisabledBlob {
                origin: StartupOrigin::RunCurrentUser,
                name: name.into(),
                command: reg_value_to_string(&raw).unwrap(),
                expand: was_expand,
            };
            let (backup, _) = hkcu.create_subkey(BACKUP_SUBKEY).unwrap();
            let id = format!("TEST|{name}");
            backup
                .set_raw_value(&id, &sz_value(&serde_json::to_string(&blob).unwrap()))
                .unwrap();
            live.delete_value(name).unwrap();
            assert!(live.get_raw_value(name).is_err(), "value still live");

            // --- enable: move backup -> live, same type as before ---
            let json = reg_value_to_string(&backup.get_raw_value(&id).unwrap()).unwrap();
            let blob: DisabledBlob = serde_json::from_str(&json).unwrap();
            let restored = if blob.expand {
                expand_sz_value(&blob.command)
            } else {
                sz_value(&blob.command)
            };
            live.set_raw_value(&blob.name, &restored).unwrap();
            backup.delete_value(&id).unwrap();

            let final_raw = live.get_raw_value(name).unwrap();
            let ok = reg_value_to_string(&final_raw).as_deref() == Some(command)
                && (final_raw.vtype == REG_EXPAND_SZ) == expand;

            // cleanup scratch key
            let _ = hkcu.delete_subkey_all(live_sub);
            ok
        }
    }
}

// ---------------------------------------------------------- non-Windows --
#[cfg(not(windows))]
mod imp {
    use super::*;

    pub fn list() -> Vec<StartupEntry> {
        Vec::new()
    }

    pub fn set_enabled(_entry: &StartupEntry, _enabled: bool) -> Result<(), CoreError> {
        Err(CoreError::Session(
            "startup management is only available on Windows".into(),
        ))
    }
}

/// All autostart entries (Run keys + Startup folders), enabled and disabled,
/// sorted by name. Empty on non-Windows.
pub fn list() -> Vec<StartupEntry> {
    imp::list()
}

/// Enable or disable one entry. Disabling moves it to the CleanMaster backup
/// store (never deletes the program); enabling restores it to its origin.
/// A no-op when the entry is already in the requested state.
pub fn set_enabled(entry: &StartupEntry, enabled: bool) -> Result<(), CoreError> {
    imp::set_enabled(entry, enabled)
}

#[cfg(all(test, windows))]
mod tests {
    use super::*;

    #[test]
    fn registry_disable_enable_roundtrip_reg_sz() {
        // Scratch key under our own namespace; never the real Run key.
        assert!(imp::testhooks::roundtrip(
            r"Software\CleanMaster\TestStartup\sz",
            "TestApp",
            r"C:\Apps\test.exe --run",
            false,
        ));
    }

    #[test]
    fn registry_roundtrip_preserves_expand_sz() {
        // A REG_EXPAND_SZ value with %VAR% must come back as REG_EXPAND_SZ,
        // or the restored autostart entry would stop expanding the variable.
        assert!(imp::testhooks::roundtrip(
            r"Software\CleanMaster\TestStartup\expand",
            "TestExpand",
            r"%ProgramFiles%\App\app.exe",
            true,
        ));
    }

    #[test]
    fn list_runs_without_error_and_is_sorted() {
        let entries = list();
        for w in entries.windows(2) {
            assert!(w[0].name.to_lowercase() <= w[1].name.to_lowercase());
        }
    }
}

// Impact heuristic is pure and platform-independent, so it is tested on every
// host (the registry-touching tests above are Windows-only).
#[cfg(test)]
mod impact_tests {
    use super::*;

    #[test]
    fn exe_path_handles_quoted_unquoted_and_args() {
        assert_eq!(
            exe_path_of(r#""C:\Program Files\App\app.exe" --run"#).as_deref(),
            Some(r"C:\Program Files\App\app.exe")
        );
        assert_eq!(
            exe_path_of(r"C:\Tools\thing.exe /background").as_deref(),
            Some(r"C:\Tools\thing.exe")
        );
        assert_eq!(exe_path_of("notepad").as_deref(), Some("notepad"));
        assert_eq!(exe_path_of("   "), None);
    }

    #[test]
    fn heavy_keyword_is_high_regardless_of_size() {
        // An updater with a tiny stub launcher is still a High-impact entry.
        assert_eq!(
            classify_impact(r"C:\App\AppUpdater.exe", Some(100_000)),
            BootImpact::High
        );
        assert_eq!(
            classify_impact(
                r#""C:\Users\me\AppData\Local\OneDrive\OneDrive.exe" /background"#,
                None
            ),
            BootImpact::High
        );
    }

    #[test]
    fn big_binary_is_high_and_small_is_low() {
        assert_eq!(
            classify_impact(r"C:\App\huge.exe", Some(80 * 1024 * 1024)),
            BootImpact::High
        );
        assert_eq!(
            classify_impact(r"C:\App\tray.exe", Some(500 * 1024)),
            BootImpact::Low
        );
    }

    #[test]
    fn unknown_size_no_keyword_is_medium() {
        assert_eq!(
            classify_impact(r"C:\App\mystery.exe", None),
            BootImpact::Medium
        );
        // Mid-sized, no keyword -> the "typical" bucket.
        assert_eq!(
            classify_impact(r"C:\App\normal.exe", Some(10 * 1024 * 1024)),
            BootImpact::Medium
        );
    }
}

#[cfg(all(test, not(windows)))]
mod tests {
    use super::*;

    #[test]
    fn non_windows_list_is_empty_and_set_errors() {
        assert!(list().is_empty());
        let e = StartupEntry {
            name: "x".into(),
            command: "x".into(),
            origin: StartupOrigin::RunCurrentUser,
            location_label: "x".into(),
            enabled: true,
            requires_admin: false,
            impact: BootImpact::Medium,
        };
        assert!(set_enabled(&e, false).is_err());
    }
}
