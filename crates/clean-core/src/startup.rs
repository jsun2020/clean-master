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
    /// True when this entry has been delayed: its Run value now launches a
    /// Clean Master shim that waits `delay_secs` before starting the original
    /// program. `command` still reflects the ORIGINAL program, not the shim.
    pub delayed: bool,
    /// Seconds the launch is delayed after login (0 when not delayed).
    pub delay_secs: u32,
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

/// The flag Clean Master's delayed-start shim is invoked with:
/// `"<clean-master.exe>" --delayed-start <id>`. Kept public so the binaries
/// can recognize it in their argv before their normal startup.
pub const DELAYED_START_FLAG: &str = "--delayed-start";

/// Split a Run command line into (exe, arguments). Mirrors [`exe_path_of`] for
/// the exe half; the arguments are whatever follows, trimmed. Pure.
pub fn split_command(command: &str) -> (String, String) {
    let c = command.trim();
    if let Some(rest) = c.strip_prefix('"') {
        return match rest.find('"') {
            Some(end) => (rest[..end].to_string(), rest[end + 1..].trim().to_string()),
            None => (rest.to_string(), String::new()),
        };
    }
    let lower = c.to_lowercase();
    if let Some(pos) = lower.find(".exe") {
        return (c[..pos + 4].to_string(), c[pos + 4..].trim().to_string());
    }
    let end = c.find(char::is_whitespace).unwrap_or(c.len());
    (c[..end].to_string(), c[end..].trim().to_string())
}

/// Lowercase hex of a string's bytes - a command-line-safe, single-token id
/// derived from an entry's origin+name for the delayed-start backup store.
pub fn hex_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len() * 2);
    for b in s.bytes() {
        out.push(char::from_digit((b >> 4) as u32, 16).unwrap());
        out.push(char::from_digit((b & 0xf) as u32, 16).unwrap());
    }
    out
}

/// If `command` is a Clean Master delayed-start shim invocation, return its id
/// token (the argument after [`DELAYED_START_FLAG`]). Pure.
pub fn parse_launcher_id(command: &str) -> Option<String> {
    let idx = command.find(DELAYED_START_FLAG)?;
    let rest = command[idx + DELAYED_START_FLAG.len()..].trim_start();
    let tok = rest.split_whitespace().next()?;
    (!tok.is_empty()).then(|| tok.to_string())
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
    // Delayed entries: the ORIGINAL command is parked here (keyed by a hex id
    // derived from origin+name), while the live Run value points at our shim.
    const DELAYED_SUBKEY: &str = r"Software\CleanMaster\DelayedStartup";

    /// The record kept for a delayed entry: enough to run the original program
    /// after the wait, and to restore the exact original Run value on undelay.
    #[derive(Serialize, Deserialize)]
    struct DelayedBlob {
        origin: StartupOrigin,
        name: String,
        command: String,
        /// Original value was REG_EXPAND_SZ (restore it as such).
        expand: bool,
        delay_secs: u32,
    }

    fn launcher_id(origin: StartupOrigin, name: &str) -> String {
        hex_encode(&backup_id(origin, name))
    }

    fn launcher_command(launcher_exe: &str, id: &str) -> String {
        format!("\"{launcher_exe}\" {DELAYED_START_FLAG} {id}")
    }

    fn read_delayed_blob(id: &str) -> Option<DelayedBlob> {
        let store = RegKey::predef(HKEY_CURRENT_USER)
            .open_subkey_with_flags(DELAYED_SUBKEY, KEY_READ)
            .ok()?;
        let raw = store.get_raw_value(id).ok()?;
        let json = reg_value_to_string(&raw)?;
        serde_json::from_str(&json).ok()
    }

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
            delayed: false,
            delay_secs: 0,
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
                // A value pointing at our shim is a DELAYED entry: show the
                // original program (from the backup blob), not the shim line.
                if let Some(blob) = parse_launcher_id(&cmd).and_then(|id| read_delayed_blob(&id)) {
                    let mut e = entry(origin, name, blob.command, true);
                    e.delayed = true;
                    e.delay_secs = blob.delay_secs;
                    out.push(e);
                } else {
                    out.push(entry(origin, name, cmd, true));
                }
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
        if entry.delayed {
            return Err(CoreError::Session(
                "this entry is delayed - remove the delay first, then disable it".into(),
            ));
        }
        match (entry.origin.is_registry(), enabled) {
            (true, false) => disable_registry(entry),
            (true, true) => enable_registry(entry),
            (false, false) => disable_folder(entry),
            (false, true) => enable_folder(entry),
        }
    }

    /// Delay an enabled HKCU Run entry: park the original command in the
    /// delayed-start store and repoint its Run value at our shim, which waits
    /// `delay_secs` after login before launching the original. Reversible via
    /// [`undelay`]; needs no admin and no Task Scheduler.
    pub fn delay(
        entry: &StartupEntry,
        delay_secs: u32,
        launcher_exe: &str,
    ) -> Result<(), CoreError> {
        if entry.origin != StartupOrigin::RunCurrentUser {
            return Err(CoreError::Session(
                "delayed start is only supported for this user's startup entries (HKCU)".into(),
            ));
        }
        if entry.delayed {
            return Err(CoreError::Session("entry is already delayed".into()));
        }
        if !entry.enabled {
            return Err(CoreError::Session(
                "enable the entry before delaying it".into(),
            ));
        }
        let (root, sub) = origin_key(entry.origin)
            .ok_or_else(|| CoreError::Session("not a registry startup entry".into()))?;
        let key = root
            .open_subkey_with_flags(sub, KEY_READ | KEY_SET_VALUE)
            .map_err(|e| io_err(sub.into(), e))?;
        let raw = key
            .get_raw_value(&entry.name)
            .map_err(|e| io_err(entry.name.clone(), e))?;
        let command = reg_value_to_string(&raw).unwrap_or_else(|| entry.command.clone());
        if parse_launcher_id(&command).is_some() {
            return Err(CoreError::Session("entry is already delayed".into()));
        }
        let blob = DelayedBlob {
            origin: entry.origin,
            name: entry.name.clone(),
            command,
            expand: raw.vtype == REG_EXPAND_SZ,
            delay_secs,
        };
        let id = launcher_id(entry.origin, &entry.name);
        let (store, _) = RegKey::predef(HKEY_CURRENT_USER)
            .create_subkey(DELAYED_SUBKEY)
            .map_err(|e| io_err(DELAYED_SUBKEY.into(), e))?;
        let json = serde_json::to_string(&blob)
            .map_err(|e| CoreError::Session(format!("serialize delayed entry: {e}")))?;
        store
            .set_raw_value(&id, &sz_value(&json))
            .map_err(|e| io_err("delayed backup value".into(), e))?;
        // Repoint the live Run value at the shim. If that write fails, roll the
        // backup back so we never leave a half-applied state.
        let launcher = launcher_command(launcher_exe, &id);
        if let Err(e) = key.set_raw_value(&entry.name, &sz_value(&launcher)) {
            let _ = store.delete_value(&id);
            return Err(io_err(entry.name.clone(), e));
        }
        Ok(())
    }

    /// Remove a delay: restore the original Run value (exact command + type)
    /// and drop the shim + backup blob.
    pub fn undelay(entry: &StartupEntry) -> Result<(), CoreError> {
        let id = launcher_id(entry.origin, &entry.name);
        let store = RegKey::predef(HKEY_CURRENT_USER)
            .open_subkey_with_flags(DELAYED_SUBKEY, KEY_READ | KEY_SET_VALUE)
            .map_err(|e| io_err(DELAYED_SUBKEY.into(), e))?;
        let raw = store
            .get_raw_value(&id)
            .map_err(|e| io_err(id.clone(), e))?;
        let json = reg_value_to_string(&raw)
            .ok_or_else(|| CoreError::Session("corrupt delayed entry".into()))?;
        let blob: DelayedBlob = serde_json::from_str(&json)
            .map_err(|e| CoreError::Session(format!("parse delayed entry: {e}")))?;
        let (root, sub) = origin_key(blob.origin)
            .ok_or_else(|| CoreError::Session("not a registry startup entry".into()))?;
        let (key, _) = root.create_subkey(sub).map_err(|e| io_err(sub.into(), e))?;
        let value = if blob.expand {
            expand_sz_value(&blob.command)
        } else {
            sz_value(&blob.command)
        };
        key.set_raw_value(&blob.name, &value)
            .map_err(|e| io_err(blob.name.clone(), e))?;
        store.delete_value(&id).map_err(|e| io_err(id, e))?;
        Ok(())
    }

    /// The shim body: called by the binary when launched as
    /// `--delayed-start <id>`. Waits, then starts the original program. Blocks
    /// for the delay, so callers should run it and exit.
    pub fn run_delayed_start(id: &str) -> Result<(), CoreError> {
        use std::os::windows::process::CommandExt;
        let blob = read_delayed_blob(id)
            .ok_or_else(|| CoreError::Session("no such delayed entry".into()))?;
        std::thread::sleep(std::time::Duration::from_secs(blob.delay_secs as u64));
        let expanded = crate::toolbox::expand_env(&blob.command);
        let (exe, args) = split_command(&expanded);
        let mut cmd = std::process::Command::new(&exe);
        if !args.is_empty() {
            // Append the original arguments verbatim (preserving their quoting)
            // rather than re-splitting/re-quoting them.
            cmd.raw_arg(&args);
        }
        cmd.spawn().map_err(|e| io_err(exe, e))?;
        Ok(())
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

    pub fn delay(_entry: &StartupEntry, _secs: u32, _launcher_exe: &str) -> Result<(), CoreError> {
        Err(CoreError::Session(
            "delayed start is only available on Windows".into(),
        ))
    }

    pub fn undelay(_entry: &StartupEntry) -> Result<(), CoreError> {
        Err(CoreError::Session(
            "delayed start is only available on Windows".into(),
        ))
    }

    pub fn run_delayed_start(_id: &str) -> Result<(), CoreError> {
        Err(CoreError::Session(
            "delayed start is only available on Windows".into(),
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

/// Delay an enabled HKCU startup entry by `delay_secs` seconds. `launcher_exe`
/// is the full path to the Clean Master executable that will act as the wait
/// shim (prefer the GUI exe, which shows no console). Reversible via [`undelay`];
/// needs no admin. Errors for non-HKCU, disabled, or already-delayed entries.
pub fn delay(entry: &StartupEntry, delay_secs: u32, launcher_exe: &str) -> Result<(), CoreError> {
    imp::delay(entry, delay_secs, launcher_exe)
}

/// Remove a delay, restoring the original immediate Run value.
pub fn undelay(entry: &StartupEntry) -> Result<(), CoreError> {
    imp::undelay(entry)
}

/// Shim entry point: run the delayed program for backup id `id` after its
/// configured wait. Called by the binaries when invoked with
/// [`DELAYED_START_FLAG`]; blocks for the delay, so run it and exit.
pub fn run_delayed_start(id: &str) -> Result<(), CoreError> {
    imp::run_delayed_start(id)
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

    #[test]
    fn split_command_separates_exe_and_args() {
        assert_eq!(
            split_command(r#""C:\Program Files\App\app.exe" --run -x"#),
            (
                r"C:\Program Files\App\app.exe".to_string(),
                "--run -x".to_string()
            )
        );
        assert_eq!(
            split_command(r"C:\Tools\thing.exe /background"),
            (r"C:\Tools\thing.exe".to_string(), "/background".to_string())
        );
        assert_eq!(
            split_command(r"C:\Tools\thing.exe"),
            (r"C:\Tools\thing.exe".to_string(), String::new())
        );
    }

    #[test]
    fn launcher_id_roundtrips_through_parse() {
        // The shim command we write must be parseable back to the same id, and
        // the id must be a single command-line-safe token (hex).
        let id = hex_encode("RunCurrentUser|Some App With Spaces");
        assert!(id.chars().all(|c| c.is_ascii_hexdigit()));
        let cmd = format!(
            "\"C:\\Program Files\\Clean Master\\clean-master.exe\" {DELAYED_START_FLAG} {id}"
        );
        assert_eq!(parse_launcher_id(&cmd).as_deref(), Some(id.as_str()));
    }

    #[test]
    fn parse_launcher_id_ignores_ordinary_commands() {
        assert_eq!(parse_launcher_id(r#""C:\App\app.exe" --run"#), None);
        assert_eq!(parse_launcher_id(""), None);
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
            delayed: false,
            delay_secs: 0,
        };
        assert!(set_enabled(&e, false).is_err());
        assert!(delay(&e, 60, "clean-master.exe").is_err());
        assert!(undelay(&e).is_err());
        assert!(run_delayed_start("00").is_err());
    }
}
