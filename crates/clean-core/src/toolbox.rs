//! Toolbox: a curated catalog of Windows maintenance tools (winutil-inspired)
//! plus the runner that executes them and streams their console output.
//!
//! Safety by construction:
//! - The catalog is Rust data, not a file: no manifest and no webview input can
//!   ever inject a command. Callers pass a tool id + a mode; the command line
//!   is re-derived here.
//! - Every invocation is `Command::new(program).args(vec)` - never a shell
//!   string. The only user-supplied text (winget query / package id) is
//!   validated and passed as one argument behind an explicit `--query`/`--id`.
//! - Read-only *checks* and *actions* are separate commands, so the UI can run
//!   a check freely and confirm an action with the literal command shown.
//! - Nothing here elevates silently: `is_elevated()` reports the state and
//!   `relaunch_elevated()` goes through the normal UAC prompt.
//!
//! The catalog is Windows-only (`builtin_tools()` is empty elsewhere); the
//! runner and decoders compile everywhere so they can be unit-tested on any CI
//! host.

use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::time::Duration;

// ---------------------------------------------------------------- model --

/// Screen grouping. `id()` is the stable string the UI keys translations on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Category {
    Storage,
    Updates,
    Software,
    Repair,
}

impl Category {
    pub fn id(self) -> &'static str {
        match self {
            Category::Storage => "storage",
            Category::Updates => "updates",
            Category::Software => "software",
            Category::Repair => "repair",
        }
    }
}

/// One process invocation: program + argument vector. No shell, ever.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Cmd {
    pub program: String,
    pub args: Vec<String>,
}

impl Cmd {
    /// `%VAR%` tokens in program and args are expanded from the environment
    /// at construction time (unknown vars are left literal, never emptied).
    pub fn new(program: &str, args: &[&str]) -> Cmd {
        Cmd {
            program: expand_env(program),
            args: args.iter().map(|a| expand_env(a)).collect(),
        }
    }

    /// Human-readable command line for confirm dialogs and the console.
    /// Arguments containing whitespace are quoted; nothing is ever executed
    /// from this string.
    pub fn display(&self) -> String {
        let mut parts = vec![quote_if_needed(&self.program)];
        parts.extend(self.args.iter().map(|a| quote_if_needed(a)));
        parts.join(" ")
    }
}

fn quote_if_needed(s: &str) -> String {
    if s.is_empty() || s.chars().any(char::is_whitespace) {
        format!("\"{s}\"")
    } else {
        s.to_string()
    }
}

/// Expand `%NAME%` tokens from the process environment. Tokens whose variable
/// is unset stay literal, so a missing var can never collapse a path to `\`.
pub fn expand_env(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut rest = s;
    while let Some(start) = rest.find('%') {
        out.push_str(&rest[..start]);
        let after = &rest[start + 1..];
        match after.find('%') {
            Some(end) if end > 0 => {
                let name = &after[..end];
                match std::env::var(name) {
                    Ok(v) => out.push_str(&v),
                    Err(_) => {
                        out.push('%');
                        out.push_str(name);
                        out.push('%');
                    }
                }
                rest = &after[end + 1..];
            }
            _ => {
                out.push('%');
                rest = after;
            }
        }
    }
    out.push_str(rest);
    out
}

/// A cheap, read-only size preview shown on the card before anything runs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Probe {
    None,
    /// Size of one file (0 when absent).
    File(PathBuf),
    /// Summed size of these directory trees (missing ones count 0).
    Dirs(Vec<PathBuf>),
}

/// How the tool takes user text, if at all.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Input {
    None,
    /// The Software "find & install" tool: check = search by query,
    /// action = install by exact package id.
    WingetTerm,
}

#[derive(Debug, Clone)]
pub struct Tool {
    pub id: &'static str,
    pub category: Category,
    pub name: &'static str,
    pub blurb: &'static str,
    /// Every command of this tool needs an elevated process.
    pub needs_admin: bool,
    /// The action asks for / needs a reboot to take full effect.
    pub reboot: bool,
    /// Minutes rather than seconds (sfc, DISM RestoreHealth).
    pub long_running: bool,
    /// Read-only inspection. Empty = no check.
    pub check: Vec<Cmd>,
    pub check_label: &'static str,
    /// The change. Steps run in order and stop at the first failure.
    pub action: Vec<Cmd>,
    pub action_label: &'static str,
    /// Launch-and-forget (Settings page, Disk Cleanup); no output captured.
    pub open: Option<Cmd>,
    pub probe: Probe,
    pub input: Input,
}

impl Tool {
    fn base(id: &'static str, category: Category, name: &'static str, blurb: &'static str) -> Tool {
        Tool {
            id,
            category,
            name,
            blurb,
            needs_admin: false,
            reboot: false,
            long_running: false,
            check: Vec::new(),
            check_label: "Check",
            action: Vec::new(),
            action_label: "Run",
            open: None,
            probe: Probe::None,
            input: Input::None,
        }
    }
}

// -------------------------------------------------------------- catalog --

/// Locate winget: the App Execution Alias dir is not always on a GUI
/// process's PATH, so fall back to the well-known WindowsApps location.
pub fn resolve_winget() -> Option<PathBuf> {
    if let Some(path) = std::env::var_os("PATH") {
        for dir in std::env::split_paths(&path) {
            let cand = dir.join("winget.exe");
            if cand.is_file() {
                return Some(cand);
            }
        }
    }
    let local = std::env::var_os("LOCALAPPDATA")?;
    let cand = PathBuf::from(local)
        .join("Microsoft")
        .join("WindowsApps")
        .join("winget.exe");
    cand.is_file().then_some(cand)
}

const WINGET_MISSING: &str = "winget_missing";
const NOT_PRESENT: &str = "not_present";
const HIBERNATION_OFF: &str = "hibernation_off";

/// The catalog. Windows-only; empty on other platforms.
pub fn builtin_tools() -> Vec<Tool> {
    if !cfg!(target_os = "windows") {
        return Vec::new();
    }
    let winget = resolve_winget()
        .map(|p| p.display().to_string())
        .unwrap_or_else(|| "winget".to_string());
    let mut tools = Vec::new();

    // ---- Storage ----------------------------------------------------------
    let mut t = Tool::base(
        "hiberfil",
        Category::Storage,
        "Hibernation file",
        "hiberfil.sys is reserved for hibernation and Fast Startup, typically 40% of RAM. Turning hibernation off deletes it (Fast Startup is disabled too); `powercfg /h on` brings it back.",
    );
    t.needs_admin = true;
    t.check = vec![Cmd::new("powercfg", &["/a"])];
    t.check_label = "Show sleep states";
    t.action = vec![Cmd::new("powercfg", &["/h", "off"])];
    t.action_label = "Turn hibernation off";
    t.probe = Probe::File(PathBuf::from(expand_env("%SystemDrive%\\hiberfil.sys")));
    tools.push(t);

    let mut t = Tool::base(
        "windows_old",
        Category::Storage,
        "Previous Windows installation",
        "Windows.old is kept for 10 days after a feature update so you can roll back. Removing it goes through Windows' own Disk Cleanup handler (the same thing Storage Sense does) - rollback is no longer possible afterwards.",
    );
    t.needs_admin = true;
    t.action = vec![
        Cmd::new(
            "reg",
            &[
                "add",
                "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\VolumeCaches\\Previous Installations",
                "/v",
                "StateFlags0071",
                "/t",
                "REG_DWORD",
                "/d",
                "2",
                "/f",
            ],
        ),
        Cmd::new("cleanmgr", &["/sagerun:71"]),
        Cmd::new(
            "reg",
            &[
                "delete",
                "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\VolumeCaches\\Previous Installations",
                "/v",
                "StateFlags0071",
                "/f",
            ],
        ),
    ];
    t.action_label = "Remove Windows.old";
    t.probe = Probe::Dirs(vec![PathBuf::from(expand_env(
        "%SystemDrive%\\Windows.old",
    ))]);
    tools.push(t);

    let mut t = Tool::base(
        "do_cache",
        Category::Storage,
        "Delivery Optimization cache",
        "Windows keeps downloaded update and Store packages to share with other PCs. The cache is safe to drop; Windows re-downloads what it needs.",
    );
    t.needs_admin = true;
    t.action = vec![Cmd::new(
        "powershell",
        &[
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            "Delete-DeliveryOptimizationCache -Force",
        ],
    )];
    t.action_label = "Clear cache";
    t.probe = Probe::Dirs(vec![
        PathBuf::from(expand_env("%WINDIR%\\SoftwareDistribution\\DeliveryOptimization")),
        PathBuf::from(expand_env(
            "%WINDIR%\\ServiceProfiles\\NetworkService\\AppData\\Local\\Microsoft\\Windows\\DeliveryOptimization\\Cache",
        )),
    ]);
    tools.push(t);

    let mut t = Tool::base(
        "disk_cleanup",
        Category::Storage,
        "Disk Cleanup (Windows built-in)",
        "Opens the classic Disk Cleanup tool. When Clean Master runs as administrator it can also clean system files (old updates, error reports).",
    );
    t.open = Some(Cmd::new("cleanmgr", &[]));
    tools.push(t);

    let mut t = Tool::base(
        "storage_sense",
        Category::Storage,
        "Storage settings",
        "Opens Settings > System > Storage, where Storage Sense schedules automatic cleanup of temporary files and the Recycle Bin.",
    );
    t.open = Some(Cmd::new("explorer.exe", &["ms-settings:storagesense"]));
    tools.push(t);

    // ---- Windows Update ---------------------------------------------------
    let mut t = Tool::base(
        "winsxs",
        Category::Updates,
        "Component store (WinSxS)",
        "Superseded update components pile up in C:\\Windows\\WinSxS - often several GB. Analyze reports the real size and whether cleanup is recommended; Clean up removes superseded versions (Microsoft-supported, no rollback of installed updates).",
    );
    t.needs_admin = true;
    t.long_running = true;
    t.check = vec![Cmd::new(
        "Dism",
        &["/Online", "/Cleanup-Image", "/AnalyzeComponentStore"],
    )];
    t.check_label = "Analyze";
    t.action = vec![Cmd::new(
        "Dism",
        &["/Online", "/Cleanup-Image", "/StartComponentCleanup"],
    )];
    t.action_label = "Clean up";
    tools.push(t);

    let mut t = Tool::base(
        "wu_settings",
        Category::Updates,
        "Windows Update",
        "Opens Settings > Windows Update to check for, pause or install updates. The update download cache itself is covered by the Junk Clean rule pack.",
    );
    t.open = Some(Cmd::new("explorer.exe", &["ms-settings:windowsupdate"]));
    tools.push(t);

    // ---- Software (winget) ------------------------------------------------
    let mut t = Tool::base(
        "winget_upgrade",
        Category::Software,
        "App upgrades (winget)",
        "Lists installed apps with a newer version in the winget catalog, and upgrades them all in one go. Apps that need it will show a UAC prompt.",
    );
    t.long_running = true;
    t.check = vec![Cmd::new(
        &winget,
        &[
            "upgrade",
            "--include-unknown",
            "--disable-interactivity",
            "--accept-source-agreements",
        ],
    )];
    t.check_label = "List upgrades";
    t.action = vec![Cmd::new(
        &winget,
        &[
            "upgrade",
            "--all",
            "--include-unknown",
            "--silent",
            "--disable-interactivity",
            "--accept-package-agreements",
            "--accept-source-agreements",
        ],
    )];
    t.action_label = "Upgrade all";
    tools.push(t);

    let mut t = Tool::base(
        "winget_search",
        Category::Software,
        "Find & install (winget)",
        "Search the winget catalog by name, then install by the exact package id shown in the results (for example Mozilla.Firefox). Uninstalling lives in App Manager.",
    );
    t.long_running = true;
    t.input = Input::WingetTerm;
    // Placeholders: the real commands are built by `winget_cmds` with the
    // validated term. Kept here so the card knows both modes exist.
    t.check = vec![Cmd::new(&winget, &["search", "--query", "<term>"])];
    t.check_label = "Search";
    t.action = vec![Cmd::new(&winget, &["install", "--id", "<term>", "--exact"])];
    t.action_label = "Install";
    tools.push(t);

    // ---- Repair -----------------------------------------------------------
    let mut t = Tool::base(
        "sfc",
        Category::Repair,
        "System File Checker",
        "Verifies protected Windows files against the component store and repairs corrupted ones. Takes 5-20 minutes.",
    );
    t.needs_admin = true;
    t.long_running = true;
    t.check = vec![Cmd::new("sfc", &["/verifyonly"])];
    t.check_label = "Verify only";
    t.action = vec![Cmd::new("sfc", &["/scannow"])];
    t.action_label = "Scan and repair";
    tools.push(t);

    let mut t = Tool::base(
        "dism_health",
        Category::Repair,
        "Windows image health (DISM)",
        "CheckHealth reads the recorded corruption flags in seconds; RestoreHealth repairs the component store from Windows Update (needs internet, 10-30 minutes). Run this before System File Checker when sfc cannot repair.",
    );
    t.needs_admin = true;
    t.long_running = true;
    t.check = vec![Cmd::new(
        "Dism",
        &["/Online", "/Cleanup-Image", "/CheckHealth"],
    )];
    t.check_label = "Check health";
    t.action = vec![Cmd::new(
        "Dism",
        &["/Online", "/Cleanup-Image", "/RestoreHealth"],
    )];
    t.action_label = "Restore health";
    tools.push(t);

    let mut t = Tool::base(
        "flush_dns",
        Category::Repair,
        "Flush DNS cache",
        "Drops cached name lookups so stale or wrong DNS answers stop being used. Instant and harmless.",
    );
    t.action = vec![Cmd::new("ipconfig", &["/flushdns"])];
    t.action_label = "Flush";
    tools.push(t);

    let mut t = Tool::base(
        "winsock",
        Category::Repair,
        "Reset network stack",
        "Resets Winsock and the TCP/IP stack to defaults - the standard fix for 'connected but no internet' after VPN or security software changes. Requires a reboot; VPN clients may need reinstalling.",
    );
    t.needs_admin = true;
    t.reboot = true;
    t.action = vec![
        Cmd::new("netsh", &["winsock", "reset"]),
        Cmd::new("netsh", &["int", "ip", "reset"]),
    ];
    t.action_label = "Reset";
    tools.push(t);

    tools
}

pub fn find_tool(id: &str) -> Option<Tool> {
    builtin_tools().into_iter().find(|t| t.id == id)
}

/// Why a tool cannot run right now (a stable reason id for the UI), or None.
/// Elevation is NOT part of this - the UI decides that from `is_elevated()`.
pub fn unavailable_reason(tool: &Tool) -> Option<&'static str> {
    match tool.id {
        "windows_old" => {
            let dir = PathBuf::from(expand_env("%SystemDrive%\\Windows.old"));
            (!dir.is_dir()).then_some(NOT_PRESENT)
        }
        "hiberfil" => {
            let f = PathBuf::from(expand_env("%SystemDrive%\\hiberfil.sys"));
            (!f.is_file()).then_some(HIBERNATION_OFF)
        }
        "winget_upgrade" | "winget_search" => resolve_winget().is_none().then_some(WINGET_MISSING),
        _ => None,
    }
}

/// Validate the user-typed winget query / package id. Rejects anything that
/// could read as a flag or carry control characters; spaces are fine (the
/// term travels as ONE argv element).
pub fn validate_winget_term(raw: &str) -> Result<String, String> {
    let term = raw.trim();
    if term.is_empty() {
        return Err("Type a package name or id first.".into());
    }
    if term.len() > 128 {
        return Err("Search term is too long.".into());
    }
    if term.starts_with('-') || term.starts_with('/') {
        return Err("Search term must not start with '-' or '/'.".into());
    }
    if term.chars().any(|c| c.is_control()) {
        return Err("Search term contains control characters.".into());
    }
    Ok(term.to_string())
}

/// Commands for the find-&-install tool with a VALIDATED term substituted.
pub fn winget_cmds(mode: Mode, term: &str) -> Vec<Cmd> {
    let winget = resolve_winget()
        .map(|p| p.display().to_string())
        .unwrap_or_else(|| "winget".to_string());
    match mode {
        Mode::Check => vec![Cmd::new(
            &winget,
            &[
                "search",
                "--query",
                term,
                "--disable-interactivity",
                "--accept-source-agreements",
            ],
        )],
        Mode::Action => vec![Cmd::new(
            &winget,
            &[
                "install",
                "--id",
                term,
                "--exact",
                "--disable-interactivity",
                "--accept-package-agreements",
                "--accept-source-agreements",
            ],
        )],
        Mode::Open => Vec::new(),
    }
}

// ---------------------------------------------------------------- probe --

/// Bytes behind a probe; None when the probe is `None` or nothing is there.
pub fn probe_bytes(probe: &Probe) -> Option<u64> {
    match probe {
        Probe::None => None,
        Probe::File(p) => std::fs::metadata(p).ok().map(|m| m.len()),
        Probe::Dirs(dirs) => {
            let mut total = 0u64;
            let mut any = false;
            for d in dirs {
                if d.is_dir() {
                    any = true;
                    total += dir_size(d);
                }
            }
            any.then_some(total)
        }
    }
}

/// Recursive size using the metadata the enumeration already returns (no
/// per-file stat, LL-021); unreadable subtrees count what was readable.
fn dir_size(dir: &Path) -> u64 {
    let Ok(rd) = std::fs::read_dir(dir) else {
        return 0;
    };
    let mut total = 0;
    for entry in rd.flatten() {
        let Ok(ft) = entry.file_type() else { continue };
        if ft.is_symlink() {
            continue;
        }
        if ft.is_dir() {
            total += dir_size(&entry.path());
        } else if let Ok(md) = entry.metadata() {
            total += md.len();
        }
    }
    total
}

// --------------------------------------------------------------- runner --

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    Check,
    Action,
    Open,
}

impl Mode {
    pub fn parse(s: &str) -> Option<Mode> {
        match s {
            "check" => Some(Mode::Check),
            "action" => Some(Mode::Action),
            "open" => Some(Mode::Open),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunOutcome {
    /// Exit code of the last step that ran (None if killed by a signal).
    pub exit_code: Option<i32>,
    /// Every step exited 0.
    pub success: bool,
    pub cancelled: bool,
    pub steps_run: usize,
}

fn configure(cmd: &mut Command) {
    // No console window may flash open behind the GUI.
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        const CREATE_NO_WINDOW: u32 = 0x0800_0000;
        cmd.creation_flags(CREATE_NO_WINDOW);
    }
    #[cfg(not(windows))]
    {
        let _ = cmd;
    }
}

/// Launch-and-forget (Settings pages, Disk Cleanup). Returns once spawned.
pub fn open_cmd(cmd: &Cmd) -> Result<(), String> {
    let mut c = Command::new(&cmd.program);
    c.args(&cmd.args)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    configure(&mut c);
    c.spawn()
        .map(|_| ())
        .map_err(|e| format!("could not start {}: {e}", cmd.program))
}

/// Run `steps` in order, streaming every output line to `on_line`
/// (decoded, without line terminators). Stops at the first failing step.
/// Setting `cancel` kills the current child and returns `cancelled = true`.
pub fn run_steps(
    steps: &[Cmd],
    cancel: &AtomicBool,
    mut on_line: impl FnMut(&str),
) -> Result<RunOutcome, String> {
    let mut outcome = RunOutcome {
        exit_code: None,
        success: false,
        cancelled: false,
        steps_run: 0,
    };
    for step in steps {
        if cancel.load(Ordering::SeqCst) {
            outcome.cancelled = true;
            return Ok(outcome);
        }
        on_line(&format!("> {}", step.display()));
        let mut c = Command::new(&step.program);
        c.args(&step.args)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        configure(&mut c);
        let mut child = c
            .spawn()
            .map_err(|e| format!("could not start {}: {e}", step.program))?;
        outcome.steps_run += 1;

        let (tx, rx) = mpsc::channel::<String>();
        let mut pumps = Vec::new();
        if let Some(out) = child.stdout.take() {
            let tx = tx.clone();
            pumps.push(std::thread::spawn(move || pump_lines(out, &tx)));
        }
        if let Some(err) = child.stderr.take() {
            let tx = tx.clone();
            pumps.push(std::thread::spawn(move || pump_lines(err, &tx)));
        }
        drop(tx);

        // Drain lines while the child runs; poll cancel between reads.
        let mut open = true;
        let status = loop {
            if open {
                match rx.recv_timeout(Duration::from_millis(100)) {
                    Ok(line) => on_line(&line),
                    Err(mpsc::RecvTimeoutError::Disconnected) => open = false,
                    Err(mpsc::RecvTimeoutError::Timeout) => {}
                }
            }
            if cancel.load(Ordering::SeqCst) {
                let _ = child.kill();
                let _ = child.wait();
                outcome.cancelled = true;
                break None;
            }
            match child.try_wait() {
                Ok(Some(st)) => {
                    // Flush whatever the pumps still hold.
                    for p in pumps.drain(..) {
                        let _ = p.join();
                    }
                    for line in rx.try_iter() {
                        on_line(&line);
                    }
                    break Some(st);
                }
                Ok(None) => {
                    if !open {
                        std::thread::sleep(Duration::from_millis(50));
                    }
                }
                Err(e) => return Err(format!("wait failed: {e}")),
            }
        };
        for p in pumps {
            let _ = p.join();
        }
        let Some(status) = status else {
            return Ok(outcome);
        };
        outcome.exit_code = status.code();
        if !status.success() {
            outcome.success = false;
            return Ok(outcome);
        }
    }
    outcome.success = outcome.steps_run == steps.len();
    Ok(outcome)
}

/// Read a pipe to EOF, sniff its encoding once, and send complete lines.
fn pump_lines(mut reader: impl Read, tx: &mpsc::Sender<String>) {
    let mut buf: Vec<u8> = Vec::new();
    let mut chunk = [0u8; 4096];
    let mut enc: Option<TextEnc> = None;
    loop {
        let n = match reader.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => n,
            Err(_) => break,
        };
        buf.extend_from_slice(&chunk[..n]);
        if enc.is_none() && buf.len() >= 32 {
            enc = Some(sniff_encoding(&buf));
        }
        if let Some(e) = enc {
            for line in drain_lines(&mut buf, e, false) {
                let _ = tx.send(line);
            }
        }
    }
    let e = enc.unwrap_or_else(|| sniff_encoding(&buf));
    for line in drain_lines(&mut buf, e, true) {
        let _ = tx.send(line);
    }
}

// -------------------------------------------------------------- decoding --

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TextEnc {
    /// sfc.exe (and some other system tools) write UTF-16LE when redirected.
    Utf16Le,
    /// UTF-8 when valid, otherwise the system ANSI code page (GBK on
    /// Chinese Windows) - DISM, netsh, ipconfig, reg.
    EightBit,
}

/// Decide from the first bytes of a stream. BOM, or NULs at every odd
/// position (ASCII text encoded as UTF-16LE), means UTF-16.
pub fn sniff_encoding(head: &[u8]) -> TextEnc {
    if head.len() >= 2 && head[0] == 0xFF && head[1] == 0xFE {
        return TextEnc::Utf16Le;
    }
    if head.len() >= 4 {
        let odd_total = head.len() / 2;
        let odd_nul = head.iter().skip(1).step_by(2).filter(|b| **b == 0).count();
        if odd_total > 0 && odd_nul * 10 >= odd_total * 6 {
            return TextEnc::Utf16Le;
        }
    }
    TextEnc::EightBit
}

/// The process's ANSI code page (Windows) or 65001 elsewhere.
pub fn ansi_codepage() -> u32 {
    #[cfg(windows)]
    {
        #[link(name = "kernel32")]
        extern "system" {
            fn GetACP() -> u32;
        }
        // SAFETY: GetACP takes no arguments and cannot fail.
        unsafe { GetACP() }
    }
    #[cfg(not(windows))]
    {
        65001
    }
}

fn encoding_for_codepage(cp: u32) -> &'static encoding_rs::Encoding {
    match cp {
        932 => encoding_rs::SHIFT_JIS,
        936 => encoding_rs::GBK,
        949 => encoding_rs::EUC_KR,
        950 => encoding_rs::BIG5,
        874 => encoding_rs::WINDOWS_874,
        1250 => encoding_rs::WINDOWS_1250,
        1251 => encoding_rs::WINDOWS_1251,
        1253 => encoding_rs::WINDOWS_1253,
        1254 => encoding_rs::WINDOWS_1254,
        1255 => encoding_rs::WINDOWS_1255,
        1256 => encoding_rs::WINDOWS_1256,
        1257 => encoding_rs::WINDOWS_1257,
        1258 => encoding_rs::WINDOWS_1258,
        65001 => encoding_rs::UTF_8,
        _ => encoding_rs::WINDOWS_1252,
    }
}

/// Decode one line of 8-bit console output: valid UTF-8 as-is, otherwise
/// through the given code page (lossy, never fails).
pub fn decode_8bit_with(bytes: &[u8], codepage: u32) -> String {
    match std::str::from_utf8(bytes) {
        Ok(s) => s.to_string(),
        Err(_) => encoding_for_codepage(codepage).decode(bytes).0.into_owned(),
    }
}

pub fn decode_8bit(bytes: &[u8]) -> String {
    decode_8bit_with(bytes, ansi_codepage())
}

/// Split complete lines off the front of `buf` (CR, LF or CRLF terminated),
/// decode them, and leave the incomplete tail in place. `flush` also emits
/// the tail. Empty lines are dropped (they carry nothing for a console).
pub fn drain_lines(buf: &mut Vec<u8>, enc: TextEnc, flush: bool) -> Vec<String> {
    let mut out = Vec::new();
    match enc {
        TextEnc::EightBit => {
            let mut start = 0;
            let mut i = 0;
            while i < buf.len() {
                if buf[i] == b'\n' || buf[i] == b'\r' {
                    push_nonempty(&mut out, decode_8bit(&buf[start..i]));
                    start = i + 1;
                }
                i += 1;
            }
            if flush && start < buf.len() {
                push_nonempty(&mut out, decode_8bit(&buf[start..]));
                start = buf.len();
            }
            buf.drain(..start);
        }
        TextEnc::Utf16Le => {
            let units: Vec<u16> = buf
                .as_chunks::<2>()
                .0
                .iter()
                .map(|c| u16::from_le_bytes(*c))
                .collect();
            let mut start = 0;
            let mut consumed_units = 0;
            for (i, u) in units.iter().enumerate() {
                if *u == 0x000A || *u == 0x000D {
                    push_nonempty(&mut out, String::from_utf16_lossy(&units[start..i]));
                    start = i + 1;
                    consumed_units = start;
                }
            }
            if flush && start < units.len() {
                push_nonempty(&mut out, String::from_utf16_lossy(&units[start..]));
                consumed_units = units.len();
            }
            buf.drain(..consumed_units * 2);
            if flush {
                buf.clear();
            }
        }
    }
    out
}

fn push_nonempty(out: &mut Vec<String>, line: String) {
    // Strip a UTF-8/UTF-16 BOM that a first line may carry.
    let line = line.trim_start_matches('\u{FEFF}');
    if !line.trim().is_empty() {
        out.push(line.to_string());
    }
}

// ------------------------------------------------------------ elevation --

/// Is this process running with an elevated (administrator) token?
pub fn is_elevated() -> bool {
    #[cfg(windows)]
    {
        use std::ffi::c_void;
        #[repr(C)]
        struct TokenElevation {
            token_is_elevated: u32,
        }
        #[link(name = "advapi32")]
        extern "system" {
            fn OpenProcessToken(process: *mut c_void, access: u32, token: *mut *mut c_void) -> i32;
            fn GetTokenInformation(
                token: *mut c_void,
                class: i32,
                info: *mut c_void,
                len: u32,
                ret_len: *mut u32,
            ) -> i32;
        }
        #[link(name = "kernel32")]
        extern "system" {
            fn GetCurrentProcess() -> *mut c_void;
            fn CloseHandle(h: *mut c_void) -> i32;
        }
        const TOKEN_QUERY: u32 = 0x0008;
        const TOKEN_ELEVATION_CLASS: i32 = 20;
        // SAFETY: plain Win32 token query on our own process handle; the
        // out-buffer is exactly the documented TOKEN_ELEVATION struct.
        unsafe {
            let mut token: *mut c_void = std::ptr::null_mut();
            if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) == 0 {
                return false;
            }
            let mut info = TokenElevation {
                token_is_elevated: 0,
            };
            let mut ret = 0u32;
            let ok = GetTokenInformation(
                token,
                TOKEN_ELEVATION_CLASS,
                &mut info as *mut _ as *mut c_void,
                std::mem::size_of::<TokenElevation>() as u32,
                &mut ret,
            );
            CloseHandle(token);
            ok != 0 && info.token_is_elevated != 0
        }
    }
    #[cfg(not(windows))]
    {
        false
    }
}

/// Command-line flag the elevated instance receives so it can wait for the
/// old process to exit before creating its window (WebView2 refuses to share
/// its user-data folder between integrity levels).
pub const WAIT_FOR_PID_FLAG: &str = "--wait-for-pid";

/// Start a second, elevated instance of this executable through the normal
/// UAC prompt (ShellExecute "runas"), passing `--wait-for-pid <this pid>`.
/// Returns Ok once the new process has been started - the caller then exits
/// this one. Err when the user cancels the prompt or the platform has no such
/// mechanism.
pub fn relaunch_elevated() -> Result<(), String> {
    #[cfg(windows)]
    {
        use std::os::windows::ffi::OsStrExt;
        #[link(name = "shell32")]
        extern "system" {
            fn ShellExecuteW(
                hwnd: *mut std::ffi::c_void,
                operation: *const u16,
                file: *const u16,
                parameters: *const u16,
                directory: *const u16,
                show_cmd: i32,
            ) -> *mut std::ffi::c_void;
        }
        const SW_SHOWNORMAL: i32 = 1;
        let exe = std::env::current_exe().map_err(|e| format!("current exe unknown: {e}"))?;
        let wide = |s: &std::ffi::OsStr| -> Vec<u16> {
            s.encode_wide().chain(std::iter::once(0)).collect()
        };
        let op = wide(std::ffi::OsStr::new("runas"));
        let file = wide(exe.as_os_str());
        let params = wide(std::ffi::OsStr::new(&format!(
            "{WAIT_FOR_PID_FLAG} {}",
            std::process::id()
        )));
        // SAFETY: all pointers are to NUL-terminated wide strings that outlive
        // the call; ShellExecuteW returns an HINSTANCE-like value > 32 on success.
        let rc = unsafe {
            ShellExecuteW(
                std::ptr::null_mut(),
                op.as_ptr(),
                file.as_ptr(),
                params.as_ptr(),
                std::ptr::null(),
                SW_SHOWNORMAL,
            )
        } as isize;
        if rc > 32 {
            Ok(())
        } else if rc == 5 {
            Err("Elevation was cancelled.".to_string())
        } else {
            Err(format!("Could not start an elevated instance (code {rc})."))
        }
    }
    #[cfg(not(windows))]
    {
        Err("Elevation is only supported on Windows.".to_string())
    }
}

/// If `args` carry `--wait-for-pid <pid>`, return the pid.
pub fn wait_for_pid_arg(args: &[String]) -> Option<u32> {
    let i = args.iter().position(|a| a == WAIT_FOR_PID_FLAG)?;
    args.get(i + 1)?.parse().ok()
}

/// Block until process `pid` has exited or `timeout_ms` passed. Returns true
/// when the process is gone (or never existed). Used by a freshly elevated
/// instance so the previous, non-elevated one has released the WebView2
/// user-data folder before the new window is created.
pub fn wait_for_pid_exit(pid: u32, timeout_ms: u32) -> bool {
    #[cfg(windows)]
    {
        use std::ffi::c_void;
        #[link(name = "kernel32")]
        extern "system" {
            fn OpenProcess(access: u32, inherit: i32, pid: u32) -> *mut c_void;
            fn WaitForSingleObject(h: *mut c_void, ms: u32) -> u32;
            fn CloseHandle(h: *mut c_void) -> i32;
        }
        const SYNCHRONIZE: u32 = 0x0010_0000;
        const WAIT_OBJECT_0: u32 = 0;
        // SAFETY: plain handle wait; a null handle (process already gone or
        // not openable) is treated as "gone".
        unsafe {
            let h = OpenProcess(SYNCHRONIZE, 0, pid);
            if h.is_null() {
                return true;
            }
            let rc = WaitForSingleObject(h, timeout_ms);
            CloseHandle(h);
            rc == WAIT_OBJECT_0
        }
    }
    #[cfg(not(windows))]
    {
        let _ = (pid, timeout_ms);
        true
    }
}

// ---------------------------------------------------------------- tests --

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn expand_env_replaces_known_and_keeps_unknown() {
        std::env::set_var("CM_TB_TEST_VAR", "abc");
        assert_eq!(expand_env("x%CM_TB_TEST_VAR%y"), "xabcy");
        assert_eq!(
            expand_env("%CM_TB_NO_SUCH_VAR_XYZ%\\p"),
            "%CM_TB_NO_SUCH_VAR_XYZ%\\p"
        );
        assert_eq!(expand_env("100% sure"), "100% sure");
        assert_eq!(expand_env("%%"), "%%");
    }

    #[test]
    fn cmd_display_quotes_whitespace_args_only() {
        let c = Cmd {
            program: "reg".into(),
            args: vec!["add".into(), "HKLM\\A B".into(), "/f".into()],
        };
        assert_eq!(c.display(), "reg add \"HKLM\\A B\" /f");
    }

    #[test]
    fn catalog_invariants() {
        let tools = builtin_tools();
        if !cfg!(target_os = "windows") {
            assert!(tools.is_empty());
            return;
        }
        assert!(tools.len() >= 12, "catalog shrank: {}", tools.len());
        let mut ids = HashSet::new();
        for t in &tools {
            assert!(ids.insert(t.id), "duplicate tool id {}", t.id);
            assert!(
                !t.name.is_empty() && !t.blurb.is_empty(),
                "{}: empty text",
                t.id
            );
            assert!(
                !t.check.is_empty() || !t.action.is_empty() || t.open.is_some(),
                "{}: no check, action or open",
                t.id
            );
            for c in t.check.iter().chain(t.action.iter()).chain(t.open.iter()) {
                assert!(!c.program.is_empty(), "{}: empty program", t.id);
                // No shell wrappers: every step is a real executable + argv.
                assert!(
                    !c.program.eq_ignore_ascii_case("cmd")
                        && !c.program.eq_ignore_ascii_case("cmd.exe"),
                    "{}: uses cmd shell",
                    t.id
                );
                for a in &c.args {
                    assert!(!a.contains('%'), "{}: unexpanded env token in {a}", t.id);
                }
            }
            if t.input == Input::WingetTerm {
                assert!(
                    !t.check.is_empty() && !t.action.is_empty(),
                    "{}: input tool needs both modes",
                    t.id
                );
            }
        }
        // System-changing tools must be flagged admin so the UI gates them.
        for id in [
            "winsxs",
            "sfc",
            "dism_health",
            "winsock",
            "hiberfil",
            "windows_old",
            "do_cache",
        ] {
            let t = tools.iter().find(|t| t.id == id).expect(id);
            assert!(t.needs_admin, "{id} must need admin");
        }
        assert!(tools.iter().find(|t| t.id == "winsock").unwrap().reboot);
        assert!(
            !tools
                .iter()
                .find(|t| t.id == "flush_dns")
                .unwrap()
                .needs_admin
        );
        assert!(find_tool("no_such_tool").is_none());
    }

    #[test]
    fn winget_term_validation() {
        assert_eq!(
            validate_winget_term("  Mozilla.Firefox ").unwrap(),
            "Mozilla.Firefox"
        );
        assert_eq!(
            validate_winget_term("visual studio code").unwrap(),
            "visual studio code"
        );
        assert!(validate_winget_term("").is_err());
        assert!(validate_winget_term("   ").is_err());
        assert!(validate_winget_term("--uninstall").is_err());
        assert!(validate_winget_term("/q").is_err());
        assert!(validate_winget_term("a\nb").is_err());
        assert!(validate_winget_term(&"x".repeat(129)).is_err());
    }

    #[test]
    fn winget_cmds_carry_term_as_single_arg() {
        let c = winget_cmds(Mode::Check, "visual studio code");
        assert_eq!(c.len(), 1);
        let i = c[0].args.iter().position(|a| a == "--query").unwrap();
        assert_eq!(c[0].args[i + 1], "visual studio code");
        let c = winget_cmds(Mode::Action, "Mozilla.Firefox");
        let i = c[0].args.iter().position(|a| a == "--id").unwrap();
        assert_eq!(c[0].args[i + 1], "Mozilla.Firefox");
        assert!(c[0].args.iter().any(|a| a == "--exact"));
        assert!(winget_cmds(Mode::Open, "x").is_empty());
    }

    #[test]
    fn sniff_encoding_detects_utf16_and_8bit() {
        let ascii16: Vec<u8> = "Beginning verification phase\r\n"
            .encode_utf16()
            .flat_map(|u| u.to_le_bytes())
            .collect();
        assert_eq!(sniff_encoding(&ascii16), TextEnc::Utf16Le);
        assert_eq!(sniff_encoding(&[0xFF, 0xFE, b'a', 0]), TextEnc::Utf16Le);
        assert_eq!(
            sniff_encoding(b"Deployment Image Servicing\r\n"),
            TextEnc::EightBit
        );
        // GBK bytes (Chinese DISM banner) are 8-bit, not UTF-16.
        assert_eq!(
            sniff_encoding(&[0xB2, 0xBF, 0xCA, 0xF0, 0xB3, 0xCC, 0xD0, 0xF2]),
            TextEnc::EightBit
        );
        assert_eq!(sniff_encoding(b"ok"), TextEnc::EightBit);
    }

    #[test]
    fn decode_8bit_prefers_utf8_then_codepage() {
        assert_eq!(decode_8bit_with("中文 ok".as_bytes(), 936), "中文 ok");
        // "中文" in GBK
        assert_eq!(decode_8bit_with(&[0xD6, 0xD0, 0xCE, 0xC4], 936), "中文");
        // Same bytes under Big5 decode to something else, never panic.
        assert!(!decode_8bit_with(&[0xD6, 0xD0, 0xCE, 0xC4], 950).is_empty());
        assert_eq!(decode_8bit_with(&[0xE9], 1252), "é");
    }

    #[test]
    fn drain_lines_8bit_keeps_partial_tail_until_flush() {
        let mut buf = b"line one\r\nline two\rpartial".to_vec();
        let lines = drain_lines(&mut buf, TextEnc::EightBit, false);
        assert_eq!(lines, vec!["line one".to_string(), "line two".to_string()]);
        assert_eq!(buf, b"partial");
        let lines = drain_lines(&mut buf, TextEnc::EightBit, true);
        assert_eq!(lines, vec!["partial".to_string()]);
        assert!(buf.is_empty());
    }

    #[test]
    fn drain_lines_utf16_decodes_and_drops_bom() {
        let mut buf: Vec<u8> = vec![0xFF, 0xFE];
        buf.extend(
            "Verification 100% complete.\r\nWindows Resource Protection\r\n"
                .encode_utf16()
                .flat_map(|u| u.to_le_bytes()),
        );
        buf.push(b'W'); // dangling half unit
        let lines = drain_lines(&mut buf, TextEnc::Utf16Le, false);
        assert_eq!(
            lines,
            vec![
                "Verification 100% complete.".to_string(),
                "Windows Resource Protection".to_string()
            ]
        );
        assert_eq!(buf, vec![b'W']);
    }

    fn echo_cmd(text: &str) -> Cmd {
        if cfg!(windows) {
            Cmd::new("cmd", &["/c", "echo", text])
        } else {
            Cmd::new("echo", &[text])
        }
    }

    fn fail_cmd() -> Cmd {
        if cfg!(windows) {
            Cmd::new("cmd", &["/c", "exit", "3"])
        } else {
            Cmd::new("sh", &["-c", "exit 3"])
        }
    }

    fn sleep_cmd(secs: u32) -> Cmd {
        if cfg!(windows) {
            Cmd::new("ping", &["-n", &(secs + 1).to_string(), "127.0.0.1"])
        } else {
            Cmd::new("sleep", &[&secs.to_string()])
        }
    }

    #[test]
    fn run_steps_streams_lines_and_reports_success() {
        let mut lines = Vec::new();
        let out = run_steps(
            &[echo_cmd("alpha"), echo_cmd("beta")],
            &AtomicBool::new(false),
            |l| lines.push(l.to_string()),
        )
        .unwrap();
        assert!(out.success, "{out:?} {lines:?}");
        assert_eq!(out.exit_code, Some(0));
        assert_eq!(out.steps_run, 2);
        assert!(
            lines.iter().any(|l| l.starts_with("> ")),
            "command echo line missing: {lines:?}"
        );
        assert!(lines.iter().any(|l| l.trim() == "alpha"), "{lines:?}");
        assert!(lines.iter().any(|l| l.trim() == "beta"), "{lines:?}");
    }

    #[test]
    fn run_steps_stops_at_first_failure() {
        let mut lines = Vec::new();
        let out = run_steps(
            &[fail_cmd(), echo_cmd("never")],
            &AtomicBool::new(false),
            |l| lines.push(l.to_string()),
        )
        .unwrap();
        assert!(!out.success);
        assert_eq!(out.exit_code, Some(3));
        assert_eq!(out.steps_run, 1);
        assert!(!lines.iter().any(|l| l.trim() == "never"));
    }

    #[test]
    fn run_steps_missing_program_is_an_error() {
        let r = run_steps(
            &[Cmd::new("cm-no-such-program-xyz", &[])],
            &AtomicBool::new(false),
            |_| {},
        );
        assert!(r.is_err());
    }

    #[test]
    fn run_steps_cancel_kills_child_quickly() {
        let cancel = std::sync::Arc::new(AtomicBool::new(false));
        let c2 = cancel.clone();
        let t = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(400));
            c2.store(true, Ordering::SeqCst);
        });
        let started = std::time::Instant::now();
        let out = run_steps(&[sleep_cmd(20), echo_cmd("after")], &cancel, |_| {}).unwrap();
        t.join().unwrap();
        assert!(out.cancelled, "{out:?}");
        assert!(!out.success);
        assert_eq!(out.steps_run, 1);
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "cancel took {:?}",
            started.elapsed()
        );
    }

    #[test]
    fn probe_reports_file_and_dir_sizes() {
        let dir = tempfile::tempdir().unwrap();
        let f = dir.path().join("a.bin");
        std::fs::write(&f, vec![7u8; 1234]).unwrap();
        let sub = dir.path().join("sub");
        std::fs::create_dir(&sub).unwrap();
        std::fs::write(sub.join("b.bin"), vec![1u8; 100]).unwrap();
        assert_eq!(probe_bytes(&Probe::File(f.clone())), Some(1234));
        assert_eq!(probe_bytes(&Probe::File(dir.path().join("missing"))), None);
        assert_eq!(
            probe_bytes(&Probe::Dirs(vec![dir.path().to_path_buf()])),
            Some(1334)
        );
        assert_eq!(
            probe_bytes(&Probe::Dirs(vec![
                dir.path().join("nope"),
                dir.path().join("nope2")
            ])),
            None
        );
        assert_eq!(probe_bytes(&Probe::None), None);
    }

    #[test]
    fn wait_for_pid_arg_parses_only_the_flag_form() {
        let a = |v: &[&str]| v.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        assert_eq!(
            wait_for_pid_arg(&a(&["clean-master.exe", "--wait-for-pid", "4242"])),
            Some(4242)
        );
        assert_eq!(wait_for_pid_arg(&a(&["clean-master.exe"])), None);
        assert_eq!(
            wait_for_pid_arg(&a(&["clean-master.exe", "--wait-for-pid"])),
            None
        );
        assert_eq!(
            wait_for_pid_arg(&a(&["clean-master.exe", "--wait-for-pid", "abc"])),
            None
        );
    }

    #[test]
    fn wait_for_pid_exit_returns_when_child_ends() {
        // A child that lives ~1s: wait must return true after it exits, and
        // a very short timeout on a still-running child must return false.
        let mut child = if cfg!(windows) {
            Command::new("ping")
                .args(["-n", "3", "127.0.0.1"])
                .stdout(Stdio::null())
                .spawn()
                .unwrap()
        } else {
            Command::new("sleep").arg("2").spawn().unwrap()
        };
        let pid = child.id();
        if cfg!(windows) {
            assert!(
                !wait_for_pid_exit(pid, 50),
                "child cannot be gone after 50ms"
            );
        }
        assert!(wait_for_pid_exit(pid, 15_000));
        let _ = child.wait();
        // Reaped: gone.
        assert!(wait_for_pid_exit(pid, 100));
    }

    #[test]
    fn mode_parse() {
        assert_eq!(Mode::parse("check"), Some(Mode::Check));
        assert_eq!(Mode::parse("action"), Some(Mode::Action));
        assert_eq!(Mode::parse("open"), Some(Mode::Open));
        assert_eq!(Mode::parse("rm -rf"), None);
    }
}
