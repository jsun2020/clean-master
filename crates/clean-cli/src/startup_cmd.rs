use clean_core::startup::{self, StartupEntry};
use comfy_table::{presets::UTF8_FULL_CONDENSED, Cell, Table};

/// `clean startup list`
pub fn list() -> Result<(), String> {
    let entries = startup::list();
    if entries.is_empty() {
        println!("No startup entries found (or not running on Windows).");
        return Ok(());
    }
    let mut t = Table::new();
    t.load_preset(UTF8_FULL_CONDENSED);
    t.set_header(vec!["State", "Name", "Location", "Admin", "Command"]);
    for e in &entries {
        t.add_row(vec![
            Cell::new(if e.enabled { "enabled" } else { "disabled" }),
            Cell::new(&e.name),
            Cell::new(&e.location_label),
            Cell::new(if e.requires_admin { "yes" } else { "" }),
            Cell::new(truncate(&e.command, 70)),
        ]);
    }
    println!("{t}");
    println!(
        "\n{} entries. Disabling moves an entry to a CleanMaster backup (the program is never \
         deleted); `clean startup enable <name>` restores it.",
        entries.len()
    );
    Ok(())
}

fn truncate(s: &str, n: usize) -> String {
    if s.chars().count() <= n {
        s.to_string()
    } else {
        let mut out: String = s.chars().take(n - 1).collect();
        out.push('…');
        out
    }
}

/// Find the single entry matching `name` in the desired state, or report the
/// ambiguity / absence. `want_enabled` is the state the entry must currently be
/// in for the requested action to make sense (disable wants enabled, etc.).
fn resolve<'a>(
    entries: &'a [StartupEntry],
    name: &str,
    want_enabled: bool,
) -> Result<&'a StartupEntry, String> {
    let matches: Vec<&StartupEntry> = entries
        .iter()
        .filter(|e| e.name.eq_ignore_ascii_case(name) && e.enabled == want_enabled)
        .collect();
    match matches.len() {
        0 => {
            let state = if want_enabled { "enabled" } else { "disabled" };
            Err(format!(
                "no {state} startup entry named '{name}'. Run `clean startup list` to see names."
            ))
        }
        1 => Ok(matches[0]),
        _ => {
            let locs: Vec<&str> = matches.iter().map(|e| e.location_label.as_str()).collect();
            Err(format!(
                "'{name}' matches {} entries ({}). This CLI acts on unique names; \
                 use the GUI to pick a specific one.",
                matches.len(),
                locs.join(", ")
            ))
        }
    }
}

/// `clean startup disable <name>`
pub fn disable(name: &str) -> Result<(), String> {
    let entries = startup::list();
    let entry = resolve(&entries, name, true)?;
    if entry.requires_admin && !is_elevated() {
        return Err(format!(
            "'{}' lives in {} and needs administrator rights to change. \
             Re-run from an elevated terminal.",
            entry.name, entry.location_label
        ));
    }
    startup::set_enabled(entry, false).map_err(|e| e.to_string())?;
    println!(
        "Disabled '{}' ({}). It will not run at login. Re-enable with `clean startup enable {}`.",
        entry.name, entry.location_label, entry.name
    );
    Ok(())
}

/// `clean startup enable <name>`
pub fn enable(name: &str) -> Result<(), String> {
    let entries = startup::list();
    let entry = resolve(&entries, name, false)?;
    if entry.requires_admin && !is_elevated() {
        return Err(format!(
            "'{}' belongs to {} and needs administrator rights to restore. \
             Re-run from an elevated terminal.",
            entry.name, entry.location_label
        ));
    }
    startup::set_enabled(entry, true).map_err(|e| e.to_string())?;
    println!(
        "Enabled '{}' ({}). It will run at the next login.",
        entry.name, entry.location_label
    );
    Ok(())
}

#[cfg(windows)]
fn is_elevated() -> bool {
    // Best-effort: try opening the all-users Startup parent for write. A
    // wrong answer only affects the friendliness of the pre-check; the real
    // registry/file operation still enforces permissions.
    use std::ffi::c_void;
    #[link(name = "advapi32")]
    extern "system" {
        fn OpenProcessToken(process: isize, access: u32, token: *mut isize) -> i32;
    }
    #[link(name = "kernel32")]
    extern "system" {
        fn GetCurrentProcess() -> isize;
        fn CloseHandle(h: isize) -> i32;
        fn GetTokenInformation(
            token: isize,
            class: i32,
            info: *mut c_void,
            len: u32,
            ret: *mut u32,
        ) -> i32;
    }
    const TOKEN_QUERY: u32 = 0x0008;
    const TOKEN_ELEVATION: i32 = 20;
    unsafe {
        let mut token: isize = 0;
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) == 0 {
            return false;
        }
        let mut elevation: u32 = 0;
        let mut ret_len: u32 = 0;
        let ok = GetTokenInformation(
            token,
            TOKEN_ELEVATION,
            &mut elevation as *mut u32 as *mut c_void,
            std::mem::size_of::<u32>() as u32,
            &mut ret_len,
        );
        CloseHandle(token);
        ok != 0 && elevation != 0
    }
}

#[cfg(not(windows))]
fn is_elevated() -> bool {
    false
}
