//! Memory optimizer: honestly free up RAM by trimming process working sets
//! and (when elevated) purging the standby list, reporting the REAL before /
//! after available physical memory.
//!
//! This is the honest version of the old "memory defrag" tools (Wopti et al.).
//! It does NOT defragment anything - RAM has no fragmentation the way a disk
//! does - and it does NOT run automatically. Trimming a working set pushes a
//! process's rarely-used pages out of physical RAM; the reclaimed memory is
//! real, but the effect is temporary: Windows pages back in whatever a program
//! touches next. Use it to reclaim RAM before a heavy task, not as a constant
//! background "booster" (the auto-trigger pattern is the debunked, harmful bit).
//!
//! Windows-only. On other platforms `status()` returns zeros and `optimize()`
//! returns an error, so the crate still type-checks and links everywhere.

use crate::error::CoreError;
use serde::{Deserialize, Serialize};

/// A snapshot of physical-memory usage.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct MemStatus {
    pub total_bytes: u64,
    pub avail_bytes: u64,
    pub used_bytes: u64,
    /// System memory load, 0-100 (Windows `dwMemoryLoad`).
    pub percent_used: u8,
}

impl MemStatus {
    fn from_total_avail(total: u64, avail: u64, load: u32) -> MemStatus {
        MemStatus {
            total_bytes: total,
            avail_bytes: avail,
            used_bytes: total.saturating_sub(avail),
            percent_used: load.min(100) as u8,
        }
    }
}

/// The result of one `optimize()` run: what was measured before and after, and
/// what the trim actually did.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrimOutcome {
    pub before: MemStatus,
    pub after: MemStatus,
    /// `avail_after - avail_before`. May be small, zero, or (rarely) negative -
    /// reported verbatim so the user sees the honest effect, not a fabricated
    /// "freed N MB" headline.
    pub freed_bytes: i64,
    /// Processes the optimizer could see.
    pub processes_total: u32,
    /// Processes whose working set was actually trimmed (the rest could not be
    /// opened - typically system/protected processes needing higher rights).
    pub processes_trimmed: u32,
    /// Whether the standby-list purge ran (requires elevation).
    pub standby_purged: bool,
    /// Whether this process is elevated (drives what was attempted).
    pub elevated: bool,
}

/// Current physical-memory usage. Best-effort; zeros if it cannot be read
/// (and on non-Windows).
pub fn status() -> MemStatus {
    imp::status()
}

/// Trim working sets (and purge the standby list when elevated), returning an
/// honest before/after report. Errors only when the platform is unsupported or
/// the memory status itself cannot be read.
pub fn optimize() -> Result<TrimOutcome, CoreError> {
    imp::optimize()
}

// -------------------------------------------------------------- Windows --
#[cfg(windows)]
mod imp {
    use super::*;
    use std::ffi::c_void;

    #[repr(C)]
    struct MemoryStatusEx {
        length: u32,
        memory_load: u32,
        total_phys: u64,
        avail_phys: u64,
        total_pagefile: u64,
        avail_pagefile: u64,
        total_virtual: u64,
        avail_virtual: u64,
        avail_extended_virtual: u64,
    }

    // Handles are pointer-sized; use `*mut c_void` to match the rest of the
    // crate's FFI (usn.rs / toolbox.rs) so the linker sees one CloseHandle.
    type Handle = *mut c_void;

    #[link(name = "kernel32")]
    extern "system" {
        fn GlobalMemoryStatusEx(buf: *mut MemoryStatusEx) -> i32;
        fn GetCurrentProcess() -> Handle;
        fn OpenProcess(access: u32, inherit: i32, pid: u32) -> Handle;
        fn CloseHandle(h: Handle) -> i32;
        fn K32EnumProcesses(pids: *mut u32, cb: u32, needed: *mut u32) -> i32;
        fn K32EmptyWorkingSet(process: Handle) -> i32;
    }

    #[link(name = "advapi32")]
    extern "system" {
        fn OpenProcessToken(process: Handle, access: u32, token: *mut Handle) -> i32;
        fn LookupPrivilegeValueW(system: *const u16, name: *const u16, luid: *mut Luid) -> i32;
        fn AdjustTokenPrivileges(
            token: Handle,
            disable_all: i32,
            new_state: *const TokenPrivileges,
            len: u32,
            prev: *mut c_void,
            ret_len: *mut u32,
        ) -> i32;
    }

    #[link(name = "ntdll")]
    extern "system" {
        fn NtSetSystemInformation(class: i32, info: *mut c_void, len: u32) -> i32;
    }

    #[repr(C)]
    #[derive(Clone, Copy)]
    struct Luid {
        low: u32,
        high: i32,
    }

    #[repr(C)]
    struct LuidAndAttributes {
        luid: Luid,
        attributes: u32,
    }

    #[repr(C)]
    struct TokenPrivileges {
        count: u32,
        privilege: LuidAndAttributes,
    }

    const PROCESS_QUERY_INFORMATION: u32 = 0x0400;
    const PROCESS_SET_QUOTA: u32 = 0x0100;
    const TOKEN_QUERY: u32 = 0x0008;
    const TOKEN_ADJUST_PRIVILEGES: u32 = 0x0020;
    const SE_PRIVILEGE_ENABLED: u32 = 0x0002;
    // SYSTEM_INFORMATION_CLASS::SystemMemoryListInformation
    const SYSTEM_MEMORY_LIST_INFORMATION: i32 = 0x50;
    // SYSTEM_MEMORY_LIST_COMMAND::MemoryPurgeStandbyList
    const MEMORY_PURGE_STANDBY_LIST: u32 = 4;

    fn read_status() -> Option<MemStatus> {
        let mut s = MemoryStatusEx {
            length: std::mem::size_of::<MemoryStatusEx>() as u32,
            memory_load: 0,
            total_phys: 0,
            avail_phys: 0,
            total_pagefile: 0,
            avail_pagefile: 0,
            total_virtual: 0,
            avail_virtual: 0,
            avail_extended_virtual: 0,
        };
        // SAFETY: `s` is a correctly-sized MEMORYSTATUSEX with `length` set.
        if unsafe { GlobalMemoryStatusEx(&mut s) } == 0 {
            return None;
        }
        Some(MemStatus::from_total_avail(
            s.total_phys,
            s.avail_phys,
            s.memory_load,
        ))
    }

    pub fn status() -> MemStatus {
        read_status().unwrap_or(MemStatus {
            total_bytes: 0,
            avail_bytes: 0,
            used_bytes: 0,
            percent_used: 0,
        })
    }

    /// Trim every process whose handle we can open with the rights
    /// `EmptyWorkingSet` needs. Returns `(total_seen, trimmed)`.
    fn trim_working_sets() -> (u32, u32) {
        // EnumProcesses fills a caller-allocated array of PIDs. Grow until the
        // returned byte count is smaller than the buffer (i.e. it fit).
        let mut cap = 1024usize;
        let mut pids: Vec<u32>;
        let count;
        loop {
            pids = vec![0u32; cap];
            let mut needed: u32 = 0;
            let cb = (cap * std::mem::size_of::<u32>()) as u32;
            // SAFETY: `pids` holds `cap` u32s; `cb` matches its byte length.
            if unsafe { K32EnumProcesses(pids.as_mut_ptr(), cb, &mut needed) } == 0 {
                return (0, 0);
            }
            let returned = needed as usize / std::mem::size_of::<u32>();
            if returned < cap {
                count = returned;
                break;
            }
            // Buffer was full - there may be more; grow and retry.
            cap *= 2;
            if cap > 1 << 20 {
                count = cap; // absurd; take what we have
                break;
            }
        }

        let mut total = 0u32;
        let mut trimmed = 0u32;
        for &pid in &pids[..count] {
            if pid == 0 {
                continue; // System Idle Process
            }
            total += 1;
            // SAFETY: OpenProcess returns null on failure; we only use / close
            // a non-null handle.
            let h = unsafe { OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_SET_QUOTA, 0, pid) };
            if h.is_null() {
                continue; // protected/system process without the rights
            }
            // SAFETY: `h` is a live process handle with SET_QUOTA rights.
            if unsafe { K32EmptyWorkingSet(h) } != 0 {
                trimmed += 1;
            }
            // SAFETY: `h` was opened above and is not used after this.
            unsafe { CloseHandle(h) };
        }
        (total, trimmed)
    }

    fn wide(s: &str) -> Vec<u16> {
        s.encode_utf16().chain(std::iter::once(0)).collect()
    }

    /// Enable `SeProfileSingleProcessPrivilege` on the current process token,
    /// which the standby-list purge requires. Best-effort.
    fn enable_profile_privilege() -> bool {
        // SAFETY: token opened for adjust+query and closed on every path; the
        // TOKEN_PRIVILEGES struct is fully initialized before AdjustTokenPrivileges.
        unsafe {
            let mut token: Handle = std::ptr::null_mut();
            if OpenProcessToken(
                GetCurrentProcess(),
                TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
                &mut token,
            ) == 0
            {
                return false;
            }
            let name = wide("SeProfileSingleProcessPrivilege");
            let mut luid = Luid { low: 0, high: 0 };
            if LookupPrivilegeValueW(std::ptr::null(), name.as_ptr(), &mut luid) == 0 {
                CloseHandle(token);
                return false;
            }
            let tp = TokenPrivileges {
                count: 1,
                privilege: LuidAndAttributes {
                    luid,
                    attributes: SE_PRIVILEGE_ENABLED,
                },
            };
            let ok = AdjustTokenPrivileges(
                token,
                0,
                &tp,
                std::mem::size_of::<TokenPrivileges>() as u32,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            );
            CloseHandle(token);
            // AdjustTokenPrivileges "succeeds" (nonzero) even if the privilege
            // was not assigned; GetLastError would say ERROR_NOT_ALL_ASSIGNED.
            // The NtSetSystemInformation call below is the real gate, so treat
            // a nonzero return as "attempted".
            ok != 0
        }
    }

    /// Purge the standby (cached) page list, which is where most of the visible
    /// "freed RAM" comes from. Requires elevation + the profile privilege.
    fn purge_standby_list() -> bool {
        if !enable_profile_privilege() {
            return false;
        }
        let mut command: u32 = MEMORY_PURGE_STANDBY_LIST;
        // SAFETY: passing a pointer to a u32 command of the documented length
        // for SystemMemoryListInformation.
        let status = unsafe {
            NtSetSystemInformation(
                SYSTEM_MEMORY_LIST_INFORMATION,
                &mut command as *mut u32 as *mut c_void,
                std::mem::size_of::<u32>() as u32,
            )
        };
        status == 0 // STATUS_SUCCESS
    }

    pub fn optimize() -> Result<TrimOutcome, CoreError> {
        let before = read_status()
            .ok_or_else(|| CoreError::Session("could not read memory status".into()))?;
        let elevated = crate::toolbox::is_elevated();

        let (processes_total, processes_trimmed) = trim_working_sets();
        // Only attempt the standby purge when elevated; unelevated it just
        // returns STATUS_PRIVILEGE_NOT_HELD, so skip it and report honestly.
        let standby_purged = elevated && purge_standby_list();

        let after = read_status().unwrap_or(before);
        let freed_bytes = after.avail_bytes as i64 - before.avail_bytes as i64;

        Ok(TrimOutcome {
            before,
            after,
            freed_bytes,
            processes_total,
            processes_trimmed,
            standby_purged,
            elevated,
        })
    }
}

// ---------------------------------------------------------- non-Windows --
#[cfg(not(windows))]
mod imp {
    use super::*;

    pub fn status() -> MemStatus {
        MemStatus {
            total_bytes: 0,
            avail_bytes: 0,
            used_bytes: 0,
            percent_used: 0,
        }
    }

    pub fn optimize() -> Result<TrimOutcome, CoreError> {
        Err(CoreError::Session(
            "memory optimization is only available on Windows".into(),
        ))
    }
}

#[cfg(all(test, windows))]
mod tests {
    use super::*;

    #[test]
    fn status_reports_real_totals() {
        let s = status();
        assert!(s.total_bytes > 0, "total physical memory should be nonzero");
        assert!(
            s.avail_bytes <= s.total_bytes,
            "available cannot exceed total"
        );
        assert!(s.percent_used <= 100);
    }

    // optimize() trims the working sets of the current user's processes. That
    // is benign and transient, but it is a real machine-wide side effect, so it
    // is not run by default - the CLI (`clean mem --run`) exercises it live.
    #[test]
    #[ignore = "has a real (benign, transient) machine-wide effect; run manually"]
    fn optimize_returns_consistent_before_after() {
        let out = optimize().expect("optimize should succeed on Windows");
        assert_eq!(out.before.total_bytes, out.after.total_bytes);
        assert!(out.processes_total > 0);
        assert!(out.processes_trimmed <= out.processes_total);
    }
}

#[cfg(all(test, not(windows)))]
mod tests {
    use super::*;

    #[test]
    fn non_windows_status_zero_and_optimize_errors() {
        assert_eq!(status().total_bytes, 0);
        assert!(optimize().is_err());
    }
}
