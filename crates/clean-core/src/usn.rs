//! NTFS USN change-journal access for differential rescans.
//!
//! The journal is the filesystem's own log of every create/delete/rename/
//! write, keyed by the changed file's PARENT directory id (FRN). Reading it
//! answers "which directories changed since checkpoint X?" without walking
//! the tree - the whole point of a fast rescan.
//!
//! Empirically verified on this project's target environment (Windows 10,
//! non-elevated, corporate EDR): opening `\\.\C:` with FILE_TRAVERSE access
//! succeeds without admin, `FSCTL_QUERY_USN_JOURNAL` and
//! `FSCTL_READ_UNPRIVILEGED_USN_JOURNAL` both work on that handle, and
//! `OpenFileById` resolves directory FRNs back to paths. The unprivileged
//! read FSCTL returns records with EMPTY file names - by design we only use
//! the parent FRN, so that costs nothing.
//!
//! Every failure path degrades to `Unavailable(reason)`: the caller falls
//! back to a full walk, never to wrong data.

use std::collections::HashSet;
#[cfg(not(windows))]
use std::path::Path;

/// Where the journal stood when a snapshot was taken. `next_usn` is the first
/// record id we have NOT yet seen.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UsnCheckpoint {
    pub journal_id: u64,
    pub next_usn: i64,
    pub volume_serial: u32,
}

/// Outcome of asking the journal what changed since a checkpoint.
#[derive(Debug)]
pub enum DeltaVerdict {
    /// Lowercased full paths of directories whose direct children changed.
    /// May be empty: nothing changed under the root.
    Dirty(HashSet<String>),
    /// The journal cannot vouch for the interval; do a full scan.
    Unavailable(&'static str),
}

#[cfg(windows)]
pub use imp::{changed_dirs_since, checkpoint_for};

#[cfg(not(windows))]
pub fn checkpoint_for(_root: &Path) -> Option<UsnCheckpoint> {
    None
}

#[cfg(not(windows))]
pub fn changed_dirs_since(_root: &Path, _cp: &UsnCheckpoint, _max_dirty: usize) -> DeltaVerdict {
    DeltaVerdict::Unavailable("usn journal is Windows-only")
}

#[cfg(windows)]
mod imp {
    use super::{DeltaVerdict, UsnCheckpoint};
    use std::collections::HashSet;

    /// Cap on volume-wide unique parent FRNs we are willing to resolve. Each
    /// resolution is one file open (~1ms under EDR); past this a full walk is
    /// competitive anyway.
    const MAX_FRN_RESOLVE: usize = 60_000;
    use std::ffi::c_void;
    use std::os::windows::ffi::OsStrExt;
    use std::path::{Component, Path, Prefix};

    // Matches the crate's other modules (toolbox.rs) so the extern
    // declarations do not clash.
    type Handle = *mut c_void;
    const INVALID_HANDLE_VALUE: Handle = -1isize as Handle;
    const OPEN_EXISTING: u32 = 3;
    const FILE_SHARE_READ: u32 = 1;
    const FILE_SHARE_WRITE: u32 = 2;
    const FILE_SHARE_DELETE: u32 = 4;
    const FILE_TRAVERSE: u32 = 0x20;
    const FILE_READ_ATTRIBUTES: u32 = 0x80;
    const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;

    const FSCTL_QUERY_USN_JOURNAL: u32 = 0x000900F4;
    const FSCTL_READ_UNPRIVILEGED_USN_JOURNAL: u32 = 0x000903AB;

    #[repr(C)]
    #[derive(Default, Clone, Copy)]
    struct ReadUsnJournalDataV0 {
        start_usn: i64,
        reason_mask: u32,
        return_only_on_close: u32,
        timeout: u64,
        bytes_to_wait_for: u64,
        journal_id: u64,
    }

    #[repr(C)]
    struct FileIdDescriptor {
        size: u32,
        kind: u32,    // 0 = FileIdType
        id: [u8; 16], // union; first 8 bytes = the 64-bit FRN
    }

    #[link(name = "kernel32")]
    extern "system" {
        fn CreateFileW(
            name: *const u16,
            access: u32,
            share: u32,
            sec: *mut c_void,
            disposition: u32,
            flags: u32,
            template: Handle,
        ) -> Handle;
        fn DeviceIoControl(
            h: Handle,
            code: u32,
            in_buf: *const c_void,
            in_len: u32,
            out_buf: *mut c_void,
            out_len: u32,
            returned: *mut u32,
            overlapped: *mut c_void,
        ) -> i32;
        fn CloseHandle(h: Handle) -> i32;
        fn OpenFileById(
            volume_hint: Handle,
            id: *const FileIdDescriptor,
            access: u32,
            share: u32,
            sec: *mut c_void,
            flags: u32,
        ) -> Handle;
        fn GetFinalPathNameByHandleW(h: Handle, buf: *mut u16, len: u32, flags: u32) -> u32;
        fn GetVolumeInformationW(
            root: *const u16,
            name_buf: *mut u16,
            name_len: u32,
            serial: *mut u32,
            max_component: *mut u32,
            fs_flags: *mut u32,
            fs_name_buf: *mut u16,
            fs_name_len: u32,
        ) -> i32;
    }

    fn wide(s: &str) -> Vec<u16> {
        std::ffi::OsStr::new(s)
            .encode_wide()
            .chain(Some(0))
            .collect()
    }

    /// Drive letter of an absolute local path (`C`), or None for UNC etc.
    fn drive_letter(root: &Path) -> Option<char> {
        match root.components().next()? {
            Component::Prefix(p) => match p.kind() {
                Prefix::Disk(d) | Prefix::VerbatimDisk(d) => Some(d as char),
                _ => None,
            },
            _ => None,
        }
    }

    /// RAII wrapper so every early return closes the volume handle.
    struct Volume(Handle);
    impl Drop for Volume {
        fn drop(&mut self) {
            unsafe { CloseHandle(self.0) };
        }
    }

    fn open_volume(letter: char) -> Option<Volume> {
        let name = wide(&format!("\\\\.\\{letter}:"));
        let h = unsafe {
            CreateFileW(
                name.as_ptr(),
                FILE_TRAVERSE,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                std::ptr::null_mut(),
                OPEN_EXISTING,
                0,
                std::ptr::null_mut(),
            )
        };
        if h == INVALID_HANDLE_VALUE {
            None
        } else {
            Some(Volume(h))
        }
    }

    fn volume_serial(letter: char) -> Option<u32> {
        let root = wide(&format!("{letter}:\\"));
        let mut serial = 0u32;
        let ok = unsafe {
            GetVolumeInformationW(
                root.as_ptr(),
                std::ptr::null_mut(),
                0,
                &mut serial,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                0,
            )
        };
        if ok == 0 {
            None
        } else {
            Some(serial)
        }
    }

    /// journal_id, first_usn, next_usn.
    fn query_journal(vol: &Volume) -> Option<(u64, i64, i64)> {
        // Buffer sized for USN_JOURNAL_DATA_V2; the V0 fields are a prefix.
        let mut out = [0u8; 80];
        let mut ret = 0u32;
        let ok = unsafe {
            DeviceIoControl(
                vol.0,
                FSCTL_QUERY_USN_JOURNAL,
                std::ptr::null(),
                0,
                out.as_mut_ptr() as *mut c_void,
                out.len() as u32,
                &mut ret,
                std::ptr::null_mut(),
            )
        };
        if ok == 0 || ret < 24 {
            return None;
        }
        let id = u64::from_le_bytes(out[0..8].try_into().ok()?);
        let first = i64::from_le_bytes(out[8..16].try_into().ok()?);
        let next = i64::from_le_bytes(out[16..24].try_into().ok()?);
        Some((id, first, next))
    }

    pub fn checkpoint_for(root: &Path) -> Option<UsnCheckpoint> {
        let letter = drive_letter(root)?;
        let vol = open_volume(letter)?;
        let (journal_id, _first, next_usn) = query_journal(&vol)?;
        Some(UsnCheckpoint {
            journal_id,
            next_usn,
            volume_serial: volume_serial(letter)?,
        })
    }

    /// Collect the unique parent FRNs of every journal record in
    /// [cp.next_usn, target). Returns None when the journal refuses mid-read
    /// or the set explodes past MAX_FRN_RESOLVE.
    fn collect_parent_frns(
        vol: &Volume,
        journal_id: u64,
        start: i64,
        target: i64,
    ) -> Option<HashSet<u64>> {
        let mut parents: HashSet<u64> = HashSet::new();
        let mut buf = vec![0u8; 1 << 20];
        let mut usn = start;
        loop {
            if usn >= target {
                return Some(parents);
            }
            let input = ReadUsnJournalDataV0 {
                start_usn: usn,
                reason_mask: 0xFFFF_FFFF,
                journal_id,
                ..Default::default()
            };
            let mut ret = 0u32;
            let ok = unsafe {
                DeviceIoControl(
                    vol.0,
                    FSCTL_READ_UNPRIVILEGED_USN_JOURNAL,
                    &input as *const _ as *const c_void,
                    std::mem::size_of::<ReadUsnJournalDataV0>() as u32,
                    buf.as_mut_ptr() as *mut c_void,
                    buf.len() as u32,
                    &mut ret,
                    std::ptr::null_mut(),
                )
            };
            if ok == 0 {
                return None;
            }
            let ret = ret as usize;
            if ret < 8 {
                return Some(parents); // caught up: no more records
            }
            let next = i64::from_le_bytes(buf[0..8].try_into().ok()?);
            let mut off = 8usize;
            while off + 60 <= ret {
                let rec_len = u32::from_le_bytes(buf[off..off + 4].try_into().ok()?) as usize;
                if rec_len < 60 || off + rec_len > ret {
                    break;
                }
                let major = u16::from_le_bytes(buf[off + 4..off + 6].try_into().ok()?);
                // The V0 read request yields V2 records; skip anything else.
                if major == 2 {
                    let parent = u64::from_le_bytes(buf[off + 16..off + 24].try_into().ok()?);
                    parents.insert(parent);
                    if parents.len() > MAX_FRN_RESOLVE {
                        return None;
                    }
                }
                off += rec_len;
            }
            if next <= usn {
                return Some(parents); // no forward progress: stop cleanly
            }
            usn = next;
        }
    }

    /// FRN -> real full path (`C:\...`), or None (commonly: dir deleted since).
    fn resolve_frn(vol: &Volume, frn: u64) -> Option<String> {
        let mut id = [0u8; 16];
        id[..8].copy_from_slice(&frn.to_le_bytes());
        let desc = FileIdDescriptor {
            size: std::mem::size_of::<FileIdDescriptor>() as u32,
            kind: 0,
            id,
        };
        let h = unsafe {
            OpenFileById(
                vol.0,
                &desc,
                FILE_READ_ATTRIBUTES,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                std::ptr::null_mut(),
                FILE_FLAG_BACKUP_SEMANTICS,
            )
        };
        if h == INVALID_HANDLE_VALUE {
            return None;
        }
        let mut buf = vec![0u16; 4096];
        let n = unsafe { GetFinalPathNameByHandleW(h, buf.as_mut_ptr(), buf.len() as u32, 0) };
        unsafe { CloseHandle(h) };
        if n == 0 || n as usize >= buf.len() {
            return None;
        }
        let s = String::from_utf16_lossy(&buf[..n as usize]);
        // VOLUME_NAME_DOS returns \\?\C:\... - strip the verbatim prefix.
        Some(s.strip_prefix("\\\\?\\").unwrap_or(&s).to_string())
    }

    pub fn changed_dirs_since(root: &Path, cp: &UsnCheckpoint, max_dirty: usize) -> DeltaVerdict {
        let Some(letter) = drive_letter(root) else {
            return DeltaVerdict::Unavailable("root has no drive letter");
        };
        if volume_serial(letter) != Some(cp.volume_serial) {
            return DeltaVerdict::Unavailable("volume changed");
        }
        let Some(vol) = open_volume(letter) else {
            return DeltaVerdict::Unavailable("cannot open volume");
        };
        let Some((journal_id, first_usn, next_usn)) = query_journal(&vol) else {
            return DeltaVerdict::Unavailable("no usn journal");
        };
        if journal_id != cp.journal_id {
            return DeltaVerdict::Unavailable("journal recreated");
        }
        if cp.next_usn < first_usn {
            return DeltaVerdict::Unavailable("journal wrapped");
        }
        if cp.next_usn > next_usn {
            return DeltaVerdict::Unavailable("checkpoint ahead of journal");
        }
        let Some(parents) = collect_parent_frns(&vol, journal_id, cp.next_usn, next_usn) else {
            return DeltaVerdict::Unavailable("too many changes on volume");
        };

        // Only paths at-or-under the scanned root matter.
        let root_lower = root
            .display()
            .to_string()
            .trim_end_matches(['\\', '/'])
            .to_lowercase();
        let mut dirty: HashSet<String> = HashSet::new();
        for frn in parents {
            // Unresolvable = the directory no longer exists; its deletion also
            // dirtied a surviving ancestor, so skipping it is safe.
            let Some(path) = resolve_frn(&vol, frn) else {
                continue;
            };
            let lower = path.to_lowercase();
            let under_root = lower == root_lower
                || (lower.starts_with(&root_lower)
                    && lower.as_bytes().get(root_lower.len()) == Some(&b'\\'));
            if under_root {
                dirty.insert(lower);
                if dirty.len() > max_dirty {
                    return DeltaVerdict::Unavailable("too many changes under root");
                }
            }
        }
        DeltaVerdict::Dirty(dirty)
    }
}

#[cfg(all(test, windows))]
mod tests {
    use super::*;
    use std::path::{Path, PathBuf};

    fn c_root() -> PathBuf {
        PathBuf::from("C:\\")
    }

    /// The dev/CI box may lack a journal; tests gate on that honestly.
    fn live_checkpoint() -> Option<UsnCheckpoint> {
        checkpoint_for(&c_root())
    }

    #[test]
    fn checkpoint_has_plausible_values() {
        let Some(cp) = live_checkpoint() else {
            eprintln!("skip: no usn journal on C:");
            return;
        };
        assert!(cp.journal_id != 0);
        assert!(cp.next_usn > 0);
        assert!(cp.volume_serial != 0);
    }

    #[test]
    fn mismatched_journal_id_is_unavailable() {
        let Some(mut cp) = live_checkpoint() else {
            eprintln!("skip: no usn journal on C:");
            return;
        };
        cp.journal_id ^= 0xDEAD_BEEF;
        match changed_dirs_since(&c_root(), &cp, 1000) {
            DeltaVerdict::Unavailable(r) => assert_eq!(r, "journal recreated"),
            DeltaVerdict::Dirty(_) => panic!("wrong journal id must not produce a delta"),
        }
    }

    #[test]
    fn wrapped_checkpoint_is_unavailable() {
        let Some(mut cp) = live_checkpoint() else {
            eprintln!("skip: no usn journal on C:");
            return;
        };
        cp.next_usn = -5; // guaranteed below any journal's first_usn
        match changed_dirs_since(&c_root(), &cp, 1000) {
            DeltaVerdict::Unavailable(r) => assert_eq!(r, "journal wrapped"),
            DeltaVerdict::Dirty(_) => panic!("wrapped checkpoint must not produce a delta"),
        }
    }

    #[test]
    fn future_checkpoint_is_unavailable() {
        let Some(mut cp) = live_checkpoint() else {
            eprintln!("skip: no usn journal on C:");
            return;
        };
        cp.next_usn = i64::MAX / 2;
        match changed_dirs_since(&c_root(), &cp, 1000) {
            DeltaVerdict::Unavailable(r) => assert_eq!(r, "checkpoint ahead of journal"),
            DeltaVerdict::Dirty(_) => panic!("future checkpoint must not produce a delta"),
        }
    }

    #[test]
    fn changed_volume_serial_is_unavailable() {
        let Some(mut cp) = live_checkpoint() else {
            eprintln!("skip: no usn journal on C:");
            return;
        };
        cp.volume_serial = cp.volume_serial.wrapping_add(1);
        match changed_dirs_since(&c_root(), &cp, 1000) {
            DeltaVerdict::Unavailable(r) => assert_eq!(r, "volume changed"),
            DeltaVerdict::Dirty(_) => panic!("serial mismatch must not produce a delta"),
        }
    }

    #[test]
    fn unc_root_is_unavailable() {
        let cp = UsnCheckpoint {
            journal_id: 1,
            next_usn: 1,
            volume_serial: 1,
        };
        match changed_dirs_since(Path::new("\\\\server\\share"), &cp, 1000) {
            DeltaVerdict::Unavailable(r) => assert_eq!(r, "root has no drive letter"),
            DeltaVerdict::Dirty(_) => panic!("UNC roots have no journal"),
        }
    }
}
