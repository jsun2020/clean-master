//! Minimal Windows `.lnk` (Shell Link) parser: extract the local target path
//! so a broken-shortcut junk rule can tell whether the target still exists.
//!
//! Deliberately conservative. It reads only the LinkInfo `LocalBasePath`
//! (+ CommonPathSuffix), the field Windows fills in for a shortcut to a
//! local file or folder. When the structure is absent, network-only, or in
//! any way unclear, it returns `None` - and a `None` target is treated as
//! "cannot determine, do not flag", so a shortcut is only ever called broken
//! when a concrete local path was resolved and does not exist on disk. Format
//! reference: [MS-SHLLINK].

fn u16le(b: &[u8], off: usize) -> Option<u16> {
    b.get(off..off + 2)
        .map(|s| u16::from_le_bytes([s[0], s[1]]))
}

fn u32le(b: &[u8], off: usize) -> Option<u32> {
    b.get(off..off + 4)
        .map(|s| u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
}

fn ansi_cstr(b: &[u8], off: usize) -> Option<String> {
    let slice = b.get(off..)?;
    let end = slice.iter().position(|&c| c == 0).unwrap_or(slice.len());
    // LocalBasePath is a system-codepage string; for existence checks the
    // ASCII subset is what matters and lossy decode keeps it total.
    Some(String::from_utf8_lossy(&slice[..end]).into_owned())
}

fn utf16_cstr(b: &[u8], off: usize) -> Option<String> {
    let slice = b.get(off..)?;
    let mut units = Vec::new();
    let mut i = 0;
    while i + 1 < slice.len() {
        let u = u16::from_le_bytes([slice[i], slice[i + 1]]);
        if u == 0 {
            break;
        }
        units.push(u);
        i += 2;
    }
    Some(String::from_utf16_lossy(&units))
}

const HEADER_SIZE: usize = 0x4C;
const FLAG_HAS_LINK_TARGET_IDLIST: u32 = 0x1;
const FLAG_HAS_LINK_INFO: u32 = 0x2;
const LINKINFO_VOLUMEID_AND_LOCAL_BASE_PATH: u32 = 0x1;

/// Resolve the local target path a `.lnk` points at, or `None` when it cannot
/// be determined from the LinkInfo (no local base path, network target,
/// truncated/invalid data).
pub fn local_target_path(bytes: &[u8]) -> Option<String> {
    // ShellLinkHeader: HeaderSize (must be 0x4C) then a 16-byte CLSID.
    if u32le(bytes, 0)? as usize != HEADER_SIZE {
        return None;
    }
    let flags = u32le(bytes, 0x14)?;

    let mut off = HEADER_SIZE;
    if flags & FLAG_HAS_LINK_TARGET_IDLIST != 0 {
        // LinkTargetIDList = u16 size prefix + that many bytes.
        let idlist_size = u16le(bytes, off)? as usize;
        off = off.checked_add(2)?.checked_add(idlist_size)?;
    }

    if flags & FLAG_HAS_LINK_INFO == 0 {
        return None; // no LinkInfo -> no local base path to test
    }

    let li = off; // LinkInfo start
    let li_flags = u32le(bytes, li + 8)?;
    if li_flags & LINKINFO_VOLUMEID_AND_LOCAL_BASE_PATH == 0 {
        return None; // network-relative only; not a local path
    }
    // Field layout inside LinkInfo:
    //   0  LinkInfoSize
    //   4  LinkInfoHeaderSize
    //   8  LinkInfoFlags
    //   12 VolumeIDOffset
    //   16 LocalBasePathOffset
    //   20 CommonNetworkRelativeLinkOffset
    //   24 CommonPathSuffixOffset
    //   28 LocalBasePathOffsetUnicode   (only if HeaderSize >= 0x24)
    let li_header = u32le(bytes, li + 4)? as usize;
    let local_base_off = u32le(bytes, li + 16)? as usize;
    let suffix_off = u32le(bytes, li + 24)? as usize;

    // Prefer the Unicode base path when present (HeaderSize >= 0x24).
    let base = if li_header >= 0x24 {
        let ubase_off = u32le(bytes, li + 28)? as usize;
        utf16_cstr(bytes, li + ubase_off)
    } else {
        ansi_cstr(bytes, li + local_base_off)
    }?;

    if base.is_empty() {
        return None;
    }
    let suffix = if suffix_off != 0 {
        ansi_cstr(bytes, li + suffix_off).unwrap_or_default()
    } else {
        String::new()
    };
    Some(format!("{base}{suffix}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a minimal `.lnk` with a LinkInfo carrying an ANSI LocalBasePath.
    fn lnk_with_ansi_target(target: &str) -> Vec<u8> {
        let mut b = vec![0u8; HEADER_SIZE];
        b[0..4].copy_from_slice(&(HEADER_SIZE as u32).to_le_bytes()); // HeaderSize
                                                                      // LinkFlags: HasLinkInfo only (no IDList) at 0x14.
        b[0x14..0x18].copy_from_slice(&FLAG_HAS_LINK_INFO.to_le_bytes());

        // LinkInfo (ANSI, HeaderSize 0x1C): fixed 28-byte header + base path.
        let li_header_size: u32 = 0x1C;
        let local_base_off: u32 = 0x1C; // path right after the header
        let path_bytes = {
            let mut v = target.as_bytes().to_vec();
            v.push(0);
            v
        };
        let mut li = Vec::new();
        let li_size = 0x1C + path_bytes.len() as u32;
        li.extend_from_slice(&li_size.to_le_bytes()); // 0 LinkInfoSize
        li.extend_from_slice(&li_header_size.to_le_bytes()); // 4 LinkInfoHeaderSize
        li.extend_from_slice(&LINKINFO_VOLUMEID_AND_LOCAL_BASE_PATH.to_le_bytes()); // 8 flags
        li.extend_from_slice(&0u32.to_le_bytes()); // 12 VolumeIDOffset
        li.extend_from_slice(&local_base_off.to_le_bytes()); // 16 LocalBasePathOffset
        li.extend_from_slice(&0u32.to_le_bytes()); // 20 CommonNetworkRelativeLinkOffset
        li.extend_from_slice(&0u32.to_le_bytes()); // 24 CommonPathSuffixOffset (0 = empty)
        li.extend_from_slice(&path_bytes); // 0x1C base path
        b.extend_from_slice(&li);
        b
    }

    #[test]
    fn parses_ansi_local_base_path() {
        let lnk = lnk_with_ansi_target(r"C:\Program Files\App\app.exe");
        assert_eq!(
            local_target_path(&lnk).as_deref(),
            Some(r"C:\Program Files\App\app.exe")
        );
    }

    #[test]
    fn rejects_non_lnk_bytes() {
        assert!(local_target_path(b"not a shortcut").is_none());
        assert!(local_target_path(&[]).is_none());
    }

    #[test]
    fn none_when_no_link_info_flag() {
        let mut b = vec![0u8; HEADER_SIZE];
        b[0..4].copy_from_slice(&(HEADER_SIZE as u32).to_le_bytes());
        // No flags set at all -> no LinkInfo.
        assert!(local_target_path(&b).is_none());
    }

    #[test]
    fn truncated_link_info_is_none_not_panic() {
        let mut lnk = lnk_with_ansi_target(r"C:\x\y.exe");
        lnk.truncate(HEADER_SIZE + 8); // cut off mid-LinkInfo
        assert!(local_target_path(&lnk).is_none());
    }
}
