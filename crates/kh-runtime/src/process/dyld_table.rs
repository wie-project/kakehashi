//! Runtime table of mapped guest dylibs for freestanding `dlopen` / `dlsym`.
//!
//! Modern Apple `ld` has `LC_LOAD_DYLIB @rpath/libLTO.dylib` (loaded at process
//! start) **and** accepts clang's `-lto_library <path>` which re-opens the same
//! plugin via `dlopen`/`dlsym`. Soft `dlopen` → null left the linker wedged on
//! that path. This table records every mapped image (path + slid exports) so
//! freestanding can return a real handle into an already-mapped image without
//! a second map of the 150 MiB LLVM dylib.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

/// High non-null handle base so guest pointers never look like small integers.
/// (`0x4B48` = "KH"; low 16 bits hold 1-based image index.)
const HANDLE_TAG: u64 = 0x0000_4B48_D100_0000;

/// Darwin `RTLD_DEFAULT` as unsigned (`(void *)-2`).
pub const RTLD_DEFAULT: u64 = !1;
/// Darwin `RTLD_NEXT` as unsigned (`(void *)-1`).
pub const RTLD_NEXT: u64 = !0;
/// Darwin `RTLD_SELF` as unsigned (`(void *)-3`).
pub const RTLD_SELF: u64 = !2;

struct ImageEntry {
    /// Host absolute path of the mapped file.
    host_path: PathBuf,
    /// Guest install name (e.g. `@rpath/libLTO.dylib` or absolute).
    install_name: String,
    /// Basename for cheap matching (`libLTO.dylib`).
    basename: String,
    /// Export nlist name → guest VA (preferred + slide).
    exports: HashMap<String, u64>,
}

static TABLE: Mutex<Vec<ImageEntry>> = Mutex::new(Vec::new());

/// Drop all registered images (start of each `kh run`).
pub fn clear() {
    if let Ok(mut g) = TABLE.lock() {
        g.clear();
    }
}

/// Register one mapped dylib/executable for later `dlopen` / `dlsym`.
///
/// `exports` are `(nlist_name, guest_va)` with slide already applied.
pub fn register_image(
    host_path: impl Into<PathBuf>,
    install_name: impl Into<String>,
    exports: impl IntoIterator<Item = (String, u64)>,
) {
    let host_path = host_path.into();
    let install_name = install_name.into();
    let basename = host_path
        .file_name()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_default();
    let mut map = HashMap::new();
    for (name, va) in exports {
        map.insert(name, va);
    }
    let entry = ImageEntry {
        host_path,
        install_name,
        basename,
        exports: map,
    };
    if let Ok(mut g) = TABLE.lock() {
        g.push(entry);
    }
}

fn handle_for_index(idx: usize) -> u64 {
    let i = u64::try_from(idx.saturating_add(1)).unwrap_or(1);
    HANDLE_TAG | i
}

fn index_from_handle(handle: u64) -> Option<usize> {
    if handle & !0xffff == HANDLE_TAG {
        let i = handle & 0xffff;
        if i == 0 {
            return None;
        }
        return usize::try_from(i.saturating_sub(1)).ok();
    }
    // Also accept plain 1-based indices (defensive).
    if (1..=0xfffe).contains(&handle) {
        return usize::try_from(handle.saturating_sub(1)).ok();
    }
    None
}

/// Resolve `dlopen(path)` against already-mapped images.
///
/// `host_path` is the bottle-translated absolute host path (preferred).
/// `guest_path` is the original guest C string (for basename / install match).
///
/// Returns a non-zero handle or `None` if no mapped image matches.
#[must_use]
pub fn dlopen_lookup(host_path: Option<&Path>, guest_path: &str) -> Option<u64> {
    let guest_base = Path::new(guest_path)
        .file_name()
        .map(|s| s.to_string_lossy())
        .unwrap_or_default();
    let g = TABLE.lock().ok()?;
    for (idx, img) in g.iter().enumerate() {
        if let Some(hp) = host_path {
            if paths_equal(&img.host_path, hp) {
                return Some(handle_for_index(idx));
            }
            // Same basename on both sides (clang absolute vs rpath real path).
            if !guest_base.is_empty()
                && img.basename == guest_base
                && hp.file_name().is_some_and(|n| n == guest_base.as_ref())
            {
                return Some(handle_for_index(idx));
            }
        }
        if !guest_base.is_empty() && img.basename == guest_base {
            return Some(handle_for_index(idx));
        }
        if !guest_path.is_empty()
            && (img.install_name == guest_path
                || img.install_name.ends_with(guest_path)
                || guest_path.ends_with(&img.basename) && !img.basename.is_empty())
        {
            return Some(handle_for_index(idx));
        }
    }
    None
}

fn paths_equal(a: &Path, b: &Path) -> bool {
    if a == b {
        return true;
    }
    // Best-effort canonicalize (symlinks / ..).
    match (a.canonicalize(), b.canonicalize()) {
        (Ok(aa), Ok(bb)) => aa == bb,
        _ => false,
    }
}

/// Snapshot of every registered export (`nlist` → slid guest VA).
///
/// Used when binding a late `dlopen` image against already-mapped libSystem /
/// libc++ without remapping those dylibs.
#[must_use]
pub fn exports_flat() -> Vec<(String, u64)> {
    let Ok(g) = TABLE.lock() else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for img in g.iter() {
        for (name, va) in &img.exports {
            out.push((name.clone(), *va));
        }
    }
    out
}

/// `dlsym(handle, name)` — name is the guest C nlist (often with leading `_`).
#[must_use]
pub fn dlsym_lookup(handle: u64, name: &str) -> Option<u64> {
    if name.is_empty() {
        return None;
    }
    let g = TABLE.lock().ok()?;
    if handle == RTLD_DEFAULT || handle == RTLD_NEXT || handle == RTLD_SELF {
        // Search last-registered first (closer to dyld "default" scan order).
        for img in g.iter().rev() {
            if let Some(&va) = img.exports.get(name) {
                return Some(va);
            }
            // Allow callers that omit the leading underscore.
            if let Some(stripped) = name.strip_prefix('_')
                && let Some(&va) = img.exports.get(stripped)
            {
                return Some(va);
            }
            let with = format!("_{name}");
            if let Some(&va) = img.exports.get(&with) {
                return Some(va);
            }
        }
        return None;
    }
    let idx = index_from_handle(handle)?;
    let img = g.get(idx)?;
    if let Some(&va) = img.exports.get(name) {
        return Some(va);
    }
    if let Some(stripped) = name.strip_prefix('_')
        && let Some(&va) = img.exports.get(stripped)
    {
        return Some(va);
    }
    let with = format!("_{name}");
    img.exports.get(&with).copied()
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn dlopen_by_basename_and_dlsym() {
        clear();
        register_image(
            "/bottle/usr/lib/libLTO.dylib",
            "@rpath/libLTO.dylib",
            [
                ("_lto_get_version".into(), 0x1000),
                ("_lto_api_version".into(), 0x2000),
            ],
        );
        let h = dlopen_lookup(
            Some(Path::new("/other/path/libLTO.dylib")),
            "/Library/Developer/CommandLineTools/usr/lib/libLTO.dylib",
        )
        .expect("basename match");
        assert_ne!(h, 0);
        assert_eq!(dlsym_lookup(h, "_lto_get_version"), Some(0x1000));
        assert_eq!(dlsym_lookup(h, "lto_get_version"), Some(0x1000));
        assert_eq!(dlsym_lookup(RTLD_DEFAULT, "_lto_api_version"), Some(0x2000));
        clear();
    }
}
