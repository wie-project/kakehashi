//! Bottle root path translation (macOS-like FS tree under a host directory).
//!
//! Guest absolute paths such as `/usr/lib/libSystem.B.dylib` resolve to
//! `{root}/usr/lib/libSystem.B.dylib`. Path escape via `..` is rejected.
#![allow(unsafe_code)]

use std::path::{Component, Path, PathBuf};
use std::sync::Mutex;

use thiserror::Error;

/// Process-wide bottle root for the trap backend (set before guest jump).
static BOTTLE_ROOT: Mutex<Option<PathBuf>> = Mutex::new(None);

/// Path translation errors.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum PathError {
    /// Guest path was empty.
    #[error("empty guest path")]
    Empty,

    /// Guest path contained `..` or other disallowed components.
    #[error("guest path escapes bottle: {0}")]
    Escape(String),

    /// Path is not valid UTF-8 / OS string.
    #[error("invalid path encoding")]
    InvalidEncoding,
}

/// Configures the bottle root used by path-taking syscalls (`open`, `access`, …).
///
/// Pass `None` to clear (pass-through absolute guest paths to the host).
pub fn set_bottle_root(root: Option<PathBuf>) {
    if let Ok(mut guard) = BOTTLE_ROOT.lock() {
        *guard = root;
    }
}

/// Returns a clone of the configured bottle root, if any.
#[must_use]
pub fn bottle_root() -> Option<PathBuf> {
    BOTTLE_ROOT.lock().ok().and_then(|g| g.clone())
}

/// Translates a guest path string into a host path.
///
/// * Absolute guest path + bottle → `{root}/{relative}`
/// * Absolute guest path, no bottle → host absolute path as-is
/// * Relative guest path + bottle → `{root}/{relative}`
/// * Relative guest path, no bottle → host-relative path as-is
pub fn translate_path(guest: &str) -> Result<PathBuf, PathError> {
    translate_path_with_root(bottle_root().as_deref(), guest)
}

/// Pure translation helper (testable without process globals).
pub fn translate_path_with_root(root: Option<&Path>, guest: &str) -> Result<PathBuf, PathError> {
    if guest.is_empty() {
        return Err(PathError::Empty);
    }

    let guest_path = Path::new(guest);
    let relative = strip_root_components(guest_path)?;

    match root {
        Some(r) => {
            let mut out = r.to_path_buf();
            out.push(relative);
            Ok(out)
        }
        None => Ok(guest_path.to_path_buf()),
    }
}

/// Strips leading `/` (and Windows-style prefixes if any) and rejects `..`.
fn strip_root_components(path: &Path) -> Result<PathBuf, PathError> {
    let mut out = PathBuf::new();
    for comp in path.components() {
        match comp {
            Component::Prefix(_) | Component::RootDir | Component::CurDir => {}
            Component::ParentDir => {
                return Err(PathError::Escape(path.display().to_string()));
            }
            Component::Normal(s) => out.push(s),
        }
    }
    Ok(out)
}

/// Reads a NUL-terminated C string from an identity-mapped guest pointer.
///
/// Used by `open` / `access` handlers. Caps length to avoid runaway scans.
#[must_use]
pub fn read_c_string(ptr: u64, max_len: usize) -> Option<String> {
    if ptr == 0 || max_len == 0 {
        return None;
    }
    let base = usize::try_from(ptr).ok()?;
    let base_ptr: *const u8 = std::ptr::with_exposed_provenance(base);
    let mut buf = Vec::new();
    for i in 0..max_len {
        // SAFETY: identity map — guest VA == host VA for mapped pages. A bad
        // pointer may fault; callers only use this from the trap path.
        let byte = unsafe { *base_ptr.wrapping_add(i) };
        if byte == 0 {
            return String::from_utf8(buf).ok();
        }
        buf.push(byte);
    }
    None
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn absolute_under_bottle() {
        let root = Path::new("/opt/bottle");
        let host = translate_path_with_root(Some(root), "/usr/lib/libSystem.B.dylib").unwrap();
        assert_eq!(host, PathBuf::from("/opt/bottle/usr/lib/libSystem.B.dylib"));
    }

    #[test]
    fn relative_under_bottle() {
        let root = Path::new("/opt/bottle");
        let host = translate_path_with_root(Some(root), "tmp/x").unwrap();
        assert_eq!(host, PathBuf::from("/opt/bottle/tmp/x"));
    }

    #[test]
    fn no_bottle_passthrough() {
        let host = translate_path_with_root(None, "/tmp/foo").unwrap();
        assert_eq!(host, PathBuf::from("/tmp/foo"));
    }

    #[test]
    fn rejects_parent_dir() {
        let root = Path::new("/opt/bottle");
        let err = translate_path_with_root(Some(root), "/usr/../etc/passwd").unwrap_err();
        assert!(matches!(err, PathError::Escape(_)));
    }

    #[test]
    fn empty_rejected() {
        assert_eq!(translate_path_with_root(None, ""), Err(PathError::Empty));
    }
}
