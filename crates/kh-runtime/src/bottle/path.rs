//! Bottle root path translation (macOS-like FS tree under a host directory).
//!
//! Guest absolute paths such as `/usr/lib/libSystem.B.dylib` resolve to
//! `{root}/usr/lib/libSystem.B.dylib`. Path escape via `..` is rejected.

use std::path::{Component, Path, PathBuf};

use thiserror::Error;

use crate::process;

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
    process::set_bottle_root(root);
}

/// Returns a clone of the configured bottle root, if any.
#[must_use]
pub fn bottle_root() -> Option<PathBuf> {
    process::bottle_root()
}

/// Translates a guest path string into a host path.
///
/// * Absolute guest path + bottle → `{root}/{stripped absolute}`
/// * Absolute guest path, no bottle → host absolute path as-is
/// * Relative guest path → **host CWD-relative** (Darwin open semantics); bottle
///   is not applied. Still rejects `..` escape components.
pub fn translate_path(guest: &str) -> Result<PathBuf, PathError> {
    // Avoid cloning the bottle root PathBuf on every open/stat.
    process::with_bottle_root(|root| translate_path_with_root(root, guest))
}

/// Pure translation helper (testable without process globals).
pub fn translate_path_with_root(root: Option<&Path>, guest: &str) -> Result<PathBuf, PathError> {
    if guest.is_empty() {
        return Err(PathError::Empty);
    }

    // Relative paths follow host CWD (fixtures / argv paths), not the bottle tree.
    if !guest.starts_with('/') {
        // Reject `..` while keeping the original relative string for open(2).
        strip_root_components(Path::new(guest))?;
        return Ok(PathBuf::from(guest));
    }

    // Fast path: no `..` and no empty components → strip leading slashes / `.`
    // without allocating intermediate PathBufs for each component.
    if let Some(rel) = try_fast_relative(guest) {
        return match root {
            Some(r) => {
                let mut out = PathBuf::with_capacity(
                    r.as_os_str()
                        .len()
                        .saturating_add(rel.len())
                        .saturating_add(1),
                );
                out.push(r);
                if !rel.is_empty() {
                    out.push(rel);
                }
                Ok(out)
            }
            None => Ok(PathBuf::from(guest)),
        };
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

/// Returns stripped relative guest path when it has no `..` (and no empty segs).
///
/// `None` means fall back to the full component walker.
fn try_fast_relative(guest: &str) -> Option<&str> {
    if guest.contains("..") {
        // May be `foo..bar` (ok) or `../x` / `a/../b` — let the slow path decide.
        if guest == ".."
            || guest.starts_with("../")
            || guest.ends_with("/..")
            || guest.contains("/../")
        {
            return None;
        }
    }
    let mut s = guest;
    while let Some(rest) = s.strip_prefix('/') {
        s = rest;
    }
    // Drop a single leading "./"
    if let Some(rest) = s.strip_prefix("./") {
        s = rest;
    }
    // Reject remaining "./" or empty segments that need normalization.
    if s.contains("/./") || s.contains("//") || s.ends_with("/.") {
        return None;
    }
    Some(s)
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

/// Stack buffer size for typical guest paths (avoids heap on open/stat).
const PATH_STACK: usize = 512;

/// Reads a NUL-terminated C string from an identity-mapped guest pointer.
///
/// Used by `open` / `access` handlers. Caps length to avoid runaway scans.
#[must_use]
#[allow(unsafe_code)]
pub fn read_c_string(ptr: u64, max_len: usize) -> Option<String> {
    if ptr == 0 || max_len == 0 {
        return None;
    }
    let base = usize::try_from(ptr).ok()?;
    let base_ptr: *const u8 = std::ptr::with_exposed_provenance(base);

    let mut stack = [0_u8; PATH_STACK];
    let stack_cap = PATH_STACK.min(max_len);
    for i in 0..stack_cap {
        // SAFETY: identity map — guest VA == host VA for mapped pages.
        let byte = unsafe { *base_ptr.wrapping_add(i) };
        if byte == 0 {
            return stack.get(..i).and_then(|s| std::str::from_utf8(s).ok()).map(str::to_owned);
        }
        if let Some(slot) = stack.get_mut(i) {
            *slot = byte;
        }
    }
    if stack_cap == max_len {
        return None; // no NUL within cap
    }

    // Longer path: fall back to heap.
    let mut buf = Vec::with_capacity(stack_cap.saturating_add(64));
    if let Some(prefix) = stack.get(..stack_cap) {
        buf.extend_from_slice(prefix);
    }
    for i in stack_cap..max_len {
        let byte = unsafe { *base_ptr.wrapping_add(i) };
        if byte == 0 {
            return String::from_utf8(buf).ok();
        }
        buf.push(byte);
    }
    None
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn absolute_under_bottle() {
        let root = Path::new("/opt/bottle");
        let host = translate_path_with_root(Some(root), "/usr/lib/libSystem.B.dylib")
            .expect("translate absolute");
        assert_eq!(host, PathBuf::from("/opt/bottle/usr/lib/libSystem.B.dylib"));
    }

    #[test]
    fn relative_stays_host_cwd_even_with_bottle() {
        let root = Path::new("/opt/bottle");
        let host = translate_path_with_root(Some(root), "tmp/x").expect("translate relative");
        assert_eq!(host, PathBuf::from("tmp/x"));
    }

    #[test]
    fn relative_rejects_dotdot() {
        let root = Path::new("/opt/bottle");
        let err = translate_path_with_root(Some(root), "../etc/passwd").expect_err("..");
        assert!(matches!(err, PathError::Escape(_)));
    }

    #[test]
    fn no_bottle_passthrough() {
        let host = translate_path_with_root(None, "/tmp/foo").expect("passthrough");
        assert_eq!(host, PathBuf::from("/tmp/foo"));
    }

    #[test]
    fn rejects_parent_dir() {
        let root = Path::new("/opt/bottle");
        let err =
            translate_path_with_root(Some(root), "/usr/../etc/passwd").expect_err("must reject ..");
        assert!(matches!(err, PathError::Escape(_)));
    }

    #[test]
    fn empty_rejected() {
        assert_eq!(translate_path_with_root(None, ""), Err(PathError::Empty));
    }

    #[test]
    fn volumes_linux_under_bottle() {
        let root = Path::new("/var/lib/my-renamed-bottle");
        let host = translate_path_with_root(Some(root), "/Volumes/linux/tmp/x")
            .expect("translate volumes");
        assert_eq!(
            host,
            PathBuf::from("/var/lib/my-renamed-bottle/Volumes/linux/tmp/x")
        );
    }

    #[test]
    fn fast_path_dots_in_name_ok() {
        let root = Path::new("/b");
        let host = translate_path_with_root(Some(root), "/foo..bar")
            .expect("dots in name");
        assert_eq!(host, PathBuf::from("/b/foo..bar"));
    }
}
