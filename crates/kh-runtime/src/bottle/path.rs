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

    // Host bridge prefixes: do **not** walk through bottle symlinks. Apple git
    // realpath's `/Volumes/linux/tmp/…` via `readlink` → `/tmp/…`; that must still
    // hit the host FS, not bottle `private/tmp`.
    if let Some(host) = host_bridge_guest_to_host(guest)? {
        return Ok(host);
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

/// Map guest bridge paths to host absolute paths (no bottle join).
///
/// | Guest | Host |
/// | --- | --- |
/// | `/Volumes/linux` + rest | `/` + rest |
/// | `/tmp` + rest | `/tmp` + rest |
/// | `/private/tmp` + rest | `/tmp` + rest (Darwin layout) |
fn host_bridge_guest_to_host(guest: &str) -> Result<Option<PathBuf>, PathError> {
    const VOL: &str = "/Volumes/linux";
    if guest == VOL || guest.starts_with("/Volumes/linux/") {
        let rest = guest.strip_prefix(VOL).unwrap_or("");
        // Reject `..` in the host-relative rest.
        let host = if rest.is_empty() {
            PathBuf::from("/")
        } else {
            strip_root_components(Path::new(rest))?;
            PathBuf::from(rest)
        };
        return Ok(Some(host));
    }
    if guest == "/private/tmp" || guest.starts_with("/private/tmp/") {
        let rest = guest.strip_prefix("/private/tmp").unwrap_or("");
        let host = if rest.is_empty() {
            PathBuf::from("/tmp")
        } else {
            strip_root_components(Path::new(rest))?;
            PathBuf::from(format!("/tmp{rest}"))
        };
        return Ok(Some(host));
    }
    if guest == "/tmp" || guest.starts_with("/tmp/") {
        strip_root_components(Path::new(guest))?;
        return Ok(Some(PathBuf::from(guest)));
    }
    Ok(None)
}

/// Bottle-relative openat target for an absolute guest path (B1).
///
/// When `Some((dirfd, rel))`, callers should `openat`/`fstatat` with `rel`
/// (`"."` when the guest path is `/`) instead of allocating `{root}/{rel}`.
/// Host-bridge paths (`/Volumes/linux`, `/tmp`, `/private/tmp`) return `None`
/// so callers use [`translate_path`] instead.
#[must_use]
pub fn bottle_openat_rel(guest: &str) -> Option<(std::os::fd::RawFd, &str)> {
    if !guest.starts_with('/') {
        return None;
    }
    if host_bridge_guest_to_host(guest).ok().flatten().is_some() {
        return None;
    }
    let dirfd = process::bottle_dirfd()?;
    let rel = try_fast_relative(guest)?;
    Some((dirfd, if rel.is_empty() { "." } else { rel }))
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

/// Guest absolute path for the host process CWD.
///
/// * Host under bottle → bottle-relative absolute (`/usr/…`).
/// * Host under `/tmp` → Darwin-style `/private/tmp/…` (bridged to host `/tmp`).
/// * Else → `/Volumes/linux` + host absolute (bridged to host).
#[must_use]
pub fn guest_cwd_string() -> Option<String> {
    let host = std::env::current_dir().ok()?;
    host_path_to_guest(&host)
}

/// Maps an absolute host path to a guest absolute path (bottle or host bridge).
#[must_use]
pub fn host_path_to_guest(host: &Path) -> Option<String> {
    let host_abs = if host.is_absolute() {
        host.to_path_buf()
    } else {
        std::env::current_dir().ok()?.join(host)
    };
    // Prefer real paths so strip_prefix works across symlinks.
    let host_real = host_abs.canonicalize().unwrap_or(host_abs);

    if let Some(root) = bottle_root() {
        let root_real = root.canonicalize().unwrap_or(root);
        if let Ok(rel) = host_real.strip_prefix(&root_real) {
            if rel.as_os_str().is_empty() {
                return Some("/".to_owned());
            }
            let mut s = String::from("/");
            s.push_str(&rel.to_string_lossy());
            return Some(s.replace('\\', "/"));
        }
    }

    let lossy = host_real.to_string_lossy();
    // Prefer Darwin `/private/tmp` for host `/tmp` so realpath/readlink walks
    // stay on the host bridge (see [`host_bridge_guest_to_host`]).
    if lossy == "/tmp" {
        return Some("/private/tmp".to_owned());
    }
    if let Some(rest) = lossy.strip_prefix("/tmp/") {
        return Some(format!("/private/tmp/{rest}"));
    }
    if lossy == "/" {
        return Some(format!("/{}", super::layout::VOLUMES_LINUX));
    }
    Some(format!("/{}{lossy}", super::layout::VOLUMES_LINUX).replace('\\', "/"))
}

/// Stack buffer size for typical guest paths (avoids heap on open/stat).
const PATH_STACK: usize = 512;

/// Reads a NUL-terminated C string from an identity-mapped guest pointer.
///
/// Read a NUL-terminated guest C string as raw bytes (no UTF-8 requirement).
///
/// Darwin paths are byte sequences; rejecting non-UTF-8 as `EFAULT` broke modern
/// `ld`/`libtapi` (G5): `open` saw a short binary blob and failed before ENOENT.
#[must_use]
#[allow(unsafe_code)]
pub fn read_c_bytes(ptr: u64, max_len: usize) -> Option<Vec<u8>> {
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
            return stack.get(..i).map(<[u8]>::to_vec);
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
            return Some(buf);
        }
        buf.push(byte);
    }
    None
}

/// Used by `open` / `access` handlers. Caps length to avoid runaway scans.
///
/// Accepts any byte path (lossy UTF-8). Prefer [`read_c_bytes`] when the caller
/// must not invent replacement characters.
#[must_use]
#[allow(unsafe_code)]
pub fn read_c_string(ptr: u64, max_len: usize) -> Option<String> {
    let bytes = read_c_bytes(ptr, max_len)?;
    Some(String::from_utf8_lossy(&bytes).into_owned())
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
    fn volumes_linux_is_host_bridge_not_bottle_join() {
        let root = Path::new("/var/lib/my-renamed-bottle");
        let host = translate_path_with_root(Some(root), "/Volumes/linux/tmp/x")
            .expect("translate volumes");
        assert_eq!(host, PathBuf::from("/tmp/x"));
    }

    #[test]
    fn fast_path_dots_in_name_ok() {
        let root = Path::new("/b");
        let host = translate_path_with_root(Some(root), "/foo..bar").expect("dots in name");
        assert_eq!(host, PathBuf::from("/b/foo..bar"));
    }

    #[test]
    fn host_tmp_maps_to_private_tmp_guest() {
        set_bottle_root(None);
        let guest = host_path_to_guest(Path::new("/tmp/kh-guest-cwd-test")).expect("map");
        assert_eq!(guest, "/private/tmp/kh-guest-cwd-test");
    }

    #[test]
    fn bridge_private_tmp_to_host() {
        let host = translate_path_with_root(Some(Path::new("/opt/bottle")), "/private/tmp/x")
            .expect("bridge");
        assert_eq!(host, PathBuf::from("/tmp/x"));
    }

    #[test]
    fn bridge_volumes_linux_to_host() {
        let host = translate_path_with_root(Some(Path::new("/opt/bottle")), "/Volumes/linux/home/a")
            .expect("bridge");
        assert_eq!(host, PathBuf::from("/home/a"));
    }

    #[test]
    fn bottle_openat_rel_uses_dirfd_when_configured() {
        let tmp = std::env::temp_dir().join(format!(
            "kh-b1-openat-{}",
            std::process::id()
        ));
        drop(std::fs::remove_dir_all(&tmp));
        std::fs::create_dir_all(tmp.join("usr/lib")).expect("mkdir");
        set_bottle_root(Some(tmp.clone()));
        let (fd, rel) = bottle_openat_rel("/usr/lib/libSystem.B.dylib").expect("openat parts");
        assert!(fd >= 0);
        assert_eq!(rel, "usr/lib/libSystem.B.dylib");
        assert!(bottle_openat_rel("relative").is_none());
        set_bottle_root(None);
        assert!(bottle_openat_rel("/usr/lib/x").is_none());
        drop(std::fs::remove_dir_all(&tmp));
    }
}
