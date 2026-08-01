//! Persistent download cache for `kh install`.
//!
//! Docker/Colima helpers set `KAKEHASHI_DATA_DIR` under the bind-mounted repo
//! (`.kh/data`). Caching archives and installed trees there means a second
//! `docker run` does **not** re-download multi‑MB / multi‑GB tools.
//!
//! Layout:
//! ```text
//! $KAKEHASHI_CACHE_DIR/   or  $KAKEHASHI_DATA_DIR/cache/
//!   downloads/<name>      raw archives
//!   extract/<name>/       durable extract roots (CLT, …)
//! ```
//!
//! Force re-fetch: `KAKEHASHI_FORCE_DOWNLOAD=1`.

use std::env;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::process::Command;

use super::registry;

/// Env: override cache root.
pub const ENV_CACHE_DIR: &str = "KAKEHASHI_CACHE_DIR";

/// Env: truthy → re-download even when the cache file exists.
pub const ENV_FORCE_DOWNLOAD: &str = "KAKEHASHI_FORCE_DOWNLOAD";

/// Subdir for raw downloaded files.
pub(crate) const DOWNLOADS_SUBDIR: &str = "downloads";

/// Subdir for durable extracted trees.
pub(crate) const EXTRACT_SUBDIR: &str = "extract";

/// Resolve the cache root.
///
/// Order: `KAKEHASHI_CACHE_DIR` → `$KAKEHASHI_DATA_DIR/cache`.
pub(crate) fn cache_dir() -> io::Result<PathBuf> {
    if let Some(p) = env::var_os(ENV_CACHE_DIR) {
        return Ok(PathBuf::from(p));
    }
    Ok(registry::data_dir()?.join("cache"))
}

/// Path under `downloads/` for a named object.
pub(crate) fn download_path(name: &str) -> io::Result<PathBuf> {
    Ok(cache_dir()?.join(DOWNLOADS_SUBDIR).join(name))
}

/// Path under `extract/` for a named tree.
pub(crate) fn extract_path(name: &str) -> io::Result<PathBuf> {
    Ok(cache_dir()?.join(EXTRACT_SUBDIR).join(name))
}

/// Whether `KAKEHASHI_FORCE_DOWNLOAD` is set truthy.
#[must_use]
pub(crate) fn force_download() -> bool {
    match env::var_os(ENV_FORCE_DOWNLOAD) {
        None => false,
        Some(v) => {
            let s = v.to_string_lossy();
            matches!(
                s.as_ref(),
                "1" | "true" | "TRUE" | "yes" | "YES" | "on" | "ON"
            )
        }
    }
}

/// True if `path` is a non-empty regular file.
#[must_use]
pub(crate) fn is_nonempty_file(path: &Path) -> bool {
    path.is_file() && path.metadata().is_ok_and(|m| m.len() > 0)
}

/// Download `url` to `dest` unless cache hit (and force is off).
pub(crate) fn ensure_url(url: &str, dest: &Path) -> Result<(), CacheError> {
    if !force_download() && is_nonempty_file(dest) {
        return Ok(());
    }
    if let Some(parent) = dest.parent() {
        fs::create_dir_all(parent)?;
    }
    let tmp = dest.with_extension("part");
    if tmp.exists() {
        drop(fs::remove_file(&tmp));
    }
    download_url(url, &tmp)?;
    // Reject tiny HTML error pages.
    let len = tmp.metadata()?.len();
    if len < 4096 {
        let head = fs::read(&tmp).unwrap_or_default();
        let looks_html = head.windows(5).any(|w| {
            w.eq_ignore_ascii_case(b"<html") || w.eq_ignore_ascii_case(b"<!doc")
        });
        if looks_html {
            drop(fs::remove_file(&tmp));
            return Err(CacheError::Command(format!(
                "download looks like an HTML error page ({len} bytes); url={url}"
            )));
        }
    }
    atomic_replace(&tmp, dest)?;
    Ok(())
}

/// Ensure a named download under `downloads/`. Returns the host path.
pub(crate) fn ensure_named_url(url: &str, name: &str) -> Result<PathBuf, CacheError> {
    let dest = download_path(name)?;
    ensure_url(url, &dest)?;
    Ok(dest)
}

/// Download with host `curl` (wget fallback).
pub(crate) fn download_url(url: &str, dest: &Path) -> Result<(), CacheError> {
    if let Some(parent) = dest.parent() {
        fs::create_dir_all(parent)?;
    }

    let status = Command::new("curl")
        .args([
            "-fL",
            "--retry",
            "3",
            "--continue-at",
            "-",
            "-o",
        ])
        .arg(dest)
        .arg(url)
        .status()
        .map_err(|e| {
            CacheError::Command(format!(
                "download failed: need host curl ({e}); url={url}"
            ))
        })?;
    if status.success() {
        return Ok(());
    }

    let wget = Command::new("wget")
        .args(["-q", "-O"])
        .arg(dest)
        .arg(url)
        .status()
        .map_err(|e| {
            CacheError::Command(format!(
                "download failed: need curl or wget ({e}); url={url}"
            ))
        })?;
    if wget.success() {
        return Ok(());
    }

    Err(CacheError::Command(format!(
        "download failed (curl exit {status}); url={url}"
    )))
}

fn atomic_replace(tmp: &Path, dest: &Path) -> Result<(), CacheError> {
    if dest.exists() {
        drop(fs::remove_file(dest));
    }
    match fs::rename(tmp, dest) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == io::ErrorKind::CrossesDevices => {
            fs::copy(tmp, dest)?;
            drop(fs::remove_file(tmp));
            Ok(())
        }
        Err(e) => Err(CacheError::Io(e)),
    }
}

/// Errors from the download cache.
#[derive(Debug, thiserror::Error)]
pub(crate) enum CacheError {
    /// Filesystem I/O.
    #[error("cache I/O: {0}")]
    Io(#[from] io::Error),
    /// Host download helper failed.
    #[error("{0}")]
    Command(String),
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::panic, unsafe_code)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    fn unique(prefix: &str) -> PathBuf {
        static N: AtomicU64 = AtomicU64::new(0);
        let n = N.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!(
            "kh-cache-{}-{}-{n}",
            prefix,
            std::process::id()
        ))
    }

    #[test]
    fn force_download_parses() {
        // SAFETY: test-only env mutation for this key.
        unsafe {
            std::env::remove_var(ENV_FORCE_DOWNLOAD);
        }
        assert!(!force_download());
        unsafe {
            std::env::set_var(ENV_FORCE_DOWNLOAD, "1");
        }
        assert!(force_download());
        unsafe {
            std::env::remove_var(ENV_FORCE_DOWNLOAD);
        }
    }

    #[test]
    fn ensure_url_keeps_existing_file() {
        let dir = unique("keep");
        fs::create_dir_all(&dir).expect("dir");
        let dest = dir.join("blob.bin");
        fs::write(&dest, b"cached-bytes").expect("write");
        ensure_url("https://example.invalid/never", &dest).expect("cache hit");
        assert_eq!(fs::read(&dest).expect("read"), b"cached-bytes");
        drop(fs::remove_dir_all(&dir));
    }
}
