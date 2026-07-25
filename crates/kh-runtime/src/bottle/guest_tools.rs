//! Host-side discovery of real-world guest binaries used for integration probes.
//!
//! These helpers do **not** execute guests. They only locate Mach-O tools that
//! `kh run` / `kh trace` can load against a bottle (libSystem + libc++ alias).

use std::path::{Path, PathBuf};

/// Default host path for 7-Zip `7zz` (user-provided universal Mach-O).
pub const DEFAULT_7ZZ_PATH: &str = "/tmp/7zz";

/// Env override for the host path of `7zz`.
pub const ENV_7ZZ: &str = "KAKEHASHI_7ZZ";

/// Discovers a host-side `7zz` binary for run/trace probes.
///
/// Order:
/// 1. `explicit` argument (CLI path)
/// 2. [`ENV_7ZZ`] (`KAKEHASHI_7ZZ`)
/// 3. [`DEFAULT_7ZZ_PATH`] (`/tmp/7zz`)
/// 4. Workspace fixture `tests/fixtures/7zz` under `cwd` (optional CI copy)
#[must_use]
pub fn discover_7zz(explicit: Option<&Path>) -> Option<PathBuf> {
    if let Some(p) = explicit {
        if p.is_file() {
            return Some(p.to_path_buf());
        }
        return None;
    }

    if let Ok(raw) = std::env::var(ENV_7ZZ) {
        let p = PathBuf::from(raw);
        if p.is_file() {
            return Some(p);
        }
    }

    let default = Path::new(DEFAULT_7ZZ_PATH);
    if default.is_file() {
        return Some(default.to_path_buf());
    }

    for rel in [
        "tests/fixtures/7zz",
        "tests/fixtures/bin/7zz",
        "tests/clang-probe/7zz",
    ] {
        let p = PathBuf::from(rel);
        if p.is_file() {
            return Some(p);
        }
    }

    None
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::panic, unsafe_code)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    fn unique(prefix: &str) -> PathBuf {
        static N: AtomicU64 = AtomicU64::new(0);
        let n = N.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!("kh-7zz-{}-{}-{n}", prefix, std::process::id()))
    }

    #[test]
    fn discover_explicit_path() {
        let path = unique("bin");
        std::fs::write(&path, b"not-a-real-macho").expect("write");
        let found = discover_7zz(Some(&path)).expect("explicit");
        assert_eq!(found, path);
        drop(std::fs::remove_file(&path));
        assert!(discover_7zz(Some(&path)).is_none());
    }

    #[test]
    fn discover_env_override() {
        let path = unique("env");
        std::fs::write(&path, b"x").expect("write");
        // SAFETY: unit test; no concurrent env mutation of this key in crate tests.
        unsafe {
            std::env::set_var(ENV_7ZZ, &path);
        }
        let found = discover_7zz(None).expect("env");
        assert_eq!(found, path);
        unsafe {
            std::env::remove_var(ENV_7ZZ);
        }
        drop(std::fs::remove_file(&path));
    }
}
