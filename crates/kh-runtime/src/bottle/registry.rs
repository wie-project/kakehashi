//! Single active bottle pointer.
//!
//! Exactly one bottle may be registered at a time. The bottle directory name is
//! not fixed — only the absolute path stored in the registry matters. Override
//! locations with `KAKEHASHI_CONFIG_DIR` / `KAKEHASHI_DATA_DIR` for tests.

use std::env;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

/// File under the config directory that stores the absolute bottle path.
pub(super) const ACTIVE_FILE: &str = "active_bottle";

/// Default bottle directory name under the data directory (when path omitted).
///
/// Users may rename the directory after creation; the registry tracks the
/// absolute path, not this name.
const DEFAULT_BOTTLE_DIRNAME: &str = "bottle";

/// Resolves the config directory (registry lives here).
///
/// Order: `KAKEHASHI_CONFIG_DIR` → `$XDG_CONFIG_HOME/kakehashi` →
/// `$HOME/.config/kakehashi`.
pub fn config_dir() -> io::Result<PathBuf> {
    if let Some(p) = env::var_os("KAKEHASHI_CONFIG_DIR") {
        return Ok(PathBuf::from(p));
    }
    if let Some(xdg) = env::var_os("XDG_CONFIG_HOME") {
        return Ok(PathBuf::from(xdg).join("kakehashi"));
    }
    let home = env::var_os("HOME").ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::NotFound,
            "HOME is unset and KAKEHASHI_CONFIG_DIR is not set",
        )
    })?;
    Ok(PathBuf::from(home).join(".config").join("kakehashi"))
}

/// Resolves the default data directory for a new bottle (parent of `bottle/`).
///
/// Order: `KAKEHASHI_DATA_DIR` → `$XDG_DATA_HOME/kakehashi` →
/// `$HOME/.local/share/kakehashi`.
pub fn data_dir() -> io::Result<PathBuf> {
    if let Some(p) = env::var_os("KAKEHASHI_DATA_DIR") {
        return Ok(PathBuf::from(p));
    }
    if let Some(xdg) = env::var_os("XDG_DATA_HOME") {
        return Ok(PathBuf::from(xdg).join("kakehashi"));
    }
    let home = env::var_os("HOME").ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::NotFound,
            "HOME is unset and KAKEHASHI_DATA_DIR is not set",
        )
    })?;
    Ok(PathBuf::from(home)
        .join(".local")
        .join("share")
        .join("kakehashi"))
}

/// Default absolute path used when `kh bottle create` is given no path.
pub fn default_bottle_path() -> io::Result<PathBuf> {
    Ok(data_dir()?.join(DEFAULT_BOTTLE_DIRNAME))
}

/// Path of the registry file that points at the active bottle.
pub fn active_file_path() -> io::Result<PathBuf> {
    Ok(config_dir()?.join(ACTIVE_FILE))
}

/// Reads the registered active bottle path, if any.
///
/// Returns `Ok(None)` when no registry file exists. Does not verify the bottle
/// still exists or still has a valid marker.
pub fn read_active() -> io::Result<Option<PathBuf>> {
    let file = active_file_path()?;
    match fs::read_to_string(&file) {
        Ok(s) => {
            let trimmed = s.trim();
            if trimmed.is_empty() {
                Ok(None)
            } else {
                Ok(Some(PathBuf::from(trimmed)))
            }
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e),
    }
}

/// Writes `path` as the single active bottle (creates config dir as needed).
///
/// `path` is canonicalized when it exists so renames of parent dirs that keep
/// the same resolved location stay stable; otherwise the absolute form is stored.
pub fn write_active(path: &Path) -> io::Result<()> {
    let cfg = config_dir()?;
    fs::create_dir_all(&cfg)?;
    let abs = absolute_path(path)?;
    let file = cfg.join(ACTIVE_FILE);
    // Atomic-ish replace: write temp then rename.
    let tmp = cfg.join(format!(".{ACTIVE_FILE}.tmp"));
    fs::write(&tmp, format!("{}\n", abs.display()))?;
    fs::rename(&tmp, &file)?;
    Ok(())
}

/// Clears the active bottle registry entry (no-op if already empty).
pub fn clear_active() -> io::Result<()> {
    let file = active_file_path()?;
    match fs::remove_file(&file) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e),
    }
}

/// Makes `path` absolute without requiring it to exist.
fn absolute_path(path: &Path) -> io::Result<PathBuf> {
    if path.is_absolute() {
        return Ok(path.to_path_buf());
    }
    let cwd = env::current_dir()?;
    Ok(cwd.join(path))
}

/// Serializes tests that mutate `KAKEHASHI_*` process environment variables.
#[cfg(test)]
pub(super) fn test_env_lock() -> std::sync::MutexGuard<'static, ()> {
    use std::sync::{Mutex, OnceLock};
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

#[cfg(test)]
#[allow(clippy::expect_used, unsafe_code)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    fn unique(prefix: &str) -> PathBuf {
        static N: AtomicU64 = AtomicU64::new(0);
        let n = N.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!("kh-reg-{}-{}-{n}", prefix, std::process::id()))
    }

    #[test]
    fn write_read_clear_active() {
        let _g = test_env_lock();
        let cfg = unique("cfg");
        let data = unique("data");
        drop(fs::remove_dir_all(&cfg));
        drop(fs::remove_dir_all(&data));
        // SAFETY: serialized by env_lock; only these tests touch the vars.
        unsafe {
            env::set_var("KAKEHASHI_CONFIG_DIR", &cfg);
            env::set_var("KAKEHASHI_DATA_DIR", &data);
        }

        assert!(read_active().expect("read empty").is_none());
        let bottle = data.join("my-custom-name");
        write_active(&bottle).expect("write");
        let got = read_active().expect("read").expect("some");
        assert_eq!(got, bottle);
        clear_active().expect("clear");
        assert!(read_active().expect("read after clear").is_none());

        // SAFETY: paired with set_var above under the same lock.
        unsafe {
            env::remove_var("KAKEHASHI_CONFIG_DIR");
            env::remove_var("KAKEHASHI_DATA_DIR");
        }
        drop(fs::remove_dir_all(&cfg));
        drop(fs::remove_dir_all(&data));
    }

    #[test]
    fn default_path_uses_data_dir() {
        let _g = test_env_lock();
        let data = unique("defdata");
        // SAFETY: serialized by env_lock.
        unsafe {
            env::set_var("KAKEHASHI_DATA_DIR", &data);
        }
        let p = default_bottle_path().expect("default");
        assert_eq!(p, data.join(DEFAULT_BOTTLE_DIRNAME));
        // SAFETY: paired cleanup under env_lock.
        unsafe {
            env::remove_var("KAKEHASHI_DATA_DIR");
        }
    }
}
