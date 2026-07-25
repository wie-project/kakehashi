//! Create / destroy / query the single Kakehashi bottle.

use std::path::{Path, PathBuf};

use thiserror::Error;

use super::layout;
use super::registry;

/// Bottle management errors.
#[derive(Debug, Error)]
pub enum BottleError {
    /// A bottle is already registered (create refused).
    #[error(
        "a bottle already exists at {path}\n\
         create a new one only after deleting the current bottle:\n\
           kh bottle destroy"
    )]
    AlreadyExists {
        /// Absolute path of the existing bottle.
        path: PathBuf,
    },

    /// Destroy requested but no bottle is registered.
    #[error("no bottle is registered (nothing to destroy)")]
    NotRegistered,

    /// Registry points at a path that is not a valid bottle.
    #[error("path is not a kakehashi bottle (missing marker): {0}")]
    NotABottle(PathBuf),

    /// Destroy refused because confirmation was not given.
    #[error("destroy cancelled (confirmation required)")]
    NotConfirmed,

    /// Underlying I/O failure.
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

/// Snapshot of the registered bottle.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BottleStatus {
    /// Absolute path from the registry (directory name is user-chosen).
    pub path: PathBuf,
    /// Whether the path exists on disk.
    pub exists: bool,
    /// Whether the path has a valid `.kakehashi-bottle` marker.
    pub valid_marker: bool,
}

/// Creates the single bottle at `path` (or the default data path when `None`).
///
/// Fails if a bottle is already registered and still present on disk. A stale
/// registry entry (path missing) is cleared automatically so create can proceed.
pub fn create(path: Option<&Path>) -> Result<PathBuf, BottleError> {
    if let Some(active) = registry::read_active()? {
        if active.exists() {
            return Err(BottleError::AlreadyExists { path: active });
        }
        // Stale pointer — drop it and continue.
        registry::clear_active()?;
    }

    let target = match path {
        Some(p) => absolute(p)?,
        None => registry::default_bottle_path()?,
    };

    if layout::is_bottle_root(&target) {
        // Directory looks like a bottle but was not registered — refuse to
        // clobber; register it only after explicit destroy of its tree, or
        // treat as already-exists at that path.
        return Err(BottleError::AlreadyExists { path: target });
    }

    if target.exists() && target.read_dir()?.next().is_some() {
        // Non-empty non-bottle directory: do not silently overwrite.
        return Err(BottleError::Io(std::io::Error::new(
            std::io::ErrorKind::AlreadyExists,
            format!(
                "refusing to create bottle in non-empty directory: {}",
                target.display()
            ),
        )));
    }

    layout::materialize(&target)?;
    registry::write_active(&target)?;
    Ok(target)
}

/// Destroys the registered bottle after `confirmed` is true.
///
/// When `confirmed` is false, returns [`BottleError::NotConfirmed`] without
/// touching the filesystem (CLI prompts, then retries with `true`).
pub fn destroy(confirmed: bool) -> Result<PathBuf, BottleError> {
    let Some(path) = registry::read_active()? else {
        return Err(BottleError::NotRegistered);
    };

    if !confirmed {
        return Err(BottleError::NotConfirmed);
    }

    if path.exists() {
        if layout::is_bottle_root(&path) {
            layout::remove_tree(&path)?;
        } else if path.is_dir() {
            // Registry path exists but marker missing — refuse blind rm -rf.
            return Err(BottleError::NotABottle(path));
        }
        // If path is a leftover file or already gone after check, still clear.
    }

    registry::clear_active()?;
    Ok(path)
}

/// Returns status of the registered bottle, if any.
pub fn status() -> Result<Option<BottleStatus>, BottleError> {
    let Some(path) = registry::read_active()? else {
        return Ok(None);
    };
    let exists = path.exists();
    let valid_marker = exists && layout::is_bottle_root(&path);
    Ok(Some(BottleStatus {
        path,
        exists,
        valid_marker,
    }))
}

/// Returns the active bottle path when registered and valid on disk.
///
/// Used by CLI root resolution as a fallback after `--root` / `KAKEHASHI_ROOT`.
pub fn active_root() -> Result<Option<PathBuf>, BottleError> {
    match status()? {
        Some(s) if s.exists && s.valid_marker => Ok(Some(s.path)),
        _ => Ok(None),
    }
}

fn absolute(path: &Path) -> Result<PathBuf, BottleError> {
    if path.is_absolute() {
        return Ok(path.to_path_buf());
    }
    let cwd = std::env::current_dir()?;
    Ok(cwd.join(path))
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::panic, unsafe_code)]
mod tests {
    use super::*;
    use crate::bottle::registry::test_env_lock;
    use std::sync::atomic::{AtomicU64, Ordering};

    fn unique(prefix: &str) -> PathBuf {
        static N: AtomicU64 = AtomicU64::new(0);
        let n = N.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!("kh-manage-{}-{}-{n}", prefix, std::process::id()))
    }

    struct EnvGuard {
        cfg: PathBuf,
        data: PathBuf,
    }

    impl EnvGuard {
        fn new() -> Self {
            let cfg = unique("cfg");
            let data = unique("data");
            drop(std::fs::remove_dir_all(&cfg));
            drop(std::fs::remove_dir_all(&data));
            std::fs::create_dir_all(&cfg).expect("cfg");
            std::fs::create_dir_all(&data).expect("data");
            // SAFETY: serialized by test_env_lock; EnvGuard restores on drop.
            unsafe {
                std::env::set_var("KAKEHASHI_CONFIG_DIR", &cfg);
                std::env::set_var("KAKEHASHI_DATA_DIR", &data);
            }
            Self { cfg, data }
        }
    }

    impl Drop for EnvGuard {
        fn drop(&mut self) {
            // SAFETY: paired with set_var in new(); still under test_env_lock.
            unsafe {
                std::env::remove_var("KAKEHASHI_CONFIG_DIR");
                std::env::remove_var("KAKEHASHI_DATA_DIR");
            }
            drop(std::fs::remove_dir_all(&self.cfg));
            drop(std::fs::remove_dir_all(&self.data));
        }
    }

    #[test]
    fn create_default_then_second_fails() {
        let _lock = test_env_lock();
        let g = EnvGuard::new();

        let path = create(None).expect("create");
        assert!(layout::is_bottle_root(&path));
        assert_eq!(path, g.data.join("bottle"));
        assert!(path.join("Volumes/linux").is_symlink());

        let err = create(None).expect_err("second create");
        assert!(matches!(err, BottleError::AlreadyExists { .. }));

        let destroyed = destroy(true).expect("destroy");
        assert_eq!(destroyed, path);
        assert!(!path.exists());
        assert!(status().expect("status").is_none());
    }

    #[test]
    fn create_custom_path_and_rename_survives_registry_update() {
        let _lock = test_env_lock();
        let _g = EnvGuard::new();

        let custom = unique("custom-bottle-name");
        let path = create(Some(&custom)).expect("create custom");
        assert_eq!(path, custom);
        assert!(layout::is_bottle_root(&path));

        // User renames the bottle directory — registry still points at old path.
        let renamed = unique("renamed-by-user");
        std::fs::rename(&path, &renamed).expect("rename");
        // Stale: exists=false after rename of registered path.
        let st = status().expect("status").expect("some");
        assert!(!st.exists);

        // Create should clear stale and succeed at a new path.
        let again = unique("after-rename");
        let path2 = create(Some(&again)).expect("create after stale");
        assert!(layout::is_bottle_root(&path2));

        destroy(true).expect("destroy");
        drop(std::fs::remove_dir_all(&renamed));
    }

    #[test]
    fn destroy_requires_confirmation() {
        let _lock = test_env_lock();
        let _g = EnvGuard::new();

        let path = create(None).expect("create");
        let err = destroy(false).expect_err("need confirm");
        assert!(matches!(err, BottleError::NotConfirmed));
        assert!(path.exists());
        destroy(true).expect("destroy");
    }

    #[test]
    fn volumes_linux_rw_outside_bottle() {
        let _lock = test_env_lock();
        let _g = EnvGuard::new();

        let root = create(None).expect("create");
        let token = format!("kh-manage-vol-{}", std::process::id());
        let host_file = std::env::temp_dir().join(&token);
        let payload = b"rw-outside\n";
        std::fs::write(&host_file, payload).expect("host write");

        let via = root
            .join(layout::VOLUMES_LINUX)
            .join(host_file.strip_prefix("/").expect("abs"));
        assert_eq!(std::fs::read(&via).expect("via read"), payload);

        let payload2 = b"from-bottle-side\n";
        std::fs::write(&via, payload2).expect("via write");
        assert_eq!(std::fs::read(&host_file).expect("host read"), payload2);

        drop(std::fs::remove_file(&host_file));
        destroy(true).expect("destroy");
    }
}
