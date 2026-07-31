//! Create / destroy / query the single Kakehashi bottle.
//!
//! Guest `libSystem.B.dylib` is installed from disk discovery first, then from
//! the freestanding dylib **embedded** in this crate (`resources/libSystem.B.dylib`).
//! That file is published on crates.io with `kh-runtime`, so
//! `cargo install kakehashi` → `kh bottle ensure` needs no separate dylib.

use std::path::{Path, PathBuf};

use thiserror::Error;

use super::layout;
use super::libsystem::{self, LibsystemInstall, LibsystemOrigin};
use super::registry;

/// Freestanding guest libSystem shipped with this crate (crates.io / cargo install).
///
/// Refresh after rebuilding `kh-libsystem` with `./scripts/stage-libsystem.sh`.
static EMBEDDED_LIBSYSTEM: &[u8] = include_bytes!("../../resources/libSystem.B.dylib");

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

    /// `--libsystem` / env pointed at a path that is not a readable file.
    #[error("libSystem source not found: {0}")]
    LibsystemNotFound(PathBuf),

    /// Underlying I/O failure.
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

/// Snapshot of the registered bottle.
#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(clippy::struct_excessive_bools)] // independent presence flags for CLI/status
pub struct BottleStatus {
    /// Absolute path from the registry (directory name is user-chosen).
    pub path: PathBuf,
    /// Whether the path exists on disk.
    pub exists: bool,
    /// Whether the path has a valid `.kakehashi-bottle` marker.
    pub valid_marker: bool,
    /// Whether `{path}/usr/lib/libSystem.B.dylib` is present.
    pub libsystem: bool,
    /// Whether `{path}/usr/lib/libc++.1.dylib` → `libSystem.B.dylib` alias exists.
    pub libcxx_alias: bool,
}

/// Options for [`create`].
#[derive(Debug, Clone, Default)]
pub struct CreateOptions<'a> {
    /// Bottle directory (default data path when `None`).
    pub path: Option<&'a Path>,
    /// Explicit guest dylib to install (`--libsystem`).
    pub libsystem: Option<&'a Path>,
    /// Skip searching/installing libSystem (skeleton only).
    pub skip_libsystem: bool,
}

/// Result of a successful [`create`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CreateResult {
    /// Absolute bottle root.
    pub path: PathBuf,
    /// libSystem install details when a source was found and copied.
    pub libsystem: Option<LibsystemInstall>,
}

/// Creates the single bottle at `path` (or the default data path when `None`).
///
/// Fails if a bottle is already registered and still present on disk. A stale
/// registry entry (path missing) is cleared automatically so create can proceed.
///
/// After the skeleton is written, installs guest `libSystem.B.dylib` when a
/// source is discovered (see [`libsystem::discover`]) or from the crate-embedded
/// freestanding dylib, unless [`CreateOptions::skip_libsystem`] is set.
/// An explicit `--libsystem` path that does not exist is an error.
pub fn create(path: Option<&Path>) -> Result<CreateResult, BottleError> {
    create_with(&CreateOptions {
        path,
        ..CreateOptions::default()
    })
}

/// Creates a bottle with full options (libSystem path / skip).
pub fn create_with(opts: &CreateOptions<'_>) -> Result<CreateResult, BottleError> {
    if let Some(active) = registry::read_active()? {
        if active.exists() {
            return Err(BottleError::AlreadyExists { path: active });
        }
        // Stale pointer — drop it and continue.
        registry::clear_active()?;
    }

    let target = match opts.path {
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

    let libsystem = match install_libsystem_for_create(&target, opts) {
        Ok(v) => v,
        Err(err) => {
            drop(layout::remove_tree(&target));
            return Err(err);
        }
    };

    if let Err(e) = super::ca_bundle::ensure_ca_bundle(&target) {
        tracing::warn!(error = %e, "failed to seed bottle CA bundle");
    }

    registry::write_active(&target)?;
    Ok(CreateResult {
        path: target,
        libsystem,
    })
}

fn install_libsystem_for_create(
    target: &Path,
    opts: &CreateOptions<'_>,
) -> Result<Option<LibsystemInstall>, BottleError> {
    if opts.skip_libsystem {
        return Ok(None);
    }
    if let Some(explicit) = opts.libsystem {
        if !explicit.is_file() {
            return Err(BottleError::LibsystemNotFound(explicit.to_path_buf()));
        }
        return Ok(Some(libsystem::install(
            target,
            explicit,
            LibsystemOrigin::Explicit,
        )?));
    }
    if let Some((src, origin)) = libsystem::discover(None) {
        return Ok(Some(libsystem::install(target, &src, origin)?));
    }

    // crates.io / cargo install: freestanding dylib is vendored in this crate.
    if !EMBEDDED_LIBSYSTEM.is_empty() {
        return Ok(Some(libsystem::install_bytes(
            target,
            EMBEDDED_LIBSYSTEM,
            LibsystemOrigin::Embedded,
        )?));
    }

    Ok(None)
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
    let libsystem = exists && path.join(libsystem::GUEST_LIBSYSTEM_REL).is_file();
    let libcxx_alias = exists && layout::has_libcxx_symlink(&path);
    Ok(Some(BottleStatus {
        path,
        exists,
        valid_marker,
        libsystem,
        libcxx_alias,
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

/// Idempotent bottle setup: create when missing, refresh libSystem when present.
///
/// ```text
/// # After cargo install kakehashi (uses embedded freestanding libSystem):
/// kh bottle ensure
///
/// # Dev: override with a just-built / staged dylib
/// kh bottle ensure --libsystem crates/kh-runtime/resources/libSystem.B.dylib
/// ```
///
/// * Valid registered bottle → reinstalls libSystem (unless `skip_libsystem`).
/// * Unregistered path that already has a bottle marker → adopt + refresh.
/// * Otherwise → same as [`create_with`].
/// * Explicit `--libsystem` that is missing is always an error.
pub fn ensure(opts: &CreateOptions<'_>) -> Result<CreateResult, BottleError> {
    if let Some(path) = active_root()? {
        return refresh_bottle(&path, opts);
    }

    // Adopt a marker'd bottle that is not in the registry (e.g. after wiping
    // KAKEHASHI_CONFIG_DIR but keeping the tree, or a previous manual path).
    if let Some(p) = opts.path {
        let abs = absolute(p)?;
        if layout::is_bottle_root(&abs) {
            return refresh_bottle(&abs, opts);
        }
    } else if let Ok(def) = registry::default_bottle_path()
        && layout::is_bottle_root(&def)
    {
        return refresh_bottle(&def, opts);
    }

    create_with(opts)
}

fn refresh_bottle(path: &Path, opts: &CreateOptions<'_>) -> Result<CreateResult, BottleError> {
    layout::ensure_libcxx_symlink(path)?;
    let libsystem = install_libsystem_for_create(path, opts)?;
    // Mozilla / host CA bundle for OpenSSL CAfile + SecTrust host verify.
    if let Err(e) = super::ca_bundle::ensure_ca_bundle(path) {
        tracing::warn!(error = %e, "failed to seed bottle CA bundle");
    }
    registry::write_active(path)?;
    Ok(CreateResult {
        path: path.to_path_buf(),
        libsystem,
    })
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

        let created = create_with(&CreateOptions {
            skip_libsystem: true,
            ..CreateOptions::default()
        })
        .expect("create");
        let path = created.path;
        assert!(layout::is_bottle_root(&path));
        assert_eq!(path, g.data.join("bottle"));
        assert!(path.join("Volumes/linux").is_symlink());
        assert!(created.libsystem.is_none());

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
        let created = create_with(&CreateOptions {
            path: Some(&custom),
            skip_libsystem: true,
            ..CreateOptions::default()
        })
        .expect("create custom");
        let path = created.path;
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
        let path2 = create_with(&CreateOptions {
            path: Some(&again),
            skip_libsystem: true,
            ..CreateOptions::default()
        })
        .expect("create after stale");
        assert!(layout::is_bottle_root(&path2.path));

        destroy(true).expect("destroy");
        drop(std::fs::remove_dir_all(&renamed));
    }

    #[test]
    fn destroy_requires_confirmation() {
        let _lock = test_env_lock();
        let _g = EnvGuard::new();

        let path = create_with(&CreateOptions {
            skip_libsystem: true,
            ..CreateOptions::default()
        })
        .expect("create")
        .path;
        let err = destroy(false).expect_err("need confirm");
        assert!(matches!(err, BottleError::NotConfirmed));
        assert!(path.exists());
        destroy(true).expect("destroy");
    }

    #[test]
    fn volumes_linux_rw_outside_bottle() {
        let _lock = test_env_lock();
        let _g = EnvGuard::new();

        let root = create_with(&CreateOptions {
            skip_libsystem: true,
            ..CreateOptions::default()
        })
        .expect("create")
        .path;
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

    #[test]
    fn create_installs_explicit_libsystem() {
        let _lock = test_env_lock();
        let _g = EnvGuard::new();

        // Synthetic bottle fixture (checked in) is a valid thin arm64 dylib.
        let repo = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
        let fixture = repo.join("tests/fixtures/bottle/usr/lib/libSystem.B.dylib");
        assert!(fixture.is_file(), "missing fixture {}", fixture.display());

        let created = create_with(&CreateOptions {
            libsystem: Some(&fixture),
            ..CreateOptions::default()
        })
        .expect("create with libsystem");
        assert!(created.libsystem.is_some());
        let dest = created.path.join(libsystem::GUEST_LIBSYSTEM_REL);
        assert!(dest.is_file());
        let st = status().expect("status").expect("registered");
        assert!(st.libsystem);
        assert!(st.libcxx_alias);
        assert!(layout::has_libcxx_symlink(&created.path));

        destroy(true).expect("destroy");
    }

    #[test]
    fn ensure_creates_then_refreshes_libsystem() {
        let _lock = test_env_lock();
        let _g = EnvGuard::new();

        let repo = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
        let fixture = repo.join("tests/fixtures/bottle/usr/lib/libSystem.B.dylib");
        assert!(fixture.is_file());

        let first = ensure(&CreateOptions {
            libsystem: Some(&fixture),
            ..CreateOptions::default()
        })
        .expect("ensure create");
        assert!(first.libsystem.is_some());
        let dest = first.path.join(libsystem::GUEST_LIBSYSTEM_REL);
        let before = std::fs::metadata(&dest).expect("meta").len();

        // Second ensure reuses the same bottle and reinstalls the dylib.
        let second = ensure(&CreateOptions {
            libsystem: Some(&fixture),
            ..CreateOptions::default()
        })
        .expect("ensure refresh");
        assert_eq!(second.path, first.path);
        assert!(second.libsystem.is_some());
        assert!(dest.is_file());
        let after = std::fs::metadata(&dest).expect("meta2").len();
        assert_eq!(before, after);

        destroy(true).expect("destroy");
    }
}
