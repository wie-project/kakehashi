//! Install guest `/usr/bin/xcrun` into a bottle.
//!
//! Discovery / install order used by `kh bottle create|ensure` (same shape as
//! [`super::libsystem`]):
//!
//! 1. **`KAKEHASHI_XCRUN`** (host path of a Mach-O `xcrun`)
//! 2. Paths next to the running `kh` binary
//! 3. Workspace / dev trees: Cargo `target/…` and
//!    `crates/kh-runtime/resources/xcrun`
//! 4. **Embedded bytes** shipped inside `kh-runtime` (`resources/xcrun`)
//!
//! Build / refresh (macOS arm64 host or cross target):
//! ```text
//! cargo build -p kh-xcrun --release --target aarch64-apple-darwin
//! ./scripts/stage-xcrun.sh
//! ```

use std::fs;
use std::path::{Path, PathBuf};

use super::manage::BottleError;

/// Relative path under the bottle root (guest `/usr/bin/xcrun`).
pub const GUEST_XCRUN_REL: &str = "usr/bin/xcrun";

/// Env var for an explicit source binary.
pub const ENV_XCRUN: &str = "KAKEHASHI_XCRUN";

/// Synthetic source label when bytes came from the crate embed.
pub const EMBEDDED_SOURCE_LABEL: &str = "<embedded>";

/// How the source `xcrun` binary was located.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum XcrunOrigin {
    /// `KAKEHASHI_XCRUN` or explicit path.
    Explicit,
    /// Next to the `kh` binary.
    Adjacent,
    /// Workspace `target/` / crate `resources/` under cwd.
    DevTarget,
    /// Bytes compiled into `kh-runtime`.
    Embedded,
}

/// Result of installing xcrun into a bottle.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct XcrunInstall {
    /// Host path of the source binary, or [`EMBEDDED_SOURCE_LABEL`].
    pub source: PathBuf,
    /// Absolute path of `{bottle}/usr/bin/xcrun`.
    pub dest: PathBuf,
    /// Where `source` was found.
    pub origin: XcrunOrigin,
}

/// Discovers a guest `xcrun` **file** for bottle install (not the embed).
#[must_use]
pub fn discover(explicit: Option<&Path>) -> Option<(PathBuf, XcrunOrigin)> {
    if let Some(p) = explicit {
        if p.is_file() {
            return Some((p.to_path_buf(), XcrunOrigin::Explicit));
        }
        return None;
    }

    if let Ok(raw) = std::env::var(ENV_XCRUN) {
        let p = PathBuf::from(raw);
        if p.is_file() {
            return Some((p, XcrunOrigin::Explicit));
        }
    }

    if let Some(p) = discover_adjacent() {
        return Some((p, XcrunOrigin::Adjacent));
    }

    if let Some(p) = discover_dev_target() {
        return Some((p, XcrunOrigin::DevTarget));
    }

    None
}

/// Copies `source` into `{root}/usr/bin/xcrun`.
pub fn install(
    root: &Path,
    source: &Path,
    origin: XcrunOrigin,
) -> Result<XcrunInstall, BottleError> {
    if !source.is_file() {
        return Err(BottleError::Io(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            format!("xcrun source not found: {}", source.display()),
        )));
    }
    let bytes = fs::read(source)?;
    let mut result = install_bytes(root, &bytes, origin)?;
    result.source = source.to_path_buf();
    Ok(result)
}

/// Writes raw Mach-O bytes into `{root}/usr/bin/xcrun`.
pub fn install_bytes(
    root: &Path,
    source_bytes: &[u8],
    origin: XcrunOrigin,
) -> Result<XcrunInstall, BottleError> {
    if source_bytes.is_empty() {
        return Err(BottleError::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "xcrun source is empty",
        )));
    }
    if !looks_like_macho(source_bytes) {
        return Err(BottleError::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "xcrun source is not a Mach-O binary (build with --target aarch64-apple-darwin)",
        )));
    }

    let dest = root.join(GUEST_XCRUN_REL);
    if let Some(parent) = dest.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(&dest, source_bytes)?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        drop(fs::set_permissions(
            &dest,
            fs::Permissions::from_mode(0o755),
        ));
    }

    Ok(XcrunInstall {
        source: PathBuf::from(EMBEDDED_SOURCE_LABEL),
        dest,
        origin,
    })
}

fn discover_adjacent() -> Option<PathBuf> {
    let exe = std::env::current_exe().ok()?;
    let dir = exe.parent()?;
    let candidates = [
        dir.join("xcrun"),
        dir.join("lib/kakehashi/xcrun"),
        dir.join("../lib/kakehashi/xcrun"),
        dir.join("share/kakehashi/xcrun"),
        dir.join("../share/kakehashi/xcrun"),
    ];
    first_file(&candidates)
}

fn discover_dev_target() -> Option<PathBuf> {
    let cwd = std::env::current_dir().ok()?;
    let mut dir = Some(cwd.as_path());
    while let Some(base) = dir {
        if let Some(p) = discover_under_workspace(base) {
            return Some(p);
        }
        dir = base.parent();
    }
    None
}

fn discover_under_workspace(base: &Path) -> Option<PathBuf> {
    let candidates = [
        base.join("target/aarch64-apple-darwin/release/xcrun"),
        base.join("target/aarch64-apple-darwin/debug/xcrun"),
        base.join("target/release/xcrun"),
        base.join("target/debug/xcrun"),
        base.join("crates/kh-runtime/resources/xcrun"),
        base.join("resources/xcrun"),
    ];
    first_file(&candidates)
}

fn first_file(paths: &[PathBuf]) -> Option<PathBuf> {
    paths.iter().find(|p| p.is_file()).cloned()
}

/// Thin / fat Mach-O magics (LE and BE). Rejects ELF host builds on Linux CI.
fn looks_like_macho(bytes: &[u8]) -> bool {
    let Some(header) = bytes.get(..4) else {
        return false;
    };
    // MH_MAGIC_64 LE / BE, FAT_MAGIC / FAT_MAGIC_64 / CIGAM variants
    matches!(
        header,
        [0xcf, 0xfa, 0xed, 0xfe]
            | [0xfe, 0xed, 0xfa, 0xcf]
            | [0xca, 0xfe, 0xba, 0xbe | 0xbf]
            | [0xbe | 0xbf, 0xba, 0xfe, 0xca]
    )
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn tmp_root(label: &str) -> PathBuf {
        let n = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time")
            .as_nanos();
        std::env::temp_dir().join(format!("kh-xcrun-{label}-{n}"))
    }

    #[test]
    fn install_bytes_writes_executable_path() {
        let root = tmp_root("install");
        fs::create_dir_all(&root).expect("mkdir");
        let payload = b"\xcf\xfa\xed\xfekh-xcrun-test-bytes";
        let report = install_bytes(&root, payload, XcrunOrigin::Embedded).expect("install");
        assert_eq!(report.dest, root.join(GUEST_XCRUN_REL));
        assert_eq!(fs::read(&report.dest).expect("read"), payload);
        drop(fs::remove_dir_all(&root));
    }

    #[test]
    fn rejects_elf_payload() {
        let root = tmp_root("elf");
        fs::create_dir_all(&root).expect("mkdir");
        let elf = b"\x7fELF\x02\x01\x01";
        let err = install_bytes(&root, elf, XcrunOrigin::Embedded).expect_err("elf");
        assert!(format!("{err}").contains("Mach-O"));
        drop(fs::remove_dir_all(&root));
    }
}
