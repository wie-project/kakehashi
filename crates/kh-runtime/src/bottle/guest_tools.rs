//! Optional guest tools installed **into the bottle** at real macOS paths.
//!
//! Example: Darwin `7zz` → `{bottle}/usr/local/bin/7zz`, which is guest path
//! `/usr/local/bin/7zz` — the same place a real Mac would keep a CLI install.
//! Kakehashi is not a 7-Zip product; packages are opt-in via `kh install`.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::process::Command;

use super::layout::is_bottle_root;
use super::manage;
use super::registry;

/// Env override: host path of a Darwin `7zz` binary (skip download).
pub const ENV_7ZZ: &str = "KAKEHASHI_7ZZ";

/// Env override: host path of a Darwin `curl` binary (skip download).
pub const ENV_CURL: &str = "KAKEHASHI_CURL";

/// Legacy ad-hoc drop location (still checked by discovery helpers).
pub const DEFAULT_7ZZ_PATH: &str = "/tmp/7zz";

/// Official macOS console 7-Zip (universal arm64 / x86_64 Mach-O).
pub const DARWIN_7ZZ_URL: &str =
    "https://github.com/ip7z/7zip/releases/download/26.02/7z2602-mac.tar.xz";

/// Public Darwin arm64 static-ish curl (stunnel/static-curl release).
///
/// Archive root contains a single `curl` Mach-O. Prefer this over Apple
/// `/usr/bin/curl` (which needs `libcurl.4.dylib`). Still may link Apple
/// frameworks for TLS — probe will surface that; see `docs/curl.md`.
pub const DARWIN_CURL_URL: &str = "https://github.com/stunnel/static-curl/releases/download/8.21.0/curl-macos-arm64-8.21.0.tar.xz";

/// Guest-relative install path for Darwin 7zz (under bottle root).
///
/// On a real Mac this is `/usr/local/bin/7zz`.
pub const GUEST_7ZZ_REL: &str = "usr/local/bin/7zz";

/// Guest-relative install path for Darwin curl (under bottle root).
///
/// On a real Mac this is `/usr/local/bin/curl`.
pub const GUEST_CURL_REL: &str = "usr/local/bin/curl";

/// Known installable package ids (`kh install <name>`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InstallPackage {
    /// Darwin 7-Zip console (`7zz`).
    SevenZip,
    /// Darwin `curl` (downloaded arm64 Mach-O; see `docs/curl.md`).
    Curl,
}

impl InstallPackage {
    /// Parse CLI package name (case-insensitive).
    #[must_use]
    pub fn parse(name: &str) -> Option<Self> {
        match name.to_ascii_lowercase().as_str() {
            "7zip" | "7zz" | "sevenzip" | "p7zip" => Some(Self::SevenZip),
            "curl" => Some(Self::Curl),
            _ => None,
        }
    }

    /// Canonical name for messages.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::SevenZip => "7zip",
            Self::Curl => "curl",
        }
    }

    /// Guest absolute path after install (with leading `/`).
    #[must_use]
    pub const fn guest_path(self) -> &'static str {
        match self {
            Self::SevenZip => "/usr/local/bin/7zz",
            Self::Curl => "/usr/local/bin/curl",
        }
    }
}

/// Errors from package install / download.
#[derive(Debug, thiserror::Error)]
pub enum ToolError {
    /// Bottle lifecycle / registry.
    #[error("{0}")]
    Bottle(String),
    /// I/O while creating dirs or writing the binary.
    #[error("tool I/O: {0}")]
    Io(#[from] io::Error),
    /// `curl` / `tar` missing or failed.
    #[error("{0}")]
    Command(String),
    /// Downloaded archive did not contain the expected binary.
    #[error("expected binary not found in downloaded archive")]
    MissingBinary,
    /// Unknown package name.
    #[error("unknown package `{0}` (known: 7zip, curl)")]
    UnknownPackage(String),
}

/// Host path of an installed package inside a bottle, if present.
#[must_use]
pub fn package_host_path(bottle: &Path, package: InstallPackage) -> PathBuf {
    match package {
        InstallPackage::SevenZip => bottle.join(GUEST_7ZZ_REL),
        InstallPackage::Curl => bottle.join(GUEST_CURL_REL),
    }
}

/// Discover Darwin `7zz` for convenience helpers (not required for `kh run`).
///
/// Order: explicit → `KAKEHASHI_7ZZ` → active bottle `/usr/local/bin/7zz` →
/// legacy `/tmp/7zz` → dev-tree fallbacks.
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

    if let Ok(Some(root)) = manage::active_root() {
        let p = package_host_path(&root, InstallPackage::SevenZip);
        if p.is_file() {
            return Some(p);
        }
    }

    let default = Path::new(DEFAULT_7ZZ_PATH);
    if default.is_file() {
        return Some(default.to_path_buf());
    }

    for rel in [
        "tests/clang-probe/7zz.bin",
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

/// Install a named package into the active bottle (creating the bottle if needed).
pub fn install_package(name: &str) -> Result<InstallReport, ToolError> {
    let package =
        InstallPackage::parse(name).ok_or_else(|| ToolError::UnknownPackage(name.to_owned()))?;
    match package {
        InstallPackage::SevenZip => install_sevenzip(),
        InstallPackage::Curl => install_curl(),
    }
}

/// Result of a successful [`install_package`].
#[derive(Debug, Clone)]
pub struct InstallReport {
    /// Package id.
    pub package: &'static str,
    /// Absolute host path of the installed binary.
    pub host_path: PathBuf,
    /// Guest absolute path (macOS layout).
    pub guest_path: &'static str,
    /// Bottle root used.
    pub bottle: PathBuf,
}

fn ensure_active_bottle() -> Result<PathBuf, ToolError> {
    if let Ok(Some(root)) = manage::active_root()
        && is_bottle_root(&root)
    {
        return Ok(root);
    }
    let created = manage::ensure(&manage::CreateOptions {
        path: None,
        libsystem: None,
        skip_libsystem: false,
    })
    .map_err(|e| ToolError::Bottle(e.to_string()))?;
    Ok(created.path)
}

fn install_sevenzip() -> Result<InstallReport, ToolError> {
    let bottle = ensure_active_bottle()?;
    let dest = package_host_path(&bottle, InstallPackage::SevenZip);
    if let Some(parent) = dest.parent() {
        fs::create_dir_all(parent)?;
    }

    // Prefer env override (already a binary) over download.
    if let Ok(raw) = std::env::var(ENV_7ZZ) {
        let src = PathBuf::from(raw);
        if src.is_file() {
            fs::copy(&src, &dest)?;
            set_executable(&dest)?;
            return Ok(InstallReport {
                package: InstallPackage::SevenZip.as_str(),
                host_path: dest,
                guest_path: InstallPackage::SevenZip.guest_path(),
                bottle,
            });
        }
    }

    let tmp_root = registry::data_dir()?.join(".kh-dl");
    drop(fs::remove_dir_all(&tmp_root));
    fs::create_dir_all(&tmp_root)?;
    let archive = tmp_root.join("7z-mac.tar.xz");
    download_url(DARWIN_7ZZ_URL, &archive)?;

    let status = Command::new("tar")
        .args(["-xJf"])
        .arg(&archive)
        .current_dir(&tmp_root)
        .status()
        .map_err(|e| ToolError::Command(format!("tar: {e}")))?;
    if !status.success() {
        drop(fs::remove_dir_all(&tmp_root));
        return Err(ToolError::Command(format!(
            "tar extract failed (status {status})"
        )));
    }

    let found = find_named_file(&tmp_root, "7zz").ok_or(ToolError::MissingBinary)?;
    if dest.exists() {
        drop(fs::remove_file(&dest));
    }
    fs::copy(&found, &dest)?;
    set_executable(&dest)?;
    drop(fs::remove_dir_all(&tmp_root));

    Ok(InstallReport {
        package: InstallPackage::SevenZip.as_str(),
        host_path: dest,
        guest_path: InstallPackage::SevenZip.guest_path(),
        bottle,
    })
}

/// Install Darwin `curl` into the bottle at `/usr/local/bin/curl`.
///
/// Order: `KAKEHASHI_CURL` (already a binary) → download [`DARWIN_CURL_URL`]
/// and extract the `curl` Mach-O from the tarball.
fn install_curl() -> Result<InstallReport, ToolError> {
    let bottle = ensure_active_bottle()?;
    let dest = package_host_path(&bottle, InstallPackage::Curl);
    if let Some(parent) = dest.parent() {
        fs::create_dir_all(parent)?;
    }

    // Prefer env override (already a binary) over download.
    if let Ok(raw) = std::env::var(ENV_CURL) {
        let src = PathBuf::from(raw);
        if src.is_file() {
            if dest.exists() {
                drop(fs::remove_file(&dest));
            }
            fs::copy(&src, &dest)?;
            set_executable(&dest)?;
            return Ok(InstallReport {
                package: InstallPackage::Curl.as_str(),
                host_path: dest,
                guest_path: InstallPackage::Curl.guest_path(),
                bottle,
            });
        }
    }

    let tmp_root = registry::data_dir()?.join(".kh-dl-curl");
    drop(fs::remove_dir_all(&tmp_root));
    fs::create_dir_all(&tmp_root)?;
    let archive = tmp_root.join("curl-macos-arm64.tar.xz");
    download_url(DARWIN_CURL_URL, &archive)?;

    let status = Command::new("tar")
        .args(["-xJf"])
        .arg(&archive)
        .current_dir(&tmp_root)
        .status()
        .map_err(|e| ToolError::Command(format!("tar: {e}")))?;
    if !status.success() {
        drop(fs::remove_dir_all(&tmp_root));
        return Err(ToolError::Command(format!(
            "tar extract failed (status {status})"
        )));
    }

    let found = find_named_file(&tmp_root, "curl").ok_or(ToolError::MissingBinary)?;
    // Avoid copying the archive itself if it were ever named `curl`.
    if found == archive {
        drop(fs::remove_dir_all(&tmp_root));
        return Err(ToolError::MissingBinary);
    }
    if dest.exists() {
        drop(fs::remove_file(&dest));
    }
    fs::copy(&found, &dest)?;
    set_executable(&dest)?;
    drop(fs::remove_dir_all(&tmp_root));

    Ok(InstallReport {
        package: InstallPackage::Curl.as_str(),
        host_path: dest,
        guest_path: InstallPackage::Curl.guest_path(),
        bottle,
    })
}

/// Discover Darwin `curl` for convenience helpers.
///
/// Order: explicit → `KAKEHASHI_CURL` → active bottle `/usr/local/bin/curl`.
#[must_use]
pub fn discover_curl(explicit: Option<&Path>) -> Option<PathBuf> {
    if let Some(p) = explicit {
        if p.is_file() {
            return Some(p.to_path_buf());
        }
        return None;
    }

    if let Ok(raw) = std::env::var(ENV_CURL) {
        let p = PathBuf::from(raw);
        if p.is_file() {
            return Some(p);
        }
    }

    if let Ok(Some(root)) = manage::active_root() {
        let p = package_host_path(&root, InstallPackage::Curl);
        if p.is_file() {
            return Some(p);
        }
    }

    None
}

fn set_executable(path: &Path) -> io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = fs::metadata(path)?.permissions();
        perms.set_mode(0o755);
        fs::set_permissions(path, perms)?;
    }
    let _ = path;
    Ok(())
}

fn download_url(url: &str, dest: &Path) -> Result<(), ToolError> {
    let curl = Command::new("curl")
        .args(["-fsSL", "--retry", "3", "-o"])
        .arg(dest)
        .arg(url)
        .status();
    match curl {
        Ok(st) if st.success() => return Ok(()),
        Ok(_) | Err(_) => {}
    }
    let wget = Command::new("wget")
        .args(["-q", "-O"])
        .arg(dest)
        .arg(url)
        .status()
        .map_err(|e| {
            ToolError::Command(format!(
                "download failed: need curl or wget ({e}); url={url}"
            ))
        })?;
    if !wget.success() {
        return Err(ToolError::Command(format!(
            "download failed (curl/wget); url={url}"
        )));
    }
    Ok(())
}

fn find_named_file(root: &Path, name: &str) -> Option<PathBuf> {
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let entries = fs::read_dir(&dir).ok()?;
        for ent in entries.flatten() {
            let p = ent.path();
            if p.is_dir() {
                stack.push(p);
            } else if p.file_name().is_some_and(|n| n == name) {
                return Some(p);
            }
        }
    }
    None
}

/// Default guest `PATH` components (macOS-like) used when resolving bare names.
pub const GUEST_PATH_DIRS: &[&str] = &["/usr/local/bin", "/usr/bin", "/bin", "/usr/sbin", "/sbin"];

/// Resolve a program path for `kh run`.
///
/// * Absolute or relative with `/` → unchanged (host path or guest path string).
/// * Bare name → search bottle under [`GUEST_PATH_DIRS`] (host files that exist).
#[must_use]
pub fn resolve_guest_program(spec: &Path, bottle: Option<&Path>) -> PathBuf {
    let s = spec.as_os_str();
    // Has path separator → user gave an explicit path.
    if spec.components().count() > 1 || s.to_string_lossy().contains('/') {
        return spec.to_path_buf();
    }
    let name = spec.file_name().unwrap_or(s);
    let Some(root) = bottle else {
        return spec.to_path_buf();
    };
    for dir in GUEST_PATH_DIRS {
        // dir is "/usr/local/bin" → relative "usr/local/bin"
        let rel = dir.trim_start_matches('/');
        let candidate = root.join(rel).join(name);
        if candidate.is_file() {
            // Return guest absolute path so loader + path translation stay consistent.
            return PathBuf::from(dir).join(name);
        }
    }
    spec.to_path_buf()
}

/// Map guest absolute path to host under bottle (for opening the Mach-O file).
#[must_use]
pub fn guest_path_to_host(bottle: &Path, guest: &Path) -> PathBuf {
    let g = guest.to_string_lossy();
    if g.starts_with('/') {
        bottle.join(g.trim_start_matches('/'))
    } else {
        guest.to_path_buf()
    }
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
    fn parse_package_names() {
        assert_eq!(
            InstallPackage::parse("7zip"),
            Some(InstallPackage::SevenZip)
        );
        assert_eq!(InstallPackage::parse("7ZZ"), Some(InstallPackage::SevenZip));
        assert_eq!(InstallPackage::parse("curl"), Some(InstallPackage::Curl));
        assert_eq!(InstallPackage::parse("CURL"), Some(InstallPackage::Curl));
        assert!(InstallPackage::parse("foo").is_none());
    }

    #[test]
    fn resolve_bare_name_in_bottle() {
        let root = unique("path");
        let bin = root.join("usr/local/bin");
        fs::create_dir_all(&bin).expect("dirs");
        let tool = bin.join("7zz");
        fs::write(&tool, b"x").expect("write");
        let resolved = resolve_guest_program(Path::new("7zz"), Some(&root));
        assert_eq!(resolved, PathBuf::from("/usr/local/bin/7zz"));
        drop(fs::remove_dir_all(&root));
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
    fn find_nested_name() {
        let root = unique("tree");
        fs::create_dir_all(root.join("a/b")).expect("dirs");
        let target = root.join("a/b/7zz");
        fs::write(&target, b"x").expect("write");
        assert_eq!(find_named_file(&root, "7zz"), Some(target));
        drop(fs::remove_dir_all(&root));
    }
}
