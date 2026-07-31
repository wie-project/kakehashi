//! Seed a CA bundle into the bottle for OpenSSL / SecTrust verify.
//!
//! Guest paths (classic OpenSSL defaults that static curl probes):
//! - `/etc/ssl/cert.pem` → `private/etc/ssl/cert.pem`
//! - `/etc/ssl/certs/`   → `private/etc/ssl/certs/` (directory present)
//!
//! Source order on seed (nothing vendored in-tree):
//! 1. Keep an existing non-empty bottle file.
//! 2. `KAKEHASHI_CA_BUNDLE` (host path override).
//! 3. Host system trust store (Linux Docker/UTM, macOS `/etc/ssl/cert.pem`, …).
//! 4. Download Mozilla CA bundle from [`MOZILLA_CACERT_URL`] (needs `curl` or `wget`).

use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::process::Command;

/// Relative path under the bottle root for the PEM CA file.
pub const GUEST_CA_FILE_REL: &str = "private/etc/ssl/cert.pem";

/// Relative directory for `CApath` (`/etc/ssl/certs`).
pub const GUEST_CA_DIR_REL: &str = "private/etc/ssl/certs";

/// Env: host path of a PEM CA bundle to seed (skip host scan / download).
pub const ENV_CA_BUNDLE: &str = "KAKEHASHI_CA_BUNDLE";

/// Mozilla CA extract published by the curl project (kept current upstream).
pub const MOZILLA_CACERT_URL: &str = "https://curl.se/ca/cacert.pem";

/// Host paths commonly used as system trust stores (Linux + macOS).
const HOST_CA_CANDIDATES: &[&str] = &[
    "/etc/ssl/certs/ca-certificates.crt",
    "/etc/ssl/cert.pem",
    "/etc/pki/tls/certs/ca-bundle.crt",
    "/etc/ssl/ca-bundle.pem",
    // Homebrew OpenSSL / LibreSSL on macOS (optional).
    "/opt/homebrew/etc/openssl@3/cert.pem",
    "/usr/local/etc/openssl@3/cert.pem",
];

/// Ensure `private/etc/ssl/{cert.pem,certs/}` exist under `bottle_root`.
///
/// Idempotent. Returns the host path of the PEM file written or already present.
pub fn ensure_ca_bundle(bottle_root: &Path) -> io::Result<PathBuf> {
    let env_override = std::env::var_os(ENV_CA_BUNDLE).map(PathBuf::from);
    ensure_ca_bundle_with(bottle_root, env_override)
}

/// Same as [`ensure_ca_bundle`], with an explicit override path (tests / tooling).
pub(crate) fn ensure_ca_bundle_with(
    bottle_root: &Path,
    env_override: Option<PathBuf>,
) -> io::Result<PathBuf> {
    let pem_path = bottle_root.join(GUEST_CA_FILE_REL);
    let certs_dir = bottle_root.join(GUEST_CA_DIR_REL);

    if let Some(parent) = pem_path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::create_dir_all(&certs_dir)?;

    if is_usable_pem(&pem_path) {
        return Ok(pem_path);
    }

    if let Some(src) = env_override {
        if is_usable_pem(&src) {
            fs::copy(&src, &pem_path)?;
            return Ok(pem_path);
        }
        tracing::warn!(
            path = %src.display(),
            "{ENV_CA_BUNDLE} set but not a usable PEM; trying host / download"
        );
    }

    if let Some(host) = first_usable_host_ca() {
        fs::copy(&host, &pem_path)?;
        tracing::info!(from = %host.display(), "bottle CA: copied host trust store");
        return Ok(pem_path);
    }

    download_mozilla_ca(&pem_path)?;
    tracing::info!(url = MOZILLA_CACERT_URL, "bottle CA: downloaded Mozilla cacert.pem");
    Ok(pem_path)
}

fn is_usable_pem(path: &Path) -> bool {
    let Ok(meta) = fs::metadata(path) else {
        return false;
    };
    meta.is_file() && meta.len() > 1024
}

fn first_usable_host_ca() -> Option<PathBuf> {
    for p in HOST_CA_CANDIDATES {
        let path = Path::new(p);
        if is_usable_pem(path) {
            return Some(path.to_path_buf());
        }
    }
    None
}

/// Download [`MOZILLA_CACERT_URL`] into `dest` via host `curl` or `wget`.
///
/// Secure fetch first; if the host has no trust store, retry with verification
/// disabled to bootstrap a CA (payload is still checked for PEM markers).
fn download_mozilla_ca(dest: &Path) -> io::Result<()> {
    let parent = dest
        .parent()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "CA dest has no parent"))?;
    fs::create_dir_all(parent)?;
    let tmp = parent.join("cert.pem.part");
    drop(fs::remove_file(&tmp));

    let ok = try_download_curl(MOZILLA_CACERT_URL, &tmp, false)
        || try_download_wget(MOZILLA_CACERT_URL, &tmp, false)
        || try_download_curl(MOZILLA_CACERT_URL, &tmp, true)
        || try_download_wget(MOZILLA_CACERT_URL, &tmp, true);
    if !ok {
        drop(fs::remove_file(&tmp));
        return Err(io::Error::other(format!(
            "no host CA found and download failed (need curl or wget); \
             set {ENV_CA_BUNDLE}, install ca-certificates, or fix network; \
             url={MOZILLA_CACERT_URL}"
        )));
    }

    if !is_usable_pem(&tmp) {
        drop(fs::remove_file(&tmp));
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "downloaded CA bundle is missing or too small",
        ));
    }
    // Basic sanity: PEM markers (rejects HTML error pages).
    let head = fs::read(&tmp)?;
    if !head.windows(10).any(|w| w == b"BEGIN CERT") {
        drop(fs::remove_file(&tmp));
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "downloaded CA bundle does not look like PEM",
        ));
    }

    fs::rename(&tmp, dest).or_else(|_| {
        fs::copy(&tmp, dest)?;
        fs::remove_file(&tmp)
    })?;
    Ok(())
}

fn try_download_curl(url: &str, dest: &Path, insecure: bool) -> bool {
    let mut cmd = Command::new("curl");
    cmd.args(["-fsSL", "--retry", "3", "--connect-timeout", "15", "-o"])
        .arg(dest)
        .arg(url);
    if insecure {
        cmd.arg("--insecure");
    }
    matches!(cmd.status(), Ok(s) if s.success())
}

fn try_download_wget(url: &str, dest: &Path, insecure: bool) -> bool {
    let mut cmd = Command::new("wget");
    cmd.args(["-q", "-T", "15", "-O"]).arg(dest).arg(url);
    if insecure {
        cmd.arg("--no-check-certificate");
    }
    matches!(cmd.status(), Ok(s) if s.success())
}

/// Host path of the bottle CA PEM when the active bottle is set and seeded.
#[must_use]
pub fn active_ca_pem_path() -> Option<PathBuf> {
    let root = super::active_root().ok().flatten()?;
    let pem = root.join(GUEST_CA_FILE_REL);
    if pem.is_file() { Some(pem) } else { None }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    fn unique(prefix: &str) -> PathBuf {
        static N: AtomicU64 = AtomicU64::new(0);
        let n = N.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!("kh-ca-{}-{}-{n}", prefix, std::process::id()))
    }

    fn write_fake_pem(path: &Path) {
        if let Some(p) = path.parent() {
            fs::create_dir_all(p).expect("dir");
        }
        // > 1024 bytes with PEM marker.
        let mut body = b"-----BEGIN CERTIFICATE-----\n".to_vec();
        body.extend(std::iter::repeat_n(b'A', 1200));
        body.extend_from_slice(b"\n-----END CERTIFICATE-----\n");
        fs::write(path, body).expect("write pem");
    }

    #[test]
    fn keeps_existing_bottle_file() {
        let root = unique("keep");
        drop(fs::remove_dir_all(&root));
        let pem = root.join(GUEST_CA_FILE_REL);
        write_fake_pem(&pem);
        let got = ensure_ca_bundle(&root).expect("seed");
        assert_eq!(got, pem);
        let len = fs::metadata(&pem).expect("m").len();
        assert!(len > 1024);
        drop(fs::remove_dir_all(&root));
    }

    #[test]
    fn seeds_from_explicit_override() {
        let root = unique("env");
        let src_dir = unique("env-src");
        drop(fs::remove_dir_all(&root));
        drop(fs::remove_dir_all(&src_dir));
        let src = src_dir.join("my-ca.pem");
        write_fake_pem(&src);

        let got = ensure_ca_bundle_with(&root, Some(src)).expect("seed");
        assert!(got.is_file());
        let bytes = fs::read(&got).expect("read");
        assert!(bytes.windows(10).any(|w| w == b"BEGIN CERT"));
        drop(fs::remove_dir_all(&root));
        drop(fs::remove_dir_all(&src_dir));
    }
}
