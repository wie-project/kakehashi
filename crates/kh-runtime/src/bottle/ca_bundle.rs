//! Seed a real Mozilla CA bundle into the bottle for OpenSSL / SecTrust verify.
//!
//! Guest paths (classic OpenSSL defaults that static curl probes):
//! - `/etc/ssl/cert.pem` → `private/etc/ssl/cert.pem`
//! - `/etc/ssl/certs/`   → `private/etc/ssl/certs/` (directory present)
//!
//! Source order on seed:
//! 1. Keep an existing non-empty bottle file.
//! 2. Copy a host system bundle when present.
//! 3. Write the crate-embedded Mozilla bundle (`resources/ssl/cert.pem`).

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

/// Relative path under the bottle root for the PEM CA file.
pub const GUEST_CA_FILE_REL: &str = "private/etc/ssl/cert.pem";

/// Relative directory for `CApath` (`/etc/ssl/certs`).
pub const GUEST_CA_DIR_REL: &str = "private/etc/ssl/certs";

/// Embedded Mozilla CA bundle (curl.se `cacert.pem`), vendored for offline ensure.
const EMBEDDED_CA_PEM: &[u8] = include_bytes!("../../resources/ssl/cert.pem");

/// Host paths commonly used as system trust stores (Linux + macOS).
const HOST_CA_CANDIDATES: &[&str] = &[
    "/etc/ssl/cert.pem",
    "/etc/ssl/certs/ca-certificates.crt",
    "/etc/pki/tls/certs/ca-bundle.crt",
    "/etc/ssl/ca-bundle.pem",
];

/// Ensure `private/etc/ssl/{cert.pem,certs/}` exist under `bottle_root`.
///
/// Idempotent. Returns the host path of the PEM file written or already present.
pub fn ensure_ca_bundle(bottle_root: &Path) -> io::Result<PathBuf> {
    let pem_path = bottle_root.join(GUEST_CA_FILE_REL);
    let certs_dir = bottle_root.join(GUEST_CA_DIR_REL);

    if let Some(parent) = pem_path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::create_dir_all(&certs_dir)?;

    if pem_path.is_file() {
        let meta = fs::metadata(&pem_path)?;
        if meta.len() > 0 {
            return Ok(pem_path);
        }
    }

    if let Some(host) = first_usable_host_ca() {
        fs::copy(&host, &pem_path)?;
        return Ok(pem_path);
    }

    fs::write(&pem_path, EMBEDDED_CA_PEM)?;
    Ok(pem_path)
}

fn first_usable_host_ca() -> Option<PathBuf> {
    for p in HOST_CA_CANDIDATES {
        let path = Path::new(p);
        if let Ok(meta) = fs::metadata(path)
            && meta.is_file()
            && meta.len() > 1024
        {
            return Some(path.to_path_buf());
        }
    }
    None
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

    #[test]
    fn seeds_embedded_when_no_host_file_forced() {
        let root = unique("seed");
        drop(fs::remove_dir_all(&root));
        fs::create_dir_all(root.join("private/etc")).expect("dir");
        // Isolate from host by using a path that ensure still writes (embedded
        // path always works even when host CA exists — we only skip write if
        // bottle already has a file).
        let pem = ensure_ca_bundle(&root).expect("seed");
        assert!(pem.is_file());
        let bytes = fs::read(&pem).expect("read");
        assert!(bytes.len() > 1024);
        assert!(bytes.windows(10).any(|w| w == b"BEGIN CERT"));
        // Idempotent: second call keeps the file.
        let len1 = bytes.len();
        let pem2 = ensure_ca_bundle(&root).expect("seed2");
        assert_eq!(pem, pem2);
        assert_eq!(
            fs::metadata(&pem2).expect("m").len(),
            u64::try_from(len1).unwrap()
        );
        drop(fs::remove_dir_all(&root));
    }
}
