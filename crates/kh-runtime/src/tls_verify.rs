//! Host-side TLS certificate verification against a PEM CA bundle.
//!
//! Used by the `KH_HELPER_VERIFY_CERT` path that backs freestanding
//! `SecTrustEvaluateWithError` (no real Security.framework in the bottle).
//!
//! Implementation: host `openssl` CLI (chain trust + hostname SAN/CN check).
//! The CA file is the bottle system/downloaded bundle under `private/etc/ssl/cert.pem`.

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU32, Ordering};

/// Verify `leaf` (DER) with optional intermediate DERs for `hostname` using `ca_pem`.
///
/// Returns `Ok(())` when the chain is trusted and the leaf matches `hostname`.
pub fn verify_der_chain(
    ca_pem: &Path,
    hostname: &str,
    leaf_der: &[u8],
    intermediates_der: &[&[u8]],
) -> Result<(), String> {
    if hostname.is_empty() {
        return Err("empty hostname".into());
    }
    if leaf_der.is_empty() {
        return Err("empty leaf certificate".into());
    }
    if !ca_pem.is_file() {
        return Err(format!("CA bundle missing: {}", ca_pem.display()));
    }

    let tmp = temp_dir()?;
    let leaf_path = tmp.join("leaf.der");
    let inter_path = tmp.join("inter.pem");
    write_all(&leaf_path, leaf_der)?;

    {
        let mut f = fs::File::create(&inter_path).map_err(|e| e.to_string())?;
        for der in intermediates_der {
            if der.is_empty() {
                continue;
            }
            let pem = der_to_pem(der);
            f.write_all(pem.as_bytes()).map_err(|e| e.to_string())?;
        }
    }

    let leaf_str = leaf_path.to_string_lossy();
    let host_ok = Command::new("openssl")
        .args([
            "x509",
            "-inform",
            "DER",
            "-in",
            leaf_str.as_ref(),
            "-noout",
            "-checkhost",
            hostname,
        ])
        .output()
        .map_err(|e| format!("openssl x509: {e}"))?;
    if !host_ok.status.success() {
        let stderr = String::from_utf8_lossy(&host_ok.stderr);
        cleanup(&tmp);
        return Err(format!("hostname mismatch for {hostname}: {stderr}"));
    }

    let leaf_pem_path = tmp.join("leaf.pem");
    write_all(&leaf_pem_path, der_to_pem(leaf_der).as_bytes())?;

    let mut args: Vec<String> = vec![
        "verify".into(),
        "-CAfile".into(),
        ca_pem.display().to_string(),
    ];
    let inter_meta = fs::metadata(&inter_path).map_or(0, |m| m.len());
    if inter_meta > 0 {
        args.push("-untrusted".into());
        args.push(inter_path.display().to_string());
    }
    args.push(leaf_pem_path.display().to_string());

    let verify = Command::new("openssl")
        .args(&args)
        .output()
        .map_err(|e| format!("openssl verify: {e}"))?;
    cleanup(&tmp);
    if verify.status.success() {
        note_ok_once();
        Ok(())
    } else {
        let stdout = String::from_utf8_lossy(&verify.stdout);
        let stderr = String::from_utf8_lossy(&verify.stderr);
        Err(format!("openssl verify failed: {stdout}{stderr}"))
    }
}

fn der_to_pem(der: &[u8]) -> String {
    let b64 = base64_encode(der);
    let mut out = String::from("-----BEGIN CERTIFICATE-----\n");
    let mut i = 0_usize;
    while i < b64.len() {
        let end = i.saturating_add(64).min(b64.len());
        if let Some(chunk) = b64.get(i..end) {
            out.push_str(chunk);
            out.push('\n');
        }
        i = end;
    }
    out.push_str("-----END CERTIFICATE-----\n");
    out
}

/// Minimal base64 encoder.
fn base64_encode(data: &[u8]) -> String {
    const T: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let cap = data
        .len()
        .saturating_mul(4)
        .saturating_add(2)
        .saturating_div(3)
        .saturating_add(4);
    let mut out = String::with_capacity(cap);
    let mut i = 0_usize;
    while i < data.len() {
        let b0 = data.get(i).copied().unwrap_or(0);
        let b1 = data.get(i.saturating_add(1)).copied();
        let b2 = data.get(i.saturating_add(2)).copied();
        let n = match (b1, b2) {
            (Some(_), Some(_)) => 3_usize,
            (Some(_), None) => 2,
            _ => 1,
        };
        let v = u32::from(b0)
            .saturating_mul(1 << 16)
            .saturating_add(u32::from(b1.unwrap_or(0)).saturating_mul(1 << 8))
            .saturating_add(u32::from(b2.unwrap_or(0)));
        let i0 = usize::try_from((v >> 18) & 63).unwrap_or(0);
        let i1 = usize::try_from((v >> 12) & 63).unwrap_or(0);
        let i2 = usize::try_from((v >> 6) & 63).unwrap_or(0);
        let i3 = usize::try_from(v & 63).unwrap_or(0);
        out.push(char::from(*T.get(i0).unwrap_or(&b'A')));
        out.push(char::from(*T.get(i1).unwrap_or(&b'A')));
        if n > 1 {
            out.push(char::from(*T.get(i2).unwrap_or(&b'A')));
        } else {
            out.push('=');
        }
        if n > 2 {
            out.push(char::from(*T.get(i3).unwrap_or(&b'A')));
        } else {
            out.push('=');
        }
        i = i.saturating_add(n);
    }
    out
}

fn temp_dir() -> Result<PathBuf, String> {
    static N: AtomicU32 = AtomicU32::new(0);
    let n = N.fetch_add(1, Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!(
        "kh-tls-verify-{}-{}",
        std::process::id(),
        n
    ));
    fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    Ok(dir)
}

fn write_all(path: &Path, data: &[u8]) -> Result<(), String> {
    fs::write(path, data).map_err(|e| e.to_string())
}

fn cleanup(dir: &Path) {
    drop(fs::remove_dir_all(dir));
}

fn note_ok_once() {
    static N: AtomicU32 = AtomicU32::new(0);
    if N.fetch_add(1, Ordering::Relaxed) == 0 {
        drop(std::io::Write::write_all(
            &mut std::io::stderr(),
            b"kh: tls verify ok (openssl + bottle CA bundle)\n",
        ));
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn base64_hello() {
        assert_eq!(base64_encode(b"hi"), "aGk=");
    }

    #[test]
    fn empty_hostname_fails() {
        let ca = Path::new("/nonexistent-ca-for-test.pem");
        let err = verify_der_chain(ca, "", b"\x30\x00", &[]).unwrap_err();
        assert!(err.contains("empty hostname"));
    }
}
