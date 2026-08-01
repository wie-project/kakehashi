//! Install Apple **Command Line Tools** into the bottle (source of Apple `git`).
//!
//! Primary path (clean Linux / Docker):
//! 1. Public Software Update catalog (`swscan.apple.com`) → latest CLT
//!    `CLTools_Executables*.pkg` (see [`swscan`])
//! 2. Persistent cache under `KAKEHASHI_DATA_DIR/cache` (Docker bind mount)
//! 3. Extract → `{bottle}/Library/Developer/CommandLineTools/…`
//! 4. Symlink `{bottle}/usr/bin/git` → CLT git
//!
//! Optional: `KAKEHASHI_XCODE_TOOLS_VERSION` pins the catalog title substring.
//! Force re-fetch: `KAKEHASHI_FORCE_DOWNLOAD=1`.
//!
//! Idempotent: if bottle already has `…/usr/bin/git`, install is a no-op (no network).

use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use super::download_cache;
use super::guest_tools::{InstallReport, ToolError};
use super::layout::is_bottle_root;
use super::manage;
use super::swscan;

/// Guest-relative root of the CLT tree under the bottle.
pub const GUEST_CLT_REL: &str = "Library/Developer/CommandLineTools";

/// Guest absolute path of Apple `git` after install.
pub const GUEST_GIT_PATH: &str = "/Library/Developer/CommandLineTools/usr/bin/git";

/// Guest-relative path of git inside the CLT tree.
pub const GUEST_GIT_REL: &str = "Library/Developer/CommandLineTools/usr/bin/git";

/// Guest-relative symlink at classic `/usr/bin/git`.
pub(crate) const GUEST_USR_BIN_GIT_REL: &str = "usr/bin/git";

/// Durable extract tree name under the download cache.
const CACHE_EXTRACT_NAME: &str = "command-line-tools";

/// Install CLT into the active bottle (creating the bottle if needed).
pub(crate) fn install_xcode_tools() -> Result<InstallReport, ToolError> {
    let bottle = ensure_active_bottle()?;

    // Idempotent: Docker re-runs must not re-download.
    if !download_cache::force_download() {
        let host_git = bottle.join(GUEST_GIT_REL);
        if host_git.is_file() {
            return Ok(InstallReport {
                package: "xcode-tools",
                host_path: host_git,
                guest_path: GUEST_GIT_PATH,
                bottle,
            });
        }
    }

    let archive = resolve_clt_archive()?;
    let clt_root = extract_archive_to_cache(&archive)?;
    install_clt_into_bottle(&bottle, &clt_root)?;

    let host_git = bottle.join(GUEST_GIT_REL);
    if !host_git.is_file() {
        return Err(ToolError::Command(format!(
            "CLT install finished but git missing at {}",
            host_git.display()
        )));
    }
    set_executable(&host_git)?;

    Ok(InstallReport {
        package: "xcode-tools",
        host_path: host_git,
        guest_path: GUEST_GIT_PATH,
        bottle,
    })
}

/// Whether the bottle already has Apple git from a prior CLT install.
#[must_use]
pub fn bottle_has_git(bottle: &Path) -> bool {
    bottle.join(GUEST_GIT_REL).is_file()
}

/// Discover Apple `git` under an active bottle.
#[must_use]
pub fn discover_git(explicit: Option<&Path>) -> Option<PathBuf> {
    if let Some(p) = explicit {
        if p.is_file() {
            return Some(p.to_path_buf());
        }
        return None;
    }
    if let Ok(Some(root)) = manage::active_root() {
        let p = root.join(GUEST_GIT_REL);
        if p.is_file() {
            return Some(p);
        }
        let alt = root.join(GUEST_USR_BIN_GIT_REL);
        if alt.is_file() {
            return Some(alt);
        }
    }
    None
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

fn resolve_clt_archive() -> Result<PathBuf, ToolError> {
    match swscan::download_selected_clt() {
        Ok((_pkg, path)) => Ok(path),
        Err(e) => {
            let mut msg = format!("Apple CLT download failed: {e}\n");
            let mut help = Vec::new();
            drop(swscan::fallback_help(&mut help));
            msg.push_str(&String::from_utf8_lossy(&help));
            Err(ToolError::Command(msg))
        }
    }
}

fn extract_archive_to_cache(archive: &Path) -> Result<PathBuf, ToolError> {
    let extract_root = download_cache::extract_path(CACHE_EXTRACT_NAME).map_err(ToolError::Io)?;
    if !download_cache::force_download()
        && let Some(existing) = find_clt_root(&extract_root)
    {
        return Ok(existing);
    }
    if extract_root.exists() {
        drop(fs::remove_dir_all(&extract_root));
    }
    fs::create_dir_all(&extract_root)?;

    let name = archive
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();

    let is_pkg = archive
        .extension()
        .is_some_and(|ext| ext.eq_ignore_ascii_case("pkg"));
    let is_tar = name.contains(".tar.")
        || Path::new(&name)
            .extension()
            .is_some_and(|ext| ext.eq_ignore_ascii_case("tar") || ext.eq_ignore_ascii_case("tgz"));

    if is_pkg {
        // Primary: own XAR + pbzx + odc (no p7zip/bsdtar).
        super::pkg_extract::extract_apple_pkg(archive, &extract_root).map_err(|e| {
            ToolError::Command(format!("Apple .pkg extract failed: {e}"))
        })?;
    } else if is_tar {
        extract_tar(archive, &extract_root)?;
    } else {
        // .dmg / odd wrappers — host 7z peel + nested pkg.
        extract_with_7z(archive, &extract_root)?;
        peel_nested_packages(&extract_root)?;
    }

    find_clt_root(&extract_root).ok_or_else(|| {
        ToolError::Command(format!(
            "extracted archive but no usr/bin/git under {} \
             (need CLTools_Executables package from Software Update)",
            extract_root.display()
        ))
    })
}

fn extract_tar(archive: &Path, dest: &Path) -> Result<(), ToolError> {
    let status = Command::new("tar")
        .arg("-xf")
        .arg(archive)
        .current_dir(dest)
        .status()
        .map_err(|e| ToolError::Command(format!("tar: {e}")))?;
    if !status.success() {
        return Err(ToolError::Command(format!(
            "tar extract failed (status {status}) for {}",
            archive.display()
        )));
    }
    Ok(())
}

fn extract_with_7z(archive: &Path, dest: &Path) -> Result<(), ToolError> {
    // Apple flat `.pkg` is XAR. Prefer bsdtar (libarchive) — Debian's p7zip 16.x
    // hardlinks every member to the Payload heap (corrupt Bom/Scripts).
    let is_pkg = archive
        .extension()
        .is_some_and(|ext| ext.eq_ignore_ascii_case("pkg"));
    if is_pkg && extract_pkg_bsdtar(archive, dest).is_ok() && pkg_extract_looks_sane(dest) {
        return Ok(());
    }

    for bin in ["7z", "7zz"] {
        let mut cmd = Command::new(bin);
        cmd.args(["x", "-y", &format!("-o{}", dest.display())]);
        if is_pkg {
            // Avoid nested open of pbzx Payload as a single xz stream.
            cmd.arg("-tXar");
        }
        cmd.arg(archive);
        let status = cmd.status();
        if let Ok(st) = status {
            // XAR extract often warns about a 20-byte trailer but still writes files.
            if (st.success() || dest_has_payload_or_files(dest))
                && (!is_pkg || pkg_extract_looks_sane(dest))
            {
                return Ok(());
            }
            // Corrupt p7zip extract: wipe and try next tool.
            if is_pkg {
                wipe_dir_contents(dest);
            }
        }
    }

    if is_pkg && extract_pkg_bsdtar(archive, dest).is_ok() && pkg_extract_looks_sane(dest) {
        return Ok(());
    }

    Err(ToolError::Command(format!(
        "need host `bsdtar` (libarchive-tools) or a working `7z`/`7zz` to extract {} \
         (Debian p7zip 16.x corrupts flat .pkg XAR members)",
        archive.display()
    )))
}

fn extract_pkg_bsdtar(archive: &Path, dest: &Path) -> Result<(), ToolError> {
    for bin in ["bsdtar", "tar"] {
        let status = Command::new(bin)
            .args(["-xf"])
            .arg(archive)
            .current_dir(dest)
            .status();
        if let Ok(st) = status
            && st.success()
            && dest_has_payload_or_files(dest)
        {
            return Ok(());
        }
    }
    Err(ToolError::Command("bsdtar/tar pkg extract failed".into()))
}

fn dest_has_payload_or_files(dest: &Path) -> bool {
    dest.join("Payload").is_file()
        || dest
            .read_dir()
            .is_ok_and(|mut d| d.next().is_some())
}

/// Reject the known p7zip-16 XAR bug: every member hardlinked to Payload size.
fn pkg_extract_looks_sane(dest: &Path) -> bool {
    let payload = dest.join("Payload");
    if !payload.is_file() {
        return false;
    }
    let Ok(payload_len) = payload.metadata().map(|m| m.len()) else {
        return false;
    };
    if payload_len == 0 {
        return false;
    }
    // Bom / PackageInfo must be smaller than Payload for real CLT packages.
    for name in ["Bom", "PackageInfo", "Scripts"] {
        let p = dest.join(name);
        if !p.is_file() {
            continue;
        }
        if p.metadata().is_ok_and(|m| m.len() == payload_len) {
            return false;
        }
    }
    // Payload itself should be pbzx / gzip / cpio — not empty.
    let mut head = [0_u8; 4];
    if File::open(&payload)
        .and_then(|mut f| f.read(&mut head))
        .is_ok_and(|n| n >= 4)
    {
        let gzip = matches!((head.first(), head.get(1)), (Some(&0x1f), Some(&0x8b)));
        if &head == b"pbzx" || gzip {
            return true;
        }
        // Accept any non-trivial payload; cpio may start with various magic.
        return payload_len > 1024;
    }
    false
}

fn wipe_dir_contents(dir: &Path) {
    if let Ok(entries) = fs::read_dir(dir) {
        for ent in entries.flatten() {
            let p = ent.path();
            if p.is_dir() {
                drop(fs::remove_dir_all(&p));
            } else {
                drop(fs::remove_file(&p));
            }
        }
    }
}

fn peel_nested_packages(root: &Path) -> Result<(), ToolError> {
    for _ in 0..6 {
        if find_clt_root(root).is_some() {
            return Ok(());
        }
        if let Some(nested) = find_first_with_suffix(root, &[".pkg", ".dmg"]) {
            let out = nested.with_extension("extracted");
            if !out.exists() {
                fs::create_dir_all(&out)?;
                extract_with_7z(&nested, &out)?;
            }
            continue;
        }
        if let Some(payload) = find_named_file(root, "Payload") {
            let out = payload
                .parent()
                .unwrap_or(root)
                .join("Payload.extracted");
            if !out.exists() {
                fs::create_dir_all(&out)?;
                extract_payload(&payload, &out)?;
            }
            continue;
        }
        break;
    }
    Ok(())
}

/// Expand a macOS package `Payload` (pbzx / gzip / plain cpio) into `dest`.
fn extract_payload(payload: &Path, dest: &Path) -> Result<(), ToolError> {
    let mut head = [0_u8; 4];
    {
        let mut f = File::open(payload).map_err(ToolError::Io)?;
        let n = f.read(&mut head).map_err(ToolError::Io)?;
        if n < 4 {
            return Err(ToolError::Command(format!(
                "Payload too small: {}",
                payload.display()
            )));
        }
    }
    if &head == b"pbzx" {
        return extract_payload_pbzx(payload, dest);
    }
    // gzip magic 1f 8b
    if head[0] == 0x1f && head[1] == 0x8b {
        return extract_payload_gzip_cpio(payload, dest);
    }
    // Try 7z, then raw cpio.
    if extract_with_7z(payload, dest).is_ok() && find_clt_root(dest).is_some() {
        return Ok(());
    }
    extract_payload_raw_cpio(payload, dest)
}

/// Apple **pbzx** multi-stream xz wrapper used by modern CLT / Xcode packages.
///
/// Layout (big-endian):
/// `pbzx` + u64 flags + repeated (u64 chunk_flags, u64 xz_size, xz_bytes…).
/// Concatenated xz streams decompress to a single cpio archive.
fn extract_payload_pbzx(payload: &Path, dest: &Path) -> Result<(), ToolError> {
    let mut input = File::open(payload).map_err(ToolError::Io)?;
    let mut magic = [0_u8; 4];
    input.read_exact(&mut magic).map_err(ToolError::Io)?;
    if &magic != b"pbzx" {
        return Err(ToolError::Command("Payload missing pbzx magic".into()));
    }
    let mut flags = [0_u8; 8];
    input.read_exact(&mut flags).map_err(ToolError::Io)?;

    let mut cpio = Command::new("cpio")
        .args(["-idm"])
        .current_dir(dest)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|e| ToolError::Command(format!("cpio: {e}")))?;
    let mut cpio_in = cpio.stdin.take().ok_or_else(|| {
        ToolError::Command("cpio produced no stdin for pbzx Payload".into())
    })?;

    let mut chunks = 0_u32;
    loop {
        let mut hdr = [0_u8; 16];
        match input.read_exact(&mut hdr) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => break,
            Err(e) => return Err(ToolError::Io(e)),
        }
        let Some(size_bytes) = hdr.get(8..16) else {
            return Err(ToolError::Command("pbzx header truncated".into()));
        };
        let mut size_arr = [0_u8; 8];
        size_arr.copy_from_slice(size_bytes);
        let xz_size = u64::from_be_bytes(size_arr);
        if xz_size == 0 {
            break;
        }
        let Ok(xz_len) = usize::try_from(xz_size) else {
            return Err(ToolError::Command(format!(
                "pbzx xz chunk too large ({xz_size} bytes)"
            )));
        };

        let mut xz = Command::new("xz")
            .args(["-dc"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| {
                ToolError::Command(format!("xz: {e} (need host xz-utils for pbzx Payload)")
                )
            })?;
        let mut xz_in = xz.stdin.take().ok_or_else(|| {
            ToolError::Command("xz produced no stdin".into())
        })?;
        let mut xz_out = xz.stdout.take().ok_or_else(|| {
            ToolError::Command("xz produced no stdout".into())
        })?;

        // Stream this xz frame into xz(1).
        let mut remaining = xz_len;
        let mut buf = vec![0_u8; 64 * 1024];
        while remaining > 0 {
            let n = remaining.min(buf.len());
            input
                .read_exact(
                    buf.get_mut(..n).ok_or_else(|| {
                        ToolError::Command("pbzx buffer slice failed".into())
                    })?,
                )
                .map_err(ToolError::Io)?;
            xz_in
                .write_all(buf.get(..n).unwrap_or(&[]))
                .map_err(ToolError::Io)?;
            remaining = remaining.saturating_sub(n);
        }
        drop(xz_in);

        io::copy(&mut xz_out, &mut cpio_in).map_err(ToolError::Io)?;
        let xz_status = xz
            .wait()
            .map_err(|e| ToolError::Command(format!("xz wait: {e}")))?;
        if !xz_status.success() {
            return Err(ToolError::Command(format!(
                "xz decompress of pbzx chunk {chunks} failed (status {xz_status})"
            )));
        }
        chunks = chunks.saturating_add(1);
    }
    drop(cpio_in);
    let status = cpio
        .wait()
        .map_err(|e| ToolError::Command(format!("cpio wait: {e}")))?;
    // cpio often exits 1 on trailer warnings; accept if we got a tree.
    if !status.success() && find_clt_root(dest).is_none() {
        return Err(ToolError::Command(format!(
            "cpio extract of pbzx Payload failed (status {status}, chunks={chunks})"
        )));
    }
    if chunks == 0 {
        return Err(ToolError::Command(
            "pbzx Payload contained no xz chunks".into(),
        ));
    }
    Ok(())
}

fn extract_payload_gzip_cpio(payload: &Path, dest: &Path) -> Result<(), ToolError> {
    let gzip = Command::new("gzip")
        .args(["-dc"])
        .arg(payload)
        .stdout(Stdio::piped())
        .spawn()
        .map_err(|e| ToolError::Command(format!("gzip: {e}")))?;
    let Some(stdout) = gzip.stdout else {
        return Err(ToolError::Command(
            "gzip produced no stdout for Payload extract".into(),
        ));
    };
    let status = Command::new("cpio")
        .args(["-idm"])
        .current_dir(dest)
        .stdin(stdout)
        .status()
        .map_err(|e| ToolError::Command(format!("cpio: {e}")))?;
    if !status.success() && find_clt_root(dest).is_none() {
        return Err(ToolError::Command(format!(
            "cpio extract of gzip Payload failed (status {status})"
        )));
    }
    Ok(())
}

fn extract_payload_raw_cpio(payload: &Path, dest: &Path) -> Result<(), ToolError> {
    let file = File::open(payload).map_err(ToolError::Io)?;
    let status = Command::new("cpio")
        .args(["-idm"])
        .current_dir(dest)
        .stdin(file)
        .status()
        .map_err(|e| ToolError::Command(format!("cpio: {e}")))?;
    if !status.success() && find_clt_root(dest).is_none() {
        return Err(ToolError::Command(format!(
            "raw cpio extract of Payload failed (status {status})"
        )));
    }
    Ok(())
}

fn find_clt_root(root: &Path) -> Option<PathBuf> {
    if root.join("usr/bin/git").is_file() {
        return Some(root.to_path_buf());
    }
    let mut stack = vec![root.to_path_buf()];
    let mut visited = 0_usize;
    while let Some(dir) = stack.pop() {
        visited = visited.saturating_add(1);
        if visited > 50_000 {
            break;
        }
        if dir.join("usr/bin/git").is_file() {
            return Some(dir);
        }
        let Ok(entries) = fs::read_dir(&dir) else {
            continue;
        };
        for ent in entries.flatten() {
            let p = ent.path();
            if p.is_dir() {
                let name = p.file_name().and_then(|n| n.to_str()).unwrap_or("");
                if name == "CommandLineTools" && p.join("usr/bin/git").is_file() {
                    return Some(p);
                }
                stack.push(p);
            }
        }
    }
    None
}

fn find_first_with_suffix(root: &Path, suffixes: &[&str]) -> Option<PathBuf> {
    let mut stack = vec![root.to_path_buf()];
    let mut visited = 0_usize;
    while let Some(dir) = stack.pop() {
        visited = visited.saturating_add(1);
        if visited > 20_000 {
            break;
        }
        let Ok(entries) = fs::read_dir(&dir) else {
            continue;
        };
        for ent in entries.flatten() {
            let p = ent.path();
            if p.is_dir() {
                stack.push(p);
                continue;
            }
            let name = p.file_name().and_then(|n| n.to_str()).unwrap_or("");
            let lower = name.to_ascii_lowercase();
            if suffixes.iter().any(|s| lower.ends_with(s)) {
                return Some(p);
            }
        }
    }
    None
}

fn find_named_file(root: &Path, name: &str) -> Option<PathBuf> {
    let mut stack = vec![root.to_path_buf()];
    let mut visited = 0_usize;
    while let Some(dir) = stack.pop() {
        visited = visited.saturating_add(1);
        if visited > 20_000 {
            break;
        }
        let Ok(entries) = fs::read_dir(&dir) else {
            continue;
        };
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

fn install_clt_into_bottle(bottle: &Path, clt_root: &Path) -> Result<(), ToolError> {
    let dest = bottle.join(GUEST_CLT_REL);
    if dest.exists() {
        drop(fs::remove_dir_all(&dest));
    }
    if let Some(parent) = dest.parent() {
        fs::create_dir_all(parent)?;
    }
    copy_dir_recursive(clt_root, &dest)?;

    let usr_bin = bottle.join("usr/bin");
    fs::create_dir_all(&usr_bin)?;
    let link = bottle.join(GUEST_USR_BIN_GIT_REL);
    if link.exists() || link.symlink_metadata().is_ok() {
        drop(fs::remove_file(&link));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::symlink;
        symlink(
            "../../Library/Developer/CommandLineTools/usr/bin/git",
            &link,
        )?;
    }
    #[cfg(not(unix))]
    {
        fs::copy(dest.join("usr/bin/git"), &link)?;
    }
    Ok(())
}

fn copy_dir_recursive(src: &Path, dst: &Path) -> Result<(), ToolError> {
    fs::create_dir_all(dst)?;
    let mut stack = vec![(src.to_path_buf(), dst.to_path_buf())];
    while let Some((from, to)) = stack.pop() {
        let entries = fs::read_dir(&from)?;
        for ent in entries {
            let ent = ent?;
            let from_path = ent.path();
            let to_path = to.join(ent.file_name());
            let ft = ent.file_type()?;
            if ft.is_dir() {
                fs::create_dir_all(&to_path)?;
                stack.push((from_path, to_path));
            } else if ft.is_symlink() {
                #[cfg(unix)]
                {
                    use std::os::unix::fs::symlink;
                    let target = fs::read_link(&from_path)?;
                    if to_path.exists() || to_path.symlink_metadata().is_ok() {
                        drop(fs::remove_file(&to_path));
                    }
                    symlink(target, &to_path)?;
                }
                #[cfg(not(unix))]
                {
                    fs::copy(&from_path, &to_path)?;
                }
            } else {
                if let Some(parent) = to_path.parent() {
                    fs::create_dir_all(parent)?;
                }
                fs::copy(&from_path, &to_path)?;
            }
        }
    }
    Ok(())
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

#[cfg(test)]
#[allow(clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    fn unique(prefix: &str) -> PathBuf {
        static N: AtomicU64 = AtomicU64::new(0);
        let n = N.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!(
            "kh-clt-{}-{}-{n}",
            prefix,
            std::process::id()
        ))
    }

    #[test]
    fn find_clt_root_nested() {
        let root = unique("tree");
        let clt = root.join("Library/Developer/CommandLineTools");
        fs::create_dir_all(clt.join("usr/bin")).expect("dirs");
        fs::write(clt.join("usr/bin/git"), b"fake").expect("write");
        assert_eq!(find_clt_root(&root), Some(clt));
        drop(fs::remove_dir_all(&root));
    }
}
