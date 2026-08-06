//! macOS-like filesystem skeleton for a bottle root.
//!
//! Mirrors the directory tree a fresh macOS install presents at `/`, without
//! shipping proprietary system blobs. Host Linux is linked via
//! `Volumes/linux` → `/` so guest paths under `/Volumes/linux/...` reach the
//! host FS through ordinary open/read/write after path translation.

use std::fs;
use std::io;
use std::path::Path;

/// Marker file name placed at the bottle root.
///
/// The bottle directory itself may be renamed; identity comes from this marker
/// plus the active-bottle registry path, not from a hard-coded directory name.
pub const MARKER_NAME: &str = ".kakehashi-bottle";

/// First line of the marker file (`format_version` is currently `1`).
pub const MARKER_MAGIC: &str = "kakehashi-bottle 1";

/// Relative path (from bottle root) of the host Linux bridge directory.
pub const VOLUMES_LINUX: &str = "Volumes/linux";

/// Guest path for the `libc++.1.dylib` alias under the bottle root.
///
/// Materialized as a **relative** symlink → [`GUEST_LIBCXX_TARGET`] so C++ guests
/// (`7zz`, …) load our freestanding libSystem without a second crate.
pub const GUEST_LIBCXX_REL: &str = "usr/lib/libc++.1.dylib";

/// Relative symlink target of [`GUEST_LIBCXX_REL`] (sibling under `usr/lib/`).
pub const GUEST_LIBCXX_TARGET: &str = "libSystem.B.dylib";

/// Guest path for the `libcurl.4.dylib` alias under the bottle root.
///
/// Same freestanding product as libSystem (`curl_*` exports live in
/// `kh-libsystem`). Apple `git-remote-http` loads `/usr/lib/libcurl.4.dylib`.
pub const GUEST_LIBCURL_REL: &str = "usr/lib/libcurl.4.dylib";

/// Relative symlink target of [`GUEST_LIBCURL_REL`].
pub const GUEST_LIBCURL_TARGET: &str = "libSystem.B.dylib";

/// Guest path for `libxar.1.dylib` (Apple `ld-classic` LC_LOAD_DYLIB).
///
/// Soft `xar_*` exports live in freestanding libSystem (`ld_surface`).
pub(crate) const GUEST_LIBXAR_REL: &str = "usr/lib/libxar.1.dylib";

/// Relative symlink target of [`GUEST_LIBXAR_REL`].
pub(crate) const GUEST_LIBXAR_TARGET: &str = "libSystem.B.dylib";

/// Guest path for `libz.1.dylib` (zlib; freestanding exports in `zlib` module).
pub(crate) const GUEST_LIBZ_REL: &str = "usr/lib/libz.1.dylib";

/// Relative symlink target of [`GUEST_LIBZ_REL`].
pub(crate) const GUEST_LIBZ_TARGET: &str = "libSystem.B.dylib";

/// Empty directories that form the post-install macOS root skeleton.
///
/// Symlinks (`etc`, `tmp`, `var`, `Volumes/linux`, `usr/lib/libc++.1.dylib`,
/// `usr/lib/libcurl.4.dylib`, `usr/lib/libxar.1.dylib`, `usr/lib/libz.1.dylib`)
/// are created separately.
const DIRS: &[&str] = &[
    "Applications",
    "Library/Application Support",
    "Library/Caches",
    "Library/Logs",
    "Library/Preferences",
    "System/Library",
    "Users/Shared",
    "Volumes",
    "bin",
    "sbin",
    "usr/bin",
    "usr/lib",
    "usr/libexec",
    "usr/local/bin",
    "usr/local/lib",
    "usr/local/share",
    "usr/sbin",
    "usr/share",
    "usr/standalone",
    "private/etc",
    "private/tmp",
    "private/var/db",
    "private/var/folders",
    "private/var/log",
    "private/var/root",
    "private/var/run",
    "private/var/tmp",
    "dev",
    "opt",
    "cores",
];

/// Returns `true` if `root` looks like a Kakehashi bottle (marker present).
#[must_use]
pub fn is_bottle_root(root: &Path) -> bool {
    let marker = root.join(MARKER_NAME);
    match fs::read_to_string(&marker) {
        Ok(contents) => contents.lines().next() == Some(MARKER_MAGIC),
        Err(_) => false,
    }
}

/// Creates the macOS-like skeleton under `root` (must not already be a bottle).
///
/// `root` is created if missing. Fails if a valid bottle marker already exists.
pub fn materialize(root: &Path) -> io::Result<()> {
    if is_bottle_root(root) {
        return Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            format!("bottle marker already present at {}", root.display()),
        ));
    }

    fs::create_dir_all(root)?;

    for rel in DIRS {
        fs::create_dir_all(root.join(rel))?;
    }

    // Classic macOS private tree aliases.
    symlink_rel(root, "private/etc", "etc")?;
    symlink_rel(root, "private/tmp", "tmp")?;
    symlink_rel(root, "private/var", "var")?;

    // C++ runtime alias: guest `/usr/lib/libc++.1.dylib` → same freestanding
    // dylib as libSystem (no second crate). Target file may be installed later
    // by `kh bottle create` / libsystem install.
    ensure_libcxx_symlink(root)?;
    // Git HTTPS: guest `/usr/lib/libcurl.4.dylib` → same freestanding dylib.
    ensure_libcurl_symlink(root)?;
    // ld-classic (clang G4): libxar + libz → freestanding surface.
    ensure_libxar_symlink(root)?;
    ensure_libz_symlink(root)?;

    // Host Linux bridge: guest `/Volumes/linux/...` → host `/...`.
    let volumes_linux = root.join(VOLUMES_LINUX);
    if volumes_linux.exists() || volumes_linux.symlink_metadata().is_ok() {
        return Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            format!("{} already exists", volumes_linux.display()),
        ));
    }
    std::os::unix::fs::symlink("/", &volumes_linux)?;

    // Classic device nodes: symlink through the host bridge so open/read/write
    // work without mknod (containers often lack CAP_MKNOD). Needed by Apple
    // `git` (`/dev/null`) and many other CLI tools.
    ensure_dev_nodes(root)?;
    // Git SSH remotes: guest `execvp("ssh")` → host OpenSSH (not in CLT).
    // `GIT_SSH_COMMAND` runs via `sh -c`, so `/bin/sh` must exist too.
    ensure_host_ssh_bridge(root)?;
    ensure_host_bin_bridges(root)?;

    fs::write(root.join(MARKER_NAME), format!("{MARKER_MAGIC}\n"))?;
    Ok(())
}

/// Host device basenames exposed under bottle `dev/` via `Volumes/linux`.
const DEV_HOST_NODES: &[&str] = &[
    "null", "zero", "urandom", "random", "tty", "stdin", "stdout", "stderr",
];

/// Ensure guest `/dev/{null,zero,…}` exist as symlinks to the host devices.
///
/// Target is relative: `../Volumes/linux/dev/<name>` so the bottle stays
/// relocatable. Idempotent; does not replace an existing non-symlink node.
pub fn ensure_dev_nodes(root: &Path) -> io::Result<()> {
    let dev_dir = root.join("dev");
    fs::create_dir_all(&dev_dir)?;
    for name in DEV_HOST_NODES {
        let link_path = dev_dir.join(name);
        if link_path.exists() || link_path.symlink_metadata().is_ok() {
            continue;
        }
        // From `dev/X` → `../Volumes/linux/dev/X` → host `/dev/X`.
        let target = format!("../{VOLUMES_LINUX}/dev/{name}");
        std::os::unix::fs::symlink(target, &link_path)?;
    }
    Ok(())
}

/// Guest-relative path for the OpenSSH client bridge (`PATH` includes `/usr/bin`).
pub const GUEST_SSH_REL: &str = "usr/bin/ssh";

/// Relative symlink target: host `/usr/bin/ssh` via the Linux bridge.
/// From `usr/bin/ssh` → two levels up to bottle root, then into the bridge.
const GUEST_SSH_TARGET: &str = "../../Volumes/linux/usr/bin/ssh";

/// Ensure guest `/usr/bin/ssh` → host OpenSSH (`/usr/bin/ssh`).
///
/// Apple CLT does not ship OpenSSH (base macOS does). Git SSH remotes
/// (`git@host:path`, `ssh://…`) `execvp("ssh")`. Bridging to the **host**
/// client is clean-room product policy: we do not reimplement the SSH protocol
/// in freestanding libSystem. Nested Mach-O helpers still re-exec via `kh`;
/// this path is a native host ELF (see `reexec_direct` + host env rewrite).
///
/// Idempotent. Does not require host `ssh` to exist at ensure time (broken
/// symlink → guest `ENOENT` on exec, same as missing binary).
pub fn ensure_host_ssh_bridge(root: &Path) -> io::Result<()> {
    let link_path = root.join(GUEST_SSH_REL);
    if let Ok(meta) = link_path.symlink_metadata() {
        if meta.file_type().is_symlink() {
            let target = fs::read_link(&link_path)?;
            if target == Path::new(GUEST_SSH_TARGET) {
                return Ok(());
            }
            // Wrong target: replace so bottle ensure always lands the bridge.
            fs::remove_file(&link_path)?;
        } else {
            // Real file (e.g. user-dropped binary) — leave alone.
            return Ok(());
        }
    }
    if let Some(parent) = link_path.parent() {
        fs::create_dir_all(parent)?;
    }
    std::os::unix::fs::symlink(GUEST_SSH_TARGET, &link_path)
}

/// Returns `true` if the bottle has the host OpenSSH bridge symlink.
#[must_use]
pub fn has_host_ssh_bridge(root: &Path) -> bool {
    let link_path = root.join(GUEST_SSH_REL);
    match fs::read_link(&link_path) {
        Ok(target) => target == Path::new(GUEST_SSH_TARGET),
        Err(_) => false,
    }
}

/// Host ELF bridges under guest `/bin` (shell for `GIT_SSH_COMMAND`, etc.).
const HOST_BIN_BRIDGES: &[(&str, &str)] = &[
    // `git` runs `GIT_SSH_COMMAND` as `sh -c '…' "$@"` — needs a real shell.
    ("bin/sh", "../Volumes/linux/bin/sh"),
    ("bin/bash", "../Volumes/linux/bin/bash"),
];

/// Ensure guest `/bin/sh` (and friends) → host shells via the Linux bridge.
///
/// Idempotent. Skips paths that already exist as non-symlink files.
pub fn ensure_host_bin_bridges(root: &Path) -> io::Result<()> {
    for &(rel, target) in HOST_BIN_BRIDGES {
        let link_path = root.join(rel);
        if let Ok(meta) = link_path.symlink_metadata() {
            if meta.file_type().is_symlink() {
                let cur = fs::read_link(&link_path)?;
                if cur == Path::new(target) {
                    continue;
                }
                fs::remove_file(&link_path)?;
            } else {
                continue;
            }
        }
        if let Some(parent) = link_path.parent() {
            fs::create_dir_all(parent)?;
        }
        std::os::unix::fs::symlink(target, &link_path)?;
    }
    Ok(())
}

/// Ensures `usr/lib/libc++.1.dylib` → `libSystem.B.dylib` (relative) under `root`.
///
/// Idempotent: existing correct symlink is left alone. A pre-existing non-symlink
/// file at that path is an error so we never clobber a real dylib.
pub fn ensure_libcxx_symlink(root: &Path) -> io::Result<()> {
    ensure_lib_alias_symlink(root, GUEST_LIBCXX_REL, GUEST_LIBCXX_TARGET, false)
}

/// Returns `true` if the bottle has the libc++ → libSystem alias symlink.
#[must_use]
pub fn has_libcxx_symlink(root: &Path) -> bool {
    let link_path = root.join(GUEST_LIBCXX_REL);
    match fs::read_link(&link_path) {
        Ok(target) => target == Path::new(GUEST_LIBCXX_TARGET),
        Err(_) => false,
    }
}

/// Ensures `usr/lib/libcurl.4.dylib` → `libSystem.B.dylib` (relative) under `root`.
///
/// Idempotent for a correct symlink. A pre-existing **regular file** at that
/// path (e.g. a temporary third-party dylib drop) is replaced by the alias so
/// freestanding exports always win after `kh bottle ensure`.
pub fn ensure_libcurl_symlink(root: &Path) -> io::Result<()> {
    ensure_lib_alias_symlink(root, GUEST_LIBCURL_REL, GUEST_LIBCURL_TARGET, true)
}

/// Returns `true` if the bottle has the libcurl → libSystem alias symlink.
#[must_use]
pub fn has_libcurl_symlink(root: &Path) -> bool {
    let link_path = root.join(GUEST_LIBCURL_REL);
    match fs::read_link(&link_path) {
        Ok(target) => target == Path::new(GUEST_LIBCURL_TARGET),
        Err(_) => false,
    }
}

/// Ensures `usr/lib/libxar.1.dylib` → freestanding libSystem (ld-classic / G4).
pub(crate) fn ensure_libxar_symlink(root: &Path) -> io::Result<()> {
    ensure_lib_alias_symlink(root, GUEST_LIBXAR_REL, GUEST_LIBXAR_TARGET, true)
}

/// Ensures `usr/lib/libz.1.dylib` → freestanding libSystem.
pub(crate) fn ensure_libz_symlink(root: &Path) -> io::Result<()> {
    ensure_lib_alias_symlink(root, GUEST_LIBZ_REL, GUEST_LIBZ_TARGET, true)
}

/// Shared install-name alias helper (libc++ / libcurl → freestanding libSystem).
///
/// When `replace_file` is true, a non-symlink file is removed and replaced.
fn ensure_lib_alias_symlink(
    root: &Path,
    rel: &str,
    target_name: &str,
    replace_file: bool,
) -> io::Result<()> {
    let link_path = root.join(rel);
    if let Ok(meta) = link_path.symlink_metadata() {
        if meta.file_type().is_symlink() {
            let target = fs::read_link(&link_path)?;
            if target == Path::new(target_name) {
                return Ok(());
            }
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                format!(
                    "{} already exists as symlink to {} (expected {})",
                    link_path.display(),
                    target.display(),
                    target_name
                ),
            ));
        }
        if replace_file {
            fs::remove_file(&link_path)?;
        } else {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                format!(
                    "{} already exists and is not a symlink",
                    link_path.display()
                ),
            ));
        }
    }
    if let Some(parent) = link_path.parent() {
        fs::create_dir_all(parent)?;
    }
    std::os::unix::fs::symlink(target_name, &link_path)
}

/// Creates `link` as a relative symlink to `target` under `root`, if absent.
fn symlink_rel(root: &Path, target: &str, link: &str) -> io::Result<()> {
    let link_path = root.join(link);
    if link_path.exists() || link_path.symlink_metadata().is_ok() {
        return Ok(());
    }
    std::os::unix::fs::symlink(target, &link_path)
}

/// Removes an entire bottle directory tree. Caller must confirm.
pub(super) fn remove_tree(root: &Path) -> io::Result<()> {
    if !root.exists() {
        return Ok(());
    }
    fs::remove_dir_all(root)
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    fn temp_root(prefix: &str) -> std::path::PathBuf {
        static N: AtomicU64 = AtomicU64::new(0);
        let n = N.fetch_add(1, Ordering::Relaxed);
        let dir =
            std::env::temp_dir().join(format!("kh-layout-{}-{}-{n}", prefix, std::process::id()));
        drop(fs::remove_dir_all(&dir));
        dir
    }

    #[test]
    fn materialize_creates_marker_and_skeleton() {
        let root = temp_root("mat");
        materialize(&root).expect("materialize");
        assert!(is_bottle_root(&root));
        assert!(root.join("usr/lib").is_dir());
        assert!(root.join("Applications").is_dir());
        assert!(root.join("private/etc").is_dir());
        assert!(root.join("etc").is_symlink());
        assert!(root.join("tmp").is_symlink());
        assert!(root.join("var").is_symlink());
        assert!(root.join(VOLUMES_LINUX).is_symlink());
        assert!(has_libcxx_symlink(&root));
        assert!(has_libcurl_symlink(&root));
        assert!(has_host_ssh_bridge(&root));
        let cxx = fs::read_link(root.join(GUEST_LIBCXX_REL)).expect("libcxx readlink");
        assert_eq!(cxx, Path::new(GUEST_LIBCXX_TARGET));
        let curl = fs::read_link(root.join(GUEST_LIBCURL_REL)).expect("libcurl readlink");
        assert_eq!(curl, Path::new(GUEST_LIBCURL_TARGET));
        let ssh = fs::read_link(root.join(GUEST_SSH_REL)).expect("ssh readlink");
        assert_eq!(ssh, Path::new(GUEST_SSH_TARGET));
        let sh = fs::read_link(root.join("bin/sh")).expect("bin/sh readlink");
        assert_eq!(sh, Path::new("../Volumes/linux/bin/sh"));

        let target = fs::read_link(root.join(VOLUMES_LINUX)).expect("readlink");
        assert_eq!(target, Path::new("/"));

        let null = fs::read_link(root.join("dev/null")).expect("dev/null");
        assert_eq!(null, Path::new(&format!("../{VOLUMES_LINUX}/dev/null")));

        // Idempotent ensure after materialize.
        ensure_libcxx_symlink(&root).expect("ensure again");
        ensure_dev_nodes(&root).expect("dev nodes again");
        ensure_host_ssh_bridge(&root).expect("ssh bridge again");
        ensure_host_bin_bridges(&root).expect("bin bridges again");

        fs::remove_dir_all(&root).expect("cleanup");
    }

    #[test]
    fn materialize_twice_fails() {
        let root = temp_root("twice");
        materialize(&root).expect("first");
        let err = materialize(&root).expect_err("second must fail");
        assert_eq!(err.kind(), io::ErrorKind::AlreadyExists);
        fs::remove_dir_all(&root).expect("cleanup");
    }

    #[test]
    fn volumes_linux_reaches_host_tmp() {
        let root = temp_root("vol");
        materialize(&root).expect("materialize");

        let token = format!("kh-vol-rw-{}", std::process::id());
        let host_file = std::env::temp_dir().join(&token);
        let payload = b"outside-bottle\n";
        fs::write(&host_file, payload).expect("write host");

        // Resolve guest /Volumes/linux/<temp>/<token> via the symlink.
        let via_bottle = root
            .join(VOLUMES_LINUX)
            .join(host_file.strip_prefix("/").expect("abs temp"));
        let read_back = fs::read(&via_bottle).expect("read via bottle");
        assert_eq!(read_back, payload);

        // Write from the bottle side and verify on the host.
        let payload2 = b"from-bottle\n";
        fs::write(&via_bottle, payload2).expect("write via bottle");
        let host_back = fs::read(&host_file).expect("read host");
        assert_eq!(host_back, payload2);

        drop(fs::remove_file(&host_file));
        fs::remove_dir_all(&root).expect("cleanup");
    }
}
