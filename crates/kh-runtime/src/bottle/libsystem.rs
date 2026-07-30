//! Install guest `libSystem.B.dylib` into a bottle.
//!
//! Discovery / install order used by `kh bottle create|ensure`:
//!
//! 1. **`--libsystem PATH`** / explicit argument
//! 2. **`KAKEHASHI_LIBSYSTEM`**
//! 3. Paths next to the running `kh` binary (release layout:
//!    `lib/kakehashi/libSystem.B.dylib`, …)
//! 4. Workspace / dev trees: Cargo `target/…` and the vendored crate resource
//!    `crates/kh-runtime/resources/libSystem.B.dylib`
//! 5. **Embedded bytes** shipped inside `kh-runtime` (`resources/libSystem.B.dylib`
//!    on crates.io) — so `cargo install kakehashi` works with only
//!    `kh bottle ensure` and no separate dylib download
//!
//! Build / refresh the freestanding dylib (macOS or cross target):
//! ```text
//! cargo build -p kh-libsystem --release --target aarch64-apple-darwin
//! ./scripts/stage-libsystem.sh   # → crates/kh-runtime/resources/ (crates.io embed)
//! ```

use std::fs;
use std::path::{Path, PathBuf};

use super::manage::BottleError;

/// Relative path under the bottle root (guest `/usr/lib/libSystem.B.dylib`).
pub const GUEST_LIBSYSTEM_REL: &str = "usr/lib/libSystem.B.dylib";

/// Canonical `LC_ID_DYLIB` / guest install name.
pub const GUEST_LIBSYSTEM_ID: &str = "/usr/lib/libSystem.B.dylib";

/// Env var for an explicit source dylib (release unpack or custom path).
pub const ENV_LIBSYSTEM: &str = "KAKEHASHI_LIBSYSTEM";

/// Synthetic `LibsystemInstall::source` when bytes came from the crate embed.
pub const EMBEDDED_SOURCE_LABEL: &str = "<embedded>";

const MH_MAGIC_64: u32 = 0xfeed_facf;
const LC_ID_DYLIB: u32 = 0xd;

/// How the source dylib was located.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LibsystemOrigin {
    /// `--libsystem` / explicit path.
    Explicit,
    /// `KAKEHASHI_LIBSYSTEM`.
    Env,
    /// Next to the `kh` binary (release layout or `target/debug/kh`).
    Adjacent,
    /// Workspace `target/` / crate `resources/` under cwd.
    DevTarget,
    /// Bytes compiled into `kh-runtime` (crates.io / `cargo install` path).
    Embedded,
}

/// Result of installing libSystem into a bottle.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LibsystemInstall {
    /// Host path of the source dylib that was copied, or
    /// [`EMBEDDED_SOURCE_LABEL`] when installed from the crate embed.
    pub source: PathBuf,
    /// Absolute path of `{bottle}/usr/lib/libSystem.B.dylib`.
    pub dest: PathBuf,
    /// Where `source` was found.
    pub origin: LibsystemOrigin,
    /// Whether `LC_ID_DYLIB` was rewritten to [`GUEST_LIBSYSTEM_ID`].
    pub id_rewritten: bool,
}

/// Discovers a guest libSystem dylib **file** for bottle install.
///
/// Does not cover the compile-time embed — that is handled by bottle create
/// after this returns `None` (see `manage`).
///
/// Order:
/// 1. `explicit` argument
/// 2. `KAKEHASHI_LIBSYSTEM`
/// 3. Paths relative to the running `kh` executable (release layout)
/// 4. Common Cargo / staged paths under the current working directory
#[must_use]
pub fn discover(explicit: Option<&Path>) -> Option<(PathBuf, LibsystemOrigin)> {
    if let Some(p) = explicit {
        if p.is_file() {
            return Some((p.to_path_buf(), LibsystemOrigin::Explicit));
        }
        return None;
    }

    if let Ok(raw) = std::env::var(ENV_LIBSYSTEM) {
        let p = PathBuf::from(raw);
        if p.is_file() {
            return Some((p, LibsystemOrigin::Env));
        }
    }

    if let Some(p) = discover_adjacent() {
        return Some((p, LibsystemOrigin::Adjacent));
    }

    if let Some(p) = discover_dev_target() {
        return Some((p, LibsystemOrigin::DevTarget));
    }

    None
}

/// Copies `source` into `{root}/usr/lib/libSystem.B.dylib` and ensures
/// `LC_ID_DYLIB` is [`GUEST_LIBSYSTEM_ID`] (in-place rewrite when needed).
pub fn install(
    root: &Path,
    source: &Path,
    origin: LibsystemOrigin,
) -> Result<LibsystemInstall, BottleError> {
    if !source.is_file() {
        return Err(BottleError::Io(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            format!("libSystem source not found: {}", source.display()),
        )));
    }

    let bytes = fs::read(source)?;
    let mut result = install_bytes(root, &bytes, origin)?;
    result.source = source.to_path_buf();
    Ok(result)
}

/// Writes raw Mach-O bytes into `{root}/usr/lib/libSystem.B.dylib`, rewriting
/// `LC_ID_DYLIB` when needed. Used for the crates.io-embedded freestanding
/// dylib and by [`install`] after reading a file.
pub fn install_bytes(
    root: &Path,
    source_bytes: &[u8],
    origin: LibsystemOrigin,
) -> Result<LibsystemInstall, BottleError> {
    if source_bytes.is_empty() {
        return Err(BottleError::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "libSystem source is empty",
        )));
    }

    let dest = root.join(GUEST_LIBSYSTEM_REL);
    if let Some(parent) = dest.parent() {
        fs::create_dir_all(parent)?;
    }

    let mut bytes = source_bytes.to_vec();
    let id_rewritten = ensure_libsystem_id(&mut bytes)?;
    fs::write(&dest, &bytes)?;

    // Match typical dylib mode (rwxr-xr-x); ignore errors on exotic FS.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        drop(fs::set_permissions(
            &dest,
            fs::Permissions::from_mode(0o755),
        ));
    }

    Ok(LibsystemInstall {
        source: PathBuf::from(EMBEDDED_SOURCE_LABEL),
        dest,
        origin,
        id_rewritten,
    })
}

/// Ensures thin little-endian Mach-O `LC_ID_DYLIB` is [`GUEST_LIBSYSTEM_ID`].
///
/// Returns `true` if the load-command path was rewritten. Fat binaries and
/// big-endian images are rejected (guest dylib is always thin arm64).
pub fn ensure_libsystem_id(bytes: &mut [u8]) -> Result<bool, BottleError> {
    patch_lc_id_dylib(bytes, GUEST_LIBSYSTEM_ID)
}

fn discover_adjacent() -> Option<PathBuf> {
    let exe = std::env::current_exe().ok()?;
    let dir = exe.parent()?;
    let candidates = [
        dir.join("libSystem.B.dylib"),
        dir.join("libkh_libsystem.dylib"),
        dir.join("lib/kakehashi/libSystem.B.dylib"),
        dir.join("lib/kakehashi/libkh_libsystem.dylib"),
        dir.join("../lib/kakehashi/libSystem.B.dylib"),
        dir.join("../lib/kakehashi/libkh_libsystem.dylib"),
        dir.join("share/kakehashi/libSystem.B.dylib"),
        dir.join("../share/kakehashi/libSystem.B.dylib"),
    ];
    first_file(&candidates)
}

fn discover_dev_target() -> Option<PathBuf> {
    let cwd = std::env::current_dir().ok()?;
    // Walk cwd → parents so Docker `-w /src` and nested shells still find a
    // workspace-staged dylib without hand-building `.tmp-bottle`.
    let mut dir = Some(cwd.as_path());
    while let Some(base) = dir {
        if let Some(p) = discover_under_workspace(base) {
            return Some(p);
        }
        dir = base.parent();
    }
    None
}

/// Candidate relative paths under a Cargo / release workspace root.
fn discover_under_workspace(base: &Path) -> Option<PathBuf> {
    let names = ["libSystem.B.dylib", "libkh_libsystem.dylib"];
    // Prefer a just-built product, then the staged crates.io embed path.
    let dirs = [
        "target/aarch64-apple-darwin/release",
        "target/aarch64-apple-darwin/debug",
        "target/release",
        "target/debug",
        // Vendored crates.io embed (same bytes as `include_bytes!` in manage).
        "crates/kh-runtime/resources",
        "resources",
    ];
    let mut candidates = Vec::new();
    for d in dirs {
        for n in names {
            candidates.push(base.join(d).join(n));
        }
    }
    first_file(&candidates)
}

fn first_file(paths: &[PathBuf]) -> Option<PathBuf> {
    paths.iter().find(|p| p.is_file()).cloned()
}

fn patch_lc_id_dylib(bytes: &mut [u8], new_id: &str) -> Result<bool, BottleError> {
    if bytes.len() < 32 {
        return Err(id_err("file too small to be Mach-O"));
    }

    let magic = read_u32_le(bytes, 0)?;
    if magic == 0xcafe_babe || magic == 0xcafe_babf || magic == 0xbeba_feca || magic == 0xbfba_feca
    {
        return Err(id_err(
            "fat Mach-O is not supported; ship a thin aarch64 libSystem.B.dylib",
        ));
    }
    if magic != MH_MAGIC_64 {
        return Err(id_err(format!(
            "not a little-endian 64-bit Mach-O (magic {magic:#x})"
        )));
    }

    let ncmds = usize_from_u32(read_u32_le(bytes, 16)?)?;
    let sizeofcmds = usize_from_u32(read_u32_le(bytes, 20)?)?;
    let cmds_start = 32usize;
    let cmds_end = cmds_start
        .checked_add(sizeofcmds)
        .ok_or_else(|| id_err("sizeofcmds overflow"))?;
    if cmds_end > bytes.len() {
        return Err(id_err("load commands extend past file"));
    }

    let mut off = cmds_start;
    for _ in 0..ncmds {
        if off.checked_add(8).is_none_or(|e| e > cmds_end) {
            return Err(id_err("truncated load command"));
        }
        let cmd = read_u32_le(bytes, off)?;
        let cmdsize = usize_from_u32(read_u32_le(bytes, off.saturating_add(4))?)?;
        if cmdsize < 8 {
            return Err(id_err("invalid load command size"));
        }
        let cmd_end = off
            .checked_add(cmdsize)
            .ok_or_else(|| id_err("cmdsize overflow"))?;
        if cmd_end > cmds_end {
            return Err(id_err("load command extends past sizeofcmds"));
        }

        if cmd == LC_ID_DYLIB {
            return rewrite_id_name(bytes, off, cmdsize, new_id);
        }
        off = cmd_end;
    }
    Err(id_err("LC_ID_DYLIB not found"))
}

fn rewrite_id_name(
    bytes: &mut [u8],
    cmd_off: usize,
    cmdsize: usize,
    new_id: &str,
) -> Result<bool, BottleError> {
    // struct dylib_command { cmd, cmdsize, dylib { name.offset, timestamp, current, compat } }
    if cmdsize < 24 {
        return Err(id_err("LC_ID_DYLIB too small"));
    }
    let name_off = usize_from_u32(read_u32_le(bytes, cmd_off.saturating_add(8))?)?;
    if name_off >= cmdsize {
        return Err(id_err("LC_ID_DYLIB name offset out of range"));
    }
    let name_start = cmd_off
        .checked_add(name_off)
        .ok_or_else(|| id_err("name offset overflow"))?;
    let name_cap = cmdsize
        .checked_sub(name_off)
        .ok_or_else(|| id_err("name capacity underflow"))?;
    let new_bytes = new_id.as_bytes();
    let need = new_bytes
        .len()
        .checked_add(1)
        .ok_or_else(|| id_err("new id length overflow"))?;
    if need > name_cap {
        return Err(id_err(format!(
            "LC_ID_DYLIB name field too short for {new_id} (cap {name_cap})"
        )));
    }

    let cmd_end = cmd_off
        .checked_add(cmdsize)
        .ok_or_else(|| id_err("cmd end overflow"))?;
    let field = bytes
        .get(name_start..cmd_end)
        .ok_or_else(|| id_err("name field out of range"))?;
    let old_len = field.iter().position(|&c| c == 0).unwrap_or(field.len());
    let old = field
        .get(..old_len)
        .ok_or_else(|| id_err("old name slice"))?;
    if old == new_bytes {
        return Ok(false);
    }

    let dest = bytes
        .get_mut(name_start..cmd_end)
        .ok_or_else(|| id_err("name field mut out of range"))?;
    if new_bytes.len() > dest.len() {
        return Err(id_err("new id does not fit"));
    }
    let (head, tail) = dest.split_at_mut(new_bytes.len());
    head.copy_from_slice(new_bytes);
    for b in tail {
        *b = 0;
    }
    Ok(true)
}

fn read_u32_le(bytes: &[u8], off: usize) -> Result<u32, BottleError> {
    let end = off
        .checked_add(4)
        .ok_or_else(|| id_err("u32 offset overflow"))?;
    let raw = bytes
        .get(off..end)
        .ok_or_else(|| id_err("out of range u32"))?;
    let arr: [u8; 4] = raw.try_into().map_err(|_| id_err("u32 slice length"))?;
    Ok(u32::from_le_bytes(arr))
}

fn usize_from_u32(v: u32) -> Result<usize, BottleError> {
    usize::try_from(v).map_err(|_| id_err("u32 does not fit usize"))
}

fn id_err(msg: impl Into<String>) -> BottleError {
    BottleError::Io(std::io::Error::new(
        std::io::ErrorKind::InvalidData,
        msg.into(),
    ))
}

#[cfg(test)]
#[allow(
    clippy::expect_used,
    clippy::panic,
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::as_conversions,
    clippy::cast_possible_truncation,
    clippy::arithmetic_side_effects
)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    fn temp_dir(prefix: &str) -> PathBuf {
        static N: AtomicU64 = AtomicU64::new(0);
        let n = N.fetch_add(1, Ordering::Relaxed);
        let dir =
            std::env::temp_dir().join(format!("kh-libsys-{}-{}-{n}", prefix, std::process::id()));
        drop(fs::remove_dir_all(&dir));
        fs::create_dir_all(&dir).expect("mkdir");
        dir
    }

    /// Minimal MH_DYLIB with LC_ID_DYLIB only (enough for the patcher).
    fn minimal_dylib(id: &str) -> Vec<u8> {
        const CPU_TYPE_ARM64: u32 = 0x0100_000c;
        const MH_DYLIB: u32 = 6;

        let mut name = id.as_bytes().to_vec();
        name.push(0);
        while !name.len().is_multiple_of(8) {
            name.push(0);
        }
        while name.len() < 40 {
            name.push(0);
        }
        let cmdsize = 24 + name.len();
        let sizeofcmds = u32::try_from(cmdsize).expect("cmdsize");
        let cmdsize_u = sizeofcmds;

        let mut buf = Vec::new();
        buf.extend_from_slice(&MH_MAGIC_64.to_le_bytes());
        buf.extend_from_slice(&CPU_TYPE_ARM64.to_le_bytes());
        buf.extend_from_slice(&0u32.to_le_bytes());
        buf.extend_from_slice(&MH_DYLIB.to_le_bytes());
        buf.extend_from_slice(&1u32.to_le_bytes());
        buf.extend_from_slice(&sizeofcmds.to_le_bytes());
        buf.extend_from_slice(&0u32.to_le_bytes());
        buf.extend_from_slice(&0u32.to_le_bytes());

        buf.extend_from_slice(&LC_ID_DYLIB.to_le_bytes());
        buf.extend_from_slice(&cmdsize_u.to_le_bytes());
        buf.extend_from_slice(&24u32.to_le_bytes());
        buf.extend_from_slice(&1u32.to_le_bytes());
        buf.extend_from_slice(&0x0001_0000u32.to_le_bytes());
        buf.extend_from_slice(&0x0001_0000u32.to_le_bytes());
        buf.extend_from_slice(&name);
        buf
    }

    fn read_id(bytes: &[u8]) -> String {
        let ncmds = u32::from_le_bytes(bytes[16..20].try_into().unwrap()) as usize;
        let mut off = 32usize;
        for _ in 0..ncmds {
            let cmd = u32::from_le_bytes(bytes[off..off + 4].try_into().unwrap());
            let cmdsize = u32::from_le_bytes(bytes[off + 4..off + 8].try_into().unwrap()) as usize;
            if cmd == LC_ID_DYLIB {
                let name_off =
                    u32::from_le_bytes(bytes[off + 8..off + 12].try_into().unwrap()) as usize;
                let start = off + name_off;
                let end = bytes[start..]
                    .iter()
                    .position(|&c| c == 0)
                    .map(|n| start + n)
                    .unwrap();
                return String::from_utf8(bytes[start..end].to_vec()).unwrap();
            }
            off += cmdsize;
        }
        panic!("no LC_ID_DYLIB");
    }

    #[test]
    fn rewrite_rpath_id_to_guest() {
        let mut bytes = minimal_dylib("@rpath/libkh_libsystem.dylib");
        assert_eq!(read_id(&bytes), "@rpath/libkh_libsystem.dylib");
        let changed = ensure_libsystem_id(&mut bytes).expect("patch");
        assert!(changed);
        assert_eq!(read_id(&bytes), GUEST_LIBSYSTEM_ID);
        let changed_again = ensure_libsystem_id(&mut bytes).expect("idempotent");
        assert!(!changed_again);
    }

    #[test]
    fn install_copies_and_sets_id() {
        let root = temp_dir("install");
        super::super::layout::materialize(&root).expect("materialize");
        let src_dir = temp_dir("src");
        let src = src_dir.join("libkh_libsystem.dylib");
        fs::write(&src, minimal_dylib("@rpath/libkh_libsystem.dylib")).expect("write src");

        let inst = install(&root, &src, LibsystemOrigin::Explicit).expect("install");
        assert!(inst.id_rewritten);
        assert_eq!(inst.dest, root.join(GUEST_LIBSYSTEM_REL));
        assert_eq!(inst.source, src);
        assert!(inst.dest.is_file());
        let on_disk = fs::read(&inst.dest).expect("read dest");
        assert_eq!(read_id(&on_disk), GUEST_LIBSYSTEM_ID);

        drop(fs::remove_dir_all(&root));
        drop(fs::remove_dir_all(&src_dir));
    }

    #[test]
    fn install_bytes_sets_embedded_label() {
        let root = temp_dir("bytes");
        super::super::layout::materialize(&root).expect("materialize");
        let raw = minimal_dylib("@rpath/libkh_libsystem.dylib");
        let inst = install_bytes(&root, &raw, LibsystemOrigin::Embedded).expect("install_bytes");
        assert_eq!(inst.source, PathBuf::from(EMBEDDED_SOURCE_LABEL));
        assert_eq!(inst.origin, LibsystemOrigin::Embedded);
        assert!(inst.id_rewritten);
        assert_eq!(
            read_id(&fs::read(&inst.dest).expect("read")),
            GUEST_LIBSYSTEM_ID
        );
        drop(fs::remove_dir_all(&root));
    }

    #[test]
    fn discover_explicit_missing_is_none() {
        assert!(discover(Some(Path::new("/no/such/libSystem.B.dylib"))).is_none());
    }

    #[test]
    fn rejects_fat_magic() {
        let mut bytes = vec![0u8; 64];
        bytes[0..4].copy_from_slice(&0xcafe_babeu32.to_be_bytes());
        let err = ensure_libsystem_id(&mut bytes).expect_err("fat");
        let msg = err.to_string();
        assert!(msg.contains("fat"), "{msg}");
    }
}
