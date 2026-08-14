//! Host PATH wrappers (`sh`, `curl`, … → `kh`) so `| sh` stays in the bottle.
//!
//! First `kh` invocation creates `host-bin` and, once, prepends it on the
//! user's `~/.profile` / `~/.bashrc` / `~/.zshrc`. No per-session `eval`.

use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde_json::json;

/// Bottle tools exposed as host `argv0` aliases of `kh`.
pub(crate) const WRAPPER_NAMES: &[&str] = &[
    "sh",
    "bash",
    "zsh",
    "dash",
    "curl",
    "git",
    "rustup",
    "rustup-init",
    "cargo",
    "rustc",
    "clang",
    "cc",
    "make",
    "7zz",
];

const RC_MARK: &str = "# kakehashi host-bin";

/// Directory under the data dir that holds `sh` → `kh` symlinks.
pub(crate) fn host_bin_dir() -> Result<PathBuf> {
    Ok(kh_runtime::bottle::data_dir()
        .context("resolve KAKEHASHI_DATA_DIR")?
        .join("host-bin"))
}

/// True when `argv0` basename is a published wrapper (not `kh` itself).
#[must_use]
pub(crate) fn invoked_wrapper_name() -> Option<String> {
    let arg0 = std::env::args_os().next()?;
    let name = Path::new(&arg0).file_name()?.to_str()?.to_owned();
    if name == "kh" || name == "kh.exe" {
        return None;
    }
    WRAPPER_NAMES.iter().any(|n| *n == name).then_some(name)
}

/// Create wrappers + one-time shell PATH. Prints `export PATH=…` (eval still works).
pub(crate) fn run(json: bool) -> Result<()> {
    let dir = ensure()?;
    if json {
        println!(
            "{}",
            json!({
                "path": dir.display().to_string(),
                "names": WRAPPER_NAMES,
            })
        );
        return Ok(());
    }
    println!("export PATH=\"{}:${{PATH}}\"", dir.display());
    Ok(())
}

/// Materialize host-bin and persist PATH in login/rc files (idempotent).
pub(crate) fn ensure() -> Result<PathBuf> {
    let dir = ensure_host_bin()?;
    install_shell_path(&dir);
    Ok(dir)
}

/// Materialize `host-bin/<name>` → current `kh` for each wrapper name.
pub(crate) fn ensure_host_bin() -> Result<PathBuf> {
    let dir = host_bin_dir()?;
    fs::create_dir_all(&dir).with_context(|| format!("create {}", dir.display()))?;
    let kh = std::env::current_exe().context("current kh executable")?;
    for name in WRAPPER_NAMES {
        let link = dir.join(name);
        match fs::symlink_metadata(&link) {
            Ok(meta) if meta.file_type().is_symlink() => {
                if fs::read_link(&link).ok().as_ref() == Some(&kh) {
                    continue;
                }
                fs::remove_file(&link).with_context(|| format!("replace {}", link.display()))?;
            }
            Ok(_) => {
                fs::remove_file(&link).with_context(|| format!("replace {}", link.display()))?;
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => return Err(e).with_context(|| format!("stat {}", link.display())),
        }
        std::os::unix::fs::symlink(&kh, &link)
            .with_context(|| format!("symlink {} → {}", link.display(), kh.display()))?;
    }
    Ok(dir)
}

/// Append a one-time `export PATH=host-bin:…` to common shell rc files.
fn install_shell_path(host_bin: &Path) {
    let Ok(home) = std::env::var("HOME") else {
        return;
    };
    let home = PathBuf::from(home);
    let line = format!("export PATH=\"{}:${{PATH}}\"", host_bin.display());
    let block = format!("\n{RC_MARK}\n{line}\n");
    for name in [".profile", ".bashrc", ".zshrc"] {
        drop(append_rc_once(&home.join(name), &block));
    }
}

fn append_rc_once(path: &Path, block: &str) -> io::Result<()> {
    if let Ok(existing) = fs::read_to_string(path)
        && existing.contains(RC_MARK)
    {
        return Ok(());
    }
    let mut f = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)?;
    f.write_all(block.as_bytes())
}

/// One-line hint after `kh bottle ensure` (human output only).
pub(crate) fn write_hint(out: &mut impl Write) -> io::Result<()> {
    writeln!(
        out,
        "  host PATH: host-bin prepended in ~/.profile ~/.bashrc ~/.zshrc (once)"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wrapper_set_includes_shells_and_curl() {
        assert!(WRAPPER_NAMES.contains(&"sh"));
        assert!(WRAPPER_NAMES.contains(&"curl"));
        assert!(WRAPPER_NAMES.contains(&"rustup-init"));
        assert!(!WRAPPER_NAMES.contains(&"kh"));
    }

    #[test]
    fn rc_mark_is_stable() {
        assert!(RC_MARK.contains("kakehashi"));
    }

    #[test]
    fn append_rc_is_idempotent() {
        let dir = std::env::temp_dir().join(format!("kh-env-rc-{}", std::process::id()));
        drop(fs::create_dir_all(&dir));
        let rc = dir.join(".bashrc");
        let block = format!("\n{RC_MARK}\nexport PATH=\"/tmp/host-bin:${{PATH}}\"\n");
        append_rc_once(&rc, &block).unwrap();
        append_rc_once(&rc, &block).unwrap();
        let text = fs::read_to_string(&rc).unwrap();
        assert_eq!(text.matches(RC_MARK).count(), 1);
        drop(fs::remove_dir_all(&dir));
    }
}
