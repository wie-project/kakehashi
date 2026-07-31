//! Install-name → host path resolution with a map allowlist.
//!
//! Absolute guest paths require a bottle root and never probe host `/usr/...`
//! when `root` is `None`. Sibling paths under the executable directory remain
//! loadable without a bottle (`@executable_path` fixtures).

use std::path::{Component, Path, PathBuf};

use kh_runtime::translate_path_with_root;

/// Context for resolving one dependency install name.
#[derive(Debug, Clone, Copy)]
pub struct ResolveContext<'a> {
    /// Bottle root (`--root` / session root). Absolute installs require this.
    pub bottle_root: Option<&'a Path>,
    /// Directory containing the main executable (host path).
    pub executable_dir: &'a Path,
    /// Directory containing the image that holds this load command (host path).
    pub loader_dir: &'a Path,
    /// `LC_RPATH` strings: loader image first, then main (caller concatenates).
    pub rpaths: &'a [String],
}

/// Failures while turning an install name into an allowlisted host path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResolveError {
    /// Empty install name.
    Empty,
    /// Path contained `..` or otherwise escaped the intended tree.
    Escape(String),
    /// Nested `@rpath` inside an rpath value.
    NestedRpath,
    /// Absolute install name but session has no bottle root.
    NoBottle,
    /// Resolved path is outside bottle ∪ executable_dir.
    OutsideAllowlist(PathBuf),
    /// Path is not valid for the host OS string model.
    InvalidEncoding,
}

impl std::fmt::Display for ResolveError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Empty => write!(f, "empty install name"),
            Self::Escape(p) => write!(f, "path escape: {p}"),
            Self::NestedRpath => write!(f, "nested @rpath in LC_RPATH"),
            Self::NoBottle => write!(f, "absolute install name requires bottle root"),
            Self::OutsideAllowlist(p) => {
                write!(f, "path outside map allowlist: {}", p.display())
            }
            Self::InvalidEncoding => write!(f, "invalid path encoding"),
        }
    }
}

impl std::error::Error for ResolveError {}

/// Resolves `install_name` to a host path that is allowlisted for open+map.
///
/// Does **not** open or map the file. Callers apply soft-skip policy for most
/// errors; [`ResolveError::InvalidEncoding`] is treated as a hard load error.
pub fn resolve_install_name(
    install_name: &str,
    ctx: &ResolveContext<'_>,
) -> Result<PathBuf, ResolveError> {
    if install_name.is_empty() {
        return Err(ResolveError::Empty);
    }

    let host = if let Some(rest) = install_name.strip_prefix("@executable_path/") {
        join_no_dotdot(ctx.executable_dir, rest)?
    } else if install_name == "@executable_path" {
        ctx.executable_dir.to_path_buf()
    } else if let Some(rest) = install_name.strip_prefix("@loader_path/") {
        join_no_dotdot(ctx.loader_dir, rest)?
    } else if install_name == "@loader_path" {
        ctx.loader_dir.to_path_buf()
    } else if let Some(rest) = install_name.strip_prefix("@rpath/") {
        resolve_rpath(rest, ctx)?
    } else if install_name == "@rpath" {
        return Err(ResolveError::Empty);
    } else if install_name.starts_with('@') {
        // Unknown token — treat as escape/reject rather than relative join.
        return Err(ResolveError::Escape(install_name.to_owned()));
    } else if is_absolute_install_name(install_name) {
        resolve_absolute(install_name, ctx)?
    } else {
        // Relative (no leading `/`, no `@` token).
        join_no_dotdot(ctx.loader_dir, install_name)?
    };

    ensure_allowlisted(&host, ctx)?;
    Ok(host)
}

fn is_absolute_install_name(name: &str) -> bool {
    name.starts_with('/')
}

fn resolve_absolute(install_name: &str, ctx: &ResolveContext<'_>) -> Result<PathBuf, ResolveError> {
    let Some(root) = ctx.bottle_root else {
        // Host-safety: never exists()-probe absolute guest paths without a bottle.
        return Err(ResolveError::NoBottle);
    };
    translate_path_with_root(Some(root), install_name).map_err(path_err_to_resolve)
}

fn resolve_rpath(rest: &str, ctx: &ResolveContext<'_>) -> Result<PathBuf, ResolveError> {
    if rest.is_empty() {
        return Err(ResolveError::Empty);
    }

    let mut last_allowlisted: Option<PathBuf> = None;

    for rpath in ctx.rpaths {
        if rpath.contains("@rpath") {
            return Err(ResolveError::NestedRpath);
        }
        let base = expand_rpath_value(rpath, ctx)?;
        let candidate = join_no_dotdot(&base, rest)?;
        match ensure_allowlisted(&candidate, ctx) {
            Ok(()) => {
                if candidate.exists() {
                    return Ok(candidate);
                }
                last_allowlisted = Some(candidate);
            }
            Err(ResolveError::OutsideAllowlist(_)) => {}
            Err(err) => return Err(err),
        }
    }

    last_allowlisted.ok_or_else(|| ResolveError::OutsideAllowlist(PathBuf::from(rest)))
}

fn expand_rpath_value(rpath: &str, ctx: &ResolveContext<'_>) -> Result<PathBuf, ResolveError> {
    if rpath.is_empty() {
        return Err(ResolveError::Empty);
    }
    if let Some(rest) = rpath.strip_prefix("@executable_path/") {
        join_no_dotdot(ctx.executable_dir, rest)
    } else if rpath == "@executable_path" {
        Ok(ctx.executable_dir.to_path_buf())
    } else if let Some(rest) = rpath.strip_prefix("@loader_path/") {
        join_no_dotdot(ctx.loader_dir, rest)
    } else if rpath == "@loader_path" {
        Ok(ctx.loader_dir.to_path_buf())
    } else if rpath.starts_with('@') {
        Err(ResolveError::Escape(rpath.to_owned()))
    } else if is_absolute_install_name(rpath) {
        resolve_absolute(rpath, ctx)
    } else {
        // Relative LC_RPATH: anchor at loader directory.
        join_no_dotdot(ctx.loader_dir, rpath)
    }
}

fn join_no_dotdot(base: &Path, rest: &str) -> Result<PathBuf, ResolveError> {
    if rest.is_empty() {
        return Ok(base.to_path_buf());
    }
    let mut out = base.to_path_buf();
    for comp in Path::new(rest).components() {
        match comp {
            Component::Normal(s) => out.push(s),
            Component::CurDir => {}
            Component::ParentDir | Component::Prefix(_) | Component::RootDir => {
                return Err(ResolveError::Escape(rest.to_owned()));
            }
        }
    }
    Ok(out)
}

/// Map allowlist: under bottle root (when set) **or** under executable_dir.
///
/// Always resolves through canonicalize when the path exists so a bottle-local
/// symlink that points outside the allowlist is rejected (see unit test).
fn ensure_allowlisted(host: &Path, ctx: &ResolveContext<'_>) -> Result<(), ResolveError> {
    let check = path_for_allowlist_check(host);

    if let Some(root) = ctx.bottle_root {
        let root_canon = canonicalize_or_owned(root);
        if is_path_under(&check, &root_canon) {
            return Ok(());
        }
    }

    let exe_canon = canonicalize_or_owned(ctx.executable_dir);
    if is_path_under(&check, &exe_canon) {
        return Ok(());
    }

    Err(ResolveError::OutsideAllowlist(host.to_path_buf()))
}

fn path_for_allowlist_check(host: &Path) -> PathBuf {
    if host.exists() {
        return host
            .canonicalize()
            .unwrap_or_else(|_| lexical_normalize(host));
    }
    // Non-existent: canonicalize the longest existing prefix, then rejoin tail.
    canonicalize_with_missing_tail(host)
}

fn canonicalize_with_missing_tail(host: &Path) -> PathBuf {
    let mut components: Vec<_> = host.components().collect();
    let mut tail = Vec::new();
    while !components.is_empty() {
        let prefix: PathBuf = components.iter().collect();
        if prefix.exists() {
            let mut base = prefix.canonicalize().unwrap_or(prefix);
            for c in tail.into_iter().rev() {
                base.push(c);
            }
            return base;
        }
        if let Some(Component::Normal(s)) = components.pop() {
            tail.push(s.to_os_string());
        } else {
            break;
        }
    }
    lexical_normalize(host)
}

fn canonicalize_or_owned(path: &Path) -> PathBuf {
    path.canonicalize().unwrap_or_else(|_| path.to_path_buf())
}

fn lexical_normalize(path: &Path) -> PathBuf {
    let mut out = PathBuf::new();
    for comp in path.components() {
        match comp {
            Component::ParentDir => {
                let _ = out.pop();
            }
            Component::CurDir => {}
            other => out.push(other.as_os_str()),
        }
    }
    out
}

fn is_path_under(path: &Path, base: &Path) -> bool {
    path.starts_with(base)
}

fn path_err_to_resolve(err: kh_runtime::PathError) -> ResolveError {
    match err {
        kh_runtime::PathError::Empty => ResolveError::Empty,
        kh_runtime::PathError::Escape(s) => ResolveError::Escape(s),
        kh_runtime::PathError::InvalidEncoding => ResolveError::InvalidEncoding,
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;
    use std::fs::{self, File};
    use std::io::Write;

    fn ctx<'a>(
        bottle: Option<&'a Path>,
        exe_dir: &'a Path,
        loader_dir: &'a Path,
        rpaths: &'a [String],
    ) -> ResolveContext<'a> {
        ResolveContext {
            bottle_root: bottle,
            executable_dir: exe_dir,
            loader_dir,
            rpaths,
        }
    }

    #[test]
    fn absolute_without_bottle_is_no_bottle() {
        let exe = Path::new("/tmp/kh-exe-dir");
        let c = ctx(None, exe, exe, &[]);
        let err = resolve_install_name("/usr/lib/libSystem.B.dylib", &c).unwrap_err();
        assert_eq!(err, ResolveError::NoBottle);
    }

    #[test]
    fn absolute_with_bottle_under_root() {
        let root = std::env::temp_dir().join(format!("kh-resolve-bottle-{}", std::process::id()));
        let lib_dir = root.join("usr/lib");
        fs::create_dir_all(&lib_dir).unwrap();
        let lib = lib_dir.join("libFoo.dylib");
        File::create(&lib).unwrap().write_all(b"x").unwrap();

        let exe = root.join("bin");
        fs::create_dir_all(&exe).unwrap();

        let c = ctx(Some(root.as_path()), &exe, &exe, &[]);
        let host = resolve_install_name("/usr/lib/libFoo.dylib", &c).unwrap();
        assert_eq!(host, lib);
        drop(fs::remove_dir_all(root));
    }

    #[test]
    fn executable_path_relative() {
        let dir = std::env::temp_dir().join(format!("kh-resolve-exe-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let dylib = dir.join("libkh_add.dylib");
        File::create(&dylib).unwrap().write_all(b"x").unwrap();

        let c = ctx(None, &dir, &dir, &[]);
        let host = resolve_install_name("@executable_path/libkh_add.dylib", &c).unwrap();
        assert_eq!(host, dylib);
        drop(fs::remove_dir_all(dir));
    }

    #[test]
    fn loader_path_relative() {
        // Allowlist is bottle ∪ executable_dir; nested loaders must sit under that tree.
        let exe_dir =
            std::env::temp_dir().join(format!("kh-resolve-loader-{}", std::process::id()));
        let loader = exe_dir.join("Frameworks");
        fs::create_dir_all(&loader).unwrap();
        let dylib = loader.join("Inner.dylib");
        File::create(&dylib).unwrap().write_all(b"x").unwrap();

        let c = ctx(None, &exe_dir, &loader, &[]);
        let host = resolve_install_name("@loader_path/Inner.dylib", &c).unwrap();
        assert_eq!(host, dylib);
        drop(fs::remove_dir_all(exe_dir));
    }

    #[test]
    fn rpath_first_hit() {
        let dir = std::env::temp_dir().join(format!("kh-resolve-rpath-{}", std::process::id()));
        let a = dir.join("a");
        let b = dir.join("b");
        fs::create_dir_all(&a).unwrap();
        fs::create_dir_all(&b).unwrap();
        // Only b has the file.
        let target = b.join("libX.dylib");
        File::create(&target).unwrap().write_all(b"x").unwrap();

        let rpaths = vec![
            "@executable_path/a".to_owned(),
            "@executable_path/b".to_owned(),
        ];
        let c = ctx(None, &dir, &dir, &rpaths);
        let host = resolve_install_name("@rpath/libX.dylib", &c).unwrap();
        assert_eq!(host, target);
        drop(fs::remove_dir_all(dir));
    }

    #[test]
    fn rejects_dotdot() {
        let exe = Path::new("/tmp/kh-exe");
        let c = ctx(None, exe, exe, &[]);
        let err = resolve_install_name("@executable_path/../etc/passwd", &c).unwrap_err();
        assert!(matches!(err, ResolveError::Escape(_)));
    }

    #[test]
    fn bottle_symlink_escape_rejected() {
        let root = std::env::temp_dir().join(format!("kh-resolve-symlink-{}", std::process::id()));
        let outside =
            std::env::temp_dir().join(format!("kh-resolve-outside-{}", std::process::id()));
        fs::create_dir_all(&root).unwrap();
        fs::create_dir_all(&outside).unwrap();
        let outside_lib = outside.join("evil.dylib");
        File::create(&outside_lib).unwrap().write_all(b"x").unwrap();

        let link = root.join("escape.dylib");
        #[cfg(unix)]
        std::os::unix::fs::symlink(&outside_lib, &link).unwrap();

        let exe = root.join("bin");
        fs::create_dir_all(&exe).unwrap();

        let c = ctx(Some(root.as_path()), &exe, &exe, &[]);
        // Absolute install name maps under bottle, but canonicalize follows the
        // symlink outside → OutsideAllowlist.
        let result = resolve_install_name("/escape.dylib", &c);
        assert!(
            matches!(result, Err(ResolveError::OutsideAllowlist(_))),
            "expected OutsideAllowlist, got {result:?}"
        );

        drop(fs::remove_dir_all(root));
        drop(fs::remove_dir_all(outside));
    }

    #[test]
    fn absolute_planted_host_path_still_no_bottle() {
        // Even if a file exists at the absolute path, without a bottle we must
        // not resolve it (no exists probe / no map candidate).
        let planted =
            std::env::temp_dir().join(format!("kh-fake-libsystem-{}", std::process::id()));
        File::create(&planted).unwrap().write_all(b"x").unwrap();
        let abs = planted.to_str().expect("utf8 temp path");
        let exe = Path::new("/tmp/kh-exe-dir");
        let c = ctx(None, exe, exe, &[]);
        let err = resolve_install_name(abs, &c).unwrap_err();
        assert_eq!(err, ResolveError::NoBottle);
        drop(fs::remove_file(planted));
    }
}
