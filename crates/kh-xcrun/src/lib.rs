//! Clean-room **xcrun** lookup/CLI logic (shared by host tests and guest bin).
//!
//! Behavior matches the public `xcrun(1)` surface used by Apple CLT shims
//! (`gcc` → `execv("/usr/bin/xcrun", ["xcrun", "clang", …])`) and by
//! Makefiles (`xcrun --show-sdk-path`, `xcrun --find …`).
//!
//! Not Apple code. The thin host binary on a real Mac only trampolines into
//! `xcselect_invoke_xcrun`; this crate reimplements that lookup/exec policy.

#![cfg_attr(not(test), no_std)]

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;

/// Default CLT developer directory (bottle / real Mac layout).
pub const DEFAULT_DEVELOPER_DIR: &str = "/Library/Developer/CommandLineTools";

/// Classic Xcode developer directory.
pub const XCODE_DEVELOPER_DIR: &str = "/Applications/Xcode.app/Contents/Developer";

/// System-wide `xcode-select` symlink (real macOS; optional in bottle).
pub const XCODE_SELECT_LINK: &str = "/var/db/xcode_select_link";

/// Guest install path for this tool.
pub const GUEST_XCRUN_PATH: &str = "/usr/bin/xcrun";

/// Result of parsing argv for xcrun.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
#[allow(clippy::struct_excessive_bools)] // mirrors independent CLI flags
pub struct ParsedArgs {
    /// Tool name from symlink invocation (`getprogname` ≠ `xcrun`), if any.
    pub tool_from_prog: Option<String>,
    /// Remaining argv after program name (and after xcrun option tokens).
    pub tool_args: Vec<String>,
    /// Explicit tool from positional when invoked as `xcrun`.
    pub tool: Option<String>,
    /// `--sdk` value.
    pub sdk: Option<String>,
    /// `--toolchain` value.
    pub toolchain: Option<String>,
    /// Find mode (`-f` / `--find`).
    pub find_only: bool,
    /// Verbose (`-v` / `--verbose`).
    pub verbose: bool,
    /// Log full command (`-l` / `--log`).
    pub log: bool,
    /// `--show-sdk-path`
    pub show_sdk_path: bool,
    /// `--show-sdk-version`
    pub show_sdk_version: bool,
    /// `--show-sdk-build-version`
    pub show_sdk_build_version: bool,
    /// `--show-sdk-platform-path`
    pub show_sdk_platform_path: bool,
    /// `--show-sdk-platform-version`
    pub show_sdk_platform_version: bool,
    /// `--show-toolchain-path`
    pub show_toolchain_path: bool,
    /// `--help`
    pub help: bool,
    /// `--version`
    pub version: bool,
}

/// Errors from xcrun lookup / CLI.
#[derive(Debug)]
pub enum XcrunError {
    /// Usage / missing required tool name.
    Usage(&'static str),
    /// Developer directory missing or unusable.
    NoDeveloperDir,
    /// Tool not found under developer dir / PATH.
    ToolNotFound,
    /// SDK not found.
    SdkNotFound,
    /// Generic I/O / exec failure.
    Io,
}

/// Strip a single leading `-` from `getprogname()`-style names (`-xcrun`).
#[must_use]
pub fn normalize_progname(name: &str) -> &str {
    name.strip_prefix('-').unwrap_or(name)
}

/// Whether `prog` (after normalize) is the xcrun entry itself.
#[must_use]
pub fn is_xcrun_progname(prog: &str) -> bool {
    normalize_progname(prog).eq_ignore_ascii_case("xcrun")
}

/// Parse argv following Apple `xcrun` + trampoline rules.
///
/// * `progname` — `getprogname()` / `argv[0]` basename.
/// * `args` — arguments after `argv[0]` (same as assembly `argv+1`).
#[must_use]
pub fn parse_args(progname: &str, args: &[&str]) -> ParsedArgs {
    let name = normalize_progname(progname);
    if !name.eq_ignore_ascii_case("xcrun") {
        let mut tool_args = Vec::new();
        for a in args {
            tool_args.push(String::from(*a));
        }
        return ParsedArgs {
            tool_from_prog: Some(String::from(name)),
            tool: Some(String::from(name)),
            tool_args,
            ..ParsedArgs::default()
        };
    }

    let mut out = ParsedArgs::default();
    let mut i = 0usize;
    while i < args.len() {
        let Some(&a) = args.get(i) else {
            break;
        };
        match a {
            "-h" | "--help" => out.help = true,
            "--version" => out.version = true,
            "-v" | "--verbose" => out.verbose = true,
            "-l" | "--log" => out.log = true,
            "-f" | "--find" => out.find_only = true,
            // Accepted for CLI compatibility; this implementation has no cache.
            "-r" | "--run" | "-n" | "--no-cache" | "-k" | "--kill-cache" => {}
            "--show-sdk-path" => out.show_sdk_path = true,
            "--show-sdk-version" => out.show_sdk_version = true,
            "--show-sdk-build-version" => out.show_sdk_build_version = true,
            "--show-sdk-platform-path" => out.show_sdk_platform_path = true,
            "--show-sdk-platform-version" => out.show_sdk_platform_version = true,
            "--show-toolchain-path" => out.show_toolchain_path = true,
            "--sdk" => {
                i = i.saturating_add(1);
                if let Some(&v) = args.get(i) {
                    out.sdk = Some(String::from(v));
                }
            }
            "--toolchain" => {
                i = i.saturating_add(1);
                if let Some(&v) = args.get(i) {
                    out.toolchain = Some(String::from(v));
                }
            }
            s if s.starts_with("--sdk=") => {
                out.sdk = Some(String::from(s.trim_start_matches("--sdk=")));
            }
            s if s.starts_with("--toolchain=") => {
                out.toolchain = Some(String::from(s.trim_start_matches("--toolchain=")));
            }
            "--" => {
                i = i.saturating_add(1);
                if out.tool.is_none()
                    && let Some(&t) = args.get(i)
                {
                    out.tool = Some(String::from(t));
                    i = i.saturating_add(1);
                }
                while let Some(&t) = args.get(i) {
                    out.tool_args.push(String::from(t));
                    i = i.saturating_add(1);
                }
                break;
            }
            s if s.starts_with('-') => {
                while let Some(&t) = args.get(i) {
                    out.tool_args.push(String::from(t));
                    i = i.saturating_add(1);
                }
                break;
            }
            s => {
                if out.tool.is_none() {
                    out.tool = Some(String::from(s));
                    i = i.saturating_add(1);
                    while let Some(&t) = args.get(i) {
                        out.tool_args.push(String::from(t));
                        i = i.saturating_add(1);
                    }
                    break;
                }
                out.tool_args.push(String::from(s));
            }
        }
        i = i.saturating_add(1);
    }
    out
}

/// Candidate SDK directory names for a user-supplied `--sdk` / `SDKROOT`.
#[must_use]
pub fn sdk_name_candidates(name: &str) -> Vec<String> {
    if name.is_empty() {
        return alloc::vec![String::from("MacOSX.sdk")];
    }
    let mut v = alloc::vec![String::from(name)];
    if name_has_sdk_ext(name) {
        return v;
    }
    let lower = name.as_bytes();
    let is_macosx = eq_ignore_ascii(name, "macosx")
        || eq_ignore_ascii(name, "macos")
        || eq_ignore_ascii(name, "osx");
    if is_macosx {
        v.push(String::from("MacOSX.sdk"));
        v.push(String::from("MacOSX26.sdk"));
        return v;
    }
    // macosx26.5 → MacOSX26.5.sdk
    if lower.len() > 6 && eq_ignore_ascii_prefix(name, "macosx") {
        let rest = &name[6..];
        if !rest.is_empty() {
            let mut s = String::from("MacOSX");
            s.push_str(rest);
            s.push_str(".sdk");
            v.push(s);
        }
    }
    {
        let mut s = String::from(name);
        s.push_str(".sdk");
        v.push(s);
    }
    {
        let mut s = String::from("MacOSX");
        s.push_str(name);
        s.push_str(".sdk");
        v.push(s);
    }
    v
}

fn name_has_sdk_ext(name: &str) -> bool {
    let b = name.as_bytes();
    b.get(b.len().saturating_sub(4)..)
        .is_some_and(|ext| ext.eq_ignore_ascii_case(b".sdk"))
}

fn eq_ignore_ascii(a: &str, b: &str) -> bool {
    a.eq_ignore_ascii_case(b)
}

fn eq_ignore_ascii_prefix(s: &str, prefix: &str) -> bool {
    s.as_bytes()
        .get(..prefix.len())
        .is_some_and(|head| head.eq_ignore_ascii_case(prefix.as_bytes()))
}

/// Whether `tool` is exempt from SDKROOT injection (man xcrun).
#[must_use]
pub fn is_sdkroot_exempt(tool: &str) -> bool {
    matches!(
        tool,
        "make" | "gnumake" | "xcodebuild" | "builtin-infoPlistUtility"
    )
}

/// Map error to process exit code (Apple-ish).
#[must_use]
pub fn exit_code_for(err: &XcrunError) -> i32 {
    match err {
        XcrunError::Usage(_) => 64,
        XcrunError::ToolNotFound | XcrunError::SdkNotFound => 72,
        XcrunError::NoDeveloperDir => 69,
        XcrunError::Io => 71,
    }
}

/// Minimal JSON `"Key":"value"` scanner (no_std).
#[must_use]
pub fn json_string_field<'a>(text: &'a str, key: &str) -> Option<&'a str> {
    let mut pat = String::from("\"");
    pat.push_str(key);
    pat.push('"');
    let idx = text.find(pat.as_str())?;
    let after = text.get(idx.saturating_add(pat.len())..)?;
    let colon = after.find(':')?;
    let rest = after.get(colon.saturating_add(1)..)?.trim_start();
    let rest = rest.strip_prefix('"')?;
    let end = rest.find('"')?;
    rest.get(..end)
}

/// XML plist `<key>K</key><string>V</string>` scanner.
#[must_use]
pub fn plist_string_value<'a>(text: &'a str, key: &str) -> Option<&'a str> {
    let mut key_tag = String::from("<key>");
    key_tag.push_str(key);
    key_tag.push_str("</key>");
    let idx = text.find(key_tag.as_str())?;
    let after = text.get(idx.saturating_add(key_tag.len())..)?;
    let start_tag = "<string>";
    let s = after.find(start_tag)?;
    let rest = after.get(s.saturating_add(start_tag.len())..)?;
    let end = rest.find("</string>")?;
    rest.get(..end)
}

/// Help text (no_std-friendly static).
pub const HELP_TEXT: &str = "\
Usage: xcrun [options] <tool name> ... arguments ...

Find and execute the named command line tool from the active developer
directory (Kakehashi clean-room implementation).

Options:
  -h, --help                  show this help message and exit
  --version                   show the xcrun version
  -v, --verbose               show verbose logging output
  --sdk <sdk name>            find the tool for the given SDK name
  --toolchain <name>          find the tool for the given toolchain
  -l, --log                   show commands to be executed (with --run)
  -f, --find                  only find and print the tool path
  -r, --run                   find and execute the tool (default)
  -n, --no-cache              accepted for compatibility (no cache)
  -k, --kill-cache            accepted for compatibility (no cache)
  --show-sdk-path             show selected SDK install path
  --show-sdk-version          show selected SDK version
  --show-sdk-build-version    show selected SDK build version
  --show-sdk-platform-path    show selected SDK platform path
  --show-sdk-platform-version show selected SDK platform version
  --show-toolchain-path       show selected toolchain path
";

/// Version banner.
pub const VERSION_TEXT: &str = "xcrun version 1 (kakehashi clean-room)\n";

#[cfg(test)]
#[allow(clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn normalize_strips_leading_dash() {
        assert_eq!(normalize_progname("-xcrun"), "xcrun");
        assert_eq!(normalize_progname("xcrun"), "xcrun");
    }

    #[test]
    fn parse_symlink_form_skips_options() {
        let args = ["--version", "a.c"];
        let p = parse_args("gcc", &args);
        assert_eq!(p.tool.as_deref(), Some("gcc"));
        assert_eq!(
            p.tool_args,
            vec![String::from("--version"), String::from("a.c")]
        );
        assert!(!p.version);
    }

    #[test]
    fn parse_find_clang() {
        let args = ["--find", "clang"];
        let p = parse_args("xcrun", &args);
        assert!(p.find_only);
        assert_eq!(p.tool.as_deref(), Some("clang"));
        assert!(p.tool_args.is_empty());
    }

    #[test]
    fn parse_sdk_and_tool_args() {
        let args = ["--sdk", "macosx", "clang", "-c", "t.c"];
        let p = parse_args("xcrun", &args);
        assert_eq!(p.sdk.as_deref(), Some("macosx"));
        assert_eq!(p.tool.as_deref(), Some("clang"));
        assert_eq!(p.tool_args, vec![String::from("-c"), String::from("t.c")]);
    }

    #[test]
    fn parse_show_sdk_path() {
        let args = ["--show-sdk-path"];
        let p = parse_args("xcrun", &args);
        assert!(p.show_sdk_path);
        assert!(p.tool.is_none());
    }

    #[test]
    fn sdk_candidates_macosx() {
        let c = sdk_name_candidates("macosx");
        assert!(c.iter().any(|s| s == "MacOSX.sdk"));
    }

    #[test]
    fn json_version_field() {
        let sample = r#"{"Version":"26.2","CanonicalName":"macosx26.2"}"#;
        assert_eq!(json_string_field(sample, "Version"), Some("26.2"));
    }

    #[test]
    fn is_xcrun_name_case_insensitive() {
        assert!(is_xcrun_progname("XCRUN"));
        assert!(is_xcrun_progname("-xcrun"));
        assert!(!is_xcrun_progname("gcc"));
    }
}
