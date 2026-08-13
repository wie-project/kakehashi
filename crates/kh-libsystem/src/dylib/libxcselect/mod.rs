//! Clean-room `libxcselect` surface used by Apple `/usr/bin/xcrun` / `gcc`.
//!
//! `/usr/bin/xcrun` is a thin trampoline that calls
//! [`xcselect_invoke_xcrun`]. Behavior follows public `xcrun(1)` /
//! `xcode-select(1)` (developer dir, SDK path, find/exec a tool).

#![allow(
    clippy::arithmetic_side_effects,
    clippy::as_conversions,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::indexing_slicing,
    clippy::manual_c_str_literals
)]

use core::ffi::{c_char, c_int, c_void};
use core::ptr;

use crate::dylib::libsystem_c::posix::{access, execv, getenv, setenv, stat};
use crate::dylib::libsystem_c::stdio::{strlen, write};
use crate::kh_core::heap::malloc;
use crate::kh_core::process::exit_now;

fn die(code: c_int) -> ! {
    unsafe { exit_now(code) }
}

const DEFAULT_DEVELOPER_DIR: &[u8] = b"/Library/Developer/CommandLineTools\0";
const F_OK: c_int = 0;
const X_OK: c_int = 1;

/// Invoked by Apple `/usr/bin/xcrun` and compiler shims.
///
/// Observed C ABI (from the trampoline's register setup, not its body):
/// `tool` is NULL when the program name is `xcrun`, otherwise the remapped
/// tool (`clang`, `clang++`, …). `argc`/`argv` skip `argv[0]`.
#[unsafe(export_name = "xcselect_invoke_xcrun")]
pub(crate) unsafe extern "C" fn xcselect_invoke_xcrun(
    tool: *const c_char,
    argc: c_int,
    argv: *const *const c_char,
    _flags: c_int,
) -> c_int {
    let argc = if argc < 0 {
        0
    } else {
        usize::try_from(argc).unwrap_or(0)
    };

    let mut show_sdk_path = false;
    let mut find_only = false;
    let mut show_version = false;
    let mut sdk_opt: Option<&str> = None;
    let mut pos_tool: Option<&str> = None;
    let mut tool_args_start = 0usize;

    if tool.is_null() {
        let mut i = 0usize;
        while i < argc {
            let Some(a) = nth_arg(argv, i) else { break };
            match a {
                "--show-sdk-path" => show_sdk_path = true,
                "-f" | "--find" => find_only = true,
                "--version" => show_version = true,
                "--sdk" => {
                    i = i.saturating_add(1);
                    sdk_opt = nth_arg(argv, i);
                }
                s if s.starts_with("--sdk=") => {
                    sdk_opt = Some(s.trim_start_matches("--sdk="));
                }
                "-h"
                | "--help"
                | "-v"
                | "--verbose"
                | "-l"
                | "--log"
                | "-r"
                | "--run"
                | "-n"
                | "--no-cache"
                | "-k"
                | "--kill-cache"
                | "--show-sdk-version"
                | "--show-sdk-build-version"
                | "--show-sdk-platform-path"
                | "--show-sdk-platform-version"
                | "--show-toolchain-path" => {}
                s if s.starts_with('-') => {
                    tool_args_start = i;
                    break;
                }
                s => {
                    pos_tool = Some(s);
                    tool_args_start = i.saturating_add(1);
                    break;
                }
            }
            i = i.saturating_add(1);
        }
    } else {
        pos_tool = cstr_to_str(tool);
        tool_args_start = 0;
    }

    let developer = resolve_developer_dir();
    if !path_ok(developer) {
        ewrite(b"xcrun: error: unable to find developer tools (no Xcode or CLT)\n");
        die(69);
    }

    let Some(sdk) = resolve_sdk(developer, sdk_opt) else {
        ewrite(b"xcrun: error: SDK cannot be located\n");
        die(72);
    };

    if show_version {
        owrite(b"xcrun version 1\n");
        die(0);
    }
    if show_sdk_path {
        owrite(sdk.as_bytes());
        owrite(b"\n");
        die(0);
    }

    let Some(tool_name) = pos_tool.filter(|s| !s.is_empty()) else {
        ewrite(b"xcrun: error: specify a tool name or a --show-sdk-* option\n");
        die(64);
    };

    let Some(tool_path) = find_tool(developer, sdk, tool_name) else {
        ewrite(b"xcrun: error: unable to find utility, not a developer tool or in PATH\n");
        die(72);
    };

    if find_only {
        owrite(tool_path.as_str().as_bytes());
        owrite(b"\n");
        die(0);
    }

    if !is_sdkroot_exempt(tool_name) {
        set_env(b"SDKROOT\0", sdk);
    }
    set_env(b"DEVELOPER_DIR\0", developer);

    // argv for execv: [tool_path, remaining args..., NULL]
    let extra = argc.saturating_sub(tool_args_start);
    let mut ptrs: [*const c_char; 64] = [ptr::null(); 64];
    let path_c = cstring_on_heap(tool_path.as_str());
    if path_c.is_null() {
        die(71);
    }
    ptrs[0] = path_c;
    let mut n = 1usize;
    let mut i = tool_args_start;
    while i < argc && n < 63 {
        if let Some(p) = nth_ptr(argv, i) {
            ptrs[n] = p;
            n = n.saturating_add(1);
        }
        i = i.saturating_add(1);
    }
    let _ = extra;
    unsafe {
        execv(path_c, ptrs.as_ptr());
    }
    ewrite(b"xcrun: error: failed to execute tool\n");
    die(71);
}

/// Public `xcselect_host_sdk_path` (SDK header). Policy is ignored: latest macOS SDK.
#[unsafe(export_name = "xcselect_host_sdk_path")]
pub(crate) unsafe extern "C" fn xcselect_host_sdk_path(
    _sdk_policy: u32,
    path_out: *mut *mut c_char,
) -> c_int {
    if path_out.is_null() {
        return 22; // EINVAL
    }
    let developer = resolve_developer_dir();
    let Some(sdk) = resolve_sdk(developer, None) else {
        return 2; // ENOENT
    };
    let p = cstring_on_heap(sdk);
    if p.is_null() {
        return 12; // ENOMEM
    }
    unsafe {
        *path_out = p.cast_mut();
    }
    0
}

fn nth_arg<'a>(argv: *const *const c_char, i: usize) -> Option<&'a str> {
    cstr_to_str(nth_ptr(argv, i)?)
}

fn nth_ptr(argv: *const *const c_char, i: usize) -> Option<*const c_char> {
    if argv.is_null() {
        return None;
    }
    let p = unsafe { *argv.add(i) };
    if p.is_null() { None } else { Some(p) }
}

fn cstr_to_str<'a>(p: *const c_char) -> Option<&'a str> {
    if p.is_null() {
        return None;
    }
    let n = unsafe { strlen(p) };
    let bytes = unsafe { core::slice::from_raw_parts(p.cast::<u8>(), n) };
    core::str::from_utf8(bytes).ok()
}

fn resolve_developer_dir() -> &'static str {
    if let Some(raw) = env_str(b"DEVELOPER_DIR\0")
        && !raw.is_empty()
        && path_ok(raw)
    {
        return raw;
    }
    cstr_to_str(DEFAULT_DEVELOPER_DIR.as_ptr().cast()).unwrap_or("")
}

fn env_str(key: &[u8]) -> Option<&'static str> {
    let p = unsafe { getenv(key.as_ptr().cast()) };
    cstr_to_str(p)
}

fn resolve_sdk(developer: &str, sdk_opt: Option<&str>) -> Option<&'static str> {
    if let Some(name) = sdk_opt {
        if name.starts_with('/') && path_ok(name) {
            return leak_path(name);
        }
        for cand in [
            "MacOSX.sdk",
            "MacOSX26.sdk",
            "MacOSX26.5.sdk",
            "MacOSX26.6.sdk",
        ] {
            let p = join3(developer, "SDKs", cand);
            if path_ok(p.as_str()) {
                return leak_path(p.as_str());
            }
        }
        if !name.is_empty() {
            let mut named = StringBuf::new();
            named.push_str(name);
            if !name.as_bytes().ends_with(b".sdk") && !name.as_bytes().ends_with(b".SDK") {
                named.push_str(".sdk");
            }
            let p = join3(developer, "SDKs", named.as_str());
            if path_ok(p.as_str()) {
                return leak_path(p.as_str());
            }
        }
    }
    if let Some(raw) = env_str(b"SDKROOT\0")
        && !raw.is_empty()
        && path_ok(raw)
    {
        return Some(raw);
    }
    for cand in [
        "MacOSX26.6.sdk",
        "MacOSX26.5.sdk",
        "MacOSX26.sdk",
        "MacOSX.sdk",
    ] {
        let p = join3(developer, "SDKs", cand);
        if path_ok(p.as_str()) {
            return leak_path(p.as_str());
        }
    }
    None
}

fn find_tool(developer: &str, sdk: &str, tool: &str) -> Option<StringBuf> {
    if tool.starts_with('/') && path_ok(tool) {
        let mut b = StringBuf::new();
        b.push_str(tool);
        return Some(b);
    }
    {
        let p = join3(developer, "usr/bin", tool);
        if path_ok(p.as_str()) {
            return Some(p);
        }
    }
    {
        let p = join3(
            developer,
            "Toolchains/XcodeDefault.xctoolchain/usr/bin",
            tool,
        );
        if path_ok(p.as_str()) {
            return Some(p);
        }
    }
    {
        let p = join3(sdk, "usr/bin", tool);
        if path_ok(p.as_str()) {
            return Some(p);
        }
    }
    if let Some(path_var) = env_str(b"PATH\0") {
        for dir in path_var.split(':') {
            if dir.is_empty() {
                continue;
            }
            let p = join2(dir, tool);
            if path_ok(p.as_str()) {
                return Some(p);
            }
        }
    }
    None
}

fn is_sdkroot_exempt(tool: &str) -> bool {
    matches!(tool, "make" | "gnumake" | "xcodebuild")
}

fn path_ok(path: &str) -> bool {
    let mut buf = StringBuf::new();
    buf.push_str(path);
    buf.push(0);
    let c = buf.as_c();
    if c.is_null() {
        return false;
    }
    unsafe { access(c, F_OK) == 0 || access(c, X_OK) == 0 || stat_ok(c) }
}

fn stat_ok(c: *const c_char) -> bool {
    let mut st = [0_u8; 512];
    unsafe { stat(c, st.as_mut_ptr().cast()) == 0 }
}

fn set_env(key: &[u8], val: &str) {
    let mut v = StringBuf::new();
    v.push_str(val);
    v.push(0);
    let vc = v.as_c();
    if !vc.is_null() {
        let _ = unsafe { setenv(key.as_ptr().cast(), vc, 1) };
    }
}

fn leak_path(s: &str) -> Option<&'static str> {
    let p = cstring_on_heap(s);
    if p.is_null() {
        return None;
    }
    cstr_to_str(p)
}

fn cstring_on_heap(s: &str) -> *const c_char {
    let n = s.len().saturating_add(1);
    let p = unsafe { malloc(n) }.cast::<u8>();
    if p.is_null() {
        return ptr::null();
    }
    unsafe {
        ptr::copy_nonoverlapping(s.as_ptr(), p, s.len());
        p.add(s.len()).write(0);
        p.cast()
    }
}

fn join2(a: &str, b: &str) -> StringBuf {
    let mut s = StringBuf::new();
    s.push_str(a);
    if !s.as_str().ends_with('/') {
        s.push(b'/');
    }
    s.push_str(b.strip_prefix('/').unwrap_or(b));
    s
}

fn join3(a: &str, b: &str, c: &str) -> StringBuf {
    let mid = join2(a, b);
    join2(mid.as_str(), c)
}

fn ewrite(bytes: &[u8]) {
    let _ = unsafe { write(2, bytes.as_ptr().cast::<c_void>(), bytes.len()) };
}

fn owrite(bytes: &[u8]) {
    let _ = unsafe { write(1, bytes.as_ptr().cast::<c_void>(), bytes.len()) };
}

/// Small stack string (paths under a bottle stay well below 1 KiB).
struct StringBuf {
    buf: [u8; 1024],
    len: usize,
}

impl StringBuf {
    fn new() -> Self {
        Self {
            buf: [0; 1024],
            len: 0,
        }
    }

    fn push(&mut self, b: u8) {
        if let Some(slot) = self.buf.get_mut(self.len) {
            *slot = b;
            self.len = self.len.saturating_add(1);
        }
    }

    fn push_str(&mut self, s: &str) {
        for b in s.as_bytes() {
            self.push(*b);
        }
    }

    fn as_str(&self) -> &str {
        let slice = self.buf.get(..self.len).unwrap_or(&[]);
        core::str::from_utf8(slice).unwrap_or("")
    }

    fn as_c(&self) -> *const c_char {
        if self.len == 0 {
            return ptr::null();
        }
        self.buf.as_ptr().cast()
    }
}
