//! Guest `/usr/bin/xcrun` — freestanding-style `no_std` binary.
//!
//! Links only against guest `libSystem` (open/stat/write/execve/getenv/…).
//! Entry is C `main(argc, argv)` so LC_MAIN supplies real guest args without
//! Rust std / `_NSGetArgc` / pthread stack helpers.

#![no_std]
#![no_main]
#![allow(unsafe_code)] // C ABI freestanding surface
#![allow(clippy::missing_safety_doc)]
#![allow(clippy::as_conversions)]
#![allow(clippy::cast_possible_truncation)]
#![allow(clippy::cast_sign_loss)]
#![allow(clippy::cast_possible_wrap)]

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;
use core::ffi::{c_char, c_int, c_void};
use core::ptr;

use kh_xcrun::{
    DEFAULT_DEVELOPER_DIR, HELP_TEXT, VERSION_TEXT, XCODE_DEVELOPER_DIR, XCODE_SELECT_LINK,
    XcrunError, exit_code_for, is_sdkroot_exempt, json_string_field, parse_args,
    plist_string_value, sdk_name_candidates,
};

// ── freestanding / libSystem imports ────────────────────────────────────────

#[link(name = "System", kind = "dylib")]
unsafe extern "C" {
    fn write(fd: c_int, buf: *const c_void, n: usize) -> isize;
    fn open(path: *const c_char, oflag: c_int, ...) -> c_int;
    fn close(fd: c_int) -> c_int;
    fn read(fd: c_int, buf: *mut c_void, n: usize) -> isize;
    fn stat(path: *const c_char, buf: *mut c_void) -> c_int;
    fn lstat(path: *const c_char, buf: *mut c_void) -> c_int;
    fn access(path: *const c_char, amode: c_int) -> c_int;
    fn getenv(name: *const c_char) -> *mut c_char;
    fn execv(path: *const c_char, argv: *const *const c_char) -> c_int;
    fn setenv(name: *const c_char, value: *const c_char, overwrite: c_int) -> c_int;
    fn opendir(name: *const c_char) -> *mut c_void;
    fn readdir(dirp: *mut c_void) -> *mut c_void;
    fn closedir(dirp: *mut c_void) -> c_int;
    fn readlink(path: *const c_char, buf: *mut c_char, bufsize: usize) -> isize;
    fn malloc(size: usize) -> *mut c_void;
    fn free(p: *mut c_void);
    fn exit(code: c_int) -> !;
    fn strlen(s: *const c_char) -> usize;
}

// Darwin O_RDONLY
const O_RDONLY: c_int = 0;
// R_OK for access
const R_OK: c_int = 4;
// F_OK
const F_OK: c_int = 0;

/// Enough space for Darwin `struct stat` on arm64 (actual size varies; we only
/// care about success/failure of the syscall).
const STAT_BUF_SIZE: usize = 512;

// ── allocator (via freestanding malloc) ─────────────────────────────────────

struct LibcAlloc;

// SAFETY: forwards to freestanding malloc/free.
unsafe impl core::alloc::GlobalAlloc for LibcAlloc {
    unsafe fn alloc(&self, layout: core::alloc::Layout) -> *mut u8 {
        let size = layout.size().max(layout.align()).max(1);
        unsafe { malloc(size).cast() }
    }
    unsafe fn dealloc(&self, ptr: *mut u8, _layout: core::alloc::Layout) {
        unsafe { free(ptr.cast()) }
    }
}

#[global_allocator]
static ALLOC: LibcAlloc = LibcAlloc;

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo<'_>) -> ! {
    let _ = ewrite(b"xcrun: panic\n");
    unsafe { exit(71) }
}

// ── tiny I/O ────────────────────────────────────────────────────────────────

fn ewrite(bytes: &[u8]) -> isize {
    unsafe { write(2, bytes.as_ptr().cast(), bytes.len()) }
}

fn owrite(bytes: &[u8]) -> isize {
    unsafe { write(1, bytes.as_ptr().cast(), bytes.len()) }
}

fn eprint_str(s: &str) {
    let _ = ewrite(s.as_bytes());
}

fn print_str(s: &str) {
    let _ = owrite(s.as_bytes());
}

fn print_line(s: &str) {
    print_str(s);
    let _ = owrite(b"\n");
}

// ── C string helpers ────────────────────────────────────────────────────────

fn cstr_len(p: *const c_char) -> usize {
    if p.is_null() {
        return 0;
    }
    unsafe { strlen(p) }
}

fn cstr_to_str<'a>(p: *const c_char) -> Option<&'a str> {
    if p.is_null() {
        return None;
    }
    let n = cstr_len(p);
    let bytes = unsafe { core::slice::from_raw_parts(p.cast::<u8>(), n) };
    core::str::from_utf8(bytes).ok()
}

fn with_c_string<R>(s: &str, f: impl FnOnce(*const c_char) -> R) -> R {
    let mut buf = Vec::with_capacity(s.len().saturating_add(1));
    buf.extend_from_slice(s.as_bytes());
    buf.push(0);
    f(buf.as_ptr().cast())
}

// ── path probes ─────────────────────────────────────────────────────────────

fn path_is_dir(path: &str) -> bool {
    with_c_string(path, |c| {
        let mut st = [0_u8; STAT_BUF_SIZE];
        let rc = unsafe { stat(c, st.as_mut_ptr().cast()) };
        rc == 0
    }) && with_c_string(path, |c| unsafe { access(c, R_OK | F_OK) } == 0)
}

fn path_is_file(path: &str) -> bool {
    with_c_string(path, |c| {
        let mut st = [0_u8; STAT_BUF_SIZE];
        // Prefer regular file: stat success + not a directory. Soft freestanding
        // may not fill mode bits reliably — also require access F_OK.
        let rc = unsafe { stat(c, st.as_mut_ptr().cast()) };
        if rc != 0 {
            return false;
        }
        // If lstat differs for symlink to dir, still OK for tool exec.
        let _ = unsafe { lstat(c, st.as_mut_ptr().cast()) };
        unsafe { access(c, X_OK) == 0 || access(c, F_OK) == 0 }
    })
}

const X_OK: c_int = 1;

fn env_get(key: &str) -> Option<String> {
    with_c_string(key, |c| {
        let p = unsafe { getenv(c) };
        cstr_to_str(p).map(String::from)
    })
}

fn env_set(key: &str, val: &str) {
    with_c_string(key, |k| {
        with_c_string(val, |v| {
            let _ = unsafe { setenv(k, v, 1) };
        });
    });
}

fn read_file_string(path: &str, max: usize) -> Option<String> {
    with_c_string(path, |c| {
        let fd = unsafe { open(c, O_RDONLY) };
        if fd < 0 {
            return None;
        }
        let mut out = Vec::new();
        let mut buf = [0_u8; 4096];
        loop {
            if out.len() >= max {
                break;
            }
            let n = unsafe { read(fd, buf.as_mut_ptr().cast(), buf.len()) };
            if n <= 0 {
                break;
            }
            let n = usize::try_from(n).unwrap_or(0);
            if let Some(chunk) = buf.get(..n) {
                out.extend_from_slice(chunk);
            }
            if out.len() > max {
                out.truncate(max);
                break;
            }
        }
        let _ = unsafe { close(fd) };
        String::from_utf8(out).ok()
    })
}

fn read_symlink(path: &str) -> Option<String> {
    with_c_string(path, |c| {
        let mut buf = [0_u8; 1024];
        let n = unsafe { readlink(c, buf.as_mut_ptr().cast(), buf.len().saturating_sub(1)) };
        if n <= 0 {
            return None;
        }
        let n = usize::try_from(n)
            .unwrap_or(0)
            .min(buf.len().saturating_sub(1));
        buf.get(..n)
            .and_then(|b| core::str::from_utf8(b).ok())
            .map(String::from)
    })
}

// ── readdir (Darwin dirent: d_name at offset 21) ────────────────────────────

const DIRENT_NAME_OFF: usize = 21;

fn list_dir_names(path: &str) -> Vec<String> {
    let mut names = Vec::new();
    with_c_string(path, |c| {
        let dir = unsafe { opendir(c) };
        if dir.is_null() {
            return;
        }
        loop {
            let ent = unsafe { readdir(dir) };
            if ent.is_null() {
                break;
            }
            let name_ptr = unsafe { ent.cast::<u8>().add(DIRENT_NAME_OFF).cast::<c_char>() };
            if let Some(s) = cstr_to_str(name_ptr)
                && s != "."
                && s != ".."
            {
                names.push(String::from(s));
            }
        }
        let _ = unsafe { closedir(dir) };
    });
    names
}

// ── path join ───────────────────────────────────────────────────────────────

fn join2(a: &str, b: &str) -> String {
    if a.is_empty() {
        return String::from(b);
    }
    if b.is_empty() {
        return String::from(a);
    }
    let mut s = String::from(a);
    if !s.ends_with('/') {
        s.push('/');
    }
    let b = b.strip_prefix('/').unwrap_or(b);
    s.push_str(b);
    s
}

fn join3(a: &str, b: &str, c: &str) -> String {
    join2(&join2(a, b), c)
}

fn basename(path: &str) -> &str {
    path.rsplit('/').next().unwrap_or(path)
}

// ── developer dir / SDK / tool lookup ───────────────────────────────────────

fn resolve_developer_dir() -> String {
    if let Some(raw) = env_get("DEVELOPER_DIR")
        && !raw.is_empty()
    {
        return raw;
    }
    if let Some(target) = read_symlink(XCODE_SELECT_LINK) {
        let abs = if target.starts_with('/') {
            target
        } else {
            join2("/var/db", &target)
        };
        if path_is_dir(&abs) {
            return abs;
        }
    }
    if path_is_dir(DEFAULT_DEVELOPER_DIR) {
        return String::from(DEFAULT_DEVELOPER_DIR);
    }
    if path_is_dir(XCODE_DEVELOPER_DIR) {
        return String::from(XCODE_DEVELOPER_DIR);
    }
    String::from(DEFAULT_DEVELOPER_DIR)
}

fn latest_macos_sdk(sdks: &str) -> Option<String> {
    let mut best: Option<String> = None;
    for name in list_dir_names(sdks) {
        if !name.starts_with("MacOSX")
            || !name
                .as_bytes()
                .get(name.len().saturating_sub(4)..)
                .is_some_and(|e| e.eq_ignore_ascii_case(b".sdk"))
            || name == "MacOSX.sdk"
        {
            continue;
        }
        let p = join2(sdks, &name);
        if !path_is_dir(&p) {
            continue;
        }
        match &best {
            None => best = Some(name),
            Some(bn) if name.as_str() > bn.as_str() => best = Some(name),
            _ => {}
        }
    }
    if let Some(name) = best {
        return Some(join2(sdks, &name));
    }
    let link = join2(sdks, "MacOSX.sdk");
    if path_is_dir(&link) {
        return Some(link);
    }
    None
}

fn resolve_sdk_path(developer_dir: &str, sdk_opt: Option<&str>) -> Result<String, XcrunError> {
    let sdks = join2(developer_dir, "SDKs");
    if let Some(name) = sdk_opt {
        for c in sdk_name_candidates(name) {
            if c.starts_with('/') {
                if path_is_dir(&c) {
                    return Ok(c);
                }
            } else {
                let p = join2(&sdks, &c);
                if path_is_dir(&p) {
                    return Ok(p);
                }
            }
        }
        if eq_macos_generic(name)
            && let Some(p) = latest_macos_sdk(&sdks)
        {
            return Ok(p);
        }
        return Err(XcrunError::SdkNotFound);
    }
    if let Some(raw) = env_get("SDKROOT")
        && !raw.is_empty()
    {
        if path_is_dir(&raw) {
            return Ok(raw);
        }
        for c in sdk_name_candidates(&raw) {
            let p = join2(&sdks, &c);
            if path_is_dir(&p) {
                return Ok(p);
            }
        }
    }
    if let Some(p) = latest_macos_sdk(&sdks) {
        return Ok(p);
    }
    Err(XcrunError::SdkNotFound)
}

fn eq_macos_generic(name: &str) -> bool {
    name.eq_ignore_ascii_case("macosx") || name.eq_ignore_ascii_case("macos") || name.is_empty()
}

fn toolchain_usr_bin(developer_dir: &str, toolchain: Option<&str>) -> String {
    let name = toolchain.unwrap_or("XcodeDefault");
    let mut root = join2(developer_dir, "Toolchains");
    root = join2(&root, &{
        let mut n = String::from(name);
        if !n.ends_with(".xctoolchain") {
            n.push_str(".xctoolchain");
        }
        n
    });
    join2(&root, "usr/bin")
}

fn find_tool(
    developer_dir: &str,
    sdk_path: &str,
    tool: &str,
    toolchain: Option<&str>,
) -> Result<String, XcrunError> {
    if tool.is_empty() {
        return Err(XcrunError::Usage("a tool name must be specified"));
    }
    if tool.starts_with('/') && path_is_file(tool) {
        return Ok(String::from(tool));
    }
    let candidates = [
        join3(developer_dir, "usr/bin", tool),
        join2(&toolchain_usr_bin(developer_dir, toolchain), tool),
        join3(sdk_path, "usr/bin", tool),
    ];
    for c in &candidates {
        if path_is_file(c) {
            return Ok(c.clone());
        }
    }
    // PATH search
    if let Some(path_var) = env_get("PATH") {
        for dir in path_var.split(':') {
            if dir.is_empty() {
                continue;
            }
            let c = join2(dir, tool);
            if path_is_file(&c) {
                return Ok(c);
            }
        }
    }
    Err(XcrunError::ToolNotFound)
}

fn read_sdk_version(sdk_path: &str) -> String {
    let json_path = join2(sdk_path, "SDKSettings.json");
    if let Some(text) = read_file_string(&json_path, 1 << 20)
        && let Some(v) = json_string_field(&text, "Version")
    {
        return String::from(v);
    }
    let plist_path = join2(sdk_path, "SDKSettings.plist");
    if let Some(text) = read_file_string(&plist_path, 1 << 20)
        && let Some(v) = plist_string_value(&text, "Version")
    {
        return String::from(v);
    }
    let name = basename(sdk_path);
    if let Some(rest) = name
        .strip_prefix("MacOSX")
        .and_then(|r| r.strip_suffix(".sdk"))
        && !rest.is_empty()
    {
        return String::from(rest);
    }
    String::from("unknown")
}

fn read_sdk_build_version(sdk_path: &str) -> String {
    let json_path = join2(sdk_path, "SDKSettings.json");
    if let Some(text) = read_file_string(&json_path, 1 << 20) {
        if let Some(v) = json_string_field(&text, "ProductBuildVersion") {
            return String::from(v);
        }
        if let Some(v) = json_string_field(&text, "CanonicalName") {
            return String::from(v);
        }
    }
    read_sdk_version(sdk_path)
}

// ── run ─────────────────────────────────────────────────────────────────────

fn run_parsed(parsed: &kh_xcrun::ParsedArgs) -> Result<(), XcrunError> {
    if parsed.help {
        print_str(HELP_TEXT);
        return Ok(());
    }
    if parsed.version {
        print_str(VERSION_TEXT);
        return Ok(());
    }

    let developer_dir = resolve_developer_dir();
    if parsed.verbose {
        eprint_str("xcrun: note: DEVELOPER_DIR = '");
        eprint_str(&developer_dir);
        eprint_str("'\n");
    }
    if !path_is_dir(&developer_dir) {
        return Err(XcrunError::NoDeveloperDir);
    }

    let sdk_path = resolve_sdk_path(&developer_dir, parsed.sdk.as_deref())?;
    if parsed.verbose {
        eprint_str("xcrun: note: SDKROOT = '");
        eprint_str(&sdk_path);
        eprint_str("'\n");
    }

    if parsed.show_sdk_path {
        print_line(&sdk_path);
        return Ok(());
    }
    if parsed.show_sdk_version {
        print_line(&read_sdk_version(&sdk_path));
        return Ok(());
    }
    if parsed.show_sdk_build_version {
        print_line(&read_sdk_build_version(&sdk_path));
        return Ok(());
    }
    if parsed.show_sdk_platform_path {
        let platform = join2(&developer_dir, "Platforms/MacOSX.platform");
        if path_is_dir(&platform) {
            print_line(&platform);
        } else {
            print_line(&developer_dir);
        }
        return Ok(());
    }
    if parsed.show_sdk_platform_version {
        print_line(&read_sdk_version(&sdk_path));
        return Ok(());
    }
    if parsed.show_toolchain_path {
        let tc_owned = parsed
            .toolchain
            .clone()
            .or_else(|| env_get("TOOLCHAINS").filter(|s| !s.is_empty()));
        let usr = toolchain_usr_bin(&developer_dir, tc_owned.as_deref());
        // parent of usr/bin → toolchain root
        let tc_root = usr.strip_suffix("/usr/bin").map_or_else(
            || join2(&developer_dir, "Toolchains/XcodeDefault.xctoolchain"),
            String::from,
        );
        print_line(&tc_root);
        return Ok(());
    }

    let tool = parsed.tool.as_deref().ok_or(XcrunError::Usage(
        "specify a tool name or a --show-sdk-* option",
    ))?;

    let toolchain = parsed
        .toolchain
        .clone()
        .or_else(|| env_get("TOOLCHAINS").filter(|s| !s.is_empty()));
    let tool_path = find_tool(&developer_dir, &sdk_path, tool, toolchain.as_deref())?;

    if parsed.find_only {
        print_line(&tool_path);
        return Ok(());
    }

    if parsed.log || parsed.verbose {
        eprint_str("env SDKROOT=");
        eprint_str(&sdk_path);
        eprint_str(" ");
        eprint_str(&tool_path);
        for a in &parsed.tool_args {
            eprint_str(" ");
            eprint_str(a);
        }
        eprint_str("\n");
    }

    if !is_sdkroot_exempt(tool) {
        env_set("SDKROOT", &sdk_path);
    }
    env_set("DEVELOPER_DIR", &developer_dir);

    // Build argv for execv: [tool_path, tool_args..., NULL]
    let mut owned: Vec<Vec<u8>> = Vec::new();
    {
        let mut b = Vec::from(tool_path.as_bytes());
        b.push(0);
        owned.push(b);
    }
    for a in &parsed.tool_args {
        let mut b = Vec::from(a.as_bytes());
        b.push(0);
        owned.push(b);
    }
    let mut ptrs: Vec<*const c_char> = owned.iter().map(|v| v.as_ptr().cast::<c_char>()).collect();
    ptrs.push(ptr::null());

    with_c_string(&tool_path, |path_c| {
        let _ = unsafe { execv(path_c, ptrs.as_ptr()) };
    });
    Err(XcrunError::Io)
}

fn eprint_error(err: &XcrunError) {
    eprint_str("xcrun: error: ");
    match err {
        XcrunError::Usage(m) => {
            eprint_str(m);
            eprint_str("\n");
        }
        XcrunError::NoDeveloperDir => {
            eprint_str("unable to find developer tools (no Xcode or CLT)\n");
        }
        XcrunError::ToolNotFound => {
            eprint_str("unable to find utility, not a developer tool or in PATH\n");
        }
        XcrunError::SdkNotFound => {
            eprint_str("SDK cannot be located\n");
        }
        XcrunError::Io => {
            eprint_str("failed to execute tool\n");
        }
    }
}

// ── C main ──────────────────────────────────────────────────────────────────

/// LC_MAIN entry: standard C `main`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn main(argc: c_int, argv: *const *const c_char) -> c_int {
    if argv.is_null() || argc < 0 {
        eprint_str("xcrun: error: bad argc/argv\n");
        return 64;
    }
    let argc = usize::try_from(argc).unwrap_or(0);

    // Collect argv as &str via temporary Vecs of owned bytes for UTF-8.
    let mut owned_args: Vec<String> = Vec::new();
    for i in 0..argc {
        let p = unsafe { *argv.add(i) };
        if let Some(s) = cstr_to_str(p) {
            owned_args.push(String::from(s));
        } else {
            owned_args.push(String::new());
        }
    }

    let prog = owned_args.first().map_or("xcrun", |s| basename(s.as_str()));
    let rest: Vec<&str> = owned_args.iter().skip(1).map(String::as_str).collect();
    let parsed = parse_args(prog, &rest);
    match run_parsed(&parsed) {
        Ok(()) => 0,
        Err(err) => {
            eprint_error(&err);
            exit_code_for(&err)
        }
    }
}
