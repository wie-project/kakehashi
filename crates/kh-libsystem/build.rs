//! Apple-only linker flags + freestanding C `*printf` for the bottle dylib.
//!
//! * `install_name` stays `@rpath/libkh_libsystem.dylib` so `ld` can still
//!   link `-lSystem` (setting id to `/usr/lib/libSystem.B.dylib` makes the
//!   linker refuse “dylib with itself”).
//! * Packaging (`kh bottle create` / CI) renames the file and runs
//!   `install_name_tool -id /usr/lib/libSystem.B.dylib`.
//! * `-lSystem` is only for host `dyld_stub_binder`; exported C symbols are
//!   defined in this crate and do not call into the real libSystem body.
//! * `printf_fmt.c` is freestanding (`-ffreestanding`) and only calls our
//!   Rust `write` / `fileno` / `_exit` exports.

fn main() {
    let target = std::env::var("TARGET").unwrap_or_default();
    if !target.contains("apple-darwin") {
        // Not a supported product target — keep the crate type-checking only.
        println!("cargo:warning=kh-libsystem product builds require aarch64-apple-darwin");
        return;
    }

    // Freestanding C for variadic ABIs (stable Rust has no c_variadic):
    // *printf + curl_easy_setopt/getinfo + fcntl (Apple arm64 stacks varargs).
    // `-force_load` is required: cdylib + dead_strip drops archive members that
    // nothing in Rust references by name.
    println!("cargo:rerun-if-changed=src/printf_fmt.c");
    println!("cargo:rerun-if-changed=src/curl_varargs.c");
    println!("cargo:rerun-if-changed=src/fcntl_varargs.c");
    cc::Build::new()
        .file("src/printf_fmt.c")
        .file("src/curl_varargs.c")
        .file("src/fcntl_varargs.c")
        .flag("-ffreestanding")
        .flag("-fno-builtin")
        .flag("-fno-builtin-printf")
        .flag("-fno-builtin-fprintf")
        .flag("-fno-builtin-vfprintf")
        .flag("-fno-builtin-snprintf")
        .flag("-fno-builtin-vsnprintf")
        .flag("-fno-builtin-fcntl")
        .flag("-fno-stack-protector")
        .warnings(false)
        .compile("kh_printf_fmt");

    let Ok(out) = std::env::var("OUT_DIR") else {
        return;
    };
    let archive = format!("{out}/libkh_printf_fmt.a");
    // Through the `cc` linker driver (not raw ld): one -Wl token.
    println!("cargo:rustc-cdylib-link-arg=-Wl,-force_load,{archive}");
    // rustc cdylib uses -exported_symbols_list (Rust-only). Explicitly export
    // freestanding C *printf + curl vararg symbols pulled from the archive.
    for sym in [
        "_printf",
        "_vprintf",
        "_snprintf",
        "_vsnprintf",
        "_sprintf",
        "_vsprintf",
        "_asprintf",
        "_vasprintf",
        "_fprintf",
        "_vfprintf",
        "_putchar",
        "___snprintf_chk",
        "___vsnprintf_chk",
        "___assert_rtn",
        "_curl_easy_setopt",
        "_curl_easy_getinfo",
        "_fcntl",
    ] {
        println!("cargo:rustc-cdylib-link-arg=-Wl,-exported_symbol,{sym}");
    }

    println!("cargo:rustc-cdylib-link-arg=-install_name");
    println!("cargo:rustc-cdylib-link-arg=@rpath/libkh_libsystem.dylib");
    println!("cargo:rustc-link-lib=System");
}
