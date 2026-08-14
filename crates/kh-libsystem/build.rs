//! Apple-only linker flags + freestanding C varargs for the bottle dylib.
//!
//! * `install_name` stays `@rpath/libkh_libsystem.dylib` so `ld` can still
//!   link `-lSystem`.
//! * Packaging renames the file and sets LC_ID to `/usr/lib/libSystem.B.dylib`.
//! * Freestanding C sources live under `src/dylib/**/c/`.

fn main() {
    let target = std::env::var("TARGET").unwrap_or_default();
    if !target.contains("apple-darwin") {
        println!("cargo:warning=kh-libsystem product builds require aarch64-apple-darwin");
        return;
    }

    let c_files = [
        "src/dylib/libsystem_c/c/printf_fmt.c",
        "src/dylib/libsystem_c/c/fcntl_varargs.c",
        "src/dylib/libsystem_c/c/open_varargs.c",
        "src/dylib/libsystem_c/c/ioctl_varargs.c",
        "src/dylib/libcurl/c/curl_varargs.c",
    ];
    for f in c_files {
        println!("cargo:rerun-if-changed={f}");
    }

    let mut build = cc::Build::new();
    for f in c_files {
        build.file(f);
    }
    build
        .flag("-ffreestanding")
        .flag("-fno-builtin")
        .flag("-fno-builtin-printf")
        .flag("-fno-builtin-fprintf")
        .flag("-fno-builtin-vfprintf")
        .flag("-fno-builtin-snprintf")
        .flag("-fno-builtin-vsnprintf")
        .flag("-fno-builtin-fcntl")
        .flag("-fno-builtin-ioctl")
        .flag("-fno-stack-protector")
        .warnings(false)
        .compile("kh_printf_fmt");

    let Ok(out) = std::env::var("OUT_DIR") else {
        return;
    };
    let archive = format!("{out}/libkh_printf_fmt.a");
    println!("cargo:rustc-cdylib-link-arg=-Wl,-force_load,{archive}");
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
        "_sscanf",
        "_vsscanf",
        "___snprintf_chk",
        "___vsnprintf_chk",
        "___sprintf_chk",
        "___vsprintf_chk",
        "___assert_rtn",
        "_warn",
        "_warnx",
        "_vwarn",
        "_vwarnx",
        "_err",
        "_errx",
        "_verr",
        "_verrx",
        "__simple_vsprintf",
        "_curl_easy_setopt",
        "_curl_easy_getinfo",
        "_fcntl",
        "_ioctl",
        "_open",
        "_openat",
    ] {
        println!("cargo:rustc-cdylib-link-arg=-Wl,-exported_symbol,{sym}");
    }

    println!("cargo:rustc-cdylib-link-arg=-install_name");
    println!("cargo:rustc-cdylib-link-arg=@rpath/libkh_libsystem.dylib");
    println!("cargo:rustc-link-lib=System");
}
