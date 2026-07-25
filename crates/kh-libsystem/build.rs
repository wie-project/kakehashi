//! Apple-only linker flags for the bottle dylib.
//!
//! * `install_name` stays `@rpath/libkh_libsystem.dylib` so `ld` can still
//!   link `-lSystem` (setting id to `/usr/lib/libSystem.B.dylib` makes the
//!   linker refuse “dylib with itself”).
//! * Packaging (`kh bottle create` / CI) renames the file and runs
//!   `install_name_tool -id /usr/lib/libSystem.B.dylib`.
//! * `-lSystem` is only for host `dyld_stub_binder`; exported C symbols are
//!   defined in this crate and do not call into the real libSystem body.

fn main() {
    let target = std::env::var("TARGET").unwrap_or_default();
    if !target.contains("apple-darwin") {
        // Not a supported product target — keep the crate type-checking only.
        println!("cargo:warning=kh-libsystem product builds require aarch64-apple-darwin");
        return;
    }
    println!("cargo:rustc-cdylib-link-arg=-install_name");
    println!("cargo:rustc-cdylib-link-arg=@rpath/libkh_libsystem.dylib");
    println!("cargo:rustc-link-lib=System");
}
