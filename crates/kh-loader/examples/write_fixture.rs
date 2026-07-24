//! Writes synthetic arm64 Mach-O fixtures under `tests/fixtures/`.
//!
//! Usage:
//!   cargo run -p kh-loader --example write_fixture
//!   cargo run -p kh-loader --example write_fixture -- errno
//!   cargo run -p kh-loader --example write_fixture -- path/to/out.macho   # minimal only
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use kh_loader::fixture::{
    ROUNDTRIP_PAYLOAD, arm64_dylib_add, arm64_dylib_ctor, arm64_libsystem_stub,
    call_dylib_chained_exit, call_dylib_exit, call_libsystem_exit, ctor_main_exit,
    errno_unknown_then_exit, memory_file_roundtrip, minimal_arm64_execute, mmap_touch_exit,
};

fn main() -> ExitCode {
    let arg = env::args().nth(1);
    let root = PathBuf::from("tests/fixtures");
    drop(fs::create_dir_all(&root));

    let jobs: Vec<(PathBuf, Vec<u8>)> = match arg.as_deref() {
        None | Some("all") => vec![
            (
                root.join("minimal_arm64_execute.macho"),
                minimal_arm64_execute(),
            ),
            (
                root.join("errno_unknown_then_exit.macho"),
                errno_unknown_then_exit(),
            ),
            (root.join("mmap_touch_exit.macho"), mmap_touch_exit()),
            (
                root.join("memory_file_roundtrip.macho"),
                memory_file_roundtrip(),
            ),
            (
                root.join("roundtrip_payload.bin"),
                ROUNDTRIP_PAYLOAD.to_vec(),
            ),
            (root.join("libkh_add.dylib"), arm64_dylib_add()),
            (root.join("call_dylib.macho"), call_dylib_exit()),
            (
                root.join("call_dylib_chained.macho"),
                call_dylib_chained_exit(),
            ),
            (root.join("libkh_ctor.dylib"), arm64_dylib_ctor()),
            (root.join("ctor_main.macho"), ctor_main_exit()),
            (root.join("call_libsystem.macho"), call_libsystem_exit()),
            (
                root.join("bottle/usr/lib/libSystem.B.dylib"),
                arm64_libsystem_stub(),
            ),
        ],
        Some("minimal") => vec![(
            root.join("minimal_arm64_execute.macho"),
            minimal_arm64_execute(),
        )],
        Some("errno") => vec![(
            root.join("errno_unknown_then_exit.macho"),
            errno_unknown_then_exit(),
        )],
        Some("mmap") => vec![(root.join("mmap_touch_exit.macho"), mmap_touch_exit())],
        Some("roundtrip") => vec![
            (
                root.join("memory_file_roundtrip.macho"),
                memory_file_roundtrip(),
            ),
            (
                root.join("roundtrip_payload.bin"),
                ROUNDTRIP_PAYLOAD.to_vec(),
            ),
        ],
        Some("dylib" | "call_dylib") => vec![
            (root.join("libkh_add.dylib"), arm64_dylib_add()),
            (root.join("call_dylib.macho"), call_dylib_exit()),
            (
                root.join("call_dylib_chained.macho"),
                call_dylib_chained_exit(),
            ),
        ],
        Some("ctor") => vec![
            (root.join("libkh_ctor.dylib"), arm64_dylib_ctor()),
            (root.join("ctor_main.macho"), ctor_main_exit()),
        ],
        Some("libsystem" | "bottle") => vec![
            (root.join("call_libsystem.macho"), call_libsystem_exit()),
            (
                root.join("bottle/usr/lib/libSystem.B.dylib"),
                arm64_libsystem_stub(),
            ),
        ],
        Some(path)
            if Path::new(path)
                .extension()
                .is_some_and(|ext| ext.eq_ignore_ascii_case("macho")) =>
        {
            vec![(PathBuf::from(path), minimal_arm64_execute())]
        }
        Some(other) => {
            eprintln!(
                "unknown fixture '{other}'; use all|minimal|errno|mmap|roundtrip|dylib|ctor|libsystem|chained|*.macho"
            );
            return ExitCode::from(2);
        }
    };

    for (path, bytes) in jobs {
        if let Err(code) = write_one(&path, &bytes) {
            return code;
        }
    }
    ExitCode::SUCCESS
}

fn write_one(path: &Path, bytes: &[u8]) -> Result<(), ExitCode> {
    if let Some(parent) = path.parent() {
        drop(fs::create_dir_all(parent));
    }
    match fs::write(path, bytes) {
        Ok(()) => {
            eprintln!("wrote {} bytes to {}", bytes.len(), path.display());
            Ok(())
        }
        Err(err) => {
            eprintln!("error writing {}: {err}", path.display());
            Err(ExitCode::from(1))
        }
    }
}
