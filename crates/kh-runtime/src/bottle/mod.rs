//! Bottle: path translation and single-bottle lifecycle management.
//!
//! * **Path translation** — guest absolute paths resolve under a host root.
//! * **Lifecycle** — exactly one bottle may exist; create materializes a
//!   macOS-like FS skeleton (including `Volumes/linux` → host `/`,
//!   `usr/lib/libc++.1.dylib` → `libSystem.B.dylib`) and installs guest
//!   `libSystem.B.dylib` when a source dylib is found.
//! * **Guest tools** — host path discovery for integration binaries (`7zz`).

mod guest_tools;
mod layout;
mod libsystem;
mod manage;
mod path;
mod registry;

pub use guest_tools::{DEFAULT_7ZZ_PATH, ENV_7ZZ, discover_7zz};
pub use layout::{
    GUEST_LIBCXX_REL, GUEST_LIBCXX_TARGET, MARKER_MAGIC, MARKER_NAME, VOLUMES_LINUX,
    ensure_libcxx_symlink, has_libcxx_symlink, is_bottle_root, materialize,
};
pub use libsystem::{
    ENV_LIBSYSTEM, GUEST_LIBSYSTEM_ID, GUEST_LIBSYSTEM_REL, LibsystemInstall, LibsystemOrigin,
    discover as discover_libsystem, ensure_libsystem_id, install as install_libsystem,
};
pub use manage::{
    BottleError, BottleStatus, CreateOptions, CreateResult, active_root, create, create_with,
    destroy, status,
};
pub use path::{
    PathError, bottle_root, read_c_string, set_bottle_root, translate_path,
    translate_path_with_root,
};
pub use registry::{
    active_file_path, clear_active, config_dir, data_dir, default_bottle_path, read_active,
    write_active,
};
