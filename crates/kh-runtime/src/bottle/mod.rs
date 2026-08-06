//! Bottle: path translation and single-bottle lifecycle management.
//!
//! * **Path translation** — guest absolute paths resolve under a host root.
//! * **Lifecycle** — exactly one bottle may exist; create materializes a
//!   macOS-like FS skeleton (including `Volumes/linux` → host `/`,
//!   `usr/lib/libc++.1.dylib` / `usr/lib/libcurl.4.dylib` → `libSystem.B.dylib`)
//!   and installs guest `libSystem.B.dylib` from disk discovery or the
//!   crate-embedded freestanding dylib (`resources/libSystem.B.dylib`,
//!   published on crates.io).
//! * **Guest tools** — host path discovery for integration binaries (`7zz`,
//!   `curl`, Apple CLT / `git`).

mod ca_bundle;
mod download_cache;
mod guest_tools;
mod layout;
mod libsystem;
mod manage;
mod path;
mod pkg_extract;
mod registry;
mod swscan;
mod xcode_tools;

pub use ca_bundle::{
    ENV_CA_BUNDLE, GUEST_CA_DIR_REL, GUEST_CA_FILE_REL, MOZILLA_CACERT_URL, active_ca_pem_path,
    ensure_ca_bundle,
};
pub use download_cache::{ENV_CACHE_DIR, ENV_FORCE_DOWNLOAD};
pub use guest_tools::{
    DARWIN_7ZZ_URL, DARWIN_CURL_URL, DEFAULT_7ZZ_PATH, ENV_7ZZ, ENV_CURL, GUEST_7ZZ_REL,
    GUEST_CURL_REL, GUEST_PATH_DIRS, InstallPackage, InstallReport, ToolError, discover_7zz,
    discover_curl, guest_path_to_host, install_package, package_host_path, resolve_guest_program,
};
pub use swscan::ENV_XCODE_TOOLS_VERSION;
pub use xcode_tools::{GUEST_CLT_REL, GUEST_GIT_PATH, GUEST_GIT_REL, bottle_has_git, discover_git};
pub use layout::{
    GUEST_LIBCURL_REL, GUEST_LIBCURL_TARGET, GUEST_LIBCXX_REL, GUEST_LIBCXX_TARGET, GUEST_SSH_REL,
    MARKER_MAGIC, MARKER_NAME, VOLUMES_LINUX, ensure_dev_nodes, ensure_host_bin_bridges,
    ensure_host_ssh_bridge, ensure_libcurl_symlink, ensure_libcxx_symlink, has_host_ssh_bridge,
    has_libcurl_symlink, has_libcxx_symlink, is_bottle_root, materialize,
};
pub use libsystem::{
    EMBEDDED_SOURCE_LABEL, ENV_LIBSYSTEM, GUEST_LIBSYSTEM_ID, GUEST_LIBSYSTEM_REL,
    LibsystemInstall, LibsystemOrigin, discover as discover_libsystem, ensure_libsystem_id,
    install as install_libsystem, install_bytes as install_libsystem_bytes,
};
pub use manage::{
    BottleError, BottleStatus, CreateOptions, CreateResult, active_root, create, create_with,
    destroy, ensure, status,
};
pub use path::{
    PathError, bottle_openat_rel, bottle_root, guest_cwd_string, host_path_to_guest, read_c_string,
    set_bottle_root, translate_path, translate_path_with_root,
};
pub use registry::{
    active_file_path, clear_active, config_dir, data_dir, default_bottle_path, read_active,
    write_active,
};
