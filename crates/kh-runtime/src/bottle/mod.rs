//! Bottle: path translation and single-bottle lifecycle management.
//!
//! * **Path translation** — guest absolute paths resolve under a host root.
//! * **Lifecycle** — exactly one bottle may exist; create materializes a
//!   macOS-like FS skeleton (including `Volumes/linux` → host `/`).

mod layout;
mod manage;
mod path;
mod registry;

pub use layout::{MARKER_MAGIC, MARKER_NAME, VOLUMES_LINUX, is_bottle_root, materialize};
pub use manage::{BottleError, BottleStatus, active_root, create, destroy, status};
pub use path::{
    PathError, bottle_root, read_c_string, set_bottle_root, translate_path,
    translate_path_with_root,
};
pub use registry::{
    active_file_path, clear_active, config_dir, data_dir, default_bottle_path, read_active,
    write_active,
};
