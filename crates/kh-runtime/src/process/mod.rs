//! Process-wide guest state: run flags, stack bootstrap, dyld image table.

mod state;
pub mod dyld_table;
pub mod stack;

pub use state::*;
