//! Process-wide guest state: run flags, stack bootstrap, dyld image table.

pub mod dyld_table;
pub mod stack;
mod state;

pub use state::*;
