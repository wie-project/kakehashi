//! `libsystem_c` — C library surface (stdio, string, POSIX, net, …).

pub(crate) mod dl;
pub(crate) mod dns_name;
pub(crate) mod extra_path;
pub(crate) mod locale;
pub(crate) mod net;
pub(crate) mod path_extras;
pub(crate) mod posix;
pub(crate) mod regex;
pub(crate) mod simple;
pub(crate) mod stdio;
pub(crate) mod string;
