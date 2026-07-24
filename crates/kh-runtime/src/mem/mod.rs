//! Guest and host page geometry for Darwin arm64 images on Linux.

mod layout;
#[allow(unsafe_code)]
mod map;
#[allow(unsafe_code)]
mod registry;

pub use layout::{DARWIN_ARM64_PAGE_SIZE, GuestPageSize, HostPageSize, PageError, PageLayout};
pub use map::{
    GuestMemory, MapError, MapRequest, MappedRegion, VM_PROT_EXECUTE, VM_PROT_READ, VM_PROT_WRITE,
    darwin_to_host_prot, map_stack, mprotect_darwin, mprotect_rw,
};
pub use registry::{
    RegRegionSnapshot, RemoveOutcome, check_range as registry_check_range, clear as registry_clear,
    find_covering as registry_find, is_active as registry_is_active, register_borrowed,
    register_owned, remove_range as registry_remove, update_prot as registry_update_prot,
};

#[cfg(test)]
pub(crate) use registry::test_lock as registry_test_lock;
