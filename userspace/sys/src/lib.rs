//! The workspace's audited `unsafe`.
//!
//! Small, typed, safe wrappers over the Linux calls the keeper and the
//! first-boot service make and std does not offer: packet and raw sockets,
//! interface addresses, `poll`, signals, priorities, reaping, the hooks a
//! child runs between `fork` and `exec`, the kernel log ring, device nodes,
//! the monotonic clock and a flash partition's bad block table. This is the
//! only crate in the workspace that may use `unsafe`: `titan-pd-keeper`,
//! `titan-pd-model` and `witcher-firstboot` are `#![forbid(unsafe_code)]`.
//!
//! Every wrapper turns a failed call into the `io::Error` for `errno`, takes
//! Rust types (`OwnedFd`, `BorrowedFd`, slices, addresses) and hands the
//! kernel pointers only to memory it owns, for the length it states. Each
//! `unsafe` block says why it is sound in a `// SAFETY:` comment, and CI runs
//! clippy with `undocumented_unsafe_blocks` denied.
#![deny(unsafe_op_in_unsafe_fn)]
#![deny(clippy::undocumented_unsafe_blocks)]

use std::io;

pub mod ifaddrs;
pub mod kernel;
pub mod mtd;
pub mod poll;
pub mod process;
pub mod socket;

/// A negative return (with `errno` set) becomes the `io::Error` for `errno`.
fn cvt(rc: libc::c_int) -> io::Result<libc::c_int> {
    if rc < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(rc)
    }
}

/// The same for calls that return a byte count.
fn cvt_len(rc: libc::ssize_t) -> io::Result<usize> {
    usize::try_from(rc).map_err(|_| io::Error::last_os_error())
}
