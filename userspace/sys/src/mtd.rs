//! A raw flash (MTD) partition's bad block table, read only.

use std::io;
use std::os::fd::{AsRawFd, BorrowedFd};

use crate::cvt;

/// `MEMGETBADBLOCK`, `_IOW('M', 11, __kernel_loff_t)` in `<mtd/mtd-abi.h>`.
/// Its neighbour 12 is `MEMSETBADBLOCK`, which marks a block bad for good,
/// and Linux 3.10 accepts it even on a read-only descriptor: a test pins
/// this number.
const MEMGETBADBLOCK: u32 = 0x4008_4d0b;

/// Whether the bad block table of the MTD partition open on `mtd` marks the
/// erase block at byte `offset` bad. It only reads the table.
pub fn is_bad_block(mtd: BorrowedFd<'_>, offset: u64) -> io::Result<bool> {
    let offset = i64::try_from(offset).map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
    // SAFETY: `MEMGETBADBLOCK` reads one `__kernel_loff_t` (an `i64`) through
    // the pointer and writes nothing back; `offset` lives across the call.
    let rc = unsafe { libc::ioctl(mtd.as_raw_fd(), MEMGETBADBLOCK as libc::Ioctl, &offset as *const i64) };
    Ok(cvt(rc)? > 0)
}

#[cfg(test)]
mod tests {
    use std::os::fd::AsFd;

    use super::*;

    /// asm-generic's `_IOW`, which ARM uses: direction, size, type, number.
    fn iow(kind: u8, number: u32, size: u32) -> u32 {
        (1 << 30) | (size << 16) | (u32::from(kind) << 8) | number
    }

    #[test]
    fn the_ioctl_is_the_read_only_one() {
        assert_eq!(MEMGETBADBLOCK, iow(b'M', 11, 8));
        assert_ne!(MEMGETBADBLOCK, iow(b'M', 12, 8), "MEMSETBADBLOCK");
    }

    #[test]
    fn a_file_that_is_no_flash_partition_is_an_error() {
        let file = std::fs::File::open("/dev/null").unwrap();
        assert!(is_bad_block(file.as_fd(), 0).is_err());
    }
}
