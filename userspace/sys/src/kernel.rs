//! The kernel log ring, `sync`, device nodes and the monotonic clock.

use std::ffi::CString;
use std::io;
use std::os::unix::ffi::OsStrExt;
use std::path::Path;

use crate::cvt;

/// `SYSLOG_ACTION_READ_ALL`: copy the ring, leaving it and its readers alone.
const SYSLOG_ACTION_READ_ALL: libc::c_int = 3;
/// `SYSLOG_ACTION_SIZE_BUFFER`: the ring's size.
const SYSLOG_ACTION_SIZE_BUFFER: libc::c_int = 10;

/// Write every filesystem's dirty data out.
pub fn sync() {
    // SAFETY: `sync` takes no arguments and always succeeds.
    unsafe { libc::sync() };
}

/// The size of the kernel log ring in bytes.
pub fn log_buffer_size() -> io::Result<usize> {
    // SAFETY: this action reads no buffer, so a null pointer and length 0 are allowed.
    let size = unsafe { libc::klogctl(SYSLOG_ACTION_SIZE_BUFFER, std::ptr::null_mut(), 0) };
    Ok(cvt(size)? as usize)
}

/// Copy the kernel log ring into `buf`: how many bytes were copied.
pub fn read_log_buffer(buf: &mut [u8]) -> io::Result<usize> {
    let len = libc::c_int::try_from(buf.len()).unwrap_or(libc::c_int::MAX);
    // SAFETY: `buf` is writable for `len` bytes, and the kernel writes no more.
    let read = unsafe { libc::klogctl(SYSLOG_ACTION_READ_ALL, buf.as_mut_ptr().cast(), len) };
    Ok(cvt(read)? as usize)
}

/// Make the character device node `path` for device `major:minor`, with
/// permission bits `mode`.
pub fn make_char_device(path: &Path, mode: libc::mode_t, major: u32, minor: u32) -> io::Result<()> {
    let path = CString::new(path.as_os_str().as_bytes())?;
    let device = libc::makedev(major, minor);
    // SAFETY: `path` is a NUL-terminated string that outlives the call.
    let rc = unsafe { libc::mknod(path.as_ptr(), libc::S_IFCHR | mode, device) };
    cvt(rc).map(drop)
}

/// Whole seconds on `CLOCK_MONOTONIC`. Every process reads the same clock, so
/// one process can write a reading to a file for another, which `Instant`
/// cannot do.
pub fn monotonic_secs() -> u64 {
    let mut now = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: `now` is a writable `timespec`.
    unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut now) };
    now.tv_sec as u64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_monotonic_clock_never_goes_back() {
        let first = monotonic_secs();
        let second = monotonic_secs();
        assert!(first > 0 && second >= first);
    }

    #[test]
    fn a_node_never_replaces_an_existing_file() {
        let path = std::env::temp_dir().join(format!("titan-sys-mknod-{}", std::process::id()));
        std::fs::write(&path, b"keep").unwrap();
        let err = make_char_device(&path, 0o600, 1, 11).unwrap_err();
        let kept = std::fs::read(&path).unwrap();
        let _ = std::fs::remove_file(&path);
        assert_eq!(err.kind(), io::ErrorKind::AlreadyExists);
        assert_eq!(kept, b"keep");
    }

    #[test]
    fn the_kernel_log_reads_back_within_its_size() {
        // A container may refuse the ring (dmesg_restrict without CAP_SYSLOG).
        let Ok(size) = log_buffer_size() else {
            return;
        };
        let mut buf = vec![0; size];
        if let Ok(read) = read_log_buffer(&mut buf) {
            assert!(read <= size);
        }
    }
}
