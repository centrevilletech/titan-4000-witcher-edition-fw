//! Waiting on several descriptors at once.

use std::io;
use std::os::fd::{AsRawFd, BorrowedFd};
use std::time::Duration;

use crate::cvt;

/// Wait until one of `fds` can be read or `timeout` passes: how many are
/// ready, 0 after the timeout. A signal ends the wait early with
/// `ErrorKind::Interrupted`.
pub fn wait_readable(fds: &[BorrowedFd<'_>], timeout: Duration) -> io::Result<usize> {
    let mut set: Vec<libc::pollfd> = fds
        .iter()
        .map(|fd| libc::pollfd {
            fd: fd.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        })
        .collect();
    let timeout = libc::c_int::try_from(timeout.as_millis()).unwrap_or(libc::c_int::MAX);
    // SAFETY: `set` holds `set.len()` initialised records for the kernel to
    // update, and their descriptors stay borrowed for the whole call.
    let ready = unsafe { libc::poll(set.as_mut_ptr(), set.len() as libc::nfds_t, timeout) };
    Ok(cvt(ready)? as usize)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::fd::AsFd;
    use std::os::unix::net::UnixDatagram;
    use std::time::Instant;

    #[test]
    fn a_queued_datagram_ends_the_wait() {
        let (tx, rx) = UnixDatagram::pair().unwrap();
        assert_eq!(wait_readable(&[rx.as_fd()], Duration::ZERO).unwrap(), 0);
        tx.send(b"x").unwrap();
        let ready = wait_readable(&[tx.as_fd(), rx.as_fd()], Duration::from_secs(5)).unwrap();
        assert_eq!(ready, 1);
    }

    #[test]
    fn an_idle_wait_lasts_its_timeout() {
        let (_tx, rx) = UnixDatagram::pair().unwrap();
        let start = Instant::now();
        assert_eq!(wait_readable(&[rx.as_fd()], Duration::from_millis(50)).unwrap(), 0);
        assert!(start.elapsed() >= Duration::from_millis(40));
    }
}
