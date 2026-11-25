//! Waiting on several descriptors at once.

use std::io;
use std::os::fd::{AsRawFd, BorrowedFd};
use std::time::Duration;

use crate::cvt;

/// The most descriptors one wait takes. The keeper waits on four at most.
pub const MAX_FDS: usize = 8;

/// Wait until one of `fds` can be read or `timeout` passes: how many are
/// ready, 0 after the timeout. `None` entries are skipped, so a caller can
/// list descriptors it may not have open; more than `MAX_FDS` present ones
/// are refused. A signal ends the wait early with `ErrorKind::Interrupted`.
pub fn wait_readable(fds: &[Option<BorrowedFd<'_>>], timeout: Duration) -> io::Result<usize> {
    let mut set = [libc::pollfd {
        fd: -1,
        events: 0,
        revents: 0,
    }; MAX_FDS];
    let mut len = 0;
    for fd in fds.iter().flatten() {
        let slot = set
            .get_mut(len)
            .ok_or_else(|| io::Error::from(io::ErrorKind::InvalidInput))?;
        *slot = libc::pollfd {
            fd: fd.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        len += 1;
    }
    let timeout = libc::c_int::try_from(timeout.as_millis()).unwrap_or(libc::c_int::MAX);
    // SAFETY: the first `len` records of `set` are initialised for the kernel to
    // update, and their descriptors stay borrowed for the whole call.
    let ready = unsafe { libc::poll(set.as_mut_ptr(), len as libc::nfds_t, timeout) };
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
        assert_eq!(wait_readable(&[Some(rx.as_fd())], Duration::ZERO).unwrap(), 0);
        tx.send(b"x").unwrap();
        let fds = [Some(tx.as_fd()), None, Some(rx.as_fd())];
        assert_eq!(wait_readable(&fds, Duration::from_secs(5)).unwrap(), 1);
    }

    #[test]
    fn an_idle_wait_lasts_its_timeout() {
        let (_tx, rx) = UnixDatagram::pair().unwrap();
        let start = Instant::now();
        let ready = wait_readable(&[Some(rx.as_fd())], Duration::from_millis(50)).unwrap();
        assert_eq!(ready, 0);
        assert!(start.elapsed() >= Duration::from_millis(40));
    }

    #[test]
    fn more_descriptors_than_one_wait_takes_are_refused() {
        let (_tx, rx) = UnixDatagram::pair().unwrap();
        let fds = [Some(rx.as_fd()); MAX_FDS + 1];
        let err = wait_readable(&fds, Duration::ZERO).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
        assert_eq!(wait_readable(&fds[..MAX_FDS], Duration::ZERO).unwrap(), 0);
    }
}
