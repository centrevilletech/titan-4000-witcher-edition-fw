//! Interface addresses from `getifaddrs`, which reads them over rtnetlink,
//! alias labels included, without spawning `ip`.

use std::ffi::{CStr, OsStr, OsString};
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::os::unix::ffi::OsStrExt;
use std::ptr;

use crate::cvt;

/// One IPv4 or IPv6 address and the interface label it is on.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IfAddr {
    name: OsString,
    /// The address.
    pub addr: IpAddr,
}

impl IfAddr {
    /// The interface label, for example `br0:9`.
    pub fn name(&self) -> &OsStr {
        &self.name
    }

    /// The address is on interface `dev`, directly or through an alias label
    /// (`br0:9` is on `br0`).
    pub fn is_on(&self, dev: &str) -> bool {
        self.name.as_bytes().split(|&byte| byte == b':').next() == Some(dev.as_bytes())
    }
}

/// Every IPv4 and IPv6 interface address, in the kernel's order.
pub fn interface_addrs() -> io::Result<Vec<IfAddr>> {
    let mut head = ptr::null_mut();
    // SAFETY: `head` is a valid place for `getifaddrs` to store the list.
    let rc = unsafe { libc::getifaddrs(&mut head) };
    cvt(rc)?;
    let list = List(head);
    let mut addrs = Vec::new();
    let mut node = list.0;
    while !node.is_null() {
        // SAFETY: `node` is a non-null node of `list`, which stays allocated
        // until `list` is dropped at the end of this function.
        let entry = unsafe { &*node };
        node = entry.ifa_next;
        if entry.ifa_addr.is_null() || entry.ifa_name.is_null() {
            continue;
        }
        // SAFETY: every socket address starts with its family, and `ifa_addr`
        // is non-null and owned by `list`.
        let family = unsafe { ptr::addr_of!((*entry.ifa_addr).sa_family).read_unaligned() };
        let addr = match libc::c_int::from(family) {
            libc::AF_INET => {
                // SAFETY: an `AF_INET` address is a `sockaddr_in`, owned by `list`.
                let sin = unsafe { entry.ifa_addr.cast::<libc::sockaddr_in>().read_unaligned() };
                IpAddr::V4(Ipv4Addr::from(sin.sin_addr.s_addr.to_ne_bytes()))
            }
            libc::AF_INET6 => {
                // SAFETY: an `AF_INET6` address is a `sockaddr_in6`, owned by `list`.
                let sin6 = unsafe { entry.ifa_addr.cast::<libc::sockaddr_in6>().read_unaligned() };
                IpAddr::V6(Ipv6Addr::from(sin6.sin6_addr.s6_addr))
            }
            _ => continue,
        };
        // SAFETY: `ifa_name` is a non-null, NUL-terminated name owned by `list`.
        let name = unsafe { CStr::from_ptr(entry.ifa_name) };
        addrs.push(IfAddr {
            name: OsStr::from_bytes(name.to_bytes()).to_owned(),
            addr,
        });
    }
    Ok(addrs)
}

/// The list `getifaddrs` returned, freed once when dropped.
struct List(*mut libc::ifaddrs);

impl Drop for List {
    fn drop(&mut self) {
        // SAFETY: the pointer came from a successful `getifaddrs` and is freed
        // only here.
        unsafe { libc::freeifaddrs(self.0) };
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn on(name: &str) -> IfAddr {
        IfAddr {
            name: name.into(),
            addr: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        }
    }

    #[test]
    fn an_alias_label_is_on_its_interface() {
        assert!(on("br0").is_on("br0"));
        assert!(on("br0:9").is_on("br0"));
        assert!(!on("br01").is_on("br0"));
        assert!(!on("lte0pdn0").is_on("br0"));
        assert!(!on("br0").is_on("br0:9"));
        assert_eq!(on("br0:9").name(), "br0:9");
    }

    #[test]
    fn loopback_addresses_read_back_as_loopback() {
        let addrs = interface_addrs().unwrap();
        for addr in addrs.iter().filter(|addr| addr.is_on("lo")) {
            assert!(addr.addr.is_loopback(), "{addr:?}");
        }
    }
}
