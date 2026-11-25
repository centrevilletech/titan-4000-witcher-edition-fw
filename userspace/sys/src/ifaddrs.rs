//! Interface addresses from `getifaddrs`, which reads them over rtnetlink,
//! alias labels included, without spawning `ip`.

use std::ffi::CStr;
use std::io;
use std::marker::PhantomData;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::ptr;

use crate::cvt;

/// The kernel's interface address list, freed when dropped.
pub struct InterfaceAddrs {
    head: *mut libc::ifaddrs,
}

/// One IPv4 or IPv6 address and the interface label it is on, borrowed from
/// an `InterfaceAddrs`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IfAddr<'a> {
    name: &'a [u8],
    /// The address.
    pub addr: IpAddr,
}

impl IfAddr<'_> {
    /// The interface label, for example `br0:9`.
    pub fn name(&self) -> &[u8] {
        self.name
    }

    /// The address is on interface `dev`, directly or through an alias label
    /// (`br0:9` is on `br0`).
    pub fn is_on(&self, dev: &str) -> bool {
        self.name.split(|&byte| byte == b':').next() == Some(dev.as_bytes())
    }
}

impl InterfaceAddrs {
    /// Read the list.
    pub fn read() -> io::Result<Self> {
        let mut head = ptr::null_mut();
        // SAFETY: `head` is a valid place for `getifaddrs` to store the list.
        let rc = unsafe { libc::getifaddrs(&mut head) };
        cvt(rc)?;
        Ok(Self { head })
    }

    /// Every IPv4 and IPv6 address, in the kernel's order.
    pub fn iter(&self) -> Iter<'_> {
        Iter {
            node: self.head,
            list: PhantomData,
        }
    }
}

impl Drop for InterfaceAddrs {
    fn drop(&mut self) {
        // SAFETY: the pointer came from a successful `getifaddrs` and is freed
        // only here.
        unsafe { libc::freeifaddrs(self.head) };
    }
}

/// The addresses of an `InterfaceAddrs`, which it borrows.
pub struct Iter<'a> {
    node: *mut libc::ifaddrs,
    list: PhantomData<&'a InterfaceAddrs>,
}

impl<'a> Iterator for Iter<'a> {
    type Item = IfAddr<'a>;

    fn next(&mut self) -> Option<IfAddr<'a>> {
        while !self.node.is_null() {
            // SAFETY: `node` is a non-null node of the borrowed list, which stays
            // allocated for `'a`.
            let entry: &'a libc::ifaddrs = unsafe { &*self.node };
            self.node = entry.ifa_next;
            if entry.ifa_addr.is_null() || entry.ifa_name.is_null() {
                continue;
            }
            // SAFETY: every socket address starts with its family, and `ifa_addr`
            // is non-null and owned by the list.
            let family = unsafe { ptr::addr_of!((*entry.ifa_addr).sa_family).read_unaligned() };
            let addr = match libc::c_int::from(family) {
                libc::AF_INET => {
                    // SAFETY: an `AF_INET` address is a `sockaddr_in`, owned by the list.
                    let sin = unsafe { entry.ifa_addr.cast::<libc::sockaddr_in>().read_unaligned() };
                    IpAddr::V4(Ipv4Addr::from(sin.sin_addr.s_addr.to_ne_bytes()))
                }
                libc::AF_INET6 => {
                    // SAFETY: an `AF_INET6` address is a `sockaddr_in6`, owned by the list.
                    let sin6 = unsafe { entry.ifa_addr.cast::<libc::sockaddr_in6>().read_unaligned() };
                    IpAddr::V6(Ipv6Addr::from(sin6.sin6_addr.s6_addr))
                }
                _ => continue,
            };
            // SAFETY: `ifa_name` is a non-null, NUL-terminated name owned by the
            // list for `'a`.
            let name: &'a CStr = unsafe { CStr::from_ptr(entry.ifa_name) };
            return Some(IfAddr {
                name: name.to_bytes(),
                addr,
            });
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn on(name: &[u8]) -> IfAddr<'_> {
        IfAddr {
            name,
            addr: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        }
    }

    #[test]
    fn an_alias_label_is_on_its_interface() {
        assert!(on(b"br0").is_on("br0"));
        assert!(on(b"br0:9").is_on("br0"));
        assert!(!on(b"br01").is_on("br0"));
        assert!(!on(b"lte0pdn0").is_on("br0"));
        assert!(!on(b"br0").is_on("br0:9"));
        assert_eq!(on(b"br0:9").name(), b"br0:9");
    }

    #[test]
    fn loopback_addresses_read_back_as_loopback() {
        let addrs = InterfaceAddrs::read().unwrap();
        for addr in addrs.iter().filter(|addr| addr.is_on("lo")) {
            assert!(addr.addr.is_loopback(), "{addr:?}");
        }
    }
}
