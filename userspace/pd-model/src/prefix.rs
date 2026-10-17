//! IPv6 blocks for one passthrough session.
//!
//! The core assigns a /56. The link prefix is its lowest /64 and the customer
//! router is delegated the upper /57. Those are the same cuts the SMF uses when
//! the router sends no PD_EXCLUDE.

use std::fmt;
use std::net::Ipv6Addr;
use std::str::FromStr;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Block {
    pub addr: [u8; 16],
    pub len: u8,
}

impl Block {
    pub fn new(addr: [u8; 16], len: u8) -> Result<Self, String> {
        if len > 128 {
            return Err("Prefix length is longer than 128".into());
        }
        let mut block = Self { addr, len };
        block.mask();
        Ok(block)
    }

    /// The /56 that contains `addr`.
    pub fn containing_56(addr: [u8; 16]) -> Self {
        let mut block = Self { addr, len: 56 };
        block.mask();
        block
    }

    pub fn link64(self) -> Self {
        let mut addr = self.addr;
        addr[7] = 0;
        Self { addr, len: 64 }
    }

    /// Upper /57 of a /56. The link /64 sits in the lower half.
    pub fn delegated57(self) -> Self {
        let mut addr = self.addr;
        addr[7] = 0x80;
        Self { addr, len: 57 }
    }

    pub fn contains(self, addr: &[u8; 16]) -> bool {
        let full = self.len / 8;
        let rest = self.len % 8;
        if addr[..full as usize] != self.addr[..full as usize] {
            return false;
        }
        if rest == 0 {
            return true;
        }
        let shift = 8 - rest;
        addr[full as usize] >> shift == self.addr[full as usize] >> shift
    }

    fn mask(&mut self) {
        let full = self.len / 8;
        let rest = self.len % 8;
        if rest != 0 {
            let keep = !0u8 << (8 - rest);
            self.addr[full as usize] &= keep;
        }
        for byte in &mut self.addr[full as usize + usize::from(rest != 0)..] {
            *byte = 0;
        }
    }
}

impl fmt::Display for Block {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", Ipv6Addr::from(self.addr), self.len)
    }
}

/// Accept a /56, or a /64 (the link address the core shows), and store the /56.
pub fn parse_pinned(text: &str) -> Result<Block, String> {
    let text = text.trim();
    if text.is_empty() {
        return Err("Pinned block is empty".into());
    }
    let (addr, len) = text
        .rsplit_once('/')
        .ok_or("Pinned block must be an IPv6 prefix, for example 2001:db8:f0:1200::/56")?;
    let len: u8 = len
        .parse()
        .map_err(|_| "Pinned block has no prefix length".to_owned())?;
    if len != 56 && len != 64 {
        return Err("Pin a /56, or the link /64 inside it".into());
    }
    let addr =
        Ipv6Addr::from_str(addr).map_err(|_| "Pinned block is not an IPv6 prefix".to_owned())?;
    Ok(Block::containing_56(addr.octets()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(text: &str) -> Block {
        let (addr, len) = text.rsplit_once('/').unwrap();
        let len: u8 = len.parse().unwrap();
        Block::new(Ipv6Addr::from_str(addr).unwrap().octets(), len).unwrap()
    }

    #[test]
    fn dynamic_session_cuts_match_the_core() {
        let link = parse("2001:db8:ff:d100::/64");
        let block = Block::containing_56(link.addr);
        assert_eq!(block.to_string(), "2001:db8:ff:d100::/56");
        assert_eq!(block.link64().to_string(), "2001:db8:ff:d100::/64");
        assert_eq!(block.delegated57().to_string(), "2001:db8:ff:d180::/57");
        assert!(block.contains(&parse("2001:db8:ff:d1ff::/128").addr));
        assert!(!block.contains(&parse("2001:db8:ff:d200::/128").addr));
        assert!(
            block
                .delegated57()
                .contains(&parse("2001:db8:ff:d181::1/128").addr)
        );
        assert!(
            !block
                .delegated57()
                .contains(&parse("2001:db8:ff:d100::1/128").addr)
        );
    }

    #[test]
    fn pinned_text_becomes_the_containing_56() {
        assert_eq!(
            parse_pinned("2001:db8:f0:12ab::/64").unwrap().to_string(),
            "2001:db8:f0:1200::/56"
        );
        assert!(parse_pinned("2001:db8:f0:1200::/48").is_err());
        assert!(parse_pinned("not-an-address").is_err());
    }
}
