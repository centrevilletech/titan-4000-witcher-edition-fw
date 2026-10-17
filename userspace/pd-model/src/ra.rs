//! Router Advertisements the bench router already accepts.
//!
//! The core sends hop limit 64, other-stateful, a /64 with autonomous and not
//! on-link, MTU 1400, and a source link-layer address. Infinite lifetimes are
//! why a router that missed a renumber never asks again, so advertisements from
//! the Titan carry finite lifetimes and are repeated.

use crate::prefix::Block;

pub const HOP_LIMIT: u8 = 64;
pub const OTHER_STATEFUL: u8 = 0x40;
pub const ROUTER_LIFETIME: u16 = 1800;
pub const PREFIX_PREFERRED: u32 = 3600;
pub const PREFIX_VALID: u32 = 7200;
pub const MTU: u32 = 1400;
const AUTONOMOUS: u8 = 0x40;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Advertisement {
    pub hop_limit: u8,
    pub flags: u8,
    pub router_lifetime: u16,
    pub prefixes: Vec<(Block, u32, u32, u8)>,
    pub mtu: Option<u32>,
    pub source_mac: Option<[u8; 6]>,
}

impl Advertisement {
    /// The periodic advertisement for a pinned block. `link` is that block's /64.
    pub fn for_block(link: Block, source_mac: [u8; 6]) -> Self {
        Self {
            hop_limit: HOP_LIMIT,
            flags: OTHER_STATEFUL,
            router_lifetime: ROUTER_LIFETIME,
            prefixes: vec![(link, PREFIX_VALID, PREFIX_PREFERRED, AUTONOMOUS)],
            mtu: Some(MTU),
            source_mac: Some(source_mac),
        }
    }

    /// Tell the router a previous default router and its prefixes are gone.
    pub fn withdraw(prefixes: Vec<Block>, source_mac: [u8; 6]) -> Self {
        Self {
            hop_limit: HOP_LIMIT,
            flags: OTHER_STATEFUL,
            router_lifetime: 0,
            prefixes: prefixes
                .into_iter()
                .map(|prefix| (prefix, 0, 0, AUTONOMOUS))
                .collect(),
            mtu: None,
            source_mac: Some(source_mac),
        }
    }
}

pub fn emit(ad: &Advertisement) -> Vec<u8> {
    let mut out = vec![134, 0, 0, 0, ad.hop_limit, ad.flags];
    out.extend_from_slice(&ad.router_lifetime.to_be_bytes());
    out.extend_from_slice(&[0; 8]);
    for (prefix, valid, preferred, flags) in &ad.prefixes {
        out.extend_from_slice(&[3, 4, prefix.len, *flags]);
        out.extend_from_slice(&valid.to_be_bytes());
        out.extend_from_slice(&preferred.to_be_bytes());
        out.extend_from_slice(&[0; 4]);
        out.extend_from_slice(&prefix.addr);
    }
    if let Some(mtu) = ad.mtu {
        out.extend_from_slice(&[5, 1, 0, 0]);
        out.extend_from_slice(&mtu.to_be_bytes());
    }
    if let Some(mac) = ad.source_mac {
        out.extend_from_slice(&[1, 1]);
        out.extend_from_slice(&mac);
    }
    out
}

/// Prefixes carried by an RA, if `icmp` is one. Used to withdraw a prefix the core already advertised.
pub fn prefixes_of(icmp: &[u8]) -> Vec<Block> {
    if icmp.first() != Some(&134) || icmp.len() < 16 {
        return Vec::new();
    }
    let mut found = Vec::new();
    let mut rest = &icmp[16..];
    while rest.len() >= 2 {
        let (kind, len) = (rest[0], rest[1] as usize * 8);
        if len < 8 || rest.len() < len {
            break;
        }
        if kind == 3 && len >= 32 {
            let mut addr = [0; 16];
            addr.copy_from_slice(&rest[16..32]);
            if let Ok(block) = Block::new(addr, rest[2]) {
                found.push(block);
            }
        }
        rest = &rest[len..];
    }
    found
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::prefix::parse_pinned;

    #[test]
    fn advertisement_matches_the_shape_the_router_accepts() {
        let link = parse_pinned("2001:db8:ff:d100::/64").unwrap().link64();
        let bytes = emit(&Advertisement::for_block(
            link,
            [0x44, 0x6f, 0xd8, 0x80, 0x11, 0xde],
        ));
        assert_eq!(bytes[0], 134);
        assert_eq!(bytes[4], 64);
        assert_eq!(bytes[5], 0x40, "other-stateful, not managed");
        assert_eq!(u16::from_be_bytes([bytes[6], bytes[7]]), 1800);
        assert_eq!(&bytes[16..18], &[3, 4]);
        assert_eq!(bytes[19] & 0xc0, 0x40, "autonomous, not on-link");
        assert_eq!(prefixes_of(&bytes)[0].to_string(), "2001:db8:ff:d100::/64");
        assert!(bytes.windows(4).any(|w| w == 1400u32.to_be_bytes()));
    }

    #[test]
    fn withdraw_zeros_the_router_lifetime_and_the_prefix() {
        let link = parse_pinned("2001:db8:ff:d200::/64").unwrap().link64();
        let bytes = emit(&Advertisement::withdraw(vec![link], [2, 0, 0, 0, 1, 1]));
        assert_eq!(u16::from_be_bytes([bytes[6], bytes[7]]), 0);
        assert_eq!(&bytes[20..28], &[0; 8]);
    }
}
