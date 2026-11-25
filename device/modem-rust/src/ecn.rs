//! ECN (RFC 3168) on raw IPv4 and IPv6 headers: read the codepoint, mark CE.
//!
//! The slice starts at byte 0 of the IP header (`pkt_buf + 2` at hook 4). Both
//! families keep the two ECN bits in byte 1: bits 1..0 of the IPv4 TOS byte, bits
//! 5..4 of IPv6's traffic class.

#![forbid(unsafe_code)]

/// The ECN codepoint of a packet.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Ecn {
    NotEct,
    Ect1,
    Ect0,
    Ce,
}

impl Ecn {
    const fn from_bits(bits: u8) -> Self {
        match bits & 3 {
            0 => Self::NotEct,
            1 => Self::Ect1,
            2 => Self::Ect0,
            _ => Self::Ce,
        }
    }

    /// ECT(0) or ECT(1): the sender accepts CE in place of a drop.
    pub const fn is_capable(self) -> bool {
        matches!(self, Self::Ect0 | Self::Ect1)
    }
}

/// Where a header keeps its ECN bits in byte 1.
#[derive(Copy, Clone)]
enum Family {
    V4,
    V6,
}

impl Family {
    /// The family of `ip`, if its version nibble is 4 or 6 and its fixed header
    /// (20 or 40 bytes) is all there.
    fn of(ip: &[u8]) -> Option<Self> {
        match ip.first()? >> 4 {
            4 if ip.len() >= 20 => Some(Self::V4),
            6 if ip.len() >= 40 => Some(Self::V6),
            _ => None,
        }
    }

    const fn shift(self) -> u32 {
        match self {
            Self::V4 => 0,
            Self::V6 => 4,
        }
    }
}

/// The ECN codepoint of the header at the start of `ip`.
pub fn ecn(ip: &[u8]) -> Option<Ecn> {
    let family = Family::of(ip)?;
    Some(Ecn::from_bits(ip.get(1)? >> family.shift()))
}

/// Whether the header at the start of `ip` is ECT(0) or ECT(1).
pub fn is_ect(ip: &[u8]) -> bool {
    ecn(ip).is_some_and(Ecn::is_capable)
}

/// Mark an ECT(0) or ECT(1) packet CE in place and return `true`.
///
/// Anything else (not ECT, already CE, not IPv4 or IPv6, truncated) is left
/// untouched and returns `false`. IPv4's header checksum is updated
/// incrementally (RFC 1624, eqn. 3).
pub fn mark_ce(ip: &mut [u8]) -> bool {
    let Some(family) = Family::of(ip) else {
        return false;
    };
    let Some(hdr) = ip.first_chunk_mut::<20>() else {
        return false;
    };
    let bits = (hdr[1] >> family.shift()) & 3;
    if !Ecn::from_bits(bits).is_capable() {
        return false;
    }
    hdr[1] |= 3 << family.shift();
    if let Family::V4 = family {
        // The 16-bit word holding TOS grew by `3 - bits`: HC' = ~(~HC + delta).
        let checksum = u16::from_be_bytes([hdr[10], hdr[11]]);
        let checksum = !ones_complement_add(!checksum, u16::from(3 - bits));
        [hdr[10], hdr[11]] = checksum.to_be_bytes();
    }
    true
}

/// 16-bit one's-complement addition (end-around carry).
const fn ones_complement_add(a: u16, b: u16) -> u16 {
    let (sum, carry) = a.overflowing_add(b);
    sum.wrapping_add(carry as u16)
}
