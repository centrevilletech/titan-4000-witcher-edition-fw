//! How many bulk flows share the uplink: one bit per hash bucket of each flow's
//! addresses and ports, set over a window, then counted (linear counting in one word).
//!
//! Why selector 3 needs it: a congestion signal halves nothing but the window of the
//! flow it hits. One CUBIC flow then drains the queue far below where it was signalled
//! (its window drops 30%), while four flows dent it by a quarter of that. So the floor
//! that keeps the second uplink carrier scheduled must be deeper for one flow than for
//! many.
//!
//! No tables, no division: a hash, a multiply by the golden ratio and a shift pick the
//! bucket. Two flows in one bucket count once, which errs toward the deeper floor.

#![forbid(unsafe_code)]

/// Fibonacci hashing: the top five bits of `x * 2^32 / phi` spread nearby keys (such
/// as consecutive source ports) over all 32 buckets.
const GOLDEN: u32 = 0x9e37_79b1;

const TCP: u8 = 6;
const UDP: u8 = 17;

/// How much of the packet the key reads: an IPv6 header and its TCP or UDP ports.
pub const KEY_BYTES: usize = 44;

/// The bucket bit of the flow whose IP packet starts `ip`.
///
/// The key is the addresses, the transport protocol and, for TCP and UDP, the ports:
/// for IPv4 with a 20-byte header, the two addresses; for IPv6, the low words of both
/// addresses (the interface identifiers) and the flow label. A packet shorter than
/// [`KEY_BYTES`], an IPv4 header with options, or another protocol simply keys on less,
/// the same way every time. Anything else lands in one bucket.
pub fn flow_bit(ip: &[u8]) -> u32 {
    1 << (flow_key(ip).wrapping_mul(GOLDEN) >> 27)
}

/// Bulk flows a window's bitmap holds, at least 1.
pub fn count(bits: u32) -> u32 {
    bits.count_ones().max(1)
}

fn flow_key(ip: &[u8]) -> u32 {
    let Some(h) = ip.first_chunk::<KEY_BYTES>() else {
        return 0;
    };
    let word = |at: usize| u32::from_le_bytes([h[at], h[at + 1], h[at + 2], h[at + 3]]);
    // TCP's and UDP's ports; other protocols' first word may change per packet (ICMP).
    let ports = |protocol: u8, at: usize| if protocol == TCP || protocol == UDP { word(at) } else { 0 };
    match h[0] >> 4 {
        4 => {
            let protocol = h[9];
            let ports = if h[0] == 0x45 { ports(protocol, 20) } else { 0 };
            word(12) ^ word(16).rotate_left(16) ^ ports ^ u32::from(protocol)
        }
        6 => {
            let protocol = h[6];
            let label = word(0) & 0xffff_0f00;
            word(20) ^ word(36).rotate_left(16) ^ ports(protocol, 40) ^ label ^ u32::from(protocol)
        }
        _ => 0,
    }
}
