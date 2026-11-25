//! ECN (RFC 3168) CE marking for IPv4 (with RFC 1624 incremental checksum update) and IPv6.
//!
//! Operates on a raw IP packet slice starting at byte 0 of the IP header.
//! In Titan 4000 `gipc_rx_loop`, the IP header begins at `pkt_buf + 2`.

/// Attempt to mark an ECT(0) or ECT(1) packet with CE in place.
///
/// Returns `true` if the packet was ECT(0) or ECT(1) and has now been marked CE.
/// Returns `false` for non-ECT (`00`), already-CE (`11`), unknown IP versions,
/// or truncated packets (leaving the buffer untouched).
#[inline]
pub fn try_mark_ce(ip: &mut [u8]) -> bool {
    if ip.len() < 20 {
        return false;
    }
    let ver = ip[0] & 0xf0;
    if ver == 0x40 {
        // IPv4: TOS/DSCP+ECN is byte 1, ECN bits are [1:0].
        // Checksum is big-endian u16 at bytes 10..12.
        let tos = ip[1];
        let ecn = tos & 0x03;
        if ecn != 0x01 && ecn != 0x02 {
            return false;
        }
        let delta = (0x03 - ecn) as u32;
        ip[1] = tos | 0x03;

        let c_old = ((ip[10] as u32) << 8) | (ip[11] as u32);
        // RFC 1624 one's-complement subtraction: c_new = ~(~c_old + delta) = c_old - delta - borrow.
        let (mut c_new, borrow) = c_old.overflowing_sub(delta);
        if borrow {
            c_new = c_new.wrapping_sub(1);
        }
        let c16 = (c_new & 0xffff) as u16;
        let c16 = if c16 == 0xffff { 0x0000 } else { c16 };
        ip[10] = (c16 >> 8) as u8;
        ip[11] = (c16 & 0xff) as u8;
        true
    } else if ver == 0x60 {
        // IPv6: minimum header is 40 bytes; Traffic Class low nibble is byte 1 bits [7:4],
        // ECN bits are byte 1 bits [5:4] (0x10 = ECT(1), 0x20 = ECT(0), 0x30 = CE).
        if ip.len() < 40 {
            return false;
        }
        let b1 = ip[1];
        let ecn = b1 & 0x30;
        if ecn != 0x10 && ecn != 0x20 {
            return false;
        }
        ip[1] = b1 | 0x30;
        true
    } else {
        false
    }
}

/// Inspect whether an IP packet carries ECT(0) or ECT(1) without modifying it.
#[inline]
pub fn is_ect(ip: &[u8]) -> bool {
    if ip.len() < 20 {
        return false;
    }
    match ip[0] & 0xf0 {
        0x40 => {
            let ecn = ip[1] & 0x03;
            ecn == 0x01 || ecn == 0x02
        }
        0x60 => {
            if ip.len() < 40 {
                return false;
            }
            let ecn = ip[1] & 0x30;
            ecn == 0x10 || ecn == 0x20
        }
        _ => false,
    }
}

/// Compute a standard RFC 1071 IPv4 header checksum (used by host tests).
#[cfg(test)]
pub fn ipv4_header_checksum(hdr: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut i = 0;
    while i + 1 < hdr.len() {
        let w = ((hdr[i] as u32) << 8) | (hdr[i + 1] as u32);
        sum += w;
        i += 2;
    }
    while (sum >> 16) != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}
