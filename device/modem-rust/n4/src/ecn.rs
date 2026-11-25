//! ECN (RFC 3168) CE marking for IPv4 (with RFC 1624 incremental checksum update) and IPv6.
//!
//! Operates on a packet slice starting at IP byte 0 (`pkt_buf + 2` in `gipc_rx_loop`).

#![forbid(unsafe_code)]

/// Attempt to mark an ECT(0) or ECT(1) IPv4/IPv6 packet with CE in place.
///
/// Matches `n4_ul_engine.s` lines 738..781 bit-for-bit, including RFC 1624 one's-complement
/// checksum subtraction and `0xffff -> 0x0000` normalization.
#[inline]
pub fn try_mark_ce(ip: &mut [u8]) -> bool {
    if ip.len() < 12 {
        return false;
    }
    let ver = ip[0] & 0xf0;
    if ver == 0x40 {
        let tos = ip[1];
        let ecn = tos & 0x03;
        if ecn != 0x01 && ecn != 0x02 {
            return false;
        }
        let delta = (0x03 - ecn) as u32;
        ip[1] = tos | 0x03;

        let c_old = ((ip[10] as u32) << 8) | (ip[11] as u32);
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

#[cfg(test)]
mod tests {
    use super::*;

    fn ipv4_csum(hdr: &[u8]) -> u16 {
        let mut sum = 0u32;
        let mut i = 0;
        while i + 1 < hdr.len() {
            sum += ((hdr[i] as u32) << 8) | (hdr[i + 1] as u32);
            i += 2;
        }
        while (sum >> 16) != 0 {
            sum = (sum & 0xffff) + (sum >> 16);
        }
        !(sum as u16)
    }

    #[test]
    fn ipv4_edge_checksums_remain_valid_after_ce_mark() {
        for &target in &[0x0000u16, 0x0001, 0x0002, 0x0003, 0x8000, 0xfffd, 0xfffe] {
            for ecn in [1u8, 2u8] {
                let mut hdr = [0u8; 20];
                hdr[0] = 0x45;
                hdr[1] = ecn;
                hdr[2] = 0x05;
                hdr[3] = 0x78;
                hdr[8] = 64;
                hdr[9] = 6;
                // Find an IP ID that produces the exact desired initial checksum.
                for id in 0u16..=u16::MAX {
                    hdr[4] = (id >> 8) as u8;
                    hdr[5] = (id & 0xff) as u8;
                    hdr[10] = 0;
                    hdr[11] = 0;
                    if ipv4_csum(&hdr) == target {
                        hdr[10] = (target >> 8) as u8;
                        hdr[11] = (target & 0xff) as u8;
                        break;
                    }
                }
                assert_eq!(ipv4_csum(&hdr), 0);
                assert!(try_mark_ce(&mut hdr));
                assert_eq!(hdr[1] & 3, 3);
                assert_eq!(ipv4_csum(&hdr), 0);
            }
        }
    }

    #[test]
    fn ipv6_and_non_ect_handling() {
        let mut v6 = [0u8; 40];
        v6[0] = 0x60;
        v6[1] = 0x20;
        assert!(try_mark_ce(&mut v6));
        assert_eq!(v6[1], 0x30);
        // Already CE -> false
        assert!(!try_mark_ce(&mut v6));

        let mut v4_none = [0u8; 20];
        v4_none[0] = 0x45;
        assert!(!try_mark_ce(&mut v4_none));
    }
}
