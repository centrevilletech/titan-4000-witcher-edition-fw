//! Bounds-checked IPv4/IPv6 header parser, stock Ring-0 fast-path detector,
//! and 5-tuple + bearer flow hash for N5 (`n5.s` Step 2).
//!
//! Uses fixed-size header slices (`&[u8; 20]` / `&[u8; 40]`) so LLVM proves all
//! offsets with a single bounds check and emits hardware `ldr + rev` / `ldrh + rev16`
//! instructions (valid on Cortex-A7 with `SCTLR.A = 0` as configured in `tk.bin`).

#![forbid(unsafe_code)]

/// Golden-ratio mixing prime used by N5's 32-bit flow hash.
const HASH_PRIME: u32 = 0x9e37_79b1;

/// Outcome of parsing an uplink IP packet in N5.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum ParsedPacket {
    /// Malformed, truncated, unsupported IP version, non-first IPv4 fragment, or IPv6 Fragment header.
    BadHdr,
    /// Unfragmented `<= 127 B` pure TCP ACK, small ICMPv4, or small ICMPv6 Echo Req/Reply.
    StockR0,
    /// Valid flow packet with 32-bit hash and IPv4 first-fragment (`MF=1`) marker.
    Flow { hash: u32, is_first_frag: bool },
}

enum L4Result {
    BadHdr,
    StockR0,
    Ports(u32),
}

#[inline(always)]
const fn be16_at(b: &[u8], off: usize) -> u16 {
    u16::from_be_bytes([b[off], b[off + 1]])
}

#[inline(always)]
const fn be32_at(b: &[u8], off: usize) -> u32 {
    u32::from_be_bytes([b[off], b[off + 1], b[off + 2], b[off + 3]])
}

/// Mix `val` into `h` using N5's golden-ratio multiply-xorshift step.
#[inline(always)]
const fn mix(mut h: u32, val: u32, shift: u32) -> u32 {
    h = (h ^ val).wrapping_mul(HASH_PRIME);
    h ^ (h >> shift)
}

/// Shared L4 header validation, `<= 127 B` pure TCP ACK detection, and port extraction
/// for both IPv4 and IPv6.
#[inline(always)]
fn parse_l4(ip: &[u8], l4_off: usize, l4_len: u32, proto: u8, allow_stock_ack: bool) -> L4Result {
    match proto {
        6 => {
            if l4_len < 20 {
                return L4Result::BadHdr;
            }
            let Some(tcp) = ip.get(l4_off..l4_off + 14) else {
                return L4Result::BadHdr;
            };
            let tcp_hdrlen = ((tcp[12] >> 4) as u32) << 2;
            if tcp_hdrlen < 20 {
                return L4Result::BadHdr;
            }
            if allow_stock_ack && (tcp[13] & 0x17) == 0x10 && l4_len == tcp_hdrlen {
                return L4Result::StockR0;
            }
            if tcp_hdrlen > l4_len {
                return L4Result::BadHdr;
            }
            L4Result::Ports(be32_at(tcp, 0))
        }
        17 => {
            if l4_len < 8 {
                return L4Result::BadHdr;
            }
            let Some(udp) = ip.get(l4_off..l4_off + 4) else {
                return L4Result::BadHdr;
            };
            L4Result::Ports(be32_at(udp, 0))
        }
        _ => L4Result::Ports(0),
    }
}

/// Parse an uplink IP header (starting at `pkt_buf + 2`) and compute N5's 32-bit flow hash.
///
/// `ip` may be truncated to a header prefix (`min(pkt_len, 80)` bytes) so callers never
/// read past `pkt_len`; `pkt_len` carries the true packet length from `r4`.
#[inline(always)]
pub fn parse_and_hash(ip: &[u8], pkt_len: u32, bearer_idx: u32) -> ParsedPacket {
    let Some(hdr20) = ip.get(..20) else {
        return ParsedPacket::BadHdr;
    };
    let vihl = hdr20[0];
    match vihl & 0xf0 {
        0x40 => parse_ipv4(ip, hdr20, vihl, pkt_len, bearer_idx),
        0x60 => parse_ipv6(ip, pkt_len, bearer_idx),
        _ => ParsedPacket::BadHdr,
    }
}

#[inline(always)]
fn parse_ipv4(
    ip: &[u8],
    hdr: &[u8],
    vihl: u8,
    pkt_len: u32,
    bearer_idx: u32,
) -> ParsedPacket {
    let ihl = ((vihl & 0x0f) as u32) << 2;
    if ihl < 20 || ihl > pkt_len {
        return ParsedPacket::BadHdr;
    }
    let ip_totlen = be16_at(hdr, 2) as u32;
    if ip_totlen < ihl || ip_totlen > pkt_len {
        return ParsedPacket::BadHdr;
    }
    let frag_field = be16_at(hdr, 6);
    if (frag_field & 0x1fff) != 0 {
        return ParsedPacket::BadHdr;
    }
    let is_first_frag = (frag_field & 0x2000) != 0;
    let proto = hdr[9];

    let allow_stock_r0 = !is_first_frag && pkt_len <= 127;
    if allow_stock_r0 && proto == 1 {
        return ParsedPacket::StockR0;
    }

    let ports = match parse_l4(ip, ihl as usize, ip_totlen - ihl, proto, allow_stock_r0) {
        L4Result::BadHdr => return ParsedPacket::BadHdr,
        L4Result::StockR0 => return ParsedPacket::StockR0,
        L4Result::Ports(p) => p,
    };

    let src_ip = be32_at(hdr, 12);
    let dst_ip = be32_at(hdr, 16);
    let h = (bearer_idx & 7) | ((proto as u32) << 4) | 0x4000;
    let h = mix(h, src_ip, 16);
    let h = mix(h, dst_ip, 16);
    let h = mix(h, ports, 13);

    ParsedPacket::Flow {
        hash: h,
        is_first_frag,
    }
}

#[inline(always)]
fn parse_ipv6(ip: &[u8], pkt_len: u32, bearer_idx: u32) -> ParsedPacket {
    if pkt_len < 40 {
        return ParsedPacket::BadHdr;
    }
    let Some(hdr) = ip.get(..40) else {
        return ParsedPacket::BadHdr;
    };
    let plen = be16_at(hdr, 4) as u32;
    if plen + 40 > pkt_len {
        return ParsedPacket::BadHdr;
    }
    let next_hdr = hdr[6];
    if next_hdr == 44 {
        return ParsedPacket::BadHdr;
    }

    let allow_stock_r0 = pkt_len <= 127;
    if allow_stock_r0 && next_hdr == 58 {
        if plen < 4 {
            return ParsedPacket::BadHdr;
        }
        let Some(&icmp_type) = ip.get(40) else {
            return ParsedPacket::BadHdr;
        };
        if (icmp_type ^ 0x80) <= 1 {
            return ParsedPacket::StockR0;
        }
    }

    let ports = match parse_l4(ip, 40, plen, next_hdr, allow_stock_r0) {
        L4Result::BadHdr => return ParsedPacket::BadHdr,
        L4Result::StockR0 => return ParsedPacket::StockR0,
        L4Result::Ports(p) => p,
    };

    let mut h = (bearer_idx & 7) | ((next_hdr as u32) << 4) | 0x6000;
    for &chunk in hdr[8..40].as_chunks::<4>().0 {
        h = mix(h, u32::from_be_bytes(chunk), 15);
    }
    h = mix(h, ports, 13);

    ParsedPacket::Flow {
        hash: h,
        is_first_frag: false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[allow(clippy::too_many_arguments)]
    fn make_ipv4(
        proto: u8,
        src: u32,
        dst: u32,
        sport: u16,
        dport: u16,
        total_len: u16,
        tcp_flags: u8,
        ihl_words: u8,
        frag: u16,
        tcp_doff_words: u8,
    ) -> Vec<u8> {
        let ihl = (ihl_words as usize) * 4;
        let mut buf = vec![0u8; (total_len as usize).max(ihl)];
        buf[0] = 0x40 | (ihl_words & 0x0f);
        buf[2..4].copy_from_slice(&total_len.to_be_bytes());
        buf[6..8].copy_from_slice(&frag.to_be_bytes());
        buf[9] = proto;
        buf[12..16].copy_from_slice(&src.to_be_bytes());
        buf[16..20].copy_from_slice(&dst.to_be_bytes());
        if (frag & 0x1fff) == 0 {
            if proto == 6 && buf.len() >= ihl + 20 {
                buf[ihl..ihl + 2].copy_from_slice(&sport.to_be_bytes());
                buf[ihl + 2..ihl + 4].copy_from_slice(&dport.to_be_bytes());
                buf[ihl + 12] = tcp_doff_words << 4;
                buf[ihl + 13] = tcp_flags;
            } else if proto == 17 && buf.len() >= ihl + 8 {
                buf[ihl..ihl + 2].copy_from_slice(&sport.to_be_bytes());
                buf[ihl + 2..ihl + 4].copy_from_slice(&dport.to_be_bytes());
            }
        }
        buf.truncate(total_len as usize);
        buf
    }

    #[allow(clippy::too_many_arguments)]
    fn make_ipv6(
        next_hdr: u8,
        src: [u8; 16],
        dst: [u8; 16],
        sport: u16,
        dport: u16,
        total_len: u16,
        tcp_flags: u8,
        icmp6_type: u8,
        tcp_doff_words: u8,
    ) -> Vec<u8> {
        let plen = total_len.saturating_sub(40);
        let mut buf = vec![0u8; (total_len as usize).max(40)];
        buf[0] = 0x60;
        buf[4..6].copy_from_slice(&plen.to_be_bytes());
        buf[6] = next_hdr;
        buf[8..24].copy_from_slice(&src);
        buf[24..40].copy_from_slice(&dst);
        if next_hdr == 6 && buf.len() >= 60 {
            buf[40..42].copy_from_slice(&sport.to_be_bytes());
            buf[42..44].copy_from_slice(&dport.to_be_bytes());
            buf[52] = tcp_doff_words << 4;
            buf[53] = tcp_flags;
        } else if next_hdr == 17 && buf.len() >= 48 {
            buf[40..42].copy_from_slice(&sport.to_be_bytes());
            buf[42..44].copy_from_slice(&dport.to_be_bytes());
        } else if next_hdr == 58 && buf.len() >= 44 {
            buf[40] = icmp6_type;
        }
        buf.truncate(total_len as usize);
        buf
    }

    #[test]
    fn ipv4_stock_r0_and_hash_match_spec() {
        let ack = make_ipv4(6, 0x0a00_0001, 0x0808_0808, 50000, 443, 52, 0x10, 5, 0, 8);
        assert_eq!(parse_and_hash(&ack, ack.len() as u32, 0), ParsedPacket::StockR0);

        let fin_ack = make_ipv4(6, 0x0a00_0001, 0x0808_0808, 50000, 443, 40, 0x11, 5, 0, 5);
        assert!(matches!(
            parse_and_hash(&fin_ack, fin_ack.len() as u32, 0),
            ParsedPacket::Flow { is_first_frag: false, .. }
        ));

        let icmp = make_ipv4(1, 0x0a00_0001, 0x0101_0101, 0, 0, 84, 0, 5, 0, 5);
        assert_eq!(parse_and_hash(&icmp, 84, 0), ParsedPacket::StockR0);

        let ff = make_ipv4(17, 0x0a00_0031, 0x0101_0101, 40001, 5000, 228, 0, 5, 0x2000, 5);
        assert!(matches!(
            parse_and_hash(&ff, 228, 0),
            ParsedPacket::Flow { is_first_frag: true, .. }
        ));
        let nf = make_ipv4(17, 0x0a00_0031, 0x0101_0101, 40001, 5000, 100, 0, 5, 185, 5);
        assert_eq!(parse_and_hash(&nf, 100, 0), ParsedPacket::BadHdr);

        let udp = make_ipv4(17, 0x0a00_0101, 0xc000_0210, 50000, 5201, 228, 0, 5, 0, 5);
        let k = 0x9e37_79b1u32;
        let mut want = 2u32 | (17u32 << 4) | 0x4000;
        want = (want ^ 0x0a00_0101).wrapping_mul(k);
        want ^= want >> 16;
        want = (want ^ 0xc000_0210).wrapping_mul(k);
        want ^= want >> 16;
        want = (want ^ ((50000u32 << 16) | 5201)).wrapping_mul(k);
        want ^= want >> 13;
        assert_eq!(
            parse_and_hash(&udp[..80], 228, 2),
            ParsedPacket::Flow {
                hash: want,
                is_first_frag: false,
            }
        );
    }

    #[test]
    fn ipv6_stock_r0_fragments_and_truncations() {
        let src = [0x20; 16];
        let dst = [0x26; 16];
        let ack6 = make_ipv6(6, src, dst, 51000, 443, 60, 0x10, 0, 5);
        assert_eq!(parse_and_hash(&ack6, 60, 0), ParsedPacket::StockR0);

        let echo6 = make_ipv6(58, src, dst, 0, 0, 88, 0, 128, 5);
        assert_eq!(parse_and_hash(&echo6, 88, 0), ParsedPacket::StockR0);

        let ns6 = make_ipv6(58, src, dst, 0, 0, 72, 0, 135, 5);
        assert!(matches!(
            parse_and_hash(&ns6, 72, 0),
            ParsedPacket::Flow { is_first_frag: false, .. }
        ));

        let frag6 = make_ipv6(44, src, dst, 0, 0, 200, 0, 0, 5);
        assert_eq!(parse_and_hash(&frag6[..80], 200, 0), ParsedPacket::BadHdr);

        let trunc_icmp_small = make_ipv6(58, src, dst, 0, 0, 42, 0, 128, 5);
        assert_eq!(parse_and_hash(&trunc_icmp_small, 42, 0), ParsedPacket::BadHdr);
    }
}
