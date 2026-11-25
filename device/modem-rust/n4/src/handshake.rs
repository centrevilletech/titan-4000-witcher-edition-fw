//! IMG4 N4 v3 TLS/QUIC handshake spare classifier (N4 flag bit 5).
//!
//! Mirrors `n4v3_spare` in `IMG4/src/img4.s` lines 670..748 exactly:
//! spares QUIC long-header packets on UDP port 443 and TLS handshake records (`16 03`)
//! on TCP port 443 while `Q_total <= 4 * Q_target`.

#![forbid(unsafe_code)]

/// Handshake protocol recognized for sparing above `Q_target`.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum HandshakeKind {
    Quic,
    Tls,
}

/// Inspect IP header + L4 header inside `ip` (bounded by `pkt_len`, measured from `sl`
/// as in `n4v3_spare`, i.e. 2 bytes stricter than IP payload length).
#[inline]
pub fn classify_handshake(ip: &[u8], pkt_len: u32) -> Option<HandshakeKind> {
    let b0 = *ip.first()?;
    let ver = b0 & 0xf0;
    let (l4_off, proto) = if ver == 0x40 {
        let ihl = ((b0 & 0x0f) as usize) << 2;
        if ihl < 20 {
            return None;
        }
        let f6 = *ip.get(6)?;
        let f7 = *ip.get(7)?;
        if ((f6 & 0x1f) | f7) != 0 {
            return None; // non-first IPv4 fragment
        }
        (ihl, *ip.get(9)?)
    } else if ver == 0x60 {
        (40usize, *ip.get(6)?)
    } else {
        return None;
    };

    // Need L4 header first 8 bytes, measured from sl (+2 bytes).
    if (l4_off as u32).wrapping_add(10) > pkt_len {
        return None;
    }
    let dp_hi = *ip.get(l4_off + 2)?;
    let dp_lo = *ip.get(l4_off + 3)?;
    let dport = ((dp_hi as u16) << 8) | (dp_lo as u16);
    if dport != 443 {
        return None;
    }

    if proto == 17 {
        // UDP: need payload byte 0 inside packet (l4_off + 8 + 1 + 2 = l4_off + 11 <= pkt_len).
        if (l4_off as u32).wrapping_add(11) > pkt_len {
            return None;
        }
        if (*ip.get(l4_off + 8)? & 0x80) != 0 {
            Some(HandshakeKind::Quic)
        } else {
            None
        }
    } else if proto == 6 {
        // TCP: need TCP header length >= 20 and payload bytes 0..1 == 0x16 0x03.
        let doff = ((*ip.get(l4_off + 12)? >> 4) as usize) << 2;
        if doff < 20 {
            return None;
        }
        let pay_off = l4_off + doff;
        if (pay_off as u32).wrapping_add(4) > pkt_len {
            return None;
        }
        if *ip.get(pay_off)? == 0x16 && *ip.get(pay_off + 1)? == 0x03 {
            Some(HandshakeKind::Tls)
        } else {
            None
        }
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recognizes_quic_and_tls_handshakes_and_rejects_others() {
        // QUIC Initial IPv4
        let mut quic = [0u8; 64];
        quic[0] = 0x45;
        quic[9] = 17;
        quic[22] = 0x01;
        quic[23] = 0xbb; // 443
        quic[28] = 0xc3; // long header
        assert_eq!(classify_handshake(&quic, 1250), Some(HandshakeKind::Quic));

        // QUIC short header rejected
        quic[28] = 0x43;
        assert_eq!(classify_handshake(&quic, 1250), None);

        // TLS ClientHello IPv4 with deepest 60+60 headers in 128 B packet
        let mut tls = [0u8; 128];
        tls[0] = 0x4f;
        tls[9] = 6;
        tls[62] = 0x01;
        tls[63] = 0xbb;
        tls[60 + 12] = 0xf0;
        tls[120] = 0x16;
        tls[121] = 0x03;
        assert_eq!(classify_handshake(&tls, 128), Some(HandshakeKind::Tls));
        tls[121] = 0x04;
        assert_eq!(classify_handshake(&tls, 128), None);
    }
}
