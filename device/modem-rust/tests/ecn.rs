//! CE marking on raw IPv4 and IPv6 headers.

use witcher_modem_aqm::ecn::{Ecn, ecn, is_ect, mark_ce};

fn checksum(header: &[u8]) -> u16 {
    let mut sum: u32 = header.chunks(2).map(|w| u32::from(u16::from_be_bytes([w[0], w[1]]))).sum();
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

fn ipv4(tos: u8, id: u16) -> [u8; 40] {
    let mut h = [0u8; 40];
    h[0] = 0x45;
    h[1] = tos;
    h[2..4].copy_from_slice(&1380u16.to_be_bytes());
    h[4..6].copy_from_slice(&id.to_be_bytes());
    h[8] = 64;
    h[9] = 6;
    h[12..16].copy_from_slice(&[192, 0, 2, 1]);
    h[16..20].copy_from_slice(&[198, 51, 100, 1]);
    let c = checksum(&h[..20]);
    h[10..12].copy_from_slice(&c.to_be_bytes());
    h
}

fn ipv6(ecn_bits: u8) -> [u8; 40] {
    let mut h = [0u8; 40];
    h[0] = 0x60;
    h[1] = (ecn_bits & 3) << 4;
    h[6] = 6;
    h[7] = 64;
    h
}

#[test]
fn ipv4_marks_keep_the_header_checksum_valid() {
    for dscp in 0u8..64 {
        for bits in [1u8, 2] {
            for id in (0u16..=u16::MAX).step_by(997) {
                let mut h = ipv4(dscp << 2 | bits, id);
                assert!(is_ect(&h));
                assert!(mark_ce(&mut h));
                assert_eq!(h[1], dscp << 2 | 3);
                assert_eq!(checksum(&h[..20]), 0, "dscp {dscp} ecn {bits} id {id}");
                assert_eq!(ecn(&h), Some(Ecn::Ce));
                let marked = h;
                assert!(!mark_ce(&mut h), "CE is final");
                assert_eq!(h, marked);
            }
        }
    }
}

#[test]
fn ipv4_checksum_update_is_rfc_1624_for_every_old_checksum() {
    // HC' = ~(~HC + delta) in one's-complement arithmetic, for all 2 x 65,536 inputs.
    for old in 0..=u16::MAX {
        for bits in [1u8, 2] {
            let mut h = [0u8; 20];
            h[0] = 0x45;
            h[1] = bits;
            h[10..12].copy_from_slice(&old.to_be_bytes());
            assert!(mark_ce(&mut h));
            let sum = u32::from(!old) + u32::from(3 - bits);
            let want = !(((sum & 0xffff) + (sum >> 16)) as u16);
            assert_eq!(u16::from_be_bytes([h[10], h[11]]), want, "old {old:#06x} ecn {bits}");
        }
    }
}

#[test]
fn ipv6_marks_the_traffic_class() {
    for bits in [1u8, 2] {
        let mut h = ipv6(bits);
        assert!(is_ect(&h));
        assert!(mark_ce(&mut h));
        assert_eq!(h[1] & 0x30, 0x30);
        assert_eq!(ecn(&h), Some(Ecn::Ce));
        assert!(!mark_ce(&mut h));
    }
}

#[test]
fn anything_else_is_left_alone() {
    let untouched = |mut h: Vec<u8>| {
        let before = h.clone();
        assert!(!mark_ce(&mut h));
        assert_eq!(h, before);
    };
    untouched(ipv4(0x00, 7).to_vec()); // not ECT
    untouched(ipv4(0x03, 7).to_vec()); // already CE
    untouched(ipv6(0).to_vec());
    untouched(ipv4(0x02, 7)[..19].to_vec()); // truncated IPv4
    untouched(ipv6(2)[..39].to_vec()); // truncated IPv6
    untouched(vec![0x55; 40]); // neither family
    untouched(Vec::new());
    assert_eq!(ecn(&ipv4(0x01, 0)), Some(Ecn::Ect1));
    assert_eq!(ecn(&ipv4(0x02, 0)), Some(Ecn::Ect0));
    assert_eq!(ecn(&ipv4(0x00, 0)), Some(Ecn::NotEct));
    assert_eq!(ecn(&[0x55; 40]), None);
}
