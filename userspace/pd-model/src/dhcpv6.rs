//! DHCPv6 prefix-delegation messages.
//!
//! Lifetimes match the replies this core already gives the bench router
//! (T1 1800, T2 2880, preferred 3600, valid 7200). A solicit without rapid-commit
//! gets an Advertise, which is what the HX220 sends. Any client identifier is
//! served: a swapped router must not wait out the core's sticky binding.

use crate::prefix::Block;

pub const T1: u32 = 1800;
pub const T2: u32 = 2880;
pub const PREFERRED: u32 = 3600;
pub const VALID: u32 = 7200;
/// DNS the SMF puts in its replies on this core.
pub const DNS: [u8; 16] = [
    0x26, 0x02, 0xf8, 0x15, 0x00, 0xef, 0xff, 0xff, 0, 0, 0, 0, 0, 0, 0, 1,
];

const SOLICIT: u8 = 1;
const ADVERTISE: u8 = 2;
const REQUEST: u8 = 3;
const CONFIRM: u8 = 4;
const RENEW: u8 = 5;
const REBIND: u8 = 6;
const REPLY: u8 = 7;
const RELEASE: u8 = 8;
const INFORMATION: u8 = 11;

const CLIENT_ID: u16 = 1;
const SERVER_ID: u16 = 2;
const STATUS: u16 = 13;
const RAPID: u16 = 14;
const DNS_SERVERS: u16 = 23;
const IA_PD: u16 = 25;
const IA_PREFIX: u16 = 26;
const NOT_ON_LINK: u16 = 4;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PrefixOpt {
    pub preferred: u32,
    pub valid: u32,
    pub len: u8,
    pub addr: [u8; 16],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IaPd {
    pub iaid: u32,
    pub t1: u32,
    pub t2: u32,
    pub prefixes: Vec<PrefixOpt>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Message {
    pub kind: u8,
    pub xid: [u8; 3],
    pub client_id: Vec<u8>,
    pub server_id: Vec<u8>,
    pub ia_pd: Vec<IaPd>,
    pub rapid: bool,
    pub dns: Vec<[u8; 16]>,
}

pub fn parse(buf: &[u8]) -> Option<Message> {
    if buf.len() < 4 {
        return None;
    }
    let mut msg = Message {
        kind: buf[0],
        xid: [buf[1], buf[2], buf[3]],
        client_id: Vec::new(),
        server_id: Vec::new(),
        ia_pd: Vec::new(),
        rapid: false,
        dns: Vec::new(),
    };
    let mut rest = &buf[4..];
    while !rest.is_empty() {
        if rest.len() < 4 {
            return None;
        }
        let code = u16::from_be_bytes([rest[0], rest[1]]);
        let len = u16::from_be_bytes([rest[2], rest[3]]) as usize;
        rest = &rest[4..];
        if rest.len() < len {
            return None;
        }
        let body = &rest[..len];
        rest = &rest[len..];
        match code {
            CLIENT_ID => msg.client_id = body.to_vec(),
            SERVER_ID => msg.server_id = body.to_vec(),
            RAPID if len == 0 => msg.rapid = true,
            DNS_SERVERS => {
                for chunk in body.chunks_exact(16) {
                    let mut addr = [0; 16];
                    addr.copy_from_slice(chunk);
                    msg.dns.push(addr);
                }
            }
            IA_PD => msg.ia_pd.push(parse_ia_pd(body)?),
            _ => {}
        }
    }
    Some(msg)
}

fn parse_ia_pd(body: &[u8]) -> Option<IaPd> {
    if body.len() < 12 {
        return None;
    }
    let mut ia = IaPd {
        iaid: u32::from_be_bytes(body[0..4].try_into().ok()?),
        t1: u32::from_be_bytes(body[4..8].try_into().ok()?),
        t2: u32::from_be_bytes(body[8..12].try_into().ok()?),
        prefixes: Vec::new(),
    };
    let mut rest = &body[12..];
    while !rest.is_empty() {
        if rest.len() < 4 {
            return None;
        }
        let code = u16::from_be_bytes([rest[0], rest[1]]);
        let len = u16::from_be_bytes([rest[2], rest[3]]) as usize;
        rest = &rest[4..];
        if rest.len() < len {
            return None;
        }
        if code == IA_PREFIX && len >= 25 {
            let mut addr = [0; 16];
            addr.copy_from_slice(&rest[9..25]);
            ia.prefixes.push(PrefixOpt {
                preferred: u32::from_be_bytes(rest[0..4].try_into().ok()?),
                valid: u32::from_be_bytes(rest[4..8].try_into().ok()?),
                len: rest[8],
                addr,
            });
        }
        rest = &rest[len..];
    }
    Some(ia)
}

fn push_option(out: &mut Vec<u8>, code: u16, body: &[u8]) {
    out.extend_from_slice(&code.to_be_bytes());
    out.extend_from_slice(&(body.len() as u16).to_be_bytes());
    out.extend_from_slice(body);
}

fn prefix_body(prefix: &PrefixOpt) -> [u8; 25] {
    let mut body = [0; 25];
    body[0..4].copy_from_slice(&prefix.preferred.to_be_bytes());
    body[4..8].copy_from_slice(&prefix.valid.to_be_bytes());
    body[8] = prefix.len;
    body[9..25].copy_from_slice(&prefix.addr);
    body
}

fn ia_body(ia: &IaPd) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(&ia.iaid.to_be_bytes());
    body.extend_from_slice(&ia.t1.to_be_bytes());
    body.extend_from_slice(&ia.t2.to_be_bytes());
    for prefix in &ia.prefixes {
        push_option(&mut body, IA_PREFIX, &prefix_body(prefix));
    }
    body
}

pub fn emit(msg: &Message) -> Vec<u8> {
    let mut out = vec![msg.kind, msg.xid[0], msg.xid[1], msg.xid[2]];
    if !msg.client_id.is_empty() {
        push_option(&mut out, CLIENT_ID, &msg.client_id);
    }
    if !msg.server_id.is_empty() {
        push_option(&mut out, SERVER_ID, &msg.server_id);
    }
    if msg.rapid {
        push_option(&mut out, RAPID, &[]);
    }
    for ia in &msg.ia_pd {
        push_option(&mut out, IA_PD, &ia_body(ia));
    }
    for dns in &msg.dns {
        push_option(&mut out, DNS_SERVERS, dns);
    }
    out
}

fn ours(block: Block) -> PrefixOpt {
    let delegated = block.delegated57();
    PrefixOpt {
        preferred: PREFERRED,
        valid: VALID,
        len: delegated.len,
        addr: delegated.addr,
    }
}

fn withdrawn(prefix: &PrefixOpt) -> PrefixOpt {
    PrefixOpt {
        preferred: 0,
        valid: 0,
        len: prefix.len,
        addr: prefix.addr,
    }
}

fn same_prefix(prefix: &PrefixOpt, block: Block) -> bool {
    prefix.len == 57 && prefix.addr == block.delegated57().addr
}

/// One reply for any client. `None` when the message is not one we answer.
pub fn respond(request: &[u8], server_duid: &[u8], block: Block) -> Option<Vec<u8>> {
    let req = parse(request)?;
    if req.client_id.is_empty() && req.kind != INFORMATION {
        return None;
    }
    let kind = match req.kind {
        SOLICIT if req.rapid => REPLY,
        SOLICIT => ADVERTISE,
        REQUEST | RENEW | REBIND | RELEASE | CONFIRM | INFORMATION => REPLY,
        _ => return None,
    };
    let mut ia_pd = Vec::new();
    if req.kind != RELEASE && req.kind != INFORMATION {
        if req.kind == CONFIRM {
            let on_link = req
                .ia_pd
                .iter()
                .flat_map(|ia| &ia.prefixes)
                .any(|prefix| same_prefix(prefix, block));
            if !on_link {
                let mut body = NOT_ON_LINK.to_be_bytes().to_vec();
                body.extend_from_slice(b"prefix is not the pinned block");
                let mut out = vec![REPLY, req.xid[0], req.xid[1], req.xid[2]];
                push_option(&mut out, CLIENT_ID, &req.client_id);
                push_option(&mut out, SERVER_ID, server_duid);
                push_option(&mut out, STATUS, &body);
                return Some(out);
            }
        }
        let ias = if req.ia_pd.is_empty() {
            vec![IaPd {
                iaid: 0,
                t1: 0,
                t2: 0,
                prefixes: Vec::new(),
            }]
        } else {
            req.ia_pd.clone()
        };
        for ia in ias {
            let mut prefixes = vec![ours(block)];
            for prefix in &ia.prefixes {
                if !same_prefix(prefix, block) {
                    prefixes.push(withdrawn(prefix));
                }
            }
            ia_pd.push(IaPd {
                iaid: ia.iaid,
                t1: T1,
                t2: T2,
                prefixes,
            });
        }
    }
    Some(emit(&Message {
        kind,
        xid: req.xid,
        client_id: req.client_id,
        server_id: server_duid.to_vec(),
        ia_pd,
        rapid: req.rapid && req.kind == SOLICIT,
        dns: if req.kind == RELEASE {
            Vec::new()
        } else {
            vec![DNS]
        },
    }))
}

/// MAC from a DUID-LL (type 3) or DUID-LLT (type 1), which is how the bench router identifies itself.
pub fn client_mac(client_id: &[u8]) -> Option<[u8; 6]> {
    if client_id.len() == 10 && client_id[0..2] == [0, 3] && client_id[2..4] == [0, 1] {
        let mut mac = [0; 6];
        mac.copy_from_slice(&client_id[4..10]);
        return Some(mac);
    }
    if client_id.len() == 14 && client_id[0..2] == [0, 1] && client_id[2..4] == [0, 1] {
        let mut mac = [0; 6];
        mac.copy_from_slice(&client_id[8..14]);
        return Some(mac);
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn block() -> Block {
        crate::prefix::parse_pinned("2001:db8:ff:d100::/56").unwrap()
    }

    fn solicit(rapid: bool) -> Vec<u8> {
        emit(&Message {
            kind: SOLICIT,
            xid: [0x21, 0x3f, 0xe6],
            client_id: vec![0, 3, 0, 1, 0x24, 0x2f, 0xd0, 0xb8, 0xf1, 0x9d],
            server_id: Vec::new(),
            ia_pd: vec![IaPd {
                iaid: 0xd0b8_f19d,
                t1: 0xffff_ffff,
                t2: 0xffff_ffff,
                prefixes: Vec::new(),
            }],
            rapid,
            dns: Vec::new(),
        })
    }

    #[test]
    fn solicit_is_advertised_with_the_upper_57_and_core_lifetimes() {
        let server = [0u8, 3, 0, 1, 0x44, 0x6f, 0xd8, 0x80, 0x11, 0xde];
        let reply = parse(&respond(&solicit(false), &server, block()).unwrap()).unwrap();
        assert_eq!(reply.kind, ADVERTISE);
        assert_eq!(reply.xid, [0x21, 0x3f, 0xe6]);
        assert!(!reply.rapid);
        assert_eq!(reply.ia_pd.len(), 1);
        assert_eq!(reply.ia_pd[0].iaid, 0xd0b8_f19d);
        assert_eq!((reply.ia_pd[0].t1, reply.ia_pd[0].t2), (1800, 2880));
        assert_eq!(reply.ia_pd[0].prefixes[0].len, 57);
        assert_eq!(
            (
                reply.ia_pd[0].prefixes[0].preferred,
                reply.ia_pd[0].prefixes[0].valid
            ),
            (3600, 7200)
        );
        assert_eq!(
            Block::new(reply.ia_pd[0].prefixes[0].addr, 57)
                .unwrap()
                .to_string(),
            "2001:db8:ff:d180::/57"
        );
        assert_eq!(reply.dns, vec![DNS]);
        assert_eq!(
            client_mac(&reply.client_id),
            Some([0x24, 0x2f, 0xd0, 0xb8, 0xf1, 0x9d])
        );
    }

    #[test]
    fn a_different_client_is_served_at_once_and_a_foreign_prefix_is_withdrawn() {
        let mut request = solicit(false);
        // A second router: change the last MAC byte and ask to renew someone else's prefix.
        let foreign = PrefixOpt {
            preferred: 3600,
            valid: 7200,
            len: 57,
            addr: crate::prefix::parse_pinned("2001:db8:ff:d200::/56")
                .unwrap()
                .delegated57()
                .addr,
        };
        let mut msg = parse(&request).unwrap();
        msg.kind = RENEW;
        msg.client_id[9] = 0x10;
        msg.ia_pd[0].prefixes.push(foreign);
        request = emit(&msg);
        let reply = parse(&respond(&request, &[9, 9], block()).unwrap()).unwrap();
        assert_eq!(reply.kind, REPLY);
        assert_eq!(reply.ia_pd[0].prefixes.len(), 2);
        assert_eq!(reply.ia_pd[0].prefixes[1].valid, 0);
        assert_eq!(reply.ia_pd[0].prefixes[0].valid, VALID);
    }

    #[test]
    fn rapid_commit_solicit_is_a_reply() {
        let reply = parse(&respond(&solicit(true), &[1], block()).unwrap()).unwrap();
        assert_eq!(reply.kind, REPLY);
        assert!(reply.rapid);
    }
}
