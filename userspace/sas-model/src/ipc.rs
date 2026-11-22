//! The datagram the vendor `rcinit` sends to the SAS client.
//!
//! `rcinit` writes to the Unix datagram socket `/tmp/.socket_fsm` each time
//! the LTE connection comes up, goes down or changes carrier. The message is
//! 16 bytes: source module, destination module, type, a pad byte, the total
//! length, the connection state and the channel mask, all little-endian.
use crate::band::{self, Range};

pub const SOCKET: &str = "/tmp/.socket_fsm";
const SOURCE_DEVICE: u8 = 3;
const DESTINATION_FSM: u8 = 0;
const LENGTH: usize = 16;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Device {
    pub connected: bool,
    pub mask: u32,
}

impl Device {
    pub fn ranges(&self) -> Vec<Range> {
        band::from_mask(self.mask)
    }
}

fn word(bytes: &[u8], at: usize) -> u32 {
    u32::from_le_bytes([bytes[at], bytes[at + 1], bytes[at + 2], bytes[at + 3]])
}

/// A device message, or `None` for anything else. Messages from the web and
/// tool modules are not for this client and are dropped.
pub fn parse_device(datagram: &[u8]) -> Option<Device> {
    if datagram.len() != LENGTH
        || datagram[0] != SOURCE_DEVICE
        || datagram[1] != DESTINATION_FSM
        || word(datagram, 4) as usize != LENGTH
    {
        return None;
    }
    Some(Device {
        connected: word(datagram, 8) != 0,
        mask: word(datagram, 12),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn message(state: u32, mask: u32) -> Vec<u8> {
        let mut bytes = vec![3, 0, 4, 0];
        bytes.extend_from_slice(&16_u32.to_le_bytes());
        bytes.extend_from_slice(&state.to_le_bytes());
        bytes.extend_from_slice(&mask.to_le_bytes());
        bytes
    }

    #[test]
    fn a_connect_message_names_the_carriers() {
        let device = parse_device(&message(1, 0x3C00_003C)).unwrap();
        assert!(device.connected);
        assert_eq!(
            device.ranges(),
            vec![
                Range::mhz(3560, 3580).unwrap(),
                Range::mhz(3680, 3700).unwrap()
            ]
        );
        assert!(!parse_device(&message(0, 0)).unwrap().connected);
    }

    #[test]
    fn other_modules_and_short_messages_are_dropped() {
        let mut tool = message(1, 20);
        tool[0] = 5;
        assert_eq!(parse_device(&tool), None);
        assert_eq!(parse_device(&message(1, 1)[..12]), None);
        let mut wrong_length = message(1, 1);
        wrong_length[4] = 20;
        assert_eq!(parse_device(&wrong_length), None);
    }
}
