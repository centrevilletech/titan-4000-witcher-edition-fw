//! Reads of `/sys/class/net/<dev>`: carrier, MAC address, interface index
//! and received frames, and the ports of the LAN bridge.

use std::fs;

use crate::files::read_file;

/// The link has carrier.
pub fn carrier_up(dev: &str) -> bool {
    read_file(format!("/sys/class/net/{dev}/carrier")).trim() == "1"
}

pub fn interface_mac(dev: &str) -> Option<[u8; 6]> {
    let text = read_file(format!("/sys/class/net/{dev}/address"));
    let mut mac = [0u8; 6];
    let parts: Vec<_> = text.trim().split(':').collect();
    if parts.len() != 6 {
        return None;
    }
    for (index, part) in parts.iter().enumerate() {
        mac[index] = u8::from_str_radix(part, 16).ok()?;
    }
    Some(mac)
}

/// The MAC address, with the reason when it cannot be read.
pub fn read_mac(dev: &str) -> Result<[u8; 6], String> {
    let text = fs::read_to_string(format!("/sys/class/net/{dev}/address"))
        .map_err(|err| err.to_string())?;
    let mut mac = [0u8; 6];
    let parts: Vec<&str> = text.trim().split(':').collect();
    if parts.len() != 6 {
        return Err(format!("bad mac on {dev}"));
    }
    for (index, part) in parts.iter().enumerate() {
        mac[index] = u8::from_str_radix(part, 16).map_err(|err| err.to_string())?;
    }
    Ok(mac)
}

pub fn interface_index(dev: &str) -> Option<i32> {
    read_file(format!("/sys/class/net/{dev}/ifindex"))
        .trim()
        .parse()
        .ok()
}

/// Frames received on `dev` since boot. `None` when the counter is unreadable.
pub fn rx_packets(dev: &str) -> Option<u64> {
    read_file(format!("/sys/class/net/{dev}/statistics/rx_packets"))
        .trim()
        .parse()
        .ok()
}

/// The ports of `br0`, none when it cannot be read.
pub fn bridge_ports() -> Vec<String> {
    fs::read_dir("/sys/class/net/br0/brif")
        .map(|entries| {
            entries
                .flatten()
                .map(|entry| entry.file_name().to_string_lossy().into_owned())
                .collect()
        })
        .unwrap_or_default()
}
