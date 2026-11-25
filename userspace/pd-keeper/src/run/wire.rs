//! The keeper's packet sockets on the LAN bridge and the customer port:
//! protocol-specific receive sockets for ARP, DHCP and IPv6 control frames
//! (never `ETH_P_ALL`), the marked IPv6 sender, and the raw sender for frames
//! with their own Ethernet header.

use std::io;
use std::net::Ipv6Addr;
use std::os::fd::{AsFd, BorrowedFd};

use titan_pd_model::filter;
use titan_pd_model::ipv4_health::Armed;
use titan_sys::socket::{Socket, SocketExt};

use crate::log_ram;
use crate::files::read_file;
use crate::netdev::interface_index;

use super::{BRIDGE, Keeper};
use super::if_inet6::link_local;
use super::packet::{Class, Event, classify_ipv6, dhcp_client_mac};

/// Modest receive buffer for control-plane packet sockets (kernel doubles this).
const CONTROL_RCVBUF: libc::c_int = 65_536;

/// Keeps `br0` subscribed to IPv6 link-local control multicast groups so Linux
/// bridge MLD snooping always delivers RS and DHCPv6 frames to `br0`.
struct Ipv6Socket {
    packet: Socket,
    _mcast_guard: Option<Socket>,
}

/// Protocol-specific `AF_PACKET` (`ptype_base`) receive sockets bound to `br0`,
/// plus an unbound protocol-0 sender socket. No `ETH_P_ALL` socket is ever
/// opened, so `ptype_all` stays empty, transmit never runs `dev_queue_xmit_nit`,
/// and bridge-forwarded customer traffic never enters `ptype_base`.
pub(super) struct ControlSockets {
    bridge_ifindex: i32,
    arp: Socket,
    dhcp: Socket,
    ipv6: Option<Ipv6Socket>,
    tx_ipv6: Socket,
}

impl ControlSockets {
    /// What the wire loop waits on: the ARP and DHCP sockets, and the IPv6
    /// one while prefix delegation is on.
    pub(super) fn receivers(&self) -> [Option<BorrowedFd<'_>>; 3] {
        [Some(self.arp.as_fd()), Some(self.dhcp.as_fd()), self.ipv6_fd()]
    }

    /// The IPv6 control socket, while prefix delegation is on.
    pub(super) fn ipv6_fd(&self) -> Option<BorrowedFd<'_>> {
        self.ipv6.as_ref().map(|ipv6| ipv6.packet.as_fd())
    }

    /// Send an IPv6 packet out `ifindex` to `dest_mac` from the marked sender.
    pub(super) fn send_ipv6(&self, ifindex: i32, dest_mac: [u8; 6], packet: &[u8]) -> Result<(), String> {
        let sent = self
            .tx_ipv6
            .send_link(packet, ifindex, libc::ETH_P_IPV6 as u16, dest_mac);
        sent_whole(sent, packet.len())
    }
}

impl Keeper {
    pub(super) fn ensure_sockets(&mut self, want_ipv6: bool) -> Result<(), String> {
        let bridge_ifindex = interface_index(BRIDGE).ok_or("br0 has no interface index")?;
        if self
            .sockets
            .as_ref()
            .is_some_and(|sockets| sockets.bridge_ifindex != bridge_ifindex)
        {
            self.sockets = None;
        }
        if self.sockets.is_none() {
            let arp =
                open_protocol_packet(bridge_ifindex, libc::ETH_P_ARP, crate::capture::install_arp)?;
            let dhcp = open_protocol_packet(
                bridge_ifindex,
                libc::ETH_P_IP,
                crate::capture::install_ipv4_dhcp,
            )?;
            let tx_ipv6 = open_tx_ipv6()?;
            self.sockets = Some(ControlSockets {
                bridge_ifindex,
                arp,
                dhcp,
                ipv6: None,
                tx_ipv6,
            });
        }
        if let Some(sockets) = self.sockets.as_mut() {
            if want_ipv6 && sockets.ipv6.is_none() {
                let packet =
                    open_protocol_packet(bridge_ifindex, libc::ETH_P_IPV6, |fd| {
                        crate::capture::install_ipv6(fd, false)
                    })?;
                let _mcast_guard = join_ipv6_control_multicast(bridge_ifindex);
                sockets.ipv6 = Some(Ipv6Socket {
                    packet,
                    _mcast_guard,
                });
            } else if !want_ipv6 && sockets.ipv6.is_some() {
                sockets.ipv6 = None;
            }
        }
        Ok(())
    }

    pub(super) fn drain_arp(&mut self) {
        loop {
            let mut buf = [0u8; 256];
            let Some(received) = self.sockets.as_ref().map(|sockets| sockets.arp.recv_link(&mut buf))
            else {
                return;
            };
            let Ok((len, peer)) = received else {
                break;
            };
            let Some(mac) = peer.mac().filter(|_| !peer.outgoing()) else {
                continue;
            };
            let packet = &buf[..len];
            match self.ipv4_watch.reply(self.now, packet, mac) {
                Some(Armed::First) => {
                    self.note("IPv4 router answered local ARP; automatic recovery is armed")
                }
                // The same router after a cable or LTE outage: routine,
                // so the RAM log only.
                Some(Armed::Again) => {
                    log_ram("IPv4 router answered local ARP again; automatic recovery is armed")
                }
                None => {}
            }
        }
    }

    pub(super) fn drain_dhcp(&mut self) {
        loop {
            let mut buf = [0u8; 2048];
            let Some(received) = self.sockets.as_ref().map(|sockets| sockets.dhcp.recv_link(&mut buf))
            else {
                return;
            };
            let Ok((len, peer)) = received else {
                break;
            };
            if peer.outgoing() {
                continue;
            }
            let packet = &buf[..len];
            if let Some(mac) = dhcp_client_mac(packet) {
                self.discover = Some(mac);
            }
        }
    }

    pub(super) fn collect_ipv6(&mut self) -> Vec<Event> {
        let mut our = None;
        let mut delegated = None;
        let mut loaded_context = false;
        let mut events = Vec::new();
        loop {
            let mut buf = [0u8; 2048];
            let Some(received) = self
                .sockets
                .as_ref()
                .and_then(|sockets| sockets.ipv6.as_ref())
                .map(|ipv6| ipv6.packet.recv_link(&mut buf))
            else {
                break;
            };
            let Ok((len, peer)) = received else {
                break;
            };
            if !loaded_context {
                our = link_local(&read_file("/proc/net/if_inet6"), BRIDGE);
                delegated = self.serving_block().map(|block| block.delegated57());
                loaded_context = true;
            }
            let packet = &buf[..len];
            let outgoing = peer.outgoing();
            let mut kind = classify_ipv6(packet, delegated, our);
            let mac = peer.mac();
            let source_mac = (!outgoing).then_some(mac).flatten();
            match kind {
                Class::DhcpV6 {
                    source, payload, ..
                } => {
                    kind = Class::DhcpV6 {
                        source_mac: mac,
                        source,
                        payload,
                    };
                }
                Class::RouterProbe { .. } => {
                    kind = Class::RouterProbe { source_mac: mac };
                }
                _ => {}
            }
            events.push(Event {
                kind,
                outgoing,
                source_mac,
            });
        }
        events
    }
}

fn open_protocol_packet<F>(
    ifindex: i32,
    protocol: libc::c_int,
    install_filter: F,
) -> Result<Socket, String>
where
    F: FnOnce(BorrowedFd<'_>) -> Result<(), String>,
{
    let socket = Socket::packet_datagram()
        .map_err(|err| format!("control packet socket ({protocol:#x}): {err}"))?;
    let _ = socket.set_recv_buffer(CONTROL_RCVBUF);
    install_filter(socket.as_fd())?;
    socket
        .bind_link(ifindex, protocol as u16)
        .map_err(|err| format!("bind bridge control socket ({protocol:#x}): {err}"))?;
    Ok(socket)
}

/// Unbound protocol-0 AF_PACKET socket for sending marked IPv6 control frames
/// out `eth0` without registering any receive tap.
fn open_tx_ipv6() -> Result<Socket, String> {
    let socket = Socket::packet_datagram().map_err(|err| format!("IPv6 send socket: {err}"))?;
    socket.set_mark(filter::MARK).map_err(|err| err.to_string())?;
    Ok(socket)
}

/// Subscribe `br0` to All-Routers (`ff02::2`) and All-DHCP-Relay-Agents-and-Servers
/// (`ff02::1:2`) so bridge MLD snooping never drops IPv6 PD control frames.
fn join_ipv6_control_multicast(ifindex: i32) -> Option<Socket> {
    let socket = Socket::ipv6_datagram().ok()?;
    let groups = [
        Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 2),
        Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 1, 2),
    ];
    for group in groups {
        let _ = socket.join_ipv6_multicast(group, ifindex as u32);
    }
    Some(socket)
}

/// A datagram goes out whole or not at all. A short count, which a packet
/// socket never returns, reports `errno` as it stands, as the keeper always did.
fn sent_whole(sent: io::Result<usize>, len: usize) -> Result<(), String> {
    match sent {
        Ok(sent) if sent == len => Ok(()),
        Ok(_) => Err(io::Error::last_os_error().to_string()),
        Err(err) => Err(err.to_string()),
    }
}

/// SOCK_RAW so the Ethernet source can be the core's MAC. The receive socket
/// stays SOCK_DGRAM. The mark lets this advertisement through our own filter.
pub(super) fn send_marked_frame(ifindex: i32, frame: &[u8]) -> Result<(), String> {
    if frame.len() < 14 {
        return Err("Ethernet frame is truncated".into());
    }
    let socket = Socket::packet_raw().map_err(|err| format!("raw send socket: {err}"))?;
    socket.set_mark(filter::MARK).map_err(|err| err.to_string())?;
    let mut dest = [0u8; 6];
    dest.copy_from_slice(&frame[..6]);
    let protocol = u16::from_be_bytes([frame[12], frame[13]]);
    sent_whole(socket.send_link(frame, ifindex, protocol, dest), frame.len())
}
