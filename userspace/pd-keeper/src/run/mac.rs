//! The two MAC repairs in passthrough: the LTE driver's downlink MAC (see
//! `titan_pd_model::driver_mac`) and the vendor kernel's IPv4 host MAC after a
//! router swap (see `titan_pd_model::host_mac`).

use titan_pd_model::driver_mac::{self, Action as DriverAction};
use titan_pd_model::host_mac::{self, Action as HostMacAction};
use titan_pd_model::ipv4;

use crate::command::run_status;
use crate::files::read_file;
use crate::netdev::{interface_index, interface_mac};
use crate::paths::env_or;

use super::{BRIDGE, CUSTOMER, Keeper};
use super::ipv4_repair::PEER_HOLD;
use super::wire::send_marked_frame;

impl Keeper {
    /// In passthrough the unit forwards no IPv6. When it starts to, the LTE
    /// driver is sending the router's downlink to the unit, and the router's
    /// own ARP request, sent out the bearer, puts the driver back. See
    /// `titan_pd_model::driver_mac`.
    pub(super) fn maintain_driver_mac(&mut self) {
        let path = env_or("TITAN_SNMP6", "/proc/net/snmp6");
        let count = driver_mac::forwarded(&read_file(&path));
        let peer = self
            .ipv4_peer
            .filter(|(_, seen)| self.now.saturating_sub(*seen) <= PEER_HOLD)
            .map(|(peer, _)| peer);
        let gateway = self.ipv4_gateway;
        let ready = self.passthrough && self.bridged && peer.is_some() && gateway.is_some();
        match self.driver_watch.tick(self.now, count, ready) {
            DriverAction::Hold => {}
            DriverAction::Correct => {
                let (Some(peer), Some(gateway)) = (peer, gateway) else {
                    return;
                };
                let frame = driver_mac::correction(peer.mac, peer.address, gateway);
                let bearer = self.bearer.clone();
                let sent = interface_index(&bearer)
                    .ok_or_else(|| format!("{bearer} is unavailable"))
                    .and_then(|index| send_marked_frame(index, &frame));
                match sent {
                    Ok(()) => {
                        self.driver_fixes += 1;
                        // keeper.log is on flash: one line a minute at most.
                        if self
                            .driver_logged_at
                            .is_none_or(|at| self.now.saturating_sub(at) >= 60)
                        {
                            self.note(&format!(
                                "the unit was forwarding the router's IPv6, so the LTE driver had the wrong downlink MAC; sent the router's ARP ({} {}) out {bearer} to put it back ({} time(s) since the last note)",
                                ipv4::mac_text(peer.mac),
                                peer.address,
                                self.driver_fixes
                            ));
                            self.driver_fixes = 0;
                            self.driver_logged_at = Some(self.now);
                        }
                    }
                    Err(err) => self.note(&format!("LTE driver MAC correction could not be sent: {err}")),
                }
            }
            DriverAction::GiveUp => self.note(&format!(
                "the unit keeps forwarding IPv6 after {} corrections; something else routes through it. Pausing the LTE driver MAC correction for {} s",
                driver_mac::TRIES,
                driver_mac::PAUSE
            )),
        }
    }

    /// The vendor kernel addresses the bearer's IPv4 to one MAC it learns once
    /// per boot, so after a router swap the new router got no IPv4 until a
    /// reboot. Point it at the router that holds the customer DHCP lease with
    /// the vendor's own command. See `titan_pd_model::host_mac`.
    pub(super) fn maintain_host_mac(&mut self) {
        let router = self
            .ipv4_peer
            .filter(|(_, seen)| self.now.saturating_sub(*seen) <= PEER_HOLD)
            .map(|(peer, _)| peer.mac);
        let ready = self.passthrough && self.bridged && self.kmsg_drained;
        // Nothing to compare on most ticks: skip the sysfs reads then.
        let settled = !ready
            || router.is_none()
            || self.host_mac_watch.stored().is_some_and(|stored| Some(stored.mac) == router);
        let own: Vec<[u8; 6]> = if settled {
            Vec::new()
        } else {
            [CUSTOMER, BRIDGE, self.bearer.as_str()]
                .into_iter()
                .filter_map(interface_mac)
                .collect()
        };
        match self.host_mac_watch.decide(self.now, ready, router, &own) {
            HostMacAction::Hold => {}
            HostMacAction::Point { hostif, from, to } => {
                let (program, args) = host_mac::command(&hostif, to);
                let args: Vec<&str> = args.iter().map(String::as_str).collect();
                let result = run_status(program, &args);
                // keeper.log is on flash: one line a minute at most.
                if self
                    .host_mac_logged_at
                    .is_some_and(|at| self.now.saturating_sub(at) < 60)
                {
                    return;
                }
                self.host_mac_logged_at = Some(self.now);
                let to = ipv4::mac_text(to);
                match result {
                    Ok(()) => {
                        let from = from.map_or_else(|| "a MAC its log no longer shows".to_owned(), ipv4::mac_text);
                        self.note(&format!(
                            "router swap: the vendor kernel addressed customer IPv4 to {from}; pointed it at {to}, the router that holds the DHCP lease (kern netif hmac {hostif})"
                        ));
                    }
                    Err(err) => self.note(&format!(
                        "router swap: could not point the vendor kernel's IPv4 host MAC at {to}: {err}"
                    )),
                }
            }
            HostMacAction::GiveUp { to } => self.note(&format!(
                "router swap: the kernel log still does not show {} as the IPv4 host MAC after {} commands; trying again in {} s",
                ipv4::mac_text(to),
                host_mac::TRIES,
                host_mac::PAUSE
            )),
        }
    }
}
