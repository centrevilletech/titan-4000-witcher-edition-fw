//! Management IPv6 on `lte0pdn0`, from the interface id the modem assigns,
//! in every mode. See `titan_pd_model::mgmt`.

use std::fs;
use std::net::{IpAddr, Ipv6Addr};

use titan_pd_model::mgmt::{self, Step};
use titan_sys::ifaddrs::InterfaceAddrs;
use titan_sys::socket::{Socket, SocketExt};

use crate::command::{command_stdout, run_status};
use crate::files::read_file;
use crate::netdev::{carrier_up, interface_index, read_mac};
use crate::paths::state_dir;

use super::{BRIDGE, Keeper};
use super::if_inet6::{link_local, proc_if_inet6_addrs};
use super::kmsg::kernel_messages;

/// Seconds between safety re-checks of `ip -6 route` once management IPv6 has settled.
const MGMT_ROUTE_VERIFY: u64 = 300;
const MGMT_EVERY: u64 = 10;
const MGMT_LOG_EVERY: u64 = 60;

impl Keeper {
    /// Install the core-assigned interface id on ue-mgmt and solicit from it.
    /// Runs in NAT and in passthrough, whether or not prefix delegation is on.
    pub(super) fn maintain_mgmt_v6(&mut self) {
        if self.now.saturating_sub(self.last_mgmt) < MGMT_EVERY && self.last_mgmt != 0 {
            return;
        }
        self.last_mgmt = self.now;
        if !carrier_up(mgmt::MGMT_DEV) {
            self.mgmt_settled = false;
            return;
        }
        // An IPv4-only bearer: the modem turns IPv6 off here, and no address can be added.
        if read_file("/proc/sys/net/ipv6/conf/lte0pdn0/disable_ipv6").trim() == "1" {
            self.mgmt_settled = false;
            return;
        }
        if !self.mgmt_klog_checked || self.kernel_log.is_none() {
            self.mgmt_klog_checked = true;
            if let Some(iid) = mgmt::assigned_iid(&kernel_messages()) {
                self.mgmt_iid = Some(iid);
            }
        }
        let assigned = self.mgmt_iid;
        let cached = cached_mgmt_iid();
        let iid = match assigned.or(cached) {
            Some(iid) => iid,
            None => return,
        };
        if assigned.is_some() && assigned != cached {
            let _ = fs::write(
                state_dir().join("mgmt-iid.txt"),
                format!("{}\n", iid.token()),
            );
        }
        let addrs = proc_if_inet6_addrs(mgmt::MGMT_DEV);
        let accept = read_file("/proc/sys/net/ipv6/conf/lte0pdn0/accept_ra");
        let up = mgmt::global_up(iid, &addrs);
        if self.mgmt_settled
            && up
            && accept.trim() == "0"
            && self.now.saturating_sub(self.last_mgmt_route_verify) < MGMT_ROUTE_VERIFY
        {
            self.scrub_mgmt_off_lan(&addrs);
            return;
        }
        let routes = command_stdout("ip", &["-6", "route", "show"]);
        let steps = mgmt::plan(iid, &addrs, &accept, &routes);
        if up && !self.mgmt_up_logged {
            self.note(&format!(
                "ue-mgmt ipv6 is up ({})",
                addrs_global_text(&addrs).unwrap_or_else(|| iid.link_local().to_string())
            ));
            self.mgmt_up_logged = true;
        }
        if up {
            self.scrub_mgmt_off_lan(&addrs);
        }
        if !up {
            self.mgmt_up_logged = false;
            self.mgmt_settled = false;
            if self.now.saturating_sub(self.last_mgmt_log) >= MGMT_LOG_EVERY {
                self.note(&format!(
                    "ue-mgmt has no global; soliciting from {} so the assigned prefix can come up",
                    iid.link_local()
                ));
                self.last_mgmt_log = self.now;
            }
        }
        if steps.is_empty() && up && accept.trim() == "0" {
            self.mgmt_settled = true;
            self.last_mgmt_route_verify = self.now;
            return;
        }
        self.mgmt_settled = false;
        for step in steps {
            if step == Step::IgnoreAdvertisements {
                self.note(
                    "ue-mgmt ipv6: closing lte0pdn0 to further router advertisements (accept_ra=0)",
                );
            }
            if matches!(step, Step::DropKeptDefault(_)) {
                self.note(
                    "ue-mgmt ipv6: removing the permanent default so the kernel can take the advertisement",
                );
            }
            if let Err(err) = self.apply_mgmt(step) {
                self.note(&format!("ue-mgmt ipv6: {err}"));
            }
        }
    }

    fn apply_mgmt(&self, step: Step) -> Result<(), String> {
        match step {
            Step::AcceptAdvertisements => {
                fs::write("/proc/sys/net/ipv6/conf/lte0pdn0/accept_ra", "2\n")
                    .map_err(|err| format!("accept_ra: {err}"))
            }
            Step::IgnoreAdvertisements => {
                fs::write("/proc/sys/net/ipv6/conf/lte0pdn0/accept_ra", "0\n")
                    .map_err(|err| format!("accept_ra: {err}"))
            }
            Step::KeepLearnedDefault(metric) => {
                // `replace` turns the learned route into a plain one with no
                // expiry. On this kernel a duplicate `add` leaves the expiry.
                let metric = metric.to_string();
                run_status(
                    "ip",
                    &[
                        "-6",
                        "route",
                        "replace",
                        "default",
                        "via",
                        "fe80::1",
                        "dev",
                        mgmt::MGMT_DEV,
                        "metric",
                        &metric,
                    ],
                )
            }
            Step::AddLinkLocal(addr) => {
                let spec = format!("{addr}/64");
                match run_status(
                    "ip",
                    &["-6", "addr", "add", &spec, "dev", mgmt::MGMT_DEV, "nodad"],
                ) {
                    Err(err) if err.contains("exists") => Ok(()),
                    other => other,
                }
            }
            Step::DropKeptDefault(metric) => {
                let metric = metric.to_string();
                run_status(
                    "ip",
                    &[
                        "-6",
                        "route",
                        "del",
                        "default",
                        "via",
                        "fe80::1",
                        "dev",
                        mgmt::MGMT_DEV,
                        "metric",
                        &metric,
                    ],
                )
            }
            Step::Solicit(addr) => solicit_mgmt(addr),
            Step::PreferManagementDefault => run_status(
                "ip",
                &[
                    "-6",
                    "route",
                    "replace",
                    "default",
                    "via",
                    "fe80::1",
                    "dev",
                    mgmt::MGMT_DEV,
                    "metric",
                    "1",
                ],
            ),
        }
    }

    /// The vendor IPv6 hook treats a learned management prefix as a LAN prefix.
    fn scrub_mgmt_off_lan(&mut self, mgmt_addrs: &str) {
        let Some(global) = addrs_global_text(mgmt_addrs).and_then(|text| text.parse().ok()) else {
            return;
        };
        for path in ["/var/config/resolv.conf", "/etc/resolv.conf"] {
            let current = read_file(path);
            let Some(cleaned) = mgmt::without_zero_nameserver(&current) else {
                continue;
            };
            if fs::write(path, &cleaned).is_ok() {
                self.note("removed the unspecified IPv6 nameserver from resolv.conf");
            }
        }
        let bridge = proc_if_inet6_addrs(BRIDGE);
        for addr in mgmt::bridge_globals_in_prefix(&bridge, global) {
            let spec = format!("{addr}/128");
            match run_status("ip", &["-6", "addr", "del", &spec, "dev", BRIDGE]) {
                Ok(()) => self.note(&format!(
                    "removed {addr} from the customer bridge; it is the management prefix"
                )),
                Err(err) => self.note(&format!("could not remove {addr} from the bridge: {err}")),
            }
        }
    }
}

/// The management bearer has an IPv4 or global IPv6 address (checked via
/// rtnetlink `getifaddrs` without spawning `ip`).
pub(super) fn mgmt_address_up() -> bool {
    if !carrier_up(mgmt::MGMT_DEV) {
        return false;
    }
    let Ok(addrs) = InterfaceAddrs::read() else {
        return command_stdout("ip", &["addr", "show", "dev", mgmt::MGMT_DEV])
            .lines()
            .map(str::trim)
            .any(|line| {
                line.starts_with("inet ")
                    || (line.starts_with("inet6 ") && line.contains("scope global"))
            });
    };
    addrs
        .iter()
        .filter(|addr| addr.is_on(mgmt::MGMT_DEV))
        .any(|addr| match addr.addr {
            IpAddr::V4(_) => true,
            IpAddr::V6(ip) => {
                let o = ip.octets();
                let link_local = o[0] == 0xfe && (o[1] & 0xc0) == 0x80;
                !link_local && !ip.is_loopback() && !ip.is_unspecified()
            }
        })
}

fn cached_mgmt_iid() -> Option<mgmt::Iid> {
    let text = fs::read_to_string(state_dir().join("mgmt-iid.txt")).unwrap_or_default();
    mgmt::parse_iid(text.trim())
}

pub(super) fn addrs_global_text(dump: &str) -> Option<String> {
    dump.split_whitespace().find_map(|word| {
        let bare = word.split('/').next()?;
        let addr: Ipv6Addr = bare.parse().ok()?;
        let octets = addr.octets();
        let link_local = octets[0] == 0xfe && (octets[1] & 0xc0) == 0x80;
        if link_local {
            None
        } else {
            Some(addr.to_string())
        }
    })
}

/// Diagnostic: one router solicitation on the management bearer, from the
/// core-assigned link-local. Changes no setting.
pub fn solicit_once() -> Result<Ipv6Addr, String> {
    let dmesg = command_stdout("dmesg", &[]);
    let iid = mgmt::assigned_iid(&dmesg)
        .or_else(cached_mgmt_iid)
        .ok_or("the modem has not reported an interface identifier for lte0pdn0")?;
    let source = iid.link_local();
    solicit_mgmt(source)?;
    Ok(source)
}

fn solicit_mgmt(src: Ipv6Addr) -> Result<(), String> {
    let mac = read_mac(mgmt::MGMT_DEV)?;
    let ifindex = interface_index(mgmt::MGMT_DEV).ok_or("lte0pdn0 has no interface index")?;
    let packet = mgmt::solicitation(mac);
    // Closed when this function returns, including on the error paths below.
    let socket = Socket::icmpv6_raw().map_err(|err| format!("socket: {err}"))?;
    let scope = ifindex as u32;
    socket
        .bind_ipv6(src, scope)
        .map_err(|err| format!("bind: {err}"))?;
    socket
        .bind_to_device(mgmt::MGMT_DEV)
        .map_err(|err| format!("bind to device: {err}"))?;
    socket
        .set_ipv6_multicast_hops(255)
        .map_err(|err| format!("hop limit: {err}"))?;
    socket
        .set_ipv6_multicast_if(ifindex)
        .map_err(|err| format!("multicast interface: {err}"))?;
    let all_routers = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 2);
    socket
        .send_ipv6(&packet, all_routers, scope)
        .map_err(|err| format!("router solicitation: {err}"))?;
    Ok(())
}
