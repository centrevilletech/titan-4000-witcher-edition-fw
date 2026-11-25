//! Decisions for IPv6 prefix delegation in IP passthrough.
//!
//! The keeper process speaks on the wire. This crate is the part that can be
//! tested on a host: prefix cuts, DHCPv6 replies, router advertisements, when
//! to escalate, the IPv4 passthrough repairs, the SAS NAT rule, the guard for
//! the vendor kernel's external device, the watchdog for a unit that is
//! attached but hears nothing, keeping the LTE driver's downlink MAC on the
//! customer router, moving the vendor kernel's IPv4 host MAC to a new router
//! after a swap, 802.3x flow control on the customer port, which keeper
//! writes reach flash, the self-revert of a setting change, the drop of
//! customer IPv6 while the unit holds no SAS grant, carrier watch against held
//! SAS grants, the boot confirm for a staged modem firmware image, its modem
//! feature flags, building that image on the unit and its default build at
//! boot and whether its rollbacks were the image's or the network's, the
//! download clamp module, the passthrough bridge fast path, the
//! off switches for those latency features, the carrier picker, the opt-in
//! CPU trims, and the sign-in limits of the web service and recovery page.
#![forbid(unsafe_code)]

pub mod carrier_pick;
pub mod carrier_watch;
pub mod cbrs_gate;
pub mod config;
pub mod cpu_trims;
pub mod deaf;
pub mod dhcpv6;
pub mod dns_probe;
pub mod durable;
pub mod driver_mac;
pub mod ethernet;
pub mod extdev;
pub mod fastpath;
pub mod filter;
pub mod health;
pub mod host_mac;
pub mod ipv4;
pub mod ipv4_health;
pub mod mgmt;
pub mod nvram;
pub mod pace;
pub mod prefix;
pub mod qctrl;
pub mod ra;
pub mod reboots;
pub mod sas_nat;
pub mod sha256;
pub mod sign_in;
pub mod switches;
pub mod tk_boot;
pub mod tk_build;
pub mod tk_default;
pub mod tk_flags;
pub mod tk_verdict;
pub mod wear;

pub use config::{Config, Report, load_config, shown_choice, store_config};
pub use prefix::Block;
pub mod radio;
