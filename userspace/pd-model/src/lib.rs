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
//! feature flags, the staged download clamp module, and the staged passthrough
//! bridge fast path.

pub mod carrier_watch;
pub mod cbrs_gate;
pub mod config;
pub mod deaf;
pub mod dhcpv6;
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
pub mod prefix;
pub mod qctrl;
pub mod ra;
pub mod sas_nat;
pub mod sha256;
pub mod tk_boot;
pub mod tk_flags;
pub mod wear;

pub use config::{Config, Report, load_config, shown_choice, store_config};
pub use prefix::Block;
pub mod radio;
