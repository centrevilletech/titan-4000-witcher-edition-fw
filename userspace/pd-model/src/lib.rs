//! Decisions for IPv6 prefix delegation in IP passthrough.
//!
//! The keeper process speaks on the wire. This crate is the part that can be
//! tested on a host: prefix cuts, DHCPv6 replies, router advertisements, when
//! to escalate, and the IPv4 passthrough repairs.

pub mod config;
pub mod dhcpv6;
pub mod filter;
pub mod health;
pub mod ipv4;
pub mod ipv4_health;
pub mod mgmt;
pub mod prefix;
pub mod ra;

pub use config::{Config, Report, load_config, shown_choice, store_config};
pub use prefix::Block;
