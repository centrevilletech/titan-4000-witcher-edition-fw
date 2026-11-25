//! The manifests in this tree. Each one rebuilds a bench-tested image byte
//! for byte from the stock modem firmware (scripts/test-tk-patch.py).

/// Lane N6H: the earlier latency image.
pub const N6H: &str = include_str!("../manifests/n6h.manifest");
/// Lane M1: N6H plus the Rust PIE uplink AQM (M1 block version 0x20261125).
pub const M1: &str = include_str!("../manifests/m1.manifest");
/// Lane R1: M1 hardened for production (M1 block version 0x20261126).
pub const R1: &str = include_str!("../manifests/r1.manifest");
/// Lane R4: M1 plus N4's uplink engine in Rust.
pub const R4: &str = include_str!("../manifests/r4.manifest");

/// Every manifest in the tree. Tests walk this list; tests/stock.rs and
/// scripts/test-tk-patch.py pin each one's bench hashes.
pub const ALL: [&str; 4] = [N6H, M1, R1, R4];

/// What `titan-pd-keeper tk-build` builds: the release image. A keeper test
/// checks that the keeper manages its M1 block version.
pub const RELEASE: &str = M1;
