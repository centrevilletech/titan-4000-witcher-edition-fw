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
/// The v1.0.16 release image, built by lane R1 (`build-combined`): N6H plus
/// R4's Rust N4 uplink engine plus R1's hardened Rust PIE (M1 block version
/// 0x20261126).
pub const N6H_R4_R1: &str = include_str!("../manifests/n6h-r4-r1.manifest");
/// Lane G1: the v1.0.16 image plus the boot-off, observation-only MAC UL
/// timeline tracer (G1 control block at 0x8412a340, 128 KiB ring at 0x87f70000).
pub const N6H_R4_R1_G1: &str = include_str!("../manifests/n6h-r4-r1-g1.manifest");

/// Every manifest in the tree. Tests walk this list; tests/stock.rs and
/// scripts/test-tk-patch.py pin each one's bench hashes.
pub const ALL: [&str; 6] = [N6H, M1, R1, R4, N6H_R4_R1, N6H_R4_R1_G1];

/// What `titan-pd-keeper tk-build` builds, and the only manifest the keeper
/// carries: each one costs about 20 KiB of flash. A keeper test checks its
/// M1 block version. The others build on a host with `tk-patch build`.
pub const RELEASE: &str = N6H_R4_R1;
