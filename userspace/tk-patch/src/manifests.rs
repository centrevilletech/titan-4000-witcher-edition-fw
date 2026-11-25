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
/// The v1.0.17 release image: N6H_R4_R1 with the uplink AQM's bench step S3
/// as the M1 block's defaults (PIE drop budget 5%, ceiling 35 ms; v1.0.16:
/// 2% and 50 ms; lanes-20261125/AB3). Every other byte is N6H_R4_R1's.
pub const N6H_R4_R1_S3: &str = include_str!("../manifests/n6h-r4-r1-s3.manifest");

/// Every manifest in the tree. Tests walk this list; tests/stock.rs and
/// scripts/test-tk-patch.py pin each one's bench hashes.
pub const ALL: [&str; 6] = [N6H, M1, R1, R4, N6H_R4_R1, N6H_R4_R1_S3];

/// What `titan-pd-keeper tk-build` builds, and the only manifest the keeper
/// carries: each one costs about 20 KiB of flash. A keeper test checks its
/// M1 block version. The others build on a host with `tk-patch build`.
pub const RELEASE: &str = N6H_R4_R1_S3;
