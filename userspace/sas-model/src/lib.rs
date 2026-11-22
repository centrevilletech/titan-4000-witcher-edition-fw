//! A CBRS SAS client for a CPE-CBSD, as decisions that can be tested on a
//! host.
//!
//! `engine` is the grant manager. `proto` builds and reads the WInnForum
//! SAS-CBSD messages. `band` handles frequency ranges and the vendor channel
//! mask, `ipc` the vendor's radio events, and `gate` the customer-traffic
//! gate. `mock` is a pretend SAS for tests: it can go silent, answer slowly,
//! suspend or terminate grants, and report conflicts.

pub mod band;
pub mod engine;
pub mod gate;
pub mod ipc;
pub mod mock;
pub mod proto;
pub mod vendor_log;

pub use band::Range;
pub use engine::{Action, Engine, Gate, Input, Policy, RadioCommand};
