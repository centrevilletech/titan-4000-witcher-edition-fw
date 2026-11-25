//! Modem feature flags for a confirmed boot of a staged modem firmware image.
//!
//! Patched modem images (see docs/tk-boot-loader.md) boot with every feature
//! off. Words in modem RAM, grouped by the patch layer's magic word, turn the
//! proven latency fixes on:
//!
//! - N4 (`0x847ed600` = `4e 34 56 32` `"N4V2"`):
//!   - `0x84f93008` hold margin (`0..=0x200`, or `0..=0x800` with `hold_ack=prb-tax`)
//!   - `0x847ed608` / `0x847ed60c` N4 PDCP staging limits (`4096..=24576`, min <= max;
//!     off values `0x4000` / `0x6000`)
//!   - `0x847ed604` N4 flags (bits `0x15`; bits `0x2`, `0x8`, `0x20` refused)
//! - IMG4 (`0x847ecfe8` = `49 4d 47 34` `"IMG4"`):
//!   - `0x847ed548` G1A, `0x847ed54c` G1B, `0x847ed550` G1C, `0x847ecf08` TK1 (0 or 1)
//!   - `0x847ed554` LNK (0 or 2 observe only; value 1 is refused unless N6 magic is
//!     present and `U2_FLAGS` bit 0 is requested in the same config)
//! - N5 (`0x84489a64` = `4e 35 46 4c` `"N5FL"`):
//!   - `0x84489a70` `N5_RATE_BPMS` (`8..=200`), `0x84489a74` `N5_BURST_B` (`512..=16384`),
//!     `0x84489a78` `N5_HOLD_MS` (`100..=5000`), `0x84489a7c` `N5_BUDGET_PCT` (`1..=50`),
//!     `0x84489a84` `N5_PDCP_MIN` / `0x84489a88` `N5_PDCP_MAX` (`4096..=24576`, min <= max),
//!     `0x84489a8c` `N5_PDCP_K_Q4` (`0..=64`), `0x84489a6c` `N5_FLAGS` (`0..=3`, bit 2
//!     refused; bit 1 requires N4 flags bit 0)
//! - N6 (`0x8418ff00` = `55 32 48 46` `"U2HF"`):
//!   - `0x8418ff08` `U2_FLAGS` (0 or 1)
//! - M1 (`0x841b5900` = `4d 31 50 49` `"M1PI"`, then a build version in
//!   `M1_VERSIONS` at `0x841b5904`):
//!   - `0x841b5908` `M1_SELECT` (0 N4 AQM v2, the boot value and rollback; 1 Rust
//!     PIE; 2 no AQM). The block's counters are read, never written (`STATUS`).
//!
//! Forbidden addresses (TRCP, W5, UHQ, U3T, R17, X4/HRB, DSR, U14, PHR, RF,
//! power, MPR, calibration, the M1 tunables, state and counters, and every
//! address outside `TABLE`) are refused.
//!
//! Guards:
//! - Only addresses on `TABLE` and values passing their range and cross-word
//!   rules (`REQUIRES`, `MIN_MAX`) are accepted.
//! - Nothing is written unless every patch layer's magic for that session reads
//!   back in the same session (N4 through `tk_boot::flag_writes_allowed`), and,
//!   for a layer with a version word (M1), one of its accepted versions.
//! - Write order: reducing/disabling flags first (reverse dependency order),
//!   then parameters, then enabling flags (`N4_FLAGS` before `N5_FLAGS`).
//! - Sessions that would exceed `MAX_SESSION_SECS` split into consecutive
//!   sessions in write order so no session leaves a half-applied enable.
//! - A write counts only when its read-back matches in the same session.
//! - After `MAX_ATTEMPTS` failed sessions in a row, if a write may have
//!   landed, the keeper rolls every managed word back to its documented off
//!   value (magic still required). The off values are a safe place to wait,
//!   not an end: it writes the wanted values again after a backoff
//!   (`BACKOFF_FIRST` doubling to `BACKOFF_MAX`), forever, and retries a
//!   rollback that did not read back the same way. A console that does not
//!   answer sends nothing, so it costs no attempt: the keeper looks again
//!   later, backing off as for a missing magic.
//! - A bench/maintenance hold (`manage=off` in `tk/config` or the hands-off
//!   marker file) pauses all console sessions and reports `state=hands-off`.
use crate::tk_boot::{self, BootStatus, MAGIC, MAGIC_ADDR, Source};

/// Patch layer whose magic must be verified in the same session before writing
/// any word that belongs to it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum MagicGroup {
    N4,
    Img4,
    N5,
    N6,
    M1,
}

impl MagicGroup {
    pub fn name(self) -> &'static str {
        magic_spec(self).name
    }
}

/// Magic word address and expected bytes in `vm` display order (MSB-first).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MagicSpec {
    pub group: MagicGroup,
    pub name: &'static str,
    pub addr: u32,
    pub bytes: [u8; 4],
    /// Build versions accepted in the word after the magic (`addr + 4`), as
    /// the console shows it (most significant byte first, like `bytes`).
    /// Empty for a layer without a version word.
    pub versions: &'static [u32],
}

/// N4 patch magic address (`0x847ed600`, `"N4V2"`).
pub const N4_MAGIC_ADDR: u32 = MAGIC_ADDR;
/// IMG4 patch magic address (`0x847ecfe8`, `"IMG4"`).
pub const IMG4_MAGIC_ADDR: u32 = 0x847e_cfe8;
/// N5 patch magic address (`0x84489a64`, `"N5FL"`).
pub const N5_MAGIC_ADDR: u32 = 0x8448_9a64;
/// N6 patch magic address (`0x8418ff00`, `"U2HF"`, shared by N6 and N6H).
pub const N6_MAGIC_ADDR: u32 = 0x8418_ff00;
/// N6/N6H variant word (`0x8418ff04`: `4e 36 00 00` on N6, `4e 36 48 03` on N6H).
pub const N6_DEFAULTS_ADDR: u32 = 0x8418_ff04;
pub const N6_DEFAULTS_STOCK: u32 = 0x4e36_0000;
pub const N6H_DEFAULTS: u32 = 0x4e36_4803;
/// M1 Rust PIE uplink AQM block (`0x841b5900..0x841b5a00`, magic `"M1PI"`).
pub const M1_MAGIC_ADDR: u32 = 0x841b_5900;
/// M1 builds whose selector and counters sit where `TABLE` and `STATUS` say
/// (`device/modem-rust/src/pie.rs`, `M1Block`). A build not on this list
/// writes nothing.
pub const M1_VERSIONS: [u32; 2] = [0x2026_1125, 0x2026_1126];

pub const MAGICS: [MagicSpec; 5] = [
    MagicSpec {
        group: MagicGroup::N4,
        name: "N4",
        addr: N4_MAGIC_ADDR,
        bytes: MAGIC,
        versions: &[],
    },
    MagicSpec {
        group: MagicGroup::Img4,
        name: "IMG4",
        addr: IMG4_MAGIC_ADDR,
        bytes: *b"IMG4",
        versions: &[],
    },
    MagicSpec {
        group: MagicGroup::N5,
        name: "N5",
        addr: N5_MAGIC_ADDR,
        bytes: *b"N5FL",
        versions: &[],
    },
    MagicSpec {
        group: MagicGroup::N6,
        name: "N6",
        addr: N6_MAGIC_ADDR,
        bytes: *b"U2HF",
        versions: &[],
    },
    MagicSpec {
        group: MagicGroup::M1,
        name: "M1",
        addr: M1_MAGIC_ADDR,
        bytes: *b"M1PI",
        versions: &M1_VERSIONS,
    },
];

pub fn magic_spec(group: MagicGroup) -> MagicSpec {
    MAGICS
        .iter()
        .copied()
        .find(|m| m.group == group)
        .expect("every MagicGroup has a MagicSpec")
}

/// N4 feature flags word (`0x847ed604`).
pub const FLAGS_ADDR: u32 = 0x847e_d604;
/// N4 grant-hold size word, in bytes (`0x84f93008`).
pub const HOLD_ADDR: u32 = 0x84f9_3008;
/// N4 PDCP staging minimum (`0x847ed608`, off/default `0x4000` = 16384).
pub const N4_PDCP_MIN_ADDR: u32 = 0x847e_d608;
/// N4 PDCP staging maximum (`0x847ed60c`, off/default `0x6000` = 24576).
pub const N4_PDCP_MAX_ADDR: u32 = 0x847e_d60c;

/// IMG4 / IMG2 UL GIPC idle-clear (`0x847ed548`).
pub const G1A_ADDR: u32 = 0x847e_d548;
/// IMG4 / IMG2 bounded LLCE1 poll (`0x847ed54c`).
pub const G1B_ADDR: u32 = 0x847e_d54c;
/// IMG4 / IMG2 early LLCE0 harvest (`0x847ed550`).
pub const G1C_ADDR: u32 = 0x847e_d550;
/// IMG4 / IMG3 batched DL GIPC send (`0x847ecf08`).
pub const TK1_ADDR: u32 = 0x847e_cf08;
/// IMG4 / IMG2 UL local NACK (`0x847ed554`; 0 or 2 observe; 1 requires N6 magic + U2_FLAGS bit 0).
pub const LNK_ADDR: u32 = 0x847e_d554;

/// N5 master flags (`0x84489a6c`; bits 0..=1, bit 2 refused).
pub const N5_FLAGS_ADDR: u32 = 0x8448_9a6c;
/// N5 per-flow sparse byte-rate threshold in bytes/ms (`0x84489a70`, 8..=200).
pub const N5_RATE_BPMS_ADDR: u32 = 0x8448_9a70;
/// N5 per-flow sparse burst allowance in bytes (`0x84489a74`, 512..=16384).
pub const N5_BURST_B_ADDR: u32 = 0x8448_9a74;
/// N5 bulk hold duration in ms (`0x84489a78`, 100..=5000).
pub const N5_HOLD_MS_ADDR: u32 = 0x8448_9a78;
/// N5 global Ring 0 promoted-byte cap percentage (`0x84489a7c`, 1..=50).
pub const N5_BUDGET_PCT_ADDR: u32 = 0x8448_9a7c;
/// N5 PDCP staging minimum (`0x84489a84`, 4096..=24576; 0 restores 16384).
pub const N5_PDCP_MIN_ADDR: u32 = 0x8448_9a84;
/// N5 PDCP staging maximum (`0x84489a88`, 4096..=24576; 0 restores 24576).
pub const N5_PDCP_MAX_ADDR: u32 = 0x8448_9a88;
/// N5 adaptive PDCP multiplier in Q4 (`0x84489a8c`, 0..=64).
pub const N5_PDCP_K_Q4_ADDR: u32 = 0x8448_9a8c;

/// N6 LNK-FIX master switch (`0x8418ff08`, 0 or 1).
pub const U2_FLAGS_ADDR: u32 = 0x8418_ff08;

/// M1 uplink AQM selector (`0x841b5908`): 0 N4 AQM v2 (boot value and
/// rollback), 1 Rust PIE, 2 no AQM. The modem acts on 1 or 2 only while
/// `N4_FLAGS` has bits `0x5`; otherwise it enqueues as with the N4 AQM off.
pub const M1_SELECT_ADDR: u32 = 0x841b_5908;

/// AQM v2 (`0x1 | 0x4`) and the grant-hold rescue (`0x10`). Bits `0x2` (lead),
/// `0x8` (stock sparse promotion) and `0x20` must stay off.
pub const FLAG_BITS: u32 = 0x15;
/// N5 flags bits: `0x1` sparse lane, `0x2` N5 PDCP staging (needs N4 bit 0).
/// Bit `0x4` (diagnostic feeder fallback) is refused.
pub const N5_FLAG_BITS: u32 = 0x3;
/// Largest grant-hold size accepted without `hold_ack=prb-tax`.
pub const HOLD_MAX: u32 = 0x200;
/// Largest grant-hold size accepted with explicit `hold_ack=prb-tax`.
pub const HOLD_ACK_MAX: u32 = 0x800;
/// Config acknowledgement token required to raise the grant-hold cap above `0x200`.
pub const HOLD_ACK_TOKEN: &str = "prb-tax";

/// PDCP staging default minimum (`0x4000` = 16384 B).
pub const PDCP_MIN_DEFAULT: u32 = 0x4000;
/// PDCP staging default maximum (`0x6000` = 24576 B).
pub const PDCP_MAX_DEFAULT: u32 = 0x6000;
/// PDCP staging range bounds (4096..=24576 B).
pub const PDCP_LIMIT_MIN: u32 = 4096;
pub const PDCP_LIMIT_MAX: u32 = 24576;

/// Role of a managed word in write ordering.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    /// Parameter or limit word: written before enable flags, after disable flags.
    Param,
    /// Enable/feature flag word: written first when turning off, last when turning on.
    Flag,
}

/// Allowed values for an operator `wm=` line.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AllowedValues {
    Bitmask(u32),
    Range { min: u32, max: u32 },
    HoldRange { normal_max: u32, ack_max: u32 },
    OneOf(&'static [u32]),
}

/// One managed modem RAM word.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WordSpec {
    pub name: &'static str,
    pub addr: u32,
    pub magic: MagicGroup,
    pub kind: Kind,
    pub allowed: AllowedValues,
    /// Documented off / rollback value written on rollback or config removal.
    pub off_value: u32,
    /// Boot value in modem RAM (used for cross-word min <= max checks when one side is omitted).
    pub boot_default: u32,
}

impl WordSpec {
    pub fn value_ok(&self, value: u32, hold_ack: bool) -> bool {
        match self.allowed {
            AllowedValues::Bitmask(mask) => value & !mask == 0,
            AllowedValues::Range { min, max } => (min..=max).contains(&value),
            AllowedValues::HoldRange {
                normal_max,
                ack_max,
            } => value <= if hold_ack { ack_max } else { normal_max },
            AllowedValues::OneOf(list) => list.contains(&value),
        }
    }

    pub fn session_value_ok(&self, value: u32, hold_ack: bool) -> bool {
        value == self.off_value || self.value_ok(value, hold_ack)
    }
}

const LNK_ALLOWED: [u32; 2] = [0, 2];

/// Complete allow-list of managed modem words in canonical apply order:
/// parameters before flags, and prerequisite flags (`N4_FLAGS`) before
/// dependent flags (`N5_FLAGS`). The M1 selector comes last: it switches the
/// uplink AQM only after every other layer is set, and goes back to 0 first.
pub const TABLE: [WordSpec; 19] = [
    // N4 parameters
    WordSpec {
        name: "HOLD_MARGIN",
        addr: HOLD_ADDR,
        magic: MagicGroup::N4,
        kind: Kind::Param,
        allowed: AllowedValues::HoldRange {
            normal_max: HOLD_MAX,
            ack_max: HOLD_ACK_MAX,
        },
        off_value: 0,
        boot_default: 0,
    },
    WordSpec {
        name: "N4_PDCP_MIN",
        addr: N4_PDCP_MIN_ADDR,
        magic: MagicGroup::N4,
        kind: Kind::Param,
        allowed: AllowedValues::Range {
            min: PDCP_LIMIT_MIN,
            max: PDCP_LIMIT_MAX,
        },
        off_value: PDCP_MIN_DEFAULT,
        boot_default: PDCP_MIN_DEFAULT,
    },
    WordSpec {
        name: "N4_PDCP_MAX",
        addr: N4_PDCP_MAX_ADDR,
        magic: MagicGroup::N4,
        kind: Kind::Param,
        allowed: AllowedValues::Range {
            min: PDCP_LIMIT_MIN,
            max: PDCP_LIMIT_MAX,
        },
        off_value: PDCP_MAX_DEFAULT,
        boot_default: PDCP_MAX_DEFAULT,
    },
    // N5 parameters (placed before enable flags so every parameter lands first)
    WordSpec {
        name: "N5_RATE_BPMS",
        addr: N5_RATE_BPMS_ADDR,
        magic: MagicGroup::N5,
        kind: Kind::Param,
        allowed: AllowedValues::Range { min: 8, max: 200 },
        off_value: 0,
        boot_default: 40,
    },
    WordSpec {
        name: "N5_BURST_B",
        addr: N5_BURST_B_ADDR,
        magic: MagicGroup::N5,
        kind: Kind::Param,
        allowed: AllowedValues::Range {
            min: 512,
            max: 16384,
        },
        off_value: 0,
        boot_default: 3072,
    },
    WordSpec {
        name: "N5_HOLD_MS",
        addr: N5_HOLD_MS_ADDR,
        magic: MagicGroup::N5,
        kind: Kind::Param,
        allowed: AllowedValues::Range { min: 100, max: 5000 },
        off_value: 0,
        boot_default: 500,
    },
    WordSpec {
        name: "N5_BUDGET_PCT",
        addr: N5_BUDGET_PCT_ADDR,
        magic: MagicGroup::N5,
        kind: Kind::Param,
        allowed: AllowedValues::Range { min: 1, max: 50 },
        off_value: 0,
        boot_default: 10,
    },
    WordSpec {
        name: "N5_PDCP_MIN",
        addr: N5_PDCP_MIN_ADDR,
        magic: MagicGroup::N5,
        kind: Kind::Param,
        allowed: AllowedValues::Range {
            min: PDCP_LIMIT_MIN,
            max: PDCP_LIMIT_MAX,
        },
        off_value: 0,
        boot_default: PDCP_MIN_DEFAULT,
    },
    WordSpec {
        name: "N5_PDCP_MAX",
        addr: N5_PDCP_MAX_ADDR,
        magic: MagicGroup::N5,
        kind: Kind::Param,
        allowed: AllowedValues::Range {
            min: PDCP_LIMIT_MIN,
            max: PDCP_LIMIT_MAX,
        },
        off_value: 0,
        boot_default: PDCP_MAX_DEFAULT,
    },
    WordSpec {
        name: "N5_PDCP_K_Q4",
        addr: N5_PDCP_K_Q4_ADDR,
        magic: MagicGroup::N5,
        kind: Kind::Param,
        allowed: AllowedValues::Range { min: 0, max: 64 },
        off_value: 0,
        boot_default: 0,
    },
    // Feature enable flags (N4_FLAGS before N5_FLAGS so bit 0 is set before N5 bit 1)
    WordSpec {
        name: "N4_FLAGS",
        addr: FLAGS_ADDR,
        magic: MagicGroup::N4,
        kind: Kind::Flag,
        allowed: AllowedValues::Bitmask(FLAG_BITS),
        off_value: 0,
        boot_default: 0,
    },
    WordSpec {
        name: "G1A",
        addr: G1A_ADDR,
        magic: MagicGroup::Img4,
        kind: Kind::Flag,
        allowed: AllowedValues::Range { min: 0, max: 1 },
        off_value: 0,
        boot_default: 0,
    },
    WordSpec {
        name: "G1B",
        addr: G1B_ADDR,
        magic: MagicGroup::Img4,
        kind: Kind::Flag,
        allowed: AllowedValues::Range { min: 0, max: 1 },
        off_value: 0,
        boot_default: 0,
    },
    WordSpec {
        name: "G1C",
        addr: G1C_ADDR,
        magic: MagicGroup::Img4,
        kind: Kind::Flag,
        allowed: AllowedValues::Range { min: 0, max: 1 },
        off_value: 0,
        boot_default: 0,
    },
    WordSpec {
        name: "TK1",
        addr: TK1_ADDR,
        magic: MagicGroup::Img4,
        kind: Kind::Flag,
        allowed: AllowedValues::Range { min: 0, max: 1 },
        off_value: 0,
        boot_default: 0,
    },
    WordSpec {
        name: "N5_FLAGS",
        addr: N5_FLAGS_ADDR,
        magic: MagicGroup::N5,
        kind: Kind::Flag,
        allowed: AllowedValues::Bitmask(N5_FLAG_BITS),
        off_value: 0,
        boot_default: 0,
    },
    WordSpec {
        name: "U2_FLAGS",
        addr: U2_FLAGS_ADDR,
        magic: MagicGroup::N6,
        kind: Kind::Flag,
        allowed: AllowedValues::Range { min: 0, max: 1 },
        off_value: 0,
        boot_default: 0,
    },
    WordSpec {
        name: "LNK",
        addr: LNK_ADDR,
        magic: MagicGroup::Img4,
        kind: Kind::Flag,
        // 0 or 2 unconditionally; value 1 requires N6 magic and U2_FLAGS bit 0
        // in the same config (enforced in parse_writes and session_body).
        // Placed after U2_FLAGS so U2_FLAGS enables before LNK and disables after LNK.
        allowed: AllowedValues::OneOf(&LNK_ALLOWED),
        off_value: 0,
        boot_default: 0,
    },
    WordSpec {
        name: "M1_SELECT",
        addr: M1_SELECT_ADDR,
        magic: MagicGroup::M1,
        kind: Kind::Flag,
        allowed: AllowedValues::Range { min: 0, max: 2 },
        off_value: 0,
        boot_default: 0,
    },
];

/// When a cross-word rule applies to its word.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum When {
    /// The word has any of these bits set.
    AnyBit(u32),
    /// The word holds this value. Only the rule admits it: it is not in the
    /// word's `allowed` set (`LNK` 1).
    Value(u32),
}

/// A cross-word rule: `word` matching `when` needs every bit of `bits` set in
/// `needs`. `parse_writes` refuses it with `reason` unless `needs` has those
/// bits in the same config. A session refuses it unless `needs` has them in
/// the same session or already in modem RAM, and it checks the magic of the
/// layer `needs` belongs to as well.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Requires {
    pub word: u32,
    pub when: When,
    pub needs: u32,
    pub bits: u32,
    pub reason: &'static str,
}

impl Requires {
    fn applies(&self, write: Write) -> bool {
        write.addr == self.word
            && match self.when {
                When::AnyBit(bits) => write.value & bits != 0,
                When::Value(value) => write.value == value,
            }
    }

    fn met_by(&self, value: u32) -> bool {
        value & self.bits == self.bits
    }
}

/// Every cross-word rule, checked in this order.
pub const REQUIRES: [Requires; 2] = [
    Requires {
        word: N5_FLAGS_ADDR,
        when: When::AnyBit(0x2),
        needs: FLAGS_ADDR,
        bits: 0x1,
        reason: "N5_FLAGS bit 1 requires N4_FLAGS bit 0",
    },
    Requires {
        word: LNK_ADDR,
        when: When::Value(1),
        needs: U2_FLAGS_ADDR,
        bits: 0x1,
        reason: "LNK value 1 requires N6 magic and U2_FLAGS bit 0 in the same config",
    },
];

/// A value only a cross-word rule admits (`LNK` 1).
fn rule_admits(addr: u32, value: u32) -> bool {
    REQUIRES
        .iter()
        .any(|rule| rule.word == addr && rule.when == When::Value(value))
}

/// Word pairs whose first may not exceed the second. An omitted side counts
/// at its boot value.
const MIN_MAX: [(u32, u32, &str); 2] = [
    (N4_PDCP_MIN_ADDR, N4_PDCP_MAX_ADDR, "N4 PDCP min exceeds max"),
    (N5_PDCP_MIN_ADDR, N5_PDCP_MAX_ADDR, "N5 PDCP min exceeds max"),
];

/// Bits refused with a reason of their own.
const REFUSED_BITS: [(u32, u32, &str); 2] = [
    (
        FLAGS_ADDR,
        0x8,
        "N4 flags bit 3 (0x8, stock sparse promotion) is refused",
    ),
    (N5_FLAGS_ADDR, 0x4, "N5_FLAGS bit 2 (0x4) is refused"),
];

pub fn find_word(addr: u32) -> Option<&'static WordSpec> {
    TABLE.iter().find(|spec| spec.addr == addr)
}

fn table_position(addr: u32) -> usize {
    TABLE
        .iter()
        .position(|spec| spec.addr == addr)
        .unwrap_or(TABLE.len())
}

/// Documented off / rollback value for `addr`, if it is on `TABLE`.
pub fn off_value(addr: u32) -> Option<u32> {
    find_word(addr).map(|spec| spec.off_value)
}

/// Failed write sessions in a row before the managed words go back to their
/// off values (when a write may have landed) and the keeper backs off.
pub const MAX_ATTEMPTS: u32 = 3;
/// Seconds between a failed session and the next try.
pub const RETRY_SECS: u64 = 20;
/// The wait after `MAX_ATTEMPTS` failed sessions, and after each failed round
/// or rollback since. It doubles up to `BACKOFF_MAX` and starts again once the
/// wanted words read back. The keeper never stops trying.
pub const BACKOFF_FIRST: u64 = 300;
pub const BACKOFF_MAX: u64 = 3600;
/// First wait for the patch magic, or for a console that answers nothing. It
/// doubles up to `MAGIC_MAX`.
pub const MAGIC_FIRST: u64 = 15;
pub const MAGIC_MAX: u64 = 600;
/// Seconds between read-only checks once the flags hold.
pub const CHECK_EVERY: u64 = 600;
/// Seconds after a modem restart before the first try.
pub const AFTER_RESTART: u64 = 30;
/// Read-only checks without a console reply before a full write session
/// (which resets the console first).
pub const CHECK_MISSES: u32 = 3;
/// Worst-case time budget for one DM session (seconds at 3 s per line).
/// Kept well below the 90 s `SESSION_LIMIT` in `tk_flags_io`.
pub const MAX_SESSION_SECS: u64 = 75;

/// One `wm` write.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Write {
    pub addr: u32,
    pub value: u32,
}

impl std::fmt::Display for Write {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "0x{:08x}=0x{:x}", self.addr, self.value)
    }
}

/// The value is inside the normal operator limit (without `hold_ack=prb-tax`).
pub fn value_ok(addr: u32, value: u32) -> bool {
    value_ok_with_ack(addr, value, false)
}

/// The value is inside the operator limit for its word.
pub fn value_ok_with_ack(addr: u32, value: u32, hold_ack: bool) -> bool {
    find_word(addr).is_some_and(|spec| spec.value_ok(value, hold_ack))
}

/// The value may be written in a DM session (either a valid operator value or
/// the word's documented off/rollback value).
pub fn session_value_ok(addr: u32, value: u32, hold_ack: bool) -> bool {
    find_word(addr).is_some_and(|spec| spec.session_value_ok(value, hold_ack))
}

fn number(text: &str) -> Option<u32> {
    if let Some(hex) = text.strip_prefix("0x").or_else(|| text.strip_prefix("0X")) {
        if hex.is_empty() || hex.len() > 8 {
            return None;
        }
        return u32::from_str_radix(hex, 16).ok();
    }
    if text.is_empty() || text.len() > 10 || !text.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    text.parse().ok()
}

fn strip_comment_and_ws(rest: &str) -> String {
    rest.split('#')
        .next()
        .unwrap_or("")
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect()
}

/// `hold_ack=prb-tax` in `tk/config` (the last `hold_ack=` line wins).
pub fn hold_ack(config: &str) -> bool {
    let mut ack = false;
    for line in config.lines() {
        if let Some(rest) = line.trim_start().strip_prefix("hold_ack=") {
            ack = strip_comment_and_ws(rest) == HOLD_ACK_TOKEN;
        }
    }
    ack
}

/// `manage=off` in `tk/config` (the last `manage=` line wins).
pub fn hands_off(config: &str) -> bool {
    let mut off = false;
    for line in config.lines() {
        if let Some(rest) = line.trim_start().strip_prefix("manage=") {
            let value = strip_comment_and_ws(rest);
            if value == "off" {
                off = true;
            } else if value == "on" {
                off = false;
            }
        }
    }
    off
}

/// Parsed `tk/config` flag directives and `wm=` lines.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Parsed {
    /// One write per allowed word, in `TABLE` order. The last valid line for a
    /// word wins.
    pub writes: Vec<Write>,
    /// Lines that were refused, as written (trimmed).
    pub refused: Vec<String>,
    /// `(line, reason)` for every entry in `refused`.
    pub refused_reasons: Vec<(String, String)>,
    /// True when `hold_ack=prb-tax` is set.
    pub hold_ack: bool,
    /// True when `manage=off` is set.
    pub hands_off: bool,
}

impl Parsed {
    fn refuse(&mut self, line: &str, reason: impl Into<String>) {
        let trimmed = line.trim().to_owned();
        let reason = reason.into();
        self.refused.push(trimmed.clone());
        self.refused_reasons.push((trimmed, reason));
    }
}

fn refuse_reason_for_value(spec: &WordSpec, value: u32, ack: bool) -> String {
    if let Some(rule) = REQUIRES
        .iter()
        .find(|rule| rule.word == spec.addr && rule.when == When::Value(value))
    {
        return rule.reason.into();
    }
    match spec.allowed {
        AllowedValues::Bitmask(mask) => {
            if let Some((_, _, reason)) = REFUSED_BITS
                .iter()
                .find(|(addr, bits, _)| *addr == spec.addr && value & bits != 0)
            {
                return (*reason).into();
            }
            format!(
                "{} value 0x{value:x} sets bits outside mask 0x{mask:x}",
                spec.name
            )
        }
        AllowedValues::Range { min, max } => {
            format!("{} value {value} outside allowed range {min}..={max}", spec.name)
        }
        AllowedValues::HoldRange {
            normal_max,
            ack_max,
        } => {
            if !ack && value <= ack_max {
                format!(
                    "hold 0x{value:x} exceeds 0x{normal_max:x}; add hold_ack={HOLD_ACK_TOKEN} to allow up to 0x{ack_max:x}"
                )
            } else {
                format!(
                    "hold 0x{value:x} exceeds maximum 0x{:x}",
                    if ack { ack_max } else { normal_max }
                )
            }
        }
        AllowedValues::OneOf(list) => {
            format!("{} value 0x{value:x} not in allowed set {:?}", spec.name, list)
        }
    }
}

/// Parse `wm=`, `hold_ack=` and `manage=` lines in `tk/config`.
///
/// Addresses must be in hex (`0x...`) and present in `TABLE`. Values may be hex
/// (`0x...`) or decimal and must pass per-word limits and cross-word rules.
pub fn parse_writes(config: &str) -> Parsed {
    let mut parsed = Parsed {
        hold_ack: hold_ack(config),
        hands_off: hands_off(config),
        ..Parsed::default()
    };
    let mut found: Vec<(Write, String)> = Vec::new();
    for line in config.lines() {
        let trimmed = line.trim_start();
        if let Some(rest) = trimmed.strip_prefix("hold_ack=") {
            let value = strip_comment_and_ws(rest);
            if value != HOLD_ACK_TOKEN {
                parsed.refuse(
                    line,
                    format!("unrecognized hold_ack value (expected hold_ack={HOLD_ACK_TOKEN})"),
                );
            }
            continue;
        }
        if let Some(rest) = trimmed.strip_prefix("manage=") {
            let value = strip_comment_and_ws(rest);
            if value != "off" && value != "on" {
                parsed.refuse(line, "unrecognized manage value (expected manage=off or manage=on)");
            }
            continue;
        }
        let Some(rest) = trimmed.strip_prefix("wm=") else {
            continue;
        };
        let text = strip_comment_and_ws(rest);
        let Some((addr_s, val_s)) = text.split_once(':') else {
            parsed.refuse(line, "malformed wm= line (expected wm=0xADDR:VALUE)");
            continue;
        };
        let addr = if addr_s.starts_with("0x") || addr_s.starts_with("0X") {
            number(addr_s)
        } else {
            None
        };
        let Some(addr) = addr else {
            parsed.refuse(line, "address must be a 32-bit hex value with 0x prefix");
            continue;
        };
        let Some(value) = number(val_s) else {
            parsed.refuse(line, "value must be a 32-bit hex (0x) or decimal number");
            continue;
        };
        let Some(spec) = find_word(addr) else {
            parsed.refuse(line, format!("address 0x{addr:08x} is not on the allow-list"));
            continue;
        };
        // A value only a cross-word rule admits waits for that rule below.
        if !rule_admits(addr, value) && !spec.value_ok(value, parsed.hold_ack) {
            let reason = refuse_reason_for_value(spec, value, parsed.hold_ack);
            parsed.refuse(line, reason);
            continue;
        }
        found.retain(|(w, _)| w.addr != addr);
        found.push((Write { addr, value }, line.trim().to_owned()));
    }

    for (min_addr, max_addr, reason) in MIN_MAX {
        check_min_max(&mut found, &mut parsed, min_addr, max_addr, reason);
    }

    for rule in &REQUIRES {
        let Some(pos) = found.iter().position(|(w, _)| rule.applies(*w)) else {
            continue;
        };
        let met = found
            .iter()
            .any(|(w, _)| w.addr == rule.needs && rule.met_by(w.value));
        if !met {
            let (_, raw) = found.remove(pos);
            parsed.refuse(&raw, rule.reason);
        }
    }

    for spec in &TABLE {
        if let Some((write, _)) = found.iter().find(|(w, _)| w.addr == spec.addr) {
            parsed.writes.push(*write);
        }
    }
    parsed
}

fn check_min_max(
    found: &mut Vec<(Write, String)>,
    parsed: &mut Parsed,
    min_addr: u32,
    max_addr: u32,
    reason: &str,
) {
    let min_entry = found.iter().find(|(w, _)| w.addr == min_addr).map(|(w, _)| w.value);
    let max_entry = found.iter().find(|(w, _)| w.addr == max_addr).map(|(w, _)| w.value);
    if min_entry.is_none() && max_entry.is_none() {
        return;
    }
    let boot = |addr: u32| find_word(addr).map_or(0, |spec| spec.boot_default);
    let eff_min = min_entry.unwrap_or_else(|| boot(min_addr));
    let eff_max = max_entry.unwrap_or_else(|| boot(max_addr));
    if eff_min > eff_max {
        let mut rejected = Vec::new();
        found.retain(|(w, raw)| {
            if w.addr == min_addr || w.addr == max_addr {
                rejected.push(raw.clone());
                false
            } else {
                true
            }
        });
        for raw in rejected {
            parsed.refuse(&raw, reason);
        }
    }
}

/// `enabled=1` in `tk/config` (the last `enabled=` line, comments removed).
pub fn enabled(config: &str) -> bool {
    let mut on = false;
    for line in config.lines() {
        if let Some(rest) = line.strip_prefix("enabled=") {
            on = strip_comment_and_ws(rest) == "1";
        }
    }
    on
}

/// What the keeper wants in modem RAM, from `tk/config` and what it managed
/// before. With the loader turned off or the `wm=` lines removed, every word
/// it managed goes back to its documented off value.
pub fn wanted(config: &str, managed: &[Write]) -> Vec<Write> {
    let writes = parse_writes(config).writes;
    if enabled(config) && !writes.is_empty() {
        let mut all = writes;
        // A word dropped from the config goes back to its documented off value.
        for old in managed {
            if !all.iter().any(|w| w.addr == old.addr) {
                if let Some(off) = off_value(old.addr) {
                    all.push(Write {
                        addr: old.addr,
                        value: off,
                    });
                }
            }
        }
        return in_table_order(all);
    }
    rollback_values(managed)
}

fn in_table_order(writes: Vec<Write>) -> Vec<Write> {
    let mut ordered = Vec::new();
    for spec in &TABLE {
        if let Some(write) = writes.iter().find(|w| w.addr == spec.addr) {
            ordered.push(*write);
        }
    }
    ordered
}

/// Every managed word mapped to its documented off / rollback value
/// (`0x4000`/`0x6000` for N4 PDCP limits, `0` for N5 tunables, flags and hold).
pub fn rollback_values(writes: &[Write]) -> Vec<Write> {
    let mapped: Vec<Write> = writes
        .iter()
        .filter_map(|w| {
            off_value(w.addr).map(|value| Write {
                addr: w.addr,
                value,
            })
        })
        .collect();
    in_table_order(mapped)
}

/// Compatibility helper: same as `rollback_values`.
pub fn zeros(writes: &[Write]) -> Vec<Write> {
    rollback_values(writes)
}

fn is_flag_reducing(spec: &WordSpec, current: Option<u32>, next: u32) -> bool {
    if next == spec.off_value {
        return true;
    }
    if spec.addr == LNK_ADDR {
        // Active local NACK (1) -> observe only (2) reduces behaviour.
        return current == Some(1) && next == 2;
    }
    current.is_some_and(|cur| (next & !cur) == 0 && (cur & !next) != 0)
}

/// The order `wm` lines go out relative to previous values `prev`:
/// 1. Flags turning off or clearing bits, in reverse `TABLE` order
///    (dependent flags like `LNK` before `U2_FLAGS` and `N5_FLAGS` before
///    `N4_FLAGS`, and every reducing flag before any parameter change).
/// 2. Parameters (`Kind::Param`), in `TABLE` order.
/// 3. Flags turning on (`value != off_value`), in `TABLE` order (`N4_FLAGS`
///    before `N5_FLAGS`, `U2_FLAGS` before `LNK`).
pub fn write_order_from(writes: &[Write], prev: &[Write]) -> Vec<Write> {
    let mut ordered = writes.to_vec();
    ordered.sort_by_key(|w| {
        let cur = prev.iter().find(|p| p.addr == w.addr).map(|p| p.value);
        order_key(w, cur)
    });
    ordered
}

/// A write's place in a session, given the value it replaces: reducing flags
/// first in reverse `TABLE` order, then parameters, then enabling flags in
/// `TABLE` order.
fn order_key(write: &Write, current: Option<u32>) -> (u8, usize) {
    let pos = table_position(write.addr);
    match find_word(write.addr) {
        Some(spec) if spec.kind == Kind::Flag && is_flag_reducing(spec, current, write.value) => {
            (0, TABLE.len().saturating_sub(pos))
        }
        Some(spec) if spec.kind == Kind::Param => (1, pos),
        _ => (2, pos),
    }
}

/// The order `wm` lines go out from a fresh boot state.
pub fn write_order(writes: &[Write]) -> Vec<Write> {
    write_order_from(writes, &[])
}

/// Write order refined with the current RAM values read in the same session:
/// a flag whose new value strictly clears bits relative to RAM (`0x15 -> 0x5`,
/// `0x3 -> 0x1`, or `LNK 1 -> 2`) also goes in tier 0 before any parameter changes.
fn write_order_with_current(need: &[(Write, Option<u32>)]) -> Vec<Write> {
    let mut items = need.to_vec();
    items.sort_by_key(|(w, current)| order_key(w, *current));
    items.into_iter().map(|(w, _)| w).collect()
}

/// Distinct patch magics required by `writes`, in canonical `MagicGroup` order.
/// Includes the magic of every word a `REQUIRES` rule needs (`N6` for `LNK=1`,
/// `N4` for `N5_FLAGS` bit 1).
pub fn required_magics(writes: &[Write]) -> Vec<MagicSpec> {
    let mut groups: Vec<MagicGroup> = Vec::new();
    let mut add = |group: MagicGroup| {
        if !groups.contains(&group) {
            groups.push(group);
        }
    };
    for write in writes {
        if let Some(spec) = find_word(write.addr) {
            add(spec.magic);
            for rule in REQUIRES.iter().filter(|rule| rule.applies(*write)) {
                if let Some(needs) = find_word(rule.needs) {
                    add(needs.magic);
                }
            }
        }
    }
    groups.sort_unstable();
    groups.into_iter().map(magic_spec).collect()
}

fn merge_magics(a: &[MagicSpec], b: &[MagicSpec]) -> Vec<MagicSpec> {
    let mut groups: Vec<MagicGroup> = Vec::new();
    for spec in a.iter().chain(b.iter()) {
        if !groups.contains(&spec.group) {
            groups.push(spec.group);
        }
    }
    groups.sort_unstable();
    groups.into_iter().map(magic_spec).collect()
}

/// Cross-word prerequisites that must already hold in modem RAM when the
/// prerequisite word is not written in the same session:
/// `(dependent_write, rule)`.
fn prereq_reads_needed(writes: &[Write]) -> Vec<(Write, &'static Requires)> {
    let mut checks = Vec::new();
    for &write in writes {
        for rule in REQUIRES.iter().filter(|rule| rule.applies(write)) {
            let in_batch = writes
                .iter()
                .any(|w| w.addr == rule.needs && rule.met_by(w.value));
            if !in_batch {
                checks.push((write, rule));
            }
        }
    }
    checks
}

fn session_budget_secs_with_magics(
    writes: &[Write],
    extra_magics: &[MagicSpec],
    session: Session,
) -> u64 {
    let overhead = match session {
        // arm1log 2 (2s), quit 0 (3s), dbg revert (3s), arm1log 1 (2s)
        Session::Apply => 10,
        // arm1log 2 (2s), arm1log 1 (2s)
        Session::Check => 4,
    };
    let magics = merge_magics(&required_magics(writes), extra_magics).len() as u64;
    let prereqs = match session {
        Session::Apply => prereq_reads_needed(writes).len() as u64,
        Session::Check => 0,
    };
    let per_word = match session {
        // read before write + write + read-back
        Session::Apply => 9,
        // read only
        Session::Check => 3,
    };
    let status_reads = status_specs(writes).len() as u64;
    overhead + magics * 3 + prereqs * 3 + (writes.len() as u64) * per_word + status_reads * 3
}

/// Estimated worst-case wall-clock seconds for one DM session at 3 s per line.
pub fn session_budget_secs(writes: &[Write], session: Session) -> u64 {
    session_budget_secs_with_magics(writes, &[], session)
}

/// Split `writes` into consecutive DM sessions that each fit within
/// `MAX_SESSION_SECS`.
///
/// For `Session::Apply`, words are ordered with `write_order_from` first so
/// every reducing/disabling flag runs before any parameter and every parameter
/// runs before any enabling flag (`N4_FLAGS` before `N5_FLAGS`, `U2_FLAGS`
/// before `LNK`). Batch 0 also budgets for every magic required by the entire
/// target set so a missing layer magic stops before any enable is written.
pub fn split_sessions_from(
    writes: &[Write],
    prev: &[Write],
    session: Session,
) -> Vec<Vec<Write>> {
    if writes.is_empty() {
        return Vec::new();
    }
    let ordered = match session {
        Session::Apply => write_order_from(writes, prev),
        Session::Check => in_table_order(writes.to_vec()),
    };
    let all_magics = required_magics(writes);
    let mut batches: Vec<Vec<Write>> = Vec::new();
    let mut current: Vec<Write> = Vec::new();
    for write in ordered {
        let mut candidate = current.clone();
        candidate.push(write);
        let extra: &[MagicSpec] = if batches.is_empty() {
            &all_magics
        } else {
            &[]
        };
        if !current.is_empty()
            && session_budget_secs_with_magics(&candidate, extra, session) > MAX_SESSION_SECS
        {
            batches.push(current);
            current = vec![write];
        } else {
            current.push(write);
        }
    }
    if !current.is_empty() {
        batches.push(current);
    }
    batches
}

/// Split `writes` from a fresh boot state.
pub fn split_sessions(writes: &[Write], session: Session) -> Vec<Vec<Write>> {
    split_sessions_from(writes, &[], session)
}

/// The boot hook staged this image, a keeper process confirmed it, and the
/// modem did not say it read NAND. Only then may flags be written.
pub fn armed_sha(status: &BootStatus, result: &str) -> Option<String> {
    let sha = status.staged.as_ref()?;
    if status.source == Some(Source::Nand) {
        return None;
    }
    let confirmed = result.lines().any(|line| {
        line.trim()
            .strip_prefix("confirmed=")
            .is_some_and(|value| value.trim().eq_ignore_ascii_case(sha))
    });
    confirmed.then(|| sha.clone())
}

/// The modem driver logged a firmware load: `read from nand` or `read from fs`.
/// Seen after the keeper started, it means the modem restarted.
pub fn modem_loaded(kernel_line: &str) -> bool {
    kernel_line.contains("read from nand") || kernel_line.contains("read from fs")
}

/// The 32-bit word at `addr` in a modem console `vm <addr> 4` dump.
///
/// The console prints a column header that names the byte offset of each
/// column. On the unit it reads `03 02 01 00  07 06 05 04 ...`, so the value
/// `0x15` prints as `0x847ED604 | 00 00 00 15`. The header maps the columns
/// back to memory order and the word is read little-endian. With no header
/// before the address line the word counts as unread.
pub fn vm_word(output: &str, addr: u32) -> Option<u32> {
    let want = format!("0x{addr:08x}");
    let mut order: Option<Vec<usize>> = None;
    let mut found = None;
    for raw in output.lines() {
        let line = tk_boot::strip_escapes(raw);
        let Some((head, rest)) = line.split_once('|') else {
            continue;
        };
        let head = head.trim();
        let words: Vec<&str> = rest.split_whitespace().collect();
        if head.is_empty() {
            if let Some(offsets) = header_order(&words) {
                order = Some(offsets);
            }
            continue;
        }
        if !head.eq_ignore_ascii_case(&want) {
            continue;
        }
        let Some(order) = order.as_ref() else {
            continue;
        };
        let mut bytes = [None; 4];
        for (column, word) in words.iter().enumerate() {
            let Some(&offset) = order.get(column) else {
                break;
            };
            if offset < 4 && word.len() == 2 {
                if let Ok(byte) = u8::from_str_radix(word, 16) {
                    bytes[offset] = Some(byte);
                }
            }
        }
        if let [Some(a), Some(b), Some(c), Some(d)] = bytes {
            found = Some(u32::from_le_bytes([a, b, c, d]));
        }
    }
    found
}

/// The byte offset each column of a `vm` dump shows, from its header line
/// (`| 03 02 01 00  07 06 05 04 ...` on the unit). `None` for any other line.
fn header_order(words: &[&str]) -> Option<Vec<usize>> {
    let offsets: Vec<usize> = words
        .iter()
        .map(|w| {
            (w.len() == 2)
                .then(|| u8::from_str_radix(w, 16).ok())
                .flatten()
                .map(usize::from)
        })
        .collect::<Option<_>>()?;
    let mut sorted = offsets.clone();
    sorted.sort_unstable();
    (sorted.len() >= 4 && sorted.iter().enumerate().all(|(i, v)| i == *v)).then_some(offsets)
}

/// The bytes at `addr..addr + len` in a `vm` dump of one or more 16-byte rows
/// (`vm 0x841b5900 160`), in memory order. Each row's columns map back
/// through the column header, as in `vm_word`. `None` when any byte is
/// missing or no header came before its row.
pub fn vm_memory(output: &str, addr: u32, len: u32) -> Option<Vec<u8>> {
    let mut bytes = vec![None; len as usize];
    let mut order: Option<Vec<usize>> = None;
    for raw in output.lines() {
        let line = tk_boot::strip_escapes(raw);
        let Some((head, rest)) = line.split_once('|') else {
            continue;
        };
        let head = head.trim();
        let words: Vec<&str> = rest.split_whitespace().collect();
        if head.is_empty() {
            if let Some(offsets) = header_order(&words) {
                order = Some(offsets);
            }
            continue;
        }
        let Some(row) = head
            .strip_prefix("0x")
            .or_else(|| head.strip_prefix("0X"))
            .and_then(|hex| u32::from_str_radix(hex, 16).ok())
        else {
            continue;
        };
        let Some(order) = order.as_ref() else {
            continue;
        };
        for (column, word) in words.iter().enumerate() {
            let Some(&offset) = order.get(column) else {
                break;
            };
            let Some(at) = (u64::from(row) + offset as u64).checked_sub(u64::from(addr)) else {
                continue;
            };
            if at < u64::from(len) && word.len() == 2 {
                if let Ok(byte) = u8::from_str_radix(word, 16) {
                    bytes[at as usize] = Some(byte);
                }
            }
        }
    }
    bytes.into_iter().collect()
}

pub fn read_cmd(addr: u32) -> String {
    format!("vm 0x{addr:08x} 4")
}

/// The console line that reads a layer's magic: `vm <addr> 4`, or
/// `vm <addr> 8` when its version word follows.
pub fn magic_read_cmd(spec: &MagicSpec) -> String {
    if spec.versions.is_empty() {
        read_cmd(spec.addr)
    } else {
        format!("vm 0x{:08x} 8", spec.addr)
    }
}

/// Read-only words of a patch layer, reported but never written. One `vm`
/// line reads them at the end of a verified session that holds a word of the
/// layer, into `/var/run/` + `status_file(group)`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StatusSpec {
    pub group: MagicGroup,
    /// Bytes read from the layer's magic on (`vm <magic addr> <len>`).
    pub len: u32,
    /// `(key, address)` of each reported word, in file order.
    pub fields: &'static [(&'static str, u32)],
}

/// The M1 selector and counters (`M1Block` in `device/modem-rust/src/pie.rs`),
/// read the way the bench read them: `vm 0x841b5900 160`.
pub const STATUS: [StatusSpec; 1] = [StatusSpec {
    group: MagicGroup::M1,
    len: 160,
    fields: &[
        ("selector", M1_SELECT_ADDR),
        ("seen", 0x841b_5960),
        ("pie_drops", 0x841b_5968),
        ("ce_marks", 0x841b_596c),
        ("hard_drops", 0x841b_5970),
        ("peak_qdelay_us", 0x841b_5980),
    ],
}];

/// One layer's status words, read at the end of a verified session.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LayerStatus {
    pub group: MagicGroup,
    /// The block's version word, for a layer that has one.
    pub version: Option<u32>,
    /// `(key, value)` for each of `StatusSpec::fields`, in order.
    pub fields: Vec<(&'static str, u32)>,
}

impl LayerStatus {
    /// The status file: `version=`, one decimal `key=value` line per field,
    /// then `updated=` on the keeper's clock.
    pub fn text(&self, now: u64) -> String {
        let version = self
            .version
            .map(|v| format!("version=0x{v:08x}\n"))
            .unwrap_or_default();
        let fields: String = self
            .fields
            .iter()
            .map(|(key, value)| format!("{key}={value}\n"))
            .collect();
        format!("{version}{fields}updated={now}\n")
    }
}

/// The status file of `group` in `/var/run` (`witcher-tk.m1`).
pub fn status_file(group: MagicGroup) -> String {
    format!("witcher-tk.{}", group.name().to_ascii_lowercase())
}

/// The console line that reads `spec`'s block.
pub fn status_read_cmd(spec: &StatusSpec) -> String {
    format!("vm 0x{:08x} {}", magic_spec(spec.group).addr, spec.len)
}

/// `spec`'s words in a `vm` dump of its block, when the dump shows the
/// layer's magic and, for a layer with a version word, an accepted version.
pub fn read_status(spec: &StatusSpec, output: &str) -> Option<LayerStatus> {
    let magic = magic_spec(spec.group);
    let block = vm_memory(output, magic.addr, spec.len)?;
    let word = |addr: u32| -> Option<u32> {
        let at = addr.checked_sub(magic.addr)? as usize;
        block
            .get(at..at + 4)
            .map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    };
    if word(magic.addr)? != u32::from_be_bytes(magic.bytes) {
        return None;
    }
    let version = if magic.versions.is_empty() {
        None
    } else {
        let version = word(magic.addr + 4)?;
        if !magic.versions.contains(&version) {
            return None;
        }
        Some(version)
    };
    let fields = spec
        .fields
        .iter()
        .map(|&(key, addr)| word(addr).map(|value| (key, value)))
        .collect::<Option<Vec<_>>>()?;
    Some(LayerStatus {
        group: spec.group,
        version,
        fields,
    })
}

/// The status blocks a session over `writes` reads: those of every layer
/// with a word in it.
fn status_specs(writes: &[Write]) -> Vec<&'static StatusSpec> {
    STATUS
        .iter()
        .filter(|spec| {
            writes
                .iter()
                .any(|w| find_word(w.addr).is_some_and(|word| word.magic == spec.group))
        })
        .collect()
}

/// `wm 0x84f93008 0x140`. Zero goes out as `0`, the form the bench used.
pub fn write_cmd(write: &Write) -> String {
    if write.value == 0 {
        return format!("wm 0x{:08x} 0", write.addr);
    }
    format!("wm 0x{:08x} 0x{:x}", write.addr, write.value)
}

/// A modem console (DM) session.
pub trait Console {
    /// Send one line. Return what the console printed after it, up to the
    /// moment the next line may go out. An empty string means no reply.
    fn command(&mut self, line: &str) -> String;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Session {
    /// Reset the console, check every required magic, write what differs, read back.
    Apply,
    /// Read only: every required magic and every word.
    Check,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Outcome {
    /// A magic read printed no dump: a console in logging mode, a modem
    /// that is not up, or no console at all.
    NoReply,
    /// A magic read printed other bytes: stock firmware, wrong image tier, or
    /// the patch has not run yet. Nothing was written.
    NoMagic(MagicGroup),
    /// A layer showed its magic but a build version this keeper does not
    /// accept (`got` is `None` when no version printed). Nothing was written.
    WrongVersion { group: MagicGroup, got: Option<u32> },
    /// Every word read back as wanted. `wrote` counts the `wm` lines sent.
    Verified { wrote: usize },
    /// Check only: a word read back other than wanted, or not at all.
    Differs {
        addr: u32,
        wanted: u32,
        got: Option<u32>,
    },
    /// A write's read-back was missing or wrong, or a disallowed write was passed.
    Unverified {
        addr: u32,
        wanted: u32,
        got: Option<u32>,
    },
    /// Another console session was open; nothing was sent.
    Busy,
}

/// What one DM session did.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Report {
    pub outcome: Outcome,
    /// A `wm` line went out.
    pub sent: bool,
    /// The status blocks read at its end (`STATUS`).
    pub status: Vec<LayerStatus>,
}

/// Run one planned DM session. Returns the outcome and whether any `wm` line went out.
pub fn run_plan(console: &mut dyn Console, plan: &Plan) -> (Outcome, bool) {
    let report = run_plan_report(console, plan);
    (report.outcome, report.sent)
}

/// Run one planned DM session and keep the status blocks it read.
pub fn run_plan_report(console: &mut dyn Console, plan: &Plan) -> Report {
    run_session_inner(console, &plan.writes, &plan.magics, plan.session, plan.hold_ack)
}

/// Run one session without `hold_ack=prb-tax`.
pub fn run_session(
    console: &mut dyn Console,
    writes: &[Write],
    session: Session,
) -> (Outcome, bool) {
    run_session_with_ack(console, writes, session, false)
}

/// Run one session. Returns the outcome and whether any `wm` line went out.
pub fn run_session_with_ack(
    console: &mut dyn Console,
    writes: &[Write],
    session: Session,
    hold_ack: bool,
) -> (Outcome, bool) {
    let report = run_session_inner(console, writes, &[], session, hold_ack);
    (report.outcome, report.sent)
}

fn run_session_inner(
    console: &mut dyn Console,
    writes: &[Write],
    extra_magics: &[MagicSpec],
    session: Session,
    hold_ack: bool,
) -> Report {
    let mut sent = false;
    let mut status = Vec::new();
    console.command("arm1log 2");
    if session == Session::Apply {
        // Leave logging mode (`quit 1`) and drop leftover debug categories,
        // or the console silently ignores what follows.
        console.command("quit 0");
        console.command("dbg revert");
    }
    let outcome = session_body(
        console,
        writes,
        extra_magics,
        session,
        hold_ack,
        &mut sent,
        &mut status,
    );
    console.command("arm1log 1");
    Report {
        outcome,
        sent,
        status,
    }
}

fn magic_matches(spec: MagicSpec, output: &str) -> bool {
    if spec.group == MagicGroup::N4 {
        return tk_boot::flag_writes_allowed(output);
    }
    tk_boot::vm_bytes(output, spec.addr)
        .is_some_and(|bytes| bytes.len() >= 4 && bytes[..4] == spec.bytes)
}

/// Why a layer's magic read allows no write, or `None` when it shows the
/// magic and, for a layer with a version word, an accepted version.
fn magic_refusal(spec: MagicSpec, reply: &str) -> Option<Outcome> {
    let Some(shown) = tk_boot::vm_bytes(reply, spec.addr) else {
        return Some(Outcome::NoReply);
    };
    if !magic_matches(spec, reply) {
        return Some(Outcome::NoMagic(spec.group));
    }
    if spec.versions.is_empty() {
        return None;
    }
    // The console shows each word most significant byte first, as the magic
    // just matched in `bytes` order.
    let got = shown
        .get(4..8)
        .map(|b| u32::from_be_bytes([b[0], b[1], b[2], b[3]]));
    if got.is_some_and(|version| spec.versions.contains(&version)) {
        return None;
    }
    Some(Outcome::WrongVersion {
        group: spec.group,
        got,
    })
}

fn session_body(
    console: &mut dyn Console,
    writes: &[Write],
    extra_magics: &[MagicSpec],
    session: Session,
    hold_ack: bool,
    sent: &mut bool,
    status: &mut Vec<LayerStatus>,
) -> Outcome {
    // Reject any disallowed address or out-of-range value before sending any
    // write, even if a caller bypassed `parse_writes`.
    for write in writes {
        let ok = session_value_ok(write.addr, write.value, hold_ack)
            || rule_admits(write.addr, write.value);
        if !ok {
            return Outcome::Unverified {
                addr: write.addr,
                wanted: write.value,
                got: None,
            };
        }
    }
    // Reject in-batch cross-word contradictions before touching the console.
    for rule in &REQUIRES {
        let Some(dep) = writes.iter().find(|w| rule.applies(**w)) else {
            continue;
        };
        if writes
            .iter()
            .any(|w| w.addr == rule.needs && !rule.met_by(w.value))
        {
            return Outcome::Unverified {
                addr: dep.addr,
                wanted: dep.value,
                got: None,
            };
        }
    }
    let magics = merge_magics(&required_magics(writes), extra_magics);
    let magics = if magics.is_empty() {
        vec![magic_spec(MagicGroup::N4)]
    } else {
        magics
    };
    for spec in magics {
        let reply = console.command(&magic_read_cmd(&spec));
        if let Some(refusal) = magic_refusal(spec, &reply) {
            return refusal;
        }
    }
    if session == Session::Apply {
        for (dep, rule) in prereq_reads_needed(writes) {
            let got = vm_word(&console.command(&read_cmd(rule.needs)), rule.needs);
            if !got.is_some_and(|v| rule.met_by(v)) {
                return Outcome::Unverified {
                    addr: dep.addr,
                    wanted: dep.value,
                    got: None,
                };
            }
        }
    }
    let mut need: Vec<(Write, Option<u32>)> = Vec::new();
    for write in writes {
        let got = vm_word(&console.command(&read_cmd(write.addr)), write.addr);
        if got != Some(write.value) {
            if session == Session::Check {
                return Outcome::Differs {
                    addr: write.addr,
                    wanted: write.value,
                    got,
                };
            }
            need.push((*write, got));
        }
    }
    if !need.is_empty() {
        let ordered = write_order_with_current(&need);
        for write in &ordered {
            console.command(&write_cmd(write));
            *sent = true;
        }
        for write in &ordered {
            let got = vm_word(&console.command(&read_cmd(write.addr)), write.addr);
            if got != Some(write.value) {
                return Outcome::Unverified {
                    addr: write.addr,
                    wanted: write.value,
                    got,
                };
            }
        }
    }
    // Every word reads as wanted: report the layers' counters while the
    // console is open (one line per layer).
    for spec in status_specs(writes) {
        let reply = console.command(&status_read_cmd(spec));
        status.extend(read_status(spec, &reply));
    }
    Outcome::Verified { wrote: need.len() }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum State {
    /// A write session is due.
    Pending,
    /// A required patch magic has not shown yet.
    WaitingMagic,
    /// Every word read back as wanted. Read-only checks follow.
    Applied,
    /// After failed sessions: writing documented off values to every managed
    /// word, the safe place to wait.
    Zeroing,
    /// After failed sessions: the managed words are at their off values (or
    /// were never written). A write session follows after the backoff.
    Retrying,
    /// Bench/maintenance hold: keeper does not open console sessions.
    HandsOff,
}

impl State {
    pub fn name(self) -> &'static str {
        match self {
            State::Pending => "pending",
            State::WaitingMagic => "waiting-magic",
            State::Applied => "applied",
            State::Zeroing => "zeroing",
            State::Retrying => "retrying",
            State::HandsOff => "hands-off",
        }
    }
}

/// The next session the keeper should run.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Plan {
    pub session: Session,
    pub writes: Vec<Write>,
    /// Patch magics verified in this session before any write (batch 0 checks
    /// every magic for the entire wanted set so a missing layer magic never
    /// leaves an earlier batch half-applied).
    pub magics: Vec<MagicSpec>,
    pub hold_ack: bool,
    pub batch: usize,
    pub total_batches: usize,
}

/// The flag writes for one confirmed boot. `now` is the keeper's monotonic
/// clock in seconds.
#[derive(Clone, Debug)]
pub struct Control {
    wanted: Vec<Write>,
    prev_wanted: Vec<Write>,
    hold_ack: bool,
    state: State,
    hands_off_reason: Option<String>,
    attempts: u32,
    check_misses: u32,
    batch_index: usize,
    batch_wrote: usize,
    next_at: u64,
    /// The next wait for a layer that has not shown, or a silent console.
    magic_wait: u64,
    /// The next wait after a failed round or rollback (`BACKOFF_FIRST` up).
    backoff: u64,
    /// The last session got no console reply (logged once per stretch).
    silent: bool,
    /// A `wm` line went out since the last modem restart.
    ever_wrote: bool,
    detail: String,
}

/// `0x84f93008=0x140 0x847ed604=0x15`, or `none`.
pub fn list(writes: &[Write]) -> String {
    if writes.is_empty() {
        return "none".into();
    }
    writes
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(" ")
}

fn got_text(got: Option<u32>) -> String {
    got.map_or_else(|| "nothing".to_owned(), |v| format!("0x{v:x}"))
}

impl Control {
    pub fn new(wanted: Vec<Write>, now: u64) -> Self {
        Self::new_with_ack(wanted, false, now)
    }

    pub fn new_with_ack(wanted: Vec<Write>, hold_ack: bool, now: u64) -> Self {
        Self {
            wanted,
            prev_wanted: Vec::new(),
            hold_ack,
            state: State::Pending,
            hands_off_reason: None,
            attempts: 0,
            check_misses: 0,
            batch_index: 0,
            batch_wrote: 0,
            next_at: now,
            magic_wait: MAGIC_FIRST,
            backoff: BACKOFF_FIRST,
            silent: false,
            ever_wrote: false,
            detail: "waiting for the first write session".into(),
        }
    }

    pub fn state(&self) -> State {
        self.state
    }

    pub fn wanted(&self) -> &[Write] {
        &self.wanted
    }

    pub fn detail(&self) -> &str {
        &self.detail
    }

    /// Enter or leave the bench/maintenance hands-off hold.
    /// Returns `(changed, optional_log_line)`.
    pub fn set_hands_off(&mut self, reason: Option<&str>, now: u64) -> (bool, Option<String>) {
        match reason {
            Some(why) => {
                if self.state == State::HandsOff {
                    if self.hands_off_reason.as_deref() != Some(why) {
                        self.hands_off_reason = Some(why.to_owned());
                        self.detail =
                            format!("bench/maintenance hold ({why}); not touching modem words");
                        return (true, None);
                    }
                    return (false, None);
                }
                self.state = State::HandsOff;
                self.hands_off_reason = Some(why.to_owned());
                self.batch_index = 0;
                self.batch_wrote = 0;
                self.detail = format!("bench/maintenance hold ({why}); not touching modem words");
                (
                    true,
                    Some(format!(
                        "tk flags: hands-off ({why}); not touching modem words"
                    )),
                )
            }
            None => {
                if self.state != State::HandsOff {
                    return (false, None);
                }
                self.hands_off_reason = None;
                self.start_over(now);
                self.detail = "hands-off cleared; reading modem words".into();
                (
                    true,
                    Some(
                        "tk flags: hands-off cleared; resuming management with a fresh read".into(),
                    ),
                )
            }
        }
    }

    /// The session to run now, if one is due. One is always due again later:
    /// only hands-off, or no words to manage, stops them.
    pub fn due(&self, now: u64) -> Option<Plan> {
        if self.state == State::HandsOff || now < self.next_at || self.wanted.is_empty() {
            return None;
        }
        let (session, target, prev): (Session, Vec<Write>, &[Write]) = match self.state {
            State::Pending | State::WaitingMagic | State::Retrying => (
                Session::Apply,
                self.wanted.clone(),
                self.prev_wanted.as_slice(),
            ),
            State::Applied => (Session::Check, self.wanted.clone(), &[]),
            State::Zeroing => (Session::Apply, rollback_values(&self.wanted), &[]),
            State::HandsOff => return None,
        };
        let batches = split_sessions_from(&target, prev, session);
        if batches.is_empty() {
            return None;
        }
        let idx = self.batch_index.min(batches.len() - 1);
        let magics = if idx == 0 {
            required_magics(&target)
        } else {
            required_magics(&batches[idx])
        };
        Some(Plan {
            session,
            writes: batches[idx].clone(),
            magics,
            hold_ack: self.hold_ack,
            batch: idx,
            total_batches: batches.len(),
        })
    }

    /// The operator changed `tk/config`. A real change starts a write session
    /// now and clears the failure count (unless hands-off is active).
    pub fn set_wanted(&mut self, wanted: Vec<Write>, now: u64) -> Option<String> {
        self.set_wanted_with_ack(wanted, self.hold_ack, now)
    }

    pub fn set_wanted_with_ack(
        &mut self,
        wanted: Vec<Write>,
        hold_ack: bool,
        now: u64,
    ) -> Option<String> {
        self.hold_ack = hold_ack;
        if wanted == self.wanted {
            return None;
        }
        let was = list(&self.wanted);
        let next = list(&wanted);
        self.prev_wanted = self.wanted.clone();
        self.wanted = wanted;
        self.batch_index = 0;
        self.batch_wrote = 0;
        if self.state == State::HandsOff {
            return Some(format!(
                "tk flags: tk/config changed while hands-off: queued {next} (was {was})"
            ));
        }
        let line = format!("tk flags: tk/config changed: writing {next} (was {was})");
        self.start_over(now);
        self.detail = "tk/config changed; a write session is due".into();
        Some(line)
    }

    /// The keeper saw a modem firmware load after it started. Modem RAM is
    /// fresh, and the modem may now run stock firmware (a crash reloads NAND).
    pub fn modem_restarted(&mut self, now: u64) -> String {
        self.ever_wrote = false;
        self.prev_wanted.clear();
        self.batch_index = 0;
        self.batch_wrote = 0;
        if self.state == State::HandsOff {
            return "tk flags: modem restart seen while hands-off; staying hands-off".into();
        }
        self.start_over(now.saturating_add(AFTER_RESTART));
        self.detail = "modem restart seen; writing again once the patch magic shows".into();
        "tk flags: modem restart seen; the flags are written again once the patch magic shows (a crash reload runs stock firmware, which never shows it)".into()
    }

    /// A session finished. Returns a log line when there is news. Every
    /// outcome leaves another session due later: failures back off, they
    /// never stop.
    pub fn finished(
        &mut self,
        now: u64,
        plan: &Plan,
        outcome: &Outcome,
        sent: bool,
    ) -> Option<String> {
        self.ever_wrote |= sent;
        let was = self.state;
        if was == State::HandsOff {
            return None;
        }
        if !matches!(outcome, Outcome::NoReply | Outcome::Busy) {
            self.silent = false;
        }
        if was == State::Zeroing {
            return self.rollback_finished(now, plan, outcome);
        }
        match outcome {
            Outcome::Busy => {
                self.next_at = now.saturating_add(RETRY_SECS);
                None
            }
            Outcome::Verified { wrote } => {
                self.attempts = 0;
                self.check_misses = 0;
                self.magic_wait = MAGIC_FIRST;
                self.batch_wrote += *wrote;
                if plan.batch + 1 < plan.total_batches {
                    self.batch_index = plan.batch + 1;
                    self.next_at = now;
                    if matches!(was, State::WaitingMagic | State::Retrying) {
                        self.state = State::Pending;
                    }
                    self.detail = format!(
                        "session {} of {} verified; continuing",
                        plan.batch + 1,
                        plan.total_batches
                    );
                    return None;
                }
                let total_wrote = self.batch_wrote;
                self.batch_index = 0;
                self.batch_wrote = 0;
                self.backoff = BACKOFF_FIRST;
                self.prev_wanted = self.wanted.clone();
                self.state = State::Applied;
                self.next_at = now.saturating_add(CHECK_EVERY);
                self.detail = format!("read back {}", list(&self.wanted));
                if was == State::Applied && total_wrote == 0 {
                    return None;
                }
                let how = if total_wrote == 0 {
                    "already set"
                } else {
                    "written"
                };
                Some(format!(
                    "tk flags: {how} and read back: {}",
                    list(&self.wanted)
                ))
            }
            Outcome::Differs { addr, wanted, got } => {
                self.state = State::Pending;
                self.attempts = 0;
                self.check_misses = 0;
                self.batch_index = 0;
                self.batch_wrote = 0;
                self.next_at = now;
                self.detail = format!(
                    "0x{addr:08x} read back {}, wanted 0x{wanted:x}; writing again",
                    got_text(*got)
                );
                Some(format!("tk flags: {}", self.detail))
            }
            Outcome::NoMagic(group) => {
                let spec = magic_spec(*group);
                let line = (was != State::WaitingMagic).then(|| {
                    if was == State::Applied {
                        format!(
                            "tk flags: the {} patch magic at 0x{:08x} is gone (the modem restarted onto stock firmware?); nothing written",
                            spec.name, spec.addr
                        )
                    } else if *group == MagicGroup::N4 {
                        format!(
                            "tk flags: waiting for the N4 patch magic at 0x{:08x} (it shows after the first uplink transport block); nothing written",
                            spec.addr
                        )
                    } else {
                        format!(
                            "tk flags: waiting for the {} patch magic at 0x{:08x}; nothing written",
                            spec.name, spec.addr
                        )
                    }
                });
                self.wait_for_layer(
                    now,
                    format!(
                        "waiting for the {} patch magic at 0x{:08x}; nothing written",
                        spec.name, spec.addr
                    ),
                );
                line
            }
            Outcome::WrongVersion { group, got } => {
                // A build the keeper does not know: never write, look again
                // as for a missing magic. Unlike a magic that has yet to
                // show, it is news each time the reason changes.
                let detail = wrong_version_text(*group, *got);
                let line = (was != State::WaitingMagic || self.detail != detail)
                    .then(|| format!("tk flags: {detail}"));
                self.wait_for_layer(now, detail);
                line
            }
            Outcome::NoReply if was == State::Applied => {
                self.check_misses += 1;
                self.next_at = now.saturating_add(RETRY_SECS);
                if self.check_misses >= CHECK_MISSES {
                    // A console stuck in logging mode answers nothing; a
                    // write session resets it first.
                    self.state = State::Pending;
                    self.attempts = 0;
                    self.check_misses = 0;
                    self.batch_index = 0;
                    self.batch_wrote = 0;
                    self.detail =
                        "no console reply to read-only checks; resetting the console".into();
                    return Some(format!("tk flags: {}", self.detail));
                }
                None
            }
            Outcome::NoReply => {
                // Nothing went out: another console client, lted restarting
                // or a modem that is not up. Not a failure: look again later.
                self.no_reply(now, "no console reply; nothing was written")
            }
            Outcome::Unverified { .. } => {
                self.attempts += 1;
                let why = describe(outcome);
                if self.attempts < MAX_ATTEMPTS {
                    self.state = State::Pending;
                    self.next_at = now.saturating_add(RETRY_SECS);
                    self.detail =
                        format!("session {} of {MAX_ATTEMPTS} failed: {why}", self.attempts);
                    return Some(format!(
                        "tk flags: {}; trying again in {RETRY_SECS} s",
                        self.detail
                    ));
                }
                self.batch_index = 0;
                self.batch_wrote = 0;
                if self.ever_wrote {
                    // A write may have landed: the off values first, at once.
                    self.state = State::Zeroing;
                    self.next_at = now.saturating_add(RETRY_SECS);
                    self.detail = if rollback_values(&self.wanted).iter().all(|w| w.value == 0) {
                        format!(
                            "{} failed sessions in a row ({why}); writing 0 to every managed word until the next try",
                            self.attempts
                        )
                    } else {
                        format!(
                            "{} failed sessions in a row ({why}); rolling every managed word back to its off value until the next try",
                            self.attempts
                        )
                    };
                } else {
                    let wait = self.back_off(now);
                    self.state = State::Retrying;
                    self.detail = format!(
                        "{} failed sessions in a row ({why}); nothing was written, so the words keep their boot values; trying again in {wait} s",
                        self.attempts
                    );
                }
                Some(format!("tk flags: {}", self.detail))
            }
        }
    }

    /// A rollback session (`State::Zeroing`) finished. A verified rollback
    /// waits out the backoff at the off values, then writes the wanted values
    /// again. One that did not read back is tried again later, backing off up
    /// to `MAGIC_MAX`, so it lands soon after the console works again.
    fn rollback_finished(&mut self, now: u64, plan: &Plan, outcome: &Outcome) -> Option<String> {
        match outcome {
            Outcome::Busy => {
                self.next_at = now.saturating_add(RETRY_SECS);
                None
            }
            Outcome::Verified { wrote } => {
                self.magic_wait = MAGIC_FIRST;
                self.batch_wrote += *wrote;
                if plan.batch + 1 < plan.total_batches {
                    self.batch_index = plan.batch + 1;
                    self.next_at = now;
                    self.detail = format!(
                        "rollback session {} of {} verified; continuing",
                        plan.batch + 1,
                        plan.total_batches
                    );
                    return None;
                }
                self.batch_index = 0;
                self.batch_wrote = 0;
                let off = rollback_values(&self.wanted);
                let read = if off.iter().all(|w| w.value == 0) {
                    "flags read back 0".to_owned()
                } else {
                    format!("managed words read back at off values ({})", list(&off))
                };
                // The RAM now holds the off values: order the next write from them.
                self.prev_wanted = off;
                let wait = self.back_off(now);
                self.state = State::Retrying;
                self.detail = format!(
                    "{} failed sessions in a row; {read}; writing the wanted values again in {wait} s",
                    self.attempts
                );
                Some(format!("tk flags: {}", self.detail))
            }
            Outcome::NoMagic(group) | Outcome::WrongVersion { group, .. } => {
                // Without the magic there is nothing of ours to roll back
                // (stock firmware after a modem reload?). Write again once the
                // layer shows: a fresh load starts at its off values.
                let detail = format!(
                    "the {} patch magic is gone, so the rollback wrote nothing; writing again once it shows",
                    group.name()
                );
                let line = format!("tk flags: {detail}");
                self.wait_for_layer(now, detail);
                Some(line)
            }
            Outcome::NoReply => self.no_reply(now, "no console reply to the rollback; nothing was written"),
            other => {
                self.attempts = self.attempts.saturating_add(1);
                let wait = self.later(now);
                self.batch_index = 0;
                self.batch_wrote = 0;
                self.detail = format!(
                    "the rollback did not read back ({}); trying it again in {wait} s",
                    describe(other)
                );
                Some(format!("tk flags: {}", self.detail))
            }
        }
    }

    /// A session got no console reply, so nothing went out: try the same
    /// session again later, backing off up to `MAGIC_MAX`. Logged once per
    /// silent stretch.
    fn no_reply(&mut self, now: u64, why: &str) -> Option<String> {
        let wait = self.later(now);
        self.detail = format!("{why}; trying again in {wait} s");
        let first = !self.silent;
        self.silent = true;
        first.then(|| format!("tk flags: {}", self.detail))
    }

    /// The next session in `magic_wait` seconds, which doubles up to
    /// `MAGIC_MAX`. Returns the wait.
    fn later(&mut self, now: u64) -> u64 {
        let wait = self.magic_wait;
        self.next_at = now.saturating_add(wait);
        self.magic_wait = wait.saturating_mul(2).min(MAGIC_MAX);
        wait
    }

    /// The wait before the next round after a failed one, which doubles each
    /// time up to `BACKOFF_MAX`. Returns it in seconds.
    fn back_off(&mut self, now: u64) -> u64 {
        let wait = self.backoff;
        self.next_at = now.saturating_add(wait);
        self.backoff = wait.saturating_mul(2).min(BACKOFF_MAX);
        wait
    }

    /// Start over from a fresh read: no failures counted, no waits owed.
    fn start_over(&mut self, next_at: u64) {
        self.state = State::Pending;
        self.attempts = 0;
        self.check_misses = 0;
        self.batch_index = 0;
        self.batch_wrote = 0;
        self.magic_wait = MAGIC_FIRST;
        self.backoff = BACKOFF_FIRST;
        self.silent = false;
        self.next_at = next_at;
    }

    /// Nothing was written because a layer did not show (its magic, or an
    /// accepted version): look again later, backing off up to `MAGIC_MAX`.
    fn wait_for_layer(&mut self, now: u64, detail: String) {
        self.batch_index = 0;
        self.batch_wrote = 0;
        self.state = State::WaitingMagic;
        self.later(now);
        self.detail = detail;
    }

    /// `/var/run/witcher-tk.flags`.
    pub fn status(&self, now: u64) -> String {
        format!(
            "state={}\ndetail={}\nwant={}\nattempts={}\nupdated={now}\n",
            self.state.name(),
            self.detail,
            list(&self.wanted),
            self.attempts
        )
    }
}

/// The status file when no `Control` runs.
pub fn idle_status(reason: &str, now: u64) -> String {
    format!("state=off\ndetail={reason}\nwant=none\nattempts=0\nupdated={now}\n")
}

fn wrong_version_text(group: MagicGroup, got: Option<u32>) -> String {
    let spec = magic_spec(group);
    let shown = got.map_or_else(
        || "no readable version".to_owned(),
        |v| format!("version 0x{v:08x}"),
    );
    let accepted = spec
        .versions
        .iter()
        .map(|v| format!("0x{v:08x}"))
        .collect::<Vec<_>>()
        .join(", ");
    format!(
        "the {} patch at 0x{:08x} shows {shown}; this keeper accepts {accepted}; nothing written",
        spec.name, spec.addr
    )
}

pub fn describe(outcome: &Outcome) -> String {
    match outcome {
        Outcome::NoReply => "no console reply to the magic read".into(),
        Outcome::NoMagic(group) => format!("no {} patch magic", group.name()),
        Outcome::WrongVersion { group, got } => wrong_version_text(*group, *got),
        Outcome::Verified { wrote } => format!("verified ({wrote} written)"),
        Outcome::Differs { addr, wanted, got } | Outcome::Unverified { addr, wanted, got } => {
            format!(
                "0x{addr:08x} read back {}, wanted 0x{wanted:x}",
                got_text(*got)
            )
        }
        Outcome::Busy => "another console session was open".into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::{HashMap, HashSet};

    const HEADER: &str = "           | 03 02 01 00  07 06 05 04  0B 0A 09 08  0F 0E 0D 0C";
    const RULE: &str = "----------------------------------------------------------------------------";

    /// A `vm` dump around `rows`, as the unit prints it.
    fn frame(addr: u32, len: usize, rows: &str) -> String {
        format!(
            "\n{RULE}\n HEX DUMP  | {len}(0x{len:x}) Bytes @ 0x{addr:08X}\n{RULE}\n{HEADER}\n{RULE}\n{rows}{RULE}\nDM> "
        )
    }

    fn dump(addr: u32, shown: &str) -> String {
        frame(
            addr,
            4,
            &format!("\u{1b}[1;32m0x{addr:08X}\u{1b}[0m | {shown}  .. .. .. ..  .. .. .. ..  .. .. .. .. \n"),
        )
    }

    /// A `vm` dump of `words` from `addr` on, four words to a row.
    fn dump_words(addr: u32, words: &[u32]) -> String {
        let rows: String = words
            .chunks(4)
            .zip((addr..).step_by(16))
            .map(|(row, at)| {
                let mut cells: Vec<String> = row.iter().map(|w| shown(*w)).collect();
                cells.resize(4, ".. .. .. ..".to_owned());
                format!("\u{1b}[1;32m0x{at:08X}\u{1b}[0m | {} \n", cells.join("  "))
            })
            .collect();
        frame(addr, words.len() * 4, &rows)
    }

    /// `vm 0x841b5900 160` on the bench Titan with the Rust PIE on, after a
    /// 4-stream CUBIC upload (2026-11-25, run `m1-s1-cubic4-a`).
    const M1_BENCH_DUMP: &str = concat!(
        "----------------------------------------------------------------------------\n",
        " HEX DUMP  | 160(0xa0) Bytes @ 0x841B5900\n",
        "----------------------------------------------------------------------------\n",
        "           | 03 02 01 00  07 06 05 04  0B 0A 09 08  0F 0E 0D 0C\n",
        "----------------------------------------------------------------------------\n",
        "0x841B5900 | 4d 31 50 49  20 26 11 25  00 00 00 01  00 00 00 0e \n",
        "0x841B5910 | 00 00 00 0f  00 00 00 37  00 00 01 00  00 00 0a 00 \n",
        "0x841B5920 | 00 00 01 f4  00 00 c3 50  00 19 99 9a  00 00 05 64 \n",
        "0x841B5930 | 00 00 00 03  00 05 1e b8  00 00 00 00  00 00 00 00 \n",
        "0x841B5940 | 00 00 00 00  00 fe 5c f7  00 00 22 d5  00 00 1e 15 \n",
        "0x841B5950 | 00 00 00 00  00 09 87 2f  00 00 05 63  ba b2 bc be \n",
        "0x841B5960 | 00 00 6d 79  00 00 6c 9d  00 00 00 82  00 00 00 00 \n",
        "0x841B5970 | 00 00 00 5a  00 00 00 00  00 00 00 81  00 00 04 ac \n",
        "0x841B5980 | 00 01 7d 4c  00 05 1e b8  00 00 00 00  00 00 00 01 \n",
        "0x841B5990 | 00 00 00 3f  00 00 00 d1  00 00 00 00  00 00 00 00 \n",
        "----------------------------------------------------------------------------\n",
        "DM> ",
    );

    /// Show a word the way the unit's console does: most significant first.
    fn shown(value: u32) -> String {
        let b = value.to_be_bytes();
        format!("{:02x} {:02x} {:02x} {:02x}", b[0], b[1], b[2], b[3])
    }

    /// A fake modem console with RAM, per-layer magics, and a logging-mode trap.
    struct Fake {
        ram: HashMap<u32, u32>,
        magics: HashSet<MagicGroup>,
        /// The version word a layer with one shows after its magic.
        version: u32,
        logging: bool,
        /// `wm` lines that change nothing (a write that does not stick).
        broken: bool,
        /// If set, writes to this address fail to stick.
        broken_addr: Option<u32>,
        /// Answers nothing, not even `quit 0`: another client holds the console.
        dead: bool,
        /// Every reply to a read but a magic's comes back cut short, as with
        /// another client on the console. Writes still land.
        cut_reads: bool,
        sent: Vec<String>,
    }

    impl Fake {
        fn new(n4_magic: bool) -> Self {
            let mut magics = HashSet::new();
            if n4_magic {
                magics.insert(MagicGroup::N4);
            }
            Self::with_magics(magics)
        }

        fn all_magics() -> Self {
            Self::with_magics(MAGICS.iter().map(|m| m.group).collect())
        }

        fn with_magics(magics: HashSet<MagicGroup>) -> Self {
            let mut ram = HashMap::new();
            // Boot defaults for non-zero words.
            ram.insert(N4_PDCP_MIN_ADDR, PDCP_MIN_DEFAULT);
            ram.insert(N4_PDCP_MAX_ADDR, PDCP_MAX_DEFAULT);
            ram.insert(N5_RATE_BPMS_ADDR, 40);
            ram.insert(N5_BURST_B_ADDR, 3072);
            ram.insert(N5_HOLD_MS_ADDR, 500);
            ram.insert(N5_BUDGET_PCT_ADDR, 10);
            ram.insert(N5_PDCP_MIN_ADDR, PDCP_MIN_DEFAULT);
            ram.insert(N5_PDCP_MAX_ADDR, PDCP_MAX_DEFAULT);
            Self {
                ram,
                magics,
                version: M1_VERSIONS[0],
                logging: false,
                broken: false,
                broken_addr: None,
                dead: false,
                cut_reads: false,
                sent: Vec::new(),
            }
        }

        fn set_n4_magic(&mut self, on: bool) {
            if on {
                self.magics.insert(MagicGroup::N4);
            } else {
                self.magics.remove(&MagicGroup::N4);
            }
        }

        /// The word the modem shows at `addr`: a layer's magic and version
        /// while the layer is present (0 otherwise), else RAM.
        fn word(&self, addr: u32) -> u32 {
            for spec in &MAGICS {
                let present = self.magics.contains(&spec.group);
                if addr == spec.addr {
                    return if present {
                        u32::from_be_bytes(spec.bytes)
                    } else {
                        0
                    };
                }
                if addr == spec.addr + 4 && !spec.versions.is_empty() && present {
                    return self.version;
                }
            }
            *self.ram.get(&addr).unwrap_or(&0)
        }
    }

    fn wm_lines(fake: &Fake) -> Vec<&str> {
        fake.sent
            .iter()
            .map(String::as_str)
            .filter(|l| l.starts_with("wm "))
            .collect()
    }

    impl Console for Fake {
        fn command(&mut self, line: &str) -> String {
            self.sent.push(line.to_owned());
            if self.dead {
                return String::new();
            }
            if line == "quit 0" {
                self.logging = false;
                return "\nDM> ".into();
            }
            if self.logging {
                return String::new();
            }
            let words: Vec<&str> = line.split_whitespace().collect();
            match words.as_slice() {
                ["vm", addr, len] => {
                    let addr = u32::from_str_radix(addr.trim_start_matches("0x"), 16).unwrap();
                    let len: u32 = len.parse().unwrap();
                    if self.cut_reads && !MAGICS.iter().any(|m| m.addr == addr) {
                        return String::new();
                    }
                    let memory: Vec<u32> = (0..len.div_ceil(4))
                        .map(|i| self.word(addr + 4 * i))
                        .collect();
                    dump_words(addr, &memory)
                }
                ["wm", addr, value] => {
                    let addr = u32::from_str_radix(addr.trim_start_matches("0x"), 16).unwrap();
                    let value = u32::from_str_radix(value.trim_start_matches("0x"), 16).unwrap();
                    if !self.broken && self.broken_addr != Some(addr) {
                        self.ram.insert(addr, value);
                    }
                    format!("\n0x{addr:08x}: 0x{value:08x}\n\nDM> ")
                }
                _ => "\nDM> ".into(),
            }
        }
    }

    fn n4() -> Vec<Write> {
        parse_writes("enabled=1\nwm=0x847ed604:0x15\nwm=0x84f93008:0x140\n").writes
    }

    fn n6_latency_profile() -> Vec<Write> {
        parse_writes(n6_latency_config()).writes
    }

    fn n6_latency_config() -> &'static str {
        "\
enabled=1
wm=0x84f93008:0x140
wm=0x847ed604:0x15
wm=0x847ed548:0x1
wm=0x847ed54c:0x1
wm=0x847ed550:0x1
wm=0x847ecf08:0x1
wm=0x84489a84:0x2000
wm=0x84489a88:0x3000
wm=0x84489a6c:0x3
wm=0x8418ff08:0x1
"
    }

    #[test]
    fn config_lines_are_allow_listed_and_bounded() {
        let parsed = parse_writes(
            "enabled=1\nsha256=ab\n wm=0x847ED604:0x15 # AQM v2 + hold\nwm = 0x84f93008:0x140\nwm=0x84f93008:320\nwm=0x847ed608:1\nwm=0x847ed604:0x2\nwm=0x84f93008:0x201\nwm=847ed604:0x5\nwm=0x847ed604\nwm=0x847ed604:0x\nwm=0x847ed604:0x100000000\n",
        );
        assert_eq!(
            parsed.writes,
            vec![
                Write {
                    addr: HOLD_ADDR,
                    value: 320
                },
                Write {
                    addr: FLAGS_ADDR,
                    value: 0x15
                },
            ]
        );
        assert_eq!(
            parsed.refused,
            vec![
                "wm=0x847ed608:1",
                "wm=0x847ed604:0x2",
                "wm=0x84f93008:0x201",
                "wm=847ed604:0x5",
                "wm=0x847ed604",
                "wm=0x847ed604:0x",
                "wm=0x847ed604:0x100000000",
            ]
        );
        assert_eq!(parsed.refused.len(), parsed.refused_reasons.len());
        // `wm = ...` is not a `wm=` line: it is ignored, not refused.
        assert!(!parsed.refused.iter().any(|l| l.starts_with("wm = ")));
        assert_eq!(parse_writes("").writes, vec![]);
        assert_eq!(
            parse_writes("wm=0x847ed604:0x15\nwm=0x847ed604:0").writes,
            vec![Write {
                addr: FLAGS_ADDR,
                value: 0
            }]
        );
    }

    #[test]
    fn table_boundaries_and_hold_ack() {
        // N4 flags: only 0x15 bits allowed; bit 3 (0x8) and bit 1 (0x2) refused.
        for flags in [0, 0x1, 0x4, 0x5, 0x10, 0x15] {
            assert!(value_ok(FLAGS_ADDR, flags), "{flags:#x}");
        }
        for flags in [0x2, 0x8, 0x9, 0x17, 0x18, 0x1d, 0x1f, 0x20, u32::MAX] {
            assert!(!value_ok(FLAGS_ADDR, flags), "{flags:#x}");
        }
        // Hold margin: 0..=0x200 without hold_ack, 0..=0x800 with hold_ack=prb-tax.
        assert!(value_ok(HOLD_ADDR, 0) && value_ok(HOLD_ADDR, HOLD_MAX));
        assert!(!value_ok(HOLD_ADDR, HOLD_MAX + 1));
        assert!(!value_ok(HOLD_ADDR, 0x400));
        assert!(!value_ok(HOLD_ADDR, HOLD_ACK_MAX));
        assert!(value_ok_with_ack(HOLD_ADDR, 0x400, true));
        assert!(value_ok_with_ack(HOLD_ADDR, HOLD_ACK_MAX, true));
        assert!(!value_ok_with_ack(HOLD_ADDR, HOLD_ACK_MAX + 1, true));

        let without_ack = parse_writes("enabled=1\nwm=0x84f93008:0x400\nwm=0x847ed604:0x15\n");
        assert!(!without_ack.hold_ack);
        assert_eq!(without_ack.refused, vec!["wm=0x84f93008:0x400"]);
        let with_ack =
            parse_writes("enabled=1\nhold_ack=prb-tax\nwm=0x84f93008:0x800\nwm=0x847ed604:0x15\n");
        assert!(with_ack.hold_ack);
        assert!(with_ack.refused.is_empty());
        assert_eq!(
            with_ack.writes[0],
            Write {
                addr: HOLD_ADDR,
                value: 0x800
            }
        );
        let bad_ack = parse_writes("hold_ack=yes\nwm=0x84f93008:0x400\n");
        assert!(!bad_ack.hold_ack);
        assert_eq!(bad_ack.refused, vec!["hold_ack=yes", "wm=0x84f93008:0x400"]);

        // N4 PDCP limits: 4096..=24576.
        assert!(value_ok(N4_PDCP_MIN_ADDR, 4096) && value_ok(N4_PDCP_MIN_ADDR, 24576));
        assert!(!value_ok(N4_PDCP_MIN_ADDR, 4095) && !value_ok(N4_PDCP_MIN_ADDR, 24577));
        assert!(value_ok(N4_PDCP_MAX_ADDR, 4096) && value_ok(N4_PDCP_MAX_ADDR, 24576));
        assert!(!value_ok(N4_PDCP_MAX_ADDR, 0) && !value_ok(N4_PDCP_MAX_ADDR, 24577));

        // IMG4 switches: G1A, G1B, G1C, TK1 are 0 or 1; LNK is 0 or 2 only (1 refused).
        for addr in [G1A_ADDR, G1B_ADDR, G1C_ADDR, TK1_ADDR] {
            assert!(value_ok(addr, 0) && value_ok(addr, 1));
            assert!(!value_ok(addr, 2));
        }
        assert!(value_ok(LNK_ADDR, 0) && value_ok(LNK_ADDR, 2));
        assert!(!value_ok(LNK_ADDR, 1) && !value_ok(LNK_ADDR, 3));

        // N5 switches.
        for v in 0..=3 {
            assert!(value_ok(N5_FLAGS_ADDR, v));
        }
        for v in [4, 5, 6, 7, 0xff] {
            assert!(!value_ok(N5_FLAGS_ADDR, v));
        }
        assert!(value_ok(N5_PDCP_MIN_ADDR, 4096) && value_ok(N5_PDCP_MIN_ADDR, 24576));
        assert!(!value_ok(N5_PDCP_MIN_ADDR, 4095) && !value_ok(N5_PDCP_MIN_ADDR, 24577));
        assert!(value_ok(N5_PDCP_MAX_ADDR, 4096) && value_ok(N5_PDCP_MAX_ADDR, 24576));
        assert!(!value_ok(N5_PDCP_MAX_ADDR, 0) && !value_ok(N5_PDCP_MAX_ADDR, 24577));
        assert!(value_ok(N5_PDCP_K_Q4_ADDR, 0) && value_ok(N5_PDCP_K_Q4_ADDR, 64));
        assert!(!value_ok(N5_PDCP_K_Q4_ADDR, 65));
        assert!(value_ok(N5_RATE_BPMS_ADDR, 8) && value_ok(N5_RATE_BPMS_ADDR, 200));
        assert!(!value_ok(N5_RATE_BPMS_ADDR, 7) && !value_ok(N5_RATE_BPMS_ADDR, 201));
        assert!(value_ok(N5_BURST_B_ADDR, 512) && value_ok(N5_BURST_B_ADDR, 16384));
        assert!(!value_ok(N5_BURST_B_ADDR, 511) && !value_ok(N5_BURST_B_ADDR, 16385));
        assert!(value_ok(N5_HOLD_MS_ADDR, 100) && value_ok(N5_HOLD_MS_ADDR, 5000));
        assert!(!value_ok(N5_HOLD_MS_ADDR, 99) && !value_ok(N5_HOLD_MS_ADDR, 5001));
        assert!(value_ok(N5_BUDGET_PCT_ADDR, 1) && value_ok(N5_BUDGET_PCT_ADDR, 50));
        assert!(!value_ok(N5_BUDGET_PCT_ADDR, 0) && !value_ok(N5_BUDGET_PCT_ADDR, 51));

        // N6 switch: U2_FLAGS is 0 or 1 only.
        assert!(value_ok(U2_FLAGS_ADDR, 0) && value_ok(U2_FLAGS_ADDR, 1));
        assert!(!value_ok(U2_FLAGS_ADDR, 2) && !value_ok(U2_FLAGS_ADDR, 3));

        // Magic words themselves are never writable.
        for m in &MAGICS {
            assert!(!value_ok(m.addr, 0));
        }
    }

    #[test]
    fn cross_word_rules_are_enforced() {
        // N4 PDCP min > max refused.
        let bad = parse_writes("wm=0x847ed608:0x5000\nwm=0x847ed60c:0x4000\n");
        assert!(bad.writes.is_empty());
        assert_eq!(bad.refused.len(), 2);
        // Only N4 PDCP max < default min (0x4000) refused.
        let bad_max_only = parse_writes("wm=0x847ed60c:0x3000\n");
        assert!(bad_max_only.writes.is_empty());
        assert_eq!(bad_max_only.refused, vec!["wm=0x847ed60c:0x3000"]);
        // Valid N4 PDCP pair accepted.
        let ok = parse_writes("wm=0x847ed608:0x2000\nwm=0x847ed60c:0x3000\n");
        assert_eq!(ok.writes.len(), 2);
        assert!(ok.refused.is_empty());

        // N5 PDCP min > max refused.
        let bad_n5 = parse_writes("wm=0x84489a84:0x4000\nwm=0x84489a88:0x3000\n");
        assert!(bad_n5.writes.is_empty());
        assert_eq!(bad_n5.refused.len(), 2);
        // Only N5 PDCP max < default min (0x4000) refused.
        let bad_n5_max = parse_writes("wm=0x84489a88:0x3000\n");
        assert!(bad_n5_max.writes.is_empty());
        assert_eq!(bad_n5_max.refused, vec!["wm=0x84489a88:0x3000"]);

        // N5_FLAGS bit 1 requires N4_FLAGS bit 0.
        let missing_n4 = parse_writes("wm=0x84489a6c:0x3\n");
        assert!(missing_n4.writes.is_empty());
        assert_eq!(missing_n4.refused, vec!["wm=0x84489a6c:0x3"]);
        // N4_FLAGS=0x10 (bit 4 only, no bit 0) is NOT enough for N5_FLAGS bit 1.
        let no_bit0 = parse_writes("wm=0x847ed604:0x10\nwm=0x84489a6c:0x2\n");
        assert_eq!(
            no_bit0.writes,
            vec![Write {
                addr: FLAGS_ADDR,
                value: 0x10
            }]
        );
        assert_eq!(no_bit0.refused, vec!["wm=0x84489a6c:0x2"]);
        // N5_FLAGS=0x1 (bit 0 only) does NOT require N4_FLAGS bit 0.
        let n5_bit0 = parse_writes("wm=0x84489a6c:0x1\n");
        assert_eq!(
            n5_bit0.writes,
            vec![Write {
                addr: N5_FLAGS_ADDR,
                value: 0x1
            }]
        );
        // N4_FLAGS bit 0 + N5_FLAGS bit 1 accepted.
        let good = parse_writes("wm=0x847ed604:0x15\nwm=0x84489a6c:0x3\n");
        assert_eq!(good.writes.len(), 2);
        assert!(good.refused.is_empty());

        // LNK=1 is refused without U2_FLAGS bit 0 in the same config.
        let lnk1_alone = parse_writes("wm=0x847ed554:0x1\n");
        assert!(lnk1_alone.writes.is_empty());
        assert_eq!(lnk1_alone.refused, vec!["wm=0x847ed554:0x1"]);
        let lnk1_u2_off = parse_writes("wm=0x8418ff08:0\nwm=0x847ed554:0x1\n");
        assert_eq!(
            lnk1_u2_off.writes,
            vec![Write {
                addr: U2_FLAGS_ADDR,
                value: 0
            }]
        );
        assert_eq!(lnk1_u2_off.refused, vec!["wm=0x847ed554:0x1"]);

        // LNK=1 WITH U2_FLAGS=1 is accepted by parse_writes, with U2_FLAGS ordered before LNK.
        let lnk1_with_u2 = parse_writes("wm=0x847ed554:0x1\nwm=0x8418ff08:0x1\n");
        assert!(lnk1_with_u2.refused.is_empty());
        assert_eq!(
            lnk1_with_u2.writes,
            vec![
                Write {
                    addr: U2_FLAGS_ADDR,
                    value: 0x1
                },
                Write {
                    addr: LNK_ADDR,
                    value: 0x1
                },
            ]
        );
        // Without N6 magic, LNK=1 + U2_FLAGS=1 writes nothing (NoMagic(N6)).
        let mut img4_only = Fake::with_magics([MagicGroup::Img4].into_iter().collect());
        let (outcome, sent) = run_session(&mut img4_only, &lnk1_with_u2.writes, Session::Apply);
        assert_eq!(outcome, Outcome::NoMagic(MagicGroup::N6));
        assert!(!sent);
        // With IMG4 + N6 magics, U2_FLAGS=1 is written BEFORE LNK=1, and rollback writes LNK=0 BEFORE U2_FLAGS=0.
        let mut n6_fake = Fake::all_magics();
        let (outcome, sent) = run_session(&mut n6_fake, &lnk1_with_u2.writes, Session::Apply);
        assert_eq!(outcome, Outcome::Verified { wrote: 2 });
        assert!(sent);
        let wm_on: Vec<&str> = n6_fake
            .sent
            .iter()
            .map(String::as_str)
            .filter(|l| l.starts_with("wm "))
            .collect();
        assert_eq!(wm_on, vec!["wm 0x8418ff08 0x1", "wm 0x847ed554 0x1"]);
        n6_fake.sent.clear();
        let (outcome, sent) = run_session(
            &mut n6_fake,
            &rollback_values(&lnk1_with_u2.writes),
            Session::Apply,
        );
        assert_eq!(outcome, Outcome::Verified { wrote: 2 });
        assert!(sent);
        let wm_off: Vec<&str> = n6_fake
            .sent
            .iter()
            .map(String::as_str)
            .filter(|l| l.starts_with("wm "))
            .collect();
        assert_eq!(wm_off, vec!["wm 0x847ed554 0", "wm 0x8418ff08 0"]);
        // Direct run_session with only LNK=1 while U2_FLAGS=0 in RAM is refused.
        let mut n6_u2_zero = Fake::all_magics();
        let (outcome, sent) = run_session(
            &mut n6_u2_zero,
            &[Write {
                addr: LNK_ADDR,
                value: 1,
            }],
            Session::Apply,
        );
        assert!(matches!(outcome, Outcome::Unverified { addr: LNK_ADDR, .. }));
        assert!(!sent);

        // LNK=2 (observe) is allowed without N6 or U2_FLAGS.
        let lnk2 = parse_writes("wm=0x847ed554:0x2\n");
        assert_eq!(
            lnk2.writes,
            vec![Write {
                addr: LNK_ADDR,
                value: 2
            }]
        );
        // N4 bit 3 (0x8) refused everywhere.
        let sparse_stock = parse_writes("wm=0x847ed604:0x8\nwm=0x847ed604:0x1d\n");
        assert!(sparse_stock.writes.is_empty());
        assert_eq!(sparse_stock.refused.len(), 2);
    }

    #[test]
    fn forbidden_addresses_are_never_on_the_list() {
        let forbidden: &[(&str, u32, u32)] = &[
            // IMG4 excluded set [TRCP, W5, UHQ, U3T, R17]
            ("TRC", 0x847e_cf1c, 0x22),
            ("TSP", 0x847e_cf20, 0x16),
            ("TPR", 0x847e_cf24, 0x4d),
            ("W5 flags", 0x847e_ce88, 0x2f),
            ("W5 unsol_pct", 0x847e_ce8c, 85),
            ("W5 abs_floor", 0x847e_ce90, 1),
            ("W5 retx_win_ms", 0x847e_ce94, 80),
            ("UHQ", 0x847e_cff0, 0x1),
            ("U3T", 0x847e_cff4, 0x1),
            ("R17", 0x847e_cff8, 0x1),
            ("R17 idle", 0x847e_cffc, 0x7d0),
            // X4 / HRB
            ("X4/HRB", 0x847e_cf14, 0x1),
            // DSR and U14 words (and other excluded IMG2/IMG3/IMG4 words)
            ("DSR", 0x847e_cf18, 0x14),
            ("U14_CTRL", 0x847e_cf28, 0x0f),
            ("U14_SRMAX_CAP", 0x847e_cf2c, 16),
            ("O3R", 0x847e_cf0c, 0x1),
            ("R4 CQI", 0x847e_ce6c, 0x1),
            ("G3A", 0x847e_d558, 0x1),
            ("G3B", 0x847e_d55c, 0x1),
            ("E1", 0x847e_d560, 0x28),
            ("E2", 0x847e_d564, 0x1),
            ("X3", 0x84a0_71ac, 0x0),
            ("X7", 0x847e_d7a4, 0x3),
            // PHR
            ("PHR", 0x847e_cf10, 0x060c),
            // RF / power / MPR / calibration / console mask / radio .data
            ("f_1(i) power", 0x84d4_7d48, 0x0),
            ("rf tx pmax/mpr", 0x84a0_6000, 0x17),
            ("rf cal table", 0x8418_f768, 0x0),
            ("vctcxo_pcc_only", 0x84a0_620c, 0x0101_0200),
            ("reest_ex", 0x84a1_0dc4, 0x0000_0001),
            ("console mask", 0x849f_74c4, 0x17),
            ("N4 lead cap", 0x847e_d610, 0x100),
            ("N4 sparse len", 0x847e_d61c, 0x200),
            ("N5 budget fixed", 0x8448_9a80, 0x4000),
            ("N5 r0 max pkts", 0x8448_9a90, 64),
            // Arbitrary addresses not in table
            ("zero addr", 0x0000_0000, 0),
            ("arbitrary ram", 0x8400_0000, 1),
            ("high addr", 0xffff_fffc, 0),
        ];
        for &(label, addr, val) in forbidden {
            assert!(find_word(addr).is_none(), "{label} (0x{addr:08x}) in TABLE");
            assert!(!value_ok(addr, val), "{label} value_ok");
            assert!(!session_value_ok(addr, val, true), "{label} session_value_ok");
            let line = format!("wm=0x{addr:08x}:0x{val:x}");
            let parsed = parse_writes(&format!("enabled=1\nhold_ack=prb-tax\n{line}\n"));
            assert!(parsed.writes.is_empty(), "{label} accepted by parse_writes");
            assert_eq!(parsed.refused, vec![line], "{label} not logged as refused");
            let mut fake = Fake::all_magics();
            let (outcome, sent) = run_session_with_ack(
                &mut fake,
                &[Write { addr, value: val }],
                Session::Apply,
                true,
            );
            assert!(
                matches!(outcome, Outcome::Unverified { .. }),
                "{label} not refused by run_session"
            );
            assert!(!sent, "{label} sent a wm line");
        }
    }

    #[test]
    fn turning_off_or_dropping_lines_writes_documented_off_values() {
        let on = n4();
        assert_eq!(
            wanted("enabled=1\nwm=0x847ed604:0x15\nwm=0x84f93008:0x140\n", &[]),
            on
        );
        assert_eq!(
            wanted("enabled=0\nwm=0x847ed604:0x15\nwm=0x84f93008:0x140\n", &on),
            zeros(&on)
        );
        assert_eq!(wanted("enabled=1\n", &on), zeros(&on));
        assert_eq!(wanted("", &on), zeros(&on));
        assert_eq!(wanted("", &[]), vec![]);
        assert_eq!(
            wanted("enabled=1\nwm=0x847ed604:0x5\n", &on),
            vec![
                Write {
                    addr: HOLD_ADDR,
                    value: 0
                },
                Write {
                    addr: FLAGS_ADDR,
                    value: 0x5
                },
            ]
        );
        assert!(enabled("enabled=1 # on\n"));
        assert!(!enabled("enabled=1\nenabled=0\n"));
        assert!(!enabled("enabled=yes\n"));

        // N4 PDCP words roll back to 0x4000 / 0x6000; N5 tunables roll back to 0.
        let mixed = parse_writes(
            "enabled=1\nwm=0x847ed608:0x2000\nwm=0x847ed60c:0x3000\nwm=0x84489a84:0x2000\nwm=0x84489a88:0x3000\nwm=0x84489a70:50\nwm=0x847ed604:0x15\nwm=0x84489a6c:0x3\n",
        )
        .writes;
        let off = wanted("enabled=0\n", &mixed);
        assert_eq!(
            off,
            vec![
                Write {
                    addr: N4_PDCP_MIN_ADDR,
                    value: 0x4000
                },
                Write {
                    addr: N4_PDCP_MAX_ADDR,
                    value: 0x6000
                },
                Write {
                    addr: N5_RATE_BPMS_ADDR,
                    value: 0
                },
                Write {
                    addr: N5_PDCP_MIN_ADDR,
                    value: 0
                },
                Write {
                    addr: N5_PDCP_MAX_ADDR,
                    value: 0
                },
                Write {
                    addr: FLAGS_ADDR,
                    value: 0
                },
                Write {
                    addr: N5_FLAGS_ADDR,
                    value: 0
                },
            ]
        );
    }

    #[test]
    fn write_order_disables_first_then_params_then_enables() {
        let on = write_order(&[
            Write {
                addr: FLAGS_ADDR,
                value: 0x15,
            },
            Write {
                addr: HOLD_ADDR,
                value: 0x140,
            },
        ]);
        assert_eq!(on[0].addr, HOLD_ADDR);
        assert_eq!(on[1].addr, FLAGS_ADDR);

        let mixed = write_order(&[
            Write {
                addr: HOLD_ADDR,
                value: 0x140,
            },
            Write {
                addr: FLAGS_ADDR,
                value: 0,
            },
        ]);
        assert_eq!(
            mixed[0],
            Write {
                addr: FLAGS_ADDR,
                value: 0
            }
        );

        // Full N6 latency profile enable order: params before flags, N4_FLAGS before N5_FLAGS.
        let n6_on = write_order(&parse_writes(n6_latency_config()).writes);
        let first_flag = n6_on
            .iter()
            .position(|w| find_word(w.addr).unwrap().kind == Kind::Flag)
            .unwrap();
        let last_param = n6_on
            .iter()
            .rposition(|w| find_word(w.addr).unwrap().kind == Kind::Param)
            .unwrap();
        assert!(last_param < first_flag, "{n6_on:?}");
        let n4_pos = n6_on.iter().position(|w| w.addr == FLAGS_ADDR).unwrap();
        let n5_pos = n6_on.iter().position(|w| w.addr == N5_FLAGS_ADDR).unwrap();
        assert!(n4_pos < n5_pos, "{n6_on:?}");

        // Full N6 rollback order: all flags to 0 first (N5_FLAGS before N4_FLAGS), then params.
        let n6_off = write_order(&rollback_values(&parse_writes(n6_latency_config()).writes));
        let last_flag_off = n6_off
            .iter()
            .rposition(|w| find_word(w.addr).unwrap().kind == Kind::Flag)
            .unwrap();
        let first_param_off = n6_off
            .iter()
            .position(|w| find_word(w.addr).unwrap().kind == Kind::Param)
            .unwrap();
        assert!(last_flag_off < first_param_off, "{n6_off:?}");
        let n5_off_pos = n6_off.iter().position(|w| w.addr == N5_FLAGS_ADDR).unwrap();
        let n4_off_pos = n6_off.iter().position(|w| w.addr == FLAGS_ADDR).unwrap();
        assert!(n5_off_pos < n4_off_pos, "{n6_off:?}");

        assert_eq!(write_cmd(&on[0]), "wm 0x84f93008 0x140");
        assert_eq!(
            write_cmd(&Write {
                addr: FLAGS_ADDR,
                value: 0
            }),
            "wm 0x847ed604 0"
        );
        assert_eq!(read_cmd(FLAGS_ADDR), "vm 0x847ed604 4");
    }

    #[test]
    fn reducing_flag_bits_goes_before_parameter_changes() {
        let mut fake = Fake::new(true);
        fake.ram.insert(HOLD_ADDR, 0x140);
        fake.ram.insert(FLAGS_ADDR, 0x15);
        // Drop hold (to 0) and drop bit 0x10 from N4_FLAGS (0x15 -> 0x5).
        let target = vec![
            Write {
                addr: HOLD_ADDR,
                value: 0,
            },
            Write {
                addr: FLAGS_ADDR,
                value: 0x5,
            },
        ];
        let (outcome, sent) = run_session(&mut fake, &target, Session::Apply);
        assert_eq!(outcome, Outcome::Verified { wrote: 2 });
        assert!(sent);
        let wm: Vec<&str> = fake
            .sent
            .iter()
            .map(String::as_str)
            .filter(|l| l.starts_with("wm "))
            .collect();
        assert_eq!(wm, vec!["wm 0x847ed604 0x5", "wm 0x84f93008 0"]);
    }

    #[test]
    fn the_console_dump_reads_in_column_order() {
        // As captured on the bench unit (lead16, 2026-11-22).
        let real = dump(HOLD_ADDR, "00 00 01 40");
        assert_eq!(vm_word(&real, HOLD_ADDR), Some(0x140));
        assert_eq!(
            vm_word(&dump(FLAGS_ADDR, "00 00 00 15"), FLAGS_ADDR),
            Some(0x15)
        );
        // The same bytes under a memory-order header.
        let memory_order = "           | 00 01 02 03  04 05 06 07  08 09 0A 0B  0C 0D 0E 0F\n0x847ED604 | 15 00 00 00  .. .. .. ..\n";
        assert_eq!(vm_word(memory_order, FLAGS_ADDR), Some(0x15));
        // Spaces squeezed, lower case, colours.
        assert_eq!(
            vm_word(
                &format!("{HEADER}\n\u{1b}[31m0x84f93008\u{1b}[0m|00 00 01 40\n"),
                HOLD_ADDR
            ),
            Some(0x140)
        );
    }

    #[test]
    fn a_dump_without_a_header_or_with_gaps_is_unread() {
        assert_eq!(vm_word("0x847ED604 | 00 00 00 15\n", FLAGS_ADDR), None);
        assert_eq!(
            vm_word(&format!("{HEADER}\n0x847ED604 | 00 00 .. ..\n"), FLAGS_ADDR),
            None
        );
        assert_eq!(
            vm_word(&format!("{HEADER}\n0x847ED608 | 00 00 00 15\n"), FLAGS_ADDR),
            None
        );
        assert_eq!(
            vm_word(&format!("{HEADER}\n0x847ED604 00 00 00 15\n"), FLAGS_ADDR),
            None
        );
        assert_eq!(
            vm_word(
                "           | 03 03 01 00\n0x847ED604 | 00 00 00 15\n",
                FLAGS_ADDR
            ),
            None
        );
        assert_eq!(vm_word("\n0x847ed604: 0x00000015\n", FLAGS_ADDR), None);
        assert_eq!(vm_word("", FLAGS_ADDR), None);
    }

    #[test]
    fn a_session_writes_after_the_magic_and_reads_every_write_back() {
        let mut fake = Fake::new(true);
        let (outcome, sent) = run_session(&mut fake, &n4(), Session::Apply);
        assert_eq!(outcome, Outcome::Verified { wrote: 2 });
        assert!(sent);
        assert_eq!(fake.ram.get(&FLAGS_ADDR), Some(&0x15));
        assert_eq!(fake.ram.get(&HOLD_ADDR), Some(&0x140));
        assert_eq!(
            fake.sent,
            vec![
                "arm1log 2",
                "quit 0",
                "dbg revert",
                "vm 0x847ed600 4",
                "vm 0x84f93008 4",
                "vm 0x847ed604 4",
                "wm 0x84f93008 0x140",
                "wm 0x847ed604 0x15",
                "vm 0x84f93008 4",
                "vm 0x847ed604 4",
                "arm1log 1",
            ]
        );
        // Again: nothing to write.
        fake.sent.clear();
        let (outcome, sent) = run_session(&mut fake, &n4(), Session::Apply);
        assert_eq!(outcome, Outcome::Verified { wrote: 0 });
        assert!(!sent);
        assert!(!fake.sent.iter().any(|l| l.starts_with("wm ")));
    }

    #[test]
    fn no_magic_means_no_write() {
        let mut fake = Fake::new(false);
        let (outcome, sent) = run_session(&mut fake, &n4(), Session::Apply);
        assert_eq!(outcome, Outcome::NoMagic(MagicGroup::N4));
        assert!(!sent);
        assert!(!fake.sent.iter().any(|l| l.starts_with("wm ")));
        assert_eq!(fake.sent.last().map(String::as_str), Some("arm1log 1"));

        // N4 magic present, N5 magic missing -> refuses N5 words, writes nothing.
        let mut n4_only = Fake::new(true);
        let n5_words = parse_writes("wm=0x847ed604:0x15\nwm=0x84489a6c:0x3\n").writes;
        let (outcome, sent) = run_session(&mut n4_only, &n5_words, Session::Apply);
        assert_eq!(outcome, Outcome::NoMagic(MagicGroup::N5));
        assert!(!sent);
        assert!(!n4_only.sent.iter().any(|l| l.starts_with("wm ")));
    }

    #[test]
    fn a_console_in_logging_mode_is_reset_before_any_write() {
        let mut fake = Fake::new(true);
        fake.logging = true;
        let (outcome, _) = run_session(&mut fake, &n4(), Session::Apply);
        assert_eq!(outcome, Outcome::Verified { wrote: 2 });
        // A read-only check does not reset it, and a silent console is no reply.
        let mut fake = Fake::new(true);
        fake.logging = true;
        let (outcome, sent) = run_session(&mut fake, &n4(), Session::Check);
        assert_eq!(outcome, Outcome::NoReply);
        assert!(!sent);
        assert!(
            !fake
                .sent
                .iter()
                .any(|l| l == "quit 0" || l.starts_with("wm "))
        );
    }

    #[test]
    fn a_write_that_does_not_stick_is_unverified() {
        let mut fake = Fake::new(true);
        fake.broken = true;
        let (outcome, sent) = run_session(&mut fake, &n4(), Session::Apply);
        assert_eq!(
            outcome,
            Outcome::Unverified {
                addr: HOLD_ADDR,
                wanted: 0x140,
                got: Some(0)
            }
        );
        assert!(sent);
    }

    #[test]
    fn a_check_reads_only() {
        let mut fake = Fake::new(true);
        let (outcome, sent) = run_session(&mut fake, &n4(), Session::Check);
        assert_eq!(
            outcome,
            Outcome::Differs {
                addr: HOLD_ADDR,
                wanted: 0x140,
                got: Some(0)
            }
        );
        assert!(!sent);
        fake.ram.insert(HOLD_ADDR, 0x140);
        fake.ram.insert(FLAGS_ADDR, 0x15);
        fake.sent.clear();
        assert_eq!(
            run_session(&mut fake, &n4(), Session::Check).0,
            Outcome::Verified { wrote: 0 }
        );
        assert!(!fake.sent.iter().any(|l| l.starts_with("wm ")));
    }

    #[test]
    fn a_word_off_the_allow_list_is_never_written() {
        let mut fake = Fake::new(true);
        let bad = [Write {
            addr: 0x847e_d608,
            value: 1,
        }];
        let (outcome, sent) = run_session(&mut fake, &bad, Session::Apply);
        assert!(matches!(outcome, Outcome::Unverified { .. }));
        assert!(!sent);
        let bad = [Write {
            addr: FLAGS_ADDR,
            value: 0x2,
        }];
        assert!(!run_session(&mut fake, &bad, Session::Apply).1);
    }

    fn drive(control: &mut Control, fake: &mut Fake, now: u64) -> Option<String> {
        let plan = control.due(now)?;
        let (outcome, sent) = run_plan(fake, &plan);
        control.finished(now, &plan, &outcome, sent)
    }

    #[test]
    fn large_profiles_split_into_safe_sessions_and_roll_back_cleanly() {
        let n6_writes = parse_writes(n6_latency_config()).writes;
        assert_eq!(n6_writes.len(), 10);
        let batches = split_sessions(&n6_writes, Session::Apply);
        assert!(batches.len() >= 2, "expected split sessions: {batches:?}");
        for b in &batches {
            assert!(
                session_budget_secs(b, Session::Apply) <= MAX_SESSION_SECS,
                "batch exceeded budget: {b:?}"
            );
        }
        // Every parameter is in an earlier (or same, preceding) slot than any flag.
        let flat: Vec<Write> = batches.iter().flatten().copied().collect();
        let last_param = flat
            .iter()
            .rposition(|w| find_word(w.addr).unwrap().kind == Kind::Param)
            .unwrap();
        let first_flag = flat
            .iter()
            .position(|w| find_word(w.addr).unwrap().kind == Kind::Flag)
            .unwrap();
        assert!(last_param < first_flag, "{flat:?}");

        // Missing N6 magic on an N5-only image stops at batch 0 BEFORE any enable is written.
        let mut n5_only = Fake::with_magics(
            [MagicGroup::N4, MagicGroup::Img4, MagicGroup::N5]
                .into_iter()
                .collect(),
        );
        let mut control_missing_n6 = Control::new(n6_writes.clone(), 0);
        let line = drive(&mut control_missing_n6, &mut n5_only, 0).unwrap();
        assert!(line.contains("N6 patch magic"), "{line}");
        assert_eq!(control_missing_n6.state(), State::WaitingMagic);
        assert!(!n5_only.sent.iter().any(|l| l.starts_with("wm ")));

        // Reducing N5_FLAGS (0x3 -> 0x1) while changing parameters puts N5_FLAGS in batch 0 first.
        let prev = n6_writes.clone();
        let next = parse_writes(
            "enabled=1\nwm=0x84f93008:0x80\nwm=0x847ed604:0x15\nwm=0x847ed548:0x1\nwm=0x847ed54c:0x1\nwm=0x847ed550:0x1\nwm=0x847ecf08:0x1\nwm=0x84489a84:0x4000\nwm=0x84489a88:0x6000\nwm=0x84489a6c:0x1\nwm=0x8418ff08:0x1\n",
        )
        .writes;
        let red_batches = split_sessions_from(&next, &prev, Session::Apply);
        assert_eq!(
            red_batches[0][0],
            Write {
                addr: N5_FLAGS_ADDR,
                value: 0x1
            }
        );

        // Drive the full N6 latency profile across its split sessions.
        let mut control = Control::new(n6_writes.clone(), 100);
        let mut fake = Fake::all_magics();
        let mut sessions = 0;
        let mut final_line = None;
        while control.state() != State::Applied {
            let line = drive(&mut control, &mut fake, 100);
            sessions += 1;
            assert!(sessions <= 5);
            if line.is_some() {
                final_line = line;
            }
        }
        assert_eq!(sessions, batches.len());
        assert!(final_line.unwrap().contains("written and read back"));
        for w in &n6_writes {
            assert_eq!(fake.ram.get(&w.addr), Some(&w.value), "0x{:08x}", w.addr);
        }

        // Check fits in a single read-only session.
        let check_plan = control.due(100 + CHECK_EVERY).unwrap();
        assert_eq!(check_plan.session, Session::Check);
        assert_eq!(check_plan.total_batches, 1);
        assert_eq!(drive(&mut control, &mut fake, 100 + CHECK_EVERY), None);

        // Failure in batch 2 after batch 1 wrote: 3 failures trigger full rollback across batches.
        let mut control2 = Control::new(n6_writes.clone(), 0);
        let mut fake2 = Fake::all_magics();
        fake2.broken_addr = Some(U2_FLAGS_ADDR); // In batch 2
        // Batch 1 succeeds.
        assert_eq!(drive(&mut control2, &mut fake2, 0), None);
        assert_eq!(control2.state(), State::Pending);
        // Batch 2 fails 3 times -> Zeroing.
        let mut now = 0;
        for _ in 0..MAX_ATTEMPTS {
            let line = drive(&mut control2, &mut fake2, now).unwrap();
            assert!(line.contains("tk flags:"));
            now += RETRY_SECS;
        }
        assert_eq!(control2.state(), State::Zeroing);
        // Allow rollback writes to stick (U2_FLAGS is already 0 anyway).
        fake2.broken_addr = None;
        let mut rb_sessions = 0;
        let mut rb_line = None;
        while control2.state() == State::Zeroing {
            rb_line = drive(&mut control2, &mut fake2, now);
            rb_sessions += 1;
            assert!(rb_sessions <= 5);
        }
        assert_eq!(control2.state(), State::Retrying);
        assert!(rb_line.unwrap().contains("flags read back 0"));
        for w in &n6_writes {
            assert_eq!(
                *fake2.ram.get(&w.addr).unwrap_or(&0),
                off_value(w.addr).unwrap(),
                "rollback missed 0x{:08x}",
                w.addr
            );
        }
    }

    #[test]
    fn hands_off_pauses_everything_and_resumes_with_fresh_read() {
        let mut control = Control::new(n4(), 0);
        let mut fake = Fake::new(true);
        drive(&mut control, &mut fake, 0);
        assert_eq!(control.state(), State::Applied);

        // Enter hands-off via manage=off.
        assert!(hands_off("enabled=1\nmanage=off\n"));
        assert!(!hands_off("enabled=1\nmanage=off\nmanage=on\n"));
        let (changed, line) = control.set_hands_off(Some("manage=off in tk/config"), 10);
        assert!(changed);
        assert!(line.unwrap().contains("hands-off"));
        assert_eq!(control.state(), State::HandsOff);
        assert!(control.status(10).starts_with("state=hands-off\n"));

        // No sessions due, even past CHECK_EVERY.
        assert_eq!(control.due(10), None);
        assert_eq!(control.due(10 + CHECK_EVERY * 10), None);

        // Operator edits RAM manually while hands-off; keeper does nothing.
        fake.ram.insert(FLAGS_ADDR, 0);
        assert_eq!(control.due(10 + CHECK_EVERY * 20), None);

        // Config change while hands-off queues without running a session.
        let line = control
            .set_wanted_with_ack(
                parse_writes("enabled=1\nhold_ack=prb-tax\nwm=0x84f93008:0x400\nwm=0x847ed604:0x15\n")
                    .writes,
                true,
                20,
            )
            .unwrap();
        assert!(line.contains("while hands-off"));
        assert_eq!(control.state(), State::HandsOff);
        assert_eq!(control.due(20), None);

        // Clearing hands-off resumes immediately with a fresh Apply session.
        let (changed, line) = control.set_hands_off(None, 30);
        assert!(changed);
        assert!(line.unwrap().contains("resuming management"));
        assert_eq!(control.state(), State::Pending);
        let plan = control.due(30).unwrap();
        assert_eq!(plan.session, Session::Apply);
        assert!(plan.hold_ack);
        let line = drive(&mut control, &mut fake, 30).unwrap();
        assert!(line.contains("written and read back"));
        assert_eq!(fake.ram.get(&HOLD_ADDR), Some(&0x400));
        assert_eq!(fake.ram.get(&FLAGS_ADDR), Some(&0x15));
    }

    #[test]
    fn the_control_waits_for_the_magic_then_applies_and_checks() {
        let mut control = Control::new(n4(), 100);
        let mut fake = Fake::new(false);
        let line = drive(&mut control, &mut fake, 100).unwrap();
        assert!(line.contains("waiting for the N4 patch magic"), "{line}");
        assert_eq!(control.state(), State::WaitingMagic);
        assert_eq!(control.due(100 + MAGIC_FIRST - 1), None);
        // Still no magic: no new log line, a longer wait.
        assert_eq!(drive(&mut control, &mut fake, 100 + MAGIC_FIRST), None);
        assert_eq!(control.due(100 + MAGIC_FIRST + 2 * MAGIC_FIRST - 1), None);
        fake.set_n4_magic(true);
        let line = drive(&mut control, &mut fake, 200).unwrap();
        assert!(line.contains("written and read back"), "{line}");
        assert_eq!(control.state(), State::Applied);
        assert_eq!(control.due(200 + CHECK_EVERY - 1), None);
        let plan = control.due(200 + CHECK_EVERY).unwrap();
        assert_eq!(plan.session, Session::Check);
        assert_eq!(drive(&mut control, &mut fake, 200 + CHECK_EVERY), None);
        assert!(
            control.status(9).starts_with("state=applied\n"),
            "{}",
            control.status(9)
        );
        assert!(
            control
                .status(9)
                .contains("want=0x84f93008=0x140 0x847ed604=0x15\n")
        );
    }

    #[test]
    fn the_magic_wait_backs_off_to_its_cap() {
        let mut control = Control::new(n4(), 0);
        let mut fake = Fake::new(false);
        let mut now = 0;
        let mut waits = Vec::new();
        for _ in 0..10 {
            drive(&mut control, &mut fake, now);
            let mut next = now;
            while control.due(next).is_none() {
                next += 1;
            }
            waits.push(next - now);
            now = next;
        }
        assert_eq!(waits[..7], [15, 30, 60, 120, 240, 480, 600]);
        assert!(waits.iter().all(|w| *w <= MAGIC_MAX));
    }

    #[test]
    fn three_failures_roll_back_then_write_again_after_a_backoff() {
        let mut control = Control::new(n4(), 0);
        let mut fake = Fake::new(true);
        fake.broken = true;
        let mut now = 0;
        for attempt in 1..=MAX_ATTEMPTS {
            let line = drive(&mut control, &mut fake, now).unwrap();
            if attempt < MAX_ATTEMPTS {
                assert!(
                    line.contains(&format!("session {attempt} of 3 failed")),
                    "{line}"
                );
            } else {
                assert!(line.contains("writing 0 to every managed word"), "{line}");
            }
            now += RETRY_SECS;
        }
        assert_eq!(control.state(), State::Zeroing);
        let plan = control.due(now).unwrap();
        assert_eq!(plan.writes, write_order(&zeros(&n4())));
        // The broken writes never changed RAM, so the zeros read back as 0.
        let line = drive(&mut control, &mut fake, now).unwrap();
        assert!(line.contains("flags read back 0"), "{line}");
        assert!(line.contains(&format!("again in {BACKOFF_FIRST} s")), "{line}");
        assert_eq!(control.state(), State::Retrying);
        assert!(control.status(now).starts_with("state=retrying\n"));
        // The off values are where it waits, not where it stops.
        assert_eq!(control.due(now + BACKOFF_FIRST - 1), None);
        fake.broken = false;
        let plan = control.due(now + BACKOFF_FIRST).unwrap();
        assert_eq!(plan.session, Session::Apply);
        assert_eq!(plan.writes, write_order(&n4()));
        let line = drive(&mut control, &mut fake, now + BACKOFF_FIRST).unwrap();
        assert!(line.contains("written and read back"), "{line}");
        assert_eq!(control.state(), State::Applied);
        assert_eq!(fake.ram.get(&FLAGS_ADDR), Some(&0x15));
    }

    #[test]
    fn a_silent_console_costs_no_attempt_and_is_tried_again_later() {
        let mut control = Control::new(n4(), 0);
        // `quit 0` would fix a console in logging mode; this one is dead.
        struct Dead;
        impl Console for Dead {
            fn command(&mut self, _: &str) -> String {
                String::new()
            }
        }
        let mut now = 0;
        let mut waits = Vec::new();
        let mut lines = 0;
        for _ in 0..12 {
            let plan = control.due(now).unwrap();
            let (outcome, sent) = run_plan(&mut Dead, &plan);
            assert_eq!(outcome, Outcome::NoReply);
            assert!(!sent);
            lines += usize::from(control.finished(now, &plan, &outcome, sent).is_some());
            let mut next = now;
            while control.due(next).is_none() {
                next += 1;
            }
            waits.push(next - now);
            now = next;
        }
        // Never a rollback or a give-up: the same session, later each time.
        assert_eq!(control.state(), State::Pending);
        assert_eq!(control.status(now).lines().nth(3), Some("attempts=0"));
        assert_eq!(waits[..7], [15, 30, 60, 120, 240, 480, 600]);
        assert!(waits.iter().all(|w| *w <= MAGIC_MAX));
        // One log line for the whole silent stretch.
        assert_eq!(lines, 1);
        assert!(control.detail().contains("nothing was written"), "{}", control.detail());
        // A console that answers again gets the words written.
        let mut fake = Fake::new(true);
        let line = drive(&mut control, &mut fake, now).unwrap();
        assert!(line.contains("written and read back"), "{line}");
        assert_eq!(control.state(), State::Applied);
    }

    /// Run `control` on a simulated clock from `start` to `end`: each session
    /// when it falls due, after `set` has put the console in its state for
    /// that moment. A session takes `SESSION_TOOK` seconds, as on the unit.
    fn run_clock(
        control: &mut Control,
        fake: &mut Fake,
        start: u64,
        end: u64,
        mut set: impl FnMut(&mut Fake, u64),
    ) -> Vec<(u64, Session, Outcome)> {
        const SESSION_TOOK: u64 = 30;
        let mut ran = Vec::new();
        let mut now = start;
        while now <= end {
            let Some(plan) = control.due(now) else {
                now += 1;
                continue;
            };
            set(fake, now);
            let (outcome, sent) = run_plan(fake, &plan);
            control.finished(now, &plan, &outcome, sent);
            ran.push((now, plan.session, outcome));
            now += SESSION_TOOK;
        }
        ran
    }

    /// The bench case of 2026-11-25: another console client made our replies
    /// come back cut short. Writes land, but no read-back arrives, so every
    /// apply and every rollback is unverified while the console is busy.
    #[test]
    fn a_console_busy_for_ten_minutes_then_free_gets_the_words_back_by_itself() {
        const BUSY_UNTIL: u64 = 600;
        let mut control = Control::new(n6_latency_profile(), 0);
        let mut fake = Fake::all_magics();
        let cut = |fake: &mut Fake, now: u64| fake.cut_reads = now < BUSY_UNTIL;
        let busy = run_clock(&mut control, &mut fake, 0, BUSY_UNTIL - 1, cut);
        // It tried, rolled back, and backed off rather than hammering the console.
        assert!(busy.iter().all(|(_, _, outcome)| matches!(outcome, Outcome::Unverified { .. })), "{busy:?}");
        assert!(busy.len() <= 10, "{} sessions while busy: {busy:?}", busy.len());
        assert!(busy.iter().filter(|(at, _, _)| *at >= BUSY_UNTIL / 2).count() <= 2, "{busy:?}");
        assert!(matches!(control.state(), State::Zeroing | State::Retrying), "{:?}", control.state());
        // Once the console is free, the rollback reads back, and after the
        // backoff the wanted words go back in, with no operator and no restart.
        let after = run_clock(&mut control, &mut fake, BUSY_UNTIL, BUSY_UNTIL + 2 * BACKOFF_MAX, cut);
        assert_eq!(control.state(), State::Applied, "{after:?}");
        for w in n6_latency_profile() {
            assert_eq!(fake.ram.get(&w.addr), Some(&w.value), "0x{:08x}", w.addr);
        }
        let back = after.iter().position(|(_, s, o)| *s == Session::Check && matches!(o, Outcome::Verified { .. }));
        let applied_at = after[back.unwrap()].0 - CHECK_EVERY;
        assert!(applied_at < BUSY_UNTIL + BACKOFF_MAX, "words back only at {applied_at} s");
        // And it stays applied: read-only checks, every one verified.
        assert!(after.iter().filter(|(at, _, _)| *at > applied_at).all(|(_, s, o)| *s == Session::Check
            && matches!(o, Outcome::Verified { .. })));
    }

    /// A console that answers nothing for ten minutes while the words are
    /// applied: nothing went out, so nothing is rolled back.
    #[test]
    fn a_silent_console_for_ten_minutes_leaves_applied_words_alone() {
        let mut control = Control::new(n4(), 0);
        let mut fake = Fake::new(true);
        drive(&mut control, &mut fake, 0);
        assert_eq!(control.state(), State::Applied);
        let writes_before = wm_lines(&fake).len();
        let start = CHECK_EVERY;
        let dead = |fake: &mut Fake, now: u64| fake.dead = now < start + 600;
        let ran = run_clock(&mut control, &mut fake, start, start + 600 + 2 * MAGIC_MAX, dead);
        assert!(ran.iter().any(|(_, _, o)| *o == Outcome::NoReply));
        assert_eq!(control.state(), State::Applied, "{ran:?}");
        // No rollback, and no write at all: the words never changed.
        assert_eq!(wm_lines(&fake).len(), writes_before);
        assert_eq!(fake.ram.get(&FLAGS_ADDR), Some(&0x15));
    }

    #[test]
    fn the_backoff_doubles_to_its_cap_and_starts_again_once_the_words_read_back() {
        // The apply sessions that failed on `FLAGS_ADDR` (rollbacks verify).
        fn failed_applies(ran: &[(u64, Session, Outcome)]) -> Vec<u64> {
            ran.iter()
                .filter(|(_, _, o)| matches!(o, Outcome::Unverified { addr, .. } if *addr == FLAGS_ADDR))
                .map(|(at, _, _)| *at)
                .collect()
        }
        let gaps = |at: &[u64]| at.windows(2).map(|w| w[1] - w[0]).collect::<Vec<u64>>();
        let mut control = Control::new(n4(), 0);
        let mut fake = Fake::new(true);
        // A word that never sticks, with read-backs that do arrive.
        fake.broken_addr = Some(FLAGS_ADDR);
        let ran = run_clock(&mut control, &mut fake, 0, 6 * BACKOFF_MAX, |_, _| {});
        assert_ne!(control.state(), State::Applied);
        let gaps_seen = gaps(&failed_applies(&ran));
        // Three tries (due 20 s apart; a session takes 30 s here), then one
        // round per backoff: the rollback's 30 s session plus 300, 600, 1200,
        // 2400 and 3600 s, held at the cap from then on.
        assert_eq!(gaps_seen[..2], [30, 30], "{gaps_seen:?}");
        let rounds: Vec<u64> = gaps_seen[2..].iter().map(|g| g - 30).collect();
        assert_eq!(rounds[..5], [300, 600, 1200, 2400, 3600], "{gaps_seen:?}");
        assert!(rounds[5..].iter().all(|r| *r == BACKOFF_MAX), "{rounds:?}");
        // Every failed round ends at the off values, read back.
        assert!(control.state() == State::Retrying, "{:?}", control.state());
        assert_eq!(fake.ram.get(&HOLD_ADDR), Some(&0));
        // Fixed: the next round writes it, and a later failure starts the
        // backoff again from BACKOFF_FIRST.
        fake.broken_addr = None;
        let fixed = run_clock(&mut control, &mut fake, 6 * BACKOFF_MAX + 1, 8 * BACKOFF_MAX, |_, _| {});
        assert_eq!(control.state(), State::Applied, "{fixed:?}");
        fake.broken_addr = Some(FLAGS_ADDR);
        fake.ram.insert(FLAGS_ADDR, 0);
        let again = run_clock(&mut control, &mut fake, 8 * BACKOFF_MAX + 1, 9 * BACKOFF_MAX, |_, _| {});
        assert_eq!(gaps(&failed_applies(&again))[..3], [30, 30, 30 + BACKOFF_FIRST], "{again:?}");
    }

    #[test]
    fn a_restart_or_a_reset_value_writes_again() {
        let mut control = Control::new(n4(), 0);
        let mut fake = Fake::new(true);
        drive(&mut control, &mut fake, 0);
        assert_eq!(control.state(), State::Applied);
        // The modem lost the values with the magic still there.
        fake.ram.clear();
        let line = drive(&mut control, &mut fake, CHECK_EVERY).unwrap();
        assert!(line.contains("read back 0x0, wanted 0x140"), "{line}");
        assert_eq!(control.state(), State::Pending);
        drive(&mut control, &mut fake, CHECK_EVERY);
        assert_eq!(control.state(), State::Applied);
        // A modem restart onto stock firmware: wait, never write.
        let line = control.modem_restarted(1000);
        assert!(line.contains("modem restart seen"), "{line}");
        assert_eq!(control.due(1000 + AFTER_RESTART - 1), None);
        fake.set_n4_magic(false);
        fake.ram.clear();
        drive(&mut control, &mut fake, 1000 + AFTER_RESTART);
        assert_eq!(control.state(), State::WaitingMagic);
        assert!(fake.ram.is_empty());
        // Even a failed control starts again after a restart.
        let mut failed = Control::new(n4(), 0);
        failed.state = State::Retrying;
        failed.modem_restarted(5);
        assert_eq!(
            failed.due(5 + AFTER_RESTART).map(|p| p.session),
            Some(Session::Apply)
        );
    }

    #[test]
    fn a_stuck_console_on_checks_gets_a_reset_session() {
        let mut control = Control::new(n4(), 0);
        let mut fake = Fake::new(true);
        drive(&mut control, &mut fake, 0);
        fake.logging = true;
        let mut now = CHECK_EVERY;
        for miss in 1..=CHECK_MISSES {
            let line = drive(&mut control, &mut fake, now);
            if miss < CHECK_MISSES {
                assert_eq!(line, None);
                assert_eq!(control.state(), State::Applied);
            } else {
                assert!(line.unwrap().contains("resetting the console"));
            }
            now += RETRY_SECS;
        }
        assert_eq!(control.state(), State::Pending);
        // The write session sends `quit 0` and reads back fine.
        let line = drive(&mut control, &mut fake, now).unwrap();
        assert!(line.contains("already set and read back"), "{line}");
        assert_eq!(control.state(), State::Applied);
        assert!(fake.sent.iter().any(|l| l == "quit 0"));
    }

    #[test]
    fn a_config_change_rewrites_and_off_zeroes() {
        let mut control = Control::new(n4(), 0);
        let mut fake = Fake::new(true);
        drive(&mut control, &mut fake, 0);
        assert_eq!(control.set_wanted(n4(), 10), None);
        let off = wanted("enabled=0\n", control.wanted());
        let line = control.set_wanted(off.clone(), 10).unwrap();
        assert!(line.contains("tk/config changed"), "{line}");
        let plan = control.due(10).unwrap();
        assert_eq!(plan.session, Session::Apply);
        drive(&mut control, &mut fake, 10);
        assert_eq!(fake.ram.get(&FLAGS_ADDR), Some(&0));
        assert_eq!(fake.ram.get(&HOLD_ADDR), Some(&0));
        // Flags first when turning off.
        let wm: Vec<&str> = fake
            .sent
            .iter()
            .map(String::as_str)
            .filter(|l| l.starts_with("wm "))
            .collect();
        assert_eq!(wm[wm.len() - 2..], ["wm 0x847ed604 0", "wm 0x84f93008 0"]);
    }

    #[test]
    fn busy_counts_no_attempt() {
        let mut control = Control::new(n4(), 0);
        let plan = control.due(0).unwrap();
        for i in 0..10 {
            assert_eq!(
                control.finished(i * RETRY_SECS, &plan, &Outcome::Busy, false),
                None
            );
        }
        assert_eq!(control.state(), State::Pending);
    }

    #[test]
    fn only_a_confirmed_staged_boot_arms() {
        let sha = "8c0a073fe1a07c4d3a0e1a79be6a58cd5898bde761ba54eeb800e00465d4903e";
        let staged = tk_boot::parse_status(&format!(
            "state=staged\nsha256={sha}\nstrikes=1\nloaded_at=20\nsource=fs\nfirmware=clean\n"
        ));
        assert_eq!(
            armed_sha(&staged, &format!("confirmed={sha}\n")).as_deref(),
            Some(sha)
        );
        assert_eq!(
            armed_sha(&staged, &format!("confirmed={}\n", sha.to_uppercase())).as_deref(),
            Some(sha)
        );
        assert_eq!(armed_sha(&staged, &format!("rollback={sha}\n")), None);
        assert_eq!(armed_sha(&staged, ""), None);
        assert_eq!(
            armed_sha(&staged, &format!("confirmed={}\n", "b".repeat(64))),
            None
        );
        let stock = tk_boot::parse_status("state=stock\nreason=off\n");
        assert_eq!(armed_sha(&stock, &format!("confirmed={sha}\n")), None);
        let nand = tk_boot::parse_status(&format!("state=staged\nsha256={sha}\nsource=nand\n"));
        assert_eq!(armed_sha(&nand, &format!("confirmed={sha}\n")), None);
        assert!(modem_loaded("[   42.1] read from nand mtd=tk0"));
        assert!(modem_loaded("<4>[ 7.0] read from fs"));
        assert!(!modem_loaded("modem: no such fw files!"));
    }

    fn m1_profile() -> Vec<Write> {
        parse_writes("enabled=1\nwm=0x847ed604:0x15\nwm=0x841b5908:0x1\n").writes
    }

    #[test]
    fn the_m1_selector_is_bounded_and_the_rest_of_its_block_is_never_written() {
        for v in 0..=2 {
            assert!(value_ok(M1_SELECT_ADDR, v), "{v}");
        }
        for v in [3, 4, 0x10, u32::MAX] {
            assert!(!value_ok(M1_SELECT_ADDR, v), "{v}");
        }
        let parsed = parse_writes("enabled=1\nwm=0x841b5908:0x2\nwm=0x841b5908:3\n");
        assert_eq!(
            parsed.writes,
            vec![Write {
                addr: M1_SELECT_ADDR,
                value: 2
            }]
        );
        assert_eq!(
            parsed.refused_reasons,
            vec![(
                "wm=0x841b5908:3".to_owned(),
                "M1_SELECT value 3 outside allowed range 0..=2".to_owned()
            )]
        );
        assert_eq!(off_value(M1_SELECT_ADDR), Some(0));
        assert_eq!(find_word(M1_SELECT_ADDR).map(|w| w.magic), Some(MagicGroup::M1));
        // Magic, version, tunables, live state and counters: never on the list.
        for addr in (M1_MAGIC_ADDR..M1_MAGIC_ADDR + 0x100).step_by(4) {
            if addr == M1_SELECT_ADDR {
                continue;
            }
            assert!(find_word(addr).is_none(), "0x{addr:08x}");
            let line = format!("wm=0x{addr:08x}:0x1");
            assert_eq!(parse_writes(&line).refused, vec![line.clone()]);
            let mut fake = Fake::all_magics();
            let bad = [Write { addr, value: 1 }];
            let (outcome, sent) = run_session(&mut fake, &bad, Session::Apply);
            assert!(matches!(outcome, Outcome::Unverified { .. }), "0x{addr:08x}");
            assert!(!sent);
        }
    }

    #[test]
    fn the_m1_selector_needs_its_magic_and_an_accepted_version() {
        // No M1 block: nothing is written.
        let mut n4_only = Fake::new(true);
        let (outcome, sent) = run_session(&mut n4_only, &m1_profile(), Session::Apply);
        assert_eq!(outcome, Outcome::NoMagic(MagicGroup::M1));
        assert!(!sent);
        // One line reads the magic and the version.
        assert!(
            n4_only.sent.iter().any(|l| l == "vm 0x841b5900 8"),
            "{:?}",
            n4_only.sent
        );
        // An M1 build this keeper does not know: nothing is written.
        let mut newer = Fake::all_magics();
        newer.version = 0x2026_1199;
        let (outcome, sent) = run_session(&mut newer, &m1_profile(), Session::Apply);
        assert_eq!(
            outcome,
            Outcome::WrongVersion {
                group: MagicGroup::M1,
                got: Some(0x2026_1199)
            }
        );
        assert!(!sent);
        assert!(wm_lines(&newer).is_empty());
        // A magic line that shows no version is refused the same way.
        let cut = dump(M1_MAGIC_ADDR, "4d 31 50 49");
        assert_eq!(
            magic_refusal(magic_spec(MagicGroup::M1), &cut),
            Some(Outcome::WrongVersion {
                group: MagicGroup::M1,
                got: None
            })
        );
        // An accepted build: N4 flags first, the selector last, both read back.
        let mut fake = Fake::all_magics();
        let (outcome, sent) = run_session(&mut fake, &m1_profile(), Session::Apply);
        assert_eq!(outcome, Outcome::Verified { wrote: 2 });
        assert!(sent);
        assert_eq!(wm_lines(&fake), vec!["wm 0x847ed604 0x15", "wm 0x841b5908 0x1"]);
        // Rollback: the selector goes back to 0 first.
        fake.sent.clear();
        let off = rollback_values(&m1_profile());
        let (outcome, _) = run_session(&mut fake, &off, Session::Apply);
        assert_eq!(outcome, Outcome::Verified { wrote: 2 });
        assert_eq!(wm_lines(&fake), vec!["wm 0x841b5908 0", "wm 0x847ed604 0"]);
        assert_eq!(fake.ram.get(&M1_SELECT_ADDR), Some(&0));
    }

    #[test]
    fn the_bench_m1_dump_reads_as_its_counters() {
        let status = read_status(&STATUS[0], M1_BENCH_DUMP).unwrap();
        assert_eq!(status.group, MagicGroup::M1);
        assert_eq!(status.version, Some(0x2026_1125));
        assert_eq!(
            status.fields,
            vec![
                ("selector", 1),
                ("seen", 28025),
                ("pie_drops", 130),
                ("ce_marks", 0),
                ("hard_drops", 90),
                ("peak_qdelay_us", 97612),
            ]
        );
        // Every packet the PIE saw was enqueued or dropped.
        let block = vm_memory(M1_BENCH_DUMP, M1_MAGIC_ADDR, 160).unwrap();
        let word = |at: usize| u32::from_le_bytes(block[at..at + 4].try_into().unwrap());
        assert_eq!(word(0x60), word(0x64) + word(0x68) + word(0x70));
        // The same dump passes the session's magic and version check.
        assert_eq!(magic_refusal(magic_spec(MagicGroup::M1), M1_BENCH_DUMP), None);
        // Another build, stock bytes, no header or a lost row: nothing is read.
        for text in [
            M1_BENCH_DUMP.replace("20 26 11 25", "20 26 11 99"),
            M1_BENCH_DUMP.replace("4d 31 50 49", "68 1a d1 0d"),
            M1_BENCH_DUMP.replace(HEADER, ""),
            M1_BENCH_DUMP
                .lines()
                .filter(|l| !l.starts_with("0x841B5980"))
                .map(|l| format!("{l}\n"))
                .collect(),
        ] {
            assert_eq!(read_status(&STATUS[0], &text), None, "{text}");
        }
    }

    #[test]
    fn a_multi_row_dump_reads_in_memory_order() {
        let words = [0x4d31_5049, 0x2026_1125, 1, 14, 15, 55];
        let text = dump_words(M1_MAGIC_ADDR, &words);
        let block = vm_memory(&text, M1_MAGIC_ADDR, 24).unwrap();
        for (i, w) in words.iter().enumerate() {
            let at = i * 4;
            assert_eq!(u32::from_le_bytes(block[at..at + 4].try_into().unwrap()), *w);
        }
        // A window inside the dump, and one past its end.
        assert_eq!(vm_memory(&text, M1_SELECT_ADDR, 4), Some(vec![1, 0, 0, 0]));
        assert_eq!(vm_memory(&text, M1_MAGIC_ADDR, 28), None);
        // `vm_word` still reads only the word that starts a row.
        assert_eq!(vm_word(&text, M1_MAGIC_ADDR), Some(0x4d31_5049));
        assert_eq!(vm_word(&text, M1_SELECT_ADDR), None);
    }

    #[test]
    fn a_verified_m1_session_reads_its_counters_in_one_line() {
        let mut fake = Fake::all_magics();
        for (addr, value) in [
            (0x841b_5960, 28025),
            (0x841b_5968, 130),
            (0x841b_596c, 7),
            (0x841b_5970, 90),
            (0x841b_5980, 97612),
        ] {
            fake.ram.insert(addr, value);
        }
        let report = run_session_inner(&mut fake, &m1_profile(), &[], Session::Apply, false);
        assert_eq!(report.outcome, Outcome::Verified { wrote: 2 });
        assert_eq!(
            report.status,
            vec![LayerStatus {
                group: MagicGroup::M1,
                version: Some(0x2026_1125),
                fields: vec![
                    ("selector", 1),
                    ("seen", 28025),
                    ("pie_drops", 130),
                    ("ce_marks", 7),
                    ("hard_drops", 90),
                    ("peak_qdelay_us", 97612),
                ],
            }]
        );
        assert_eq!(
            report.status[0].text(42),
            "version=0x20261125\nselector=1\nseen=28025\npie_drops=130\nce_marks=7\nhard_drops=90\npeak_qdelay_us=97612\nupdated=42\n"
        );
        assert_eq!(status_file(MagicGroup::M1), "witcher-tk.m1");
        // One line, after every read-back, before `arm1log 1`.
        let n = fake.sent.len();
        assert_eq!(fake.sent[n - 2..], ["vm 0x841b5900 160", "arm1log 1"]);
        assert_eq!(
            fake.sent.iter().filter(|l| *l == "vm 0x841b5900 160").count(),
            1
        );
        // A read-only check reads it too, and its budget counts the line.
        let report = run_session_inner(&mut fake, &m1_profile(), &[], Session::Check, false);
        assert_eq!(report.outcome, Outcome::Verified { wrote: 0 });
        assert_eq!(report.status.len(), 1);
        assert_eq!(session_budget_secs(&m1_profile(), Session::Check), 4 + 2 * 3 + 2 * 3 + 3);
        // A failed session, or one without an M1 word, reads no block.
        let mut broken = Fake::all_magics();
        broken.broken_addr = Some(M1_SELECT_ADDR);
        let report = run_session_inner(&mut broken, &m1_profile(), &[], Session::Apply, false);
        assert!(matches!(
            report.outcome,
            Outcome::Unverified {
                addr: M1_SELECT_ADDR,
                ..
            }
        ));
        assert!(report.status.is_empty());
        assert!(!broken.sent.iter().any(|l| l.starts_with("vm 0x841b5900 1")));
        let mut plain = Fake::all_magics();
        let report = run_session_inner(&mut plain, &n4(), &[], Session::Apply, false);
        assert_eq!(report.outcome, Outcome::Verified { wrote: 2 });
        assert!(report.status.is_empty());
        assert!(!plain.sent.iter().any(|l| l.starts_with("vm 0x841b5900")));
    }

    #[test]
    fn the_control_waits_for_an_accepted_m1_build_and_says_which() {
        let mut control = Control::new(m1_profile(), 0);
        let mut fake = Fake::all_magics();
        fake.version = 0x2026_1199;
        let line = drive(&mut control, &mut fake, 0).unwrap();
        assert!(
            line.contains(
                "the M1 patch at 0x841b5900 shows version 0x20261199; this keeper accepts 0x20261125, 0x20261126; nothing written"
            ),
            "{line}"
        );
        assert_eq!(control.state(), State::WaitingMagic);
        assert!(control.status(0).contains("detail=the M1 patch"), "{}", control.status(0));
        // The same reason again is no news, and nothing is ever written.
        assert_eq!(drive(&mut control, &mut fake, MAGIC_FIRST), None);
        assert!(wm_lines(&fake).is_empty());
        // After a modem restart onto an accepted build the words go out.
        fake.version = M1_VERSIONS[0];
        control.modem_restarted(100);
        let line = drive(&mut control, &mut fake, 100 + AFTER_RESTART).unwrap();
        assert!(line.contains("written and read back"), "{line}");
        assert_eq!(fake.ram.get(&M1_SELECT_ADDR), Some(&1));
        assert_eq!(control.state(), State::Applied);
    }

    #[test]
    fn the_n6h_profile_with_m1_splits_safely_and_rolls_the_selector_back_first() {
        let config = format!("{}wm=0x841b5908:0x1\n", n6_latency_config());
        let writes = parse_writes(&config).writes;
        assert_eq!(writes.len(), 11);
        assert_eq!(
            writes.last(),
            Some(&Write {
                addr: M1_SELECT_ADDR,
                value: 1
            })
        );
        let batches = split_sessions(&writes, Session::Apply);
        for b in &batches {
            assert!(
                session_budget_secs(b, Session::Apply) <= MAX_SESSION_SECS,
                "batch exceeded budget: {b:?}"
            );
        }
        // The selector goes out last, after N4_FLAGS and every other layer.
        let flat: Vec<Write> = batches.iter().flatten().copied().collect();
        assert_eq!(flat.last().map(|w| w.addr), Some(M1_SELECT_ADDR));
        let mut control = Control::new(writes.clone(), 0);
        let mut fake = Fake::all_magics();
        let mut sessions = 0;
        while control.state() != State::Applied {
            drive(&mut control, &mut fake, 0);
            sessions += 1;
            assert!(sessions <= 5);
        }
        assert_eq!(sessions, batches.len());
        for w in &writes {
            assert_eq!(fake.ram.get(&w.addr), Some(&w.value), "0x{:08x}", w.addr);
        }
        // The 10-minute check is one session within budget and reads the block.
        let plan = control.due(CHECK_EVERY).unwrap();
        assert_eq!(plan.session, Session::Check);
        assert_eq!(plan.total_batches, 1);
        assert!(session_budget_secs(&plan.writes, Session::Check) <= MAX_SESSION_SECS);
        let report = run_plan_report(&mut fake, &plan);
        assert_eq!(report.outcome, Outcome::Verified { wrote: 0 });
        assert_eq!(report.status.len(), 1);
        control.finished(CHECK_EVERY, &plan, &report.outcome, report.sent);
        // Turning it all off writes the selector back to 0 before anything else.
        let off = wanted("enabled=0\n", control.wanted());
        control.set_wanted(off, CHECK_EVERY + 1).unwrap();
        fake.sent.clear();
        while control.state() != State::Applied {
            drive(&mut control, &mut fake, CHECK_EVERY + 1);
        }
        assert_eq!(wm_lines(&fake)[0], "wm 0x841b5908 0");
        for w in &writes {
            assert_eq!(
                fake.ram.get(&w.addr).copied(),
                off_value(w.addr),
                "0x{:08x}",
                w.addr
            );
        }
    }

    #[test]
    fn every_layer_names_itself_from_the_magic_table() {
        for spec in &MAGICS {
            assert_eq!(spec.group.name(), spec.name);
            assert_eq!(magic_spec(spec.group), *spec);
        }
        for word in &TABLE {
            magic_spec(word.magic);
        }
        for rule in &REQUIRES {
            assert!(find_word(rule.word).is_some() && find_word(rule.needs).is_some());
        }
    }
}
