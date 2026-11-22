//! Modem feature flags for a confirmed boot of a staged modem firmware image.
//!
//! The N4 image (see docs/tk-boot-loader.md) boots with every feature off.
//! Two words in modem RAM turn its latency fixes on:
//!
//! - `0x847ed604`, the feature flags: `0x5` is AQM v2 (uplink queue control),
//!   `0x10` is the grant-hold rescue. Only bits `0x15` may be set.
//! - `0x84f93008`, the grant-hold size in bytes (`0x140` fits a 228-byte ping).
//!
//! The operator lists the writes in `tk/config` as `wm=<addr>:<value>` lines.
//! After the keeper confirms a staged boot, it writes them through a modem
//! console (DM) session and reads each one back in that same session.
//!
//! Guards:
//! - Only addresses on `ALLOWED` and values inside their limits are written.
//! - Nothing is written unless `vm 0x847ed600 4` shows the N4 patch magic in the
//!   same session (`tk_boot::flag_writes_allowed`). Stock firmware keeps other
//!   data there. The magic appears only after the first uplink transport block,
//!   so the keeper waits and asks again until it shows.
//! - A write counts only when its read-back matches. A console left in logging
//!   mode by `quit 1` ignores input with no error, so every write session first
//!   sends `quit 0` and `dbg revert`.
//! - After `MAX_ATTEMPTS` failed sessions the keeper writes 0 to every word it
//!   manages (again only with the magic present) and stops until the next modem
//!   restart it sees.
//! - Nothing here runs on a stock boot: the keeper builds a `Control` only for
//!   a boot it confirmed for a staged image.
use crate::tk_boot::{self, BootStatus, MAGIC_ADDR, Source};

/// The feature flags word.
pub const FLAGS_ADDR: u32 = 0x847e_d604;
/// The grant-hold size word, in bytes.
pub const HOLD_ADDR: u32 = 0x84f9_3008;
/// Every word the keeper may write, in the order it writes them when turning
/// features on: the hold size first, the flags last.
pub const ALLOWED: [u32; 2] = [HOLD_ADDR, FLAGS_ADDR];
/// AQM v2 (`0x1 | 0x4`) and the grant-hold rescue (`0x10`). Bits `0x2` and
/// `0x8` exist in the image and must stay off.
pub const FLAG_BITS: u32 = 0x15;
/// Largest grant-hold size accepted. The bench tried `0x80` to `0x140`.
pub const HOLD_MAX: u32 = 0x200;

/// Failed write sessions before the keeper gives up.
pub const MAX_ATTEMPTS: u32 = 3;
/// Seconds between a failed session and the next try.
pub const RETRY_SECS: u64 = 20;
/// First wait for the patch magic. It doubles up to `MAGIC_MAX`.
pub const MAGIC_FIRST: u64 = 15;
pub const MAGIC_MAX: u64 = 600;
/// Seconds between read-only checks once the flags hold.
pub const CHECK_EVERY: u64 = 600;
/// Seconds after a modem restart before the first try.
pub const AFTER_RESTART: u64 = 30;
/// Read-only checks without a console reply before a full write session
/// (which resets the console first).
pub const CHECK_MISSES: u32 = 3;

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

/// The value is inside the limit for its word.
pub fn value_ok(addr: u32, value: u32) -> bool {
    match addr {
        FLAGS_ADDR => value & !FLAG_BITS == 0,
        HOLD_ADDR => value <= HOLD_MAX,
        _ => false,
    }
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

/// The `wm=` lines of `tk/config`.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Parsed {
    /// One write per allowed word, in `ALLOWED` order. The last line for a
    /// word wins.
    pub writes: Vec<Write>,
    /// Lines that were not used, as written.
    pub refused: Vec<String>,
}

/// `wm=0x847ed604:0x15`. The address must be on `ALLOWED` and written in hex.
/// The value is hex (`0x`) or decimal and must be inside its word's limit.
pub fn parse_writes(config: &str) -> Parsed {
    let mut parsed = Parsed::default();
    let mut found: Vec<Write> = Vec::new();
    for line in config.lines() {
        let Some(rest) = line.trim_start().strip_prefix("wm=") else {
            continue;
        };
        let text: String = rest
            .split('#')
            .next()
            .unwrap_or("")
            .chars()
            .filter(|c| !c.is_whitespace())
            .collect();
        let write = text.split_once(':').and_then(|(addr, value)| {
            let addr = if addr.starts_with("0x") || addr.starts_with("0X") {
                number(addr)?
            } else {
                return None;
            };
            let value = number(value)?;
            (ALLOWED.contains(&addr) && value_ok(addr, value)).then_some(Write { addr, value })
        });
        match write {
            Some(write) => {
                found.retain(|w| w.addr != write.addr);
                found.push(write);
            }
            None => parsed.refused.push(line.trim().to_owned()),
        }
    }
    for addr in ALLOWED {
        if let Some(write) = found.iter().find(|w| w.addr == addr) {
            parsed.writes.push(*write);
        }
    }
    parsed
}

/// `enabled=1` in `tk/config` (the last `enabled=` line, comments removed).
pub fn enabled(config: &str) -> bool {
    let mut on = false;
    for line in config.lines() {
        if let Some(rest) = line.strip_prefix("enabled=") {
            let value: String = rest
                .split('#')
                .next()
                .unwrap_or("")
                .chars()
                .filter(|c| !c.is_whitespace())
                .collect();
            on = value == "1";
        }
    }
    on
}

/// What the keeper wants in modem RAM, from `tk/config` and what it managed
/// before. With the loader turned off or the `wm=` lines removed, every word
/// it managed goes back to 0.
pub fn wanted(config: &str, managed: &[Write]) -> Vec<Write> {
    let writes = parse_writes(config).writes;
    if enabled(config) && !writes.is_empty() {
        let mut all = writes;
        // A word dropped from the config goes back to 0.
        for old in managed {
            if !all.iter().any(|w| w.addr == old.addr) {
                all.push(Write {
                    addr: old.addr,
                    value: 0,
                });
            }
        }
        return in_allowed_order(all);
    }
    zeros(managed)
}

fn in_allowed_order(writes: Vec<Write>) -> Vec<Write> {
    let mut ordered = Vec::new();
    for addr in ALLOWED {
        if let Some(write) = writes.iter().find(|w| w.addr == addr) {
            ordered.push(*write);
        }
    }
    ordered
}

pub fn zeros(writes: &[Write]) -> Vec<Write> {
    writes
        .iter()
        .map(|w| Write {
            addr: w.addr,
            value: 0,
        })
        .collect()
}

/// The order the `wm` lines go out: anything turned off first (the flags
/// before the hold size they use), then the rest in `ALLOWED` order (the hold
/// size before the flags).
pub fn write_order(writes: &[Write]) -> Vec<Write> {
    let mut ordered = writes.to_vec();
    ordered.sort_by_key(|w| {
        let position = ALLOWED
            .iter()
            .position(|a| *a == w.addr)
            .unwrap_or(ALLOWED.len());
        if w.value == 0 {
            (false, ALLOWED.len() - position)
        } else {
            (true, position)
        }
    });
    ordered
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
            let offsets: Option<Vec<usize>> = words
                .iter()
                .map(|w| {
                    (w.len() == 2)
                        .then(|| u8::from_str_radix(w, 16).ok())
                        .flatten()
                        .map(usize::from)
                })
                .collect();
            if let Some(offsets) = offsets {
                let mut sorted = offsets.clone();
                sorted.sort_unstable();
                if sorted.len() >= 4 && sorted.iter().enumerate().all(|(i, v)| i == *v) {
                    order = Some(offsets);
                }
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

pub fn read_cmd(addr: u32) -> String {
    format!("vm 0x{addr:08x} 4")
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
    /// Reset the console, check the magic, write what differs, read back.
    Apply,
    /// Read only: the magic and every word.
    Check,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Outcome {
    /// The magic read printed no dump: a console in logging mode, a modem
    /// that is not up, or no console at all.
    NoReply,
    /// The magic read printed other bytes: stock firmware, or the patch has
    /// not run yet. Nothing was written.
    NoMagic,
    /// Every word read back as wanted. `wrote` counts the `wm` lines sent.
    Verified { wrote: usize },
    /// Check only: a word read back other than wanted, or not at all.
    Differs {
        addr: u32,
        wanted: u32,
        got: Option<u32>,
    },
    /// A write's read-back was missing or wrong.
    Unverified {
        addr: u32,
        wanted: u32,
        got: Option<u32>,
    },
    /// Another console session was open; nothing was sent.
    Busy,
}

/// One session. Returns the outcome and whether any `wm` line went out.
pub fn run_session(
    console: &mut dyn Console,
    writes: &[Write],
    session: Session,
) -> (Outcome, bool) {
    let mut sent = false;
    console.command("arm1log 2");
    if session == Session::Apply {
        // Leave logging mode (`quit 1`) and drop leftover debug categories,
        // or the console silently ignores what follows.
        console.command("quit 0");
        console.command("dbg revert");
    }
    let outcome = session_body(console, writes, session, &mut sent);
    console.command("arm1log 1");
    (outcome, sent)
}

fn session_body(
    console: &mut dyn Console,
    writes: &[Write],
    session: Session,
    sent: &mut bool,
) -> Outcome {
    let magic = console.command(&read_cmd(MAGIC_ADDR));
    if tk_boot::vm_bytes(&magic, MAGIC_ADDR).is_none() {
        return Outcome::NoReply;
    }
    if !tk_boot::flag_writes_allowed(&magic) {
        return Outcome::NoMagic;
    }
    let mut need = Vec::new();
    for write in writes {
        if !ALLOWED.contains(&write.addr) || !value_ok(write.addr, write.value) {
            // Never reached through `parse_writes`; refuse anyway.
            return Outcome::Unverified {
                addr: write.addr,
                wanted: write.value,
                got: None,
            };
        }
        let got = vm_word(&console.command(&read_cmd(write.addr)), write.addr);
        if got != Some(write.value) {
            if session == Session::Check {
                return Outcome::Differs {
                    addr: write.addr,
                    wanted: write.value,
                    got,
                };
            }
            need.push(*write);
        }
    }
    if need.is_empty() {
        return Outcome::Verified { wrote: 0 };
    }
    let ordered = write_order(&need);
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
    Outcome::Verified {
        wrote: ordered.len(),
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum State {
    /// A write session is due.
    Pending,
    /// The patch magic has not shown yet.
    WaitingMagic,
    /// Every word read back as wanted. Read-only checks follow.
    Applied,
    /// Giving up: writing 0 to every managed word.
    Zeroing,
    /// Gave up until the next modem restart.
    Failed,
}

impl State {
    pub fn name(self) -> &'static str {
        match self {
            State::Pending => "pending",
            State::WaitingMagic => "waiting-magic",
            State::Applied => "applied",
            State::Zeroing => "zeroing",
            State::Failed => "failed",
        }
    }
}

/// The next session the keeper should run.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Plan {
    pub session: Session,
    pub writes: Vec<Write>,
}

/// The flag writes for one confirmed boot. `now` is the keeper's monotonic
/// clock in seconds.
#[derive(Clone, Debug)]
pub struct Control {
    wanted: Vec<Write>,
    state: State,
    attempts: u32,
    check_misses: u32,
    next_at: u64,
    magic_wait: u64,
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
        Self {
            wanted,
            state: State::Pending,
            attempts: 0,
            check_misses: 0,
            next_at: now,
            magic_wait: MAGIC_FIRST,
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

    /// The session to run now, if one is due.
    pub fn due(&self, now: u64) -> Option<Plan> {
        if now < self.next_at || self.wanted.is_empty() {
            return None;
        }
        let (session, writes) = match self.state {
            State::Pending | State::WaitingMagic => (Session::Apply, self.wanted.clone()),
            State::Applied => (Session::Check, self.wanted.clone()),
            State::Zeroing => (Session::Apply, zeros(&self.wanted)),
            State::Failed => return None,
        };
        Some(Plan { session, writes })
    }

    /// The operator changed `tk/config`. A real change starts a write session
    /// now and clears the failure count. Returns a log line.
    pub fn set_wanted(&mut self, wanted: Vec<Write>, now: u64) -> Option<String> {
        if wanted == self.wanted {
            return None;
        }
        let line = format!(
            "tk flags: tk/config changed: writing {} (was {})",
            list(&wanted),
            list(&self.wanted)
        );
        self.wanted = wanted;
        self.state = State::Pending;
        self.attempts = 0;
        self.check_misses = 0;
        self.magic_wait = MAGIC_FIRST;
        self.next_at = now;
        self.detail = "tk/config changed; a write session is due".into();
        Some(line)
    }

    /// The keeper saw a modem firmware load after it started. Modem RAM is
    /// fresh, and the modem may now run stock firmware (a crash reloads NAND).
    pub fn modem_restarted(&mut self, now: u64) -> String {
        self.state = State::Pending;
        self.attempts = 0;
        self.check_misses = 0;
        self.magic_wait = MAGIC_FIRST;
        self.ever_wrote = false;
        self.next_at = now.saturating_add(AFTER_RESTART);
        self.detail = "modem restart seen; writing again once the patch magic shows".into();
        "tk flags: modem restart seen; the flags are written again once the patch magic shows (a crash reload runs stock firmware, which never shows it)".into()
    }

    /// A session finished. Returns a log line when there is news.
    pub fn finished(
        &mut self,
        now: u64,
        plan: &Plan,
        outcome: &Outcome,
        sent: bool,
    ) -> Option<String> {
        self.ever_wrote |= sent;
        let was = self.state;
        if was == State::Zeroing {
            self.state = State::Failed;
            self.detail = match outcome {
                Outcome::Verified { .. } => {
                    format!("gave up after {MAX_ATTEMPTS} failed sessions; flags read back 0")
                }
                Outcome::NoMagic => {
                    "gave up; the patch magic is gone, so nothing more was written".into()
                }
                Outcome::Busy => {
                    // Try the zero writes again.
                    self.state = State::Zeroing;
                    self.next_at = now.saturating_add(RETRY_SECS);
                    return None;
                }
                other => format!(
                    "gave up after {MAX_ATTEMPTS} failed sessions; flags NOT confirmed at 0 ({})",
                    describe(other)
                ),
            };
            return Some(format!("tk flags: {}", self.detail));
        }
        match outcome {
            Outcome::Busy => {
                self.next_at = now.saturating_add(RETRY_SECS);
                None
            }
            Outcome::Verified { wrote } => {
                self.state = State::Applied;
                self.attempts = 0;
                self.check_misses = 0;
                self.magic_wait = MAGIC_FIRST;
                self.next_at = now.saturating_add(CHECK_EVERY);
                self.detail = format!("read back {}", list(&plan.writes));
                if was == State::Applied && *wrote == 0 {
                    return None;
                }
                let how = if *wrote == 0 {
                    "already set"
                } else {
                    "written"
                };
                Some(format!(
                    "tk flags: {how} and read back: {}",
                    list(&plan.writes)
                ))
            }
            Outcome::Differs { addr, wanted, got } => {
                self.state = State::Pending;
                self.attempts = 0;
                self.check_misses = 0;
                self.next_at = now;
                self.detail = format!(
                    "0x{addr:08x} read back {}, wanted 0x{wanted:x}; writing again",
                    got_text(*got)
                );
                Some(format!("tk flags: {}", self.detail))
            }
            Outcome::NoMagic => {
                let line = (was != State::WaitingMagic).then(|| {
                    if was == State::Applied {
                        "tk flags: the patch magic is gone (the modem restarted onto stock firmware?); nothing written".to_owned()
                    } else {
                        "tk flags: waiting for the N4 patch magic at 0x847ed600 (it shows after the first uplink transport block); nothing written".to_owned()
                    }
                });
                self.state = State::WaitingMagic;
                self.next_at = now.saturating_add(self.magic_wait);
                self.magic_wait = (self.magic_wait.saturating_mul(2)).min(MAGIC_MAX);
                self.detail = "waiting for the N4 patch magic; nothing written".into();
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
                    self.detail =
                        "no console reply to read-only checks; resetting the console".into();
                    return Some(format!("tk flags: {}", self.detail));
                }
                None
            }
            Outcome::NoReply | Outcome::Unverified { .. } => {
                self.attempts += 1;
                let why = describe(outcome);
                if self.attempts >= MAX_ATTEMPTS {
                    if self.ever_wrote {
                        self.state = State::Zeroing;
                        self.next_at = now.saturating_add(RETRY_SECS);
                        self.detail = format!("giving up ({why}); writing 0 to every managed word");
                    } else {
                        self.state = State::Failed;
                        self.detail = format!(
                            "gave up after {MAX_ATTEMPTS} sessions ({why}); nothing was written, flags stay 0"
                        );
                    }
                    return Some(format!("tk flags: {}", self.detail));
                }
                self.state = State::Pending;
                self.next_at = now.saturating_add(RETRY_SECS);
                self.detail = format!("session {} of {MAX_ATTEMPTS} failed: {why}", self.attempts);
                Some(format!(
                    "tk flags: {}; trying again in {RETRY_SECS} s",
                    self.detail
                ))
            }
        }
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

pub fn describe(outcome: &Outcome) -> String {
    match outcome {
        Outcome::NoReply => "no console reply to the magic read".into(),
        Outcome::NoMagic => "no patch magic".into(),
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

    const HEADER: &str = "           | 03 02 01 00  07 06 05 04  0B 0A 09 08  0F 0E 0D 0C";

    fn dump(addr: u32, shown: &str) -> String {
        format!(
            "\n----------------------------------------------------------------------------\n HEX DUMP  | 4(0x4) Bytes @ 0x{addr:08X}\n----------------------------------------------------------------------------\n{HEADER}\n----------------------------------------------------------------------------\n\u{1b}[1;32m0x{addr:08X}\u{1b}[0m | {shown}  .. .. .. ..  .. .. .. ..  .. .. .. .. \n----------------------------------------------------------------------------\nDM> "
        )
    }

    /// Show a word the way the unit's console does: most significant first.
    fn shown(value: u32) -> String {
        let b = value.to_be_bytes();
        format!("{:02x} {:02x} {:02x} {:02x}", b[0], b[1], b[2], b[3])
    }

    /// A fake modem console with RAM, the patch magic and a logging-mode trap.
    struct Fake {
        ram: std::collections::HashMap<u32, u32>,
        magic: bool,
        logging: bool,
        /// `wm` lines that change nothing (a write that does not stick).
        broken: bool,
        sent: Vec<String>,
    }

    impl Fake {
        fn new(magic: bool) -> Self {
            Self {
                ram: Default::default(),
                magic,
                logging: false,
                broken: false,
                sent: Vec::new(),
            }
        }
    }

    impl Console for Fake {
        fn command(&mut self, line: &str) -> String {
            self.sent.push(line.to_owned());
            if line == "quit 0" {
                self.logging = false;
                return "\nDM> ".into();
            }
            if self.logging {
                return String::new();
            }
            let words: Vec<&str> = line.split_whitespace().collect();
            match words.as_slice() {
                ["vm", addr, "4"] => {
                    let addr = u32::from_str_radix(addr.trim_start_matches("0x"), 16).unwrap();
                    if addr == MAGIC_ADDR {
                        let text = if self.magic {
                            "4e 34 56 32".to_owned()
                        } else {
                            "00 00 00 00".to_owned()
                        };
                        return dump(addr, &text);
                    }
                    dump(addr, &shown(*self.ram.get(&addr).unwrap_or(&0)))
                }
                ["wm", addr, value] => {
                    let addr = u32::from_str_radix(addr.trim_start_matches("0x"), 16).unwrap();
                    let value = u32::from_str_radix(value.trim_start_matches("0x"), 16).unwrap();
                    if !self.broken {
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
    fn only_the_two_bench_words_are_allowed() {
        assert_eq!(ALLOWED, [0x84f9_3008, 0x847e_d604]);
        for flags in [0, 0x1, 0x4, 0x5, 0x10, 0x15] {
            assert!(value_ok(FLAGS_ADDR, flags), "{flags:#x}");
        }
        for flags in [0x2, 0x8, 0x17, 0x1f, 0x20, u32::MAX] {
            assert!(!value_ok(FLAGS_ADDR, flags), "{flags:#x}");
        }
        assert!(
            value_ok(HOLD_ADDR, 0) && value_ok(HOLD_ADDR, 0x140) && value_ok(HOLD_ADDR, HOLD_MAX)
        );
        assert!(!value_ok(HOLD_ADDR, HOLD_MAX + 1));
        assert!(!value_ok(MAGIC_ADDR, 0));
    }

    #[test]
    fn turning_off_or_dropping_lines_writes_zero() {
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
    }

    #[test]
    fn the_hold_goes_in_before_the_flags_and_off_goes_first() {
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
        assert_eq!(outcome, Outcome::NoMagic);
        assert!(!sent);
        assert!(fake.ram.is_empty());
        assert!(!fake.sent.iter().any(|l| l.starts_with("wm ")));
        assert_eq!(fake.sent.last().map(String::as_str), Some("arm1log 1"));
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
        assert!(fake.ram.is_empty());
    }

    fn drive(control: &mut Control, fake: &mut Fake, now: u64) -> Option<String> {
        let plan = control.due(now)?;
        let (outcome, sent) = run_session(fake, &plan.writes, plan.session);
        control.finished(now, &plan, &outcome, sent)
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
        fake.magic = true;
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
        assert!(fake.ram.is_empty());
    }

    #[test]
    fn three_failures_write_zero_and_stop() {
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
        assert_eq!(plan.writes, zeros(&n4()));
        // The broken writes never changed RAM, so the zeros read back as 0.
        let line = drive(&mut control, &mut fake, now).unwrap();
        assert!(line.contains("flags read back 0"), "{line}");
        assert_eq!(control.state(), State::Failed);
        assert_eq!(control.due(now + 100_000), None);
        assert!(control.status(now).starts_with("state=failed\n"));
    }

    #[test]
    fn a_silent_console_gives_up_without_writing() {
        let mut control = Control::new(n4(), 0);
        // `quit 0` would fix a console in logging mode; this one is dead.
        struct Dead;
        impl Console for Dead {
            fn command(&mut self, _: &str) -> String {
                String::new()
            }
        }
        let mut now = 0;
        for _ in 0..MAX_ATTEMPTS {
            let plan = control.due(now).unwrap();
            let (outcome, sent) = run_session(&mut Dead, &plan.writes, plan.session);
            assert_eq!(outcome, Outcome::NoReply);
            assert!(!sent);
            control.finished(now, &plan, &outcome, sent);
            now += RETRY_SECS;
        }
        assert_eq!(control.state(), State::Failed);
        assert!(
            control.detail().contains("nothing was written"),
            "{}",
            control.detail()
        );
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
        fake.magic = false;
        fake.ram.clear();
        drive(&mut control, &mut fake, 1000 + AFTER_RESTART);
        assert_eq!(control.state(), State::WaitingMagic);
        assert!(fake.ram.is_empty());
        // Even a failed control starts again after a restart.
        let mut failed = Control::new(n4(), 0);
        failed.state = State::Failed;
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
}
