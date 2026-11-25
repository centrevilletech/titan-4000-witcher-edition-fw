//! The default modem image (v1.0.17): on unless an operator says otherwise.
//!
//! A unit with no operator files in `tk/` gets the release image without
//! anyone staging it. `witcher-tk-stage pre` runs `titan-pd-keeper tk-build
//! boot` right before the boot's one `modprobe modem`. The keeper builds the
//! image from the unit's own stock firmware (the bank `/proc/cmdline` names
//! active), writes `tk/active.gz` and a default `tk/config`, and the hook's
//! usual checks then load it for that same `modprobe`. Later boots reuse the
//! file. See docs/tk-boot-loader.md.
//!
//! This module holds the decisions, with no I/O:
//! - who owns `tk/`: an operator, or the firmware (`owner`);
//! - what this boot does: reuse the image, build it, or keep stock (`plan`);
//! - the default config with its marker and checksum (`config_text`), and
//!   the latency profile's words for the release image (`WORDS`);
//! - the build record, which stops a build from repeating (`Record`).
//!
//! Guards:
//! - An operator's `tk/config` always wins: anything but an intact default
//!   config is the operator's, the firmware never rewrites it, and
//!   `enabled=0` there keeps stock firmware.
//! - An `active.gz` with no config is an operator's, or one an operator
//!   turned off by deleting the config: nothing is built over it.
//! - A rollback that waits for its stock verdict, or a quarantine that stuck
//!   (`tk_verdict`), keeps stock firmware and builds nothing, and so does an
//!   unreadable strike count, or one at the limit that this firmware build
//!   counted (boots cut short; the keeper's stock boot judges them).
//! - What another firmware build, or a rollback of another image, left
//!   behind no longer applies (`stale`): the release image's quarantine line,
//!   strikes at the limit and a verdict for another image or build are
//!   cleared at boot (`Plan::Clear`), and the image loads. So a new firmware
//!   always tries the image again, and nothing a network outage left in
//!   older firmware keeps it off. Quarantine lines for other images (an
//!   operator's) are left alone and do not block the default.
//! - A bank that is not the pinned stock image builds nothing, now or on a
//!   later boot of the same release image (`stock-mismatch` is recorded).
//! - Each build is recorded before it starts, so a build that is killed or
//!   loses power still counts. After `MAX_BUILDS` builds of one release
//!   image nothing is built for it again.
use crate::sha256;
use crate::tk_boot::{self, STRIKE_LIMIT};
use crate::tk_verdict::Verdict;

/// The first line of a config the firmware wrote, followed by the manifest
/// name and the SHA-256 of the rest of the file.
pub const MARKER: &str = "# witcher-default ";
/// Builds of one release image before the firmware stops trying.
pub const MAX_BUILDS: u32 = 3;

/// The latency profile for the release image (N6H + R4's Rust N4 + R1's
/// PIE), in the order `scripts/stage-latency.sh --profile latency` writes it
/// for that image: grant hold `0x140`, N4 AQM v2 and the hold rescue
/// (`0x15`), G1A, G1B, G1C, TK1, N5 PDCP staging 8/12 KiB and both N5 flags,
/// U2's LNK-FIX filter, and the Rust PIE selector last. CI compares the two
/// on the real image (scripts/test-tk-build.py).
pub const WORDS: [(u32, u32); 11] = [
    (0x84f9_3008, 0x140),
    (0x847e_d604, 0x15),
    (0x847e_d548, 0x1),
    (0x847e_d54c, 0x1),
    (0x847e_d550, 0x1),
    (0x847e_cf08, 0x1),
    (0x8448_9a84, 0x2000),
    (0x8448_9a88, 0x3000),
    (0x8448_9a6c, 0x3),
    (0x8418_ff08, 0x1),
    (0x841b_5908, 0x1),
];

/// Who decides what `tk/` holds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Owner {
    /// The hook's usual checks decide; the firmware writes nothing.
    Operator,
    /// The default image: the firmware may build and replace it.
    Firmware,
}

/// What this boot does with the default image.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Plan {
    /// The release image is in place: load it.
    Ready,
    /// Build the release image, then load it.
    Build,
    /// Clear what no longer applies (`stale`, `clear`), then plan again.
    Clear,
    /// Keep stock modem firmware, for this reason (the hook's `reason=`).
    Stock(&'static str),
}

/// The default config for the release image `name` whose gzip SHA-256 is
/// `gzip`: the marker line, then the body it checksums.
pub fn config_text(name: &str, gzip: &str) -> String {
    let mut body = String::from(
        "# Built at boot from this unit's own stock modem firmware (docs/tk-boot-loader.md).\n\
         # Edit any line and this config is yours: no firmware rewrites it. enabled=0 keeps\n\
         # stock modem firmware from the next boot; modem=off in latency/config turns the words off now.\n\
         enabled=1\n",
    );
    body.push_str(&format!("sha256={gzip}\n"));
    for (addr, value) in WORDS {
        body.push_str(&format!("wm=0x{addr:08x}:0x{value:x}\n"));
    }
    format!("{MARKER}{name} {}\n{body}", sha256::hex(&sha256::digest(body.as_bytes())))
}

/// The image hash an intact default config allows: its marker names the
/// manifest, and the checksum covers every byte after the marker line. Any
/// edit makes the config an operator's.
pub fn default_sha(config: &str) -> Option<String> {
    let rest = config.strip_prefix(MARKER)?;
    let (first, body) = rest.split_once('\n')?;
    let mut words = first.split(' ');
    let (_name, sum) = (words.next().filter(|n| !n.is_empty())?, words.next()?);
    if words.next().is_some() || sum != sha256::hex(&sha256::digest(body.as_bytes())) {
        return None;
    }
    let sha = body.lines().filter_map(|l| l.strip_prefix("sha256=")).last()?;
    tk_boot::valid_sha(sha).then(|| sha.to_ascii_lowercase())
}

/// Who owns `tk/`, from `config` (when the file exists), whether
/// `active.gz` exists, and the build record.
pub fn owner(config: Option<&str>, image: bool, record: Option<&str>, release: &str) -> Owner {
    match config {
        Some(text) if default_sha(text).is_some() => Owner::Firmware,
        Some(_) => Owner::Operator,
        None if !image => Owner::Firmware,
        // Our own build stopped after the image and before the config.
        None if Record::parse(record.unwrap_or("")).started(release) => Owner::Firmware,
        None => Owner::Operator,
    }
}

/// Everything `plan` reads, for a `tk/` the firmware owns.
#[derive(Clone, Copy, Debug, Default)]
pub struct Inputs<'a> {
    /// `tk/strikes`, `tk/quarantine` and `tk/verdict`, when they exist.
    pub strikes: Option<&'a str>,
    pub quarantine: Option<&'a str>,
    pub verdict: Option<&'a str>,
    /// This firmware build (`tk_boot::firmware_id`).
    pub firmware: &'a str,
    /// `tk/default`, the build record, when it exists.
    pub record: Option<&'a str>,
    /// The release image's gzip SHA-256 (the keeper's built-in manifest).
    pub release: &'a str,
    /// The config is an intact default for `release`, and `active.gz`
    /// hashes to `release`.
    pub cached: bool,
    /// The modem bank this boot runs (`tk_build::active_bank`).
    pub bank: Option<&'a str>,
}

/// What this boot does. The rollback rules come first: a rollback waiting
/// for its stock verdict, a quarantine that stuck, or this build's strikes
/// at the limit keep stock firmware, and nothing is built. What no longer
/// applies is cleared first.
pub fn plan(i: &Inputs<'_>) -> Plan {
    let strikes = i.strikes.map(tk_boot::parse_strikes);
    if matches!(strikes, Some(None)) {
        return Plan::Stock("strikes-unreadable");
    }
    if Verdict::parse(i.verdict.unwrap_or("")).holds(i.release, i.firmware) {
        return Plan::Stock("quarantined");
    }
    if stale(i) {
        return Plan::Clear;
    }
    if strikes.flatten().is_some_and(|n| n >= STRIKE_LIMIT) {
        return Plan::Stock("strikes");
    }
    if i.cached {
        return Plan::Ready;
    }
    let record = Record::parse(i.record.unwrap_or(""));
    if record.gzip == i.release {
        if record.result == "stock-mismatch" {
            return Plan::Stock("stock-mismatch");
        }
        if record.builds >= MAX_BUILDS {
            return Plan::Stock("build-limit");
        }
    }
    if i.bank.is_none() {
        return Plan::Stock("bank-unknown");
    }
    Plan::Build
}

/// Records that no longer apply to the release image under this firmware
/// build: its quarantine line without a verdict that holds it, strikes at the
/// limit that another build (or a firmware before v1.0.17) counted, and a
/// verdict for another image or build. `plan` checks `holds` first, so this
/// never clears a rollback that waits for its verdict or a quarantine that
/// stuck under this build.
pub fn stale(i: &Inputs<'_>) -> bool {
    let listed = i
        .quarantine
        .is_some_and(|text| tk_boot::parse_quarantine(text).iter().any(|q| q.eq_ignore_ascii_case(i.release)));
    let strikes = i.strikes.is_some_and(|text| {
        tk_boot::parse_strikes(text).is_some_and(|n| n >= STRIKE_LIMIT)
            && tk_boot::strikes_firmware(text).as_deref() != Some(i.firmware)
    });
    let verdict = i.verdict.is_some_and(|text| {
        let verdict = Verdict::parse(text);
        !verdict.gzip.is_empty() && !verdict.applies(i.release, i.firmware)
    });
    listed || strikes || verdict
}

/// What `Plan::Clear` writes: the quarantine without the release image's
/// line, strikes at 0 for this build, and whether the verdict goes (one for
/// another image or build). `None` leaves that file as it is.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Cleared {
    pub quarantine: Option<String>,
    pub strikes: Option<String>,
    pub drop_verdict: bool,
}

pub fn clear(i: &Inputs<'_>) -> Cleared {
    let mut cleared = Cleared::default();
    if let Some(text) = i.quarantine {
        if tk_boot::parse_quarantine(text).iter().any(|q| q.eq_ignore_ascii_case(i.release)) {
            cleared.quarantine = Some(tk_boot::remove_quarantine(text, i.release));
        }
    }
    let other_build = i
        .strikes
        .is_some_and(|text| tk_boot::strikes_firmware(text).as_deref() != Some(i.firmware));
    if other_build && i.strikes.and_then(tk_boot::parse_strikes).is_some_and(|n| n >= STRIKE_LIMIT) {
        cleared.strikes = Some(tk_boot::format_strikes(0, i.firmware));
    }
    cleared.drop_verdict = i.verdict.is_some_and(|text| {
        let verdict = Verdict::parse(text);
        !verdict.gzip.is_empty() && !verdict.applies(i.release, i.firmware)
    });
    cleared
}

/// `tk/default`: the release image the last build was for, how many builds
/// of it have started, and how the last one ended (`started` until then).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Record {
    pub gzip: String,
    pub builds: u32,
    pub result: String,
}

impl Record {
    pub fn parse(text: &str) -> Self {
        let mut record = Self::default();
        for line in text.lines() {
            match line.split_once('=') {
                Some(("gzip", v)) => record.gzip = v.trim().to_ascii_lowercase(),
                Some(("builds", v)) => record.builds = v.trim().parse().unwrap_or(MAX_BUILDS),
                Some(("result", v)) => record.result = v.trim().to_owned(),
                _ => {}
            }
        }
        record
    }

    /// A build for `release` started and never recorded an end.
    pub fn started(&self, release: &str) -> bool {
        self.gzip == release && self.result == "started"
    }

    /// The record to write before a build of `release` starts.
    pub fn start(text: &str, release: &str) -> Self {
        let old = Self::parse(text);
        let builds = if old.gzip == release { old.builds.saturating_add(1) } else { 1 };
        Self { gzip: release.to_owned(), builds, result: "started".into() }
    }

    pub fn finish(mut self, result: &str) -> Self {
        self.result = result.to_owned();
        self
    }

    pub fn render(&self) -> String {
        format!("gzip={}\nbuilds={}\nresult={}\n", self.gzip, self.builds, self.result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tk_flags;

    const RELEASE: &str = "3348aa361c4689c4ff18b647a03bfa55cea36bc6675059cd9995e591592e40bb";

    const BUILD: &str = "0123456789abcdef";

    fn inputs<'a>() -> Inputs<'a> {
        Inputs { release: RELEASE, bank: Some("tk2"), firmware: BUILD, ..Inputs::default() }
    }

    #[test]
    fn the_default_config_allows_the_release_image_with_the_latency_profile() {
        let text = config_text("n6h-r4-r1", RELEASE);
        assert!(text.starts_with("# witcher-default n6h-r4-r1 "));
        assert_eq!(default_sha(&text).as_deref(), Some(RELEASE));
        assert!(tk_flags::enabled(&text));
        // The hook reads the same switch and allow-list lines.
        assert_eq!(text.lines().filter(|l| l.starts_with("enabled=")).collect::<Vec<_>>(), ["enabled=1"]);
        let wm: Vec<&str> = text.lines().filter(|l| l.starts_with("wm=")).collect();
        assert_eq!(
            wm,
            [
                "wm=0x84f93008:0x140",
                "wm=0x847ed604:0x15",
                "wm=0x847ed548:0x1",
                "wm=0x847ed54c:0x1",
                "wm=0x847ed550:0x1",
                "wm=0x847ecf08:0x1",
                "wm=0x84489a84:0x2000",
                "wm=0x84489a88:0x3000",
                "wm=0x84489a6c:0x3",
                "wm=0x8418ff08:0x1",
                "wm=0x841b5908:0x1",
            ]
        );
        // Every word passes the keeper's allow-list and rules, and the PIE
        // selector is written after every other word.
        let parsed = tk_flags::parse_writes(&text);
        assert!(parsed.refused.is_empty(), "{:?}", parsed.refused_reasons);
        assert_eq!(parsed.writes.len(), WORDS.len());
        assert_eq!(parsed.writes.last().map(|w| w.addr), Some(0x841b_5908));
        assert!(!parsed.hands_off && !parsed.hold_ack);
    }

    #[test]
    fn any_edit_makes_the_config_the_operators() {
        let text = config_text("n6h-r4-r1", RELEASE);
        for edited in [
            text.replace("enabled=1", "enabled=0"),
            text.replace("wm=0x841b5908:0x1\n", ""),
            format!("{text}target=192.0.2.1\n"),
            text.replacen("# witcher-default ", "# witcher-defaults ", 1),
            text.trim_end().to_owned(),
            text.replacen("n6h-r4-r1 ", "", 1),
            format!("# bench\n{text}"),
        ] {
            assert_eq!(default_sha(&edited), None, "{edited}");
            assert_eq!(owner(Some(&edited), true, None, RELEASE), Owner::Operator);
        }
        assert_eq!(owner(Some(&text), true, None, RELEASE), Owner::Firmware);
        assert_eq!(owner(Some("enabled=0\n"), false, None, RELEASE), Owner::Operator);
    }

    #[test]
    fn an_image_without_a_config_is_left_alone_unless_our_build_stopped_halfway() {
        assert_eq!(owner(None, false, None, RELEASE), Owner::Firmware);
        assert_eq!(owner(None, true, None, RELEASE), Owner::Operator);
        let started = Record::start("", RELEASE).render();
        assert_eq!(owner(None, true, Some(&started), RELEASE), Owner::Firmware);
        let built = Record::start("", RELEASE).finish("built").render();
        assert_eq!(owner(None, true, Some(&built), RELEASE), Owner::Operator, "an operator deleted the config");
        let other = Record::start("", &"cd".repeat(32)).render();
        assert_eq!(owner(None, true, Some(&other), RELEASE), Owner::Operator);
    }

    /// The plan once `Plan::Clear` has written what `clear` says.
    fn plan_after_clear(i: &Inputs<'_>) -> (Plan, Cleared) {
        let cleared = clear(i);
        let quarantine = cleared.quarantine.clone().or(i.quarantine.map(str::to_owned));
        let strikes = cleared.strikes.clone().or(i.strikes.map(str::to_owned));
        let verdict = if cleared.drop_verdict { None } else { i.verdict };
        let next = Inputs { quarantine: quarantine.as_deref(), strikes: strikes.as_deref(), verdict, ..*i };
        (plan(&next), cleared)
    }

    #[test]
    fn this_builds_rollbacks_and_strikes_keep_stock_and_build_nothing() {
        let strikes = |n: u32| tk_boot::format_strikes(n, BUILD);
        let pending = Verdict::default().rolled_back(RELEASE, BUILD).render();
        let quarantine = format!("{RELEASE}\n");
        let held = Inputs { strikes: Some(&strikes(2)), quarantine: Some(&quarantine), verdict: Some(&pending), cached: true, ..inputs() };
        assert_eq!(plan(&held), Plan::Stock("quarantined"));
        let (stuck, _) = Verdict::default().rolled_back(RELEASE, BUILD).judge(true).0.rolled_back(RELEASE, BUILD).judge(true);
        let stuck = stuck.render();
        assert_eq!(plan(&Inputs { verdict: Some(&stuck), ..held }), Plan::Stock("quarantined"));
        // Boots cut short under this build: stock, and its keeper judges them.
        assert_eq!(plan(&Inputs { strikes: Some(&strikes(2)), cached: true, ..inputs() }), Plan::Stock("strikes"));
        assert_eq!(plan(&Inputs { strikes: Some("strikes=lots\n"), cached: true, ..inputs() }), Plan::Stock("strikes-unreadable"));
        assert_eq!(plan(&Inputs { strikes: Some(&strikes(1)), cached: true, ..inputs() }), Plan::Ready);
        // An operator's quarantine of another image does not block the default.
        let other = format!("# keeper\n{}\n", "ab".repeat(32));
        assert_eq!(plan(&Inputs { quarantine: Some(&other), cached: true, ..inputs() }), Plan::Ready);
        assert_eq!(plan(&Inputs { quarantine: Some("# none yet\n"), cached: true, ..inputs() }), Plan::Ready);
    }

    #[test]
    fn a_new_firmware_build_clears_what_an_older_one_left_and_loads_the_image() {
        let old = "fedcba9876543210";
        let (stuck, _) = Verdict::default().rolled_back(RELEASE, old).judge(true).0.rolled_back(RELEASE, old).judge(true);
        let stuck = stuck.render();
        let quarantine = format!("{}\n{RELEASE}\n", "ab".repeat(32));
        let old_strikes = tk_boot::format_strikes(2, old);
        let left = Inputs { strikes: Some(&old_strikes), quarantine: Some(&quarantine), verdict: Some(&stuck), cached: true, ..inputs() };
        assert!(stale(&left));
        assert_eq!(plan(&left), Plan::Clear);
        let (next, cleared) = plan_after_clear(&left);
        assert_eq!(next, Plan::Ready, "the image loads after the clear");
        assert_eq!(cleared.quarantine.as_deref(), Some(format!("{}\n", "ab".repeat(32)).as_str()));
        assert_eq!(cleared.strikes.as_deref(), Some(tk_boot::format_strikes(0, BUILD).as_str()));
        assert!(cleared.drop_verdict);
        // Strikes written before v1.0.17 name no build, and a quarantine line
        // of the release image with no verdict at all is a leftover too.
        for (strikes, quarantine) in [(Some("strikes=2\n"), None), (None, Some(quarantine.as_str()))] {
            let left = Inputs { strikes, quarantine, cached: true, ..inputs() };
            assert_eq!(plan(&left), Plan::Clear);
            assert_eq!(plan_after_clear(&left).0, Plan::Ready);
        }
        // A verdict this build wrote and that holds nothing is kept: its
        // counts and its wait for the network still apply.
        let waiting = Verdict::default().rolled_back(RELEASE, BUILD).judge(false).0.render();
        let kept = Inputs { verdict: Some(&waiting), cached: true, ..inputs() };
        assert!(!stale(&kept));
        assert_eq!(plan(&kept), Plan::Ready);
        // Nothing to clear without the release image's records.
        assert_eq!(clear(&inputs()), Cleared::default());
    }

    #[test]
    fn a_build_runs_once_per_release_and_stops_for_good_on_another_stock_image() {
        assert_eq!(plan(&inputs()), Plan::Build);
        assert_eq!(plan(&Inputs { cached: true, ..inputs() }), Plan::Ready);
        assert_eq!(plan(&Inputs { bank: None, ..inputs() }), Plan::Stock("bank-unknown"));
        let mismatch = Record::start("", RELEASE).finish("stock-mismatch").render();
        assert_eq!(plan(&Inputs { record: Some(&mismatch), ..inputs() }), Plan::Stock("stock-mismatch"));
        // A new release image tries again.
        let new = "ef".repeat(32);
        assert_eq!(plan(&Inputs { record: Some(&mismatch), release: &new, ..inputs() }), Plan::Build);
        // Builds that die (time limit, power) count before they start.
        let mut record = String::new();
        for n in 1..=MAX_BUILDS {
            assert_eq!(plan(&Inputs { record: Some(&record), ..inputs() }), Plan::Build, "build {n}");
            record = Record::start(&record, RELEASE).render();
            assert_eq!(Record::parse(&record).builds, n);
        }
        assert_eq!(plan(&Inputs { record: Some(&record), ..inputs() }), Plan::Stock("build-limit"));
        assert_eq!(plan(&Inputs { record: Some(&record), cached: true, ..inputs() }), Plan::Ready);
        assert_eq!(Record::parse("builds=x\n").builds, MAX_BUILDS, "an unreadable count is spent");
    }
}
