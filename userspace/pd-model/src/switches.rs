//! The off switches for Witcher's default-on latency features (v1.0.17).
//!
//! `/mnt/titan-api/latency/config` holds one line per feature. The keeper
//! reads it, and the web service's Latency screen reads and writes it, so the
//! file is the one place the choice lives:
//!
//! ```text
//! modem=on      # upload latency and AQM: the modem words, the Rust PIE included
//! clamp=on      # the download clamp (titan_qctrl)
//! fastpath=on   # the passthrough fast path (titan_k1fp)
//! ```
//!
//! A missing file or line means on. `off`, `0`, `no` or `false` turns a
//! feature off, live: the keeper writes the modem words back to their off
//! values, and the clamp and the fast path to mode 0. Any other value also
//! means off, because a line is only ever written to change a default, and
//! the keeper logs it. The last line for a key wins; `#` starts a comment.
//!
//! The web service builds a copy of this module, so both read the file the
//! same way; both copies run these tests.

/// Where the file lives on the Witcher volume, under `/mnt/titan-api`.
pub const DIR: &str = "latency";

/// The three features, in the file's order: key and what it controls.
pub const KEYS: [(&str, &str); 3] = [
    (
        "modem",
        "upload latency and AQM (the modem words, the Rust PIE included)",
    ),
    ("clamp", "the download clamp"),
    ("fastpath", "the passthrough fast path"),
];

/// Where a default-on feature's settings came from, for its status line.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Source {
    /// Its switch is off in `latency/config`.
    Off,
    /// The operator's own config file for the feature.
    Operator,
    /// The firmware default.
    Default,
    /// The firmware default stands aside, for this reason.
    Aside(&'static str),
}

impl Source {
    /// Words for a status line; `key` is the switch, `file` the operator's file.
    pub fn describe(self, key: &str, file: &str) -> String {
        match self {
            Source::Off => format!("{key}=off in latency/config"),
            Source::Operator => file.to_owned(),
            Source::Default => "the firmware default".to_owned(),
            Source::Aside(why) => format!("the default stands aside: {why}"),
        }
    }
}

/// Each feature's switch.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Switches {
    pub modem: bool,
    pub clamp: bool,
    pub fastpath: bool,
    /// Lines that were not understood, as written. Each one that names a
    /// feature turned it off.
    pub refused: Vec<String>,
}

impl Default for Switches {
    fn default() -> Self {
        Self {
            modem: true,
            clamp: true,
            fastpath: true,
            refused: Vec::new(),
        }
    }
}

impl Switches {
    fn slot(&mut self, key: &str) -> Option<&mut bool> {
        match key {
            "modem" => Some(&mut self.modem),
            "clamp" => Some(&mut self.clamp),
            "fastpath" => Some(&mut self.fastpath),
            _ => None,
        }
    }

    /// The switches as `on`/`off` words, in `KEYS` order, for a log line.
    pub fn describe(&self) -> String {
        let word = |on: bool| if on { "on" } else { "off" };
        format!(
            "modem {}, clamp {}, fastpath {}",
            word(self.modem),
            word(self.clamp),
            word(self.fastpath)
        )
    }

    /// The same three switches, ignoring `refused`.
    pub fn same_as(&self, other: &Self) -> bool {
        (self.modem, self.clamp, self.fastpath) == (other.modem, other.clamp, other.fastpath)
    }
}

fn value(text: &str) -> Option<bool> {
    match text {
        "on" | "1" | "yes" | "true" => Some(true),
        "off" | "0" | "no" | "false" => Some(false),
        _ => None,
    }
}

/// The switches in `text`. Spaces and case do not matter.
pub fn parse(text: &str) -> Switches {
    let mut switches = Switches::default();
    for raw in text.lines() {
        let line: String = raw
            .split('#')
            .next()
            .unwrap_or("")
            .chars()
            .filter(|c| !c.is_whitespace())
            .collect::<String>()
            .to_ascii_lowercase();
        if line.is_empty() {
            continue;
        }
        let (key, text) = line.split_once('=').unwrap_or((line.as_str(), ""));
        let parsed = value(text);
        match switches.slot(key) {
            Some(slot) => *slot = parsed.unwrap_or(false),
            None => {
                switches.refused.push(raw.trim().to_owned());
                continue;
            }
        }
        if parsed.is_none() {
            switches.refused.push(raw.trim().to_owned());
        }
    }
    switches
}

/// The file for these switches, as the web service writes it.
pub fn render(switches: &Switches) -> String {
    let word = |on: bool| if on { "on" } else { "off" };
    format!(
        "# Witcher latency features (docs/latency-switches.md). on is the default.\n\
         modem={}\nclamp={}\nfastpath={}\n",
        word(switches.modem),
        word(switches.clamp),
        word(switches.fastpath)
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn set(modem: bool, clamp: bool, fastpath: bool) -> (bool, bool, bool) {
        (modem, clamp, fastpath)
    }

    fn of(s: &Switches) -> (bool, bool, bool) {
        (s.modem, s.clamp, s.fastpath)
    }

    #[test]
    fn everything_is_on_without_a_file_or_a_line() {
        assert_eq!(parse(""), Switches::default());
        assert_eq!(of(&parse("# nothing to change\n\n")), set(true, true, true));
        assert_eq!(of(&parse("clamp=off\n")), set(true, false, true));
    }

    #[test]
    fn each_line_turns_its_feature_off_and_the_last_line_wins() {
        assert_eq!(
            of(&parse("modem=off\nclamp=0\nfastpath=no\n")),
            set(false, false, false)
        );
        assert_eq!(
            of(&parse("Modem = OFF # gone\nmodem=on\n")),
            set(true, true, true)
        );
        assert_eq!(
            of(&parse("fastpath=false\nclamp=yes\n")),
            set(true, true, false)
        );
        assert!(
            parse("modem=off\nclamp=0\nfastpath=no\n")
                .refused
                .is_empty()
        );
    }

    #[test]
    fn an_unreadable_value_turns_its_feature_off_and_is_reported() {
        let s = parse("clamp=maybe\nmodem\nturbo=on\n");
        assert_eq!(of(&s), set(false, false, true));
        assert_eq!(s.refused, ["clamp=maybe", "modem", "turbo=on"]);
    }

    #[test]
    fn the_rendered_file_reads_back_as_written() {
        for bits in 0..8u8 {
            let s = Switches {
                modem: bits & 1 != 0,
                clamp: bits & 2 != 0,
                fastpath: bits & 4 != 0,
                refused: Vec::new(),
            };
            assert_eq!(parse(&render(&s)), s);
        }
        assert_eq!(
            render(&Switches::default()),
            "# Witcher latency features (docs/latency-switches.md). on is the default.\nmodem=on\nclamp=on\nfastpath=on\n"
        );
        assert_eq!(
            parse("clamp=off").describe(),
            "modem on, clamp off, fastpath on"
        );
        assert!(parse("clamp=off\n").same_as(&parse("clamp = off # again\nturbo=1\n")));
    }
}
