//! The vendor SAS client's log (`/mnt/cbrslog0.txt`), read for shadow mode.
//!
//! In shadow mode the vendor client stays in charge. This reader turns its
//! log lines into events, so the engine can be shown the same radio changes
//! and the same SAS trouble and its decisions compared with the vendor's.
use crate::proto::Kind;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Outcome {
    Code(i64),
    /// No connection, or no answer in the vendor's 6 seconds.
    NoAnswer,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Event {
    /// The radio came up on the carriers in this mask.
    Online(u32),
    Offline,
    Call(Kind, Outcome),
    /// The vendor opened or blocked customer traffic.
    Traffic(bool),
}

fn call_kind(name: &str) -> Option<Kind> {
    let name = name.trim_end_matches(|c: char| c.is_ascii_digit());
    Some(match name {
        "Registration" => Kind::Registration,
        "Deregistration" => Kind::Deregistration,
        "SpectrumInquiry" => Kind::SpectrumInquiry,
        "Grant" => Kind::Grant,
        "Heartbeat" => Kind::Heartbeat,
        "Relinquish" => Kind::Relinquishment,
        _ => return None,
    })
}

/// The time on a stamp line (`2026-11-22 05:21:58 UTC (L1/P0/R1/G0)`), as
/// Unix seconds. The lines after a stamp happened at that time.
pub fn parse_stamp(line: &str) -> Option<u64> {
    let mut words = line.split_whitespace();
    let date = words.next()?;
    let time = words.next()?;
    if words.next()? != "UTC" {
        return None;
    }
    crate::proto::parse_utc(&format!("{date}T{time}Z"))
}

/// One log line, or `None` when it carries nothing the shadow needs.
pub fn parse_line(line: &str) -> Option<Event> {
    let text = line.trim().strip_prefix("=(CBRS):")?.trim();
    if let Some(rest) = text
        .strip_prefix("Radio Connected on Channel(0x")
        .or_else(|| text.strip_prefix("Radio Online on Channel(0x"))
    {
        let digits = rest.split(')').next()?;
        return u32::from_str_radix(digits, 16).ok().map(Event::Online);
    }
    if text.starts_with("Radio Offline") || text.starts_with("Radio Disconnected") {
        return Some(Event::Offline);
    }
    if text.starts_with("Open Radio Traffic Channel") {
        return Some(Event::Traffic(true));
    }
    if text.starts_with("Block Radio Traffic Channel") {
        return Some(Event::Traffic(false));
    }
    let kind = call_kind(text.split_whitespace().next()?)?;
    if let Some(at) = text.find("responseCode = ") {
        let digits: String = text[at + "responseCode = ".len()..]
            .chars()
            .take_while(char::is_ascii_digit)
            .collect();
        return digits
            .parse()
            .ok()
            .map(|code| Event::Call(kind, Outcome::Code(code)));
    }
    text.contains("Https Error")
        .then_some(Event::Call(kind, Outcome::NoAnswer))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_lines_seen_on_a_bench_unit_parse() {
        assert_eq!(
            parse_line("=(CBRS): Radio Connected on Channel(0x3C00003C)(40Mhz)."),
            Some(Event::Online(0x3C00_003C))
        );
        assert_eq!(
            parse_line("=(CBRS): Grant0 Success!(responseCode = 0)"),
            Some(Event::Call(Kind::Grant, Outcome::Code(0)))
        );
        assert_eq!(
            parse_line("=(CBRS): Grant1 Failed!(responseCode = 401)"),
            Some(Event::Call(Kind::Grant, Outcome::Code(401)))
        );
        assert_eq!(
            parse_line("=(CBRS): Heartbeat Failed!(responseCode = 501)"),
            Some(Event::Call(Kind::Heartbeat, Outcome::Code(501)))
        );
        assert_eq!(
            parse_line("=(CBRS): Relinquish0 Failed! Https Error. "),
            Some(Event::Call(Kind::Relinquishment, Outcome::NoAnswer))
        );
        assert_eq!(
            parse_line("=(CBRS): SpectrumInquiry Https Error."),
            Some(Event::Call(Kind::SpectrumInquiry, Outcome::NoAnswer))
        );
        assert_eq!(
            parse_line("=(CBRS): Open Radio Traffic Channel."),
            Some(Event::Traffic(true))
        );
        assert_eq!(parse_line("=(CBRS): Radio Offline."), Some(Event::Offline));
    }

    #[test]
    fn stamps_state_lines_and_noise_are_skipped() {
        assert_eq!(parse_line("2026-11-22 05:21:58 UTC (L1/P0/R1/G0)"), None);
        assert_eq!(
            parse_stamp("2026-11-22 07:00:44 UTC (L1/P0/R1/G2)"),
            Some(1_795_330_844)
        );
        assert_eq!(parse_stamp("=(CBRS): Radio Offline."), None);
        assert_eq!(parse_line("=0(1):(3560000000-3580000000:27)"), None);
        assert_eq!(parse_line("=(CBRS): SpectrumInquiry Retry Timer..."), None);
        assert_eq!(parse_line("=(CBRS): SSL Time out. Give Up!."), None);
        assert_eq!(parse_line(""), None);
    }
}
