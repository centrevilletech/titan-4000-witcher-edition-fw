//! SAS-CBSD messages (WINNF-TS-0016, protocol v1.2) as JSON.
//!
//! Requests are arrays, so one HTTPS call can carry a heartbeat for every
//! grant the unit holds. Answers come back in the same order.
use serde_json::{Value, json};

use crate::band::Range;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    Registration,
    SpectrumInquiry,
    Grant,
    Heartbeat,
    Relinquishment,
    Deregistration,
}

impl Kind {
    /// The last part of the URL, after the protocol version.
    pub fn method(self) -> &'static str {
        match self {
            Kind::Registration => "registration",
            Kind::SpectrumInquiry => "spectrumInquiry",
            Kind::Grant => "grant",
            Kind::Heartbeat => "heartbeat",
            Kind::Relinquishment => "relinquishment",
            Kind::Deregistration => "deregistration",
        }
    }

    pub fn request_key(self) -> String {
        format!("{}Request", self.method())
    }

    pub fn response_key(self) -> String {
        format!("{}Response", self.method())
    }
}

pub const SUCCESS: i64 = 0;
pub const VERSION: i64 = 100;
pub const BLACKLISTED: i64 = 101;
pub const MISSING_PARAM: i64 = 102;
pub const INVALID_VALUE: i64 = 103;
pub const CERT_ERROR: i64 = 104;
pub const DEREGISTER: i64 = 105;
pub const REG_PENDING: i64 = 200;
pub const UNSUPPORTED_SPECTRUM: i64 = 300;
pub const INTERFERENCE: i64 = 400;
pub const GRANT_CONFLICT: i64 = 401;
pub const TERMINATED_GRANT: i64 = 500;
pub const SUSPENDED_GRANT: i64 = 501;
pub const UNSYNC_OP_PARAM: i64 = 502;

/// One response object, with the fields any procedure may carry.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Item {
    pub code: i64,
    pub message: String,
    pub data: Vec<String>,
    pub cbsd_id: Option<String>,
    pub grant_id: Option<String>,
    pub heartbeat_interval: Option<u64>,
    /// Unix seconds.
    pub grant_expire: Option<u64>,
    /// Unix seconds.
    pub transmit_expire: Option<u64>,
    /// `operationParam`: a range and power the SAS suggests.
    pub suggestion: Option<(Range, f64)>,
    /// `availableChannel` entries from a spectrum inquiry.
    pub available: Vec<(Range, f64)>,
}

fn frequency_range(range: Range) -> Value {
    json!({ "lowFrequency": range.low, "highFrequency": range.high })
}

pub fn envelope(kind: Kind, items: Vec<Value>) -> String {
    let mut body = serde_json::Map::new();
    body.insert(kind.request_key(), Value::Array(items));
    Value::Object(body).to_string()
}

pub fn inquiry_item(cbsd: &str, ranges: &[Range]) -> Value {
    let inquired: Vec<Value> = ranges.iter().map(|range| frequency_range(*range)).collect();
    json!({ "cbsdId": cbsd, "inquiredSpectrum": inquired })
}

/// `max_eirp` is in dBm/MHz, as TS-0016 defines it.
pub fn grant_item(cbsd: &str, range: Range, max_eirp: f64) -> Value {
    json!({
        "cbsdId": cbsd,
        "operationParam": {
            "maxEirp": max_eirp,
            "operationFrequencyRange": frequency_range(range),
        },
    })
}

pub fn heartbeat_item(cbsd: &str, grant: &str, authorized: bool, renew: bool) -> Value {
    let state = if authorized { "AUTHORIZED" } else { "GRANTED" };
    let mut item = json!({ "cbsdId": cbsd, "grantId": grant, "operationState": state });
    if renew {
        item["grantRenew"] = Value::Bool(true);
    }
    item
}

pub fn relinquishment_item(cbsd: &str, grant: &str) -> Value {
    json!({ "cbsdId": cbsd, "grantId": grant })
}

pub fn deregistration_item(cbsd: &str) -> Value {
    json!({ "cbsdId": cbsd })
}

fn hertz(value: &Value) -> Option<u64> {
    value
        .as_u64()
        .or_else(|| value.as_f64().filter(|v| *v >= 0.0).map(|v| v as u64))
}

fn parse_range(value: &Value) -> Option<Range> {
    Range::new(
        hertz(value.get("lowFrequency")?)?,
        hertz(value.get("highFrequency")?)?,
    )
}

fn parse_item(value: &Value) -> Result<Item, String> {
    let response = value
        .get("response")
        .ok_or("a response object has no response field")?;
    let code = response
        .get("responseCode")
        .and_then(Value::as_i64)
        .ok_or("a response has no responseCode")?;
    let text =
        |source: &Value, key: &str| source.get(key).and_then(Value::as_str).map(String::from);
    let data = match response.get("responseData") {
        Some(Value::Array(entries)) => entries
            .iter()
            .filter_map(|entry| entry.as_str().map(String::from))
            .collect(),
        _ => Vec::new(),
    };
    let suggestion = value.get("operationParam").and_then(|param| {
        let range = parse_range(param.get("operationFrequencyRange")?)?;
        Some((range, param.get("maxEirp")?.as_f64()?))
    });
    let available = match value.get("availableChannel") {
        Some(Value::Array(channels)) => channels
            .iter()
            .filter_map(|channel| {
                let range = parse_range(channel.get("frequencyRange")?)?;
                Some((range, channel.get("maxEirp").and_then(Value::as_f64)?))
            })
            .collect(),
        _ => Vec::new(),
    };
    Ok(Item {
        code,
        message: text(response, "responseMessage").unwrap_or_default(),
        data,
        cbsd_id: text(value, "cbsdId"),
        grant_id: text(value, "grantId"),
        heartbeat_interval: value.get("heartbeatInterval").and_then(hertz),
        grant_expire: text(value, "grantExpireTime").and_then(|time| parse_utc(&time)),
        transmit_expire: text(value, "transmitExpireTime").and_then(|time| parse_utc(&time)),
        suggestion,
        available,
    })
}

/// The response objects of one answer, in the order the SAS sent them.
pub fn parse(kind: Kind, body: &str) -> Result<Vec<Item>, String> {
    let value: Value =
        serde_json::from_str(body).map_err(|err| format!("the answer is not JSON: {err}"))?;
    let key = kind.response_key();
    let items = value
        .get(&key)
        .and_then(Value::as_array)
        .ok_or_else(|| format!("the answer has no {key} array"))?;
    items.iter().map(parse_item).collect()
}

fn days_from_civil(year: i64, month: i64, day: i64) -> i64 {
    let year = if month <= 2 { year - 1 } else { year };
    let era = year.div_euclid(400);
    let year_of_era = year.rem_euclid(400);
    let shifted = (month + 9) % 12;
    let day_of_year = (153 * shifted + 2) / 5 + day - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    era * 146_097 + day_of_era - 719_468
}

fn civil_from_days(days: i64) -> (i64, i64, i64) {
    let days = days + 719_468;
    let era = days.div_euclid(146_097);
    let day_of_era = days.rem_euclid(146_097);
    let year_of_era =
        (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let shifted = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * shifted + 2) / 5 + 1;
    let month = if shifted < 10 {
        shifted + 3
    } else {
        shifted - 9
    };
    let year = year_of_era + era * 400 + i64::from(month <= 2);
    (year, month, day)
}

fn unix_from_parts(
    year: i64,
    month: i64,
    day: i64,
    hour: i64,
    minute: i64,
    second: i64,
) -> Option<u64> {
    if !(1..=12).contains(&month)
        || !(1..=31).contains(&day)
        || !(0..24).contains(&hour)
        || !(0..60).contains(&minute)
        || !(0..=60).contains(&second)
    {
        return None;
    }
    let seconds = days_from_civil(year, month, day) * 86_400 + hour * 3_600 + minute * 60 + second;
    u64::try_from(seconds).ok()
}

/// `YYYY-MM-DDThh:mm:ssZ`, the only time format TS-0016 allows. A fraction of
/// a second is accepted and dropped.
pub fn parse_utc(text: &str) -> Option<u64> {
    let text = text.trim().strip_suffix('Z')?;
    let (date, time) = text.split_once('T')?;
    let mut date = date.split('-');
    let year: i64 = date.next()?.parse().ok()?;
    let month: i64 = date.next()?.parse().ok()?;
    let day: i64 = date.next()?.parse().ok()?;
    if date.next().is_some() {
        return None;
    }
    let time = time.split('.').next()?;
    let mut time = time.split(':');
    let hour: i64 = time.next()?.parse().ok()?;
    let minute: i64 = time.next()?.parse().ok()?;
    let second: i64 = time.next()?.parse().ok()?;
    if time.next().is_some() {
        return None;
    }
    unix_from_parts(year, month, day, hour, minute, second)
}

pub fn format_utc(unix: u64) -> String {
    let unix = i64::try_from(unix).unwrap_or(0);
    let (year, month, day) = civil_from_days(unix.div_euclid(86_400));
    let rest = unix.rem_euclid(86_400);
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}Z",
        rest / 3_600,
        rest % 3_600 / 60,
        rest % 60
    )
}

/// The `Date` header of an HTTP answer (`Sun, 22 Nov 2026 07:00:44 GMT`).
/// It gives the SAS's own clock, so transmit expiry does not depend on the
/// unit's clock.
pub fn parse_http_date(text: &str) -> Option<u64> {
    let mut words = text.split_whitespace();
    let _weekday = words.next()?;
    let day: i64 = words.next()?.parse().ok()?;
    let month = match words.next()?.to_ascii_lowercase().as_str() {
        "jan" => 1,
        "feb" => 2,
        "mar" => 3,
        "apr" => 4,
        "may" => 5,
        "jun" => 6,
        "jul" => 7,
        "aug" => 8,
        "sep" => 9,
        "oct" => 10,
        "nov" => 11,
        "dec" => 12,
        _ => return None,
    };
    let year: i64 = words.next()?.parse().ok()?;
    let mut time = words.next()?.split(':');
    let hour: i64 = time.next()?.parse().ok()?;
    let minute: i64 = time.next()?.parse().ok()?;
    let second: i64 = time.next()?.parse().ok()?;
    if words.next()? != "GMT" {
        return None;
    }
    unix_from_parts(year, month, day, hour, minute, second)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn times_parse_and_print() {
        assert_eq!(parse_utc("1970-01-01T00:00:00Z"), Some(0));
        assert_eq!(parse_utc("2000-03-01T00:00:00Z"), Some(951_868_800));
        assert_eq!(parse_utc("2026-11-22T07:00:44Z"), Some(1_795_330_844));
        assert_eq!(parse_utc("2026-11-22T07:00:44.250Z"), Some(1_795_330_844));
        assert_eq!(parse_utc("2026-11-22 07:00:44"), None);
        assert_eq!(parse_utc("2026-13-22T07:00:44Z"), None);
        assert_eq!(format_utc(1_795_330_844), "2026-11-22T07:00:44Z");
        assert_eq!(format_utc(951_868_800), "2000-03-01T00:00:00Z");
        for unix in [0_u64, 86_399, 951_782_400, 1_709_164_800, 4_102_444_799] {
            assert_eq!(parse_utc(&format_utc(unix)), Some(unix));
        }
    }

    #[test]
    fn an_http_date_gives_the_same_clock() {
        assert_eq!(
            parse_http_date("Sun, 22 Nov 2026 07:00:44 GMT"),
            Some(1_795_330_844)
        );
        assert_eq!(parse_http_date("22 Nov 2026 07:00:44"), None);
    }

    #[test]
    fn a_heartbeat_batch_carries_every_grant_in_order() {
        let body = envelope(
            Kind::Heartbeat,
            vec![
                heartbeat_item("cbsd", "g1", true, false),
                heartbeat_item("cbsd", "g2", false, true),
            ],
        );
        let value: Value = serde_json::from_str(&body).unwrap();
        let items = value["heartbeatRequest"].as_array().unwrap();
        assert_eq!(items.len(), 2);
        assert_eq!(items[0]["operationState"], "AUTHORIZED");
        assert!(items[0].get("grantRenew").is_none());
        assert_eq!(items[1]["grantId"], "g2");
        assert_eq!(items[1]["operationState"], "GRANTED");
        assert_eq!(items[1]["grantRenew"], true);
    }

    #[test]
    fn a_grant_request_names_the_range_in_hertz() {
        let range = Range::mhz(3560, 3580).unwrap();
        let body = envelope(Kind::Grant, vec![grant_item("cbsd", range, 27.0)]);
        let value: Value = serde_json::from_str(&body).unwrap();
        let param = &value["grantRequest"][0]["operationParam"];
        assert_eq!(
            param["operationFrequencyRange"]["lowFrequency"],
            3_560_000_000_u64
        );
        assert_eq!(
            param["operationFrequencyRange"]["highFrequency"],
            3_580_000_000_u64
        );
        assert_eq!(param["maxEirp"], 27.0);
    }

    #[test]
    fn a_grant_conflict_names_the_grant_in_the_way() {
        let body = r#"{"grantResponse":[{"cbsdId":"c","response":{"responseCode":401,
            "responseMessage":"Existing grant overlaps","responseData":["c/123"]}}]}"#;
        let items = parse(Kind::Grant, body).unwrap();
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].code, GRANT_CONFLICT);
        assert_eq!(items[0].data, vec!["c/123".to_string()]);
        assert_eq!(items[0].grant_id, None);
    }

    #[test]
    fn a_heartbeat_answer_gives_the_expiry_and_any_suggestion() {
        let body = r#"{"heartbeatResponse":[{"cbsdId":"c","grantId":"g",
            "transmitExpireTime":"2026-11-22T13:00:44Z","heartbeatInterval":1800,
            "operationParam":{"maxEirp":20,"operationFrequencyRange":
              {"lowFrequency":3560000000,"highFrequency":3580000000}},
            "response":{"responseCode":0}}]}"#;
        let items = parse(Kind::Heartbeat, body).unwrap();
        assert_eq!(items[0].transmit_expire, Some(1_795_330_844 + 21_600));
        assert_eq!(items[0].heartbeat_interval, Some(1800));
        assert_eq!(
            items[0].suggestion,
            Some((Range::mhz(3560, 3580).unwrap(), 20.0))
        );
    }

    #[test]
    fn an_inquiry_answer_lists_the_available_channels() {
        let body = r#"{"spectrumInquiryResponse":[{"cbsdId":"c","availableChannel":[
            {"frequencyRange":{"lowFrequency":3560000000,"highFrequency":3570000000},
             "channelType":"GAA","ruleApplied":"FCC_PART_96","maxEirp":27}],
            "response":{"responseCode":0}}]}"#;
        let items = parse(Kind::SpectrumInquiry, body).unwrap();
        assert_eq!(
            items[0].available,
            vec![(Range::mhz(3560, 3570).unwrap(), 27.0)]
        );
    }

    #[test]
    fn an_answer_of_the_wrong_kind_is_refused() {
        let body = r#"{"grantResponse":[{"response":{"responseCode":0}}]}"#;
        assert!(parse(Kind::Heartbeat, body).is_err());
        assert!(parse(Kind::Grant, "<html>").is_err());
        assert!(parse(Kind::Grant, r#"{"grantResponse":[{}]}"#).is_err());
    }
}
