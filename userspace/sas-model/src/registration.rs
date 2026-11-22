//! The registration request (WINNF-TS-0016 V1.2.7, sections 8.3 and 10.1),
//! built only from what the unit already stores.
//!
//! The vendor client registers the same way:
//!
//! - **Multi-step** (`cbrs_isSingleReg` is 0 or empty): `userId`, `fccId` and
//!   `cbsdSerialNumber` only. Category, air interface and installation data
//!   are "REG-Conditional" (section 10.1): the installer gives them to the SAS
//!   by other means, and the SAS answers 200 (REG_PENDING) until it has them.
//! - **Single-step** (`cbrs_isSingleReg` is 1): the same three, plus
//!   `cbsdCategory`, `airInterface` and the installer's signed data
//!   (`cpiSignatureData`, table 9) read from the unit's CPI file. Installation
//!   data comes only from that signed file. It is never built from loose
//!   settings, and nothing is filled in by guess.
//!
//! Anything missing or inconsistent fails closed: no request is built, and
//! the caller learns which item is missing, never its value.
//!
//! `measCapability` is left out unless the operator asks for an empty list.
//! This client makes no measurements, so it never claims it can.
use serde_json::{Map, Value, json};

/// What the unit stores, as read. Empty means not set.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Stored {
    /// `cbrs_userId` (nvram slot 3): the operator's account at the SAS.
    pub user_id: String,
    /// `cbrs_fccId`.
    pub fcc_id: String,
    /// `sqns_identity_serialNumber`.
    pub serial: String,
    /// `cbrs_isSingleReg` (nvram slot 3): "1" for single-step.
    pub single_step: String,
    /// `cbrs_category`: "A" or "B".
    pub category: String,
    /// The CPI file's text: protected header, signed data and signature,
    /// one per line. `None` when the file does not exist.
    pub cpi_file: Option<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MeasField {
    /// No `measCapability` field. The default.
    Omit,
    /// `"measCapability": []`, for a SAS that wants the field present.
    Empty,
}

impl MeasField {
    pub fn parse(text: &str) -> Result<Self, String> {
        match text.trim().to_ascii_lowercase().as_str() {
            "" | "omit" => Ok(MeasField::Omit),
            "empty" => Ok(MeasField::Empty),
            _ => Err("the measCapability setting must be omit or empty".into()),
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct Options {
    pub meas: MeasField,
    /// `groupingParam` entries (table 7): group type and group ID.
    pub grouping: Vec<(String, String)>,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            meas: MeasField::Omit,
            grouping: Vec::new(),
        }
    }
}

/// The group types table 7 permits.
const GROUP_TYPES: [&str; 1] = ["INTERFERENCE_COORDINATION"];

/// `INTERFERENCE_COORDINATION:group-1,INTERFERENCE_COORDINATION:group-2`.
pub fn parse_grouping(text: &str) -> Result<Vec<(String, String)>, String> {
    let mut groups = Vec::new();
    for entry in text.split(',').map(str::trim).filter(|entry| !entry.is_empty()) {
        let (kind, id) = entry
            .split_once(':')
            .ok_or("a group must be written TYPE:ID")?;
        let (kind, id) = (kind.trim(), id.trim());
        if !GROUP_TYPES.contains(&kind) {
            return Err(format!("unknown group type {kind}"));
        }
        if id.is_empty() || id.len() > 256 || id.chars().any(char::is_control) {
            return Err("a group ID must be 1 to 256 printable characters".into());
        }
        groups.push((kind.to_string(), id.to_string()));
    }
    Ok(groups)
}

fn plain(text: &str, most: usize) -> bool {
    !text.trim().is_empty() && text.len() <= most && !text.chars().any(char::is_control)
}

/// Unpadded or padded base64url, as RFC 7515 uses. Standard base64 letters
/// are accepted too, since some tools write them.
pub fn decode_base64url(text: &str) -> Option<Vec<u8>> {
    let mut bits = 0_u32;
    let mut count = 0;
    let mut out = Vec::new();
    let body = text.trim_end_matches('=');
    if body.is_empty() {
        return None;
    }
    for byte in body.bytes() {
        let value = match byte {
            b'A'..=b'Z' => byte - b'A',
            b'a'..=b'z' => byte - b'a' + 26,
            b'0'..=b'9' => byte - b'0' + 52,
            b'-' | b'+' => 62,
            b'_' | b'/' => 63,
            _ => return None,
        };
        bits = (bits << 6) | u32::from(value);
        count += 6;
        if count >= 8 {
            count -= 8;
            out.push((bits >> count) as u8);
        }
    }
    // A single leftover character cannot hold a whole byte.
    if body.len() % 4 == 1 {
        return None;
    }
    Some(out)
}

fn decode_json(text: &str) -> Option<Value> {
    serde_json::from_slice(&decode_base64url(text)?).ok()
}

/// The installer's signed data, checked against this unit. Returns the
/// `cpiSignatureData` object and the signed `installationParam`.
fn signed_cpi(stored: &Stored, missing: &mut Vec<String>) -> Option<(Value, Value)> {
    let Some(text) = &stored.cpi_file else {
        missing.push("the CPI file (single-step registration needs the installer's signed data)".into());
        return None;
    };
    let lines: Vec<&str> = text
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .collect();
    let [header, payload, signature] = lines.as_slice() else {
        missing.push("a CPI file with exactly three lines".into());
        return None;
    };
    let header_ok = decode_json(header)
        .and_then(|value| value.get("alg").and_then(Value::as_str).map(String::from))
        .is_some_and(|alg| alg == "RS256" || alg == "ES256");
    if !header_ok {
        missing.push("a CPI protected header naming RS256 or ES256".into());
    }
    if decode_base64url(signature).is_none_or(|bytes| bytes.len() < 32) {
        missing.push("a CPI digital signature".into());
    }
    let Some(signed) = decode_json(payload) else {
        missing.push("readable CPI signed data".into());
        return None;
    };
    // Table 10: these two "shall be equal" to the enclosing request's.
    if signed.get("fccId").and_then(Value::as_str) != Some(stored.fcc_id.as_str()) {
        missing.push("CPI signed data for this unit's FCC ID".into());
    }
    if signed.get("cbsdSerialNumber").and_then(Value::as_str) != Some(stored.serial.as_str()) {
        missing.push("CPI signed data for this unit's serial number".into());
    }
    let installation = signed.get("installationParam").filter(|value| {
        value.get("latitude").is_some_and(Value::is_number)
            && value.get("longitude").is_some_and(Value::is_number)
    });
    if installation.is_none() {
        missing.push("an installationParam with latitude and longitude in the CPI signed data".into());
    }
    let installer = signed.get("professionalInstallerData");
    let installer_ok = ["cpiId", "cpiName", "installCertificationTime"]
        .iter()
        .all(|key| installer.and_then(|data| data.get(*key)).is_some_and(Value::is_string));
    if !installer_ok {
        missing.push("professionalInstallerData in the CPI signed data".into());
    }
    if !missing.is_empty() {
        return None;
    }
    let data = json!({
        "protectedHeader": header,
        "encodedCpiSignedData": payload,
        "digitalSignature": signature,
    });
    Some((data, installation.cloned().unwrap_or(Value::Null)))
}

/// The RegistrationRequest object, or the list of what is missing.
pub fn build(stored: &Stored, options: &Options) -> Result<Value, Vec<String>> {
    let mut missing = Vec::new();
    if !plain(&stored.user_id, 256) {
        missing.push("the SAS user ID (cbrs_userId)".to_string());
    }
    // Table 4 limits: fccId 19 characters, cbsdSerialNumber 64 octets.
    if !plain(&stored.fcc_id, 19) {
        missing.push("the FCC ID (cbrs_fccId)".to_string());
    }
    if !plain(&stored.serial, 64) {
        missing.push("the serial number (sqns_identity_serialNumber)".to_string());
    }
    let single = match stored.single_step.trim() {
        "" | "0" => false,
        "1" => true,
        _ => {
            missing.push("a registration mode of 0 or 1 (cbrs_isSingleReg)".to_string());
            false
        }
    };
    let mut request = Map::new();
    if missing.is_empty() {
        request.insert("userId".into(), json!(stored.user_id));
        request.insert("fccId".into(), json!(stored.fcc_id));
        request.insert("cbsdSerialNumber".into(), json!(stored.serial));
    }
    if single {
        let category = stored.category.trim().to_ascii_uppercase();
        if category != "A" && category != "B" {
            missing.push("the device category A or B (cbrs_category)".to_string());
        }
        if let Some((signature, installation)) = signed_cpi(stored, &mut missing) {
            if missing.is_empty() {
                request.insert("cbsdCategory".into(), json!(category));
                // The Titan is an LTE device: E_UTRA, as the vendor client sends.
                request.insert("airInterface".into(), json!({ "radioTechnology": "E_UTRA" }));
                if category == "A" {
                    // A Category A unit has no CPI requirement at the SAS, so
                    // the signed values also go at the top level. They are the
                    // installer's, copied as signed.
                    request.insert("installationParam".into(), installation);
                }
                request.insert("cpiSignatureData".into(), signature);
            }
        }
    }
    if !missing.is_empty() {
        return Err(missing);
    }
    if options.meas == MeasField::Empty {
        request.insert("measCapability".into(), json!([]));
    }
    if !options.grouping.is_empty() {
        let groups: Vec<Value> = options
            .grouping
            .iter()
            .map(|(kind, id)| json!({ "groupType": kind, "groupId": id }))
            .collect();
        request.insert("groupingParam".into(), Value::Array(groups));
    }
    Ok(Value::Object(request))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn encode(bytes: &[u8]) -> String {
        const TABLE: &[u8; 64] =
            b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
        let mut out = String::new();
        let (mut bits, mut count) = (0_u32, 0);
        for byte in bytes {
            bits = (bits << 8) | u32::from(*byte);
            count += 8;
            while count >= 6 {
                count -= 6;
                out.push(TABLE[((bits >> count) & 63) as usize] as char);
            }
        }
        if count > 0 {
            out.push(TABLE[((bits << (6 - count)) & 63) as usize] as char);
        }
        out
    }

    fn unit() -> Stored {
        Stored {
            user_id: "test-account".into(),
            fcc_id: "TEST-FCC-ID".into(),
            serial: "TESTSERIAL0001".into(),
            single_step: "0".into(),
            category: "B".into(),
            cpi_file: None,
        }
    }

    fn cpi_file(fcc: &str, serial: &str) -> String {
        let header = encode(br#"{"typ":"JWT","alg":"RS256"}"#);
        let signed = json!({
            "fccId": fcc,
            "cbsdSerialNumber": serial,
            "installationParam": {
                "latitude": 1.5, "longitude": -2.5, "height": 6, "heightType": "AGL",
                "indoorDeployment": false, "antennaAzimuth": 90, "antennaDowntilt": 0,
                "antennaGain": 14, "antennaBeamwidth": 60
            },
            "professionalInstallerData": {
                "cpiId": "test-installer", "cpiName": "Test Installer",
                "installCertificationTime": "2026-01-01T00:00:00Z"
            }
        });
        let payload = encode(signed.to_string().as_bytes());
        let signature = encode(&[7_u8; 256]);
        format!("{header}\n{payload}\n{signature}\n")
    }

    fn single(cpi: Option<String>) -> Stored {
        Stored {
            single_step: "1".into(),
            cpi_file: cpi,
            ..unit()
        }
    }

    #[test]
    fn multi_step_sends_only_the_unit_identity() {
        let request = build(&unit(), &Options::default()).unwrap();
        let keys: Vec<&String> = request.as_object().unwrap().keys().collect();
        assert_eq!(keys.len(), 3, "{keys:?}");
        assert_eq!(request["userId"], "test-account");
        assert_eq!(request["fccId"], "TEST-FCC-ID");
        assert_eq!(request["cbsdSerialNumber"], "TESTSERIAL0001");
        // An empty mode is the vendor's default: multi-step.
        let empty = Stored {
            single_step: String::new(),
            ..unit()
        };
        assert_eq!(build(&empty, &Options::default()).unwrap(), request);
    }

    #[test]
    fn multi_step_ignores_a_cpi_file() {
        let stored = Stored {
            cpi_file: Some(cpi_file("TEST-FCC-ID", "TESTSERIAL0001")),
            ..unit()
        };
        let request = build(&stored, &Options::default()).unwrap();
        assert!(request.get("cpiSignatureData").is_none());
        assert!(request.get("installationParam").is_none());
    }

    #[test]
    fn single_step_category_b_sends_the_signed_data_and_no_loose_installation() {
        let file = cpi_file("TEST-FCC-ID", "TESTSERIAL0001");
        let request = build(&single(Some(file.clone())), &Options::default()).unwrap();
        assert_eq!(request["cbsdCategory"], "B");
        assert_eq!(request["airInterface"]["radioTechnology"], "E_UTRA");
        assert!(request.get("installationParam").is_none());
        let lines: Vec<&str> = file.lines().collect();
        let signature = &request["cpiSignatureData"];
        assert_eq!(signature["protectedHeader"], lines[0]);
        assert_eq!(signature["encodedCpiSignedData"], lines[1]);
        assert_eq!(signature["digitalSignature"], lines[2]);
    }

    #[test]
    fn single_step_category_a_copies_the_signed_installation_exactly() {
        let stored = Stored {
            category: "a".into(),
            ..single(Some(cpi_file("TEST-FCC-ID", "TESTSERIAL0001")))
        };
        let request = build(&stored, &Options::default()).unwrap();
        assert_eq!(request["cbsdCategory"], "A");
        assert_eq!(request["installationParam"]["latitude"], 1.5);
        assert_eq!(request["installationParam"]["antennaGain"], 14);
    }

    #[test]
    fn missing_identity_fails_closed_and_names_no_value() {
        let stored = Stored {
            fcc_id: String::new(),
            serial: "x".repeat(65),
            ..unit()
        };
        let missing = build(&stored, &Options::default()).unwrap_err();
        assert_eq!(missing.len(), 2, "{missing:?}");
        assert!(missing.iter().all(|line| !line.contains("xxxx")));
        let no_account = Stored {
            user_id: " \n".into(),
            ..unit()
        };
        assert!(build(&no_account, &Options::default()).is_err());
        let odd_mode = Stored {
            single_step: "yes".into(),
            ..unit()
        };
        assert!(build(&odd_mode, &Options::default()).is_err());
    }

    #[test]
    fn single_step_without_signed_data_fails_closed() {
        assert!(build(&single(None), &Options::default()).is_err());
        let two_lines = Some("aGVhZGVy\ncGF5bG9hZA\n".to_string());
        assert!(build(&single(two_lines), &Options::default()).is_err());
        let no_category = Stored {
            category: String::new(),
            ..single(Some(cpi_file("TEST-FCC-ID", "TESTSERIAL0001")))
        };
        assert!(build(&no_category, &Options::default()).is_err());
    }

    #[test]
    fn signed_data_for_another_unit_is_refused() {
        let other_serial = single(Some(cpi_file("TEST-FCC-ID", "OTHERSERIAL")));
        let missing = build(&other_serial, &Options::default()).unwrap_err();
        assert!(missing.iter().any(|line| line.contains("serial")));
        let other_fcc = single(Some(cpi_file("OTHER-FCC", "TESTSERIAL0001")));
        assert!(build(&other_fcc, &Options::default()).is_err());
    }

    #[test]
    fn signed_data_without_installation_or_installer_is_refused() {
        let header = encode(br#"{"alg":"RS256"}"#);
        let payload = encode(
            json!({"fccId": "TEST-FCC-ID", "cbsdSerialNumber": "TESTSERIAL0001"})
                .to_string()
                .as_bytes(),
        );
        let signature = encode(&[1_u8; 256]);
        let stored = single(Some(format!("{header}\n{payload}\n{signature}")));
        let missing = build(&stored, &Options::default()).unwrap_err();
        assert_eq!(missing.len(), 2, "{missing:?}");
        let bad_header = encode(br#"{"alg":"none"}"#);
        let file = cpi_file("TEST-FCC-ID", "TESTSERIAL0001");
        let rest: Vec<&str> = file.lines().skip(1).collect();
        let stored = single(Some(format!("{bad_header}\n{}\n{}", rest[0], rest[1])));
        assert!(build(&stored, &Options::default()).is_err());
    }

    #[test]
    fn the_request_never_claims_a_measurement_capability() {
        let request = build(&unit(), &Options::default()).unwrap();
        assert!(request.get("measCapability").is_none());
        let options = Options {
            meas: MeasField::Empty,
            ..Options::default()
        };
        let request = build(&unit(), &options).unwrap();
        assert_eq!(request["measCapability"], json!([]));
        assert_eq!(MeasField::parse("EMPTY"), Ok(MeasField::Empty));
        assert_eq!(MeasField::parse(""), Ok(MeasField::Omit));
        assert!(MeasField::parse("RECEIVED_POWER_WITHOUT_GRANT").is_err());
    }

    #[test]
    fn grouping_comes_only_from_the_operator_setting() {
        assert_eq!(parse_grouping(""), Ok(Vec::new()));
        let groups = parse_grouping("INTERFERENCE_COORDINATION:site-1").unwrap();
        let options = Options {
            grouping: groups,
            ..Options::default()
        };
        let request = build(&unit(), &options).unwrap();
        assert_eq!(
            request["groupingParam"],
            json!([{ "groupType": "INTERFERENCE_COORDINATION", "groupId": "site-1" }])
        );
        assert!(parse_grouping("OTHER:x").is_err());
        assert!(parse_grouping("INTERFERENCE_COORDINATION:").is_err());
        assert!(parse_grouping("nocolon").is_err());
    }

    #[test]
    fn base64url_round_trips() {
        let samples: [&[u8]; 6] = [b"", b"a", b"ab", b"abc", b"abcd", &[0xff, 0xfe, 0x00]];
        for sample in samples {
            if sample.is_empty() {
                assert_eq!(decode_base64url(""), None);
                continue;
            }
            assert_eq!(decode_base64url(&encode(sample)).as_deref(), Some(sample));
        }
        assert_eq!(decode_base64url("YWJj").as_deref(), Some(&b"abc"[..]));
        assert_eq!(decode_base64url("YWI=").as_deref(), Some(&b"ab"[..]));
        assert_eq!(decode_base64url("Y"), None);
        assert_eq!(decode_base64url("YW*j"), None);
    }
}
