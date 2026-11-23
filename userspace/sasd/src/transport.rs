//! One HTTPS call to the SAS, made by the unit's own `curl`.
//!
//! TS-0016 requires TLS 1.2 with both sides authenticated. The unit's CBSD
//! certificate and key stay in the vendor's encrypted files in flash. At
//! start the vendor's own tool decrypts them into a RAM directory only root
//! can read, and `curl` is pointed at those files. This program never reads
//! the key, and removes the copies when it exits.
//!
//! The SAS trust store is the vendor's encrypted chain by default. A new SAS
//! may chain to a WInnForum root the vendor file lacks, so the operator can
//! point `WITCHER_SAS_CA_FILE` at a plain PEM bundle instead, or name another
//! encrypted file with `WITCHER_SAS_CA_SOURCE`.
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};

use witcher_sas_model::engine::{Answer, Failure, Request};
use witcher_sas_model::proto;

use crate::host;

/// The cipher suites TS-0016 section 8.2.1 allows, in OpenSSL names.
const CIPHERS: &str = "ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES128-GCM-SHA256:\
ECDHE-RSA-AES128-GCM-SHA256:AES256-GCM-SHA384:AES128-GCM-SHA256";

const CERT_SOURCE: &str = "/mnt/cbsduutcert.bin";
const KEY_SOURCE: &str = "/mnt/cbsduutpriv.bin";
const CA_SOURCE: &str = "/mnt/sas_chaincacert.bin";
/// The vendor tool copies each path into a 64-byte buffer.
const VENDOR_PATH_MAX: usize = 63;

/// Where the SAS trust store comes from.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CaSource {
    /// A vendor-encrypted file, decrypted at start like the certificate.
    Encrypted(String),
    /// A plain PEM bundle, used as it is.
    Plain(String),
}

/// `WITCHER_SAS_CA_FILE` (plain) wins over `WITCHER_SAS_CA_SOURCE`
/// (encrypted). With neither, the vendor's own chain.
pub fn ca_source(plain: Option<&str>, encrypted: Option<&str>) -> CaSource {
    fn given(value: Option<&str>) -> Option<&str> {
        value.map(str::trim).filter(|text| !text.is_empty())
    }
    match (given(plain), given(encrypted)) {
        (Some(path), _) => CaSource::Plain(path.to_string()),
        (None, Some(path)) => CaSource::Encrypted(path.to_string()),
        (None, None) => CaSource::Encrypted(CA_SOURCE.to_string()),
    }
}

/// How many whole certificates a PEM text holds.
pub fn pem_certificates(text: &str) -> usize {
    let begins = text.matches("-----BEGIN CERTIFICATE-----").count();
    let ends = text.matches("-----END CERTIFICATE-----").count();
    begins.min(ends)
}

/// Which IP family `curl` may use to reach the SAS.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Family {
    /// IPv4 only, the default. A passthrough unit has a SAS SNAT rule for
    /// IPv4 that the keeper restores.
    V4,
    V6,
    Any,
}

impl Family {
    /// `WITCHER_SAS_IP`: `4` (or empty), `6` or `any`.
    pub fn parse(text: &str) -> Result<Self, String> {
        match text.trim().to_ascii_lowercase().as_str() {
            "" | "4" | "ipv4" => Ok(Family::V4),
            "6" | "ipv6" => Ok(Family::V6),
            "any" => Ok(Family::Any),
            _ => Err("WITCHER_SAS_IP must be 4, 6 or any".into()),
        }
    }

    fn flag(self) -> Option<&'static str> {
        match self {
            Family::V4 => Some("-4"),
            Family::V6 => Some("-6"),
            Family::Any => None,
        }
    }
}

/// Where and how to reach the SAS.
pub struct Endpoint {
    pub base: String,
    pub family: Family,
}

pub struct Credentials {
    directory: PathBuf,
    ca: String,
}

fn decrypt(tool: &str, source: &str, target: &Path) -> Result<(), String> {
    let target_text = target.to_string_lossy().into_owned();
    if source.len() > VENDOR_PATH_MAX || target_text.len() > VENDOR_PATH_MAX {
        return Err(format!(
            "{source}: the vendor tool takes paths of at most {VENDOR_PATH_MAX} bytes"
        ));
    }
    let name = target
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_default();
    let done = host::run(tool, &["2".to_string(), target_text, source.to_string()]);
    // The vendor tool can exit 0 after failing, so the output decides.
    let usable = fs::metadata(target).is_ok_and(|meta| meta.len() > 0);
    if !done && !usable {
        return Err(format!("cannot prepare {name} from {source}"));
    }
    if !usable {
        return Err(format!("{name} from {source} is empty"));
    }
    let _ = fs::set_permissions(target, fs::Permissions::from_mode(0o600));
    Ok(())
}

/// The first bytes of a file, for a format check. Never used on the key.
fn head(path: &Path) -> String {
    fs::read(path)
        .map(|bytes| String::from_utf8_lossy(&bytes[..bytes.len().min(256 * 1024)]).into_owned())
        .unwrap_or_default()
}

impl Credentials {
    /// Decrypt the vendor files into `runtime/tls`, and find the trust
    /// store. Errors name the file, never its contents.
    pub fn prepare(runtime: &Path, ca: &CaSource) -> Result<Self, String> {
        let directory = runtime.join("tls");
        let _ = fs::remove_dir_all(&directory);
        fs::create_dir_all(&directory)
            .map_err(|err| format!("cannot make the TLS directory: {err}"))?;
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o700))
            .map_err(|err| format!("cannot protect the TLS directory: {err}"))?;
        // From here on, dropping `credentials` removes the directory.
        let mut credentials = Self {
            directory: directory.clone(),
            ca: String::new(),
        };
        let tool = host::tool("WITCHER_SAS_DECRYPT", "/usr/sbin/cbrs_encrypt");
        decrypt(&tool, CERT_SOURCE, &directory.join("cert.pem"))?;
        decrypt(&tool, KEY_SOURCE, &directory.join("key.pem"))?;
        if pem_certificates(&head(&directory.join("cert.pem"))) == 0 {
            return Err(format!("cert.pem from {CERT_SOURCE} holds no certificate"));
        }
        let ca_path = match ca {
            CaSource::Encrypted(source) => {
                let target = directory.join("ca.pem");
                decrypt(&tool, source, &target)?;
                target
            }
            CaSource::Plain(path) => PathBuf::from(path),
        };
        let shown = ca_path.display().to_string();
        if pem_certificates(&head(&ca_path)) == 0 {
            return Err(format!("the SAS trust store {shown} holds no certificate"));
        }
        credentials.ca = shown;
        Ok(credentials)
    }

    fn path(&self, name: &str) -> String {
        self.directory.join(name).to_string_lossy().into_owned()
    }
}

impl Drop for Credentials {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.directory);
    }
}

/// `https://host[/prefix]/v1.2` from the configured SAS address. TS-0016
/// section 9.2: each SAS picks its base URL, and the request path ends with
/// `/v1.2/<method>`. With `exact`, the address is used as written, for a SAS
/// whose path does not fit that pattern.
pub fn base_url(configured: &str, exact: bool) -> Option<String> {
    let trimmed = configured.trim().trim_end_matches('/');
    if trimmed.is_empty() {
        return None;
    }
    let rest = trimmed.strip_prefix("https://").unwrap_or(trimmed);
    if rest.starts_with("http://")
        || rest.contains(char::is_whitespace)
        || rest.contains(['?', '#'])
        || rest.starts_with('/')
    {
        return None;
    }
    if exact {
        return Some(format!("https://{rest}"));
    }
    let versioned = rest.rsplit('/').next().is_some_and(|last| {
        last.strip_prefix('v').is_some_and(|digits| {
            digits.chars().all(|c| c.is_ascii_digit() || c == '.') && !digits.is_empty()
        })
    });
    Some(if versioned {
        format!("https://{rest}")
    } else {
        format!("https://{rest}/v1.2")
    })
}

pub struct Call {
    pub id: u64,
    request: Request,
    child: Child,
    body: PathBuf,
    headers: PathBuf,
    answer: PathBuf,
}

pub fn start(
    credentials: &Credentials,
    endpoint: &Endpoint,
    runtime: &Path,
    request: Request,
) -> Result<Call, String> {
    let body = runtime.join("request.json");
    let headers = runtime.join("answer.headers");
    let answer = runtime.join("answer.json");
    let _ = fs::remove_file(&headers);
    let _ = fs::remove_file(&answer);
    fs::write(&body, &request.body).map_err(|err| format!("cannot stage the request: {err}"))?;
    let child = Command::new(host::tool("WITCHER_SAS_CURL", "curl"))
        .args(endpoint.family.flag())
        .args(["-sS", "--tlsv1.2", "--ciphers", CIPHERS])
        .args(["--connect-timeout", &request.connect_timeout.to_string()])
        .args([
            "--max-time",
            &(request.connect_timeout + request.answer_timeout).to_string(),
        ])
        .args(["--cert", &credentials.path("cert.pem")])
        .args(["--key", &credentials.path("key.pem")])
        .args(["--cacert", &credentials.ca])
        .args(["-H", "Content-Type: application/json"])
        .arg("--data-binary")
        .arg(format!("@{}", body.display()))
        .arg("-D")
        .arg(&headers)
        .arg("-o")
        .arg(&answer)
        .args(["-w", "%{http_code} %{time_connect}"])
        .arg(format!("{}/{}", endpoint.base, request.kind.method()))
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|err| format!("cannot start curl: {err}"))?;
    Ok(Call {
        id: request.id,
        request,
        child,
        body,
        headers,
        answer,
    })
}

/// What a finished `curl` run means. `report` is its `-w` output: the HTTP
/// status and the seconds the TCP connect took (zero when it never did).
pub fn classify(
    exit: Option<i32>,
    report: &str,
    headers: &str,
    body: &str,
    request: &Request,
) -> Result<Answer, Failure> {
    let mut words = report.split_whitespace();
    let status = words.next().unwrap_or("000");
    let connected = words
        .next()
        .and_then(|seconds| seconds.parse::<f64>().ok())
        .is_some_and(|seconds| seconds > 0.0);
    if exit != Some(0) {
        return Err(if connected {
            Failure::Timeout
        } else {
            Failure::Connect
        });
    }
    let server_time = header(headers, "date").and_then(proto::parse_http_date);
    if status == "429" || status == "503" {
        return Err(Failure::Busy {
            retry_after: header(headers, "retry-after")
                .and_then(|value| retry_after(value, server_time)),
        });
    }
    if status != "200" {
        return Err(Failure::Malformed(format!("HTTP status {status}")));
    }
    proto::parse(request.kind, body)
        .map(|items| Answer { items, server_time })
        .map_err(Failure::Malformed)
}

/// The value of the last header with this name. `curl -D` writes every
/// header block of the exchange, and the final answer's comes last.
fn header<'a>(headers: &'a str, name: &str) -> Option<&'a str> {
    headers
        .lines()
        .filter_map(|line| {
            let (key, value) = line.split_once(':')?;
            key.trim().eq_ignore_ascii_case(name).then(|| value.trim())
        })
        .last()
}

/// `Retry-After` is either seconds or an HTTP date (RFC 7231 section 7.1.3).
/// A date counts from the server's own `Date` header.
pub fn retry_after(value: &str, server_time: Option<u64>) -> Option<u64> {
    if let Ok(seconds) = value.trim().parse::<u64>() {
        return Some(seconds);
    }
    let at = proto::parse_http_date(value.trim())?;
    Some(at.saturating_sub(server_time?))
}

impl Call {
    /// `None` while `curl` is still running.
    pub fn poll(&mut self) -> Option<Result<Answer, Failure>> {
        let status = match self.child.try_wait() {
            Ok(Some(status)) => status,
            Ok(None) => return None,
            Err(_) => return Some(Err(Failure::Connect)),
        };
        let mut report = String::new();
        if let Some(mut output) = self.child.stdout.take() {
            let _ = std::io::Read::read_to_string(&mut output, &mut report);
        }
        let headers = fs::read_to_string(&self.headers).unwrap_or_default();
        let body = fs::read_to_string(&self.answer).unwrap_or_default();
        for path in [&self.body, &self.headers, &self.answer] {
            let _ = fs::remove_file(path);
        }
        Some(classify(
            status.code(),
            &report,
            &headers,
            &body,
            &self.request,
        ))
    }
}

impl Drop for Call {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use witcher_sas_model::proto::Kind;

    fn request() -> Request {
        Request {
            id: 1,
            kind: Kind::Heartbeat,
            body: String::new(),
            connect_timeout: 10,
            answer_timeout: 30,
        }
    }

    #[test]
    fn the_sas_address_gets_the_protocol_version_once() {
        assert_eq!(
            base_url("sas.example", false).as_deref(),
            Some("https://sas.example/v1.2")
        );
        assert_eq!(
            base_url("https://sas.example/", false).as_deref(),
            Some("https://sas.example/v1.2")
        );
        assert_eq!(
            base_url("https://sas.example/v1.2", false).as_deref(),
            Some("https://sas.example/v1.2")
        );
        assert_eq!(
            base_url("sas.example/cbrs", false).as_deref(),
            Some("https://sas.example/cbrs/v1.2")
        );
        assert_eq!(base_url("http://sas.example", false), None);
        assert_eq!(base_url("  ", false), None);
    }

    #[test]
    fn an_exact_sas_address_is_used_as_written() {
        assert_eq!(
            base_url("https://sas.example/api/cbsd/v1.2.7/", true).as_deref(),
            Some("https://sas.example/api/cbsd/v1.2.7")
        );
        assert_eq!(
            base_url("https://sas.example/cbrs", true).as_deref(),
            Some("https://sas.example/cbrs")
        );
        // A method is appended to the path, so a query or fragment cannot work.
        assert_eq!(base_url("https://sas.example/v1.2?key=1", true), None);
        assert_eq!(base_url("https://sas.example/v1.2#top", false), None);
        assert_eq!(base_url("http://sas.example/v1.2", true), None);
    }

    #[test]
    fn the_ip_family_is_chosen_by_the_operator() {
        assert_eq!(Family::parse(""), Ok(Family::V4));
        assert_eq!(Family::parse("4"), Ok(Family::V4));
        assert_eq!(Family::parse("6"), Ok(Family::V6));
        assert_eq!(Family::parse("ANY"), Ok(Family::Any));
        assert!(Family::parse("5").is_err());
        assert_eq!(Family::V4.flag(), Some("-4"));
        assert_eq!(Family::V6.flag(), Some("-6"));
        assert_eq!(Family::Any.flag(), None);
    }

    #[test]
    fn the_trust_store_can_be_a_plain_bundle_or_another_vendor_file() {
        assert_eq!(
            ca_source(None, None),
            CaSource::Encrypted("/mnt/sas_chaincacert.bin".into())
        );
        assert_eq!(
            ca_source(Some(" "), Some("/mnt/other.bin")),
            CaSource::Encrypted("/mnt/other.bin".into())
        );
        assert_eq!(
            ca_source(Some("/etc/cbrs/roots.pem"), Some("/mnt/other.bin")),
            CaSource::Plain("/etc/cbrs/roots.pem".into())
        );
        let one = "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n";
        assert_eq!(pem_certificates(one), 1);
        assert_eq!(pem_certificates(&one.repeat(4)), 4);
        assert_eq!(pem_certificates("-----BEGIN CERTIFICATE-----\nAAAA"), 0);
        assert_eq!(pem_certificates(""), 0);
    }

    #[test]
    fn a_vendor_path_too_long_for_its_tool_is_refused() {
        let long = format!("/mnt/{}", "x".repeat(VENDOR_PATH_MAX));
        let error = decrypt("/bin/true", &long, Path::new("/tmp/out.pem")).unwrap_err();
        assert!(error.contains("at most"));
    }

    #[test]
    fn a_busy_server_says_when_to_come_back() {
        let request = request();
        let headers = "HTTP/1.1 429 Too Many Requests\r\nRetry-After: 120\r\n\r\n";
        assert_eq!(
            classify(Some(0), "429 0.2", headers, "", &request),
            Err(Failure::Busy {
                retry_after: Some(120)
            })
        );
        let headers = "HTTP/1.1 503 Service Unavailable\r\nDate: Sun, 22 Nov 2026 07:00:44 GMT\r\n\
            Retry-After: Sun, 22 Nov 2026 07:05:44 GMT\r\n\r\n";
        assert_eq!(
            classify(Some(0), "503 0.2", headers, "", &request),
            Err(Failure::Busy {
                retry_after: Some(300)
            })
        );
        assert_eq!(
            classify(Some(0), "503 0.2", "HTTP/1.1 503 x\r\n\r\n", "", &request),
            Err(Failure::Busy { retry_after: None })
        );
        assert!(matches!(
            classify(Some(0), "500 0.2", "", "", &request),
            Err(Failure::Malformed(_))
        ));
        assert_eq!(retry_after("soon", Some(0)), None);
    }

    #[test]
    fn a_failed_call_is_a_lost_connection_or_a_lost_answer() {
        let request = request();
        assert_eq!(
            classify(Some(7), "000 0.000", "", "", &request),
            Err(Failure::Connect)
        );
        assert_eq!(
            classify(Some(28), "000 0.000000", "", "", &request),
            Err(Failure::Connect)
        );
        assert_eq!(
            classify(Some(28), "000 0.412", "", "", &request),
            Err(Failure::Timeout)
        );
        assert_eq!(classify(None, "", "", "", &request), Err(Failure::Connect));
        assert!(matches!(
            classify(Some(0), "400 0.2", "", "bad", &request),
            Err(Failure::Malformed(_))
        ));
    }

    #[test]
    fn a_good_answer_carries_the_sas_clock() {
        let body = r#"{"heartbeatResponse":[{"cbsdId":"c","grantId":"g",
            "transmitExpireTime":"2026-11-22T13:00:44Z","response":{"responseCode":0}}]}"#;
        let headers = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\ndate: Sun, 22 Nov 2026 07:00:44 GMT\r\n\r\n";
        let answer = classify(Some(0), "200 0.210", headers, body, &request()).unwrap();
        assert_eq!(answer.server_time, Some(1_795_330_844));
        assert_eq!(
            answer.items[0].transmit_expire,
            Some(1_795_330_844 + 21_600)
        );
    }
}
