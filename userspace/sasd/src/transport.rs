//! One HTTPS call to the SAS, made by the unit's own `curl`.
//!
//! TS-0016 requires TLS 1.2 with both sides authenticated. The unit's CBSD
//! certificate and key stay in the vendor's encrypted files in flash. At
//! start the vendor's own tool decrypts them into a RAM directory only root
//! can read, and `curl` is pointed at those files. This program never reads
//! their contents, and removes the copies when it exits.
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

const SOURCES: [(&str, &str); 3] = [
    ("/mnt/cbsduutcert.bin", "cert.pem"),
    ("/mnt/cbsduutpriv.bin", "key.pem"),
    ("/mnt/sas_chaincacert.bin", "ca.pem"),
];

pub struct Credentials {
    directory: PathBuf,
}

impl Credentials {
    /// Decrypt the three vendor files into `runtime/tls`. Errors name the
    /// file, never its contents.
    pub fn prepare(runtime: &Path) -> Result<Self, String> {
        let directory = runtime.join("tls");
        let _ = fs::remove_dir_all(&directory);
        fs::create_dir_all(&directory)
            .map_err(|err| format!("cannot make the TLS directory: {err}"))?;
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o700))
            .map_err(|err| format!("cannot protect the TLS directory: {err}"))?;
        let tool = host::tool("WITCHER_SAS_DECRYPT", "/usr/sbin/cbrs_encrypt");
        for (source, name) in SOURCES {
            let target = directory.join(name);
            let done = host::run(
                &tool,
                &[
                    "2".to_string(),
                    target.to_string_lossy().into_owned(),
                    source.to_string(),
                ],
            );
            let usable = fs::metadata(&target).is_ok_and(|meta| meta.len() > 0);
            if !done && !usable {
                return Err(format!("cannot prepare {name} from {source}"));
            }
            if !usable {
                return Err(format!("{name} from {source} is empty"));
            }
            let _ = fs::set_permissions(&target, fs::Permissions::from_mode(0o600));
        }
        Ok(Self { directory })
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

/// `https://host[/prefix]/v1.2` from the configured SAS address.
pub fn base_url(configured: &str) -> Option<String> {
    let trimmed = configured.trim().trim_end_matches('/');
    if trimmed.is_empty() {
        return None;
    }
    let rest = trimmed.strip_prefix("https://").unwrap_or(trimmed);
    if rest.starts_with("http://") || rest.contains(char::is_whitespace) {
        return None;
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
    base: &str,
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
        .args(["-4", "-sS", "--tlsv1.2", "--ciphers", CIPHERS])
        .args(["--connect-timeout", &request.connect_timeout.to_string()])
        .args([
            "--max-time",
            &(request.connect_timeout + request.answer_timeout).to_string(),
        ])
        .args(["--cert", &credentials.path("cert.pem")])
        .args(["--key", &credentials.path("key.pem")])
        .args(["--cacert", &credentials.path("ca.pem")])
        .args(["-H", "Content-Type: application/json"])
        .arg("--data-binary")
        .arg(format!("@{}", body.display()))
        .arg("-D")
        .arg(&headers)
        .arg("-o")
        .arg(&answer)
        .args(["-w", "%{http_code} %{time_connect}"])
        .arg(format!("{base}/{}", request.kind.method()))
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
    if status != "200" {
        return Err(Failure::Malformed(format!("HTTP status {status}")));
    }
    let server_time = headers.lines().find_map(|line| {
        let (name, value) = line.split_once(':')?;
        name.eq_ignore_ascii_case("date")
            .then(|| proto::parse_http_date(value.trim()))
            .flatten()
    });
    proto::parse(request.kind, body)
        .map(|items| Answer { items, server_time })
        .map_err(Failure::Malformed)
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
            base_url("sas.example").as_deref(),
            Some("https://sas.example/v1.2")
        );
        assert_eq!(
            base_url("https://sas.example/").as_deref(),
            Some("https://sas.example/v1.2")
        );
        assert_eq!(
            base_url("https://sas.example/v1.2").as_deref(),
            Some("https://sas.example/v1.2")
        );
        assert_eq!(
            base_url("sas.example/cbrs").as_deref(),
            Some("https://sas.example/cbrs/v1.2")
        );
        assert_eq!(base_url("http://sas.example"), None);
        assert_eq!(base_url("  "), None);
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
            classify(Some(0), "503 0.2", "", "busy", &request),
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
