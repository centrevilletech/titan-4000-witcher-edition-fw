//! Password-authenticated first setup and recovery on LAN and remote IPv4.
//! Autonomous jitter seed bootstrap normally starts the native HTTPS login.
//! HTTP browser seeding remains a trusted-network recovery path on failure.
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    fs::{self, File, OpenOptions},
    io::{self, Read, Write},
    net::{TcpListener, TcpStream},
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::Path,
    process::{Command, Stdio},
    time::{Duration, Instant},
};

const BUNDLE: &str = "/usr/lib/titan-api";
const STATE: &str = "/mnt/titan-api";
const VERSION: &str = include_str!("../../../VERSION");
const PAGE: &str = include_str!("setup.html");
const MAX_BODY: usize = 4096;

#[derive(Debug)]
struct Request {
    method: String,
    path: String,
    headers: BTreeMap<String, String>,
    body: Vec<u8>,
}
struct DeadlineReader<'a> {
    stream: &'a mut TcpStream,
    deadline: Instant,
}
impl Read for DeadlineReader<'_> {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        let remaining = self
            .deadline
            .checked_duration_since(Instant::now())
            .filter(|d| !d.is_zero())
            .ok_or_else(|| io::Error::new(io::ErrorKind::TimedOut, "Request deadline"))?;
        self.stream.set_read_timeout(Some(remaining))?;
        self.stream.read(bytes)
    }
}
fn invalid() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, "Invalid request")
}

fn request(input: &mut impl Read) -> io::Result<Request> {
    let mut header = Vec::new();
    while !header.ends_with(b"\r\n\r\n") {
        if header.len() >= 4096 {
            return Err(invalid());
        }
        let mut byte = [0];
        input.read_exact(&mut byte)?;
        header.push(byte[0]);
    }
    let text = std::str::from_utf8(&header).map_err(|_| invalid())?;
    let mut lines = text.split("\r\n");
    let first: Vec<_> = lines.next().ok_or_else(invalid)?.split(' ').collect();
    if first.len() != 3 || first[2] != "HTTP/1.1" {
        return Err(invalid());
    }
    let mut headers = BTreeMap::new();
    for line in lines.filter(|s| !s.is_empty()) {
        let (name, value) = line.split_once(':').ok_or_else(invalid)?;
        if name.is_empty() || !name.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'-') {
            return Err(invalid());
        }
        if headers
            .insert(name.to_ascii_lowercase(), value.trim().to_owned())
            .is_some()
        {
            return Err(invalid());
        }
    }
    if headers.contains_key("transfer-encoding") {
        return Err(invalid());
    }
    let size = match headers.get("content-length") {
        Some(v) if !v.is_empty() && v.bytes().all(|c| c.is_ascii_digit()) => {
            v.parse::<usize>().map_err(|_| invalid())?
        }
        Some(_) => return Err(invalid()),
        None => 0,
    };
    if size > MAX_BODY {
        return Err(invalid());
    }
    let mut body = vec![0; size];
    input.read_exact(&mut body)?;
    Ok(Request {
        method: first[0].into(),
        path: first[1].into(),
        headers,
        body,
    })
}

fn origin_allowed(r: &Request, local: std::net::SocketAddr) -> bool {
    let expected = if local.port() == 80 {
        local.ip().to_string()
    } else {
        local.to_string()
    };
    r.headers.get("host") == Some(&expected)
        && r.headers.get("origin") == Some(&format!("http://{expected}"))
        && r.headers
            .get("content-type")
            .is_some_and(|v| v == "application/json")
        && r.headers.get("x-witcher-setup").is_some_and(|v| v == "1")
}
fn constant_equal(a: &[u8], b: &[u8]) -> bool {
    let mut difference = a.len() ^ b.len();
    for i in 0..a.len().max(b.len()) {
        difference |= usize::from(a.get(i).unwrap_or(&0) ^ b.get(i).unwrap_or(&0));
    }
    difference == 0
}
fn authenticate(password: &str) -> bool {
    if password.is_empty() || password.len() > 256 {
        return false;
    }
    let Ok(output) = Command::new(format!("{BUNDLE}/titan-nvram"))
        .args(["read", "0", "http_passwd"])
        .stderr(Stdio::null())
        .output()
    else {
        return false;
    };
    if !output.status.success() || output.stdout.len() > 8192 {
        return false;
    }
    let Ok(value) = serde_json::from_slice::<Value>(&output.stdout) else {
        return false;
    };
    value["http_passwd"].as_str().is_some_and(|actual| {
        !actual.is_empty() && constant_equal(password.as_bytes(), actual.as_bytes())
    })
}
fn decode_seed(value: &str) -> io::Result<[u8; 64]> {
    if value.len() != 128 || !value.is_ascii() {
        return Err(invalid());
    }
    let mut seed = [0; 64];
    for (i, slot) in seed.iter_mut().enumerate() {
        *slot = u8::from_str_radix(&value[i * 2..i * 2 + 2], 16).map_err(|_| invalid())?;
    }
    if seed == [0; 64] {
        return Err(invalid());
    }
    Ok(seed)
}
fn save_seed(directory: &Path, seed: &[u8; 64]) -> io::Result<()> {
    let meta = fs::symlink_metadata(directory)?;
    if !meta.is_dir() || meta.uid() != unsafe { libc::geteuid() } || meta.mode() & 0o077 != 0 {
        return Err(invalid());
    }
    let temporary = directory.join(format!(".seed-bootstrap-{}", std::process::id()));
    let target = directory.join("seed");
    let result = (|| {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&temporary)?;
        file.write_all(seed)?;
        file.sync_all()?;
        // Never overwrite an existing seed, including a symlink or partial file.
        fs::hard_link(&temporary, &target)?;
        fs::remove_file(&temporary)?;
        File::open(directory)?.sync_all()
    })();
    let _ = fs::remove_file(temporary);
    result
}
// Called before native entropy consumption and TLS. The collector has its own
// 90-second alarm; no seed or TLS identity is published on a health failure.
fn bootstrap(directory: &Path, collector: &Path) -> io::Result<()> {
    let target = directory.join("seed");
    if fs::symlink_metadata(&target).is_ok() {
        return Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "Existing seed preserved",
        ));
    }
    let mut output = Command::new(collector).stdin(Stdio::null()).output()?;
    if !output.status.success() || output.stdout.len() != 64 {
        output.stdout.fill(0);
        return Err(io::Error::other(
            "Autonomous entropy health checks failed; use recovery",
        ));
    }
    let mut seed = [0u8; 64];
    seed.copy_from_slice(&output.stdout);
    output.stdout.fill(0);
    if seed == [0; 64] {
        return Err(invalid());
    }
    let result = save_seed(directory, &seed);
    seed.fill(0);
    result
}

fn reply(stream: &mut TcpStream, code: u16, content_type: &str, body: &str) -> io::Result<()> {
    write!(
        stream,
        "HTTP/1.1 {code} Response\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nCache-Control: no-store\r\nX-Content-Type-Options: nosniff\r\nX-Frame-Options: DENY\r\nReferrer-Policy: no-referrer\r\nContent-Security-Policy: default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; connect-src 'self'; frame-ancestors 'none'; form-action 'self'\r\nConnection: close\r\n\r\n{body}",
        body.len()
    )
}
fn json_reply(stream: &mut TcpStream, code: u16, message: &str) -> io::Result<()> {
    reply(
        stream,
        code,
        "application/json",
        &json!({"message": message}).to_string(),
    )
}

fn main() -> io::Result<()> {
    let mode = std::env::args().nth(1).unwrap_or_default();
    if mode == "--version" {
        println!("Witcher v{}", VERSION.trim());
        return Ok(());
    }
    if mode == "bootstrap" && unsafe { libc::geteuid() } == 0 {
        return bootstrap(
            Path::new(STATE),
            Path::new(&format!("{BUNDLE}/witcher-entropy")),
        );
    }
    if !matches!(mode.as_str(), "setup" | "recovery") || unsafe { libc::geteuid() } != 0 {
        return Err(invalid());
    }
    let setup = mode == "setup";
    let port = if setup { "80" } else { "8081" };
    if !Command::new("/bin/sh")
        .args(["/etc/init.d/witcher-management-access", port])
        .status()?
        .success()
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "Management access rules failed",
        ));
    }
    let listener = TcpListener::bind(("0.0.0.0", if setup { 80 } else { 8081 }))?;
    let mut attempts = Vec::<Instant>::new();
    for connection in listener.incoming() {
        let Ok(mut stream) = connection else {
            continue;
        };
        stream.set_read_timeout(Some(Duration::from_secs(5)))?;
        stream.set_write_timeout(Some(Duration::from_secs(5)))?;
        let Ok(mut r) = request(&mut DeadlineReader {
            stream: &mut stream,
            deadline: Instant::now() + Duration::from_secs(5),
        }) else {
            let _ = json_reply(&mut stream, 400, "Invalid request.");
            continue;
        };
        if r.method == "GET" && r.path == "/" {
            let page = PAGE
                .replace("{{VERSION}}", VERSION.trim())
                .replace("{{MODE}}", &mode);
            let _ = reply(&mut stream, 200, "text/html; charset=utf-8", &page);
            continue;
        }
        if r.method != "POST" || r.path != "/configure" || !origin_allowed(&r, stream.local_addr()?)
        {
            let _ = json_reply(
                &mut stream,
                403,
                "Use the setup page at this device's numeric IP address.",
            );
            continue;
        }
        attempts.retain(|time| time.elapsed() < Duration::from_secs(60));
        if attempts.len() >= 5 {
            let _ = json_reply(
                &mut stream,
                429,
                "Please wait one minute before trying again.",
            );
            continue;
        }
        attempts.push(Instant::now());
        let Ok(mut input) = serde_json::from_slice::<Value>(&r.body) else {
            let _ = json_reply(&mut stream, 400, "Invalid request.");
            continue;
        };
        if !authenticate(input["password"].as_str().unwrap_or("")) {
            let _ = json_reply(
                &mut stream,
                401,
                "Use the existing device administrator password.",
            );
            continue;
        }
        let action = input["action"].as_str().unwrap_or("").to_owned();
        if setup && action == "setup" {
            let result = (|| {
                let mut seed = decode_seed(input["seed"].as_str().unwrap_or(""))?;
                let result = save_seed(Path::new(STATE), &seed);
                seed.fill(0);
                result
            })();
            r.body.fill(0);
            input = Value::Null;
            drop(input);
            if result.is_ok() {
                let _ = json_reply(&mut stream, 200, "Setup saved. Starting Witcher.");
                return Ok(());
            }
            let _ = json_reply(
                &mut stream,
                409,
                "Setup could not be saved. Open the recovery page; existing state was preserved.",
            );
        } else if !setup && matches!(action.as_str(), "vendor" | "native") {
            let marker = Path::new(STATE).join("use-vendor-ui");
            let result = if action == "vendor" {
                OpenOptions::new()
                    .write(true)
                    .create(true)
                    .truncate(false)
                    .mode(0o600)
                    .custom_flags(libc::O_NOFOLLOW)
                    .open(&marker)
                    .and_then(|f| f.sync_all())
            } else {
                match fs::remove_file(&marker) {
                    Err(e) if e.kind() != io::ErrorKind::NotFound => Err(e),
                    _ => Ok(()),
                }
            };
            // Recovery can still select vendor UI for this boot if storage failed.
            if result.is_err() && action != "vendor" {
                let _ = json_reply(
                    &mut stream,
                    503,
                    "Storage is unavailable. Factory desktop recovery remains available.",
                );
                continue;
            }
            let command = if action == "vendor" {
                "vendor"
            } else {
                "restart"
            };
            let started = Command::new("/bin/sh")
                .args(["/etc/init.d/titan-api", command])
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn();
            let success = started.is_ok();
            if let Ok(mut child) = started {
                std::thread::spawn(move || {
                    let _ = child.wait();
                });
            }
            let _ = json_reply(
                &mut stream,
                if success { 200 } else { 503 },
                "Switch requested. Open the device's normal address in a few seconds.",
            );
        } else {
            let _ = json_reply(&mut stream, 400, "Unavailable action.");
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn bounded_unambiguous_http() {
        assert!(
            request(&mut &b"POST /configure HTTP/1.1\r\nContent-Length: 999999\r\n\r\n"[..])
                .is_err()
        );
        assert!(
            request(
                &mut &b"POST /configure HTTP/1.1\r\nContent-Length: 0\r\nContent-Length: 2\r\n\r\n"
                    [..]
            )
            .is_err()
        );
        assert!(
            request(&mut &b"POST /configure HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n"[..])
                .is_err()
        );
        assert!(
            request(&mut &b"POST /configure HTTP/1.1\r\nContent-Length: 5\r\n\r\nx"[..]).is_err()
        );
    }
    #[test]
    fn cross_origin_and_dns_rebinding_rejected() {
        let mut r = request(&mut &b"POST /configure HTTP/1.1\r\nHost: 192.168.0.1\r\nOrigin: http://192.168.0.1\r\nContent-Type: application/json\r\nX-Witcher-Setup: 1\r\n\r\n"[..]).unwrap();
        let local = "192.168.0.1:80".parse().unwrap();
        assert!(origin_allowed(&r, local));
        r.headers.insert("origin".into(), "http://evil.test".into());
        assert!(!origin_allowed(&r, local));
        r.headers.insert("host".into(), "evil.test".into());
        assert!(!origin_allowed(&r, local));
    }
    #[test]
    fn strict_seed_and_password_comparison() {
        assert!(decode_seed(&"aa".repeat(64)).is_ok());
        for bad in [
            "00".repeat(64),
            "aa".repeat(63),
            "zz".repeat(64),
            "é".repeat(64),
        ] {
            assert!(decode_seed(&bad).is_err());
        }
        assert!(constant_equal(b"password", b"password"));
        assert!(!constant_equal(b"password", b"password\0"));
        assert!(!constant_equal(b"password", b"passw0rd"));
    }
    #[test]
    fn autonomous_collector_failures_never_publish_or_replace_seed() {
        use std::os::unix::fs::PermissionsExt;
        let root =
            std::env::temp_dir().join(format!("witcher-autoseed-test-{}", std::process::id()));
        fs::create_dir(&root).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        let collector = root.join("collector");
        for body in [
            "exit 1",
            "printf short",
            "head -c 64 /dev/zero",
            "head -c 64 /dev/zero; exit 1",
        ] {
            fs::write(&collector, format!("#!/bin/sh\n{body}\n")).unwrap();
            fs::set_permissions(&collector, fs::Permissions::from_mode(0o700)).unwrap();
            assert!(bootstrap(&root, &collector).is_err());
            assert!(!root.join("seed").exists());
        }
        fs::write(&collector, "#!/bin/sh\nprintf '%064d' 1\n").unwrap();
        bootstrap(&root, &collector).unwrap();
        let before = fs::read(root.join("seed")).unwrap();
        assert_eq!(before.len(), 64);
        assert!(bootstrap(&root, &collector).is_err());
        assert_eq!(before, fs::read(root.join("seed")).unwrap());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn durable_seed_never_overwrites_existing_state() {
        use std::os::unix::fs::PermissionsExt;
        let root =
            std::env::temp_dir().join(format!("witcher-firstboot-test-{}", std::process::id()));
        fs::create_dir(&root).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        save_seed(&root, &[7; 64]).unwrap();
        assert!(save_seed(&root, &[8; 64]).is_err());
        assert_eq!(fs::read(root.join("seed")).unwrap(), [7; 64]);
        assert_eq!(fs::metadata(root.join("seed")).unwrap().nlink(), 1);
        assert_eq!(
            fs::metadata(root.join("seed")).unwrap().mode() & 0o777,
            0o600
        );
        fs::remove_file(root.join("seed")).unwrap();
        std::os::unix::fs::symlink("elsewhere", root.join("seed")).unwrap();
        assert!(save_seed(&root, &[9; 64]).is_err());
        fs::remove_dir_all(root).unwrap();
    }
}
