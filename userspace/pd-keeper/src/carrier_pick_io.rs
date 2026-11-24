//! The carrier picker's measurements, run by a radio worker: a UDP burst each
//! way through the management bearer and the probe server, an idle round
//! trip, and the radio state the vendor writes to `/tmp/nvram.cfg`.
//! See `titan_pd_model::carrier_pick`.
use std::{
    fs,
    io::{self, BufRead, BufReader, Read, Write},
    net::{SocketAddrV4, TcpStream, UdpSocket},
    process::{Command, Stdio},
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use titan_pd_model::{
    carrier_pick::{self as pick, Measure, Reply},
    mgmt::MGMT_DEV,
    radio::{self as model, Cell},
};

fn fail(s: &str) -> io::Error {
    io::Error::other(s.to_owned())
}

/// One value of the vendor's RAM configuration cache.
pub fn nvram(key: &str) -> String {
    let raw = fs::read("/tmp/nvram.cfg").unwrap_or_default();
    let key = format!("{key}=");
    raw.split(|b| *b == 0 || *b == b'\n')
        .find_map(|s| s.strip_prefix(key.as_bytes()))
        .map(|s| String::from_utf8_lossy(s).trim().to_string())
        .unwrap_or_default()
}

/// Where the unit is attached now: primary cell and carrier count.
pub fn attach() -> Option<(Cell, u8)> {
    if nvram("sqns_connection_mediaState") != "ATTACHED" {
        return None;
    }
    let earfcn = nvram("sqns_radio_earfcnDl").parse().ok()?;
    let pci = nvram("sqns_radio_pci").parse().ok()?;
    let carriers = model::carriers(&nvram("sqns_connection_sccInfo"))?;
    Some((Cell { earfcn, pci }, carriers))
}

/// Whether current SAS grants cover the primary and uplink secondary carrier.
pub fn granted() -> bool {
    let Some((cell, _)) = attach() else {
        return false;
    };
    if nvram("cbrs_mode_grant") != "1" || nvram("cbrs_grant_state") != "2" {
        return false;
    }
    let log = fs::read("/mnt/cbrslog0.txt").unwrap_or_default();
    let grants = pick::grants(&String::from_utf8_lossy(&log));
    let bw = nvram("sqns_radio_bandwidthDl").parse().unwrap_or(20_000);
    pick::covered(cell.earfcn, pick::ul_scc(&nvram("sqns_connection_uplinkScc")), bw, &grants)
}

/// Receive and transmit byte counters of an interface.
pub fn counters(dev: &str) -> Option<(u64, u64)> {
    let read = |name: &str| {
        fs::read_to_string(format!("/sys/class/net/{dev}/statistics/{name}"))
            .ok()?
            .trim()
            .parse()
            .ok()
    };
    Some((read("rx_bytes")?, read("tx_bytes")?))
}

fn control(probe: SocketAddrV4, request: &str, wait: Duration) -> io::Result<(TcpStream, BufReader<TcpStream>)> {
    let mut tcp = TcpStream::connect_timeout(&probe.into(), Duration::from_secs(5))?;
    tcp.set_read_timeout(Some(wait))?;
    tcp.set_write_timeout(Some(Duration::from_secs(5)))?;
    tcp.write_all(request.as_bytes())?;
    let reader = BufReader::new(tcp.try_clone()?);
    Ok((tcp, reader))
}

fn reply(reader: &mut BufReader<TcpStream>) -> io::Result<Reply> {
    let mut line = String::new();
    if reader.by_ref().take(256).read_line(&mut line)? == 0 {
        return Err(fail("probe server closed the connection"));
    }
    match pick::parse_reply(&line) {
        Some(Reply::Refused(why)) => Err(fail(&format!("probe server refused: {why}"))),
        Some(r) => Ok(r),
        None => Err(fail("probe server reply unreadable")),
    }
}

/// Download: the server sends a UDP burst to an open socket that is never
/// read, and the management bearer's receive counter measures the rate.
pub fn download(probe: SocketAddrV4) -> io::Result<u32> {
    let udp = UdpSocket::bind("0.0.0.0:0")?;
    let port = udp.local_addr()?.port();
    let burst = Duration::from_millis(u64::from(pick::DL_BURST_MS));
    let (_tcp, mut reader) = control(
        probe,
        &pick::dl_request(pick::DL_BURST_MS, pick::DL_OFFER_KBPS, port),
        burst + Duration::from_secs(5),
    )?;
    if reply(&mut reader)? != Reply::Ok(None) {
        return Err(fail("probe server did not start the download"));
    }
    let start = Instant::now();
    let mut samples = Vec::new();
    while start.elapsed() < burst + Duration::from_millis(400) {
        let (rx, _) = counters(MGMT_DEV).ok_or_else(|| fail("management counters unreadable"))?;
        samples.push((start.elapsed().as_secs_f64(), rx));
        thread::sleep(Duration::from_millis(100));
    }
    match reply(&mut reader)? {
        Reply::Done(_) => {}
        _ => return Err(fail("probe server did not finish the download")),
    }
    drop(udp);
    pick::burst_kbps(&samples, 0.0, burst.as_secs_f64() + 0.4)
        .ok_or_else(|| fail("download burst too short to measure"))
}

/// Upload: a paced UDP burst to the port the server names; it counts what
/// arrives.
pub fn upload(probe: SocketAddrV4) -> io::Result<u32> {
    let burst = Duration::from_millis(u64::from(pick::UL_BURST_MS));
    let (_tcp, mut reader) = control(probe, &pick::ul_request(pick::UL_BURST_MS), burst + Duration::from_secs(8))?;
    let Reply::Ok(Some(port)) = reply(&mut reader)? else {
        return Err(fail("probe server did not open an upload port"));
    };
    let udp = UdpSocket::bind("0.0.0.0:0")?;
    udp.connect((*probe.ip(), port))?;
    let payload = [0u8; 1200];
    // Batches every 2 ms at the offered rate.
    let per_tick = (u64::from(pick::UL_OFFER_KBPS) * 1000 / 8 * 2 / 1000 / payload.len() as u64).max(1);
    let start = Instant::now();
    let mut tick = 0u32;
    while start.elapsed() < burst {
        for _ in 0..per_tick {
            // A full modem queue drops here: that is the measurement.
            let _ = udp.send(&payload);
        }
        tick += 1;
        let due = Duration::from_millis(2 * u64::from(tick));
        if let Some(wait) = due.checked_sub(start.elapsed()) {
            thread::sleep(wait);
        }
    }
    match reply(&mut reader)? {
        Reply::Counted { bytes, span_ms } => {
            pick::ul_kbps(bytes, span_ms).ok_or_else(|| fail("upload burst too short to measure"))
        }
        _ => Err(fail("probe server did not count the upload")),
    }
}

/// Idle round trip over the management bearer.
pub fn round_trip(probe: SocketAddrV4) -> Option<u32> {
    let out = Command::new("ping")
        .args(["-I", MGMT_DEV, "-c", "5", "-W", "2", &probe.ip().to_string()])
        .stderr(Stdio::null())
        .output()
        .ok()?;
    pick::ping_avg_ms(&String::from_utf8_lossy(&out.stdout))
}

pub fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// One visit's measurement of arm `arm`.
pub fn measure(probe: SocketAddrV4, arm: usize) -> io::Result<Measure> {
    let (pcell, carriers) = attach().ok_or_else(|| fail("not attached"))?;
    let ul_scc = pick::ul_scc(&nvram("sqns_connection_uplinkScc"));
    let sinr_db = pick::hundredths(&nvram("sqns_radio_SINR"));
    let rsrp_dbm = pick::hundredths(&nvram("sqns_radio_RSRP"));
    let rtt_ms = round_trip(probe);
    let dl_kbps = download(probe)?;
    let ul_kbps = upload(probe)?;
    Ok(Measure {
        arm,
        pcell,
        carriers,
        ul_scc,
        sinr_db,
        rsrp_dbm,
        dl_kbps,
        ul_kbps,
        rtt_ms,
        at: unix_now(),
    })
}
