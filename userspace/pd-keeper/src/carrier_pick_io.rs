//! The carrier picker's measurements, run by a radio worker. No server: the
//! download is estimated from the SINR the modem reports on every serving
//! carrier, the upload is a UDP burst to the discard port of the profile's
//! management probe rated by the modem's own upload report, and the round
//! trip is five pings to the same address. The radio state comes from the
//! vendor's `/tmp/nvram.cfg`. See `titan_pd_model::carrier_pick`.
use std::{
    fs, io,
    net::{Ipv4Addr, UdpSocket},
    os::fd::AsRawFd,
    process::{Command, Stdio},
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use titan_pd_model::{
    carrier_pick::{self as pick, Measure},
    mgmt::MGMT_DEV,
    radio::{self as model, Cell},
};

fn fail(s: &str) -> io::Error {
    io::Error::other(s.to_owned())
}

/// Values of the vendor's RAM configuration cache, read in one pass.
fn nvram_values<const N: usize>(keys: [&str; N]) -> [String; N] {
    let raw = fs::read("/tmp/nvram.cfg").unwrap_or_default();
    let lines: Vec<&[u8]> = raw.split(|b| *b == 0 || *b == b'\n').collect();
    keys.map(|key| {
        let key = format!("{key}=");
        lines
            .iter()
            .find_map(|s| s.strip_prefix(key.as_bytes()))
            .map(|s| String::from_utf8_lossy(s).trim().to_string())
            .unwrap_or_default()
    })
}

/// One value of the vendor's RAM configuration cache.
pub fn nvram(key: &str) -> String {
    let [value] = nvram_values([key]);
    value
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

/// What the radio reported once a second during the burst.
#[derive(Default)]
struct Samples {
    /// `(seconds since the burst started, sqns_radio_ulThroughput in bit/s)`.
    ul: Vec<(f64, u64)>,
    pcell_sinr: Vec<i32>,
    scc_sinr: Vec<Vec<i32>>,
    rank: Vec<u8>,
}

impl Samples {
    fn take(&mut self, t: f64) {
        let [ul, sinr, scc, rank] = nvram_values([
            "sqns_radio_ulThroughput",
            "sqns_radio_SINR",
            "sqns_connection_downlinkSccEx",
            "sqns_radio_RI",
        ]);
        if let Ok(bps) = ul.parse() {
            self.ul.push((t, bps));
        }
        if let Some(db) = pick::hundredths(&sinr) {
            self.pcell_sinr.push(db);
        }
        self.scc_sinr.push(pick::scc_sinr_db(&scc));
        if let Ok(r @ 1..=4) = rank.parse::<u8>() {
            self.rank.push(r);
        }
    }
}

/// A socket that can only leave through the management bearer.
fn mgmt_socket() -> io::Result<UdpSocket> {
    let udp = UdpSocket::bind("0.0.0.0:0")?;
    let dev = MGMT_DEV.as_bytes();
    let rc = unsafe {
        libc::setsockopt(
            udp.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_BINDTODEVICE,
            dev.as_ptr().cast(),
            dev.len() as libc::socklen_t,
        )
    };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    // A full modem queue drops the packet here instead of stalling the pace.
    udp.set_nonblocking(true)?;
    Ok(udp)
}

/// The upload burst: paced UDP to the discard port of `sink` for
/// `UL_BURST_SECS`, through the management bearer. The sink drops the
/// packets; the modem's own report rates the radio. Unconnected, so a sink
/// that answers port unreachable cannot fail the sends. The radio is sampled
/// once a second meanwhile, which also feeds the download estimate.
fn burst(sink: Ipv4Addr) -> io::Result<Samples> {
    let udp = mgmt_socket()?;
    let sink = (sink, pick::UL_SINK_PORT);
    let payload = [0u8; 1200];
    // Batches every 2 ms at the offered rate.
    let per_tick = (u64::from(pick::UL_OFFER_KBPS) * 1000 / 8 * 2 / 1000 / payload.len() as u64).max(1);
    let length = Duration::from_secs(pick::UL_BURST_SECS);
    let mut samples = Samples::default();
    let start = Instant::now();
    samples.take(0.0);
    let mut next_sample = Duration::from_secs(1);
    let mut tick = 0u64;
    while start.elapsed() < length {
        for _ in 0..per_tick {
            let _ = udp.send_to(&payload, sink);
        }
        tick += 1;
        if start.elapsed() >= next_sample {
            samples.take(start.elapsed().as_secs_f64());
            next_sample += Duration::from_secs(1);
        }
        let due = Duration::from_millis(2 * tick);
        if let Some(wait) = due.checked_sub(start.elapsed()) {
            thread::sleep(wait);
        }
    }
    // One more report may land just after the queue drains.
    thread::sleep(Duration::from_millis(500));
    samples.take(start.elapsed().as_secs_f64());
    Ok(samples)
}

/// Idle round trip over the management bearer.
pub fn round_trip(probe: Ipv4Addr) -> Option<u32> {
    let out = Command::new("ping")
        .args(["-I", MGMT_DEV, "-c", "5", "-W", "2", &probe.to_string()])
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

fn kbps(value: &str) -> Option<u32> {
    value.parse::<u64>().ok().map(|bps| u32::try_from(bps / 1000).unwrap_or(u32::MAX))
}

/// One visit's measurement of arm `arm`: pings to the management probe, the
/// upload burst to `sink`.
pub fn measure(probe: Ipv4Addr, sink: Ipv4Addr, arm: usize) -> io::Result<Measure> {
    let (pcell, carriers) = attach().ok_or_else(|| fail("not attached"))?;
    let ul_scc = pick::ul_scc(&nvram("sqns_connection_uplinkScc"));
    let rsrp_dbm = pick::hundredths(&nvram("sqns_radio_RSRP"));
    let rtt_ms = round_trip(probe);
    let samples = burst(sink)?;
    if attach() != Some((pcell, carriers)) {
        return Err(fail("the attach changed during the measurement"));
    }
    let serving = pick::serving_sinr(&samples.pcell_sinr, &samples.scc_sinr, carriers)
        .ok_or_else(|| fail("SINR unreadable"))?;
    let layers = pick::median(&samples.rank).unwrap_or(2);
    let ul_kbps = pick::ul_from_reports(&samples.ul, 0.5).ok_or_else(|| fail("no fresh upload report"))?;
    let [dl_max, ul_max] = nvram_values(["sqns_radio_dlMaxThroughput", "sqns_radio_ulMaxThroughput"]);
    Ok(Measure {
        arm,
        pcell,
        carriers,
        ul_scc,
        sinr_db: serving.first().copied(),
        rsrp_dbm,
        dl_kbps: pick::dl_estimate_kbps(&serving, layers),
        ul_kbps,
        rtt_ms,
        scc_sinr_db: serving[1..].to_vec(),
        dl_max_kbps: kbps(&dl_max),
        ul_max_kbps: kbps(&ul_max),
        at: unix_now(),
    })
}
