//! The carrier picker's measurements, run by a radio worker. No server: the
//! download is estimated from the SINR the modem reports on every serving
//! carrier, the upload is a UDP burst to the discard port of the profile's
//! management probe rated by the modem's own upload report, and the round
//! trip is five pings to the same address. The radio state comes from the
//! vendor's `/tmp/nvram.cfg`. See `titan_pd_model::carrier_pick`.
use std::{
    fs, io,
    net::{Ipv4Addr, UdpSocket},
    process::{Command, Stdio},
    thread,
    time::{Duration, Instant},
};
use titan_pd_model::{
    carrier_pick::{self as pick, Measure},
    mgmt::MGMT_DEV,
    radio::{self as model, Cell},
};
use titan_sys::socket::SocketExt;

use crate::nvram;

fn fail(s: &str) -> io::Error {
    io::Error::other(s.to_owned())
}


/// Where the unit is attached now: primary cell and carrier count.
pub fn attach() -> Option<(Cell, u8)> {
    if nvram::read_value("sqns_connection_mediaState") != "ATTACHED" {
        return None;
    }
    let earfcn = nvram::read_value("sqns_radio_earfcnDl").parse().ok()?;
    let pci = nvram::read_value("sqns_radio_pci").parse().ok()?;
    let carriers = model::carriers(&nvram::read_value("sqns_connection_sccInfo"))?;
    Some((Cell { earfcn, pci }, carriers))
}

/// Whether current SAS grants cover the primary and uplink secondary carrier.
pub fn granted() -> bool {
    let Some((cell, _)) = attach() else {
        return false;
    };
    if nvram::read_value("cbrs_mode_grant") != "1" || nvram::read_value("cbrs_grant_state") != "2" {
        return false;
    }
    let log = fs::read(crate::carrier_watch_io::cbrslog_path()).unwrap_or_default();
    let grants = pick::grants(&String::from_utf8_lossy(&log));
    let bw = nvram::read_value("sqns_radio_bandwidthDl").parse().unwrap_or(20_000);
    pick::covered(cell.earfcn, pick::ul_scc(&nvram::read_value("sqns_connection_uplinkScc")), bw, &grants)
}

/// The customer bearer's interface, as the vendor names it.
pub fn customer_dev() -> String {
    let dev = nvram::read_value("pdn_data_ifname");
    if dev.starts_with("lte0pdn") { dev } else { "lte0pdn2".into() }
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
        let [ul, sinr, scc, rank] = nvram::read_values([
            "sqns_radio_ulThroughput",
            "sqns_radio_SINR",
            "sqns_connection_downlinkSccEx",
            "sqns_radio_RI",
        ]);
        if let Ok(bps) = ul.parse() {
            self.ul.push((t, bps));
        }
        if let Some(db) = pick::weakest_hundredths(&sinr) {
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
    udp.bind_to_device(MGMT_DEV)?;
    // A full modem queue drops the packet here instead of stalling the pace.
    udp.set_nonblocking(true)?;
    Ok(udp)
}

/// The upload burst: paced UDP to the discard port of `sink` for
/// `UL_BURST_SECS`, through the management bearer. The sink drops the
/// packets; the modem's own report rates the radio. Unconnected, so a sink
/// that answers port unreachable cannot fail the sends. The radio is sampled
/// once a second meanwhile, which also feeds the download estimate. The burst
/// stops with `CUSTOMER_BUSY` as soon as the customer bearer carries traffic.
fn burst(sink: Ipv4Addr) -> io::Result<Samples> {
    let customer = customer_dev();
    let mut seen = counters(&customer);
    let mut seen_at = Instant::now();
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
            let now = counters(&customer);
            if let (Some(before), Some(after)) = (seen, now) {
                let millis = u64::try_from(seen_at.elapsed().as_millis()).unwrap_or(u64::MAX);
                if pick::busy(before, after, millis) {
                    return Err(fail(pick::CUSTOMER_BUSY));
                }
            }
            (seen, seen_at) = (now, Instant::now());
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

fn kbps(value: &str) -> Option<u32> {
    value.parse::<u64>().ok().map(|bps| u32::try_from(bps / 1000).unwrap_or(u32::MAX))
}

/// One visit's measurement of arm `arm`: pings to the management probe, the
/// upload burst to `sink`.
pub fn measure(probe: Ipv4Addr, sink: Ipv4Addr, arm: usize) -> io::Result<Measure> {
    let (pcell, carriers) = attach().ok_or_else(|| fail("not attached"))?;
    let ul_scc = pick::ul_scc(&nvram::read_value("sqns_connection_uplinkScc"));
    let rsrp_dbm = pick::hundredths(&nvram::read_value("sqns_radio_RSRP"));
    let rtt_ms = round_trip(probe);
    let samples = burst(sink)?;
    if attach() != Some((pcell, carriers)) {
        return Err(fail("the attach changed during the measurement"));
    }
    let serving = pick::serving_sinr(&samples.pcell_sinr, &samples.scc_sinr, carriers)
        .ok_or_else(|| fail("SINR unreadable"))?;
    let layers = pick::median(&samples.rank).unwrap_or(2);
    let ul_kbps = pick::ul_from_reports(&samples.ul, 0.5).ok_or_else(|| fail("no fresh upload report"))?;
    let [dl_max, ul_max] = nvram::read_values(["sqns_radio_dlMaxThroughput", "sqns_radio_ulMaxThroughput"]);
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
        at: crate::clock::unix_now(),
    })
}
