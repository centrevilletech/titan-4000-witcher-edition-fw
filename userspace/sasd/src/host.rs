//! The unit's own tools: nvram, the firewall, the vendor services.
//!
//! Nothing here prints a certificate, a key or a registration value.
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};

use witcher_sas_model::band::Range;
use witcher_sas_model::gate;

pub fn tool(variable: &str, default: &str) -> String {
    std::env::var(variable).unwrap_or_else(|_| default.to_string())
}

pub fn wall() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs())
        .unwrap_or(0)
}

pub fn stdout(program: &str, args: &[&str]) -> String {
    Command::new(program)
        .args(args)
        .stderr(Stdio::null())
        .output()
        .map(|output| String::from_utf8_lossy(&output.stdout).into_owned())
        .unwrap_or_default()
}

/// Run a command, discarding what it prints. True when it exits with zero.
pub fn run(program: &str, args: &[String]) -> bool {
    Command::new(program)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|status| status.success())
}

/// The value in `nvram_get 0 <key>` output (`nvram_get success: <value>`).
pub fn nvram_value(output: &str) -> &str {
    match output.split_once("success:") {
        Some((_, value)) => value.trim(),
        None => "",
    }
}

pub fn nvram_get(key: &str) -> String {
    let program = tool("TITAN_NVRAM_GET", "nvram_get");
    nvram_value(&stdout(&program, &["0", key])).to_string()
}

/// Set a key in the shared configuration cache through the Witcher helper,
/// the same way the keeper does. Nothing is committed to flash.
pub fn nvram_set(key: &str, value: &str) -> bool {
    let program = tool("TITAN_NVRAM", "/usr/lib/titan-api/titan-nvram");
    let Ok(mut child) = Command::new(program)
        .args(["set", "0", key])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
    else {
        return false;
    };
    let written = child
        .stdin
        .take()
        .is_some_and(|mut input| input.write_all(value.as_bytes()).is_ok());
    child.wait().is_ok_and(|status| status.success()) && written
}

/// The carriers the modem transmits on, from the keys `rcinit` reads: the
/// main carrier and, when carrier aggregation has an uplink, that carrier.
pub fn carriers() -> Option<(Range, Option<Range>)> {
    let number = |key: &str| nvram_get(key).parse::<u64>().ok();
    if nvram_get("sqns_radio_band") != "48" {
        return None;
    }
    let primary = Range::from_carrier(
        number("sqns_radio_freqDl")?,
        number("sqns_radio_bandwidthDl")?,
    )?;
    let uplink = number("cbrs_radio_freqUl")
        .zip(number("cbrs_radio_bandwidthUl"))
        .and_then(|(centre, width)| Range::from_carrier(centre, width));
    Some((primary, uplink))
}

/// Whether the data bearer holds an address, read at start to learn the
/// radio state the vendor events would have told a client started earlier.
pub fn attached() -> bool {
    let address = nvram_get("pdn_data_ipaddr");
    !address.is_empty() && address != "0.0.0.0" && address.parse::<std::net::Ipv4Addr>().is_ok()
}

fn firewall_program(name: &'static str) -> String {
    match name {
        "ebtables" => tool("TITAN_EBTABLES", "/usr/bin/ebtables"),
        other => other.to_string(),
    }
}

fn apply(commands: Vec<gate::Command>) {
    for (name, args) in commands {
        // A command that fails here found its effect already in place.
        run(&firewall_program(name), &args);
    }
}

pub fn close_gate() {
    nvram_set("cbrs_mode_grant", "0");
    nvram_set("cbrs_grant_state", "1");
    apply(gate::close_commands());
}

/// True when all three tables send forwarded packets to the gate first.
pub fn gate_holds() -> bool {
    let v4 = gate::closed_in(&stdout("iptables", &["-S", "FORWARD"]));
    let v6 = gate::closed_in(&stdout("ip6tables", &["-S", "FORWARD"]));
    let bridge = gate::closed_in(&stdout(&firewall_program("ebtables"), &["-L", "FORWARD"]));
    v4 == Some(true) && v6 == Some(true) && bridge == Some(true)
}

/// Open customer traffic the way the vendor's Start Channel does: publish the
/// power limit for the modem, mark the grant, and take our drop rules away.
/// If the vendor's own no-grant rule is in the way, ask `rcinit` to rebuild
/// its firewall, as the vendor client does after every grant.
pub fn open_gate(max_eirp: f64) {
    let diversity = nvram_get("sqns_connection_cdd") == "1";
    let enable_max = nvram_get("sqns_connection_EnMaxTxPower") == "1";
    let limit = gate::transmit_limit(max_eirp, diversity, enable_max);
    nvram_set("cbrs_grant_erip", &format!("{}", max_eirp.floor() as i64));
    nvram_set("sqns_radio_maxTxPower", &limit.to_string());
    nvram_set("cbrs_grant_state", "2");
    nvram_set("cbrs_mode_grant", "1");
    apply(gate::open_commands());
    let vendor_drop = stdout("iptables", &["-S", "FORWARD"])
        .lines()
        .any(|line| line.trim() == "-A FORWARD -j DROP");
    if vendor_drop {
        nvram_set("action_service", "cbrs");
        signal_rcinit();
    }
}

/// Give customer-traffic control back to the vendor stack. `rcinit` rebuilds
/// its firewall with its own no-grant rule and starts the vendor client when
/// none runs. Our rules go only after its rule has had time to land.
pub fn hand_back() {
    nvram_set("cbrs_mode_grant", "0");
    nvram_set("cbrs_grant_state", "0");
    nvram_set("action_service", "cbrs");
    signal_rcinit();
    std::thread::sleep(std::time::Duration::from_secs(5));
    apply(gate::open_commands());
}

fn signal_rcinit() {
    let pid = stdout("pidof", &["rcinit"]);
    if let Some(pid) = pid.split_whitespace().next() {
        run("kill", &["-USR1".to_string(), pid.to_string()]);
    }
}

/// Take the modem off the main cell with the vendor's own mechanism: the
/// cell goes on the block list and the connection manager re-applies.
pub fn leave_primary() {
    let cell = format!(
        "{},{}",
        nvram_get("sqns_radio_earfcnDl"),
        nvram_get("sqns_radio_pci")
    );
    let mut list = nvram_get("cbrs_block_list");
    if !list.split(';').any(|entry| entry == cell) {
        list.push_str(&cell);
        list.push(';');
    }
    nvram_set("cbrs_block_list", &list);
    nvram_set("sqns_admin_apply", "1");
}

pub fn rejoin() {
    nvram_set("cbrs_block_list", "");
    nvram_set("sqns_admin_apply", "1");
}

/// The operator's command for dropping the uplink secondary carrier, if one
/// is configured. False means the caller must leave the main cell instead.
pub fn drop_uplink() -> bool {
    match std::env::var("WITCHER_SAS_DROP_UPLINK") {
        Ok(command) if !command.trim().is_empty() => run("/bin/sh", &["-c".to_string(), command]),
        _ => false,
    }
}

pub fn write_atomic(path: &Path, text: &str) -> bool {
    let staged = path.with_extension("new");
    fs::write(&staged, text).is_ok() && fs::rename(&staged, path).is_ok()
}

pub struct Log {
    path: PathBuf,
}

impl Log {
    pub fn new(directory: &Path) -> Self {
        Self {
            path: directory.join("sas.log"),
        }
    }

    pub fn line(&self, text: &str) {
        if fs::metadata(&self.path).is_ok_and(|meta| meta.len() > 256 * 1024) {
            let _ = fs::rename(&self.path, self.path.with_extension("log.1"));
        }
        if let Ok(mut file) = fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
        {
            let _ = writeln!(file, "{} {text}", wall());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_nvram_value_may_hold_colons() {
        assert_eq!(
            nvram_value("nvram_get success: https://sas.example/v1.2\n"),
            "https://sas.example/v1.2"
        );
        assert_eq!(nvram_value("nvram_get success: \n"), "");
        assert_eq!(nvram_value("nvram_get fail"), "");
    }
}
