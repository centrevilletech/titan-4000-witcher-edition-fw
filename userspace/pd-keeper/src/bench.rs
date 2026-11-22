//! Read-only preflight for the explicitly requested, temporary bridge trial.
use std::{
    fs,
    net::Ipv4Addr,
    process::Command,
    time::{SystemTime, UNIX_EPOCH},
};
use titan_pd_model::{extdev, sas_nat};

fn output(program: &str, args: &[&str]) -> Option<String> {
    let out = Command::new(program).args(args).output().ok()?;
    out.status
        .success()
        .then(|| String::from_utf8_lossy(&out.stdout).into_owned())
}

fn authorized(text: &str, now_ms: u128) -> bool {
    let Ok(state) = serde_json::from_str::<serde_json::Value>(text) else {
        return false;
    };
    let collected = state["collected_unix_ms"]
        .as_str()
        .and_then(|s| s.parse().ok());
    collected
        .and_then(|at| now_ms.checked_sub(at))
        .is_some_and(|age| age <= 2500)
        && state["cbrs_status_available"] == "1"
        && state["cbrs_registration_status"] == "1"
        && state["cbrs_grant_state"] == "2"
        && state["cbrs_protocol_error"] == "0"
}

pub fn endpoints(sas: Ipv4Addr) -> Option<String> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()?
        .as_millis();
    if !authorized(&fs::read_to_string("/tmp/witcher-api/sas.json").ok()?, now) {
        return None;
    }
    let ports: Vec<_> = fs::read_dir("/sys/class/net/br0/brif")
        .ok()?
        .map(|entry| entry.ok().and_then(|e| e.file_name().into_string().ok()))
        .collect::<Option<_>>()?;
    if ports.len() != 2 || !ports.iter().any(|p| p == "eth0") {
        return None;
    }
    let bearer = extdev::bridged_bearer(ports.iter().map(String::as_str))?;
    let routes = output("ip", &["route"])?;
    let snat = sas_nat::needed(
        &output("nvram_get", &["0", "lan_management_ipaddr"])?,
        &output("nvram_get", &["0", "pdn_data_ipaddr"])?,
        &routes,
    )?;
    if sas == snat.bearer || sas == snat.local || sas.is_unspecified() || sas.is_multicast() {
        return None;
    }
    // An unknown host route may also depend on reverse NAT. Require the
    // operator's verified TLS peer to be the only other bridge host route.
    let mut found = false;
    for line in routes.lines() {
        let words: Vec<_> = line.split_whitespace().collect();
        if !words.windows(2).any(|w| w == ["dev", "br0"]) {
            continue;
        }
        let dest = words.first()?.trim_end_matches("/32");
        let Ok(addr) = dest.parse::<Ipv4Addr>() else {
            continue;
        };
        if addr == sas {
            found = true;
        } else if addr != snat.bearer {
            return None;
        }
    }
    if !found
        || sas_nat::present(
            &output("iptables", &["-t", "nat", "-S", "POSTROUTING"])?,
            snat,
        ) != Some(true)
        || output("iptables", &["-S", "FORWARD"])?.trim() != "-P FORWARD ACCEPT"
    {
        return None;
    }
    Some(format!("{bearer} {} {sas}", snat.bearer))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn a_missing_failed_stale_or_future_grant_stops_the_trial() {
        let mut state = serde_json::json!({"collected_unix_ms":"10000",
            "cbrs_status_available":"1","cbrs_registration_status":"1",
            "cbrs_grant_state":"2","cbrs_protocol_error":"0"});
        assert!(authorized(&state.to_string(), 12000));
        assert!(!authorized(&state.to_string(), 9999));
        assert!(!authorized(&state.to_string(), 12501));
        state["cbrs_grant_state"] = "0".into();
        assert!(!authorized(&state.to_string(), 10000));
        assert!(!authorized("{}", 10000));
    }
}
