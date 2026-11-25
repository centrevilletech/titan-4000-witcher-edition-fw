//! Which bearer carries the customer, and whether the unit is in IP
//! passthrough.

use titan_pd_model::extdev;

use crate::netdev::bridge_ports;

use super::Keeper;

/// How often the vendor mode is asked when the bridge has no LTE port.
const MODE_EVERY: u64 = 5;

impl Keeper {
    /// Which bearer carries the customer, and whether it is bridged to the
    /// LAN port. The bridge answers both without a fork. Only when it has no
    /// LTE port is the vendor asked, and then at most every `MODE_EVERY` s.
    pub(super) fn refresh_mode(&mut self) {
        let ports = bridge_ports();
        if let Some(port) = extdev::bridged_bearer(ports.iter().map(String::as_str)) {
            self.bearer = port;
            self.passthrough = true;
            self.bridged = true;
            if self.bridged_since.is_none() {
                self.bridged_since = Some(self.now);
                // The vendor adds the SAS SNAT rule during this setup and its
                // firewall restarts can drop it again. Check it every second.
                self.sas_watch.burst(self.now);
                self.last_flood = 0;
            }
            self.mode_checked = None;
            return;
        }
        self.bridged = false;
        self.bridged_since = None;
        if self
            .mode_checked
            .is_some_and(|last| self.now.saturating_sub(last) < MODE_EVERY)
        {
            return;
        }
        self.mode_checked = Some(self.now);
        // A failed or empty read keeps the last mode. Taking it for NAT stopped
        // the responder and removed the port filter, and the SQM under it.
        if let Some(mode) = vendor_passthrough(&self.nvram_get_cached("router_disable")) {
            self.passthrough = mode;
        }
        let named = self.nvram_get_cached("pdn_data_ifname");
        let named = named.rsplit(':').next().unwrap_or("").trim();
        if extdev::is_lte_bearer(named) {
            self.bearer = named.to_owned();
        }
    }
}

/// `nvram_get 0 router_disable`: `Some(true)` for passthrough, `Some(false)`
/// for NAT, `None` for a failed or empty read.
fn vendor_passthrough(output: &str) -> Option<bool> {
    if !output.contains(':') {
        return None;
    }
    match output.rsplit(':').next().unwrap_or("").trim() {
        "1" => Some(true),
        "0" => Some(false),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_unreadable_vendor_mode_keeps_the_last_one() {
        assert_eq!(vendor_passthrough("nvram_get success: 1\n"), Some(true));
        assert_eq!(vendor_passthrough("nvram_get success: 0\n"), Some(false));
        assert_eq!(vendor_passthrough("nvram_get success: \n"), None);
        assert_eq!(vendor_passthrough(""), None);
        assert_eq!(vendor_passthrough("nvram_get failed\n"), None);
    }
}
