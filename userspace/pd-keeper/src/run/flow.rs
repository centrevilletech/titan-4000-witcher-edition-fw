//! 802.3x flow control on the customer port. See `titan_pd_model::ethernet`.

use titan_pd_model::ethernet;

use crate::command::run_status;
use crate::files::read_file;
use crate::netdev::carrier_up;
use crate::paths::state_dir;

use super::{CUSTOMER, Keeper};

impl Keeper {
    /// Clear 802.3x hardware flow control on eth0 when the keeper starts and
    /// each time eth0 gets its carrier back. See `titan_pd_model::ethernet`.
    pub(super) fn maintain_flow_control(&mut self) {
        if self.flow_checked == Some(self.now) {
            return;
        }
        // Wait for the kernel log backlog, so an old report is not taken for
        // the answer to this command. Without a kernel log, go ahead.
        if self.kernel_log.is_some() && !self.kmsg_drained {
            return;
        }
        self.flow_checked = Some(self.now);
        if !self.flow_watch.tick(carrier_up(CUSTOMER)) {
            return;
        }
        if ethernet::stock_requested(&read_file(state_dir().join("ethernet.conf"))) {
            if !self.flow_stock_logged {
                self.note("ethernet.conf asks for flow_control=stock; leaving the vendor's 802.3x setting on eth0");
                self.flow_stock_logged = true;
            }
            return;
        }
        match run_status(ethernet::PROGRAM, &ethernet::DISABLE) {
            Ok(()) => self.flow_pending = self.kernel_log.is_some(),
            Err(err) => {
                if !self.flow_failed_logged {
                    self.note(&format!("could not turn off 802.3x PAUSE on eth0; trying again when eth0 next comes up: {err}"));
                    self.flow_failed_logged = true;
                }
            }
        }
    }

    /// The kernel's flow control report. One line per outcome per run, since
    /// keeper.log is on flash.
    pub(super) fn flow_report(&mut self, efc: bool) {
        if !self.flow_pending {
            return;
        }
        self.flow_pending = false;
        if !efc && !self.flow_logged {
            self.note("eth0 no longer sends 802.3x PAUSE frames to the router (kern eth -fc; the kernel reports efc=0). The keeper does this again each time eth0 comes back up");
            self.flow_logged = true;
        } else if efc && !self.flow_failed_logged {
            self.note("kern eth -fc ran but the kernel still reports efc=1 on eth0; leaving it");
            self.flow_failed_logged = true;
        }
    }
}
