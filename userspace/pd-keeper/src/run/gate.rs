//! Customer IPv6 is dropped while the unit holds no SAS grant. See
//! `titan_pd_model::cbrs_gate`.

use std::process::Command;

use titan_pd_model::cbrs_gate::{self, Step as GateStep, Tool as GateTool};

use crate::command::ebtables_program;
use crate::paths::env_or;

use super::Keeper;

impl Keeper {
    /// Drop customer IPv6 to and from LTE while the unit holds no SAS grant.
    /// The vendor stops only IPv4 then, and bridged IPv6 never reaches
    /// ip6tables. Reads the grant every second; while the gate is closed it
    /// also puts back rules a vendor firewall restart flushed. See
    /// `titan_pd_model::cbrs_gate`.
    pub(super) fn maintain_cbrs_gate(&mut self) {
        if !self.cbrs_gate.due(self.now) {
            return;
        }
        let gate = cbrs_gate::decide(self.read_nvram_cache());
        let (step, line) = self.cbrs_gate.observe(self.now, &gate);
        // Close or renew the fast-path grant lease before anything else in this tick.
        self.fastpath.on_gate(&gate, step);
        let changed = line.is_some();
        if let Some(line) = line {
            self.note(&line);
        }
        let failed = match step {
            GateStep::Hold => return,
            GateStep::Close => {
                let (added, failed) = cbrs_gate::close(&mut gate_command);
                if added > 0 && !changed {
                    self.note(&format!(
                        "CBRS gate rules put back: a vendor firewall restart removed {added} of {}",
                        cbrs_gate::RULES.len()
                    ));
                }
                failed
            }
            GateStep::Open => {
                let (cleanup, failed) = cbrs_gate::open(&mut gate_command);
                self.cbrs_gate.cleaned(self.now, cleanup);
                failed
            }
        };
        for err in failed {
            self.note(&format!("CBRS gate: {err}"));
        }
    }
}

/// One ebtables or ip6tables command for the CBRS gate: its output when it
/// exits 0.
fn gate_command(tool: GateTool, args: &[&str]) -> Result<String, String> {
    let program = match tool {
        GateTool::Ebtables => {
            ebtables_program()
        }
        GateTool::Ip6tables => {
            env_or("TITAN_IP6TABLES", "ip6tables")
        }
    };
    let output = Command::new(program)
        .args(args)
        .output()
        .map_err(|err| err.to_string())?;
    if output.status.success() {
        return Ok(String::from_utf8_lossy(&output.stdout).into_owned());
    }
    let err = String::from_utf8_lossy(&output.stderr);
    let err = err.trim();
    Err(if err.is_empty() { output.status.to_string() } else { err.to_owned() })
}
