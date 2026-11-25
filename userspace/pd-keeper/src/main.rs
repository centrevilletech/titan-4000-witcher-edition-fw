//! Prefix keeper for a Titan in IP passthrough.
//!
//! `run` is the supervised process. `guard` and `confirm` are the self-revert
//! pair for a setting change that re-attaches LTE: the guard puts the old
//! setting back if confirm has not recorded that management returned.
//! `solicit-mgmt` is a diagnostic: it sends one router solicitation on the
//! management bearer, to check that the answer no longer reaches the vendor
//! stack once the keeper has closed the bearer to advertisements.
//! `tk-build` builds the patched modem image on the unit from its stock
//! firmware (docs/tk-patch.md): `check` and `stage` for an operator, `boot`
//! for the boot hook, which builds the default image (docs/tk-boot-loader.md).
//!
//! The keeper has no `unsafe` code: its system calls go through the audited
//! wrappers in `titan-sys`.
#![forbid(unsafe_code)]

use std::env;
use std::fs;
use std::io::Write;

use titan_pd_model::config;

mod bench;
mod capture;
mod carrier_pick_io;
mod carrier_watch_io;
mod clock;
mod command;
mod console_lock;
mod cpu_trims_io;
mod fastpath_io;
mod files;
mod filter_probe;
mod logging;
mod mtd;
mod netdev;
mod nvram;
mod paths;
mod radio;
mod radio_modem;
mod qctrl_io;
mod radio_sqm;
mod revert;
mod run;
mod staged;
mod status_file;
mod tk_build_io;
mod tk_default_io;
mod tk_flags_io;

pub(crate) use logging::{log, log_ram};

fn main() {
    let mut args = env::args().skip(1);
    match args.next().as_deref() {
        Some("run") | None => {
            if env::var_os("TITAN_PD_STATE").is_none() && !config::persistent_volume_mounted() {
                log("persistent volume is not mounted; keeper state is under /tmp");
            }
            revert::recover_pending();
            radio::supervise();
            if let Err(err) = run::serve() {
                log(&format!("keeper stopped: {err}"));
                std::process::exit(1);
            }
        }
        Some(op @ ("radio-profile" | "opt-guard" | "radio-worker")) => {
            let result = match op {
                "radio-profile" => radio::api(args.next().as_deref()),
                "opt-guard" => radio::guard(),
                _ => radio::worker(args.next().as_deref()),
            };
            if let Err(e) = result {
                eprintln!("{op}: {e}");
                std::process::exit(1);
            }
        }
        Some("guard") => std::process::exit(revert::guard(&args.collect::<Vec<_>>())),
        Some("confirm") => std::process::exit(revert::confirm(&args.collect::<Vec<_>>())),
        Some("tk-build") => std::process::exit(tk_build_io::main(&args.collect::<Vec<_>>())),
        Some("filter-probe") => std::process::exit(filter_probe::probe()),
        Some("filter-undo") => std::process::exit(filter_probe::undo(&args.collect::<Vec<_>>())),
        Some("solicit-mgmt") => match run::solicit_once() {
            Ok(source) => {
                let _ = writeln!(
                    std::io::stdout(),
                    "router solicitation sent on lte0pdn0 from {source}"
                );
            }
            Err(err) => {
                eprintln!("solicit-mgmt: {err}");
                std::process::exit(1);
            }
        },
        Some("bench-bridge-endpoints") => {
            let result = args
                .next()
                .and_then(|s| s.parse().ok())
                .and_then(bench::endpoints);
            match result {
                Some(line) => println!("{line}"),
                None => std::process::exit(1),
            }
        }
        Some("status") => {
            // The RAM copy is current. The flash copy can lag by up to a minute.
            let live = fs::read_to_string(paths::runtime_dir().join("status.json"))
                .or_else(|_| fs::read_to_string(paths::state_dir().join("status.json")))
                .unwrap_or_default();
            let _ = writeln!(std::io::stdout(), "{live}");
        }
        _ => {
            eprintln!(
                "usage: titan-pd-keeper run|guard|confirm|filter-probe|filter-undo|solicit-mgmt|status|tk-build"
            );
            std::process::exit(64);
        }
    }
}
