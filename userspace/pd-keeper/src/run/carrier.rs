//! Band 48 transmit carriers against the SAS grants the unit holds. See
//! `titan_pd_model::carrier_watch`.

use std::fs;

use titan_pd_model::carrier_watch::{self, Action as CarrierAction};

use crate::{carrier_watch_io, nvram};
use crate::clock::unix_now;

use super::Keeper;

/// Carrier-watch state and incremental `/mnt/cbrslog0.txt` reader.
pub(super) struct CarrierWatch {
    watch: carrier_watch::Watch,
    log_tail: carrier_watch_io::CbrsLogTail,
    config: carrier_watch::Config,
    config_at: Option<u64>,
    refused_logged: Vec<String>,
    status_body: String,
}

impl CarrierWatch {
    pub(super) fn new() -> Self {
        Self {
            watch: carrier_watch::Watch::default(),
            log_tail: carrier_watch_io::CbrsLogTail::new(carrier_watch_io::cbrslog_path()),
            config: carrier_watch::Config::default(),
            config_at: None,
            refused_logged: Vec::new(),
            status_body: String::new(),
        }
    }
}

impl Keeper {
    /// Compare active Band 48 transmit carriers (PCell + uplink SCell) against
    /// held authorized grants in `/mnt/cbrslog0.txt`, at most once per second.
    /// Runs in every mode. See `titan_pd_model::carrier_watch`.
    pub(super) fn maintain_carrier_watch(&mut self) {
        if !self.carrier_watch.watch.due(self.now) {
            return;
        }
        if self
            .carrier_watch
            .config_at
            .is_none_or(|at| self.now.saturating_sub(at) >= carrier_watch::CONFIG_EVERY)
        {
            self.carrier_watch.config_at = Some(self.now);
            let cfg = carrier_watch_io::load_config();
            if cfg.refused != self.carrier_watch.refused_logged {
                for line in &cfg.refused {
                    self.note(&format!(
                        "carrier watch: ignored {line:?} in carrier-watch/config"
                    ));
                }
                self.carrier_watch.refused_logged = cfg.refused.clone();
            }
            self.carrier_watch.config = cfg;
        }

        let cache = fs::read(nvram::cache_path()).unwrap_or_default();
        let nvram = carrier_watch::read_nvram(&cache);
        if nvram.cbrs_present && self.carrier_watch.config.mode != carrier_watch::Mode::Off {
            self.carrier_watch.log_tail.poll();
        }
        let wall = unix_now();
        let grants = self
            .carrier_watch
            .log_tail
            .parser
            .active_grants(wall, self.carrier_watch.config.hide_grant);
        let log_seen = self.carrier_watch.log_tail.parser.seen();
        let outcome = self.carrier_watch.watch.observe(
            self.now,
            wall,
            &self.carrier_watch.config,
            &nvram,
            log_seen,
            &grants,
        );
        for line in outcome.logs {
            self.note(&line);
        }
        if outcome.action == CarrierAction::ForceRegrant {
            if let Err(err) = carrier_watch_io::trigger_regrant() {
                let line = self
                    .carrier_watch
                    .watch
                    .regrant_dispatch_failed(self.now, &err);
                self.note(&line);
            }
        }
        let body = self
            .carrier_watch
            .watch
            .status_body(&self.carrier_watch.config);
        if body != self.carrier_watch.status_body {
            self.carrier_watch.status_body = body;
            let text = self
                .carrier_watch
                .watch
                .status_text(&self.carrier_watch.config, self.now);
            let _ = fs::write(carrier_watch_io::status_path(), text);
        }
    }
}
