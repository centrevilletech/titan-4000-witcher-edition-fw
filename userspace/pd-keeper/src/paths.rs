//! Where the keeper keeps its files.

use std::env;
use std::path::PathBuf;

use titan_pd_model::config;

/// The keeper's state directory: on the persistent volume when it is
/// mounted (see `config::default_state_dir`).
pub fn state_dir() -> PathBuf {
    config::default_state_dir()
}

/// The keeper's RAM directory (`/tmp` is RAM on the Titan). Hot files live here.
pub fn runtime_dir() -> PathBuf {
    env::var_os("TITAN_PD_RUNTIME")
        .map_or_else(|| PathBuf::from("/tmp/titan-pd-keeper"), PathBuf::from)
}
