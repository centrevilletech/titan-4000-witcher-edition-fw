//! Where the keeper keeps its files.

use std::env;
use std::fs;
use std::path::{Path, PathBuf};

use titan_pd_model::config;

/// The keeper's state directory: on the persistent volume when it is
/// mounted (see `config::default_state_dir`).
pub fn state_dir() -> PathBuf {
    config::default_state_dir()
}

/// The keeper's RAM directory (`/tmp` is RAM on the Titan). Hot files live here.
pub fn runtime_dir() -> PathBuf {
    env_path_or("TITAN_PD_RUNTIME", "/tmp/titan-pd-keeper")
}

/// `/mnt/titan-api/<name>` while the persistent volume is mounted, or the
/// directory the variable `env` names (tests).
pub fn volume_dir(env: &str, name: &str) -> Option<PathBuf> {
    if let Ok(path) = env::var(env) {
        return Some(PathBuf::from(path));
    }
    config::persistent_volume_mounted().then(|| Path::new("/mnt/titan-api").join(name))
}

/// The variable `env` (set by tests), else `default`.
pub fn env_or(env: &str, default: &str) -> String {
    env::var(env).unwrap_or_else(|_| default.to_owned())
}

/// The path the variable `env` names (tests), else `default`.
pub fn env_path_or(env: &str, default: &str) -> PathBuf {
    env::var_os(env).map_or_else(|| PathBuf::from(default), PathBuf::from)
}

/// The text of `config` in a volume directory (see `volume_dir`), when the
/// volume is mounted and the file can be read.
pub fn volume_config(env: &str, name: &str) -> Option<String> {
    fs::read_to_string(volume_dir(env, name)?.join("config")).ok()
}
