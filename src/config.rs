//! Trust-on-first-use store for the file channel.
//!
//! Maps `endpoint -> peer public key`, pinned on first `connect --key` and
//! reused thereafter. Kept in `known_servers.toml` next to the settings file
//! actually in use. This module is ONLY the trust store — the identity itself
//! lives in the settings file's `[identity]` section (see `settings.rs`), and
//! the old standalone identity/config document no longer exists.

use anyhow::Result;
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

/// Path to the trust store, kept next to the settings file in use.
pub fn known_servers_path(settings_path: &Path) -> PathBuf {
    let mut p = settings_path.to_path_buf();
    p.set_file_name("known_servers.toml");
    p
}

/// Look up a previously-pinned peer public key for an endpoint.
pub fn load_known_server(settings_path: &Path, endpoint: &str) -> Option<String> {
    let content = fs::read_to_string(known_servers_path(settings_path)).ok()?;
    let map: HashMap<String, String> = toml::from_str(&content).ok()?;
    map.get(endpoint).cloned()
}

/// Pin (or update) a peer public key for an endpoint.
pub fn save_known_server(settings_path: &Path, endpoint: &str, public_key: &str) -> Result<()> {
    let path = known_servers_path(settings_path);
    let mut map: HashMap<String, String> = fs::read_to_string(&path)
        .ok()
        .and_then(|c| toml::from_str(&c).ok())
        .unwrap_or_default();
    map.insert(endpoint.to_string(), public_key.to_string());
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent)?;
        }
    }
    fs::write(&path, toml::to_string(&map)?)?;
    Ok(())
}
