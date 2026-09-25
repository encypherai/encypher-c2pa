// Copyright 2026 Encypher Corporation
// SPDX-License-Identifier: Apache-2.0

//! Where saved preferences live.

use std::env;
use std::path::PathBuf;

const CONFIG_DIR_ENV: &str = "ENCYPHER_C2PA_CONFIG_DIR";

/// The directory holding this SDK's saved preferences for the current
/// operating-system account, or `None` when none can be resolved (containers,
/// service accounts, HOME-less shells).
///
/// Resolution order: `ENCYPHER_C2PA_CONFIG_DIR`, `$XDG_CONFIG_HOME/encypher`,
/// `%APPDATA%\Encypher` on Windows, then `$HOME/.config/encypher`.
pub fn config_directory() -> Option<PathBuf> {
    if let Some(directory) = env::var_os(CONFIG_DIR_ENV) {
        return Some(PathBuf::from(directory));
    }
    if let Some(directory) = env::var_os("XDG_CONFIG_HOME") {
        return Some(PathBuf::from(directory).join("encypher"));
    }
    #[cfg(target_os = "windows")]
    if let Some(directory) = env::var_os("APPDATA") {
        return Some(PathBuf::from(directory).join("Encypher"));
    }
    env::var_os("HOME").map(|directory| PathBuf::from(directory).join(".config").join("encypher"))
}
