// Copyright 2026 Encypher Corporation
// SPDX-License-Identifier: Apache-2.0

//! Saved consent for online checks.
//!
//! This mirrors [`crate::telemetry_consent`] and deliberately keeps its own
//! file. The telemetry preference lives in `c2pa.json`, which older SDKs read
//! with `deny_unknown_fields`: adding a key there would make this release's
//! configuration unreadable by an installed older binary. The online choice
//! therefore lives beside it in `online.json`, under the same directory
//! resolution.
//!
//! Only a person at a terminal writes this file, and only a terminal surface
//! reads it. A library call may be verifying an untrusted file on a server,
//! where a choice made at somebody's laptop must not switch fetching on, so
//! library entry points never consult it. The CLI opts in for its own process
//! with [`allow_interactive_online_consent`].

use std::env;
use std::fs;
use std::io::{self, IsTerminal, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use serde::{Deserialize, Serialize};

const ONLINE_ENV: &str = "ENCYPHER_C2PA_ONLINE";
const CONFIG_FILE_NAME: &str = "online.json";
static TEMP_FILE_SEQUENCE: AtomicU64 = AtomicU64::new(0);
static INTERACTIVE_CONSENT_ALLOWED: AtomicBool = AtomicBool::new(false);

#[derive(Debug, thiserror::Error)]
pub enum OnlinePreferenceError {
    #[error("could not resolve a user configuration directory")]
    ConfigDirectoryUnavailable,
    #[error("invalid {ONLINE_ENV} value: {0} (expected on or off)")]
    InvalidEnvironment(String),
    #[error("could not read or write online preference: {0}")]
    Io(#[from] io::Error),
    #[error("invalid online preference file: {0}")]
    InvalidConfig(#[from] serde_json::Error),
}

/// The saved answer to "may this machine fetch what a file references?".
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum OnlinePreference {
    /// Fetch whatever a verification needs, without asking again.
    On,
    /// Never fetch.
    Off,
    /// Ask each time a verification would fetch something.
    Ask,
}

impl OnlinePreference {
    /// The saved token (`"on"`, `"off"`, `"ask"`).
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::On => "on",
            Self::Off => "off",
            Self::Ask => "ask",
        }
    }

    /// Resolve a token, ASCII case-insensitively.
    pub fn from_token(token: &str) -> Option<Self> {
        match token.trim().to_ascii_lowercase().as_str() {
            "on" | "1" | "true" | "yes" => Some(Self::On),
            "off" | "0" | "false" | "no" => Some(Self::Off),
            "ask" | "prompt" => Some(Self::Ask),
            _ => None,
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SavedPreference {
    online: OnlinePreference,
}

/// The effective saved choice. `ENCYPHER_C2PA_ONLINE` is an operator override
/// and wins over the file; it accepts only `on` and `off`, because an operator
/// setting an environment variable on a service has nobody to ask.
pub fn online_preference() -> Result<Option<OnlinePreference>, OnlinePreferenceError> {
    if let Some(enabled) = environment_online()? {
        return Ok(Some(if enabled {
            OnlinePreference::On
        } else {
            OnlinePreference::Off
        }));
    }
    read_preference(&preference_path()?)
}

/// Persist the online choice for later runs of every terminal surface used by
/// this operating-system account.
pub fn set_online_preference(preference: OnlinePreference) -> Result<(), OnlinePreferenceError> {
    write_preference(&preference_path()?, preference)
}

/// Let this process ask the operator before it fetches anything.
///
/// Call it from a command-line program, once, before verifying. Without it the
/// saved file is ignored and no prompt is ever printed, which is what a server
/// embedding the library wants.
pub fn allow_interactive_online_consent() {
    set_interactive_online_consent(true);
}

/// Set this process's interactive-consent flag.
pub(crate) fn set_interactive_online_consent(allowed: bool) {
    INTERACTIVE_CONSENT_ALLOWED.store(allowed, Ordering::Relaxed);
}

pub(crate) fn interactive_online_consent_allowed() -> bool {
    INTERACTIVE_CONSENT_ALLOWED.load(Ordering::Relaxed)
}

/// Read the operator override. `Ok(None)` means it is not set.
pub(crate) fn environment_online() -> Result<Option<bool>, OnlinePreferenceError> {
    let Some(value) = env::var_os(ONLINE_ENV) else {
        return Ok(None);
    };
    let value = value.to_string_lossy();
    match value.trim().to_ascii_lowercase().as_str() {
        "on" | "1" | "true" | "yes" => Ok(Some(true)),
        "off" | "0" | "false" | "no" => Ok(Some(false)),
        _ => Err(OnlinePreferenceError::InvalidEnvironment(
            value.into_owned(),
        )),
    }
}

/// Read the saved file, ignoring the environment override.
pub(crate) fn saved_online_preference() -> Result<Option<OnlinePreference>, OnlinePreferenceError> {
    read_preference(&preference_path()?)
}

/// Ask once, listing every purpose and host this verification would contact.
///
/// `Ok(None)` means there was nobody to ask: a pipe, a cron job, a CI runner.
/// Those runs stay offline rather than blocking on a prompt nobody reads.
/// `a` and `v` persist the answer; `y` and `n` apply to this run only.
pub(crate) fn prompt_for_online_consent(
    lines: &[String],
) -> Result<Option<bool>, OnlinePreferenceError> {
    if !io::stdin().is_terminal() || !io::stderr().is_terminal() {
        return Ok(None);
    }

    let mut stderr = io::stderr().lock();
    writeln!(
        stderr,
        "This file references {} resource{} that only a network check can settle:",
        lines.len(),
        if lines.len() == 1 { "" } else { "s" }
    )?;
    for line in lines {
        writeln!(stderr, "  {line}")?;
    }
    writeln!(
        stderr,
        "Contacting them tells those servers that this file is being checked."
    )?;
    write!(
        stderr,
        "Allow? [y] yes, this time  [N] no  [a] always  [v] never "
    )?;
    stderr.flush()?;

    let mut answer = String::new();
    io::stdin().read_line(&mut answer)?;
    let enabled = match answer.trim().to_ascii_lowercase().as_str() {
        "y" | "yes" => true,
        "a" | "always" => {
            set_online_preference(OnlinePreference::On)?;
            true
        }
        "v" | "never" => {
            set_online_preference(OnlinePreference::Off)?;
            false
        }
        _ => false,
    };
    Ok(Some(enabled))
}

fn preference_path() -> Result<PathBuf, OnlinePreferenceError> {
    crate::config_dir::config_directory()
        .map(|directory| directory.join(CONFIG_FILE_NAME))
        .ok_or(OnlinePreferenceError::ConfigDirectoryUnavailable)
}

fn read_preference(path: &Path) -> Result<Option<OnlinePreference>, OnlinePreferenceError> {
    let contents = match fs::read(path) {
        Ok(contents) => contents,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    let preference: SavedPreference = serde_json::from_slice(&contents)?;
    Ok(Some(preference.online))
}

fn write_preference(
    path: &Path,
    preference: OnlinePreference,
) -> Result<(), OnlinePreferenceError> {
    let parent = path
        .parent()
        .ok_or(OnlinePreferenceError::ConfigDirectoryUnavailable)?;
    fs::create_dir_all(parent)?;
    let payload = serde_json::to_vec_pretty(&SavedPreference { online: preference })?;
    let sequence = TEMP_FILE_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    let temporary = path.with_extension(format!("tmp.{}.{}", std::process::id(), sequence));
    fs::write(&temporary, payload)?;
    #[cfg(target_os = "windows")]
    if path.exists() {
        fs::remove_file(path)?;
    }
    if let Err(error) = fs::rename(&temporary, path) {
        let _ = fs::remove_file(temporary);
        return Err(error.into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        read_preference, write_preference, OnlinePreference, SavedPreference, CONFIG_FILE_NAME,
    };
    use std::path::PathBuf;

    fn temporary_dir(name: &str) -> PathBuf {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../target/test-state")
            .join(format!("online-consent-{}-{name}", std::process::id()));
        std::fs::create_dir_all(&path).expect("test state directory");
        path
    }

    #[test]
    fn saved_choice_round_trips_on_off_and_ask() {
        let directory = temporary_dir("round-trip");
        let path = directory.join(CONFIG_FILE_NAME);
        for preference in [
            OnlinePreference::On,
            OnlinePreference::Off,
            OnlinePreference::Ask,
        ] {
            write_preference(&path, preference).unwrap();
            assert_eq!(read_preference(&path).unwrap(), Some(preference));
        }
        let _ = std::fs::remove_dir_all(directory);
    }

    /// The file is the contract with older and newer installs alike, so the
    /// on-disk spelling is asserted rather than assumed from the enum.
    #[test]
    fn the_saved_file_spells_the_choice_as_a_token() {
        let directory = temporary_dir("spelling");
        let path = directory.join(CONFIG_FILE_NAME);
        write_preference(&path, OnlinePreference::Ask).unwrap();
        let contents = std::fs::read_to_string(&path).unwrap();
        assert!(contents.contains("\"online\""), "{contents}");
        assert!(contents.contains("\"ask\""), "{contents}");
        let _ = std::fs::remove_dir_all(directory);
    }

    #[test]
    fn an_unset_choice_reads_as_none() {
        let directory = temporary_dir("missing");
        let path = directory.join(CONFIG_FILE_NAME);
        let _ = std::fs::remove_file(&path);
        assert_eq!(read_preference(&path).unwrap(), None);
        let _ = std::fs::remove_dir_all(directory);
    }

    /// The telemetry key belongs to `c2pa.json`. Finding it here means the two
    /// files were merged by mistake, and the merge would break older installs.
    #[test]
    fn an_unrelated_key_is_refused_rather_than_ignored() {
        let directory = temporary_dir("foreign-key");
        let path = directory.join(CONFIG_FILE_NAME);
        std::fs::write(&path, br#"{"online":"on","telemetry_enabled":true}"#).unwrap();
        assert!(read_preference(&path).is_err());
        let _ = std::fs::remove_dir_all(directory);
    }

    #[test]
    fn tokens_are_case_insensitive_and_strict() {
        assert_eq!(
            OnlinePreference::from_token("ON"),
            Some(OnlinePreference::On)
        );
        assert_eq!(
            OnlinePreference::from_token(" ask "),
            Some(OnlinePreference::Ask)
        );
        assert_eq!(OnlinePreference::from_token("sometimes"), None);
    }

    #[test]
    fn the_saved_shape_is_a_single_online_key() {
        let payload = serde_json::to_string(&SavedPreference {
            online: OnlinePreference::On,
        })
        .unwrap();
        assert_eq!(payload, r#"{"online":"on"}"#);
    }
}
