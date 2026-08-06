use std::env;
use std::fs;
use std::io::{self, IsTerminal, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use serde::{Deserialize, Serialize};

const CONFIG_DIR_ENV: &str = "ENCYPHER_C2PA_CONFIG_DIR";
const TELEMETRY_ENV: &str = "ENCYPHER_C2PA_TELEMETRY";
const CONFIG_FILE_NAME: &str = "c2pa.json";
static TEMP_FILE_SEQUENCE: AtomicU64 = AtomicU64::new(0);

#[derive(Debug, thiserror::Error)]
pub enum TelemetryPreferenceError {
    #[error("could not resolve a user configuration directory")]
    ConfigDirectoryUnavailable,
    #[error("invalid {TELEMETRY_ENV} value: {0}")]
    InvalidEnvironment(String),
    #[error("could not read or write telemetry preference: {0}")]
    Io(#[from] io::Error),
    #[error("invalid telemetry preference file: {0}")]
    InvalidConfig(#[from] serde_json::Error),
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SavedPreference {
    telemetry_enabled: bool,
}

/// Return the effective saved preference. An environment override takes
/// precedence over the per-user configuration file.
pub fn telemetry_preference() -> Result<Option<bool>, TelemetryPreferenceError> {
    if let Some(value) = env::var_os(TELEMETRY_ENV) {
        let value = value.to_string_lossy();
        return parse_environment_preference(&value)
            .map(Some)
            .ok_or_else(|| TelemetryPreferenceError::InvalidEnvironment(value.into_owned()));
    }
    read_preference(&preference_path()?)
}

/// Persist the telemetry preference for subsequent verifications by every
/// native Encypher C2PA binding used by this operating-system account.
pub fn set_telemetry_enabled(enabled: bool) -> Result<(), TelemetryPreferenceError> {
    write_preference(&preference_path()?, enabled)
}

/// Ask for consent on the first interactive verification and persist the
/// answer. Non-interactive processes return `None` and remain disabled.
pub fn prompt_for_telemetry_consent() -> Result<Option<bool>, TelemetryPreferenceError> {
    if !io::stdin().is_terminal() || !io::stderr().is_terminal() {
        return Ok(None);
    }

    let mut stderr = io::stderr().lock();
    writeln!(
        stderr,
        "Help improve Encypher's free C2PA detection? If enabled, failed verifications send only the media type and validation status codes. No files, manifests, paths, keys, or account identifiers are sent."
    )?;
    write!(stderr, "Enable failure telemetry? [y/N] ")?;
    stderr.flush()?;

    let mut answer = String::new();
    io::stdin().read_line(&mut answer)?;
    let enabled = matches!(answer.trim().to_ascii_lowercase().as_str(), "y" | "yes");
    set_telemetry_enabled(enabled)?;
    writeln!(
        stderr,
        "Failure telemetry {}. Change this later with `encypher-c2pa telemetry on|off`.",
        if enabled { "enabled" } else { "disabled" }
    )?;
    Ok(Some(enabled))
}

pub(crate) fn resolve_telemetry_enabled(explicit: Option<bool>) -> bool {
    if let Some(enabled) = explicit {
        return enabled;
    }
    match telemetry_preference() {
        Ok(Some(enabled)) => enabled,
        Ok(None) => prompt_for_telemetry_consent()
            .ok()
            .flatten()
            .unwrap_or(false),
        Err(error) => {
            if io::stderr().is_terminal() {
                eprintln!("warning: {error}");
            }
            prompt_for_telemetry_consent()
                .ok()
                .flatten()
                .unwrap_or(false)
        }
    }
}

fn parse_environment_preference(value: &str) -> Option<bool> {
    match value.trim().to_ascii_lowercase().as_str() {
        "1" | "true" | "yes" | "on" => Some(true),
        "0" | "false" | "no" | "off" => Some(false),
        _ => None,
    }
}

fn preference_path() -> Result<PathBuf, TelemetryPreferenceError> {
    if let Some(directory) = env::var_os(CONFIG_DIR_ENV) {
        return Ok(PathBuf::from(directory).join(CONFIG_FILE_NAME));
    }
    if let Some(directory) = env::var_os("XDG_CONFIG_HOME") {
        return Ok(PathBuf::from(directory)
            .join("encypher")
            .join(CONFIG_FILE_NAME));
    }
    #[cfg(target_os = "windows")]
    if let Some(directory) = env::var_os("APPDATA") {
        return Ok(PathBuf::from(directory)
            .join("Encypher")
            .join(CONFIG_FILE_NAME));
    }
    if let Some(directory) = env::var_os("HOME") {
        return Ok(PathBuf::from(directory)
            .join(".config")
            .join("encypher")
            .join(CONFIG_FILE_NAME));
    }
    Err(TelemetryPreferenceError::ConfigDirectoryUnavailable)
}

fn read_preference(path: &Path) -> Result<Option<bool>, TelemetryPreferenceError> {
    let contents = match fs::read(path) {
        Ok(contents) => contents,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    let preference: SavedPreference = serde_json::from_slice(&contents)?;
    Ok(Some(preference.telemetry_enabled))
}

fn write_preference(path: &Path, enabled: bool) -> Result<(), TelemetryPreferenceError> {
    let parent = path
        .parent()
        .ok_or(TelemetryPreferenceError::ConfigDirectoryUnavailable)?;
    fs::create_dir_all(parent)?;
    let payload = serde_json::to_vec_pretty(&SavedPreference {
        telemetry_enabled: enabled,
    })?;
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
    use super::{parse_environment_preference, read_preference, write_preference};
    use std::path::PathBuf;

    fn temporary_path(name: &str) -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../target/test-state")
            .join(format!(
                "encypher-c2pa-consent-{}-{name}.json",
                std::process::id()
            ))
    }

    #[test]
    fn saved_preference_round_trips_on_and_off() {
        let path = temporary_path("round-trip");
        write_preference(&path, true).unwrap();
        assert_eq!(read_preference(&path).unwrap(), Some(true));
        write_preference(&path, false).unwrap();
        assert_eq!(read_preference(&path).unwrap(), Some(false));
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn missing_preference_is_unset() {
        let path = temporary_path("missing");
        let _ = std::fs::remove_file(&path);
        assert_eq!(read_preference(&path).unwrap(), None);
    }

    #[test]
    fn environment_values_are_strict_and_case_insensitive() {
        assert_eq!(parse_environment_preference("ON"), Some(true));
        assert_eq!(parse_environment_preference(" false "), Some(false));
        assert_eq!(parse_environment_preference("sometimes"), None);
    }
}
