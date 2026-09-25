// Copyright 2026 Encypher Corporation
// SPDX-License-Identifier: Apache-2.0

//! Update check for the command line.
//!
//! Each release carries verification fixes and a refreshed trust snapshot, so
//! an old binary judges files against old trust lists. Once a day, when a
//! person is at the terminal, the CLI reads the crates.io index entry for this
//! crate and, if a newer release exists, offers to install it.
//!
//! The check is on by default and bounded: one GET for a static index file,
//! carrying no file, path, or identifier, with a short timeout and silent
//! failure. Runs with nobody at the terminal (pipes, CI, cron) never check,
//! and `--offline` suppresses it for a run. The libraries never check: a
//! server embedding them must not contact anyone on its own initiative.
//!
//! Settings live in `update.json` in the SDK configuration directory:
//! `{"check": false}` turns the check off. `ENCYPHER_C2PA_UPDATE_CHECK=on|off`
//! overrides the file.

use std::env;
use std::fs;
use std::io::{self, IsTerminal, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

const CRATE_NAME: &str = "encypher-c2pa-cli";
const CURRENT_VERSION: &str = env!("CARGO_PKG_VERSION");
/// The crates.io sparse-index entry for this crate: one JSON line per
/// published version, with its yanked flag. A static file, meant for tools.
const INDEX_URL: &str = "https://index.crates.io/en/cy/encypher-c2pa-cli";
/// Points the check at a mirror or a test server.
const INDEX_URL_ENV: &str = "ENCYPHER_C2PA_UPDATE_INDEX_URL";
const UPDATE_ENV: &str = "ENCYPHER_C2PA_UPDATE_CHECK";
const SETTINGS_FILE: &str = "update.json";
const CHECK_INTERVAL_SECS: u64 = 24 * 60 * 60;
const REQUEST_TIMEOUT: Duration = Duration::from_secs(2);
const MAX_INDEX_BYTES: u64 = 1024 * 1024;
const USER_AGENT: &str = concat!("encypher-c2pa-cli/", env!("CARGO_PKG_VERSION"));
const RELEASES_URL: &str = "https://github.com/encypherai/encypher-c2pa/releases";

/// Contents of `update.json`. Unknown keys are kept readable so a later
/// release can add fields without breaking this one.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub(crate) struct UpdateSettings {
    /// Check for a newer release when a command starts.
    pub check: bool,
    /// Unix time of the last check attempt, successful or not.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_checked: Option<u64>,
    /// A release the user chose to skip. A later one is still offered.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub skipped_version: Option<String>,
}

impl Default for UpdateSettings {
    fn default() -> Self {
        Self {
            check: true,
            last_checked: None,
            skipped_version: None,
        }
    }
}

/// A release version: `major.minor.patch`, with a flag for a pre-release
/// suffix. Build metadata is ignored.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Version {
    pub triple: (u64, u64, u64),
    pub prerelease: bool,
}

impl Version {
    pub fn parse(text: &str) -> Option<Self> {
        let text = text.split('+').next()?;
        let (core, prerelease) = match text.split_once('-') {
            Some((core, _)) => (core, true),
            None => (text, false),
        };
        let mut parts = core.split('.').map(|part| {
            (!part.is_empty() && part.bytes().all(|b| b.is_ascii_digit()))
                .then(|| part.parse::<u64>().ok())
                .flatten()
        });
        let triple = (parts.next()??, parts.next()??, parts.next()??);
        parts
            .next()
            .is_none()
            .then_some(Self { triple, prerelease })
    }

    /// Whether this stable release supersedes `current`. A stable release with
    /// the same numbers as a pre-release supersedes it.
    fn supersedes(&self, current: &Self) -> bool {
        self.triple > current.triple || (self.triple == current.triple && current.prerelease)
    }
}

impl std::fmt::Display for Version {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let (major, minor, patch) = self.triple;
        write!(f, "{major}.{minor}.{patch}")
    }
}

/// The newest stable, unyanked release in a sparse-index file that supersedes
/// `current`. Lines that do not parse are skipped: the index is read for one
/// number and nothing in it is trusted beyond that.
pub(crate) fn newest_release(index: &str, current: &Version) -> Option<Version> {
    #[derive(Deserialize)]
    struct Entry {
        vers: String,
        #[serde(default)]
        yanked: bool,
    }
    index
        .lines()
        .filter_map(|line| serde_json::from_str::<Entry>(line).ok())
        .filter(|entry| !entry.yanked)
        .filter_map(|entry| Version::parse(&entry.vers))
        .filter(|version| !version.prerelease && version.supersedes(current))
        .max_by_key(|version| version.triple)
}

/// Whether a day has passed since the last attempt. A timestamp in the future
/// means the clock moved, so the check runs rather than waiting it out.
pub(crate) fn check_due(last_checked: Option<u64>, now: u64) -> bool {
    match last_checked {
        None => true,
        Some(last) => last > now || now - last >= CHECK_INTERVAL_SECS,
    }
}

/// `ENCYPHER_C2PA_UPDATE_CHECK`: `Some(true)`/`Some(false)` when set to a
/// recognized value, `None` when unset or unrecognized.
fn environment_setting() -> Option<bool> {
    let value = env::var(UPDATE_ENV).ok()?;
    match value.trim().to_ascii_lowercase().as_str() {
        "1" | "true" | "yes" | "on" => Some(true),
        "0" | "false" | "no" | "off" => Some(false),
        _ => {
            eprintln!("warning: ignoring {UPDATE_ENV}={value} (expected on or off)");
            None
        }
    }
}

fn settings_path() -> Option<PathBuf> {
    encypher_c2pa::config_directory().map(|directory| directory.join(SETTINGS_FILE))
}

pub(crate) fn read_settings(path: &Path) -> io::Result<UpdateSettings> {
    match fs::read(path) {
        Ok(contents) => serde_json::from_slice(&contents)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error)),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(UpdateSettings::default()),
        Err(error) => Err(error),
    }
}

fn write_settings(path: &Path, settings: &UpdateSettings) -> io::Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let payload = serde_json::to_vec_pretty(settings).map_err(io::Error::other)?;
    let temporary = path.with_extension(format!("tmp.{}", std::process::id()));
    fs::write(&temporary, payload)?;
    #[cfg(target_os = "windows")]
    if path.exists() {
        fs::remove_file(path)?;
    }
    fs::rename(&temporary, path).inspect_err(|_| {
        let _ = fs::remove_file(&temporary);
    })
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs())
}

fn current_version() -> Version {
    Version::parse(CURRENT_VERSION).expect("the crate version is a release version")
}

fn fetch_index() -> Result<String, String> {
    let url = env::var(INDEX_URL_ENV).unwrap_or_else(|_| INDEX_URL.to_string());
    let agent = ureq::AgentBuilder::new().timeout(REQUEST_TIMEOUT).build();
    let response = agent
        .get(&url)
        .set("User-Agent", USER_AGENT)
        .call()
        .map_err(|error| error.to_string())?;
    let mut body = String::new();
    response
        .into_reader()
        .take(MAX_INDEX_BYTES)
        .read_to_string(&mut body)
        .map_err(|error| error.to_string())?;
    Ok(body)
}

/// The check run when a command starts. Returns an exit code only when it
/// installed an update and re-ran the command on the new binary.
pub(crate) fn check_on_start(offline: bool) -> Option<ExitCode> {
    if offline || !io::stdin().is_terminal() || !io::stderr().is_terminal() {
        return None;
    }
    let from_environment = environment_setting();
    if from_environment == Some(false) {
        return None;
    }
    let path = settings_path()?;
    let mut settings = match read_settings(&path) {
        Ok(settings) => settings,
        Err(error) => {
            eprintln!("warning: ignoring {} ({error})", path.display());
            return None;
        }
    };
    let now = now();
    if !(from_environment == Some(true) || settings.check) || !check_due(settings.last_checked, now)
    {
        return None;
    }
    // Recorded before the request, so an offline laptop pays the timeout once
    // a day rather than on every command.
    settings.last_checked = Some(now);
    let _ = write_settings(&path, &settings);

    let index = fetch_index().ok()?;
    let newest = newest_release(&index, &current_version())?;
    if settings.skipped_version.as_deref() == Some(newest.to_string().as_str()) {
        return None;
    }
    match prompt(&newest).ok()? {
        Answer::Update => install(&newest, true),
        Answer::Skip => {
            settings.skipped_version = Some(newest.to_string());
            let _ = write_settings(&path, &settings);
            None
        }
        Answer::StopChecking => {
            settings.check = false;
            let _ = write_settings(&path, &settings);
            eprintln!(
                "Update checks are off. Turn them back on with: encypher-c2pa update-check on"
            );
            None
        }
        Answer::NotNow => None,
    }
}

enum Answer {
    Update,
    NotNow,
    Skip,
    StopChecking,
}

fn prompt(newest: &Version) -> io::Result<Answer> {
    let mut stderr = io::stderr().lock();
    writeln!(
        stderr,
        "encypher-c2pa {newest} is available. You have {CURRENT_VERSION}, with trust lists dated {}.",
        encypher_c2pa::DEFAULT_TRUST_SNAPSHOT_DATE
    )?;
    writeln!(
        stderr,
        "Releases carry verification fixes and refreshed trust lists."
    )?;
    write!(
        stderr,
        "Update now? [y] yes  [N] not now  [s] skip this version  [o] stop checking "
    )?;
    stderr.flush()?;
    let mut answer = String::new();
    io::stdin().read_line(&mut answer)?;
    Ok(match answer.trim().to_ascii_lowercase().as_str() {
        "y" | "yes" => Answer::Update,
        "s" | "skip" => Answer::Skip,
        "o" | "off" | "stop" => Answer::StopChecking,
        _ => Answer::NotNow,
    })
}

/// Whether this binary sits in cargo's install directory, so `cargo install`
/// replaces it.
fn installed_by_cargo(executable: &Path) -> bool {
    let cargo_home = env::var_os("CARGO_HOME")
        .map(PathBuf::from)
        .or_else(|| env::var_os("HOME").map(|home| PathBuf::from(home).join(".cargo")));
    let (Some(cargo_home), Some(directory)) = (cargo_home, executable.parent()) else {
        return false;
    };
    let canonical = |path: &Path| fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf());
    canonical(directory) == canonical(&cargo_home.join("bin"))
}

fn install_command(version: &Version) -> String {
    format!("cargo install {CRATE_NAME} --version {version} --locked")
}

/// Install `version` with cargo. With `rerun`, run the interrupted command
/// again on the new binary and return its exit code; a failed install falls
/// back to the running binary.
fn install(version: &Version, rerun: bool) -> Option<ExitCode> {
    let executable = env::current_exe().ok();
    if !executable.as_deref().is_some_and(installed_by_cargo) {
        eprintln!(
            "This copy was not installed by cargo. Update with: {}\nRelease notes: {RELEASES_URL}/tag/v{version}",
            install_command(version)
        );
        return None;
    }
    eprintln!("Running: {}", install_command(version));
    let version_text = version.to_string();
    let status = Command::new("cargo")
        .args([
            "install",
            CRATE_NAME,
            "--version",
            &version_text,
            "--locked",
        ])
        .status();
    match status {
        Ok(status) if status.success() => {}
        Ok(_) | Err(_) => {
            eprintln!("The update did not complete; continuing with {CURRENT_VERSION}.");
            return None;
        }
    }
    eprintln!("Updated to {version}.");
    if !rerun {
        return Some(ExitCode::SUCCESS);
    }
    let status = Command::new(executable?)
        .args(env::args_os().skip(1))
        .status()
        .ok()?;
    Some(ExitCode::from(
        status
            .code()
            .and_then(|code| u8::try_from(code).ok())
            .unwrap_or(1),
    ))
}

/// `encypher-c2pa update`: check now and install a newer release. An explicit
/// request, so it ignores the saved setting and the daily interval.
pub(crate) fn run_update() -> ExitCode {
    let index = match fetch_index() {
        Ok(index) => index,
        Err(error) => {
            eprintln!("could not reach the crates.io index: {error}");
            return ExitCode::FAILURE;
        }
    };
    if let Some(path) = settings_path() {
        if let Ok(mut settings) = read_settings(&path) {
            settings.last_checked = Some(now());
            let _ = write_settings(&path, &settings);
        }
    }
    match newest_release(&index, &current_version()) {
        None => {
            println!(
                "encypher-c2pa {CURRENT_VERSION} is the latest release (trust lists dated {}).",
                encypher_c2pa::DEFAULT_TRUST_SNAPSHOT_DATE
            );
            ExitCode::SUCCESS
        }
        Some(newest) => {
            println!("encypher-c2pa {newest} is available. You have {CURRENT_VERSION}.");
            install(&newest, false).unwrap_or(ExitCode::FAILURE)
        }
    }
}

/// `encypher-c2pa update-check on|off|status`.
pub(crate) fn run_update_check_setting(enable: Option<bool>) -> ExitCode {
    let Some(path) = settings_path() else {
        eprintln!("could not resolve a user configuration directory");
        return ExitCode::FAILURE;
    };
    let mut settings = match read_settings(&path) {
        Ok(settings) => settings,
        Err(error) => {
            eprintln!("could not read {}: {error}", path.display());
            return ExitCode::FAILURE;
        }
    };
    if let Some(enable) = enable {
        settings.check = enable;
        if let Err(error) = write_settings(&path, &settings) {
            eprintln!("could not write {}: {error}", path.display());
            return ExitCode::FAILURE;
        }
    }
    let effective = match environment_setting() {
        Some(value) => format!(
            "{} ({UPDATE_ENV} overrides the saved setting)",
            if value { "on" } else { "off" }
        ),
        None => (if settings.check { "on" } else { "off" }).to_string(),
    };
    println!("update check: {effective}");
    println!("settings: {}", path.display());
    ExitCode::SUCCESS
}

#[cfg(test)]
mod tests {
    use super::{check_due, newest_release, read_settings, UpdateSettings, Version};

    fn version(text: &str) -> Version {
        Version::parse(text).unwrap()
    }

    fn index(lines: &[(&str, bool)]) -> String {
        lines
            .iter()
            .map(|(vers, yanked)| {
                format!(r#"{{"name":"encypher-c2pa-cli","vers":"{vers}","deps":[],"cksum":"00","features":{{}},"yanked":{yanked}}}"#)
            })
            .collect::<Vec<_>>()
            .join("\n")
    }

    #[test]
    fn newest_release_skips_yanked_prerelease_and_older_versions() {
        let index = index(&[
            ("1.0.5", false),
            ("1.0.6", false),
            ("1.0.10", false),
            ("1.1.0", true),
            ("1.2.0-rc.1", false),
        ]);
        assert_eq!(
            newest_release(&index, &version("1.0.6")),
            Some(version("1.0.10")),
            "numeric, not lexical, ordering; yanked and pre-releases never offered"
        );
        assert_eq!(newest_release(&index, &version("1.0.10")), None);
        assert_eq!(newest_release(&index, &version("2.0.0")), None);
    }

    #[test]
    fn stable_release_supersedes_its_own_prerelease() {
        let index = index(&[("1.1.0", false)]);
        assert_eq!(
            newest_release(&index, &version("1.1.0-rc.2")),
            Some(version("1.1.0"))
        );
    }

    #[test]
    fn malformed_index_lines_are_ignored() {
        let index = format!(
            "not json\n{{\"vers\":\"1.0.7; rm -rf /\"}}\n{{\"vers\":\"01x.2.3\"}}\n{}",
            index(&[("1.0.7", false)])
        );
        assert_eq!(
            newest_release(&index, &version("1.0.6")),
            Some(version("1.0.7"))
        );
        assert_eq!(Version::parse("1.0"), None);
        assert_eq!(Version::parse("1.0.0.0"), None);
    }

    #[test]
    fn check_runs_once_a_day_and_after_a_clock_jump_back() {
        let day = 24 * 60 * 60;
        assert!(check_due(None, 1_000));
        assert!(!check_due(Some(1_000), 1_000 + day - 1));
        assert!(check_due(Some(1_000), 1_000 + day));
        assert!(check_due(Some(1_000 + day), 1_000), "clock moved backwards");
    }

    #[test]
    fn settings_default_to_checking_and_honor_check_false() {
        let directory =
            std::env::temp_dir().join(format!("encypher-update-settings-{}", std::process::id()));
        std::fs::create_dir_all(&directory).unwrap();
        let path = directory.join("update.json");

        assert!(read_settings(&path).unwrap().check, "no file means on");

        std::fs::write(&path, r#"{"check": false, "added_later": 1}"#).unwrap();
        assert_eq!(
            read_settings(&path).unwrap(),
            UpdateSettings {
                check: false,
                ..UpdateSettings::default()
            },
            "a hand-written file turns the check off; unknown keys are tolerated"
        );

        std::fs::write(&path, "{").unwrap();
        assert!(read_settings(&path).is_err());
        std::fs::remove_dir_all(&directory).unwrap();
    }
}
