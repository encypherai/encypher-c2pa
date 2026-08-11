use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use crate::{Error, VerificationReport, C2PA_PROFILE};

pub const DEFAULT_TELEMETRY_ENDPOINT: &str =
    "https://api.encypher.com/api/v1/sdk-validation-failures";
const TELEMETRY_SCHEMA_VERSION: &str = "1.0";
const MAX_STATUS_CODES: usize = 8;

/// Per-verification override for persisted failure telemetry consent.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct TelemetryOptions {
    /// Override the saved preference for this verification. `None` uses the
    /// environment or saved per-user setting and prompts on first interactive use.
    pub enabled: Option<bool>,
    /// Override the Encypher ingest URL, mainly for self-hosting and tests.
    pub endpoint: Option<String>,
    /// Binding name included in the event, such as `rust`, `python`, or `go`.
    pub sdk_name: Option<String>,
}

impl TelemetryOptions {
    pub fn endpoint(&self) -> &str {
        self.endpoint
            .as_deref()
            .unwrap_or(DEFAULT_TELEMETRY_ENDPOINT)
    }
}

/// Privacy-bounded validation failure report. It contains no asset bytes,
/// manifest data, filenames, URLs, keys, trust material, or stable identifiers.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ValidationFailureTelemetry {
    pub schema_version: String,
    pub sdk_name: String,
    pub sdk_version: String,
    pub profile: String,
    pub mime_type: String,
    pub failure_kind: String,
    pub status_codes: Vec<String>,
}

impl ValidationFailureTelemetry {
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string(self)
    }
}

pub fn validation_failure_telemetry(
    mime_type: &str,
    result: &Result<VerificationReport, Error>,
    options: &TelemetryOptions,
) -> Option<ValidationFailureTelemetry> {
    let enabled = crate::telemetry_consent::resolve_telemetry_enabled(options.enabled);
    validation_failure_telemetry_with_enabled(mime_type, result, options, enabled)
}

pub(crate) fn validation_failure_telemetry_with_enabled(
    mime_type: &str,
    result: &Result<VerificationReport, Error>,
    options: &TelemetryOptions,
    enabled: bool,
) -> Option<ValidationFailureTelemetry> {
    if !enabled {
        return None;
    }

    let (failure_kind, status_codes, canonical_mime) = match result {
        Ok(report) if report.integrity == "invalid" => {
            let codes = report
                .validation_results
                .failure
                .iter()
                .map(|status| status.code.as_str());
            (
                "invalid_provenance",
                bounded_codes(codes),
                report.mime_type.clone(),
            )
        }
        Err(Error::Verification(_)) => (
            "verification_error",
            vec!["verification_error".to_string()],
            safe_mime(mime_type)?,
        ),
        _ => return None,
    };

    Some(ValidationFailureTelemetry {
        schema_version: TELEMETRY_SCHEMA_VERSION.to_string(),
        sdk_name: safe_sdk_name(options.sdk_name.as_deref()),
        sdk_version: env!("CARGO_PKG_VERSION").to_string(),
        profile: C2PA_PROFILE.to_string(),
        mime_type: canonical_mime,
        failure_kind: failure_kind.to_string(),
        status_codes,
    })
}

fn bounded_codes<'a>(codes: impl Iterator<Item = &'a str>) -> Vec<String> {
    let codes: Vec<_> = codes
        .filter(|code| is_safe_token(code))
        .collect::<BTreeSet<_>>()
        .into_iter()
        .take(MAX_STATUS_CODES)
        .map(str::to_string)
        .collect();
    if codes.is_empty() {
        vec!["invalid_provenance".to_string()]
    } else {
        codes
    }
}

fn safe_mime(mime_type: &str) -> Option<String> {
    let mime = crate::c2pa_core::spec::canonicalize_mime(mime_type);
    crate::c2pa_core::spec::mimes_for_version(crate::c2pa_core::SpecVersion::V2_4)
        .contains(&mime.as_str())
        .then_some(mime)
}

fn safe_sdk_name(value: Option<&str>) -> String {
    value
        .filter(|name| !name.is_empty() && name.len() <= 24 && is_safe_token(name))
        .unwrap_or("rust")
        .to_string()
}

fn is_safe_token(value: &str) -> bool {
    value
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
}

#[cfg(feature = "telemetry")]
pub(crate) fn enqueue(endpoint: &str, event: ValidationFailureTelemetry) {
    transport::enqueue(endpoint, event);
}

#[cfg(not(feature = "telemetry"))]
pub(crate) fn enqueue(_endpoint: &str, _event: ValidationFailureTelemetry) {}

#[cfg(feature = "telemetry")]
mod transport {
    use std::sync::mpsc::{sync_channel, SyncSender, TrySendError};
    use std::sync::LazyLock;
    use std::time::Duration;

    use super::ValidationFailureTelemetry;

    const QUEUE_CAPACITY: usize = 64;
    const REQUEST_TIMEOUT: Duration = Duration::from_secs(2);
    static SENDER: LazyLock<SyncSender<(String, ValidationFailureTelemetry)>> =
        LazyLock::new(|| {
            let (sender, receiver) =
                sync_channel::<(String, ValidationFailureTelemetry)>(QUEUE_CAPACITY);
            std::thread::Builder::new()
                .name("encypher-c2pa-telemetry".to_string())
                .spawn(move || {
                    let agent = ureq::AgentBuilder::new().timeout(REQUEST_TIMEOUT).build();
                    while let Ok((endpoint, event)) = receiver.recv() {
                        let _ = agent.post(&endpoint).send_json(&event);
                    }
                })
                .ok();
            sender
        });

    pub(super) fn enqueue(endpoint: &str, event: ValidationFailureTelemetry) {
        match SENDER.try_send((endpoint.to_string(), event)) {
            Ok(()) | Err(TrySendError::Full(_)) | Err(TrySendError::Disconnected(_)) => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{validation_failure_telemetry, TelemetryOptions};
    use crate::{
        FreshnessReport, RevocationReport, TrustReport, ValidationResults, VerificationReport,
    };
    use serde_json::Value;

    fn invalid_report() -> VerificationReport {
        VerificationReport {
            schema_version: "1.0".to_string(),
            profile: "c2pa-2.4".to_string(),
            mime_type: "video/mp4".to_string(),
            present: true,
            integrity: "invalid".to_string(),
            signature: "invalid".to_string(),
            hard_binding: "mismatch".to_string(),
            trust: TrustReport {
                status: "not_evaluated".to_string(),
                basis: "none".to_string(),
                validation_time: "2026-08-03T00:00:00Z".to_string(),
                revocation: RevocationReport {
                    status: "not_checked".to_string(),
                    source: "none".to_string(),
                    responder_signature: "not_applicable".to_string(),
                },
                freshness: FreshnessReport {
                    status: "unknown".to_string(),
                    as_of: None,
                },
            },
            policy: None,
            managed_receipt: None,
            validation_state: "invalid".to_string(),
            validation_results: ValidationResults {
                success: vec![],
                informational: vec![],
                failure: vec![
                    crate::VerificationStatus {
                        code: "claimSignature.mismatch".to_string(),
                        url: String::new(),
                        explanation: "must not leave the device".to_string(),
                        details: None,
                    },
                    crate::VerificationStatus {
                        code: "assertion.dataHash.mismatch".to_string(),
                        url: String::new(),
                        explanation: "must not leave the device".to_string(),
                        details: None,
                    },
                ],
            },
            manifest_report: Value::Null,
            content_credentials: None,
        }
    }

    #[test]
    fn emits_only_bounded_codes_for_invalid_provenance() {
        let options = TelemetryOptions {
            enabled: Some(true),
            endpoint: None,
            sdk_name: Some("python".to_string()),
        };
        let event =
            validation_failure_telemetry("video/mp4", &Ok(invalid_report()), &options).unwrap();
        assert_eq!(event.sdk_name, "python");
        assert_eq!(event.mime_type, "video/mp4");
        assert_eq!(event.failure_kind, "invalid_provenance");
        assert_eq!(
            event.status_codes,
            ["assertion.dataHash.mismatch", "claimSignature.mismatch"]
        );
        let json = serde_json::to_string(&event).unwrap();
        assert!(!json.contains("must not leave"));
    }

    #[test]
    fn disabled_telemetry_emits_nothing() {
        assert!(validation_failure_telemetry(
            "video/mp4",
            &Ok(invalid_report()),
            &TelemetryOptions {
                enabled: Some(false),
                ..TelemetryOptions::default()
            }
        )
        .is_none());
    }
}
