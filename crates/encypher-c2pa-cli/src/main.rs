// Copyright 2026 Encypher Corporation
// SPDX-License-Identifier: Apache-2.0

use std::collections::HashMap;
use std::fs::{self, OpenOptions};
use std::io::{self, Read};
#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::{Parser, Subcommand, ValueEnum};
use encypher_c2pa::{
    allow_interactive_online_consent, binding_target, detached_manifest_evidence_with_options,
    mime_from_path, online_preference, request_soft_binding_receipt_verification,
    resolve_soft_binding, set_online_preference, set_telemetry_enabled, supported_mime_types_for,
    telemetry_preference, verify_ertmp_with_options, verify_file, verify_fragmented_with_options,
    verify_manifest_store_only, verify_stream_with_options, verify_with_caller_verified_binding,
    verify_with_manifest_store, verify_with_options, CallerBindingEvidence, CallerBindingVerdict,
    CawgStoreHost, CawgTrustConfiguration, Error, ErtmpInput, GraphInputs, ManifestBindingTarget,
    OnlinePreference, SoftBindingQuery, SoftBindingResolverOptions, StreamEncapsulation,
    StreamMethod, TelemetryOptions, TrustListSource, VerifyOptions,
};

mod encypher_api;
mod update;

const MAX_PATH_ASSET_BYTES: u64 = 128 * 1024 * 1024;

#[derive(Debug, Parser)]
#[command(name = "encypher-c2pa", version, about = "Local C2PA verification")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum TelemetrySetting {
    On,
    Off,
    Status,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum UpdateCheckSetting {
    /// Check for a newer release once a day (the default).
    On,
    /// Never check.
    Off,
    /// Print the setting and where it is saved.
    Status,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum OnlineSetting {
    /// Fetch what a verification needs, without asking again.
    On,
    /// Never fetch.
    Off,
    /// Ask each time a verification would fetch something.
    Ask,
    /// Print the saved choice.
    Status,
}

// `Verify` carries every CLI flag inline, which clap's derive requires: a
// boxed or flattened args struct cannot be parsed into a subcommand variant.
// The enum is built once, from argv, and dropped at the end of main, so the
// variant size difference has no runtime cost worth restructuring for.
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Subcommand)]
enum Command {
    /// Verify one local asset. First interactive use asks about failure telemetry.
    Verify {
        asset: PathBuf,
        #[arg(long)]
        mime: Option<String>,
        /// External C2PA Manifest Store (`.c2pa`) to verify the asset against.
        /// Use when the manifest is a sidecar, or was fetched from the URI the
        /// asset declares. This tool never fetches it for you.
        #[arg(
            long,
            value_name = "FILE",
            conflicts_with_all = ["fragment", "encapsulation", "encypher_api"]
        )]
        manifest: Option<PathBuf>,
        /// Fragmented BMFF media segment (`.m4s`). Repeat for each available segment.
        #[arg(long, value_name = "FILE", conflicts_with = "encypher_api")]
        fragment: Vec<PathBuf>,
        /// Zero-based fragment/segment index where the player expects a seek.
        /// Repeat for each discontinuity.
        #[arg(long, value_name = "N", requires = "fragment")]
        expected_seek: Vec<usize>,
        /// Encapsulation the stream was packaged as. With `--fragment`, turns
        /// on stream verification: brands are gated and the binding is read
        /// from the init manifest.
        #[arg(long, value_name = "fmp4|cmaf", requires = "fragment")]
        encapsulation: Option<String>,
        /// C2PA protection method the stream was signed under. Requires
        /// `--encapsulation`.
        #[arg(
            long,
            value_name = "verifiable-segment-info|per-segment",
            requires = "encapsulation"
        )]
        segment_mode: Option<String>,
        /// Claim-signer trust anchors (PEM bundle). Repeatable; bundles merge.
        #[arg(long, value_name = "PEM")]
        trust: Vec<PathBuf>,
        /// Claim trust sources with crJSON provenance. Each file is a JSON
        /// array of `{uri,type,identifier?,certificates_pem}` entries.
        #[arg(long, value_name = "JSON")]
        claim_trust_sources: Vec<PathBuf>,
        /// Timestamp-authority trust anchors (PEM bundle). Repeatable.
        #[arg(long, value_name = "PEM")]
        tsa_trust: Vec<PathBuf>,
        /// TSA trust sources with crJSON provenance. Each file is a JSON array
        /// of `{uri,type,identifier?,certificates_pem}` entries.
        #[arg(long, value_name = "JSON")]
        tsa_trust_sources: Vec<PathBuf>,
        /// Directly allowed end-entity certificates (PEM bundle). Repeatable.
        #[arg(long, visible_alias = "allowed-certs", value_name = "PEM")]
        allowed: Vec<PathBuf>,
        /// CAWG named-actor (identity) trust anchors (PEM bundle). Repeatable.
        #[arg(long, value_name = "PEM")]
        cawg_trust: Vec<PathBuf>,
        /// Directly allowed CAWG end-entity certificates (PEM). Repeatable.
        #[arg(long, value_name = "PEM")]
        cawg_allowed: Vec<PathBuf>,
        /// Typed CAWG trust configurations: a JSON array of
        /// `{profile: base|smime_interim, certificates_pem, not_before?,
        /// not_after?}`. Repeatable; arrays concatenate in flag order.
        #[arg(long, value_name = "JSON")]
        cawg_trust_configurations: Vec<PathBuf>,
        /// RFC 3339 start of trust for the caller-supplied trust anchors above.
        #[arg(long, value_name = "RFC3339")]
        trust_anchor_not_before: Option<String>,
        /// RFC 3339 end of trust for the caller-supplied trust anchors above.
        #[arg(long, value_name = "RFC3339")]
        trust_anchor_not_after: Option<String>,
        /// Verify with caller-supplied trust only; ignore bundled snapshots.
        #[arg(long)]
        no_default_trust: bool,
        /// Pinned offline did:web DID documents for CAWG ICA issuers.
        /// Repeatable; each file is a DID document, an array of documents, or
        /// a DID -> document map. Without it did:web resolution fails closed.
        #[arg(long, value_name = "JSON")]
        cawg_did_documents: Vec<PathBuf>,
        /// Trust an ICA issuer DID directly. Repeatable.
        #[arg(long, value_name = "DID")]
        cawg_ica_trusted_issuer: Vec<String>,
        /// Trust an ICA DID controller anchor. Repeatable.
        #[arg(long, value_name = "DID")]
        cawg_ica_trust_anchor: Vec<String>,
        /// Offline ICA revocation bitstrings as a JSON URI -> base64 map.
        /// Repeatable; later files override earlier entries.
        #[arg(long, value_name = "JSON")]
        cawg_ica_status_lists: Vec<PathBuf>,
        /// Refuse the CAWG field-order signer payload that c2pa-rs writes,
        /// without the rest of the conformance posture.
        #[arg(long)]
        cawg_strict_encoding: bool,
        /// Apply strict technical validation. With C2PA 2.4 this is the
        /// published Conformance Program posture. With 2.5 it is conformance
        /// mode under the core-spec bar, not certified scope or an unpublished
        /// program profile.
        #[arg(long)]
        strict_conformance: bool,
        /// C2PA validation policy: `2.2`, `2.4` (the default and current
        /// behavior), or `2.5` (the proposed draft). Any other value fails with
        /// `unsupported_spec_version` before the asset is read.
        #[arg(long, visible_alias = "spec-version", value_name = "2.2|2.4|2.5")]
        spec: Option<String>,
        /// RFC 3339 validation instant (default: current UTC time).
        #[arg(long, visible_alias = "validation-time", value_name = "RFC3339")]
        time: Option<String>,
        /// Send anonymous, bounded validation failure codes to Encypher.
        #[arg(long)]
        telemetry: bool,
        /// Disable failure telemetry and save that preference.
        #[arg(long, conflicts_with = "telemetry")]
        no_telemetry: bool,
        /// Override the failure telemetry endpoint.
        #[arg(long, value_name = "URL")]
        telemetry_endpoint: Option<String>,
        /// Allow this run to fetch what the asset references: a manifest store
        /// held elsewhere, certificate revocation status, a did:web document,
        /// externally stored content. Nothing is fetched without this flag,
        /// the saved choice, or the ENCYPHER_C2PA_ONLINE environment variable.
        #[arg(long)]
        online: bool,
        /// Keep this run offline whatever is saved or set in the environment.
        #[arg(long, conflicts_with = "online")]
        offline: bool,
        /// Let online checks reach loopback, private, and link-local addresses
        /// and accept plaintext http. For an intranet deployment whose
        /// manifest repository or OCSP responder is on an internal host. Do
        /// not set it where files arrive from strangers.
        #[arg(long)]
        online_allow_private_networks: bool,
        #[arg(long)]
        json: bool,
        /// Ask Encypher to validate the raw C2PA manifest and match its signed
        /// registry. Requires `ENCYPHER_API_KEY` or `ENCYPHER_API_TOKEN`.
        /// Sends the file SHA-256 plus the embedded manifest carrier, not the
        /// media bytes. The response never changes the local verdict or exit code.
        #[arg(long)]
        encypher_api: bool,
        /// Override the Encypher verification endpoint (self-hosting, tests).
        #[arg(long, value_name = "URL", hide = true)]
        encypher_api_endpoint: Option<String>,
    },
    /// Validate a C2PA Manifest Store without claiming an asset-content match.
    VerifyStore {
        manifest: PathBuf,
        /// JSON file matching VerifyOptions.
        #[arg(long, value_name = "JSON")]
        options: Option<PathBuf>,
        #[arg(long)]
        json: bool,
    },
    /// Derive the exact hard-binding target a trusted caller must compare.
    BindingTarget {
        manifest: PathBuf,
        #[arg(long)]
        hostless: bool,
        #[arg(long, value_name = "JSON")]
        options: Option<PathBuf>,
        #[arg(long)]
        json: bool,
    },
    /// Validate a store using an asset comparison made by a trusted caller.
    VerifyCallerBinding {
        manifest: PathBuf,
        #[arg(long, value_name = "MIME")]
        mime: String,
        /// JSON target emitted by `binding-target`.
        #[arg(long, value_name = "JSON")]
        target: PathBuf,
        #[arg(long)]
        engine: String,
        #[arg(long)]
        hostless: bool,
        #[arg(long, conflicts_with = "mismatch")]
        matched: bool,
        #[arg(long, value_name = "EXPLANATION", conflicts_with = "matched")]
        mismatch: Option<String>,
        #[arg(long, value_name = "JSON")]
        options: Option<PathBuf>,
        #[arg(long)]
        json: bool,
    },
    /// Verify caller-parsed Enhanced RTMP events in exact transmission order.
    VerifyErtmp {
        /// JSON file containing bilateral capsEx, objectEncoding and events.
        input: PathBuf,
        /// JSON file matching VerifyOptions. Omission selects C2PA 2.5.
        #[arg(long, value_name = "JSON")]
        options: Option<PathBuf>,
        #[arg(long)]
        json: bool,
    },
    /// Recover and verify manifests through an explicitly allowlisted service.
    ResolveSoftBinding {
        asset: PathBuf,
        #[arg(long)]
        mime: Option<String>,
        /// Service origin or base URL hosting the well-known discovery document.
        #[arg(long, value_name = "URL")]
        service_root: String,
        /// JSON file containing one explicitly tagged query route.
        #[arg(long, value_name = "JSON")]
        query: PathBuf,
        /// Exact allowed endpoint origin (`scheme://host[:port]`). Repeat for
        /// every discovery, federation, or repository origin.
        #[arg(long, value_name = "ORIGIN", required = true)]
        allowed_origin: Vec<String>,
        /// Permit explicitly allowlisted private destinations and plaintext HTTP.
        #[arg(long)]
        allow_private_networks: bool,
        /// Maximum matches requested from the service (1-100; default 10).
        #[arg(long, default_value_t = 10)]
        max_results: u16,
        /// Fetch the service's optional status document as operational evidence.
        #[arg(long)]
        fetch_status: bool,
        /// Fetch repository-reported receipt evidence for recovered manifests.
        #[arg(long)]
        fetch_receipts: bool,
        /// JSON file matching VerifyOptions. The service cannot select policy.
        #[arg(long, value_name = "JSON")]
        options: Option<PathBuf>,
        #[arg(long)]
        json: bool,
    },
    /// Ask a repository to report whether a caller-supplied receipt verifies.
    VerifySoftBindingReceipt {
        #[arg(long, value_name = "URL")]
        service_root: String,
        #[arg(long)]
        manifest_id: String,
        #[arg(long, value_name = "JSON")]
        receipt: PathBuf,
        #[arg(long, value_name = "ORIGIN", required = true)]
        allowed_origin: Vec<String>,
        #[arg(long)]
        allow_private_networks: bool,
        #[arg(long, value_name = "JSON")]
        options: Option<PathBuf>,
    },
    /// Read or change the saved failure telemetry preference.
    Telemetry {
        #[arg(value_enum)]
        setting: TelemetrySetting,
    },
    /// Read or change the saved choice about online checks.
    Online {
        #[arg(value_enum)]
        setting: OnlineSetting,
    },
    /// Check for a newer release and install it with cargo.
    Update,
    /// Turn the daily update check on or off, or print its setting.
    UpdateCheck {
        #[arg(value_enum)]
        setting: UpdateCheckSetting,
    },
    /// List canonical MIME types readable under a caller-selected policy.
    Formats {
        /// C2PA policy. Omission is exactly 2.4.
        #[arg(long, visible_alias = "spec-version", value_name = "2.2|2.4|2.5")]
        spec: Option<String>,
        #[arg(long)]
        json: bool,
    },
    /// Explain a stable validation status code.
    Explain { code: String },
}

fn main() -> ExitCode {
    match run(Cli::parse()) {
        Ok(code) => code,
        Err(error) => {
            eprintln!("{}: {error}", error.code());
            if matches!(error, Error::UnsupportedMime(_)) {
                ExitCode::from(3)
            } else {
                ExitCode::FAILURE
            }
        }
    }
}

fn run(cli: Cli) -> Result<ExitCode, Error> {
    // Offer a newer release before working. Commands that change settings
    // skip it, so turning the check off never starts with an update prompt.
    if matches!(
        cli.command,
        Command::Verify { .. }
            | Command::VerifyStore { .. }
            | Command::BindingTarget { .. }
            | Command::VerifyCallerBinding { .. }
            | Command::VerifyErtmp { .. }
            | Command::ResolveSoftBinding { .. }
            | Command::VerifySoftBindingReceipt { .. }
            | Command::Formats { .. }
            | Command::Explain { .. }
    ) {
        let offline = matches!(cli.command, Command::Verify { offline: true, .. });
        if let Some(code) = update::check_on_start(offline) {
            return Ok(code);
        }
    }
    match cli.command {
        Command::Verify {
            asset,
            mime,
            manifest,
            fragment,
            expected_seek,
            encapsulation,
            segment_mode,
            trust,
            claim_trust_sources,
            tsa_trust,
            tsa_trust_sources,
            allowed,
            cawg_trust,
            cawg_allowed,
            cawg_trust_configurations,
            trust_anchor_not_before,
            trust_anchor_not_after,
            no_default_trust,
            cawg_did_documents,
            cawg_ica_trusted_issuer,
            cawg_ica_trust_anchor,
            cawg_ica_status_lists,
            cawg_strict_encoding,
            strict_conformance,
            spec,
            time,
            telemetry,
            no_telemetry,
            telemetry_endpoint,
            online,
            offline,
            online_allow_private_networks,
            json,
            encypher_api,
            encypher_api_endpoint,
        } => {
            // Telemetry preference persistence is best-effort: verification
            // MUST run even when no user configuration directory can be
            // resolved (containers, service accounts, HOME-less shells). The
            // explicit flag still governs this run via TelemetryOptions.
            let explicit_telemetry = if telemetry {
                Some(true)
            } else if no_telemetry {
                Some(false)
            } else {
                None
            };
            if let Some(enabled) = explicit_telemetry {
                if let Err(error) = set_telemetry_enabled(enabled) {
                    eprintln!(
                        "warning: could not save telemetry preference ({error}); \
                         telemetry stays {} for this run",
                        if enabled { "enabled" } else { "disabled" }
                    );
                }
            }
            // This is a terminal, so the saved choice applies and the operator
            // can be asked. A library embedding this SDK never does either.
            allow_interactive_online_consent();
            let options = VerifyOptions {
                trust_pem: read_merged_pem(&trust)?,
                claim_trust_sources: read_trust_list_sources(
                    &claim_trust_sources,
                    "claim trust sources",
                )?,
                tsa_trust_pem: read_merged_pem(&tsa_trust)?,
                tsa_trust_sources: read_trust_list_sources(
                    &tsa_trust_sources,
                    "TSA trust sources",
                )?,
                allowed_list_pem: read_merged_pem(&allowed)?,
                cawg_trust_pem: read_merged_pem(&cawg_trust)?,
                cawg_allowed_certs_pem: read_merged_pem(&cawg_allowed)?,
                cawg_trust_configurations: read_trust_configurations(&cawg_trust_configurations)?,
                // The public CLI keeps the default: a documentSigning identity
                // must chain to a configured anchor or be allowed directly.
                cawg_document_signing_require_anchor: None,
                trust_anchor_not_before,
                trust_anchor_not_after,
                no_default_trust,
                cawg_did_documents: read_did_documents(&cawg_did_documents)?,
                cawg_ica_trusted_issuers: nonempty(cawg_ica_trusted_issuer),
                cawg_ica_trust_anchors: nonempty(cawg_ica_trust_anchor),
                cawg_ica_status_lists: read_string_map(
                    &cawg_ica_status_lists,
                    "cawg ICA status lists",
                )?,
                // Online evidence is supplied by the fetch layer, never by
                // these flags.
                ocsp_responses: None,
                ocsp_unreachable: None,
                external_data: None,
                external_data_media_types: None,
                external_data_unreachable: None,
                expected_seek_positions: expected_seek,
                cawg_strict_encoding,
                strict_conformance,
                spec_version: spec,
                validation_time: time,
                telemetry: TelemetryOptions {
                    enabled: explicit_telemetry,
                    endpoint: telemetry_endpoint,
                    sdk_name: Some("cli".to_string()),
                },
                online: if online {
                    Some(true)
                } else if offline {
                    Some(false)
                } else {
                    None
                },
                online_allow_private_networks,
            };
            // Resolve trust and validation options before opening the asset,
            // detached manifest, or stream fragments. Every branch below then
            // observes the same canonical validation and error ordering.
            options.validate()?;
            // Declared stream verification is a different question with a
            // different answer shape (per-segment results, a chain verdict), so
            // it returns its own report rather than being squeezed into the
            // single-asset one.
            if let Some(encapsulation) = encapsulation {
                return run_stream_verify(
                    &asset,
                    mime.as_deref(),
                    &fragment,
                    &encapsulation,
                    segment_mode.as_deref(),
                    &options,
                    json,
                );
            }
            let (report, encypher_api_result) = if encypher_api {
                let mime = match mime {
                    Some(value) => value,
                    None => mime_from_path(&asset)
                        .ok_or_else(|| Error::UnsupportedMime(asset.display().to_string()))?
                        .to_string(),
                };
                let bytes = read_path_asset(&asset)?;
                let report = verify_with_options(&bytes, &mime, &options)?;
                let evidence = detached_manifest_evidence_with_options(&bytes, &mime, &options)?;
                let endpoint = encypher_api_endpoint
                    .unwrap_or_else(|| encypher_api::DEFAULT_ENDPOINT.to_string());
                let api_key = std::env::var("ENCYPHER_API_KEY")
                    .or_else(|_| std::env::var("ENCYPHER_API_TOKEN"))
                    .ok();
                let result = encypher_api::verify(
                    &endpoint,
                    api_key.as_deref(),
                    &bytes,
                    &mime,
                    &report,
                    evidence.as_ref(),
                );
                (report, Some(result))
            } else if let Some(manifest) = manifest {
                let mime = match mime {
                    Some(value) => value,
                    None => mime_from_path(&asset)
                        .ok_or_else(|| Error::UnsupportedMime(asset.display().to_string()))?
                        .to_string(),
                };
                let bytes = read_path_asset(&asset)?;
                let store = read_path_asset(&manifest)?;
                (
                    verify_with_manifest_store(&bytes, &store, &mime, &options)?,
                    None,
                )
            } else if fragment.is_empty() {
                (verify_file(&asset, mime.as_deref(), &options)?, None)
            } else {
                let mime = match mime {
                    Some(value) => value,
                    None => mime_from_path(&asset)
                        .ok_or_else(|| Error::UnsupportedMime(asset.display().to_string()))?
                        .to_string(),
                };
                let init_segment = read_path_asset(&asset)?;
                let fragment_bytes: Vec<Vec<u8>> = fragment
                    .iter()
                    .map(|path| read_path_asset(path))
                    .collect::<Result<_, _>>()?;
                let fragment_refs: Vec<&[u8]> = fragment_bytes.iter().map(Vec::as_slice).collect();
                (
                    verify_fragmented_with_options(&init_segment, &fragment_refs, &mime, &options)?,
                    None,
                )
            };
            if json {
                if let Some(lookup) = &encypher_api_result {
                    let mut value: serde_json::Value =
                        serde_json::from_str(&report.to_pretty_json()?)
                            .map_err(Error::Serialize)?;
                    if let Some(object) = value.as_object_mut() {
                        object.insert("encypher_api".to_string(), lookup.clone());
                    }
                    println!(
                        "{}",
                        serde_json::to_string_pretty(&value).map_err(Error::Serialize)?
                    );
                } else {
                    println!("{}", report.to_pretty_json()?);
                }
            } else {
                println!("asset: {}", asset.display());
                println!("profile: {}", report.profile);
                println!(
                    "provenance: {}",
                    if report.present { "present" } else { "absent" }
                );
                println!("integrity: {}", report.integrity);
                println!("signature: {}", report.signature);
                println!("hard binding: {}", report.hard_binding);
                println!("trust: {} ({})", report.trust.status, report.trust.basis);
                if !report.validation_results.failure.is_empty() {
                    println!("failures:");
                    for status in &report.validation_results.failure {
                        println!("  {}: {}", status.code, status.explanation);
                    }
                }
                render_network(&report.network);
                println!("docs: https://encypher.com/c2pa/codes");
                if let Some(lookup) = &encypher_api_result {
                    encypher_api::render_human(lookup);
                }
            }
            Ok(if report.integrity == "valid" {
                ExitCode::SUCCESS
            } else {
                ExitCode::from(2)
            })
        }
        Command::VerifyStore {
            manifest,
            options,
            json,
        } => {
            let store = read_path_asset(&manifest)?;
            let options = if let Some(path) = options {
                let bytes = read_path_asset(&path)?;
                serde_json::from_slice::<VerifyOptions>(&bytes).map_err(|error| {
                    Error::Verification(format!(
                        "store verification options {}: {error}",
                        path.display()
                    ))
                })?
            } else {
                VerifyOptions::default()
            };
            let result = verify_manifest_store_only(&store, &options)?;
            if json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&result).map_err(Error::Serialize)?
                );
            } else {
                println!("store integrity: {}", result.report.integrity);
                println!(
                    "active manifest: {}",
                    result.active_manifest_label.as_deref().unwrap_or("none")
                );
                println!("manifests: {}", result.store_manifests.len());
                println!("hard binding: not evaluated");
            }
            Ok(if result.report.integrity == "invalid" {
                ExitCode::from(2)
            } else {
                ExitCode::SUCCESS
            })
        }
        Command::BindingTarget {
            manifest,
            hostless,
            options,
            json,
        } => {
            let store = read_path_asset(&manifest)?;
            let options = read_verify_options_file(options.as_deref(), "binding target")?;
            let target = binding_target(
                &store,
                if hostless {
                    CawgStoreHost::HostLess
                } else {
                    CawgStoreHost::Asset
                },
                &options,
            )?;
            if json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&target).map_err(Error::Serialize)?
                );
            } else if let Some(target) = target {
                println!("active manifest: {}", target.active_manifest_label);
                println!("binding manifest: {}", target.binding_manifest_label);
                println!("binding assertion: {}", target.binding_assertion_label);
                println!(
                    "manifest store SHA-256: {}",
                    hex::encode(target.manifest_store_sha256)
                );
            } else {
                println!("no unique operative hard binding");
            }
            Ok(ExitCode::SUCCESS)
        }
        Command::VerifyCallerBinding {
            manifest,
            mime,
            target,
            engine,
            hostless,
            matched,
            mismatch,
            options,
            json,
        } => {
            let store = read_path_asset(&manifest)?;
            let target_bytes = read_path_asset(&target)?;
            let target: ManifestBindingTarget =
                serde_json::from_slice(&target_bytes).map_err(|error| {
                    Error::Verification(format!("binding target {}: {error}", target.display()))
                })?;
            let verdict = match (matched, mismatch) {
                (true, None) => CallerBindingVerdict::Match,
                (false, Some(explanation)) if !explanation.is_empty() => {
                    serde_json::from_value(serde_json::json!({
                        "Mismatch": { "explanation": explanation }
                    }))
                    .map_err(Error::Serialize)?
                }
                _ => {
                    return Err(Error::Verification(
                        "select exactly one of --matched or --mismatch EXPLANATION".into(),
                    ))
                }
            };
            let evidence = CallerBindingEvidence::new(target, verdict, &engine)?;
            let options = read_verify_options_file(options.as_deref(), "caller binding")?;
            let report = verify_with_caller_verified_binding(
                &store,
                &mime,
                if hostless {
                    CawgStoreHost::HostLess
                } else {
                    CawgStoreHost::Asset
                },
                &evidence,
                &options,
                GraphInputs::default(),
            )?;
            if json {
                println!("{}", report.to_pretty_json()?);
            } else {
                println!("integrity: {}", report.integrity);
                println!("hard binding: {}", report.hard_binding);
                println!("signature: {}", report.signature);
            }
            Ok(if report.integrity == "valid" {
                ExitCode::SUCCESS
            } else {
                ExitCode::from(2)
            })
        }
        Command::VerifyErtmp {
            input,
            options,
            json,
        } => {
            let input_bytes = read_path_asset(&input)?;
            let input: ErtmpInput = serde_json::from_slice(&input_bytes).map_err(|error| {
                Error::Verification(format!("E-RTMP input {}: {error}", input.display()))
            })?;
            let options = if let Some(path) = options {
                let bytes = read_path_asset(&path)?;
                serde_json::from_slice::<VerifyOptions>(&bytes).map_err(|error| {
                    Error::Verification(format!(
                        "E-RTMP verification options {}: {error}",
                        path.display()
                    ))
                })?
            } else {
                VerifyOptions {
                    spec_version: Some("2.5".into()),
                    ..VerifyOptions::default()
                }
            };
            options.validate()?;
            let report = verify_ertmp_with_options(&input, &options)?;
            if json {
                println!("{}", report.to_pretty_json()?);
            } else {
                println!(
                    "E-RTMP integrity: {} ({} segments, {} manifests)",
                    report.integrity,
                    report.segments.len(),
                    report.manifests.len()
                );
                for failure in &report.failures {
                    println!("failure: {failure}");
                }
            }
            Ok(if report.integrity == "valid" {
                ExitCode::SUCCESS
            } else {
                ExitCode::from(2)
            })
        }
        Command::ResolveSoftBinding {
            asset,
            mime,
            service_root,
            query,
            allowed_origin,
            allow_private_networks,
            max_results,
            fetch_status,
            fetch_receipts,
            options,
            json,
        } => {
            let asset_bytes = read_path_asset(&asset)?;
            let mime = match mime {
                Some(value) => value,
                None => mime_from_path(&asset)
                    .ok_or_else(|| Error::UnsupportedMime(asset.display().to_string()))?
                    .to_string(),
            };
            let query_bytes = read_path_asset(&query)?;
            let query: SoftBindingQuery =
                serde_json::from_slice(&query_bytes).map_err(|error| {
                    Error::Verification(format!("soft-binding query {}: {error}", query.display()))
                })?;
            let mut options = if let Some(path) = options {
                let bytes = read_path_asset(&path)?;
                serde_json::from_slice::<VerifyOptions>(&bytes).map_err(|error| {
                    Error::Verification(format!(
                        "soft-binding verification options {}: {error}",
                        path.display()
                    ))
                })?
            } else {
                VerifyOptions::default()
            };
            // Invoking this network-specific command is explicit authorization.
            // A supplied `online: false` remains an explicit refusal.
            if options.online.is_none() {
                options.online = Some(true);
            }
            let resolver_options = SoftBindingResolverOptions {
                allowed_origins: allowed_origin,
                allow_private_networks,
                max_results,
                fetch_status,
                fetch_receipts,
            };
            let resolution = resolve_soft_binding(
                &asset_bytes,
                &mime,
                &service_root,
                &query,
                &options,
                &resolver_options,
            )?;
            if json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&resolution).map_err(Error::Serialize)?
                );
            } else {
                println!(
                    "soft-binding service {} recovered and verified {} manifest store(s)",
                    resolution.discovery.api_endpoint,
                    resolution.recovered.len()
                );
                for recovered in &resolution.recovered {
                    println!(
                        "{}: {}",
                        recovered.matched.manifest_id, recovered.report.integrity
                    );
                }
            }
            Ok(ExitCode::SUCCESS)
        }
        Command::VerifySoftBindingReceipt {
            service_root,
            manifest_id,
            receipt,
            allowed_origin,
            allow_private_networks,
            options,
        } => {
            let receipt_bytes = read_path_asset(&receipt)?;
            let receipt = serde_json::from_slice(&receipt_bytes).map_err(|error| {
                Error::Verification(format!(
                    "soft-binding receipt {}: {error}",
                    receipt.display()
                ))
            })?;
            let mut options = if let Some(path) = options {
                let bytes = read_path_asset(&path)?;
                serde_json::from_slice::<VerifyOptions>(&bytes).map_err(|error| {
                    Error::Verification(format!(
                        "soft-binding verification options {}: {error}",
                        path.display()
                    ))
                })?
            } else {
                VerifyOptions::default()
            };
            if options.online.is_none() {
                options.online = Some(true);
            }
            let resolver_options = SoftBindingResolverOptions {
                allowed_origins: allowed_origin,
                allow_private_networks,
                ..SoftBindingResolverOptions::default()
            };
            let evidence = request_soft_binding_receipt_verification(
                &service_root,
                &manifest_id,
                receipt,
                &options,
                &resolver_options,
            )?;
            println!(
                "{}",
                serde_json::to_string_pretty(&evidence).map_err(Error::Serialize)?
            );
            Ok(ExitCode::SUCCESS)
        }
        Command::Telemetry { setting } => {
            match setting {
                TelemetrySetting::On => {
                    set_telemetry_enabled(true)?;
                    println!("Failure telemetry enabled.");
                }
                TelemetrySetting::Off => {
                    set_telemetry_enabled(false)?;
                    println!("Failure telemetry disabled.");
                }
                TelemetrySetting::Status => match telemetry_preference()? {
                    Some(true) => println!("Failure telemetry is enabled."),
                    Some(false) => println!("Failure telemetry is disabled."),
                    None => println!("Failure telemetry preference is not set."),
                },
            }
            Ok(ExitCode::SUCCESS)
        }
        Command::Online { setting } => {
            match setting {
                OnlineSetting::On => {
                    set_online_preference(OnlinePreference::On)?;
                    println!("Online checks allowed.");
                }
                OnlineSetting::Off => {
                    set_online_preference(OnlinePreference::Off)?;
                    println!("Online checks refused.");
                }
                OnlineSetting::Ask => {
                    set_online_preference(OnlinePreference::Ask)?;
                    println!("Online checks will be offered each time one is needed.");
                }
                OnlineSetting::Status => match online_preference()? {
                    Some(OnlinePreference::On) => println!("Online checks are allowed."),
                    Some(OnlinePreference::Off) => println!("Online checks are refused."),
                    Some(OnlinePreference::Ask) => {
                        println!("Online checks are offered each time one is needed.");
                    }
                    None => println!("No choice about online checks is saved. Nothing is fetched."),
                },
            }
            Ok(ExitCode::SUCCESS)
        }
        Command::Update => Ok(update::run_update()),
        Command::UpdateCheck { setting } => Ok(update::run_update_check_setting(match setting {
            UpdateCheckSetting::On => Some(true),
            UpdateCheckSetting::Off => Some(false),
            UpdateCheckSetting::Status => None,
        })),
        Command::Formats { spec, json } => {
            let formats = supported_mime_types_for(spec.as_deref())?;
            if json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&formats).map_err(Error::Serialize)?
                );
            } else {
                for mime in formats {
                    println!("{mime}");
                }
            }
            Ok(ExitCode::SUCCESS)
        }
        Command::Explain { code } => {
            let explanation = explain(&code).ok_or_else(|| {
                Error::Verification(format!("unknown validation status code: {code}"))
            })?;
            println!("{code}: {explanation}");
            println!("details: https://encypher.com/c2pa/codes/{code}");
            Ok(ExitCode::SUCCESS)
        }
    }
}

/// Verify a declared fMP4/CMAF stream: `asset` is the init segment and each
/// `--fragment` is a media segment in playback order.
///
/// `--segment-mode` defaults to `verifiable-segment-info`, the method where one
/// init manifest binds the whole stream. Which binding it used - C2PA 2.4
/// session keys or a Merkle tree - is read off that manifest, so the caller
/// never gets to pick the integrity check.
#[allow(clippy::too_many_arguments)]
fn run_stream_verify(
    asset: &Path,
    mime: Option<&str>,
    fragments: &[PathBuf],
    encapsulation: &str,
    segment_mode: Option<&str>,
    options: &VerifyOptions,
    json: bool,
) -> Result<ExitCode, Error> {
    let encapsulation = StreamEncapsulation::from_token(encapsulation).ok_or_else(|| {
        Error::Verification(format!(
            "unknown --encapsulation: {encapsulation} (expected fmp4 or cmaf)"
        ))
    })?;
    let method = match segment_mode {
        None => StreamMethod::VerifiableSegmentInfo,
        Some(token) => StreamMethod::from_token(token).ok_or_else(|| {
            Error::Verification(format!(
                "unknown --segment-mode: {token} \
                 (expected verifiable-segment-info or per-segment)"
            ))
        })?,
    };
    let mime = match mime {
        Some(value) => value.to_string(),
        None => mime_from_path(asset)
            .ok_or_else(|| Error::UnsupportedMime(asset.display().to_string()))?
            .to_string(),
    };
    let init_segment = read_path_asset(asset)?;
    let segment_bytes: Vec<Vec<u8>> = fragments
        .iter()
        .map(|path| read_path_asset(path))
        .collect::<Result<_, _>>()?;
    let segment_refs: Vec<&[u8]> = segment_bytes.iter().map(Vec::as_slice).collect();
    let report = verify_stream_with_options(
        &init_segment,
        &segment_refs,
        &mime,
        encapsulation,
        method,
        options,
    )?;

    if json {
        println!("{}", report.to_pretty_json()?);
    } else {
        println!("init segment: {}", asset.display());
        println!("encapsulation: {encapsulation}");
        println!("method: {method}");
        println!("integrity: {}", report.integrity);
        if let Some(stream) = &report.stream {
            println!("signature: {}", stream.signature);
            println!("hard binding: {}", stream.hard_binding);
            println!("trust: {} ({})", stream.trust.status, stream.trust.basis);
            if !stream.validation_results.failure.is_empty() {
                println!("failures:");
                for status in &stream.validation_results.failure {
                    println!("  {}: {}", status.code, status.explanation);
                }
            }
        }
        for segment in &report.segments {
            println!(
                "segment {}: integrity {} trust {} ({})",
                segment.sequence_number,
                segment.report.integrity,
                segment.report.trust.status,
                segment.manifest_label
            );
            for status in &segment.report.validation_results.failure {
                println!("    {}: {}", status.code, status.explanation);
            }
        }
        if let Some(chain_valid) = report.chain_valid {
            println!("chain: {}", if chain_valid { "valid" } else { "broken" });
            for failure in &report.chain_failures {
                println!("    {failure}");
            }
        }
        render_network(&report.network);
        println!("docs: https://encypher.com/c2pa/codes");
    }
    Ok(if report.integrity == "valid" {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(2)
    })
}

/// Say what the run did on the network, and what it would do if allowed.
///
/// A verification that stayed offline still names the checks it could have
/// made, so the reader can decide whether to allow them rather than having to
/// guess that there was anything to allow.
fn render_network(network: &encypher_c2pa::NetworkReport) {
    if network.needed.is_empty() && network.requests.is_empty() {
        return;
    }
    if !network.enabled {
        println!(
            "online checks: off, {} available (re-run with --online)",
            network.needed.len()
        );
        return;
    }
    println!("online checks: allowed");
    for request in &network.requests {
        println!(
            "  {} {}: {} ({})",
            request.purpose, request.url, request.outcome, request.detail
        );
    }
}

/// Read repeatable PEM-bundle options and merge them into one bundle (PEM
/// concatenates trivially), so separate anchor lists — your own CA, the C2PA
/// official list, a partner list — can be passed without cat-ing files.
fn read_merged_pem(paths: &[PathBuf]) -> Result<Option<String>, Error> {
    if paths.is_empty() {
        return Ok(None);
    }
    let mut pem = String::new();
    for path in paths {
        pem.push_str(&fs::read_to_string(path)?);
        if !pem.ends_with('\n') {
            pem.push('\n');
        }
    }
    Ok(Some(pem))
}

fn read_verify_options_file(path: Option<&Path>, purpose: &str) -> Result<VerifyOptions, Error> {
    let Some(path) = path else {
        return Ok(VerifyOptions::default());
    };
    let bytes = read_path_asset(path)?;
    serde_json::from_slice(&bytes).map_err(|error| {
        Error::Verification(format!("{purpose} options {}: {error}", path.display()))
    })
}

fn read_path_asset(path: &Path) -> io::Result<Vec<u8>> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    options.custom_flags(libc::O_NONBLOCK | libc::O_CLOEXEC);

    let mut file = options.open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("asset path is not a regular file: {}", path.display()),
        ));
    }
    if metadata.len() > MAX_PATH_ASSET_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("asset exceeds the 128 MiB path limit: {}", path.display()),
        ));
    }

    let expected_len = usize::try_from(metadata.len())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "asset size is not addressable"))?;
    let mut data = vec![0_u8; expected_len + 1];
    let mut used = 0;
    while used < expected_len {
        let count = file.read(&mut data[used..expected_len])?;
        if count == 0 {
            break;
        }
        used += count;
    }
    if used == expected_len && file.read(&mut data[expected_len..expected_len + 1])? != 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "asset grew while being read",
        ));
    }
    data.truncate(used);
    Ok(data)
}

/// Build the pinned offline `did:web` DID-document store from repeatable
/// `--cawg-did-documents PATH` options. Each file holds either a single DID
/// document (keyed by its `id`), an array of DID documents, or an object
/// mapping DID -> document. Later files override earlier entries.
fn read_did_documents(
    paths: &[PathBuf],
) -> Result<Option<HashMap<String, serde_json::Value>>, Error> {
    if paths.is_empty() {
        return Ok(None);
    }
    let mut store = HashMap::new();
    fn insert_doc(
        doc: serde_json::Value,
        path: &std::path::Path,
        store: &mut HashMap<String, serde_json::Value>,
    ) -> Result<(), Error> {
        let id = doc
            .get("id")
            .and_then(|value| value.as_str())
            .filter(|id| id.starts_with("did:"))
            .ok_or_else(|| {
                Error::Verification(format!(
                    "cawg did documents: {}: document lacks a DID `id`",
                    path.display()
                ))
            })?
            .to_string();
        store.insert(id.split('#').next().unwrap_or(&id).to_string(), doc);
        Ok(())
    }
    for path in paths {
        let contents = fs::read_to_string(path)?;
        let parsed: serde_json::Value = serde_json::from_str(&contents).map_err(|error| {
            Error::Verification(format!("cawg did documents: {}: {error}", path.display()))
        })?;
        match parsed {
            serde_json::Value::Array(docs) => {
                for doc in docs {
                    insert_doc(doc, path, &mut store)?;
                }
            }
            doc @ serde_json::Value::Object(_) if doc.get("id").is_some() => {
                insert_doc(doc, path, &mut store)?;
            }
            serde_json::Value::Object(map) => {
                for (did, doc) in map {
                    if !did.starts_with("did:") {
                        return Err(Error::Verification(format!(
                            "cawg did documents: {}: key {did:?} is not a DID",
                            path.display()
                        )));
                    }
                    store.insert(did.split('#').next().unwrap_or(&did).to_string(), doc);
                }
            }
            _ => {
                return Err(Error::Verification(format!(
                    "cawg did documents: {}: expected a DID document, array, or DID->document map",
                    path.display()
                )))
            }
        }
    }
    Ok(Some(store))
}

fn nonempty<T>(values: Vec<T>) -> Option<Vec<T>> {
    (!values.is_empty()).then_some(values)
}

/// Read repeatable `--cawg-trust-configurations PATH` files, each a JSON array
/// of configurations, concatenated in flag order.
fn read_trust_configurations(
    paths: &[PathBuf],
) -> Result<Option<Vec<CawgTrustConfiguration>>, Error> {
    if paths.is_empty() {
        return Ok(None);
    }
    let mut configurations = Vec::new();
    for path in paths {
        let entries: Vec<CawgTrustConfiguration> = serde_json::from_str(&fs::read_to_string(path)?)
            .map_err(|error| {
                Error::Verification(format!(
                    "cawg trust configurations: {}: {error}",
                    path.display()
                ))
            })?;
        configurations.extend(entries);
    }
    Ok(Some(configurations))
}

fn read_trust_list_sources(
    paths: &[PathBuf],
    label: &str,
) -> Result<Option<Vec<TrustListSource>>, Error> {
    if paths.is_empty() {
        return Ok(None);
    }
    let mut sources = Vec::new();
    for path in paths {
        let entries: Vec<TrustListSource> = serde_json::from_str(&fs::read_to_string(path)?)
            .map_err(|error| {
                Error::Verification(format!("{label}: {}: {error}", path.display()))
            })?;
        sources.extend(entries);
    }
    Ok(Some(sources))
}

fn read_string_map(
    paths: &[PathBuf],
    label: &str,
) -> Result<Option<HashMap<String, String>>, Error> {
    if paths.is_empty() {
        return Ok(None);
    }
    let mut output = HashMap::new();
    for path in paths {
        let contents = fs::read_to_string(path)?;
        let entries: HashMap<String, String> =
            serde_json::from_str(&contents).map_err(|error| {
                Error::Verification(format!("{label}: {}: {error}", path.display()))
            })?;
        output.extend(entries);
    }
    Ok(Some(output))
}

fn explain(code: &str) -> Option<&'static str> {
    Some(match code {
        "claimSignature.validated" => "The active claim signature is cryptographically valid.",
        "claimSignature.mismatch" => "The active claim signature does not verify.",
        "assertion.hashedURI.match" => "A claim reference matches the exact assertion bytes.",
        "assertion.hashedURI.mismatch" => {
            "A referenced assertion changed or is not the referenced bytes."
        }
        "assertion.dataHash.match" => "The asset bytes match the signed data-hash assertion.",
        "assertion.dataHash.mismatch" => {
            "The asset bytes do not match the signed data-hash assertion."
        }
        "assertion.bmffHash.match" => "The BMFF boxes match the signed box-hash assertion.",
        "assertion.bmffHash.mismatch" => {
            "The BMFF boxes do not match the signed box-hash assertion."
        }
        "signingCredential.trusted" => "The signer chains to configured trust material.",
        "signingCredential.untrusted" => "The signer does not chain to configured trust material.",
        "signingCredential.ocsp.revoked" => {
            "Supplied revocation evidence marks the signer as revoked."
        }
        "manifest.inaccessible" => {
            "The asset names a remote manifest. Fetch it and pass --manifest."
        }
        "assertion.inaccessible" => {
            "An assertion is stored remotely and was not retrieved. Not a rejection."
        }
        "assertion.cloud-data.malformed" => {
            "A cloud data assertion is incomplete or names a type that may not be remote."
        }
        "assertion.external-reference.malformed" => {
            "An external reference is incomplete or names a type that may not be external."
        }
        "claim.missing" => "No readable active C2PA claim is present.",
        "ingredient.manifest.missing" => {
            "An ingredient points to a manifest absent from the store."
        }
        _ => return None,
    })
}
