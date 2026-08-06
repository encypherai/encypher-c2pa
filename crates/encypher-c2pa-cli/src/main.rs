use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand, ValueEnum};
use encypher_c2pa::{
    set_telemetry_enabled, supported_mime_types, telemetry_preference, verify_file, Error,
    TelemetryOptions, VerifyOptions,
};

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
        /// Claim-signer trust anchors (PEM bundle). Repeatable; bundles merge.
        #[arg(long, value_name = "PEM")]
        trust: Vec<PathBuf>,
        /// Timestamp-authority trust anchors (PEM bundle). Repeatable.
        #[arg(long, value_name = "PEM")]
        tsa_trust: Vec<PathBuf>,
        /// Directly allowed end-entity certificates (PEM bundle). Repeatable.
        #[arg(long, visible_alias = "allowed-certs", value_name = "PEM")]
        allowed: Vec<PathBuf>,
        /// CAWG named-actor (identity) trust anchors (PEM bundle). Repeatable.
        #[arg(long, value_name = "PEM")]
        cawg_trust: Vec<PathBuf>,
        /// Directly allowed CAWG end-entity certificates (PEM). Repeatable.
        #[arg(long, value_name = "PEM")]
        cawg_allowed: Vec<PathBuf>,
        /// Require CAWG document-signing credentials to chain to a supplied
        /// anchor (or match the allowed list).
        #[arg(long)]
        cawg_document_signing_require_anchor: bool,
        /// Pinned offline did:web DID documents for CAWG ICA issuers.
        /// Repeatable; each file is a DID document, an array of documents, or
        /// a DID -> document map. Without it did:web resolution fails closed.
        #[arg(long, value_name = "JSON")]
        cawg_did_documents: Vec<PathBuf>,
        /// Refuse CAWG 1.1-era legacy encodings; accept only CAWG 1.2
        /// canonical shapes.
        #[arg(long)]
        cawg_strict_encoding: bool,
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
        #[arg(long)]
        json: bool,
    },
    /// Read or change the saved failure telemetry preference.
    Telemetry {
        #[arg(value_enum)]
        setting: TelemetrySetting,
    },
    /// List canonical MIME types covered by the C2PA 2.4 profile.
    Formats {
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
    match cli.command {
        Command::Verify {
            asset,
            mime,
            trust,
            tsa_trust,
            allowed,
            cawg_trust,
            cawg_allowed,
            cawg_document_signing_require_anchor,
            cawg_did_documents,
            cawg_strict_encoding,
            time,
            telemetry,
            no_telemetry,
            telemetry_endpoint,
            json,
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
            let options = VerifyOptions {
                trust_pem: read_merged_pem(&trust)?,
                tsa_trust_pem: read_merged_pem(&tsa_trust)?,
                allowed_list_pem: read_merged_pem(&allowed)?,
                cawg_trust_pem: read_merged_pem(&cawg_trust)?,
                cawg_allowed_certs_pem: read_merged_pem(&cawg_allowed)?,
                cawg_document_signing_require_anchor,
                cawg_did_documents: read_did_documents(&cawg_did_documents)?,
                cawg_strict_encoding,
                validation_time: time,
                telemetry: TelemetryOptions {
                    enabled: explicit_telemetry,
                    endpoint: telemetry_endpoint,
                    sdk_name: Some("cli".to_string()),
                },
            };
            let report = verify_file(&asset, mime.as_deref(), &options)?;
            if json {
                println!("{}", report.to_pretty_json()?);
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
            }
            Ok(if report.integrity == "valid" {
                ExitCode::SUCCESS
            } else {
                ExitCode::from(2)
            })
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
        Command::Formats { json } => {
            let formats = supported_mime_types();
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
            Ok(ExitCode::SUCCESS)
        }
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
        "signingCredential.trusted" => "The signer chains to caller-supplied trust material.",
        "signingCredential.untrusted" => {
            "The signer does not chain to caller-supplied trust material."
        }
        "signingCredential.ocsp.revoked" => {
            "Supplied revocation evidence marks the signer as revoked."
        }
        "claim.missing" => "No readable active C2PA claim is present.",
        "ingredient.manifest.missing" => {
            "An ingredient points to a manifest absent from the store."
        }
        _ => return None,
    })
}
