//! Engine profile and the per-version format registry.
//!
//! Three orthogonal axes describe how the engine operates:
//!
//! - [`SpecVersion`] — which C2PA spec revision (2.2, 2.4). Drives the emitted
//!   `specVersion` string, the in-scope format set, and version-specific rules.
//! - [`OperatingMode`] — restricted to the certified/conformance-evaluated
//!   surface ([`OperatingMode::Conformance`]) vs the full engine capability
//!   ([`OperatingMode::Regular`]).
//! - [`ComplianceLevel`] — validate against the **core spec**
//!   ([`ComplianceLevel::CoreSpec`]) vs the **conformance program**
//!   ([`ComplianceLevel::ConformanceProgram`]), which turns some of the core
//!   spec's SHOULDs into SHALLs (so a check that is informational/optional under
//!   the core spec becomes a hard failure under the program).
//!
//! # Format registry (single SSOT)
//!
//! [`FORMAT_REGISTRY`] is the one place that says which MIME types belong to
//! which spec version. Adding or removing a format from a version is a one-line
//! edit here — nothing else needs to change. This drives conformance scoping,
//! sample-output generation, and interop test selection.

/// C2PA specification revision.
///
/// Ordered by release: `V1_4 < V2_0 < V2_1 < V2_2 < V2_3 < V2_4`, so the
/// verifier's version ladder can compare revisions directly. `V1_4` stands in
/// for the whole claim-v1 generation (1.0–1.4): the 1.x revisions are not
/// distinguishable from a manifest's validator-observable structure, and 1.4
/// is the terminal 1.x rule set.
///
/// Conformance/certification scope exists only for [`SpecVersion::V2_2`] (the
/// certified set) and [`SpecVersion::V2_4`] (the next application target);
/// the other revisions exist for *validation* — classifying which spec
/// revision an in-the-wild manifest conforms to — and have no entries in
/// [`FORMAT_REGISTRY`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub enum SpecVersion {
    /// C2PA 1.4 — the terminal claim-v1 revision (stands in for 1.0–1.4).
    V1_4,
    /// C2PA 2.0 — first claim-v2 revision.
    V2_0,
    /// C2PA 2.1 — adds `c2pa.ingredient.v3` and collection data hashes.
    V2_1,
    /// C2PA 2.2 — the currently certified Generator Product revision. Adds
    /// `c2pa.hash.multi-asset`.
    #[default]
    V2_2,
    /// C2PA 2.3.
    V2_3,
    /// C2PA 2.4 — the next conformance application target (adds text + more).
    V2_4,
}

impl SpecVersion {
    /// Every revision the engine can validate against, ascending.
    pub const ALL: [SpecVersion; 6] = [
        SpecVersion::V1_4,
        SpecVersion::V2_0,
        SpecVersion::V2_1,
        SpecVersion::V2_2,
        SpecVersion::V2_3,
        SpecVersion::V2_4,
    ];

    /// The string emitted in `claim_generator_info.specVersion`.
    pub fn version_str(self) -> &'static str {
        match self {
            SpecVersion::V1_4 => "1.4",
            SpecVersion::V2_0 => "2.0",
            SpecVersion::V2_1 => "2.1",
            SpecVersion::V2_2 => "2.2",
            SpecVersion::V2_3 => "2.3",
            SpecVersion::V2_4 => "2.4",
        }
    }

    /// Parse from a version string. The 1.x family (`"1.0"`–`"1.4"`) maps to
    /// [`SpecVersion::V1_4`] (see the type docs). `None` for unknown.
    // Intentionally NOT std::str::FromStr: this parse is total over known
    // versions and returns Option (unknown -> None), not Result.
    #[allow(clippy::should_implement_trait)]
    pub fn from_str(s: &str) -> Option<Self> {
        match s.trim() {
            "1.0" | "1.1" | "1.2" | "1.3" | "1.4" => Some(SpecVersion::V1_4),
            "2.0" => Some(SpecVersion::V2_0),
            "2.1" => Some(SpecVersion::V2_1),
            "2.2" => Some(SpecVersion::V2_2),
            "2.3" => Some(SpecVersion::V2_3),
            "2.4" => Some(SpecVersion::V2_4),
            _ => None,
        }
    }
}

/// Whether the engine is restricted to the certified surface, or runs its full
/// in-house capability.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum OperatingMode {
    /// Strict conformance: ONLY the formats certified for the active
    /// [`SpecVersion`] are *in scope*. The certified, locked surface. Default.
    #[default]
    Conformance,
    /// Regular API mode: the full engine surface — every format the engine
    /// implements, including ones the conformance program does not cover (text).
    Regular,
}

/// Which compliance bar validation is held to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum ComplianceLevel {
    /// The C2PA core technical specification. Some requirements are SHOULDs
    /// (recommended, not mandatory) — those surface as informational rather than
    /// failures.
    #[default]
    CoreSpec,
    /// The C2PA conformance program, which upgrades a set of core-spec SHOULDs to
    /// SHALLs. Under this level those checks are hard failures.
    ConformanceProgram,
}

/// The engine's active profile across all three axes. Default is the certified
/// production posture: `{ V2_2, Conformance, ConformanceProgram }`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct EngineProfile {
    /// C2PA spec revision.
    pub version: SpecVersion,
    /// Conformance restriction vs full engine surface.
    pub mode: OperatingMode,
    /// Core-spec vs conformance-program compliance bar.
    pub compliance: ComplianceLevel,
    /// Diagnostics / strict-debug mode. When `true`, the engine emits the full
    /// crJSON (Content Credentials JSON) manifest rendering as a side output on
    /// BOTH the sign and verify paths — for conformance-evidence generation,
    /// sample outputs, and deep debugging. Off by default: production sign/verify
    /// pays no crJSON cost. Orthogonal to [`ComplianceLevel`] (which governs
    /// SHALL enforcement, not output verbosity).
    pub debug: bool,
}

impl Default for EngineProfile {
    fn default() -> Self {
        EngineProfile::CONFORMANCE_V2_2
    }
}

impl EngineProfile {
    /// The certified production profile: C2PA 2.2, strict conformance scope,
    /// conformance-program compliance bar. The default and the safe choice for
    /// anything that must match the certified baseline.
    pub const CONFORMANCE_V2_2: EngineProfile = EngineProfile {
        version: SpecVersion::V2_2,
        mode: OperatingMode::Conformance,
        compliance: ComplianceLevel::ConformanceProgram,
        debug: false,
    };

    /// A generous verification profile: full engine surface, core-spec bar. The
    /// default posture for the public verify API (read/validate anything).
    pub const GENEROUS: EngineProfile = EngineProfile {
        version: SpecVersion::V2_4,
        mode: OperatingMode::Regular,
        compliance: ComplianceLevel::CoreSpec,
        debug: false,
    };

    /// A version-INDEPENDENT strict diagnostics profile for `version`:
    /// conformance scope + conformance-program SHALL bar + diagnostics ON (crJSON
    /// on sign and verify). For conformance-evidence generation and deep
    /// debugging at ANY spec version — not a production posture. Compose with any
    /// [`SpecVersion`]: `EngineProfile::strict(SpecVersion::V2_4)`.
    pub fn strict(version: SpecVersion) -> Self {
        Self {
            version,
            mode: OperatingMode::Conformance,
            compliance: ComplianceLevel::ConformanceProgram,
            debug: true,
        }
    }

    /// Construct a profile from version + mode, with the core-spec compliance bar
    /// and diagnostics off.
    pub fn new(version: SpecVersion, mode: OperatingMode) -> Self {
        Self {
            version,
            mode,
            compliance: ComplianceLevel::CoreSpec,
            debug: false,
        }
    }

    /// Set the compliance level (builder style).
    pub fn with_compliance(mut self, compliance: ComplianceLevel) -> Self {
        self.compliance = compliance;
        self
    }

    /// Enable/disable diagnostics (strict-debug) mode (builder style).
    pub fn with_debug(mut self, debug: bool) -> Self {
        self.debug = debug;
        self
    }

    /// The `specVersion` string this profile emits.
    pub fn version_str(self) -> &'static str {
        self.version.version_str()
    }

    /// Whether `mime` is in scope for this profile.
    ///
    /// - In [`OperatingMode::Conformance`], only MIME types registered for the
    ///   active [`SpecVersion`] are permitted. Validation-only revisions
    ///   (1.4/2.0/2.1/2.3) have no certified scope, so conformance mode falls
    ///   back to the full known-format set for them — their strictness comes
    ///   from the target-spec-version conformance check in the verifier, not
    ///   from a format gate.
    /// - In [`OperatingMode::Regular`], every MIME type the registry knows (any
    ///   version) is permitted.
    pub fn permits_mime(self, mime: &str) -> bool {
        let canon = canonicalize_mime(mime);
        match self.mode {
            OperatingMode::Conformance if version_has_scope(self.version) => {
                mime_in_version(&canon, self.version)
            }
            _ => mime_known(&canon),
        }
    }
}

/// Canonicalize a MIME type to the form the engine signs/verifies.
///
/// Strips any `; charset=…` parameter, lowercases the type/subtype, and applies
/// the certified alias mappings so each accepted spelling resolves to one
/// canonical form that signs to identical bytes: `audio/MPA`→`audio/mpeg`,
/// `audio/aac`→`audio/mp4`, the WAV aliases (`audio/wave`, `audio/vnd.wave`,
/// `audio/x-wav`)→`audio/wav`, `audio/x-flac`→`audio/flac`,
/// `application/ogg`→`audio/ogg`, the AVI aliases (`video/avi`,
/// `video/msvideo`, `application/x-troff-msvideo`)→`video/x-msvideo`,
/// `image/dng`→`image/x-adobe-dng`, and `application/svg+xml`→`image/svg+xml`.
/// The canonical targets match the C2PA 2.4 media-type names.
pub fn canonicalize_mime(mime: &str) -> String {
    let base = mime.split(';').next().unwrap_or(mime).trim();
    match base.to_ascii_lowercase().as_str() {
        "audio/mpa" => "audio/mpeg".to_string(),
        "audio/aac" => "audio/mp4".to_string(),
        // WAV container aliases (RIFF) → certified canonical form.
        "audio/wave" | "audio/vnd.wave" | "audio/x-wav" => "audio/wav".to_string(),
        // FLAC container alias.
        "audio/x-flac" => "audio/flac".to_string(),
        // Generic Ogg container spelling -> Ogg audio canonical form.
        "application/ogg" => "audio/ogg".to_string(),
        // AVI container aliases (RIFF) → certified canonical form.
        "video/avi" | "video/msvideo" | "application/x-troff-msvideo" => {
            "video/x-msvideo".to_string()
        }
        // Adobe DNG, SVG, and text spelling aliases -> canonical registry forms.
        "image/dng" => "image/x-adobe-dng".to_string(),
        "application/svg+xml" => "image/svg+xml".to_string(),
        "text/javascript" => "application/javascript".to_string(),
        "text/yaml" | "application/x-yaml" => "application/yaml".to_string(),
        other => other.to_string(),
    }
}

// ---------------------------------------------------------------------------
// Format registry — the single SSOT for "which MIME in which version".
// ---------------------------------------------------------------------------

/// A registry entry: a canonical MIME type and the set of spec versions whose
/// scope includes it. Edit this table to add/remove a format from a version.
pub struct FormatEntry {
    /// Canonical (lowercase, de-aliased) MIME type.
    pub mime: &'static str,
    /// Spec versions whose certified/in-scope set includes this MIME.
    pub versions: &'static [SpecVersion],
}

use SpecVersion::{V2_2, V2_4};

/// The certified C2PA 2.2 Generator Product set and the C2PA 2.4 superset.
///
/// **v2.2** = the 20 certified MIME types (load-bearing; MUST NOT change without
/// re-certification). **v2.4** adds the remaining C2PA reference media formats
/// plus the text formats (unstructured A.8, structured A.9, HTML A.7) supported
/// via the published `c2pa-text` crate. ML-model formats are intentionally
/// excluded — the C2PA spec does not define them.
///
/// Aliases (`audio/MPA`, `audio/aac`) are handled by [`canonicalize_mime`], not
/// listed here, so the registry holds only canonical forms.
pub static FORMAT_REGISTRY: &[FormatEntry] = &[
    // ---- Certified v2.2 set (also in v2.4) ----
    FormatEntry {
        mime: "application/pdf",
        versions: &[V2_2, V2_4],
    },
    FormatEntry {
        mime: "audio/mp4",
        versions: &[V2_2, V2_4],
    },
    FormatEntry {
        mime: "audio/mpeg",
        versions: &[V2_2, V2_4],
    },
    FormatEntry {
        mime: "audio/wav",
        versions: &[V2_2, V2_4],
    },
    FormatEntry {
        mime: "image/avif",
        versions: &[V2_2, V2_4],
    },
    FormatEntry {
        mime: "image/gif",
        versions: &[V2_2, V2_4],
    },
    FormatEntry {
        mime: "image/heic",
        versions: &[V2_2, V2_4],
    },
    FormatEntry {
        mime: "image/heif",
        versions: &[V2_2, V2_4],
    },
    FormatEntry {
        mime: "image/heic-sequence",
        versions: &[V2_4],
    },
    FormatEntry {
        mime: "image/heif-sequence",
        versions: &[V2_4],
    },
    FormatEntry {
        mime: "image/jpeg",
        versions: &[V2_2, V2_4],
    },
    FormatEntry {
        mime: "image/jxl",
        versions: &[V2_2, V2_4],
    },
    FormatEntry {
        mime: "image/png",
        versions: &[V2_2, V2_4],
    },
    FormatEntry {
        mime: "image/svg+xml",
        versions: &[V2_2, V2_4],
    },
    FormatEntry {
        mime: "image/tiff",
        versions: &[V2_2, V2_4],
    },
    FormatEntry {
        mime: "image/webp",
        versions: &[V2_2, V2_4],
    },
    FormatEntry {
        mime: "image/x-adobe-dng",
        versions: &[V2_2, V2_4],
    },
    FormatEntry {
        mime: "video/mp4",
        versions: &[V2_2, V2_4],
    },
    FormatEntry {
        mime: "video/quicktime",
        versions: &[V2_2, V2_4],
    },
    FormatEntry {
        mime: "video/x-msvideo",
        versions: &[V2_2, V2_4],
    },
    // ---- v2.4 additions: remaining reference media formats ----
    FormatEntry {
        mime: "audio/flac",
        versions: &[V2_4],
    },
    FormatEntry {
        mime: "audio/ogg",
        versions: &[V2_4],
    },
    FormatEntry {
        mime: "video/x-m4v",
        versions: &[V2_4],
    },
    FormatEntry {
        mime: "application/mp4",
        versions: &[V2_4],
    },
    // ---- v2.4 additions: text provenance (via c2pa-text 2.0.0) ----
    FormatEntry {
        mime: "text/plain",
        versions: &[V2_4],
    }, // A.8 unstructured (VS)
    FormatEntry {
        mime: "text/csv",
        versions: &[V2_4],
    }, // A.8 unstructured (VS)
    FormatEntry {
        mime: "text/html",
        versions: &[V2_4],
    }, // A.7 HTML
    FormatEntry {
        mime: "text/markdown",
        versions: &[V2_4],
    }, // A.9 structured
    FormatEntry {
        mime: "text/xml",
        versions: &[V2_4],
    }, // A.9 structured
    FormatEntry {
        mime: "application/xml",
        versions: &[V2_4],
    }, // A.9 structured
    FormatEntry {
        mime: "application/xhtml+xml",
        versions: &[V2_4],
    }, // A.9 structured
    FormatEntry {
        mime: "application/json",
        versions: &[V2_4],
    }, // A.9 structured
    FormatEntry {
        mime: "application/yaml",
        versions: &[V2_4],
    }, // A.9 structured
    FormatEntry {
        mime: "application/toml",
        versions: &[V2_4],
    }, // A.9 structured
    FormatEntry {
        mime: "text/css",
        versions: &[V2_4],
    }, // A.9 structured
    FormatEntry {
        mime: "application/javascript",
        versions: &[V2_4],
    }, // A.9 structured
    // ---- v2.4 additions: packaged documents (ZIP family) + fonts ----
    FormatEntry {
        mime: "application/epub+zip",
        versions: &[V2_4],
    },
    FormatEntry {
        mime: "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        versions: &[V2_4],
    },
    FormatEntry {
        mime: "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        versions: &[V2_4],
    },
    FormatEntry {
        mime: "application/vnd.openxmlformats-officedocument.presentationml.presentation",
        versions: &[V2_4],
    },
    FormatEntry {
        mime: "application/vnd.openxmlformats-officedocument.wordprocessingml.template",
        versions: &[V2_4],
    },
    FormatEntry {
        mime: "application/vnd.ms-word.document.macroenabled.12",
        versions: &[V2_4],
    },
    FormatEntry {
        mime: "application/vnd.ms-word.template.macroenabled.12",
        versions: &[V2_4],
    },
    FormatEntry {
        mime: "application/vnd.openxmlformats-officedocument.spreadsheetml.template",
        versions: &[V2_4],
    },
    FormatEntry {
        mime: "application/vnd.ms-excel.sheet.macroenabled.12",
        versions: &[V2_4],
    },
    FormatEntry {
        mime: "application/vnd.ms-excel.template.macroenabled.12",
        versions: &[V2_4],
    },
    FormatEntry {
        mime: "application/vnd.ms-excel.sheet.binary.macroenabled.12",
        versions: &[V2_4],
    },
    FormatEntry {
        mime: "application/vnd.openxmlformats-officedocument.presentationml.template",
        versions: &[V2_4],
    },
    FormatEntry {
        mime: "application/vnd.openxmlformats-officedocument.presentationml.slideshow",
        versions: &[V2_4],
    },
    FormatEntry {
        mime: "application/vnd.ms-powerpoint.presentation.macroenabled.12",
        versions: &[V2_4],
    },
    FormatEntry {
        mime: "application/vnd.ms-powerpoint.template.macroenabled.12",
        versions: &[V2_4],
    },
    FormatEntry {
        mime: "application/vnd.ms-powerpoint.slideshow.macroenabled.12",
        versions: &[V2_4],
    },
    FormatEntry {
        mime: "application/vnd.ms-visio.drawing",
        versions: &[V2_4],
    },
    FormatEntry {
        mime: "application/vnd.ms-visio.drawing.macroenabled.12",
        versions: &[V2_4],
    },
    FormatEntry {
        mime: "application/vnd.ms-visio.stencil",
        versions: &[V2_4],
    },
    FormatEntry {
        mime: "application/vnd.ms-visio.stencil.macroenabled.12",
        versions: &[V2_4],
    },
    FormatEntry {
        mime: "application/vnd.ms-visio.template",
        versions: &[V2_4],
    },
    FormatEntry {
        mime: "application/vnd.ms-visio.template.macroenabled.12",
        versions: &[V2_4],
    },
    FormatEntry {
        mime: "application/vnd.oasis.opendocument.text",
        versions: &[V2_4],
    },
    FormatEntry {
        mime: "application/vnd.oasis.opendocument.spreadsheet",
        versions: &[V2_4],
    },
    FormatEntry {
        mime: "application/vnd.oasis.opendocument.presentation",
        versions: &[V2_4],
    },
    FormatEntry {
        mime: "application/oxps",
        versions: &[V2_4],
    },
    FormatEntry {
        mime: "application/vnd.ms-xpsdocument",
        versions: &[V2_4],
    },
    FormatEntry {
        mime: "font/otf",
        versions: &[V2_4],
    },
    FormatEntry {
        mime: "font/ttf",
        versions: &[V2_4],
    },
    FormatEntry {
        mime: "font/sfnt",
        versions: &[V2_4],
    },
    FormatEntry {
        mime: "application/font-sfnt",
        versions: &[V2_4],
    },
    FormatEntry {
        mime: "application/x-font-ttf",
        versions: &[V2_4],
    },
];

/// True when `canon_mime` (already canonicalized) is in scope for `version`.
fn mime_in_version(canon_mime: &str, version: SpecVersion) -> bool {
    FORMAT_REGISTRY
        .iter()
        .any(|e| e.mime.eq_ignore_ascii_case(canon_mime) && e.versions.contains(&version))
}

/// True when `canon_mime` is registered for any version.
fn mime_known(canon_mime: &str) -> bool {
    FORMAT_REGISTRY
        .iter()
        .any(|e| e.mime.eq_ignore_ascii_case(canon_mime))
}

/// True when `version` defines a certified format scope (any registry row).
/// The validation-only revisions (1.4/2.0/2.1/2.3) have none.
fn version_has_scope(version: SpecVersion) -> bool {
    FORMAT_REGISTRY
        .iter()
        .any(|e| e.versions.contains(&version))
}

/// The canonical MIME types in scope for a given spec version (certified set).
/// Useful for conformance harnesses, sample-output generation, and interop test
/// selection.
pub fn mimes_for_version(version: SpecVersion) -> Vec<&'static str> {
    FORMAT_REGISTRY
        .iter()
        .filter(|e| e.versions.contains(&version))
        .map(|e| e.mime)
        .collect()
}

/// The certified C2PA 2.2 MIME set, as the *accepted* input forms (aliases
/// included). Retained for the conformance harness and tests; derived from the
/// registry so it cannot drift.
pub fn v2_2_certified_mimes() -> Vec<&'static str> {
    let mut v = mimes_for_version(SpecVersion::V2_2);
    // The two certified alias input forms canonicalize into the registry set.
    v.push("audio/MPA");
    v.push("audio/aac");
    v
}

#[cfg(test)]
mod tests {
    use super::*;

    const CONF_2_2: EngineProfile = EngineProfile::CONFORMANCE_V2_2;
    fn regular_2_2() -> EngineProfile {
        EngineProfile::new(SpecVersion::V2_2, OperatingMode::Regular)
    }
    fn conf_2_4() -> EngineProfile {
        EngineProfile::new(SpecVersion::V2_4, OperatingMode::Conformance)
    }

    #[test]
    fn default_is_certified_v2_2() {
        assert_eq!(EngineProfile::default(), CONF_2_2);
        assert_eq!(CONF_2_2.version_str(), "2.2");
        assert_eq!(CONF_2_2.compliance, ComplianceLevel::ConformanceProgram);
    }

    #[test]
    fn v2_2_certified_set_is_exactly_twenty() {
        // 18 registry rows tagged V2_2 + the 2 canonical-alias input forms.
        let certified = v2_2_certified_mimes();
        assert_eq!(
            certified.len(),
            20,
            "certified v2.2 set is 20 accepted forms"
        );
    }

    #[test]
    fn conformance_v2_2_permits_certified_refuses_v2_4_only() {
        for mime in v2_2_certified_mimes() {
            assert!(
                CONF_2_2.permits_mime(mime),
                "conformance 2.2 must permit {mime}"
            );
        }
        // v2.4-only formats (text, fonts, FLAC, ZIP) are out of the 2.2 scope.
        for mime in [
            "text/plain",
            "text/html",
            "audio/flac",
            "font/otf",
            "application/epub+zip",
            "video/x-m4v",
        ] {
            assert!(
                !CONF_2_2.permits_mime(mime),
                "conformance 2.2 must REFUSE {mime}"
            );
        }
    }

    #[test]
    fn conformance_v2_4_permits_text_and_media() {
        for mime in [
            "text/plain",
            "text/html",
            "text/markdown",
            "image/jpeg",
            "audio/flac",
        ] {
            assert!(
                conf_2_4().permits_mime(mime),
                "conformance 2.4 must permit {mime}"
            );
        }
    }

    #[test]
    fn regular_mode_permits_any_known_format() {
        for mime in [
            "text/plain",
            "image/jpeg",
            "font/otf",
            "audio/flac",
            "application/json",
        ] {
            assert!(
                regular_2_2().permits_mime(mime),
                "regular must permit known {mime}"
            );
        }
        // Genuinely unknown / ML-model formats are never permitted.
        for mime in [
            "model/gguf",
            "application/x-onnx",
            "application/octet-stream",
        ] {
            assert!(
                !regular_2_2().permits_mime(mime),
                "regular must refuse unknown {mime}"
            );
            assert!(!conf_2_4().permits_mime(mime));
        }
    }

    #[test]
    fn aliases_canonicalize() {
        assert_eq!(canonicalize_mime("audio/MPA"), "audio/mpeg");
        assert_eq!(canonicalize_mime("audio/aac"), "audio/mp4");
        assert_eq!(
            canonicalize_mime("image/svg+xml; charset=utf-8"),
            "image/svg+xml"
        );
        assert!(CONF_2_2.permits_mime("audio/MPA"));
        assert!(CONF_2_2.permits_mime("AUDIO/AAC"));
    }

    #[test]
    fn container_aliases_canonicalize_to_certified_forms() {
        // c2pa-rs / C2PA 2.4 alias spellings resolve to one certified canonical
        // MIME, so they sign to identical bytes and share conformance scope.
        for (alias, canon) in [
            ("video/avi", "video/x-msvideo"),
            ("video/msvideo", "video/x-msvideo"),
            ("application/x-troff-msvideo", "video/x-msvideo"),
            ("audio/wave", "audio/wav"),
            ("audio/vnd.wave", "audio/wav"),
            ("audio/x-wav", "audio/wav"),
            ("audio/x-flac", "audio/flac"),
            ("image/dng", "image/x-adobe-dng"),
            ("application/svg+xml", "image/svg+xml"),
        ] {
            assert_eq!(canonicalize_mime(alias), canon, "{alias}");
        }
        // Aliases inherit their canonical form's certified scope.
        assert!(CONF_2_2.permits_mime("video/avi"));
        assert!(CONF_2_2.permits_mime("audio/x-wav"));
        assert!(CONF_2_2.permits_mime("image/dng"));
        assert!(CONF_2_2.permits_mime("application/svg+xml"));
        assert!(!CONF_2_2.permits_mime("audio/x-flac"));
        assert!(conf_2_4().permits_mime("audio/x-flac"));
    }

    #[test]
    fn mimes_for_version_filters_correctly() {
        let v22 = mimes_for_version(SpecVersion::V2_2);
        let v24 = mimes_for_version(SpecVersion::V2_4);
        assert!(v22.contains(&"image/jpeg") && !v22.contains(&"text/plain"));
        assert!(v24.contains(&"text/plain") && v24.contains(&"image/jpeg"));
        assert!(v24.len() > v22.len(), "v2.4 is a superset");
    }

    #[test]
    fn spec_version_round_trips() {
        assert_eq!(SpecVersion::from_str("2.2"), Some(SpecVersion::V2_2));
        assert_eq!(SpecVersion::from_str("2.4"), Some(SpecVersion::V2_4));
        assert_eq!(SpecVersion::from_str("9.9"), None);
    }

    #[test]
    fn compliance_level_builder() {
        let p = EngineProfile::new(SpecVersion::V2_4, OperatingMode::Regular)
            .with_compliance(ComplianceLevel::ConformanceProgram);
        assert_eq!(p.compliance, ComplianceLevel::ConformanceProgram);
        assert_eq!(
            EngineProfile::new(SpecVersion::V2_2, OperatingMode::Conformance).compliance,
            ComplianceLevel::CoreSpec
        );
    }

    #[test]
    fn strict_mode_is_version_independent() {
        for v in [SpecVersion::V2_2, SpecVersion::V2_4] {
            let p = EngineProfile::strict(v);
            assert_eq!(p.version, v);
            assert!(p.debug, "strict implies diagnostics on");
            assert_eq!(p.mode, OperatingMode::Conformance);
            assert_eq!(p.compliance, ComplianceLevel::ConformanceProgram);
        }
        // debug is independent of version: can attach to any profile.
        assert!(
            EngineProfile::new(SpecVersion::V2_4, OperatingMode::Regular)
                .with_debug(true)
                .debug
        );
    }
}
