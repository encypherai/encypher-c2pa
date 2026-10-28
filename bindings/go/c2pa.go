// Copyright 2026 Encypher Corporation
// SPDX-License-Identifier: Apache-2.0

// Package c2pa verifies C2PA manifests locally through the shared Rust core.
package c2pa

/*
#cgo CFLAGS: -I${SRCDIR}/../c/include
#cgo linux LDFLAGS: ${SRCDIR}/../../target/release/libencypher_c2pa_ffi.a -ldl -lpthread -lm
#cgo darwin LDFLAGS: ${SRCDIR}/../../target/release/libencypher_c2pa_ffi.a -framework Security -framework CoreFoundation
#include <stdlib.h>
#include "encypher_c2pa.h"
*/
import "C"

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"runtime"
	"unsafe"
)

const (
	ReportSchemaVersion = "1.0"
	C2PAProfile22       = "c2pa-2.2"
	C2PAProfile         = "c2pa-2.4"
	C2PAProfile25       = "c2pa-2.5"
)

const maxPathAssetBytes int64 = 128 * 1024 * 1024

type TelemetryOptions struct {
	Enabled  *bool  `json:"enabled,omitempty"`
	Endpoint string `json:"endpoint,omitempty"`
	SDKName  string `json:"sdk_name,omitempty"`
}

// CAWGTrustProfile names the CAWG Identity 1.3 rules a trust configuration
// is accepted under.
type CAWGTrustProfile string

const (
	// CAWGTrustProfileBase is an entry the validator configured itself.
	CAWGTrustProfileBase CAWGTrustProfile = "base"
	// CAWGTrustProfileSMIMEInterim is the Mozilla email root store or an IPTC
	// Verified News Publishers list: S/MIME identities only, and only until
	// 31 March 2027 or with a trusted time stamp from before it.
	CAWGTrustProfileSMIMEInterim CAWGTrustProfile = "smime_interim"
)

// CAWGTrustConfiguration is one typed CAWG trust source. CertificatesPEM may
// mix CA and end-entity certificates; NotBefore and NotAfter are RFC 3339
// bounds on this entry alone.
type CAWGTrustConfiguration struct {
	Profile         CAWGTrustProfile `json:"profile"`
	CertificatesPEM string           `json:"certificates_pem"`
	NotBefore       string           `json:"not_before,omitempty"`
	NotAfter        string           `json:"not_after,omitempty"`
}

// TrustListSource retains the identity of a caller-supplied claim or TSA trust
// list. URI is an identifier and is never fetched by verification.
type TrustListSource struct {
	URI             string `json:"uri"`
	Type            string `json:"type"`
	Identifier      string `json:"identifier,omitempty"`
	CertificatesPEM string `json:"certificates_pem"`
}

// Options mirrors the SDK VerifyOptions JSON. TrustAnchorNotBefore and
// TrustAnchorNotAfter are RFC 3339 instants bounding when the caller-supplied
// anchors are trusted; the bundled snapshots are unaffected.
type Options struct {
	TrustPEM            string `json:"trust_pem,omitempty"`
	ClaimTrustSources     []TrustListSource `json:"claim_trust_sources,omitempty"`
	TSATrustPEM         string `json:"tsa_trust_pem,omitempty"`
	TSATrustSources       []TrustListSource `json:"tsa_trust_sources,omitempty"`
	AllowedCertsPEM     string `json:"allowed_list_pem,omitempty"`
	CAWGTrustPEM        string `json:"cawg_trust_pem,omitempty"`
	CAWGAllowedCertsPEM string `json:"cawg_allowed_certs_pem,omitempty"`
	// CAWGTrustConfigurations are typed CAWG trust sources, appended after
	// CAWGTrustPEM and CAWGAllowedCertsPEM.
	CAWGTrustConfigurations []CAWGTrustConfiguration   `json:"cawg_trust_configurations,omitempty"`
	TrustAnchorNotBefore    string                     `json:"trust_anchor_not_before,omitempty"`
	TrustAnchorNotAfter     string                     `json:"trust_anchor_not_after,omitempty"`
	NoDefaultTrust          bool                       `json:"no_default_trust,omitempty"`
	CAWGDIDDocuments        map[string]json.RawMessage `json:"cawg_did_documents,omitempty"`
	CAWGICATrustedIssuers   []string                   `json:"cawg_ica_trusted_issuers,omitempty"`
	CAWGICATrustAnchors     []string                   `json:"cawg_ica_trust_anchors,omitempty"`
	CAWGICAStatusLists      map[string]string          `json:"cawg_ica_status_lists,omitempty"`
	// CAWGStrictEncoding refuses the CAWG field-order signer payload that
	// c2pa-rs writes; StrictConformance refuses it either way.
	CAWGStrictEncoding bool `json:"cawg_strict_encoding,omitempty"`
	// ExpectedSeekPositions are zero-based indexes into supplied fragments or
	// stream segments where the player expects a discontinuity. Single-asset
	// verification ignores them.
	ExpectedSeekPositions []int `json:"expected_seek_positions,omitempty"`
	// SpecVersion selects the C2PA validation policy: "2.2", "" or "2.4"
	// (the default, identical reports), or "2.5" for the published standard.
	// StrictConformance selects the published program posture under 2.2/2.4
	// and strict technical core validation under 2.5. The latter makes no
	// certified or Conformance Program claim.
	SpecVersion       string `json:"spec_version,omitempty"`
	StrictConformance bool   `json:"strict_conformance,omitempty"`
	ValidationTime    string `json:"validation_time,omitempty"`
	// StreamPresentationTimes are trusted RFC 3339 instants, one per segment.
	// Nil assesses every segment at ValidationTime (default now). A non-nil
	// slice must have one entry per segment; empty is refused, not absent.
	// Merkle-bound and per-segment streams, and VerifyFragmented, refuse it.
	// Only supply times from a record you control, never from signed iat.
	StreamPresentationTimes []string `json:"stream_presentation_times"`
	// Online allows this call to fetch what the asset references: a manifest
	// store held elsewhere, certificate revocation status, a did:web
	// document, externally stored content. Nil leaves it off unless the
	// operator sets ENCYPHER_C2PA_ONLINE=on. This library never reads the
	// per-user choice saved by the command line and never prompts: the host
	// running it may be checking files sent in by strangers. What is fetched
	// is evidence only; the verdict still comes from the same offline checks.
	Online *bool `json:"online,omitempty"`
	// OnlineAllowPrivateNetworks is intranet mode: online checks may reach
	// loopback and private addresses and accept plaintext http. Do not set it
	// on a host that verifies files sent in by strangers.
	OnlineAllowPrivateNetworks bool              `json:"online_allow_private_networks,omitempty"`
	// ExternalData is caller-supplied linked-resource evidence, keyed by URI
	// with base64 values. Media types bind the corresponding bodies, and
	// ExternalDataUnreachable records attempted retrievals with no usable body.
	ExternalData             map[string]string `json:"external_data,omitempty"`
	ExternalDataMediaTypes   map[string]string `json:"external_data_media_types,omitempty"`
	ExternalDataUnreachable  []string          `json:"external_data_unreachable,omitempty"`
	Telemetry                  *TelemetryOptions `json:"telemetry,omitempty"`
}

type Status struct {
	Code        string          `json:"code"`
	URL         string          `json:"url"`
	Explanation string          `json:"explanation"`
	Details     json.RawMessage `json:"details,omitempty"`
}

type ValidationResults struct {
	Success       []Status `json:"success"`
	Informational []Status `json:"informational"`
	Failure       []Status `json:"failure"`
}

type RevocationReport struct {
	Status             string `json:"status"`
	Source             string `json:"source"`
	ResponderSignature string `json:"responder_signature"`
}

type FreshnessReport struct {
	Status string  `json:"status"`
	AsOf   *string `json:"as_of"`
}

type TrustReport struct {
	Status         string           `json:"status"`
	Basis          string           `json:"basis"`
	ValidationTime string           `json:"validation_time"`
	Revocation     RevocationReport `json:"revocation"`
	Freshness      FreshnessReport  `json:"freshness"`
}

// NetworkRequest is one attempted fetch. Outcome is fetched, failed, blocked,
// or skipped.
type NetworkRequest struct {
	Purpose string `json:"purpose"`
	URL     string `json:"url"`
	Outcome string `json:"outcome"`
	Detail  string `json:"detail"`
}

// NetworkReport says what the verification did, or could have done, on the
// network. Needed is filled in whether or not fetching was allowed, so an
// offline caller can see what allowing it would settle.
type NetworkReport struct {
	Enabled  bool              `json:"enabled"`
	Needed   []json.RawMessage `json:"needed"`
	Requests []NetworkRequest  `json:"requests"`
}

type Report struct {
	SchemaVersion      string            `json:"schema_version"`
	Profile            string            `json:"profile"`
	MIMEType           string            `json:"mime_type"`
	Present            bool              `json:"present"`
	Integrity          string            `json:"integrity"`
	Signature          string            `json:"signature"`
	HardBinding        string            `json:"hard_binding"`
	Trust              TrustReport       `json:"trust"`
	Policy             json.RawMessage   `json:"policy"`
	ManagedReceipt     json.RawMessage   `json:"managed_receipt"`
	ValidationState    string            `json:"validation_state"`
	ValidationResults  ValidationResults `json:"validation_results"`
	ManifestReport     json.RawMessage   `json:"manifest_report"`
	ContentCredentials json.RawMessage   `json:"content_credentials"`
	Network            NetworkReport     `json:"network"`
}

type VerificationError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

func (e *VerificationError) Error() string {
	return fmt.Sprintf("%s: %s", e.Code, e.Message)
}

type responseEnvelope struct {
	OK     bool               `json:"ok"`
	Report *Report            `json:"report"`
	Error  *VerificationError `json:"error"`
}

type telemetryPreferenceEnvelope struct {
	OK      bool               `json:"ok"`
	Enabled *bool              `json:"enabled"`
	Error   *VerificationError `json:"error"`
}

// Verify verifies asset bytes locally. On first interactive use it asks for
// failure telemetry consent and saves the answer. Options.Telemetry overrides
// the saved preference for this call.
func Verify(asset []byte, mimeType string, options *Options) (*Report, error) {
	if mimeType == "" {
		return nil, errors.New("mime type is required")
	}
	optionsJSON, err := marshalOptions(options)
	if err != nil {
		return nil, err
	}

	var assetPtr *C.uint8_t
	if len(asset) > 0 {
		assetPtr = (*C.uint8_t)(unsafe.Pointer(&asset[0]))
	}
	mime := C.CString(mimeType)
	defer C.free(unsafe.Pointer(mime))
	opts := C.CString(string(optionsJSON))
	defer C.free(unsafe.Pointer(opts))

	result := C.encypher_c2pa_verify(assetPtr, C.size_t(len(asset)), mime, opts)
	runtime.KeepAlive(asset)
	if result == nil {
		return nil, errors.New("verifier returned no result")
	}
	defer C.encypher_c2pa_free_string(result)

	var envelope responseEnvelope
	if err := json.Unmarshal([]byte(C.GoString(result)), &envelope); err != nil {
		return nil, fmt.Errorf("decode verifier response: %w", err)
	}
	if !envelope.OK {
		if envelope.Error != nil {
			return nil, envelope.Error
		}
		return nil, errors.New("verification failed without a structured error")
	}
	if envelope.Report == nil {
		return nil, errors.New("verification succeeded without a report")
	}
	return envelope.Report, nil
}

// VerifyWithManifestStore verifies asset bytes against a C2PA Manifest Store
// held outside the asset: a .c2pa sidecar, or a store the caller fetched from
// the URI the asset declares in its XMP dcterms:provenance key. This SDK never
// fetches it. mimeType describes the asset, not the store.
func VerifyWithManifestStore(asset []byte, manifestStore []byte, mimeType string, options *Options) (*Report, error) {
	if mimeType == "" {
		return nil, errors.New("mime type is required")
	}
	if len(manifestStore) == 0 {
		return nil, errors.New("manifest store is required")
	}
	optionsJSON, err := marshalOptions(options)
	if err != nil {
		return nil, err
	}

	var assetPtr *C.uint8_t
	if len(asset) > 0 {
		assetPtr = (*C.uint8_t)(unsafe.Pointer(&asset[0]))
	}
	storePtr := (*C.uint8_t)(unsafe.Pointer(&manifestStore[0]))
	mime := C.CString(mimeType)
	defer C.free(unsafe.Pointer(mime))
	opts := C.CString(string(optionsJSON))
	defer C.free(unsafe.Pointer(opts))

	result := C.encypher_c2pa_verify_with_manifest_store(
		assetPtr,
		C.size_t(len(asset)),
		storePtr,
		C.size_t(len(manifestStore)),
		mime,
		opts,
	)
	runtime.KeepAlive(asset)
	runtime.KeepAlive(manifestStore)
	if result == nil {
		return nil, errors.New("verifier returned no result")
	}
	defer C.encypher_c2pa_free_string(result)

	var envelope responseEnvelope
	if err := json.Unmarshal([]byte(C.GoString(result)), &envelope); err != nil {
		return nil, fmt.Errorf("decode verifier response: %w", err)
	}
	if !envelope.OK {
		if envelope.Error != nil {
			return nil, envelope.Error
		}
		return nil, errors.New("verification failed without a structured error")
	}
	if envelope.Report == nil {
		return nil, errors.New("verification succeeded without a report")
	}
	return envelope.Report, nil
}

// ManifestDigest identifies one manifest in store order.
type ManifestDigest struct {
	Label  string `json:"label"`
	SHA256 string `json:"sha256"`
}

// StoreOnlyValidation is a store-level verdict with no asset-content claim.
type StoreOnlyValidation struct {
	Report              Report           `json:"report"`
	ActiveManifestLabel *string          `json:"active_manifest_label"`
	StoreManifests      []ManifestDigest `json:"store_manifests"`
}

type storeOnlyResponseEnvelope struct {
	OK     bool                 `json:"ok"`
	Result *StoreOnlyValidation `json:"result"`
	Error  *VerificationError   `json:"error"`
}

// VerifyManifestStoreOnly validates claim, assertion, signature, trust and
// identity evidence without asset bytes. Intact stores remain "unbound".
func VerifyManifestStoreOnly(manifestStore []byte, options *Options) (*StoreOnlyValidation, error) {
	if len(manifestStore) == 0 {
		return nil, errors.New("manifest store is required")
	}
	optionsJSON, err := marshalOptions(options)
	if err != nil {
		return nil, err
	}
	storePtr := (*C.uint8_t)(unsafe.Pointer(&manifestStore[0]))
	opts := C.CString(string(optionsJSON))
	defer C.free(unsafe.Pointer(opts))
	result := C.encypher_c2pa_verify_manifest_store_only(
		storePtr,
		C.size_t(len(manifestStore)),
		opts,
	)
	runtime.KeepAlive(manifestStore)
	if result == nil {
		return nil, errors.New("verifier returned no result")
	}
	defer C.encypher_c2pa_free_string(result)
	var envelope storeOnlyResponseEnvelope
	if err := json.Unmarshal([]byte(C.GoString(result)), &envelope); err != nil {
		return nil, fmt.Errorf("decode verifier response: %w", err)
	}
	if !envelope.OK {
		if envelope.Error != nil {
			return nil, envelope.Error
		}
		return nil, errors.New("store-only validation failed without a structured error")
	}
	if envelope.Result == nil {
		return nil, errors.New("store-only validation succeeded without a result")
	}
	return envelope.Result, nil
}

// ManifestBindingTarget binds caller evidence to exact store bytes, the active
// manifest and the operative assertion reference.
type ManifestBindingTarget struct {
	ManifestStoreSHA256   [32]byte `json:"manifest_store_sha256"`
	ActiveManifestLabel   string   `json:"active_manifest_label"`
	ActiveManifestSHA256  [32]byte `json:"active_manifest_sha256"`
	BindingManifestLabel  string   `json:"binding_manifest_label"`
	BindingAssertionLabel string   `json:"binding_assertion_label"`
	BindingReferenceAlg   string   `json:"binding_reference_alg"`
	BindingReferenceHash  []byte   `json:"binding_reference_hash"`
}

type bindingTargetResponseEnvelope struct {
	OK     bool                   `json:"ok"`
	Target *ManifestBindingTarget `json:"target"`
	Error  *VerificationError     `json:"error"`
}

// BindingTarget derives the exact target a trusted caller must independently
// compare against asset bytes. A nil target means no unique operative binding.
func BindingTarget(manifestStore []byte, hostless bool, options *Options) (*ManifestBindingTarget, error) {
	if len(manifestStore) == 0 {
		return nil, errors.New("manifest store is required")
	}
	optionsJSON, err := marshalOptions(options)
	if err != nil {
		return nil, err
	}
	storePtr := (*C.uint8_t)(unsafe.Pointer(&manifestStore[0]))
	opts := C.CString(string(optionsJSON))
	defer C.free(unsafe.Pointer(opts))
	result := C.encypher_c2pa_binding_target(
		storePtr,
		C.size_t(len(manifestStore)),
		C.bool(hostless),
		opts,
	)
	runtime.KeepAlive(manifestStore)
	if result == nil {
		return nil, errors.New("verifier returned no result")
	}
	defer C.encypher_c2pa_free_string(result)
	var envelope bindingTargetResponseEnvelope
	if err := json.Unmarshal([]byte(C.GoString(result)), &envelope); err != nil {
		return nil, fmt.Errorf("decode binding-target response: %w", err)
	}
	if !envelope.OK {
		if envelope.Error != nil {
			return nil, envelope.Error
		}
		return nil, errors.New("binding-target derivation failed without a structured error")
	}
	return envelope.Target, nil
}

// VerifyWithCallerBinding validates a store after a trusted caller compared
// the exact target against asset bytes. A mismatch requires an explanation.
func VerifyWithCallerBinding(
	manifestStore []byte,
	contentMime string,
	hostless bool,
	target *ManifestBindingTarget,
	matched bool,
	explanation string,
	engine string,
	options *Options,
) (*Report, error) {
	if len(manifestStore) == 0 || target == nil {
		return nil, errors.New("manifest store and binding target are required")
	}
	if contentMime == "" || engine == "" {
		return nil, errors.New("content MIME type and engine are required")
	}
	if matched && explanation != "" {
		return nil, errors.New("explanation is only valid for a mismatch")
	}
	if !matched && explanation == "" {
		return nil, errors.New("a mismatch requires explanation")
	}
	optionsJSON, err := marshalOptions(options)
	if err != nil {
		return nil, err
	}
	targetJSON, err := json.Marshal(target)
	if err != nil {
		return nil, fmt.Errorf("encode binding target: %w", err)
	}
	var verdictJSON []byte
	if matched {
		verdictJSON = []byte(`"Match"`)
	} else {
		verdictJSON, err = json.Marshal(map[string]any{
			"Mismatch": map[string]string{"explanation": explanation},
		})
		if err != nil {
			return nil, fmt.Errorf("encode binding verdict: %w", err)
		}
	}
	storePtr := (*C.uint8_t)(unsafe.Pointer(&manifestStore[0]))
	mime := C.CString(contentMime)
	targetValue := C.CString(string(targetJSON))
	verdict := C.CString(string(verdictJSON))
	engineValue := C.CString(engine)
	opts := C.CString(string(optionsJSON))
	defer C.free(unsafe.Pointer(mime))
	defer C.free(unsafe.Pointer(targetValue))
	defer C.free(unsafe.Pointer(verdict))
	defer C.free(unsafe.Pointer(engineValue))
	defer C.free(unsafe.Pointer(opts))
	result := C.encypher_c2pa_verify_with_caller_binding(
		storePtr,
		C.size_t(len(manifestStore)),
		mime,
		C.bool(hostless),
		targetValue,
		verdict,
		engineValue,
		opts,
	)
	runtime.KeepAlive(manifestStore)
	if result == nil {
		return nil, errors.New("verifier returned no result")
	}
	defer C.encypher_c2pa_free_string(result)
	var envelope responseEnvelope
	if err := json.Unmarshal([]byte(C.GoString(result)), &envelope); err != nil {
		return nil, fmt.Errorf("decode verifier response: %w", err)
	}
	if !envelope.OK {
		if envelope.Error != nil {
			return nil, envelope.Error
		}
		return nil, errors.New("caller-binding validation failed without a structured error")
	}
	if envelope.Report == nil {
		return nil, errors.New("caller-binding validation succeeded without a report")
	}
	return envelope.Report, nil
}

// StreamEncapsulation is how a fragmented stream is packaged.
type StreamEncapsulation string

// StreamMethod is the C2PA protection method a fragmented stream was signed under.
type StreamMethod string

const (
	// EncapsulationFMP4 is fragmented MP4 (DASH/HLS packaging).
	EncapsulationFMP4 StreamEncapsulation = "fMP4"
	// EncapsulationCMAF is the Common Media Application Format.
	EncapsulationCMAF StreamEncapsulation = "CMAF"

	// MethodVerifiableSegmentInfo means one init manifest binds the whole
	// stream. Which binding it used - C2PA 2.4 session keys or a Merkle tree -
	// is read from that manifest, never declared by the caller.
	MethodVerifiableSegmentInfo StreamMethod = "verifiable-segment-info"
	// MethodPerSegment means every segment carries its own manifest and is
	// chained to its predecessor.
	MethodPerSegment StreamMethod = "per-segment"
)

// SegmentReport is one per-segment stream position verified as a standalone asset.
type SegmentReport struct {
	SequenceNumber        int     `json:"sequence_number"`
	ManifestLabel         string  `json:"manifest_label"`
	PreviousManifestLabel *string `json:"previous_manifest_label"`
	Report                Report  `json:"report"`
}

// StreamReport is the result of VerifyStream.
type StreamReport struct {
	SchemaVersion string              `json:"schema_version"`
	Encapsulation StreamEncapsulation `json:"encapsulation"`
	Method        StreamMethod        `json:"method"`
	Integrity     string              `json:"integrity"`
	Stream        *Report             `json:"stream"`
	Segments      []SegmentReport     `json:"segments"`
	ChainValid    *bool               `json:"chain_valid"`
	ChainFailures []string            `json:"chain_failures"`
}

type streamResponseEnvelope struct {
	OK     bool               `json:"ok"`
	Report *StreamReport      `json:"report"`
	Error  *VerificationError `json:"error"`
}

// ErtmpReport is the result of VerifyErtmp.
type ErtmpReport struct {
	SchemaVersion string `json:"schema_version"`
	Integrity     string `json:"integrity"`
	Manifests     []struct {
		ManifestID string `json:"manifest_id"`
		Report     Report `json:"report"`
	} `json:"manifests"`
	Segments []struct {
		Track struct {
			MediaType string `json:"media_type"`
			TrackID   uint8  `json:"track_id"`
		} `json:"track"`
		SequenceNumber *uint64  `json:"sequence_number"`
		ManifestID     *string  `json:"manifest_id"`
		KeyID          *string  `json:"key_id"`
		Valid          bool     `json:"valid"`
		Failures       []string `json:"failures"`
	} `json:"segments"`
	Failures []string `json:"failures"`
}

type ertmpResponseEnvelope struct {
	OK     bool               `json:"ok"`
	Report *ErtmpReport       `json:"report"`
	Error  *VerificationError `json:"error"`
}

// SoftBindingQuery selects exactly one read-only resolution route. Route is
// binding_get, binding_post, content, or reference. Content requires
// Consent="upload_asset"; reference requires Consent="disclose_reference".
type SoftBindingQuery struct {
	Route        string          `json:"route"`
	Alg          *string         `json:"alg,omitempty"`
	Value        *string         `json:"value,omitempty"`
	HintAlg      *string         `json:"hint_alg,omitempty"`
	HintValue    *string         `json:"hint_value,omitempty"`
	ReferenceURL *string         `json:"reference_url,omitempty"`
	AssetLength  *uint64         `json:"asset_length,omitempty"`
	AssetType    *string         `json:"asset_type,omitempty"`
	Region       json.RawMessage `json:"region,omitempty"`
	Consent      *string         `json:"consent,omitempty"`
}

// SoftBindingResolverOptions is the mandatory network boundary for recovery.
// Every service, federation, and repository origin must appear exactly in
// AllowedOrigins. Redirects are refused.
type SoftBindingResolverOptions struct {
	AllowedOrigins       []string `json:"allowed_origins"`
	AllowPrivateNetworks bool     `json:"allow_private_networks,omitempty"`
	MaxResults           uint16   `json:"max_results,omitempty"`
	FetchStatus          bool     `json:"fetch_status,omitempty"`
	FetchReceipts        bool     `json:"fetch_receipts,omitempty"`
}

// SoftBindingResolution is discovery evidence and locally verified stores.
// Status and each receipt are server-reported operational evidence, not local
// cryptographic verdicts.
type SoftBindingResolution struct {
	Discovery    json.RawMessage `json:"discovery"`
	Capabilities json.RawMessage `json:"capabilities"`
	Algorithms   json.RawMessage `json:"algorithms"`
	Status       json.RawMessage `json:"status,omitempty"`
	Recovered    []struct {
		Matched json.RawMessage `json:"matched"`
		Report  Report          `json:"report"`
		Receipt json.RawMessage `json:"receipt,omitempty"`
	} `json:"recovered"`
}

// SoftBindingReceiptEvidence is a repository's report, not a local
// cryptographic receipt verdict.
type SoftBindingReceiptEvidence struct {
	Receipt                json.RawMessage `json:"receipt"`
	ServerReportedVerified bool            `json:"server_reported_verified"`
	ServerError            *string         `json:"server_error,omitempty"`
}

type softBindingReceiptResponseEnvelope struct {
	OK       bool                        `json:"ok"`
	Evidence *SoftBindingReceiptEvidence `json:"evidence"`
	Error    *VerificationError          `json:"error"`
}

type softBindingResponseEnvelope struct {
	OK         bool                   `json:"ok"`
	Resolution *SoftBindingResolution `json:"resolution"`
	Error      *VerificationError     `json:"error"`
}

// VerifyFragmented verifies a Merkle-bound fragmented ISO BMFF stream.
//
// initSegment carries the manifest and fragments are its media segments. Any
// contiguous subset may be supplied; each fragment carries its own Merkle-tree
// location. Mark intentional discontinuities in Options.ExpectedSeekPositions.
// Fragments that the init manifest's binding cannot cover are a verification
// FAILURE, not a silent pass - use VerifyStream for session-key or per-segment
// streams.
func VerifyFragmented(initSegment []byte, fragments [][]byte, mimeType string, options *Options) (*Report, error) {
	if mimeType == "" {
		return nil, errors.New("mime type is required")
	}
	optionsJSON, err := marshalOptions(options)
	if err != nil {
		return nil, err
	}

	segmentsPtr, lengthsPtr, releaseSegments := segmentArrays(fragments)
	defer releaseSegments()
	mime := C.CString(mimeType)
	defer C.free(unsafe.Pointer(mime))
	opts := C.CString(string(optionsJSON))
	defer C.free(unsafe.Pointer(opts))

	var assetPtr *C.uint8_t
	if len(initSegment) > 0 {
		assetPtr = (*C.uint8_t)(unsafe.Pointer(&initSegment[0]))
	}
	result := C.encypher_c2pa_verify_fragmented(
		assetPtr,
		C.size_t(len(initSegment)),
		segmentsPtr,
		lengthsPtr,
		C.size_t(len(fragments)),
		mime,
		opts,
	)
	runtime.KeepAlive(initSegment)
	runtime.KeepAlive(fragments)
	if result == nil {
		return nil, errors.New("verifier returned no result")
	}
	defer C.encypher_c2pa_free_string(result)

	var envelope responseEnvelope
	if err := json.Unmarshal([]byte(C.GoString(result)), &envelope); err != nil {
		return nil, fmt.Errorf("decode verifier response: %w", err)
	}
	if !envelope.OK {
		if envelope.Error != nil {
			return nil, envelope.Error
		}
		return nil, errors.New("verification failed without a structured error")
	}
	if envelope.Report == nil {
		return nil, errors.New("verification succeeded without a report")
	}
	return envelope.Report, nil
}

// VerifyStream verifies a declared fMP4/CMAF stream.
//
// initSegment is the initialization segment and segments are its media
// segments in playback order. Both files' declared brands are checked against
// encapsulation, so a stream presented under the wrong one is refused rather
// than verified.
// Mark intentional discontinuities in Options.ExpectedSeekPositions, and pass
// trusted per-segment presentation times in Options.StreamPresentationTimes.
func VerifyStream(initSegment []byte, segments [][]byte, mimeType string, encapsulation StreamEncapsulation, method StreamMethod, options *Options) (*StreamReport, error) {
	if mimeType == "" {
		return nil, errors.New("mime type is required")
	}
	if encapsulation == "" {
		encapsulation = EncapsulationFMP4
	}
	if method == "" {
		method = MethodVerifiableSegmentInfo
	}
	optionsJSON, err := marshalOptions(options)
	if err != nil {
		return nil, err
	}

	segmentsPtr, lengthsPtr, releaseSegments := segmentArrays(segments)
	defer releaseSegments()
	mime := C.CString(mimeType)
	defer C.free(unsafe.Pointer(mime))
	encap := C.CString(string(encapsulation))
	defer C.free(unsafe.Pointer(encap))
	meth := C.CString(string(method))
	defer C.free(unsafe.Pointer(meth))
	opts := C.CString(string(optionsJSON))
	defer C.free(unsafe.Pointer(opts))

	var assetPtr *C.uint8_t
	if len(initSegment) > 0 {
		assetPtr = (*C.uint8_t)(unsafe.Pointer(&initSegment[0]))
	}

	result := C.encypher_c2pa_verify_stream(
		assetPtr,
		C.size_t(len(initSegment)),
		segmentsPtr,
		lengthsPtr,
		C.size_t(len(segments)),
		mime,
		encap,
		meth,
		opts,
	)
	runtime.KeepAlive(initSegment)
	runtime.KeepAlive(segments)
	if result == nil {
		return nil, errors.New("verifier returned no result")
	}
	defer C.encypher_c2pa_free_string(result)

	var envelope streamResponseEnvelope
	if err := json.Unmarshal([]byte(C.GoString(result)), &envelope); err != nil {
		return nil, fmt.Errorf("decode verifier response: %w", err)
	}
	if !envelope.OK {
		if envelope.Error != nil {
			return nil, envelope.Error
		}
		return nil, errors.New("verification failed without a structured error")
	}
	if envelope.Report == nil {
		return nil, errors.New("verification succeeded without a report")
	}
	return envelope.Report, nil
}

// VerifyErtmp verifies caller-parsed Enhanced RTMP events in exact wire order.
// inputJSON contains bilateral capsEx, object_encoding and the ordered events
// array. Aggregate timestamps must already be normalized and each Multitrack
// event must contain only the selected track packet. Nil options select 2.5.
func VerifyErtmp(inputJSON json.RawMessage, options *Options) (*ErtmpReport, error) {
	if len(inputJSON) == 0 {
		return nil, errors.New("E-RTMP input JSON is required")
	}
	if options == nil {
		options = &Options{SpecVersion: "2.5"}
	}
	optionsJSON, err := marshalOptions(options)
	if err != nil {
		return nil, err
	}
	input := C.CString(string(inputJSON))
	defer C.free(unsafe.Pointer(input))
	opts := C.CString(string(optionsJSON))
	defer C.free(unsafe.Pointer(opts))

	result := C.encypher_c2pa_verify_ertmp(input, opts)
	runtime.KeepAlive(inputJSON)
	if result == nil {
		return nil, errors.New("verifier returned no result")
	}
	defer C.encypher_c2pa_free_string(result)

	var envelope ertmpResponseEnvelope
	if err := json.Unmarshal([]byte(C.GoString(result)), &envelope); err != nil {
		return nil, fmt.Errorf("decode E-RTMP verifier response: %w", err)
	}
	if !envelope.OK {
		if envelope.Error != nil {
			return nil, envelope.Error
		}
		return nil, errors.New("E-RTMP verification failed without a structured error")
	}
	if envelope.Report == nil {
		return nil, errors.New("E-RTMP verification succeeded without a report")
	}
	return envelope.Report, nil
}

// ResolveSoftBinding queries an allowlisted soft-binding service and verifies
// each recovered manifest store against asset. Set options.Online to true (or
// ENCYPHER_C2PA_ONLINE=on) to authorize access. The service's advertised C2PA
// version never changes options.SpecVersion.
func ResolveSoftBinding(asset []byte, mimeType string, serviceRoot string, query SoftBindingQuery, options *Options, resolverOptions SoftBindingResolverOptions) (*SoftBindingResolution, error) {
	if mimeType == "" {
		return nil, errors.New("mime type is required")
	}
	if serviceRoot == "" {
		return nil, errors.New("soft-binding service root is required")
	}
	if len(resolverOptions.AllowedOrigins) == 0 {
		return nil, errors.New("at least one exact allowed origin is required")
	}
	queryJSON, err := json.Marshal(query)
	if err != nil {
		return nil, fmt.Errorf("encode soft-binding query: %w", err)
	}
	optionsJSON, err := marshalOptions(options)
	if err != nil {
		return nil, err
	}
	resolverJSON, err := json.Marshal(resolverOptions)
	if err != nil {
		return nil, fmt.Errorf("encode soft-binding resolver options: %w", err)
	}
	var assetPtr *C.uint8_t
	if len(asset) > 0 {
		assetPtr = (*C.uint8_t)(unsafe.Pointer(&asset[0]))
	}
	mime := C.CString(mimeType)
	defer C.free(unsafe.Pointer(mime))
	root := C.CString(serviceRoot)
	defer C.free(unsafe.Pointer(root))
	queryArg := C.CString(string(queryJSON))
	defer C.free(unsafe.Pointer(queryArg))
	optionsArg := C.CString(string(optionsJSON))
	defer C.free(unsafe.Pointer(optionsArg))
	resolverArg := C.CString(string(resolverJSON))
	defer C.free(unsafe.Pointer(resolverArg))

	result := C.encypher_c2pa_resolve_soft_binding(
		assetPtr,
		C.size_t(len(asset)),
		mime,
		root,
		queryArg,
		optionsArg,
		resolverArg,
	)
	runtime.KeepAlive(asset)
	if result == nil {
		return nil, errors.New("soft-binding resolver returned no result")
	}
	defer C.encypher_c2pa_free_string(result)

	var envelope softBindingResponseEnvelope
	if err := json.Unmarshal([]byte(C.GoString(result)), &envelope); err != nil {
		return nil, fmt.Errorf("decode soft-binding resolution response: %w", err)
	}
	if !envelope.OK {
		if envelope.Error != nil {
			return nil, envelope.Error
		}
		return nil, errors.New("soft-binding resolution failed without a structured error")
	}
	if envelope.Resolution == nil {
		return nil, errors.New("soft-binding resolution succeeded without evidence")
	}
	return envelope.Resolution, nil
}

// RequestSoftBindingReceiptVerification submits receipt to a repository. Its
// result remains server-reported operational evidence.
func RequestSoftBindingReceiptVerification(serviceRoot string, manifestID string, receipt json.RawMessage, options *Options, resolverOptions SoftBindingResolverOptions) (*SoftBindingReceiptEvidence, error) {
	if serviceRoot == "" {
		return nil, errors.New("soft-binding service root is required")
	}
	if manifestID == "" {
		return nil, errors.New("soft-binding manifest id is required")
	}
	if len(receipt) == 0 {
		return nil, errors.New("soft-binding receipt is required")
	}
	if len(resolverOptions.AllowedOrigins) == 0 {
		return nil, errors.New("at least one exact allowed origin is required")
	}
	optionsJSON, err := marshalOptions(options)
	if err != nil {
		return nil, err
	}
	resolverJSON, err := json.Marshal(resolverOptions)
	if err != nil {
		return nil, fmt.Errorf("encode soft-binding resolver options: %w", err)
	}
	root := C.CString(serviceRoot)
	defer C.free(unsafe.Pointer(root))
	id := C.CString(manifestID)
	defer C.free(unsafe.Pointer(id))
	receiptArg := C.CString(string(receipt))
	defer C.free(unsafe.Pointer(receiptArg))
	optionsArg := C.CString(string(optionsJSON))
	defer C.free(unsafe.Pointer(optionsArg))
	resolverArg := C.CString(string(resolverJSON))
	defer C.free(unsafe.Pointer(resolverArg))
	result := C.encypher_c2pa_request_soft_binding_receipt_verification(
		root,
		id,
		receiptArg,
		optionsArg,
		resolverArg,
	)
	if result == nil {
		return nil, errors.New("soft-binding receipt verifier returned no result")
	}
	defer C.encypher_c2pa_free_string(result)
	var envelope softBindingReceiptResponseEnvelope
	if err := json.Unmarshal([]byte(C.GoString(result)), &envelope); err != nil {
		return nil, fmt.Errorf("decode soft-binding receipt response: %w", err)
	}
	if !envelope.OK {
		if envelope.Error != nil {
			return nil, envelope.Error
		}
		return nil, errors.New("soft-binding receipt verification failed without a structured error")
	}
	if envelope.Evidence == nil {
		return nil, errors.New("soft-binding receipt verification succeeded without evidence")
	}
	return envelope.Evidence, nil
}

func validateOptions(options *Options) error {
	optionsJSON, err := marshalOptions(options)
	if err != nil {
		return err
	}
	opts := C.CString(string(optionsJSON))
	defer C.free(unsafe.Pointer(opts))

	result := C.encypher_c2pa_validate_options(opts)
	if result == nil {
		return errors.New("verifier returned no option validation result")
	}
	defer C.encypher_c2pa_free_string(result)

	var envelope responseEnvelope
	if err := json.Unmarshal([]byte(C.GoString(result)), &envelope); err != nil {
		return fmt.Errorf("decode option validation response: %w", err)
	}
	if !envelope.OK {
		if envelope.Error != nil {
			return envelope.Error
		}
		return errors.New("option validation failed without a structured error")
	}
	return nil
}

// marshalOptions encodes caller options, stamping the Go SDK name on telemetry.
func marshalOptions(options *Options) ([]byte, error) {
	if options == nil {
		return []byte("{}"), nil
	}
	normalized := *options
	if normalized.Telemetry != nil {
		telemetry := *normalized.Telemetry
		telemetry.SDKName = "go"
		normalized.Telemetry = &telemetry
	}
	encoded, err := json.Marshal(&normalized)
	if err != nil {
		return nil, fmt.Errorf("encode options: %w", err)
	}
	return encoded, nil
}

// segmentArrays builds the parallel pointer/length arrays the C ABI expects,
// plus the release function that frees them.
//
// The arrays live in C memory, not Go memory, because cgo refuses a Go pointer
// to memory that itself holds Go pointers - a Go `[]*C.uint8_t` is exactly
// that, and passing one panics with "argument of cgo function has Go pointer to
// unpinned Go pointer". Each segment's backing array is pinned for the duration
// of the call, which is what makes storing its address in C memory legal and
// keeps the collector from moving the bytes the verifier is reading.
func segmentArrays(segments [][]byte) (**C.uint8_t, *C.size_t, func()) {
	if len(segments) == 0 {
		return nil, nil, func() {}
	}
	pointerBytes := C.size_t(len(segments)) * C.size_t(unsafe.Sizeof((*C.uint8_t)(nil)))
	lengthBytes := C.size_t(len(segments)) * C.size_t(unsafe.Sizeof(C.size_t(0)))
	pointersRaw := C.malloc(pointerBytes)
	lengthsRaw := C.malloc(lengthBytes)
	pointers := unsafe.Slice((**C.uint8_t)(pointersRaw), len(segments))
	lengths := unsafe.Slice((*C.size_t)(lengthsRaw), len(segments))

	var pinner runtime.Pinner
	for index, segment := range segments {
		if len(segment) > 0 {
			pinner.Pin(&segment[0])
			pointers[index] = (*C.uint8_t)(unsafe.Pointer(&segment[0]))
		} else {
			pointers[index] = nil
		}
		lengths[index] = C.size_t(len(segment))
	}
	return (**C.uint8_t)(pointersRaw), (*C.size_t)(lengthsRaw), func() {
		pinner.Unpin()
		C.free(pointersRaw)
		C.free(lengthsRaw)
	}
}

// ConfigureTelemetry saves failure telemetry consent for subsequent native SDK calls.
func ConfigureTelemetry(enabled bool) error {
	result := C.encypher_c2pa_set_telemetry_enabled(C.bool(enabled))
	if result == nil {
		return errors.New("verifier returned no telemetry preference result")
	}
	defer C.encypher_c2pa_free_string(result)
	var envelope telemetryPreferenceEnvelope
	if err := json.Unmarshal([]byte(C.GoString(result)), &envelope); err != nil {
		return fmt.Errorf("decode telemetry preference response: %w", err)
	}
	if !envelope.OK {
		if envelope.Error != nil {
			return envelope.Error
		}
		return errors.New("telemetry preference update failed without a structured error")
	}
	return nil
}

// TelemetryEnabled returns the saved preference. Nil means the user has not answered.
func TelemetryEnabled() (*bool, error) {
	result := C.encypher_c2pa_telemetry_preference()
	if result == nil {
		return nil, errors.New("verifier returned no telemetry preference result")
	}
	defer C.encypher_c2pa_free_string(result)
	var envelope telemetryPreferenceEnvelope
	if err := json.Unmarshal([]byte(C.GoString(result)), &envelope); err != nil {
		return nil, fmt.Errorf("decode telemetry preference response: %w", err)
	}
	if !envelope.OK {
		if envelope.Error != nil {
			return nil, envelope.Error
		}
		return nil, errors.New("telemetry preference lookup failed without a structured error")
	}
	return envelope.Enabled, nil
}

// VerifyFile reads and verifies a regular local asset up to 128 MiB.
func VerifyFile(path, mimeType string, options *Options) (*Report, error) {
	if err := validateOptions(options); err != nil {
		return nil, err
	}
	asset, err := readPathAsset(path, maxPathAssetBytes)
	if err != nil {
		return nil, fmt.Errorf("read asset: %w", err)
	}
	return Verify(asset, mimeType, options)
}

func readPathAsset(path string, limit int64) ([]byte, error) {
	file, err := openAsset(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	info, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("asset path is not a regular file: %s", path)
	}
	if info.Size() > limit {
		return nil, fmt.Errorf("asset exceeds the 128 MiB path limit: %s", path)
	}

	expected := info.Size()
	asset := make([]byte, expected+1)
	read, err := io.ReadFull(file, asset[:expected])
	if err == io.EOF || err == io.ErrUnexpectedEOF {
		return asset[:read], nil
	}
	if err != nil {
		return nil, err
	}
	read, err = file.Read(asset[expected : expected+1])
	if err != nil && err != io.EOF {
		return nil, err
	}
	if read != 0 {
		return nil, fmt.Errorf("asset grew while being read: %s", path)
	}
	return asset[:expected], nil
}
