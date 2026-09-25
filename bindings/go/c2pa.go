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
	C2PAProfile         = "c2pa-2.4"
)

const maxPathAssetBytes int64 = 128 * 1024 * 1024

type TelemetryOptions struct {
	Enabled  *bool  `json:"enabled,omitempty"`
	Endpoint string `json:"endpoint,omitempty"`
	SDKName  string `json:"sdk_name,omitempty"`
}

// Options mirrors the SDK VerifyOptions JSON. TrustAnchorNotBefore and
// TrustAnchorNotAfter are RFC 3339 instants bounding when the caller-supplied
// anchors are trusted; the bundled snapshots are unaffected.
type Options struct {
	TrustPEM              string                     `json:"trust_pem,omitempty"`
	TSATrustPEM           string                     `json:"tsa_trust_pem,omitempty"`
	AllowedCertsPEM       string                     `json:"allowed_list_pem,omitempty"`
	CAWGTrustPEM          string                     `json:"cawg_trust_pem,omitempty"`
	CAWGAllowedCertsPEM   string                     `json:"cawg_allowed_certs_pem,omitempty"`
	TrustAnchorNotBefore  string                     `json:"trust_anchor_not_before,omitempty"`
	TrustAnchorNotAfter   string                     `json:"trust_anchor_not_after,omitempty"`
	NoDefaultTrust        bool                       `json:"no_default_trust,omitempty"`
	CAWGDIDDocuments      map[string]json.RawMessage `json:"cawg_did_documents,omitempty"`
	CAWGICATrustedIssuers []string                   `json:"cawg_ica_trusted_issuers,omitempty"`
	CAWGICATrustAnchors   []string                   `json:"cawg_ica_trust_anchors,omitempty"`
	CAWGICAStatusLists    map[string]string          `json:"cawg_ica_status_lists,omitempty"`
	// CAWGStrictEncoding refuses the CAWG field-order signer payload that
	// c2pa-rs writes; StrictConformance refuses it either way.
	CAWGStrictEncoding bool `json:"cawg_strict_encoding,omitempty"`
	// ExpectedSeekPositions are zero-based indexes into supplied fragments or
	// stream segments where the player expects a discontinuity. Single-asset
	// verification ignores them.
	ExpectedSeekPositions []int  `json:"expected_seek_positions,omitempty"`
	StrictConformance     bool   `json:"strict_conformance,omitempty"`
	ValidationTime        string `json:"validation_time,omitempty"`
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
// Mark intentional discontinuities in Options.ExpectedSeekPositions.
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
