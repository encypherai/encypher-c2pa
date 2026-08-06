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
	"os"
	"unsafe"
)

const (
	ReportSchemaVersion = "1.0"
	C2PAProfile         = "c2pa-2.4"
)

type TelemetryOptions struct {
	Enabled  *bool  `json:"enabled,omitempty"`
	Endpoint string `json:"endpoint,omitempty"`
	SDKName  string `json:"sdk_name,omitempty"`
}

type Options struct {
	TrustPEM        string            `json:"trust_pem,omitempty"`
	TSATrustPEM     string            `json:"tsa_trust_pem,omitempty"`
	AllowedCertsPEM string            `json:"allowed_list_pem,omitempty"`
	ValidationTime  string            `json:"validation_time,omitempty"`
	Telemetry       *TelemetryOptions `json:"telemetry,omitempty"`
}

type Status struct {
	Code        string `json:"code"`
	URL         string `json:"url"`
	Explanation string `json:"explanation"`
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
	optionsJSON := []byte("{}")
	if options != nil {
		normalized := *options
		if normalized.Telemetry != nil {
			telemetry := *normalized.Telemetry
			telemetry.SDKName = "go"
			normalized.Telemetry = &telemetry
		}
		var err error
		optionsJSON, err = json.Marshal(&normalized)
		if err != nil {
			return nil, fmt.Errorf("encode options: %w", err)
		}
	}

	var assetPtr unsafe.Pointer
	if len(asset) > 0 {
		assetPtr = C.CBytes(asset)
		defer C.free(assetPtr)
	}
	mime := C.CString(mimeType)
	defer C.free(unsafe.Pointer(mime))
	opts := C.CString(string(optionsJSON))
	defer C.free(unsafe.Pointer(opts))

	result := C.encypher_c2pa_verify((*C.uint8_t)(assetPtr), C.size_t(len(asset)), mime, opts)
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

// VerifyFile reads and verifies a local asset.
func VerifyFile(path, mimeType string, options *Options) (*Report, error) {
	asset, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read asset: %w", err)
	}
	return Verify(asset, mimeType, options)
}
