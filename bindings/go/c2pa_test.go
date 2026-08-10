package c2pa

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestSignedJPEGReportsIntegrityWithoutTrust(t *testing.T) {
	asset, err := os.ReadFile(filepath.Join("..", "..", "tests", "fixtures", "signed_test.jpg"))
	if err != nil {
		t.Fatal(err)
	}
	report, err := Verify(asset, "image/jpeg", nil)
	if err != nil {
		t.Fatal(err)
	}
	if !report.Present || report.Integrity != "valid" || report.HardBinding != "match" {
		t.Fatalf("unexpected verification report: %+v", report)
	}
	if report.Trust.Status != "not_evaluated" {
		t.Fatalf("integrity must not imply trust: %+v", report.Trust)
	}
}

func TestCAWGOptionsAndStatusDetailsRoundTrip(t *testing.T) {
	optionsJSON, err := json.Marshal(Options{
		CAWGTrustPEM:        "anchor",
		CAWGAllowedCertsPEM: "leaf",
		CAWGDIDDocuments:    map[string]json.RawMessage{"did:web:example.test": json.RawMessage(`{"id":"did:web:example.test"}`)},
		CAWGStrictEncoding:  true,
	})
	if err != nil {
		t.Fatal(err)
	}
	var options map[string]json.RawMessage
	if err := json.Unmarshal(optionsJSON, &options); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{
		"cawg_trust_pem",
		"cawg_allowed_certs_pem",
		"cawg_did_documents",
		"cawg_strict_encoding",
	} {
		if _, ok := options[key]; !ok {
			t.Fatalf("missing CAWG option %q in %s", key, optionsJSON)
		}
	}

	var status Status
	if err := json.Unmarshal([]byte(`{"code":"cawg.identity.trusted","url":"self#jumbf=c2pa.assertions/cawg.identity","explanation":"trusted","details":{"trust_source":"allowed_list"}}`), &status); err != nil {
		t.Fatal(err)
	}
	var details map[string]string
	if err := json.Unmarshal(status.Details, &details); err != nil {
		t.Fatal(err)
	}
	if details["trust_source"] != "allowed_list" {
		t.Fatalf("unexpected status details: %s", status.Details)
	}
}

func TestTelemetryPreferenceRoundTrips(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	enabled, err := TelemetryEnabled()
	if err != nil {
		t.Fatal(err)
	}
	if enabled != nil {
		t.Fatalf("new config should have no preference: %v", *enabled)
	}
	if err := ConfigureTelemetry(true); err != nil {
		t.Fatal(err)
	}
	enabled, err = TelemetryEnabled()
	if err != nil {
		t.Fatal(err)
	}
	if enabled == nil || !*enabled {
		t.Fatalf("expected enabled preference, got %v", enabled)
	}
	if err := ConfigureTelemetry(false); err != nil {
		t.Fatal(err)
	}
	enabled, err = TelemetryEnabled()
	if err != nil {
		t.Fatal(err)
	}
	if enabled == nil || *enabled {
		t.Fatalf("expected disabled preference, got %v", enabled)
	}
}
