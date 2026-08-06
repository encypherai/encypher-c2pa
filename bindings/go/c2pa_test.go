package c2pa

import (
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
