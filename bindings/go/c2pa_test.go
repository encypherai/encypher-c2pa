package c2pa

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
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

func TestPathReaderAcceptsExactBoundaryWithSmallLimit(t *testing.T) {
	path := filepath.Join(t.TempDir(), "exact.jpg")
	if err := os.WriteFile(path, []byte("1234"), 0o600); err != nil {
		t.Fatal(err)
	}
	asset, err := readPathAsset(path, 4)
	if err != nil {
		t.Fatal(err)
	}
	if string(asset) != "1234" {
		t.Fatalf("unexpected asset: %q", asset)
	}
}

func TestVerifyFileRejectsSparseAssetOverPathLimit(t *testing.T) {
	path := filepath.Join(t.TempDir(), "oversized.jpg")
	file, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := file.Truncate(maxPathAssetBytes + 1); err != nil {
		file.Close()
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}

	_, err = VerifyFile(path, "image/jpeg", nil)
	if err == nil || !strings.Contains(err.Error(), "128 MiB path limit") {
		t.Fatalf("expected clear path-limit error, got %v", err)
	}
}

func TestVerifyFileRejectsNonRegularSourceWithoutReadingIt(t *testing.T) {
	if runtime.GOOS != "linux" && runtime.GOOS != "darwin" {
		t.Skip("requires a POSIX character device")
	}
	_, err := VerifyFile("/dev/zero", "image/jpeg", nil)
	if err == nil || !strings.Contains(err.Error(), "not a regular file") {
		t.Fatalf("expected clear non-regular-file error, got %v", err)
	}
}

func TestVerifyFileRejectsFIFOWithoutBlocking(t *testing.T) {
	if runtime.GOOS != "linux" && runtime.GOOS != "darwin" {
		t.Skip("requires POSIX FIFO support")
	}
	path := filepath.Join(t.TempDir(), "asset.fifo")
	if err := exec.Command("mkfifo", path).Run(); err != nil {
		t.Fatalf("create FIFO: %v", err)
	}

	result := make(chan error, 1)
	go func() {
		_, err := VerifyFile(path, "image/jpeg", nil)
		result <- err
	}()

	select {
	case err := <-result:
		if err == nil || !strings.Contains(err.Error(), "not a regular file") {
			t.Fatalf("expected clear non-regular-file error, got %v", err)
		}
	case <-time.After(time.Second):
		// Release a blocking reader before failing so the test leaves no stuck goroutine.
		writer, err := os.OpenFile(path, os.O_WRONLY, 0)
		if err == nil {
			_ = writer.Close()
		}
		<-result
		t.Fatal("VerifyFile blocked while opening a FIFO")
	}
}
