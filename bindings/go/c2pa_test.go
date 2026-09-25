// Copyright 2026 Encypher Corporation
// SPDX-License-Identifier: Apache-2.0

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

func TestSignedJPEGCanDisableBundledTrust(t *testing.T) {
	asset, err := os.ReadFile(filepath.Join("..", "..", "tests", "fixtures", "signed_test.jpg"))
	if err != nil {
		t.Fatal(err)
	}
	report, err := Verify(asset, "image/jpeg", &Options{NoDefaultTrust: true})
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

func TestVerifyWithManifestStoreBindsTheSidecarToItsAsset(t *testing.T) {
	fixtures := filepath.Join("..", "..", "tests", "fixtures")
	asset, err := os.ReadFile(filepath.Join(fixtures, "signed_test.jpg"))
	if err != nil {
		t.Fatal(err)
	}
	store, err := os.ReadFile(filepath.Join(fixtures, "signed_test.c2pa"))
	if err != nil {
		t.Fatal(err)
	}

	report, err := VerifyWithManifestStore(asset, store, "image/jpeg", &Options{NoDefaultTrust: true})
	if err != nil {
		t.Fatal(err)
	}
	if report.Integrity != "valid" || report.HardBinding != "match" {
		t.Fatalf("sidecar store must verify against its asset: %+v", report)
	}

	tampered := append([]byte(nil), asset...)
	tampered[len(tampered)-32] ^= 0x01
	altered, err := VerifyWithManifestStore(tampered, store, "image/jpeg", &Options{NoDefaultTrust: true})
	if err != nil {
		t.Fatal(err)
	}
	if altered.Integrity == "valid" || altered.HardBinding == "match" {
		t.Fatalf("sidecar store must not verify an altered asset: %+v", altered)
	}

	if _, err := VerifyWithManifestStore(asset, nil, "image/jpeg", nil); err == nil {
		t.Fatal("an empty manifest store must be refused")
	}
}

func liveVideoStream(t *testing.T, name string, tamper bool) ([]byte, [][]byte) {
	t.Helper()
	base := filepath.Join("..", "..", "crates", "encypher-c2pa", "tests", "fixtures", "live-video", name)
	init, err := os.ReadFile(filepath.Join(base, "init.mp4"))
	if err != nil {
		t.Fatal(err)
	}
	var segments [][]byte
	for _, file := range []string{"seg-0.m4s", "seg-1.m4s", "seg-2.m4s"} {
		segment, err := os.ReadFile(filepath.Join(base, file))
		if err != nil {
			t.Fatal(err)
		}
		if tamper && file == "seg-1.m4s" {
			segment[len(segment)-1] ^= 0x01
		}
		segments = append(segments, segment)
	}
	return init, segments
}

func TestVerifyStreamAcceptsCleanSessionKeyStreamAndRejectsTampering(t *testing.T) {
	init, segments := liveVideoStream(t, "fmp4-verifiable-segment-info", false)
	report, err := VerifyStream(init, segments, "video/mp4", EncapsulationFMP4, MethodVerifiableSegmentInfo, nil)
	if err != nil {
		t.Fatal(err)
	}
	if report.Integrity != "valid" {
		t.Fatalf("clean session-key stream must verify: %+v", report)
	}

	init, segments = liveVideoStream(t, "fmp4-verifiable-segment-info", true)
	report, err = VerifyStream(init, segments, "video/mp4", EncapsulationFMP4, MethodVerifiableSegmentInfo, nil)
	if err != nil {
		t.Fatal(err)
	}
	if report.Integrity != "invalid" {
		t.Fatalf("tampered segment must not verify: %+v", report)
	}
	found := false
	for _, status := range report.Stream.ValidationResults.Failure {
		if status.Code == "livevideo.segment.invalid" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected livevideo.segment.invalid, got %+v", report.Stream.ValidationResults.Failure)
	}
}

func TestVerifyStreamRecomputesThePerSegmentChain(t *testing.T) {
	init, segments := liveVideoStream(t, "cmaf-per-segment", false)
	report, err := VerifyStream(init, segments, "video/mp4", EncapsulationCMAF, MethodPerSegment, nil)
	if err != nil {
		t.Fatal(err)
	}
	if report.ChainValid == nil || !*report.ChainValid || report.Integrity != "valid" {
		t.Fatalf("clean per-segment stream must verify: %+v", report)
	}
	if len(report.Segments) != 4 {
		t.Fatalf("expected the init segment plus three media segments, got %d", len(report.Segments))
	}

	init, segments = liveVideoStream(t, "cmaf-per-segment", true)
	report, err = VerifyStream(init, segments, "video/mp4", EncapsulationCMAF, MethodPerSegment, nil)
	if err != nil {
		t.Fatal(err)
	}
	if report.Integrity != "invalid" || report.ChainValid == nil || *report.ChainValid {
		t.Fatalf("tampered per-segment stream must break the chain: %+v", report)
	}
}

func TestVerifyStreamRefusesAStreamDeclaredAsTheWrongEncapsulation(t *testing.T) {
	init, segments := liveVideoStream(t, "fmp4-verifiable-segment-info", false)
	_, err := VerifyStream(init, segments, "video/mp4", EncapsulationCMAF, MethodVerifiableSegmentInfo, nil)
	if err == nil || !strings.Contains(err.Error(), "CMAF") {
		t.Fatalf("expected the brand gate to refuse fMP4 bytes declared as CMAF, got %v", err)
	}
}

func TestVerifyFragmentedFailsClosedOnSegmentsNoBindingCovers(t *testing.T) {
	// A session-key stream's segments are not Merkle-bound. Ignoring them and
	// reporting the init manifest's own match would be a success verdict over
	// unchecked bytes.
	init, segments := liveVideoStream(t, "fmp4-verifiable-segment-info", true)
	report, err := VerifyFragmented(init, segments, "video/mp4", nil)
	if err != nil {
		t.Fatal(err)
	}
	if report.Integrity != "invalid" || report.HardBinding == "match" {
		t.Fatalf("unbound segments must never verify: %+v", report)
	}
}

func TestCAWGOptionsAndStatusDetailsRoundTrip(t *testing.T) {
	optionsJSON, err := json.Marshal(Options{
		CAWGTrustPEM:          "anchor",
		CAWGAllowedCertsPEM:   "leaf",
		CAWGDIDDocuments:      map[string]json.RawMessage{"did:web:example.test": json.RawMessage(`{"id":"did:web:example.test"}`)},
		CAWGICATrustedIssuers: []string{"did:web:example.test"},
		CAWGICATrustAnchors:   []string{"did:web:root.test"},
		CAWGICAStatusLists:    map[string]string{"https://example.test/status": "AA=="},
		NoDefaultTrust:        true,
		CAWGStrictEncoding:    true,
		StrictConformance:     true,
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
		"cawg_ica_trusted_issuers",
		"cawg_ica_trust_anchors",
		"cawg_ica_status_lists",
		"no_default_trust",
		"cawg_strict_encoding",
		"strict_conformance",
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
