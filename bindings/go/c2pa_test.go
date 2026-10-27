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

func liveVideoDir(name string) string {
	return filepath.Join("..", "..", "crates", "encypher-c2pa", "tests", "fixtures", "live-video", name)
}

func liveVideoStream(t *testing.T, name string, tamper bool) ([]byte, [][]byte) {
	t.Helper()
	base := liveVideoDir(name)
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

// fixtureClock is the trusted instant a fixture set's segments.json recorded
// as validation_time when the set was signed and verified. It follows the
// session key's creation and falls inside its 24-hour window; two days either
// side is outside the window and inside every fixture certificate. Tests pin
// to it rather than the wall clock, so a regenerated set carries its own
// anchor.
type fixtureClock time.Time

func fixtureValidationTime(t *testing.T, name string) fixtureClock {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(liveVideoDir(name), "segments.json"))
	if err != nil {
		t.Fatal(err)
	}
	var index struct {
		ValidationTime string `json:"validation_time"`
	}
	if err := json.Unmarshal(raw, &index); err != nil {
		t.Fatal(err)
	}
	at, err := time.Parse(time.RFC3339Nano, index.ValidationTime)
	if err != nil {
		t.Fatalf("%s/segments.json validation_time: %v", name, err)
	}
	return fixtureClock(at)
}

func (c fixtureClock) at(offset time.Duration) string {
	return time.Time(c).Add(offset).Format(time.RFC3339Nano)
}

func (c fixtureClock) inWindow() string {
	return c.at(0)
}

func (c fixtureClock) afterExpiry() string {
	return c.at(48 * time.Hour)
}

const sessionKeyStream = "fmp4-verifiable-segment-info"

func TestVerifyStreamAcceptsCleanSessionKeyStreamAndRejectsTampering(t *testing.T) {
	pinned := &Options{ValidationTime: fixtureValidationTime(t, sessionKeyStream).inWindow()}
	init, segments := liveVideoStream(t, sessionKeyStream, false)
	report, err := VerifyStream(init, segments, "video/mp4", EncapsulationFMP4, MethodVerifiableSegmentInfo, pinned)
	if err != nil {
		t.Fatal(err)
	}
	if report.Integrity != "valid" {
		t.Fatalf("clean session-key stream must verify: %+v", report)
	}

	init, segments = liveVideoStream(t, sessionKeyStream, true)
	report, err = VerifyStream(init, segments, "video/mp4", EncapsulationFMP4, MethodVerifiableSegmentInfo, pinned)
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
	pinned := &Options{ValidationTime: fixtureValidationTime(t, "cmaf-per-segment").inWindow()}
	init, segments := liveVideoStream(t, "cmaf-per-segment", false)
	report, err := VerifyStream(init, segments, "video/mp4", EncapsulationCMAF, MethodPerSegment, pinned)
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
	report, err = VerifyStream(init, segments, "video/mp4", EncapsulationCMAF, MethodPerSegment, pinned)
	if err != nil {
		t.Fatal(err)
	}
	if report.Integrity != "invalid" || report.ChainValid == nil || *report.ChainValid {
		t.Fatalf("tampered per-segment stream must break the chain: %+v", report)
	}
}

func TestVerifyStreamRefusesAStreamDeclaredAsTheWrongEncapsulation(t *testing.T) {
	pinned := &Options{ValidationTime: fixtureValidationTime(t, sessionKeyStream).inWindow()}
	init, segments := liveVideoStream(t, sessionKeyStream, false)
	_, err := VerifyStream(init, segments, "video/mp4", EncapsulationCMAF, MethodVerifiableSegmentInfo, pinned)
	if err == nil || !strings.Contains(err.Error(), "CMAF") {
		t.Fatalf("expected the brand gate to refuse fMP4 bytes declared as CMAF, got %v", err)
	}
}

func segmentFailureURLs(report *StreamReport) map[string]bool {
	urls := map[string]bool{}
	for _, status := range report.Stream.ValidationResults.Failure {
		if status.Code == "livevideo.segment.invalid" {
			urls[status.URL] = true
		}
	}
	return urls
}

func TestVerifyStreamChecksEachSessionKeySegmentAtItsPresentationTime(t *testing.T) {
	clock := fixtureValidationTime(t, sessionKeyStream)
	init, segments := liveVideoStream(t, sessionKeyStream, false)
	verify := func(options *Options) *StreamReport {
		t.Helper()
		report, err := VerifyStream(init, segments, "video/mp4", EncapsulationFMP4, MethodVerifiableSegmentInfo, options)
		if err != nil {
			t.Fatal(err)
		}
		return report
	}

	// Without per-segment times, an archive check after the key expired
	// assesses every segment at ValidationTime and fails.
	expired := verify(&Options{ValidationTime: clock.afterExpiry()})
	if expired.Integrity != "invalid" || len(segmentFailureURLs(expired)) == 0 {
		t.Fatalf("segments assessed after key expiry must fail: %+v", expired)
	}

	// Distinct trusted presentation times inside the window verify the same
	// archive, and the common ValidationTime still governs the certificates.
	archived := verify(&Options{
		ValidationTime:          clock.afterExpiry(),
		StreamPresentationTimes: []string{clock.at(0), clock.at(time.Second), clock.at(2 * time.Second)},
	})
	if archived.Integrity != "valid" {
		t.Fatalf("segments presented inside the key window must verify: %+v", archived)
	}

	// Each time applies to its own segment only, on either side of the window.
	for _, outside := range []string{clock.afterExpiry(), clock.at(-48 * time.Hour)} {
		mixed := verify(&Options{
			ValidationTime:          clock.inWindow(),
			StreamPresentationTimes: []string{clock.inWindow(), clock.inWindow(), outside},
		})
		urls := segmentFailureURLs(mixed)
		if mixed.Integrity != "invalid" || !urls["self#segment=3"] || urls["self#segment=1"] || urls["self#segment=2"] {
			t.Fatalf("%s: only the segment presented outside the window may fail: %+v", outside, mixed.Stream.ValidationResults.Failure)
		}
	}
}

func TestVerifyStreamRefusesMalformedOrMiscountedPresentationTimes(t *testing.T) {
	in := fixtureValidationTime(t, sessionKeyStream).inWindow()
	init, segments := liveVideoStream(t, sessionKeyStream, false)
	for name, times := range map[string][]string{
		"too few":   {in, in},
		"too many":  {in, in, in, in},
		"empty":     {},
		"malformed": {in, "yesterday", in},
	} {
		_, err := VerifyStream(init, segments, "video/mp4", EncapsulationFMP4, MethodVerifiableSegmentInfo, &Options{
			ValidationTime:          in,
			StreamPresentationTimes: times,
		})
		if err == nil || !strings.Contains(err.Error(), "invalid_validation_time") || !strings.Contains(err.Error(), "stream_presentation_times") {
			t.Fatalf("%s: expected an invalid_validation_time refusal naming stream_presentation_times, got %v", name, err)
		}
	}

	perSegmentInit, perSegment := liveVideoStream(t, "cmaf-per-segment", false)
	if _, err := VerifyStream(perSegmentInit, perSegment, "video/mp4", EncapsulationCMAF, MethodPerSegment, &Options{
		ValidationTime:          in,
		StreamPresentationTimes: []string{in, in, in},
	}); err == nil {
		t.Fatal("a per-segment stream must refuse per-segment presentation times, not ignore them")
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
		CAWGTrustPEM:        "anchor",
		CAWGAllowedCertsPEM: "leaf",
		CAWGTrustConfigurations: []CAWGTrustConfiguration{{
			Profile:         CAWGTrustProfileSMIMEInterim,
			CertificatesPEM: "roots",
			NotAfter:        "2027-03-31T23:59:59Z",
		}},
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
		"cawg_trust_configurations",
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
	var configurations []map[string]string
	if err := json.Unmarshal(options["cawg_trust_configurations"], &configurations); err != nil {
		t.Fatal(err)
	}
	if len(configurations) != 1 || configurations[0]["profile"] != "smime_interim" ||
		configurations[0]["certificates_pem"] != "roots" || configurations[0]["not_after"] != "2027-03-31T23:59:59Z" {
		t.Fatalf("unexpected CAWG trust configurations: %s", options["cawg_trust_configurations"])
	}
	if _, ok := configurations[0]["not_before"]; ok {
		t.Fatalf("unset not_before must be omitted: %s", options["cawg_trust_configurations"])
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

func TestVerifyFileResolvesOptionsBeforeOpeningTheAsset(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "missing.jpg")
	_, err := VerifyFile(missing, "image/jpeg", &Options{
		CAWGTrustConfigurations: []CAWGTrustConfiguration{{
			Profile:         CAWGTrustProfileBase,
			CertificatesPEM: "",
		}},
	})
	if err == nil ||
		!strings.Contains(err.Error(), "invalid_trust_material") ||
		!strings.Contains(err.Error(), "cawg_trust_configurations[0].certificates_pem") {
		t.Fatalf("expected trust configuration error before asset I/O, got %v", err)
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
