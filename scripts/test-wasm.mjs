// Copyright 2026 Encypher Corporation
// SPDX-License-Identifier: Apache-2.0

import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { mkdtemp, readFile } from "node:fs/promises";
import { rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { resolve } from "node:path";
import { pathToFileURL } from "node:url";
import { promisify } from "node:util";

const execFileAsync = promisify(execFile);
const storage = new Map();
globalThis.localStorage = {
  getItem: (key) => storage.get(key) ?? null,
  setItem: (key, value) => storage.set(key, value),
};

const root = resolve(import.meta.dirname, "..");
const sourcePkg = resolve(root, "bindings/wasm/pkg");
const packedRoot = await mkdtemp(resolve(tmpdir(), "encypher-c2pa-wasm-"));
process.on("exit", () => rmSync(packedRoot, { recursive: true, force: true }));
const npmEnv = {
  ...process.env,
  npm_config_cache: process.env.npm_config_cache ?? resolve(root, "target/npm-cache"),
};
const { stdout } = await execFileAsync(
  "npm",
  ["pack", "--json", "--pack-destination", packedRoot],
  { cwd: sourcePkg, env: npmEnv },
);
const [{ filename }] = JSON.parse(stdout);
const installRoot = resolve(packedRoot, "install");
await execFileAsync(
  "npm",
  [
    "install",
    "--ignore-scripts",
    "--no-audit",
    "--no-fund",
    "--no-package-lock",
    "--prefix",
    installRoot,
    resolve(packedRoot, filename),
  ],
  { env: npmEnv },
);
const pkg = resolve(installRoot, "node_modules/@encypherai/c2pa");
const {
  default: init,
  configureTelemetry,
  telemetryEnabled,
  verify,
  verifyFragmented,
  verifyStream,
  verifyWithManifestStore,
  supportedMimeTypes,
} = await import(pathToFileURL(resolve(pkg, "encypher_c2pa_wasm.js")).href);
const wasm = await readFile(resolve(pkg, "encypher_c2pa_wasm_bg.wasm"));
await init({ module_or_path: wasm });
assert.equal(telemetryEnabled(), null);
let consentPrompts = 0;
globalThis.confirm = () => {
  consentPrompts += 1;
  return false;
};

const asset = await readFile(resolve(root, "tests/fixtures/signed_test.jpg"));
const report = verify(asset, "image/jpeg");
assert.equal(consentPrompts, 1);
assert.equal(telemetryEnabled(), false);
verify(asset, "image/jpeg");
assert.equal(consentPrompts, 1);
configureTelemetry(true);
assert.equal(telemetryEnabled(), true);
configureTelemetry(false);
assert.equal(report.schema_version, "1.0");
assert.equal(report.profile, "c2pa-2.4");
assert.equal(report.integrity, "valid");
assert.equal(report.signature, "valid");
assert.equal(report.hard_binding, "match");
assert.equal(report.trust.status, "not_valid_for_supplied_material");
assert.equal(report.trust.basis, "bundled_static_material");
assert.equal(
  Object.getPrototypeOf(report.manifest_report.manifests),
  Object.prototype,
);
assert.ok(Object.keys(report.manifest_report.manifests).length > 0);
assert.ok(report.manifest_report.active_manifest);
const customTrustOnly = verify(asset, "image/jpeg", { no_default_trust: true });
assert.equal(customTrustOnly.trust.status, "not_evaluated");

// An external (sidecar) manifest store verifies against its asset, and refuses
// an altered one. Nothing is fetched: the store is handed in by the caller.
const sidecar = await readFile(resolve(root, "tests/fixtures/signed_test.c2pa"));
const detachedOptions = { telemetry: { enabled: false } };
const detached = verifyWithManifestStore(asset, sidecar, "image/jpeg", detachedOptions);
assert.equal(detached.integrity, "valid");
assert.equal(detached.signature, "valid");
assert.equal(detached.hard_binding, "match");
const detachedTampered = new Uint8Array(asset);
detachedTampered[detachedTampered.length - 32] ^= 0x01;
const detachedFailure = verifyWithManifestStore(
  detachedTampered,
  sidecar,
  "image/jpeg",
  detachedOptions,
);
assert.notEqual(detachedFailure.integrity, "valid");
assert.notEqual(detachedFailure.hard_binding, "match");
assert.ok(supportedMimeTypes().includes("video/mp4"));
assert.ok(supportedMimeTypes().includes("text/tab-separated-values"));
assert.ok(supportedMimeTypes().includes("application/vnd.oasis.opendocument.graphics"));
const mp4 = await readFile(resolve(root, "tests/fixtures/signed_test.mp4"));
const fragmented = verifyFragmented(mp4, [], "video/mp4");
assert.equal(fragmented.integrity, "valid");
assert.equal(fragmented.hard_binding, "match");
assert.equal(
  Object.getPrototypeOf(fragmented.manifest_report.manifests),
  Object.prototype,
);
const timestampedAsset = await readFile(
  resolve(
    root,
    "tests/vectors/cawg/generated/identity-1.2/assets/x509-es256-smime-jpeg.jpg",
  ),
);
const historicalReport = verify(timestampedAsset, "image/jpeg", {
  validation_time: "2020-01-01T00:00:00Z",
  telemetry: { enabled: false },
});
assert.equal(historicalReport.trust.validation_time, "2020-01-01T00:00:00Z");
assert.ok(
  historicalReport.validation_results.informational.some(
    ({ code, explanation }) =>
      code === "timeStamp.malformed" &&
      explanation.includes("timestamp_time_in_future"),
  ),
);

const allStatuses = (value) =>
  ["success", "informational", "failure"].flatMap(
    (bucket) => value.validation_results[bucket] ?? [],
  );
const statusAt = (value, code, url) =>
  allStatuses(value).find((status) => status.code === code && status.url === url);
const assertNoIdentitySubject = (status) => {
  const details = status.details ?? {};
  assert.equal("subject_organization" in details, false);
  assert.equal("subject_common_name" in details, false);
  assert.equal("certificate_trusted" in details, false);
};

// The packed npm artifact must preserve trusted, unevaluated, and rejected
// X.509 subject evidence. Read exact assertion labels so two identities can
// never be paired through array position or a prefix-only match.
const subjectAsset = await readFile(
  resolve(root, "tests/vectors/cawg/generated/identity-1.2/assets/x509-es256-jpeg.jpg"),
);
const subjectClaimTrust = await readFile(
  resolve(root, "tests/vectors/cawg/generated/identity-1.2/certs/claim-es256.cert.pem"),
  "utf8",
);
const subjectIdentityTrust = await readFile(
  resolve(root, "tests/vectors/cawg/generated/identity-1.2/certs/es256.cert.pem"),
  "utf8",
);
const subjectOptions = {
  no_default_trust: true,
  trust_pem: subjectClaimTrust,
  cawg_trust_pem: subjectIdentityTrust,
  validation_time: "2026-08-06T00:00:00Z",
  telemetry: { enabled: false },
};
const trustedSubjectReport = verify(subjectAsset, "image/jpeg", subjectOptions);
const trustedSubject = statusAt(
  trustedSubjectReport,
  "cawg.identity.trusted",
  "cawg.identity",
);
assert.ok(trustedSubject);
assert.equal(trustedSubject.details.certificate_trusted, true);
assert.equal(trustedSubject.details.subject_organization, "Encypher Test Vectors");
assert.equal(
  trustedSubject.details.subject_common_name,
  "CAWG Identity 1.2 ES256 Test Actor",
);

const unevaluatedSubjectReport = verify(subjectAsset, "image/jpeg", {
  no_default_trust: true,
  trust_pem: subjectClaimTrust,
  validation_time: "2026-08-06T00:00:00Z",
  telemetry: { enabled: false },
});
const unevaluatedSubject = statusAt(
  unevaluatedSubjectReport,
  "cawg.identity.well-formed",
  "cawg.identity",
);
assert.ok(unevaluatedSubject);
assert.equal("certificate_trusted" in unevaluatedSubject.details, true);
assert.equal(unevaluatedSubject.details.certificate_trusted, false);
assert.equal(
  unevaluatedSubject.details.subject_organization,
  "Encypher Test Vectors",
);

const unrelatedIdentityTrust = await readFile(
  resolve(
    root,
    "tests/vectors/cawg/generated/identity-1.2/certs/es256-wrong-eku.cert.pem",
  ),
  "utf8",
);
const rejectedSubjectReport = verify(subjectAsset, "image/jpeg", {
  no_default_trust: true,
  trust_pem: subjectClaimTrust,
  cawg_trust_pem: unrelatedIdentityTrust,
  validation_time: "2026-08-06T00:00:00Z",
  telemetry: { enabled: false },
});
const rejectedSubject = statusAt(
  rejectedSubjectReport,
  "cawg.x509.credential.untrusted",
  "cawg.identity",
);
assert.ok(rejectedSubject);
assertNoIdentitySubject(rejectedSubject);

const icaAsset = await readFile(
  resolve(
    root,
    "tests/vectors/cawg/external/contentauth-c2pa-rs/d7f13829/assets/sdk__src__identity__tests__fixtures__claim_aggregation__ica_validation__success.jpg",
  ),
);
for (const status of allStatuses(
  verify(icaAsset, "image/jpeg", {
    no_default_trust: true,
    telemetry: { enabled: false },
  }),
).filter(({ code }) => code.startsWith("cawg.ica."))) {
  assertNoIdentitySubject(status);
}
assert.throws(
  () => verifyFragmented(asset, [new Uint8Array([1])], "image/jpeg"),
  /unsupported_mime/,
);

// Live-stream verification: the binding is read from the init manifest, and a
// mutated media segment must sink the stream rather than be ignored.
const streamDir = resolve(
  root,
  "crates/encypher-c2pa/tests/fixtures/live-video/fmp4-verifiable-segment-info",
);
const initSegment = await readFile(resolve(streamDir, "init.mp4"));
const mediaSegments = await Promise.all(
  ["seg-0.m4s", "seg-1.m4s", "seg-2.m4s"].map(async (file) =>
    new Uint8Array(await readFile(resolve(streamDir, file))),
  ),
);
const streamOptions = { telemetry: { enabled: false } };
const stream = verifyStream(
  initSegment,
  mediaSegments,
  "video/mp4",
  "fMP4",
  "verifiable-segment-info",
  streamOptions,
);
assert.equal(stream.schema_version, "1.0");
assert.equal(stream.integrity, "valid");
assert.equal(stream.encapsulation, "fMP4");
assert.equal(stream.method, "verifiable-segment-info");
assert.equal(stream.stream.hard_binding, "match");

const tamperedSegments = mediaSegments.map((segment) => new Uint8Array(segment));
tamperedSegments[1][tamperedSegments[1].length - 1] ^= 0x01;
const tamperedStream = verifyStream(
  initSegment,
  tamperedSegments,
  "video/mp4",
  "fMP4",
  "verifiable-segment-info",
  streamOptions,
);
assert.equal(tamperedStream.integrity, "invalid");
assert.ok(
  tamperedStream.stream.validation_results.failure.some(
    ({ code }) => code === "livevideo.segment.invalid",
  ),
);
assert.throws(
  () =>
    verifyStream(
      initSegment,
      mediaSegments,
      "video/mp4",
      "CMAF",
      "verifiable-segment-info",
      streamOptions,
    ),
  /CMAF/,
);
assert.throws(
  () =>
    verifyStream(initSegment, mediaSegments, "video/mp4", "mpeg-ts", "per-segment", streamOptions),
  /invalid_argument/,
);

let telemetryRequest;
const originalFetch = globalThis.fetch;
globalThis.fetch = async (url, options) => {
  telemetryRequest = { url, options };
  return new Response(null, { status: 202 });
};
const tampered = new Uint8Array(asset);
tampered[200] ^= 0x01;
try {
  verify(tampered, "image/jpeg", {
    telemetry: {
      enabled: true,
      endpoint: "https://telemetry.test/sdk-validation-failures",
    },
  });
} catch {
  // A malformed container can fail before producing an invalid report.
}
globalThis.fetch = originalFetch;
assert.equal(telemetryRequest.url, "https://telemetry.test/sdk-validation-failures");
assert.equal(telemetryRequest.options.headers["content-type"], "text/plain;charset=UTF-8");
const telemetry = JSON.parse(telemetryRequest.options.body);
assert.equal(telemetry.sdk_name, "browser");
assert.equal(telemetry.mime_type, "image/jpeg");
assert.ok(["invalid_provenance", "verification_error"].includes(telemetry.failure_kind));
assert.equal("asset" in telemetry, false);
assert.equal("manifest" in telemetry, false);
console.log("WASM verifier smoke test passed");
