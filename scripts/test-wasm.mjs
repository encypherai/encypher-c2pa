import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { resolve } from "node:path";

const storage = new Map();
globalThis.localStorage = {
  getItem: (key) => storage.get(key) ?? null,
  setItem: (key, value) => storage.set(key, value),
};

const root = resolve(import.meta.dirname, "..");
const pkg = resolve(root, "bindings/wasm/pkg");
const { default: init, configureTelemetry, telemetryEnabled, verify, supportedMimeTypes } =
  await import(new URL(`file://${resolve(pkg, "encypher_c2pa_wasm.js")}`));
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
assert.equal(report.trust.status, "not_evaluated");
assert.ok(supportedMimeTypes().includes("video/mp4"));

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
