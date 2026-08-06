# Privacy

Telemetry starts off. On the first interactive verification, the SDK presents this data contract, asks once, and saves the answer. Native bindings share a per-user config file. Browser JavaScript stores the choice under `encypher-c2pa.telemetry-enabled` in local storage. Non-interactive processes do not prompt and remain off unless configured through the API or `ENCYPHER_C2PA_TELEMETRY`.

The CLI exposes `telemetry on`, `telemetry off`, and `telemetry status`. Python exposes `configure_telemetry`, Go exposes `ConfigureTelemetry`, browser JavaScript exposes `configureTelemetry`, and Rust/C expose the same preference through their native APIs. A caller can still override the saved native choice for one verification call.

The client sends an event only when provenance integrity is invalid or the validation engine cannot complete. The event contains exactly:

- schema version;
- SDK name and package version;
- engine profile;
- canonical MIME type;
- failure kind, either `invalid_provenance` or `verification_error`;
- up to eight bounded validation status codes.

The event does not contain asset bytes, manifest data, full reports, error messages, filenames, file paths, page URLs, certificates, keys, trust material, account or organization IDs, usage counts, package-install events, or machine identifiers. Unknown fields are rejected by the Encypher endpoint.

Native clients place events on a 64-item in-memory queue. They drop events when the queue is full or unavailable, use a two-second HTTP timeout, and do not retry. Verification never waits for delivery. The browser binding uses a best-effort `fetch` with `keepalive`. A caller can override the endpoint for self-hosting or tests.

The receiving service necessarily sees the connection's source IP and uses it for a 240-request-per-hour abuse limit. The event and stored metric do not include the IP or user-agent. Reports use a fixed anonymous organization identity and cannot enter the privileged incident or paging path.

The browser example loads its JavaScript and WebAssembly from the same server that serves the page. With telemetry disabled, selecting and verifying an asset does not make a verification request. Applications can self-host both files and enforce this with Content Security Policy.

Package registries and source hosts may record ordinary download logs when a user installs the software. Those services are outside the runtime verifier.

A product may add its own logging around the SDK. That logging is not part of this repository. Applications should disclose it and avoid recording asset bytes, manifests, certificates, or full reports unless the user expects that handling.
