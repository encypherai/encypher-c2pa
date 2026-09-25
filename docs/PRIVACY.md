# Privacy

## Online checks

Online checks are off on every surface. A verification that has not been allowed to fetch opens no socket: it reads the file and answers from the file and the packaged trust snapshot.

When they are allowed, exactly four kinds of request can be made, and only when the file itself references them:

| Request | What the host learns |
|---|---|
| GET the manifest store an asset names in its XMP `dcterms:provenance` | that somebody is checking a file that points at that URL |
| POST an OCSP request for a claim-signer or CAWG identity certificate | that somebody is checking a file signed with that certificate; the request carries the certificate serial number and hashes of the issuer name and key, nothing else |
| GET the `did:web` document of an identity issuer | that somebody is checking a file naming that issuer |
| GET content an assertion stores outside the asset | that somebody is checking a file that references that content |

Asset bytes never leave the machine. No filename, path, report, account identifier, or machine identifier is sent. The requests carry no cookies and no credentials, and identify themselves as `encypher-c2pa/<version>`. Each host also necessarily sees the connection's source IP, as any web request does.

Every attempt appears in the report's `network` block, with its purpose, URL, and outcome. A verification that stayed offline still lists what a fetch would settle, under `network.needed`, so nothing has to be fetched to find out whether fetching would help.

The command line asks before the first fetch, listing each purpose and host and saying that contacting them tells those servers the file is being checked. The answer is saved as `on`, `off`, or `ask` in `online.json`, beside the telemetry choice, under the same per-user configuration directory. `encypher-c2pa online on|off|ask|status` reads and changes it. `ENCYPHER_C2PA_ONLINE=on` or `off` is an operator override and outranks the file. A process with nobody at the terminal never prompts and stays offline.

Libraries - Rust, Python, Go, C, and the browser - never read the saved answer and never prompt. They fetch only when the caller passes the `online` option or the operator sets the environment variable. A server verifying files sent in by strangers must not start making requests because somebody answered a prompt on a laptop.

In the browser, `verify` is synchronous and fetches nothing. `verifyOnline` fetches through the page's own `fetch`, so the page's origin, CORS, and Content-Security-Policy rules govern every request. OCSP is not attempted from a browser.

## Update check

The command line, and only the command line, checks for a newer release once a day when a person is at the terminal. It sends one HTTPS GET to `https://index.crates.io/en/cy/encypher-c2pa-cli` with a `User-Agent` of `encypher-c2pa-cli/<version>`. The request carries no file, filename, path, report, or account or machine identifier; crates.io sees the requesting IP address, as with any request. Runs with no terminal, and runs with `--offline`, send nothing. Turn it off with `encypher-c2pa update-check off`, `{"check": false}` in `update.json`, or `ENCYPHER_C2PA_UPDATE_CHECK=off`. The libraries never make this request.

## Failure telemetry

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

The CLI `verify` command offers a separate, explicit call to the Encypher API. It is off unless `--encypher-api` is passed on that invocation and requires `ENCYPHER_API_KEY` for the production endpoint. The request contains the exact asset SHA-256, byte length, MIME type, and a bounded local-validation summary. When the asset format exposes its embedded C2PA manifest as one contiguous carrier, the request also contains the raw manifest store and carrier, encoded as base64, so the server can validate that detached evidence independently. The complete asset, filename, and file path do not leave the machine. Formats without contiguous detached evidence send no manifest data. The default endpoint is `https://api.encypher.com/api/v1/verify/local`, uses a 30-second timeout, and is overridable with the hidden `--encypher-api-endpoint` flag for self-hosting or tests. The response renders separately and never changes the local verdict or process exit code; any network or response failure degrades to a warning and a bounded error object.

The browser example loads its JavaScript and WebAssembly from the same server that serves the page. With telemetry disabled, selecting an asset and calling `verify` makes no request at all. Applications can self-host both files and enforce this with Content Security Policy.

Package registries and source hosts may record ordinary download logs when a user installs the software. Those services are outside the runtime verifier.

A product may add its own logging around the SDK. That logging is not part of this repository. Applications should disclose it and avoid recording asset bytes, manifests, certificates, or full reports unless the user expects that handling.
