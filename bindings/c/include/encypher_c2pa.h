// Copyright 2026 Encypher Corporation
// SPDX-License-Identifier: Apache-2.0

#ifndef ENCYPHER_C2PA_H
#define ENCYPHER_C2PA_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Returns an allocated UTF-8 JSON envelope. options_json may be NULL.
 * This function makes a telemetry request only after saved consent or an explicit option.
 *
 * Online checks are off. Set "online": true in options_json to let one
 * verification fetch what the asset references: a manifest store held
 * elsewhere, certificate revocation status, a did:web document, externally
 * stored content. An operator may instead set ENCYPHER_C2PA_ONLINE=on. This
 * library never reads the per-user choice saved by the command line and never
 * prompts, because the host running it may be checking files sent in by
 * strangers. Set "online_allow_private_networks": true for intranet mode,
 * where those fetches may reach loopback and private addresses and accept
 * plaintext http. Every report carries a "network" block listing what could
 * be fetched and what was.
 */
char *encypher_c2pa_verify(
    const uint8_t *asset,
    size_t asset_len,
    const char *mime_type,
    const char *options_json
);

/*
 * Verifies an asset against a C2PA Manifest Store supplied separately: a
 * .c2pa sidecar, or a store the caller fetched from the URI the asset
 * declares. This entry point fetches nothing by itself; to have the store
 * fetched for you, call encypher_c2pa_verify with "online": true.
 * mime_type describes the asset, not the store.
 */
char *encypher_c2pa_verify_with_manifest_store(
    const uint8_t *asset,
    size_t asset_len,
    const uint8_t *manifest_store,
    size_t manifest_store_len,
    const char *mime_type,
    const char *options_json
);

/*
 * Verifies fragmented ISO BMFF. asset is the initialization segment.
 * fragments and fragment_lengths are parallel arrays with fragment_count entries.
 */
char *encypher_c2pa_verify_fragmented(
    const uint8_t *asset,
    size_t asset_len,
    const uint8_t *const *fragments,
    const size_t *fragment_lengths,
    size_t fragment_count,
    const char *mime_type,
    const char *options_json
);

/*
 * Verifies a declared fMP4/CMAF stream. asset is the initialization segment.
 * segments and segment_lengths are parallel arrays with segment_count entries,
 * in playback order. encapsulation is "fMP4" or "CMAF"; method is
 * "verifiable-segment-info" or "per-segment". Both are matched ASCII
 * case-insensitively and may be NULL for those defaults.
 *
 * The report carries a top-level integrity, the init manifest report under
 * stream, and, for a per-segment stream, segments plus chain_valid.
 */
char *encypher_c2pa_verify_stream(
    const uint8_t *asset,
    size_t asset_len,
    const uint8_t *const *segments,
    const size_t *segment_lengths,
    size_t segment_count,
    const char *mime_type,
    const char *encapsulation,
    const char *method,
    const char *options_json
);

/* Saves failure telemetry consent for subsequent native SDK verifications. */
char *encypher_c2pa_set_telemetry_enabled(bool enabled);

/* Returns a JSON envelope whose enabled field is true, false, or null. */
char *encypher_c2pa_telemetry_preference(void);

/* Releases any string returned by this library. */
void encypher_c2pa_free_string(char *value);

#ifdef __cplusplus
}
#endif

#endif
