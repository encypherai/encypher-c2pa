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
 */
char *encypher_c2pa_verify(
    const uint8_t *asset,
    size_t asset_len,
    const char *mime_type,
    const char *options_json
);

/* Saves failure telemetry consent for subsequent native SDK verifications. */
char *encypher_c2pa_set_telemetry_enabled(bool enabled);

/* Returns a JSON envelope whose enabled field is true, false, or null. */
char *encypher_c2pa_telemetry_preference(void);

/* Releases a string returned by encypher_c2pa_verify. */
void encypher_c2pa_free_string(char *value);

#ifdef __cplusplus
}
#endif

#endif
