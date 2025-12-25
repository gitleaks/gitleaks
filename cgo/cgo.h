#pragma once

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// All returned C strings are allocated by the library and MUST be freed with
// GitleaksFreeString.

// Creates a detector with the embedded default gitleaks configuration.
// Returns 0 on error (outErr will contain the error message).
uint64_t GitleaksCreateDefaultDetector(char **outErr);

// Creates a detector from TOML configuration content.
// Returns 0 on error (outErr will contain the error message).
uint64_t GitleaksCreateDetectorFromToml(const char *configToml, char **outErr);

// Frees a previously created detector handle. Safe to call with invalid handles.
void GitleaksFreeDetector(uint64_t handle);

// Scans text and returns a JSON payload:
// { "findings": [ { ... } ] }
// Returns NULL on error (outErr will contain the error message).
char *GitleaksDetectString(uint64_t handle, const char *text, const char *filePath, char **outErr);

// Scans arbitrary bytes as UTF-8 text and returns the same JSON payload as above.
// Returns NULL on error (outErr will contain the error message).
char *GitleaksDetectBytes(uint64_t handle, const uint8_t *data, int dataLen, const char *filePath, char **outErr);

// Frees strings returned by this library (both results and error messages).
void GitleaksFreeString(char *s);

#ifdef __cplusplus
}
#endif


