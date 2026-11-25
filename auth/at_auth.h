/* at_auth.h - Logit license + HWID auth client.
 *
 * Call at_auth_check() ONCE at startup, before any driver access.
 * Returns 1 if authorised (saves the key encrypted via DPAPI), 0 otherwise.
 * On failure, reason_buf is filled with a short human-readable cause.
 *
 * The server URL is baked at compile time via AT_AUTH_URL below; swap it
 * to your deployment before you build.
 */
#ifndef AT_AUTH_H
#define AT_AUTH_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>

/* The auth endpoint. HTTPS strongly recommended for shipped builds. */
#ifndef AT_AUTH_URL
#define AT_AUTH_URL "https://api.logit.lol/api/v1/auth"
#endif

/* Product label for the DPAPI blob description. */
#define AT_PRODUCT_NAME L"Logit"

/* Returns 1 on success, 0 on failure. reason_buf receives a wide string
 * explaining the failure (bounded by reason_cap, always NUL-terminated).
 * The caller shows that string to the user. */
int at_auth_check(wchar_t* reason_buf, size_t reason_cap);

/* Manual seed: DPAPI-encrypt and save the given key to the state file.
 * Bypasses the input dialog. Used for scripted installs / --license flag. */
void at_auth_store_key(const char* key);

#ifdef __cplusplus
}
#endif

#endif /* AT_AUTH_H */
