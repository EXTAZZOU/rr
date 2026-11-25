/* at_payload.c - derive payload key, decrypt, parse offsets. */
#define WIN32_LEAN_AND_MEAN
#define _CRT_SECURE_NO_WARNINGS
#include <windows.h>
#include <bcrypt.h>
#include <wincrypt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "at_payload.h"
#include "at_shared.h"

#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "crypt32.lib")

static AT_Payload g_payload;

const AT_Payload* at_payload_get(void) { return &g_payload; }
void at_payload_wipe(void) { memset(&g_payload, 0, sizeof(g_payload)); }

static int at_hmac_sha256(const unsigned char* key, ULONG keylen,
                          const unsigned char* data, ULONG datalen,
                          unsigned char out[32]) {
    BCRYPT_ALG_HANDLE alg = NULL;
    BCRYPT_HASH_HANDLE h  = NULL;
    int ok = 0;
    if (BCryptOpenAlgorithmProvider(&alg, BCRYPT_SHA256_ALGORITHM, NULL,
                                    BCRYPT_ALG_HANDLE_HMAC_FLAG) != 0) goto done;
    if (BCryptCreateHash(alg, &h, NULL, 0, (PUCHAR)key, keylen, 0) != 0) goto done;
    if (BCryptHashData(h, (PUCHAR)data, datalen, 0) != 0) goto done;
    if (BCryptFinishHash(h, out, 32, 0) != 0) goto done;
    ok = 1;
done:
    if (h)   BCryptDestroyHash(h);
    if (alg) BCryptCloseAlgorithmProvider(alg, 0);
    return ok;
}

static int at_aes_gcm_decrypt(const unsigned char* key32,
                              const unsigned char* iv,  ULONG ivlen,
                              const unsigned char* tag, ULONG taglen,
                              const unsigned char* ct,  ULONG ctlen,
                              unsigned char* pt_out, ULONG pt_cap,
                              ULONG* pt_len) {
    BCRYPT_ALG_HANDLE alg = NULL;
    BCRYPT_KEY_HANDLE k   = NULL;
    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO info;
    int ok = 0;
    if (BCryptOpenAlgorithmProvider(&alg, BCRYPT_AES_ALGORITHM, NULL, 0) != 0) goto done;
    if (BCryptSetProperty(alg, BCRYPT_CHAINING_MODE,
                          (PUCHAR)BCRYPT_CHAIN_MODE_GCM,
                          sizeof(BCRYPT_CHAIN_MODE_GCM), 0) != 0) goto done;
    if (BCryptGenerateSymmetricKey(alg, &k, NULL, 0, (PUCHAR)key32, 32, 0) != 0) goto done;

    BCRYPT_INIT_AUTH_MODE_INFO(info);
    info.pbNonce = (PUCHAR)iv;  info.cbNonce = ivlen;
    info.pbTag   = (PUCHAR)tag; info.cbTag   = taglen;

    if (BCryptDecrypt(k, (PUCHAR)ct, ctlen, &info, NULL, 0,
                      pt_out, pt_cap, pt_len, 0) != 0) goto done;
    ok = 1;
done:
    if (k)   BCryptDestroyKey(k);
    if (alg) BCryptCloseAlgorithmProvider(alg, 0);
    return ok;
}

/* Minimal JSON number extractor: find "key":<number> and parse. */
static int parse_num(const char* json, const char* key, unsigned* out) {
    char look[64];
    const char *p, *end;
    unsigned long v;
    _snprintf_s(look, sizeof(look), _TRUNCATE, "\"%s\":", key);
    p = strstr(json, look);
    if (!p) return 0;
    p += strlen(look);
    while (*p == ' ' || *p == '\t') ++p;
    v = strtoul(p, (char**)&end, 0);
    if (end == p) return 0;
    *out = (unsigned)v;
    return 1;
}

int at_payload_install(const char* sig_b64, const char* pl_b64) {
    unsigned char sig_bin[128];
    unsigned char pl_bin[1024];
    unsigned char key[32];
    unsigned char pt[1024];
    ULONG sig_len = sizeof(sig_bin);
    ULONG pl_len  = sizeof(pl_bin);
    ULONG pt_len  = 0;
    char json[1024];
    AT_Payload tmp;
    unsigned val;

    memset(&g_payload, 0, sizeof(g_payload));

    if (!sig_b64 || !pl_b64) return 0;
    if (!CryptStringToBinaryA(sig_b64, 0, CRYPT_STRING_BASE64,
                              sig_bin, &sig_len, NULL, NULL)) return 0;
    if (!CryptStringToBinaryA(pl_b64, 0, CRYPT_STRING_BASE64,
                              pl_bin, &pl_len, NULL, NULL)) return 0;
    if (pl_len < 12 + 16 + 1) return 0;

    /* Derive the GCM key: HMAC-SHA256(SHARED_SECRET, sig). */
    if (!at_hmac_sha256(AT_SHARED_SECRET, 32, sig_bin, sig_len, key)) return 0;

    /* Wire format: IV(12) | TAG(16) | CT. */
    if (!at_aes_gcm_decrypt(key,
                            pl_bin,       12,
                            pl_bin + 12,  16,
                            pl_bin + 28,  pl_len - 28,
                            pt, sizeof(pt), &pt_len)) {
        /* Wipe key before bailing. */
        SecureZeroMemory(key, sizeof(key));
        return 0;
    }
    SecureZeroMemory(key, sizeof(key));
    if (pt_len == 0 || pt_len >= sizeof(json)) return 0;
    memcpy(json, pt, pt_len);
    json[pt_len] = 0;
    SecureZeroMemory(pt, sizeof(pt));

    /* Parse JSON (tiny ad-hoc parser - keys are stable). */
    memset(&tmp, 0, sizeof(tmp));
    if (!parse_num(json, "magic",            &val)) return 0;
    tmp.magic = val;
    if (tmp.magic != AT_PAYLOAD_MAGIC) return 0;
    if (!parse_num(json, "o_battle_player",  &val)) return 0; tmp.o_battle_player = val;
    if (!parse_num(json, "o_player_client",  &val)) return 0; tmp.o_player_client = val;
    if (!parse_num(json, "o_client_recoil",  &val)) return 0; tmp.o_client_recoil = val;
    if (!parse_num(json, "o_client_spread",  &val)) return 0; tmp.o_client_spread = val;
    if (!parse_num(json, "o_recoil_offset",  &val)) return 0; tmp.o_recoil_offset = val;
    if (!parse_num(json, "o_spread_spread",  &val)) return 0; tmp.o_spread_spread = val;
    if (!parse_num(json, "o_spread_air",     &val)) return 0; tmp.o_spread_air    = val;
    if (!parse_num(json, "o_spread_move",    &val)) return 0; tmp.o_spread_move   = val;

    g_payload = tmp;
    SecureZeroMemory(json, sizeof(json));
    return 1;
}
