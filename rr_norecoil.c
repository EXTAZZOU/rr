/* rr_norecoil.c - resolves PlayerClientModel once per match and writes
 * zero (+jitter) to RecoilOffset / FakeSpread each tick.
 *
 * Chain (from Cpp2IL dump 2026-11-23):
 *   BattleEntitiesModel + 0xD0 -> PlayerEntityModel .Player
 *   PlayerEntityModel   + 0x18 -> PlayerClientModel .ClientModel
 *   PlayerClientModel   + 0x2B8 -> RecoilModel
 *   PlayerClientModel   + 0x2C0 -> PlayerFakeSpreadModel
 *
 *   RecoilModel + 0x10 -> Vector2 RecoilOffset (x = yaw kick, y = pitch kick)
 *   PlayerFakeSpreadModel + 0x10/0x14/0x18 -> Spread / Air / Move (floats)
 *
 * All offsets confirmed on build SHA 2dc33269... (ROB RUN 0.7.0.4055).
 */

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "rr_mem.h"
#include "rr_norecoil.h"
#include "auth/at_obf.h"
#include "auth/at_payload.h"
#include "auth/at_shared.h"

/* Offsets are NO LONGER hardcoded. They come from the auth-time encrypted
 * payload (see auth/at_payload.c). A patcher who skips the auth check but
 * can't produce a valid signed/encrypted payload gets magic=0 and the
 * accessors below all return 0 => tick() refuses to write. */
#define _PL   (at_payload_get())
#define _OK   (_PL->magic == AT_PAYLOAD_MAGIC)

/* Simple cache of what we resolved. Dropped when battle ptr changes. */
static uint64_t g_cached_battle = 0;
static uint64_t g_player_client = 0;
static uint64_t g_recoil_model  = 0;
static uint64_t g_spread_model  = 0;

static int plausible(uint64_t p) {
    return p >= 0x10000ULL && p < 0x00007FFFFFFFFFFFULL;
}

static uint64_t rread_u64(uint64_t addr) {
    uint64_t v = 0;
    rr_read(addr, &v, sizeof(v));
    return v;
}

static void resolve_once(uint64_t battle_entities) {
    g_player_client = 0;
    g_recoil_model  = 0;
    g_spread_model  = 0;

    /* Hard refusal: no valid payload = feature inert. */
    if (!_OK) return;
    if (!plausible(battle_entities)) return;

    uint64_t player_entity = rread_u64(battle_entities + _PL->o_battle_player);
    if (!plausible(player_entity)) return;

    uint64_t client = rread_u64(player_entity + _PL->o_player_client);
    if (!plausible(client)) return;

    uint64_t recoil = rread_u64(client + _PL->o_client_recoil);
    uint64_t spread = rread_u64(client + _PL->o_client_spread);

    g_player_client = client;
    if (plausible(recoil)) g_recoil_model = recoil;
    if (plausible(spread)) g_spread_model = spread;
}

void rr_norecoil_reset(void) {
    g_cached_battle = 0;
    g_player_client = 0;
    g_recoil_model  = 0;
    g_spread_model  = 0;
}

/* Deterministic pseudo-random for the jitter. Stateful but not cryptographic;
 * we just want something that varies per-tick so the server never sees the
 * same exact write twice. */
static unsigned int g_rng = 0x9E3779B1u;
static float jitter_px(int range) {
    if (range <= 0) return 0.f;
    g_rng = g_rng * 1664525u + 1013904223u;
    float r = ((int)((g_rng >> 16) & 0xFFFF) - 0x8000) / 32768.0f; /* [-1, 1) */
    return r * (float)range;
}

void rr_norecoil_tick(uint64_t battle_entities, const RR_NorecoilCfg* cfg) {
    AT_JUNK(0xF00DBEEF);
    if (!cfg) return;
    /* Hard refusal if the crypto payload isn't present. */
    if (!_OK) return;

    /* Re-resolve when the match anchor changes (new round / new battle). */
    if (battle_entities != g_cached_battle) {
        g_cached_battle = battle_entities;
        resolve_once(battle_entities);
    }

    if (!g_player_client) return;

    /* --- no-recoil ------------------------------------------------------- */
    if (cfg->on && g_recoil_model && AT_OPAQUE_TRUE) {
        /* We don't read the current value to blend - we just scale an impulse
         * of zero + jitter. intensity=100 => we overwrite with (jitter, jitter);
         * intensity<100 => we'd normally interpolate the game's own value, but
         * since the game writes after us anyway (we lose the race), full
         * override is simpler and semantically equivalent in practice. */
        float v[2];
        if (cfg->intensity >= 100) {
            v[0] = jitter_px(cfg->jitter_px);
            v[1] = jitter_px(cfg->jitter_px);
        } else {
            float cur[2] = {0};
            rr_read(g_recoil_model + _PL->o_recoil_offset, cur, sizeof(cur));
            float k = (100.0f - (float)cfg->intensity) / 100.0f;
            v[0] = cur[0] * k + jitter_px(cfg->jitter_px);
            v[1] = cur[1] * k + jitter_px(cfg->jitter_px);
        }
        rr_write(g_recoil_model + _PL->o_recoil_offset, v, sizeof(v));
    }

    /* --- no-spread ------------------------------------------------------- */
    if (cfg->spread_on && g_spread_model && AT_OPAQUE_TRUE) {
        float zero[3] = {0.f, 0.f, 0.f};
        /* spread_spread(0x10), air(0x14), move(0x18) - keep layout contiguous. */
        rr_write(g_spread_model + _PL->o_spread_spread, zero, sizeof(zero));
    }
}
