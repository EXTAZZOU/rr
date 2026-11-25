/* at_payload.h - decrypted runtime payload.
 *
 * Populated once per session after a valid auth. Zeroed otherwise. The
 * feature modules (rr_norecoil, future ones) read their critical offsets
 * from this struct and refuse to act when magic != expected. A patcher
 * who bypasses the bool check but can't produce a valid signed response
 * ends up with magic=0 and the features never activate.
 */
#ifndef AT_PAYLOAD_H
#define AT_PAYLOAD_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    uint32_t magic;             /* must equal AT_PAYLOAD_MAGIC after decrypt */
    uint32_t o_battle_player;   /* BattleEntitiesModel + X -> PlayerEntityModel */
    uint32_t o_player_client;   /* PlayerEntityModel   + X -> PlayerClientModel */
    uint32_t o_client_recoil;   /* PlayerClientModel   + X -> RecoilModel       */
    uint32_t o_client_spread;   /* PlayerClientModel   + X -> PlayerFakeSpread  */
    uint32_t o_recoil_offset;   /* RecoilModel         + X -> Vector2 kick      */
    uint32_t o_spread_spread;
    uint32_t o_spread_air;
    uint32_t o_spread_move;
} AT_Payload;

/* Fill the global payload from a fresh auth response.
 * Returns 1 on success, 0 if any step failed (sig, HMAC, AES-GCM, JSON).
 * On failure, at_payload_get() still returns a struct with magic==0. */
int at_payload_install(const char* sig_b64, const char* pl_b64);

/* Returns a pointer to the current (or zeroed) payload. Never NULL. */
const AT_Payload* at_payload_get(void);

/* Clear the payload (e.g., on auth failure). */
void at_payload_wipe(void);

#ifdef __cplusplus
}
#endif

#endif
