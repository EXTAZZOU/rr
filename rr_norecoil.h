/* rr_norecoil.h - no-recoil + no-spread writer for Logit.
 *
 * Call rr_norecoil_tick() from ReadThread each cycle. It lazily resolves
 * the PlayerClientModel pointer the first time it has a valid battle
 * entities anchor, then writes 0,0 to RecoilModel.RecoilOffset and/or
 * zero to PlayerFakeSpreadModel.Spread/Air/Move when enabled.
 */
#ifndef RR_NORECOIL_H
#define RR_NORECOIL_H

#include <stdint.h>

typedef struct {
    int on;          /* 0/1 - master toggle */
    int intensity;   /* 0-100 - % of recoil zeroed (100 = full) */
    int jitter_px;   /* 0-20 - random noise added back to avoid "too perfect" */
    int spread_on;   /* 0/1 - no-spread toggle */
} RR_NorecoilCfg;

/* Must be called every few frames with the current cfg. Cheap when disabled. */
void rr_norecoil_tick(uint64_t battle_entities, const RR_NorecoilCfg* cfg);

/* Called when the match ends / battle pointer changes: drops the cache. */
void rr_norecoil_reset(void);

#endif
