/* menu_bridge.h - Shared integer settings, limits, colors and menu telemetry.
 * BR_SETTINGS is the schema used for declarations, defaults and validation.
 */
#ifndef MENU_BRIDGE_H
#define MENU_BRIDGE_H

#ifdef __cplusplus
extern "C" {
#endif

#define BR_MAGIC 0x57444D31u
#define BR_VERSION 16u
#define BR_COLOR_COUNT 17

/* Table d'indexation des slots couleur (identique pour color[] et color_occluded[]) :
 *  0  réservé (marqueur par défaut)
 *  1  box (trait)
 *  2  skel
 *  3  model (trait)
 *  4  health (borne haute du dégradé PV)
 *  5  downed (état)
 *  6  name
 *  7  weapon
 *  8  dist
 *  9  armor
 * 10  targeted (état)
 * 11  hptext (borne haute)
 * 12  crouch
 * 13  libre — ne pas réattribuer sans concertation
 * 14  aim
 * 15  box fill
 * 16  model fill
 */

/* Shared schema for the WebView, defaults and on-disk settings.
 * Each entry is a field, default, minimum and maximum. */
#define BR_SETTINGS(X) \
    X(enabled, 1, 0, 1) \
    X(show_box, 1, 0, 1) \
    X(show_skeleton, 1, 0, 1) \
    X(show_name, 1, 0, 1) \
    X(show_armor, 1, 0, 1) \
    X(show_distance, 1, 0, 1) \
    X(show_weapon, 1, 0, 1) \
    X(show_head, 1, 0, 1) \
    X(show_self, 0, 0, 1) \
    X(show_clan, 1, 0, 1) \
    X(show_police, 1, 0, 1) \
    X(cham_on, 0, 0, 1) \
    X(max_distance, 30000, 0, 200000) \
    X(skel_distance, 15000, 0, 200000) \
    X(line_w, 1, 1, 4) \
    X(radar_on, 1, 0, 1) \
    X(radar_range, 150, 25, 500) \
    X(aa_on, 0, 0, 1) \
    X(aa_show_fov, 1, 0, 1) \
    X(aa_fov_px, 150, 30, 600) \
    X(aa_key, 0x12, 1, 254) \
    X(aa_smooth, 5, 1, 10) \
    X(aa_aim_cal, 100, 10, 2000) \
    X(aa_dist, 0, 0, 1000) \
    X(aa_target_clan, 0, 0, 1) \
    X(aa_target_police, 0, 0, 1) \
    X(aa_bone, 0, 0, 9) \
    X(aa_los_on, 0, 0, 1) \
    X(aa_closest_first, 0, 0, 1) \
    X(show_loot, 0, 0, 1) \
    X(show_loot_nodes, 0, 0, 1) \
    X(loot_tier_none, 1, 0, 1) \
    X(loot_tier_common, 1, 0, 1) \
    X(loot_tier_uncommon, 1, 0, 1) \
    X(loot_tier_rare, 1, 0, 1) \
    X(loot_tier_epic, 1, 0, 1) \
    X(loot_tier_legendary, 1, 0, 1) \
    X(loot_tier_exotic, 1, 0, 1) \
    X(vehicle_chams, 0, 0, 1) \
    X(show_containers, 0, 0, 1) \
    X(show_doors, 0, 0, 1) \
    X(show_dropped_loot, 0, 0, 1) \
    X(show_vehicle_loot, 0, 0, 1) \
    X(radar_world, 0, 0, 1) \
    X(show_crouch, 0, 0, 1) \
    X(show_health, 0, 0, 1) \
    X(show_vehicle_markers, 0, 0, 1) \
    X(show_vehicle_occupants, 0, 0, 1) \
    X(norecoil_on, 0, 0, 1) \
    X(norecoil_intensity, 100, 0, 100) \
    X(norecoil_jitter, 0, 0, 20) \
    X(nospread_on, 0, 0, 1) \
    X(show_hpbar, 1, 0, 1) \
    X(show_snapline, 0, 0, 3) \
    X(snapline_from_crosshair, 1, 0, 1) \
    X(los_dim, 0, 0, 1) \
    X(xhair_on, 0, 0, 1) \
    X(xhair_style, 1, 0, 3) \
    X(xhair_size, 8, 2, 40) \
    X(xhair_thick, 1, 1, 4) \
    X(xhair_outline, 1, 0, 1) \
    X(streamsafe_on, 1, 0, 1) \
    X(show_robbers, 1, 0, 1) \
    X(show_civilians, 1, 0, 1) \
    X(box_fill, 0, 0, 3) \
    X(model_fill, 0, 0, 2)

typedef struct BR_Config {
    unsigned int magic, version;
#define BR_DECLARE(field, initial, minimum, maximum) int field;
    BR_SETTINGS(BR_DECLARE)
#undef BR_DECLARE
    /* Deux variantes par slot : visible et derrière les murs. Mêmes index pour les deux. */
    struct { unsigned char rgb[3]; } color[BR_COLOR_COUNT];
    struct { unsigned char rgb[3]; } color_occluded[BR_COLOR_COUNT];

    int menu_open;
    int telem_targets;
    int telem_game_pid;
    int telem_cham_n;
    int telem_los_state; /* 0 off, 1 loading/stale, 2 ready */

#ifdef RR_PORT_DIAGNOSTICS
    int show_vehicles;
#endif
} BR_Config;

/* Lecture couleur bornée : écrête `idx` dans [0, BR_COLOR_COUNT-1], ne renvoie jamais NULL.
 * occluded != 0 → color_occluded[idx], sinon color[idx]. */
const unsigned char* br_color(const BR_Config* config, int idx, int occluded);

/* Unrecognized values use the same no-rarity bucket as the loot renderer. */
static int br_loot_rarity_visible(const BR_Config* config, int rarity) {
    switch (rarity) {
        case 1: return config->loot_tier_common;
        case 2: return config->loot_tier_uncommon;
        case 3: return config->loot_tier_rare;
        case 4: return config->loot_tier_epic;
        case 5: return config->loot_tier_legendary;
        case 6: return config->loot_tier_exotic;
        default: return config->loot_tier_none;
    }
}

BR_Config* br_get(void);
int br_config_set(BR_Config* config, const char* key, int value);
int br_config_save(void);
int br_config_load(void);

int br_start_menu(void);
void br_stop_menu(void);
void br_set_menu_visible(int visible);
void br_request_toggle(void);

#ifdef __cplusplus
}
#endif
#endif
