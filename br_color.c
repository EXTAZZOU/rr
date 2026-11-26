/* br_color.c — fonctions pures de couleur, sans D3D, sans WebView2, sans jeu.
 * Extraites de menu_webview.cpp pour être linkables par le harnais console
 * (build_tests.bat) sans entraîner la pile graphique. Comportement identique
 * à l'octet près : aucune valeur de retour ne change. */
#include "menu_bridge.h"

/* Renormalise l'alpha d'une couleur sur un plafond donné, en conservant l'ordre
 * relatif des états. Remplace les cinq calculs inline qui étaient recopiés dans
 * rr_draw.c (cham, cham véhicule, fill de boîte, fond de badge, fond de HP bar).
 * Exemple : alpha 204 (voile occlus) et plafond 80 -> 64 ; alpha 255 -> 80. */
uint32_t alpha_scale(uint32_t color, unsigned ceiling) {
    unsigned a = ((color >> 24) * ceiling) / 255u;
    return (color & 0x00FFFFFFu) | (a << 24);
}

/* Couleur d'un élément ESP : lit br_color pour le slot donné (dead force slot 5),
 * applique le voile 80% si occluded, 60% si mort visible, sinon pleine opacité.
 * Écrêtage silencieux : idx hors borne est ramené dans [0, BR_COLOR_COUNT-1].
 * C'est voulu — un slot non bumpé lit un slot voisin au lieu de planter, et le
 * harnais de test est le seul endroit où l'oubli doit être bruyant. */
const unsigned char* br_color(const BR_Config* cfg, int idx, int occluded) {
    static const unsigned char zero[3] = {0, 0, 0};
    if (!cfg) return zero;
    if (idx < 0) idx = 0;
    if (idx >= BR_COLOR_COUNT) idx = BR_COLOR_COUNT - 1;
    return occluded ? cfg->color_occluded[idx].rgb : cfg->color[idx].rgb;
}
