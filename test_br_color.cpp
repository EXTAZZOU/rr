/* test_br_color.cpp — harnais console des fonctions pures extraites.
 * Aucune dépendance D3D / WebView2 / jeu. Compilé sans NDEBUG (cl ne le
 * définit pas par défaut) : les A() sont le seul mécanisme d'assertion. */
#include "menu_bridge.h"
#include <stdio.h>
#include <string.h>

static int g_pass = 0, g_fail = 0;

#define A(cond)                                                                  \
    do {                                                                         \
        if (cond) { ++g_pass; }                                                  \
        else { ++g_fail; printf("FAIL %s:%d  %s\n", __FILE__, __LINE__, #cond); } \
    } while (0)

int main(void) {
    /* Table figée : si BR_COLOR_COUNT bouge sans que les tests hors-borne
     * suivent, cette ligne casse avant tout le reste. */
    A(BR_COLOR_COUNT == 17);

    /* alpha_scale — plafonds réellement utilisés dans rr_draw.c.
     * Entrées 255 (vivant), 204 (occlus, voile 80%), 153 (mort, 60%).
     * Le RGB doit traverser intact sur chaque ligne. */
    A(alpha_scale(0xFF123456u,   80u) == 0x50123456u);  /* 255 -> 80  */
    A(alpha_scale(0xCC123456u,   80u) == 0x40123456u);  /* 204 -> 64  */
    A(alpha_scale(0x99123456u,   80u) == 0x30123456u);  /* 153 -> 48  */
    A(alpha_scale(0xFF123456u, 0x66u) == 0x66123456u);  /* 255 -> 102 */
    A(alpha_scale(0xCC123456u, 0x66u) == 0x51123456u);  /* 204 -> 81  */
    A(alpha_scale(0x99123456u, 0x66u) == 0x3D123456u);  /* 153 -> 61  */
    A(alpha_scale(0xFF123456u,  170u) == 0xAA123456u);  /* 255 -> 170 */
    A(alpha_scale(0xFF123456u,   60u) == 0x3C123456u);  /* 255 -> 60  */
    A(alpha_scale(0x00123456u,   80u) == 0x00123456u);  /* alpha 0 stable */
    A(alpha_scale(0xFF123456u,    0u) == 0x00123456u);  /* plafond 0 */
    A(alpha_scale(0x00000000u,   80u) == 0x00000000u);  /* tout à zéro */

    /* br_color — écrêtage, sélection visible/occlus, NULL. */
    BR_Config cfg;
    memset(&cfg, 0, sizeof(cfg));
    for (int i = 0; i < BR_COLOR_COUNT; ++i) {
        cfg.color[i].rgb[0]          = (unsigned char)(i + 1);
        cfg.color[i].rgb[1]          = (unsigned char)(i + 2);
        cfg.color[i].rgb[2]          = (unsigned char)(i + 3);
        cfg.color_occluded[i].rgb[0] = (unsigned char)(101 + i);
        cfg.color_occluded[i].rgb[1] = (unsigned char)(102 + i);
        cfg.color_occluded[i].rgb[2] = (unsigned char)(103 + i);
    }

    /* Identité : la fonction rend l'adresse du tableau, pas une copie. */
    A(br_color(&cfg,  5, 0) == cfg.color[5].rgb);
    A(br_color(&cfg,  5, 1) == cfg.color_occluded[5].rgb);
    A(br_color(&cfg, 16, 0) == cfg.color[16].rgb);

    /* Écrêtage : c'est ce qui rend un BR_COLOR_COUNT non bumpé silencieux.
     * Ces quatre lignes sont le garde-fou du slot 13 quand il s'ouvrira. */
    A(br_color(&cfg,   -1, 0) == cfg.color[0].rgb);
    A(br_color(&cfg, -999, 1) == cfg.color_occluded[0].rgb);
    A(br_color(&cfg,   17, 0) == cfg.color[16].rgb);
    A(br_color(&cfg, 1000, 1) == cfg.color_occluded[16].rgb);

    /* NULL : triplet statique à zéro, jamais de déréférencement. */
    {
        const unsigned char* z = br_color(NULL, 5, 0);
        A(z != NULL && z[0] == 0 && z[1] == 0 && z[2] == 0);
    }

    printf("%d passed, %d failed\n", g_pass, g_fail);
    return g_fail ? 1 : 0;
}
