# CONTEXT.md — état hors-code du projet Logit

Registre tenu passe après passe. Trois sections, pas une de plus.

## Dettes ouvertes

- **Slot 3 réservé non consommé.** `COLOR_INDEX.el.model = 3` dans `menu.html`, slot 3 présent dans `BR_Config.color[17]` / `color_occluded[17]`, mais aucun site de rendu dans `rr_draw.c` ne lit `br_color(b, 3, …)`. `mesh_highlight` ne trace qu'un remplissage (`r_fill_triangles`), pas d'outline. Les widgets Outline/Width/Color du `FORM.model` ont été retirés depuis `cd4e074` (option 3 stricte). Ouverture = passe complète : stroke par arête dans `mesh_highlight` (coût ~3 × `RR_CHAM_TRIANGLES` lignes par joueur, D3D11) ou outline silhouette via second pass dilaté, plus émission `set:cham_outline` / `set:cham_width` dans `BR_SETTINGS`, plus réintroduction des widgets. À la création d'un profil futur avec contour, semer avec une couleur par défaut explicite — sinon le contour hérite d'une valeur résiduelle oubliée d'un drag passé.

- **Slot 16 partagé entre `Characters.model` et `Vehicles.cars.model`.** Le profil `car` dans `VIEWS` lit les mêmes chips que le profil `char`, donc son chip `model` ouvre `S.pick = { el: "model", prop: "fillColor" }` et `colorIndex()` renvoie 16 pour les deux panneaux. Conséquence : régler la couleur de remplissage d'un personnage repeint aussi le châssis des véhicules. Le cham véhicule a perdu sa fonction d'identification que l'ambre fixe assurait avant `a5e8f9f`. Sortie = ouverture du slot 13 pour le cham véhicule, fork du profil `car` qui lirait un sous-arbre `COLOR_INDEX` différent, re-mapping et re-câblage du panneau Vehicles. Passe complète, pas un correctif.

- **Politique LOS divergente draw / aim.** Enum dans `rr_los_geom.h` : `RR_LOS_UNKNOWN = -1`, `RR_LOS_BLOCKED = 0`, `RR_LOS_CLEAR = 1`. `rr_draw.c` est fail-open (`UNKNOWN` ne voile pas) ; `rr_esp.c:447 aa_clear_path` est fail-closed (`UNKNOWN` = ne tire pas). Côté draw c'est le bon choix (pas de flash au cold start). Côté aim, `-1` correspond à une fenêtre morte de 600 ms après chaque changement de monde (plus 5 s si le static trace est périmé) pendant laquelle l'aim ne tire sur rien, et l'utilisateur lira ça comme un bug, pas comme une sécurité. Sorties possibles plus tard, à trancher : soit l'aim retombe sur le runtime trace seul quand le static est périmé, soit il traite `UNKNOWN` comme `CLEAR` sous un garde-fou de distance. Les deux changent le comportement de tir, donc hors passe mécanique.

- **`applyState` ignore `config.colors` et `config.colors_occluded`.** `build_state_json` dans `menu_webview.cpp` sérialise les deux tableaux ; `applyState` dans `menu.html` ne les lit pas. Conséquence : au boot et après chaque `act:load`, l'UI repart des défauts `newProfile()` hardcodés alors que le backend détient les vraies couleurs persistées par slot. Désync sur **tous** les color pickers (box, skel, model, name, weapon, dist, armor, hptext, crouch, aim, boxFill, modelFill, states), pas seulement fillColor. L'utilisateur voit une couleur, le rendu en applique une autre, jusqu'à ce qu'il redragge le picker — et le prochain reload remet la désync. Correctif = boucle de lecture `config.colors[idx]` → chaque swatch mappé par `COLOR_INDEX.el` inverse, plus `config.colors_occluded[idx]` → variante `w`. Attention à ne pas écraser une édition en cours pendant que le state arrive.

## Deltas visuels non validés depuis le ban

Ban actif de 1824 j sur ROB RUN depuis cette session. Les patches ci-dessous compilent mais aucun n'a été vu tourner dans le jeu. Chaque ligne : commit, puis ce qu'il faut regarder précisément, phrase actionnable.

- **`1d73820` refactor couleur + seuils de fill.** Au prochain lancement, chaque élément (box, skel, chams, name, weapon, dist, armor, hptext, crouch, aim, HP bar) prend sa couleur du slot correspondant au lieu du rôle codé en dur. Vérifier qu'activer « Color » ou « Health drain » dans Fill box remplit effectivement la boîte, et que régler Flat/Textured sur model affiche le cham — avant `1d73820`, seul `box_fill >= 2` et `model_fill >= 2` dessinaient, les seuils corrects sont `>= 1`.

- **`6894998` fix inversion LOS.** Au prochain lancement, confirmer que le voile `color_occluded` s'applique aux joueurs bloqués par géométrie et plus aux visibles. Pendant les ~600 ms de cold start après changement de monde, aucun voile ne doit apparaître (fail-open sur `UNKNOWN`), c'est le bon comportement.

- **`a5e8f9f` cham véhicule par slot 16 + LOS.** Confirmer que la teinte du cham véhicule suit maintenant le color picker du model au lieu de l'ambre fixe. Vérifier aussi que l'alpha diminue (80 → 64) quand le véhicule est derrière un mur avec `los_dim` actif.

- **`923d91c` renormalisation d'alpha `mesh_highlight` + hpbar bg.** Vérification précise sur `mesh_highlight` : un cadavre doit afficher un cham plus transparent qu'un vivant, et un vivant occlus plus transparent qu'un vivant visible. Vérification précise sur la HP bar : barre de PV d'un cadavre, fond à alpha 48 contre 80 habituel, lisibilité à contrôler sur fond clair et sur fond sombre — c'est le seul site où la renormalisation peut poser un problème ergonomique (élément d'UI en espace écran, pas marqueur monde).

- **`c62001b` fail-closed outline predicate.** Pas de delta visuel actuel (les champs du profil restent à leur défaut `outline: "Off"`). Vérification = aucune, le bloc est inatteignable par construction. À revérifier si on ouvre jamais un vrai outline cham.

## Note de process

`CONTEXT.md` était absent de `main` au début de la passe cham. Les premières passes de slot ont été ouvertes à l'aveugle sur le seul diff visible, ce qui a laissé passer la divergence d'énumération LOS et le partage de slot 16 non documenté. Le fichier doit exister avant toute passe suivante. C'est la seule contrainte qui empêche la récidive.
