---
name: revue
description: Revue de code de niveau senior pour Cyward, avec la grille propre au projet (justesse des détecteurs, performance du chemin critique, mémoire bornée, sécurité de l'agent et du dashboard, tests, commentaires, documentation). À utiliser quand on demande une revue, un review, une relecture, un audit de code, ou avant de valider une modification importante.
---

# Revue de code Cyward

Adopte la posture d'un développeur senior qui relit avant mise en production un outil de sécurité exposé à du trafic hostile. L'objectif est de trouver les vrais problèmes, pas de commenter le style.

## 1. Délimiter le périmètre

- Sans précision : les modifications non commitées (`git status`, `git diff`, et les fichiers non suivis).
- Sinon : les fichiers, le commit ou la branche indiqués.

Lire chaque fichier modifié **en entier**, ainsi que les appelants des fonctions modifiées : un changement local peut casser un invariant ailleurs.

## 2. Grille de revue

### Structure et conception (voir CLAUDE.md, « Structure et design patterns »)
- Chaque module garde une seule responsabilité. Le sens des dépendances correspond au tableau de CLAUDE.md : les producteurs d'alertes (`detect/`, `logs.rs`) n'importent jamais `llm` ni `web`, et inversement. Pour le contrôler :
  ```bash
  for f in src/detect.rs src/detect/*.rs src/logs.rs src/logs/*.rs src/llm.rs src/web.rs; do printf '%-22s ' $f; grep -v '^\s*//' $f | grep -oE '\b(alert|capture|config|stats|llm|web|logs|banner)::' | sort -u | tr '\n' ' '; echo; done
  ```
- La logique de décision reste pure (sans I/O), donc testable ; les I/O restent en bordure.
- Le changement réutilise les patterns en place (Strategy `Detector`, Builder `Alert`, façade `AlertSink`, Observer `broadcast`, pipeline par canaux, middleware, superviseur) plutôt qu'une mécanique parallèle.
- Une nouvelle détection est une nouvelle implémentation enregistrée, pas une série de cas ajoutés dans du code existant.
- Pas d'état global ni de singleton ; des enums plutôt que des chaînes ou des booléens magiques ; des fonctions courtes.
- Signaler aussi l'excès inverse : une abstraction sans second usage, une couche « au cas où », un pattern objet transposé qui complique le code Rust.

### Bonnes pratiques Rust (voir CLAUDE.md, « Bonnes pratiques Rust »)
- Erreurs propagées par `?` ; aucun `unwrap()`, `expect()`, `panic!` ni indexation non vérifiée hors des tests, sauf invariant garanti et commenté sur place.
- Emprunts plutôt que clones ; un `clone()` ou une allocation sur le chemin critique est justifié par un commentaire.
- Types qui excluent les états invalides (enums, `Option`), traits standard dérivés, visibilité minimale (`pub(crate)`, `pub(super)`).
- Aucun `unsafe` ; aucun verrou tenu à travers un `.await` ni pendant une I/O ; canaux bornés.
- Conventions de nommage Rust. Pas de reformatage par `cargo fmt` : le diff ne doit contenir que des changements voulus.

### Justesse de la détection
- Les détecteurs utilisent-ils uniquement le temps des paquets (`p.ts`, `now` de `tick`) ? Un `SystemTime::now()` dans `src/detect/` casse le rejeu.
- Les seuils sont-ils testés avec `==`, pour une seule alerte par fenêtre ? Avec `>=`, il y a une alerte par paquet.
- L'empreinte (`type|src|dst` ou `.fingerprint()`) fusionne-t-elle les bonnes répétitions, ni trop ni trop peu ?
- Les fenêtres se réinitialisent-elles correctement ? Bornes `<` / `<=`, unités (secondes en `f64` côté réseau, `chrono::Duration` côté logs).
- Interne / externe : `is_local` est-il appliqué à la bonne adresse (source ou destination) ?

### Performance du chemin critique
- `on_packet` est appelé pour chaque paquet : filtrage précoce, pas d'allocation (`String`, `Vec`, `format!`) dans le cas courant, pas de verrou.
- La capture ne doit jamais bloquer (`try_send`) ; le rejeu peut attendre (`send().await`).
- Aucun appel réseau ou LLM ne doit être synchrone avec la détection.

### Mémoire bornée
- Tout nouvel état (`HashMap`, `VecDeque`, `HashSet`) est-il purgé dans `tick` ou plafonné ?
- Un attaquant peut-il le faire grossir sans limite (adresses usurpées, noms DNS aléatoires, comptes inventés) ?

### Sécurité
- **Dashboard** : aucune donnée d'alerte insérée via `innerHTML`. Tout passe par `el()` (textContent).
- **Jeton** : comparé en temps constant, jamais affiché (bannière, logs, alertes).
- **Entrées hostiles** : paquets tronqués ou malformés (le parsing renvoie `None`, jamais de `panic`, d'`unwrap()` ou d'indexation sans vérification) ; lignes de logs piégées.
- **Prompt injection** : le texte des preuves vient potentiellement d'un attaquant. Le verdict du LLM ne doit jamais modifier la sévérité calculée ni déclencher d'action automatique.
- **Privilèges** : rien qui demande plus que `CAP_NET_RAW`/`CAP_NET_ADMIN`. Pas d'écriture disque inattendue, l'image Docker est en lecture seule.
- **Commandes externes** : arguments passés en liste, jamais via un shell.

### Robustesse
- Erreurs propagées avec contexte (`anyhow::Context`), messages en français qui disent quoi faire.
- Une tâche qui échoue (web, logs, LLM) ne doit pas arrêter la détection.

### Tests et commentaires (règles obligatoires de CLAUDE.md)
- Chaque comportement nouveau ou corrigé a un test positif **et** un test négatif. Une correction de bug a un test qui reproduisait le bug.
- Les commentaires sont en français, expliquent le *pourquoi*, et ne décrivent pas ce qui a changé.
- Piège clap : un `///` sur `Cli`/`Command` apparaît dans `--help`.

### Documentation
- `docs/architecture.md` : l'arborescence, les composants, le tableau des dépendances entre modules et celui des design patterns reflètent-ils le code après la modification ? Un nouveau fichier, une nouvelle dépendance ou un nouveau pattern sans mise à jour de ce document est **bloquant** (règle de CLAUDE.md).
- Le tableau des dépendances de CLAUDE.md est-il cohérent avec celui de `docs/architecture.md` (mêmes modules, mêmes dépendances) ?
- `docs/` (`detecteurs.md`, `configuration.md`, `dashboard-api.md`, `tests.md`), la liste « Fonctionnalités » du README, `config.example.toml` et CLAUDE.md sont-ils à jour (nouveaux détecteurs, clés de configuration, types d'alerte, nombre d'alertes du rejeu) ? Une documentation ajoutée au README au lieu de `docs/` est à déplacer.

## 3. Vérifier, puis rapporter

1. Lancer `.claude/skills/verifier/check.sh` et inclure son résultat.
2. Pour chaque problème suspecté, le confirmer : relire le code, écrire si possible un test ou un cas qui le déclenche. Ne rapporter que ce qui est confirmé ou très probable, en le précisant.
3. Rapport, du plus grave au moins grave :

```
### [Bloquant | Important | Mineur] Titre court
`fichier.rs:ligne` — Ce qui ne va pas, en une phrase.
Scénario : entrée ou situation concrète → conséquence.
Correction proposée : …
```

Terminer par un verdict en une ligne (« prêt à fusionner », « à corriger avant fusion »…) et ce qui n'a pas pu être vérifié (capture live, LLM réel, dashboard). Ne pas modifier le code pendant la revue, sauf si on le demande.
