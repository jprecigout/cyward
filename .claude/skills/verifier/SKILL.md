---
name: verifier
description: Vérifie que Cyward est en état d'être livré (compilation, clippy sans avertissement, tests, en-têtes de commentaires, rejeu des attaques simulées, image Docker en option). À utiliser avant de déclarer une tâche terminée, avant un commit, ou quand on demande de vérifier, tester, valider, check ou verify le projet.
---

# Vérifier Cyward

Lance le script de vérification depuis la racine du dépôt :

```bash
.claude/skills/verifier/check.sh
```

Il enchaîne, et s'arrête à la première étape en échec (code de sortie non nul) :

1. **En-têtes `//!`** : chaque fichier de `src/` et `examples/` doit commencer par un commentaire de module (règle de CLAUDE.md).
2. **Compilation** de tout le projet, exemples compris.
3. **Clippy** en `-D warnings` : un seul avertissement suffit à échouer.
4. **Tests unitaires** (`cargo test`).
5. **Rejeu de bout en bout** : génère le pcap de `examples/gen_attacks.rs`, le rejoue, et exige **exactement** les alertes listées dans `EXPECTED_TITLES` en haut du script, sans aucune en trop. Une alerte manquante = régression de détection ; une alerte en trop = faux positif sur le trafic normal.

Ajoute `--docker` pour construire aussi l'image et y rejouer le pcap :

```bash
.claude/skills/verifier/check.sh --docker
```

## Quand l'utiliser

- Avant d'annoncer qu'une modification est terminée : c'est la preuve que les règles « commenté et testé » de CLAUDE.md sont respectées.
- Après tout changement dans `src/detect/`, `src/logs.rs`, `src/logs/` ou `examples/gen_attacks.rs`.
- `--docker` seulement si le `Dockerfile`, `compose.yaml`, `docker/` ou les dépendances (`Cargo.toml`) ont changé : la construction prend plusieurs minutes.

## Lire un échec

| Message | Cause probable |
|---|---|
| `fichiers sans en-tête //!` | Nouveau fichier Rust sans commentaire de module |
| erreur clippy | Corriger le code ; ne pas ajouter de `#[allow]` sans justification en commentaire |
| `N alerte(s) au lieu de M` | Un détecteur ne déclenche plus (régression) ou déclenche sur le trafic normal (faux positif). Comparer le bilan affiché avec `EXPECTED_TITLES` |
| `alerte attendue absente : « … »` | Le titre d'une alerte a changé, ou son détecteur ne déclenche plus |

Si un nouveau scénario est ajouté au générateur, ajouter la sous-chaîne de son titre dans `EXPECTED_TITLES` (et mettre à jour le nombre d'alertes cité dans CLAUDE.md et `docs/tests.md`).

## Limites

Le script ne vérifie ni la capture live (il faut `setcap`), ni l'analyse par le LLM (il faut Ollama et le modèle), ni l'affichage du dashboard. Pour ces parties, voir les commandes de CLAUDE.md et vérifier à la main.
