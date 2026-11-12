# Documentation de Cyward

Le [README](../README.md) du dépôt présente le projet et son démarrage rapide avec Docker. Le détail est ici.

**Comprendre**

| Document | Contenu |
|---|---|
| [Principe de fonctionnement](fonctionnement.md) | Les deux étages : détection temps réel en Rust, puis triage par le modèle de langage |
| [Les détecteurs](detecteurs.md) | Chaque détecteur réseau, les règles sur les logs, les sévérités, l'apprentissage du comportement normal |
| [Le modèle de langage](llm.md) | Le modèle par défaut, en changer, ce qui lui est envoyé, son indisponibilité |
| [Conception de l'apprentissage du comportement normal](conception-normalite.md) | Choix, garde-fous de validation humaine et limites de l'Isolation Forest |

**Installer et utiliser**

| Document | Contenu |
|---|---|
| [Installation](installation.md) | Prérequis, modèle, compilation, droits, et le détail du déploiement Docker |
| [Utilisation](utilisation.md) | Les commandes, le choix de l'interface, la bannière, l'analyse d'un pcap |
| [Configuration](configuration.md) | Toutes les sections du fichier TOML et leurs valeurs par défaut |
| [Le dashboard et l'API](dashboard-api.md) | L'interface web, les routes HTTP, le flux SSE, les types d'alerte |
| [Déploiement](deploiement.md) | Où placer l'agent dans le réseau, service systemd |
| [Exploitation](exploitation.md) | Réduire les faux positifs, dépannage |
| [Sécurité de l'agent](securite.md) | Comment l'agent se protège lui-même |
| [Limites et évolutions](limites.md) | Ce que Cyward ne fait pas, et les pistes |

**Contribuer**

| Document | Contenu |
|---|---|
| [Architecture du code](architecture.md) | Arborescence, composants, dépendances entre modules, design patterns |
| [Tests et simulation d'attaques](tests.md) | Tests unitaires, rejeu d'attaques simulées, tests en conditions réelles |
