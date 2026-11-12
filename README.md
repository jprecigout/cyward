<p align="center">
  <img src="assets/logo-wordmark.svg" alt="Cyward — détection d'intrusions" width="520">
</p>

# Cyward

**Cyward** est un agent de détection d'intrusions écrit en Rust. On l'installe sur une machine du réseau à protéger. Il observe le trafic réseau et les journaux système, lève des alertes en temps réel quand il repère une attaque ou un comportement anormal, puis fait analyser chaque alerte importante par un **modèle de langage open source spécialisé en cybersécurité**, exécuté en local.

Tout reste sur ta machine : aucune donnée réseau ni aucun log ne part vers un service externe.

---

## Fonctionnalités

**Détection en temps réel sur le trafic réseau** (capture `AF_PACKET`, sans libpcap) :
- scan de ports et balayage du réseau, plus sévère quand il vient de l'intérieur (mouvement latéral) ;
- force brute sur les services réseau (SSH, RDP, bases de données…) ;
- inondation SYN ;
- balise périodique vers un serveur de commande et contrôle (C2) ;
- volume sortant anormal, signe d'exfiltration ;
- DNS suspect et tunnel DNS ;
- trafic avec des adresses présentes dans des listes de menaces ;
- usurpation ARP (homme du milieu), plus sévère pour les adresses protégées (passerelle, DNS…).

**Détection sur les journaux système** (journald ou fichiers) : force brute SSH et connexion réussie après des échecs, échecs `sudo`/`su`, création de comptes et ajout à un groupe privilégié, et règles personnalisées par expression régulière dans la configuration.

**Apprentissage du comportement normal** (optionnel) : un Isolation Forest apprend l'activité habituelle de chaque machine interne et signale les écarts. Rien n'entre dans le comportement normal sans validation humaine.

**Triage par un modèle de langage local** : chaque alerte importante est analysée par [Foundation-Sec-8B-Instruct](https://huggingface.co/fdtn-ai/Foundation-Sec-8B-Instruct), via Ollama ou tout serveur compatible OpenAI. Il donne un verdict (malveillant, suspect, bénin), une confiance, une explication, les techniques MITRE ATT&CK et des recommandations. Le modèle n'est jamais sur le chemin critique : la détection continue s'il est hors ligne.

**Dashboard web** : alertes en direct, filtres, détail des preuves et de l'analyse IA, noms des machines, onglet « Flux » qui anime le trafic en temps réel. Une seule page embarquée dans le binaire, sans dépendance externe, protégeable par jeton. Une API JSON et un flux SSE permettent de brancher un SIEM.

**Et aussi** : notifications sur le téléphone (ntfy) ou par webhook, historique des alertes en SQLite, dédoublonnage des alertes répétées, rejeu de captures pcap pour analyser du trafic enregistré ailleurs.

---

## Lancer avec Docker (Linux)

Prérequis : Docker avec le plugin Compose, 8 Go de RAM libre et environ 6 Go de disque pour le modèle.

```bash
docker compose up -d --build
```
```bash
docker compose logs -f cyward
```

Le premier lancement télécharge environ 5 Go de modèle. Le dashboard est ensuite sur `http://127.0.0.1:8080`.

Pour lancer l'agent seul, sans Ollama ni téléchargement du modèle (les alertes restent en attente de triage) :

```bash
docker compose run --rm --no-deps cyward
```

Pour analyser une capture pcap avec l'image :

```bash
docker run --rm -v "$PWD:/data:ro" cyward:latest replay /data/capture.pcap
```

La configuration du conteneur est [`docker/cyward.toml`](docker/cyward.toml). Les choix du déploiement Docker (réseau de l'hôte, droits minimaux, secrets, GPU, changement de modèle) sont détaillés dans [Installation](docs/installation.md#avec-docker-linux). Pour une installation sans Docker, voir [Installation](docs/installation.md).

**Important :** l'agent ne voit que le trafic qui arrive sur son interface. Pour surveiller tout un réseau, voir [Où déployer l'agent](docs/deploiement.md).

---

## Documentation

Toute la documentation détaillée est dans [`docs/`](docs/README.md) : fonctionnement, détecteurs, modèle de langage, installation, utilisation, configuration, dashboard et API, déploiement, exploitation, sécurité, limites, architecture du code et tests.

---

## Licence

Cyward est distribué sous la **licence Apache 2.0**. Le texte complet est dans le fichier [`LICENSE`](LICENSE).

En résumé, tu peux utiliser, modifier et redistribuer le code, y compris dans un produit commercial ou fermé, à condition de :
- joindre une copie de la licence ;
- signaler les fichiers que tu as modifiés ;
- conserver les mentions de droits d'auteur existantes.

La licence accorde aussi une licence sur les brevets éventuels des contributeurs. Le logiciel est fourni « tel quel », sans garantie.

**Ce que la licence ne couvre pas :**
- **Le modèle Foundation-Sec-8B-Instruct** : il n'est pas inclus dans ce dépôt et a sa propre licence, à consulter sur sa [fiche Hugging Face](https://huggingface.co/fdtn-ai/Foundation-Sec-8B-Instruct).
- **Les dépendances Rust** : chacune garde sa licence. Toutes sont permissives et compatibles avec Apache 2.0 (MIT, Apache-2.0, BSD, ISC, Zlib, Unicode-3.0, CDLA-Permissive-2.0). Pour les lister :
  ```bash
  cargo metadata --format-version 1 | jq -r '.packages[] | "\(.name) \(.license)"'
  ```
- **L'image Docker** : elle contient des paquets Debian (dont `systemd`) distribués sous leurs propres licences.
