# Cyward

**Cyward** est un agent de détection d'intrusions écrit en Rust. On l'installe sur une machine du réseau à protéger. Il observe le trafic réseau et les journaux système, lève des alertes en temps réel quand il repère une attaque ou un comportement anormal, puis fait analyser chaque alerte importante par un **modèle de langage open source spécialisé en cybersécurité**, exécuté en local.

Tout reste sur ta machine : aucune donnée réseau ni aucun log ne part vers un service externe.

---

## Sommaire

1. [Principe de fonctionnement](#1-principe-de-fonctionnement)
2. [Architecture du code](#2-architecture-du-code)
3. [Les détecteurs en détail](#3-les-détecteurs-en-détail)
4. [Le modèle de langage (triage IA)](#4-le-modèle-de-langage-triage-ia)
5. [Installation](#5-installation)
6. [Utilisation](#6-utilisation)
7. [Configuration complète](#7-configuration-complète)
8. [Le dashboard et l'API](#8-le-dashboard-et-lapi)
9. [Où déployer l'agent dans le réseau](#9-où-déployer-lagent-dans-le-réseau)
10. [Lancer l'agent comme service systemd](#10-lancer-lagent-comme-service-systemd)
11. [Tests et simulation d'attaques](#11-tests-et-simulation-dattaques)
12. [Réduire les faux positifs](#12-réduire-les-faux-positifs)
13. [Dépannage](#13-dépannage)
14. [Sécurité de l'agent lui-même](#14-sécurité-de-lagent-lui-même)
15. [Limites connues](#15-limites-connues)
16. [Pistes d'évolution](#16-pistes-dévolution)

---

## 1. Principe de fonctionnement

```
                    ┌─────────────────────────── Cyward ───────────────────────────┐
                    │                                                              │
 interface réseau ──┼─► capture AF_PACKET ─► parsing ─► détecteurs réseau ──┐      │
  (ou fichier pcap) │      (thread dédié)    (etherparse)  (scan, C2, DNS…)  │      │
                    │                                                      ▼      │
 journald ──────────┼─► journalctl -f ─┐                               AlertSink   │
 /var/log/*.log ────┼─► tail -F ───────┴─► règles de logs ──────────────►  │      │
                    │                      (SSH, sudo, comptes…)            │      │
                    │                                                      ▼      │
                    │                                   AlertStore (dédoublonnage)│
                    │                                     │               │       │
                    │                    alerte ≥ seuil   │               │ SSE   │
                    │                                     ▼               ▼       │
                    │                            file de triage     dashboard web │
                    │                                     │          (axum)       │
                    └─────────────────────────────────────┼───────────────────────┘
                                                          ▼
                                       LLM cyber local (Ollama, llama.cpp, vLLM…)
                                       → verdict, explication, MITRE ATT&CK, actions
```

Le système fonctionne en deux étages.

**Étage 1 : détection rapide, en Rust.** Chaque paquet est réduit à ses métadonnées : adresses, ports, drapeaux TCP, taille et nom DNS demandé. Le contenu n'est jamais conservé. Des détecteurs statistiques et à seuils traitent ces métadonnées au fil de l'eau. En parallèle, les journaux système sont lus en continu et comparés à des règles. Cet étage traite des dizaines de milliers de paquets par seconde sur un CPU ordinaire.

**Étage 2 : analyse par un modèle de langage.** Les alertes dont la sévérité dépasse un seuil, `medium` par défaut, sont envoyées une par une au modèle. Il reçoit l'alerte, ses preuves et les autres alertes récentes impliquant les mêmes adresses. Il renvoie :

- un verdict : malveillant, suspect ou bénin ;
- un indice de confiance ;
- une explication en langage clair ;
- les techniques MITRE ATT&CK correspondantes ;
- des recommandations concrètes.

**Pourquoi ne pas tout envoyer au modèle ?** Un modèle de 8 milliards de paramètres sur CPU produit quelques mots par seconde. Il ne peut pas suivre un flux de paquets. En revanche, il excelle à contextualiser une alerte déjà isolée : faire le lien entre un scan et une force brute venant de la même IP, distinguer une sauvegarde nocturne d'une exfiltration, proposer une réponse. La détection reste donc temps réel, et l'IA apporte le jugement.

---

## 2. Architecture du code

```
cyward/
├── Cargo.toml
├── config.example.toml        # configuration commentée, toutes valeurs par défaut
├── assets/
│   └── index.html             # dashboard (embarqué dans le binaire à la compilation)
├── examples/
│   └── gen_attacks.rs         # générateur de pcap d'attaques simulées
└── src/
    ├── main.rs                # CLI, assemblage des tâches, boucle du moteur
    ├── config.rs              # structures de configuration (TOML + valeurs par défaut)
    ├── alert.rs               # modèle d'alerte, AlertStore, AlertSink
    ├── stats.rs               # compteurs exposés au dashboard
    ├── capture.rs             # capture live, rejeu pcap, parsing des paquets et du DNS
    ├── detect/
    │   ├── mod.rs             # trait Detector et moteur
    │   ├── scan.rs            # scan de ports, balayage, force brute réseau, inondation SYN
    │   ├── beacon.rs          # balises périodiques (C2)
    │   ├── volume.rs          # volume sortant anormal (exfiltration)
    │   └── dns.rs             # DNS à forte entropie, tunnel DNS
    ├── logs.rs                # sources de logs et règles d'analyse
    ├── llm.rs                 # client du modèle, prompt, parsing de la réponse
    └── web.rs                 # serveur HTTP, API JSON, flux SSE, authentification
```

### Les composants

**`capture.rs`**
- **Capture live** : utilise `pnet_datalink`, qui ouvre une socket `AF_PACKET`. Cette crate est en pur Rust, sans dépendance à libpcap. La lecture tourne dans un thread dédié et envoie des `PacketMeta` au moteur par un canal borné (`capture.queue_size`). Si le moteur ne suit pas, les paquets sont abandonnés plutôt que de bloquer la capture, et le compteur « Perdus » augmente.
- **Rejeu** : lit un fichier pcap classique avec `pcap-file`. Les types de lien gérés sont Ethernet, Linux SLL (`tcpdump -i any`) et IP brut.
- **Parsing** : assuré par `etherparse` ; la question DNS est extraite à la main.

**`detect/`**
- Chaque détecteur implémente :
  ```rust
  trait Detector {
      fn on_packet(&mut self, p: &PacketMeta, out: &mut Vec<Alert>);
      fn tick(&mut self, now: f64, out: &mut Vec<Alert>);   // ~1 fois par seconde
  }
  ```
- Les détecteurs raisonnent sur **l'horodatage des paquets**, pas sur l'horloge murale. Le rejeu d'un pcap donne donc exactement les mêmes résultats que la capture d'origine.
- `tick` sert à clore des fenêtres de temps et à purger l'état ancien, ce qui borne la mémoire.
- Les IP de la `whitelist` sont ignorées en tant que source.

**`logs.rs`**
- Lance `journalctl -f -o json` et/ou `tail -F` sur les fichiers configurés, et relance la commande si elle s'arrête.
- Le `LogAnalyzer` applique des expressions régulières et garde, par IP, l'historique des échecs d'authentification.

**`alert.rs`**
- **`AlertSink`** est le point d'entrée unique des détecteurs. Il enregistre l'alerte et l'envoie en triage IA si sa sévérité le justifie.
- **`AlertStore`** garde les 5 000 dernières alertes en mémoire.
- Il **dédoublonne** les alertes selon une empreinte (type + source + cible). Une alerte identique pendant `alert_cooldown_secs` incrémente le compteur `count` de l'alerte existante au lieu d'en créer une nouvelle.
- Chaque création ou mise à jour est diffusée aux navigateurs connectés.

**`llm.rs`**
- Une tâche de fond vérifie toutes les 30 s que le serveur répond et que le modèle est installé.
- Une autre tâche consomme la file de triage, une alerte à la fois.

**`web.rs`**
- Serveur `axum`. Il sert le dashboard, une API JSON et un flux Server-Sent Events pour les mises à jour en direct.

---

## 3. Les détecteurs en détail

Chaque seuil cité est modifiable dans la configuration (section 7).

### 3.1 Scan de ports et balayage (`PortScan`)

**Ce qu'il repère :** la reconnaissance, première étape de presque toute attaque.

**Fonctionnement :**
- Le détecteur ne regarde que les **ouvertures de connexion TCP** (paquet SYN sans ACK).
- Pour chaque IP source, il tient une fenêtre de `window_secs` (60 s) contenant :
  - les **ports distincts** visés sur chaque hôte : au-delà de `ports_threshold` (25), c'est un **scan vertical** (`port_scan`) ;
  - les **hôtes distincts** visés sur chaque port : au-delà de `hosts_threshold` (20), c'est un **balayage horizontal** (`host_sweep`), typique d'un ver ou de la recherche de SMB ouverts.

**Sévérité :**
- **Haute** si la source est interne : une machine de ton réseau qui en scanne d'autres est un signe classique de **mouvement latéral** après une compromission.
- **Moyenne** si la source est externe : les scans venant d'Internet sont permanents.

**MITRE :** T1046 (Network Service Discovery).

### 3.2 Force brute réseau (`BruteForce`)

**Ce qu'il repère :** les essais de mots de passe en rafale sur un service d'authentification.

**Fonctionnement :**
- Le détecteur compte les nouvelles connexions TCP par triplet (source, destination, port), pour les ports listés dans `bruteforce.ports` : SSH, RDP, SMB, FTP, Telnet, SMTP, IMAP, POP3, MySQL, PostgreSQL, MSSQL, VNC, Redis.
- Au-delà de `threshold` (20) connexions en `window_secs` (60 s), il lève une alerte **haute**.
- Il fonctionne même si le service est chiffré : seul le rythme des connexions compte.

**MITRE :** T1110 (Brute Force).

### 3.3 Inondation SYN (`SynFlood`)

**Ce qu'il repère :** un déni de service qui sature la table de connexions d'un serveur.

**Fonctionnement :**
- Le détecteur compte les SYN reçus par chaque destination.
- Au-delà de `threshold` (3 000) en `window_secs` (10 s), il lève une alerte **haute**.
- Il compte aussi les sources distinctes. Au-delà de 50, l'alerte précise qu'il s'agit probablement d'une attaque distribuée ou d'adresses usurpées.

**MITRE :** T1498/T1499 (Network/Endpoint Denial of Service).

### 3.4 Balise périodique (`Beaconing`)

**Ce qu'il repère :** un implant (cheval de Troie, agent Cobalt Strike…) qui contacte régulièrement son **serveur de commande et contrôle (C2)** pour recevoir des ordres.

**Fonctionnement :**
- Seules les connexions **d'un hôte interne vers l'extérieur** sont suivies, par triplet (source, destination, port).
- Le détecteur garde les `min_samples + 1` (9) dernières dates d'ouverture de connexion.
- Il calcule les intervalles entre ces dates, leur moyenne, et leur **coefficient de variation** (écart-type ÷ moyenne).
- Si la moyenne est ≥ `min_interval_secs` (5 s) et la variation ≤ `max_jitter` (12 %), le rythme est jugé trop régulier pour un humain : alerte **moyenne**.
- Les SYN à moins d'une seconde d'écart sont ignorés : ce sont des retransmissions ou des connexions parallèles.
- Tant que la balise continue, l'alerte est ré-émise. Le store la fusionne et son compteur augmente.

**Faux positifs fréquents :** mises à jour automatiques, sondes de supervision, synchronisation cloud, NTP. C'est précisément le cas où le triage IA aide à trier. Les ports de `ignore_ports` (53, 123, 5353) sont exclus.

**MITRE :** T1071 (Application Layer Protocol), T1573 (Encrypted Channel).

### 3.5 Volume sortant anormal (`Volume`)

**Ce qu'il repère :** l'**exfiltration** de données, c'est-à-dire un poste qui envoie soudain beaucoup plus de données vers Internet que d'habitude.

**Fonctionnement :**
- Le détecteur compte les octets envoyés par chaque hôte interne vers l'extérieur, par période de `bucket_secs` (60 s).
- Pour chaque hôte, il apprend une **moyenne et une variance mobiles exponentielles** (EWMA, α = 0,1). La normale s'adapte donc lentement aux usages.
- Après `warmup_buckets` (15) périodes d'apprentissage, il calcule le **score z** de chaque période : (volume − moyenne) ÷ écart-type.
- Il lève une alerte **haute** si le score z dépasse `zscore` (4) **et** si le volume dépasse `min_bytes` (50 Mo). Le second critère évite d'alerter pour un hôte habituellement silencieux qui envoie 2 Mo.
- L'écart-type est borné vers le bas (25 % de la moyenne, ou 1 Mo au minimum). Sans ce plancher, un hôte très régulier déclencherait au moindre écart.
- Les périodes sans trafic comptent comme des zéros dans la normale.

**MITRE :** T1041 (Exfiltration Over C2 Channel), T1567 (Exfiltration Over Web Service).

### 3.6 DNS suspect et tunnel DNS (`Dns`)

**Ce qu'il repère :** deux abus du DNS, qui traverse presque tous les pare-feux.

**1. Nom suspect** (alerte **moyenne**). Le nom demandé dépasse `max_name_len` (80 caractères), **ou** son plus long segment fait au moins `min_label_len` (25 caractères) avec une **entropie de Shannon** ≥ `entropy_threshold` (3,8 bits/caractère).
- Un nom lisible comme `wikipedia` a une entropie faible.
- Une chaîne aléatoire ou encodée en base32/base64 a une entropie élevée.
- C'est la signature des domaines générés par algorithme (DGA) des botnets, et des données encodées dans les requêtes.

**2. Tunnel DNS** (alerte **haute**). Un même hôte demande plus de `unique_subdomains_threshold` (150) **sous-domaines différents** d'un même domaine en `window_secs` (300 s). Exemple : `a1f3.d.exfil.net`, `b7c2.d.exfil.net`… Chaque requête transporte un morceau de données vers le serveur DNS de l'attaquant.

**Détails :**
- Les suffixes de `ignore_suffixes` ne sont jamais analysés : résolution inverse `in-addr.arpa`/`ip6.arpa` et mDNS `.local`.
- Le « domaine » est pris naïvement comme les deux derniers segments (voir les limites).

**MITRE :** T1071.004 (DNS), T1568.002 (Domain Generation Algorithms), T1048 (Exfiltration Over Alternative Protocol).

### 3.7 Règles sur les journaux système (`LogAnalyzer`)

| Règle | Exemple de ligne | Alerte |
|---|---|---|
| Échecs SSH répétés | `Failed password for invalid user admin from 203.0.113.4` | `failures_threshold` (6) échecs de la même IP en `window_secs` (300 s) → **Haute** `auth_brute_force` |
| Connexion réussie après échecs | `Accepted password for root from 203.0.113.4` | si la même IP a eu au moins la moitié du seuil (3) en échecs récents → **Critique** `auth_compromise` : le mot de passe a peut-être été trouvé |
| sudo non autorisé | `bob : user NOT in sudoers ; …` | **Haute** `privilege_escalation` |
| Mauvais mot de passe sudo | `bob : 3 incorrect password attempts ; …` | **Moyenne** |
| Échec de `su` | `pam_unix(su:auth): authentication failure … ruser=bob` | **Basse** |
| Création de compte | `new user: name=backdoor, UID=1001 …` | **Moyenne** `account_change` (persistance possible) |
| Ajout à un groupe privilégié | `add 'backdoor' to group 'sudo'` (aussi `wheel`, `admin`, `root`, `docker`, `lxd`) | **Haute** |
| Inondation SYN vue par le noyau | `Possible SYN flooding on port 80` | **Moyenne** |
| Règles personnalisées | ce que tu veux | sévérité choisie |

`sshd` écrit `Invalid user X from IP` **puis** `Failed password for invalid user X from IP` pour une même tentative. Seule la seconde ligne compte comme un échec ; la première sert à lister les comptes essayés, ce qui évite de compter double.

**Règles personnalisées.** Elles se déclarent dans la configuration. Un groupe nommé `ip` dans la regex devient la source de l'alerte :

```toml
[[detection.custom_log_rules]]
name = "wordpress-login"
pattern = '(?P<ip>\d+\.\d+\.\d+\.\d+) .*"POST /wp-login\.php'
severity = "low"
title = "Tentative de connexion WordPress"
```

Pour qu'une règle s'applique aux logs d'une application (nginx, Apache…), ajoute son fichier dans `logs.files`.

### 3.8 Sévérités

| Niveau | Sens | Envoyé au LLM par défaut |
|---|---|---|
| `critical` | Compromission probable, agir immédiatement | oui |
| `high` | Attaque caractérisée | oui |
| `medium` | Comportement suspect à qualifier | oui |
| `low` | Signal faible, utile en corrélation | non |
| `info` | Information | non |

---

## 4. Le modèle de langage (triage IA)

### 4.1 Le modèle par défaut : Foundation-Sec-8B-Instruct

[Foundation-Sec-8B-Instruct](https://huggingface.co/fdtn-ai/Foundation-Sec-8B-Instruct) est un modèle publié en open weights par **Cisco Foundation AI**. Il est construit sur **Llama 3.1 8B**, pré-entraîné sur un large corpus de cybersécurité (CVE, rapports de menaces, MITRE ATT&CK, documentation d'outils de sécurité), puis ajusté pour suivre des instructions. Il est donc plus pertinent qu'un modèle généraliste de même taille pour qualifier une alerte et citer les bonnes techniques ATT&CK.

Cyward utilise par défaut une **quantification Q4_K_M au format GGUF**, publiée par mradermacher sur Hugging Face :

| | |
|---|---|
| Taille sur disque | ~5 Go |
| RAM nécessaire | ~6 à 8 Go |
| GPU | facultatif (NVIDIA, AMD ou Apple accélèrent fortement) |
| Durée d'une analyse sur CPU 8–12 cœurs | ~20 à 90 s |
| Durée avec GPU | quelques secondes |

Licence : consulte la fiche Hugging Face du modèle avant un usage commercial. Cisco recommande de l'utiliser avec une supervision humaine.

### 4.2 Utiliser un autre modèle ou un autre serveur

Cyward parle l'**API compatible OpenAI** (`POST /v1/chat/completions`, `GET /v1/models`). Tout serveur qui l'expose fonctionne : il suffit de changer `llm.base_url` et `llm.model`.

| Serveur | `base_url` | Exemple de `model` |
|---|---|---|
| Ollama | `http://127.0.0.1:11434/v1` | `hf.co/mradermacher/Foundation-Sec-8B-Instruct-GGUF:Q4_K_M` |
| llama.cpp (`llama-server -m modele.gguf`) | `http://127.0.0.1:8080/v1` | nom du fichier chargé |
| vLLM | `http://127.0.0.1:8000/v1` | `fdtn-ai/Foundation-Sec-8B-Instruct` |

Si le serveur exige une clé, renseigne `llm.api_key` : elle est envoyée en `Authorization: Bearer`. Attention : avec llama.cpp sur le port 8080, déplace le dashboard ailleurs (`web.listen`).

D'autres modèles orientés sécurité peuvent convenir, comme d'autres versions de Foundation-Sec ou les modèles Llama-Primus de Trend Micro. Un modèle généraliste récent marche aussi, avec des analyses moins précises sur le vocabulaire sécurité.

### 4.3 Ce qui est envoyé au modèle

**Le message système** fixe le rôle et le format de réponse : analyste SOC niveau 3, réponse uniquement en JSON, ne rien supposer qui ne figure pas dans les données, réponse dans la langue de `llm.language`.

**Le message utilisateur** contient :
- l'alerte (type, sévérité, origine, titre, description, source, cible, nombre d'occurrences, dates, preuves) ;
- jusqu'à 8 autres alertes récentes impliquant les mêmes adresses. Par exemple, une force brute SSH précédée d'un scan venant de la même IP : le modèle peut alors relier les deux.

**Réglages de génération :** température 0,1 pour des réponses stables, 700 tokens au maximum, `response_format: json_object`.

**Réponse attendue :**

```json
{
  "verdict": "malveillant",
  "confidence": 0.9,
  "summary": "203.0.113.4 a ouvert une session root après 14 échecs : le mot de passe a très probablement été deviné par force brute.",
  "mitre": ["T1110.001", "T1078"],
  "recommendations": [
    "Couper immédiatement la session et bloquer 203.0.113.4 au pare-feu",
    "Changer le mot de passe root et interdire PermitRootLogin dans sshd_config",
    "Examiner l'historique de commandes et les crontabs pour une persistance"
  ]
}
```

Les petits modèles enrobent parfois le JSON dans du texte ou des balises ```` ``` ````. Le parseur extrait l'objet entre la première `{` et la dernière `}`. Il accepte aussi une confiance exprimée en pourcentage (`"85%"`) et un champ `mitre` en chaîne simple.

### 4.4 Comportement en cas d'indisponibilité

- Si le serveur est injoignable ou si le modèle n'est pas installé, un avertissement apparaît dans les logs de l'agent. La pastille « IA » du dashboard passe à « hors ligne ».
- Les alertes restent **en attente** et sont analysées dès le retour du modèle. Elles ne sont jamais marquées en échec pour cette raison.
- La file contient au plus `llm.queue_size` (32) alertes. Au-delà, les nouvelles alertes ne sont pas analysées, mais elles restent visibles.
- Une erreur pendant l'analyse (délai dépassé, JSON illisible) marque l'alerte « IA en échec ».
- La détection n'est jamais ralentie par le modèle.

---

## 5. Installation

### 5.1 Prérequis

- Linux (la capture utilise `AF_PACKET`, les logs utilisent `journalctl` ou `tail`).
- Rust 1.88 ou plus récent (édition 2024). Installation : `curl https://sh.rustup.rs -sSf | sh`.
- Pour le modèle : 8 Go de RAM libre et ~6 Go de disque.

Aucune bibliothèque système n'est nécessaire : ni libpcap, ni OpenSSL.

### 5.2 Le modèle

```bash
curl -fsSL https://ollama.com/install.sh | sh
```
```bash
ollama pull hf.co/mradermacher/Foundation-Sec-8B-Instruct-GGUF:Q4_K_M
```

Pour vérifier que le modèle répond :

```bash
ollama run hf.co/mradermacher/Foundation-Sec-8B-Instruct-GGUF:Q4_K_M "Qu'est-ce que la technique MITRE T1110 ?"
```

### 5.3 L'agent

```bash
cargo build --release
```
```bash
cp config.example.toml cyward.toml
```

**Droits de capture.** Pour éviter de lancer l'agent en root, donne-lui uniquement la capacité de capturer le trafic. Cette commande est à refaire après chaque recompilation :

```bash
sudo setcap cap_net_raw,cap_net_admin=eip target/release/cyward
```

**Droits de lecture du journal systemd.** Il faut se déconnecter puis se reconnecter pour que le groupe soit pris en compte :

```bash
sudo usermod -aG systemd-journal $USER
```

**Vérifier que tout est en place :**

```bash
./target/release/cyward -c cyward.toml check-llm
```

Cette commande soumet au modèle une alerte d'exemple et affiche son analyse.

### 5.4 Avec Docker (Linux)

[`compose.yaml`](compose.yaml) lance trois services :

| Service | Rôle |
|---|---|
| `ollama` | Serveur du modèle, port publié sur `127.0.0.1:11434`, modèles dans le volume `ollama` |
| `ollama-pull` | Télécharge le modèle s'il est absent, puis s'arrête |
| `cyward` | L'agent, construit depuis le [`Dockerfile`](Dockerfile) (image d'environ 105 Mo) |

```bash
docker compose up -d --build
```
```bash
docker compose logs -f cyward
```

Le premier lancement télécharge environ 5 Go de modèle. Le dashboard est ensuite sur `http://127.0.0.1:8080`.

**Choix de conception :**
- **Réseau de l'hôte (`network_mode: host`)** : sans lui, le conteneur ne verrait que son propre réseau virtuel. En contrepartie, `127.0.0.1` dans le conteneur désigne l'hôte : c'est ainsi que Cyward joint Ollama (port publié) et que le dashboard reste sur le localhost de l'hôte. Ce mode n'a pas le même sens sous Docker Desktop (macOS, Windows) : la capture n'y verra pas le réseau réel.
- **Droits minimaux** : toutes les capacités sont retirées sauf `NET_RAW` et `NET_ADMIN`. S'y ajoutent `no-new-privileges` et un système de fichiers en lecture seule.
- **Logs de l'hôte** : `/var/log/journal` et `/etc/machine-id` sont montés en lecture seule. Le `machine-id` permet à `journalctl` de reconnaître le journal de l'hôte comme le sien. Les systèmes sans journal persistant (pas de `/var/log/journal`) ne sont pas couverts.
- **Configuration** : [`docker/cyward.toml`](docker/cyward.toml), monté dans `/etc/cyward/cyward.toml`. Une modification se prend en compte avec `docker compose restart cyward`.
- **Modèle** : pour en changer, modifie `llm.model` dans `docker/cyward.toml` **et** définis `CYWARD_MODEL` (dans `.env` ou l'environnement) avec la même valeur.
- **GPU NVIDIA** : décommente le bloc `deploy` du service `ollama` (nécessite `nvidia-container-toolkit`).

**Rejouer un pcap avec l'image :**

```bash
docker run --rm -v "$PWD:/data:ro" cyward:latest replay /data/capture.pcap
```

**Lancer l'agent seul, sans Ollama** (triage IA hors ligne, alertes en attente) :

```bash
docker compose run --rm --no-deps cyward
```

---

## 6. Utilisation

| Commande | Rôle |
|---|---|
| `cyward interfaces` | Liste les interfaces réseau, leur état et leurs adresses |
| `cyward [-c fichier.toml] run` | Surveillance continue (réseau + logs + IA + dashboard) |
| `cyward run -i eth0` | Force l'interface à écouter |
| `cyward run --no-capture` | Logs seulement (pas besoin de `setcap`) |
| `cyward run --no-logs` | Réseau seulement |
| `cyward run --no-llm` | Sans triage IA |
| `cyward replay capture.pcap` | Passe un pcap dans les détecteurs, affiche les alertes et quitte |
| `cyward replay capture.pcap --serve` | Idem, puis garde le dashboard et le triage IA actifs |
| `cyward check-llm` | Teste la connexion au modèle |

Sans `-c`, toutes les valeurs par défaut s'appliquent.

**Choix de l'interface.** Si `capture.interface` est vide, l'agent prend celle qui porte la **route par défaut** (lue dans `/proc/net/route`), c'est-à-dire celle qui voit le trafic vers Internet. Les ponts Docker et les tunnels VPN sont ainsi écartés. À défaut, il prend la première interface active non-loopback.

**Niveau de log** de l'agent : variable `RUST_LOG`, par exemple `RUST_LOG=debug cyward run`. Chaque nouvelle alerte apparaît dans la sortie en `WARN`.

**Analyser une capture faite ailleurs :**

```bash
sudo tcpdump -i eth0 -w capture.pcap
```
```bash
cyward replay capture.pcap
```

Seul le format pcap classique est lu. Pour convertir un fichier pcapng (le format par défaut de Wireshark) :

```bash
editcap -F pcap capture.pcapng capture.pcap
```

---

## 7. Configuration complète

Toutes les clés sont optionnelles. [`config.example.toml`](config.example.toml) contient l'intégralité des options avec leurs valeurs par défaut.

### `[capture]`

| Clé | Défaut | Description |
|---|---|---|
| `enabled` | `true` | Active la capture réseau |
| `interface` | `""` | Interface à écouter (vide = route par défaut) |
| `promiscuous` | `true` | Mode promiscuité : voir aussi le trafic destiné aux autres machines (indispensable avec un port miroir) |
| `queue_size` | `65536` | Paquets en attente entre la capture et le moteur |

### `[logs]`

| Clé | Défaut | Description |
|---|---|---|
| `enabled` | `true` | Active l'analyse des logs |
| `journald` | `true` | Lit le journal systemd |
| `files` | `[]` | Fichiers texte à suivre. **Ne mets pas `/var/log/auth.log` si `journald = true`**, les lignes seraient comptées deux fois |

### `[detection]`

| Clé | Défaut | Description |
|---|---|---|
| `whitelist` | `[]` | IP jamais signalées comme source, ex. `["192.168.1.5"]` |
| `local_networks` | plages privées RFC 1918, `fc00::/7`, `fe80::/10` | Ce qui est « interne » (mouvement latéral, sens sortant) |
| `alert_cooldown_secs` | `300` | Fenêtre de fusion des alertes identiques |

### `[detection.portscan]`, `[detection.bruteforce]`, `[detection.synflood]`

| Clé | Défaut | Description |
|---|---|---|
| `portscan.window_secs` | `60` | Fenêtre d'observation |
| `portscan.ports_threshold` | `25` | Ports distincts sur un hôte |
| `portscan.hosts_threshold` | `20` | Hôtes distincts sur un port |
| `bruteforce.window_secs` | `60` | Fenêtre |
| `bruteforce.threshold` | `20` | Connexions vers un service d'authentification |
| `bruteforce.ports` | 16 ports courants | Services surveillés |
| `synflood.window_secs` | `10` | Fenêtre |
| `synflood.threshold` | `3000` | SYN vers une même cible |

### `[detection.beacon]`

| Clé | Défaut | Description |
|---|---|---|
| `min_samples` | `8` | Intervalles observés avant de conclure |
| `max_jitter` | `0.12` | Variation maximale des intervalles (12 %) |
| `min_interval_secs` | `5` | Intervalle moyen minimal |
| `ignore_ports` | `[53, 123, 5353]` | Ports exclus |

### `[detection.volume]`

| Clé | Défaut | Description |
|---|---|---|
| `bucket_secs` | `60` | Durée d'une période |
| `warmup_buckets` | `15` | Périodes d'apprentissage avant d'alerter |
| `zscore` | `4.0` | Écart à la normale (en écarts-types) |
| `min_bytes` | `50000000` | Volume minimal par période pour alerter |

### `[detection.dns]`

| Clé | Défaut | Description |
|---|---|---|
| `max_name_len` | `80` | Longueur de nom suspecte |
| `min_label_len` | `25` | Longueur de segment à partir de laquelle l'entropie est testée |
| `entropy_threshold` | `3.8` | Entropie (bits/caractère) jugée aléatoire |
| `window_secs` | `300` | Fenêtre du détecteur de tunnel |
| `unique_subdomains_threshold` | `150` | Sous-domaines uniques d'un même domaine |
| `ignore_suffixes` | `["in-addr.arpa", "ip6.arpa", "local"]` | Suffixes ignorés |

### `[detection.auth]`

| Clé | Défaut | Description |
|---|---|---|
| `window_secs` | `300` | Fenêtre de comptage des échecs |
| `failures_threshold` | `6` | Échecs avant l'alerte de force brute |

### `[[detection.custom_log_rules]]`

Champs : `name`, `pattern` (regex Rust), `severity` (`info` à `critical`), `title`. Voir la section 3.7.

### `[llm]`

| Clé | Défaut | Description |
|---|---|---|
| `enabled` | `true` | Active le triage IA |
| `base_url` | `http://127.0.0.1:11434/v1` | Endpoint compatible OpenAI |
| `model` | `hf.co/mradermacher/Foundation-Sec-8B-Instruct-GGUF:Q4_K_M` | Nom du modèle côté serveur |
| `api_key` | `""` | Clé éventuelle |
| `timeout_secs` | `300` | Délai maximal d'une analyse |
| `min_severity` | `"medium"` | Sévérité minimale envoyée au modèle |
| `language` | `"français"` | Langue des réponses |
| `queue_size` | `32` | Alertes en attente d'analyse |

### `[web]`

| Clé | Défaut | Description |
|---|---|---|
| `listen` | `127.0.0.1:8080` | Adresse d'écoute du dashboard |
| `token` | `""` | Jeton d'accès (obligatoire si le dashboard est exposé) |

---

## 8. Le dashboard et l'API

### Le dashboard

Ouvre `http://127.0.0.1:8080`, ou `http://hôte:8080/?token=…` si un jeton est défini.

- **Bandeau du haut** : interface écoutée, paquets et débit, volume, paquets perdus, lignes de logs lues, état du modèle et nombre d'analyses faites. Le point vert devient rouge si la connexion à l'agent est perdue.
- **Compteurs par sévérité** : cliquer sur l'un d'eux filtre la liste.
- **Filtres** : recherche libre (IP, titre, type), source (réseau ou logs), verdict de l'IA.
- **Liste des alertes** : mise à jour en direct, sans recharger la page. Une nouvelle alerte clignote brièvement. Le badge indique l'état du triage : en attente, verdict avec confiance, ou échec.
- **Détail d'une alerte**, en cliquant dessus :
  - à gauche : description, source, cible, dates, occurrences et preuves brutes en JSON ;
  - à droite : l'analyse de l'IA, avec verdict, jauge de confiance, explication, liens vers les fiches MITRE ATT&CK et recommandations numérotées.

Le dashboard est une seule page HTML sans dépendance externe, embarquée dans le binaire. Il fonctionne donc sur un réseau isolé d'Internet. Tous les textes sont insérés comme du texte et non comme du HTML : un attaquant qui glisse du code dans un nom d'utilisateur SSH ou une requête DNS ne peut pas l'exécuter dans ton navigateur.

### L'API

Toutes les routes acceptent le jeton en `?token=` ou en `Authorization: Bearer …`.

| Route | Réponse |
|---|---|
| `GET /api/alerts?limit=500` | Les alertes, de la plus récente à la plus ancienne (5 000 au maximum) |
| `GET /api/alerts/{id}` | Une alerte |
| `GET /api/stats` | `{ "stats": {...}, "alerts_by_severity": {...} }` |
| `GET /api/events` | Flux SSE : `{"type":"new"\|"update","alert":{...}}` |

Exemple, pour suivre les alertes en direct depuis un terminal :

```bash
curl -N http://127.0.0.1:8080/api/events
```

Format d'une alerte :

```json
{
  "id": 3,
  "kind": "brute_force",
  "severity": "high",
  "source": "network",
  "title": "Force brute probable sur 192.168.1.10:22 depuis 203.0.113.77",
  "description": "20 connexions TCP vers le port 22 (SSH) en moins de 60 s.",
  "src": "203.0.113.77",
  "dst": "192.168.1.10:22",
  "evidence": { "connections": 20, "port": 22, "service": "SSH" },
  "first_seen": "2026-11-11T10:10:22Z",
  "last_seen": "2026-11-11T10:10:22Z",
  "count": 1,
  "triage": "done",
  "analysis": { "verdict": "malveillant", "confidence": 0.85, "summary": "…", "mitre": ["T1110"], "recommendations": ["…"], "model": "…" }
}
```

**Types (`kind`) :**

| Réseau | Logs |
|---|---|
| `port_scan`, `host_sweep`, `brute_force`, `syn_flood`, `beaconing`, `volume_anomaly`, `dns_tunneling`, `suspicious_dns` | `auth_brute_force`, `auth_compromise`, `privilege_escalation`, `account_change`, `custom_rule` |

`syn_flood` peut aussi venir des logs, quand c'est le noyau qui le signale.

**États de triage (`triage`) :** `none` (pas envoyée), `pending`, `done`, `failed`.

Les alertes sont gardées **en mémoire** : elles disparaissent au redémarrage. Pour les conserver ou les centraliser, interroge l'API, ou écoute le flux SSE et envoie les événements vers ton SIEM.

---

## 9. Où déployer l'agent dans le réseau

C'est le point le plus important. **L'agent ne voit que le trafic qui arrive sur son interface.** Sur un réseau avec switch (presque tous aujourd'hui), une machine ordinaire ne reçoit que **son propre trafic**, plus le broadcast et le multicast.

| Emplacement | Ce qui est vu | Mise en place |
|---|---|---|
| **Port miroir (SPAN)** d'un switch administrable | Tout le trafic du switch ou des VLAN choisis | Configurer le port miroir vers une carte réseau dédiée de la machine Cyward. Garder `promiscuous = true`. **Option recommandée.** |
| **Routeur / pare-feu Linux** (ou machine en coupure) | Tout le trafic entre le réseau et Internet, et entre VLAN routés | Installer Cyward sur le routeur, écouter l'interface LAN |
| **TAP réseau** | Tout le trafic d'un lien, sans risque de perte | Boîtier matériel entre deux équipements |
| **Un agent par serveur sensible** | Le trafic et les logs de ce serveur | Simple et sans matériel : un Cyward par machine, avec un dashboard chacun |
| **Poste de travail ordinaire** | Son propre trafic | Utile pour tester, ou pour un usage personnel |

**Conseils :**
- Sur un port miroir, utilise une carte dédiée **sans adresse IP**, et précise-la avec `capture.interface`.
- Les switchs grand public « smart managed » (TP-Link, Netgear…) proposent souvent un port miroir.
- Adapte `local_networks` à ton plan d'adressage, sinon le sens des flux (interne ou externe) sera faux.
- Une Wi-Fi en mode client ne voit pas le trafic des autres appareils, même en mode promiscuité.

---

## 10. Lancer l'agent comme service systemd

Les commandes suivantes installent le binaire et la configuration, et créent un utilisateur système dédié :

```bash
sudo install -m 755 target/release/cyward /usr/local/bin/cyward
```
```bash
sudo install -D -m 640 cyward.toml /etc/cyward/cyward.toml
```
```bash
sudo useradd --system --no-create-home --groups systemd-journal cyward
```

Crée ensuite `/etc/systemd/system/cyward.service` :

```ini
[Unit]
Description=Cyward - détection d'intrusions
After=network-online.target ollama.service
Wants=network-online.target

[Service]
User=cyward
ExecStart=/usr/local/bin/cyward -c /etc/cyward/cyward.toml run
Restart=on-failure
AmbientCapabilities=CAP_NET_RAW CAP_NET_ADMIN
CapabilityBoundingSet=CAP_NET_RAW CAP_NET_ADMIN
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true

[Install]
WantedBy=multi-user.target
```

Donne à l'utilisateur `cyward` le droit de lire la configuration, puis active le service :

```bash
sudo chown root:cyward /etc/cyward/cyward.toml
```
```bash
sudo systemctl daemon-reload && sudo systemctl enable --now cyward
```

Pour suivre l'agent :

```bash
journalctl -u cyward -f
```

Avec `AmbientCapabilities`, le `setcap` sur le binaire n'est pas nécessaire.

---

## 11. Tests et simulation d'attaques

### Tests unitaires

```bash
cargo test
```

22 tests couvrent :
- le parsing des paquets et du DNS ;
- chaque détecteur, cas positifs et négatifs (un scan lent ou un trafic irrégulier ne doivent pas déclencher) ;
- les règles de logs ;
- la fusion des alertes ;
- l'extraction du JSON renvoyé par le modèle.

### Simulation d'attaques

Le programme d'exemple génère un pcap de 40 minutes. Il contient le trafic normal d'un portable (navigation, DNS ordinaire) et le scénario d'un poste compromis :

1. balise C2 toutes les 60 s vers `198.51.100.66:8443` ;
2. force brute SSH d'un attaquant externe sur le serveur ;
3. scan de 200 ports du serveur par le poste compromis ;
4. balayage du port 445 sur 40 machines ;
5. exfiltration par tunnel DNS (300 sous-domaines encodés) ;
6. envoi de ~85 Mo en une minute vers le serveur C2.

```bash
cargo run --example gen_attacks -- attaques.pcap
```
```bash
cargo run -- replay attaques.pcap
```

Résultat attendu (les heures sont celles du pcap, en UTC) :

```
61660 paquets, 88663669 octets analysés, 6 alerte(s)
[  Medium] 2026-11-11 10:09:41 Balise périodique de 192.168.1.20 vers 198.51.100.66:8443  (x12)
[    High] 2026-11-11 10:10:22 Force brute probable sur 192.168.1.10:22 depuis 203.0.113.77  (x1)
[    High] 2026-11-11 10:15:01 Scan de ports de 192.168.1.20 vers 192.168.1.10  (x1)
[    High] 2026-11-11 10:16:02 Balayage du port 445 par 192.168.1.20  (x1)
[    High] 2026-11-11 10:21:14 Tunnel DNS probable de 192.168.1.20 via tunnel-exfil.net  (x1)
[    High] 2026-11-11 10:31:00 Volume sortant anormal depuis 192.168.1.20  (x1)
```

Pour voir l'analyse de l'IA, ajoute `--serve` et ouvre le dashboard. Comme toutes ces alertes concernent `192.168.1.20`, le modèle reçoit les autres en contexte et peut reconstituer la chaîne d'attaque.

### Tester en conditions réelles

Ne le fais que sur **ton propre réseau ou un réseau où tu es autorisé**.

- **Scan :** depuis une autre machine, lance `nmap -sS <ip>`.
- **Force brute SSH :** échoue volontairement plusieurs fois à te connecter en SSH.
- **sudo refusé :** avec un compte sans droits, lance `sudo -l`.

---

## 12. Réduire les faux positifs

Les premiers jours, observe les alertes et ajuste la configuration :

| Symptôme | Réglage |
|---|---|
| Ton scanner de vulnérabilités ou ta supervision déclenche des scans | Ajoute son IP dans `whitelist` |
| Balises sur des services légitimes (mises à jour, sondes) | Ajoute le port dans `beacon.ignore_ports`, ou baisse `max_jitter` |
| Alertes de volume pendant les sauvegardes cloud | Monte `volume.min_bytes` ou `volume.zscore`, ou mets le serveur de sauvegarde en `whitelist` |
| Alertes DNS sur un antivirus ou un CDN qui utilise des noms aléatoires | Ajoute son domaine dans `dns.ignore_suffixes` |
| Force brute sur un serveur de messagerie très sollicité | Monte `bruteforce.threshold` |
| Trop d'alertes en attente d'IA | Passe `llm.min_severity` à `"high"` |

Le verdict « bénin » de l'IA aide à repérer ces cas, mais vérifie toujours avant d'exclure quoi que ce soit.

---

## 13. Dépannage

| Message ou symptôme | Cause et solution |
|---|---|
| `capture refusée sur … : lancez en root ou donnez la capacité au binaire` | Lance `sudo setcap cap_net_raw,cap_net_admin=eip target/release/cyward`, à refaire après chaque `cargo build` |
| `interface X introuvable` | Vérifie le nom avec `cyward interfaces` |
| `journalctl: No journal files were opened due to insufficient permissions` | Ajoute l'utilisateur au groupe `systemd-journal`, puis reconnecte-toi |
| `LLM indisponible : connexion à http://127.0.0.1:11434/v1` | Ollama n'est pas lancé : `systemctl status ollama` ou `ollama serve` |
| `modèle … absent du serveur` | Lance `ollama pull <modèle>`, puis vérifie que le nom correspond exactement à `ollama list` |
| Analyses toujours en échec (délai dépassé) | Machine trop lente : monte `llm.timeout_secs`, utilise une quantification plus petite (Q3_K_M), ou un GPU |
| Le compteur « Perdus » augmente | Le moteur ne suit pas le débit : compile en `--release`, monte `capture.queue_size` |
| Aucun paquet sur un port miroir | Vérifie `promiscuous = true`, l'interface choisie et la configuration du switch |
| `fichier pcap invalide` | C'est probablement du pcapng : convertis-le avec `editcap -F pcap` |
| `écoute sur 127.0.0.1:8080` échoue | Le port est pris (par exemple par llama-server) : change `web.listen` |

---

## 14. Sécurité de l'agent lui-même

Un outil de détection est une cible de choix : il voit tout le réseau. Plusieurs précautions sont déjà prises.

- **Privilèges minimaux :** pas besoin d'être root, seulement `CAP_NET_RAW`/`CAP_NET_ADMIN` pour la capture et le groupe `systemd-journal` pour les logs.
- **Contenu non conservé :** seules les métadonnées des paquets sont gardées, jamais leur contenu, et rien n'est écrit sur disque.
- **Dashboard sur localhost par défaut.** Si tu l'exposes, définis `web.token` avec une valeur longue et aléatoire (`openssl rand -hex 32`), et place-le idéalement derrière un reverse proxy HTTPS ou un VPN. La comparaison du jeton se fait en temps constant.
- **Dashboard protégé contre l'injection :** les données venant du réseau sont toujours affichées comme du texte.
- **Modèle local :** les alertes, IP et logs envoyés au modèle ne quittent pas la machine, tant que `llm.base_url` pointe vers un serveur local.
- **Prompt injection :** les preuves envoyées au modèle peuvent contenir du texte choisi par l'attaquant, par exemple un nom d'utilisateur SSH. Un attaquant pourrait tenter d'influencer le verdict de cette façon. Le verdict de l'IA ne modifie jamais la sévérité calculée par les détecteurs et ne déclenche aucune action automatique. Garde un regard humain sur les décisions.

---

## 15. Limites connues

- **Détection comportementale, pas par signatures.** Cyward repère des comportements (rythmes, volumes, diversité) mais ne reconnaît pas un exploit précis dans le contenu d'un paquet. Il **complète** un IDS à signatures comme Suricata ou un outil comme Zeek, il ne les remplace pas.
- **Trafic chiffré :** seules les métadonnées sont analysées. Une exfiltration lente et régulière sous le seuil de volume passera inaperçue.
- **Domaine DNS naïf :** le domaine est pris comme les deux derniers segments. `exemple.co.uk` est donc vu comme `co.uk`, ce qui peut fusionner des domaines distincts dans le détecteur de tunnel.
- **Beaconing :** seul le TCP est suivi ; une balise en UDP ou QUIC n'est pas détectée.
- **Fragmentation et IPv6 :** les fragments IP et les en-têtes d'extension IPv6 exotiques peuvent échapper au parsing.
- **Historique en mémoire :** 5 000 alertes au maximum, perdues au redémarrage. L'apprentissage du volume repart aussi de zéro.
- **Un seul analyseur IA à la fois :** sur CPU, une rafale d'alertes peut prendre plusieurs minutes à être analysée.
- **Fiabilité du LLM :** le modèle peut se tromper ou inventer une technique MITRE. Ses verdicts sont une aide au tri, pas une vérité.
- **Linux uniquement** pour la capture live et la lecture des logs. Le rejeu de pcap fonctionne partout.

---

## 16. Pistes d'évolution

- Persistance des alertes et des normales apprises (SQLite).
- Export vers un SIEM : fichier JSON lignes, syslog, Elasticsearch, Loki, Wazuh.
- Notifications pour les alertes critiques (ntfy, Discord, Slack, e-mail).
- Ingestion des alertes Suricata (`eve.json`) et des logs Zeek, pour combiner signatures et comportement.
- Réponse active optionnelle et validée par un humain : blocage d'IP via nftables.
- Modèle d'anomalies léger (Isolation Forest en ONNX) entraîné sur des jeux comme CIC-IDS2017.
- Détections supplémentaires : ARP spoofing, nouveaux appareils sur le réseau, connexions vers des IP de listes de menaces (abuse.ch, Spamhaus), TLS/JA3/JA4.
- Capture haute performance avec AF_XDP ou eBPF.
