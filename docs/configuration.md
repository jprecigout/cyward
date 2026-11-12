# Configuration complète

Toutes les clés sont optionnelles. [`config.example.toml`](../config.example.toml) contient l'intégralité des options avec leurs valeurs par défaut.

## `[capture]`

| Clé | Défaut | Description |
|---|---|---|
| `enabled` | `true` | Active la capture réseau |
| `interface` | `""` | Interface à écouter (vide = route par défaut) |
| `promiscuous` | `true` | Mode promiscuité : voir aussi le trafic destiné aux autres machines (indispensable avec un port miroir) |
| `queue_size` | `65536` | Paquets en attente entre la capture et le moteur |

## `[logs]`

| Clé | Défaut | Description |
|---|---|---|
| `enabled` | `true` | Active l'analyse des logs |
| `journald` | `true` | Lit le journal systemd |
| `files` | `[]` | Fichiers texte à suivre. **Ne mets pas `/var/log/auth.log` si `journald = true`**, les lignes seraient comptées deux fois |

## `[detection]`

| Clé | Défaut | Description |
|---|---|---|
| `whitelist` | `[]` | IP jamais signalées comme source, ex. `["192.168.1.5"]` |
| `local_networks` | plages privées RFC 1918, `fc00::/7`, `fe80::/10` | Ce qui est « interne » (mouvement latéral, sens sortant) |
| `alert_cooldown_secs` | `300` | Fenêtre de fusion des alertes identiques |

## `[detection.portscan]`, `[detection.bruteforce]`, `[detection.synflood]`

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

## `[detection.beacon]`

| Clé | Défaut | Description |
|---|---|---|
| `min_samples` | `8` | Intervalles observés avant de conclure |
| `max_jitter` | `0.12` | Variation maximale des intervalles (12 %) |
| `min_interval_secs` | `5` | Intervalle moyen minimal |
| `ignore_ports` | `[53, 123, 5353]` | Ports exclus |

## `[detection.volume]`

| Clé | Défaut | Description |
|---|---|---|
| `bucket_secs` | `60` | Durée d'une période |
| `warmup_buckets` | `15` | Périodes d'apprentissage avant d'alerter |
| `zscore` | `4.0` | Écart à la normale (en écarts-types) |
| `min_bytes` | `50000000` | Volume minimal par période pour alerter |

## `[detection.dns]`

| Clé | Défaut | Description |
|---|---|---|
| `max_name_len` | `80` | Longueur de nom suspecte |
| `min_label_len` | `25` | Longueur de segment à partir de laquelle l'entropie est testée |
| `entropy_threshold` | `3.8` | Entropie (bits/caractère) jugée aléatoire |
| `window_secs` | `300` | Fenêtre du détecteur de tunnel |
| `unique_subdomains_threshold` | `150` | Sous-domaines uniques d'un même domaine |
| `ignore_suffixes` | `["in-addr.arpa", "ip6.arpa", "local"]` | Suffixes ignorés |

## `[detection.threat_list]`

| Clé | Défaut | Description |
|---|---|---|
| `lists` | `[]` | Fichiers de listes de menaces, lus au démarrage (formats : [listes de menaces](detecteurs.md#listes-de-menaces-threatlist)). Vide = détecteur désactivé |
| `realert_secs` | `3600` | Délai avant de signaler à nouveau un même couple (hôte interne, IP listée) |

## `[detection.arp]`

| Clé | Défaut | Description |
|---|---|---|
| `window_secs` | `3600` | Durée pendant laquelle une MAC reste active pour une IP : une seconde MAC dans ce délai est un conflit |
| `protected_ips` | `[]` | IP sensibles (passerelle, DNS…) dont l'usurpation est de sévérité haute, ex. `["192.168.1.1"]` |

## `[detection.auth]`

| Clé | Défaut | Description |
|---|---|---|
| `window_secs` | `300` | Fenêtre de comptage des échecs |
| `failures_threshold` | `6` | Échecs avant l'alerte de force brute |

## `[[detection.custom_log_rules]]`

Champs : `name`, `pattern` (regex Rust), `severity` (`info` à `critical`), `title`. Voir les [règles sur les journaux système](detecteurs.md#règles-sur-les-journaux-système-loganalyzer-srclogsrulesrs).

## `[detection.anomaly]`

Apprentissage du comportement normal ([détecteur `HostAnomaly`](detecteurs.md#apprentissage-du-comportement-normal-hostanomaly)).

| Clé | Défaut | Description |
|---|---|---|
| `enabled` | `false` | Active l'apprentissage |
| `mode` | `"observation"` | `observation` : anomalies en `info`, sans LLM ; `alert` : anomalies en `medium`, analysées par le LLM |
| `window_secs` | `300` | Durée d'une fenêtre (un échantillon par machine active) |
| `data_dir` | `""` | Dossier de persistance ; vide = en mémoire seulement, perdu à l'arrêt |
| `min_training_samples` | `500` | Échantillons utilisables nécessaires pour apprendre |
| `learning_hours` | `168` | Durée d'observation avant le premier apprentissage automatique |
| `retrain_interval_hours` | `168` | Délai entre deux apprentissages automatiques |
| `retention_days` | `28` | Conservation des échantillons |
| `max_samples` | `200000` | Plafond du nombre d'échantillons |
| `trees`, `sample_size` | `100`, `256` | Paramètres de l'Isolation Forest |
| `contamination` | `0.005` | Part des données apprises au-dessus du seuil : fixe la sensibilité |
| `drift_factor` | `10` | Facteur de dérive cumulée qui lève une alerte |
| `max_versions` | `10` | Versions de modèle conservées pour le retour arrière |

## `[llm]`

| Clé | Défaut | Description |
|---|---|---|
| `enabled` | `true` | Active le triage IA |
| `base_url` | `http://127.0.0.1:11434/v1` | Endpoint compatible OpenAI |
| `model` | `hf.co/mradermacher/Foundation-Sec-8B-Instruct-GGUF:IQ4_XS` | Nom du modèle côté serveur (Q4_K_M : [le modèle par défaut](llm.md#le-modèle-par-défaut--foundation-sec-8b-instruct)) |
| `api_key` | `""` | Clé éventuelle |
| `timeout_secs` | `300` | Délai maximal d'une analyse |
| `min_severity` | `"medium"` | Sévérité minimale envoyée au modèle (`"high"` pour ménager le CPU d'une machine modeste, voir [le modèle par défaut](llm.md#le-modèle-par-défaut--foundation-sec-8b-instruct)) |
| `language` | `"français"` | Langue des réponses |
| `queue_size` | `32` | Alertes en attente d'analyse |

## `[web]`

| Clé | Défaut | Description |
|---|---|---|
| `listen` | `127.0.0.1:8080` | Adresse d'écoute du dashboard |
| `token` | `""` | Jeton d'accès. Obligatoire si le dashboard est exposé, et pour toute action (répondre aux anomalies, valider un modèle) |

## `[names]`

Noms des machines affichés à côté des adresses, obtenus par DNS inverse (PTR). Sur un réseau domestique, c'est en général la box qui répond, avec le nom que chaque appareil lui a donné.

| Clé | Défaut | Description |
|---|---|---|
| `enabled` | `true` | Afficher les noms des machines |
| `external` | `false` | Résoudre aussi les adresses externes. Désactivé par défaut : la question PTR aboutit au serveur DNS du propriétaire de l'adresse, qui apprend ainsi qu'elle est examinée (un attaquant qui surveille sa zone serait prévenu) |
| `nameserver` | `""` | Serveur DNS à interroger (adresse IP). Vide = premier `nameserver` de `/etc/resolv.conf` |
| `timeout_ms` | `1000` | Délai maximal d'une résolution, en millisecondes |
| `cache_secs` | `3600` | Durée de conservation d'un nom trouvé, en secondes (une absence de nom est gardée 5 minutes) |

## `[notify]`

Notifications des attaques sur ton téléphone ([ntfy](https://ntfy.sh)) ou vers n'importe quel service qui accepte un webhook. Une alerte est notifiée **une seule fois**, dès que l'une de ces conditions est remplie :

1. le **verdict de l'IA** est dans `verdicts` avec une confiance d'au moins `min_confidence` ;
2. sa **sévérité** atteint `immediate_severity` : on n'attend pas l'IA, qui peut mettre plusieurs minutes ;
3. **repli** : sévérité d'au moins `fallback_severity` mais pas de verdict après `fallback_after_secs` (IA hors ligne). Si aucun verdict ne peut venir (IA désactivée, analyse en échec, file d'analyse pleine), la notification part sans attendre le délai.

| Clé | Défaut | Description |
|---|---|---|
| `enabled` | `false` | Activer les notifications |
| `verdicts` | `["malveillant", "suspect"]` | Verdicts de l'IA qui déclenchent une notification |
| `min_confidence` | `0.6` | Confiance minimale du verdict (0 à 1) |
| `immediate_severity` | `"critical"` | Sévérité notifiée sans attendre l'IA |
| `fallback_severity` | `"high"` | Sévérité minimale d'une notification de repli |
| `fallback_after_secs` | `600` | Attente du verdict avant le repli, en secondes (0 = jamais de repli) |
| `max_per_hour` | `20` | Plafond de notifications par heure ; au-delà, un résumé unique est envoyé dès que possible |
| `dashboard_url` | `""` | Adresse du dashboard vue depuis le téléphone (ex. `http://192.168.1.2:8080/`) : la notification ouvre directement l'alerte. Si `web.token` est défini, tu peux y ajouter `?token=…`, mais le jeton passe alors par le service de notification : à réserver à un ntfy auto-hébergé |
| `channels` | `[]` | Canaux, voir ci-dessous |

Les canaux, autant que tu veux, chacun dans une section `[[notify.channels]]` :

```toml
# ntfy (auto-hébergé ou ntfy.sh) : l'appli ntfy du téléphone s'abonne au sujet.
[[notify.channels]]
type = "ntfy"
url = "http://127.0.0.1:8090"   # le serveur, sans le sujet
topic = "cyward"
token = "tk_…"                  # jeton d'accès ntfy ; vide si le sujet est public

# Webhook générique : POST JSON.
[[notify.channels]]
type = "webhook"
url = "https://discord.com/api/webhooks/…"
headers = { Authorization = "Bearer …" }   # facultatif
```

Le corps JSON du webhook est accepté tel quel par plusieurs services : `title`, `message` et `priority` (1 à 5) pour Gotify, `text` pour Slack, `content` pour Discord (avec les mentions désactivées). Il contient aussi `reason` (`verdict`, `severity`, `no_verdict`, `throttled`, `test`), `url` et l'alerte complète (`alert`) pour une automatisation (n8n, Home Assistant, SIEM). Les textes venus du réseau sont nettoyés (caractères de contrôle) et envoyés en texte brut.

Vérifie la configuration avec `cyward check-notify`, qui envoie une notification de test sur chaque canal.

## `[history]`

Historique des alertes dans une base **SQLite**. Les alertes survivent au redémarrage : les 5 000 plus récentes sont rechargées dans le dashboard, avec leur analyse IA et les réponses. Désactivé tant que `path` est vide. Le rejeu (`cyward replay`) n'y écrit jamais.

| Clé | Défaut | Description |
|---|---|---|
| `path` | `""` | Fichier de la base, créé au besoin avec son dossier (ex. `/var/lib/cyward/alerts.db`). Vide = alertes en mémoire seulement |
| `retention_days` | `90.0` | Durée de conservation d'une alerte après sa dernière occurrence, en jours |
| `max_alerts` | `100000` | Nombre maximal d'alertes en base ; au-delà, les moins récemment vues sont supprimées |

**Taille bornée, même sous une inondation.** Un attaquant peut provoquer beaucoup d'alertes distinctes en peu de temps ; une rétention par âge seule le laisserait remplir le disque. Cyward combine donc :
- **l'âge** (`retention_days`), pour le besoin d'historique ;
- **un plafond** (`max_alerts`), garde-fou absolu. La purge a lieu toutes les heures, mais aussi dès que `max_alerts / 10` alertes nouvelles ont été écrites : la base ne dépasse jamais le plafond de plus de 10 % (plus un lot de 500) ;
- **des preuves plafonnées** à 4 Ko par alerte (au-delà, un extrait de 1 Ko les remplace dans la base).

Une alerte pèse de 1 à 2 Ko : avec les valeurs par défaut, la base reste sous 200 à 250 Mo. L'espace libéré par les purges est rendu au système (`auto_vacuum` incrémental). Une limite abaissée s'applique dès le démarrage suivant.

**Performances.** La détection n'attend jamais le disque : les alertes modifiées sont regroupées (une écriture par alerte et par lot, même si elle a été mise à jour dix fois) et écrites toutes les 5 s par un thread dédié, en une transaction, en mode WAL. À l'arrêt (Ctrl+C), le dernier lot est écrit ; une coupure brutale peut faire perdre les 5 dernières secondes.

**Consulter la base** (lecture possible pendant que l'agent tourne) :

```bash
sqlite3 /var/lib/cyward/alerts.db "SELECT id, datetime(last_seen, 'unixepoch'), severity, kind, src, dst FROM alerts ORDER BY last_seen DESC LIMIT 20"
```
