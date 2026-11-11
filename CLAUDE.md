# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Projet

Cyward est un agent de détection d'intrusions en Rust (Linux). Il capture le trafic réseau et lit les logs système, lève des alertes via des détecteurs à seuils et statistiques, puis fait trier les alertes importantes par un LLM cyber local (Foundation-Sec-8B-Instruct via Ollama, API compatible OpenAI). Le [README.md](README.md) documente en détail chaque détecteur, la configuration et le déploiement.

Les commentaires, messages de log, textes d'alerte, prompts du LLM et l'interface du dashboard sont **en français** : garder cette langue.

## Commandes

```bash
cargo build                      # aucune dépendance système (ni libpcap ni OpenSSL)
cargo test                       # tous les tests (unitaires, dans chaque module)
cargo test detect::scan          # tests d'un module
cargo test detects_ssh_bruteforce   # un seul test (filtre sur le nom)
cargo clippy --all-targets       # doit rester sans avertissement
```

Test de bout en bout sans réseau ni droits : générer un pcap d'attaques simulées puis le rejouer. Le rejeu doit produire 6 alertes (balise C2 ×12, force brute, scan, balayage, tunnel DNS, volume) :

```bash
cargo run --example gen_attacks -- /tmp/attaques.pcap
cargo run -- replay /tmp/attaques.pcap            # affiche les alertes et quitte
cargo run -- replay /tmp/attaques.pcap --serve    # garde dashboard + triage LLM actifs
```

Docker (Linux) : `docker compose build cyward` puis `docker compose run --rm --no-deps cyward`. Cette commande lance l'agent sans Ollama et sans télécharger le modèle de 5 Go. Le service tourne en `network_mode: host`, avec uniquement `NET_RAW`/`NET_ADMIN` et le journal de l'hôte monté, donc la capture live fonctionne sans `setcap`. La config du conteneur est `docker/cyward.toml`, distincte de `config.example.toml`. Si une dépendance est ajoutée, la couche de cache du `Dockerfile` (faux `main.rs`) suffit ; si un nouveau dossier est embarqué via `include_str!`, il faut ajouter son `COPY`.

La capture live (`cyward run`) exige `sudo setcap cap_net_raw,cap_net_admin=eip target/<profil>/cyward`, à refaire **après chaque build**. `run --no-capture` (logs seuls) n'en a pas besoin. `check-llm` vérifie le modèle avec une alerte d'exemple. Le dashboard écoute par défaut sur `127.0.0.1:8080` (`web.listen`).

## Architecture

Pipeline assemblé dans `main.rs` :

```
capture.rs (thread bloquant AF_PACKET, ou rejeu pcap) ──mpsc<PacketMeta>──► run_engine ─► detect::Engine ─┐
logs.rs (journalctl -f -o json / tail -F, sous-processus relancés) ─► LogAnalyzer ──────────────────────────┤
                                                                                                          ▼
                                     AlertSink::emit ─► AlertStore (dédoublonnage + broadcast) ─► web.rs (SSE)
                                            └─ si sévérité ≥ llm.min_severity ─► file mpsc<u64> ─► llm.rs
```

Points qui demandent de lire plusieurs fichiers pour être compris :

- **Temps des paquets, pas l'horloge murale.** Les détecteurs raisonnent sur `PacketMeta.ts`, horodatage de capture ou du pcap. C'est ce qui rend le rejeu déterministe : ne pas introduire `SystemTime::now()` dans `detect/`.
  - `Engine::process` appelle `tick` quand le temps des paquets avance d'une seconde.
  - En live, `run_engine` ajoute un tick sur horloge murale pour les périodes sans trafic.
  - En fin de rejeu, un tick final à `last_ts + 3600` clôt les fenêtres ouvertes (nécessaire au détecteur de volume).
- **Émission « une fois par seuil » + dédoublonnage central.** Les détecteurs émettent quand un compteur atteint *exactement* le seuil (`== threshold`), donc une fois par fenêtre. `AlertStore::push` fusionne les alertes de même empreinte arrivant dans `alert_cooldown_secs` : il incrémente `count` et met à jour `last_seen`, `evidence` et la sévérité maximale.
  - L'empreinte par défaut est `kind|src|dst` ; `.fingerprint()` permet de la surcharger.
  - Seule une alerte *nouvelle* part au LLM.
  - `Beaconing` ré-émet volontairement à chaque nouvelle balise régulière pour que le compteur monte.
- **`AlertSink` est le seul point d'entrée** des alertes. Les détecteurs réseau et le `LogAnalyzer` ne touchent jamais directement au store ni à la file LLM.
- **Le LLM n'est jamais sur le chemin critique.**
  - `llm.rs` traite une alerte à la fois.
  - Une tâche `health_loop` sonde `GET /models` toutes les 30 s et met à jour `Stats.llm_online`.
  - Tant que le serveur est hors ligne, les alertes restent `Pending` ; elles ne sont pas marquées en échec.
  - Le prompt inclut jusqu'à 8 alertes récentes impliquant les mêmes hôtes, comparées sans le port grâce à `host_part`.
  - `parse_analysis` est volontairement tolérant : il extrait le JSON entouré de texte, accepte une confiance en `"85%"` et un champ `mitre` en chaîne simple.
- **Mémoire bornée.** Tout l'état des détecteurs est en `HashMap` purgées dans `tick`, avec des plafonds (`MAX_TRACKED` dans beacon, 10 000 sources dans synflood, purge des échecs dans logs). L'`AlertStore` garde 5 000 alertes. Tout nouvel état doit avoir sa purge.
- **Interne / externe.** `DetectionConfig::is_local` (basé sur `local_networks`) détermine :
  - la sévérité des scans (source interne = mouvement latéral = High) ;
  - les flux suivis par `Beaconing` et `Volume` (interne → externe uniquement).
  Pour cette raison, plusieurs détecteurs reçoivent une copie de toute la `DetectionConfig`.
- **Capture.**
  - `pnet_datalink` (AF_PACKET, pur Rust) pour le live ; `pcap-file` v2 pour le rejeu. Le rejeu gère Ethernet, Linux SLL et IP brut, mais pas pcapng.
  - Le parsing passe par `etherparse::SlicedPacket` ; la question DNS est décodée à la main dans `parse_dns_query`.
  - La capture fait `try_send` et compte les pertes dans `Stats.dropped` plutôt que de bloquer.
  - Sans `capture.interface`, `pick_interface` prend l'interface de la route par défaut (`/proc/net/route`).

## Ajouter un détecteur réseau

1. Créer `src/detect/<nom>.rs` qui implémente `Detector` (`on_packet`, et `tick` pour la purge et la clôture des fenêtres), puis l'enregistrer dans `Engine::new` (`detect/mod.rs`).
2. Ajouter sa struct de config dans `config.rs`. Toutes les structs ont `#[serde(default)]` et un `impl Default` qui porte les valeurs par défaut ; reporter la section dans `config.example.toml`.
3. Ajouter si besoin une variante à `AlertKind`. Elle est sérialisée en snake_case, et le dashboard l'affiche en remplaçant `_` par un espace.
4. Tester avec `detect::testutil::{syn, dns}` (constructeurs de `PacketMeta`), y compris un cas négatif. Ajouter éventuellement le scénario à `examples/gen_attacks.rs`.
5. Mettre à jour les tableaux du README (détecteurs, configuration, types d'alerte).

Les règles de logs vivent dans `LogAnalyzer` (`logs.rs`). Particularité sshd : une même tentative produit `Invalid user …` **et** `Failed password for invalid user …`. Seule la seconde ligne compte comme un échec ; la première sert uniquement à collecter les noms de compte.

## Dashboard

`assets/index.html` est une page unique en JS vanilla, **embarquée à la compilation** par `include_str!` dans `web.rs`. Après une modification, il faut recompiler et relancer le serveur pour la voir.

Les données affichées viennent du réseau et des logs, donc potentiellement d'un attaquant. Le DOM est construit uniquement via le helper `el()` (textContent) : ne jamais utiliser `innerHTML` avec des données d'alerte.

Le jeton optionnel (`web.token`) est vérifié par un middleware axum, en `?token=` ou `Authorization: Bearer`. Le JS le propage aux appels `fetch` et `EventSource` via `q()`.
