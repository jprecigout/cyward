# Le dashboard et l'API

## Le dashboard

Ouvre `http://127.0.0.1:8080`, ou `http://hôte:8080/?token=…` si un jeton est défini.

- **Bandeau du haut** : interface écoutée et pastille « En direct », qui passe au rouge (« Déconnecté ») si la connexion à l'agent est perdue.
- **Tuiles de statistiques** : débit en paquets par seconde avec sa courbe sur les deux dernières minutes, paquets capturés, volume, paquets perdus, lignes de logs lues, état du modèle et nombre d'analyses faites.
- **Compteurs par sévérité** : nombre d'alertes et part du total ; cliquer sur l'un d'eux filtre la liste.
- **Noms des machines** : à côté de chaque adresse, le nom obtenu par DNS inverse (celui que la box donne à la machine), en pastille violette. Seules les adresses internes sont résolues par défaut (voir `[names]`).
- **Filtres** : recherche libre (IP, nom de machine, titre, type), source (réseau ou logs), verdict de l'IA.
- **Panneau « Comportement normal »** (si l'apprentissage est activé) : modèle actif ou progression de l'apprentissage (avec une barre d'avancement), fenêtres par statut, bouton « Lancer un apprentissage », retour à une version précédente. Quand un modèle candidat attend, son diff s'affiche machine par machine, avec « Accepter » ou « Refuser » pour chacune, « Tout accepter », « Tout refuser », et les machines peu actives repliées. Suivent les exceptions actives et les dernières décisions.
- **Question « est-ce normal ? »** : dans le détail d'une anomalie, un motif, une portée, et les boutons « C'est normal » et « C'est suspect ». La réponse donnée s'affiche ensuite à la place.
- **Liste des alertes** : mise à jour en direct, sans recharger la page. Le titre de la section indique combien d'alertes sont affichées. Une nouvelle alerte s'illumine brièvement. Le badge indique l'état du triage : en attente, verdict avec confiance, ou échec.
- **Onglet « Flux »** : le trafic en direct. À gauche, les 8 machines qui émettent le plus (les autres sont regroupées) ; elles envoient vers Cyward des blocs dont la taille suit le volume et la couleur la nature (TCP, UDP, DNS, ICMP, ARP). Chaque nouvelle alerte fait sortir un bloc vers la colonne des alertes et entoure de rouge les machines concernées pendant une minute. En dessous, les alertes levées pendant l'observation ; un clic ouvre l'alerte dans l'onglet Alertes. Le bandeau donne le débit de la dernière seconde, et un bouton met l'animation en pause. Le flux n'est ouvert que lorsque l'onglet est affiché : le reste du temps, l'agent ne compte rien. Lien direct : `…/#flux`.
  - Pour une démonstration : `cyward -c examples/rejeu.toml replay attaques.pcap --serve --speed 20`, puis ouvrir `http://127.0.0.1:8080/#flux`. À pleine vitesse, les 40 minutes du pcap passeraient en moins d'une seconde.
- **Lien d'une notification** (`…/#alerte-12`) : le dashboard s'ouvre sur cette alerte, dépliée, filtres remis à zéro.
- **Détail d'une alerte**, en cliquant dessus :
  - à gauche : description, source, cible, dates, occurrences et preuves brutes en JSON ;
  - à droite : l'analyse de l'IA, avec verdict, jauge de confiance, explication, liens vers les fiches MITRE ATT&CK et recommandations numérotées.

Le dashboard est une seule page HTML sans dépendance externe, embarquée dans le binaire. Il fonctionne donc sur un réseau isolé d'Internet. Tous les textes sont insérés comme du texte et non comme du HTML : un attaquant qui glisse du code dans un nom d'utilisateur SSH ou une requête DNS ne peut pas l'exécuter dans ton navigateur.

## L'API

Toutes les routes acceptent le jeton en `?token=` ou en `Authorization: Bearer …`.

| Route | Réponse |
|---|---|
| `GET /api/alerts?limit=500` | Les alertes en mémoire, de la plus récente à la plus ancienne (5 000 au maximum ; l'historique complet est dans la base SQLite) |
| `GET /api/alerts/{id}` | Une alerte |
| `GET /api/stats` | `{ "stats": {...}, "alerts_by_severity": {...} }` |
| `GET /api/events` | Flux SSE : `{"type":"new"\|"update","alert":{...}}` |
| `GET /api/flows` | Flux SSE du trafic, une fois par seconde de trafic : `{"ts": 1794391200, "flows": [{"src": "192.168.1.20", "dst": "198.51.100.66", "kind": "tcp", "packets": 12, "bytes": 8400}], "other_packets": 0, "other_bytes": 0}` ; `kind` vaut `tcp`, `udp`, `dns`, `icmp`, `arp` ou `other`, 50 couples au plus |
| `GET /api/names?ips=192.168.1.20,192.168.1.10:22` | Noms des machines (DNS inverse) : `{"192.168.1.20": "pc-salon.lan"}`, seulement pour les adresses qui en ont un ; 64 valeurs au plus |
| `GET /api/baseline` | État de l'apprentissage : mode, fenêtres par statut, modèle actif, candidat et son diff, versions, exceptions, décisions récentes (`{"enabled": false}` s'il est désactivé) |
| `POST /api/alerts/{id}/feedback` | Réponse à une anomalie : `{"verdict": "normal"\|"suspect", "reason": "Sauvegarde", "scope": "once"\|"always"}` |
| `POST /api/baseline/train` | Lance un apprentissage maintenant |
| `POST /api/baseline/decision` | Valide le candidat : `{"accepted": ["192.168.1.20"], "rejected": ["192.168.1.35"]}`, chaque machine du diff dans l'une des listes |
| `POST /api/baseline/rollback` | Revient à une version : `{"version": 3}` |

Les routes `POST` exigent que `web.token` soit défini, et le jeton dans l'en-tête `Authorization: Bearer …`. Le jeton en paramètre d'URL est refusé pour elles, pour qu'une page tierce ne puisse pas agir à la place de l'utilisateur.

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

| Réseau | Logs | Apprentissage du comportement normal |
|---|---|---|
| `port_scan`, `host_sweep`, `brute_force`, `syn_flood`, `beaconing`, `volume_anomaly`, `dns_tunneling`, `suspicious_dns`, `threat_list_match`, `arp_spoofing` | `auth_brute_force`, `auth_compromise`, `privilege_escalation`, `account_change`, `custom_rule` | `host_anomaly`, `baseline_drift`, `baseline_rejected` |

`syn_flood` peut aussi venir des logs, quand c'est le noyau qui le signale.

**États de triage (`triage`) :** `none` (pas envoyée), `pending`, `done`, `failed`.

**Réponse (`feedback`)** : présente sur une anomalie à laquelle l'utilisateur a répondu : `verdict`, `reason`, `scope`, `at`.

Par défaut, les alertes sont gardées **en mémoire** et disparaissent au redémarrage. Avec `history.path` ([`[history]`](configuration.md#history)), elles sont aussi enregistrées dans une base SQLite et rechargées au démarrage. Pour les centraliser, écoute le flux SSE et envoie les événements vers ton SIEM.
