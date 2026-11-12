# Les détecteurs en détail

Chaque seuil cité est modifiable dans la [configuration](configuration.md).

## Scan de ports et balayage (`PortScan`)

**Ce qu'il repère :** la reconnaissance, première étape de presque toute attaque.

**Fonctionnement :**
- Le détecteur ne regarde que les **ouvertures de connexion TCP** (paquet SYN sans ACK).
- Pour chaque IP source, il tient une fenêtre de `window_secs` (60 s) contenant :
  - les **ports distincts** visés sur chaque hôte : au-delà de `ports_threshold` (25), c'est un **scan vertical** (`port_scan`) ;
  - les **hôtes distincts** visés sur chaque port : au-delà de `hosts_threshold` (20), c'est un **balayage horizontal** (`host_sweep`), typique d'un ver ou de la recherche de SMB ouverts.
- **Mémoire bornée** : un ensemble cesse de grossir une fois son seuil atteint (l'alerte est émise), et le détecteur mémorise au plus 1 000 000 de couples (hôte, port), environ 50 Mo, toutes sources confondues. Des SYN aux adresses usurpées ne peuvent donc pas remplir la mémoire. Une fois le plafond atteint, les sources déjà suivies le restent.

**Sévérité :**
- **Haute** si la source est interne : une machine de ton réseau qui en scanne d'autres est un signe classique de **mouvement latéral** après une compromission.
- **Moyenne** si la source est externe : les scans venant d'Internet sont permanents.

**MITRE :** T1046 (Network Service Discovery).

## Force brute réseau (`BruteForce`)

**Ce qu'il repère :** les essais de mots de passe en rafale sur un service d'authentification.

**Fonctionnement :**
- Le détecteur compte les nouvelles connexions TCP par triplet (source, destination, port), pour les ports listés dans `bruteforce.ports` : SSH, RDP, SMB, FTP, Telnet, SMTP, IMAP, POP3, MySQL, PostgreSQL, MSSQL, VNC, Redis.
- Au-delà de `threshold` (20) connexions en `window_secs` (60 s), il lève une alerte **haute**.
- Il fonctionne même si le service est chiffré : seul le rythme des connexions compte.
- **Mémoire bornée** : 100 000 triplets suivis au plus. Au-delà, les triplets déjà suivis restent comptés, aucun nouveau n'est créé.

**MITRE :** T1110 (Brute Force).

## Inondation SYN (`SynFlood`)

**Ce qu'il repère :** un déni de service qui sature la table de connexions d'un serveur.

**Fonctionnement :**
- Le détecteur compte les SYN reçus par chaque destination.
- Au-delà de `threshold` (3 000) en `window_secs` (10 s), il lève une alerte **haute**.
- Il compte aussi les sources distinctes. Au-delà de 50, l'alerte précise qu'il s'agit probablement d'une attaque distribuée ou d'adresses usurpées.

**MITRE :** T1498/T1499 (Network/Endpoint Denial of Service).

## Balise périodique (`Beaconing`)

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

## Volume sortant anormal (`Volume`)

**Ce qu'il repère :** l'**exfiltration** de données, c'est-à-dire un poste qui envoie soudain beaucoup plus de données vers Internet que d'habitude.

**Fonctionnement :**
- Le détecteur compte les octets envoyés par chaque hôte interne vers l'extérieur, par période de `bucket_secs` (60 s).
- Pour chaque hôte, il apprend une **moyenne et une variance mobiles exponentielles** (EWMA, α = 0,1). La normale s'adapte donc lentement aux usages.
- Après `warmup_buckets` (15) périodes d'apprentissage, il calcule le **score z** de chaque période : (volume − moyenne) ÷ écart-type.
- Il lève une alerte **haute** si le score z dépasse `zscore` (4) **et** si le volume dépasse `min_bytes` (50 Mo). Le second critère évite d'alerter pour un hôte habituellement silencieux qui envoie 2 Mo.
- L'écart-type est borné vers le bas (25 % de la moyenne, ou 1 Mo au minimum). Sans ce plancher, un hôte très régulier déclencherait au moindre écart.
- Les périodes sans trafic comptent comme des zéros dans la normale.

**MITRE :** T1041 (Exfiltration Over C2 Channel), T1567 (Exfiltration Over Web Service).

## DNS suspect et tunnel DNS (`Dns`)

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

## Listes de menaces (`ThreatList`)

**Ce qu'il repère :** le trafic avec des adresses connues pour être malveillantes. Des projets publics recensent les serveurs de commande (C2) de botnets actifs et les réseaux détournés par des criminels. Un poste qui contacte l'un d'eux est très probablement infecté, même si sa balise est trop irrégulière pour le détecteur `Beaconing`.

**Fonctionnement :**
- Les fichiers de `threat_list.lists` sont lus **au démarrage**. Sans liste, le détecteur n'est pas créé ; une liste illisible empêche le démarrage.
- Formats reconnus : une IP ou un réseau CIDR en début de ligne (commentaires `#` et `;`, colonnes en plus ignorées), ou un objet JSON par ligne avec un champ `cidr` ou `ip`. Cela couvre notamment :

  | Liste | URL | Contenu |
  |---|---|---|
  | abuse.ch Feodo Tracker | `https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.txt` | Serveurs C2 de botnets actifs (Emotet, QakBot, Dridex…) |
  | Spamhaus DROP | `https://www.spamhaus.org/drop/drop_v4.json` (et `drop_v6.json`) | Réseaux entiers détournés ou exploités par des criminels |
  | FireHOL level1 | `https://iplists.firehol.org/files/firehol_level1.netset` | Agrégat de plusieurs listes, peu de faux positifs |
- Seul le trafic qui **franchit la frontière** du réseau interne est vérifié (`local_networks`). La recherche est faite sur chaque paquet. Les réseaux sont rangés par longueur de préfixe : une adresse se vérifie en une recherche par longueur présente (une trentaine au plus), quelle que soit la taille des listes.
- Une alerte par couple (hôte interne, IP listée), puis plus rien pour ce couple pendant `realert_secs` (1 h). La mémoire est bornée à 10 000 couples ; au-delà, les alertes restent émises et fusionnées par le store.

**Sévérité :**
- **Haute** pour un hôte interne qui contacte une IP listée (`Connexion vers une IP listée`).
- **Basse** pour une IP listée qui contacte un hôte interne (`Trafic entrant d'une IP listée`) : c'est le plus souvent un scanner. L'alerte n'est pas envoyée au LLM par défaut, mais elle figure dans le contexte des autres alertes visant cet hôte.

**Mise à jour des listes :** Cyward ne télécharge rien lui-même. Un timer systemd ou une tâche cron télécharge les listes, puis redémarre l'agent :

```bash
curl -fsS -o /etc/cyward/feodo.txt https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.txt && systemctl restart cyward
```

**Faux positifs fréquents :** un réseau Spamhaus DROP peut contenir, rarement, une adresse réattribuée depuis. Les listes de C2 contiennent parfois des hébergeurs partagés.

**MITRE :** T1071 (Application Layer Protocol), T1105 (Ingress Tool Transfer), T1595 (Active Scanning) pour le trafic entrant.

## Usurpation ARP (`ArpSpoofing`)

**Ce qu'il repère :** l'**empoisonnement de cache ARP**. Sur un réseau local, l'ARP associe chaque IP à une adresse MAC sans aucune authentification. Une machine qui annonce « l'IP de la passerelle, c'est moi » reçoit le trafic des autres, qu'elle peut lire ou modifier avant de le relayer (homme du milieu, outils `arpspoof`, `ettercap`, `bettercap`).

**Fonctionnement :**
- Le détecteur lit les requêtes et réponses ARP (IPv4 sur Ethernet), et retient pour chaque IP les adresses MAC qui l'ont annoncée, avec la date de leur dernière annonce.
- L'attaquant doit répéter ses annonces, car la vraie machine continue de répondre. Quand **une seconde MAC** annonce la même IP alors que la première s'est annoncée il y a moins de `window_secs` (1 h), l'alerte est levée, une seule fois par conflit.
- Une MAC silencieuse depuis `window_secs` est oubliée : une nouvelle MAC après ce délai est un remplacement ordinaire (carte changée, IP réattribuée par DHCP).
- Les sondes de détection de doublon (émetteur `0.0.0.0`, RFC 5227) sont ignorées.
- **Mémoire bornée** : 10 000 IP suivies et 4 MAC par IP au plus, purgées après `window_secs` de silence.
- Il faut voir le trafic ARP du réseau : l'agent doit être sur le même segment que les machines surveillées (les annonces ARP sont diffusées à tout le segment, un port miroir n'est pas nécessaire).

**Sévérité :**
- **Haute** si l'IP fait partie de `protected_ips` (mets-y la passerelle, le DNS et les serveurs importants).
- **Moyenne** sinon.

**Faux positifs fréquents :** deux machines configurées avec la même IP, basculement entre deux cartes réseau (bonding actif-passif), machines virtuelles migrées. Les preuves de l'alerte donnent les deux MAC, que l'on retrouve dans la table du commutateur ou dans `ip neigh`.

**MITRE :** T1557.002 (Adversary-in-the-Middle: ARP Cache Poisoning).

## Règles sur les journaux système (`LogAnalyzer`, `src/logs/rules.rs`)

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

## Sévérités

| Niveau | Sens | Envoyé au LLM par défaut |
|---|---|---|
| `critical` | Compromission probable, agir immédiatement | oui |
| `high` | Attaque caractérisée | oui |
| `medium` | Comportement suspect à qualifier | oui |
| `low` | Signal faible, utile en corrélation | non |
| `info` | Information | non |

## Apprentissage du comportement normal (`HostAnomaly`)

**Ce qu'il repère :** ce qui sort de l'habitude d'une machine, sans règle écrite à l'avance. Par exemple, une combinaison dont chaque mesure, prise seule, resterait sous les seuils : 40 destinations inconnues, la nuit, sur des ports inhabituels.

**Fonctionnement :**
- Toutes les `window_secs` (5 min par défaut), chaque machine interne active est résumée par **12 caractéristiques** : volumes envoyés et reçus, connexions, destinations et ports distincts, part du trafic vers l'extérieur, part de destinations jamais vues, requêtes DNS et leur entropie, heure de la journée.
- Un **Isolation Forest** apprend ces profils. Un point est d'autant plus anormal qu'il est vite isolé par des coupures aléatoires. Le seuil est calculé automatiquement à partir des données apprises (`contamination`).
- Chaque anomalie est **expliquée** par ses plus gros écarts au profil habituel de la machine : « Octets envoyés : 83.2 Mo (habituellement 1.2 Mo) ». Une machine encore peu connue est comparée à la médiane du réseau, et l'explication le dit.

**Garde-fous : rien n'entre dans le comportement normal sans validation humaine.**
- Chaque anomalie pose la question **« est-ce normal ? »** dans le dashboard, avec un motif (mise à jour, sauvegarde, nouvel appareil…) et une portée (cette fois, ou désormais pour cette machine et ce type d'écart). Tant qu'elle reste sans réponse, la période n'est pas apprise. « Suspect » l'exclut définitivement.
- Chaque apprentissage produit un **modèle candidat**. Avant qu'il remplace le modèle actif, Cyward calcule le **diff** entre les deux : par machine, ce que le nouveau modèle accepterait de plus, et comment son profil change. L'utilisateur accepte ou refuse chaque machine. Une machine refusée voit ses fenêtres marquées suspectes et lève une alerte `baseline_rejected`.
- **Sans réponse, rien ne change** : le modèle actif reste en place. Seul un diff vide (rien de nouveau) est activé automatiquement.
- Les périodes d'une machine visée par une **alerte à règles** (scan, force brute, C2…) ne sont jamais apprises.
- Une **dérive cumulée** (volume multiplié ou divisé par plus de `drift_factor` depuis le premier modèle validé) lève une alerte `baseline_drift` : elle bloque l'empoisonnement par petits pas.
- Les modèles validés sont versionnés, avec **retour arrière**, et chaque décision est inscrite dans un **journal** (`decisions.jsonl`).

**Sans gêner la détection :** l'apprentissage (environ 1 s pour 200 000 fenêtres sur un PC, davantage sur un Raspberry Pi) calcule sur une copie des données, sans tenir le verrou que le moteur de détection prend à chaque fin de fenêtre. Pendant ce calcul, un second apprentissage, une validation ou un retour arrière sont refusés avec un message. La sauvegarde, incrémentale, s'exécute dans un thread dédié.

**Mise en route :**
1. Activer `[detection.anomaly]` avec un `data_dir`, et définir `web.token` : sans jeton, le dashboard ne permet ni de répondre ni de valider.
2. Laisser observer : le premier apprentissage automatique a lieu après `learning_hours` (une semaine par défaut), ou plus tôt avec le bouton « Lancer un apprentissage ».
3. Valider le premier modèle dans le panneau « Comportement normal » du dashboard.
4. Rester quelques semaines en mode `observation` (anomalies en `info`, sans LLM) avant de passer en mode `alert`.

Conception détaillée, choix et limites : [docs/conception-normalite.md](conception-normalite.md).

**MITRE :** couverture transverse, selon le comportement (découverte, exfiltration, C2…).
