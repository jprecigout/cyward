# Limites et évolutions

## Limites connues

- **Détection comportementale, pas par signatures.** Cyward repère des comportements (rythmes, volumes, diversité) mais ne reconnaît pas un exploit précis dans le contenu d'un paquet. Il **complète** un IDS à signatures comme Suricata ou un outil comme Zeek, il ne les remplace pas.
- **Trafic chiffré :** seules les métadonnées sont analysées. Une exfiltration lente et régulière sous le seuil de volume passera inaperçue.
- **Domaine DNS naïf :** le domaine est pris comme les deux derniers segments. `exemple.co.uk` est donc vu comme `co.uk`, ce qui peut fusionner des domaines distincts dans le détecteur de tunnel.
- **Beaconing :** seul le TCP est suivi ; une balise en UDP ou QUIC n'est pas détectée.
- **Listes de menaces :** lues au démarrage seulement ; une mise à jour demande un redémarrage, qui remet à zéro l'état des autres détecteurs.
- **ARP :** seul l'ARP IPv4 est suivi ; l'équivalent IPv6 (NDP, usurpation de voisins ou de routeur) ne l'est pas. Une attaque déjà en place au démarrage de l'agent passe pour l'état normal jusqu'à ce que la vraie machine s'annonce.
- **Fragmentation et IPv6 :** les fragments IP et les en-têtes d'extension IPv6 exotiques peuvent échapper au parsing.
- **Historique :** sans `history.path`, 5 000 alertes au maximum, perdues au redémarrage. Avec, le dashboard et l'API ne montrent toujours que les 5 000 plus récentes ; le reste de la base se consulte avec `sqlite3`. Une analyse IA interrompue par l'arrêt ne reprend pas (l'alerte revient « non analysée »). L'apprentissage du volume repart de zéro.
- **Un seul analyseur IA à la fois :** sur CPU, une rafale d'alertes peut prendre plusieurs minutes à être analysée.
- **Fiabilité du LLM :** le modèle peut se tromper ou inventer une technique MITRE. Ses verdicts sont une aide au tri, pas une vérité.
- **Linux uniquement** pour la capture live et la lecture des logs. Le rejeu de pcap fonctionne partout.

## Pistes d'évolution

- **Historique** : recherche dans les alertes enregistrées depuis le dashboard (par hôte, type, période), au-delà des 5 000 gardées en mémoire.
- **Export vers un SIEM** dans des formats natifs : syslog, fichier JSON lignes, Loki, Elasticsearch, Wazuh. Le webhook des notifications transmet déjà l'alerte complète, mais seulement pour les alertes notifiées.
- **Notifications par e-mail** (SMTP), en plus de ntfy et du webhook.
- **Ingestion des alertes Suricata** (`eve.json`) et des logs Zeek, pour combiner signatures et comportement.
- **Réponse active** optionnelle et validée par un humain : blocage d'IP via nftables.
- **Apprentissage** : persister l'état du détecteur de volume, qui repart de zéro à chaque redémarrage, et le modèle candidat en attente de validation.
- **Détections supplémentaires** : nouveaux appareils sur le réseau, usurpation NDP en IPv6, TLS/JA3/JA4, téléchargement et rechargement des listes de menaces sans redémarrage.
- **Capture haute performance** avec AF_XDP ou eBPF.

Les notifications (ntfy, webhook), l'apprentissage du comportement normal par Isolation Forest, l'usurpation ARP et les listes de menaces, autrefois dans cette liste, sont implémentés : voir [`[notify]`](configuration.md#notify) et, dans les détecteurs, les [listes de menaces](detecteurs.md#listes-de-menaces-threatlist), l'[usurpation ARP](detecteurs.md#usurpation-arp-arpspoofing) et l'[apprentissage du comportement normal](detecteurs.md#apprentissage-du-comportement-normal-hostanomaly).
