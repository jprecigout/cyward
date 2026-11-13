# Tests et simulation d'attaques

## Qualité du code

Avant de proposer une modification, le code doit être formaté et sans avertissement :

```bash
cargo fmt                    # formate selon rustfmt.toml ; cargo fmt --check vérifie sans modifier
cargo clippy --all-targets   # aucun avertissement toléré
```

Le script `.claude/skills/verifier/check.sh` enchaîne ces contrôles, les tests et le rejeu ci-dessous.

## Tests unitaires

```bash
cargo test
```

170 tests couvrent :
- le parsing des paquets, du DNS et de l'ARP, et des formats de listes de menaces ;
- chaque détecteur, cas positifs et négatifs (un scan lent ou un trafic irrégulier ne doivent pas déclencher), et le plafond mémoire des détecteurs exposés aux adresses usurpées ;
- les règles de logs, cas positifs et négatifs (lignes ordinaires, regex personnalisée invalide), et le décodage des lignes journald et texte ;
- la fusion des alertes ;
- l'extraction du JSON renvoyé par le modèle ;
- l'apprentissage du comportement normal : l'Isolation Forest (point isolé, reproductibilité, sérialisation), les caractéristiques, le diff (bruit, nouveau comportement, dérive), le cycle de vie complet avec ses garde-fous (validation obligatoire, réponses, exceptions, refus, fenêtres exclues, retour arrière, calcul en cours qui bloque les décisions concurrentes), la persistance (sauvegarde incrémentale, compaction, reprise de l'ancien format, ligne coupée) ;
- le résumé du trafic par seconde de l'onglet Flux (cumul, 50 couples les plus lourds, plafond mémoire) et la cadence du rejeu ralenti ;
- le contrôle d'accès des routes d'écriture et le résumé de la bannière.

## Simulation d'attaques

Le programme d'exemple génère un pcap de 40 minutes. Il contient le trafic normal d'un portable (navigation, DNS ordinaire) et le scénario d'un poste compromis :

1. balise C2 toutes les 60 s vers `198.51.100.66:8443` ;
2. force brute SSH d'un attaquant externe sur le serveur ;
3. scan de 200 ports du serveur par le poste compromis ;
4. balayage du port 445 sur 40 machines ;
5. exfiltration par tunnel DNS (300 sous-domaines encodés) ;
6. envoi de ~85 Mo en une minute vers le serveur C2 ;
7. connexion vers `192.0.2.200`, serveur C2 présent dans la liste de menaces d'exemple ;
8. usurpation ARP de la passerelle `192.168.1.1` par le poste compromis.

Le pcap contient aussi les annonces ARP ordinaires de la passerelle et du portable, qui ne doivent rien déclencher. La configuration [`examples/rejeu.toml`](../examples/rejeu.toml) charge la liste [`examples/menaces.txt`](../examples/menaces.txt) et protège la passerelle ; les chemins sont relatifs à la racine du dépôt.

```bash
cargo run --example gen_attacks -- attaques.pcap
```
```bash
cargo run -- -c examples/rejeu.toml replay attaques.pcap
```

Résultat attendu (les heures sont celles du pcap, en UTC) :

```
61773 paquets, 88668451 octets analysés, 8 alerte(s)
[  Medium] 2026-11-11 10:09:41 Balise périodique de 192.168.1.20 vers 198.51.100.66:8443  (x12)
[    High] 2026-11-11 10:10:22 Force brute probable sur 192.168.1.10:22 depuis 203.0.113.77  (x1)
[    High] 2026-11-11 10:15:01 Scan de ports de 192.168.1.20 vers 192.168.1.10  (x1)
[    High] 2026-11-11 10:16:02 Balayage du port 445 par 192.168.1.20  (x1)
[    High] 2026-11-11 10:21:14 Tunnel DNS probable de 192.168.1.20 via tunnel-exfil.net  (x1)
[    High] 2026-11-11 10:23:20 Connexion vers une IP listée : 192.0.2.200  (x1)
[    High] 2026-11-11 10:25:00 Usurpation ARP de 192.168.1.1 (IP protégée)  (x1)
[    High] 2026-11-11 10:31:00 Volume sortant anormal depuis 192.168.1.20  (x1)
```

Sans `-c examples/rejeu.toml`, le rejeu donne 7 alertes : pas de liste de menaces, et l'usurpation ARP est de sévérité moyenne.

Pour voir l'analyse de l'IA, ajoute `--serve` et ouvre le dashboard. Comme toutes ces alertes concernent `192.168.1.20`, le modèle reçoit les autres en contexte et peut reconstituer la chaîne d'attaque.

## Tester en conditions réelles

Ne le fais que sur **ton propre réseau ou un réseau où tu es autorisé**.

- **Scan :** depuis une autre machine, lance `nmap -sS <ip>`.
- **Force brute SSH :** échoue volontairement plusieurs fois à te connecter en SSH.
- **sudo refusé :** avec un compte sans droits, lance `sudo -l`.
- **Usurpation ARP :** depuis une machine de test, `arpspoof -i <interface> -t <victime> <passerelle>` (paquet `dsniff`).
