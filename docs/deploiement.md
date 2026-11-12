# Déploiement

## Où déployer l'agent dans le réseau

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

## Lancer l'agent comme service systemd

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
