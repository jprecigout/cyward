# Installation

## Prérequis

- Linux (la capture utilise `AF_PACKET`, les logs utilisent `journalctl` ou `tail`).
- Rust 1.88 ou plus récent (édition 2024). Installation : `curl https://sh.rustup.rs -sSf | sh`.
- Pour le modèle : 8 Go de RAM libre et ~6 Go de disque.

Aucune bibliothèque système n'est nécessaire : ni libpcap, ni OpenSSL.

## Le modèle

```bash
curl -fsSL https://ollama.com/install.sh | sh
```
```bash
ollama pull hf.co/mradermacher/Foundation-Sec-8B-Instruct-GGUF:IQ4_XS
```

Pour vérifier que le modèle répond :

```bash
ollama run hf.co/mradermacher/Foundation-Sec-8B-Instruct-GGUF:IQ4_XS "Qu'est-ce que la technique MITRE T1110 ?"
```

## L'agent

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

## Avec Docker (Linux)

[`compose.yaml`](../compose.yaml) lance trois services :

| Service | Rôle |
|---|---|
| `ollama` | Serveur du modèle, port publié sur `127.0.0.1:11434`, modèles dans le volume `ollama` |
| `ollama-pull` | Télécharge le modèle s'il est absent, puis s'arrête |
| `cyward` | L'agent, construit depuis le [`Dockerfile`](../Dockerfile) (image d'environ 105 Mo) |

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
- **Configuration** : [`docker/cyward.toml`](../docker/cyward.toml), monté dans `/etc/cyward/cyward.toml`. Une modification se prend en compte avec `docker compose restart cyward`.
- **Secrets (jeton ntfy, `web.token`…)** : ne jamais les écrire dans `docker/cyward.toml`, qui est versionné. Copie-le en `docker/cyward.local.toml` et crée un `compose.override.yaml`, chargé automatiquement par `docker compose`, qui monte cette copie à sa place. Les deux fichiers sont ignorés par git :
  ```yaml
  services:
    cyward:
      volumes:
        - ./docker/cyward.local.toml:/etc/cyward/cyward.toml:ro
  ```
- **Historique des alertes** : activé dans l'image, dans `/var/lib/cyward/alerts.db` (volume `cyward-data`).
- **Apprentissage du comportement normal** : activé dans l'image, en mode observation. Ses données sont dans le volume `cyward-data` (`/var/lib/cyward`), seul emplacement accessible en écriture. Définir `web.token` pour pouvoir répondre et valider depuis le dashboard.
- **Modèle** : IQ4_XS par défaut. Pour en changer, modifie `llm.model` dans `docker/cyward.toml` (la ligne Q4_K_M y est prête en commentaire) **et** définis `CYWARD_MODEL` avec la même valeur dans `.env`, puis `docker compose up -d`. Pour revenir à Q4_K_M, la ligne à mettre dans `.env` :
  ```
  CYWARD_MODEL=hf.co/mradermacher/Foundation-Sec-8B-Instruct-GGUF:Q4_K_M
  ```
- **GPU NVIDIA** : décommente le bloc `deploy` du service `ollama` (nécessite `nvidia-container-toolkit`).

**Rejouer un pcap avec l'image :**

```bash
docker run --rm -v "$PWD:/data:ro" cyward:latest replay /data/capture.pcap
```

**Lancer l'agent seul, sans Ollama** (triage IA hors ligne, alertes en attente) :

```bash
docker compose run --rm --no-deps cyward
```
