# Utilisation

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
| `cyward replay capture.pcap --serve --speed 20` | Rejoue au rythme de la capture accéléré 20 fois, pour suivre l'onglet Flux. Le rejeu attend que l'onglet soit ouvert |
| `cyward check-llm` | Teste la connexion au modèle |
| `cyward check-notify` | Envoie une notification de test sur chaque canal de `[notify]` |

Sans `-c`, toutes les valeurs par défaut s'appliquent.

**Choix de l'interface.** Si `capture.interface` est vide, l'agent prend celle qui porte la **route par défaut** (lue dans `/proc/net/route`), c'est-à-dire celle qui voit le trafic vers Internet. Les ponts Docker et les tunnels VPN sont ainsi écartés. À défaut, il prend la première interface active non-loopback.

**Bannière de démarrage.** `run` et `replay --serve` affichent d'abord le logo (bouclier et pulsation), la version, puis un résumé de ce que l'agent va réellement faire, une fois les options appliquées :

```
  ╭─────────────╮    ██████╗██╗   ██╗██╗    ██╗ █████╗ ██████╗ ██████╗
  │      ╱╲     │   ██╔════╝╚██╗ ██╔╝██║    ██║██╔══██╗██╔══██╗██╔══██╗
  │ ────╱  ╲  ──│   ██║      ╚████╔╝ ██║ █╗ ██║███████║██████╔╝██║  ██║
  │         ╲╱  │   ██║       ╚██╔╝  ██║███╗██║██╔══██║██╔══██╗██║  ██║
   ╲           ╱    ╚██████╗   ██║   ╚███╔███╔╝██║  ██║██║  ██║██████╔╝
     ╲       ╱       ╚═════╝   ╚═╝    ╚══╝╚══╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝
       ╲   ╱        Détection d'intrusions · triage par IA locale
         V          v0.1.0

  Dashboard   http://127.0.0.1:8080
  Capture     interface de la route par défaut
  Logs        journald
  Modèle IA   hf.co/mradermacher/Foundation-Sec-8B-Instruct-GGUF:IQ4_XS
```

- Dans un terminal, elle est en couleur : bouclier bleu, pulsation verte, nom en dégradé.
- Les couleurs (de la bannière comme des journaux) sont coupées automatiquement quand la sortie n'est pas un terminal (`docker logs`, journal systemd, redirection vers un fichier), ou si la variable `NO_COLOR` est définie.
- Si un jeton protège le dashboard, le résumé affiche `?token=…` sans jamais montrer sa valeur.
- `replay` sans `--serve` n'affiche pas de bannière : sa sortie est un rapport destiné à être lu ou traité par un script.

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
