# Sécurité de l'agent lui-même

Un outil de détection est une cible de choix : il voit tout le réseau. Plusieurs précautions sont déjà prises.

- **Privilèges minimaux :** pas besoin d'être root, seulement `CAP_NET_RAW`/`CAP_NET_ADMIN` pour la capture et le groupe `systemd-journal` pour les logs.
- **Contenu non conservé :** seules les métadonnées des paquets sont gardées, jamais leur contenu, et rien n'est écrit sur disque.
- **Dashboard sur localhost par défaut.** Si tu l'exposes, définis `web.token` avec une valeur longue et aléatoire (`openssl rand -hex 32`), et place-le idéalement derrière un reverse proxy HTTPS ou un VPN. La comparaison du jeton se fait en temps constant.
- **Dashboard protégé contre l'injection :** les données venant du réseau sont toujours affichées comme du texte.
- **Modèle local :** les alertes, IP et logs envoyés au modèle ne quittent pas la machine, tant que `llm.base_url` pointe vers un serveur local.
- **Prompt injection :** les preuves envoyées au modèle peuvent contenir du texte choisi par l'attaquant, par exemple un nom d'utilisateur SSH. Un attaquant pourrait tenter d'influencer le verdict de cette façon. Le verdict de l'IA ne modifie jamais la sévérité calculée par les détecteurs et ne déclenche aucune action automatique. Garde un regard humain sur les décisions.
