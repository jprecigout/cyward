# Le modèle de langage (triage IA)

## Le modèle par défaut : Foundation-Sec-8B-Instruct

[Foundation-Sec-8B-Instruct](https://huggingface.co/fdtn-ai/Foundation-Sec-8B-Instruct) est un modèle publié en open weights par **Cisco Foundation AI**. Il est construit sur **Llama 3.1 8B**, pré-entraîné sur un large corpus de cybersécurité (CVE, rapports de menaces, MITRE ATT&CK, documentation d'outils de sécurité), puis ajusté pour suivre des instructions. Il est donc plus pertinent qu'un modèle généraliste de même taille pour qualifier une alerte et citer les bonnes techniques ATT&CK.

Cyward utilise par défaut une **quantification IQ4_XS au format GGUF**, publiée par mradermacher sur Hugging Face. Elle est un peu plus légère que la Q4_K_M, la référence habituelle, pour une qualité quasi identique :

| | IQ4_XS (défaut) | Q4_K_M |
|---|---|---|
| Taille sur disque | 4,5 Go | 4,9 Go |
| RAM nécessaire | ~5,5 à 7 Go | ~6 à 8 Go |
| GPU | facultatif (NVIDIA, AMD ou Apple accélèrent fortement) | idem |
| Durée d'une analyse sur CPU 8–12 cœurs | ~20 à 90 s | idem, un peu plus lente |
| Durée avec GPU | quelques secondes | idem |

**Machine modeste :** `llm.min_severity = "high"` ne fait analyser que les alertes hautes et critiques. Le CPU est moins sollicité, mais les comportements suspects (balises, DNS, ARP hors IP protégées, anomalies en mode `alert`) n'ont plus de verdict de l'IA ; ils restent visibles dans le dashboard et servent de contexte au modèle pour les alertes du même hôte. Ce réglage est propre à une machine : mets-le dans ta configuration locale (avec Docker, `docker/cyward.local.toml`, voir [Avec Docker](installation.md#avec-docker-linux)), pas dans les fichiers versionnés.

**Revenir à Q4_K_M**, si la machine a de la marge :

```bash
ollama pull hf.co/mradermacher/Foundation-Sec-8B-Instruct-GGUF:Q4_K_M
```

puis, dans la configuration, la ligne déjà prête en commentaire dans `config.example.toml` :

```toml
[llm]
model = "hf.co/mradermacher/Foundation-Sec-8B-Instruct-GGUF:Q4_K_M"
```

Avec Docker, voir [Avec Docker](installation.md#avec-docker-linux) (`CYWARD_MODEL`). Les autres quantifications publiées (Q3_K_M, Q5_K_M, Q8_0…) se choisissent de la même façon, en changeant le suffixe.

Licence : consulte la fiche Hugging Face du modèle avant un usage commercial. Cisco recommande de l'utiliser avec une supervision humaine.

## Utiliser un autre modèle ou un autre serveur

Cyward parle l'**API compatible OpenAI** (`POST /v1/chat/completions`, `GET /v1/models`). Tout serveur qui l'expose fonctionne : il suffit de changer `llm.base_url` et `llm.model`.

| Serveur | `base_url` | Exemple de `model` |
|---|---|---|
| Ollama | `http://127.0.0.1:11434/v1` | `hf.co/mradermacher/Foundation-Sec-8B-Instruct-GGUF:IQ4_XS` |
| llama.cpp (`llama-server -m modele.gguf`) | `http://127.0.0.1:8080/v1` | nom du fichier chargé |
| vLLM | `http://127.0.0.1:8000/v1` | `fdtn-ai/Foundation-Sec-8B-Instruct` |

Si le serveur exige une clé, renseigne `llm.api_key` : elle est envoyée en `Authorization: Bearer`. Attention : avec llama.cpp sur le port 8080, déplace le dashboard ailleurs (`web.listen`).

D'autres modèles orientés sécurité peuvent convenir, comme d'autres versions de Foundation-Sec ou les modèles Llama-Primus de Trend Micro. Un modèle généraliste récent marche aussi, avec des analyses moins précises sur le vocabulaire sécurité.

## Ce qui est envoyé au modèle

**Le message système** fixe le rôle et le format de réponse : analyste SOC niveau 3, réponse uniquement en JSON, ne rien supposer qui ne figure pas dans les données, réponse dans la langue de `llm.language`.

**Le message utilisateur** contient :
- l'alerte (type, sévérité, origine, titre, description, source, cible, nombre d'occurrences, dates, preuves) ;
- jusqu'à 8 autres alertes récentes impliquant les mêmes adresses. Par exemple, une force brute SSH précédée d'un scan venant de la même IP : le modèle peut alors relier les deux.

**Réglages de génération :** température 0,1 pour des réponses stables, 700 tokens au maximum, `response_format: json_object`.

**Réponse attendue :**

```json
{
  "verdict": "malveillant",
  "confidence": 0.9,
  "summary": "203.0.113.4 a ouvert une session root après 14 échecs : le mot de passe a très probablement été deviné par force brute.",
  "mitre": ["T1110.001", "T1078"],
  "recommendations": [
    "Couper immédiatement la session et bloquer 203.0.113.4 au pare-feu",
    "Changer le mot de passe root et interdire PermitRootLogin dans sshd_config",
    "Examiner l'historique de commandes et les crontabs pour une persistance"
  ]
}
```

Les petits modèles enrobent parfois le JSON dans du texte ou des balises ```` ``` ````. Le parseur extrait l'objet entre la première `{` et la dernière `}`. Il accepte aussi une confiance exprimée en pourcentage (`"85%"`) et un champ `mitre` en chaîne simple.

## Comportement en cas d'indisponibilité

- Si le serveur est injoignable ou si le modèle n'est pas installé, un avertissement apparaît dans les logs de l'agent. La pastille « IA » du dashboard passe à « hors ligne ».
- Les alertes restent **en attente** et sont analysées dès le retour du modèle. Elles ne sont jamais marquées en échec pour cette raison.
- La file contient au plus `llm.queue_size` (32) alertes. Au-delà, les nouvelles alertes ne sont pas analysées, mais elles restent visibles.
- Une erreur pendant l'analyse (délai dépassé, JSON illisible) marque l'alerte « IA en échec ».
- La détection n'est jamais ralentie par le modèle.
