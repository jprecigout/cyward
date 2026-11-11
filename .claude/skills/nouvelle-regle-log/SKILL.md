---
name: nouvelle-regle-log
description: Ajoute à Cyward une règle de détection sur les journaux système (sshd, sudo, su, noyau, nginx, applications…), soit comme règle intégrée en Rust, soit comme règle personnalisée dans la configuration. À utiliser quand on demande de détecter un événement dans les logs, d'ajouter une règle de log, une regex d'alerte, ou de surveiller un nouveau programme via journald ou un fichier.
---

# Ajouter une règle de log

Les lignes de logs arrivent dans `LogAnalyzer::analyze` (`src/logs.rs`) sous forme de `LogLine` (horodatage, programme, message), depuis `journalctl -f -o json` ou `tail -F`.

## 1. Choisir : règle de configuration ou règle intégrée ?

**Règle de configuration** (aucun code) quand une simple regex suffit, sans mémoire d'un événement à l'autre :

```toml
[[detection.custom_log_rules]]
name = "wordpress-login"
pattern = '(?P<ip>\d+\.\d+\.\d+\.\d+) .*"POST /wp-login\.php'
severity = "low"
title = "Tentative de connexion WordPress"
```

Un groupe nommé `ip` devient la source de l'alerte. Les répétitions de la même IP sont fusionnées. Si les lignes viennent d'un fichier (nginx, Apache…), l'ajouter dans `logs.files`. S'arrêter là : documenter la règle dans `config.example.toml` si elle est d'intérêt général.

**Règle intégrée** (en Rust) quand il faut :
- corréler plusieurs lignes (compter des échecs, détecter un succès après des échecs) ;
- extraire plusieurs champs pour la description ;
- que la règle soit active pour tous, sans configuration.

## 2. Récupérer de vraies lignes d'exemple

Ne jamais écrire une regex à partir d'un format supposé. Récupérer des lignes réelles :

```bash
journalctl -o cat -t sshd -n 20       # par identifiant syslog
journalctl -o json -n 5 _COMM=sudo    # pour voir les champs journald
```

Ces lignes (anonymisées si besoin) servent ensuite de données de test.

## 3. Implémenter une règle intégrée

Dans `src/logs.rs` :

1. **Champ** dans `LogAnalyzer` : `nom: Regex`, avec un `///` qui dit ce que la règle repère.
2. **Compilation** dans `LogAnalyzer::new`, à côté des autres. Utiliser la constante `IP` pour capturer une adresse, et des groupes nommés (`(?P<user>…)`). Les regex Rust s'exécutent en temps linéaire : une ligne piégée ne peut pas bloquer l'analyse.
3. **Bloc** dans `analyze`, précédé d'un commentaire `// --- <événement> ---` comme les autres :
   ```rust
   // --- <Événement> : <pourquoi c'est suspect> ---
   if let Some(c) = self.nom.captures(msg) {
       out.push(
           Alert::new(AlertKind::Xxx, Severity::Medium, AlertSource::Logs, ts, format!("<Titre> {}", &c["user"]))
               .description("<Explication pour l'analyste.>")
               .src(&c["user"])
               .evidence(evidence()),
       );
   }
   ```
   - `evidence()` joint la ligne brute et le programme. Elle peut contenir du texte choisi par un attaquant ; le dashboard l'affiche comme du texte, ne jamais changer cela.
   - Une règle avec mémoire (compteurs par IP, par compte) garde son état dans une `HashMap` du `LogAnalyzer`, sur le modèle de `failures`, **avec une purge** (voir la fin de `analyze`).
   - Pour un nouveau type d'alerte, ajouter une variante à `AlertKind` (`src/alert.rs`) ; sinon réutiliser `PrivilegeEscalation`, `AccountChange`, etc.
4. **Tests** dans le module `tests` de `logs.rs`, avec les vraies lignes récupérées à l'étape 2 :
   - un cas positif (la ligne déclenche l'alerte attendue, avec la bonne sévérité) ;
   - un cas négatif (une ligne voisine mais légitime ne déclenche rien) ;
   - pour une règle avec mémoire : sous le seuil → rien, au seuil → une alerte, au-delà → pas d'autre alerte.
5. **Documentation** : une ligne dans le tableau de la section 3.7 du README (règle, exemple de ligne, alerte).
6. **Vérifier** avec le skill `verifier` : `.claude/skills/verifier/check.sh`.

## Pièges connus

- sshd écrit `Invalid user X from IP` **puis** `Failed password for invalid user X from IP` pour une même tentative : ne compter qu'une des deux lignes.
- Si `journald = true` et qu'un fichier comme `/var/log/auth.log` est aussi suivi, chaque ligne arrive deux fois.
- Les lignes de fichiers texte sont horodatées à la réception (`Utc::now()`), celles de journald avec leur date d'origine.
