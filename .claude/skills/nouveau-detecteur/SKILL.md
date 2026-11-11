---
name: nouveau-detecteur
description: Ajoute un détecteur réseau à Cyward (nouveau type d'attaque repéré à partir des paquets) en suivant les conventions du projet, avec configuration, tests, scénario de simulation et documentation. À utiliser quand on demande d'ajouter, créer ou implémenter un détecteur, une détection réseau, ou de repérer un nouveau type d'attaque ou d'anomalie dans le trafic (ARP spoofing, exfiltration ICMP, nouveaux appareils…).
---

# Ajouter un détecteur réseau

Un détecteur réseau reçoit chaque paquet sous forme de `PacketMeta` (adresses, ports, drapeaux TCP, taille, nom DNS) et produit des `Alert`. Avant d'écrire du code, lire un détecteur existant proche du besoin : `src/detect/scan.rs` (compteurs par fenêtre), `beacon.rs` (série temporelle), `volume.rs` (normale apprise), `dns.rs` (analyse de contenu).

Si l'information nécessaire n'est pas dans `PacketMeta`, l'ajouter dans `src/capture.rs` (`PacketMeta` + `parse_packet`), en extrayant le minimum : le contenu applicatif n'est jamais conservé.

## Règles du projet à respecter

- **Temps des paquets uniquement** : raisonner sur `p.ts` et sur le `now` reçu par `tick`, jamais sur `SystemTime::now()`. C'est ce qui rend le rejeu d'un pcap déterministe et testable.
- **Une alerte par franchissement** : émettre quand le compteur atteint *exactement* le seuil (`==`), pas à chaque paquet au-delà. Les répétitions sont fusionnées par l'`AlertStore` grâce à l'empreinte `type|src|dst`. Sans cible unique (balayage, inondation), fixer l'empreinte avec `.fingerprint(...)`.
- **Chemin critique** : `on_packet` est appelé pour chaque paquet. Filtrer le plus tôt possible (`return` dès que le paquet ne concerne pas le détecteur), et éviter toute allocation dans le cas courant. Une alerte peut allouer, elle est rare.
- **Mémoire bornée** : tout état (`HashMap`…) est purgé dans `tick`. Ajouter un plafond si un attaquant peut faire grossir l'état (adresses usurpées, noms aléatoires).
- **Interne / externe** : utiliser `DetectionConfig::is_local`. Le détecteur reçoit alors une copie de la `DetectionConfig`, comme `PortScan`.
- **Sévérité** : `High` si l'attaque est caractérisée ou vient de l'intérieur ; `Medium` pour un comportement suspect à qualifier (envoyé au LLM par défaut) ; `Low` pour un signal faible.
- **Commentaires en français et tests** : obligatoires (voir CLAUDE.md).

## Étapes

1. **Configuration** (`src/config.rs`) : une struct `XxxConfig` avec `#[derive(Debug, Clone, Deserialize)]`, `#[serde(default)]`, un `///` par champ (avec l'unité) et un `impl Default` qui porte les valeurs par défaut. L'ajouter comme champ de `DetectionConfig` et dans son `Default`.
2. **Type d'alerte** (`src/alert.rs`) : une variante de `AlertKind` avec son `///`. Elle est sérialisée en snake_case dans l'API et le dashboard.
3. **Détecteur** : `src/detect/<nom>.rs`, sur le modèle ci-dessous. Le déclarer (`mod <nom>;`) et l'ajouter à la liste de `Engine::new` dans `src/detect/mod.rs`.
4. **Tests** dans le module : au moins un cas positif (l'attaque est détectée, une seule fois) et un cas négatif (un trafic normal proche ne déclenche rien). Utiliser `crate::detect::testutil::{syn, dns}` ou construire un `PacketMeta`.
5. **Scénario de simulation** dans `examples/gen_attacks.rs` : ajouter l'attaque au scénario (les paquets sont triés à l'écriture). Ajouter la sous-chaîne de son titre dans `EXPECTED_TITLES` de `.claude/skills/verifier/check.sh`.
6. **Configuration d'exemple** : la section `[detection.<nom>]` dans `config.example.toml`, avec les valeurs par défaut et un commentaire par clé.
7. **Documentation** :
   - README section 2 : le nouveau fichier dans l'arborescence ; le tableau des dépendances si le détecteur importe un module de plus ; le tableau des design patterns s'il en introduit un ;
   - README section 3 : une sous-section « 3.x » (ce qui est repéré, fonctionnement, sévérité, faux positifs fréquents, techniques MITRE) ;
   - README section 7 : le tableau de configuration ;
   - README section 8 : le type dans la liste des `kind` ;
   - README section 11 et CLAUDE.md : le nombre d'alertes attendues au rejeu.
8. **Vérifier** avec le skill `verifier` : `.claude/skills/verifier/check.sh`.

## Modèle de détecteur

```rust
//! <Ce que ce détecteur repère, et pourquoi ce comportement est suspect.>

use std::{collections::HashMap, net::IpAddr};

use serde_json::json;

use super::{Detector, ts_to_dt};
use crate::{
    alert::{Alert, AlertKind, AlertSource, Severity},
    capture::{PacketMeta, Proto},
    config::XxxConfig,
};

/// <Résumé en une phrase.>
pub struct Xxx {
    cfg: XxxConfig,
    /// <Clé> → (début de fenêtre, compteur).
    counters: HashMap<IpAddr, (f64, usize)>,
}

impl Xxx {
    pub fn new(cfg: XxxConfig) -> Self {
        Self { cfg, counters: HashMap::new() }
    }
}

impl Detector for Xxx {
    fn on_packet(&mut self, p: &PacketMeta, out: &mut Vec<Alert>) {
        // Filtrer tôt : la plupart des paquets ne concernent pas ce détecteur.
        if p.proto != Proto::Tcp {
            return;
        }
        let (start, count) = self.counters.entry(p.src).or_insert((p.ts, 0));
        // Fenêtre expirée : on repart de zéro.
        if p.ts - *start > self.cfg.window_secs {
            *start = p.ts;
            *count = 0;
        }
        *count += 1;
        // `==` : une seule alerte par fenêtre ; les suivantes sont fusionnées par le store.
        if *count == self.cfg.threshold {
            out.push(
                Alert::new(AlertKind::Xxx, Severity::Medium, AlertSource::Network, ts_to_dt(p.ts), format!("<Titre court> depuis {}", p.src))
                    .description(format!("{} <événements> en moins de {} s. <Ce que cela peut signifier.>", count, self.cfg.window_secs))
                    .src(p.src)
                    .evidence(json!({ "count": count, "window_secs": self.cfg.window_secs })),
            );
        }
    }

    fn tick(&mut self, now: f64, _out: &mut Vec<Alert>) {
        // Oublie les clés inactives depuis deux fenêtres, pour borner la mémoire.
        let w = self.cfg.window_secs;
        self.counters.retain(|_, (start, _)| now - *start <= 2.0 * w);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::detect::testutil::syn;

    // <Cas positif : l'attaque est détectée, une seule fois.>
    #[test]
    fn detects_xxx() {
        let mut d = Xxx::new(XxxConfig::default());
        let mut out = Vec::new();
        for i in 0..100 {
            d.on_packet(&syn(i as f64 * 0.1, "192.168.1.50", "192.168.1.1", 80), &mut out);
        }
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].kind, AlertKind::Xxx);
    }

    // <Cas négatif : un trafic normal proche ne déclenche rien.>
    #[test]
    fn normal_traffic_is_quiet() {
        let mut d = Xxx::new(XxxConfig::default());
        let mut out = Vec::new();
        for i in 0..100 {
            d.on_packet(&syn(i as f64 * 60.0, "192.168.1.50", "192.168.1.1", 80), &mut out);
        }
        assert!(out.is_empty());
    }
}
```
