//! Détection des balises périodiques : un implant malveillant contacte son serveur de
//! commande (C2) à intervalle régulier pour récupérer des ordres. Un humain ne produit pas
//! des connexions aussi régulières ; une tâche automatique légitime, si.

use std::{
    collections::{HashMap, HashSet, VecDeque},
    net::IpAddr,
};

use serde_json::json;

use super::{Detector, ts_to_dt};
use crate::{
    alert::{Alert, AlertKind, AlertSource, Severity},
    capture::{PacketMeta, Proto},
    config::{BeaconConfig, DetectionConfig},
};

/// Nombre maximal de triplets suivis simultanément (borne mémoire).
const MAX_TRACKED: usize = 200_000;

/// Connexions sortantes à intervalle quasi régulier : signature typique d'un implant
/// qui contacte son serveur de commande (C2).
pub struct Beaconing {
    cfg: BeaconConfig,
    net: DetectionConfig,
    ignore: HashSet<u16>,
    /// (source, destination, port) → dates des dernières ouvertures de connexion.
    series: HashMap<(IpAddr, IpAddr, u16), VecDeque<f64>>,
}

impl Beaconing {
    pub fn new(cfg: BeaconConfig, net: DetectionConfig) -> Self {
        let ignore = cfg.ignore_ports.iter().copied().collect();
        Self { cfg, net, ignore, series: HashMap::new() }
    }
}

impl Detector for Beaconing {
    fn on_packet(&mut self, p: &PacketMeta, out: &mut Vec<Alert>) {
        // Seules les connexions TCP d'un hôte interne vers l'extérieur sont suivies :
        // le trafic interne régulier (supervision, sauvegardes) produirait trop de bruit.
        if p.proto != Proto::Tcp
            || !p.tcp.is_connection_start()
            || self.ignore.contains(&p.dport)
            || !self.net.is_local(&p.src)
            || self.net.is_local(&p.dst)
        {
            return;
        }
        let key = (p.src, p.dst, p.dport);
        // Au-delà du plafond, on continue de suivre les séries existantes mais on n'en crée plus.
        if !self.series.contains_key(&key) && self.series.len() >= MAX_TRACKED {
            return;
        }
        let times = self.series.entry(key).or_default();
        if times.back().is_some_and(|&last| p.ts - last < 1.0) {
            return; // retransmission de SYN ou connexions parallèles
        }
        // Fenêtre glissante des `min_samples + 1` dernières dates, soit `min_samples` intervalles.
        times.push_back(p.ts);
        if times.len() > self.cfg.min_samples + 1 {
            times.pop_front();
        }
        if times.len() < self.cfg.min_samples + 1 {
            return;
        }

        // Intervalles entre dates consécutives, puis leur régularité.
        let intervals: Vec<f64> = times.iter().zip(times.iter().skip(1)).map(|(a, b)| b - a).collect();
        let (mean, cv) = mean_and_cv(&intervals);
        if mean >= self.cfg.min_interval_secs && cv <= self.cfg.max_jitter {
            out.push(
                Alert::new(AlertKind::Beaconing, Severity::Medium, AlertSource::Network, ts_to_dt(p.ts), format!("Balise périodique de {} vers {}:{}", p.src, p.dst, p.dport))
                    .description(format!(
                        "{} connexions successives espacées de {:.1} s (variation {:.1} %). Peut indiquer un implant contactant un serveur C2, ou une tâche planifiée légitime.",
                        times.len(),
                        mean,
                        cv * 100.0
                    ))
                    .src(p.src)
                    .dst(format!("{}:{}", p.dst, p.dport))
                    .evidence(json!({ "interval_secs": mean, "jitter": cv, "samples": intervals })),
            );
            // Chaque nouvelle balise régulière ré-émet l'alerte : le store la fusionne et incrémente son compteur.
        }
    }

    fn tick(&mut self, now: f64, _out: &mut Vec<Alert>) {
        // Oublie les séries sans connexion depuis deux heures.
        self.series.retain(|_, t| t.back().is_some_and(|&last| now - last < 7200.0));
    }
}

/// Moyenne et coefficient de variation (écart-type ÷ moyenne) d'une série.
/// Le coefficient de variation mesure la régularité indépendamment de l'échelle :
/// 0,1 signifie que les intervalles s'écartent en moyenne de 10 % de leur valeur moyenne.
fn mean_and_cv(xs: &[f64]) -> (f64, f64) {
    let n = xs.len() as f64;
    let mean = xs.iter().sum::<f64>() / n;
    let var = xs.iter().map(|x| (x - mean).powi(2)).sum::<f64>() / n;
    (mean, if mean > 0.0 { var.sqrt() / mean } else { f64::INFINITY })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::detect::testutil::syn;

    // Une connexion toutes les 30 s à ±0,4 s près.
    #[test]
    fn detects_regular_beacon() {
        let mut d = Beaconing::new(BeaconConfig::default(), DetectionConfig::default());
        let mut out = Vec::new();
        for i in 0..12 {
            let jitter = if i % 2 == 0 { 0.4 } else { -0.4 };
            d.on_packet(&syn(i as f64 * 30.0 + jitter, "192.168.1.20", "203.0.113.66", 443), &mut out);
        }
        // 12 connexions : alerte dès la 9e, puis à chaque nouvelle balise.
        assert_eq!(out.len(), 4);
        assert!(out.iter().all(|a| a.kind == AlertKind::Beaconing));
    }

    // Intervalles pseudo-aléatoires entre 5 et 64 s : pas de régularité.
    #[test]
    fn irregular_traffic_is_ignored() {
        let mut d = Beaconing::new(BeaconConfig::default(), DetectionConfig::default());
        let mut out = Vec::new();
        let mut t = 0.0;
        for i in 0..30 {
            t += 5.0 + (i * 37 % 60) as f64;
            d.on_packet(&syn(t, "192.168.1.20", "203.0.113.66", 443), &mut out);
        }
        assert!(out.is_empty());
    }
}
