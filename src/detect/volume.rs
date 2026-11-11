//! Détection d'exfiltration par volume : un hôte interne qui envoie vers Internet beaucoup
//! plus de données que d'habitude.

use std::{collections::HashMap, net::IpAddr};

use serde_json::json;

use super::{Detector, ts_to_dt};
use crate::{
    alert::{Alert, AlertKind, AlertSource, Severity, human_bytes},
    capture::PacketMeta,
    config::{DetectionConfig, VolumeConfig},
};

/// Poids de la nouvelle période dans la moyenne mobile : 0,1 = la normale suit l'évolution
/// des usages sur une dizaine de périodes, sans être déformée par un pic isolé.
const ALPHA: f64 = 0.1;

/// Volume sortant anormal par hôte interne (exfiltration de données).
///
/// Chaque hôte a une moyenne et une variance mobiles (EWMA) de ses octets envoyés vers
/// l'extérieur par période ; on alerte quand une période dépasse largement sa normale.
pub struct Volume {
    cfg: VolumeConfig,
    net: DetectionConfig,
    /// Début de la période en cours (None avant le premier paquet).
    bucket_start: Option<f64>,
    /// Octets sortants par hôte pendant la période en cours.
    current: HashMap<IpAddr, u64>,
    /// Normale apprise pour chaque hôte.
    baselines: HashMap<IpAddr, Baseline>,
}

/// Statistiques mobiles d'un hôte, en octets par période.
#[derive(Default)]
struct Baseline {
    mean: f64,
    var: f64,
    /// Nombre de périodes intégrées (sert à la phase d'apprentissage).
    n: u32,
}

impl Volume {
    pub fn new(cfg: VolumeConfig, net: DetectionConfig) -> Self {
        Self { cfg, net, bucket_start: None, current: HashMap::new(), baselines: HashMap::new() }
    }

    /// Termine une période : compare chaque hôte à sa normale, puis met cette normale à jour.
    fn close_bucket(&mut self, end: f64, out: &mut Vec<Alert>) {
        // On vide les compteurs de la période ; la suivante repart de zéro.
        let current = std::mem::take(&mut self.current);
        // Tous les hôtes connus sont évalués, y compris ceux qui n'ont rien envoyé (x = 0).
        for (host, b) in self.baselines.iter_mut() {
            let x = current.get(host).copied().unwrap_or(0) as f64;
            // Deux conditions : normale assez apprise, et volume significatif en valeur absolue.
            if b.n >= self.cfg.warmup_buckets && x >= self.cfg.min_bytes as f64 {
                // Plancher sur l'écart-type pour qu'un hôte très régulier ne déclenche pas au moindre écart.
                let std = b.var.sqrt().max(b.mean * 0.25).max(1_000_000.0);
                // Score z : de combien d'écarts-types la période dépasse la moyenne.
                let z = (x - b.mean) / std;
                if z >= self.cfg.zscore {
                    out.push(
                        Alert::new(AlertKind::VolumeAnomaly, Severity::High, AlertSource::Network, ts_to_dt(end), format!("Volume sortant anormal depuis {host}"))
                            .description(format!(
                                "{} envoyés vers l'extérieur en {} s, contre {} habituellement (z = {:.1}). Possible exfiltration de données.",
                                human_bytes(x),
                                self.cfg.bucket_secs,
                                human_bytes(b.mean),
                                z
                            ))
                            .src(host)
                            .evidence(json!({ "bytes": x as u64, "baseline_bytes": b.mean as u64, "zscore": z })),
                    );
                }
            }
            // Mise à jour incrémentale de la moyenne et de la variance mobiles exponentielles.
            let delta = x - b.mean;
            b.mean += ALPHA * delta;
            b.var = (1.0 - ALPHA) * (b.var + ALPHA * delta * delta);
            b.n += 1;
        }
        // Les hôtes vus pour la première fois obtiennent une normale vide ; leur
        // apprentissage commence à la période suivante.
        for host in current.into_keys() {
            self.baselines.entry(host).or_default();
        }
    }

    /// Clôt la période en cours (et les éventuelles périodes vides qui suivent) si `now` l'a dépassée.
    fn roll(&mut self, now: f64, out: &mut Vec<Alert>) {
        let Some(start) = self.bucket_start else {
            self.bucket_start = Some(now);
            return;
        };
        if now - start >= self.cfg.bucket_secs {
            let end = start + self.cfg.bucket_secs;
            self.close_bucket(end, out);
            // Périodes entières sans trafic : elles comptent comme des zéros dans la normale.
            let mut next = end;
            let mut gaps = 0;
            while now - next >= self.cfg.bucket_secs && gaps < 60 {
                next += self.cfg.bucket_secs;
                self.close_bucket(next, out);
                gaps += 1;
            }
            if now - next >= self.cfg.bucket_secs {
                next = now; // très long silence : inutile de rejouer chaque période vide
            }
            self.bucket_start = Some(next);
        }
    }
}

impl Detector for Volume {
    fn on_packet(&mut self, p: &PacketMeta, out: &mut Vec<Alert>) {
        // Clore d'abord la période si ce paquet appartient déjà à la suivante.
        self.roll(p.ts, out);
        // Seul le trafic interne → externe compte.
        if self.net.is_local(&p.src) && !self.net.is_local(&p.dst) {
            *self.current.entry(p.src).or_default() += p.len as u64;
        }
    }

    fn tick(&mut self, now: f64, out: &mut Vec<Alert>) {
        self.roll(now, out);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::detect::testutil::syn;

    #[test]
    fn detects_exfiltration_spike() {
        let cfg = VolumeConfig::default();
        let mut d = Volume::new(cfg.clone(), DetectionConfig::default());
        let mut out = Vec::new();
        // Paquet réutilisé : seuls l'horodatage et la taille changent.
        let mut pkt = syn(0.0, "192.168.1.30", "203.0.113.5", 443);

        // 30 minutes de trafic normal : ~1 Mo par minute.
        for minute in 0..30 {
            for i in 0..100 {
                pkt.ts = minute as f64 * 60.0 + i as f64 * 0.5;
                pkt.len = 10_000;
                d.on_packet(&pkt, &mut out);
            }
        }
        assert!(out.is_empty());

        // Puis 200 Mo en une minute.
        for i in 0..2000 {
            pkt.ts = 30.0 * 60.0 + i as f64 * 0.02;
            pkt.len = 100_000;
            d.on_packet(&pkt, &mut out);
        }
        // Le tick clôt la période du pic.
        d.tick(32.0 * 60.0, &mut out);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].kind, AlertKind::VolumeAnomaly);
    }
}
