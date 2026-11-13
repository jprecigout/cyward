//! Détection d'exfiltration par volume : un hôte interne qui envoie vers Internet beaucoup
//! plus de données que d'habitude.

use std::{collections::HashMap, net::IpAddr};

use serde_json::json;

use super::{Detector, ts_to_dt};
use crate::{
    alert::{Alert, AlertKind, AlertSource, Severity, human_bytes},
    capture::{PacketMeta, Proto},
    config::{DetectionConfig, VolumeConfig},
};

/// Poids de la nouvelle période dans la moyenne mobile : 0,1 = la normale suit l'évolution
/// des usages sur une dizaine de périodes, sans être déformée par un pic isolé.
const ALPHA: f64 = 0.1;
/// Hôtes internes suivis au plus. Des paquets aux adresses source usurpées (une adresse
/// interne inventée par paquet) créeraient sinon une normale par paquet, parcourue à chaque
/// fin de période.
const MAX_HOSTS: usize = 10_000;
/// Silence (secondes, temps des paquets) au-delà duquel la normale d'un hôte est oubliée.
/// Une journée : une machine éteinte la nuit garde sa normale, alors qu'une adresse usurpée ou
/// réattribuée par DHCP libère sa place. Après un oubli, l'hôte refait sa phase d'apprentissage.
const FORGET_AFTER_SECS: f64 = 86_400.0;

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
    /// Hôtes de `current` qui n'ont pas encore de normale : ils en recevront une à la fin de la période.
    newcomers: usize,
    /// Plafond de `baselines` ([`MAX_HOSTS`], réduit dans les tests). Une fois atteint, les hôtes
    /// déjà suivis continuent de l'être, mais aucun nouveau n'est compté.
    max_hosts: usize,
}

/// Statistiques mobiles d'un hôte, en octets par période.
#[derive(Default)]
struct Baseline {
    mean: f64,
    var: f64,
    /// Nombre de périodes intégrées (sert à la phase d'apprentissage).
    n: u32,
    /// Fin de la dernière période où l'hôte a envoyé quelque chose, en secondes (temps des paquets).
    last_active: f64,
}

impl Volume {
    pub fn new(cfg: VolumeConfig, net: DetectionConfig) -> Self {
        Self { cfg, net, bucket_start: None, current: HashMap::new(), baselines: HashMap::new(), newcomers: 0, max_hosts: MAX_HOSTS }
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
            if x > 0.0 {
                b.last_active = end;
            }
        }
        // Avant d'ajouter les nouveaux : un hôte actif pendant cette période vient d'être daté, il reste.
        self.baselines.retain(|_, b| end - b.last_active <= FORGET_AFTER_SECS);
        // Les hôtes vus pour la première fois obtiennent une normale vide ; leur apprentissage
        // commence à la période suivante. `on_packet` n'en a admis que dans la limite du plafond.
        for host in current.into_keys() {
            self.baselines.entry(host).or_insert_with(|| Baseline { last_active: end, ..Default::default() });
        }
        self.newcomers = 0;
    }

    /// Ajoute `len` octets sortants à `host` pour la période en cours. Un hôte sans normale n'est
    /// admis que s'il reste de la place sous le plafond, en comptant les autres nouveaux de la période.
    fn count(&mut self, host: IpAddr, len: u64) {
        if let Some(bytes) = self.current.get_mut(&host) {
            *bytes += len;
            return;
        }
        let known = self.baselines.contains_key(&host);
        if !known && self.baselines.len() + self.newcomers >= self.max_hosts {
            return;
        }
        self.newcomers += usize::from(!known);
        self.current.insert(host, len);
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
        // Seul le trafic IP interne → externe compte.
        if p.proto != Proto::Arp && self.net.is_local(&p.src) && !self.net.is_local(&p.dst) {
            self.count(p.src, u64::from(p.len));
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

    // Les trames ARP ne sont pas du trafic sortant, même si l'IP visée paraît externe.
    #[test]
    fn arp_frames_are_not_counted() {
        let mut d = Volume::new(VolumeConfig::default(), DetectionConfig::default());
        let mut out = Vec::new();
        let arp = PacketMeta { proto: Proto::Arp, len: 1_000_000, ..syn(1.0, "192.168.1.30", "203.0.113.5", 0) };
        d.on_packet(&arp, &mut out);
        assert!(d.current.is_empty());
    }

    // Des sources internes usurpées (une adresse par paquet) ne font pas grossir l'état au-delà
    // du plafond, ni pendant la période ni d'une période à l'autre.
    #[test]
    fn spoofed_sources_are_bounded() {
        let mut d = Volume::new(VolumeConfig::default(), DetectionConfig::default());
        d.max_hosts = 50;
        let mut out = Vec::new();
        for minute in 0..5u32 {
            for i in 0..1000u32 {
                let src = format!("10.{}.{}.{}", minute, i / 256, i % 256);
                d.on_packet(&syn(f64::from(minute) * 60.0 + f64::from(i) * 0.01, &src, "203.0.113.5", 443), &mut out);
                assert!(d.current.len() <= d.max_hosts);
            }
        }
        d.tick(10.0 * 60.0, &mut out);
        assert!(d.baselines.len() <= d.max_hosts, "{}", d.baselines.len());
        assert!(out.is_empty());
    }

    // Un hôte déjà suivi continue d'être compté et détecté quand le plafond est atteint.
    #[test]
    fn known_host_is_tracked_at_capacity() {
        let mut d = Volume::new(VolumeConfig::default(), DetectionConfig::default());
        d.max_hosts = 1;
        let mut out = Vec::new();
        let mut pkt = syn(0.0, "192.168.1.30", "203.0.113.5", 443);
        for minute in 0..30 {
            pkt.ts = f64::from(minute) * 60.0;
            pkt.len = 1_000_000;
            d.on_packet(&pkt, &mut out);
            // Une autre machine arrive chaque minute : elle n'a pas de place.
            d.on_packet(&syn(pkt.ts + 1.0, &format!("192.168.2.{minute}"), "203.0.113.5", 443), &mut out);
        }
        for i in 0..200 {
            pkt.ts = 30.0 * 60.0 + f64::from(i) * 0.1;
            pkt.len = 1_000_000;
            d.on_packet(&pkt, &mut out);
        }
        d.tick(32.0 * 60.0, &mut out);
        assert_eq!(d.baselines.len(), 1);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].src.as_deref(), Some("192.168.1.30"));
    }

    // Un hôte silencieux plus longtemps que `FORGET_AFTER_SECS` est oublié ; une absence d'une
    // nuit ne lui fait pas perdre sa normale.
    #[test]
    fn silent_hosts_are_forgotten() {
        let mut d = Volume::new(VolumeConfig::default(), DetectionConfig::default());
        let mut out = Vec::new();
        d.on_packet(&syn(0.0, "192.168.1.30", "203.0.113.5", 443), &mut out);
        d.on_packet(&syn(0.0, "192.168.1.31", "203.0.113.5", 443), &mut out);
        // Seul .31 reste actif ; .30 se tait.
        let mut t = 60.0;
        while t < FORGET_AFTER_SECS / 2.0 {
            d.on_packet(&syn(t, "192.168.1.31", "203.0.113.5", 443), &mut out);
            t += 600.0;
        }
        d.tick(t, &mut out);
        assert_eq!(d.baselines.len(), 2, "une demi-journée de silence ne suffit pas");
        while t < FORGET_AFTER_SECS + 3600.0 {
            d.on_packet(&syn(t, "192.168.1.31", "203.0.113.5", 443), &mut out);
            t += 600.0;
        }
        d.tick(t, &mut out);
        let known: Vec<String> = d.baselines.keys().map(|ip| ip.to_string()).collect();
        assert_eq!(known, vec!["192.168.1.31"]);
    }

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
