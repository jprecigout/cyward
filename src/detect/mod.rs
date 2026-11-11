//! Détection temps réel sur les métadonnées de paquets.
//!
//! Chaque détecteur garde son propre état et raisonne sur l'horodatage des paquets
//! (et non sur l'horloge murale), ce qui rend le rejeu d'un pcap déterministe.
//!
//! Pour ajouter un détecteur : créer un module qui implémente [`Detector`], puis l'ajouter
//! à la liste dans [`Engine::new`].

mod beacon;
mod dns;
mod scan;
mod volume;

use std::{collections::HashSet, net::IpAddr};

use chrono::{DateTime, Utc};

use crate::{alert::Alert, capture::PacketMeta, config::DetectionConfig};

/// Comportement commun des détecteurs réseau.
///
/// Les alertes sont ajoutées à `out` plutôt que renvoyées, pour éviter d'allouer un vecteur
/// par paquet alors que l'immense majorité des paquets n'en produit aucune.
pub trait Detector: Send {
    /// Appelé pour chaque paquet (hors sources en liste blanche).
    fn on_packet(&mut self, p: &PacketMeta, out: &mut Vec<Alert>);
    /// Appelé environ une fois par seconde, pour clore des fenêtres et purger l'état.
    fn tick(&mut self, _now: f64, _out: &mut Vec<Alert>) {}
}

/// Regroupe les détecteurs et leur distribue paquets et ticks.
pub struct Engine {
    detectors: Vec<Box<dyn Detector>>,
    whitelist: HashSet<IpAddr>,
    /// Temps (paquet ou horloge) du dernier tick.
    last_tick: f64,
}

impl Engine {
    pub fn new(cfg: &DetectionConfig) -> Self {
        Self {
            // Certains détecteurs reçoivent toute la DetectionConfig pour accéder à `is_local`.
            detectors: vec![
                Box::new(scan::PortScan::new(cfg.portscan.clone(), cfg.clone())),
                Box::new(scan::BruteForce::new(cfg.bruteforce.clone())),
                Box::new(scan::SynFlood::new(cfg.synflood.clone())),
                Box::new(beacon::Beaconing::new(cfg.beacon.clone(), cfg.clone())),
                Box::new(volume::Volume::new(cfg.volume.clone(), cfg.clone())),
                Box::new(dns::Dns::new(cfg.dns.clone())),
            ],
            whitelist: cfg.whitelist.iter().copied().collect(),
            last_tick: 0.0,
        }
    }

    /// Fait passer un paquet dans tous les détecteurs et renvoie les alertes produites.
    pub fn process(&mut self, p: &PacketMeta) -> Vec<Alert> {
        let mut out = Vec::new();
        if !self.whitelist.contains(&p.src) {
            for d in &mut self.detectors {
                d.on_packet(p, &mut out);
            }
        }
        // Tick piloté par le temps des paquets : en rejeu, c'est la seule source de ticks.
        if p.ts - self.last_tick >= 1.0 {
            out.extend(self.tick(p.ts));
        }
        out
    }

    /// Propage un tick à tous les détecteurs.
    pub fn tick(&mut self, now: f64) -> Vec<Alert> {
        let mut out = Vec::new();
        if now < self.last_tick {
            return out; // horloge de capture en retard sur un tick précédent
        }
        self.last_tick = now;
        for d in &mut self.detectors {
            d.tick(now, &mut out);
        }
        out
    }
}

/// Convertit un horodatage en secondes flottantes en date UTC (pour les alertes).
pub fn ts_to_dt(ts: f64) -> DateTime<Utc> {
    DateTime::from_timestamp(ts.trunc() as i64, (ts.fract() * 1e9) as u32).unwrap_or_else(Utc::now)
}

/// Constructeurs de paquets factices pour les tests des détecteurs.
#[cfg(test)]
pub(crate) mod testutil {
    use std::net::IpAddr;

    use crate::capture::{PacketMeta, Proto, TcpFlags};

    /// Ouverture de connexion TCP (SYN) de `src` vers `dst:dport` à l'instant `ts`.
    pub fn syn(ts: f64, src: &str, dst: &str, dport: u16) -> PacketMeta {
        PacketMeta {
            ts,
            src: src.parse::<IpAddr>().unwrap(),
            dst: dst.parse::<IpAddr>().unwrap(),
            proto: Proto::Tcp,
            sport: 40000,
            dport,
            len: 60,
            tcp: TcpFlags { syn: true, ..Default::default() },
            dns_query: None,
        }
    }

    /// Requête DNS UDP de `src` vers le résolveur 10.0.0.1 pour le nom `name`.
    pub fn dns(ts: f64, src: &str, name: &str) -> PacketMeta {
        PacketMeta {
            proto: Proto::Udp,
            tcp: TcpFlags::default(),
            dport: 53,
            dns_query: Some(name.to_string()),
            ..syn(ts, src, "10.0.0.1", 53)
        }
    }
}
