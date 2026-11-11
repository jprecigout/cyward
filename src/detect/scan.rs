//! Détecteurs fondés sur le comptage des ouvertures de connexion TCP (paquets SYN) :
//! scan de ports, balayage d'hôtes, force brute réseau et inondation SYN.
//!
//! Tous fonctionnent par fenêtres fixes : un compteur démarre au premier paquet et repart de
//! zéro quand la fenêtre est dépassée. Une alerte est émise quand un compteur atteint
//! *exactement* son seuil, donc une seule fois par fenêtre ; les fenêtres suivantes sont
//! fusionnées par le store (cooldown).

use std::{
    collections::{HashMap, HashSet},
    net::IpAddr,
};

use serde_json::json;

use super::{Detector, ts_to_dt};
use crate::{
    alert::{Alert, AlertKind, AlertSource, Severity},
    capture::{PacketMeta, Proto},
    config::{BruteForceConfig, DetectionConfig, PortScanConfig, SynFloodConfig},
};

/// Scan vertical (beaucoup de ports sur un hôte) et balayage horizontal (un port sur beaucoup d'hôtes).
pub struct PortScan {
    cfg: PortScanConfig,
    /// Config générale, pour savoir si la source est interne.
    net: DetectionConfig,
    /// État par adresse source.
    sources: HashMap<IpAddr, ScanState>,
}

/// Ce qu'une source a sondé depuis le début de sa fenêtre.
struct ScanState {
    start: f64,
    /// Pour chaque hôte visé : les ports distincts essayés.
    ports_by_host: HashMap<IpAddr, HashSet<u16>>,
    /// Pour chaque port visé : les hôtes distincts essayés.
    hosts_by_port: HashMap<u16, HashSet<IpAddr>>,
}

impl PortScan {
    pub fn new(cfg: PortScanConfig, net: DetectionConfig) -> Self {
        Self { cfg, net, sources: HashMap::new() }
    }
}

impl Detector for PortScan {
    fn on_packet(&mut self, p: &PacketMeta, out: &mut Vec<Alert>) {
        // Seules les tentatives de connexion TCP comptent (les scans UDP ne sont pas suivis).
        if p.proto != Proto::Tcp || !p.tcp.is_connection_start() {
            return;
        }
        let st = self.sources.entry(p.src).or_insert_with(|| ScanState {
            start: p.ts,
            ports_by_host: HashMap::new(),
            hosts_by_port: HashMap::new(),
        });
        // Fenêtre expirée : on repart de zéro.
        if p.ts - st.start > self.cfg.window_secs {
            st.start = p.ts;
            st.ports_by_host.clear();
            st.hosts_by_port.clear();
        }

        // Un scan depuis l'intérieur du réseau est bien plus inquiétant : une machine
        // compromise cherche d'autres cibles. Depuis Internet, c'est un bruit de fond permanent.
        let lateral = self.net.is_local(&p.src);
        let severity = if lateral { Severity::High } else { Severity::Medium };
        let origin = if lateral { "un hôte interne (possible mouvement latéral)" } else { "une adresse externe" };

        // Scan vertical. `insert` renvoie vrai si le port est nouveau : un même port répété
        // ne fait pas grossir le compteur.
        let ports = st.ports_by_host.entry(p.dst).or_default();
        if ports.insert(p.dport) && ports.len() == self.cfg.ports_threshold {
            // Ports triés dans les preuves, pour une lecture plus facile.
            let mut sample: Vec<_> = ports.iter().copied().collect();
            sample.sort_unstable();
            out.push(
                Alert::new(AlertKind::PortScan, severity, AlertSource::Network, ts_to_dt(p.ts), format!("Scan de ports de {} vers {}", p.src, p.dst))
                    .description(format!(
                        "{} ports distincts sondés en moins de {} s depuis {origin}.",
                        ports.len(),
                        self.cfg.window_secs
                    ))
                    .src(p.src)
                    .dst(p.dst)
                    .evidence(json!({ "ports": sample, "window_secs": self.cfg.window_secs })),
            );
        }

        // Balayage horizontal : même principe, par port.
        let hosts = st.hosts_by_port.entry(p.dport).or_default();
        if hosts.insert(p.dst) && hosts.len() == self.cfg.hosts_threshold {
            let sample: Vec<_> = hosts.iter().take(30).map(|h| h.to_string()).collect();
            out.push(
                Alert::new(AlertKind::HostSweep, severity, AlertSource::Network, ts_to_dt(p.ts), format!("Balayage du port {} par {}", p.dport, p.src))
                    .description(format!(
                        "{} hôtes distincts contactés sur le port {} en moins de {} s depuis {origin}.",
                        hosts.len(),
                        p.dport,
                        self.cfg.window_secs
                    ))
                    .src(p.src)
                    // Pas de cible unique : l'empreinte regroupe par source et par port.
                    .fingerprint(format!("sweep|{}|{}", p.src, p.dport))
                    .evidence(json!({ "port": p.dport, "hosts": sample })),
            );
        }
    }

    fn tick(&mut self, now: f64, _out: &mut Vec<Alert>) {
        // Oublie les sources inactives depuis deux fenêtres, pour borner la mémoire.
        let w = self.cfg.window_secs;
        self.sources.retain(|_, s| now - s.start <= 2.0 * w);
    }
}

/// Rafale de connexions vers un service d'authentification (SSH, RDP, SMB, bases de données…).
pub struct BruteForce {
    cfg: BruteForceConfig,
    /// Ports surveillés, en ensemble pour une recherche rapide.
    ports: HashSet<u16>,
    /// (source, destination, port) → (début de fenêtre, nombre de connexions).
    counters: HashMap<(IpAddr, IpAddr, u16), (f64, usize)>,
}

impl BruteForce {
    pub fn new(cfg: BruteForceConfig) -> Self {
        let ports = cfg.ports.iter().copied().collect();
        Self { cfg, ports, counters: HashMap::new() }
    }
}

impl Detector for BruteForce {
    fn on_packet(&mut self, p: &PacketMeta, out: &mut Vec<Alert>) {
        if p.proto != Proto::Tcp || !p.tcp.is_connection_start() || !self.ports.contains(&p.dport) {
            return;
        }
        // Chaque essai de mot de passe ouvre en général une nouvelle connexion : compter les
        // SYN suffit, même si le protocole est chiffré.
        let (start, count) = self.counters.entry((p.src, p.dst, p.dport)).or_insert((p.ts, 0));
        if p.ts - *start > self.cfg.window_secs {
            *start = p.ts;
            *count = 0;
        }
        *count += 1;
        if *count == self.cfg.threshold {
            out.push(
                Alert::new(AlertKind::BruteForce, Severity::High, AlertSource::Network, ts_to_dt(p.ts), format!("Force brute probable sur {}:{} depuis {}", p.dst, p.dport, p.src))
                    .description(format!(
                        "{} connexions TCP vers le port {} ({}) en moins de {} s.",
                        count,
                        p.dport,
                        service_name(p.dport),
                        self.cfg.window_secs
                    ))
                    .src(p.src)
                    .dst(format!("{}:{}", p.dst, p.dport))
                    .evidence(json!({ "connections": count, "port": p.dport, "service": service_name(p.dport) })),
            );
        }
    }

    fn tick(&mut self, now: f64, _out: &mut Vec<Alert>) {
        let w = self.cfg.window_secs;
        self.counters.retain(|_, (start, _)| now - *start <= 2.0 * w);
    }
}

/// Inondation de SYN vers une même cible (déni de service).
pub struct SynFlood {
    cfg: SynFloodConfig,
    /// État par adresse ciblée.
    targets: HashMap<IpAddr, FloodState>,
}

struct FloodState {
    start: f64,
    count: usize,
    /// Sources distinctes, pour distinguer une attaque d'une seule machine d'une attaque distribuée.
    sources: HashSet<IpAddr>,
}

impl SynFlood {
    pub fn new(cfg: SynFloodConfig) -> Self {
        Self { cfg, targets: HashMap::new() }
    }
}

impl Detector for SynFlood {
    fn on_packet(&mut self, p: &PacketMeta, out: &mut Vec<Alert>) {
        if p.proto != Proto::Tcp || !p.tcp.is_connection_start() {
            return;
        }
        let st = self.targets.entry(p.dst).or_insert_with(|| FloodState { start: p.ts, count: 0, sources: HashSet::new() });
        if p.ts - st.start > self.cfg.window_secs {
            st.start = p.ts;
            st.count = 0;
            st.sources.clear();
        }
        st.count += 1;
        // Plafond : une attaque à adresses usurpées pourrait sinon remplir la mémoire.
        if st.sources.len() < 10_000 {
            st.sources.insert(p.src);
        }
        if st.count == self.cfg.threshold {
            let distributed = st.sources.len() > 50;
            out.push(
                Alert::new(AlertKind::SynFlood, Severity::High, AlertSource::Network, ts_to_dt(p.ts), format!("Inondation SYN vers {}", p.dst))
                    .description(format!(
                        "{} demandes de connexion en {} s depuis {} sources{}.",
                        st.count,
                        self.cfg.window_secs,
                        st.sources.len(),
                        if distributed { " (attaque distribuée ou adresses usurpées)" } else { "" }
                    ))
                    .dst(p.dst)
                    .evidence(json!({ "syn": st.count, "distinct_sources": st.sources.len() })),
            );
        }
    }

    fn tick(&mut self, now: f64, _out: &mut Vec<Alert>) {
        let w = self.cfg.window_secs;
        self.targets.retain(|_, s| now - s.start <= 2.0 * w);
    }
}

/// Nom lisible du service associé à un port, pour les descriptions d'alerte.
pub fn service_name(port: u16) -> &'static str {
    match port {
        21 => "FTP",
        22 => "SSH",
        23 => "Telnet",
        25 | 587 => "SMTP",
        110 | 995 => "POP3",
        143 | 993 => "IMAP",
        445 => "SMB",
        1433 => "MSSQL",
        3306 => "MySQL",
        3389 => "RDP",
        5432 => "PostgreSQL",
        5900 => "VNC",
        6379 => "Redis",
        _ => "service",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::detect::testutil::syn;

    // 100 ports en 1 seconde : une seule alerte malgré les 75 ports au-delà du seuil.
    #[test]
    fn detects_vertical_scan_once() {
        let mut d = PortScan::new(PortScanConfig::default(), DetectionConfig::default());
        let mut out = Vec::new();
        for port in 1..=100 {
            d.on_packet(&syn(port as f64 * 0.01, "192.168.1.50", "192.168.1.1", port), &mut out);
        }
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].kind, AlertKind::PortScan);
        assert_eq!(out[0].severity, Severity::High); // source interne
    }

    #[test]
    fn detects_host_sweep() {
        let mut d = PortScan::new(PortScanConfig::default(), DetectionConfig::default());
        let mut out = Vec::new();
        for h in 1..=30 {
            d.on_packet(&syn(h as f64, "203.0.113.9", &format!("192.168.1.{h}"), 445), &mut out);
        }
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].kind, AlertKind::HostSweep);
        assert_eq!(out[0].severity, Severity::Medium);
    }

    // Un port toutes les 10 s : jamais 25 ports dans une même fenêtre de 60 s.
    #[test]
    fn slow_connections_are_not_a_scan() {
        let mut d = PortScan::new(PortScanConfig::default(), DetectionConfig::default());
        let mut out = Vec::new();
        for port in 1..=100 {
            d.on_packet(&syn(port as f64 * 10.0, "192.168.1.50", "192.168.1.1", port), &mut out);
        }
        assert!(out.is_empty());
    }

    #[test]
    fn detects_ssh_bruteforce() {
        let mut d = BruteForce::new(BruteForceConfig::default());
        let mut out = Vec::new();
        for i in 0..50 {
            d.on_packet(&syn(i as f64, "198.51.100.7", "192.168.1.10", 22), &mut out);
        }
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].kind, AlertKind::BruteForce);
    }
}
