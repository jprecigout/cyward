//! Résumé du trafic seconde par seconde, pour la vue « Flux » du dashboard.
//!
//! Le moteur additionne paquets et octets par couple (source, destination, protocole) pendant
//! une seconde de temps des paquets, puis publie un [`FlowSnapshot`] limité aux couples les
//! plus actifs. Le navigateur ne reçoit donc jamais les paquets eux-mêmes, seulement quelques
//! dizaines de lignes par seconde.
//!
//!   run_engine ──record──▶ FlowMeter ──snapshot/s──▶ FlowHub (broadcast) ──▶ /api/flows (SSE)
//!
//! Rien n'est compté quand aucun onglet n'affiche la vue ([`FlowHub::is_watched`]) : la
//! fonctionnalité ne coûte alors rien au chemin critique. [`FlowMeter`] est pur (aucune I/O),
//! ce qui le rend testable sans réseau ni serveur.

use std::{collections::HashMap, net::IpAddr, sync::Arc};

use serde::Serialize;
use tokio::sync::broadcast;

use crate::capture::{PacketMeta, Proto};

/// Couples gardés dans un résumé : au-delà, ils sont regroupés dans « autres ».
const TOP_FLOWS: usize = 50;
/// Plafond des couples comptés pendant une seconde. Des adresses usurpées peuvent créer un
/// couple par paquet : au-delà, les paquets vont directement dans « autres ».
const MAX_FLOWS: usize = 10_000;

/// Nature du trafic, telle que la vue la colore.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FlowKind {
    Tcp,
    Udp,
    /// Requête DNS (UDP vers le port 53), distinguée du reste de l'UDP : c'est un canal d'exfiltration courant.
    Dns,
    Icmp,
    Arp,
    Other,
}

impl FlowKind {
    /// Nature d'un paquet.
    fn of(p: &PacketMeta) -> Self {
        match p.proto {
            _ if p.dns_query.is_some() => Self::Dns,
            Proto::Tcp => Self::Tcp,
            Proto::Udp => Self::Udp,
            Proto::Icmp => Self::Icmp,
            Proto::Arp => Self::Arp,
            Proto::Other => Self::Other,
        }
    }
}

/// Trafic d'un couple pendant une seconde.
#[derive(Debug, Clone, Serialize)]
pub struct Flow {
    pub src: IpAddr,
    pub dst: IpAddr,
    pub kind: FlowKind,
    pub packets: u64,
    /// Octets (taille des trames).
    pub bytes: u64,
}

/// Résumé d'une seconde de trafic, envoyé tel quel au dashboard.
#[derive(Debug, Clone, Default, Serialize)]
pub struct FlowSnapshot {
    /// Début de la seconde résumée, en secondes depuis l'epoch (temps des paquets).
    pub ts: i64,
    /// Couples les plus actifs, par octets décroissants (`TOP_FLOWS` au plus).
    pub flows: Vec<Flow>,
    /// Paquets et octets des couples non détaillés.
    pub other_packets: u64,
    pub other_bytes: u64,
}

/// Additionne le trafic de la seconde en cours et produit son résumé quand elle se termine.
pub struct FlowMeter {
    /// Seconde en cours (partie entière du temps des paquets) ; None avant le premier paquet.
    second: Option<i64>,
    /// (source, destination, nature) → (paquets, octets) pendant la seconde en cours.
    table: HashMap<(IpAddr, IpAddr, FlowKind), (u64, u64)>,
    /// Paquets et octets refusés par le plafond de `table`.
    overflow: (u64, u64),
    /// Plafond de `table` (`MAX_FLOWS`, réduit dans les tests).
    max_flows: usize,
}

impl FlowMeter {
    pub fn new() -> Self {
        Self { second: None, table: HashMap::new(), overflow: (0, 0), max_flows: MAX_FLOWS }
    }

    /// Compte un paquet. Si celui-ci ouvre une nouvelle seconde, renvoie le résumé de la précédente.
    pub fn record(&mut self, p: &PacketMeta) -> Option<FlowSnapshot> {
        let snapshot = self.flush(p.ts);
        self.second.get_or_insert(p.ts.floor() as i64);
        let len = u64::from(p.len);
        let key = (p.src, p.dst, FlowKind::of(p));
        let full = self.table.len() >= self.max_flows;
        match self.table.get_mut(&key) {
            Some((packets, bytes)) => {
                *packets += 1;
                *bytes += len;
            }
            None if !full => {
                self.table.insert(key, (1, len));
            }
            None => {
                self.overflow.0 += 1;
                self.overflow.1 += len;
            }
        }
        snapshot
    }

    /// Clôt la seconde en cours si `now` (en secondes) appartient à une seconde suivante, et
    /// renvoie son résumé. Sert aussi en direct, sur l'horloge murale, quand le trafic s'arrête.
    pub fn flush(&mut self, now: f64) -> Option<FlowSnapshot> {
        let second = self.second?;
        if (now.floor() as i64) <= second {
            return None;
        }
        self.second = None;
        Some(self.take(second))
    }

    /// Vide la table en un résumé : les `TOP_FLOWS` couples les plus lourds, le reste additionné.
    fn take(&mut self, ts: i64) -> FlowSnapshot {
        let mut flows: Vec<Flow> =
            self.table.drain().map(|((src, dst, kind), (packets, bytes))| Flow { src, dst, kind, packets, bytes }).collect();
        // Tri partiel : seuls les TOP_FLOWS premiers doivent être ordonnés.
        if flows.len() > TOP_FLOWS {
            flows.select_nth_unstable_by(TOP_FLOWS, |a, b| b.bytes.cmp(&a.bytes));
        }
        let rest = flows.split_off(flows.len().min(TOP_FLOWS));
        flows.sort_unstable_by_key(|f| std::cmp::Reverse(f.bytes));
        let (other_packets, other_bytes) = rest.iter().fold(std::mem::take(&mut self.overflow), |(p, b), f| (p + f.packets, b + f.bytes));
        FlowSnapshot { ts, flows, other_packets, other_bytes }
    }
}

/// Diffusion des résumés aux onglets qui affichent la vue (Observer, comme le store des alertes).
#[derive(Clone)]
pub struct FlowHub {
    tx: broadcast::Sender<Arc<FlowSnapshot>>,
}

impl FlowHub {
    pub fn new() -> Self {
        // 16 secondes de tampon par onglet : un onglet en retard saute des secondes, sans gêner le moteur.
        Self { tx: broadcast::channel(16).0 }
    }

    /// Vrai si au moins un onglet affiche la vue : sinon, inutile de compter quoi que ce soit.
    pub fn is_watched(&self) -> bool {
        self.tx.receiver_count() > 0
    }

    /// Publie un résumé ; sans abonné, il est simplement perdu.
    pub fn publish(&self, s: FlowSnapshot) {
        let _ = self.tx.send(Arc::new(s));
    }

    pub fn subscribe(&self) -> broadcast::Receiver<Arc<FlowSnapshot>> {
        self.tx.subscribe()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capture::TcpFlags;

    /// Paquet de `len` octets de `src` vers `dst`, à l'instant `ts`.
    fn pkt(ts: f64, src: &str, dst: &str, proto: Proto, len: u32) -> PacketMeta {
        PacketMeta {
            ts,
            src: src.parse().unwrap(),
            dst: dst.parse().unwrap(),
            proto,
            sport: 40000,
            dport: 443,
            len,
            tcp: TcpFlags::default(),
            dns_query: None,
            arp: None,
        }
    }

    // Les paquets d'une même seconde sont additionnés ; le résumé sort au premier paquet de la seconde suivante.
    #[test]
    fn sums_one_second_then_emits() {
        let mut m = FlowMeter::new();
        assert!(m.record(&pkt(10.1, "192.168.1.20", "198.51.100.66", Proto::Tcp, 100)).is_none());
        assert!(m.record(&pkt(10.9, "192.168.1.20", "198.51.100.66", Proto::Tcp, 300)).is_none());
        let s = m.record(&pkt(11.2, "192.168.1.35", "93.184.216.34", Proto::Tcp, 50)).unwrap();
        assert_eq!(s.ts, 10);
        assert_eq!(s.flows.len(), 1);
        assert_eq!((s.flows[0].packets, s.flows[0].bytes), (2, 400));
        // La seconde 11 ne contient que le nouveau paquet.
        let s = m.flush(12.0).unwrap();
        assert_eq!((s.ts, s.flows[0].bytes), (11, 50));
    }

    // Sans trafic, rien n'est publié, et une seconde en cours n'est pas close avant son terme.
    #[test]
    fn no_traffic_no_snapshot() {
        let mut m = FlowMeter::new();
        assert!(m.flush(100.0).is_none());
        m.record(&pkt(100.2, "192.168.1.20", "192.168.1.1", Proto::Udp, 80));
        assert!(m.flush(100.9).is_none());
        assert!(m.flush(101.0).is_some());
        assert!(m.flush(102.0).is_none());
    }

    // Le DNS et l'ARP sont distingués du reste du trafic.
    #[test]
    fn classifies_dns_and_arp() {
        let mut dns = pkt(1.0, "192.168.1.20", "192.168.1.1", Proto::Udp, 70);
        dns.dns_query = Some("example.com".into());
        assert_eq!(FlowKind::of(&dns), FlowKind::Dns);
        assert_eq!(FlowKind::of(&pkt(1.0, "192.168.1.1", "192.168.1.20", Proto::Arp, 42)), FlowKind::Arp);
        assert_eq!(FlowKind::of(&pkt(1.0, "192.168.1.1", "192.168.1.20", Proto::Udp, 42)), FlowKind::Udp);
    }

    // Seuls les couples les plus lourds sont détaillés, triés ; les autres sont additionnés.
    #[test]
    fn keeps_top_flows_and_sums_the_rest() {
        let mut m = FlowMeter::new();
        for i in 0..(TOP_FLOWS + 10) {
            m.record(&pkt(5.0, &format!("10.0.{}.{}", i / 250, i % 250 + 1), "198.51.100.1", Proto::Tcp, 100 + i as u32));
        }
        let s = m.flush(6.0).unwrap();
        assert_eq!(s.flows.len(), TOP_FLOWS);
        assert!(s.flows.windows(2).all(|w| w[0].bytes >= w[1].bytes));
        assert_eq!(s.flows[0].bytes, 100 + (TOP_FLOWS + 9) as u64);
        assert_eq!(s.other_packets, 10);
        assert_eq!(s.other_bytes, (100..110).sum::<u64>());
    }

    // Au plafond, les nouveaux couples ne sont plus mémorisés mais restent comptés dans « autres ».
    #[test]
    fn table_is_capped() {
        let mut m = FlowMeter::new();
        m.max_flows = 3;
        for host in 1..=8 {
            m.record(&pkt(1.0, &format!("203.0.113.{host}"), "192.168.1.10", Proto::Tcp, 60));
        }
        assert_eq!(m.table.len(), 3);
        let s = m.flush(2.0).unwrap();
        assert_eq!(s.flows.len() as u64 + s.other_packets, 8);
    }

    // Le hub ne se dit regardé que tant qu'un abonné existe.
    #[test]
    fn hub_knows_when_it_is_watched() {
        let hub = FlowHub::new();
        assert!(!hub.is_watched());
        let rx = hub.subscribe();
        assert!(hub.is_watched());
        drop(rx);
        assert!(!hub.is_watched());
    }
}
