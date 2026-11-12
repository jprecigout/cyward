//! Usurpation ARP (empoisonnement de cache ARP).
//!
//! Sur un réseau local, l'ARP associe chaque IP à une adresse MAC, sans aucune
//! authentification : n'importe quelle machine peut annoncer « l'IP de la passerelle, c'est
//! moi ». Les autres lui envoient alors leur trafic, qu'elle peut lire ou modifier avant de le
//! relayer (homme du milieu, MITRE T1557.002). L'attaquant doit répéter ses annonces, car la
//! vraie machine continue de répondre : deux MAC actives pour la même IP trahissent l'attaque.
//!
//! Une MAC qui n'a rien annoncé depuis `window_secs` est oubliée : une nouvelle MAC après ce
//! délai est un remplacement ordinaire (carte changée, IP réattribuée par DHCP), pas un conflit.

use std::{
    collections::{HashMap, HashSet},
    net::IpAddr,
};

use serde_json::json;

use super::{Detector, ts_to_dt};
use crate::{
    alert::{Alert, AlertKind, AlertSource, Severity},
    capture::{ArpOp, PacketMeta},
    config::ArpConfig,
};

/// Plafond des IP suivies : un attaquant peut annoncer des milliers d'IP inventées.
const MAX_TRACKED: usize = 10_000;
/// MAC mémorisées au plus par IP : deux suffisent pour le conflit, les suivantes servent de preuve.
const MAX_MACS_PER_IP: usize = 4;

/// Repère une IP annoncée par plusieurs adresses MAC dans le même intervalle.
pub struct ArpSpoofing {
    cfg: ArpConfig,
    /// IP sensibles (passerelle…), pour la sévérité.
    protected: HashSet<IpAddr>,
    /// IP → MAC qui l'ont annoncée, avec la date de leur dernière annonce (secondes, temps des paquets).
    table: HashMap<IpAddr, Vec<([u8; 6], f64)>>,
    /// Plafond de `table` (`MAX_TRACKED`, réduit dans les tests).
    max_tracked: usize,
}

impl ArpSpoofing {
    pub fn new(cfg: ArpConfig) -> Self {
        let protected = cfg.protected_ips.iter().copied().collect();
        Self { cfg, protected, table: HashMap::new(), max_tracked: MAX_TRACKED }
    }

    /// Alerte de conflit : `known` est la MAC déjà active, `new` celle qui vient d'apparaître.
    fn alert(&self, p: &PacketMeta, op: ArpOp, known: [u8; 6], new: [u8; 6]) -> Alert {
        let ip = p.src;
        let (sev, role) = if self.protected.contains(&ip) { (Severity::High, " (IP protégée)") } else { (Severity::Medium, "") };
        Alert::new(AlertKind::ArpSpoofing, sev, AlertSource::Network, ts_to_dt(p.ts), format!("Usurpation ARP de {ip}{role}"))
            .description(format!(
                "{ip} est annoncée par deux adresses MAC en moins de {} s : {} (connue) et {} (nouvelle). Une machine qui se fait passer pour {ip} reçoit le trafic qui lui est destiné (homme du milieu). Causes légitimes possibles : IP en double, basculement de carte réseau.",
                self.cfg.window_secs,
                fmt_mac(known),
                fmt_mac(new)
            ))
            .src(ip)
            // La MAC n'est pas une adresse IP : l'empreinte reste l'IP usurpée seule, pour
            // qu'une même attaque ne donne qu'une alerte quel que soit le paquet qui l'a révélée.
            .fingerprint(format!("arp_spoofing|{ip}"))
            .evidence(json!({
                "ip": ip.to_string(),
                "known_mac": fmt_mac(known),
                "new_mac": fmt_mac(new),
                // Une réponse non sollicitée (ARP gratuit) est l'outil habituel de l'empoisonnement.
                "operation": format!("{op:?}"),
            }))
    }
}

impl Detector for ArpSpoofing {
    fn on_packet(&mut self, p: &PacketMeta, out: &mut Vec<Alert>) {
        let Some(arp) = p.arp else { return };
        // 0.0.0.0 : sonde de détection de doublon (RFC 5227), qui n'annonce aucune IP.
        if p.src.is_unspecified() {
            return;
        }
        if !self.table.contains_key(&p.src) && self.table.len() >= self.max_tracked {
            return;
        }
        let window = self.cfg.window_secs;
        let macs = self.table.entry(p.src).or_default();
        // Les MAC silencieuses depuis la fenêtre sont oubliées : leur remplacement n'est pas un conflit.
        macs.retain(|(_, last)| p.ts - *last <= window);
        if let Some(entry) = macs.iter_mut().find(|(m, _)| *m == arp.sender_mac) {
            entry.1 = p.ts; // cas courant : la MAC connue renouvelle son annonce
            return;
        }
        if macs.len() >= MAX_MACS_PER_IP {
            return;
        }
        macs.push((arp.sender_mac, p.ts));
        // `== 2` : une alerte au moment où le conflit apparaît, pas une par annonce suivante.
        if macs.len() == 2 {
            let (known, new) = (macs[0].0, macs[1].0);
            out.push(self.alert(p, arp.op, known, new));
        }
    }

    fn tick(&mut self, now: f64, _out: &mut Vec<Alert>) {
        // Mêmes règles d'oubli que dans `on_packet`, pour les IP qui ne s'annoncent plus.
        let window = self.cfg.window_secs;
        self.table.retain(|_, macs| {
            macs.retain(|(_, last)| now - *last <= window);
            !macs.is_empty()
        });
    }
}

/// Format usuel d'une adresse MAC : « 02:00:00:00:00:09 ».
fn fmt_mac(m: [u8; 6]) -> String {
    m.iter().map(|b| format!("{b:02x}")).collect::<Vec<_>>().join(":")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        capture::{ArpInfo, Proto},
        detect::testutil::syn,
    };

    const GATEWAY_MAC: [u8; 6] = [2, 0, 0, 0, 0, 1];
    const ATTACKER_MAC: [u8; 6] = [2, 0, 0, 0, 0, 0x20];

    /// Réponse ARP : `ip` annonce être à `mac`.
    fn arp(ts: f64, ip: &str, mac: [u8; 6]) -> PacketMeta {
        PacketMeta { proto: Proto::Arp, dport: 0, arp: Some(ArpInfo { op: ArpOp::Reply, sender_mac: mac }), ..syn(ts, ip, "192.168.1.20", 0) }
    }

    fn detector() -> ArpSpoofing {
        ArpSpoofing::new(ArpConfig { protected_ips: vec!["192.168.1.1".parse().unwrap()], ..Default::default() })
    }

    // Un attaquant qui annonce l'IP de la passerelle pendant qu'elle répond : une seule alerte haute.
    #[test]
    fn detects_gateway_spoofing_once() {
        let mut d = detector();
        let mut out = Vec::new();
        for i in 0..30 {
            let t = i as f64 * 2.0;
            d.on_packet(&arp(t, "192.168.1.1", GATEWAY_MAC), &mut out);
            d.on_packet(&arp(t + 1.0, "192.168.1.1", ATTACKER_MAC), &mut out);
        }
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].kind, AlertKind::ArpSpoofing);
        assert_eq!(out[0].severity, Severity::High);
        assert_eq!(out[0].evidence["new_mac"], "02:00:00:00:00:20");
    }

    // Une IP non protégée en conflit est de sévérité moyenne.
    #[test]
    fn unprotected_conflict_is_medium() {
        let mut d = detector();
        let mut out = Vec::new();
        d.on_packet(&arp(0.0, "192.168.1.50", GATEWAY_MAC), &mut out);
        d.on_packet(&arp(1.0, "192.168.1.50", ATTACKER_MAC), &mut out);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].severity, Severity::Medium);
    }

    // Annonces répétées d'une même MAC, et plusieurs machines distinctes : rien à signaler.
    #[test]
    fn stable_arp_table_is_quiet() {
        let mut d = detector();
        let mut out = Vec::new();
        for i in 0..100 {
            let t = i as f64 * 30.0;
            d.on_packet(&arp(t, "192.168.1.1", GATEWAY_MAC), &mut out);
            d.on_packet(&arp(t, "192.168.1.35", [2, 0, 0, 0, 0, 0x35]), &mut out);
        }
        // Les paquets IP (sans information ARP) sont ignorés.
        d.on_packet(&syn(10.0, "192.168.1.1", "192.168.1.35", 80), &mut out);
        assert!(out.is_empty());
    }

    // Une nouvelle MAC après le silence de l'ancienne est un remplacement, pas une attaque.
    #[test]
    fn replacement_after_window_is_quiet() {
        let mut d = detector();
        let mut out = Vec::new();
        d.on_packet(&arp(0.0, "192.168.1.1", GATEWAY_MAC), &mut out);
        d.on_packet(&arp(4000.0, "192.168.1.1", ATTACKER_MAC), &mut out);
        assert!(out.is_empty());
    }

    // Les sondes RFC 5227 (émetteur 0.0.0.0) ne sont pas des annonces.
    #[test]
    fn ignores_probes() {
        let mut d = detector();
        let mut out = Vec::new();
        d.on_packet(&arp(0.0, "0.0.0.0", GATEWAY_MAC), &mut out);
        d.on_packet(&arp(1.0, "0.0.0.0", ATTACKER_MAC), &mut out);
        assert!(out.is_empty());
    }

    // L'état est borné : plafond d'IP suivies et purge des IP silencieuses.
    #[test]
    fn memory_is_bounded() {
        let mut d = detector();
        d.max_tracked = 3;
        let mut out = Vec::new();
        for host in 1..=10 {
            d.on_packet(&arp(0.0, &format!("10.0.0.{host}"), ATTACKER_MAC), &mut out);
        }
        assert_eq!(d.table.len(), 3);
        d.tick(4000.0, &mut out);
        assert!(d.table.is_empty());
    }
}
