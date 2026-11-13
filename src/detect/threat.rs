//! Trafic avec des IP de listes de menaces (renseignement sur les menaces).
//!
//! Des listes publiques recensent les serveurs de commande (C2) de botnets actifs (abuse.ch
//! Feodo Tracker) ou les réseaux détournés par des criminels (Spamhaus DROP). Un poste interne
//! qui contacte l'une de ces adresses est très probablement compromis ; une adresse listée qui
//! nous contacte est le plus souvent un scanner, signal faible à garder en contexte.
//!
//! Les listes sont lues une fois au démarrage ([`Blocklist::load`], seule I/O du module) ; leur
//! décodage ([`Blocklist::add_list`]) et la recherche sont purs. Pour une recherche rapide sur
//! chaque paquet, les réseaux sont rangés par longueur de préfixe : une adresse se vérifie en
//! une recherche de table par longueur présente (une trentaine au plus), quelle que soit la
//! taille des listes.

use std::{
    collections::HashMap,
    net::IpAddr,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result};
use ipnet::IpNet;
use serde_json::json;

use super::{Detector, ts_to_dt};
use crate::{
    alert::{Alert, AlertKind, AlertSource, Severity},
    capture::{PacketMeta, Proto},
    config::{DetectionConfig, ThreatListConfig},
};

/// Plafond des couples (hôte interne, IP listée) mémorisés pour ne pas répéter l'alerte.
/// Au-delà, les alertes restent émises (et fusionnées par le store) mais ne sont plus mémorisées.
const MAX_SEEN: usize = 10_000;

/// Réseaux d'une même longueur de préfixe : adresse réseau → indice de la liste d'origine.
type PrefixTable<K> = (u8, HashMap<K, u16>);

/// Ensemble de réseaux IPv4 et IPv6 issus d'une ou plusieurs listes.
#[derive(Default)]
pub struct Blocklist {
    /// Tables IPv4 par longueur de préfixe, de la plus longue à la plus courte (le réseau le plus précis l'emporte).
    v4: Vec<PrefixTable<u32>>,
    /// Idem pour l'IPv6.
    v6: Vec<PrefixTable<u128>>,
    /// Nom de chaque liste (nom du fichier), indexé par la valeur des tables.
    names: Vec<String>,
    /// Nombre total de réseaux chargés.
    len: usize,
}

impl Blocklist {
    /// Lit les fichiers de listes. Une liste illisible empêche le démarrage : mieux vaut une
    /// erreur explicite qu'une détection silencieusement désactivée.
    pub fn load(paths: &[PathBuf]) -> Result<Self> {
        let mut list = Self::default();
        for path in paths {
            let text = std::fs::read_to_string(path).with_context(|| format!("lecture de la liste de menaces {}", path.display()))?;
            let added = list.add_list(&list_name(path), &text);
            if added == 0 {
                tracing::warn!("liste de menaces {} : aucune adresse reconnue", path.display());
            }
        }
        tracing::info!("listes de menaces : {} réseau(x) chargé(s) depuis {} fichier(s)", list.len, paths.len());
        Ok(list)
    }

    /// Ajoute les réseaux d'une liste au format texte et renvoie le nombre de réseaux reconnus.
    /// Les lignes illisibles sont ignorées : les listes publiques mêlent en-têtes et commentaires.
    pub fn add_list(&mut self, name: &str, text: &str) -> usize {
        // Au-delà de 65 535 listes, l'indice déborderait : cas irréaliste, on ignore la liste.
        let Ok(idx) = u16::try_from(self.names.len()) else { return 0 };
        self.names.push(name.to_string());
        let before = self.len;
        for net in text.lines().filter_map(parse_line) {
            self.insert(net, idx);
        }
        self.len - before
    }

    /// Range un réseau dans la table de sa longueur de préfixe.
    fn insert(&mut self, net: IpNet, idx: u16) {
        // `trunc` met à zéro les bits d'hôte (« 10.1.2.3/8 » → « 10.0.0.0/8 ») : c'est la clé recherchée.
        let added = match net.trunc() {
            IpNet::V4(n) => table(&mut self.v4, n.prefix_len()).insert(u32::from(n.network()), idx).is_none(),
            IpNet::V6(n) => table(&mut self.v6, n.prefix_len()).insert(u128::from(n.network()), idx).is_none(),
        };
        // Un réseau présent dans deux listes ne compte qu'une fois (la première liste est gardée).
        if added {
            self.len += 1;
        }
    }

    /// Cherche le réseau le plus précis contenant `ip` ; renvoie ce réseau et le nom de sa liste.
    pub fn lookup(&self, ip: &IpAddr) -> Option<(IpNet, &str)> {
        let (net, idx) = match ip {
            IpAddr::V4(a) => {
                let a = u32::from(*a);
                // `checked_shl` : un décalage de 32 bits (préfixe /0) donne le masque nul.
                self.v4.iter().find_map(|(plen, t)| {
                    let key = a & u32::MAX.checked_shl(32 - u32::from(*plen)).unwrap_or(0);
                    t.get(&key).map(|i| (IpNet::new(IpAddr::V4(key.into()), *plen), *i))
                })?
            }
            IpAddr::V6(a) => {
                let a = u128::from(*a);
                self.v6.iter().find_map(|(plen, t)| {
                    let key = a & u128::MAX.checked_shl(128 - u32::from(*plen)).unwrap_or(0);
                    t.get(&key).map(|i| (IpNet::new(IpAddr::V6(key.into()), *plen), *i))
                })?
            }
        };
        // `new` ne peut pas échouer : le préfixe vient d'un réseau valide.
        Some((net.ok()?, self.names[usize::from(idx)].as_str()))
    }

    /// Vrai si aucune adresse n'a été chargée.
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }
}

/// Table d'une longueur de préfixe, créée au besoin à sa place dans l'ordre décroissant.
fn table<K>(tables: &mut Vec<PrefixTable<K>>, plen: u8) -> &mut HashMap<K, u16> {
    let pos = match tables.binary_search_by(|(p, _)| plen.cmp(p)) {
        Ok(pos) => pos,
        Err(pos) => {
            tables.insert(pos, (plen, HashMap::new()));
            pos
        }
    };
    &mut tables[pos].1
}

/// Nom affiché d'une liste : le nom de son fichier.
fn list_name(path: &Path) -> String {
    path.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_else(|| path.display().to_string())
}

/// Décode une ligne de liste. Formats acceptés :
/// - une IP ou un CIDR en début de ligne, suivi éventuellement d'un commentaire `#` ou `;`
///   ou d'autres colonnes séparées par des virgules ou des espaces (Feodo, Spamhaus DROP texte, FireHOL) ;
/// - un objet JSON par ligne avec un champ `cidr` ou `ip` (Spamhaus DROP JSON).
fn parse_line(line: &str) -> Option<IpNet> {
    let line = line.trim();
    if line.starts_with('{') {
        let v: serde_json::Value = serde_json::from_str(line).ok()?;
        return parse_addr(v.get("cidr").or_else(|| v.get("ip"))?.as_str()?);
    }
    let token = line.split(['#', ';', ',', ' ', '\t']).next()?.trim_matches('"');
    parse_addr(token)
}

/// Lit « 192.0.2.0/24 » ou une adresse seule (réseau d'une seule adresse).
fn parse_addr(s: &str) -> Option<IpNet> {
    s.parse::<IpNet>().ok().or_else(|| s.parse::<IpAddr>().ok().map(IpNet::from))
}

/// Signale le trafic entre un hôte interne et une IP listée, une fois par couple et par délai.
pub struct ThreatList {
    cfg: ThreatListConfig,
    /// Pour `is_local` : seul le trafic qui franchit la frontière du réseau interne est vérifié.
    net: DetectionConfig,
    list: Blocklist,
    /// (hôte interne, IP listée) → date de la dernière alerte, en secondes (temps des paquets).
    seen: HashMap<(IpAddr, IpAddr), f64>,
    /// Plafond de `seen` (`MAX_SEEN`, réduit dans les tests).
    max_seen: usize,
}

impl ThreatList {
    pub fn new(cfg: ThreatListConfig, net: DetectionConfig, list: Blocklist) -> Self {
        Self { cfg, net, list, seen: HashMap::new(), max_seen: MAX_SEEN }
    }

    /// Construit l'alerte : sortante (poste probablement compromis) ou entrante (signal faible).
    fn alert(p: &PacketMeta, outbound: bool, remote: IpAddr, net: IpNet, list: &str) -> Alert {
        let evidence = json!({ "list": list, "matched": net.to_string(), "remote": remote.to_string(), "dport": p.dport, "proto": format!("{:?}", p.proto) });
        let (sev, title, desc) = if outbound {
            (
                Severity::High,
                format!("Connexion vers une IP listée : {remote}"),
                format!(
                    "{} communique avec {remote}, présente dans la liste « {list} » ({net}). Ces listes recensent des serveurs de commande de botnets et des réseaux malveillants : le poste est probablement compromis.",
                    p.src
                ),
            )
        } else {
            (
                Severity::Low,
                format!("Trafic entrant d'une IP listée : {remote}"),
                format!(
                    "{remote}, présente dans la liste « {list} » ({net}), contacte {} (port {}). Le plus souvent un scanner ; à rapprocher des autres alertes visant cet hôte.",
                    p.dst, p.dport
                ),
            )
        };
        Alert::new(AlertKind::ThreatListMatch, sev, AlertSource::Network, ts_to_dt(p.ts), title)
            .description(desc)
            .src(p.src)
            .dst(p.dst)
            .evidence(evidence)
    }
}

impl Detector for ThreatList {
    fn on_packet(&mut self, p: &PacketMeta, out: &mut Vec<Alert>) {
        if p.proto == Proto::Arp {
            return;
        }
        // Seul le trafic qui franchit la frontière est vérifié : (hôte interne, adresse distante, sens).
        let (local, remote, outbound) = match (self.net.is_local(&p.src), self.net.is_local(&p.dst)) {
            (true, false) => (p.src, p.dst, true),
            (false, true) => (p.dst, p.src, false),
            _ => return,
        };
        let Some((net, list)) = self.list.lookup(&remote) else { return };
        // Une alerte par couple et par délai, pas une par paquet d'un flux.
        if self.seen.get(&(local, remote)).is_some_and(|t| p.ts - t < self.cfg.realert_secs) {
            return;
        }
        if self.seen.len() < self.max_seen || self.seen.contains_key(&(local, remote)) {
            self.seen.insert((local, remote), p.ts);
        }
        out.push(Self::alert(p, outbound, remote, net, list));
    }

    fn tick(&mut self, now: f64, _out: &mut Vec<Alert>) {
        // Un couple dont le délai est écoulé peut de nouveau alerter : inutile de le garder.
        let d = self.cfg.realert_secs;
        self.seen.retain(|_, t| now - *t < d);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::detect::testutil::syn;

    /// Liste de test : une adresse seule (format Feodo) et un réseau (format Spamhaus DROP).
    fn list() -> Blocklist {
        let mut b = Blocklist::default();
        b.add_list("feodo.txt", "# Feodo Tracker\n198.51.100.66\n");
        b.add_list("drop.txt", "; Spamhaus DROP\n203.0.113.0/24 ; SBL000001\n");
        b
    }

    fn detector() -> ThreatList {
        ThreatList::new(ThreatListConfig::default(), DetectionConfig::default(), list())
    }

    // Les formats courants sont reconnus, les en-têtes et commentaires ignorés.
    #[test]
    fn parses_common_list_formats() {
        assert_eq!(parse_line("198.51.100.66"), "198.51.100.66/32".parse().ok());
        assert_eq!(parse_line("203.0.113.0/24 ; SBL123"), "203.0.113.0/24".parse().ok());
        assert_eq!(parse_line(r#"{"cidr":"192.0.2.0/25","sblid":"SBL1","rir":"arin"}"#), "192.0.2.0/25".parse().ok());
        assert_eq!(parse_line("\"192.0.2.7\",443,online"), "192.0.2.7/32".parse().ok());
        assert_eq!(parse_line("2001:db8::/32 # IPv6"), "2001:db8::/32".parse().ok());
        assert_eq!(parse_line("# commentaire"), None);
        assert_eq!(parse_line(r#"{"type":"metadata","timestamp":1}"#), None);
        assert_eq!(parse_line(""), None);
    }

    // La recherche trouve une adresse seule, une adresse dans un réseau, et rien ailleurs.
    #[test]
    fn lookup_matches_addresses_and_networks() {
        let b = list();
        assert_eq!(b.lookup(&"198.51.100.66".parse().unwrap()).map(|(_, l)| l), Some("feodo.txt"));
        let (net, l) = b.lookup(&"203.0.113.200".parse().unwrap()).unwrap();
        assert_eq!((net.to_string().as_str(), l), ("203.0.113.0/24", "drop.txt"));
        assert!(b.lookup(&"198.51.100.67".parse().unwrap()).is_none());
        assert!(b.lookup(&"2001:db8::1".parse().unwrap()).is_none());
    }

    // Le réseau le plus précis l'emporte quand deux listes se recouvrent.
    #[test]
    fn longest_prefix_wins() {
        let mut b = Blocklist::default();
        b.add_list("large.txt", "10.0.0.0/8\n");
        b.add_list("precis.txt", "10.1.0.0/16\n");
        assert_eq!(b.lookup(&"10.1.2.3".parse().unwrap()).map(|(_, l)| l), Some("precis.txt"));
        assert_eq!(b.lookup(&"10.2.0.1".parse().unwrap()).map(|(_, l)| l), Some("large.txt"));
    }

    // Un poste interne qui contacte une IP listée : une seule alerte haute pour tout le flux.
    #[test]
    fn detects_outbound_to_listed_ip_once() {
        let mut d = detector();
        let mut out = Vec::new();
        for i in 0..50 {
            d.on_packet(&syn(i as f64, "192.168.1.20", "198.51.100.66", 443), &mut out);
        }
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].kind, AlertKind::ThreatListMatch);
        assert_eq!(out[0].severity, Severity::High);
        assert_eq!(out[0].evidence["list"], "feodo.txt");
    }

    // Une IP listée qui contacte un hôte interne : alerte de sévérité basse.
    #[test]
    fn inbound_from_listed_network_is_low() {
        let mut d = detector();
        let mut out = Vec::new();
        d.on_packet(&syn(1.0, "203.0.113.77", "192.168.1.10", 22), &mut out);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].severity, Severity::Low);
    }

    // Le trafic vers des IP non listées, ou interne, ne déclenche rien.
    #[test]
    fn unlisted_and_internal_traffic_is_quiet() {
        let mut d = detector();
        let mut out = Vec::new();
        for i in 0..100 {
            d.on_packet(&syn(i as f64, "192.168.1.35", "93.184.216.34", 443), &mut out);
            d.on_packet(&syn(i as f64, "192.168.1.35", "192.168.1.10", 445), &mut out);
        }
        assert!(out.is_empty());
    }

    // Passé le délai, le même couple alerte de nouveau ; l'état est purgé par `tick`.
    #[test]
    fn realerts_after_delay_and_purges() {
        let mut d = detector();
        let mut out = Vec::new();
        d.on_packet(&syn(0.0, "192.168.1.20", "198.51.100.66", 443), &mut out);
        d.tick(4000.0, &mut out);
        assert!(d.seen.is_empty());
        d.on_packet(&syn(4000.0, "192.168.1.20", "198.51.100.66", 443), &mut out);
        assert_eq!(out.len(), 2);
    }

    // Au plafond, les nouveaux couples ne sont plus mémorisés : la mémoire reste bornée.
    #[test]
    fn seen_is_capped() {
        let mut d = detector();
        d.max_seen = 2;
        let mut out = Vec::new();
        for host in 1..=5 {
            d.on_packet(&syn(1.0, &format!("192.168.1.{host}"), "198.51.100.66", 443), &mut out);
        }
        assert_eq!(d.seen.len(), 2);
        assert_eq!(out.len(), 5);
    }
}
