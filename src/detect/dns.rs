//! Détection d'abus du DNS. Le DNS traverse presque tous les pare-feux, ce qui en fait un
//! canal discret pour les botnets (domaines générés aléatoirement) et pour faire sortir des
//! données (tunnel DNS : les données sont encodées dans les sous-domaines demandés).

use std::{
    collections::{HashMap, HashSet},
    net::IpAddr,
};

use serde_json::json;

use super::{Detector, ts_to_dt};
use crate::{
    alert::{Alert, AlertKind, AlertSource, Severity},
    capture::PacketMeta,
    config::DnsConfig,
};

/// Requêtes DNS suspectes : noms à forte entropie (DGA, données encodées) et
/// multitude de sous-domaines uniques sous un même domaine (tunnel DNS).
pub struct Dns {
    cfg: DnsConfig,
    /// (source, domaine de base) → (début de fenêtre, sous-domaines distincts demandés).
    windows: HashMap<(IpAddr, String), (f64, HashSet<String>)>,
}

impl Dns {
    pub fn new(cfg: DnsConfig) -> Self {
        Self { cfg, windows: HashMap::new() }
    }
}

impl Detector for Dns {
    fn on_packet(&mut self, p: &PacketMeta, out: &mut Vec<Alert>) {
        let Some(name) = p.dns_query.as_deref() else { return };
        let name = name.trim_end_matches('.');
        if self.cfg.ignore_suffixes.iter().any(|s| name == s || name.ends_with(&format!(".{s}"))) {
            return;
        }
        let labels: Vec<&str> = name.split('.').collect();
        if labels.len() < 2 {
            return;
        }
        // Domaine de base = deux derniers segments (approximation : « co.uk » serait pris
        // pour un domaine). `sub` est tout ce qui précède.
        let base = labels[labels.len() - 2..].join(".");
        let sub = labels[..labels.len() - 2].join(".");

        // 1. Nom suspect : trop long, ou segment long et d'apparence aléatoire.
        let longest = labels.iter().copied().max_by_key(|l| l.len()).unwrap_or("");
        let entropy = shannon_entropy(longest);
        if name.len() > self.cfg.max_name_len || (longest.len() >= self.cfg.min_label_len && entropy >= self.cfg.entropy_threshold) {
            out.push(
                Alert::new(AlertKind::SuspiciousDns, Severity::Medium, AlertSource::Network, ts_to_dt(p.ts), format!("Requête DNS suspecte de {} vers *.{base}", p.src))
                    .description(format!(
                        "Nom de {} caractères, segment le plus long de {} caractères avec une entropie de {:.2} bits. Typique de domaines générés (DGA) ou de données encodées dans le DNS.",
                        name.len(),
                        longest.len(),
                        entropy
                    ))
                    .src(p.src)
                    .dst(&base)
                    .evidence(json!({ "query": name, "entropy": entropy })),
            );
        }

        // 2. Tunnel DNS : nombre de sous-domaines distincts d'un même domaine.
        if sub.is_empty() {
            return;
        }
        let (start, subs) = self.windows.entry((p.src, base.clone())).or_insert_with(|| (p.ts, HashSet::new()));
        if p.ts - *start > self.cfg.window_secs {
            *start = p.ts;
            subs.clear();
        }
        // L'ensemble cesse de grossir au seuil : inutile de mémoriser des milliers de noms
        // une fois l'alerte levée.
        if subs.len() < self.cfg.unique_subdomains_threshold && subs.insert(sub) && subs.len() == self.cfg.unique_subdomains_threshold {
            let sample: Vec<_> = subs.iter().take(10).cloned().collect();
            out.push(
                Alert::new(AlertKind::DnsTunneling, Severity::High, AlertSource::Network, ts_to_dt(p.ts), format!("Tunnel DNS probable de {} via {base}", p.src))
                    .description(format!(
                        "{} sous-domaines uniques de {base} demandés en moins de {} s : des données transitent probablement dans les requêtes DNS.",
                        subs.len(),
                        self.cfg.window_secs
                    ))
                    .src(p.src)
                    .dst(&base)
                    .evidence(json!({ "unique_subdomains": subs.len(), "sample": sample })),
            );
        }
    }

    fn tick(&mut self, now: f64, _out: &mut Vec<Alert>) {
        let w = self.cfg.window_secs;
        self.windows.retain(|_, (start, _)| now - *start <= 2.0 * w);
    }
}

/// Entropie de Shannon d'une chaîne, en bits par caractère.
///
/// Mesure le « désordre » : un mot lisible réutilise peu de lettres (entropie faible, ~2,5 à 3),
/// une chaîne aléatoire ou encodée en base32/base64 en utilise beaucoup, de façon uniforme (> 4).
pub fn shannon_entropy(s: &str) -> f64 {
    if s.is_empty() {
        return 0.0;
    }
    // Fréquence de chaque octet.
    let mut counts = [0u32; 256];
    for b in s.bytes() {
        counts[b as usize] += 1;
    }
    let n = s.len() as f64;
    // H = -Σ p·log2(p) sur les caractères présents.
    counts.iter().filter(|&&c| c > 0).map(|&c| {
        let p = c as f64 / n;
        -p * p.log2()
    }).sum()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::detect::testutil::dns;

    #[test]
    fn normal_names_pass() {
        let mut d = Dns::new(DnsConfig::default());
        let mut out = Vec::new();
        for n in ["www.google.com", "api.github.com", "fr.wikipedia.org", "1.1.168.192.in-addr.arpa"] {
            d.on_packet(&dns(0.0, "192.168.1.5", n), &mut out);
        }
        assert!(out.is_empty());
    }

    // Segment de 32 caractères encodé en base32 : entropie élevée.
    #[test]
    fn flags_high_entropy_label() {
        let mut d = Dns::new(DnsConfig::default());
        let mut out = Vec::new();
        d.on_packet(&dns(0.0, "192.168.1.5", "mzxw6ytboi4dgnzqgq3tsmrxhe2tq9kq.evil-c2.net"), &mut out);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].kind, AlertKind::SuspiciousDns);
    }

    // 200 sous-domaines distincts de exfil.io : une seule alerte de tunnel.
    #[test]
    fn flags_tunnel() {
        let mut d = Dns::new(DnsConfig::default());
        let mut out = Vec::new();
        for i in 0..200 {
            d.on_packet(&dns(i as f64, "192.168.1.5", &format!("c{i:04x}.t.exfil.io")), &mut out);
        }
        assert_eq!(out.iter().filter(|a| a.kind == AlertKind::DnsTunneling).count(), 1);
    }
}
