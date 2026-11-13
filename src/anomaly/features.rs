//! Caractéristiques d'une machine sur une fenêtre de temps, et statistiques de profil.
//!
//! Tout ici est pur (aucune entrée/sortie) : les compteurs d'une fenêtre deviennent un
//! vecteur de 12 nombres, et un ensemble de vecteurs devient un profil (médiane, dispersion,
//! 95e centile) qui sert à expliquer les anomalies et à comparer deux modèles.

use std::{collections::HashSet, net::IpAddr};

use serde::{Deserialize, Serialize};

use crate::alert::human_bytes;

/// Nombre de caractéristiques par échantillon.
pub const N: usize = 12;

/// Vecteur de caractéristiques d'une machine sur une fenêtre (valeurs transformées).
pub type Features = [f64; N];

/// Libellés affichés, dans l'ordre des indices.
pub const NAMES: [&str; N] = [
    "Octets envoyés",
    "Octets reçus",
    "Paquets envoyés",
    "Connexions ouvertes",
    "Destinations distinctes",
    "Ports de destination distincts",
    "Part du trafic vers l'extérieur",
    "Part de destinations nouvelles",
    "Requêtes DNS",
    "Entropie DNS moyenne",
    "Heure (sinus)",
    "Heure (cosinus)",
];

/// Caractéristiques stockées sous forme `ln(1 + x)` (volumes et comptages).
const LOG: [usize; 7] = [0, 1, 2, 3, 4, 5, 8];
/// Caractéristiques en octets (affichées en Ko, Mo…).
const BYTES: [usize; 2] = [0, 1];
/// Caractéristiques qui ont un sens pour un humain, prises seules : l'heure encodée en
/// sinus/cosinus est utile au modèle mais illisible dans une explication.
pub const EXPLAINABLE: [usize; 10] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9];
/// Volumes surveillés pour la dérive cumulée (octets envoyés et reçus, connexions, destinations).
pub const DRIFT: [usize; 4] = [0, 1, 3, 4];

/// Plafonds des ensembles de compteurs, pour qu'une machine qui balaie tout le réseau
/// (ou des adresses usurpées) ne fasse pas grossir la mémoire sans limite.
pub const MAX_DSTS: usize = 4096;
pub const MAX_PORTS: usize = 1024;

/// Compteurs bruts d'une machine pendant une fenêtre, alimentés paquet par paquet.
#[derive(Debug, Default, Clone)]
pub struct HostCounters {
    pub bytes_out: u64,
    pub bytes_in: u64,
    pub packets_out: u64,
    /// Octets envoyés vers une adresse externe.
    pub bytes_out_external: u64,
    /// Ouvertures de connexion TCP (SYN) émises.
    pub conn_out: u64,
    pub dsts: HashSet<IpAddr>,
    pub dports: HashSet<u16>,
    pub dns_queries: u64,
    /// Somme des entropies des noms demandés (divisée par `dns_queries` pour la moyenne).
    pub dns_entropy_sum: f64,
}

/// Transforme les compteurs d'une fenêtre en caractéristiques. `new_dsts` est le nombre de
/// destinations jamais vues pour cette machine ; `hour` l'heure locale (0 à 24, décimale).
pub fn compute(c: &HostCounters, new_dsts: usize, hour: f64) -> Features {
    let ratio = |num: f64, den: f64| if den > 0.0 { num / den } else { 0.0 };
    let angle = std::f64::consts::TAU * hour / 24.0;
    [
        (c.bytes_out as f64).ln_1p(),
        (c.bytes_in as f64).ln_1p(),
        (c.packets_out as f64).ln_1p(),
        (c.conn_out as f64).ln_1p(),
        (c.dsts.len() as f64).ln_1p(),
        (c.dports.len() as f64).ln_1p(),
        ratio(c.bytes_out_external as f64, c.bytes_out as f64),
        ratio(new_dsts as f64, c.dsts.len() as f64),
        (c.dns_queries as f64).ln_1p(),
        ratio(c.dns_entropy_sum, c.dns_queries as f64),
        angle.sin(),
        angle.cos(),
    ]
}

/// Valeur d'une caractéristique dans son unité naturelle (annule la transformation logarithmique).
pub fn natural(i: usize, v: f64) -> f64 {
    if LOG.contains(&i) { v.exp_m1() } else { v }
}

/// Valeur lisible d'une caractéristique transformée : « 85.0 Mo », « 37 », « 42 % »…
pub fn display(i: usize, v: f64) -> String {
    let x = natural(i, v);
    match i {
        _ if BYTES.contains(&i) => human_bytes(x),
        6 | 7 => format!("{:.0} %", x * 100.0),
        9 => format!("{x:.2} bits"),
        _ => format!("{:.0}", x),
    }
}

/// Statistiques d'une caractéristique sur un ensemble d'échantillons (valeurs transformées).
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize)]
pub struct FeatureStat {
    pub median: f64,
    /// Écart absolu médian : mesure de dispersion insensible aux valeurs extrêmes.
    pub mad: f64,
    pub p95: f64,
}

/// Profil d'un ensemble d'échantillons : une statistique par caractéristique.
pub fn profile(rows: &[&Features]) -> Vec<FeatureStat> {
    (0..N)
        .map(|i| {
            let mut v: Vec<f64> = rows.iter().map(|r| r[i]).collect();
            v.sort_by(f64::total_cmp);
            let median = quantile(&v, 0.5);
            let mut dev: Vec<f64> = v.iter().map(|x| (x - median).abs()).collect();
            dev.sort_by(f64::total_cmp);
            FeatureStat { median, mad: quantile(&dev, 0.5), p95: quantile(&v, 0.95) }
        })
        .collect()
}

/// Quantile `q` (0 à 1) d'une série **triée**, par interpolation linéaire. 0 si la série est vide.
pub fn quantile(sorted: &[f64], q: f64) -> f64 {
    if sorted.is_empty() {
        return 0.0;
    }
    let pos = q.clamp(0.0, 1.0) * (sorted.len() - 1) as f64;
    let (lo, hi) = (pos.floor() as usize, pos.ceil() as usize);
    sorted[lo] + (sorted[hi] - sorted[lo]) * (pos - lo as f64)
}

/// Écart d'une caractéristique à son profil habituel.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Deviation {
    pub index: usize,
    /// Écart en nombre de dispersions robustes (positif = au-dessus de l'habitude).
    pub z: f64,
}

/// Écarts des caractéristiques explicables, du plus fort au plus faible (en valeur absolue).
pub fn deviations(x: &Features, profile: &[FeatureStat]) -> Vec<Deviation> {
    let mut d: Vec<Deviation> = EXPLAINABLE
        .iter()
        .map(|&i| {
            let s = profile[i];
            // 1,4826 rend le MAD comparable à un écart-type ; le +0,1 évite une division par
            // zéro quand la machine est parfaitement régulière.
            Deviation { index: i, z: (x[i] - s.median) / (1.4826 * s.mad + 0.1) }
        })
        .collect();
    d.sort_by(|a, b| b.z.abs().total_cmp(&a.z.abs()));
    d
}

/// Écart (en dispersions robustes) à partir duquel une caractéristique explique une anomalie.
const EXPLAIN_Z: f64 = 3.0;

/// Une caractéristique qui s'écarte de l'habitude, en valeurs lisibles.
#[derive(Debug, Clone, PartialEq)]
pub struct Explained {
    pub index: usize,
    pub z: f64,
    pub value: String,
    /// Valeur de référence, lisible.
    pub usual: String,
    /// Référence de comparaison, à afficher : « habituellement 1.2 Mo » si la machine a son
    /// propre profil, « médiane du réseau 0.0 o » sinon. Sans cette précision, comparer une
    /// machine peu connue à la médiane de tout le réseau passerait pour son habitude.
    pub reference: String,
}

/// Explique une fenêtre : les écarts forts, ou à défaut le plus fort, en valeurs lisibles.
/// `own_profile` : la machine est comparée à son propre profil (et non à celui du réseau).
pub fn explain(x: &Features, profile: &[FeatureStat], own_profile: bool) -> Vec<Explained> {
    let all = deviations(x, profile);
    let strong: Vec<_> = all.iter().filter(|d| d.z.abs() >= EXPLAIN_Z).take(3).copied().collect();
    let chosen = if strong.is_empty() { all.into_iter().take(1).collect() } else { strong };
    chosen
        .into_iter()
        .map(|d| {
            let usual = display(d.index, profile[d.index].median);
            let reference = if own_profile {
                format!("habituellement {usual}")
            } else {
                format!("médiane du réseau {usual}, machine encore peu connue")
            };
            Explained { index: d.index, z: d.z, value: display(d.index, x[d.index]), usual, reference }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    // Les volumes sont stockés en ln(1+x), les ratios tels quels, et 0 h et 24 h coïncident.
    #[test]
    fn compute_transforms_values() {
        let mut c = HostCounters { bytes_out: 1000, bytes_out_external: 250, dns_queries: 4, dns_entropy_sum: 12.0, ..Default::default() };
        c.dsts.insert("10.0.0.1".parse().unwrap());
        c.dsts.insert("10.0.0.2".parse().unwrap());
        let f = compute(&c, 1, 0.0);
        assert!((natural(0, f[0]) - 1000.0).abs() < 1e-6);
        assert_eq!(f[6], 0.25);
        assert_eq!(f[7], 0.5);
        assert_eq!(f[9], 3.0);
        let g = compute(&c, 1, 24.0);
        assert!((f[10] - g[10]).abs() < 1e-9 && (f[11] - g[11]).abs() < 1e-9);
    }

    // Une machine sans trafic DNS ni destination ne produit pas de division par zéro.
    #[test]
    fn empty_counters_give_zero_ratios() {
        let f = compute(&HostCounters::default(), 0, 12.0);
        assert!(f.iter().all(|v| v.is_finite()));
        assert_eq!(f[6], 0.0);
        assert_eq!(f[7], 0.0);
    }

    // L'affichage revient aux unités naturelles.
    #[test]
    fn display_uses_natural_units() {
        assert_eq!(display(0, (2.0 * 1024.0 * 1024.0f64).ln_1p()), "2.0 Mo");
        assert_eq!(display(6, 0.42), "42 %");
        assert_eq!(display(3, 9f64.ln_1p()), "9");
    }

    // Le quantile interpole entre les valeurs, et la médiane d'un profil est correcte.
    #[test]
    fn quantile_and_profile() {
        assert_eq!(quantile(&[1.0, 2.0, 3.0, 4.0], 0.5), 2.5);
        let rows: Vec<Features> = (0..5).map(|i| [i as f64; N]).collect();
        let refs: Vec<&Features> = rows.iter().collect();
        let p = profile(&refs);
        assert_eq!(p[0].median, 2.0);
        assert_eq!(p[0].mad, 1.0);
    }

    // Le plus gros écart est classé en premier, et l'heure n'apparaît jamais dans l'explication.
    #[test]
    fn deviations_are_sorted_and_explainable() {
        let usual: Vec<FeatureStat> = vec![FeatureStat { median: 1.0, mad: 0.1, p95: 1.2 }; N];
        let mut x = [1.0; N];
        x[0] = 9.0;
        x[4] = 2.0;
        x[10] = 50.0;
        let d = deviations(&x, &usual);
        assert_eq!(d[0].index, 0);
        assert_eq!(d[1].index, 4);
        assert!(d.iter().all(|v| v.index != 10 && v.index != 11));
    }
}
