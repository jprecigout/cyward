//! Données de l'apprentissage : échantillons et modèles versionnés.
//!
//! Un [`Sample`] est l'activité d'une machine sur une fenêtre, avec son statut de validation.
//! Un [`Model`] est une forêt entraînée, accompagnée de son seuil et des profils habituels
//! qui servent à expliquer les anomalies et à comparer deux modèles.

use std::collections::BTreeMap;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use super::{
    features::{self, FeatureStat, Features},
    iforest::IsolationForest,
};
use crate::config::AnomalyConfig;

/// En dessous de ce nombre d'échantillons, une machine est comparée au profil global.
const MIN_HOST_SAMPLES: usize = 20;

/// Statut de validation d'un échantillon (voir doc/conception-normalite.md, § 4.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SampleStatus {
    /// Rien d'anormal (ou couvert par une exception) : utilisable pour l'apprentissage.
    Normal,
    /// Anomalie en attente de réponse : exclu de l'apprentissage.
    Flagged,
    /// L'utilisateur a répondu « c'est normal » : utilisable.
    ConfirmedNormal,
    /// Réponse « suspect » ou changement refusé : jamais appris.
    Suspicious,
}

impl SampleStatus {
    /// Vrai si l'échantillon peut entrer dans l'apprentissage (avant le contrôle des alertes à règles).
    pub fn learnable(&self) -> bool {
        matches!(self, SampleStatus::Normal | SampleStatus::ConfirmedNormal)
    }
}

/// Activité d'une machine sur une fenêtre.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Sample {
    /// Adresse IP de la machine.
    pub host: String,
    /// Début et fin de la fenêtre (secondes depuis l'epoch, temps des paquets).
    pub start: f64,
    pub end: f64,
    pub features: Features,
    pub status: SampleStatus,
}

/// Modèle entraîné et versionné.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Model {
    pub version: u32,
    /// Date de l'apprentissage (horloge murale), pour planifier le suivant.
    pub trained_at: DateTime<Utc>,
    /// Fin de la dernière fenêtre apprise (temps des paquets).
    pub data_until: f64,
    /// Nombre d'échantillons appris.
    pub samples: usize,
    /// Score à partir duquel une fenêtre est anormale.
    pub threshold: f64,
    pub forest: IsolationForest,
    /// Profil habituel de l'ensemble des machines.
    pub global: Vec<FeatureStat>,
    /// Profil habituel de chaque machine ayant assez d'échantillons.
    pub hosts: BTreeMap<String, Vec<FeatureStat>>,
}

impl Model {
    /// Entraîne un modèle sur les échantillons fournis (déjà filtrés : uniquement des
    /// échantillons validés). La graine dépend de la version, pour un résultat reproductible.
    pub fn train(samples: &[&Sample], cfg: &AnomalyConfig, version: u32, trained_at: DateTime<Utc>) -> Self {
        let rows: Vec<&Features> = samples.iter().map(|s| &s.features).collect();
        let seed = 0x5EED_0000_0000_0000 ^ u64::from(version);
        let forest = IsolationForest::fit(&rows, cfg.trees, cfg.sample_size, seed);

        // Seuil = quantile élevé des scores d'apprentissage : seule la part `contamination`
        // des données apprises le dépasse. Plancher à 0,5 : en dessous, l'Isolation Forest
        // considère un point comme ordinaire, quelle que soit la régularité des données.
        let mut scores: Vec<f64> = rows.iter().map(|r| forest.score(&r[..])).collect();
        scores.sort_by(f64::total_cmp);
        let threshold = features::quantile(&scores, 1.0 - cfg.contamination).max(0.5);

        let mut by_host: BTreeMap<&str, Vec<&Features>> = BTreeMap::new();
        for s in samples {
            by_host.entry(s.host.as_str()).or_default().push(&s.features);
        }
        let hosts = by_host
            .into_iter()
            .filter(|(_, v)| v.len() >= MIN_HOST_SAMPLES)
            .map(|(h, v)| (h.to_string(), features::profile(&v)))
            .collect();

        Self {
            version,
            trained_at,
            data_until: samples.iter().map(|s| s.end).fold(0.0, f64::max),
            samples: samples.len(),
            threshold,
            forest,
            global: features::profile(&rows),
            hosts,
        }
    }

    pub fn score(&self, f: &Features) -> f64 {
        self.forest.score(f)
    }

    pub fn is_anomalous(&self, f: &Features) -> bool {
        self.score(f) >= self.threshold
    }

    /// Profil habituel de la machine, ou profil global si elle est peu connue.
    pub fn profile_for(&self, host: &str) -> &[FeatureStat] {
        self.hosts.get(host).unwrap_or(&self.global)
    }

    /// Vrai si la machine a son propre profil (sinon elle est comparée à l'ensemble du réseau).
    pub fn knows_host(&self, host: &str) -> bool {
        self.hosts.contains_key(host)
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// Échantillon de test : une machine dont l'activité vaut environ `level` sur toutes les
    /// caractéristiques. La variation est continue et pseudo-aléatoire (déterministe), comme
    /// celle de vraies fenêtres : des valeurs répétées fausseraient le seuil par des ex aequo.
    pub fn sample(host: &str, i: usize, level: f64) -> Sample {
        let mut f = [level; features::N];
        for (k, v) in f.iter_mut().enumerate() {
            let x = ((i as f64) * 12.9898 + (k as f64) * 78.233).sin() * 43_758.545_3;
            *v += 0.3 * (x - x.floor());
        }
        Sample { host: host.into(), start: i as f64 * 300.0, end: (i + 1) as f64 * 300.0, features: f, status: SampleStatus::Normal }
    }

    // Un modèle entraîné sur une activité régulière signale une fenêtre très différente,
    // pas une fenêtre habituelle ; le seuil n'est jamais sous 0,5.
    #[test]
    fn model_flags_unusual_window() {
        let samples: Vec<Sample> = (0..300).map(|i| sample("10.0.0.5", i, 2.0)).collect();
        let refs: Vec<&Sample> = samples.iter().collect();
        let m = Model::train(&refs, &AnomalyConfig::default(), 1, Utc::now());
        assert!(m.threshold >= 0.5);
        assert!(!m.is_anomalous(&sample("10.0.0.5", 3, 2.0).features));
        assert!(m.is_anomalous(&[9.0; features::N]));
        assert!(m.hosts.contains_key("10.0.0.5"));
        assert_eq!(m.data_until, 300.0 * 300.0);
    }

    // Une machine peu connue est comparée au profil global.
    #[test]
    fn unknown_host_uses_global_profile() {
        let samples: Vec<Sample> = (0..100).map(|i| sample("10.0.0.5", i, 1.0)).collect();
        let refs: Vec<&Sample> = samples.iter().collect();
        let m = Model::train(&refs, &AnomalyConfig::default(), 1, Utc::now());
        assert_eq!(m.profile_for("10.0.0.99").len(), features::N);
        assert_eq!(m.profile_for("10.0.0.99")[0].median, m.global[0].median);
    }
}
