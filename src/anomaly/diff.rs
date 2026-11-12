//! Diff entre le modèle actif et un modèle candidat : ce que l'apprentissage s'apprête à
//! faire entrer dans le comportement normal, présenté machine par machine.
//!
//! Comparer deux forêts directement n'a pas de sens (leurs arbres sont aléatoires) : on
//! compare ce qu'elles **acceptent**. Trois éclairages (docs/conception-normalite.md, § 4.5) :
//! - diff de décision : fenêtres signalées par l'actif et acceptées par le candidat ;
//! - diff de profil : caractéristiques dont le 95e centile change de plus de 50 % ;
//! - dérive cumulée : volumes multipliés ou divisés par plus de `drift_factor` depuis le
//!   premier modèle validé (contre l'empoisonnement par petits pas).
//!
//! Fonction pure : aucune entrée/sortie, testable avec des modèles en mémoire.

use std::collections::BTreeMap;

use chrono::{DateTime, Utc};
use serde::Serialize;

use super::{
    features::{self, FeatureStat},
    model::{Model, Sample},
};

/// Variation relative du 95e centile au-delà de laquelle un changement de profil est signalé.
const PROFILE_CHANGE: f64 = 0.5;
/// Caractéristiques résumées pour un premier modèle (pas d'ancien profil à comparer).
const FIRST_MODEL_SUMMARY: [usize; 6] = [0, 1, 3, 4, 6, 7];

/// Diff complet, regroupé par machine.
#[derive(Debug, Clone, Serialize)]
pub struct Diff {
    /// Vrai s'il n'existe pas encore de modèle actif : on valide alors le profil appris.
    pub first_model: bool,
    pub hosts: Vec<HostDiff>,
}

impl Diff {
    /// Vrai si le candidat n'accepte rien de nouveau et ne change aucun profil.
    pub fn is_empty(&self) -> bool {
        self.hosts.is_empty()
    }

    /// Machines présentant une dérive cumulée.
    pub fn drift_hosts(&self) -> Vec<String> {
        self.hosts.iter().filter(|h| !h.drift.is_empty()).map(|h| h.host.clone()).collect()
    }
}

/// Ce qui change pour une machine.
#[derive(Debug, Clone, Serialize)]
pub struct HostDiff {
    pub host: String,
    /// Fenêtres que l'actif signalait et que le candidat accepterait. Pour un premier modèle :
    /// toutes les fenêtres apprises de la machine.
    pub newly_accepted: usize,
    /// Période couverte par ces fenêtres.
    pub first: Option<DateTime<Utc>>,
    pub last: Option<DateTime<Utc>>,
    /// Machine absente du modèle actif (nouvel appareil, ou trop peu connue jusqu'ici).
    pub new_host: bool,
    pub changes: Vec<FeatureChange>,
    pub drift: Vec<FeatureChange>,
    /// Début des fenêtres nouvellement acceptées, pour les exclure si la machine est refusée.
    #[serde(skip)]
    pub accepted_starts: Vec<f64>,
}

/// Évolution d'une caractéristique, en valeurs lisibles.
#[derive(Debug, Clone, Serialize)]
pub struct FeatureChange {
    pub feature: String,
    pub before: String,
    pub after: String,
}

/// Calcule le diff entre `active` (absent pour un premier modèle) et `candidate`, à partir des
/// échantillons d'apprentissage du candidat. `first_profile` : profils du premier modèle validé.
///
/// Bruit : chaque modèle place par construction environ `contamination` de ses données
/// d'apprentissage au-dessus de son seuil, et deux forêts ne choisissent pas exactement les
/// mêmes fenêtres limites. Les fenêtres nouvellement acceptées ne sont donc retenues pour une
/// machine que si elles dépassent ce bruit attendu (2 × contamination, et au moins 3).
pub fn compute(
    active: Option<&Model>,
    candidate: &Model,
    training: &[&Sample],
    first_profile: Option<&BTreeMap<String, Vec<FeatureStat>>>,
    drift_factor: f64,
    contamination: f64,
) -> Diff {
    let mut by_host: BTreeMap<&str, Vec<&Sample>> = BTreeMap::new();
    for s in training {
        by_host.entry(s.host.as_str()).or_default().push(s);
    }

    let mut hosts: Vec<HostDiff> = by_host
        .into_iter()
        .map(|(host, samples)| {
            // Diff de décision : tout est nouveau pour un premier modèle.
            let mut accepted: Vec<&&Sample> = match active {
                Some(a) => samples.iter().filter(|s| a.is_anomalous(&s.features) && !candidate.is_anomalous(&s.features)).collect(),
                None => samples.iter().collect(),
            };
            let noise = (2.0 * contamination * samples.len() as f64).ceil().max(3.0) as usize;
            if active.is_some() && accepted.len() < noise {
                accepted.clear();
            }
            let after = candidate.hosts.get(host);
            let changes = match (active, after) {
                (None, Some(c)) => summary(c),
                (Some(a), Some(c)) => a.hosts.get(host).map(|b| profile_changes(b, c)).unwrap_or_default(),
                _ => Vec::new(),
            };
            let drift = match (first_profile.and_then(|f| f.get(host)), after) {
                (Some(f), Some(c)) => drift_changes(f, c, drift_factor),
                _ => Vec::new(),
            };
            let ts = |t: f64| DateTime::from_timestamp(t as i64, 0);
            HostDiff {
                host: host.to_string(),
                newly_accepted: accepted.len(),
                first: accepted.iter().map(|s| s.start).reduce(f64::min).and_then(ts),
                last: accepted.iter().map(|s| s.end).reduce(f64::max).and_then(ts),
                new_host: active.is_some_and(|a| !a.hosts.contains_key(host)),
                changes,
                drift,
                accepted_starts: accepted.iter().map(|s| s.start).collect(),
            }
        })
        .filter(|h| h.newly_accepted > 0 || !h.changes.is_empty() || !h.drift.is_empty())
        .collect();
    hosts.sort_by(|a, b| b.newly_accepted.cmp(&a.newly_accepted).then(a.host.cmp(&b.host)));
    Diff { first_model: active.is_none(), hosts }
}

/// Résumé du profil appris, pour un premier modèle : valeur habituelle et pointes.
fn summary(p: &[FeatureStat]) -> Vec<FeatureChange> {
    FIRST_MODEL_SUMMARY
        .iter()
        .map(|&i| FeatureChange {
            feature: features::NAMES[i].into(),
            before: "—".into(),
            after: format!("{} (pointes : {})", features::display(i, p[i].median), features::display(i, p[i].p95)),
        })
        .collect()
}

/// Caractéristiques dont le 95e centile varie de plus de 50 %, en unités naturelles.
fn profile_changes(before: &[FeatureStat], after: &[FeatureStat]) -> Vec<FeatureChange> {
    features::EXPLAINABLE
        .iter()
        .filter(|&&i| {
            let (b, a) = (features::natural(i, before[i].p95), features::natural(i, after[i].p95));
            // Plancher par unité, pour ignorer les variations insignifiantes (3 → 5 octets).
            let floor = match i {
                0 | 1 => 10_240.0,
                6 | 7 => 0.05,
                9 => 0.2,
                _ => 2.0,
            };
            (a - b).abs() / b.abs().max(floor) > PROFILE_CHANGE
        })
        .map(|&i| FeatureChange {
            feature: features::NAMES[i].into(),
            before: format!("pointes à {}", features::display(i, before[i].p95)),
            after: format!("pointes à {}", features::display(i, after[i].p95)),
        })
        .collect()
}

/// Volumes dont la médiane a été multipliée ou divisée par plus de `factor` depuis le premier modèle.
fn drift_changes(first: &[FeatureStat], now: &[FeatureStat], factor: f64) -> Vec<FeatureChange> {
    features::DRIFT
        .iter()
        .filter(|&&i| {
            // +1 : une valeur nulle au départ ne provoque pas de division par zéro.
            let ratio = (features::natural(i, now[i].median) + 1.0) / (features::natural(i, first[i].median) + 1.0);
            ratio > factor || ratio < 1.0 / factor
        })
        .map(|&i| FeatureChange {
            feature: features::NAMES[i].into(),
            before: format!("{} au premier modèle", features::display(i, first[i].median)),
            after: format!("{} aujourd'hui", features::display(i, now[i].median)),
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use chrono::Utc;

    use super::*;
    use crate::{anomaly::model::tests::sample, config::AnomalyConfig};

    fn train(samples: &[Sample], version: u32) -> Model {
        let refs: Vec<&Sample> = samples.iter().collect();
        Model::train(&refs, &AnomalyConfig::default(), version, Utc::now())
    }

    // Premier modèle : chaque machine apparaît avec toutes ses fenêtres et un résumé de profil.
    #[test]
    fn first_model_lists_every_host() {
        let s: Vec<Sample> = (0..60).map(|i| sample(if i % 2 == 0 { "10.0.0.1" } else { "10.0.0.2" }, i, 2.0)).collect();
        let m = train(&s, 1);
        let refs: Vec<&Sample> = s.iter().collect();
        let d = compute(None, &m, &refs, None, 10.0, 0.005);
        assert!(d.first_model);
        assert_eq!(d.hosts.len(), 2);
        assert_eq!(d.hosts[0].newly_accepted, 30);
        assert_eq!(d.hosts[0].changes.len(), FIRST_MODEL_SUMMARY.len());
    }

    // Rien de nouveau : diff vide (le candidat pourra être activé sans question).
    #[test]
    fn identical_behaviour_gives_empty_diff() {
        let s: Vec<Sample> = (0..300).map(|i| sample("10.0.0.1", i, 2.0)).collect();
        let (a, c) = (train(&s, 1), train(&s, 2));
        let refs: Vec<&Sample> = s.iter().collect();
        assert!(compute(Some(&a), &c, &refs, Some(&a.hosts), 10.0, 0.005).is_empty());
    }

    // Une machine dont l'activité augmente nettement : ses fenêtres signalées par l'ancien
    // modèle et acceptées par le nouveau apparaissent dans le diff, avec le changement de profil.
    #[test]
    fn new_behaviour_appears_in_diff() {
        let old: Vec<Sample> = (0..300).map(|i| sample("10.0.0.1", i, 2.0)).collect();
        let active = train(&old, 1);
        let mut recent = old.clone();
        recent.extend((300..450).map(|i| sample("10.0.0.1", i, 6.0)));
        let cand = train(&recent, 2);
        let refs: Vec<&Sample> = recent.iter().collect();
        let d = compute(Some(&active), &cand, &refs, Some(&active.hosts), 1000.0, 0.005);
        assert_eq!(d.hosts.len(), 1);
        assert!(d.hosts[0].newly_accepted > 0);
        // Comptages en dizaines : l'évolution des connexions dépasse le plancher de signification.
        assert!(d.hosts[0].changes.iter().any(|c| c.feature == features::NAMES[3]));
        // L'essentiel des fenêtres acceptées est le nouveau comportement (le reste est du bruit de seuil).
        let new = d.hosts[0].accepted_starts.iter().filter(|&&t| t >= 300.0 * 300.0).count();
        assert!(new * 10 >= d.hosts[0].accepted_starts.len() * 9, "{new} / {}", d.hosts[0].accepted_starts.len());
    }

    // Médiane d'octets envoyés multipliée par plus de 10 depuis le premier modèle : dérive.
    #[test]
    fn cumulative_drift_is_detected() {
        let first = train(&(0..300).map(|i| sample("10.0.0.1", i, 2.0)).collect::<Vec<_>>(), 1);
        let now: Vec<Sample> = (0..300).map(|i| sample("10.0.0.1", i, 6.0)).collect();
        let cand = train(&now, 5);
        let refs: Vec<&Sample> = now.iter().collect();
        let d = compute(Some(&cand), &cand, &refs, Some(&first.hosts), 10.0, 0.005);
        assert_eq!(d.drift_hosts(), vec!["10.0.0.1".to_string()]);
    }
}
