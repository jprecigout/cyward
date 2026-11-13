//! Échantillons de l'apprentissage : leur journal sur disque, leur rétention et leur couverture.
//!
//! Les échantillons sont persistés sous forme de journal d'événements (ajout d'une fenêtre,
//! changement de statut) : une sauvegarde n'écrit que ce qui a changé. Ce module définit ces
//! événements, la façon de les rejouer et la règle de compaction ; `Baseline` décide quand
//! les produire et `Storage` les écrit. Tout ici est pur.

use std::collections::{HashMap, HashSet, VecDeque};

use serde::{Deserialize, Serialize};

use crate::{
    anomaly::model::{Sample, SampleStatus},
    config::AnomalyConfig,
};

/// Lignes de journal tolérées en plus des échantillons conservés avant de le réécrire
/// (compaction). La marge évite de réécrire sans cesse un petit état.
pub(super) const COMPACT_SLACK: usize = 10_000;

/// Modification des échantillons, telle qu'écrite dans le journal `samples.jsonl` : rejouer
/// le journal dans l'ordre reconstruit les échantillons.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum SampleEvent {
    /// Nouvelle fenêtre enregistrée.
    Add(Sample),
    /// Changement de statut d'une fenêtre (réponse de l'utilisateur, refus d'un diff).
    Status { host: String, start: f64, status: SampleStatus },
}

/// Ensemble de fenêtres désignées par (machine, début), sans copier les noms de machine.
/// Le début est comparé par ses bits : c'est la même valeur, relue telle quelle.
pub(super) struct Windows<'a>(HashMap<&'a str, HashSet<u64>>);

impl<'a> Windows<'a> {
    pub(super) fn new(items: impl IntoIterator<Item = (&'a str, f64)>) -> Self {
        let mut m: HashMap<&str, HashSet<u64>> = HashMap::new();
        for (host, start) in items {
            m.entry(host).or_default().insert(start.to_bits());
        }
        Self(m)
    }

    pub(super) fn contains(&self, s: &Sample) -> bool {
        self.0.get(s.host.as_str()).is_some_and(|t| t.contains(&s.start.to_bits()))
    }

    pub(super) fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

/// Reconstruit les échantillons en rejouant le journal dans l'ordre. Un changement de statut
/// visant une fenêtre inconnue (ligne d'ajout perdue) est ignoré.
pub(super) fn replay(events: Vec<SampleEvent>) -> VecDeque<Sample> {
    let mut samples = VecDeque::with_capacity(events.len());
    let mut index: HashMap<(String, u64), usize> = HashMap::new();
    for e in events {
        match e {
            SampleEvent::Add(s) => {
                index.insert((s.host.clone(), s.start.to_bits()), samples.len());
                samples.push_back(s);
            }
            SampleEvent::Status { host, start, status } => {
                if let Some(&i) = index.get(&(host, start.to_bits())) {
                    samples[i].status = status;
                }
            }
        }
    }
    samples
}

/// Rétention des échantillons : par ancienneté (temps des paquets, par rapport au plus
/// récent), puis par nombre. Renvoie la machine de chaque fenêtre retirée, pour que l'état qui
/// en dépend (destinations vues) suive la même rétention.
pub(super) fn enforce_retention(samples: &mut VecDeque<Sample>, cfg: &AnomalyConfig) -> Vec<String> {
    let mut removed = Vec::new();
    let Some(last) = samples.back().map(|s| s.end) else { return removed };
    let oldest = last - cfg.retention_days * 86_400.0;
    while samples.front().is_some_and(|s| s.end < oldest) || samples.len() > cfg.max_samples {
        if let Some(s) = samples.pop_front() {
            removed.push(s.host);
        }
    }
    removed
}

/// Vrai si le journal doit être réécrit : demandé explicitement, ou plus de deux fois plus
/// long (plus une marge) que les échantillons encore conservés. Le coût est amorti : entre
/// deux compactions, au moins autant de lignes ont été ajoutées que la réécriture en écrit.
pub(super) fn needs_compaction(forced: bool, journal_lines: usize, samples: usize) -> bool {
    forced || journal_lines > 2 * samples + COMPACT_SLACK
}

/// Durée couverte par les échantillons, en heures (temps des paquets).
pub(super) fn covered_hours(samples: &VecDeque<Sample>) -> f64 {
    let first = samples.iter().map(|s| s.start).reduce(f64::min);
    let last = samples.iter().map(|s| s.end).reduce(f64::max);
    match (first, last) {
        (Some(a), Some(b)) => (b - a) / 3600.0,
        _ => 0.0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::anomaly::model::tests::sample;

    // Le journal n'est réécrit qu'au-delà de deux fois sa taille utile (plus la marge), ou sur demande.
    #[test]
    fn compaction_threshold() {
        assert!(!needs_compaction(false, 2 * 1000 + COMPACT_SLACK, 1000));
        assert!(needs_compaction(false, 2 * 1000 + COMPACT_SLACK + 1, 1000));
        assert!(needs_compaction(true, 0, 0));
    }

    // Le rejeu applique chaque changement de statut à sa fenêtre et ignore celui d'une fenêtre inconnue.
    #[test]
    fn replay_applies_status_changes() {
        let (a, b) = (sample("10.0.0.1", 0, 1.0), sample("10.0.0.1", 1, 1.0));
        let events = vec![
            SampleEvent::Add(a.clone()),
            SampleEvent::Add(b),
            SampleEvent::Status { host: a.host.clone(), start: a.start, status: SampleStatus::Suspicious },
            SampleEvent::Status { host: "10.0.0.9".into(), start: 0.0, status: SampleStatus::Suspicious },
        ];
        let s = replay(events);
        assert_eq!(s.len(), 2);
        assert_eq!((s[0].status, s[1].status), (SampleStatus::Suspicious, SampleStatus::Normal));
    }

    // La rétention retire les fenêtres trop anciennes par rapport à la plus récente, puis l'excédent.
    #[test]
    fn retention_by_age_then_count() {
        let cfg = AnomalyConfig { retention_days: 1.0, max_samples: 2, ..Default::default() };
        // Fenêtres de 300 s : 400 fenêtres couvrent plus d'un jour.
        let mut s: VecDeque<Sample> = (0..400).map(|i| sample("10.0.0.1", i, 1.0)).collect();
        assert_eq!(enforce_retention(&mut s, &cfg).len(), 398);
        assert_eq!(s.len(), 2);
        assert_eq!(s.back().unwrap().start, 399.0 * 300.0);
        assert!((covered_hours(&s) - 600.0 / 3600.0).abs() < 1e-9);
    }
}
