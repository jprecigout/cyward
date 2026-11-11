//! État de l'apprentissage tel que l'API `GET /api/baseline` le renvoie au dashboard.
//!
//! Ces structures sont de simples vues, construites par `Baseline::status` : elles ne portent
//! aucune règle, et changer l'affichage ne touche pas à la logique de validation.

use chrono::{DateTime, Utc};
use serde::Serialize;

use super::{Decision, Exception};
use crate::{
    anomaly::{diff::Diff, model::Model},
    config::AnomalyMode,
};

#[derive(Debug, Serialize)]
pub struct Status {
    pub enabled: bool,
    pub mode: AnomalyMode,
    pub persistent: bool,
    pub window_secs: f64,
    pub samples: SampleCounts,
    pub learning: Learning,
    pub active: Option<ModelInfo>,
    pub candidate: Option<CandidateInfo>,
    pub versions: Vec<u32>,
    pub exceptions: Vec<Exception>,
    pub decisions: Vec<Decision>,
}

#[derive(Debug, Serialize)]
pub struct SampleCounts {
    pub normal: usize,
    pub flagged: usize,
    pub confirmed_normal: usize,
    pub suspicious: usize,
}

#[derive(Debug, Serialize)]
pub struct Learning {
    pub required_samples: usize,
    pub required_hours: f64,
    pub covered_hours: f64,
}

#[derive(Debug, Serialize)]
pub struct ModelInfo {
    pub version: u32,
    pub trained_at: DateTime<Utc>,
    pub samples: usize,
    pub threshold: f64,
    pub hosts: usize,
}

impl From<&Model> for ModelInfo {
    fn from(m: &Model) -> Self {
        Self { version: m.version, trained_at: m.trained_at, samples: m.samples, threshold: m.threshold, hosts: m.hosts.len() }
    }
}

#[derive(Debug, Serialize)]
pub struct CandidateInfo {
    pub model: ModelInfo,
    pub diff: Diff,
}
