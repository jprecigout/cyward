//! Cycle de vie du comportement normal (pattern Façade) : échantillons, modèle actif,
//! modèle candidat, exceptions, versions et journal des décisions.
//!
//! Toutes les règles de validation humaine de doc/conception-normalite.md sont ici :
//! - une fenêtre signalée n'est jamais apprise tant que l'utilisateur n'a pas répondu ;
//! - un modèle ne devient actif qu'après validation de son diff, machine par machine
//!   (sauf si le diff est vide : rien de nouveau n'est alors accepté) ;
//! - aucun nouvel apprentissage tant qu'un candidat attend une réponse.
//!
//! Les méthodes sont synchrones et sans réseau : le détecteur, l'entraîneur et l'API web les
//! appellent, et les tests les exercent directement. Le journal des échantillons est dans
//! [`samples`], les vues renvoyées à l'API dans [`status`].
//!
//! Le verrou de l'état n'est jamais tenu pendant un calcul long ni pendant une écriture sur
//! disque : le moteur de détection le prend à chaque fin de fenêtre, et l'attendre ferait
//! perdre des paquets. L'apprentissage travaille sur une copie des échantillons, et la
//! sauvegarde n'ajoute au journal que ce qui a changé depuis la précédente.

mod samples;
mod status;

use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};

use anyhow::{Result, anyhow, bail};
use chrono::{DateTime, Utc};
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};

pub use self::status::{CandidateInfo, Learning, ModelInfo, SampleCounts, Status};
use self::samples::{SampleEvent, Windows, covered_hours, enforce_retention, needs_compaction, replay};
use super::{
    diff::{self, Diff},
    features::{self, Explained, FeatureStat, Features, explain},
    model::{Model, Sample, SampleStatus},
    storage::Storage,
};
use crate::{
    alert::{FeedbackScope, FeedbackVerdict},
    config::AnomalyConfig,
};

/// Destinations mémorisées par machine pour la caractéristique « destinations nouvelles ».
const MAX_SEEN_PER_HOST: usize = 2000;
/// Décisions gardées en mémoire pour l'affichage (le journal sur disque est complet).
const MAX_RECENT_DECISIONS: usize = 100;

/// Ce que le détecteur doit faire d'une fenêtre qui vient de se terminer.
#[derive(Debug, Clone, PartialEq)]
pub enum WindowVerdict {
    /// Pas encore de modèle actif : la fenêtre est seulement enregistrée.
    Learning,
    Normal,
    /// Anormale, mais couverte par une exception accordée par l'utilisateur.
    Excepted,
    Anomaly(AnomalyInfo),
}

/// Détail d'une fenêtre anormale, pour construire l'alerte.
#[derive(Debug, Clone, PartialEq)]
pub struct AnomalyInfo {
    pub score: f64,
    pub threshold: f64,
    pub version: u32,
    /// Principaux écarts au profil habituel, du plus fort au plus faible.
    pub deviations: Vec<Explained>,
}

/// Exception accordée par une réponse « normal, désormais ».
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Exception {
    pub host: String,
    /// Caractéristiques dont l'écart est toléré pour cette machine.
    pub features: Vec<usize>,
    pub labels: Vec<String>,
    pub reason: String,
    pub created: DateTime<Utc>,
}

/// Entrée du journal des décisions.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Decision {
    pub at: DateTime<Utc>,
    /// `feedback`, `validation`, `activation_auto` ou `rollback`.
    pub kind: String,
    pub host: Option<String>,
    pub detail: String,
    pub reason: Option<String>,
}

/// Résultat d'un apprentissage.
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "result", rename_all = "snake_case")]
pub enum TrainOutcome {
    /// Diff vide : le candidat a été activé sans question.
    AutoActivated { version: u32 },
    /// Le candidat attend la validation de l'utilisateur.
    PendingReview { version: u32, hosts: usize, drift_hosts: Vec<String> },
}

/// Résultat d'une validation.
#[derive(Debug, Clone, Serialize)]
pub struct DecisionOutcome {
    /// Version activée, ou `None` s'il ne restait pas assez de données après les refus.
    pub activated: Option<u32>,
    pub rejected: Vec<String>,
}

/// Modèle candidat en attente de validation.
struct Candidate {
    model: Model,
    diff: Diff,
    /// Échantillons d'apprentissage du candidat : (machine, début de fenêtre).
    training: Vec<(String, f64)>,
}

/// Destinations déjà vues par une machine. Sérialisé comme une liste ordonnée (les plus
/// anciennes d'abord, évincées en premier) ; l'ensemble sert aux recherches rapides.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
#[serde(from = "VecDeque<String>", into = "VecDeque<String>")]
struct Seen {
    order: VecDeque<String>,
    set: HashSet<String>,
}

impl From<VecDeque<String>> for Seen {
    fn from(order: VecDeque<String>) -> Self {
        let set = order.iter().cloned().collect();
        Self { order, set }
    }
}

impl From<Seen> for VecDeque<String> {
    fn from(s: Seen) -> Self {
        s.order
    }
}

/// État persistant (et, pour les champs `skip`, état de travail en mémoire).
#[derive(Default, Serialize, Deserialize)]
#[serde(default)]
struct State {
    /// Échantillons, persistés à part dans le journal `samples.jsonl`. Encore lus depuis
    /// `state.json` pour reprendre l'ancien format, où ils y étaient tous réécrits.
    #[serde(skip_serializing)]
    samples: VecDeque<Sample>,
    seen: HashMap<String, Seen>,
    exceptions: Vec<Exception>,
    decisions: VecDeque<Decision>,
    active_version: Option<u32>,
    /// Profils du premier modèle validé : référence de la dérive cumulée.
    first_profile: Option<BTreeMap<String, Vec<FeatureStat>>>,
    /// Numéro du prochain modèle activé.
    next_version: u32,
    #[serde(skip)]
    active: Option<Model>,
    #[serde(skip)]
    candidate: Option<Candidate>,
    /// Modèles validés gardés en mémoire (retour arrière sans disque).
    #[serde(skip)]
    versions: BTreeMap<u32, Model>,
    /// Un apprentissage calcule hors verrou : pendant ce temps, ni second apprentissage, ni
    /// validation, ni retour arrière (son résultat serait aussitôt périmé).
    #[serde(skip)]
    training: bool,
    /// Modifications des échantillons pas encore écrites dans le journal.
    #[serde(skip)]
    pending: Vec<SampleEvent>,
    /// Lignes déjà présentes dans le journal (pour décider de la compaction).
    #[serde(skip)]
    journal_lines: usize,
    /// Le journal doit être entièrement réécrit à la prochaine sauvegarde (ancien format, ou
    /// écriture précédente en échec).
    #[serde(skip)]
    compact: bool,
    /// Le reste de l'état (exceptions, journal récent, destinations vues, version active…) a
    /// changé depuis la dernière écriture de `state.json`.
    #[serde(skip)]
    meta_dirty: bool,
}

pub struct Baseline {
    cfg: AnomalyConfig,
    storage: Option<Storage>,
    state: Mutex<State>,
    /// Une sauvegarde à la fois : deux sauvegardes entrelacées pourraient écrire deux fois la
    /// même fenêtre dans le journal. Pris avant `state`, jamais l'inverse.
    saving: Mutex<()>,
}

/// Remet `training` à faux à la fin d'un apprentissage, même s'il échoue ou panique.
/// Doit être détruit après la libération de tout verrou sur l'état (sinon interblocage).
struct TrainingFlag<'a>(&'a Mutex<State>);

impl Drop for TrainingFlag<'_> {
    fn drop(&mut self) {
        self.0.lock().training = false;
    }
}

/// Ce que la sauvegarde doit écrire, préparé sous verrou puis écrit hors verrou.
struct SaveWork {
    /// Nouveau contenu de `state.json`, s'il a changé.
    meta: Option<Vec<u8>>,
    /// Lignes du journal des échantillons.
    events: Vec<SampleEvent>,
    /// Vrai : `events` remplace tout le journal (compaction). Faux : il s'y ajoute.
    rewrite: bool,
}

impl Baseline {
    /// Ouvre l'apprentissage : recharge l'état et le modèle actif depuis `data_dir` s'il est
    /// configuré, sinon démarre en mémoire (tout est perdu à l'arrêt).
    pub fn open(cfg: AnomalyConfig) -> Result<Self> {
        if cfg.data_dir.is_empty() {
            tracing::warn!("apprentissage du comportement normal en mémoire seulement (detection.anomaly.data_dir vide) : il sera perdu à l'arrêt");
            return Ok(Self::in_memory(cfg));
        }
        let storage = Storage::open(std::path::Path::new(&cfg.data_dir))?;
        let mut state: State = storage.load_state()?.unwrap_or_default();
        match storage.load_samples::<SampleEvent>()? {
            Some(events) => {
                state.journal_lines = events.len();
                state.samples = replay(events);
            }
            // Ancien format : les échantillons étaient dans state.json. La première sauvegarde
            // les écrit dans le journal et réécrit state.json sans eux.
            None if !state.samples.is_empty() => {
                state.compact = true;
                state.meta_dirty = true;
            }
            None => {}
        }
        enforce_retention(&mut state.samples, &cfg);
        if let Some(v) = state.active_version {
            let m = storage.load_model(v)?;
            state.versions.insert(v, m.clone());
            state.active = Some(m);
        }
        tracing::info!(
            "apprentissage du comportement normal : {} échantillon(s), modèle actif {}",
            state.samples.len(),
            state.active_version.map(|v| format!("v{v}")).unwrap_or_else(|| "aucun".into())
        );
        Ok(Self { cfg, storage: Some(storage), state: Mutex::new(state), saving: Mutex::new(()) })
    }

    pub fn in_memory(cfg: AnomalyConfig) -> Self {
        Self { cfg, storage: None, state: Mutex::new(State::default()), saving: Mutex::new(()) }
    }

    pub fn config(&self) -> &AnomalyConfig {
        &self.cfg
    }

    /// Version du modèle actif, s'il y en a un.
    pub fn active_version(&self) -> Option<u32> {
        self.state.lock().active.as_ref().map(|m| m.version)
    }

    /// Compte les destinations jamais vues par `host` et les mémorise.
    pub fn new_destinations<'a>(&self, host: &str, dsts: impl Iterator<Item = &'a str>) -> usize {
        let mut st = self.state.lock();
        let seen = st.seen.entry(host.to_string()).or_default();
        let mut new = 0;
        for d in dsts {
            if seen.set.insert(d.to_string()) {
                new += 1;
                seen.order.push_back(d.to_string());
                if seen.order.len() > MAX_SEEN_PER_HOST
                    && let Some(old) = seen.order.pop_front()
                {
                    seen.set.remove(&old);
                }
            }
        }
        // Sur un réseau stable, rien de nouveau : state.json n'a pas à être réécrit.
        if new > 0 {
            st.meta_dirty = true;
        }
        new
    }

    /// Enregistre la fenêtre d'une machine et la juge avec le modèle actif.
    pub fn record_window(&self, host: &str, start: f64, end: f64, features: Features) -> WindowVerdict {
        let mut st = self.state.lock();
        let (status, verdict) = match &st.active {
            None => (SampleStatus::Normal, WindowVerdict::Learning),
            Some(m) => {
                let score = m.score(&features);
                if score < m.threshold {
                    (SampleStatus::Normal, WindowVerdict::Normal)
                } else {
                    let deviations = explain(&features, m.profile_for(host), m.knows_host(host));
                    // Exception : les deux principaux écarts sont déjà tolérés pour cette machine.
                    let main: Vec<usize> = deviations.iter().take(2).map(|d| d.index).collect();
                    let excepted = st.exceptions.iter().any(|e| e.host == host && main.iter().all(|i| e.features.contains(i)));
                    if excepted {
                        (SampleStatus::Normal, WindowVerdict::Excepted)
                    } else {
                        (SampleStatus::Flagged, WindowVerdict::Anomaly(AnomalyInfo { score, threshold: m.threshold, version: m.version, deviations }))
                    }
                }
            }
        };
        let sample = Sample { host: host.to_string(), start, end, features, status };
        st.pending.push(SampleEvent::Add(sample.clone()));
        st.samples.push_back(sample);
        enforce_retention(&mut st.samples, &self.cfg);
        verdict
    }

    /// Applique la réponse de l'utilisateur aux fenêtres signalées de `host` commençant dans
    /// [`from`, `to`]. Renvoie le nombre de fenêtres mises à jour.
    #[allow(clippy::too_many_arguments)]
    pub fn feedback(&self, host: &str, from: f64, to: f64, verdict: FeedbackVerdict, scope: FeedbackScope, reason: &str, feature_ids: &[usize], now: DateTime<Utc>) -> Result<usize> {
        let mut guard = self.state.lock();
        // Accès direct aux champs : `samples` et `pending` sont modifiés dans la même boucle.
        let st = &mut *guard;
        let status = match verdict {
            FeedbackVerdict::Normal => SampleStatus::ConfirmedNormal,
            FeedbackVerdict::Suspect => SampleStatus::Suspicious,
        };
        let mut n = 0;
        for s in st.samples.iter_mut().filter(|s| s.host == host && s.status == SampleStatus::Flagged && s.start >= from - 0.5 && s.start <= to + 0.5) {
            s.status = status;
            st.pending.push(SampleEvent::Status { host: s.host.clone(), start: s.start, status });
            n += 1;
        }
        if n == 0 {
            bail!("aucune fenêtre en attente de réponse pour cette alerte (déjà répondue, ou plus conservée)");
        }
        if verdict == FeedbackVerdict::Normal && scope == FeedbackScope::Always && !feature_ids.is_empty() {
            st.exceptions.push(Exception {
                host: host.to_string(),
                features: feature_ids.to_vec(),
                labels: feature_ids.iter().filter_map(|&i| features::NAMES.get(i)).map(|s| s.to_string()).collect(),
                reason: reason.to_string(),
                created: now,
            });
        }
        let detail = format!(
            "{n} fenêtre(s) marquée(s) {}{}",
            if verdict == FeedbackVerdict::Normal { "normales" } else { "suspectes" },
            if verdict == FeedbackVerdict::Normal && scope == FeedbackScope::Always { ", exception créée" } else { "" }
        );
        self.log(st, now, "feedback", Some(host), detail, Some(reason));
        Ok(n)
    }

    /// Vrai si un apprentissage automatique doit être lancé maintenant.
    pub fn should_train(&self, now: DateTime<Utc>) -> bool {
        let st = self.state.lock();
        if st.candidate.is_some() || st.training {
            return false; // on attend la réponse de l'utilisateur, ou la fin du calcul en cours
        }
        match &st.active {
            Some(m) => (now - m.trained_at).num_seconds() as f64 >= self.cfg.retrain_interval_hours * 3600.0,
            None => {
                let usable = st.samples.iter().filter(|s| s.status.learnable()).count();
                usable >= self.cfg.min_training_samples && covered_hours(&st.samples) >= self.cfg.learning_hours
            }
        }
    }

    /// Entraîne un candidat sur les échantillons validés, sauf ceux que `tainted` désigne
    /// (fenêtres touchées par une alerte à règles), et calcule son diff.
    ///
    /// Trois temps : copie des données sous verrou (quelques millisecondes), calcul hors
    /// verrou (une seconde ou plus sur 200 000 fenêtres), puis publication sous verrou.
    pub fn train(&self, tainted: &dyn Fn(&Sample) -> bool, now: DateTime<Utc>) -> Result<TrainOutcome> {
        let (training, active, first_profile, version) = {
            let mut st = self.state.lock();
            if let Some(c) = &st.candidate {
                bail!("le modèle candidat v{} attend déjà votre validation", c.model.version);
            }
            if st.training {
                bail!("un apprentissage est déjà en cours");
            }
            let training: Vec<Sample> = st.samples.iter().filter(|s| s.status.learnable() && !tainted(s)).cloned().collect();
            if training.len() < self.cfg.min_training_samples {
                bail!("{} échantillon(s) utilisable(s), {} nécessaire(s) pour apprendre", training.len(), self.cfg.min_training_samples);
            }
            st.training = true;
            (training, st.active.clone(), st.first_profile.clone(), st.next_version.max(1))
        };
        // Déclaré avant le verrou de publication : détruit après lui.
        let _busy = TrainingFlag(&self.state);

        let refs: Vec<&Sample> = training.iter().collect();
        let model = Model::train(&refs, &self.cfg, version, now);
        let diff = diff::compute(active.as_ref(), &model, &refs, first_profile.as_ref(), self.cfg.drift_factor, self.cfg.contamination);
        let keys = training.into_iter().map(|s| (s.host, s.start)).collect();

        let mut st = self.state.lock();
        // Ne devrait pas arriver (retour arrière et validation sont refusés pendant le calcul),
        // mais un diff calculé contre un autre modèle actif serait trompeur.
        if st.active.as_ref().map(|m| m.version) != active.as_ref().map(|m| m.version) {
            bail!("le modèle actif a changé pendant l'apprentissage : relancez-le");
        }
        if st.active.is_some() && diff.is_empty() {
            self.activate(&mut st, model, now);
            self.log(&mut st, now, "activation_auto", None, format!("modèle v{version} activé : aucun nouveau comportement à valider"), None);
            return Ok(TrainOutcome::AutoActivated { version });
        }
        let outcome = TrainOutcome::PendingReview { version, hosts: diff.hosts.len(), drift_hosts: diff.drift_hosts() };
        st.candidate = Some(Candidate { model, diff, training: keys });
        Ok(outcome)
    }

    /// Valide le candidat : chaque machine du diff doit être acceptée ou refusée. Les
    /// fenêtres nouvellement acceptées des machines refusées deviennent suspectes ; le modèle
    /// est alors réentraîné sans elles, puis activé.
    ///
    /// Le réapprentissage éventuel se fait hors verrou, comme dans [`Baseline::train`].
    pub fn decide(&self, accepted: &[String], rejected: &[String], now: DateTime<Utc>) -> Result<DecisionOutcome> {
        let mut guard = self.state.lock();
        if guard.training {
            bail!("un apprentissage est en cours : réessayez dans quelques secondes");
        }
        let cand = guard.candidate.as_ref().ok_or_else(|| anyhow!("aucun modèle candidat en attente"))?;
        for h in &cand.diff.hosts {
            match (accepted.contains(&h.host), rejected.contains(&h.host)) {
                (true, true) => bail!("{} est à la fois acceptée et refusée", h.host),
                (false, false) => bail!("aucune décision pour {} : chaque machine du diff doit être acceptée ou refusée", h.host),
                _ => {}
            }
        }
        let cand = guard.candidate.take().expect("vérifié ci-dessus");
        let st = &mut *guard;

        // Fenêtres à exclure : celles que le candidat accepterait pour les machines refusées.
        let excluded = Windows::new(
            cand.diff
                .hosts
                .iter()
                .filter(|h| rejected.contains(&h.host))
                .flat_map(|h| h.accepted_starts.iter().map(move |&t| (h.host.as_str(), t))),
        );
        for s in st.samples.iter_mut().filter(|s| excluded.contains(s)) {
            s.status = SampleStatus::Suspicious;
            st.pending.push(SampleEvent::Status { host: s.host.clone(), start: s.start, status: s.status });
        }

        for h in &cand.diff.hosts {
            let ok = accepted.contains(&h.host);
            let detail = format!("modèle v{} : {} ({} fenêtre(s))", cand.model.version, if ok { "comportement accepté" } else { "comportement refusé" }, h.newly_accepted);
            self.log(st, now, "validation", Some(&h.host), detail, None);
        }
        let outcome = |activated| Ok(DecisionOutcome { activated, rejected: rejected.to_vec() });

        let version = cand.model.version;
        if excluded.is_empty() {
            self.activate(st, cand.model, now);
            return outcome(Some(version));
        }
        // Réapprentissage sans les fenêtres refusées, avec le même numéro de version.
        let keys = Windows::new(cand.training.iter().map(|(h, t)| (h.as_str(), *t)));
        let training: Vec<Sample> = st.samples.iter().filter(|s| s.status.learnable() && keys.contains(s)).cloned().collect();
        if training.len() < self.cfg.min_training_samples {
            return outcome(None);
        }
        st.training = true;
        drop(guard);
        let _busy = TrainingFlag(&self.state);

        let refs: Vec<&Sample> = training.iter().collect();
        let m = Model::train(&refs, &self.cfg, version, now);
        let mut st = self.state.lock();
        self.activate(&mut st, m, now);
        outcome(Some(version))
    }

    /// Revient à une version validée précédente. Le candidat éventuel est abandonné : son diff
    /// avait été calculé par rapport à l'ancien modèle actif.
    pub fn rollback(&self, version: u32, now: DateTime<Utc>) -> Result<()> {
        let mut st = self.state.lock();
        if st.training {
            bail!("un apprentissage est en cours : réessayez dans quelques secondes");
        }
        let model = match st.versions.get(&version) {
            Some(m) => m.clone(),
            None => self.storage.as_ref().ok_or_else(|| anyhow!("version v{version} inconnue"))?.load_model(version)?,
        };
        st.candidate = None;
        st.active_version = Some(version);
        st.active = Some(model);
        self.log(&mut st, now, "rollback", None, format!("retour au modèle v{version}"), None);
        Ok(())
    }

    /// État complet pour l'API et le dashboard.
    pub fn status(&self) -> Status {
        let st = self.state.lock();
        let count = |status| st.samples.iter().filter(|s| s.status == status).count();
        let mut versions: Vec<u32> = st.versions.keys().copied().collect();
        if let Some(s) = &self.storage {
            versions.extend(s.versions());
        }
        versions.sort_unstable();
        versions.dedup();
        Status {
            enabled: true,
            mode: self.cfg.mode,
            persistent: self.storage.is_some(),
            window_secs: self.cfg.window_secs,
            samples: SampleCounts {
                normal: count(SampleStatus::Normal),
                flagged: count(SampleStatus::Flagged),
                confirmed_normal: count(SampleStatus::ConfirmedNormal),
                suspicious: count(SampleStatus::Suspicious),
            },
            learning: Learning {
                required_samples: self.cfg.min_training_samples,
                required_hours: self.cfg.learning_hours,
                covered_hours: covered_hours(&st.samples),
            },
            active: st.active.as_ref().map(ModelInfo::from),
            candidate: st.candidate.as_ref().map(|c| CandidateInfo { model: ModelInfo::from(&c.model), diff: c.diff.clone() }),
            versions,
            exceptions: st.exceptions.clone(),
            decisions: st.decisions.iter().rev().cloned().collect(),
        }
    }

    /// Écrit sur disque ce qui a changé depuis la dernière sauvegarde (sans effet en mode
    /// mémoire) : les nouvelles lignes du journal des échantillons, et `state.json` s'il a
    /// changé. Le journal est réécrit en entier seulement quand il devient trop long.
    pub fn save(&self) -> Result<()> {
        let Some(storage) = &self.storage else { return Ok(()) };
        let _one = self.saving.lock();
        let work = self.prepare_save()?;
        let written = (|| {
            if let Some(meta) = &work.meta {
                storage.save_state(meta)?;
            }
            if work.rewrite {
                storage.rewrite_samples(&work.events)
            } else {
                storage.append_samples(&work.events)
            }
        })();
        if written.is_err() {
            // Les modifications retirées de `pending` seraient perdues : tout réécrire la prochaine fois.
            let mut st = self.state.lock();
            st.compact = true;
            st.meta_dirty = true;
        }
        written
    }

    /// Prépare une sauvegarde sous verrou, sans rien écrire : retire les modifications en
    /// attente, ou copie tous les échantillons si le journal doit être compacté.
    fn prepare_save(&self) -> Result<SaveWork> {
        let mut st = self.state.lock();
        let meta = if st.meta_dirty { Some(serde_json::to_vec(&*st)?) } else { None };
        st.meta_dirty = false;
        let rewrite = needs_compaction(st.compact, st.journal_lines + st.pending.len(), st.samples.len());
        let events = if rewrite {
            // La copie couvre aussi les modifications en attente : elles sont abandonnées.
            st.pending.clear();
            st.compact = false;
            st.journal_lines = st.samples.len();
            st.samples.iter().cloned().map(SampleEvent::Add).collect()
        } else {
            st.journal_lines += st.pending.len();
            std::mem::take(&mut st.pending)
        };
        Ok(SaveWork { meta, events, rewrite })
    }

    /// Active un modèle : il devient la référence, est enregistré, et les exceptions (qu'il a
    /// désormais apprises) sont effacées. Le premier modèle fixe la référence de dérive.
    fn activate(&self, st: &mut State, model: Model, now: DateTime<Utc>) {
        let v = model.version;
        if let Some(s) = &self.storage {
            if let Err(e) = s.save_model(&model) {
                tracing::error!("enregistrement du modèle v{v} : {e:#}");
            }
            s.prune_models(self.cfg.max_versions, v);
        }
        if st.first_profile.is_none() {
            st.first_profile = Some(model.hosts.clone());
        }
        st.versions.insert(v, model.clone());
        while st.versions.len() > self.cfg.max_versions {
            st.versions.pop_first();
        }
        st.exceptions.clear();
        st.active_version = Some(v);
        st.active = Some(model);
        st.next_version = v + 1;
        st.meta_dirty = true;
        tracing::info!("modèle de comportement normal v{v} activé ({})", now.format("%Y-%m-%d %H:%M"));
    }

    /// Ajoute une entrée au journal (mémoire + disque).
    fn log(&self, st: &mut State, at: DateTime<Utc>, kind: &str, host: Option<&str>, detail: String, reason: Option<&str>) {
        let d = Decision { at, kind: kind.into(), host: host.map(str::to_string), detail, reason: reason.map(str::to_string) };
        if let Some(s) = &self.storage
            && let Err(e) = s.append_decision(&d)
        {
            tracing::error!("journal des décisions : {e:#}");
        }
        st.decisions.push_back(d);
        while st.decisions.len() > MAX_RECENT_DECISIONS {
            st.decisions.pop_front();
        }
        st.meta_dirty = true;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::anomaly::{model::tests::sample, storage::tests::temp_dir};

    const A: &str = "10.0.0.1";
    const B: &str = "10.0.0.2";

    fn cfg() -> AnomalyConfig {
        AnomalyConfig { min_training_samples: 100, ..Default::default() }
    }

    fn never(_: &Sample) -> bool {
        false
    }

    /// Enregistre `n` fenêtres régulières pour A et B à partir de l'indice `from`.
    fn feed(b: &Baseline, from: usize, n: usize, level: f64) {
        for i in from..from + n {
            for h in [A, B] {
                let s = sample(h, i, level);
                b.record_window(h, s.start, s.end, s.features);
            }
        }
    }

    /// Baseline avec un premier modèle validé (v1) sur 200 fenêtres régulières par machine.
    fn trained() -> Baseline {
        let b = Baseline::in_memory(cfg());
        feed(&b, 0, 200, 2.0);
        b.train(&never, Utc::now()).unwrap();
        b.decide(&[A.into(), B.into()], &[], Utc::now()).unwrap();
        b
    }

    // Le premier modèle n'est jamais activé sans validation, même si tout semble normal.
    #[test]
    fn first_model_requires_review() {
        let b = Baseline::in_memory(cfg());
        feed(&b, 0, 200, 2.0);
        assert_eq!(b.record_window(A, 0.0, 1.0, [2.0; features::N]), WindowVerdict::Learning);
        match b.train(&never, Utc::now()).unwrap() {
            TrainOutcome::PendingReview { hosts, .. } => assert_eq!(hosts, 2),
            o => panic!("{o:?}"),
        }
        assert_eq!(b.active_version(), None);
        // Un second apprentissage est refusé tant que le candidat attend.
        assert!(b.train(&never, Utc::now()).is_err());
        // Une décision incomplète est refusée.
        assert!(b.decide(&[A.into()], &[], Utc::now()).is_err());
        assert_eq!(b.decide(&[A.into(), B.into()], &[], Utc::now()).unwrap().activated, Some(1));
        assert_eq!(b.active_version(), Some(1));
    }

    // Pas assez de données : l'apprentissage est refusé avec un message explicite.
    #[test]
    fn not_enough_samples() {
        let b = Baseline::in_memory(cfg());
        feed(&b, 0, 10, 2.0);
        assert!(b.train(&never, Utc::now()).unwrap_err().to_string().contains("nécessaire"));
    }

    // Avec un modèle actif, une fenêtre habituelle est normale et une fenêtre très différente
    // est signalée, expliquée, et exclue de l'apprentissage tant qu'elle est sans réponse.
    #[test]
    fn anomaly_is_flagged_and_explained() {
        let b = trained();
        let s = sample(A, 500, 2.0);
        assert_eq!(b.record_window(A, s.start, s.end, s.features), WindowVerdict::Normal);
        let mut odd = [2.0; features::N];
        odd[0] = 9.0;
        match b.record_window(A, 1e6, 1e6 + 300.0, odd) {
            WindowVerdict::Anomaly(info) => {
                assert_eq!(info.version, 1);
                assert_eq!(info.deviations[0].index, 0);
            }
            v => panic!("{v:?}"),
        }
        assert_eq!(b.status().samples.flagged, 1);
    }

    // « Normal, désormais » : les fenêtres deviennent apprenables et une exception évite de
    // reposer la question pour le même type d'écart sur la même machine (pas sur une autre).
    #[test]
    fn feedback_always_creates_exception() {
        let b = trained();
        let mut odd = [2.0; features::N];
        odd[0] = 9.0;
        let WindowVerdict::Anomaly(info) = b.record_window(A, 1e6, 1e6 + 300.0, odd) else { panic!() };
        let ids: Vec<usize> = info.deviations.iter().map(|d| d.index).collect();
        assert_eq!(b.feedback(A, 1e6, 1e6, FeedbackVerdict::Normal, FeedbackScope::Always, "sauvegarde", &ids, Utc::now()).unwrap(), 1);
        assert_eq!(b.status().samples.confirmed_normal, 1);
        assert_eq!(b.record_window(A, 2e6, 2e6 + 300.0, odd), WindowVerdict::Excepted);
        assert!(matches!(b.record_window(B, 2e6, 2e6 + 300.0, odd), WindowVerdict::Anomaly(_)));
        // Répondre deux fois à la même alerte est refusé.
        assert!(b.feedback(A, 1e6, 1e6, FeedbackVerdict::Normal, FeedbackScope::Once, "", &[], Utc::now()).is_err());
    }

    // « Suspect » : la fenêtre ne sera jamais apprise.
    #[test]
    fn feedback_suspect_excludes() {
        let b = trained();
        let mut odd = [2.0; features::N];
        odd[3] = 9.0;
        b.record_window(A, 1e6, 1e6 + 300.0, odd);
        b.feedback(A, 1e6, 1e6, FeedbackVerdict::Suspect, FeedbackScope::Once, "", &[], Utc::now()).unwrap();
        assert_eq!(b.status().samples.suspicious, 1);
    }

    // Rien de nouveau entre deux apprentissages : activation automatique, sans question.
    #[test]
    fn empty_diff_auto_activates() {
        let b = trained();
        assert!(matches!(b.train(&never, Utc::now()).unwrap(), TrainOutcome::AutoActivated { version: 2 }));
        assert_eq!(b.active_version(), Some(2));
    }

    // Une machine change de comportement : elle apparaît dans le diff. Refusée, ses nouvelles
    // fenêtres deviennent suspectes et le modèle activé ne les a pas apprises.
    #[test]
    fn rejected_host_is_excluded() {
        let b = trained();
        // A garde son activité ; B passe à une activité nettement plus forte.
        for i in 200..400 {
            let a = sample(A, i, 2.0);
            b.record_window(A, a.start, a.end, a.features);
        }
        for i in 200..260 {
            let s = sample(B, i, 6.0);
            b.record_window(B, s.start, s.end, s.features);
        }
        // Ces fenêtres ont été signalées : l'utilisateur répond qu'elles sont normales…
        b.feedback(B, 0.0, 1e9, FeedbackVerdict::Normal, FeedbackScope::Once, "nouvel usage", &[], Utc::now()).unwrap();
        // …le diff les présente donc, et c'est à la validation qu'on les refuse finalement.
        match b.train(&never, Utc::now()).unwrap() {
            TrainOutcome::PendingReview { .. } => {}
            o => panic!("{o:?}"),
        }
        let diff = b.status().candidate.unwrap().diff;
        let hosts: Vec<&str> = diff.hosts.iter().map(|h| h.host.as_str()).collect();
        assert!(hosts.contains(&B), "{hosts:?}");
        let accepted: Vec<String> = hosts.iter().filter(|h| **h != B).map(|h| h.to_string()).collect();
        let out = b.decide(&accepted, &[B.into()], Utc::now()).unwrap();
        assert_eq!(out.activated, Some(2));
        assert!(b.status().samples.suspicious > 0);
        // Le comportement refusé reste anormal pour le nouveau modèle.
        let s = sample(B, 999, 6.0);
        assert!(matches!(b.record_window(B, 1e7, 1e7 + 300.0, s.features), WindowVerdict::Anomaly(_)));
    }

    // Les fenêtres touchées par une alerte à règles ne sont pas apprises.
    #[test]
    fn tainted_samples_are_not_learned() {
        let b = Baseline::in_memory(cfg());
        feed(&b, 0, 200, 2.0);
        let only_a = |s: &Sample| s.host == B;
        b.train(&only_a, Utc::now()).unwrap();
        let diff = b.status().candidate.unwrap().diff;
        assert_eq!(diff.hosts.len(), 1);
        assert_eq!(diff.hosts[0].host, A);
    }

    // Retour à une version précédente.
    #[test]
    fn rollback_restores_version() {
        let b = trained();
        b.train(&never, Utc::now()).unwrap();
        assert_eq!(b.active_version(), Some(2));
        b.rollback(1, Utc::now()).unwrap();
        assert_eq!(b.active_version(), Some(1));
        assert!(b.rollback(42, Utc::now()).is_err());
        assert!(b.status().decisions.iter().any(|d| d.kind == "rollback"));
    }

    // Une machine sans profil propre est comparée au réseau, et l'explication le dit.
    #[test]
    fn unknown_host_explanation_names_the_network() {
        let b = trained();
        let mut odd = [2.0; features::N];
        odd[0] = 9.0;
        let WindowVerdict::Anomaly(info) = b.record_window("10.0.0.99", 1e6, 1e6 + 300.0, odd) else { panic!() };
        assert!(info.deviations[0].reference.starts_with("médiane du réseau"), "{}", info.deviations[0].reference);
        let WindowVerdict::Anomaly(info) = b.record_window(A, 2e6, 2e6 + 300.0, odd) else { panic!() };
        assert!(info.deviations[0].reference.starts_with("habituellement"));
    }

    // Destinations : seules les nouvelles sont comptées, et la mémoire est plafonnée.
    #[test]
    fn new_destinations_are_counted_once() {
        let b = Baseline::in_memory(cfg());
        assert_eq!(b.new_destinations(A, ["1.1.1.1", "8.8.8.8"].into_iter()), 2);
        assert_eq!(b.new_destinations(A, ["1.1.1.1", "9.9.9.9"].into_iter()), 1);
        let many: Vec<String> = (0..3000).map(|i| format!("10.1.{}.{}", i / 256, i % 256)).collect();
        b.new_destinations(B, many.iter().map(String::as_str));
        assert_eq!(b.state.lock().seen[B].order.len(), MAX_SEEN_PER_HOST);
    }

    // Persistance : échantillons, modèle actif, exceptions et destinations vues survivent à un redémarrage.
    #[test]
    fn state_survives_restart() {
        let dir = temp_dir("baseline");
        let c = AnomalyConfig { data_dir: dir.display().to_string(), ..cfg() };
        let b = Baseline::open(c.clone()).unwrap();
        feed(&b, 0, 200, 2.0);
        b.new_destinations(A, ["1.1.1.1"].into_iter());
        b.train(&never, Utc::now()).unwrap();
        b.decide(&[A.into(), B.into()], &[], Utc::now()).unwrap();
        b.save().unwrap();

        let r = Baseline::open(c).unwrap();
        assert_eq!(r.active_version(), Some(1));
        assert_eq!(r.status().samples.normal, 400);
        assert_eq!(r.new_destinations(A, ["1.1.1.1"].into_iter()), 0);
        assert!(dir.join("decisions.jsonl").exists());
    }

    /// Nombre de lignes du journal des échantillons.
    fn journal_lines(dir: &std::path::Path) -> usize {
        std::fs::read_to_string(dir.join("samples.jsonl")).unwrap().lines().count()
    }

    // La sauvegarde n'ajoute que ce qui a changé : les fenêtres nouvelles et les changements
    // de statut. Rien de nouveau : rien n'est écrit. Tout est retrouvé au redémarrage.
    #[test]
    fn save_is_incremental() {
        let dir = temp_dir("incremental");
        let c = AnomalyConfig { data_dir: dir.display().to_string(), ..cfg() };
        let b = Baseline::open(c.clone()).unwrap();
        feed(&b, 0, 200, 2.0);
        b.save().unwrap();
        assert_eq!(journal_lines(&dir), 400);
        assert!(!std::fs::read_to_string(dir.join("state.json")).map(|s| s.contains("\"samples\"")).unwrap_or(false));

        b.train(&never, Utc::now()).unwrap();
        b.decide(&[A.into(), B.into()], &[], Utc::now()).unwrap();
        let mut odd = [2.0; features::N];
        odd[0] = 9.0;
        b.record_window(A, 1e6, 1e6 + 300.0, odd);
        b.feedback(A, 1e6, 1e6, FeedbackVerdict::Suspect, FeedbackScope::Once, "", &[], Utc::now()).unwrap();
        b.save().unwrap();
        // Une fenêtre ajoutée + son changement de statut, pas 401 lignes réécrites.
        assert_eq!(journal_lines(&dir), 402);
        b.save().unwrap();
        assert_eq!(journal_lines(&dir), 402);

        let r = Baseline::open(c).unwrap();
        let counts = r.status().samples;
        assert_eq!((counts.normal, counts.suspicious, counts.flagged), (400, 1, 0));
    }

    // Compaction : le journal réécrit ne contient plus qu'une ligne par échantillon conservé,
    // avec son dernier statut.
    #[test]
    fn compaction_rewrites_current_samples() {
        let dir = temp_dir("compaction");
        let c = AnomalyConfig { data_dir: dir.display().to_string(), ..cfg() };
        let b = Baseline::open(c.clone()).unwrap();
        feed(&b, 0, 200, 2.0);
        b.train(&never, Utc::now()).unwrap();
        b.decide(&[A.into(), B.into()], &[], Utc::now()).unwrap();
        let mut odd = [2.0; features::N];
        odd[0] = 9.0;
        b.record_window(A, 1e6, 1e6 + 300.0, odd);
        b.save().unwrap();
        b.feedback(A, 1e6, 1e6, FeedbackVerdict::Suspect, FeedbackScope::Once, "", &[], Utc::now()).unwrap();
        b.state.lock().compact = true;
        b.save().unwrap();
        assert_eq!(journal_lines(&dir), 401);
        assert_eq!(Baseline::open(c).unwrap().status().samples.suspicious, 1);
    }

    // Ancien format (échantillons dans state.json) : repris au chargement, puis déplacés
    // dans le journal à la première sauvegarde.
    #[test]
    fn legacy_state_is_migrated() {
        let dir = temp_dir("legacy");
        let c = AnomalyConfig { data_dir: dir.display().to_string(), ..cfg() };
        std::fs::create_dir_all(&dir).unwrap();
        let legacy = serde_json::json!({ "samples": [sample(A, 0, 2.0), sample(A, 1, 2.0)], "next_version": 1 });
        std::fs::write(dir.join("state.json"), legacy.to_string()).unwrap();

        let b = Baseline::open(c.clone()).unwrap();
        assert_eq!(b.status().samples.normal, 2);
        b.save().unwrap();
        assert_eq!(journal_lines(&dir), 2);
        assert!(!std::fs::read_to_string(dir.join("state.json")).unwrap().contains("\"samples\""));
        assert_eq!(Baseline::open(c).unwrap().status().samples.normal, 2);
    }

    // Pendant un apprentissage (calcul hors verrou), ni second apprentissage, ni validation,
    // ni retour arrière ; la détection, elle, continue d'enregistrer des fenêtres.
    #[test]
    fn training_in_progress_blocks_concurrent_changes() {
        let b = trained();
        b.train(&never, Utc::now()).unwrap(); // v2 auto-activée
        b.state.lock().training = true;
        assert!(!b.should_train(Utc::now() + chrono::Duration::days(365)));
        assert!(b.train(&never, Utc::now()).unwrap_err().to_string().contains("en cours"));
        assert!(b.rollback(1, Utc::now()).unwrap_err().to_string().contains("en cours"));
        assert!(b.decide(&[], &[], Utc::now()).unwrap_err().to_string().contains("en cours"));
        let s = sample(A, 900, 2.0);
        assert_eq!(b.record_window(A, s.start, s.end, s.features), WindowVerdict::Normal);
        // Le drapeau est remis à zéro à la fin de l'apprentissage.
        b.state.lock().training = false;
        b.train(&never, Utc::now()).unwrap();
        assert!(!b.state.lock().training);
    }
}
