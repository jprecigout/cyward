//! Modèle de données des alertes, stockage en mémoire et point d'entrée des détecteurs.
//!
//! Toutes les alertes, qu'elles viennent du réseau ou des logs, passent par [`AlertSink::emit`],
//! qui les enregistre dans l'[`AlertStore`] et, si elles sont assez graves, les met dans la file
//! d'analyse du LLM. Le store dédoublonne les alertes répétées et diffuse chaque changement aux
//! navigateurs connectés au dashboard.

use std::{
    collections::{HashMap, VecDeque},
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
};

use chrono::{DateTime, Utc};
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use tokio::sync::{broadcast, mpsc};

/// Gravité d'une alerte. L'ordre de déclaration compte : `PartialOrd`/`Ord` dérivés permettent
/// d'écrire `severity >= Severity::Medium`, et `max` garde la plus grave.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

/// Type d'alerte. Sérialisé en snake_case (`port_scan`…) dans l'API et le dashboard.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AlertKind {
    // --- Détecteurs réseau ---
    /// Beaucoup de ports sondés sur un même hôte.
    PortScan,
    /// Un même port sondé sur beaucoup d'hôtes.
    HostSweep,
    /// Rafale de connexions vers un service d'authentification.
    BruteForce,
    /// Inondation de SYN vers une cible (déni de service).
    SynFlood,
    /// Connexions sortantes à intervalle régulier (C2).
    Beaconing,
    /// Volume sortant très supérieur à la normale de l'hôte.
    VolumeAnomaly,
    /// Nombreux sous-domaines uniques d'un même domaine.
    DnsTunneling,
    /// Nom DNS très long ou à forte entropie.
    SuspiciousDns,
    // --- Règles de logs ---
    /// Échecs d'authentification répétés.
    AuthBruteForce,
    /// Connexion réussie juste après une série d'échecs.
    AuthCompromise,
    /// sudo/su refusé ou ajout à un groupe privilégié.
    PrivilegeEscalation,
    /// Création de compte.
    AccountChange,
    /// Règle définie par l'utilisateur dans la configuration.
    CustomRule,
    // --- Apprentissage du comportement normal ---
    /// Fenêtre d'activité d'une machine jugée anormale par l'Isolation Forest.
    HostAnomaly,
    /// Un modèle candidat présente une dérive cumulée depuis le premier modèle validé.
    BaselineDrift,
    /// L'utilisateur a refusé le nouveau comportement d'une machine lors d'une validation.
    BaselineRejected,
}

impl AlertKind {
    /// Vrai pour les alertes produites par l'apprentissage du comportement normal. Les autres
    /// viennent de détecteurs à règles : une fenêtre touchée par l'une d'elles n'est jamais apprise.
    pub fn is_learning(&self) -> bool {
        matches!(self, AlertKind::HostAnomaly | AlertKind::BaselineDrift | AlertKind::BaselineRejected)
    }
}

/// Réponse de l'utilisateur à la question « est-ce normal ? » sur une anomalie.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum FeedbackVerdict {
    Normal,
    Suspect,
}

/// Portée d'une réponse « normal ».
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum FeedbackScope {
    /// Seulement les fenêtres de cette alerte.
    Once,
    /// Ces fenêtres, et une exception pour ce type d'écart sur cette machine jusqu'au prochain modèle.
    Always,
}

/// Réponse enregistrée sur une alerte d'anomalie.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Feedback {
    pub verdict: FeedbackVerdict,
    /// Motif choisi par l'utilisateur (mise à jour, sauvegarde…).
    pub reason: String,
    pub scope: FeedbackScope,
    pub at: DateTime<Utc>,
}

/// Origine de l'alerte, affichée et filtrable dans le dashboard.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AlertSource {
    Network,
    Logs,
}

/// Où en est l'analyse de l'alerte par le LLM.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TriageStatus {
    /// Pas envoyée au modèle (sévérité trop basse ou LLM désactivé).
    None,
    /// Dans la file, ou en cours d'analyse, ou en attente du retour du serveur.
    Pending,
    /// Analyse disponible dans `Alert::analysis`.
    Done,
    /// Le modèle a répondu en erreur ou de façon inexploitable.
    Failed,
}

/// Verdict produit par le modèle cyber.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Analysis {
    /// « malveillant », « suspect » ou « bénin » (en minuscules).
    pub verdict: String,
    /// Confiance du modèle entre 0 et 1.
    pub confidence: f64,
    /// Explication en quelques phrases.
    pub summary: String,
    /// Identifiants MITRE ATT&CK (ex. T1110.001).
    #[serde(default)]
    pub mitre: Vec<String>,
    /// Actions recommandées, par ordre de priorité.
    #[serde(default)]
    pub recommendations: Vec<String>,
    /// Nom du modèle qui a produit l'analyse.
    #[serde(default)]
    pub model: String,
}

/// Une alerte telle qu'exposée par l'API et affichée dans le dashboard. `Deserialize` sert à
/// la relire depuis l'historique sur disque (`history.rs`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Alert {
    /// Identifiant unique attribué par le store (0 tant que l'alerte n'est pas enregistrée).
    pub id: u64,
    pub kind: AlertKind,
    pub severity: Severity,
    pub source: AlertSource,
    pub title: String,
    pub description: String,
    /// Origine de l'activité : IP, ou nom d'utilisateur pour certaines règles de logs.
    pub src: Option<String>,
    /// Cible : IP, IP:port, domaine ou compte.
    pub dst: Option<String>,
    /// Données brutes justifiant l'alerte (ports, compteurs, ligne de log…), libres par détecteur.
    pub evidence: serde_json::Value,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
    /// Nombre d'occurrences fusionnées dans cette alerte.
    pub count: u32,
    pub triage: TriageStatus,
    pub analysis: Option<Analysis>,
    /// Réponse de l'utilisateur (alertes d'anomalie uniquement).
    pub feedback: Option<Feedback>,
    /// Clé de dédoublonnage, interne : non exposée dans l'API (l'historique la range à part).
    #[serde(skip)]
    pub fingerprint: String,
}

impl Alert {
    /// Crée une alerte minimale ; les champs optionnels se complètent avec les méthodes
    /// chaînables ci-dessous (patron « builder »).
    pub fn new(kind: AlertKind, severity: Severity, source: AlertSource, at: DateTime<Utc>, title: impl Into<String>) -> Self {
        Self {
            id: 0,
            kind,
            severity,
            source,
            title: title.into(),
            description: String::new(),
            src: None,
            dst: None,
            evidence: serde_json::Value::Null,
            first_seen: at,
            last_seen: at,
            count: 1,
            triage: TriageStatus::None,
            analysis: None,
            feedback: None,
            fingerprint: String::new(),
        }
    }

    pub fn description(mut self, d: impl Into<String>) -> Self {
        self.description = d.into();
        self
    }

    pub fn src(mut self, s: impl ToString) -> Self {
        self.src = Some(s.to_string());
        self
    }

    pub fn dst(mut self, d: impl ToString) -> Self {
        self.dst = Some(d.to_string());
        self
    }

    pub fn evidence(mut self, e: serde_json::Value) -> Self {
        self.evidence = e;
        self
    }

    /// Par défaut deux alertes sont « identiques » si elles ont le même type, la même source et la même cible.
    pub fn fingerprint(mut self, f: impl Into<String>) -> Self {
        self.fingerprint = f.into();
        self
    }

    /// Empreinte explicite si le détecteur en a fourni une, sinon `type|source|cible`.
    fn effective_fingerprint(&self) -> String {
        if self.fingerprint.is_empty() {
            format!("{:?}|{}|{}", self.kind, self.src.as_deref().unwrap_or(""), self.dst.as_deref().unwrap_or(""))
        } else {
            self.fingerprint.clone()
        }
    }
}

/// Événement diffusé au dashboard. Sérialisé en `{"type": "new" | "update", "alert": {...}}`.
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "type", content = "alert", rename_all = "lowercase")]
pub enum AlertEvent {
    New(Alert),
    Update(Alert),
}

/// Historique des alertes en mémoire, avec dé-duplication et diffusion aux clients du dashboard.
pub struct AlertStore {
    /// Données protégées par un verrou : le store est partagé entre toutes les tâches.
    inner: Mutex<StoreInner>,
    /// Prochain identifiant ; atomique pour ne pas dépendre du verrou.
    next_id: AtomicU64,
    /// Fenêtre de fusion des alertes identiques.
    cooldown: chrono::Duration,
    /// Nombre maximal d'alertes conservées ; les plus anciennes sont évincées.
    capacity: usize,
    /// Canal de diffusion : chaque client SSE du dashboard en possède un récepteur.
    events: broadcast::Sender<AlertEvent>,
}

struct StoreInner {
    /// Alertes dans l'ordre d'arrivée (la plus ancienne devant).
    alerts: VecDeque<Alert>,
    /// Dernière alerte créée pour chaque empreinte, pour retrouver un doublon sans tout parcourir.
    by_fingerprint: HashMap<String, u64>,
}

impl StoreInner {
    /// Évince les alertes les plus anciennes au-delà de `capacity`. L'index par empreinte n'est
    /// nettoyé que s'il pointe encore sur l'alerte évincée (une plus récente a pu le remplacer).
    fn evict(&mut self, capacity: usize) {
        while self.alerts.len() > capacity {
            if let Some(old) = self.alerts.pop_front()
                && self.by_fingerprint.get(&old.fingerprint) == Some(&old.id)
            {
                self.by_fingerprint.remove(&old.fingerprint);
            }
        }
    }
}

impl AlertStore {
    pub fn new(capacity: usize, cooldown_secs: u64) -> Self {
        // 256 événements en tampon par client ; un client trop lent perd les plus anciens
        // (il les récupère en rechargeant la liste).
        let (events, _) = broadcast::channel(256);
        Self {
            inner: Mutex::new(StoreInner { alerts: VecDeque::new(), by_fingerprint: HashMap::new() }),
            next_id: AtomicU64::new(1),
            cooldown: chrono::Duration::seconds(cooldown_secs as i64),
            capacity,
            events,
        }
    }

    /// Nouveau récepteur d'événements (un par client du dashboard).
    pub fn subscribe(&self) -> broadcast::Receiver<AlertEvent> {
        self.events.subscribe()
    }

    /// Enregistre une alerte. Renvoie `Some` uniquement si c'est une nouvelle alerte
    /// (et pas la répétition d'une alerte encore dans sa période de cooldown).
    pub fn push(&self, mut alert: Alert) -> Option<Alert> {
        let fp = alert.effective_fingerprint();
        let mut inner = self.inner.lock();

        // Doublon : même empreinte, alerte encore présente, et vue il y a moins de `cooldown`.
        // On met à jour l'alerte existante au lieu d'en créer une nouvelle.
        if let Some(&id) = inner.by_fingerprint.get(&fp)
            && let Some(existing) = inner.alerts.iter_mut().find(|a| a.id == id)
            && alert.first_seen - existing.last_seen < self.cooldown
        {
            existing.count += 1;
            existing.last_seen = alert.last_seen;
            existing.severity = existing.severity.max(alert.severity);
            // Les preuves les plus récentes remplacent les anciennes.
            existing.evidence = alert.evidence;
            // L'envoi échoue seulement s'il n'y a aucun client : sans importance.
            let _ = self.events.send(AlertEvent::Update(existing.clone()));
            return None;
        }

        alert.id = self.next_id.fetch_add(1, Ordering::Relaxed);
        alert.fingerprint = fp.clone();
        inner.by_fingerprint.insert(fp, alert.id);
        inner.alerts.push_back(alert.clone());
        inner.evict(self.capacity);
        // Libérer le verrou avant de journaliser et diffuser.
        drop(inner);

        tracing::warn!(id = alert.id, kind = ?alert.kind, severity = ?alert.severity, src = ?alert.src, "{}", alert.title);
        let _ = self.events.send(AlertEvent::New(alert.clone()));
        Some(alert)
    }

    /// Recharge des alertes enregistrées (historique sur disque), avant que les détecteurs ne
    /// démarrent et sans rien diffuser. `alerts` est dans l'ordre chronologique ; `next_id` est le
    /// prochain identifiant d'après l'historique, pour qu'un identifiant ne soit jamais réutilisé.
    /// Les répétitions d'une alerte rechargée lui sont fusionnées comme si l'agent n'avait pas redémarré.
    pub fn restore(&self, alerts: Vec<Alert>, next_id: u64) {
        let mut inner = self.inner.lock();
        for mut a in alerts {
            // La file du LLM était en mémoire : une analyse interrompue par l'arrêt ne reprendra pas.
            if a.triage == TriageStatus::Pending {
                a.triage = TriageStatus::None;
            }
            inner.by_fingerprint.insert(a.fingerprint.clone(), a.id);
            inner.alerts.push_back(a);
        }
        inner.evict(self.capacity);
        self.next_id.fetch_max(next_id, Ordering::Relaxed);
    }

    /// Modifie une alerte existante (statut de triage, analyse…) et diffuse la mise à jour.
    /// Sans effet si l'alerte a déjà été évincée.
    pub fn update(&self, id: u64, f: impl FnOnce(&mut Alert)) {
        let mut inner = self.inner.lock();
        if let Some(a) = inner.alerts.iter_mut().find(|a| a.id == id) {
            f(a);
            let _ = self.events.send(AlertEvent::Update(a.clone()));
        }
    }

    pub fn get(&self, id: u64) -> Option<Alert> {
        self.inner.lock().alerts.iter().find(|a| a.id == id).cloned()
    }

    /// Alertes les plus récentes d'abord.
    pub fn list(&self, limit: usize) -> Vec<Alert> {
        self.inner.lock().alerts.iter().rev().take(limit).cloned().collect()
    }

    /// Nombre d'alertes par sévérité (pour `/api/stats`).
    pub fn counts(&self) -> HashMap<Severity, usize> {
        let mut m = HashMap::new();
        for a in self.inner.lock().alerts.iter() {
            *m.entry(a.severity).or_default() += 1;
        }
        m
    }
}

/// Point d'entrée unique des détecteurs : enregistre l'alerte et l'envoie au triage LLM si elle le mérite.
// `Clone` est bon marché : il ne copie que des pointeurs partagés (Arc, émetteur de canal).
#[derive(Clone)]
pub struct AlertSink {
    pub store: Arc<AlertStore>,
    /// Émetteur vers la file du LLM (identifiants d'alertes) ; None si le LLM est désactivé.
    triage: Option<mpsc::Sender<u64>>,
    min_severity: Severity,
}

impl AlertSink {
    pub fn new(store: Arc<AlertStore>, triage: Option<mpsc::Sender<u64>>, min_severity: Severity) -> Self {
        Self { store, triage, min_severity }
    }

    pub fn emit(&self, alert: Alert) {
        // Une répétition fusionnée (None) n'est pas ré-analysée : seul le premier exemplaire l'est.
        let Some(new) = self.store.push(alert) else { return };
        if let Some(tx) = &self.triage
            && new.severity >= self.min_severity
        {
            self.store.update(new.id, |a| a.triage = TriageStatus::Pending);
            // `try_send` ne bloque jamais la détection : si la file est pleine, on renonce à l'analyse.
            if tx.try_send(new.id).is_err() {
                tracing::warn!(id = new.id, "file d'analyse LLM pleine, alerte non analysée");
                self.store.update(new.id, |a| a.triage = TriageStatus::None);
            }
        }
    }
}

/// Retire le port d'une adresse « hôte:port » telle que les détecteurs l'écrivent dans
/// `src`/`dst` (« 10.0.0.1:22 » → « 10.0.0.1 »). Les IPv6, à plusieurs « : », sont laissées
/// intactes. Sert partout où l'on regroupe des alertes par machine (contexte du LLM,
/// fenêtres exclues de l'apprentissage) : une seule définition, pour un regroupement identique.
pub fn host_part(s: &str) -> &str {
    if s.matches(':').count() == 1 { s.split(':').next().unwrap_or(s) } else { s }
}

/// Formate un nombre d'octets en unité lisible (o, Ko, Mo…), en base 1024, pour les textes d'alerte.
pub fn human_bytes(b: f64) -> String {
    const UNITS: [&str; 5] = ["o", "Ko", "Mo", "Go", "To"];
    let mut v = b;
    let mut i = 0;
    while v >= 1024.0 && i < UNITS.len() - 1 {
        v /= 1024.0;
        i += 1;
    }
    format!("{v:.1} {}", UNITS[i])
}

#[cfg(test)]
mod tests {
    use super::*;

    // Deux alertes identiques rapprochées n'en font qu'une, avec un compteur à 2.
    #[test]
    fn duplicate_within_cooldown_is_merged() {
        let store = AlertStore::new(10, 300);
        let t = Utc::now();
        let a = || Alert::new(AlertKind::PortScan, Severity::Medium, AlertSource::Network, t, "scan").src("10.0.0.5");
        assert!(store.push(a()).is_some());
        assert!(store.push(a()).is_none());
        let list = store.list(10);
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].count, 2);
    }

    // Passé le cooldown, la même activité redevient une nouvelle alerte.
    #[test]
    fn duplicate_after_cooldown_is_new() {
        let store = AlertStore::new(10, 60);
        let t = Utc::now();
        let mk = |at| Alert::new(AlertKind::PortScan, Severity::Medium, AlertSource::Network, at, "scan").src("10.0.0.5");
        assert!(store.push(mk(t)).is_some());
        assert!(store.push(mk(t + chrono::Duration::seconds(120))).is_some());
        assert_eq!(store.list(10).len(), 2);
    }

    // Alertes rechargées : identifiants poursuivis, analyse interrompue remise à « non analysée »,
    // capacité respectée, et une répétition fusionnée à l'alerte rechargée.
    #[test]
    fn restore_continues_ids_and_merges_repeats() {
        let store = AlertStore::new(2, 300);
        let t = Utc::now();
        let mk = |id, src: &str| {
            let mut a = Alert::new(AlertKind::PortScan, Severity::Medium, AlertSource::Network, t, "scan").src(src);
            a.id = id;
            a.fingerprint = a.effective_fingerprint();
            a.triage = TriageStatus::Pending;
            a
        };
        store.restore(vec![mk(3, "10.0.0.1"), mk(5, "10.0.0.2"), mk(8, "10.0.0.3")], 12);
        let list = store.list(10);
        assert_eq!(list.iter().map(|a| a.id).collect::<Vec<_>>(), vec![8, 5]);
        assert!(list.iter().all(|a| a.triage == TriageStatus::None));

        let repeat = Alert::new(AlertKind::PortScan, Severity::High, AlertSource::Network, t, "scan").src("10.0.0.3");
        assert!(store.push(repeat).is_none());
        assert_eq!(store.get(8).unwrap().count, 2);
        let fresh = Alert::new(AlertKind::PortScan, Severity::Medium, AlertSource::Network, t, "scan").src("10.0.0.9");
        assert_eq!(store.push(fresh).unwrap().id, 12);
    }

    // Sans historique, rien ne change : les identifiants commencent à 1.
    #[test]
    fn restore_empty_keeps_first_id() {
        let store = AlertStore::new(10, 300);
        store.restore(Vec::new(), 1);
        let a = Alert::new(AlertKind::PortScan, Severity::Medium, AlertSource::Network, Utc::now(), "scan");
        assert_eq!(store.push(a).unwrap().id, 1);
    }

    // Le port est retiré des adresses IPv4, jamais d'une IPv6.
    #[test]
    fn host_part_strips_port_only_for_ipv4() {
        assert_eq!(host_part("10.0.0.1:22"), "10.0.0.1");
        assert_eq!(host_part("10.0.0.1"), "10.0.0.1");
        assert_eq!(host_part("fe80::1"), "fe80::1");
    }

    // Les octets sont affichés dans l'unité qui convient, en base 1024.
    #[test]
    fn human_bytes_picks_unit() {
        assert_eq!(human_bytes(512.0), "512.0 o");
        assert_eq!(human_bytes(1536.0), "1.5 Ko");
        assert_eq!(human_bytes(85.0 * 1024.0 * 1024.0), "85.0 Mo");
    }
}
