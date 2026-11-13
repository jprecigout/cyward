//! Modèle de données des alertes : types, gravité, constructeur et utilitaires de texte.
//!
//! Toutes les alertes, qu'elles viennent du réseau ou des logs, passent par [`AlertSink::emit`]
//! (`alert/sink.rs`), qui les enregistre dans l'[`AlertStore`] (`alert/store.rs`) et, si elles
//! sont assez graves, les met dans la file d'analyse du LLM. Le store dédoublonne les alertes
//! répétées et diffuse chaque changement à ses abonnés. Les deux sont réexportés ici : le reste
//! du code les importe depuis `crate::alert`, sans connaître ce découpage.

mod sink;
mod store;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

pub use self::{
    sink::AlertSink,
    store::{AlertEvent, AlertStore},
};

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
    /// Trafic avec une IP présente dans une liste de menaces.
    ThreatListMatch,
    /// Deux adresses MAC annoncées en même temps pour une même IP (usurpation ARP).
    ArpSpoofing,
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
