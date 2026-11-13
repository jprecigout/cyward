//! Notifications des attaques jugées malveillantes ou suspectes (ntfy, webhook).
//!
//! Consommateur des alertes, au même titre que le dashboard : il s'abonne aux événements de
//! l'[`AlertStore`] (Observer), sans que les détecteurs ni le LLM ne le connaissent.
//!
//! ```text
//! AlertStore ──broadcast──► watch : Dispatcher (décision) ──mpsc──► deliver : canaux (HTTP)
//! ```
//!
//! Une alerte est notifiée **une seule fois**, dès que l'une de ces conditions est remplie :
//! - le verdict de l'IA est dans `notify.verdicts` (malveillant, suspect) avec une confiance
//!   d'au moins `notify.min_confidence` ;
//! - sa sévérité atteint `notify.immediate_severity` : on n'attend pas le modèle, qui peut
//!   mettre plusieurs minutes ;
//! - repli : elle est assez grave (`notify.fallback_severity`) mais n'a toujours pas de verdict
//!   après `notify.fallback_after_secs` (IA hors ligne), ou n'en aura jamais (analyse en échec,
//!   IA désactivée, file d'analyse pleine) : dans ce cas, sans attendre le délai.
//!
//! Au-delà de `notify.max_per_hour` notifications par heure, les suivantes sont comptées puis
//! résumées en une seule dès que le plafond le permet. La décision ([`Dispatcher`]) est pure et
//! se teste sans réseau ; l'envoi tourne dans sa propre tâche, derrière une file bornée, pour
//! qu'un service de notification lent ou en panne ne retarde jamais rien d'autre.

pub mod channels;

use std::{
    collections::{HashMap, HashSet, VecDeque},
    sync::Arc,
    time::{Duration, Instant},
};

use anyhow::{Result, bail};
use reqwest::Client;
use serde::Serialize;
use tokio::sync::{broadcast, mpsc};

use crate::{
    alert::{Alert, AlertEvent, AlertStore, Severity, TriageStatus},
    config::NotifyConfig,
};
use channels::Notifier;

/// Fenêtre du plafond de notifications.
const RATE_WINDOW: Duration = Duration::from_secs(3600);
/// Période de vérification des alertes en attente de verdict et du résumé, en secondes.
const TICK: Duration = Duration::from_secs(15);
/// Taille de la file entre la décision et l'envoi.
const QUEUE: usize = 64;
/// Délai maximal d'un envoi HTTP.
const SEND_TIMEOUT: Duration = Duration::from_secs(10);
/// Nombre d'essais d'un envoi, espacés de 2 s puis 4 s.
const ATTEMPTS: u32 = 3;
/// Nombre d'alertes suivies (déjà notifiées, ou en attente de verdict) avant d'oublier les plus anciennes.
const MAX_TRACKED: usize = 10_000;
/// Alertes relues dans le store quand des événements ont été perdus (abonné trop lent).
const LAG_RESCAN: usize = 1000;
/// Longueur maximale du titre, en caractères.
const MAX_TITLE: usize = 200;
/// Longueur maximale du message, en caractères (ntfy limite le message à 4 096 octets).
const MAX_MESSAGE: usize = 1500;

/// Pourquoi une notification est envoyée. Sérialisé en snake_case dans le webhook (`reason`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Reason {
    /// Verdict de l'IA malveillant ou suspect.
    Verdict,
    /// Sévérité suffisante pour ne pas attendre l'IA.
    Severity,
    /// Pas de verdict au bout du délai de repli.
    NoVerdict,
    /// Résumé des notifications retenues par le plafond horaire.
    Throttled,
    /// Envoyée par `cyward check-notify`.
    Test,
}

/// Une notification prête à envoyer, indépendante du canal.
#[derive(Debug, Clone)]
pub struct Notification {
    pub reason: Reason,
    /// Titre court, sur une ligne.
    pub title: String,
    /// Corps en texte brut, sur plusieurs lignes.
    pub message: String,
    /// Priorité de 1 (minimale) à 5 (urgente), selon l'échelle de ntfy.
    pub priority: u8,
    /// Lien vers l'alerte dans le dashboard, si `notify.dashboard_url` est renseigné.
    pub url: Option<String>,
    /// L'alerte complète (pour le webhook), absente des résumés et des tests.
    pub alert: Option<Alert>,
}

/// Démarre les notifications : abonnement aux alertes, décision, envoi. Sans canal configuré,
/// ne fait rien (avec un avertissement).
pub fn spawn(cfg: NotifyConfig, store: Arc<AlertStore>) -> Result<()> {
    let channels = channels::from_config(&cfg.channels);
    if channels.is_empty() {
        tracing::warn!("notifications activées sans canal ([[notify.channels]]) : rien ne sera envoyé");
        return Ok(());
    }
    tracing::info!("notifications vers {}", channels.iter().map(|c| c.name()).collect::<Vec<_>>().join(", "));
    let client = Client::builder().timeout(SEND_TIMEOUT).build()?;
    let (tx, rx) = mpsc::channel(QUEUE);
    // Abonnement immédiat, avant le démarrage des détecteurs : aucune alerte ne doit lui échapper.
    let events = store.subscribe();
    tokio::spawn(deliver(client, channels, rx));
    tokio::spawn(watch(Dispatcher::new(cfg), store, events, tx));
    Ok(())
}

/// Envoie une notification de test sur chaque canal et affiche le résultat (`cyward check-notify`).
/// Échoue si un canal au moins n'a pas pu être joint.
pub async fn check(cfg: &NotifyConfig) -> Result<()> {
    let channels = channels::from_config(&cfg.channels);
    if channels.is_empty() {
        bail!("aucun canal configuré : ajoutez une section [[notify.channels]]");
    }
    let client = Client::builder().timeout(SEND_TIMEOUT).build()?;
    let n = Notification {
        reason: Reason::Test,
        title: "Cyward : notification de test".into(),
        message: "Si vous lisez ceci, ce canal de notification fonctionne.".into(),
        priority: 3,
        url: link(&cfg.dashboard_url, None),
        alert: None,
    };
    let mut failed = 0;
    for c in &channels {
        match send(&client, c.as_ref(), &n).await {
            Ok(()) => println!("ok     {}", c.name()),
            Err(e) => {
                failed += 1;
                println!("ÉCHEC  {} : {e:#}", c.name());
            }
        }
    }
    if failed > 0 {
        bail!("{failed} canal(aux) injoignable(s)");
    }
    Ok(())
}

/// Tâche de décision : suit les événements du store et le temps qui passe (délai de repli,
/// résumé), et confie les notifications à la tâche d'envoi.
async fn watch(mut d: Dispatcher, store: Arc<AlertStore>, mut events: broadcast::Receiver<AlertEvent>, tx: mpsc::Sender<Notification>) {
    let mut ticker = tokio::time::interval(TICK);
    loop {
        let out: Vec<Notification> = tokio::select! {
            ev = events.recv() => match ev {
                Ok(AlertEvent::New(a) | AlertEvent::Update(a)) => d.on_alert(&a, Instant::now()).into_iter().collect(),
                Err(broadcast::error::RecvError::Lagged(n)) => {
                    // Événements perdus : on relit les alertes récentes, celles déjà notifiées sont ignorées.
                    tracing::warn!("notifications : {n} événement(s) manqué(s), relecture des alertes récentes");
                    let now = Instant::now();
                    store.list(LAG_RESCAN).iter().filter_map(|a| d.on_alert(a, now)).collect()
                }
                Err(broadcast::error::RecvError::Closed) => break,
            },
            _ = ticker.tick() => d.on_tick(Instant::now(), |id| store.get(id)),
        };
        for n in out {
            // `try_send` : si l'envoi est bloqué (service en panne), on abandonne plutôt que d'accumuler.
            if tx.try_send(n).is_err() {
                tracing::warn!("file des notifications pleine, notification abandonnée");
            }
        }
    }
}

/// Tâche d'envoi : chaque notification part sur tous les canaux, l'un après l'autre.
async fn deliver(client: Client, channels: Vec<Box<dyn Notifier>>, mut rx: mpsc::Receiver<Notification>) {
    while let Some(n) = rx.recv().await {
        for c in &channels {
            if let Err(e) = send(&client, c.as_ref(), &n).await {
                tracing::warn!("notification « {} » non envoyée via {} : {e:#}", n.title, c.name());
            }
        }
    }
}

/// Envoie une notification sur un canal, avec `ATTEMPTS` essais. Une réponse HTTP d'erreur
/// (jeton refusé, sujet inconnu…) compte comme un échec.
async fn send(client: &Client, c: &dyn Notifier, n: &Notification) -> Result<()> {
    let mut attempt = 1;
    loop {
        let res = c.request(client, n).send().await.and_then(|r| r.error_for_status());
        match res {
            Ok(_) => return Ok(()),
            Err(e) if attempt >= ATTEMPTS => return Err(e.into()),
            Err(_) => {
                // Attente croissante (2 s, puis 4 s) : laisse le temps à un service qui redémarre.
                tokio::time::sleep(Duration::from_secs(1 << attempt)).await;
                attempt += 1;
            }
        }
    }
}

/// Décision des notifications : quelles alertes notifier, quand, et dans la limite du plafond.
/// Ne fait aucune I/O ; le temps lui est fourni (`now`) pour être testable.
struct Dispatcher {
    cfg: NotifyConfig,
    /// Alertes déjà notifiées (ou retenues par le plafond), et leur ordre pour oublier les plus anciennes.
    notified: HashSet<u64>,
    order: VecDeque<u64>,
    /// Alertes candidates au repli, et l'instant où elles ont été vues pour la première fois.
    // L'instant de réception, et non `first_seen` : en rejeu, `first_seen` est la date du pcap.
    waiting: HashMap<u64, Instant>,
    limiter: RateLimiter,
    /// Plafond de `notified` et de `waiting` : `MAX_TRACKED`, réduit dans les tests.
    max_tracked: usize,
}

impl Dispatcher {
    fn new(mut cfg: NotifyConfig) -> Self {
        // Comparaison insensible à la casse avec le verdict du modèle, déjà en minuscules.
        cfg.verdicts = cfg.verdicts.iter().map(|v| v.trim().to_lowercase()).collect();
        let limiter = RateLimiter::new(cfg.max_per_hour);
        Self { cfg, notified: HashSet::new(), order: VecDeque::new(), waiting: HashMap::new(), limiter, max_tracked: MAX_TRACKED }
    }

    /// Raison de notifier cette alerte, si elle en a une. `give_up` : elle est candidate au repli
    /// et il est inutile d'attendre son verdict plus longtemps.
    fn reason(&self, a: &Alert, give_up: bool) -> Option<Reason> {
        if let Some(an) = &a.analysis
            && self.cfg.verdicts.contains(&an.verdict.trim().to_lowercase())
            && an.confidence >= self.cfg.min_confidence
        {
            return Some(Reason::Verdict);
        }
        if a.severity >= self.cfg.immediate_severity {
            return Some(Reason::Severity);
        }
        give_up.then_some(Reason::NoVerdict)
    }

    /// Vrai si l'alerte attend un verdict et sera notifiée sans lui passé le délai de repli.
    fn awaits_verdict(&self, a: &Alert) -> bool {
        self.cfg.fallback_after_secs > 0 && a.analysis.is_none() && a.severity >= self.cfg.fallback_severity
    }

    /// Nouvel état d'une alerte (création ou mise à jour) : la notification à envoyer, s'il y en a une.
    fn on_alert(&mut self, a: &Alert, now: Instant) -> Option<Notification> {
        self.evaluate(a, now, false)
    }

    /// Décision pour une alerte. `hopeless` : son état relu dans le store dit qu'aucun verdict ne
    /// viendra. Les événements ne le disent pas de façon fiable : la création est diffusée avant
    /// le passage en `Pending` ; seule la relecture périodique (`on_tick`) l'utilise donc.
    fn evaluate(&mut self, a: &Alert, now: Instant, hopeless: bool) -> Option<Notification> {
        if self.notified.contains(&a.id) {
            return None;
        }
        if !self.awaits_verdict(a) {
            // Verdict arrivé (même bénin) ou sévérité trop basse : plus de repli pour elle.
            self.waiting.remove(&a.id);
        } else if !self.waiting.contains_key(&a.id) && self.waiting.len() < self.max_tracked {
            self.waiting.insert(a.id, now);
        }
        let delay = Duration::from_secs(self.cfg.fallback_after_secs);
        let give_up = self.waiting.get(&a.id).is_some_and(|t| hopeless || now.saturating_duration_since(*t) >= delay);
        let reason = self.reason(a, give_up)?;
        self.mark_notified(a.id);
        // Au-delà du plafond, l'alerte est seulement comptée : elle figurera dans le résumé.
        self.limiter.allow(now).then(|| build(a, reason, &self.cfg))
    }

    /// Vérification périodique des alertes en attente de verdict (relues dans le store), puis
    /// résumé des notifications retenues si le plafond le permet de nouveau.
    fn on_tick(&mut self, now: Instant, get: impl Fn(u64) -> Option<Alert>) -> Vec<Notification> {
        let ids: Vec<u64> = self.waiting.keys().copied().collect();
        let mut out = Vec::new();
        for id in ids {
            match get(id) {
                // Pas envoyée à l'IA (désactivée, file pleine) ou analyse en échec : pas de verdict à attendre.
                Some(a) => out.extend(self.evaluate(&a, now, matches!(a.triage, TriageStatus::None | TriageStatus::Failed))),
                // Évincée du store entre-temps : on l'oublie.
                None => {
                    self.waiting.remove(&id);
                }
            }
        }
        if let Some(n) = self.limiter.summary(now) {
            out.push(throttled(n, &self.cfg));
        }
        out
    }

    /// Retient qu'une alerte a été traitée, en oubliant les plus anciennes au-delà du plafond.
    fn mark_notified(&mut self, id: u64) {
        self.waiting.remove(&id);
        self.notified.insert(id);
        self.order.push_back(id);
        while self.order.len() > self.max_tracked {
            if let Some(old) = self.order.pop_front() {
                self.notified.remove(&old);
            }
        }
    }
}

/// Plafond de notifications sur une heure glissante, avec le compte de celles retenues.
struct RateLimiter {
    max: usize,
    /// Instants des envois de la dernière heure.
    sent: VecDeque<Instant>,
    /// Notifications retenues depuis le dernier résumé.
    suppressed: usize,
}

impl RateLimiter {
    fn new(max: usize) -> Self {
        Self { max, sent: VecDeque::new(), suppressed: 0 }
    }

    /// Oublie les envois sortis de la fenêtre d'une heure.
    fn purge(&mut self, now: Instant) {
        while self.sent.front().is_some_and(|t| now.saturating_duration_since(*t) >= RATE_WINDOW) {
            self.sent.pop_front();
        }
    }

    /// Vrai si une notification peut partir maintenant (et la compte) ; sinon la compte comme retenue.
    fn allow(&mut self, now: Instant) -> bool {
        self.purge(now);
        if self.sent.len() < self.max {
            self.sent.push_back(now);
            true
        } else {
            self.suppressed += 1;
            false
        }
    }

    /// Nombre de notifications retenues, à résumer maintenant si le plafond le permet.
    fn summary(&mut self, now: Instant) -> Option<usize> {
        if self.suppressed == 0 {
            return None;
        }
        self.purge(now);
        if self.sent.len() >= self.max {
            return None;
        }
        self.sent.push_back(now);
        Some(std::mem::take(&mut self.suppressed))
    }
}

/// Libellé français d'une sévérité, comme dans le dashboard.
fn severity_label(s: Severity) -> &'static str {
    match s {
        Severity::Critical => "Critique",
        Severity::High => "Haute",
        Severity::Medium => "Moyenne",
        Severity::Low => "Basse",
        Severity::Info => "Info",
    }
}

/// Priorité ntfy (1 à 5) : la plus haute entre celle de la sévérité et celle du verdict.
fn priority(a: &Alert) -> u8 {
    let by_severity = match a.severity {
        Severity::Critical => 5,
        Severity::High => 4,
        Severity::Medium => 3,
        Severity::Low | Severity::Info => 2,
    };
    let by_verdict = match a.analysis.as_ref().map(|an| an.verdict.as_str()) {
        Some("malveillant") => 5,
        Some("suspect") => 4,
        _ => 0,
    };
    by_severity.max(by_verdict)
}

/// Durée lisible : « 45 s », « 10 min ».
fn duration_label(secs: u64) -> String {
    if secs < 60 { format!("{secs} s") } else { format!("{} min", secs.div_ceil(60)) }
}

/// Lien vers le dashboard, et vers l'alerte `id` s'il est donné (le dashboard la déplie).
fn link(base: &str, id: Option<u64>) -> Option<String> {
    let base = base.trim();
    if base.is_empty() {
        return None;
    }
    Some(match id {
        Some(id) => format!("{base}#alerte-{id}"),
        None => base.to_string(),
    })
}

/// Texte sûr à transmettre : caractères de contrôle remplacés par des espaces (sauf les sauts
/// de ligne si `multiline`), longueur limitée à `max` caractères.
fn clean(s: &str, max: usize, multiline: bool) -> String {
    s.chars().map(|c| if c.is_control() && !(multiline && c == '\n') { ' ' } else { c }).take(max).collect()
}

/// Notification d'une alerte : sévérité et titre, puis raison, machines en jeu, résumé de
/// l'IA et première recommandation.
fn build(a: &Alert, reason: Reason, cfg: &NotifyConfig) -> Notification {
    let mut lines = vec![match (reason, &a.analysis) {
        (Reason::Verdict, Some(an)) => format!("Verdict de l'IA : {} ({:.0} %)", an.verdict, an.confidence * 100.0),
        (Reason::NoVerdict, _) => match a.triage {
            TriageStatus::Failed => "Analyse de l'IA en échec".to_string(),
            TriageStatus::Pending => format!("Pas de verdict de l'IA après {}", duration_label(cfg.fallback_after_secs)),
            _ => "Alerte non analysée par l'IA (désactivée ou file d'analyse pleine)".to_string(),
        },
        _ => format!("Sévérité {} : notification sans attendre l'IA", severity_label(a.severity).to_lowercase()),
    }];
    if let Some(src) = &a.src {
        lines.push(format!("Source : {src}"));
    }
    if let Some(dst) = &a.dst {
        lines.push(format!("Cible : {dst}"));
    }
    if let Some(an) = &a.analysis {
        lines.push(an.summary.clone());
        if let Some(r) = an.recommendations.first() {
            lines.push(format!("À faire : {r}"));
        }
    }
    Notification {
        reason,
        title: clean(&format!("[{}] {}", severity_label(a.severity), a.title), MAX_TITLE, false),
        message: clean(&lines.join("\n"), MAX_MESSAGE, true),
        priority: priority(a),
        url: link(&cfg.dashboard_url, Some(a.id)),
        alert: Some(a.clone()),
    }
}

/// Résumé des `n` notifications retenues par le plafond horaire.
fn throttled(n: usize, cfg: &NotifyConfig) -> Notification {
    Notification {
        reason: Reason::Throttled,
        title: "Cyward : notifications limitées".into(),
        message: format!(
            "{n} autre(s) alerte(s) n'ont pas été notifiées (plafond de {} par heure). Consultez le dashboard.",
            cfg.max_per_hour
        ),
        priority: 3,
        url: link(&cfg.dashboard_url, None),
        alert: None,
    }
}

#[cfg(test)]
mod tests {
    use chrono::Utc;

    use super::*;
    use crate::alert::{AlertKind, AlertSource, Analysis, TriageStatus};

    /// Configuration de test : verdicts et délais par défaut, lien vers le dashboard.
    fn cfg() -> NotifyConfig {
        NotifyConfig { enabled: true, dashboard_url: "http://192.168.1.2:8080/".into(), ..Default::default() }
    }

    /// Alerte d'identifiant `id` et de sévérité `severity`, sans verdict.
    fn alert(id: u64, severity: Severity) -> Alert {
        let mut a = Alert::new(AlertKind::PortScan, severity, AlertSource::Network, Utc::now(), "Scan de ports")
            .src("192.168.1.20")
            .dst("192.168.1.10");
        a.id = id;
        a
    }

    /// La même alerte, avec un verdict de l'IA.
    fn judged(mut a: Alert, verdict: &str, confidence: f64) -> Alert {
        a.triage = TriageStatus::Done;
        a.analysis = Some(Analysis {
            verdict: verdict.into(),
            confidence,
            summary: "Reconnaissance du réseau interne.".into(),
            mitre: vec![],
            recommendations: vec!["Isoler 192.168.1.20".into()],
            model: "test".into(),
        });
        a
    }

    // Un verdict malveillant suffisamment sûr déclenche une notification complète.
    #[test]
    fn notifies_malicious_verdict() {
        let mut d = Dispatcher::new(cfg());
        let now = Instant::now();
        assert!(d.on_alert(&alert(1, Severity::Medium), now).is_none());
        let n = d.on_alert(&judged(alert(1, Severity::Medium), "malveillant", 0.9), now).unwrap();
        assert_eq!(n.reason, Reason::Verdict);
        assert_eq!(n.priority, 5);
        assert_eq!(n.title, "[Moyenne] Scan de ports");
        assert!(
            n.message.contains("malveillant (90 %)")
                && n.message.contains("Source : 192.168.1.20")
                && n.message.contains("À faire : Isoler")
        );
        assert_eq!(n.url.as_deref(), Some("http://192.168.1.2:8080/#alerte-1"));
    }

    // Verdict bénin, ou suspect avec une confiance trop basse : rien.
    #[test]
    fn ignores_benign_or_unsure_verdicts() {
        let mut d = Dispatcher::new(cfg());
        let now = Instant::now();
        assert!(d.on_alert(&judged(alert(1, Severity::High), "bénin", 0.95), now).is_none());
        assert!(d.on_alert(&judged(alert(2, Severity::Medium), "suspect", 0.4), now).is_none());
        assert!(d.on_alert(&judged(alert(3, Severity::Medium), "Suspect", 0.7), now).is_some());
    }

    // Une alerte critique est notifiée tout de suite, puis plus jamais (mises à jour, verdict).
    #[test]
    fn critical_is_immediate_and_notified_once() {
        let mut d = Dispatcher::new(cfg());
        let now = Instant::now();
        let n = d.on_alert(&alert(1, Severity::Critical), now).unwrap();
        assert_eq!(n.reason, Reason::Severity);
        assert!(d.on_alert(&alert(1, Severity::Critical), now).is_none());
        assert!(d.on_alert(&judged(alert(1, Severity::Critical), "malveillant", 0.9), now).is_none());
    }

    // Analyse en attente : une alerte haute est notifiée au bout du délai de repli, pas avant.
    #[test]
    fn falls_back_without_verdict() {
        let mut d = Dispatcher::new(cfg());
        let t0 = Instant::now();
        let mut a = alert(1, Severity::High);
        a.triage = TriageStatus::Pending;
        assert!(d.on_alert(&a, t0).is_none());
        assert!(d.on_tick(t0 + Duration::from_secs(599), |_| Some(a.clone())).is_empty());
        let out = d.on_tick(t0 + Duration::from_secs(600), |_| Some(a.clone()));
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].reason, Reason::NoVerdict);
        assert!(out[0].message.contains("après 10 min"));
    }

    // Alerte non envoyée à l'IA, ou analyse en échec : notifiée à la vérification suivante, sans attendre le délai.
    #[test]
    fn no_wait_when_no_verdict_will_come() {
        let mut d = Dispatcher::new(cfg());
        let t0 = Instant::now();
        let mut failed = alert(2, Severity::High);
        failed.triage = TriageStatus::Failed;
        // L'événement de création est diffusé avant le passage en attente : il ne déclenche rien.
        assert!(d.on_alert(&alert(1, Severity::High), t0).is_none());
        assert!(d.on_alert(&failed, t0).is_none());
        let out = d.on_tick(t0 + TICK, |id| Some(if id == 2 { failed.clone() } else { alert(1, Severity::High) }));
        assert_eq!(out.len(), 2);
        assert!(out.iter().any(|n| n.message.starts_with("Alerte non analysée")));
        assert!(out.iter().any(|n| n.message.starts_with("Analyse de l'IA en échec")));
    }

    // Un verdict bénin arrivé avant le délai annule le repli ; une alerte moyenne n'en a jamais.
    #[test]
    fn verdict_or_low_severity_cancels_fallback() {
        let mut d = Dispatcher::new(cfg());
        let t0 = Instant::now();
        d.on_alert(&alert(1, Severity::High), t0);
        d.on_alert(&judged(alert(1, Severity::High), "bénin", 0.9), t0);
        d.on_alert(&alert(2, Severity::Medium), t0);
        assert!(d.waiting.is_empty());
        assert!(d.on_tick(t0 + Duration::from_secs(3600), |id| Some(alert(id, Severity::High))).is_empty());
    }

    // `fallback_after_secs = 0` désactive le repli.
    #[test]
    fn fallback_can_be_disabled() {
        let mut d = Dispatcher::new(NotifyConfig { fallback_after_secs: 0, ..cfg() });
        let t0 = Instant::now();
        let a = alert(1, Severity::High);
        d.on_alert(&a, t0);
        assert!(d.waiting.is_empty());
        assert!(d.on_tick(t0 + Duration::from_secs(86_400), |_| Some(a.clone())).is_empty());
    }

    // Au-delà du plafond horaire, les notifications sont retenues puis résumées une heure plus tard.
    #[test]
    fn rate_limit_then_summary() {
        let mut d = Dispatcher::new(NotifyConfig { max_per_hour: 2, ..cfg() });
        let t0 = Instant::now();
        let sent = (1..=5).filter_map(|id| d.on_alert(&alert(id, Severity::Critical), t0)).count();
        assert_eq!(sent, 2);
        assert!(d.on_tick(t0 + Duration::from_secs(60), |_| None).is_empty());
        let out = d.on_tick(t0 + RATE_WINDOW, |_| None);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].reason, Reason::Throttled);
        assert!(out[0].message.starts_with("3 autre(s)"));
        // Le compteur repart de zéro après le résumé.
        assert!(d.on_tick(t0 + RATE_WINDOW, |_| None).is_empty());
    }

    // Les textes venus du réseau ne peuvent pas casser le titre (sauts de ligne, contrôle).
    #[test]
    fn strips_control_characters() {
        let mut a = alert(1, Severity::Critical);
        a.title = "Titre\npiégé\u{1b}[31m".into();
        let n = build(&a, Reason::Severity, &cfg());
        assert_eq!(n.title, "[Critique] Titre piégé [31m");
        assert!(!n.title.contains('\n'));
    }

    // La mémoire des alertes notifiées est bornée.
    #[test]
    fn tracked_alerts_are_bounded() {
        let mut d = Dispatcher::new(NotifyConfig { max_per_hour: 1000, ..cfg() });
        d.max_tracked = 3;
        let now = Instant::now();
        for id in 1..=10 {
            d.on_alert(&alert(id, Severity::Critical), now);
        }
        assert_eq!(d.notified.len(), 3);
        assert_eq!(d.order.len(), 3);
    }

    // Sans adresse du dashboard, pas de lien.
    #[test]
    fn no_link_without_dashboard_url() {
        assert_eq!(link("", Some(3)), None);
        assert_eq!(link("http://h:8080/", None).as_deref(), Some("http://h:8080/"));
    }
}
