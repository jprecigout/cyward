//! Historique des alertes sur disque (SQLite) : rechargé au démarrage, tenu à jour pendant
//! l'exécution, borné en âge et en nombre.
//!
//! Consommateur des alertes au même titre que le dashboard et les notifications : il s'abonne
//! aux événements de l'[`AlertStore`] (Observer), sans que les détecteurs ni le LLM ne le connaissent.
//!
//! ```text
//! AlertStore ──broadcast──► watch : Batcher (regroupement) ──mpsc──► thread d'écriture : AlertRepository (SQLite)
//! ```
//!
//! - **La détection n'attend jamais le disque** : `AlertSink::emit` et le verrou du store ne
//!   touchent pas à la base. Les écritures passent par un thread dédié, derrière une file bornée.
//! - **Regroupement** : une alerte modifiée plusieurs fois entre deux écritures (répétitions,
//!   verdict du LLM) n'est écrite qu'une fois, dans son dernier état. Un lot part toutes les
//!   [`FLUSH`], ou dès [`MAX_BATCH`] alertes, en une seule transaction.
//! - **Protection contre une inondation** : la base est purgée par âge (`history.retention_days`)
//!   et par nombre (`history.max_alerts`) toutes les heures, mais aussi dès que `max_alerts / 10`
//!   alertes nouvelles ont été écrites depuis la dernière purge. Une rafale d'alertes distinctes
//!   ne fait donc jamais dépasser le plafond de plus de 10 % (plus un lot). Les preuves de chaque
//!   alerte sont plafonnées (`repository::MAX_EVIDENCE_BYTES`) et la file d'attente en mémoire
//!   aussi ([`MAX_PENDING`]).

pub mod repository;

use std::{collections::HashMap, path::Path, sync::Arc, time::Duration};

use anyhow::{Result, bail};
use chrono::{DateTime, Utc};
use tokio::sync::{broadcast, mpsc, oneshot};

use crate::{
    alert::{Alert, AlertEvent, AlertStore},
    config::HistoryConfig,
};
use repository::AlertRepository;

/// Période d'écriture des alertes modifiées.
const FLUSH: Duration = Duration::from_secs(5);
/// Taille d'un lot qui déclenche une écriture sans attendre la période.
const MAX_BATCH: usize = 500;
/// Alertes en attente d'écriture au-delà desquelles les nouvelles sont abandonnées (disque bloqué).
const MAX_PENDING: usize = 10_000;
/// Lots en attente entre la tâche de regroupement et le thread d'écriture.
const WRITE_QUEUE: usize = 4;
/// Délai maximal de purge par âge, même sans nouvelle alerte.
const PRUNE_INTERVAL: chrono::Duration = chrono::Duration::hours(1);
/// Attente maximale de la dernière écriture à l'arrêt : un disque bloqué ne doit pas empêcher de quitter.
const FLUSH_TIMEOUT: Duration = Duration::from_secs(5);

/// Poignée sur l'historique en cours d'exécution, pour la dernière écriture à l'arrêt.
pub struct History {
    /// Demande d'écriture finale ; l'émetteur `oneshot` est notifié quand elle est sur disque.
    stop: mpsc::Sender<oneshot::Sender<()>>,
}

impl History {
    /// Écrit les alertes encore en attente puis arrête l'historique. À appeler à l'arrêt de l'agent.
    pub async fn flush(&self) {
        let (ack, done) = oneshot::channel();
        if self.stop.send(ack).await.is_ok() && tokio::time::timeout(FLUSH_TIMEOUT, done).await.is_err() {
            tracing::warn!("historique : dernière écriture non terminée à l'arrêt");
        }
    }
}

/// Ouvre la base, recharge dans le store les `restore` alertes les plus récentes, puis démarre
/// l'écriture. À appeler avant le démarrage des détecteurs : aucune alerte ne doit lui échapper.
pub fn spawn(cfg: HistoryConfig, store: Arc<AlertStore>, restore: usize) -> Result<History> {
    let retention = Retention::new(&cfg, Utc::now())?;
    let mut repo = AlertRepository::open(Path::new(&cfg.path))?;
    // Purge dès l'ouverture : une limite abaissée dans la configuration s'applique tout de suite.
    let removed = repo.prune(retention.cutoff(Utc::now()), retention.max_alerts)?;
    let alerts = repo.load_recent(restore)?;
    tracing::info!("historique {} : {} alerte(s) en base, {} rechargée(s), {removed} purgée(s)", cfg.path, repo.count()?, alerts.len());
    store.restore(alerts, repo.next_id()?);

    let events = store.subscribe();
    let (tx, rx) = mpsc::channel(WRITE_QUEUE);
    let (stop, stop_rx) = mpsc::channel(1);
    // Thread système et non tâche tokio : SQLite bloque, et la connexion ne change jamais de thread.
    std::thread::Builder::new().name("cyward-history".into()).spawn(move || write_loop(repo, retention, rx))?;
    tokio::spawn(watch(store, events, tx, stop_rx));
    Ok(History { stop })
}

/// Un lot d'alertes à écrire. `done` est notifié une fois le lot sur disque (écriture finale).
struct Batch {
    alerts: Vec<Alert>,
    done: Option<oneshot::Sender<()>>,
}

/// Tâche de regroupement : suit les événements du store et envoie un lot au thread d'écriture
/// à chaque période, ou dès qu'il est assez gros.
async fn watch(
    store: Arc<AlertStore>,
    mut events: broadcast::Receiver<AlertEvent>,
    tx: mpsc::Sender<Batch>,
    mut stop: mpsc::Receiver<oneshot::Sender<()>>,
) {
    let mut batcher = Batcher::default();
    let mut ticker = tokio::time::interval(FLUSH);
    loop {
        tokio::select! {
            ev = events.recv() => match ev {
                Ok(AlertEvent::New(a) | AlertEvent::Update(a)) => {
                    batcher.add(a);
                    if batcher.len() >= MAX_BATCH {
                        send(&mut batcher, &tx);
                    }
                }
                Err(broadcast::error::RecvError::Lagged(n)) => {
                    // Événements perdus : on réécrit tout le store, l'écriture étant idempotente.
                    tracing::warn!("historique : {n} événement(s) manqué(s), réécriture des alertes en mémoire");
                    store.list(usize::MAX).into_iter().for_each(|a| batcher.add(a));
                }
                Err(broadcast::error::RecvError::Closed) => break,
            },
            // Lot envoyé même vide : le thread d'écriture en profite pour la purge par âge.
            _ = ticker.tick() => send(&mut batcher, &tx),
            Some(ack) = stop.recv() => {
                // Les événements déjà publiés mais pas encore lus font partie de l'écriture finale.
                while let Ok(AlertEvent::New(a) | AlertEvent::Update(a)) = events.try_recv() {
                    batcher.add(a);
                }
                // `send` et non `try_send` : à l'arrêt, on attend une place dans la file.
                let _ = tx.send(Batch { alerts: batcher.take(), done: Some(ack) }).await;
                break;
            }
        }
    }
    if batcher.dropped > 0 {
        tracing::warn!("historique : {} alerte(s) abandonnée(s), file d'écriture saturée", batcher.dropped);
    }
}

/// Confie le lot en cours au thread d'écriture. S'il est occupé (file pleine), les alertes
/// restent en attente pour le lot suivant : la tâche de regroupement ne bloque jamais.
fn send(batcher: &mut Batcher, tx: &mpsc::Sender<Batch>) {
    let alerts = batcher.take();
    if let Err(mpsc::error::TrySendError::Full(b)) = tx.try_send(Batch { alerts, done: None }) {
        batcher.put_back(b.alerts);
    }
}

/// Thread d'écriture : écrit chaque lot, puis purge quand la politique de rétention l'exige.
/// Une erreur d'écriture (disque plein…) est journalisée, sans arrêter l'agent.
fn write_loop(mut repo: AlertRepository, mut retention: Retention, mut rx: mpsc::Receiver<Batch>) {
    while let Some(batch) = rx.blocking_recv() {
        match repo.upsert(&batch.alerts) {
            Ok(new) => retention.record(new),
            Err(e) => tracing::warn!("historique : {} alerte(s) non écrite(s) : {e:#}", batch.alerts.len()),
        }
        let now = Utc::now();
        if retention.due(now) {
            match repo.prune(retention.cutoff(now), retention.max_alerts) {
                Ok(0) => {}
                Ok(n) => tracing::info!("historique : {n} alerte(s) ancienne(s) purgée(s)"),
                Err(e) => tracing::warn!("historique : purge impossible : {e:#}"),
            }
            retention.pruned(now);
        }
        if let Some(done) = batch.done {
            let _ = done.send(());
        }
    }
}

/// Alertes modifiées depuis la dernière écriture, une seule fois chacune (dernier état).
#[derive(Default)]
struct Batcher {
    /// Dernier état de chaque alerte modifiée, par identifiant.
    pending: HashMap<u64, Alert>,
    /// Alertes nouvelles abandonnées faute de place.
    dropped: u64,
}

impl Batcher {
    /// Ajoute ou remplace une alerte. Au-delà de [`MAX_PENDING`], une alerte qui n'est pas déjà
    /// en attente est abandonnée : la mémoire reste bornée même si le disque ne suit plus.
    fn add(&mut self, a: Alert) {
        if self.pending.len() >= MAX_PENDING && !self.pending.contains_key(&a.id) {
            self.dropped += 1;
            return;
        }
        self.pending.insert(a.id, a);
    }

    /// Vide la file, par identifiant croissant (ordre d'écriture reproductible).
    fn take(&mut self) -> Vec<Alert> {
        let mut alerts: Vec<Alert> = self.pending.drain().map(|(_, a)| a).collect();
        alerts.sort_unstable_by_key(|a| a.id);
        alerts
    }

    /// Remet en attente un lot non envoyé, sans écraser un état plus récent arrivé entre-temps.
    fn put_back(&mut self, alerts: Vec<Alert>) {
        for a in alerts {
            self.pending.entry(a.id).or_insert(a);
        }
    }

    fn len(&self) -> usize {
        self.pending.len()
    }
}

/// Politique de rétention : quand purger, et jusqu'où. Pure (l'heure est passée en paramètre).
struct Retention {
    /// Durée de conservation après la dernière occurrence d'une alerte.
    max_age: chrono::Duration,
    /// Nombre maximal d'alertes en base.
    max_alerts: usize,
    /// Alertes nouvelles écrites depuis la dernière purge.
    written: usize,
    /// Heure de la dernière purge.
    last: DateTime<Utc>,
}

impl Retention {
    /// Politique tirée de la configuration ; refuse des limites qui videraient la base.
    fn new(cfg: &HistoryConfig, now: DateTime<Utc>) -> Result<Self> {
        if cfg.retention_days.is_nan() || cfg.retention_days <= 0.0 {
            bail!("history.retention_days doit être strictement positif ({})", cfg.retention_days);
        }
        if cfg.max_alerts == 0 {
            bail!("history.max_alerts doit être strictement positif");
        }
        // Une durée démesurée (1e9 jours) est ramenée au maximum représentable au lieu de paniquer.
        let max_age = chrono::Duration::try_seconds((cfg.retention_days * 86_400.0) as i64).unwrap_or(chrono::Duration::MAX);
        Ok(Self { max_age, max_alerts: cfg.max_alerts, written: 0, last: now })
    }

    /// Date avant laquelle une alerte (sa dernière occurrence) est trop ancienne.
    fn cutoff(&self, now: DateTime<Utc>) -> DateTime<Utc> {
        now.checked_sub_signed(self.max_age).unwrap_or(DateTime::<Utc>::MIN_UTC)
    }

    /// Nombre d'alertes nouvelles au-delà duquel on purge sans attendre : 10 % du plafond.
    fn burst(&self) -> usize {
        (self.max_alerts / 10).max(1)
    }

    fn record(&mut self, new: usize) {
        self.written += new;
    }

    /// Vrai si une purge s'impose : rafale d'alertes nouvelles, ou purge par âge trop ancienne.
    fn due(&self, now: DateTime<Utc>) -> bool {
        self.written >= self.burst() || now - self.last >= PRUNE_INTERVAL
    }

    fn pruned(&mut self, now: DateTime<Utc>) {
        self.written = 0;
        self.last = now;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::alert::{AlertKind, AlertSink, AlertSource, Severity};
    use repository::tests::{alert, temp_db};

    fn cfg(path: &str, max_alerts: usize) -> HistoryConfig {
        HistoryConfig { path: path.into(), retention_days: 90.0, max_alerts }
    }

    // Plusieurs modifications d'une même alerte n'en font qu'une écriture, dans son dernier état.
    #[test]
    fn batcher_keeps_last_state_once() {
        let mut b = Batcher::default();
        let t = Utc::now();
        let mut a = alert(2, t);
        b.add(a.clone());
        a.count = 5;
        b.add(a);
        b.add(alert(1, t));
        let out = b.take();
        assert_eq!(out.iter().map(|a| (a.id, a.count)).collect::<Vec<_>>(), vec![(1, 1), (2, 5)]);
        assert_eq!(b.len(), 0);
    }

    // File pleine : une alerte nouvelle est abandonnée, la mise à jour d'une alerte en attente non.
    #[test]
    fn batcher_is_bounded() {
        let mut b = Batcher::default();
        let t = Utc::now();
        (0..MAX_PENDING as u64).for_each(|i| b.add(alert(i, t)));
        b.add(alert(MAX_PENDING as u64, t));
        assert_eq!((b.len(), b.dropped), (MAX_PENDING, 1));
        let mut update = alert(0, t);
        update.count = 9;
        b.add(update);
        assert_eq!((b.len(), b.dropped), (MAX_PENDING, 1));
        assert_eq!(b.pending[&0].count, 9);
    }

    // Un lot remis en attente n'écrase pas un état plus récent arrivé entre-temps.
    #[test]
    fn put_back_keeps_newer_state() {
        let mut b = Batcher::default();
        let t = Utc::now();
        let mut newer = alert(1, t);
        newer.count = 3;
        b.add(newer);
        b.put_back(vec![alert(1, t), alert(2, t)]);
        assert_eq!(b.pending[&1].count, 3);
        assert_eq!(b.len(), 2);
    }

    // Une rafale de 10 % du plafond déclenche la purge sans attendre l'heure.
    #[test]
    fn retention_due_on_burst() {
        let now = Utc::now();
        let mut r = Retention::new(&cfg("x", 1000), now).unwrap();
        r.record(99);
        assert!(!r.due(now));
        r.record(1);
        assert!(r.due(now));
        r.pruned(now);
        assert!(!r.due(now));
    }

    // Sans nouvelle alerte, la purge par âge a lieu au plus tard une heure après la précédente.
    #[test]
    fn retention_due_after_interval() {
        let now = Utc::now();
        let r = Retention::new(&cfg("x", 1000), now).unwrap();
        assert!(!r.due(now + chrono::Duration::minutes(59)));
        assert!(r.due(now + PRUNE_INTERVAL));
    }

    // Des limites qui videraient la base sont refusées ; une durée démesurée ne panique pas.
    #[test]
    fn retention_validates_limits() {
        let now = Utc::now();
        assert!(Retention::new(&cfg("x", 0), now).is_err());
        assert!(Retention::new(&HistoryConfig { retention_days: 0.0, ..cfg("x", 10) }, now).is_err());
        assert!(Retention::new(&HistoryConfig { retention_days: f64::NAN, ..cfg("x", 10) }, now).is_err());
        let huge = Retention::new(&HistoryConfig { retention_days: 1e12, ..cfg("x", 10) }, now).unwrap();
        assert_eq!(huge.cutoff(now), DateTime::<Utc>::MIN_UTC);
        let days = Retention::new(&cfg("x", 10), now).unwrap();
        assert_eq!(days.cutoff(now), now - chrono::Duration::days(90));
    }

    // Bout en bout : les alertes émises sont écrites à l'arrêt, puis rechargées au lancement
    // suivant, avec des identifiants qui continuent.
    #[tokio::test]
    async fn alerts_survive_restart() {
        let path = temp_db("restart");
        let path_str = path.to_str().unwrap();
        let mk = |src: &str| Alert::new(AlertKind::PortScan, Severity::High, AlertSource::Network, Utc::now(), "scan").src(src);
        {
            let store = Arc::new(AlertStore::new(100, 300));
            let history = spawn(cfg(path_str, 1000), store.clone(), 100).unwrap();
            let sink = AlertSink::new(store.clone(), None, Severity::Medium);
            sink.emit(mk("10.0.0.1"));
            sink.emit(mk("10.0.0.2"));
            // Répétition : fusionnée, elle met à jour l'alerte au lieu d'en créer une.
            sink.emit(mk("10.0.0.2"));
            history.flush().await;
        }
        let store = Arc::new(AlertStore::new(100, 300));
        let _history = spawn(cfg(path_str, 1000), store.clone(), 100).unwrap();
        let back = store.list(10);
        assert_eq!(back.iter().map(|a| (a.id, a.count)).collect::<Vec<_>>(), vec![(2, 2), (1, 1)]);
        assert_eq!(store.push(mk("10.0.0.3")).unwrap().id, 3);
    }

    // Inondation : 2 000 alertes distinctes, plafond de 100 ; la base ne dépasse jamais
    // le plafond de plus de 10 % plus un lot, et se termine au plafond ou en dessous.
    #[test]
    fn flood_stays_bounded() {
        let path = temp_db("flood");
        let probe = AlertRepository::open(&path).unwrap();
        let (tx, rx) = mpsc::channel(1);
        let retention = Retention::new(&cfg(path.to_str().unwrap(), 100), Utc::now()).unwrap();
        let writer = std::thread::spawn(move || write_loop(AlertRepository::open(&path).unwrap(), retention, rx));
        let now = Utc::now();
        let mut peak = 0;
        for lot in 0..40u64 {
            let alerts = (0..50).map(|i| alert(lot * 50 + i + 1, now)).collect();
            let (ack, done) = oneshot::channel();
            tx.blocking_send(Batch { alerts, done: Some(ack) }).unwrap();
            done.blocking_recv().unwrap();
            peak = peak.max(probe.count().unwrap());
        }
        drop(tx);
        writer.join().unwrap();
        assert!(peak <= 100 + 10 + 50, "pic à {peak}");
        assert!(probe.count().unwrap() <= 100 + 10 + 50);
    }

    // Trafic normal : sous le plafond, rien n'est purgé.
    #[test]
    fn normal_volume_is_kept() {
        let path = temp_db("normal");
        let probe = AlertRepository::open(&path).unwrap();
        let (tx, rx) = mpsc::channel(1);
        let retention = Retention::new(&cfg(path.to_str().unwrap(), 100), Utc::now()).unwrap();
        let writer = std::thread::spawn(move || write_loop(AlertRepository::open(&path).unwrap(), retention, rx));
        let (ack, done) = oneshot::channel();
        tx.blocking_send(Batch { alerts: (1..=30).map(|i| alert(i, Utc::now())).collect(), done: Some(ack) }).unwrap();
        done.blocking_recv().unwrap();
        drop(tx);
        writer.join().unwrap();
        assert_eq!(probe.count().unwrap(), 30);
    }

    // Au redémarrage, une base au-delà du plafond (limite abaissée) est ramenée au plafond.
    #[tokio::test]
    async fn lowered_limit_applies_at_startup() {
        let path = temp_db("lowered");
        let mut repo = AlertRepository::open(&path).unwrap();
        let now = Utc::now();
        repo.upsert(&(1..=5).map(|i| alert(i, now - chrono::Duration::minutes(10 - i as i64))).collect::<Vec<_>>()).unwrap();
        drop(repo);
        let store = Arc::new(AlertStore::new(100, 300));
        let _history = spawn(cfg(path.to_str().unwrap(), 2), store.clone(), 100).unwrap();
        assert_eq!(store.list(10).iter().map(|a| a.id).collect::<Vec<_>>(), vec![5, 4]);
    }
}
