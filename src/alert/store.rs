//! Stockage en mémoire des alertes (pattern Observer) : dédoublonnage des répétitions et
//! diffusion de chaque création ou mise à jour à ses abonnés (dashboard, notifications,
//! historique).
//!
//! Seul [`AlertSink`](super::AlertSink) y ajoute des alertes. Les abonnés reçoivent les
//! changements par [`AlertStore::subscribe`] ; le LLM et le dashboard modifient une alerte
//! existante par [`AlertStore::update`], ce qui diffuse aussi la mise à jour.

use std::{
    collections::{HashMap, VecDeque},
    sync::atomic::{AtomicU64, Ordering},
};

use parking_lot::Mutex;
use serde::Serialize;
use tokio::sync::broadcast;

use super::{Alert, Severity, TriageStatus};

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

#[cfg(test)]
mod tests {
    use chrono::Utc;

    use super::*;
    use crate::alert::{AlertKind, AlertSource};

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
}
