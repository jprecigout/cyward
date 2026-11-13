//! Point d'entrée unique des alertes (pattern Façade) : les détecteurs, les règles de logs et
//! l'apprentissage appellent [`AlertSink::emit`], sans connaître ni le store ni la file du LLM.

use std::sync::Arc;

use tokio::sync::mpsc;

use super::{Alert, AlertStore, Severity, TriageStatus};

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

#[cfg(test)]
mod tests {
    use chrono::Utc;

    use super::*;
    use crate::alert::{AlertKind, AlertSource};

    /// Sink de test : store vide, file du LLM de `queue` places, seuil `Medium`.
    fn sink(queue: usize) -> (AlertSink, mpsc::Receiver<u64>) {
        let (tx, rx) = mpsc::channel(queue);
        (AlertSink::new(Arc::new(AlertStore::new(10, 300)), Some(tx), Severity::Medium), rx)
    }

    /// Alerte de gravité `severity` venant de `src`.
    fn alert(severity: Severity, src: &str) -> Alert {
        Alert::new(AlertKind::PortScan, severity, AlertSource::Network, Utc::now(), "scan").src(src)
    }

    // Une alerte assez grave part dans la file du LLM et passe « en attente d'analyse ».
    #[test]
    fn severe_alert_is_queued_for_triage() {
        let (s, mut rx) = sink(4);
        s.emit(alert(Severity::High, "10.0.0.1"));
        let id = rx.try_recv().unwrap();
        assert_eq!(s.store.get(id).unwrap().triage, TriageStatus::Pending);
    }

    // Une alerte sous le seuil, ou la répétition d'une alerte déjà envoyée, ne part pas au LLM.
    #[test]
    fn minor_or_repeated_alert_is_not_queued() {
        let (s, mut rx) = sink(4);
        s.emit(alert(Severity::Low, "10.0.0.2"));
        assert!(rx.try_recv().is_err());
        assert_eq!(s.store.list(10)[0].triage, TriageStatus::None);
        s.emit(alert(Severity::High, "10.0.0.1"));
        s.emit(alert(Severity::High, "10.0.0.1"));
        assert!(rx.try_recv().is_ok());
        assert!(rx.try_recv().is_err(), "répétition renvoyée au LLM");
    }

    // File pleine : la détection n'attend pas, et l'alerte reste « non analysée » au lieu d'attendre à tort.
    #[test]
    fn full_queue_drops_triage_without_blocking() {
        let (s, _rx) = sink(1);
        s.emit(alert(Severity::High, "10.0.0.1"));
        s.emit(alert(Severity::High, "10.0.0.2"));
        let list = s.store.list(10);
        assert_eq!((list[0].src.as_deref(), list[0].triage), (Some("10.0.0.2"), TriageStatus::None));
        assert_eq!(list[1].triage, TriageStatus::Pending);
    }

    // LLM désactivé : les alertes sont enregistrées, sans statut d'analyse.
    #[test]
    fn without_llm_alerts_are_only_stored() {
        let s = AlertSink::new(Arc::new(AlertStore::new(10, 300)), None, Severity::Medium);
        s.emit(alert(Severity::Critical, "10.0.0.1"));
        assert_eq!(s.store.list(10)[0].triage, TriageStatus::None);
    }
}
