//! Compteurs de fonctionnement affichés dans le bandeau du dashboard (`/api/stats`).
//!
//! Les compteurs sont des atomiques : le thread de capture les incrémente à chaque paquet
//! sans prendre de verrou. `Ordering::Relaxed` suffit, aucune autre donnée n'en dépend.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use chrono::{DateTime, Utc};
use parking_lot::Mutex;
use serde::Serialize;

/// État partagé (via `Arc`) entre la capture, les logs, le LLM et le serveur web.
#[derive(Default)]
pub struct Stats {
    /// Paquets lus sur l'interface ou dans le pcap.
    pub packets: AtomicU64,
    /// Octets correspondants.
    pub bytes: AtomicU64,
    /// Paquets perdus parce que le moteur de détection ne suivait pas.
    pub dropped: AtomicU64,
    /// Lignes de logs reçues (toutes sources confondues).
    pub log_lines: AtomicU64,
    /// Analyses LLM réussies.
    pub llm_analyzed: AtomicU64,
    /// Analyses LLM en échec.
    pub llm_failed: AtomicU64,
    /// Résultat de la dernière vérification du serveur LLM (toutes les 30 s).
    pub llm_online: AtomicBool,
    /// Interface écoutée, ou nom du fichier pcap rejoué.
    pub interface: Mutex<Option<String>>,
    pub started_at: Mutex<Option<DateTime<Utc>>>,
}

/// Copie figée et sérialisable des compteurs, renvoyée par l'API.
#[derive(Serialize)]
pub struct StatsSnapshot {
    pub packets: u64,
    pub bytes: u64,
    pub dropped: u64,
    pub log_lines: u64,
    pub llm_analyzed: u64,
    pub llm_failed: u64,
    pub llm_online: bool,
    pub interface: Option<String>,
    pub started_at: Option<DateTime<Utc>>,
}

impl Stats {
    /// Lit chaque compteur une fois. Les valeurs ne sont pas lues au même instant exact,
    /// ce qui est sans importance pour un affichage.
    pub fn snapshot(&self) -> StatsSnapshot {
        StatsSnapshot {
            packets: self.packets.load(Ordering::Relaxed),
            bytes: self.bytes.load(Ordering::Relaxed),
            dropped: self.dropped.load(Ordering::Relaxed),
            log_lines: self.log_lines.load(Ordering::Relaxed),
            llm_analyzed: self.llm_analyzed.load(Ordering::Relaxed),
            llm_failed: self.llm_failed.load(Ordering::Relaxed),
            llm_online: self.llm_online.load(Ordering::Relaxed),
            interface: self.interface.lock().clone(),
            started_at: *self.started_at.lock(),
        }
    }
}
