//! Persistance des alertes dans une base SQLite (pattern Repository) : le reste du code
//! manipule des [`Alert`], ce fichier seul connaît le schéma, le format et les réglages SQLite.
//!
//! ```text
//! alerts  id (clé), kind, severity, src, dst, first_seen, last_seen (secondes Unix),
//!         fingerprint, data (l'alerte complète en JSON)
//! meta    next_id : prochain identifiant, conservé même si toutes les alertes sont purgées
//! ```
//!
//! Les colonnes à côté de `data` servent aux purges (index sur `last_seen`) et aux requêtes à la
//! main avec `sqlite3` ; `data` seul suffit à reconstruire l'alerte.

use std::path::Path;

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use rusqlite::{Connection, params};
use serde::Serialize;

use crate::alert::Alert;

/// Taille maximale des preuves d'une alerte enregistrée, en octets de JSON. Les preuves viennent
/// du réseau et des logs, donc d'un attaquant : au-delà, elles sont remplacées par un extrait.
pub const MAX_EVIDENCE_BYTES: usize = 4096;
/// Longueur de l'extrait gardé à la place de preuves trop longues, en octets.
const EVIDENCE_EXCERPT_BYTES: usize = 1024;

/// Schéma, créé au premier lancement. `auto_vacuum` doit précéder la création des tables pour
/// s'appliquer : il permet de rendre au système l'espace libéré par les purges.
const SCHEMA: &str = "
    PRAGMA auto_vacuum = INCREMENTAL;
    CREATE TABLE IF NOT EXISTS alerts (
        id          INTEGER PRIMARY KEY,
        kind        TEXT NOT NULL,
        severity    TEXT NOT NULL,
        src         TEXT,
        dst         TEXT,
        first_seen  INTEGER NOT NULL,
        last_seen   INTEGER NOT NULL,
        fingerprint TEXT NOT NULL,
        data        TEXT NOT NULL
    );
    CREATE INDEX IF NOT EXISTS alerts_last_seen ON alerts (last_seen);
    CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value INTEGER NOT NULL);
";

/// Accès à la base des alertes. N'est utilisé que par le thread d'écriture (et au démarrage) :
/// une connexion SQLite ne se partage pas entre threads.
pub struct AlertRepository {
    conn: Connection,
    /// Plus grand identifiant déjà écrit : distingue une alerte nouvelle d'une mise à jour.
    max_id: u64,
}

impl AlertRepository {
    /// Ouvre (et crée si besoin, dossier parent compris) la base SQLite.
    pub fn open(path: &Path) -> Result<Self> {
        if let Some(dir) = path.parent().filter(|d| !d.as_os_str().is_empty()) {
            std::fs::create_dir_all(dir).with_context(|| format!("création de {}", dir.display()))?;
        }
        let conn = Connection::open(path).with_context(|| format!("ouverture de {}", path.display()))?;
        Self::init(conn).with_context(|| format!("initialisation de {}", path.display()))
    }

    /// Base en mémoire, pour les tests.
    #[cfg(test)]
    pub fn in_memory() -> Self {
        Self::init(Connection::open_in_memory().unwrap()).unwrap()
    }

    fn init(conn: Connection) -> Result<Self> {
        // WAL : les écritures n'effacent pas les lectures en cours (sqlite3 ouvert à côté) ;
        // `synchronous = NORMAL` évite un fsync par transaction, au prix des toutes dernières
        // écritures en cas de coupure de courant (la base reste cohérente).
        conn.pragma_update_and_check(None, "journal_mode", "WAL", |r| r.get::<_, String>(0))?;
        conn.pragma_update(None, "synchronous", "NORMAL")?;
        conn.execute_batch(SCHEMA)?;
        let max_id: i64 = conn.query_row("SELECT COALESCE(MAX(id), 0) FROM alerts", [], |r| r.get(0))?;
        Ok(Self { conn, max_id: max_id as u64 })
    }

    /// Écrit des alertes (création ou remplacement par identifiant) en une seule transaction.
    /// Renvoie le nombre d'alertes nouvelles, que la politique de rétention comptabilise.
    pub fn upsert(&mut self, alerts: &[Alert]) -> Result<usize> {
        if alerts.is_empty() {
            return Ok(0);
        }
        let tx = self.conn.transaction()?;
        {
            let mut stmt = tx.prepare_cached(
                "INSERT INTO alerts (id, kind, severity, src, dst, first_seen, last_seen, fingerprint, data)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
                 ON CONFLICT (id) DO UPDATE SET
                     kind = excluded.kind, severity = excluded.severity, src = excluded.src,
                     dst = excluded.dst, first_seen = excluded.first_seen, last_seen = excluded.last_seen,
                     fingerprint = excluded.fingerprint, data = excluded.data",
            )?;
            for a in alerts {
                stmt.execute(params![
                    a.id as i64,
                    name(&a.kind),
                    name(&a.severity),
                    a.src,
                    a.dst,
                    a.first_seen.timestamp(),
                    a.last_seen.timestamp(),
                    a.fingerprint,
                    encode(a)?,
                ])?;
            }
        }
        let top = alerts.iter().map(|a| a.id).max().unwrap_or(0);
        // `max` : un lot ne fait jamais reculer le compteur (mises à jour d'alertes anciennes).
        tx.execute(
            "INSERT INTO meta (key, value) VALUES ('next_id', ?1)
             ON CONFLICT (key) DO UPDATE SET value = max(value, excluded.value)",
            [top as i64 + 1],
        )?;
        tx.commit()?;
        let new = alerts.iter().filter(|a| a.id > self.max_id).count();
        self.max_id = self.max_id.max(top);
        Ok(new)
    }

    /// Supprime les alertes vues pour la dernière fois avant `cutoff`, puis les plus anciennes
    /// au-delà de `max_alerts`, et rend l'espace libéré au système. Renvoie le nombre supprimé.
    pub fn prune(&mut self, cutoff: DateTime<Utc>, max_alerts: usize) -> Result<usize> {
        let tx = self.conn.transaction()?;
        let mut removed = tx.execute("DELETE FROM alerts WHERE last_seen < ?1", [cutoff.timestamp()])?;
        // `LIMIT -1 OFFSET n` : toutes les lignes après les n plus récentes.
        removed += tx.execute(
            "DELETE FROM alerts WHERE id IN
                 (SELECT id FROM alerts ORDER BY last_seen DESC, id DESC LIMIT -1 OFFSET ?1)",
            [max_alerts as i64],
        )?;
        tx.commit()?;
        if removed > 0 {
            self.conn.execute_batch("PRAGMA incremental_vacuum")?;
        }
        Ok(removed)
    }

    /// Les `limit` alertes les plus récentes (par identifiant), dans l'ordre chronologique. Une
    /// ligne illisible (base modifiée à la main, format d'une ancienne version) est ignorée.
    pub fn load_recent(&self, limit: usize) -> Result<Vec<Alert>> {
        let mut stmt = self.conn.prepare("SELECT data, fingerprint FROM alerts ORDER BY id DESC LIMIT ?1")?;
        let rows = stmt.query_map([limit.min(i64::MAX as usize) as i64], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))?;
        let mut bad = 0;
        let mut alerts = Vec::new();
        for row in rows {
            let (data, fingerprint) = row?;
            match serde_json::from_str::<Alert>(&data) {
                Ok(mut a) => {
                    a.fingerprint = fingerprint;
                    alerts.push(a);
                }
                Err(_) => bad += 1,
            }
        }
        if bad > 0 {
            tracing::warn!("historique : {bad} alerte(s) illisible(s) ignorée(s)");
        }
        alerts.reverse();
        Ok(alerts)
    }

    /// Prochain identifiant à attribuer : jamais un identifiant déjà écrit, même purgé depuis.
    pub fn next_id(&self) -> Result<u64> {
        let stored: Option<i64> = self.conn.query_row("SELECT MAX(value) FROM meta WHERE key = 'next_id'", [], |r| r.get(0))?;
        Ok((stored.unwrap_or(1) as u64).max(self.max_id + 1))
    }

    /// Nombre d'alertes enregistrées.
    pub fn count(&self) -> Result<usize> {
        let n: i64 = self.conn.query_row("SELECT COUNT(*) FROM alerts", [], |r| r.get(0))?;
        Ok(n as usize)
    }
}

/// Nom sérialisé d'une valeur d'enum (`port_scan`, `high`…), le même que dans l'API.
fn name<T: Serialize>(v: &T) -> String {
    serde_json::to_value(v).ok().and_then(|v| v.as_str().map(str::to_owned)).unwrap_or_default()
}

/// L'alerte en JSON, preuves plafonnées à [`MAX_EVIDENCE_BYTES`].
fn encode(a: &Alert) -> Result<String> {
    let raw = a.evidence.to_string();
    if raw.len() <= MAX_EVIDENCE_BYTES {
        return Ok(serde_json::to_string(a)?);
    }
    let mut capped = a.clone();
    capped.evidence = serde_json::json!({
        "tronqué": true,
        "octets": raw.len(),
        "extrait": truncate(&raw, EVIDENCE_EXCERPT_BYTES),
    });
    Ok(serde_json::to_string(&capped)?)
}

/// Les `max` premiers octets de `s`, sans couper un caractère UTF-8.
fn truncate(s: &str, max: usize) -> &str {
    let mut end = max.min(s.len());
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    &s[..end]
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::alert::{AlertKind, AlertSource, Severity, TriageStatus};

    /// Alerte de test d'identifiant `id`, vue pour la dernière fois à `last_seen`.
    pub fn alert(id: u64, last_seen: DateTime<Utc>) -> Alert {
        let mut a = Alert::new(AlertKind::PortScan, Severity::High, AlertSource::Network, last_seen, format!("scan {id}"))
            .src("10.0.0.5")
            .dst("10.0.0.9")
            .evidence(serde_json::json!({ "ports": [22, 80] }));
        a.id = id;
        a.fingerprint = format!("fp-{id}");
        a
    }

    /// Fichier de base temporaire propre à un test (supprimé s'il existait déjà).
    pub fn temp_db(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("cyward-test-{}-history-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        dir.join("alerts.db")
    }

    // Une alerte écrite puis relue est identique, empreinte comprise, dans l'ordre chronologique.
    #[test]
    fn roundtrip_keeps_order_and_fingerprint() {
        let mut r = AlertRepository::in_memory();
        let t = Utc::now();
        assert_eq!(r.upsert(&[alert(1, t), alert(2, t)]).unwrap(), 2);
        let back = r.load_recent(10).unwrap();
        assert_eq!(back.iter().map(|a| a.id).collect::<Vec<_>>(), vec![1, 2]);
        assert_eq!(back[0].fingerprint, "fp-1");
        assert_eq!(back[0].evidence, serde_json::json!({ "ports": [22, 80] }));
        assert_eq!(back[0].dst.as_deref(), Some("10.0.0.9"));
    }

    // Réécrire une alerte la remplace (une seule ligne, dernier état) et ne compte pas comme nouvelle.
    #[test]
    fn upsert_replaces_existing_alert() {
        let mut r = AlertRepository::in_memory();
        let mut a = alert(1, Utc::now());
        r.upsert(std::slice::from_ref(&a)).unwrap();
        a.count = 7;
        a.triage = TriageStatus::Done;
        assert_eq!(r.upsert(&[a]).unwrap(), 0);
        let back = r.load_recent(10).unwrap();
        assert_eq!(back.len(), 1);
        assert_eq!((back[0].count, back[0].triage), (7, TriageStatus::Done));
    }

    // La purge par âge supprime les alertes anciennes et garde les récentes.
    #[test]
    fn prune_removes_old_alerts_only() {
        let mut r = AlertRepository::in_memory();
        let now = Utc::now();
        r.upsert(&[alert(1, now - chrono::Duration::days(100)), alert(2, now - chrono::Duration::days(1))]).unwrap();
        assert_eq!(r.prune(now - chrono::Duration::days(90), 1000).unwrap(), 1);
        assert_eq!(r.load_recent(10).unwrap().iter().map(|a| a.id).collect::<Vec<_>>(), vec![2]);
    }

    // Le plafond garde les alertes vues le plus récemment, même si leur identifiant est plus ancien.
    #[test]
    fn prune_caps_count_keeping_most_recent() {
        let mut r = AlertRepository::in_memory();
        let now = Utc::now();
        let alerts: Vec<_> = (1..=5).map(|i| alert(i, now - chrono::Duration::minutes(10 - i as i64))).collect();
        r.upsert(&alerts).unwrap();
        // L'alerte 1 se répète : c'est désormais la plus récente.
        r.upsert(&[alert(1, now)]).unwrap();
        assert_eq!(r.prune(now - chrono::Duration::days(90), 2).unwrap(), 3);
        assert_eq!(r.load_recent(10).unwrap().iter().map(|a| a.id).collect::<Vec<_>>(), vec![1, 5]);
    }

    // Sous les limites, la purge ne supprime rien.
    #[test]
    fn prune_within_limits_removes_nothing() {
        let mut r = AlertRepository::in_memory();
        let now = Utc::now();
        r.upsert(&[alert(1, now), alert(2, now)]).unwrap();
        assert_eq!(r.prune(now - chrono::Duration::days(90), 2).unwrap(), 0);
        assert_eq!(r.count().unwrap(), 2);
    }

    // Le chargement se limite aux plus récentes.
    #[test]
    fn load_recent_honours_limit() {
        let mut r = AlertRepository::in_memory();
        let t = Utc::now();
        r.upsert(&(1..=4).map(|i| alert(i, t)).collect::<Vec<_>>()).unwrap();
        assert_eq!(r.load_recent(2).unwrap().iter().map(|a| a.id).collect::<Vec<_>>(), vec![3, 4]);
    }

    // Le prochain identifiant survit à la réouverture, même quand toutes les alertes ont été purgées.
    #[test]
    fn next_id_survives_reopen_and_full_purge() {
        let path = temp_db("next-id");
        {
            let mut r = AlertRepository::open(&path).unwrap();
            assert_eq!(r.next_id().unwrap(), 1);
            r.upsert(&[alert(41, Utc::now())]).unwrap();
            r.prune(Utc::now() + chrono::Duration::days(1), 1000).unwrap();
            assert_eq!(r.count().unwrap(), 0);
        }
        assert_eq!(AlertRepository::open(&path).unwrap().next_id().unwrap(), 42);
    }

    // Des preuves trop longues sont remplacées par un extrait ; des preuves courtes restent intactes.
    #[test]
    fn oversized_evidence_is_capped() {
        let mut r = AlertRepository::in_memory();
        let t = Utc::now();
        let big = alert(1, t).evidence(serde_json::json!({ "ligne": "é".repeat(MAX_EVIDENCE_BYTES) }));
        r.upsert(&[big, alert(2, t)]).unwrap();
        let back = r.load_recent(10).unwrap();
        assert_eq!(back[0].evidence["tronqué"], true);
        assert!(back[0].evidence["extrait"].as_str().unwrap().len() <= EVIDENCE_EXCERPT_BYTES);
        assert_eq!(back[1].evidence, serde_json::json!({ "ports": [22, 80] }));
    }

    // Une ligne illisible n'empêche pas de recharger les autres.
    #[test]
    fn unreadable_row_is_skipped() {
        let mut r = AlertRepository::in_memory();
        r.upsert(&[alert(1, Utc::now()), alert(2, Utc::now())]).unwrap();
        r.conn.execute("UPDATE alerts SET data = '{pas du json' WHERE id = 1", []).unwrap();
        assert_eq!(r.load_recent(10).unwrap().iter().map(|a| a.id).collect::<Vec<_>>(), vec![2]);
    }

    // La troncature ne coupe jamais un caractère multi-octets.
    #[test]
    fn truncate_respects_char_boundaries() {
        assert_eq!(truncate("éé", 3), "é");
        assert_eq!(truncate("abc", 10), "abc");
    }
}
