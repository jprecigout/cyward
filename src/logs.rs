//! Surveillance des journaux système : sources de lignes (entrées/sorties), puis analyse par
//! les règles de [`rules`] (authentifications SSH, sudo/su, comptes, noyau, règles
//! personnalisées).
//!
//! Les lignes sont obtenues en lançant des commandes standard en sous-processus
//! (`journalctl -f` pour le journal systemd, `tail -F` pour les fichiers), ce qui évite toute
//! dépendance à libsystemd et gère gratuitement la rotation des fichiers.

mod rules;

use std::{
    process::Stdio,
    sync::{Arc, atomic::Ordering},
    time::Duration,
};

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use tokio::{
    io::{AsyncBufReadExt, BufReader},
    process::Command,
    sync::mpsc,
};

use self::rules::LogAnalyzer;
use crate::{
    alert::AlertSink,
    config::{AuthConfig, CustomLogRule, LogsConfig},
    stats::Stats,
};

/// Une ligne de log normalisée, quelle que soit sa source.
pub struct LogLine {
    pub ts: DateTime<Utc>,
    /// Programme émetteur (sshd, sudo…), à titre informatif.
    pub ident: String,
    pub message: String,
}

/// Lance les sources configurées et analyse leurs lignes jusqu'à l'arrêt du programme.
pub async fn run(cfg: LogsConfig, auth: AuthConfig, custom: Vec<CustomLogRule>, sink: AlertSink, stats: Arc<Stats>) -> Result<()> {
    // Échoue tout de suite si une regex personnalisée est invalide.
    let mut analyzer = LogAnalyzer::new(auth, &custom)?;
    // Toutes les sources écrivent dans un même canal ; un seul analyseur les lit, ce qui
    // permet de corréler par exemple des échecs vus dans un fichier et un succès vu dans journald.
    let (tx, mut rx) = mpsc::channel::<LogLine>(4096);

    if cfg.journald {
        let tx = tx.clone();
        // `-n 0` : seulement les nouvelles lignes ; `-o json` : champs structurés, sans ambiguïté de format.
        tokio::spawn(supervise(
            "journalctl",
            vec!["-f".into(), "-n".into(), "0".into(), "-o".into(), "json".into()],
            tx,
            parse_journal_json,
        ));
    }
    for path in cfg.files {
        let tx = tx.clone();
        // `-F` suit le fichier même après une rotation (logrotate).
        tokio::spawn(supervise("tail", vec!["-F".into(), "-n".into(), "0".into(), path], tx, parse_plain));
    }
    // Libère l'émetteur d'origine : le canal se fermera quand toutes les sources seront arrêtées.
    drop(tx);

    while let Some(line) = rx.recv().await {
        stats.log_lines.fetch_add(1, Ordering::Relaxed);
        for alert in analyzer.analyze(&line) {
            sink.emit(alert);
        }
    }
    Ok(())
}

/// Garde une commande de lecture de logs en vie, en la relançant si elle s'arrête.
async fn supervise(program: &'static str, args: Vec<String>, tx: mpsc::Sender<LogLine>, parse: fn(&str) -> Option<LogLine>) {
    loop {
        if let Err(e) = follow(program, &args, &tx, parse).await {
            tracing::warn!("source de logs `{program} {}` : {e:#}", args.join(" "));
        }
        // L'analyseur s'est arrêté : plus personne ne lit, inutile de relancer.
        if tx.is_closed() {
            return;
        }
        tokio::time::sleep(Duration::from_secs(10)).await;
    }
}

/// Exécute la commande et transmet chacune de ses lignes de sortie, une fois décodée.
async fn follow(program: &str, args: &[String], tx: &mpsc::Sender<LogLine>, parse: fn(&str) -> Option<LogLine>) -> Result<()> {
    let mut child = Command::new(program)
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        // Le sous-processus est tué si cette tâche est abandonnée.
        .kill_on_drop(true)
        .spawn()
        .with_context(|| format!("lancement de {program}"))?;
    tracing::info!("lecture des logs via `{program} {}`", args.join(" "));

    // La sortie d'erreur (ex. « permissions insuffisantes » de journalctl) est remontée en avertissement.
    if let Some(stderr) = child.stderr.take() {
        let program = program.to_string();
        tokio::spawn(async move {
            let mut lines = BufReader::new(stderr).lines();
            while let Ok(Some(l)) = lines.next_line().await {
                tracing::warn!("{program}: {l}");
            }
        });
    }

    let mut lines = BufReader::new(child.stdout.take().context("stdout absent")?).lines();
    while let Some(raw) = lines.next_line().await? {
        if let Some(line) = parse(&raw)
            && tx.send(line).await.is_err()
        {
            // Canal fermé : arrêt normal.
            return Ok(());
        }
    }
    // Fin de la sortie : le processus s'est terminé alors qu'il devait suivre indéfiniment.
    let status = child.wait().await?;
    anyhow::bail!("processus terminé ({status})")
}

/// Décode une entrée `journalctl -o json` (un objet JSON par ligne).
fn parse_journal_json(raw: &str) -> Option<LogLine> {
    let v: serde_json::Value = serde_json::from_str(raw).ok()?;
    let message = match &v["MESSAGE"] {
        serde_json::Value::String(s) => s.clone(),
        // journald encode en tableau d'octets les messages non UTF-8
        serde_json::Value::Array(bytes) => {
            String::from_utf8_lossy(&bytes.iter().filter_map(|b| b.as_u64().map(|b| b as u8)).collect::<Vec<_>>()).into_owned()
        }
        _ => return None,
    };
    let ident = v["SYSLOG_IDENTIFIER"].as_str().or(v["_COMM"].as_str()).unwrap_or("").to_string();
    // Horodatage journald : microsecondes depuis l'epoch, sous forme de chaîne.
    let ts = v["__REALTIME_TIMESTAMP"]
        .as_str()
        .and_then(|s| s.parse::<i64>().ok())
        .and_then(DateTime::from_timestamp_micros)
        .unwrap_or_else(Utc::now);
    Some(LogLine { ts, ident, message })
}

/// Décode une ligne de fichier texte. L'heure de réception sert d'horodatage.
fn parse_plain(raw: &str) -> Option<LogLine> {
    // Format syslog classique « date hôte programme[pid]: message » : on garde la ligne entière,
    // les règles ne sont pas ancrées.
    let ident = raw
        .split_whitespace()
        .find(|w| w.ends_with(':'))
        .map(|w| w.trim_end_matches(':').split('[').next().unwrap_or("").to_string())
        .unwrap_or_default();
    Some(LogLine { ts: Utc::now(), ident, message: raw.to_string() })
}

#[cfg(test)]
mod tests {
    use super::*;

    // Une entrée journald est décodée : message, programme et horodatage en microsecondes.
    #[test]
    fn journal_json_is_parsed() {
        let l = parse_journal_json(r#"{"MESSAGE":"hello","SYSLOG_IDENTIFIER":"sshd","__REALTIME_TIMESTAMP":"1762855200000000"}"#).unwrap();
        assert_eq!(l.ident, "sshd");
        assert_eq!(l.message, "hello");
        assert_eq!(l.ts.timestamp(), 1_762_855_200);
    }

    // Une ligne syslog en texte garde son message entier et en extrait le programme.
    #[test]
    fn plain_line_keeps_message_and_program() {
        let l = parse_plain("Nov 11 10:00:00 srv sshd[123]: Failed password for root from 1.2.3.4 port 22 ssh2").unwrap();
        assert_eq!(l.ident, "sshd");
        assert!(l.message.ends_with("ssh2"));
    }
}
