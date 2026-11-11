//! Surveillance des journaux système : authentifications SSH, sudo/su, comptes, noyau,
//! et règles personnalisées.
//!
//! Les lignes sont obtenues en lançant des commandes standard en sous-processus
//! (`journalctl -f` pour le journal systemd, `tail -F` pour les fichiers), ce qui évite toute
//! dépendance à libsystemd et gère gratuitement la rotation des fichiers.

use std::{
    collections::{HashMap, HashSet, VecDeque},
    process::Stdio,
    sync::{Arc, atomic::Ordering},
    time::Duration,
};

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use regex::Regex;
use serde_json::json;
use tokio::{
    io::{AsyncBufReadExt, BufReader},
    process::Command,
    sync::mpsc,
};

use crate::{
    alert::{Alert, AlertKind, AlertSink, AlertSource, Severity},
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
        tokio::spawn(supervise("journalctl", vec!["-f".into(), "-n".into(), "0".into(), "-o".into(), "json".into()], tx, parse_journal_json));
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
        serde_json::Value::Array(bytes) => String::from_utf8_lossy(&bytes.iter().filter_map(|b| b.as_u64().map(|b| b as u8)).collect::<Vec<_>>()).into_owned(),
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
    let ident = raw.split_whitespace().find(|w| w.ends_with(':')).map(|w| w.trim_end_matches(':').split('[').next().unwrap_or("").to_string()).unwrap_or_default();
    Some(LogLine { ts: Utc::now(), ident, message: raw.to_string() })
}

/// Historique des échecs d'authentification d'une adresse IP.
#[derive(Default)]
struct FailureTrack {
    /// Dates des échecs encore dans la fenêtre.
    times: VecDeque<DateTime<Utc>>,
    /// Comptes essayés (pour les preuves de l'alerte).
    users: HashSet<String>,
}

/// Applique les règles aux lignes de logs. Garde un état par IP pour les corrélations
/// (échecs répétés, succès après échecs).
pub struct LogAnalyzer {
    cfg: AuthConfig,
    // Règles intégrées, compilées une seule fois.
    failed: Regex,
    invalid: Regex,
    accepted: Regex,
    sudo_fail: Regex,
    sudo_denied: Regex,
    su_fail: Regex,
    useradd: Regex,
    priv_group: Regex,
    syn_flood: Regex,
    /// Règles de la configuration, avec leur regex compilée.
    custom: Vec<(CustomLogRule, Regex)>,
    /// Échecs d'authentification par adresse IP.
    failures: HashMap<String, FailureTrack>,
}

impl LogAnalyzer {
    pub fn new(cfg: AuthConfig, custom: &[CustomLogRule]) -> Result<Self> {
        // Capture une adresse IPv4 ou IPv6 (volontairement permissive).
        const IP: &str = r"(?P<ip>[0-9a-fA-F:.]+)";
        Ok(Self {
            cfg,
            // Les exemples de lignes visées sont dans les tests en bas du fichier et dans le README.
            failed: Regex::new(&format!(r"Failed (?:password|publickey|keyboard-interactive/pam) for (?:invalid user )?(?P<user>\S+) from {IP}"))?,
            invalid: Regex::new(&format!(r"Invalid user (?P<user>\S*) from {IP}"))?,
            accepted: Regex::new(&format!(r"Accepted (?P<method>\S+) for (?P<user>\S+) from {IP}"))?,
            sudo_fail: Regex::new(r"(?P<user>\S+) : (?P<n>\d+) incorrect password attempts?")?,
            sudo_denied: Regex::new(r"(?P<user>\S+) : (?:user NOT in sudoers|command not allowed)")?,
            su_fail: Regex::new(r"pam_unix\(su(?:-l)?:auth\): authentication failure.*?ruser=(?P<user>\S*)")?,
            useradd: Regex::new(r"new user: name=(?P<user>[^,\s]+)")?,
            priv_group: Regex::new(r"add '(?P<user>[^']+)' to (?:shadow )?group '(?P<group>sudo|wheel|admin|root|docker|lxd)'")?,
            syn_flood: Regex::new(r"Possible SYN flooding on port (?P<port>\d+)")?,
            custom: custom
                .iter()
                .map(|r| Regex::new(&r.pattern).map(|re| (r.clone(), re)).with_context(|| format!("règle {}", r.name)))
                .collect::<Result<_>>()?,
            failures: HashMap::new(),
        })
    }

    /// Analyse une ligne et renvoie les alertes qu'elle déclenche (souvent aucune).
    /// Une même ligne peut déclencher plusieurs règles.
    pub fn analyze(&mut self, line: &LogLine) -> Vec<Alert> {
        let mut out = Vec::new();
        let msg = line.message.as_str();
        let ts = line.ts;
        // Preuves communes à la plupart des règles : la ligne brute et son programme.
        let evidence = || json!({ "log": msg, "program": line.ident });

        // sshd écrit « Invalid user » puis « Failed password » pour la même tentative :
        // seul le second compte comme un échec, le premier sert à connaître les comptes essayés.
        if let Some(c) = self.invalid.captures(msg) {
            self.failures.entry(c["ip"].to_string()).or_default().users.insert(c["user"].to_string());
        }

        // --- Échecs SSH : fenêtre glissante par IP ---
        if let Some(c) = self.failed.captures(msg) {
            let ip = c["ip"].to_string();
            let window = chrono::Duration::seconds(self.cfg.window_secs);
            let track = self.failures.entry(ip.clone()).or_default();
            track.times.push_back(ts);
            track.users.insert(c["user"].to_string());
            // Retire les échecs sortis de la fenêtre.
            while track.times.front().is_some_and(|&t| ts - t > window) {
                track.times.pop_front();
            }
            // `==` : une seule alerte quand le seuil est franchi, pas une par échec supplémentaire.
            if track.times.len() == self.cfg.failures_threshold {
                let users: Vec<_> = track.users.iter().take(20).cloned().collect();
                out.push(
                    Alert::new(AlertKind::AuthBruteForce, Severity::High, AlertSource::Logs, ts, format!("Force brute SSH depuis {ip}"))
                        .description(format!(
                            "{} échecs d'authentification en moins de {} s, {} compte(s) essayé(s).",
                            track.times.len(),
                            self.cfg.window_secs,
                            track.users.len()
                        ))
                        .src(&ip)
                        .evidence(json!({ "failures": track.times.len(), "users": users, "last_log": msg })),
                );
            }
        // --- Succès SSH : suspect s'il suit de près des échecs de la même IP ---
        } else if let Some(c) = self.accepted.captures(msg) {
            let ip = &c["ip"];
            // Fenêtre plus large (×4) : un attaquant peut se connecter un peu après avoir trouvé le mot de passe.
            let window = chrono::Duration::seconds(self.cfg.window_secs * 4);
            if let Some(track) = self.failures.get(ip) {
                let recent = track.times.iter().filter(|&&t| ts - t <= window).count();
                // Il suffit de la moitié du seuil d'échecs (arrondie au-dessus) pour rendre un succès suspect.
                if recent >= self.cfg.failures_threshold.div_ceil(2) {
                    out.push(
                        Alert::new(AlertKind::AuthCompromise, Severity::Critical, AlertSource::Logs, ts, format!("Connexion réussie de {} après {recent} échecs", &c["user"]))
                            .description(format!(
                                "{ip} a ouvert une session ({}) sur le compte {} juste après une série d'échecs : le mot de passe a peut-être été trouvé.",
                                &c["method"],
                                &c["user"]
                            ))
                            .src(ip)
                            .dst(&c["user"])
                            .evidence(json!({ "previous_failures": recent, "log": msg })),
                    );
                }
            }
        }

        // --- sudo : refus (grave) ou mauvais mot de passe (moins grave) ---
        if let Some(c) = self.sudo_denied.captures(msg) {
            out.push(
                Alert::new(AlertKind::PrivilegeEscalation, Severity::High, AlertSource::Logs, ts, format!("Tentative sudo non autorisée par {}", &c["user"]))
                    .description("Un utilisateur sans droits sudo a tenté d'exécuter une commande privilégiée.")
                    .src(&c["user"])
                    .evidence(evidence()),
            );
        } else if let Some(c) = self.sudo_fail.captures(msg) {
            out.push(
                Alert::new(AlertKind::PrivilegeEscalation, Severity::Medium, AlertSource::Logs, ts, format!("Échecs de mot de passe sudo pour {}", &c["user"]))
                    .description(format!("{} tentative(s) de mot de passe incorrect(es) pour sudo.", &c["n"]))
                    .src(&c["user"])
                    .evidence(evidence()),
            );
        }

        // --- su : échec d'authentification ---
        if let Some(c) = self.su_fail.captures(msg) {
            let user = if c["user"].is_empty() { "inconnu" } else { &c["user"] };
            out.push(
                Alert::new(AlertKind::PrivilegeEscalation, Severity::Low, AlertSource::Logs, ts, format!("Échec de su par {user}"))
                    .src(user)
                    .evidence(evidence()),
            );
        }

        // --- Création de compte (useradd) : moyen classique de persistance ---
        if let Some(c) = self.useradd.captures(msg) {
            out.push(
                Alert::new(AlertKind::AccountChange, Severity::Medium, AlertSource::Logs, ts, format!("Nouveau compte créé : {}", &c["user"]))
                    .description("Création d'un compte local. À vérifier si elle n'était pas prévue (persistance d'un attaquant).")
                    .dst(&c["user"])
                    .evidence(evidence()),
            );
        }

        // --- Ajout à un groupe donnant des droits d'administration (usermod/gpasswd) ---
        if let Some(c) = self.priv_group.captures(msg) {
            out.push(
                Alert::new(AlertKind::PrivilegeEscalation, Severity::High, AlertSource::Logs, ts, format!("{} ajouté au groupe privilégié {}", &c["user"], &c["group"]))
                    .description("Un compte a reçu des droits d'administration.")
                    .dst(&c["user"])
                    .evidence(evidence()),
            );
        }

        // --- Le noyau signale lui-même une inondation SYN ---
        if let Some(c) = self.syn_flood.captures(msg) {
            out.push(
                Alert::new(AlertKind::SynFlood, Severity::Medium, AlertSource::Logs, ts, format!("Le noyau signale une inondation SYN sur le port {}", &c["port"]))
                    .dst(format!("port {}", &c["port"]))
                    .evidence(evidence()),
            );
        }

        // --- Règles personnalisées ---
        for (rule, re) in &self.custom {
            if let Some(c) = re.captures(msg) {
                // Empreinte par règle et par IP : une même IP répétant le motif est fusionnée.
                let mut a = Alert::new(AlertKind::CustomRule, rule.severity, AlertSource::Logs, ts, rule.title.clone())
                    .description(format!("Règle personnalisée « {} ».", rule.name))
                    .fingerprint(format!("custom|{}|{}", rule.name, c.name("ip").map(|m| m.as_str()).unwrap_or("")))
                    .evidence(evidence());
                if let Some(ip) = c.name("ip") {
                    a = a.src(ip.as_str());
                }
                out.push(a);
            }
        }

        // Purge occasionnelle des IP inactives, pour qu'une attaque depuis de nombreuses
        // adresses ne fasse pas croître la mémoire indéfiniment.
        if self.failures.len() > 50_000 {
            let window = chrono::Duration::seconds(self.cfg.window_secs * 4);
            self.failures.retain(|_, t| t.times.back().is_some_and(|&last| ts - last <= window));
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn line(ts: DateTime<Utc>, msg: &str) -> LogLine {
        LogLine { ts, ident: "sshd".into(), message: msg.into() }
    }

    // 8 échecs → une alerte de force brute, puis le succès de la même IP → alerte critique.
    #[test]
    fn ssh_bruteforce_then_success() {
        let mut a = LogAnalyzer::new(AuthConfig::default(), &[]).unwrap();
        let t0 = Utc::now();
        let mut alerts = Vec::new();
        for i in 0..8 {
            let msg = format!("Failed password for invalid user admin{i} from 203.0.113.4 port 5{i}222 ssh2");
            alerts.extend(a.analyze(&line(t0 + chrono::Duration::seconds(i), &msg)));
        }
        assert_eq!(alerts.len(), 1);
        assert_eq!(alerts[0].kind, AlertKind::AuthBruteForce);

        let ok = a.analyze(&line(t0 + chrono::Duration::seconds(20), "Accepted password for root from 203.0.113.4 port 50000 ssh2"));
        assert_eq!(ok.len(), 1);
        assert_eq!(ok[0].kind, AlertKind::AuthCompromise);
        assert_eq!(ok[0].severity, Severity::Critical);
    }

    // Une connexion normale sans échec préalable ne lève rien.
    #[test]
    fn normal_login_is_quiet() {
        let mut a = LogAnalyzer::new(AuthConfig::default(), &[]).unwrap();
        assert!(a.analyze(&line(Utc::now(), "Accepted publickey for jerome from 192.168.1.2 port 4242 ssh2: ED25519 SHA256:abc")).is_empty());
    }

    #[test]
    fn sudo_and_accounts() {
        let mut a = LogAnalyzer::new(AuthConfig::default(), &[]).unwrap();
        let t = Utc::now();
        assert_eq!(a.analyze(&line(t, "bob : user NOT in sudoers ; TTY=pts/1 ; PWD=/home/bob ; USER=root ; COMMAND=/bin/bash"))[0].severity, Severity::High);
        assert_eq!(a.analyze(&line(t, "new user: name=backdoor, UID=1001, GID=1001, home=/home/backdoor, shell=/bin/bash, from=/dev/pts/0"))[0].kind, AlertKind::AccountChange);
        assert_eq!(a.analyze(&line(t, "add 'backdoor' to group 'sudo'"))[0].kind, AlertKind::PrivilegeEscalation);
    }

    // Le groupe nommé `ip` d'une règle personnalisée devient la source de l'alerte.
    #[test]
    fn custom_rule_extracts_ip() {
        let rule = CustomLogRule {
            name: "nginx-wp".into(),
            pattern: r#"(?P<ip>\d+\.\d+\.\d+\.\d+) .*"(?:GET|POST) /wp-login\.php"#.into(),
            severity: Severity::Low,
            title: "Sonde WordPress".into(),
        };
        let mut a = LogAnalyzer::new(AuthConfig::default(), &[rule]).unwrap();
        let out = a.analyze(&line(Utc::now(), r#"198.51.100.3 - - [11/Nov/2026:10:00:00 +0000] "POST /wp-login.php HTTP/1.1" 404"#));
        assert_eq!(out[0].src.as_deref(), Some("198.51.100.3"));
    }

    #[test]
    fn journal_json_is_parsed() {
        let l = parse_journal_json(r#"{"MESSAGE":"hello","SYSLOG_IDENTIFIER":"sshd","__REALTIME_TIMESTAMP":"1762855200000000"}"#).unwrap();
        assert_eq!(l.ident, "sshd");
        assert_eq!(l.message, "hello");
        assert_eq!(l.ts.timestamp(), 1_762_855_200);
    }
}
