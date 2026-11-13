//! Règles de détection sur les lignes de logs (pattern Strategy, comme `detect::Detector`).
//!
//! Chaque règle implémente [`LogRule`] et garde son propre état. [`LogAnalyzer`] les enregistre
//! dans une liste et leur passe chaque ligne : ajouter une règle, c'est écrire une struct et
//! l'ajouter dans [`LogAnalyzer::new`], sans toucher aux autres. Tout ici est pur : aucune
//! entrée/sortie, les lignes arrivent déjà décodées de `logs.rs`.

use std::collections::{HashMap, HashSet, VecDeque};

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use regex::{Captures, Regex};
use serde_json::json;

use super::LogLine;
use crate::{
    alert::{Alert, AlertKind, AlertSource, Severity},
    config::{AuthConfig, CustomLogRule},
};

/// Capture une adresse IPv4 ou IPv6 dans un groupe nommé `ip` (volontairement permissive).
const IP: &str = r"(?P<ip>[0-9a-fA-F:.]+)";
/// Au-delà de ce nombre d'adresses suivies, `SshAuth` purge celles qui sont inactives.
const MAX_TRACKED_IPS: usize = 50_000;

/// Comportement commun des règles de logs.
///
/// Comme pour les détecteurs réseau, les alertes sont ajoutées à `out` : la plupart des
/// lignes n'en produisent aucune, inutile d'allouer un vecteur par ligne et par règle.
pub trait LogRule: Send {
    fn check(&mut self, line: &LogLine, out: &mut Vec<Alert>);
}

/// Preuves communes à la plupart des règles : la ligne brute et son programme.
fn evidence(line: &LogLine) -> serde_json::Value {
    json!({ "log": line.message, "program": line.ident })
}

/// Applique toutes les règles à chaque ligne. Une même ligne peut en déclencher plusieurs.
pub struct LogAnalyzer {
    rules: Vec<Box<dyn LogRule>>,
}

impl LogAnalyzer {
    /// Compile les règles intégrées et celles de la configuration ; échoue si une regex
    /// personnalisée est invalide. L'ordre de la liste est celui des alertes produites.
    pub fn new(cfg: AuthConfig, custom: &[CustomLogRule]) -> Result<Self> {
        // Les exemples de lignes visées sont dans les tests en bas du fichier et dans docs/detecteurs.md.
        let mut rules: Vec<Box<dyn LogRule>> = vec![
            Box::new(SshAuth::new(cfg)?),
            Box::new(Sudo::new()?),
            Box::new(Pattern::new(r"pam_unix\(su(?:-l)?:auth\): authentication failure.*?ruser=(?P<user>\S*)", su_failure)?),
            // Création de compte (useradd) : moyen classique de persistance.
            Box::new(Pattern::new(r"new user: name=(?P<user>[^,\s]+)", account_created)?),
            // Ajout à un groupe donnant des droits d'administration (usermod/gpasswd).
            Box::new(Pattern::new(
                r"add '(?P<user>[^']+)' to (?:shadow )?group '(?P<group>sudo|wheel|admin|root|docker|lxd)'",
                privileged_group,
            )?),
            // Le noyau signale lui-même une inondation SYN.
            Box::new(Pattern::new(r"Possible SYN flooding on port (?P<port>\d+)", kernel_syn_flood)?),
        ];
        for r in custom {
            rules.push(Box::new(Custom::new(r.clone())?));
        }
        Ok(Self { rules })
    }

    /// Analyse une ligne et renvoie les alertes qu'elle déclenche (souvent aucune).
    pub fn analyze(&mut self, line: &LogLine) -> Vec<Alert> {
        let mut out = Vec::new();
        for r in &mut self.rules {
            r.check(line, &mut out);
        }
        out
    }
}

/// Règle à une seule regex et sans état : la regex, et la fonction qui construit l'alerte à
/// partir de ses captures. Évite une struct par règle simple.
struct Pattern {
    re: Regex,
    build: fn(&Captures, &LogLine) -> Alert,
}

impl Pattern {
    fn new(pattern: &str, build: fn(&Captures, &LogLine) -> Alert) -> Result<Self> {
        Ok(Self { re: Regex::new(pattern)?, build })
    }
}

impl LogRule for Pattern {
    fn check(&mut self, line: &LogLine, out: &mut Vec<Alert>) {
        if let Some(c) = self.re.captures(&line.message) {
            out.push((self.build)(&c, line));
        }
    }
}

fn su_failure(c: &Captures, line: &LogLine) -> Alert {
    let user = if c["user"].is_empty() { "inconnu" } else { &c["user"] };
    Alert::new(AlertKind::PrivilegeEscalation, Severity::Low, AlertSource::Logs, line.ts, format!("Échec de su par {user}"))
        .src(user)
        .evidence(evidence(line))
}

fn account_created(c: &Captures, line: &LogLine) -> Alert {
    Alert::new(AlertKind::AccountChange, Severity::Medium, AlertSource::Logs, line.ts, format!("Nouveau compte créé : {}", &c["user"]))
        .description("Création d'un compte local. À vérifier si elle n'était pas prévue (persistance d'un attaquant).")
        .dst(&c["user"])
        .evidence(evidence(line))
}

fn privileged_group(c: &Captures, line: &LogLine) -> Alert {
    Alert::new(
        AlertKind::PrivilegeEscalation,
        Severity::High,
        AlertSource::Logs,
        line.ts,
        format!("{} ajouté au groupe privilégié {}", &c["user"], &c["group"]),
    )
    .description("Un compte a reçu des droits d'administration.")
    .dst(&c["user"])
    .evidence(evidence(line))
}

fn kernel_syn_flood(c: &Captures, line: &LogLine) -> Alert {
    Alert::new(
        AlertKind::SynFlood,
        Severity::Medium,
        AlertSource::Logs,
        line.ts,
        format!("Le noyau signale une inondation SYN sur le port {}", &c["port"]),
    )
    .dst(format!("port {}", &c["port"]))
    .evidence(evidence(line))
}

/// Historique des échecs d'authentification d'une adresse IP.
#[derive(Default)]
struct FailureTrack {
    /// Dates des échecs encore dans la fenêtre.
    times: VecDeque<DateTime<Utc>>,
    /// Comptes essayés (pour les preuves de l'alerte).
    users: HashSet<String>,
}

/// Authentifications SSH : échecs répétés d'une même IP (force brute), puis succès de cette
/// IP peu après (compte probablement compromis). Garde un état par IP.
struct SshAuth {
    cfg: AuthConfig,
    failed: Regex,
    invalid: Regex,
    accepted: Regex,
    /// Échecs d'authentification par adresse IP.
    failures: HashMap<String, FailureTrack>,
}

impl SshAuth {
    fn new(cfg: AuthConfig) -> Result<Self> {
        Ok(Self {
            cfg,
            failed: Regex::new(&format!(
                r"Failed (?:password|publickey|keyboard-interactive/pam) for (?:invalid user )?(?P<user>\S+) from {IP}"
            ))?,
            invalid: Regex::new(&format!(r"Invalid user (?P<user>\S*) from {IP}"))?,
            accepted: Regex::new(&format!(r"Accepted (?P<method>\S+) for (?P<user>\S+) from {IP}"))?,
            failures: HashMap::new(),
        })
    }

    /// Échec : fenêtre glissante par IP, alerte quand le seuil est atteint.
    fn on_failure(&mut self, c: &Captures, line: &LogLine, out: &mut Vec<Alert>) {
        let ts = line.ts;
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
                    .evidence(json!({ "failures": track.times.len(), "users": users, "last_log": line.message })),
            );
        }
    }

    /// Succès : suspect s'il suit de près des échecs de la même IP.
    fn on_success(&self, c: &Captures, line: &LogLine, out: &mut Vec<Alert>) {
        let ts = line.ts;
        let ip = &c["ip"];
        // Fenêtre plus large (×4) : un attaquant peut se connecter un peu après avoir trouvé le mot de passe.
        let window = chrono::Duration::seconds(self.cfg.window_secs * 4);
        let Some(track) = self.failures.get(ip) else { return };
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
                    .evidence(json!({ "previous_failures": recent, "log": line.message })),
            );
        }
    }
}

impl LogRule for SshAuth {
    fn check(&mut self, line: &LogLine, out: &mut Vec<Alert>) {
        let msg = line.message.as_str();
        // sshd écrit « Invalid user » puis « Failed password » pour la même tentative :
        // seul le second compte comme un échec, le premier sert à connaître les comptes essayés.
        if let Some(c) = self.invalid.captures(msg) {
            self.failures.entry(c["ip"].to_string()).or_default().users.insert(c["user"].to_string());
        }
        if let Some(c) = self.failed.captures(msg) {
            self.on_failure(&c, line, out);
        } else if let Some(c) = self.accepted.captures(msg) {
            self.on_success(&c, line, out);
        }
        // Purge occasionnelle des IP inactives, pour qu'une attaque depuis de nombreuses
        // adresses ne fasse pas croître la mémoire indéfiniment.
        if self.failures.len() > MAX_TRACKED_IPS {
            let window = chrono::Duration::seconds(self.cfg.window_secs * 4);
            self.failures.retain(|_, t| t.times.back().is_some_and(|&last| line.ts - last <= window));
        }
    }
}

/// sudo : refus (grave) ou mauvais mot de passe (moins grave). Les deux sont exclusifs : une
/// ligne de refus n'est pas comptée aussi comme échec de mot de passe.
struct Sudo {
    denied: Regex,
    fail: Regex,
}

impl Sudo {
    fn new() -> Result<Self> {
        Ok(Self {
            denied: Regex::new(r"(?P<user>\S+) : (?:user NOT in sudoers|command not allowed)")?,
            fail: Regex::new(r"(?P<user>\S+) : (?P<n>\d+) incorrect password attempts?")?,
        })
    }
}

impl LogRule for Sudo {
    fn check(&mut self, line: &LogLine, out: &mut Vec<Alert>) {
        if let Some(c) = self.denied.captures(&line.message) {
            out.push(
                Alert::new(
                    AlertKind::PrivilegeEscalation,
                    Severity::High,
                    AlertSource::Logs,
                    line.ts,
                    format!("Tentative sudo non autorisée par {}", &c["user"]),
                )
                .description("Un utilisateur sans droits sudo a tenté d'exécuter une commande privilégiée.")
                .src(&c["user"])
                .evidence(evidence(line)),
            );
        } else if let Some(c) = self.fail.captures(&line.message) {
            out.push(
                Alert::new(
                    AlertKind::PrivilegeEscalation,
                    Severity::Medium,
                    AlertSource::Logs,
                    line.ts,
                    format!("Échecs de mot de passe sudo pour {}", &c["user"]),
                )
                .description(format!("{} tentative(s) de mot de passe incorrect(es) pour sudo.", &c["n"]))
                .src(&c["user"])
                .evidence(evidence(line)),
            );
        }
    }
}

/// Règle personnalisée de la configuration (`[[rules]]`).
struct Custom {
    rule: CustomLogRule,
    re: Regex,
}

impl Custom {
    fn new(rule: CustomLogRule) -> Result<Self> {
        let re = Regex::new(&rule.pattern).with_context(|| format!("règle {}", rule.name))?;
        Ok(Self { rule, re })
    }
}

impl LogRule for Custom {
    fn check(&mut self, line: &LogLine, out: &mut Vec<Alert>) {
        let Some(c) = self.re.captures(&line.message) else { return };
        let ip = c.name("ip").map(|m| m.as_str());
        // Empreinte par règle et par IP : une même IP répétant le motif est fusionnée.
        let mut a = Alert::new(AlertKind::CustomRule, self.rule.severity, AlertSource::Logs, line.ts, self.rule.title.clone())
            .description(format!("Règle personnalisée « {} ».", self.rule.name))
            .fingerprint(format!("custom|{}|{}", self.rule.name, ip.unwrap_or("")))
            .evidence(evidence(line));
        if let Some(ip) = ip {
            a = a.src(ip);
        }
        out.push(a);
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
        assert!(
            a.analyze(&line(Utc::now(), "Accepted publickey for jerome from 192.168.1.2 port 4242 ssh2: ED25519 SHA256:abc")).is_empty()
        );
    }

    // Refus sudo, création de compte et ajout à un groupe privilégié.
    #[test]
    fn sudo_and_accounts() {
        let mut a = LogAnalyzer::new(AuthConfig::default(), &[]).unwrap();
        let t = Utc::now();
        assert_eq!(
            a.analyze(&line(t, "bob : user NOT in sudoers ; TTY=pts/1 ; PWD=/home/bob ; USER=root ; COMMAND=/bin/bash"))[0].severity,
            Severity::High
        );
        assert_eq!(
            a.analyze(&line(t, "new user: name=backdoor, UID=1001, GID=1001, home=/home/backdoor, shell=/bin/bash, from=/dev/pts/0"))[0]
                .kind,
            AlertKind::AccountChange
        );
        assert_eq!(a.analyze(&line(t, "add 'backdoor' to group 'sudo'"))[0].kind, AlertKind::PrivilegeEscalation);
    }

    // Les règles simples (su, noyau) produisent chacune une alerte, avec leurs captures.
    #[test]
    fn single_pattern_rules() {
        let mut a = LogAnalyzer::new(AuthConfig::default(), &[]).unwrap();
        let t = Utc::now();
        let su = a.analyze(&line(
            t,
            "pam_unix(su:auth): authentication failure; logname=bob uid=1000 euid=0 tty=/dev/pts/1 ruser=bob rhost=  user=root",
        ));
        assert_eq!((su.len(), su[0].src.as_deref()), (1, Some("bob")));
        let k = a.analyze(&line(t, "TCP: request_sock_TCP: Possible SYN flooding on port 80. Sending cookies."));
        assert_eq!((k[0].kind, k[0].dst.as_deref()), (AlertKind::SynFlood, Some("port 80")));
    }

    // Des lignes ordinaires ne déclenchent aucune règle.
    #[test]
    fn ordinary_lines_are_quiet() {
        let mut a = LogAnalyzer::new(AuthConfig::default(), &[]).unwrap();
        let t = Utc::now();
        for msg in [
            "Started Daily apt download activities.",
            "bob : TTY=pts/1 ; PWD=/home/bob ; USER=root ; COMMAND=/usr/bin/apt update",
            "pam_unix(sshd:session): session opened for user bob",
        ] {
            assert!(a.analyze(&line(t, msg)).is_empty(), "{msg}");
        }
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

    // Une regex personnalisée invalide est refusée au démarrage, avec le nom de la règle.
    #[test]
    fn invalid_custom_regex_is_rejected() {
        let rule = CustomLogRule { name: "cassée".into(), pattern: "(".into(), severity: Severity::Low, title: "x".into() };
        let err = LogAnalyzer::new(AuthConfig::default(), &[rule]).err().unwrap();
        assert!(format!("{err:#}").contains("cassée"));
    }
}
