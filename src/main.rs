//! Point d'entrée de Cyward : interface en ligne de commande et assemblage des tâches.
//!
//! Le programme relie entre elles des tâches indépendantes qui communiquent par canaux :
//!
//! ```text
//! capture (thread) ──PacketMeta──► run_engine ──┐
//! logs (tâche tokio) ───────────────────────────┼──► AlertSink ──► AlertStore ──► dashboard (SSE)
//!                                               │        │          ├──► notifications
//!                                               │        │          └──► historique (SQLite)
//!                                               │        └──► file de triage ──► LLM
//! ```
//!
//! Chaque module ne connaît que ses voisins immédiats : les détecteurs ignorent le LLM et le
//! dashboard, le LLM ignore d'où viennent les alertes.

// Déclaration des modules du crate (un fichier ou dossier par module dans src/).
mod alert;
mod anomaly;
mod banner;
mod capture;
mod config;
mod detect;
mod history;
mod llm;
mod logs;
mod names;
mod notify;
mod stats;
mod web;

use std::{
    path::PathBuf,
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};

use anyhow::Result;
use clap::{Parser, Subcommand};
use tokio::sync::mpsc;
use tracing_subscriber::EnvFilter;

use crate::{
    alert::{AlertSink, AlertStore},
    anomaly::baseline::Baseline,
    capture::PacketMeta,
    config::{AnomalyMode, Config},
    detect::Engine,
    history::History,
    stats::Stats,
};

/// Nombre d'alertes gardées en mémoire (dashboard, API), et rechargées depuis l'historique au démarrage.
const STORE_CAPACITY: usize = 5000;

// Arguments de la ligne de commande, analysés par clap à partir de ces structures.
// Les commentaires `///` des champs deviennent le texte d'aide de `cyward --help` : on n'y
// met donc que des phrases destinées à l'utilisateur, et des `//` pour les notes de code.
#[derive(Parser)]
#[command(version, about = "Agent de détection d'attaques réseau et système, avec triage par un LLM cyber local")]
struct Cli {
    /// Fichier de configuration TOML (voir config.example.toml).
    // `global = true` : l'option est acceptée avant comme après la sous-commande.
    #[arg(short, long, global = true)]
    config: Option<PathBuf>,
    #[command(subcommand)]
    command: Command,
}

// Sous-commandes disponibles (même remarque : les `///` sont affichés par --help).
#[derive(Subcommand)]
enum Command {
    /// Surveille le réseau et les logs en continu, avec le dashboard web.
    Run {
        /// Interface réseau (remplace capture.interface).
        #[arg(short, long)]
        interface: Option<String>,
        // Les trois options suivantes désactivent un étage du pipeline sans modifier le fichier de config.
        #[arg(long)]
        no_capture: bool,
        #[arg(long)]
        no_logs: bool,
        #[arg(long)]
        no_llm: bool,
    },
    /// Passe un fichier pcap dans les détecteurs (tests, analyse après incident).
    Replay {
        file: PathBuf,
        /// Garder le dashboard et le triage LLM actifs après le rejeu.
        #[arg(long)]
        serve: bool,
    },
    /// Liste les interfaces réseau disponibles.
    Interfaces,
    /// Vérifie que le modèle répond, avec une alerte d'exemple.
    CheckLlm,
    /// Envoie une notification de test sur chaque canal configuré ([[notify.channels]]).
    CheckNotify,
}

// `#[tokio::main]` crée le runtime asynchrone multi-thread qui exécute toutes les tâches.
#[tokio::main]
async fn main() -> Result<()> {
    // Journalisation sur la sortie standard. Le niveau se règle avec la variable RUST_LOG
    // (ex. RUST_LOG=debug) ; par défaut « info ».
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")))
        .with_target(false)
        // Mêmes règles que la bannière : pas de codes couleur hors terminal ni avec NO_COLOR,
        // sinon `docker logs` et le journal systemd seraient pollués de séquences ANSI.
        .with_ansi(banner::use_color())
        .init();

    let cli = Cli::parse();
    // Sans -c, toutes les valeurs par défaut de config.rs s'appliquent.
    let mut cfg = Config::load(cli.config.as_deref())?;

    match cli.command {
        Command::Interfaces => {
            // Une ligne par interface : nom, état, adresses IP.
            for i in capture::list_interfaces() {
                let ips: Vec<_> = i.ips.iter().map(|ip| ip.to_string()).collect();
                println!("{:<16} {:<5} {}", i.name, if i.is_up() { "up" } else { "down" }, ips.join(", "));
            }
            Ok(())
        }
        Command::CheckLlm => {
            println!("Interrogation de {} sur {}…", cfg.llm.model, cfg.llm.base_url);
            let a = llm::self_test(cfg.llm).await?;
            println!("{}", serde_json::to_string_pretty(&a)?);
            Ok(())
        }
        Command::CheckNotify => notify::check(&cfg.notify).await,
        Command::Run { interface, no_capture, no_logs, no_llm } => {
            // Les options de la ligne de commande l'emportent sur le fichier de configuration.
            if let Some(i) = interface {
                cfg.capture.interface = i;
            }
            // `&=` : une option --no-xxx peut désactiver un étage, jamais l'activer s'il est coupé dans la config.
            cfg.capture.enabled &= !no_capture;
            cfg.logs.enabled &= !no_logs;
            cfg.llm.enabled &= !no_llm;
            let capture = match (cfg.capture.enabled, cfg.capture.interface.as_str()) {
                (false, _) => "désactivée".to_string(),
                (true, "") => "interface de la route par défaut".to_string(),
                (true, name) => name.to_string(),
            };
            let baseline = open_baseline(&cfg)?;
            print!("{}", banner::render(&banner_info(&cfg, capture, baseline.as_deref()), banner::use_color()));
            run(cfg, baseline).await
        }
        Command::Replay { file, serve } => replay(cfg, file, serve).await,
    }
}

/// Lignes de résumé affichées sous la bannière : ce que l'agent va réellement faire, une fois
/// la configuration et les options de la ligne de commande appliquées. `capture` décrit la
/// source des paquets (interface ou fichier rejoué) ; `baseline` l'apprentissage du
/// comportement normal, s'il est activé.
fn banner_info(cfg: &Config, capture: String, baseline: Option<&Baseline>) -> Vec<(&'static str, String)> {
    let dashboard = if cfg.web.token.is_empty() {
        format!("http://{}", cfg.web.listen)
    } else {
        format!("http://{}/?token=…", cfg.web.listen)
    };
    let logs = if cfg.logs.enabled {
        // Ex. « journald + 2 fichier(s) » ; « aucune source » si tout est vide dans la config.
        let mut sources = Vec::new();
        if cfg.logs.journald {
            sources.push("journald".to_string());
        }
        if !cfg.logs.files.is_empty() {
            sources.push(format!("{} fichier(s)", cfg.logs.files.len()));
        }
        if sources.is_empty() { "aucune source".to_string() } else { sources.join(" + ") }
    } else {
        "désactivés".to_string()
    };
    let model = if cfg.llm.enabled { cfg.llm.model.clone() } else { "désactivé".to_string() };
    // Ex. « observation · modèle v3 » ou « alerte · apprentissage en cours ».
    let normality = match baseline {
        None => "désactivée".to_string(),
        Some(b) => {
            let mode = match b.config().mode {
                AnomalyMode::Observation => "observation",
                AnomalyMode::Alert => "alerte",
            };
            let model = b.active_version().map(|v| format!("modèle v{v}")).unwrap_or_else(|| "apprentissage en cours".into());
            format!("{mode} · {model}")
        }
    };
    // Ex. « /var/lib/cyward/alerts.db (90 j, 100000 max) ».
    let history = if cfg.history.path.is_empty() {
        "en mémoire".to_string()
    } else {
        format!("{} ({} j, {} max)", cfg.history.path, cfg.history.retention_days, cfg.history.max_alerts)
    };
    // Ex. « 2 canal(aux) » ; les adresses ne sont pas affichées, car elles peuvent contenir un secret.
    let notifications = if cfg.notify.enabled { format!("{} canal(aux)", cfg.notify.channels.len()) } else { "désactivées".to_string() };
    vec![("Dashboard", dashboard), ("Capture", capture), ("Logs", logs), ("Modèle IA", model), ("Normalité", normality), ("Historique", history), ("Notifications", notifications)]
}

/// Ouvre l'apprentissage du comportement normal s'il est activé (et recharge son état disque).
fn open_baseline(cfg: &Config) -> Result<Option<Arc<Baseline>>> {
    if !cfg.detection.anomaly.enabled {
        return Ok(None);
    }
    Ok(Some(Arc::new(Baseline::open(cfg.detection.anomaly.clone())?)))
}

/// Démarre la partie commune à `run` et `replay --serve` : stockage des alertes, historique
/// sur disque, worker LLM, entraîneur du comportement normal, notifications (chacun s'il est
/// activé) et serveur web. Renvoie le point d'entrée des alertes, et l'historique pour la
/// dernière écriture à l'arrêt.
fn start_pipeline(cfg: &Config, stats: &Arc<Stats>, baseline: Option<Arc<Baseline>>) -> Result<(AlertSink, Option<History>)> {
    *stats.started_at.lock() = Some(chrono::Utc::now());
    let store = Arc::new(AlertStore::new(STORE_CAPACITY, cfg.detection.alert_cooldown_secs));
    // En premier : les alertes rechargées sont dans le store avant que le dashboard ne les serve.
    let history = if cfg.history.path.is_empty() { None } else { Some(history::spawn(cfg.history.clone(), store.clone(), STORE_CAPACITY)?) };
    // `triage` est l'émetteur de la file vers le LLM ; None si le LLM est désactivé.
    let triage = if cfg.llm.enabled { Some(llm::spawn(cfg.llm.clone(), store.clone(), stats.clone())?) } else { None };
    let sink = AlertSink::new(store.clone(), triage, cfg.llm.min_severity);
    if let Some(b) = &baseline {
        anomaly::trainer::spawn(b.clone(), sink.clone());
    }
    if cfg.notify.enabled {
        notify::spawn(cfg.notify.clone(), store.clone())?;
    }

    // Le serveur web tourne dans sa propre tâche ; une erreur (port occupé…) est journalisée
    // sans arrêter la détection.
    let (listen, token) = (cfg.web.listen.clone(), cfg.web.token.clone());
    let (web_sink, stats) = (sink.clone(), stats.clone());
    // Les mêmes réseaux internes que la détection décident des adresses dont on demande le nom.
    let resolver = Arc::new(names::Resolver::new(cfg.names.clone(), cfg.detection.local_networks.clone()));
    tokio::spawn(async move {
        if let Err(e) = web::serve(&listen, token, web_sink, stats, baseline, resolver).await {
            tracing::error!("dashboard arrêté : {e:#}");
        }
    });
    Ok((sink, history))
}

/// Mode surveillance continue (`cyward run`).
async fn run(cfg: Config, baseline: Option<Arc<Baseline>>) -> Result<()> {
    let stats = Arc::new(Stats::default());
    let (sink, history) = start_pipeline(&cfg, &stats, baseline.clone())?;

    if cfg.capture.enabled {
        let iface = capture::pick_interface(&cfg.capture.interface)?;
        tracing::info!("capture sur {} ({})", iface.name, iface.ips.iter().map(|i| i.to_string()).collect::<Vec<_>>().join(", "));
        *stats.interface.lock() = Some(iface.name.clone());
        // Canal borné entre le thread de capture et le moteur : s'il est plein, la capture
        // abandonne des paquets plutôt que de bloquer (voir capture::spawn_live).
        let (tx, rx) = mpsc::channel(cfg.capture.queue_size);
        capture::spawn_live(iface, cfg.capture.promiscuous, tx, stats.clone())?;
        tokio::spawn(run_engine(Engine::new(&cfg.detection, baseline.clone()), rx, sink.clone(), true));
    }

    if cfg.logs.enabled {
        // Clones nécessaires : la tâche prend possession de ses données (`async move`).
        let (logs, auth, custom) = (cfg.logs.clone(), cfg.detection.auth.clone(), cfg.detection.custom_log_rules.clone());
        let (sink, stats) = (sink.clone(), stats.clone());
        tokio::spawn(async move {
            if let Err(e) = logs::run(logs, auth, custom, sink, stats).await {
                tracing::error!("analyse des logs arrêtée : {e:#}");
            }
        });
    }

    if !cfg.capture.enabled && !cfg.logs.enabled {
        anyhow::bail!("ni capture ni logs activés : rien à surveiller");
    }

    // Toutes les tâches tournent en arrière-plan ; on attend simplement Ctrl+C (ou SIGINT).
    tokio::signal::ctrl_c().await?;
    tracing::info!("arrêt");
    // Écriture finale : les alertes modifiées depuis le dernier lot (5 s au plus).
    if let Some(h) = &history {
        h.flush().await;
    }
    // Sauvegarde finale : les fenêtres apprises depuis la dernière sauvegarde périodique.
    if let Some(b) = &baseline {
        b.save()?;
    }
    Ok(())
}

/// Mode rejeu (`cyward replay`) : passe un pcap dans les détecteurs puis affiche le bilan.
async fn replay(mut cfg: Config, file: PathBuf, serve: bool) -> Result<()> {
    // Sans --serve, personne ne verrait les analyses : inutile de solliciter le LLM.
    cfg.llm.enabled &= serve;
    // Les alertes d'un pcap (dates d'origine, attaques simulées) n'ont rien à faire dans
    // l'historique de la surveillance : le rejeu reste en mémoire.
    cfg.history.path.clear();
    let stats = Arc::new(Stats::default());
    // Le nom du fichier s'affiche à la place de l'interface dans le dashboard.
    *stats.interface.lock() = file.file_name().map(|n| n.to_string_lossy().into_owned());
    let baseline = open_baseline(&cfg)?;
    let sink = if serve {
        // Bannière seulement avec --serve : sans, la sortie est un rapport destiné à être lu
        // ou traité par un script, que la bannière encombrerait.
        // Le rejeu ne lit jamais les logs système : on le reflète dans la config pour que le
        // résumé de la bannière affiche « désactivés » plutôt que « journald ».
        cfg.logs.enabled = false;
        let source = format!("rejeu de {}", file.display());
        print!("{}", banner::render(&banner_info(&cfg, source, baseline.as_deref()), banner::use_color()));
        start_pipeline(&cfg, &stats, baseline.clone())?.0
    } else {
        // Store seul, sans dashboard ni LLM, assez grand pour garder toutes les alertes du fichier.
        AlertSink::new(Arc::new(AlertStore::new(100_000, cfg.detection.alert_cooldown_secs)), None, cfg.llm.min_severity)
    };

    let (tx, rx) = mpsc::channel(4096);
    // `live = false` : pas de tick sur l'horloge murale, seul le temps du pcap compte.
    let engine = tokio::spawn(run_engine(Engine::new(&cfg.detection, baseline.clone()), rx, sink.clone(), false));
    capture::replay(&file, tx, stats.clone()).await?;
    // `replay` a rendu l'émetteur du canal : le moteur termine dès qu'il a vidé la file.
    engine.await?;
    // Les fenêtres du pcap enrichissent l'apprentissage : on les enregistre tout de suite.
    if let Some(b) = &baseline {
        b.save()?;
    }

    let alerts = sink.store.list(usize::MAX);
    let s = stats.snapshot();
    println!("{} paquets, {} octets analysés, {} alerte(s)", s.packets, s.bytes, alerts.len());
    // `list` renvoie les plus récentes d'abord ; on affiche dans l'ordre chronologique.
    for a in alerts.iter().rev() {
        println!("[{:>8}] {} {}  (x{})", format!("{:?}", a.severity), a.first_seen.format("%Y-%m-%d %H:%M:%S"), a.title, a.count);
    }

    if serve {
        tracing::info!("rejeu terminé, dashboard actif (Ctrl+C pour quitter)");
        tokio::signal::ctrl_c().await?;
    }
    Ok(())
}

/// Boucle du moteur de détection : consomme les paquets et transmet les alertes produites.
///
/// En mode live, un tick par seconde sur l'horloge murale permet aux détecteurs de clore
/// leurs fenêtres même quand aucun paquet n'arrive.
async fn run_engine(mut engine: Engine, mut rx: mpsc::Receiver<PacketMeta>, sink: AlertSink, live: bool) {
    let mut ticker = tokio::time::interval(std::time::Duration::from_secs(1));
    // Horodatage du dernier paquet vu, pour le tick de fin de rejeu.
    let mut last_ts = 0.0;
    loop {
        // `select!` attend le premier des deux événements : un paquet, ou le tick (live seulement).
        tokio::select! {
            p = rx.recv() => match p {
                Some(p) => {
                    last_ts = p.ts;
                    for a in engine.process(&p) {
                        sink.emit(a);
                    }
                }
                // Canal fermé : fin du pcap, ou thread de capture arrêté.
                None => break,
            },
            _ = ticker.tick(), if live => {
                let now = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs_f64()).unwrap_or(0.0);
                for a in engine.tick(now) {
                    sink.emit(a);
                }
            }
        }
    }
    // Fin de rejeu : clore les fenêtres en cours (volume notamment).
    for a in engine.tick(last_ts + 3600.0) {
        sink.emit(a);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Valeur d'une ligne du résumé, par son libellé.
    fn value<'a>(info: &'a [(&str, String)], label: &str) -> &'a str {
        info.iter().find(|(l, _)| *l == label).map(|(_, v)| v.as_str()).unwrap()
    }

    // Configuration par défaut : dashboard sans jeton, journald seul, modèle par défaut.
    #[test]
    fn banner_info_default_config() {
        let info = banner_info(&Config::default(), "eth0".into(), None);
        assert_eq!(value(&info, "Dashboard"), "http://127.0.0.1:8080");
        assert_eq!(value(&info, "Capture"), "eth0");
        assert_eq!(value(&info, "Logs"), "journald");
        assert_eq!(value(&info, "Modèle IA"), Config::default().llm.model);
        assert_eq!(value(&info, "Normalité"), "désactivée");
        assert_eq!(value(&info, "Historique"), "en mémoire");
    }

    // Historique activé : le fichier et ses limites apparaissent dans le résumé.
    #[test]
    fn banner_info_shows_history() {
        let mut cfg = Config::default();
        cfg.history.path = "/var/lib/cyward/alerts.db".into();
        let info = banner_info(&cfg, "eth0".into(), None);
        assert_eq!(value(&info, "Historique"), "/var/lib/cyward/alerts.db (90 j, 100000 max)");
    }

    // Étages désactivés, jeton défini, fichiers de logs : le résumé le reflète, sans jamais
    // afficher la valeur du jeton.
    #[test]
    fn banner_info_reflects_overrides() {
        let mut cfg = Config::default();
        cfg.web.token = "secret".into();
        cfg.logs.files = vec!["/var/log/auth.log".into(), "/var/log/nginx/access.log".into()];
        cfg.llm.enabled = false;
        let info = banner_info(&cfg, "désactivée".into(), None);
        assert_eq!(value(&info, "Dashboard"), "http://127.0.0.1:8080/?token=…");
        assert!(info.iter().all(|(_, v)| !v.contains("secret")));
        assert_eq!(value(&info, "Logs"), "journald + 2 fichier(s)");
        assert_eq!(value(&info, "Modèle IA"), "désactivé");

        cfg.logs.enabled = false;
        assert_eq!(value(&banner_info(&cfg, String::new(), None), "Logs"), "désactivés");
    }

    // Apprentissage activé : le mode et l'état du modèle apparaissent dans le résumé.
    #[test]
    fn banner_info_shows_normality_state() {
        let b = Baseline::in_memory(config::AnomalyConfig { enabled: true, mode: AnomalyMode::Alert, ..Default::default() });
        let info = banner_info(&Config::default(), "eth0".into(), Some(&b));
        assert_eq!(value(&info, "Normalité"), "alerte · apprentissage en cours");
    }
}
