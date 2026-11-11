//! Point d'entrée de Cyward : interface en ligne de commande et assemblage des tâches.
//!
//! Le programme relie entre elles des tâches indépendantes qui communiquent par canaux :
//!
//! ```text
//! capture (thread) ──PacketMeta──► run_engine ──┐
//! logs (tâche tokio) ───────────────────────────┼──► AlertSink ──► AlertStore ──► dashboard (SSE)
//!                                               │        └──► file de triage ──► LLM
//! ```
//!
//! Chaque module ne connaît que ses voisins immédiats : les détecteurs ignorent le LLM et le
//! dashboard, le LLM ignore d'où viennent les alertes.

// Déclaration des modules du crate (un fichier ou dossier par module dans src/).
mod alert;
mod capture;
mod config;
mod detect;
mod llm;
mod logs;
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
    capture::PacketMeta,
    config::Config,
    detect::Engine,
    stats::Stats,
};

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
}

// `#[tokio::main]` crée le runtime asynchrone multi-thread qui exécute toutes les tâches.
#[tokio::main]
async fn main() -> Result<()> {
    // Journalisation sur la sortie standard. Le niveau se règle avec la variable RUST_LOG
    // (ex. RUST_LOG=debug) ; par défaut « info ».
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")))
        .with_target(false)
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
        Command::Run { interface, no_capture, no_logs, no_llm } => {
            // Les options de la ligne de commande l'emportent sur le fichier de configuration.
            if let Some(i) = interface {
                cfg.capture.interface = i;
            }
            // `&=` : une option --no-xxx peut désactiver un étage, jamais l'activer s'il est coupé dans la config.
            cfg.capture.enabled &= !no_capture;
            cfg.logs.enabled &= !no_logs;
            cfg.llm.enabled &= !no_llm;
            run(cfg).await
        }
        Command::Replay { file, serve } => replay(cfg, file, serve).await,
    }
}

/// Démarre la partie commune à `run` et `replay --serve` : stockage des alertes,
/// worker LLM (si activé) et serveur web. Renvoie le point d'entrée des alertes.
fn start_pipeline(cfg: &Config, stats: &Arc<Stats>) -> Result<AlertSink> {
    *stats.started_at.lock() = Some(chrono::Utc::now());
    let store = Arc::new(AlertStore::new(5000, cfg.detection.alert_cooldown_secs));
    // `triage` est l'émetteur de la file vers le LLM ; None si le LLM est désactivé.
    let triage = if cfg.llm.enabled { Some(llm::spawn(cfg.llm.clone(), store.clone(), stats.clone())?) } else { None };
    let sink = AlertSink::new(store.clone(), triage, cfg.llm.min_severity);

    // Le serveur web tourne dans sa propre tâche ; une erreur (port occupé…) est journalisée
    // sans arrêter la détection.
    let (listen, token) = (cfg.web.listen.clone(), cfg.web.token.clone());
    let stats = stats.clone();
    tokio::spawn(async move {
        if let Err(e) = web::serve(&listen, token, store, stats).await {
            tracing::error!("dashboard arrêté : {e:#}");
        }
    });
    Ok(sink)
}

/// Mode surveillance continue (`cyward run`).
async fn run(cfg: Config) -> Result<()> {
    let stats = Arc::new(Stats::default());
    let sink = start_pipeline(&cfg, &stats)?;

    if cfg.capture.enabled {
        let iface = capture::pick_interface(&cfg.capture.interface)?;
        tracing::info!("capture sur {} ({})", iface.name, iface.ips.iter().map(|i| i.to_string()).collect::<Vec<_>>().join(", "));
        *stats.interface.lock() = Some(iface.name.clone());
        // Canal borné entre le thread de capture et le moteur : s'il est plein, la capture
        // abandonne des paquets plutôt que de bloquer (voir capture::spawn_live).
        let (tx, rx) = mpsc::channel(cfg.capture.queue_size);
        capture::spawn_live(iface, cfg.capture.promiscuous, tx, stats.clone())?;
        tokio::spawn(run_engine(Engine::new(&cfg.detection), rx, sink.clone(), true));
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
    Ok(())
}

/// Mode rejeu (`cyward replay`) : passe un pcap dans les détecteurs puis affiche le bilan.
async fn replay(mut cfg: Config, file: PathBuf, serve: bool) -> Result<()> {
    // Sans --serve, personne ne verrait les analyses : inutile de solliciter le LLM.
    cfg.llm.enabled &= serve;
    let stats = Arc::new(Stats::default());
    // Le nom du fichier s'affiche à la place de l'interface dans le dashboard.
    *stats.interface.lock() = file.file_name().map(|n| n.to_string_lossy().into_owned());
    let sink = if serve {
        start_pipeline(&cfg, &stats)?
    } else {
        // Store seul, sans dashboard ni LLM, assez grand pour garder toutes les alertes du fichier.
        AlertSink::new(Arc::new(AlertStore::new(100_000, cfg.detection.alert_cooldown_secs)), None, cfg.llm.min_severity)
    };

    let (tx, rx) = mpsc::channel(4096);
    // `live = false` : pas de tick sur l'horloge murale, seul le temps du pcap compte.
    let engine = tokio::spawn(run_engine(Engine::new(&cfg.detection), rx, sink.clone(), false));
    capture::replay(&file, tx, stats.clone()).await?;
    // `replay` a rendu l'émetteur du canal : le moteur termine dès qu'il a vidé la file.
    engine.await?;

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
