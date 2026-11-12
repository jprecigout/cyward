//! Configuration de Cyward, lue depuis un fichier TOML.
//!
//! Chaque section du fichier correspond à une structure ci-dessous. Toutes portent
//! `#[serde(default)]` : une clé absente prend la valeur de l'implémentation `Default`,
//! ce qui permet un fichier minimal (ou pas de fichier du tout). Les valeurs par défaut
//! sont reproduites et commentées dans `config.example.toml`.

use std::{
    collections::HashMap,
    net::IpAddr,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result};
use ipnet::IpNet;
use serde::Deserialize;

use crate::alert::Severity;

/// Racine du fichier de configuration : une section par sous-système.
#[derive(Debug, Clone, Deserialize, Default)]
#[serde(default)]
pub struct Config {
    pub capture: CaptureConfig,
    pub logs: LogsConfig,
    pub detection: DetectionConfig,
    pub llm: LlmConfig,
    pub web: WebConfig,
    pub names: NamesConfig,
    pub notify: NotifyConfig,
    pub history: HistoryConfig,
}

impl Config {
    /// Charge le fichier indiqué, ou renvoie la configuration par défaut si aucun chemin n'est donné.
    pub fn load(path: Option<&Path>) -> Result<Self> {
        match path {
            Some(p) => {
                let raw = std::fs::read_to_string(p)
                    .with_context(|| format!("lecture de {}", p.display()))?;
                // Une clé inconnue ou un type erroné produit une erreur avec la ligne fautive.
                toml::from_str(&raw).with_context(|| format!("format invalide dans {}", p.display()))
            }
            None => Ok(Self::default()),
        }
    }
}

/// Section `[capture]` : écoute du trafic réseau.
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct CaptureConfig {
    pub enabled: bool,
    /// Interface à écouter. Vide = première interface active non-loopback.
    pub interface: String,
    /// Mode promiscuité : recevoir aussi les trames destinées à d'autres machines (port miroir).
    pub promiscuous: bool,
    /// Taille de la file entre la capture et le moteur de détection.
    pub queue_size: usize,
}

impl Default for CaptureConfig {
    fn default() -> Self {
        Self { enabled: true, interface: String::new(), promiscuous: true, queue_size: 65_536 }
    }
}

/// Section `[logs]` : sources de journaux système à surveiller.
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct LogsConfig {
    pub enabled: bool,
    /// Suivre le journal systemd via `journalctl -f`.
    pub journald: bool,
    /// Fichiers texte à suivre (ex. /var/log/auth.log).
    pub files: Vec<String>,
}

impl Default for LogsConfig {
    fn default() -> Self {
        Self { enabled: true, journald: true, files: Vec::new() }
    }
}

/// Section `[detection]` : paramètres communs et sous-section par détecteur.
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct DetectionConfig {
    /// IP jamais signalées comme source (scanners internes autorisés, supervision…).
    pub whitelist: Vec<IpAddr>,
    /// Réseaux considérés comme internes (sert à repérer les flux sortants).
    pub local_networks: Vec<IpNet>,
    /// Pendant cette durée, une alerte identique incrémente un compteur au lieu d'en créer une nouvelle.
    pub alert_cooldown_secs: u64,
    pub portscan: PortScanConfig,
    pub bruteforce: BruteForceConfig,
    pub synflood: SynFloodConfig,
    pub beacon: BeaconConfig,
    pub volume: VolumeConfig,
    pub dns: DnsConfig,
    pub threat_list: ThreatListConfig,
    pub arp: ArpConfig,
    pub auth: AuthConfig,
    /// Règles regex supplémentaires appliquées aux logs (`[[detection.custom_log_rules]]`).
    pub custom_log_rules: Vec<CustomLogRule>,
    /// Apprentissage du comportement normal (`[detection.anomaly]`).
    pub anomaly: AnomalyConfig,
}

impl Default for DetectionConfig {
    fn default() -> Self {
        Self {
            whitelist: Vec::new(),
            // Plages privées IPv4 (RFC 1918), adresses IPv6 locales uniques et lien-local.
            // Les `unwrap` ne peuvent pas échouer : ces chaînes sont des CIDR valides.
            local_networks: ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fc00::/7", "fe80::/10"]
                .iter()
                .map(|n| n.parse().unwrap())
                .collect(),
            alert_cooldown_secs: 300,
            portscan: Default::default(),
            bruteforce: Default::default(),
            synflood: Default::default(),
            beacon: Default::default(),
            volume: Default::default(),
            dns: Default::default(),
            threat_list: Default::default(),
            arp: Default::default(),
            auth: Default::default(),
            custom_log_rules: Vec::new(),
            anomaly: Default::default(),
        }
    }
}

impl DetectionConfig {
    /// Vrai si l'adresse appartient au réseau interne (ou est une adresse de bouclage).
    /// Sert à distinguer mouvement latéral (interne → interne) et trafic sortant (interne → externe).
    pub fn is_local(&self, ip: &IpAddr) -> bool {
        ip.is_loopback() || self.local_networks.iter().any(|n| n.contains(ip))
    }
}

/// Section `[detection.portscan]` : scan de ports et balayage d'hôtes.
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct PortScanConfig {
    /// Durée de la fenêtre d'observation, en secondes.
    pub window_secs: f64,
    /// Ports distincts sondés sur un même hôte.
    pub ports_threshold: usize,
    /// Hôtes distincts sondés sur un même port (balayage).
    pub hosts_threshold: usize,
}

impl Default for PortScanConfig {
    fn default() -> Self {
        Self { window_secs: 60.0, ports_threshold: 25, hosts_threshold: 20 }
    }
}

/// Section `[detection.bruteforce]` : rafales de connexions vers un service d'authentification.
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct BruteForceConfig {
    pub window_secs: f64,
    /// Nouvelles connexions TCP vers un même service d'authentification.
    pub threshold: usize,
    /// Ports des services surveillés.
    pub ports: Vec<u16>,
}

impl Default for BruteForceConfig {
    fn default() -> Self {
        Self {
            window_secs: 60.0,
            threshold: 20,
            // FTP, SSH, Telnet, SMTP, POP3, IMAP, SMB, SMTP soumission, IMAPS, POP3S,
            // MSSQL, MySQL, RDP, PostgreSQL, VNC, Redis.
            ports: vec![21, 22, 23, 25, 110, 143, 445, 587, 993, 995, 1433, 3306, 3389, 5432, 5900, 6379],
        }
    }
}

/// Section `[detection.synflood]` : inondation de demandes de connexion.
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct SynFloodConfig {
    pub window_secs: f64,
    /// Nombre de SYN reçus par une même cible dans la fenêtre.
    pub threshold: usize,
}

impl Default for SynFloodConfig {
    fn default() -> Self {
        Self { window_secs: 10.0, threshold: 3000 }
    }
}

/// Section `[detection.beacon]` : connexions sortantes à intervalle régulier (C2).
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct BeaconConfig {
    /// Nombre d'intervalles observés avant de conclure.
    pub min_samples: usize,
    /// Coefficient de variation maximal des intervalles (0.1 = ±10 %).
    pub max_jitter: f64,
    /// Intervalle moyen minimal : en dessous, ce sont des rafales, pas des balises.
    pub min_interval_secs: f64,
    /// Ports exclus (DNS, NTP, mDNS : naturellement périodiques).
    pub ignore_ports: Vec<u16>,
}

impl Default for BeaconConfig {
    fn default() -> Self {
        Self { min_samples: 8, max_jitter: 0.12, min_interval_secs: 5.0, ignore_ports: vec![53, 123, 5353] }
    }
}

/// Section `[detection.volume]` : volume sortant anormal (exfiltration).
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct VolumeConfig {
    /// Durée d'une période de comptage, en secondes.
    pub bucket_secs: f64,
    /// Nombre de périodes pour apprendre la normale d'un hôte avant d'alerter.
    pub warmup_buckets: u32,
    /// Écart à la normale, en nombre d'écarts-types, au-delà duquel on alerte.
    pub zscore: f64,
    /// Volume sortant minimal (octets par période) pour alerter.
    pub min_bytes: u64,
}

impl Default for VolumeConfig {
    fn default() -> Self {
        Self { bucket_secs: 60.0, warmup_buckets: 15, zscore: 4.0, min_bytes: 50_000_000 }
    }
}

/// Section `[detection.dns]` : noms suspects (DGA, encodage) et tunnels DNS.
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct DnsConfig {
    /// Longueur totale de nom jugée suspecte.
    pub max_name_len: usize,
    /// Longueur de segment à partir de laquelle on mesure l'entropie.
    pub min_label_len: usize,
    /// Entropie de Shannon (bits par caractère) au-delà de laquelle un segment semble aléatoire.
    pub entropy_threshold: f64,
    /// Fenêtre du détecteur de tunnel, en secondes.
    pub window_secs: f64,
    /// Sous-domaines uniques d'un même domaine demandés par un hôte (tunnel DNS).
    pub unique_subdomains_threshold: usize,
    /// Suffixes jamais signalés (résolution inverse, mDNS, services légitimes très bavards…).
    pub ignore_suffixes: Vec<String>,
}

impl Default for DnsConfig {
    fn default() -> Self {
        Self {
            max_name_len: 80,
            min_label_len: 25,
            entropy_threshold: 3.8,
            window_secs: 300.0,
            unique_subdomains_threshold: 150,
            ignore_suffixes: vec!["in-addr.arpa".into(), "ip6.arpa".into(), "local".into()],
        }
    }
}

/// Section `[detection.threat_list]` : trafic avec des IP de listes de menaces (abuse.ch, Spamhaus…).
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct ThreatListConfig {
    /// Fichiers de listes, lus au démarrage (une IP ou un réseau CIDR par ligne, commentaires
    /// `#` et `;`, ou JSON lignes avec un champ `cidr`). Vide = détecteur désactivé.
    pub lists: Vec<PathBuf>,
    /// Délai avant de signaler à nouveau un même couple (hôte interne, IP listée), en secondes.
    pub realert_secs: f64,
}

impl Default for ThreatListConfig {
    fn default() -> Self {
        Self { lists: Vec::new(), realert_secs: 3600.0 }
    }
}

/// Section `[detection.arp]` : usurpation ARP (empoisonnement de cache, homme du milieu).
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct ArpConfig {
    /// Durée pendant laquelle une MAC reste « active » pour une IP, en secondes. Une seconde
    /// MAC annoncée pour la même IP dans ce délai est un conflit ; au-delà, un simple remplacement.
    pub window_secs: f64,
    /// IP sensibles (passerelle, DNS, serveurs) : un conflit sur l'une d'elles est de sévérité haute.
    pub protected_ips: Vec<IpAddr>,
}

impl Default for ArpConfig {
    fn default() -> Self {
        Self { window_secs: 3600.0, protected_ips: Vec::new() }
    }
}

/// Section `[detection.auth]` : échecs d'authentification lus dans les logs.
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct AuthConfig {
    /// Fenêtre de comptage des échecs, en secondes (entier : comparée à des dates chrono).
    pub window_secs: i64,
    /// Échecs d'une même IP avant l'alerte de force brute.
    pub failures_threshold: usize,
}

impl Default for AuthConfig {
    fn default() -> Self {
        Self { window_secs: 300, failures_threshold: 6 }
    }
}

/// Mode de l'apprentissage du comportement normal.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, serde::Serialize)]
#[serde(rename_all = "lowercase")]
pub enum AnomalyMode {
    /// Anomalies en sévérité `info`, sans LLM : pour calibrer le modèle sans être dérangé.
    Observation,
    /// Anomalies en sévérité `medium`, analysées par le LLM.
    Alert,
}

/// Section `[detection.anomaly]` : apprentissage du comportement normal par Isolation Forest.
/// Voir doc/conception-normalite.md.
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct AnomalyConfig {
    /// Désactivé par défaut : la fonctionnalité demande une période d'apprentissage et des validations.
    pub enabled: bool,
    pub mode: AnomalyMode,
    /// Durée d'une fenêtre d'observation, en secondes (un échantillon par machine et par fenêtre).
    pub window_secs: f64,
    /// Dossier de persistance (échantillons, modèles, journal). Vide = en mémoire seulement.
    pub data_dir: String,
    /// Échantillons utilisables nécessaires pour lancer un apprentissage.
    pub min_training_samples: usize,
    /// Durée couverte par les échantillons avant le premier apprentissage automatique, en heures.
    pub learning_hours: f64,
    /// Délai entre deux apprentissages automatiques, en heures.
    pub retrain_interval_hours: f64,
    /// Durée de conservation des échantillons, en jours.
    pub retention_days: f64,
    /// Plafond du nombre d'échantillons conservés.
    pub max_samples: usize,
    /// Nombre d'arbres de l'Isolation Forest.
    pub trees: usize,
    /// Taille du sous-échantillon tiré pour chaque arbre.
    pub sample_size: usize,
    /// Part des données d'apprentissage considérée comme atypique : fixe le seuil d'anomalie.
    pub contamination: f64,
    /// Facteur de variation d'un volume, depuis le premier modèle validé, qui déclenche une alerte de dérive.
    pub drift_factor: f64,
    /// Nombre de versions de modèle conservées pour le retour arrière.
    pub max_versions: usize,
}

impl Default for AnomalyConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            mode: AnomalyMode::Observation,
            window_secs: 300.0,
            data_dir: String::new(),
            min_training_samples: 500,
            learning_hours: 168.0,
            retrain_interval_hours: 168.0,
            retention_days: 28.0,
            max_samples: 200_000,
            trees: 100,
            sample_size: 256,
            contamination: 0.005,
            drift_factor: 10.0,
            max_versions: 10,
        }
    }
}

/// Une règle `[[detection.custom_log_rules]]`. Pas de `Default` : tous les champs sont obligatoires.
#[derive(Debug, Clone, Deserialize)]
pub struct CustomLogRule {
    /// Identifiant de la règle, repris dans la description et l'empreinte de l'alerte.
    pub name: String,
    /// Expression régulière. Un groupe nommé `ip` est repris comme source de l'alerte.
    pub pattern: String,
    pub severity: Severity,
    /// Titre de l'alerte affiché dans le dashboard.
    pub title: String,
}

/// Section `[llm]` : modèle de langage chargé du triage des alertes.
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct LlmConfig {
    pub enabled: bool,
    /// Endpoint compatible OpenAI (Ollama, llama.cpp server, vLLM…).
    pub base_url: String,
    /// Nom du modèle tel que le serveur le connaît (`ollama list`).
    pub model: String,
    /// Clé envoyée en `Authorization: Bearer` si non vide.
    pub api_key: String,
    /// Délai maximal d'une analyse (un modèle 8B sur CPU peut prendre plus d'une minute).
    pub timeout_secs: u64,
    /// Seules les alertes de cette sévérité ou plus sont envoyées au modèle.
    pub min_severity: Severity,
    /// Langue demandée au modèle pour ses réponses.
    pub language: String,
    /// Nombre d'alertes en attente d'analyse au-delà duquel les nouvelles sont ignorées.
    pub queue_size: usize,
}

impl Default for LlmConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            // Port par défaut d'Ollama, qui expose l'API OpenAI sous /v1.
            base_url: "http://127.0.0.1:11434/v1".into(),
            // Foundation-Sec-8B-Instruct (Cisco) quantifié en Q4_K_M, tiré directement de Hugging Face par Ollama.
            model: "hf.co/mradermacher/Foundation-Sec-8B-Instruct-GGUF:Q4_K_M".into(),
            api_key: String::new(),
            timeout_secs: 300,
            min_severity: Severity::Medium,
            language: "français".into(),
            queue_size: 32,
        }
    }
}

/// Section `[web]` : dashboard et API HTTP.
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct WebConfig {
    /// Adresse et port d'écoute.
    pub listen: String,
    /// Si renseigné, le dashboard exige `?token=` ou l'en-tête `Authorization: Bearer`.
    pub token: String,
}

impl Default for WebConfig {
    fn default() -> Self {
        // Localhost par défaut : le dashboard révèle la topologie du réseau.
        Self { listen: "127.0.0.1:8080".into(), token: String::new() }
    }
}

/// Section `[names]` : noms des machines affichés à côté des adresses (DNS inverse, voir `names.rs`).
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct NamesConfig {
    pub enabled: bool,
    /// Résoudre aussi les adresses externes. Désactivé par défaut : la question aboutit au
    /// serveur DNS du propriétaire de l'adresse, qui apprend ainsi qu'elle est examinée.
    pub external: bool,
    /// Serveur DNS à interroger (adresse IP). Vide = premier `nameserver` de /etc/resolv.conf.
    pub nameserver: String,
    /// Délai maximal d'une résolution, en millisecondes.
    pub timeout_ms: u64,
    /// Durée de conservation d'un nom trouvé, en secondes.
    pub cache_secs: u64,
}

impl Default for NamesConfig {
    fn default() -> Self {
        Self { enabled: true, external: false, nameserver: String::new(), timeout_ms: 1000, cache_secs: 3600 }
    }
}

/// Section `[history]` : historique des alertes sur disque (SQLite, voir `history.rs`).
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct HistoryConfig {
    /// Fichier de la base SQLite (créé au besoin). Vide = alertes en mémoire seulement, perdues à l'arrêt.
    pub path: String,
    /// Durée de conservation d'une alerte après sa dernière occurrence, en jours.
    pub retention_days: f64,
    /// Nombre maximal d'alertes en base ; au-delà, les moins récemment vues sont supprimées.
    /// Garde-fou contre une inondation : la base reste vers 1 à 2 Ko par alerte au plus.
    pub max_alerts: usize,
}

impl Default for HistoryConfig {
    fn default() -> Self {
        Self { path: String::new(), retention_days: 90.0, max_alerts: 100_000 }
    }
}

/// Section `[notify]` : notifications (ntfy, webhook) des attaques jugées malveillantes ou suspectes.
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct NotifyConfig {
    pub enabled: bool,
    /// Verdicts de l'IA qui déclenchent une notification (en minuscules).
    pub verdicts: Vec<String>,
    /// Confiance minimale du verdict, entre 0 et 1.
    pub min_confidence: f64,
    /// À partir de cette sévérité, notification immédiate, sans attendre le verdict de l'IA.
    pub immediate_severity: Severity,
    /// Sévérité minimale d'une alerte notifiée faute de verdict (IA hors ligne, en échec ou désactivée).
    pub fallback_severity: Severity,
    /// Attente du verdict avant la notification de repli, en secondes (0 = jamais de repli).
    pub fallback_after_secs: u64,
    /// Nombre maximal de notifications par heure ; au-delà, un résumé unique est envoyé.
    pub max_per_hour: usize,
    /// Adresse du dashboard vue depuis le téléphone, pour le lien de la notification (vide = pas de lien).
    pub dashboard_url: String,
    /// Canaux de notification (`[[notify.channels]]`).
    pub channels: Vec<ChannelConfig>,
}

impl Default for NotifyConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            verdicts: vec!["malveillant".into(), "suspect".into()],
            min_confidence: 0.6,
            immediate_severity: Severity::Critical,
            fallback_severity: Severity::High,
            // 10 minutes : un modèle 8B sur CPU, qui traite une alerte à la fois, peut prendre plusieurs minutes.
            fallback_after_secs: 600,
            max_per_hour: 20,
            dashboard_url: String::new(),
            channels: Vec::new(),
        }
    }
}

/// Un canal de notification, choisi par la clé `type`.
#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase", deny_unknown_fields)]
pub enum ChannelConfig {
    /// Serveur ntfy (auto-hébergé ou ntfy.sh), publication en JSON.
    Ntfy {
        /// Adresse du serveur, sans le sujet (ex. `http://127.0.0.1:8090`).
        url: String,
        /// Sujet auquel le téléphone est abonné.
        topic: String,
        /// Jeton d'accès ntfy (`tk_…`), vide si le sujet est public.
        #[serde(default)]
        token: String,
    },
    /// Requête POST JSON vers une adresse quelconque (Discord, Slack, Gotify, Home Assistant, n8n…).
    Webhook {
        url: String,
        /// En-têtes HTTP ajoutés à la requête (ex. `Authorization`).
        #[serde(default)]
        headers: HashMap<String, String>,
    },
}
