//! Triage des alertes par un modèle de langage spécialisé en cybersécurité
//! (par défaut Foundation-Sec-8B-Instruct servi par Ollama).
//!
//! Le modèle n'est jamais dans le chemin critique : il reçoit uniquement les alertes déjà
//! levées par les détecteurs, une à la fois, et ajoute un verdict et des recommandations.
//!
//! Le dialogue passe par l'API « chat completions » compatible OpenAI, que proposent Ollama,
//! llama.cpp (`llama-server`) et vLLM : changer de serveur ne demande que de la configuration.

use std::{
    sync::{Arc, atomic::Ordering},
    time::Duration,
};

use anyhow::{Context, Result, anyhow, bail};
use serde_json::{Value, json};
use tokio::sync::mpsc;

use crate::{
    alert::{Alert, AlertStore, Analysis, TriageStatus, host_part},
    config::LlmConfig,
    stats::Stats,
};

/// Démarre le worker d'analyse et la surveillance du serveur. Renvoie l'émetteur de la
/// file : on y envoie l'identifiant des alertes à analyser.
pub fn spawn(cfg: LlmConfig, store: Arc<AlertStore>, stats: Arc<Stats>) -> Result<mpsc::Sender<u64>> {
    let (tx, rx) = mpsc::channel(cfg.queue_size);
    let client = reqwest::Client::builder().timeout(Duration::from_secs(cfg.timeout_secs)).build()?;
    // Partagé (Arc) entre les deux tâches ci-dessous.
    let triage = Arc::new(Triage { cfg, client, store, stats });
    tokio::spawn(triage.clone().health_loop());
    tokio::spawn(triage.run(rx));
    Ok(tx)
}

/// Vérifie la configuration du modèle en lui soumettant une alerte d'exemple.
pub async fn self_test(cfg: LlmConfig) -> Result<Analysis> {
    let client = reqwest::Client::builder().timeout(Duration::from_secs(cfg.timeout_secs)).build()?;
    // Store et compteurs jetables : seul `analyze` est utilisé, sans worker.
    let triage = Triage { cfg, client, store: Arc::new(AlertStore::new(1, 0)), stats: Arc::default() };
    triage.check_model().await?;
    let alert = Alert::new(
        crate::alert::AlertKind::AuthCompromise,
        crate::alert::Severity::Critical,
        crate::alert::AlertSource::Logs,
        chrono::Utc::now(),
        "Connexion réussie de root après 14 échecs",
    )
    .description("203.0.113.4 a ouvert une session (password) sur le compte root juste après une série d'échecs.")
    .src("203.0.113.4")
    .dst("root")
    .evidence(json!({ "previous_failures": 14, "log": "Accepted password for root from 203.0.113.4 port 50412 ssh2" }));
    triage.analyze(&alert).await
}

/// Client du serveur de modèle et accès au store pour y écrire les analyses.
struct Triage {
    cfg: LlmConfig,
    client: reqwest::Client,
    store: Arc<AlertStore>,
    stats: Arc<Stats>,
}

impl Triage {
    /// URL complète d'un point d'accès de l'API (`models`, `chat/completions`).
    fn url(&self, path: &str) -> String {
        format!("{}/{}", self.cfg.base_url.trim_end_matches('/'), path)
    }

    /// Ajoute la clé d'API à la requête si elle est configurée.
    fn request(&self, req: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
        if self.cfg.api_key.is_empty() { req } else { req.bearer_auth(&self.cfg.api_key) }
    }

    /// Vérifie toutes les 30 s que le serveur répond et que le modèle est installé, et tient
    /// `Stats::llm_online` à jour. Ne journalise qu'aux changements d'état, pas à chaque essai.
    async fn health_loop(self: Arc<Self>) {
        // Vrai si l'indisponibilité a déjà été signalée (évite de répéter l'avertissement).
        let mut warned = false;
        loop {
            let online = match self.check_model().await {
                Ok(()) => {
                    if warned || !self.stats.llm_online.load(Ordering::Relaxed) {
                        tracing::info!("modèle {} disponible sur {}", self.cfg.model, self.cfg.base_url);
                    }
                    warned = false;
                    true
                }
                Err(e) => {
                    if !warned {
                        tracing::warn!("LLM indisponible : {e:#}. Les alertes restent en attente d'analyse.");
                        warned = true;
                    }
                    false
                }
            };
            self.stats.llm_online.store(online, Ordering::Relaxed);
            tokio::time::sleep(Duration::from_secs(30)).await;
        }
    }

    /// Interroge `GET /models` et vérifie que le modèle configuré y figure.
    async fn check_model(&self) -> Result<()> {
        let resp: Value = self
            // Délai court : cette requête ne fait que lister les modèles.
            .request(self.client.get(self.url("models")).timeout(Duration::from_secs(5)))
            .send()
            .await
            .with_context(|| format!("connexion à {}", self.cfg.base_url))?
            .error_for_status()?
            .json()
            .await?;
        // Ollama peut suffixer le nom par « :latest » ; on accepte les deux formes.
        let found = resp["data"].as_array().is_some_and(|models| {
            models.iter().filter_map(|m| m["id"].as_str()).any(|id| id == self.cfg.model || id.trim_end_matches(":latest") == self.cfg.model)
        });
        if !found {
            bail!("modèle {} absent du serveur (avec Ollama : `ollama pull {}`)", self.cfg.model, self.cfg.model);
        }
        Ok(())
    }

    /// Worker : analyse les alertes de la file une par une (un modèle sur CPU ne gagne rien
    /// à traiter plusieurs requêtes en parallèle).
    async fn run(self: Arc<Self>, mut rx: mpsc::Receiver<u64>) {
        while let Some(id) = rx.recv().await {
            // L'alerte a pu être évincée du store entre-temps.
            let Some(alert) = self.store.get(id) else { continue };
            // Si le serveur est tombé, attendre son retour plutôt que de marquer les alertes en échec.
            while !self.stats.llm_online.load(Ordering::Relaxed) {
                tokio::time::sleep(Duration::from_secs(5)).await;
            }
            match self.analyze(&alert).await {
                Ok(analysis) => {
                    tracing::info!(id, verdict = %analysis.verdict, "alerte analysée par le LLM");
                    self.stats.llm_analyzed.fetch_add(1, Ordering::Relaxed);
                    // La mise à jour est diffusée au dashboard par le store.
                    self.store.update(id, |a| {
                        a.analysis = Some(analysis);
                        a.triage = TriageStatus::Done;
                    });
                }
                Err(e) => {
                    tracing::warn!(id, "analyse LLM échouée : {e:#}");
                    self.stats.llm_failed.fetch_add(1, Ordering::Relaxed);
                    self.store.update(id, |a| a.triage = TriageStatus::Failed);
                }
            }
        }
    }

    /// Envoie une alerte au modèle et décode son verdict.
    async fn analyze(&self, alert: &Alert) -> Result<Analysis> {
        let body = json!({
            "model": self.cfg.model,
            // Température basse : réponses stables et factuelles plutôt que créatives.
            "temperature": 0.1,
            "max_tokens": 700,
            "stream": false,
            // Demande au serveur de forcer une sortie JSON (le parseur reste tolérant au cas où).
            "response_format": { "type": "json_object" },
            "messages": [
                { "role": "system", "content": system_prompt(&self.cfg.language) },
                { "role": "user", "content": user_prompt(alert, &self.related(alert)) },
            ],
        });
        let resp: Value = self
            .request(self.client.post(self.url("chat/completions")).json(&body))
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?;
        // Format OpenAI : le texte généré est dans choices[0].message.content.
        let content = resp["choices"][0]["message"]["content"].as_str().ok_or_else(|| anyhow!("réponse sans contenu : {resp}"))?;
        let mut analysis = parse_analysis(content)?;
        analysis.model = self.cfg.model.clone();
        Ok(analysis)
    }

    /// Autres alertes récentes impliquant les mêmes adresses, pour que le modèle puisse corréler.
    fn related(&self, alert: &Alert) -> Vec<Alert> {
        // Adresses de l'alerte, sans port.
        let keys: Vec<&str> = [alert.src.as_deref(), alert.dst.as_deref()].into_iter().flatten().map(host_part).collect();
        self.store
            .list(500)
            .into_iter()
            .filter(|a| a.id != alert.id)
            // Une alerte est liée si sa source ou sa cible correspond à l'une de ces adresses.
            .filter(|a| [a.src.as_deref(), a.dst.as_deref()].into_iter().flatten().any(|x| keys.contains(&host_part(x))))
            .take(8)
            .collect()
    }
}

/// Message système : rôle du modèle, règles de raisonnement et format de réponse imposé.
fn system_prompt(language: &str) -> String {
    format!(
        "Tu es un analyste SOC de niveau 3. Un système de détection d'intrusion a levé une alerte sur un réseau d'entreprise ou domestique. \
Évalue s'il s'agit d'une attaque réelle, d'une activité suspecte à surveiller ou d'un faux positif probable, en t'appuyant sur les preuves fournies et sur les alertes liées. \
Ne suppose pas de faits absents des données. \
Réponds en {language}, uniquement avec un objet JSON de la forme :\n\
{{\"verdict\": \"malveillant\" | \"suspect\" | \"bénin\", \"confidence\": nombre entre 0 et 1, \"summary\": \"2 à 4 phrases d'explication\", \
\"mitre\": [\"identifiants MITRE ATT&CK, ex. T1110.001\"], \"recommendations\": [\"actions concrètes et vérifiables, par ordre de priorité\"]}}"
    )
}

/// Message utilisateur : l'alerte en JSON lisible, puis la liste des alertes liées.
fn user_prompt(alert: &Alert, related: &[Alert]) -> String {
    // Clés en français, pour rester cohérent avec la langue demandée au modèle.
    let main = json!({
        "type": alert.kind,
        "severite": alert.severity,
        "origine": alert.source,
        "titre": alert.title,
        "description": alert.description,
        "source": alert.src,
        "cible": alert.dst,
        "occurrences": alert.count,
        "premiere_vue": alert.first_seen,
        "derniere_vue": alert.last_seen,
        "preuves": alert.evidence,
    });
    let mut s = format!("Alerte à analyser :\n{}\n", serde_json::to_string_pretty(&main).unwrap_or_default());
    // Anomalie de comportement : le modèle aide l'utilisateur à répondre « est-ce normal ? »,
    // mais ne décide pas à sa place (les données observées peuvent avoir été choisies par un attaquant).
    if alert.kind == crate::alert::AlertKind::HostAnomaly {
        s.push_str(
            "\nCette alerte vient d'un modèle qui a appris le comportement habituel de la machine (Isolation Forest). \
Si l'écart peut avoir une cause bénigne (mise à jour d'un jeu ou du système, sauvegarde, nouvel appareil, nouvel usage), \
cite le motif le plus probable au début de summary, en précisant qu'il s'agit d'une hypothèse : c'est l'utilisateur qui confirmera.\n",
        );
    }
    if !related.is_empty() {
        s.push_str("\nAlertes récentes impliquant les mêmes adresses :\n");
        // Une ligne résumée par alerte liée, pour ne pas gonfler le prompt.
        for r in related {
            s.push_str(&format!("- [{}] {:?} {:?} : {} (x{})\n", r.first_seen.format("%Y-%m-%d %H:%M:%S"), r.severity, r.kind, r.title, r.count));
        }
    }
    s
}

/// Les petits modèles enrobent parfois le JSON de texte ou de balises ``` : on extrait l'objet.
fn parse_analysis(content: &str) -> Result<Analysis> {
    // Du premier « { » au dernier « } » : ignore tout texte autour de l'objet.
    let start = content.find('{').ok_or_else(|| anyhow!("pas de JSON dans la réponse : {content}"))?;
    let end = content.rfind('}').ok_or_else(|| anyhow!("JSON incomplet : {content}"))?;
    let v: Value = serde_json::from_str(&content[start..=end]).with_context(|| format!("JSON invalide : {content}"))?;
    // Accepte une liste de chaînes, ou une chaîne seule (convertie en liste d'un élément).
    let strings = |key: &str| -> Vec<String> {
        match &v[key] {
            Value::Array(a) => a.iter().filter_map(|x| x.as_str().map(str::to_string)).collect(),
            Value::String(s) if !s.is_empty() => vec![s.clone()],
            _ => Vec::new(),
        }
    };
    // Confiance en nombre ou en texte (« 85% »).
    let confidence = match &v["confidence"] {
        Value::Number(n) => n.as_f64().unwrap_or(0.0),
        Value::String(s) => s.trim_end_matches('%').parse::<f64>().unwrap_or(0.0),
        _ => 0.0,
    };
    Ok(Analysis {
        verdict: v["verdict"].as_str().unwrap_or("inconnu").to_lowercase(),
        // Une valeur supérieure à 1 est interprétée comme un pourcentage.
        confidence: if confidence > 1.0 { confidence / 100.0 } else { confidence },
        summary: v["summary"].as_str().unwrap_or_default().to_string(),
        mitre: strings("mitre"),
        recommendations: strings("recommendations"),
        model: String::new(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    // Réponse « sale » typique : texte, balises markdown, confiance en pourcentage, mitre en chaîne.
    #[test]
    fn parses_wrapped_json() {
        let a = parse_analysis("Voici l'analyse :\n```json\n{\"verdict\":\"Malveillant\",\"confidence\":\"85%\",\"summary\":\"Force brute.\",\"mitre\":\"T1110\",\"recommendations\":[\"Bloquer l'IP\"]}\n```").unwrap();
        assert_eq!(a.verdict, "malveillant");
        assert!((a.confidence - 0.85).abs() < 1e-9);
        assert_eq!(a.mitre, vec!["T1110"]);
        assert_eq!(a.recommendations.len(), 1);
    }
}
