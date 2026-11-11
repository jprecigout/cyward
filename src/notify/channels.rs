//! Canaux de notification : la forme de la requête HTTP propre à chaque service.
//!
//! Chaque canal implémente [`Notifier`], qui se contente de **construire** la requête à partir
//! d'une [`Notification`] (Strategy). L'envoi, les nouvelles tentatives et la journalisation
//! sont communs à tous les canaux, dans `notify.rs`. Construire sans envoyer rend le format de
//! chaque service testable sans réseau.
//!
//! Les titres d'alerte et les adresses viennent du réseau et des logs, donc potentiellement
//! d'un attaquant : ils sont envoyés en texte brut, jamais interprétés (pas de Markdown côté
//! ntfy, mentions désactivées pour Discord, caractères spéciaux échappés pour Slack).

use std::collections::HashMap;

use reqwest::{Client, RequestBuilder};
use serde_json::json;

use super::Notification;
use crate::config::ChannelConfig;

/// Longueur maximale du champ `content` de Discord, en caractères.
const DISCORD_MAX: usize = 2000;

/// Un canal de notification : transforme une notification en requête HTTP prête à envoyer.
pub trait Notifier: Send + Sync {
    /// Nom affiché dans les logs et par `cyward check-notify`.
    fn name(&self) -> String;
    /// Requête à envoyer pour cette notification.
    fn request(&self, client: &Client, n: &Notification) -> RequestBuilder;
}

/// Crée les canaux décrits dans la configuration.
pub fn from_config(channels: &[ChannelConfig]) -> Vec<Box<dyn Notifier>> {
    channels
        .iter()
        .map(|c| -> Box<dyn Notifier> {
            match c {
                ChannelConfig::Ntfy { url, topic, token } => Box::new(Ntfy { url: url.clone(), topic: topic.clone(), token: token.clone() }),
                ChannelConfig::Webhook { url, headers } => Box::new(Webhook { url: url.clone(), headers: headers.clone() }),
            }
        })
        .collect()
}

/// Serveur ntfy : publication JSON sur la racine du serveur, le sujet dans le corps.
struct Ntfy {
    /// Adresse du serveur, sans le sujet.
    url: String,
    topic: String,
    /// Jeton d'accès (`tk_…`), vide si le sujet est public.
    token: String,
}

impl Notifier for Ntfy {
    fn name(&self) -> String {
        format!("ntfy {}/{}", self.url.trim_end_matches('/'), self.topic)
    }

    fn request(&self, client: &Client, n: &Notification) -> RequestBuilder {
        // L'API JSON plutôt que les en-têtes `Title:`… : un en-tête HTTP n'accepte pas les
        // accents, alors que tous les textes de Cyward sont en français.
        let mut body = json!({
            "topic": self.topic,
            "title": n.title,
            "message": n.message,
            "priority": n.priority,
            "tags": [if n.priority >= 5 { "rotating_light" } else { "warning" }],
        });
        if let Some(url) = &n.url {
            body["click"] = json!(url);
        }
        let req = client.post(self.url.trim_end_matches('/')).json(&body);
        if self.token.is_empty() { req } else { req.bearer_auth(&self.token) }
    }
}

/// Webhook générique : un POST JSON avec les champs attendus par les services courants.
struct Webhook {
    url: String,
    /// En-têtes ajoutés à la requête (authentification…).
    headers: HashMap<String, String>,
}

impl Notifier for Webhook {
    fn name(&self) -> String {
        // Le chemin d'un webhook Discord ou Slack contient son secret : seul l'hôte est affiché.
        let host = self.url.split("://").nth(1).and_then(|r| r.split('/').next()).unwrap_or(&self.url);
        format!("webhook {host}")
    }

    fn request(&self, client: &Client, n: &Notification) -> RequestBuilder {
        let full = format!("{}\n{}", n.title, n.message);
        let body = json!({
            "source": "cyward",
            "reason": n.reason,
            // `title`, `message` et `priority` (1 à 5) : compris tels quels par Gotify.
            "title": n.title,
            "message": n.message,
            "priority": n.priority,
            "url": n.url,
            // L'alerte complète, pour une automatisation (n8n, Home Assistant, SIEM…).
            "alert": n.alert,
            // `text` : Slack ; `content` : Discord, avec les mentions (@everyone…) désactivées.
            "text": slack_escape(&full),
            "content": full.chars().take(DISCORD_MAX).collect::<String>(),
            "allowed_mentions": { "parse": [] },
        });
        self.headers.iter().fold(client.post(&self.url).json(&body), |req, (k, v)| req.header(k, v))
    }
}

/// Échappe `&`, `<` et `>` comme l'exige Slack : sans cela, un titre contenant `<!channel>`
/// préviendrait tout le canal.
fn slack_escape(s: &str) -> String {
    s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::notify::Reason;

    /// Notification d'exemple, avec un titre piégé.
    fn sample() -> Notification {
        Notification {
            reason: Reason::Verdict,
            title: "[Critique] <!channel> @everyone".into(),
            message: "Verdict de l'IA : malveillant".into(),
            priority: 5,
            url: Some("http://192.168.1.2:8080/#alerte-3".into()),
            alert: None,
        }
    }

    /// Corps JSON d'une requête construite.
    fn body(req: RequestBuilder) -> (reqwest::Request, serde_json::Value) {
        let r = req.build().unwrap();
        let v = serde_json::from_slice(r.body().unwrap().as_bytes().unwrap()).unwrap();
        (r, v)
    }

    // ntfy : JSON sur la racine du serveur, sujet, priorité, lien et jeton.
    #[test]
    fn ntfy_request() {
        let c = &from_config(&[ChannelConfig::Ntfy { url: "http://127.0.0.1:8090/".into(), topic: "cyward".into(), token: "tk_abc".into() }])[0];
        let (r, v) = body(c.request(&Client::new(), &sample()));
        assert_eq!(r.url().as_str(), "http://127.0.0.1:8090/");
        assert_eq!(r.headers()["authorization"], "Bearer tk_abc");
        assert_eq!(v["topic"], "cyward");
        assert_eq!(v["priority"], 5);
        assert_eq!(v["tags"][0], "rotating_light");
        assert_eq!(v["click"], "http://192.168.1.2:8080/#alerte-3");
    }

    // ntfy sans jeton ni lien : pas d'en-tête d'authentification, pas de champ `click`.
    #[test]
    fn ntfy_without_token_or_link() {
        let c = &from_config(&[ChannelConfig::Ntfy { url: "https://ntfy.sh".into(), topic: "t".into(), token: String::new() }])[0];
        let (r, v) = body(c.request(&Client::new(), &Notification { url: None, priority: 4, ..sample() }));
        assert!(r.headers().get("authorization").is_none());
        assert!(v.get("click").is_none());
        assert_eq!(v["tags"][0], "warning");
    }

    // Webhook : en-têtes configurés, champs Gotify, Slack échappé, mentions Discord désactivées.
    #[test]
    fn webhook_request() {
        let headers = HashMap::from([("X-Api-Key".to_string(), "secret".to_string())]);
        let c = &from_config(&[ChannelConfig::Webhook { url: "https://hooks.example/abc/def".into(), headers }])[0];
        assert_eq!(c.name(), "webhook hooks.example");
        let (r, v) = body(c.request(&Client::new(), &sample()));
        assert_eq!(r.headers()["x-api-key"], "secret");
        assert_eq!(v["reason"], "verdict");
        assert_eq!(v["priority"], 5);
        assert!(v["text"].as_str().unwrap().contains("&lt;!channel&gt;"));
        assert!(v["allowed_mentions"]["parse"].as_array().unwrap().is_empty());
    }
}
