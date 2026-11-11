//! Serveur HTTP : dashboard, API JSON et flux d'événements en direct.
//!
//! | Route                               | Contenu                                              |
//! |-------------------------------------|------------------------------------------------------|
//! | `GET /`                             | Le dashboard (page HTML unique)                      |
//! | `GET /api/alerts`                   | Liste des alertes, plus récentes d'abord (`?limit=`) |
//! | `GET /api/alerts/{id}`              | Une alerte                                           |
//! | `GET /api/stats`                    | Compteurs et nombre d'alertes par sévérité           |
//! | `GET /api/events`                   | Flux Server-Sent Events des créations et mises à jour |
//! | `GET /api/baseline`                 | État de l'apprentissage du comportement normal       |
//! | `GET /api/names?ips=a,b`            | Noms des machines (DNS inverse) des adresses données |
//! | `POST /api/alerts/{id}/feedback`    | Réponse « est-ce normal ? » à une anomalie           |
//! | `POST /api/baseline/train`          | Lance un apprentissage                               |
//! | `POST /api/baseline/decision`       | Valide le diff d'un modèle candidat                  |
//! | `POST /api/baseline/rollback`       | Revient à une version de modèle                      |
//!
//! Les routes `POST` modifient ce que la détection considère comme normal : elles exigent un
//! jeton configuré, transmis dans l'en-tête `Authorization` (jamais dans l'URL).

use std::{convert::Infallible, sync::Arc};

use anyhow::{Context, Result};
use axum::{
    Json, Router,
    extract::{Path, Query, Request, State},
    http::{StatusCode, header},
    middleware::{self, Next},
    response::{
        Html, IntoResponse, Response,
        sse::{Event, KeepAlive, Sse},
    },
    routing::{get, post},
};
use chrono::Utc;
use futures::Stream;
use serde::Deserialize;
use serde_json::json;
use tokio_stream::{StreamExt, wrappers::BroadcastStream};

use crate::{
    alert::{AlertKind, AlertSink, Feedback, FeedbackScope, FeedbackVerdict},
    anomaly::{baseline::Baseline, trainer},
    names::{self, Resolver},
    stats::Stats,
};

/// Page du dashboard, incluse dans le binaire à la compilation : modifier le fichier HTML
/// demande de recompiler.
const INDEX: &str = include_str!("../assets/index.html");

/// État partagé par les handlers (cloné à chaque requête, d'où les `Arc`).
#[derive(Clone)]
struct AppState {
    /// Point d'entrée des alertes ; donne aussi accès au store (`sink.store`).
    sink: AlertSink,
    stats: Arc<Stats>,
    /// Jeton d'accès ; chaîne vide = pas d'authentification (et pas d'écriture possible).
    token: Arc<String>,
    /// Apprentissage du comportement normal, s'il est activé.
    baseline: Option<Arc<Baseline>>,
    /// Noms des machines affichés à côté des adresses.
    names: Arc<Resolver>,
}

/// Démarre le serveur et ne rend la main qu'en cas d'erreur.
pub async fn serve(listen: &str, token: String, sink: AlertSink, stats: Arc<Stats>, baseline: Option<Arc<Baseline>>, names: Arc<Resolver>) -> Result<()> {
    let state = AppState { sink, stats, token: Arc::new(token), baseline, names };
    // Routes d'écriture : un second middleware, appliqué à elles seules, exige le jeton en en-tête.
    let writes = Router::new()
        .route("/api/alerts/{id}/feedback", post(feedback))
        .route("/api/baseline/train", post(train))
        .route("/api/baseline/decision", post(decision))
        .route("/api/baseline/rollback", post(rollback))
        .route_layer(middleware::from_fn_with_state(state.clone(), write_guard));
    let app = Router::new()
        .route("/", get(|| async { Html(INDEX) }))
        .route("/api/alerts", get(list_alerts))
        .route("/api/alerts/{id}", get(get_alert))
        .route("/api/stats", get(get_stats))
        .route("/api/events", get(events))
        .route("/api/baseline", get(baseline_status))
        .route("/api/names", get(get_names))
        .merge(writes)
        // Le middleware d'authentification s'applique à toutes les routes ci-dessus.
        .layer(middleware::from_fn_with_state(state.clone(), auth))
        .with_state(state);

    let listener = tokio::net::TcpListener::bind(listen).await.with_context(|| format!("écoute sur {listen}"))?;
    tracing::info!("dashboard disponible sur http://{listen}");
    axum::serve(listener, app).await?;
    Ok(())
}

/// Vérifie le jeton s'il est configuré. Il est accepté en en-tête `Authorization: Bearer`
/// ou en paramètre `?token=` (indispensable pour EventSource, qui ne permet pas d'en-têtes).
async fn auth(State(s): State<AppState>, req: Request, next: Next) -> Response {
    if s.token.is_empty() {
        return next.run(req).await;
    }
    let from_header = bearer(&req);
    let from_query = req.uri().query().and_then(|q| q.split('&').find_map(|kv| kv.strip_prefix("token=")));
    let ok = [from_header, from_query].into_iter().flatten().any(|t| constant_time_eq(t.as_bytes(), s.token.as_bytes()));
    if ok { next.run(req).await } else { (StatusCode::UNAUTHORIZED, "jeton requis : ajoutez ?token=… à l'URL").into_response() }
}

/// Contrôle supplémentaire des routes d'écriture (voir [`write_allowed`]).
async fn write_guard(State(s): State<AppState>, req: Request, next: Next) -> Response {
    match write_allowed(&s.token, bearer(&req)) {
        Ok(()) => next.run(req).await,
        Err((code, msg)) => error(code, msg),
    }
}

/// Une écriture n'est permise que si un jeton est configuré **et** présent dans l'en-tête
/// `Authorization`. Le jeton en paramètre d'URL ne suffit pas : une page tierce piégée pourrait
/// sinon déclencher une validation à la place de l'utilisateur (CSRF), alors qu'elle ne peut
/// pas poser cet en-tête sans l'accord du navigateur.
fn write_allowed(token: &str, header: Option<&str>) -> Result<(), (StatusCode, String)> {
    if token.is_empty() {
        return Err((StatusCode::FORBIDDEN, "actions désactivées : définissez web.token dans la configuration pour pouvoir répondre et valider".into()));
    }
    match header {
        Some(t) if constant_time_eq(t.as_bytes(), token.as_bytes()) => Ok(()),
        _ => Err((StatusCode::UNAUTHORIZED, "jeton requis dans l'en-tête Authorization: Bearer".into())),
    }
}

/// Jeton de l'en-tête `Authorization: Bearer …`, s'il y en a un.
fn bearer(req: &Request) -> Option<&str> {
    req.headers().get(header::AUTHORIZATION).and_then(|v| v.to_str().ok()).and_then(|v| v.strip_prefix("Bearer "))
}

/// Comparaison en temps constant : sa durée ne dépend pas de la position du premier caractère
/// différent, ce qui empêche de deviner le jeton caractère par caractère en mesurant les temps
/// de réponse. (Seule la longueur peut fuiter.)
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// Réponse d'erreur JSON : `{"error": "…"}`.
fn error(code: StatusCode, msg: impl Into<String>) -> Response {
    (code, Json(json!({ "error": msg.into() }))).into_response()
}

/// Paramètres de `GET /api/alerts`.
#[derive(Deserialize)]
struct ListQuery {
    limit: Option<usize>,
}

async fn list_alerts(State(s): State<AppState>, Query(q): Query<ListQuery>) -> impl IntoResponse {
    // 500 par défaut, 5000 au maximum (la capacité du store).
    Json(s.sink.store.list(q.limit.unwrap_or(500).min(5000)))
}

async fn get_alert(State(s): State<AppState>, Path(id): Path<u64>) -> Response {
    match s.sink.store.get(id) {
        Some(a) => Json(a).into_response(),
        None => StatusCode::NOT_FOUND.into_response(),
    }
}

async fn get_stats(State(s): State<AppState>) -> impl IntoResponse {
    Json(json!({ "stats": s.stats.snapshot(), "alerts_by_severity": s.sink.store.counts() }))
}

/// Flux SSE : chaque événement du store est envoyé au navigateur sous forme d'un message JSON.
async fn events(State(s): State<AppState>) -> Sse<impl Stream<Item = Result<Event, Infallible>>> {
    // `r.ok()` ignore les erreurs « Lagged » (client trop lent) : les événements manqués sont
    // simplement sautés, le client se resynchronise en rechargeant la liste.
    let stream = BroadcastStream::new(s.sink.store.subscribe()).filter_map(|r| r.ok().and_then(|e| Event::default().json_data(e).ok()).map(Ok));
    // Le keep-alive envoie un commentaire périodique pour que les proxys ne coupent pas la connexion.
    Sse::new(stream).keep_alive(KeepAlive::default())
}

/// Paramètres de `GET /api/names` : valeurs `src`/`dst` séparées par des virgules.
#[derive(Deserialize)]
struct NamesQuery {
    #[serde(default)]
    ips: String,
}

/// Noms des machines : `{"192.168.1.20:443": "pc-salon.lan"}`, seulement pour les valeurs qui
/// en ont un. Au plus `names::MAX_BATCH` valeurs par requête, le reste est ignoré.
async fn get_names(State(s): State<AppState>, Query(q): Query<NamesQuery>) -> impl IntoResponse {
    let values: Vec<String> = q.ips.split(',').map(str::trim).filter(|v| !v.is_empty()).take(names::MAX_BATCH).map(String::from).collect();
    Json(s.names.names(&values).await)
}

/// Réponse des routes d'apprentissage quand la fonctionnalité est désactivée.
fn disabled() -> Response {
    error(StatusCode::NOT_FOUND, "apprentissage du comportement normal désactivé (detection.anomaly.enabled)")
}

async fn baseline_status(State(s): State<AppState>) -> Response {
    match &s.baseline {
        Some(b) => Json(b.status()).into_response(),
        None => Json(json!({ "enabled": false })).into_response(),
    }
}

/// Corps de `POST /api/alerts/{id}/feedback`.
#[derive(Deserialize)]
struct FeedbackBody {
    verdict: FeedbackVerdict,
    #[serde(default)]
    reason: String,
    scope: FeedbackScope,
}

/// Réponse « est-ce normal ? » : met à jour les fenêtres de l'anomalie et l'alerte elle-même.
async fn feedback(State(s): State<AppState>, Path(id): Path<u64>, Json(body): Json<FeedbackBody>) -> Response {
    let Some(b) = s.baseline.clone() else { return disabled() };
    let Some(alert) = s.sink.store.get(id) else { return error(StatusCode::NOT_FOUND, "alerte inconnue") };
    if alert.kind != AlertKind::HostAnomaly {
        return error(StatusCode::BAD_REQUEST, "seules les anomalies de comportement attendent une réponse");
    }
    let Some(host) = alert.evidence["host"].as_str() else { return error(StatusCode::BAD_REQUEST, "alerte sans machine") };
    let ids: Vec<usize> = alert.evidence["feature_ids"].as_array().into_iter().flatten().filter_map(|v| v.as_u64().map(|v| v as usize)).collect();
    let (from, to) = (alert.first_seen.timestamp() as f64, alert.last_seen.timestamp() as f64);
    let now = Utc::now();
    match b.feedback(host, from, to, body.verdict, body.scope, body.reason.trim(), &ids, now) {
        Ok(n) => {
            s.sink.store.update(id, |a| a.feedback = Some(Feedback { verdict: body.verdict, reason: body.reason.trim().to_string(), scope: body.scope, at: now }));
            trainer::save(&b).await;
            Json(json!({ "updated_windows": n })).into_response()
        }
        Err(e) => error(StatusCode::CONFLICT, e.to_string()),
    }
}

/// Lance un apprentissage maintenant, sans attendre la fin de la période d'observation.
async fn train(State(s): State<AppState>) -> Response {
    let Some(b) = s.baseline.clone() else { return disabled() };
    match trainer::run_training(b, s.sink.clone()).await {
        Ok(o) => Json(o).into_response(),
        Err(e) => error(StatusCode::CONFLICT, format!("{e:#}")),
    }
}

/// Corps de `POST /api/baseline/decision`.
#[derive(Deserialize)]
struct DecisionBody {
    #[serde(default)]
    accepted: Vec<String>,
    #[serde(default)]
    rejected: Vec<String>,
}

/// Validation du diff : accepte ou refuse chaque machine, puis active le modèle.
async fn decision(State(s): State<AppState>, Json(body): Json<DecisionBody>) -> Response {
    let Some(b) = s.baseline.clone() else { return disabled() };
    // Peut réentraîner le modèle : calcul hors de la boucle asynchrone.
    let bb = b.clone();
    let res = tokio::task::spawn_blocking(move || bb.decide(&body.accepted, &body.rejected, Utc::now())).await;
    match res {
        Ok(Ok(o)) => {
            trainer::emit_rejected(&s.sink, &o.rejected, o.activated);
            trainer::save(&b).await;
            Json(o).into_response()
        }
        Ok(Err(e)) => error(StatusCode::CONFLICT, e.to_string()),
        Err(e) => error(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()),
    }
}

/// Corps de `POST /api/baseline/rollback`.
#[derive(Deserialize)]
struct RollbackBody {
    version: u32,
}

async fn rollback(State(s): State<AppState>, Json(body): Json<RollbackBody>) -> Response {
    let Some(b) = s.baseline.clone() else { return disabled() };
    match b.rollback(body.version, Utc::now()) {
        Ok(()) => {
            trainer::save(&b).await;
            Json(json!({ "active": body.version })).into_response()
        }
        Err(e) => error(StatusCode::CONFLICT, e.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Sans jeton configuré, aucune écriture n'est possible, même avec un en-tête.
    #[test]
    fn writes_need_a_configured_token() {
        assert_eq!(write_allowed("", Some("x")).unwrap_err().0, StatusCode::FORBIDDEN);
    }

    // Avec un jeton : l'en-tête doit être présent et exact.
    #[test]
    fn writes_need_the_header_token() {
        assert_eq!(write_allowed("s3cret", None).unwrap_err().0, StatusCode::UNAUTHORIZED);
        assert_eq!(write_allowed("s3cret", Some("wrong")).unwrap_err().0, StatusCode::UNAUTHORIZED);
        assert!(write_allowed("s3cret", Some("s3cret")).is_ok());
    }
}
