//! Serveur HTTP : dashboard, API JSON et flux d'événements en direct.
//!
//! | Route                 | Contenu                                              |
//! |-----------------------|------------------------------------------------------|
//! | `GET /`               | Le dashboard (page HTML unique)                      |
//! | `GET /api/alerts`     | Liste des alertes, plus récentes d'abord (`?limit=`) |
//! | `GET /api/alerts/{id}`| Une alerte                                           |
//! | `GET /api/stats`      | Compteurs et nombre d'alertes par sévérité           |
//! | `GET /api/events`     | Flux Server-Sent Events des créations et mises à jour |

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
    routing::get,
};
use futures::Stream;
use serde::Deserialize;
use serde_json::json;
use tokio_stream::{StreamExt, wrappers::BroadcastStream};

use crate::{alert::AlertStore, stats::Stats};

/// Page du dashboard, incluse dans le binaire à la compilation : modifier le fichier HTML
/// demande de recompiler.
const INDEX: &str = include_str!("../assets/index.html");

/// État partagé par les handlers (cloné à chaque requête, d'où les `Arc`).
#[derive(Clone)]
struct AppState {
    store: Arc<AlertStore>,
    stats: Arc<Stats>,
    /// Jeton d'accès ; chaîne vide = pas d'authentification.
    token: Arc<String>,
}

/// Démarre le serveur et ne rend la main qu'en cas d'erreur.
pub async fn serve(listen: &str, token: String, store: Arc<AlertStore>, stats: Arc<Stats>) -> Result<()> {
    let state = AppState { store, stats, token: Arc::new(token) };
    let app = Router::new()
        .route("/", get(|| async { Html(INDEX) }))
        .route("/api/alerts", get(list_alerts))
        .route("/api/alerts/{id}", get(get_alert))
        .route("/api/stats", get(get_stats))
        .route("/api/events", get(events))
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
    let from_header = req
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "));
    let from_query = req.uri().query().and_then(|q| q.split('&').find_map(|kv| kv.strip_prefix("token=")));
    let ok = [from_header, from_query].into_iter().flatten().any(|t| constant_time_eq(t.as_bytes(), s.token.as_bytes()));
    if ok { next.run(req).await } else { (StatusCode::UNAUTHORIZED, "jeton requis : ajoutez ?token=… à l'URL").into_response() }
}

/// Comparaison en temps constant : sa durée ne dépend pas de la position du premier caractère
/// différent, ce qui empêche de deviner le jeton caractère par caractère en mesurant les temps
/// de réponse. (Seule la longueur peut fuiter.)
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// Paramètres de `GET /api/alerts`.
#[derive(Deserialize)]
struct ListQuery {
    limit: Option<usize>,
}

async fn list_alerts(State(s): State<AppState>, Query(q): Query<ListQuery>) -> impl IntoResponse {
    // 500 par défaut, 5000 au maximum (la capacité du store).
    Json(s.store.list(q.limit.unwrap_or(500).min(5000)))
}

async fn get_alert(State(s): State<AppState>, Path(id): Path<u64>) -> Response {
    match s.store.get(id) {
        Some(a) => Json(a).into_response(),
        None => StatusCode::NOT_FOUND.into_response(),
    }
}

async fn get_stats(State(s): State<AppState>) -> impl IntoResponse {
    Json(json!({ "stats": s.stats.snapshot(), "alerts_by_severity": s.store.counts() }))
}

/// Flux SSE : chaque événement du store est envoyé au navigateur sous forme d'un message JSON.
async fn events(State(s): State<AppState>) -> Sse<impl Stream<Item = Result<Event, Infallible>>> {
    // `r.ok()` ignore les erreurs « Lagged » (client trop lent) : les événements manqués sont
    // simplement sautés, le client se resynchronise en rechargeant la liste.
    let stream = BroadcastStream::new(s.store.subscribe()).filter_map(|r| r.ok().and_then(|e| Event::default().json_data(e).ok()).map(Ok));
    // Le keep-alive envoie un commentaire périodique pour que les proxys ne coupent pas la connexion.
    Sse::new(stream).keep_alive(KeepAlive::default())
}
