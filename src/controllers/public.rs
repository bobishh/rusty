use crate::http::{self, AppState, IncomingMessage};
use axum::{
    Json,
    extract::OriginalUri,
    http::HeaderMap,
    response::{IntoResponse, Redirect},
    routing::{get, post},
};
use loco_rs::{
    controller::{Routes, format},
    prelude::SharedStore,
};
use serde_json::json;

pub(crate) fn routes() -> Routes {
    Routes::new()
        .add("/", get(admin_entry))
        .add("/health", get(health))
        .add("/.well-known/mesh-lighthouse", get(discovery))
        .add("/challenge", get(challenge))
        .add("/ingest", post(ingest))
}
async fn admin_entry(OriginalUri(uri): OriginalUri) -> Redirect {
    let target = match uri.query() {
        Some(query) => format!("/admin/?{query}"),
        None => "/admin/".to_owned(),
    };
    Redirect::temporary(&target)
}

async fn health() -> loco_rs::Result<axum::response::Response> {
    format::json(json!({"status":"ok"}))
}
async fn discovery(
    SharedStore(state): SharedStore<AppState>,
    headers: HeaderMap,
) -> impl IntoResponse {
    http::discover(state, headers).await
}
async fn challenge(SharedStore(state): SharedStore<AppState>) -> impl IntoResponse {
    http::challenge(state).await
}
async fn ingest(
    SharedStore(state): SharedStore<AppState>,
    Json(input): Json<IncomingMessage>,
) -> impl IntoResponse {
    http::ingest(state, input).await
}
