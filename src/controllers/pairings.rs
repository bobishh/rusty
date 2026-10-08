use crate::{
    http::{self, AppState},
    pairing::ControllerRequest,
};
use axum::{Json, extract::Path, response::IntoResponse, routing::post};
use loco_rs::{controller::Routes, prelude::SharedStore};

pub(crate) fn routes() -> Routes {
    Routes::new()
        .prefix("/v1/pairings")
        .add("/", post(create))
        .add("/{id}/decision", post(decision))
        .add("/{id}/withdraw", post(withdraw))
        .add("/{id}/withdraw/complete", post(withdraw_complete))
        .add("/{id}/status", post(status))
        .add("/{id}/provision", post(provision))
}

pub(crate) fn login_routes() -> Routes {
    Routes::new()
        .prefix("/v1/login")
        .add("/challenges/{id}", axum::routing::get(login_challenge))
        .add("/proof", post(login_proof))
}

async fn create(
    SharedStore(state): SharedStore<AppState>,
    Json(request): Json<ControllerRequest>,
) -> impl IntoResponse {
    http::create_pairing(state, request).await
}
async fn decision(
    SharedStore(state): SharedStore<AppState>,
    Path(id): Path<String>,
    Json(request): Json<ControllerRequest>,
) -> impl IntoResponse {
    http::pairing_decision(state, id, request).await
}
async fn status(
    SharedStore(state): SharedStore<AppState>,
    Path(id): Path<String>,
    Json(request): Json<ControllerRequest>,
) -> impl IntoResponse {
    http::pairing_status(state, id, request).await
}
async fn withdraw(
    SharedStore(state): SharedStore<AppState>,
    Path(id): Path<String>,
    Json(request): Json<ControllerRequest>,
) -> impl IntoResponse {
    http::pairing_withdraw(state, id, request).await
}
async fn withdraw_complete(
    SharedStore(state): SharedStore<AppState>,
    Path(id): Path<String>,
    Json(request): Json<ControllerRequest>,
) -> impl IntoResponse {
    http::pairing_withdraw_complete(state, id, request).await
}
async fn provision(
    SharedStore(state): SharedStore<AppState>,
    Path(id): Path<String>,
    Json(request): Json<ControllerRequest>,
) -> impl IntoResponse {
    http::pairing_provision(state, id, request).await
}
async fn login_challenge(
    SharedStore(state): SharedStore<AppState>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    http::login_challenge(state, id).await
}
async fn login_proof(
    SharedStore(state): SharedStore<AppState>,
    Json(request): Json<ControllerRequest>,
) -> impl IntoResponse {
    http::login_proof(state, request).await
}
