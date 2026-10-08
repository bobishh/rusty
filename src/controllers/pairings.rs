use crate::{
    http::{self, AppState},
    pairing::ControllerRequest,
};
use axum::{
    Json,
    extract::{DefaultBodyLimit, Path},
    http::HeaderMap,
    response::IntoResponse,
    routing::post,
};
use loco_rs::{controller::Routes, prelude::SharedStore};

// Signed baselines allow 4,096 IDs up to 256 bytes, repeated in pairing offers
// and provisioning updates. Withdrawal evidence allows 8 MiB of raw documents,
// base64 expansion, and bounded authority bundles. Keep other routes at 16 KiB.
const MAX_PAIRING_OFFER_REQUEST_BODY_BYTES: usize = 16 * 1024 * 1024;
const MAX_PAIRING_PROVISION_REQUEST_BODY_BYTES: usize = 16 * 1024 * 1024;
const MAX_WITHDRAWAL_REQUEST_BODY_BYTES: usize = 16 * 1024 * 1024;

pub(crate) fn routes() -> Routes {
    Routes::new()
        .prefix("/v1/pairings")
        .add(
            "/",
            post(create).layer(DefaultBodyLimit::max(MAX_PAIRING_OFFER_REQUEST_BODY_BYTES)),
        )
        .add("/{id}/decision", post(decision))
        .add(
            "/{id}/withdraw",
            post(withdraw).layer(DefaultBodyLimit::max(MAX_WITHDRAWAL_REQUEST_BODY_BYTES)),
        )
        .add(
            "/{id}/withdraw/complete",
            post(withdraw_complete).layer(DefaultBodyLimit::max(MAX_WITHDRAWAL_REQUEST_BODY_BYTES)),
        )
        .add("/{id}/status", post(status))
        .add(
            "/{id}/provision",
            post(provision).layer(DefaultBodyLimit::max(
                MAX_PAIRING_PROVISION_REQUEST_BODY_BYTES,
            )),
        )
}

pub(crate) fn login_routes() -> Routes {
    Routes::new()
        .prefix("/v1/login")
        .add("/challenges/{id}", axum::routing::get(login_challenge))
        .add("/proof", post(login_proof))
}

async fn create(
    SharedStore(state): SharedStore<AppState>,
    headers: HeaderMap,
    Json(request): Json<ControllerRequest>,
) -> impl IntoResponse {
    http::create_pairing(state, headers, request).await
}
async fn decision(
    SharedStore(state): SharedStore<AppState>,
    Path(id): Path<String>,
    headers: HeaderMap,
    Json(request): Json<ControllerRequest>,
) -> impl IntoResponse {
    http::pairing_decision(state, id, headers, request).await
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
