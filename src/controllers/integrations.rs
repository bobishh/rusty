use crate::{
    http::{self, AppState},
    pairing::ControllerRequest,
};
use axum::{
    Json,
    extract::{DefaultBodyLimit, Path},
    response::IntoResponse,
    routing::post,
};
use loco_rs::{controller::Routes, prelude::SharedStore};

const MAX_INTEGRATION_MUTATION_REQUEST_BODY_BYTES: usize = 64 * 1024;

pub(crate) fn routes() -> Routes {
    Routes::new()
        .prefix("/v1/integrations")
        .add("/status", post(status))
        .add(
            "/{id}/disconnect",
            post(disconnect).layer(DefaultBodyLimit::max(
                MAX_INTEGRATION_MUTATION_REQUEST_BODY_BYTES,
            )),
        )
}

async fn status(
    SharedStore(state): SharedStore<AppState>,
    Json(request): Json<ControllerRequest>,
) -> impl IntoResponse {
    http::integration_status(state, request).await
}

async fn disconnect(
    SharedStore(state): SharedStore<AppState>,
    Path(id): Path<String>,
    Json(request): Json<ControllerRequest>,
) -> impl IntoResponse {
    http::integration_disconnect(state, id, request).await
}
