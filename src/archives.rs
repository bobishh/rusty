//! Immutable encrypted history evidence; never part of snapshot pruning or attachment coverage.
use super::*;
use std::io::Read;
#[path = "archive_coverage.rs"]
mod aggregates;
pub(super) use aggregates::aggregate;

const MAX_CIPHERTEXT_BYTES: usize = 256 * 1024 + 16;
const MAX_ENCODED_BYTES: usize = MAX_CIPHERTEXT_BYTES.div_ceil(3) * 4 + 1024;
const MAX_OBJECTS: usize = 1_048_576;
const MAX_COVERAGE_OBJECTS: usize = 64;

fn canonical_id(id: &str) -> bool {
    id.len() == 43
        && URL_SAFE_NO_PAD
            .decode(id)
            .is_ok_and(|bytes| bytes.len() == 32 && URL_SAFE_NO_PAD.encode(bytes) == id)
}
fn validate(object: &BlindObject, scope: &str) -> Result<(), String> {
    if object.ciphertext.len() > MAX_CIPHERTEXT_BYTES.div_ceil(3) * 4 {
        return Err("Archive ciphertext exceeds chunk limit".into());
    }
    object.validate(scope)?;
    for (value, minimum, maximum) in [
        (&object.nonce, 12, 12),
        (&object.ciphertext, 16, MAX_CIPHERTEXT_BYTES),
    ] {
        let bytes = URL_SAFE_NO_PAD
            .decode(value)
            .map_err(|_| "Invalid archive encoding")?;
        if bytes.len() < minimum || bytes.len() > maximum || URL_SAFE_NO_PAD.encode(bytes) != *value
        {
            return Err("Non-canonical archive encoding or size".into());
        }
    }
    Ok(())
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct CoverageObject {
    object_id: String,
    key_epoch: u64,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct CoverageRequest {
    version: u8,
    request_id: String,
    objects: Vec<CoverageObject>,
}
impl CoverageRequest {
    fn validate(&self) -> Result<(), String> {
        if self.version != 1
            || !(20..=64).contains(&self.request_id.len())
            || !valid_id(&self.request_id)
            || self.objects.is_empty()
            || self.objects.len() > MAX_COVERAGE_OBJECTS
        {
            return Err("Invalid archive coverage batch".into());
        }
        for (i, object) in self.objects.iter().enumerate() {
            if !canonical_id(&object.object_id)
                || object.key_epoch == 0
                || object.key_epoch > 9_007_199_254_740_991
                || i > 0 && self.objects[i - 1].object_id >= object.object_id
            {
                return Err("Invalid archive coverage object set".into());
            }
        }
        Ok(())
    }
}

impl BlindStore {
    // All mutation callers hold the store lock. Immutable files allow a warm
    // accounting cache; uncertain writes invalidate it before touching disk.
    pub(super) fn archive_storage_usage(&self, scope: &str) -> Result<(u64, usize), String> {
        if let Some(usage) = self
            .archive_usage
            .lock()
            .map_err(|_| "Archive usage cache unavailable")?
            .get(scope)
        {
            return Ok(*usage);
        }
        let usage = blobs::directory_usage(&self.scope_dir(scope)?.join("archives"))?;
        self.archive_usage
            .lock()
            .map_err(|_| "Archive usage cache unavailable")?
            .insert(scope.to_owned(), usage);
        Ok(usage)
    }
    pub(super) fn read_archive(&self, scope: &str, id: &str) -> Result<BlindObject, String> {
        if !canonical_id(id) {
            return Err("Invalid archive object ID".into());
        }
        let path = self
            .scope_dir(scope)?
            .join("archives")
            .join(format!("{id}.json"));
        let file = File::open(path).map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                "Archive object unavailable"
            } else {
                "Archive storage unavailable"
            }
        })?;
        let mut bytes = Vec::new();
        file.take(MAX_ENCODED_BYTES as u64 + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| "Archive storage unavailable")?;
        if bytes.len() > MAX_ENCODED_BYTES {
            return Err("Stored archive exceeds size limit".into());
        }
        let object: BlindObject =
            serde_json::from_slice(&bytes).map_err(|_| "Invalid stored archive object")?;
        validate(&object, scope)?;
        if object.id()? != id {
            return Err("Archive object integrity failure".into());
        }
        Ok(object)
    }
    pub(super) fn save_archive_for_writer(
        &self,
        scope: &str,
        token: &str,
        object: BlindObject,
        request_id: &str,
        writer_version: u8,
    ) -> Result<SignedEnvelope<Value>, String> {
        validate(&object, scope)?;
        if !(20..=64).contains(&request_id.len()) || !valid_id(request_id) {
            return Err("Invalid archive receipt challenge".into());
        }
        let _guard = self.lock.lock().map_err(|_| "Storage lock unavailable")?;
        let policy = self.authorize(scope, token, true)?;
        if policy.minimum_writer_version < 2 {
            return Err("Writer policy required for encrypted archives".into());
        }
        require_writer_version(&policy, writer_version)?;
        let id = object.id()?;
        let scope_dir = self.scope_dir(scope)?;
        let directory = scope_dir.join("archives");
        fs::create_dir_all(&directory).map_err(|_| "Archive storage unavailable")?;
        sync_directory(&scope_dir).map_err(|_| "Durable storage commit failed")?;
        let path = directory.join(format!("{id}.json"));
        let bytes = serde_json::to_vec(&object).map_err(|_| "Invalid archive object")?;
        match fs::metadata(&path) {
            Ok(_) => {
                if self.read_archive(scope, &id)? != object {
                    return Err("Stored archive mismatch".into());
                }
                sync_directory(&directory).map_err(|_| "Durable storage commit failed")?;
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                let (archive_bytes, archive_count) = self.archive_storage_usage(scope)?;
                let used = self.scope_storage_bytes(scope)?;
                if archive_count >= MAX_OBJECTS
                    || used.saturating_add(bytes.len() as u64) > self.max_scope_bytes
                {
                    return Err("Storage capacity exceeded".into());
                }
                self.archive_usage
                    .lock()
                    .map_err(|_| "Archive usage cache unavailable")?
                    .remove(scope);
                atomic_write(&path, &bytes)?;
                self.archive_usage
                    .lock()
                    .map_err(|_| "Archive usage cache unavailable")?
                    .insert(
                        scope.to_owned(),
                        (archive_bytes + bytes.len() as u64, archive_count + 1),
                    );
            }
            Err(_) => return Err("Archive storage unavailable".into()),
        }
        let service_id = public_key_id(&self.public_key()?)?;
        sign_json_envelope(
            &self.seed,
            json!({"kind":"blind-archive-storage-receipt","version":1,
            "serviceId":service_id,"scopeId":scope,"keyEpoch":object.key_epoch,"objectId":id,
            "policyRevision":policy.revision,"requestId":request_id}),
            service_id,
            DOMAIN,
        )
    }
    pub(super) fn archive_coverage(
        &self,
        scope: &str,
        token: &str,
        request: CoverageRequest,
    ) -> Result<SignedEnvelope<Value>, String> {
        request.validate()?;
        let _guard = self.lock.lock().map_err(|_| "Storage lock unavailable")?;
        let policy = self.authorize(scope, token, false)?;
        for entry in &request.objects {
            if self.read_archive(scope, &entry.object_id)?.key_epoch != entry.key_epoch {
                return Err("Archive key epoch mismatch".into());
            }
        }
        let directory = self.scope_dir(scope)?;
        sync_directory(&directory).map_err(|_| "Durable storage commit failed")?;
        sync_directory(&directory.join("archives")).map_err(|_| "Durable storage commit failed")?;
        let service_id = public_key_id(&self.public_key()?)?;
        sign_json_envelope(
            &self.seed,
            json!({"kind":"blind-archive-coverage-batch-receipt","version":1,
            "serviceId":service_id,"scopeId":scope,"policyRevision":policy.revision,
            "requestId":request.request_id,"objects":request.objects}),
            service_id,
            DOMAIN,
        )
    }
}

fn storage_failure(message: String) -> ApiError {
    if message == "Writer policy required for encrypted archives" {
        return (
            StatusCode::CONFLICT,
            Json(json!({"code":"writer_policy_required","message":message})),
        );
    }
    if message == "Writer upgrade required" || message == "Unsupported writer version" {
        return (
            StatusCode::UPGRADE_REQUIRED,
            Json(json!({"code":"writer_upgrade_required","message":message})),
        );
    }
    let status = if message.contains("access") || message == "Scope unavailable" {
        StatusCode::FORBIDDEN
    } else if message == "Archive object unavailable" {
        StatusCode::NOT_FOUND
    } else if message == "Storage capacity exceeded" {
        StatusCode::INSUFFICIENT_STORAGE
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };
    failure(status, &message)
}
pub(super) async fn upload(
    State(state): State<HttpState>,
    RoutePath((scope, id)): RoutePath<(String, String)>,
    headers: HeaderMap,
    Query(query): Query<WriterQuery>,
    Json(object): Json<BlindObject>,
) -> Result<impl IntoResponse, ApiError> {
    validate(&object, &scope).map_err(|e| failure(StatusCode::BAD_REQUEST, &e))?;
    if !canonical_id(&id)
        || object
            .id()
            .map_err(|e| failure(StatusCode::BAD_REQUEST, &e))?
            != id
    {
        return Err(failure(
            StatusCode::BAD_REQUEST,
            "Archive ciphertext object hash mismatch",
        ));
    }
    let token = bearer(&headers)?;
    let request = headers
        .get("x-rusty-request-id")
        .and_then(|v| v.to_str().ok())
        .filter(|v| (20..=64).contains(&v.len()) && valid_id(v))
        .ok_or_else(|| {
            failure(
                StatusCode::BAD_REQUEST,
                "Archive receipt challenge required",
            )
        })?
        .to_owned();
    let receipt = tokio::task::spawn_blocking(move || {
        state
            .store
            .save_archive_for_writer(&scope, &token, object, &request, query.writer_version)
    })
    .await
    .map_err(|_| {
        failure(
            StatusCode::SERVICE_UNAVAILABLE,
            "Archive storage unavailable",
        )
    })?
    .map_err(storage_failure)?;
    Ok((
        [(axum::http::header::CACHE_CONTROL, "no-store")],
        Json(receipt),
    ))
}
pub(super) async fn download(
    State(state): State<HttpState>,
    RoutePath((scope, id)): RoutePath<(String, String)>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, ApiError> {
    if !canonical_id(&id) {
        return Err(failure(
            StatusCode::BAD_REQUEST,
            "Invalid archive object ID",
        ));
    }
    let token = bearer(&headers)?;
    let object = tokio::task::spawn_blocking(move || {
        let _guard = state
            .store
            .lock
            .lock()
            .map_err(|_| "Storage lock unavailable")?;
        state.store.authorize(&scope, &token, false)?;
        state.store.read_archive(&scope, &id)
    })
    .await
    .map_err(|_| {
        failure(
            StatusCode::SERVICE_UNAVAILABLE,
            "Archive storage unavailable",
        )
    })?
    .map_err(storage_failure)?;
    Ok((
        [(axum::http::header::CACHE_CONTROL, "no-store")],
        Json(object),
    ))
}
pub(super) async fn coverage(
    State(state): State<HttpState>,
    RoutePath(scope): RoutePath<String>,
    headers: HeaderMap,
    Json(request): Json<CoverageRequest>,
) -> Result<impl IntoResponse, ApiError> {
    request
        .validate()
        .map_err(|e| failure(StatusCode::BAD_REQUEST, &e))?;
    let token = bearer(&headers)?;
    let receipt =
        tokio::task::spawn_blocking(move || state.store.archive_coverage(&scope, &token, request))
            .await
            .map_err(|_| {
                failure(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "Archive storage unavailable",
                )
            })?
            .map_err(storage_failure)?;
    Ok((
        [(axum::http::header::CACHE_CONTROL, "no-store")],
        Json(receipt),
    ))
}
