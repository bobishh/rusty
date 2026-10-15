//! Immutable opaque attachment objects, isolated from snapshot inventory/retention.
use super::*;

const MAX_BLOB_CIPHERTEXT_BYTES: usize = 1024 * 1024 + 16;
const MAX_BLOB_OBJECTS: usize = 16_384;
const MAX_COVERAGE_OBJECTS: usize = 33;

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct CoverageObject {
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
            return Err("Invalid attachment coverage request".into());
        }
        for (index, object) in self.objects.iter().enumerate() {
            if object.object_id.len() != 43
                || URL_SAFE_NO_PAD
                    .decode(&object.object_id)
                    .map_or(true, |bytes| bytes.len() != 32)
                || object.key_epoch == 0
                || object.key_epoch > 9_007_199_254_740_991
                || (index > 0 && self.objects[index - 1].object_id >= object.object_id)
            {
                return Err("Invalid attachment coverage object set".into());
            }
        }
        Ok(())
    }
}

pub(super) fn directory_usage(directory: &Path) -> Result<(u64, usize), String> {
    let mut entries = match fs::read_dir(directory) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok((0, 0)),
        Err(_) => return Err("Attachment storage unavailable".into()),
    };
    entries.try_fold((0u64, 0usize), |(bytes, count), entry| {
        let entry = entry.map_err(|_| "Attachment storage unavailable")?;
        let metadata = entry
            .metadata()
            .map_err(|_| "Attachment storage unavailable")?;
        if !metadata.is_file() {
            return Err("Invalid attachment storage entry".into());
        }
        Ok((bytes.saturating_add(metadata.len()), count + 1))
    })
}

fn validate_blob(object: &BlindObject, scope: &str) -> Result<(), String> {
    if object.ciphertext.len() > MAX_BLOB_CIPHERTEXT_BYTES.div_ceil(3) * 4 {
        return Err("Attachment ciphertext exceeds chunk limit".into());
    }
    object.validate(scope)?;
    if URL_SAFE_NO_PAD
        .decode(&object.ciphertext)
        .map_err(|_| "Invalid ciphertext")?
        .len()
        > MAX_BLOB_CIPHERTEXT_BYTES
    {
        return Err("Attachment ciphertext exceeds chunk limit".into());
    }
    Ok(())
}

impl BlindStore {
    fn blob_coverage(
        &self,
        scope: &str,
        token: &str,
        request: CoverageRequest,
    ) -> Result<SignedEnvelope<Value>, String> {
        let _guard = self.lock.lock().map_err(|_| "Storage lock unavailable")?;
        let policy = self.authorize(scope, token, false)?;
        for expected in &request.objects {
            let object = self.read_blob(scope, &expected.object_id)?;
            if object.key_epoch != expected.key_epoch {
                return Err("Attachment key epoch mismatch".into());
            }
        }
        // A visible namespace alone cannot attest a durable rename after an interrupted write.
        let scope_directory = self.scope_dir(scope)?;
        sync_directory(&scope_directory).map_err(|_| "Durable storage commit failed")?;
        sync_directory(&scope_directory.join("blobs"))
            .map_err(|_| "Durable storage commit failed")?;
        let service_id = public_key_id(&self.public_key()?)?;
        sign_json_envelope(
            &self.seed,
            json!({"kind":"blind-blob-coverage-receipt", "version":1,
                "serviceId":service_id, "scopeId":scope, "policyRevision":policy.revision,
                "requestId":request.request_id, "objects":request.objects}),
            service_id,
            DOMAIN,
        )
    }

    pub(super) fn scope_storage_bytes(&self, scope: &str) -> Result<u64, String> {
        let directory = self.scope_dir(scope)?;
        let snapshots = directory_usage(&directory.join("objects"))?.0;
        let blobs = directory_usage(&directory.join("blobs"))?.0;
        Ok(snapshots
            .saturating_add(blobs)
            .saturating_add(self.archive_storage_usage(scope)?.0))
    }

    pub(super) fn blob_storage_bytes(&self, scope: &str) -> Result<u64, String> {
        Ok(directory_usage(&self.scope_dir(scope)?.join("blobs"))?.0)
    }

    fn read_blob(&self, scope: &str, object_id: &str) -> Result<BlindObject, String> {
        if !valid_id(object_id) {
            return Err("Invalid attachment object ID".into());
        }
        let path = self
            .scope_dir(scope)?
            .join("blobs")
            .join(format!("{object_id}.json"));
        let bytes = fs::read(path).map_err(|error| {
            if error.kind() == std::io::ErrorKind::NotFound {
                "Attachment object unavailable"
            } else {
                "Attachment storage unavailable"
            }
        })?;
        let object: BlindObject =
            serde_json::from_slice(&bytes).map_err(|_| "Invalid stored attachment object")?;
        validate_blob(&object, scope)?;
        if object.id()? != object_id {
            return Err("Attachment object integrity failure".into());
        }
        Ok(object)
    }

    pub(super) fn save_blob(
        &self,
        scope: &str,
        token: &str,
        object: BlindObject,
        request_id: &str,
    ) -> Result<SignedEnvelope<Value>, String> {
        self.save_blob_for_writer(scope, token, object, request_id, legacy_writer_version())
    }

    pub(super) fn save_blob_for_writer(
        &self,
        scope: &str,
        token: &str,
        object: BlindObject,
        request_id: &str,
        writer_version: u8,
    ) -> Result<SignedEnvelope<Value>, String> {
        validate_blob(&object, scope)?;
        if !valid_id(request_id) {
            return Err("Invalid receipt challenge".into());
        }
        let _guard = self.lock.lock().map_err(|_| "Storage lock unavailable")?;
        let policy = self.authorize(scope, token, true)?;
        if policy.minimum_writer_version < 2 {
            return Err("Writer policy required for encrypted attachments".into());
        }
        require_writer_version(&policy, writer_version)?;
        let object_id = object.id()?;
        let directory = self.scope_dir(scope)?.join("blobs");
        fs::create_dir_all(&directory).map_err(|_| "Attachment storage unavailable")?;
        // Persist the new namespace link before any receipt can attest durability.
        sync_directory(&self.scope_dir(scope)?).map_err(|_| "Durable storage commit failed")?;
        let path = directory.join(format!("{object_id}.json"));
        let bytes = serde_json::to_vec(&object).map_err(|_| "Invalid attachment object")?;
        match fs::metadata(&path) {
            Ok(_) => {
                if self.read_blob(scope, &object_id)? != object {
                    return Err("Stored attachment mismatch".into());
                }
                sync_directory(&directory).map_err(|_| "Durable storage commit failed")?;
                self.telemetry.emit(
                    Level::Debug,
                    "storage.blob.reused",
                    "attachment-upload",
                    "ok",
                    scope,
                    0.0,
                    json!({"bytes":bytes.len()}),
                );
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                let used = self.scope_storage_bytes(scope)?;
                if directory_usage(&directory)?.1 >= MAX_BLOB_OBJECTS
                    || used.saturating_add(bytes.len() as u64) > self.max_scope_bytes
                {
                    self.telemetry.emit(Level::Error, "storage.quota.exceeded", "attachment-upload", "error", scope, 0.0,
                        json!({"stored_bytes":used,"bytes":bytes.len(),"scope_limit_bytes":self.max_scope_bytes,"error_code":"capacity_exceeded"}));
                    return Err("Storage capacity exceeded".into());
                }
                atomic_write(&path, &bytes)?;
                self.telemetry.emit(Level::Info, "storage.blob.stored", "attachment-upload", "ok", scope, 0.0,
                    json!({"stored_bytes_before":used,"stored_bytes":used.saturating_add(bytes.len() as u64),"bytes":bytes.len()}));
            }
            Err(_) => return Err("Attachment storage unavailable".into()),
        }
        let service_id = public_key_id(&self.public_key()?)?;
        sign_json_envelope(
            &self.seed,
            json!({"kind":"blind-blob-storage-receipt", "version":1,
            "serviceId":service_id, "scopeId":scope, "keyEpoch":object.key_epoch, "objectId":object_id,
            "policyRevision":policy.revision, "requestId":request_id}),
            service_id,
            DOMAIN,
        )
    }
}

fn storage_failure(message: String) -> ApiError {
    if message == "Writer policy required for encrypted attachments" {
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
    } else if message == "Attachment object unavailable" {
        StatusCode::NOT_FOUND
    } else if message == "Storage capacity exceeded" {
        StatusCode::INSUFFICIENT_STORAGE
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };
    failure(status, &message)
}

pub(super) async fn coverage(
    State(state): State<HttpState>,
    RoutePath(scope): RoutePath<String>,
    headers: HeaderMap,
    Json(request): Json<CoverageRequest>,
) -> Result<impl IntoResponse, ApiError> {
    request
        .validate()
        .map_err(|message| failure(StatusCode::BAD_REQUEST, &message))?;
    let token = bearer(&headers)?;
    let receipt =
        tokio::task::spawn_blocking(move || state.store.blob_coverage(&scope, &token, request))
            .await
            .map_err(|_| failure(StatusCode::SERVICE_UNAVAILABLE, "Storage unavailable"))?
            .map_err(storage_failure)?;
    Ok((
        [(axum::http::header::CACHE_CONTROL, "no-store")],
        Json(receipt),
    ))
}

pub(super) async fn upload(
    State(state): State<HttpState>,
    RoutePath((scope, object_id)): RoutePath<(String, String)>,
    headers: HeaderMap,
    Query(query): Query<WriterQuery>,
    Json(object): Json<BlindObject>,
) -> Result<impl IntoResponse, ApiError> {
    let token = bearer(&headers)?;
    let request_id = headers
        .get("x-rusty-request-id")
        .and_then(|value| value.to_str().ok())
        .filter(|value| valid_id(value))
        .ok_or_else(|| failure(StatusCode::BAD_REQUEST, "Receipt challenge required"))?
        .to_owned();
    validate_blob(&object, &scope).map_err(|message| failure(StatusCode::BAD_REQUEST, &message))?;
    if object
        .id()
        .map_err(|message| failure(StatusCode::BAD_REQUEST, &message))?
        != object_id
    {
        return Err(failure(
            StatusCode::BAD_REQUEST,
            "Ciphertext object hash mismatch",
        ));
    }
    let writer_version = query.writer_version;
    let receipt = tokio::task::spawn_blocking(move || {
        state
            .store
            .save_blob_for_writer(&scope, &token, object, &request_id, writer_version)
    })
    .await
    .map_err(|_| failure(StatusCode::SERVICE_UNAVAILABLE, "Storage unavailable"))?
    .map_err(storage_failure)?;
    Ok((
        [(axum::http::header::CACHE_CONTROL, "no-store")],
        Json(receipt),
    ))
}

pub(super) async fn download(
    State(state): State<HttpState>,
    RoutePath((scope, object_id)): RoutePath<(String, String)>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, ApiError> {
    if !valid_id(&object_id) {
        return Err(failure(
            StatusCode::BAD_REQUEST,
            "Invalid attachment object ID",
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
        state.store.read_blob(&scope, &object_id)
    })
    .await
    .map_err(|_| failure(StatusCode::SERVICE_UNAVAILABLE, "Storage unavailable"))?
    .map_err(storage_failure)?;
    Ok((
        [(axum::http::header::CACHE_CONTROL, "no-store")],
        Json(object),
    ))
}

#[cfg(test)]
#[path = "blob_tests.rs"]
mod tests;
