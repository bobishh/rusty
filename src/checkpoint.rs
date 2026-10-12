//! Owner-confirmed retention of a complete, admitted encrypted workspace snapshot.
use super::*;

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct CheckpointMarker {
    expected_sequence: u64,
    authorization_hash: String,
}

impl CheckpointMarker {
    pub(super) fn valid_for(&self, sequence: u64) -> bool {
        self.expected_sequence.checked_add(1) == Some(sequence)
            && URL_SAFE_NO_PAD
                .decode(&self.authorization_hash)
                .is_ok_and(|hash| hash.len() == 32)
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct Manifest {
    version: u8,
    pub(super) floor: u64,
    pub(super) sequence: u64,
    pub(super) object_id: String,
    authorization_hash: String,
}

impl Manifest {
    pub(super) fn matches(&self, stored: &StoredObject) -> bool {
        stored.object_id == self.object_id
            && stored.sequence == self.sequence
            && stored.checkpoint.as_ref().is_some_and(|marker| {
                marker.expected_sequence == self.floor
                    && marker.authorization_hash == self.authorization_hash
            })
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct Request {
    object: BlindObject,
    identity: PublicIdentity,
    device_id: String,
    certificates: Vec<DeviceCertificate>,
    authorization: SignedEnvelope<Authorization>,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Authorization {
    kind: String,
    version: u8,
    service_id: String,
    origin: String,
    scope_id: String,
    key_epoch: u64,
    policy_revision: u64,
    expected_sequence: u64,
    object_id: String,
    request_id: String,
    issued_at: u64,
    expires_at: u64,
}

impl BlindStore {
    pub(super) fn recover_checkpoint_scopes(&self) -> Result<(), String> {
        let scopes = self.directory.join("scopes");
        if !scopes.exists() {
            return Ok(());
        }
        for entry in fs::read_dir(scopes).map_err(|_| "Scope recovery unavailable")? {
            let entry = entry.map_err(|_| "Scope recovery unavailable")?;
            if !entry
                .file_type()
                .map_err(|_| "Scope recovery unavailable")?
                .is_dir()
            {
                continue;
            }
            let scope = entry.file_name().to_string_lossy().into_owned();
            if let Some(manifest) = self.checkpoint_manifest(&scope)? {
                self.objects(&scope)?; // Verify retained checkpoint before deleting any previous bytes.
                self.prune_checkpoint_objects(&scope, manifest.floor)?;
            }
        }
        Ok(())
    }
    pub(super) fn checkpoint_manifest(&self, scope: &str) -> Result<Option<Manifest>, String> {
        let path = self.scope_dir(scope)?.join("compaction.json");
        let bytes = match fs::read(path) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(_) => return Err("Checkpoint manifest unavailable".into()),
        };
        let value: Manifest =
            serde_json::from_slice(&bytes).map_err(|_| "Invalid checkpoint manifest")?;
        if value.version != 1
            || value.floor.checked_add(1) != Some(value.sequence)
            || !valid_id(&value.object_id)
            || !URL_SAFE_NO_PAD
                .decode(&value.authorization_hash)
                .is_ok_and(|hash| hash.len() == 32)
        {
            return Err("Checkpoint manifest integrity failure".into());
        }
        Ok(Some(value))
    }

    fn prune_checkpoint_objects(&self, scope: &str, floor: u64) -> Result<(u64, usize), String> {
        let directory = self.scope_dir(scope)?.join("objects");
        let mut bytes = 0u64;
        let mut count = 0usize;
        for entry in fs::read_dir(&directory).map_err(|_| "Checkpoint cleanup unavailable")? {
            let entry = entry.map_err(|_| "Checkpoint cleanup unavailable")?;
            if entry
                .path()
                .extension()
                .is_none_or(|extension| extension != "json")
            {
                continue;
            }
            let stored: StoredObject = serde_json::from_slice(
                &fs::read(entry.path()).map_err(|_| "Checkpoint cleanup unavailable")?,
            )
            .map_err(|_| "Invalid stored checkpoint object")?;
            if stored.sequence <= floor {
                bytes = bytes.saturating_add(
                    entry
                        .metadata()
                        .map_err(|_| "Checkpoint cleanup unavailable")?
                        .len(),
                );
                fs::remove_file(entry.path()).map_err(|_| "Checkpoint cleanup failed")?;
                count += 1;
            }
        }
        File::open(directory)
            .and_then(|file| file.sync_all())
            .map_err(|_| "Checkpoint cleanup durability failed")?;
        Ok((bytes, count))
    }

    pub(super) fn checkpoint(
        &self,
        scope: &str,
        token: &str,
        request: Request,
        trusted: &TrustedOwner,
        origin: &str,
    ) -> Result<SignedEnvelope<Value>, String> {
        let _guard = self.lock.lock().map_err(|_| "Storage lock unavailable")?;
        let policy = self.authorize(scope, token, true)?;
        if !trusted_identity_matches(&request.identity, &trusted.identity)
            || policy.owner_person_id.as_deref() != Some(request.identity.person_id.as_str())
            || request.certificates.is_empty()
            || !trusted
                .allowed_controller_device_ids
                .contains(&request.device_id)
        {
            return Err("Untrusted checkpoint owner or device".into());
        }
        let device_key = verify_device_certificate_chain(
            &request.identity,
            &request.device_id,
            &request.certificates,
            "MATCH/1",
        )
        .map_err(|_| "Checkpoint device certificate invalid")?;
        if public_key_id(&device_key)? != request.device_id
            || request.authorization.signer_key_id != request.device_id
            || !verify_signed_envelope(&request.authorization, &device_key, "MATCH/1")
                .map_err(|_| "Checkpoint signature invalid")?
        {
            return Err("Checkpoint signature invalid".into());
        }
        request
            .object
            .validate(scope)
            .map_err(|_| "Checkpoint object binding invalid")?;
        let object_id = request.object.id()?;
        let service_id = public_key_id(&self.public_key()?)?;
        let proof = &request.authorization.payload;
        if proof.kind != "rusty-snapshot-checkpoint"
            || proof.version != 1
            || proof.service_id != service_id
            || proof.origin != origin
            || proof.scope_id != scope
            || proof.key_epoch != request.object.key_epoch
            || proof.policy_revision != policy.revision
            || proof.object_id != object_id
            || !valid_id(&proof.request_id)
            || proof.expected_sequence >= 9_007_199_254_740_991
        {
            return Err("Checkpoint authorization binding invalid".into());
        }
        let authorization_hash = digest(
            canonicalize_json(
                &serde_json::to_value(&request.authorization)
                    .map_err(|_| "Invalid checkpoint authorization")?,
            )?
            .as_bytes(),
        );
        let manifest = self.checkpoint_manifest(scope)?;
        let objects = self.objects(scope)?;
        let maximum = objects.last().map_or(0, |object| object.sequence);
        let sequence = proof.expected_sequence + 1;
        let completed = manifest.as_ref().is_some_and(|manifest| {
            manifest.floor == proof.expected_sequence
                && manifest.sequence == sequence
                && manifest.object_id == object_id
        });
        if manifest
            .as_ref()
            .is_some_and(|manifest| manifest.floor > proof.expected_sequence)
        {
            return Err(format!("Checkpoint inventory changed:{maximum}"));
        }
        let exact_completed = completed
            && manifest
                .as_ref()
                .is_some_and(|manifest| manifest.authorization_hash == authorization_hash);
        if !exact_completed {
            let now = now_ms()?;
            if proof.issued_at > now.saturating_add(30_000)
                || proof.expires_at <= now
                || proof.expires_at <= proof.issued_at
                || proof.expires_at - proof.issued_at > 120_000
            {
                return Err("Checkpoint authorization expired or time invalid".into());
            }
        }
        if !completed {
            let directory = self.scope_dir(scope)?;
            let path = directory.join("objects").join(format!("{object_id}.json"));
            let existing = if path.exists() {
                Some(
                    serde_json::from_slice::<StoredObject>(
                        &fs::read(&path).map_err(|_| "Checkpoint object unavailable")?,
                    )
                    .map_err(|_| "Invalid checkpoint object")?,
                )
            } else {
                None
            };
            let recovery = existing.as_ref().is_some_and(|stored| {
                stored.sequence == sequence
                    && stored.object_id == object_id
                    && stored.object == request.object
                    && stored
                        .checkpoint
                        .as_ref()
                        .is_some_and(|marker| marker.expected_sequence == proof.expected_sequence)
            });
            if maximum != proof.expected_sequence && !(recovery && maximum >= sequence)
                || existing.is_some() && !recovery
            {
                return Err(format!("Checkpoint inventory changed:{maximum}"));
            }
            let record = StoredObject {
                sequence,
                object_id: object_id.clone(),
                object: request.object.clone(),
                checkpoint: Some(CheckpointMarker {
                    expected_sequence: proof.expected_sequence,
                    authorization_hash: authorization_hash.clone(),
                }),
            };
            let encoded = serde_json::to_vec(&record).map_err(|_| "Invalid checkpoint object")?;
            let remaining_bytes = objects
                .iter()
                .filter(|object| {
                    object.sequence > proof.expected_sequence && object.object_id != object_id
                })
                .try_fold(encoded.len() as u64, |total, object| {
                    directory
                        .join("objects")
                        .join(format!("{}.json", object.object_id))
                        .metadata()
                        .map(|metadata| total.saturating_add(metadata.len()))
                        .map_err(|_| "Checkpoint storage unavailable")
                })?;
            if remaining_bytes > self.max_scope_bytes {
                return Err("Checkpoint exceeds storage capacity".into());
            }
            if !recovery {
                // Bound disk scratch by one maximum-sized encoded replacement slot.
                let used = fs::read_dir(directory.join("objects"))
                    .map_err(|_| "Checkpoint storage unavailable")?
                    .try_fold(0u64, |total, entry| {
                        entry
                            .and_then(|entry| entry.metadata())
                            .map(|metadata| total.saturating_add(metadata.len()))
                    })
                    .map_err(|_| "Checkpoint storage unavailable")?;
                let scratch_limit = (MAX_OBJECT_BYTES as u64 + 2) / 3 * 4 + 4096;
                if objects.len() > MAX_SCOPE_OBJECTS
                    || used.saturating_add(encoded.len() as u64)
                        > self.max_scope_bytes.saturating_add(scratch_limit)
                {
                    return Err("Checkpoint scratch capacity exceeded".into());
                }
                self.inventories
                    .lock()
                    .map_err(|_| "Inventory cache unavailable")?
                    .remove(scope);
                atomic_write(&path, &encoded)?;
            }
            self.inventories
                .lock()
                .map_err(|_| "Inventory cache unavailable")?
                .remove(scope);
            atomic_write(
                &directory.join("compaction.json"),
                &serde_json::to_vec(&Manifest {
                    version: 1,
                    floor: proof.expected_sequence,
                    sequence,
                    object_id: object_id.clone(),
                    authorization_hash: existing
                        .as_ref()
                        .and_then(|stored| stored.checkpoint.as_ref())
                        .map_or_else(
                            || authorization_hash.clone(),
                            |marker| marker.authorization_hash.clone(),
                        ),
                })
                .map_err(|_| "Invalid checkpoint manifest")?,
            )?;
            self.inventories
                .lock()
                .map_err(|_| "Inventory cache unavailable")?
                .remove(scope);
        }
        let (freed_bytes, pruned_count) =
            self.prune_checkpoint_objects(scope, proof.expected_sequence)?;
        self.telemetry.emit(Level::Info, "storage.checkpoint.completed", "checkpoint", "ok", scope, 0.0,
            json!({"freed_bytes":freed_bytes,"pruned_count":pruned_count,"object_count":self.objects(scope)?.len()}));
        sign_json_envelope(
            &self.seed,
            json!({"kind":"rusty-snapshot-checkpoint-receipt","version":1,
            "serviceId":service_id,"scopeId":scope,"keyEpoch":request.object.key_epoch,"objectId":object_id,
            "sequence":sequence,"supersedesThrough":proof.expected_sequence,"policyRevision":policy.revision,
            "requestId":proof.request_id,"authorizationHash":authorization_hash}),
            &service_id,
            DOMAIN,
        )
    }
}

pub(super) async fn checkpoint(
    State(state): State<HttpState>,
    RoutePath(scope): RoutePath<String>,
    headers: HeaderMap,
    body: Result<Json<Request>, axum::extract::rejection::JsonRejection>,
) -> Result<Json<SignedEnvelope<Value>>, ApiError> {
    let token = bearer(&headers)?;
    let request = body
        .map_err(|_| failure(StatusCode::BAD_REQUEST, "Invalid checkpoint request"))?
        .0;
    let trusted = state
        .trusted_owner
        .ok_or_else(|| failure(StatusCode::FORBIDDEN, "Checkpoint owner is not configured"))?;
    state.store.telemetry.emit(
        Level::Info,
        "storage.checkpoint.requested",
        "checkpoint",
        "pending",
        &scope,
        0.0,
        json!({}),
    );
    let telemetry = state.store.telemetry.clone();
    let event_scope = scope.clone();
    let result = tokio::task::spawn_blocking(move || {
        state
            .store
            .checkpoint(&scope, &token, request, &trusted, &state.origin)
    })
    .await
    .map_err(|_| {
        failure(
            StatusCode::SERVICE_UNAVAILABLE,
            "Checkpoint storage unavailable",
        )
    })?;
    result.map(Json).map_err(|message| {
        let (status, code) = if message.starts_with("Checkpoint inventory changed:") { (StatusCode::CONFLICT, "checkpoint_conflict") }
            else if message.contains("owner") || message.contains("device") || message.contains("signature") || message.contains("access") || message.contains("Scope unavailable") { (StatusCode::FORBIDDEN, "checkpoint_forbidden") }
            else if message.contains("binding") || message.contains("expired") || message.contains("Invalid object") || message.contains("Invalid encrypted") { (StatusCode::BAD_REQUEST, "checkpoint_invalid") }
            else { (StatusCode::SERVICE_UNAVAILABLE, "checkpoint_unavailable") };
        telemetry.emit(Level::Warn, "storage.checkpoint.rejected", "checkpoint", "error", &event_scope, 0.0, json!({"error_code":code}));
        if status == StatusCode::CONFLICT {
            (status, Json(json!({"code":code,"message":"Checkpoint inventory changed",
                "currentSequence":message.split(':').next_back().and_then(|value|value.parse::<u64>().ok())})))
        } else { (status, Json(json!({"code":code,"message":message}))) }
    })
}
