//! Durable opaque object replication. This module never loads application documents.
use axum::{
    Json, Router,
    extract::{DefaultBodyLimit, Path as RoutePath, Query, State},
    http::{HeaderMap, StatusCode},
    routing::{get, put},
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use hmac::{Hmac, Mac};
use meta_mesh_core::{
    DeviceCertificate, PublicIdentity, SignedEnvelope, canonicalize_json, public_key_from_seed,
    public_key_id, sign_json_envelope, verify_device_certificate_chain, verify_signed_envelope,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::HashMap,
    fs::{self, File, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::{SystemTime, UNIX_EPOCH},
};
use tower_http::cors::CorsLayer;

pub const DOMAIN: &str = "RUSTY/2";
const MAX_OBJECT_BYTES: usize = 16 * 1024 * 1024;
const MAX_SCOPE_BYTES: u64 = 1024 * 1024 * 1024;
const MAX_SCOPE_OBJECTS: usize = 10_000;
const ENROLLMENT_CHALLENGE_TTL_MS: u64 = 120_000;
const MAX_PENDING_CHALLENGES: usize = 128;
const MAX_PENDING_CHALLENGES_PER_SCOPE: usize = 8;

type ApiError = (StatusCode, Json<Value>);
fn failure(status: StatusCode, message: &str) -> ApiError {
    (status, Json(json!({"message": message})))
}
fn valid_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 128
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}
fn digest(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(bytes))
}
fn now_ms() -> Result<u64, String> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis().try_into().unwrap_or(u64::MAX))
        .map_err(|_| "System clock is before Unix epoch".into())
}
fn trusted_identity_matches(identity: &PublicIdentity, trusted: &PublicIdentity) -> bool {
    identity.person_id == trusted.person_id && identity.public_key == trusted.public_key
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BlindObject {
    version: u8,
    scope_id: String,
    key_epoch: u64,
    nonce: String,
    ciphertext: String,
}
impl BlindObject {
    fn validate(&self, scope: &str) -> Result<(), String> {
        if self.version != 1
            || self.scope_id != scope
            || !valid_id(scope)
            || self.key_epoch == 0
            || self.key_epoch > 9_007_199_254_740_991
        {
            return Err("Invalid object scope or epoch".into());
        }
        let nonce = URL_SAFE_NO_PAD
            .decode(&self.nonce)
            .map_err(|_| "Invalid nonce")?;
        let ciphertext = URL_SAFE_NO_PAD
            .decode(&self.ciphertext)
            .map_err(|_| "Invalid ciphertext")?;
        if nonce.len() != 12 || ciphertext.len() < 16 || ciphertext.len() > MAX_OBJECT_BYTES {
            return Err("Invalid encrypted object size".into());
        }
        Ok(())
    }
    pub fn id(&self) -> Result<String, String> {
        let value = serde_json::to_value(self).map_err(|e| e.to_string())?;
        Ok(digest(
            meta_mesh_core::canonicalize_json(&value)?.as_bytes(),
        ))
    }
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ScopePolicy {
    revision: u64,
    read_mac: String,
    write_mac: String,
    revoked: bool,
    #[serde(default)]
    owner_person_id: Option<String>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TrustedOwner {
    pub identity: PublicIdentity,
    pub allowed_controller_device_ids: Vec<String>,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct EnrollmentChallengeRequest {
    version: u8,
    scope_id: String,
    identity: PublicIdentity,
    device_id: String,
    certificates: Vec<DeviceCertificate>,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ScopeEnrollmentRequest {
    challenge: SignedEnvelope<Value>,
    identity: PublicIdentity,
    device_id: String,
    certificates: Vec<DeviceCertificate>,
    read_token: String,
    write_token: String,
    revoked: bool,
    authorization: SignedEnvelope<ScopeEnrollmentAuthorization>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ScopeEnrollmentAuthorization {
    kind: String,
    version: u8,
    challenge_id: String,
    nonce: String,
    service_id: String,
    public_origin: String,
    scope_id: String,
    person_id: String,
    device_id: String,
    device_key_id: String,
    expected_revision: u64,
    read_token_hash: String,
    write_token_hash: String,
    revoked: bool,
    expires_at: u64,
}
#[cfg(test)]
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ScopeApproval {
    expected_revision: u64,
    read_token: String,
    write_token: String,
    revoked: bool,
}
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PendingChallenge {
    scope_id: String,
    person_id: String,
    device_id: String,
    expires_at: u64,
    envelope: SignedEnvelope<Value>,
}
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct StoredObject {
    sequence: u64,
    object_id: String,
    object: BlindObject,
}
#[derive(Clone)]
struct ObjectMetadata {
    sequence: u64,
    object_id: String,
}

#[derive(Clone)]
pub struct BlindStore {
    directory: Arc<PathBuf>,
    seed: [u8; 32],
    lock: Arc<Mutex<()>>,
    _process_lock: Arc<File>,
    inventories: Arc<Mutex<HashMap<String, Vec<ObjectMetadata>>>>,
}
impl BlindStore {
    pub fn open(directory: PathBuf) -> Result<Self, String> {
        if directory.exists() {
            for entry in fs::read_dir(&directory).map_err(|_| "Storage directory unavailable")? {
                let name = entry
                    .map_err(|_| "Storage directory unavailable")?
                    .file_name();
                let name = name.to_str().ok_or("Unknown file in storage directory")?;
                if !["service-key", "scopes", "storage.lock", "enrollment"].contains(&name)
                    && !name.starts_with(".pending-")
                {
                    return Err("Legacy or unknown state requires client re-encryption into a fresh directory".into());
                }
            }
            if directory.join("scopes").exists() && !directory.join("service-key").exists() {
                return Err(
                    "Existing blind storage lost its service key; restore the key before startup"
                        .into(),
                );
            }
        }
        fs::create_dir_all(&directory).map_err(|e| e.to_string())?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&directory, fs::Permissions::from_mode(0o700))
                .map_err(|e| e.to_string())?;
        }
        let process_lock = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(directory.join("storage.lock"))
            .map_err(|_| "Storage lock unavailable")?;
        process_lock
            .try_lock()
            .map_err(|_| "Another Rusty process owns this storage directory")?;
        let seed_path = directory.join("service-key");
        let seed = if seed_path.exists() {
            fs::read(&seed_path)
                .map_err(|e| e.to_string())?
                .try_into()
                .map_err(|_| "Invalid service identity key")?
        } else {
            let seed: [u8; 32] = rand::random();
            atomic_write(&seed_path, &seed)?;
            seed
        };
        public_key_from_seed(&seed)?;
        Ok(Self {
            directory: Arc::new(directory),
            seed,
            lock: Arc::new(Mutex::new(())),
            _process_lock: Arc::new(process_lock),
            inventories: Arc::new(Mutex::new(HashMap::new())),
        })
    }
    pub fn public_key(&self) -> Result<String, String> {
        public_key_from_seed(&self.seed)
    }
    fn token_mac(&self, scope: &str, token: &str) -> Result<String, String> {
        if token.len() < 43 || token.len() > 128 || !valid_id(token) {
            return Err("Storage token must contain 43–128 base64url characters".into());
        }
        let mut mac =
            Hmac::<Sha256>::new_from_slice(&self.seed).map_err(|_| "Invalid service key")?;
        mac.update(format!("storage/{scope}\0{token}").as_bytes());
        Ok(URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes()))
    }
    fn scope_dir(&self, scope: &str) -> Result<PathBuf, String> {
        if !valid_id(scope) {
            return Err("Invalid opaque scope ID".into());
        }
        Ok(self.directory.join("scopes").join(scope))
    }
    fn policy(&self, scope: &str) -> Result<ScopePolicy, String> {
        serde_json::from_slice(
            &fs::read(self.scope_dir(scope)?.join("policy.json"))
                .map_err(|_| "Scope unavailable")?,
        )
        .map_err(|_| "Invalid scope policy".into())
    }
    fn authorize(&self, scope: &str, token: &str, write: bool) -> Result<ScopePolicy, String> {
        let policy = self.policy(scope)?;
        if policy.revoked {
            return Err("Storage access revoked".into());
        }
        let expected = URL_SAFE_NO_PAD
            .decode(if write {
                &policy.write_mac
            } else {
                &policy.read_mac
            })
            .map_err(|_| "Invalid storage policy")?;
        let mut mac =
            Hmac::<Sha256>::new_from_slice(&self.seed).map_err(|_| "Invalid service key")?;
        mac.update(format!("storage/{scope}\0{token}").as_bytes());
        mac.verify_slice(&expected)
            .map_err(|_| "Storage access denied")?;
        Ok(policy)
    }
    #[cfg(test)]
    fn approve(&self, scope: &str, approval: ScopeApproval) -> Result<u64, String> {
        let _guard = self.lock.lock().map_err(|_| "Storage lock unavailable")?;
        let directory = self.scope_dir(scope)?;
        let revision = if directory.join("policy.json").exists() {
            self.policy(scope)?.revision
        } else {
            0
        };
        if approval.expected_revision != revision {
            return Err("Storage policy revision conflict".into());
        }
        let next = revision
            .checked_add(1)
            .ok_or("Storage policy revision exhausted")?;
        let policy = ScopePolicy {
            revision: next,
            read_mac: self.token_mac(scope, &approval.read_token)?,
            write_mac: self.token_mac(scope, &approval.write_token)?,
            revoked: approval.revoked,
            owner_person_id: None,
        };
        fs::create_dir_all(directory.join("objects")).map_err(|e| e.to_string())?;
        for ancestor in [
            self.directory.as_path(),
            self.directory.join("scopes").as_path(),
            directory.as_path(),
        ] {
            File::open(ancestor)
                .and_then(|f| f.sync_all())
                .map_err(|_| "Scope durability failed")?;
        }
        atomic_write(
            &directory.join("policy.json"),
            &serde_json::to_vec(&policy).map_err(|e| e.to_string())?,
        )?;
        Ok(next)
    }
    fn policy_revision(&self, scope: &str) -> Result<u64, String> {
        let path = self.scope_dir(scope)?.join("policy.json");
        if !path.exists() {
            return Ok(0);
        }
        Ok(self.policy(scope)?.revision)
    }
    fn create_challenge(
        &self,
        scope: &str,
        person_id: &str,
        device_id: &str,
        device_key_id: &str,
        origin: &str,
    ) -> Result<SignedEnvelope<Value>, String> {
        let _guard = self.lock.lock().map_err(|_| "Storage lock unavailable")?;
        let now = now_ms()?;
        let enrollment_dir = self.directory.join("enrollment");
        fs::create_dir_all(&enrollment_dir).map_err(|_| "Enrollment storage unavailable")?;
        let mut global_pending = 0usize;
        let mut scope_pending = 0usize;
        let mut controller_pending = 0usize;
        for entry in fs::read_dir(&enrollment_dir).map_err(|_| "Enrollment storage unavailable")? {
            let path = entry.map_err(|_| "Enrollment storage unavailable")?.path();
            if path.extension().is_none_or(|extension| extension != "json") {
                continue;
            }
            let pending: PendingChallenge = match fs::read(&path)
                .ok()
                .and_then(|bytes| serde_json::from_slice(&bytes).ok())
            {
                Some(value) => value,
                None => return Err("Invalid enrollment state".into()),
            };
            if pending.expires_at <= now {
                fs::remove_file(&path).map_err(|_| "Enrollment storage unavailable")?;
            } else {
                global_pending += 1;
                if pending.person_id == person_id {
                    controller_pending += 1;
                    if pending.scope_id == scope {
                        scope_pending += 1;
                    }
                }
            }
        }
        if global_pending >= MAX_PENDING_CHALLENGES
            || scope_pending >= MAX_PENDING_CHALLENGES_PER_SCOPE
            || controller_pending >= MAX_PENDING_CHALLENGES_PER_SCOPE
        {
            return Err("Enrollment challenge capacity exceeded".into());
        }
        let revision = self.policy_revision(scope)?;
        let issued_at = now;
        let expires_at = issued_at
            .checked_add(ENROLLMENT_CHALLENGE_TTL_MS)
            .ok_or("Enrollment time overflow")?;
        let challenge_id = URL_SAFE_NO_PAD.encode(rand::random::<[u8; 32]>());
        let nonce = URL_SAFE_NO_PAD.encode(rand::random::<[u8; 32]>());
        let service_public_key = self.public_key()?;
        let service_id = public_key_id(&service_public_key)?;
        let envelope = sign_json_envelope(
            &self.seed,
            json!({
                "kind": "rusty-enrollment-challenge", "version": 1,
                "challengeId": challenge_id, "nonce": nonce, "serviceId": service_id,
                "publicOrigin": origin, "scopeId": scope, "personId": person_id,
                "deviceId": device_id, "deviceKeyId": device_key_id,
                "expectedRevision": revision, "issuedAt": issued_at, "expiresAt": expires_at
            }),
            service_id,
            DOMAIN,
        )?;
        let pending = PendingChallenge {
            scope_id: scope.into(),
            person_id: person_id.into(),
            device_id: device_id.into(),
            expires_at,
            envelope: envelope.clone(),
        };
        atomic_write(
            &enrollment_dir.join(format!("{challenge_id}.json")),
            &serde_json::to_vec(&pending).map_err(|_| "Enrollment state invalid")?,
        )?;
        Ok(envelope)
    }
    fn approve_signed(
        &self,
        scope: &str,
        request: ScopeEnrollmentRequest,
        trusted_owner: &TrustedOwner,
        origin: &str,
    ) -> Result<SignedEnvelope<Value>, String> {
        let _guard = self.lock.lock().map_err(|_| "Storage lock unavailable")?;
        if !trusted_identity_matches(&request.identity, &trusted_owner.identity)
            || request.certificates.is_empty()
            || !trusted_owner
                .allowed_controller_device_ids
                .iter()
                .any(|id| id == &request.device_id)
        {
            return Err("Untrusted controller identity or device".into());
        }
        let device_public_key = verify_device_certificate_chain(
            &request.identity,
            &request.device_id,
            &request.certificates,
            "MATCH/1",
        )?;
        let device_key_id = public_key_id(&device_public_key)?;
        if device_key_id != request.device_id {
            return Err("Controller device key mismatch".into());
        }
        let challenge_id = request
            .challenge
            .payload
            .get("challengeId")
            .and_then(Value::as_str)
            .filter(|id| valid_id(id))
            .ok_or("Invalid enrollment challenge")?;
        let challenge_path = self
            .directory
            .join("enrollment")
            .join(format!("{challenge_id}.json"));
        let pending: PendingChallenge = serde_json::from_slice(
            &fs::read(&challenge_path).map_err(|_| "Enrollment challenge expired or consumed")?,
        )
        .map_err(|_| "Enrollment challenge invalid")?;
        let service_public_key = self.public_key()?;
        let service_id = public_key_id(&service_public_key)?;
        if pending.envelope != request.challenge
            || request.challenge.signer_key_id != service_id
            || !verify_signed_envelope(&request.challenge, &service_public_key, DOMAIN)?
            || pending.scope_id != scope
            || pending.person_id != request.identity.person_id
            || pending.device_id != request.device_id
            || pending.expires_at <= now_ms()?
        {
            return Err("Enrollment challenge binding, signature, or expiry invalid".into());
        }
        let proof = &request.authorization.payload;
        let payload_challenge_id = proof.challenge_id.as_str();
        let challenge_payload = &request.challenge.payload;
        let read_hash = digest(request.read_token.as_bytes());
        let write_hash = digest(request.write_token.as_bytes());
        if proof.kind != "rusty-scope-enrollment"
            || proof.version != 1
            || payload_challenge_id != challenge_id
            || Some(proof.nonce.as_str()) != challenge_payload.get("nonce").and_then(Value::as_str)
            || Some(proof.service_id.as_str())
                != challenge_payload.get("serviceId").and_then(Value::as_str)
            || proof.public_origin != origin
            || proof.scope_id != scope
            || proof.person_id != request.identity.person_id
            || proof.device_id != request.device_id
            || proof.device_key_id != device_key_id
            || Some(proof.expected_revision)
                != challenge_payload
                    .get("expectedRevision")
                    .and_then(Value::as_u64)
            || proof.read_token_hash != read_hash
            || proof.write_token_hash != write_hash
            || proof.revoked != request.revoked
            || Some(proof.expires_at) != challenge_payload.get("expiresAt").and_then(Value::as_u64)
            || request.authorization.signer_key_id != device_key_id
            || !verify_signed_envelope(&request.authorization, &device_public_key, "MATCH/1")?
        {
            return Err("Controller authorization signature or binding invalid".into());
        }
        let expected_revision = proof.expected_revision;
        let directory = self.scope_dir(scope)?;
        let current = if directory.join("policy.json").exists() {
            self.policy(scope)?
        } else {
            ScopePolicy {
                revision: 0,
                read_mac: String::new(),
                write_mac: String::new(),
                revoked: false,
                owner_person_id: None,
            }
        };
        if current.revision != expected_revision {
            return Err("Storage policy revision conflict".into());
        }
        if current
            .owner_person_id
            .as_ref()
            .is_some_and(|owner| owner != &request.identity.person_id)
        {
            return Err("Scope owner binding conflict".into());
        }
        let revision = current
            .revision
            .checked_add(1)
            .ok_or("Storage policy revision exhausted")?;
        let policy = ScopePolicy {
            revision,
            read_mac: self.token_mac(scope, &request.read_token)?,
            write_mac: self.token_mac(scope, &request.write_token)?,
            revoked: request.revoked,
            owner_person_id: Some(request.identity.person_id.clone()),
        };
        fs::create_dir_all(directory.join("objects")).map_err(|e| e.to_string())?;
        for ancestor in [
            self.directory.as_path(),
            self.directory.join("scopes").as_path(),
            directory.as_path(),
        ] {
            File::open(ancestor)
                .and_then(|file| file.sync_all())
                .map_err(|_| "Scope durability failed")?;
        }
        atomic_write(
            &directory.join("policy.json"),
            &serde_json::to_vec(&policy).map_err(|_| "Storage policy invalid")?,
        )?;
        fs::remove_file(&challenge_path).map_err(|_| "Enrollment challenge consume failed")?;
        File::open(
            challenge_path
                .parent()
                .ok_or("Enrollment storage unavailable")?,
        )
        .and_then(|file| file.sync_all())
        .map_err(|_| "Enrollment durability failed")?;
        let authorization_envelope = serde_json::to_value(&request.authorization)
            .map_err(|_| "Controller authorization invalid")?;
        let authorization_hash = digest(canonicalize_json(&authorization_envelope)?.as_bytes());
        sign_json_envelope(
            &self.seed,
            json!({
                "kind": "rusty-scope-policy-receipt", "version": 1,
                "serviceId": service_id, "scopeId": scope,
                "personId": request.identity.person_id, "revision": revision,
                "revoked": request.revoked, "challengeId": challenge_id,
                "authorizationHash": authorization_hash
            }),
            service_id,
            DOMAIN,
        )
    }
    fn objects(&self, scope: &str) -> Result<Vec<ObjectMetadata>, String> {
        if let Some(cached) = self
            .inventories
            .lock()
            .map_err(|_| "Inventory cache unavailable")?
            .get(scope)
        {
            return Ok(cached.clone());
        }
        let mut objects = Vec::new();
        for entry in fs::read_dir(self.scope_dir(scope)?.join("objects"))
            .map_err(|_| "Storage unavailable")?
        {
            let path = entry.map_err(|_| "Storage unavailable")?.path();
            if path
                .extension()
                .is_some_and(|extension| extension == "json")
            {
                let value: StoredObject =
                    serde_json::from_slice(&fs::read(path).map_err(|_| "Storage unavailable")?)
                        .map_err(|_| "Invalid stored object")?;
                value.object.validate(scope)?;
                if value.object.id()? != value.object_id {
                    return Err("Stored object integrity failure".into());
                }
                objects.push(ObjectMetadata {
                    sequence: value.sequence,
                    object_id: value.object_id,
                });
                if objects.len() > MAX_SCOPE_OBJECTS {
                    return Err("Storage object capacity exceeded".into());
                }
            }
        }
        objects.sort_by_key(|value| value.sequence);
        if objects
            .iter()
            .enumerate()
            .any(|(index, value)| value.sequence != (index as u64 + 1))
        {
            return Err("Stored object sequence integrity failure".into());
        }
        let mut cache = self
            .inventories
            .lock()
            .map_err(|_| "Inventory cache unavailable")?;
        if cache.len() < 128 || cache.contains_key(scope) {
            cache.insert(scope.to_owned(), objects.clone());
        }
        Ok(objects)
    }
    fn save(
        &self,
        scope: &str,
        token: &str,
        object: BlindObject,
        request_id: &str,
    ) -> Result<SignedEnvelope<Value>, String> {
        object.validate(scope)?;
        if !valid_id(request_id) {
            return Err("Invalid receipt challenge".into());
        }
        let _guard = self.lock.lock().map_err(|_| "Storage lock unavailable")?;
        let policy = self.authorize(scope, token, true)?;
        let object_id = object.id()?;
        let path = self
            .scope_dir(scope)?
            .join("objects")
            .join(format!("{object_id}.json"));
        let sequence = if path.exists() {
            let stored: StoredObject =
                serde_json::from_slice(&fs::read(&path).map_err(|_| "Storage unavailable")?)
                    .map_err(|_| "Invalid stored object")?;
            if stored.object != object || stored.object_id != object_id {
                return Err("Stored object mismatch".into());
            }
            stored.sequence
        } else {
            let objects = self.objects(scope)?;
            let used = fs::read_dir(path.parent().ok_or("Invalid object path")?)
                .map_err(|e| e.to_string())?
                .try_fold(0u64, |total, entry| {
                    let size = entry?.metadata()?.len();
                    Ok::<u64, std::io::Error>(total.saturating_add(size))
                })
                .map_err(|e| e.to_string())?;
            let bytes = serde_json::to_vec(&object).map_err(|e| e.to_string())?;
            if objects.len() >= MAX_SCOPE_OBJECTS
                || used.saturating_add(bytes.len() as u64 + 1024) > MAX_SCOPE_BYTES
            {
                return Err("Storage capacity exceeded".into());
            }
            let sequence = objects.last().map_or(Ok(1), |value| {
                value
                    .sequence
                    .checked_add(1)
                    .ok_or("Object sequence exhausted")
            })?;
            let record = StoredObject {
                sequence,
                object_id: object_id.clone(),
                object: object.clone(),
            };
            if let Err(error) = atomic_write(
                &path,
                &serde_json::to_vec(&record).map_err(|e| e.to_string())?,
            ) {
                self.inventories
                    .lock()
                    .map_err(|_| "Inventory cache unavailable")?
                    .remove(scope);
                return Err(error);
            }
            if let Some(cached) = self
                .inventories
                .lock()
                .map_err(|_| "Inventory cache unavailable")?
                .get_mut(scope)
            {
                cached.push(ObjectMetadata {
                    sequence,
                    object_id: object_id.clone(),
                });
            }
            sequence
        };
        let public_key = self.public_key()?;
        let service_id = public_key_id(&public_key)?;
        sign_json_envelope(
            &self.seed,
            json!({"kind": "blind-storage-receipt", "version": 2, "serviceId": service_id,
            "scopeId": scope, "keyEpoch": object.key_epoch, "objectId": object_id, "sequence": sequence,
            "policyRevision": policy.revision, "requestId": request_id}),
            service_id,
            DOMAIN,
        )
    }
}

fn atomic_write(path: &Path, bytes: &[u8]) -> Result<(), String> {
    let parent = path.parent().ok_or("Invalid storage path")?;
    fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    let temporary = parent.join(format!(".pending-{}", rand::random::<u64>()));
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let result = (|| {
        let mut file = options.open(&temporary)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        fs::rename(&temporary, path)?;
        File::open(parent)?.sync_all()?;
        Ok::<(), std::io::Error>(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result.map_err(|_| "Durable storage commit failed".into())
}

#[derive(Clone)]
struct HttpState {
    store: BlindStore,
    trusted_owner: Option<TrustedOwner>,
    origin: String,
}
fn bearer(headers: &HeaderMap) -> Result<String, ApiError> {
    headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .filter(|v| !v.is_empty() && v.len() <= 256)
        .map(str::to_owned)
        .ok_or_else(|| failure(StatusCode::UNAUTHORIZED, "Storage authentication required"))
}
pub fn router(
    store: BlindStore,
    origin: String,
    trusted_owner: Option<TrustedOwner>,
    origins: Vec<String>,
) -> Result<Router, String> {
    let cors_origins = origins
        .iter()
        .map(|value| value.parse())
        .collect::<Result<Vec<axum::http::HeaderValue>, _>>()
        .map_err(|_| "Invalid CORS origin")?;
    let state = HttpState {
        trusted_owner,
        store,
        origin,
    };
    Ok(Router::new()
        .route(
            "/health",
            get(|| async { Json(json!({"status": "ok", "mode": "blind"})) }),
        )
        .route("/.well-known/mesh-lighthouse", get(discovery))
        .route(
            "/v2/enrollment/challenge",
            axum::routing::post(enrollment_challenge),
        )
        .route("/v2/scopes/{scope}", put(approve_scope))
        .route("/v2/scopes/{scope}/objects", get(inventory))
        .route(
            "/v2/scopes/{scope}/objects/{object_id}",
            get(download).put(upload),
        )
        .layer(DefaultBodyLimit::max(MAX_OBJECT_BYTES * 2))
        .layer(
            CorsLayer::new()
                .allow_origin(cors_origins)
                .allow_methods([
                    axum::http::Method::GET,
                    axum::http::Method::POST,
                    axum::http::Method::PUT,
                ])
                .allow_headers([
                    axum::http::header::AUTHORIZATION,
                    axum::http::header::CONTENT_TYPE,
                    axum::http::HeaderName::from_static("x-rusty-request-id"),
                ]),
        )
        .with_state(state))
}
async fn discovery(State(state): State<HttpState>) -> Result<Json<Value>, ApiError> {
    let public_key = state.store.public_key().map_err(|_| {
        failure(
            StatusCode::SERVICE_UNAVAILABLE,
            "Service identity unavailable",
        )
    })?;
    let service_id = public_key_id(&public_key).map_err(|_| {
        failure(
            StatusCode::SERVICE_UNAVAILABLE,
            "Service identity unavailable",
        )
    })?;
    Ok(Json(
        json!({"protocolVersions": [2], "publicOrigin": state.origin, "displayName": "Rusty",
        "service": {"serviceId": service_id, "publicKey": public_key},
        "capabilities": {"modes": ["blind"], "encryptedObjectReplication": true, "applicationWrites": false, "classification": false}}),
    ))
}
async fn enrollment_challenge(
    State(state): State<HttpState>,
    Json(request): Json<EnrollmentChallengeRequest>,
) -> Result<Json<Value>, ApiError> {
    if request.version != 1 || !valid_id(&request.scope_id) {
        return Err(failure(
            StatusCode::BAD_REQUEST,
            "Invalid enrollment request",
        ));
    }
    let trusted_owner = state.trusted_owner.as_ref().ok_or_else(|| {
        failure(
            StatusCode::FORBIDDEN,
            "No trusted owner controller configured",
        )
    })?;
    if !trusted_identity_matches(&request.identity, &trusted_owner.identity)
        || !trusted_owner
            .allowed_controller_device_ids
            .iter()
            .any(|id| id == &request.device_id)
    {
        return Err(failure(
            StatusCode::FORBIDDEN,
            "Untrusted controller identity or device",
        ));
    }
    let device_public_key = verify_device_certificate_chain(
        &request.identity,
        &request.device_id,
        &request.certificates,
        "MATCH/1",
    )
    .map_err(|_| {
        failure(
            StatusCode::FORBIDDEN,
            "Untrusted controller certificate chain",
        )
    })?;
    let device_key_id = public_key_id(&device_public_key)
        .map_err(|_| failure(StatusCode::FORBIDDEN, "Invalid controller device key"))?;
    let store = state.store.clone();
    let scope = request.scope_id;
    let person_id = request.identity.person_id;
    let device_id = request.device_id;
    let origin = state.origin.clone();
    let challenge = tokio::task::spawn_blocking(move || {
        let revision = store.policy_revision(&scope)?;
        if revision > 0 {
            let policy = store.policy(&scope)?;
            if policy
                .owner_person_id
                .as_ref()
                .is_some_and(|owner| owner != &person_id)
            {
                return Err("Scope owner binding conflict".into());
            }
        }
        store.create_challenge(&scope, &person_id, &device_id, &device_key_id, &origin)
    })
    .await
    .map_err(|_| {
        failure(
            StatusCode::SERVICE_UNAVAILABLE,
            "Enrollment storage unavailable",
        )
    })?
    .map_err(|message| {
        failure(
            if message.contains("capacity") {
                StatusCode::TOO_MANY_REQUESTS
            } else {
                StatusCode::CONFLICT
            },
            &message,
        )
    })?;
    Ok(Json(json!({"challenge": challenge})))
}
async fn approve_scope(
    State(state): State<HttpState>,
    RoutePath(scope): RoutePath<String>,
    Json(request): Json<ScopeEnrollmentRequest>,
) -> Result<Json<Value>, ApiError> {
    if !valid_id(&scope) {
        return Err(failure(StatusCode::BAD_REQUEST, "Invalid scope ID"));
    }
    let trusted_owner = state.trusted_owner.clone().ok_or_else(|| {
        failure(
            StatusCode::FORBIDDEN,
            "No trusted owner controller configured",
        )
    })?;
    let origin = state.origin.clone();
    let receipt = tokio::task::spawn_blocking(move || {
        state
            .store
            .approve_signed(&scope, request, &trusted_owner, &origin)
    })
    .await
    .map_err(|_| failure(StatusCode::SERVICE_UNAVAILABLE, "Storage unavailable"))?
    .map_err(|message| {
        let status = if message.contains("expired")
            || message.contains("expiry")
            || message.contains("consumed")
        {
            StatusCode::GONE
        } else if message.contains("Untrusted")
            || message.contains("signature")
            || message.contains("binding")
        {
            StatusCode::FORBIDDEN
        } else if message.contains("revision conflict")
            || message.contains("owner binding conflict")
        {
            StatusCode::CONFLICT
        } else {
            StatusCode::BAD_REQUEST
        };
        failure(status, &message)
    })?;
    Ok(Json(json!({"receipt": receipt})))
}
async fn upload(
    State(state): State<HttpState>,
    RoutePath((scope, object_id)): RoutePath<(String, String)>,
    headers: HeaderMap,
    Json(object): Json<BlindObject>,
) -> Result<Json<SignedEnvelope<Value>>, ApiError> {
    let token = bearer(&headers)?;
    let request_id = headers
        .get("x-rusty-request-id")
        .and_then(|v| v.to_str().ok())
        .filter(|v| valid_id(v))
        .ok_or_else(|| failure(StatusCode::BAD_REQUEST, "Receipt challenge required"))?
        .to_owned();
    object
        .validate(&scope)
        .map_err(|message| failure(StatusCode::BAD_REQUEST, &message))?;
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
    let receipt =
        tokio::task::spawn_blocking(move || state.store.save(&scope, &token, object, &request_id))
            .await
            .map_err(|_| failure(StatusCode::SERVICE_UNAVAILABLE, "Storage unavailable"))?
            .map_err(|message| {
                failure(
                    if message.contains("access") || message.contains("Scope unavailable") {
                        StatusCode::FORBIDDEN
                    } else {
                        StatusCode::SERVICE_UNAVAILABLE
                    },
                    &message,
                )
            })?;
    Ok(Json(receipt))
}
#[derive(Deserialize)]
struct InventoryQuery {
    #[serde(default)]
    after: u64,
}
async fn inventory(
    State(state): State<HttpState>,
    RoutePath(scope): RoutePath<String>,
    headers: HeaderMap,
    Query(query): Query<InventoryQuery>,
) -> Result<Json<Value>, ApiError> {
    let token = bearer(&headers)?;
    let result = tokio::task::spawn_blocking(move || {
        let _guard = state.store.lock.lock().map_err(|_| "Storage lock unavailable")?;
        state.store.authorize(&scope, &token, false)?;
        let objects = state.store.objects(&scope)?;
        let page = objects.iter().filter(|o| o.sequence > query.after).take(128).map(|o| json!({"objectId": o.object_id, "sequence": o.sequence})).collect::<Vec<_>>();
        let cursor = page.last().and_then(|o| o["sequence"].as_u64()).unwrap_or(query.after);
        Ok::<Value, String>(json!({"objects": page, "cursor": cursor, "hasMore": objects.last().is_some_and(|o| o.sequence > cursor)}))
    }).await.map_err(|_| failure(StatusCode::SERVICE_UNAVAILABLE, "Storage unavailable"))?.map_err(|message| failure(StatusCode::FORBIDDEN, &message))?;
    Ok(Json(result))
}
async fn download(
    State(state): State<HttpState>,
    RoutePath((scope, object_id)): RoutePath<(String, String)>,
    headers: HeaderMap,
) -> Result<Json<BlindObject>, ApiError> {
    if !valid_id(&object_id) {
        return Err(failure(StatusCode::BAD_REQUEST, "Invalid object ID"));
    }
    let token = bearer(&headers)?;
    let object = tokio::task::spawn_blocking(move || {
        let _guard = state
            .store
            .lock
            .lock()
            .map_err(|_| "Storage lock unavailable")?;
        state.store.authorize(&scope, &token, false)?;
        let path = state
            .store
            .scope_dir(&scope)?
            .join("objects")
            .join(format!("{object_id}.json"));
        let stored: StoredObject =
            serde_json::from_slice(&fs::read(path).map_err(|_| "Object unavailable")?)
                .map_err(|_| "Invalid stored object")?;
        stored.object.validate(&scope)?;
        if stored.object_id != object_id || stored.object.id()? != object_id {
            return Err("Object integrity failure".into());
        }
        Ok::<BlindObject, String>(stored.object)
    })
    .await
    .map_err(|_| failure(StatusCode::SERVICE_UNAVAILABLE, "Storage unavailable"))?
    .map_err(|message| failure(StatusCode::FORBIDDEN, &message))?;
    Ok(Json(object))
}

#[cfg(test)]
#[path = "blind_tests.rs"]
mod tests;
