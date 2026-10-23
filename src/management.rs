//! Person/resource authority, separate from device-certificate ancestry.
use super::*;
use std::collections::BTreeMap;

const MAX_RECORD_BYTES: u64 = 512 * 1024;
const MAX_INDEX_BYTES: u64 = 128 * 1024;
const MAX_RESOURCES: usize = 256;
const MAX_REVOKED_DEVICES: usize = 4096;
const MAX_SAFE_INTEGER: u64 = 9_007_199_254_740_991;

#[derive(Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Capability {
    kind: String,
    version: u8,
    service_id: String,
    origin: String,
    person_id: String,
    resource_kind: String,
    resource_id: String,
    revision: u64,
    operations: Vec<String>,
    revoked_device_ids: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    restored_device_ids: Option<Vec<String>>,
    request_id: String,
    authorization_hash: String,
    issued_at: u64,
}
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PolicyUpdate {
    kind: String,
    version: u8,
    service_id: String,
    origin: String,
    person_id: String,
    device_id: String,
    resource_kind: String,
    resource_id: String,
    expected_revision: u64,
    operations: Vec<String>,
    revoked_device_ids: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    restored_device_ids: Option<Vec<String>>,
    request_id: String,
    issued_at: u64,
    expires_at: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    person_management_revision: Option<u64>,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct UpdateRequest {
    version: u8,
    identity: PublicIdentity,
    device_id: String,
    certificates: Vec<DeviceCertificate>,
    management_capability: Option<SignedEnvelope<Value>>,
    person_management_capability: Option<SignedEnvelope<Value>>,
    authorization: SignedEnvelope<PolicyUpdate>,
}
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Record {
    version: u8,
    capability: SignedEnvelope<Value>,
    identity: PublicIdentity,
    device_id: String,
    certificates: Vec<DeviceCertificate>,
    authorization: SignedEnvelope<PolicyUpdate>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    person_management_capability: Option<SignedEnvelope<Value>>,
}
#[derive(Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ManagementControllerTransfer {
    kind: String,
    version: u8,
    resource_kind: String,
    resource_id: String,
    previous_record_hash: String,
    previous_person_id: String,
    successor_identity: PublicIdentity,
    origin: String,
    transition_hash: String,
    capability: SignedEnvelope<Value>,
    transferred_at: u64,
}
// Separate from the publication projection so existing readers retain their schema.
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PublicationOwner {
    kind: String,
    version: u8,
    board_id: String,
    identity: PublicIdentity,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    succession_from_person_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    succession_transition_hash: Option<String>,
}
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Index {
    version: u8,
    resources: BTreeMap<String, String>,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Pending {
    version: u8,
    resource_kind: String,
    resource_id: String,
    expected_revision: u64,
    request_id: String,
    authorization_hash: String,
    record_hash: String,
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct StatusAuthorization {
    kind: String,
    version: u8,
    service_id: String,
    origin: String,
    person_id: String,
    device_id: String,
    resource_kind: String,
    resource_id: String,
    request_id: String,
    issued_at: u64,
    expires_at: u64,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct StatusRequest {
    version: u8,
    identity: PublicIdentity,
    device_id: String,
    certificates: Vec<DeviceCertificate>,
    authorization: SignedEnvelope<StatusAuthorization>,
}
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct StatusNonces {
    version: u8,
    used: BTreeMap<String, u64>,
}

fn resource(kind: &str, id: &str) -> Result<String, String> {
    if !["scope", "board", "person"].contains(&kind) || !valid_id(id) {
        return Err("Invalid management resource".into());
    }
    Ok(format!("{kind}/{id}"))
}
fn hash(value: &impl Serialize) -> Result<String, String> {
    Ok(digest(
        canonicalize_json(
            &serde_json::to_value(value).map_err(|_| "Invalid management evidence")?,
        )?
        .as_bytes(),
    ))
}
fn ordered_ids(ids: &[String], maximum: usize) -> bool {
    ids.len() <= maximum
        && ids.iter().all(|id| valid_id(id))
        && ids.windows(2).all(|pair| pair[0] < pair[1])
}
fn operations(kind: &str, values: &[String]) -> bool {
    let allowed: &[&str] = if kind == "person" {
        &["management.update", "resource.create"]
    } else if kind == "scope" {
        &["management.update", "scope.policy", "snapshot.checkpoint"]
    } else {
        &[
            "management.update",
            "publication.status",
            "publication.publish",
            "publication.update",
            "publication.unpublish",
            "publication.stage-file",
        ]
    };
    !values.is_empty()
        && values.len() <= allowed.len()
        && values.iter().any(|value| value == "management.update")
        && values.iter().all(|value| allowed.contains(&value.as_str()))
        && values.windows(2).all(|pair| pair[0] < pair[1])
}
fn capability(value: &SignedEnvelope<Value>) -> Result<Capability, String> {
    let cap: Capability = serde_json::from_value(value.payload.clone())
        .map_err(|_| "Invalid management capability")?;
    resource(&cap.resource_kind, &cap.resource_id)?;
    let expected_kind = if cap.resource_kind == "person" {
        "rusty-person-management-capability"
    } else {
        "rusty-scope-management-capability"
    };
    if cap.kind != expected_kind
        || (cap.resource_kind == "person" && cap.resource_id != cap.person_id)
        || cap.version != 1
        || cap.revision == 0
        || cap.revision > MAX_SAFE_INTEGER
        || !valid_id(&cap.person_id)
        || !valid_id(&cap.service_id)
        || !valid_id(&cap.request_id)
        || cap.issued_at > MAX_SAFE_INTEGER
        || !operations(&cap.resource_kind, &cap.operations)
        || !ordered_ids(&cap.revoked_device_ids, MAX_REVOKED_DEVICES)
        || cap.restored_device_ids.as_ref().is_some_and(|ids| {
            !ordered_ids(ids, MAX_REVOKED_DEVICES)
                || ids.iter().any(|id| cap.revoked_device_ids.contains(id))
        })
        || URL_SAFE_NO_PAD
            .decode(&cap.authorization_hash)
            .map_or(true, |hash| hash.len() != 32)
    {
        return Err("Invalid management capability".into());
    }
    Ok(cap)
}

impl BlindStore {
    fn person_device_allowed(
        &self,
        identity: &PublicIdentity,
        device_id: &str,
        origin: &str,
        allow_pending: bool,
    ) -> Result<bool, String> {
        if !allow_pending && self.management_pending("person", &identity.person_id)? {
            return Ok(false);
        }
        // Identity revocation is deployment-wide authority, independent of the
        // older per-person management capability. Fail closed until the current
        // signed view has been registered with this Rusty service.
        if !self.identity_device_active(identity, device_id)? {
            return Ok(false);
        }
        let Some(record) = self.management_record("person", &identity.person_id)? else {
            return Ok(true);
        };
        let cap = capability(&record.capability)?;
        Ok(cap.origin == origin
            && cap.person_id == identity.person_id
            && !cap.revoked_device_ids.iter().any(|id| id == device_id))
    }

    fn resource_identity_allowed(
        &self,
        kind: &str,
        id: &str,
        identity: &PublicIdentity,
    ) -> Result<bool, String> {
        if let Some(record) = self.management_record(kind, id)? {
            let effective = self.effective_management_identity(kind, id, &record)?;
            return Ok(trusted_identity_matches(&effective, identity));
        }
        if kind == "board"
            && self
                .stored_publication_owner(id)?
                .is_some_and(|owner| !trusted_identity_matches(&owner, identity))
        {
            return Ok(false);
        }
        match kind {
            "scope" if self.policy_revision(id)? > 0 => Ok(self
                .policy(id)?
                .owner_person_id
                .as_ref()
                .is_none_or(|owner| owner == &identity.person_id)),
            "board" => Ok(self
                .current_publication(id)?
                .is_none_or(|publication| publication.controller_person_id == identity.person_id)),
            "person" => Ok(id == identity.person_id),
            "scope" => Ok(true),
            _ => Ok(false),
        }
    }

    fn stored_publication_owner(&self, board_id: &str) -> Result<Option<PublicIdentity>, String> {
        resource("board", board_id)?;
        let path = self
            .directory
            .join("management/publication-owners")
            .join(format!("{board_id}.json"));
        if !path.exists() {
            return Ok(None);
        }
        if fs::metadata(&path)
            .map_err(|_| "Publication owner unavailable")?
            .len()
            > 16 * 1024
        {
            return Err("Invalid publication owner evidence size".into());
        }
        let evidence: SignedEnvelope<PublicationOwner> =
            serde_json::from_slice(&fs::read(path).map_err(|_| "Publication owner unavailable")?)
                .map_err(|_| "Invalid publication owner evidence")?;
        let value: SignedEnvelope<Value> = serde_json::from_value(
            serde_json::to_value(&evidence).map_err(|_| "Invalid publication owner evidence")?,
        )
        .map_err(|_| "Invalid publication owner evidence")?;
        let service_key = self.public_key()?;
        let owner = evidence.payload;
        if owner.kind != "rusty-publication-owner"
            || owner.version != 1
            || owner.board_id != board_id
            || evidence.signer_key_id != public_key_id(&service_key)?
            || !verify_signed_envelope(&value, &service_key, DOMAIN)?
            || public_key_id(&owner.identity.public_key)? != owner.identity.person_id
            || self
                .current_publication(board_id)?
                .is_some_and(|publication| {
                    publication.controller_person_id != owner.identity.person_id
                })
        {
            return Err("Publication owner evidence integrity failure".into());
        }
        Ok(Some(owner.identity))
    }

    // Call only after the complete publication command and projection are verified.
    // Persist before the projection: a crash retains the authorized original owner.
    pub(super) fn retain_publication_owner(
        &self,
        board_id: &str,
        owner: &ResourceOwner,
    ) -> Result<(), String> {
        let known = self.publication_owner(board_id, &owner.identity)?;
        if !trusted_identity_matches(&known.identity, &owner.identity) {
            return Err("Publication owner conflict".into());
        }
        let path = self
            .directory
            .join("management/publication-owners")
            .join(format!("{board_id}.json"));
        if self.stored_publication_owner(board_id)?.is_none() {
            let identity = PublicIdentity {
                person_id: owner.identity.person_id.clone(),
                public_key: owner.identity.public_key.clone(),
                display_name: String::new(),
            };
            let evidence = sign_json_envelope(
                &self.seed,
                json!({
                    "kind":"rusty-publication-owner", "version":1, "boardId":board_id, "identity":identity
                }),
                &public_key_id(&self.public_key()?)?,
                DOMAIN,
            )?;
            atomic_write(
                &path,
                &serde_json::to_vec(&evidence).map_err(|_| "Invalid publication owner evidence")?,
            )?;
        }
        // A previous rename may have succeeded while its directory sync failed.
        // Reconfirm the whole hierarchy on retries before publishing a receipt.
        sync_directory(path.parent().ok_or("Invalid publication owner path")?)
            .map_err(|_| "Publication owner durability failed")?;
        sync_directory(&self.directory.join("management"))
            .map_err(|_| "Publication owner durability failed")?;
        sync_directory(&self.directory).map_err(|_| "Publication owner durability failed")?;
        Ok(())
    }

    // A delivery writer never supplies its own identity as the board owner.
    pub(super) fn publication_owner(
        &self,
        board_id: &str,
        requester: &PublicIdentity,
    ) -> Result<ResourceOwner, String> {
        let stored = self.stored_publication_owner(board_id)?;
        let publication = self.current_publication(board_id)?;
        if let Some(record) = self.management_record("board", board_id)? {
            let effective = self.effective_management_identity("board", board_id, &record)?;
            if stored
                .as_ref()
                .is_some_and(|owner| !trusted_identity_matches(owner, &effective))
                || publication.as_ref().is_some_and(|publication| {
                    publication.controller_person_id != effective.person_id
                })
            {
                return Err("Publication owner management evidence conflict".into());
            }
            return Ok(ResourceOwner {
                identity: effective,
            });
        }
        if let Some(identity) = stored {
            return Ok(ResourceOwner { identity });
        }
        if let Some(publication) = publication {
            // Legacy publications may already have independently verified owner evidence.
            if let Some(record) =
                self.management_record("person", &publication.controller_person_id)?
            {
                return Ok(ResourceOwner {
                    identity: record.identity,
                });
            }
            if publication.controller_person_id != requester.person_id {
                return Err(
                    "Publication owner identity unavailable; owner confirmation required".into(),
                );
            }
        }
        if public_key_id(&requester.public_key)? != requester.person_id {
            return Err("Invalid publication owner identity".into());
        }
        Ok(ResourceOwner {
            identity: requester.clone(),
        })
    }

    fn resource_creation_authorized(
        &self,
        kind: &str,
        request: &UpdateRequest,
        owner: &ResourceOwner,
        origin: &str,
    ) -> Result<bool, String> {
        if !self.resource_identity_allowed(
            kind,
            &request.authorization.payload.resource_id,
            &request.identity,
        )? {
            return Ok(false);
        }
        if request.management_capability.is_some() {
            return Ok(false);
        }
        if kind != "person" {
            if let Some(record) = self.management_record("person", &request.identity.person_id)? {
                let cap = capability(&record.capability)?;
                return Ok(request.person_management_capability.as_ref()
                    == Some(&record.capability)
                    && request.authorization.payload.person_management_revision
                        == Some(cap.revision)
                    && cap.origin == origin
                    && cap.person_id == request.identity.person_id
                    && cap.operations.iter().any(|op| op == "resource.create")
                    && !cap.revoked_device_ids.contains(&request.device_id));
            }
        }
        Ok(request.person_management_capability.is_none()
            && request
                .authorization
                .payload
                .person_management_revision
                .is_none()
            && trusted_identity_matches(&request.identity, &owner.identity)
            && verify_device_certificate_chain(
                &request.identity,
                &request.device_id,
                &request.certificates,
                "MATCH/1",
            )
            .is_ok())
    }

    fn management_status(
        &self,
        kind: &str,
        id: &str,
        request: StatusRequest,
        owner: &ResourceOwner,
        origin: &str,
    ) -> Result<(Option<SignedEnvelope<Value>>, bool, SignedEnvelope<Value>), String> {
        let _guard = self
            .lock
            .lock()
            .map_err(|_| "Management storage unavailable")?;
        resource(kind, id)?;
        if request.version != 1
            || (kind == "person" && id != request.identity.person_id)
            || !self.resource_identity_allowed(kind, id, &request.identity)?
            || !trusted_identity_matches(&request.identity, &owner.identity)
            || request.certificates.is_empty()
            || request.certificates.len() > 32
            || request
                .certificates
                .iter()
                .any(|certificate| certificate.payload.person_id != request.identity.person_id)
        {
            return Err("Unauthorized management status identity".into());
        }
        let device_key = verify_device_certificate_chain(
            &request.identity,
            &request.device_id,
            &request.certificates,
            "MATCH/1",
        )
        .map_err(|_| "Unauthorized management status device")?;
        let signed: SignedEnvelope<Value> = serde_json::from_value(
            serde_json::to_value(&request.authorization)
                .map_err(|_| "Invalid management status proof")?,
        )
        .map_err(|_| "Invalid management status proof")?;
        if public_key_id(&device_key)? != request.device_id
            || signed.signer_key_id != request.device_id
            || !verify_signed_envelope(&signed, &device_key, "MATCH/1")
                .map_err(|_| "Unauthorized management status signature")?
        {
            return Err("Unauthorized management status signature".into());
        }
        let payload = &request.authorization.payload;
        let now = now_ms()?;
        if payload.kind != "rusty-management-policy-status"
            || payload.version != 1
            || payload.origin != origin
            || payload.service_id != public_key_id(&self.public_key()?)?
            || payload.person_id != request.identity.person_id
            || payload.device_id != request.device_id
            || payload.resource_kind != kind
            || payload.resource_id != id
            || !valid_id(&payload.request_id)
            || payload.issued_at > now.saturating_add(30_000)
            || payload.expires_at <= now
            || payload.expires_at > MAX_SAFE_INTEGER
            || payload.expires_at <= payload.issued_at
            || payload.expires_at - payload.issued_at > 120_000
        {
            return Err("Unauthorized or expired management status binding".into());
        }
        let record = self.management_record(kind, id)?;
        if !self.person_device_allowed(
            &request.identity,
            &request.device_id,
            origin,
            kind == "person",
        )? {
            return Err("Unauthorized or revoked person management status device".into());
        }
        if let Some(record) = &record {
            let effective_capability = self.effective_management_capability(kind, id, record)?;
            let cap = capability(&effective_capability)?;
            if cap.origin != origin
                || cap.person_id != request.identity.person_id
                || cap.revoked_device_ids.contains(&request.device_id)
            {
                return Err("Unauthorized or revoked management status device".into());
            }
        }
        let nonce_path = self.directory.join("management/status-nonces.json");
        let mut nonces = if nonce_path.exists() {
            if fs::metadata(&nonce_path)
                .map_err(|_| "Management status replay state unavailable")?
                .len()
                > 64 * 1024
            {
                return Err("Invalid management status replay state".into());
            }
            serde_json::from_slice::<StatusNonces>(
                &fs::read(&nonce_path).map_err(|_| "Management status replay state unavailable")?,
            )
            .map_err(|_| "Invalid management status replay state")?
        } else {
            StatusNonces {
                version: 1,
                used: BTreeMap::new(),
            }
        };
        if nonces.version != 1
            || nonces.used.len() > 128
            || nonces.used.iter().any(|(nonce, expiry)| {
                URL_SAFE_NO_PAD
                    .decode(nonce)
                    .map_or(true, |value| value.len() != 32)
                    || *expiry > MAX_SAFE_INTEGER
            })
        {
            return Err("Invalid management status replay state".into());
        }
        nonces.used.retain(|_, expiry| *expiry > now);
        let nonce = hash(&json!([
            payload.person_id,
            payload.device_id,
            payload.request_id
        ]))?;
        if nonces.used.contains_key(&nonce) {
            return Err("Unauthorized management status replay".into());
        }
        if nonces.used.len() >= 128 {
            return Err("Management status capacity exceeded".into());
        }
        nonces.used.insert(nonce, payload.expires_at);
        atomic_write(
            &nonce_path,
            &serde_json::to_vec(&nonces).map_err(|_| "Invalid management status replay state")?,
        )?;
        sync_directory(&self.directory).map_err(|_| "Management status durability unavailable")?;
        let pending = self.management_pending(kind, id)?;
        let confirmed_capability = record
            .as_ref()
            .map(|record| self.effective_management_capability(kind, id, record))
            .transpose()?;
        let revision = confirmed_capability
            .as_ref()
            .map(|value| capability(value).map(|cap| cap.revision))
            .transpose()?
            .unwrap_or(0);
        let receipt = sign_json_envelope(
            &self.seed,
            json!({
                "kind":"rusty-management-policy-status-receipt", "version":1,
                "serviceId":payload.service_id, "origin":origin, "personId":payload.person_id,
                "deviceId":payload.device_id, "resourceKind":kind, "resourceId":id,
                "requestId":payload.request_id, "authorizationHash":hash(&request.authorization)?,
                "capabilityHash":confirmed_capability.as_ref().map(hash).transpose()?, "revision":revision,
                "migrationPending":pending, "issuedAt":now_ms()?,
            }),
            &payload.service_id,
            DOMAIN,
        )?;
        Ok((confirmed_capability, pending, receipt))
    }
    fn management_pending_record(&self, kind: &str, id: &str) -> Result<Option<Pending>, String> {
        resource(kind, id)?;
        let path = self
            .directory
            .join("management/pending")
            .join(kind)
            .join(format!("{id}.json"));
        if !path.exists() {
            return Ok(None);
        }
        if fs::metadata(&path)
            .map_err(|_| "Management pending state unavailable")?
            .len()
            > 4096
        {
            return Err("Invalid management pending state".into());
        }
        let pending: Pending = serde_json::from_slice(
            &fs::read(path).map_err(|_| "Management pending state unavailable")?,
        )
        .map_err(|_| "Invalid management pending state")?;
        if pending.version != 1
            || pending.resource_kind != kind
            || pending.resource_id != id
            || pending.expected_revision > MAX_SAFE_INTEGER
            || !valid_id(&pending.request_id)
            || [&pending.authorization_hash, &pending.record_hash]
                .iter()
                .any(|value| {
                    URL_SAFE_NO_PAD
                        .decode(value.as_bytes())
                        .map_or(true, |bytes| bytes.len() != 32)
                })
        {
            return Err("Invalid management pending state".into());
        }
        Ok(Some(pending))
    }

    fn management_pending(&self, kind: &str, id: &str) -> Result<bool, String> {
        Ok(self.management_pending_record(kind, id)?.is_some())
    }

    fn finish_management_pending(
        &self,
        kind: &str,
        id: &str,
        request_id: &str,
        authorization_hash: &str,
    ) -> Result<(), String> {
        let Some(pending) = self.management_pending_record(kind, id)? else {
            return Ok(());
        };
        if pending.request_id != request_id || pending.authorization_hash != authorization_hash {
            return Ok(());
        }
        resource(kind, id)?;
        let path = self
            .directory
            .join("management/pending")
            .join(kind)
            .join(format!("{id}.json"));
        if path.exists() {
            fs::remove_file(&path).map_err(|_| "Management pending cleanup unavailable")?;
            sync_directory(
                path.parent()
                    .ok_or("Management pending state unavailable")?,
            )
            .map_err(|_| "Management pending durability unavailable")?;
        }
        Ok(())
    }
    fn management_index(&self) -> Result<Index, String> {
        let path = self.directory.join("management/policy.json");
        if !path.exists() {
            return Ok(Index {
                version: 1,
                resources: BTreeMap::new(),
            });
        }
        if fs::metadata(&path)
            .map_err(|_| "Management storage unavailable")?
            .len()
            > MAX_INDEX_BYTES
        {
            return Err("Invalid management index size".into());
        }
        let index: Index =
            serde_json::from_slice(&fs::read(path).map_err(|_| "Management storage unavailable")?)
                .map_err(|_| "Invalid management index")?;
        if index.version != 1 || index.resources.len() > MAX_RESOURCES {
            return Err("Invalid management index".into());
        }
        for (key, digest) in &index.resources {
            let (kind, id) = key.split_once('/').ok_or("Invalid management resource")?;
            resource(kind, id)?;
            if URL_SAFE_NO_PAD
                .decode(digest)
                .map_or(true, |bytes| bytes.len() != 32)
            {
                return Err("Invalid management pointer".into());
            }
        }
        Ok(index)
    }
    fn management_transfer_path(&self, kind: &str, id: &str) -> Result<std::path::PathBuf, String> {
        resource(kind, id)?;
        Ok(self
            .directory
            .join("management/controller-transfers")
            .join(kind)
            .join(format!("{id}.json")))
    }

    fn management_controller_transfer(
        &self,
        kind: &str,
        id: &str,
        record: &Record,
    ) -> Result<Option<ManagementControllerTransfer>, String> {
        let path = self.management_transfer_path(kind, id)?;
        if !path.exists() {
            return Ok(None);
        }
        if fs::metadata(&path)
            .map_err(|_| "Management transfer unavailable")?
            .len()
            > MAX_RECORD_BYTES
        {
            return Err("Invalid management transfer size".into());
        }
        let envelope: SignedEnvelope<ManagementControllerTransfer> =
            serde_json::from_slice(&fs::read(path).map_err(|_| "Management transfer unavailable")?)
                .map_err(|_| "Invalid management transfer")?;
        let transfer = envelope.payload.clone();
        let index = self.management_index()?;
        let key = resource(kind, id)?;
        let Some(record_hash) = index.resources.get(&key) else {
            return Err("Management transfer has no resource pointer".into());
        };
        let old_capability = capability(&record.capability)?;
        let new_capability = capability(&transfer.capability)?;
        let service_key = self.public_key()?;
        let service_id = public_key_id(&service_key)?;
        if record_hash != &transfer.previous_record_hash {
            // A normal user-signed update replaced the projected historical record.
            // The old sidecar is then inert and must not override the new record.
            return Ok(None);
        }
        if envelope.signer_key_id != service_id
            || !verify_signed_envelope(&envelope, &service_key, DOMAIN)?
            || transfer.kind != "rusty-management-controller-transfer"
            || transfer.version != 1
            || transfer.resource_kind != kind
            || transfer.resource_id != id
            || transfer.previous_record_hash != *record_hash
            || transfer.previous_person_id != record.identity.person_id
            || public_key_id(&transfer.successor_identity.public_key)?
                != transfer.successor_identity.person_id
            || transfer.successor_identity.person_id == transfer.previous_person_id
            || !valid_id(&transfer.transition_hash)
            || transfer.origin != old_capability.origin
            || transfer.transferred_at == 0
            || transfer.capability.signer_key_id != service_id
            || !verify_signed_envelope(&transfer.capability, &service_key, DOMAIN)?
            || new_capability.service_id != service_id
            || new_capability.origin != transfer.origin
            || new_capability.person_id != transfer.successor_identity.person_id
            || new_capability.resource_kind != kind
            || new_capability.resource_id != id
            || new_capability.revision != old_capability.revision.saturating_add(1)
            || new_capability.operations != old_capability.operations
            || new_capability.revoked_device_ids != old_capability.revoked_device_ids
            || new_capability.restored_device_ids != old_capability.restored_device_ids
        {
            return Err("Management controller transfer integrity failure".into());
        }
        Ok(Some(transfer))
    }

    fn effective_management_identity(
        &self,
        kind: &str,
        id: &str,
        record: &Record,
    ) -> Result<PublicIdentity, String> {
        Ok(self
            .management_controller_transfer(kind, id, record)?
            .map(|transfer| transfer.successor_identity)
            .unwrap_or_else(|| record.identity.clone()))
    }

    fn effective_management_capability(
        &self,
        kind: &str,
        id: &str,
        record: &Record,
    ) -> Result<SignedEnvelope<Value>, String> {
        Ok(self
            .management_controller_transfer(kind, id, record)?
            .map(|transfer| transfer.capability)
            .unwrap_or_else(|| record.capability.clone()))
    }

    pub(super) fn prepare_root_succession_management_transfers(
        &self,
        previous_person_id: &str,
        successor_identity: &PublicIdentity,
        transition_hash: &str,
        origin: &str,
    ) -> Result<Vec<crate::identity_authority::IdentityRootSuccessionTargetReceipt>, String> {
        let service_key = self.public_key()?;
        let service_id = public_key_id(&service_key)?;
        if public_key_id(&successor_identity.public_key)? != successor_identity.person_id
            || successor_identity.person_id == previous_person_id
        {
            return Err("Invalid Identity successor controller".into());
        }
        let mut targets = Vec::new();
        let index = self.management_index()?;
        for key in index.resources.keys() {
            let (kind, id) = key.split_once('/').ok_or("Invalid management resource")?;
            let Some(record) = self.management_record(kind, id)? else {
                continue;
            };
            if record.identity.person_id != previous_person_id {
                continue;
            }
            if kind == "person" {
                // A person's self-management record is tied to the retired person ID.
                // Resources created through it retain their own scoped capabilities.
                continue;
            }
            let old_capability = capability(&record.capability)?;
            if old_capability.origin != origin {
                continue;
            }
            if let Some(existing) = self.management_controller_transfer(kind, id, &record)? {
                if existing.transition_hash != transition_hash
                    || existing.successor_identity.person_id != successor_identity.person_id
                    || existing.successor_identity.public_key != successor_identity.public_key
                {
                    return Err(
                        "Management resource already transferred to another Identity".into(),
                    );
                }
                targets.push(
                    crate::identity_authority::IdentityRootSuccessionTargetReceipt {
                        kind: "management".into(),
                        resource_id: key.clone(),
                        evidence_hash: hash(&existing)?,
                        epoch: Some(capability(&existing.capability)?.revision),
                    },
                );
                continue;
            }
            let index_hash = index
                .resources
                .get(key)
                .ok_or("Management resource pointer unavailable")?;
            let revision = old_capability
                .revision
                .checked_add(1)
                .ok_or("Management revision overflow")?;
            let request_id = format!("succession-{}", &transition_hash[..32]);
            let transfer_authorization_hash = hash(&json!({
                "kind": "rusty-management-controller-transfer-authorization",
                "version": 1,
                "resourceKind": kind,
                "resourceId": id,
                "previousRecordHash": index_hash,
                "previousPersonId": previous_person_id,
                "successorPersonId": successor_identity.person_id,
                "transitionHash": transition_hash,
            }))?;
            let capability_envelope = sign_json_envelope(
                &self.seed,
                serde_json::to_value(Capability {
                    kind: old_capability.kind.clone(),
                    version: 1,
                    service_id: service_id.clone(),
                    origin: origin.to_owned(),
                    person_id: successor_identity.person_id.clone(),
                    resource_kind: kind.to_owned(),
                    resource_id: id.to_owned(),
                    revision,
                    operations: old_capability.operations.clone(),
                    revoked_device_ids: old_capability.revoked_device_ids.clone(),
                    restored_device_ids: old_capability.restored_device_ids.clone(),
                    request_id,
                    authorization_hash: transfer_authorization_hash,
                    issued_at: now_ms()?,
                })
                .map_err(|_| "Management transfer capability invalid")?,
                service_id.clone(),
                DOMAIN,
            )?;
            let transfer = ManagementControllerTransfer {
                kind: "rusty-management-controller-transfer".into(),
                version: 1,
                resource_kind: kind.to_owned(),
                resource_id: id.to_owned(),
                previous_record_hash: index_hash.clone(),
                previous_person_id: previous_person_id.to_owned(),
                successor_identity: successor_identity.clone(),
                origin: origin.to_owned(),
                transition_hash: transition_hash.to_owned(),
                capability: capability_envelope,
                transferred_at: now_ms()?,
            };
            let signed = sign_json_envelope(
                &self.seed,
                serde_json::to_value(&transfer).map_err(|_| "Management transfer invalid")?,
                service_id.clone(),
                DOMAIN,
            )?;
            let path = self.management_transfer_path(kind, id)?;
            atomic_write(
                &path,
                &serde_json::to_vec(&signed).map_err(|_| "Management transfer invalid")?,
            )?;
            targets.push(
                crate::identity_authority::IdentityRootSuccessionTargetReceipt {
                    kind: "management".into(),
                    resource_id: key.clone(),
                    evidence_hash: hash(&signed)?,
                    epoch: Some(revision),
                },
            );
        }
        self.transfer_publication_owners(
            previous_person_id,
            successor_identity,
            transition_hash,
            origin,
            &service_id,
            &mut targets,
        )?;
        Ok(targets)
    }

    fn transfer_publication_owners(
        &self,
        previous_person_id: &str,
        successor_identity: &PublicIdentity,
        transition_hash: &str,
        origin: &str,
        service_id: &str,
        targets: &mut Vec<crate::identity_authority::IdentityRootSuccessionTargetReceipt>,
    ) -> Result<(), String> {
        let publications = self.directory.join("publications/records");
        if !publications.exists() {
            return Ok(());
        }
        for entry in fs::read_dir(&publications).map_err(|_| "Publication storage unavailable")? {
            let entry = entry.map_err(|_| "Publication storage unavailable")?;
            let path = entry.path();
            if path.extension().and_then(|value| value.to_str()) != Some("json") {
                continue;
            }
            let Some(board_id) = path.file_stem().and_then(|value| value.to_str()) else {
                return Err("Invalid publication resource path".into());
            };
            if !valid_id(board_id) {
                return Err("Invalid publication resource ID".into());
            }
            let Some(mut publication) = self.current_publication(board_id)? else {
                continue;
            };
            if publication.controller_person_id != previous_person_id
                && publication.controller_person_id != successor_identity.person_id
            {
                continue;
            }
            let owner_path = self
                .directory
                .join("management/publication-owners")
                .join(format!("{board_id}.json"));
            if publication.controller_person_id == successor_identity.person_id
                && !owner_path.exists()
            {
                // Already controlled by the successor, with no retained old owner
                // evidence to move. Do not adopt it as a side effect of succession.
                continue;
            }
            if owner_path.exists() {
                let owner_envelope: SignedEnvelope<Value> = serde_json::from_slice(
                    &fs::read(&owner_path).map_err(|_| "Publication owner unavailable")?,
                )
                .map_err(|_| "Invalid publication owner")?;
                let owner: PublicationOwner =
                    serde_json::from_value(owner_envelope.payload.clone())
                        .map_err(|_| "Invalid publication owner")?;
                if owner_envelope.signer_key_id != service_id
                    || !verify_signed_envelope(&owner_envelope, &self.public_key()?, DOMAIN)?
                    || owner.kind != "rusty-publication-owner"
                    || owner.version != 1
                    || owner.board_id != board_id
                    || (owner.identity.person_id != previous_person_id
                        && owner.identity.person_id != successor_identity.person_id)
                {
                    return Err("Publication owner succession binding conflict".into());
                }
                if owner.identity.person_id == successor_identity.person_id {
                    if publication.controller_person_id != successor_identity.person_id {
                        return Err(
                            "Publication owner conflicts with its controller projection".into()
                        );
                    }
                    if owner.succession_from_person_id.as_deref() == Some(previous_person_id)
                        && owner.succession_transition_hash.as_deref() == Some(transition_hash)
                    {
                        targets.push(
                            crate::identity_authority::IdentityRootSuccessionTargetReceipt {
                                kind: "publication".into(),
                                resource_id: board_id.to_owned(),
                                evidence_hash: hash(&owner_envelope)?,
                                epoch: Some(publication.revision),
                            },
                        );
                    } else if owner.succession_from_person_id.is_some()
                        || owner.succession_transition_hash.is_some()
                    {
                        return Err(
                            "Publication was transferred by another Identity succession".into()
                        );
                    }
                    // An independently successor-owned publication needs no transfer.
                    continue;
                }
            }
            let new_owner = sign_json_envelope(
                &self.seed,
                serde_json::to_value(PublicationOwner {
                    kind: "rusty-publication-owner".into(),
                    version: 1,
                    board_id: board_id.to_owned(),
                    identity: successor_identity.clone(),
                    succession_from_person_id: Some(previous_person_id.to_owned()),
                    succession_transition_hash: Some(transition_hash.to_owned()),
                })
                .map_err(|_| "Publication owner invalid")?,
                service_id.to_owned(),
                DOMAIN,
            )?;
            if publication.controller_person_id != successor_identity.person_id {
                publication.controller_person_id = successor_identity.person_id.clone();
                publication.revision = publication
                    .revision
                    .checked_add(1)
                    .ok_or("Publication revision overflow")?;
                atomic_write(
                    &path,
                    &serde_json::to_vec(&publication).map_err(|_| "Public publication invalid")?,
                )?;
            }
            atomic_write(
                &owner_path,
                &serde_json::to_vec(&new_owner).map_err(|_| "Publication owner invalid")?,
            )?;
            targets.push(
                crate::identity_authority::IdentityRootSuccessionTargetReceipt {
                    kind: "publication".into(),
                    resource_id: board_id.to_owned(),
                    evidence_hash: hash(&new_owner)?,
                    epoch: Some(publication.revision),
                },
            );
            let _ = transition_hash;
            let _ = origin;
        }
        Ok(())
    }

    fn management_record(&self, kind: &str, id: &str) -> Result<Option<Record>, String> {
        let key = resource(kind, id)?;
        let index = self.management_index()?;
        let Some(digest) = index.resources.get(&key) else {
            return Ok(None);
        };
        let path = self
            .directory
            .join("management/records")
            .join(format!("{digest}.json"));
        if fs::metadata(&path)
            .map_err(|_| "Management evidence unavailable")?
            .len()
            > MAX_RECORD_BYTES
        {
            return Err("Invalid management evidence size".into());
        }
        let record: Record =
            serde_json::from_slice(&fs::read(path).map_err(|_| "Management evidence unavailable")?)
                .map_err(|_| "Invalid management evidence")?;
        let cap = capability(&record.capability)?;
        let service_key = self.public_key()?;
        let authorization = &record.authorization.payload;
        let signed = serde_json::from_value::<SignedEnvelope<Value>>(
            serde_json::to_value(&record.authorization)
                .map_err(|_| "Invalid management authorization")?,
        )
        .map_err(|_| "Invalid management authorization")?;
        let device_key = verify_device_certificate_chain(
            &record.identity,
            &record.device_id,
            &record.certificates,
            "MATCH/1",
        )?;
        if record.version != 1
            || hash(&record)? != *digest
            || cap.resource_kind != kind
            || cap.resource_id != id
            || cap.service_id != public_key_id(&service_key)?
            || record.capability.signer_key_id != cap.service_id
            || !verify_signed_envelope(&record.capability, &service_key, DOMAIN)?
            || cap.person_id != record.identity.person_id
            || authorization.kind != "rusty-management-policy-update"
            || authorization.version != 1
            || authorization.resource_kind != kind
            || authorization.resource_id != id
            || authorization.origin != cap.origin
            || authorization.service_id != cap.service_id
            || authorization.person_id != cap.person_id
            || authorization.expected_revision.checked_add(1) != Some(cap.revision)
            || authorization.operations != cap.operations
            || authorization.revoked_device_ids != cap.revoked_device_ids
            || authorization.request_id != cap.request_id
            || authorization.issued_at != cap.issued_at
            || hash(&record.authorization)? != cap.authorization_hash
            || authorization.device_id != record.device_id
            || public_key_id(&device_key)? != record.device_id
            || signed.signer_key_id != record.device_id
            || !verify_signed_envelope(&signed, &device_key, "MATCH/1")?
        {
            return Err("Management evidence integrity failure".into());
        }
        match &record.person_management_capability {
            Some(parent) => {
                let parent_cap = capability(parent)?;
                if kind == "person"
                    || authorization.expected_revision != 0
                    || parent_cap.resource_kind != "person"
                    || parent_cap.person_id != cap.person_id
                    || parent_cap.origin != cap.origin
                    || parent_cap.service_id != cap.service_id
                    || parent_cap.revision != authorization.person_management_revision.unwrap_or(0)
                    || !parent_cap
                        .operations
                        .iter()
                        .any(|op| op == "resource.create")
                    || parent_cap.revoked_device_ids.contains(&record.device_id)
                    || parent.signer_key_id != cap.service_id
                    || !verify_signed_envelope(parent, &service_key, DOMAIN)?
                {
                    return Err("Management person evidence integrity failure".into());
                }
            }
            None if authorization.person_management_revision.is_some() => {
                return Err("Management person evidence is missing".into());
            }
            None => {}
        }
        Ok(Some(record))
    }
    pub(super) fn recover_management(&self) -> Result<(), String> {
        for key in self.management_index()?.resources.keys() {
            let (kind, id) = key.split_once('/').ok_or("Invalid management resource")?;
            if let Some(record) = self.management_record(kind, id)? {
                self.management_controller_transfer(kind, id, &record)?;
            }
        }
        Ok(())
    }
    pub(super) fn management_authorized(
        &self,
        owner: &ResourceOwner,
        identity: &PublicIdentity,
        device_id: &str,
        certificates: &[DeviceCertificate],
        kind: &str,
        id: &str,
        operation: &str,
        presented: Option<&SignedEnvelope<Value>>,
        origin: &str,
    ) -> Result<bool, String> {
        if !self.resource_identity_allowed(kind, id, identity)?
            || !trusted_identity_matches(identity, &owner.identity)
            || (kind == "person" && id != identity.person_id)
            || certificates.is_empty()
            || certificates.len() > 32
            || certificates
                .iter()
                .any(|certificate| certificate.payload.person_id != identity.person_id)
            || !self.identity_device_certificate_matches(identity, device_id, certificates)?
            || !verify_device_certificate_chain(identity, device_id, certificates, "MATCH/1")
                .is_ok_and(|key| public_key_id(&key).is_ok_and(|id| id == device_id))
        {
            return Ok(false);
        }
        if !self.person_device_allowed(identity, device_id, origin, kind == "person")? {
            return Ok(false);
        }
        let Some(record) = self.management_record(kind, id)? else {
            return Ok(!self.management_pending(kind, id)?
                && presented.is_none()
                && (kind == "person"
                    || self
                        .management_record("person", &identity.person_id)?
                        .is_none()));
        };
        let effective_capability = self.effective_management_capability(kind, id, &record)?;
        let current = capability(&effective_capability)?;
        Ok(
            presented.is_some_and(|value| value == &effective_capability)
                && current.origin == origin
                && current.person_id == identity.person_id
                && current.operations.iter().any(|value| value == operation)
                && !current
                    .revoked_device_ids
                    .iter()
                    .any(|value| value == device_id),
        )
    }
    pub(super) fn management_revision_matches(
        &self,
        kind: &str,
        id: &str,
        supplied_revision: Option<u64>,
    ) -> Result<bool, String> {
        let current_revision = self
            .management_record(kind, id)?
            .map(|record| {
                self.effective_management_capability(kind, id, &record)
                    .and_then(|value| capability(&value).map(|capability| capability.revision))
            })
            .transpose()?;
        Ok(match current_revision {
            Some(revision) => supplied_revision == Some(revision),
            None => supplied_revision.is_none(),
        })
    }
    fn update_management(
        &self,
        kind: &str,
        id: &str,
        request: UpdateRequest,
        owner: &ResourceOwner,
        origin: &str,
    ) -> Result<SignedEnvelope<Value>, String> {
        let _guard = self
            .lock
            .lock()
            .map_err(|_| "Management storage unavailable")?;
        let key = resource(kind, id)?;
        if kind == "person" && id != request.identity.person_id {
            return Err("Invalid management person resource".into());
        }
        if request.version != 1
            || !trusted_identity_matches(&request.identity, &owner.identity)
            || request.certificates.is_empty()
            || request.certificates.len() > 32
            || request
                .certificates
                .iter()
                .any(|certificate| certificate.payload.person_id != request.identity.person_id)
        {
            return Err("Unauthorized management identity".into());
        }
        let device_key = verify_device_certificate_chain(
            &request.identity,
            &request.device_id,
            &request.certificates,
            "MATCH/1",
        )?;
        let signed: SignedEnvelope<Value> = serde_json::from_value(
            serde_json::to_value(&request.authorization)
                .map_err(|_| "Invalid management authorization")?,
        )
        .map_err(|_| "Invalid management authorization")?;
        if public_key_id(&device_key)? != request.device_id
            || signed.signer_key_id != request.device_id
            || !verify_signed_envelope(&signed, &device_key, "MATCH/1")?
        {
            return Err("Unauthorized management signature".into());
        }
        let update = &request.authorization.payload;
        let service_id = public_key_id(&self.public_key()?)?;
        let authorization_hash = hash(&request.authorization)?;
        let current = self.management_record(kind, id)?;
        let effective_capability = current
            .as_ref()
            .map(|record| self.effective_management_capability(kind, id, record))
            .transpose()?;
        if !self.person_device_allowed(
            &request.identity,
            &request.device_id,
            origin,
            kind == "person",
        )? {
            return Err("Unauthorized or revoked person management device".into());
        }
        if current.is_some() {
            let cap = capability(
                effective_capability
                    .as_ref()
                    .ok_or("Management capability unavailable")?,
            )?;
            if cap.request_id == update.request_id && cap.authorization_hash == authorization_hash {
                if cap.origin != origin
                    || cap.person_id != request.identity.person_id
                    || cap.revoked_device_ids.contains(&request.device_id)
                {
                    return Err("Unauthorized completed management retry".into());
                }
                self.finish_management_pending(kind, id, &cap.request_id, &cap.authorization_hash)?;
                return Ok(effective_capability
                    .as_ref()
                    .ok_or("Management capability unavailable")?
                    .clone());
            }
            if cap.request_id == update.request_id {
                return Err("Management request identity conflict".into());
            }
        }
        let authorized = if current.is_none() {
            self.resource_creation_authorized(kind, &request, owner, origin)?
        } else {
            if request.person_management_capability.is_some()
                || update.person_management_revision.is_some()
            {
                return Err("Invalid person authority on existing resource update".into());
            }
            self.management_authorized(
                owner,
                &request.identity,
                &request.device_id,
                &request.certificates,
                kind,
                id,
                "management.update",
                request.management_capability.as_ref(),
                origin,
            )?
        };
        if !authorized {
            return Err("Unauthorized management capability or legacy controller".into());
        }
        let now = now_ms()?;
        if update.kind != "rusty-management-policy-update"
            || update.version != 1
            || update.origin != origin
            || update.service_id != service_id
            || update.person_id != request.identity.person_id
            || update.device_id != request.device_id
            || update.resource_kind != kind
            || update.resource_id != id
            || !valid_id(&update.request_id)
            || !operations(kind, &update.operations)
            || !ordered_ids(&update.revoked_device_ids, MAX_REVOKED_DEVICES)
            || update.restored_device_ids.as_ref().is_some_and(|ids| {
                !ordered_ids(ids, MAX_REVOKED_DEVICES)
                    || ids.iter().any(|id| update.revoked_device_ids.contains(id))
            })
            || update.issued_at > now.saturating_add(30_000)
            || update.expires_at <= now
            || update.expires_at > MAX_SAFE_INTEGER
            || update.expires_at <= update.issued_at
            || update.expires_at - update.issued_at > 120_000
        {
            return Err("Invalid or expired management update".into());
        }
        let revision = current
            .as_ref()
            .map(|_| {
                capability(
                    effective_capability
                        .as_ref()
                        .ok_or("Management capability unavailable")?,
                )
                .map(|value| value.revision)
            })
            .transpose()?
            .unwrap_or(0);
        if update.expected_revision != revision || revision >= MAX_SAFE_INTEGER {
            return Err("Management revision conflict".into());
        }
        if current.is_some() {
            if capability(
                effective_capability
                    .as_ref()
                    .ok_or("Management capability unavailable")?,
            )?
            .revoked_device_ids
            .iter()
            .any(|id| {
                !update.revoked_device_ids.contains(id)
                    && !update
                        .restored_device_ids
                        .as_ref()
                        .is_some_and(|ids| ids.contains(id))
            }) {
                return Err("Management revocation rollback conflict".into());
            }
        }
        let mut restored = current
            .as_ref()
            .map(|_| {
                capability(
                    effective_capability
                        .as_ref()
                        .ok_or("Management capability unavailable")?,
                )
            })
            .transpose()?
            .and_then(|cap| cap.restored_device_ids)
            .unwrap_or_default();
        restored.extend(update.restored_device_ids.clone().unwrap_or_default());
        restored.retain(|id| !update.revoked_device_ids.contains(id));
        restored.sort();
        restored.dedup();
        if restored.len() > MAX_REVOKED_DEVICES {
            return Err("Too many restored device records".into());
        }
        let payload = Capability {
            kind: if kind == "person" {
                "rusty-person-management-capability"
            } else {
                "rusty-scope-management-capability"
            }
            .into(),
            version: 1,
            service_id: service_id.clone(),
            origin: origin.into(),
            person_id: request.identity.person_id.clone(),
            resource_kind: kind.into(),
            resource_id: id.into(),
            revision: revision + 1,
            operations: update.operations.clone(),
            revoked_device_ids: update.revoked_device_ids.clone(),
            restored_device_ids: (!restored.is_empty()).then_some(restored),
            request_id: update.request_id.clone(),
            authorization_hash: authorization_hash.clone(),
            issued_at: update.issued_at,
        };
        let confirmed = sign_json_envelope(
            &self.seed,
            serde_json::to_value(payload).map_err(|_| "Invalid management capability")?,
            &service_id,
            DOMAIN,
        )?;
        let record = Record {
            version: 1,
            capability: confirmed.clone(),
            identity: request.identity,
            device_id: request.device_id,
            certificates: request.certificates,
            authorization: request.authorization,
            person_management_capability: request.person_management_capability,
        };
        let bytes = canonicalize_json(
            &serde_json::to_value(&record).map_err(|_| "Invalid management evidence")?,
        )?
        .into_bytes();
        if bytes.len() as u64 > MAX_RECORD_BYTES {
            return Err("Invalid management evidence size".into());
        }
        let mut index = self.management_index()?;
        if !index.resources.contains_key(&key) && index.resources.len() >= MAX_RESOURCES {
            return Err("Management resource capacity exceeded".into());
        }
        let root = self.directory.join("management");
        let records = root.join("records");
        fs::create_dir_all(&records).map_err(|_| "Management storage unavailable")?;
        sync_directory(&root).map_err(|_| "Management durability unavailable")?;
        sync_directory(&self.directory).map_err(|_| "Management durability unavailable")?;
        let evidence_hash = digest(&bytes);
        let pending_root = root.join("pending").join(kind);
        fs::create_dir_all(&pending_root).map_err(|_| "Management pending state unavailable")?;
        sync_directory(&root.join("pending"))
            .map_err(|_| "Management pending durability unavailable")?;
        sync_directory(&root).map_err(|_| "Management pending durability unavailable")?;
        atomic_write(
            &pending_root.join(format!("{id}.json")),
            &serde_json::to_vec(&Pending {
                version: 1,
                resource_kind: kind.into(),
                resource_id: id.into(),
                expected_revision: revision,
                request_id: record.authorization.payload.request_id.clone(),
                authorization_hash: hash(&record.authorization)?,
                record_hash: evidence_hash.clone(),
            })
            .map_err(|_| "Invalid management pending state")?,
        )?;
        let path = records.join(format!("{evidence_hash}.json"));
        if path.exists() {
            if fs::read(&path).map_err(|_| "Management evidence unavailable")? != bytes {
                return Err("Management evidence hash conflict".into());
            }
        } else {
            atomic_write(&path, &bytes)?;
        }
        index.resources.insert(key, evidence_hash);
        #[cfg(test)]
        if self
            .management_commit_failure
            .swap(false, std::sync::atomic::Ordering::SeqCst)
        {
            return Err("Management pointer commit failed".into());
        }
        atomic_write(
            &root.join("policy.json"),
            &serde_json::to_vec(&index).map_err(|_| "Invalid management index")?,
        )?;
        self.finish_management_pending(
            kind,
            id,
            &record.authorization.payload.request_id,
            &authorization_hash,
        )?;
        Ok(confirmed)
    }

    pub(super) fn create_managed_enrollment_challenge(
        &self,
        request: EnrollmentChallengeRequest,
        owner: &ResourceOwner,
        origin: &str,
        device_key_id: &str,
    ) -> Result<SignedEnvelope<Value>, String> {
        let _guard = self
            .lock
            .lock()
            .map_err(|_| "Management storage unavailable")?;
        if request
            .scope_purpose
            .as_deref()
            .is_some_and(|purpose| !valid_scope_purpose(purpose))
            || (self.identity_authority_enforced.load(Ordering::SeqCst)
                && request.scope_purpose.is_none())
        {
            return Err("Scope purpose is required or invalid".into());
        }
        if !self.management_authorized(
            owner,
            &request.identity,
            &request.device_id,
            &request.certificates,
            "scope",
            &request.scope_id,
            "scope.policy",
            request.management_capability.as_ref(),
            origin,
        )? {
            return Err("Unauthorized enrollment management capability".into());
        }
        if self.policy_revision(&request.scope_id)? > 0
            && self
                .policy(&request.scope_id)?
                .owner_person_id
                .as_ref()
                .is_some_and(|person| person != &request.identity.person_id)
        {
            return Err("Scope owner binding conflict".into());
        }
        if self.policy_revision(&request.scope_id)? > 0 {
            let existing = self.policy(&request.scope_id)?;
            if existing.scope_purpose.as_deref().is_some_and(|purpose| {
                request
                    .scope_purpose
                    .as_deref()
                    .is_some_and(|requested| requested != purpose)
            }) || (existing.scope_purpose.is_none() && request.scope_purpose.is_some())
            {
                return Err("Scope purpose is immutable; use the one-time migration route".into());
            }
        }
        self.create_challenge_unlocked(
            &request.scope_id,
            &request.identity.person_id,
            &request.device_id,
            device_key_id,
            request.scope_purpose.as_deref(),
            origin,
        )
    }

    pub(super) fn create_managed_public_challenge(
        &self,
        request: PublicChallengeRequest,
        owner: &ResourceOwner,
        origin: &str,
        device_key_id: &str,
    ) -> Result<SignedEnvelope<Value>, String> {
        let _guard = self
            .lock
            .lock()
            .map_err(|_| "Management storage unavailable")?;
        if let Some(source_heads) = request.source_heads.as_deref() {
            validate_source_heads(source_heads)?;
        }
        if !self.management_authorized(
            owner,
            &request.identity,
            &request.device_id,
            &request.certificates,
            "board",
            &request.board_id,
            "publication.status",
            request.management_capability.as_ref(),
            origin,
        )? {
            return Err("Unauthorized publication management capability".into());
        }
        self.create_public_challenge_unlocked(
            &request.board_id,
            &request.identity.person_id,
            &request.device_id,
            device_key_id,
            origin,
            None,
            request.source_heads.as_deref(),
        )
    }

    pub(super) fn create_public_delivery_challenge(
        &self,
        request: PublicChallengeRequest,
        owner: &ResourceOwner,
        origin: &str,
    ) -> Result<SignedEnvelope<Value>, String> {
        if !self.identity_device_certificate_matches(
            &request.identity,
            &request.device_id,
            &request.certificates,
        )? {
            return Err("Public delivery device is revoked or not registered".into());
        }
        let _guard = self
            .lock
            .lock()
            .map_err(|_| "Management storage unavailable")?;
        let publication = self
            .current_publication(&request.board_id)?
            .ok_or("Public publication unavailable")?;
        let grant = request
            .delivery_grant
            .as_ref()
            .ok_or("Missing public delivery grant")?;
        let source_heads = request
            .source_heads
            .as_deref()
            .ok_or("Missing public source heads")?;
        let device_key = verify_device_certificate_chain(
            &request.identity,
            &request.device_id,
            &request.certificates,
            "MATCH/1",
        )?;
        let device_key_id = public_key_id(&device_key)?;
        if device_key_id != request.device_id {
            return Err("Public delivery device mismatch".into());
        }
        let binding = authorize_public_delivery_writer(
            &publication,
            owner,
            &request.board_id,
            &request.identity,
            &request.device_id,
            &request.certificates,
            grant,
            source_heads,
            now_ms()?,
        )?;
        self.create_public_challenge_unlocked(
            &request.board_id,
            &request.identity.person_id,
            &request.device_id,
            &device_key_id,
            origin,
            Some(&binding),
            None,
        )
    }
}

pub(super) async fn status(
    State(state): State<HttpState>,
    RoutePath((kind, id)): RoutePath<(String, String)>,
    Json(request): Json<StatusRequest>,
) -> Result<impl IntoResponse, ApiError> {
    let owner = ResourceOwner {
        identity: request.identity.clone(),
    };
    let (capability, pending, receipt) = tokio::task::spawn_blocking(move || {
        state
            .store
            .management_status(&kind, &id, request, &owner, &state.origin)
    })
    .await
    .map_err(|_| {
        failure(
            StatusCode::SERVICE_UNAVAILABLE,
            "Management storage unavailable",
        )
    })?
    .map_err(|message| {
        failure(
            if message.contains("Unauthorized") {
                StatusCode::FORBIDDEN
            } else if message.contains("capacity") {
                StatusCode::TOO_MANY_REQUESTS
            } else if message == "Invalid management resource" {
                StatusCode::BAD_REQUEST
            } else {
                StatusCode::SERVICE_UNAVAILABLE
            },
            &message,
        )
    })?;
    Ok((
        [("cache-control", "no-store")],
        Json(json!({"capability":capability, "migrationPending":pending, "receipt":receipt})),
    ))
}
pub(super) async fn update(
    State(state): State<HttpState>,
    RoutePath((kind, id)): RoutePath<(String, String)>,
    Json(request): Json<UpdateRequest>,
) -> Result<Json<Value>, ApiError> {
    let owner = ResourceOwner {
        identity: request.identity.clone(),
    };
    let result = tokio::task::spawn_blocking(move || {
        state
            .store
            .update_management(&kind, &id, request, &owner, &state.origin)
    })
    .await
    .map_err(|_| {
        failure(
            StatusCode::SERVICE_UNAVAILABLE,
            "Management storage unavailable",
        )
    })?
    .map_err(|message| {
        failure(
            if message.contains("Unauthorized") {
                StatusCode::FORBIDDEN
            } else if message.contains("conflict") {
                StatusCode::CONFLICT
            } else if message.starts_with("Invalid") {
                StatusCode::BAD_REQUEST
            } else {
                StatusCode::SERVICE_UNAVAILABLE
            },
            &message,
        )
    })?;
    Ok(Json(json!({"capability":result})))
}
