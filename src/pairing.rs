use std::{
    collections::HashMap,
    fs,
    path::PathBuf,
    sync::{Arc, Mutex},
    time::{SystemTime, UNIX_EPOCH},
};

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use meta_mesh_core::{
    DeviceCertificate, PublicIdentity, SignedEnvelope, WorkspaceJoinInvitation, canonicalize_json,
    public_key_id, sign_json_envelope, verify_device_certificate_chain, verify_signed_envelope,
};
use meta_mesh_native::FileScopeStore;
use rand::Rng;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

#[cfg(test)]
#[path = "owner_auth_tests.rs"]
mod owner_auth_tests;

use crate::{ProvisioningCommit, integration_id};

pub const CONTROL_DOMAIN: &str = "MESH-LIGHTHOUSE/1";
const MAX_AGE_SECONDS: u64 = 600;
const LOGIN_TTL_SECONDS: u64 = 5 * 60;
const MAX_PENDING_LOGINS: usize = 128;
const MAX_SCOPES: usize = 16;
const MAX_BASELINE_WORKSPACES: usize = 4096;
const MAX_REVOCATION_DOCUMENT_BYTES: usize = 8 * 1024 * 1024;

#[derive(Clone)]
pub struct PairingService {
    state: Arc<Mutex<PairingState>>,
    directory: Arc<PathBuf>,
    service_identity: PublicIdentity,
    service_device_id: String,
    service_seed: Arc<[u8; 32]>,
    origin: String,
    admin_secret: Arc<String>,
    provisioning_runs: Arc<Mutex<std::collections::HashSet<String>>>,
}

#[derive(Clone, Default, Serialize, Deserialize)]
struct PairingState {
    records: HashMap<String, PairingRecord>,
    #[serde(skip)]
    sessions: HashMap<String, AdminSession>,
    #[serde(skip)]
    login_challenges: HashMap<String, LoginChallenge>,
    #[serde(skip)]
    login_codes: HashMap<String, LoginCode>,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PairingRecord {
    pub id: String,
    pub expires_at: u64,
    pub created_at: u64,
    pub transcript_hash: String,
    pub comparison_code: String,
    pub operator_approved: Option<bool>,
    pub controller_approved: Option<bool>,
    pub controller_decision_operation: Option<String>,
    pub controller_decision_hash: Option<String>,
    pub controller: PublicIdentity,
    pub controller_device_id: String,
    pub controller_certificates: Vec<DeviceCertificate>,
    pub offer: Value,
    pub challenge: SignedEnvelope<Value>,
    pub last_operation_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provisioning: Option<ProvisioningRecord>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub withdrawal: Option<PairingWithdrawal>,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PairingWithdrawal {
    pub operation_id: String,
    pub request_hash: String,
    pub status: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub completion_hash: Option<String>,
    #[serde(default)]
    pub verified_revocations: Vec<VerifiedWithdrawalRevocation>,
    #[serde(default)]
    pub verified_grants: Vec<VerifiedWithdrawalGrant>,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VerifiedWithdrawalRevocation {
    pub workspace_id: String,
    pub revocation_epoch: u64,
    pub revocation_hash: String,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VerifiedWithdrawalGrant {
    pub workspace_id: String,
    pub grant_id: String,
    pub grant_epoch: u64,
    pub grant_hash: String,
}

pub struct WithdrawalGrantScope {
    pub workspace_id: String,
    pub document: Vec<u8>,
    pub authorization_bundle: Value,
    pub grant: Value,
}

pub struct WithdrawalCompletionScope {
    pub workspace_id: String,
    pub document: Vec<u8>,
    pub authorization_bundle: Value,
}

pub struct VerifiedWithdrawalCompletion {
    pub request_hash: String,
    pub operation_id: String,
    pub integration_id: String,
    pub controller_person_id: String,
    pub service_person_id: String,
    pub scopes: Vec<WithdrawalCompletionScope>,
    /// Exact grant epochs durably observed during this pairing, if any.
    /// Missing values require a Rusty integration tombstone before completion.
    pub issued_grant_epochs: HashMap<String, Option<u64>>,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProvisioningRecord {
    pub operation_id: String,
    pub request_hash: String,
    pub status: String,
    pub scopes: Vec<ProvisionedScope>,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProvisionedScope {
    pub workspace_id: String,
    pub status: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub grant_epoch: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error_detail: Option<String>,
}

pub struct ProvisionRequest {
    pub invitation: WorkspaceJoinInvitation,
    pub scopes: Vec<String>,
    pub integration_id: String,
    pub operation_id: String,
    pub transcript_hash: String,
    pub future_boards: bool,
    pub baseline_workspace_ids: Vec<String>,
    pub should_run: bool,
}

#[derive(Clone)]
pub struct IntegrationCandidate {
    pub integration_id: String,
    pub pairing_id: String,
    pub controller_person_id: String,
    pub future_boards: bool,
}

#[derive(Clone)]
pub struct VerifiedDisconnectRequest {
    pub integration_id: String,
    pub operation_id: String,
    pub controller_person_id: String,
    pub controller_device_id: String,
    pub expected_revision: u64,
    pub scopes: Vec<(String, u64)>,
    pub request_hash: String,
}

fn provisioning_future_boards(record: &PairingRecord) -> bool {
    record
        .offer
        .pointer("/body/policy/futureBoards")
        .and_then(Value::as_bool)
        .unwrap_or(false)
        && pairing_baseline(record).is_ok_and(|baseline| !baseline.is_empty())
}

fn parse_baseline_workspace_ids(
    value: Option<&Value>,
    approved: &[String],
    required: bool,
) -> Result<Vec<String>, ()> {
    let Some(value) = value else {
        return if required {
            Err(())
        } else {
            Ok(approved.to_vec())
        };
    };
    let values = value.as_array().ok_or(())?;
    if values.is_empty() || values.len() > MAX_BASELINE_WORKSPACES {
        return Err(());
    }
    let ids = values
        .iter()
        .map(|value| {
            value
                .as_str()
                .filter(|id| !id.is_empty() && id.len() <= 256)
                .map(str::to_owned)
                .ok_or(())
        })
        .collect::<Result<Vec<_>, _>>()?;
    if ids.windows(2).any(|pair| pair[0] >= pair[1])
        || approved.iter().any(|id| ids.binary_search(id).is_err())
    {
        return Err(());
    }
    Ok(ids)
}

fn pairing_baseline(record: &PairingRecord) -> Result<Vec<String>, ()> {
    let approved = record.offer["body"]["scopes"]
        .as_array()
        .ok_or(())?
        .iter()
        .map(|scope| scope["workspaceId"].as_str().map(str::to_owned).ok_or(()))
        .collect::<Result<Vec<_>, _>>()?;
    let policy = &record.offer["body"]["policy"];
    let future_boards = policy["futureBoards"].as_bool().unwrap_or(false);
    parse_baseline_workspace_ids(policy.get("baselineWorkspaceIds"), &approved, future_boards)
}

#[derive(Clone)]
struct AdminSession {
    csrf: String,
    expires_at: u64,
    person_id: Option<String>,
    display_name: String,
    operator: bool,
}

#[derive(Clone)]
struct LoginChallenge {
    nonce: String,
    intent_cookie: String,
    expires_at: u64,
}

#[derive(Clone)]
struct LoginCode {
    person_id: String,
    display_name: String,
    intent_cookie: String,
    expires_at: u64,
}

#[derive(Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ControllerRequest {
    pub identity: PublicIdentity,
    pub device_id: String,
    pub certificates: Vec<DeviceCertificate>,
    pub signed: SignedEnvelope<Value>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LoginRequest {
    pub secret: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LoginExchangeRequest {
    pub code: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SessionResponse {
    pub csrf_token: String,
    pub person_id: Option<String>,
    pub display_name: String,
    pub operator: bool,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LoginChallengeResponse {
    pub challenge_id: String,
    pub match_url: String,
    pub expires_at: u64,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LoginProofResponse {
    pub code: String,
    pub redirect_url: String,
}

impl PairingService {
    pub fn service_person_id(&self) -> &str {
        &self.service_identity.person_id
    }

    #[allow(clippy::too_many_arguments)]
    pub fn open(
        directory: PathBuf,
        peer: &Value,
        origin: String,
        service_seed: [u8; 32],
        admin_secret: String,
    ) -> Result<Self, String> {
        if admin_secret.len() < 24 {
            return Err("LIGHTHOUSE_ADMIN_TOKEN must contain at least 24 characters".into());
        }
        let payload = peer
            .pointer("/advertisement/payload")
            .or_else(|| peer.pointer("/payload"))
            .ok_or("Missing service identity")?;
        let identity = PublicIdentity {
            person_id: payload["personId"]
                .as_str()
                .ok_or("Missing personId")?
                .into(),
            public_key: peer["publicKey"]
                .as_str()
                .ok_or("Missing service public key")?
                .into(),
            display_name: payload["displayName"]
                .as_str()
                .unwrap_or("Lighthouse")
                .into(),
        };
        let device_id = payload["deviceId"]
            .as_str()
            .ok_or("Missing service deviceId")?
            .to_owned();
        let certificates: Vec<DeviceCertificate> =
            serde_json::from_value(peer["certificates"].clone())
                .map_err(|_| "Invalid service certificate chain")?;
        let device_public_key =
            verify_device_certificate_chain(&identity, &device_id, &certificates, "MATCH/1")?;
        if public_key_id(&device_public_key)? != device_id {
            return Err("Service signing seed does not match its device certificate".into());
        }
        fs::create_dir_all(&directory).map_err(|error| error.to_string())?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&directory, fs::Permissions::from_mode(0o700))
                .map_err(|error| error.to_string())?;
        }
        let store_path = directory.join("pairings.json");
        let state = if store_path.exists() {
            serde_json::from_slice(&fs::read(store_path).map_err(|error| error.to_string())?)
                .map_err(|_| "Invalid durable pairing state")?
        } else {
            PairingState::default()
        };
        Ok(Self {
            state: Arc::new(Mutex::new(state)),
            directory: Arc::new(directory),
            service_identity: identity,
            service_device_id: device_id,
            service_seed: Arc::new(service_seed),
            origin,
            admin_secret: Arc::new(admin_secret),
            provisioning_runs: Arc::new(Mutex::new(std::collections::HashSet::new())),
        })
    }

    pub fn create(&self, request: ControllerRequest) -> Result<PairingRecord, PairingError> {
        let now = now_seconds();
        self.verify_controller(&request)?;
        let payload = &request.signed.payload;
        validate_common(
            payload,
            "lighthouse-pairing-offer",
            &request,
            &self.service_identity,
            &self.origin,
            now,
        )?;
        let operation_id = string_field(payload, "operationId")?;
        let body = payload
            .get("body")
            .ok_or(PairingError::Invalid("Missing offer body"))?;
        let future_boards = body
            .pointer("/policy/futureBoards")
            .and_then(Value::as_bool)
            .ok_or(PairingError::Invalid("Missing future-board policy"))?;
        let scopes = body
            .get("scopes")
            .and_then(Value::as_array)
            .ok_or(PairingError::Invalid("Missing scope list"))?;
        if scopes.is_empty() || scopes.len() > MAX_SCOPES {
            return Err(PairingError::Invalid("Select between 1 and 16 boards"));
        }
        let mut seen = std::collections::HashSet::new();
        for scope in scopes {
            let id = scope
                .get("workspaceId")
                .and_then(Value::as_str)
                .ok_or(PairingError::Invalid("Scope is missing workspaceId"))?;
            let title = scope
                .get("title")
                .and_then(Value::as_str)
                .unwrap_or_default();
            let anchor = scope
                .get("genesisAnchor")
                .and_then(Value::as_str)
                .unwrap_or_default();
            if id.is_empty()
                || id.len() > 256
                || title.trim().is_empty()
                || title.len() > 256
                || anchor.is_empty()
                || anchor.len() > 4096
                || !seen.insert(id)
                || scope.get("mode").and_then(Value::as_str) != Some("replicate")
            {
                return Err(PairingError::Invalid(
                    "Scopes must have unique IDs, genesis anchors and replicate mode",
                ));
            }
        }
        let approved_ids = scopes
            .iter()
            .map(|scope| scope["workspaceId"].as_str().unwrap().to_owned())
            .collect::<Vec<_>>();
        parse_baseline_workspace_ids(
            body.pointer("/policy/baselineWorkspaceIds"),
            &approved_ids,
            future_boards,
        )
        .map_err(|_| PairingError::Invalid("Missing or invalid signed workspace baseline"))?;
        let canonical = canonicalize_json(payload)
            .map_err(|_| PairingError::Invalid("Invalid signed offer"))?;
        let transcript_hash = URL_SAFE_NO_PAD.encode(Sha256::digest(canonical.as_bytes()));
        let mut state = self.state.lock().map_err(|_| PairingError::Unavailable)?;
        // Keep operation replay records through expiry plus the bounded clock skew.
        state
            .records
            .retain(|_, record| record.expires_at.saturating_add(30) > now);
        if let Some(existing) = state
            .records
            .values()
            .find(|record| record.last_operation_id == operation_id)
        {
            return if existing.transcript_hash == transcript_hash {
                Ok(existing.clone())
            } else {
                Err(PairingError::Conflict)
            };
        }
        if state
            .records
            .values()
            .filter(|record| record.expires_at > now)
            .count()
            >= 100
        {
            return Err(PairingError::Unavailable);
        }
        let id = random_token(16);
        let nonce = random_token(32);
        let expires_at = now.saturating_add(MAX_AGE_SECONDS);
        let challenge_payload = json!({
            "kind": "lighthouse-pairing-challenge", "version": 1,
            "pairingId": id, "transcriptHash": transcript_hash,
            "servicePersonId": self.service_identity.person_id,
            "serviceDeviceId": self.service_device_id,
            "serviceOrigin": self.origin, "nonce": nonce,
            "integrationId": integration_id(&request.identity.person_id, &self.service_identity.person_id), "issuedAt": now, "expiresAt": expires_at,
        });
        let challenge = sign_json_envelope(
            &self.service_seed,
            challenge_payload,
            &self.service_device_id,
            CONTROL_DOMAIN,
        )
        .map_err(|_| PairingError::Unavailable)?;
        let comparison_code = comparison_code(
            &payload.clone(),
            &serde_json::to_value(&challenge).unwrap_or(Value::Null),
        );
        let record = PairingRecord {
            id,
            expires_at,
            created_at: now,
            transcript_hash,
            comparison_code,
            operator_approved: None,
            controller_approved: None,
            controller_decision_operation: None,
            controller_decision_hash: None,
            controller: request.identity,
            controller_device_id: request.device_id,
            controller_certificates: request.certificates,
            offer: payload.clone(),
            challenge,
            last_operation_id: operation_id.to_owned(),
            provisioning: None,
            withdrawal: None,
        };
        let mut next = state.clone();
        next.records.insert(record.id.clone(), record.clone());
        self.persist(&next)?;
        *state = next;
        Ok(record)
    }

    pub fn controller_decision(
        &self,
        id: &str,
        request: ControllerRequest,
    ) -> Result<PairingRecord, PairingError> {
        let _ = self.verify_controller(&request)?;
        let now = now_seconds();
        let mut state = self.state.lock().map_err(|_| PairingError::Unavailable)?;
        let record = state.records.get(id).ok_or(PairingError::NotFound)?;
        if record.expires_at <= now
            && record
                .provisioning
                .as_ref()
                .map(|provisioning| provisioning.status.as_str())
                != Some("active")
        {
            return Err(PairingError::Expired);
        }
        if request.identity.person_id != record.controller.person_id
            || request.device_id != record.controller_device_id
        {
            return Err(PairingError::Forbidden);
        }
        if record.withdrawal.is_some() {
            return Err(PairingError::Conflict);
        }
        let payload = &request.signed.payload;
        validate_common(
            payload,
            "lighthouse-pairing-decision",
            &request,
            &self.service_identity,
            &self.origin,
            now,
        )?;
        if payload["kind"] != "lighthouse-pairing-decision"
            || payload["pairingId"] != id
            || payload["transcriptHash"] != record.transcript_hash
            || payload["challengeNonce"] != record.challenge.payload["nonce"]
            || !matches!(payload["decision"].as_str(), Some("approve" | "decline"))
            || payload["issuedAt"]
                .as_u64()
                .is_none_or(|v| v > now + 30 || now.saturating_sub(v) > MAX_AGE_SECONDS)
        {
            return Err(PairingError::Invalid(
                "Decision is not bound to this pairing transcript",
            ));
        }
        let approved = payload["decision"] == "approve";
        let operation_id = string_field(payload, "operationId")?;
        let decision_hash = URL_SAFE_NO_PAD.encode(Sha256::digest(
            canonicalize_json(payload)
                .map_err(|_| PairingError::Invalid("Invalid decision payload"))?
                .as_bytes(),
        ));
        if record.controller_decision_operation.as_deref() == Some(operation_id) {
            return if record.controller_decision_hash.as_deref() == Some(&decision_hash) {
                Ok(record.clone())
            } else {
                Err(PairingError::Conflict)
            };
        }
        if record.controller_decision_operation.is_some() {
            return Err(PairingError::Conflict);
        }
        if record
            .controller_approved
            .is_some_and(|previous| previous != approved)
        {
            return Err(PairingError::Conflict);
        }
        let mut next = state.clone();
        let record = next.records.get_mut(id).ok_or(PairingError::NotFound)?;
        record.controller_approved = Some(approved);
        record.controller_decision_operation = Some(operation_id.to_owned());
        record.controller_decision_hash = Some(decision_hash);
        if !approved {
            record.operator_approved = Some(false);
        }
        let result = record.clone();
        self.persist(&next)?;
        *state = next;
        Ok(result)
    }

    /// Persist a controller-signed fence before acknowledging pairing withdrawal.
    /// Active scopes still require the existing signed disconnect protocol.
    pub fn withdraw(
        &self,
        id: &str,
        request: ControllerRequest,
    ) -> Result<SignedEnvelope<Value>, PairingError> {
        self.verify_controller(&request)?;
        let now = now_seconds();
        let payload = &request.signed.payload;
        validate_common(
            payload,
            "lighthouse-pairing-withdrawal",
            &request,
            &self.service_identity,
            &self.origin,
            now,
        )?;
        let mut state = self.state.lock().map_err(|_| PairingError::Unavailable)?;
        let record = state.records.get(id).ok_or(PairingError::NotFound)?;
        if request.identity.person_id != record.controller.person_id
            || request.device_id != record.controller_device_id
            || payload["pairingId"] != id
            || payload["transcriptHash"] != record.transcript_hash
            || payload["challengeNonce"] != record.challenge.payload["nonce"]
        {
            return Err(PairingError::Forbidden);
        }
        let operation_id = string_field(payload, "operationId")?.to_owned();
        let mut semantic = payload.clone();
        if let Some(object) = semantic.as_object_mut() {
            object.remove("issuedAt");
            object.remove("expiresAt");
        }
        let request_hash = URL_SAFE_NO_PAD.encode(Sha256::digest(
            canonicalize_json(&semantic)
                .map_err(|_| PairingError::Invalid("Invalid withdrawal payload"))?
                .as_bytes(),
        ));
        let mut next = state.clone();
        let record = next.records.get_mut(id).ok_or(PairingError::NotFound)?;
        if let Some(previous) = &record.withdrawal {
            if previous.operation_id != operation_id || previous.request_hash != request_hash {
                return Err(PairingError::Conflict);
            }
        } else {
            record.withdrawal = Some(PairingWithdrawal {
                operation_id: operation_id.clone(),
                request_hash: request_hash.clone(),
                status: "cancel_pending".into(),
                completion_hash: None,
                verified_revocations: Vec::new(),
                verified_grants: Vec::new(),
            });
        }
        self.persist(&next)?;
        *state = next;
        self.sign_status_record(state.records.get(id).ok_or(PairingError::NotFound)?)
    }

    /// Parse owner-signed grants supplied at withdrawal for legacy pairing
    /// records whose exact issued epochs were not persisted by older binaries.
    /// The caller verifies each proof before `record_withdrawal_grants` stores it.
    pub fn withdrawal_grant_scopes(
        &self,
        id: &str,
        request: &ControllerRequest,
    ) -> Result<Vec<WithdrawalGrantScope>, PairingError> {
        self.verify_controller(request)?;
        let payload = &request.signed.payload;
        validate_common(
            payload,
            "lighthouse-pairing-withdrawal",
            request,
            &self.service_identity,
            &self.origin,
            now_seconds(),
        )?;
        let state = self.state.lock().map_err(|_| PairingError::Unavailable)?;
        let record = state.records.get(id).ok_or(PairingError::NotFound)?;
        if request.identity.person_id != record.controller.person_id
            || request.device_id != record.controller_device_id
            || payload["pairingId"] != id
            || payload["transcriptHash"] != record.transcript_hash
            || payload["challengeNonce"] != record.challenge.payload["nonce"]
        {
            return Err(PairingError::Forbidden);
        }
        if record
            .withdrawal
            .as_ref()
            .is_some_and(|withdrawal| withdrawal.status == "cancelled")
        {
            return Ok(Vec::new());
        }
        // A pairing that never entered provisioning issued no grant. Ignore any
        // stale grant proofs supplied by the client; they may belong to a prior
        // integration for the same keeper and must not seed or revoke it.
        if record.provisioning.is_none() {
            return Ok(Vec::new());
        }
        let approved_scopes = record.offer["body"]["scopes"]
            .as_array()
            .ok_or(PairingError::Invalid("Pairing has no approved scopes"))?
            .iter()
            .map(|scope| {
                scope["workspaceId"]
                    .as_str()
                    .map(str::to_owned)
                    .ok_or(PairingError::Invalid("Invalid approved scope"))
            })
            .collect::<Result<Vec<_>, _>>()?;
        let proofs = match payload.get("grantScopes") {
            None => &[][..],
            Some(Value::Array(proofs)) => proofs.as_slice(),
            Some(_) => return Err(PairingError::Invalid("Invalid grant proof list")),
        };
        if proofs.len() > MAX_SCOPES {
            return Err(PairingError::Invalid("Too many grant proofs"));
        }
        let mut result = Vec::with_capacity(proofs.len());
        let mut ids = Vec::with_capacity(proofs.len());
        let mut total_document_bytes = 0usize;
        for proof in proofs {
            let workspace_id = proof["workspaceId"]
                .as_str()
                .filter(|value| !value.is_empty() && value.len() <= 256)
                .ok_or(PairingError::Invalid("Invalid grant proof scope"))?
                .to_owned();
            let encoded_document = proof["document"]
                .as_str()
                .ok_or(PairingError::Invalid("Missing grant proof document"))?;
            let document = URL_SAFE_NO_PAD
                .decode(encoded_document)
                .map_err(|_| PairingError::Invalid("Invalid grant proof document"))?;
            total_document_bytes = total_document_bytes.saturating_add(document.len());
            if document.is_empty() || total_document_bytes > MAX_REVOCATION_DOCUMENT_BYTES {
                return Err(PairingError::Invalid("Grant evidence is too large"));
            }
            let authorization_bundle = proof["authorizationBundle"]
                .as_object()
                .map(|_| proof["authorizationBundle"].clone())
                .ok_or(PairingError::Invalid("Missing grant authority proof"))?;
            let grant = proof["grant"]
                .as_object()
                .map(|_| proof["grant"].clone())
                .ok_or(PairingError::Invalid("Missing signed grant"))?;
            ids.push(workspace_id.clone());
            result.push(WithdrawalGrantScope {
                workspace_id,
                document,
                authorization_bundle,
                grant,
            });
        }
        if ids.windows(2).any(|pair| pair[0] >= pair[1])
            || ids
                .iter()
                .any(|workspace_id| !approved_scopes.contains(workspace_id))
        {
            return Err(PairingError::Invalid(
                "Grant proofs must be sorted, unique, and selected by this pairing",
            ));
        }
        Ok(result)
    }

    /// Persist cryptographically verified legacy grant generations against the
    /// immutable first withdrawal operation. Retries cannot replace a generation.
    pub fn record_withdrawal_grants(
        &self,
        id: &str,
        operation_id: &str,
        grants: Vec<VerifiedWithdrawalGrant>,
    ) -> Result<SignedEnvelope<Value>, PairingError> {
        let mut state = self.state.lock().map_err(|_| PairingError::Unavailable)?;
        let mut next = state.clone();
        let record = next.records.get_mut(id).ok_or(PairingError::NotFound)?;
        let withdrawal = record.withdrawal.as_mut().ok_or(PairingError::Conflict)?;
        if withdrawal.operation_id != operation_id || withdrawal.status == "cancelled" {
            return Err(PairingError::Conflict);
        }
        let provisioning = record.provisioning.as_mut().ok_or(PairingError::Conflict)?;
        let mut new_ids = grants
            .iter()
            .map(|grant| grant.workspace_id.clone())
            .collect::<Vec<_>>();
        new_ids.sort();
        if new_ids.windows(2).any(|pair| pair[0] == pair[1]) {
            return Err(PairingError::Invalid("Duplicate verified grant scope"));
        }
        for grant in grants {
            if grant.grant_id.is_empty() || grant.grant_epoch == 0 || grant.grant_hash.is_empty() {
                return Err(PairingError::Forbidden);
            }
            let scope = provisioning
                .scopes
                .iter_mut()
                .find(|scope| scope.workspace_id == grant.workspace_id)
                .ok_or(PairingError::Forbidden)?;
            if scope
                .grant_epoch
                .is_some_and(|epoch| epoch != grant.grant_epoch)
            {
                return Err(PairingError::Conflict);
            }
            if let Some(previous) = withdrawal
                .verified_grants
                .iter()
                .find(|previous| previous.workspace_id == grant.workspace_id)
            {
                if previous.grant_id != grant.grant_id
                    || previous.grant_epoch != grant.grant_epoch
                    || previous.grant_hash != grant.grant_hash
                {
                    return Err(PairingError::Conflict);
                }
            } else {
                withdrawal.verified_grants.push(grant.clone());
            }
            scope.grant_epoch = Some(grant.grant_epoch);
        }
        withdrawal
            .verified_grants
            .sort_by(|left, right| left.workspace_id.cmp(&right.workspace_id));
        self.persist(&next)?;
        *state = next;
        self.sign_status_record(state.records.get(id).ok_or(PairingError::NotFound)?)
    }

    /// Validate exact owner-signed revocation evidence for every pairing scope.
    /// The caller must pass each returned bundle to the shared Tincanban authority verifier.
    pub fn withdrawal_completion_request(
        &self,
        id: &str,
        request: ControllerRequest,
    ) -> Result<VerifiedWithdrawalCompletion, PairingError> {
        self.verify_controller(&request)?;
        let now = now_seconds();
        let payload = &request.signed.payload;
        validate_common(
            payload,
            "lighthouse-pairing-withdrawal-complete",
            &request,
            &self.service_identity,
            &self.origin,
            now,
        )?;
        let operation_id = string_field(payload, "operationId")?.to_owned();
        let withdrawal_operation_id = string_field(payload, "withdrawalOperationId")?;
        let transcript_hash = string_field(payload, "transcriptHash")?;
        let mut semantic = payload.clone();
        if let Some(object) = semantic.as_object_mut() {
            object.remove("issuedAt");
            object.remove("expiresAt");
        }
        let request_hash = URL_SAFE_NO_PAD.encode(Sha256::digest(
            canonicalize_json(&semantic)
                .map_err(|_| PairingError::Invalid("Invalid withdrawal completion"))?
                .as_bytes(),
        ));

        let state = self.state.lock().map_err(|_| PairingError::Unavailable)?;
        let record = state.records.get(id).ok_or(PairingError::NotFound)?;
        let withdrawal = record.withdrawal.as_ref().ok_or(PairingError::Conflict)?;
        if request.identity.person_id != record.controller.person_id
            || request.device_id != record.controller_device_id
            || payload["pairingId"] != id
            || transcript_hash != record.transcript_hash
            || payload["challengeNonce"] != record.challenge.payload["nonce"]
            || withdrawal_operation_id != withdrawal.operation_id
        {
            return Err(PairingError::Forbidden);
        }
        if withdrawal.status == "cancelled" {
            if withdrawal.completion_hash.as_deref() != Some(request_hash.as_str()) {
                return Err(PairingError::Conflict);
            }
            return Ok(VerifiedWithdrawalCompletion {
                request_hash,
                operation_id,
                integration_id: record.challenge.payload["integrationId"]
                    .as_str()
                    .ok_or(PairingError::Invalid("Missing pairing integration ID"))?
                    .to_owned(),
                controller_person_id: record.controller.person_id.clone(),
                service_person_id: self.service_identity.person_id.clone(),
                scopes: Vec::new(),
                issued_grant_epochs: HashMap::new(),
            });
        }

        let offered = record.offer["body"]["scopes"]
            .as_array()
            .ok_or(PairingError::Invalid("Pairing has no approved scopes"))?;
        let mut expected = offered
            .iter()
            .map(|scope| {
                scope["workspaceId"]
                    .as_str()
                    .filter(|id| !id.is_empty() && id.len() <= 256)
                    .map(str::to_owned)
                    .ok_or(PairingError::Invalid("Invalid approved scope"))
            })
            .collect::<Result<Vec<_>, _>>()?;
        expected.sort();
        let provided = payload["scopes"]
            .as_array()
            .filter(|scopes| !scopes.is_empty() && scopes.len() <= MAX_SCOPES)
            .ok_or(PairingError::Invalid("Invalid withdrawal scope proof list"))?;
        let mut scopes = Vec::with_capacity(provided.len());
        let mut provided_ids = Vec::with_capacity(provided.len());
        let mut total_document_bytes = 0usize;
        for proof in provided {
            let workspace_id = proof["workspaceId"]
                .as_str()
                .filter(|id| !id.is_empty() && id.len() <= 256)
                .ok_or(PairingError::Invalid("Invalid withdrawal scope proof"))?
                .to_owned();
            let encoded_document = proof["document"]
                .as_str()
                .ok_or(PairingError::Invalid("Missing revocation document"))?;
            let document = URL_SAFE_NO_PAD
                .decode(encoded_document)
                .map_err(|_| PairingError::Invalid("Invalid revocation document"))?;
            total_document_bytes = total_document_bytes.saturating_add(document.len());
            if document.is_empty() || total_document_bytes > MAX_REVOCATION_DOCUMENT_BYTES {
                return Err(PairingError::Invalid("Revocation evidence is too large"));
            }
            let authorization_bundle = proof["authorizationBundle"]
                .as_object()
                .map(|_| proof["authorizationBundle"].clone())
                .ok_or(PairingError::Invalid("Missing revocation authority proof"))?;
            provided_ids.push(workspace_id.clone());
            scopes.push(WithdrawalCompletionScope {
                workspace_id,
                document,
                authorization_bundle,
            });
        }
        if provided_ids.windows(2).any(|pair| pair[0] >= pair[1]) || provided_ids != expected {
            return Err(PairingError::Invalid(
                "Withdrawal proofs must exactly match approved scopes in sorted order",
            ));
        }
        Ok(VerifiedWithdrawalCompletion {
            request_hash,
            operation_id,
            integration_id: record.challenge.payload["integrationId"]
                .as_str()
                .ok_or(PairingError::Invalid("Missing pairing integration ID"))?
                .to_owned(),
            controller_person_id: record.controller.person_id.clone(),
            service_person_id: self.service_identity.person_id.clone(),
            scopes,
            issued_grant_epochs: record
                .provisioning
                .as_ref()
                .map(|provisioning| {
                    provisioning
                        .scopes
                        .iter()
                        .map(|scope| (scope.workspace_id.clone(), scope.grant_epoch))
                        .collect()
                })
                .unwrap_or_default(),
        })
    }

    /// Persist completion only after verified revocation and integration cleanup.
    pub fn record_withdrawal_completion(
        &self,
        id: &str,
        completion: VerifiedWithdrawalCompletion,
        revocations: Vec<VerifiedWithdrawalRevocation>,
        minimum_grant_epochs: HashMap<String, u64>,
        integration_detached: bool,
    ) -> Result<SignedEnvelope<Value>, PairingError> {
        let mut state = self.state.lock().map_err(|_| PairingError::Unavailable)?;
        let mut next = state.clone();
        let record = next.records.get_mut(id).ok_or(PairingError::NotFound)?;
        let withdrawal = record.withdrawal.as_mut().ok_or(PairingError::Conflict)?;
        if withdrawal.status == "cancelled" {
            if withdrawal.completion_hash.as_deref() != Some(completion.request_hash.as_str()) {
                return Err(PairingError::Conflict);
            }
            return self.sign_status_record(record);
        }
        if withdrawal.operation_id != completion.operation_id
            || record.challenge.payload["integrationId"] != completion.integration_id
            || completion.controller_person_id != record.controller.person_id
            || completion.service_person_id != self.service_identity.person_id
            || !integration_detached
        {
            return Err(PairingError::Conflict);
        }
        let expected = record.offer["body"]["scopes"]
            .as_array()
            .ok_or(PairingError::Invalid("Pairing has no approved scopes"))?
            .iter()
            .map(|scope| scope["workspaceId"].as_str().map(str::to_owned))
            .collect::<Option<Vec<_>>>()
            .ok_or(PairingError::Invalid("Invalid approved scope"))?;
        let mut expected = expected;
        expected.sort();
        let provided = revocations
            .iter()
            .map(|proof| proof.workspace_id.clone())
            .collect::<Vec<_>>();
        if provided != expected
            || minimum_grant_epochs.len() != expected.len()
            || expected
                .iter()
                .any(|workspace_id| !minimum_grant_epochs.contains_key(workspace_id))
            || revocations.iter().any(|proof| {
                proof.revocation_epoch == 0
                    || proof.revocation_hash.is_empty()
                    || minimum_grant_epochs
                        .get(&proof.workspace_id)
                        .is_none_or(|epoch| proof.revocation_epoch <= *epoch)
            })
        {
            return Err(PairingError::Forbidden);
        }
        let running = self
            .provisioning_runs
            .lock()
            .map_err(|_| PairingError::Unavailable)?;
        let in_flight = running.contains(id);
        drop(running);
        if in_flight
            || record
                .provisioning
                .as_ref()
                .is_some_and(|value| value.scopes.iter().any(|scope| scope.status == "active"))
        {
            return Err(PairingError::Conflict);
        }
        if let Some(provisioning) = &record.provisioning {
            for scope in &provisioning.scopes {
                let Some(stored_epoch) = scope.grant_epoch else {
                    // Legacy/incomplete records cannot use an assumed epoch. A
                    // verified Rusty tombstone may supply the missing bound.
                    continue;
                };
                if minimum_grant_epochs
                    .get(&scope.workspace_id)
                    .is_none_or(|minimum| *minimum < stored_epoch)
                {
                    return Err(PairingError::Forbidden);
                }
            }
        }
        withdrawal.status = "cancelled".into();
        withdrawal.completion_hash = Some(completion.request_hash);
        withdrawal.verified_revocations = revocations;
        if let Some(provisioning) = record.provisioning.as_mut() {
            provisioning.status = "detached".into();
            for scope in &mut provisioning.scopes {
                scope.status = "removed".into();
            }
        }
        self.persist(&next)?;
        *state = next;
        self.sign_status_record(state.records.get(id).ok_or(PairingError::NotFound)?)
    }

    /// Finish cancellation only after durable activation and cleanup reconciliation.
    pub fn finalize_withdrawal(&self, id: &str) -> Result<SignedEnvelope<Value>, PairingError> {
        let mut state = self.state.lock().map_err(|_| PairingError::Unavailable)?;
        let mut next = state.clone();
        let record = next.records.get_mut(id).ok_or(PairingError::NotFound)?;
        if record.withdrawal.is_none() {
            return Err(PairingError::Conflict);
        }
        if record
            .withdrawal
            .as_ref()
            .is_some_and(|withdrawal| withdrawal.status != "cancelled")
        {
            let running = self
                .provisioning_runs
                .lock()
                .map_err(|_| PairingError::Unavailable)?;
            let in_flight = running.contains(id);
            drop(running);
            let provisioning = record.provisioning.as_ref();
            let has_active_scopes = provisioning
                .is_some_and(|value| value.scopes.iter().any(|scope| scope.status == "active"));
            let cleanup_pending =
                provisioning.is_some_and(|value| value.status == "pending_cleanup");
            let detached = provisioning.is_some_and(|value| value.status == "detached");
            let grant_generations_known = provisioning
                .is_none_or(|value| value.scopes.iter().all(|scope| scope.grant_epoch.is_some()));
            let safe = !in_flight
                && !has_active_scopes
                && !cleanup_pending
                && grant_generations_known
                && (provisioning.is_none() || detached);
            if safe {
                record.withdrawal.as_mut().unwrap().status = "cancelled".into();
            }
        }
        self.persist(&next)?;
        *state = next;
        self.sign_status_record(state.records.get(id).ok_or(PairingError::NotFound)?)
    }

    /// Serialize activation against withdrawal so a fenced pairing cannot commit late.
    pub fn commit_activation_if_not_withdrawn(
        &self,
        id: &str,
        commit: impl FnOnce() -> Result<(), String>,
    ) -> Result<(), String> {
        let state = self
            .state
            .lock()
            .map_err(|_| "Pairing state lock poisoned".to_owned())?;
        let record = state
            .records
            .get(id)
            .ok_or_else(|| "Pairing was not found".to_owned())?;
        if record.withdrawal.is_some() {
            return Err("Pairing withdrawal is pending".into());
        }
        commit()
    }

    /// Persist every owner-issued grant epoch as soon as its staged scope is verified.
    /// This survives a later staging/activation failure so withdrawal can prove revocation
    /// moved beyond the exact credential issued by this pairing.
    pub fn record_issued_grant_epoch(
        &self,
        id: &str,
        workspace_id: &str,
        grant_epoch: u64,
    ) -> Result<(), String> {
        if grant_epoch == 0 || workspace_id.is_empty() {
            return Err("Invalid issued workspace grant".into());
        }
        let mut state = self
            .state
            .lock()
            .map_err(|_| "Pairing state lock poisoned".to_owned())?;
        let mut next = state.clone();
        let record = next
            .records
            .get_mut(id)
            .ok_or_else(|| "Pairing was not found".to_owned())?;
        let approved = record.offer["body"]["scopes"]
            .as_array()
            .is_some_and(|scopes| {
                scopes
                    .iter()
                    .any(|scope| scope["workspaceId"] == workspace_id)
            });
        if !approved {
            return Err("Issued grant is outside approved pairing scopes".into());
        }
        let provisioning = record
            .provisioning
            .as_mut()
            .ok_or_else(|| "Provisioning has not started".to_owned())?;
        let scope = provisioning
            .scopes
            .iter_mut()
            .find(|scope| scope.workspace_id == workspace_id)
            .ok_or_else(|| "Issued grant is outside provisioning scopes".to_owned())?;
        scope.grant_epoch = Some(scope.grant_epoch.unwrap_or(0).max(grant_epoch));
        self.persist(&next)
            .map_err(|_| "Could not persist issued grant epoch".to_owned())?;
        *state = next;
        Ok(())
    }

    /// Admit only an ordinary workspace invitation for the exact dual-approved
    /// service identity and scope set. The invitation secret stays out of every
    /// durable pairing record and status response.
    pub fn begin_provision(
        &self,
        id: &str,
        request: ControllerRequest,
    ) -> Result<ProvisionRequest, PairingError> {
        let device_key = self.verify_controller(&request)?;
        let now = now_seconds();
        let payload = &request.signed.payload;
        validate_common(
            payload,
            "lighthouse-pairing-provision",
            &request,
            &self.service_identity,
            &self.origin,
            now,
        )?;
        let operation_id = string_field(payload, "operationId")?.to_owned();
        let body = payload
            .get("body")
            .and_then(Value::as_object)
            .ok_or(PairingError::Invalid("Missing provisioning body"))?;
        let future_boards = body
            .get("futureBoards")
            .and_then(Value::as_bool)
            .ok_or(PairingError::Invalid("Missing future-board policy"))?;
        if body.get("pairingId").and_then(Value::as_str) != Some(id)
            || body.get("transcriptHash").and_then(Value::as_str).is_none()
            || body.get("servicePersonId").and_then(Value::as_str)
                != Some(self.service_identity.person_id.as_str())
        {
            return Err(PairingError::Invalid(
                "Provision request is not bound to this service and pairing",
            ));
        }
        let approved = body
            .get("approvedScopes")
            .and_then(Value::as_array)
            .ok_or(PairingError::Invalid("Missing approved scope list"))?;
        let request_hash = URL_SAFE_NO_PAD.encode(Sha256::digest(
            canonicalize_json(payload)
                .map_err(|_| PairingError::Invalid("Invalid provisioning request"))?
                .as_bytes(),
        ));

        let mut state = self.state.lock().map_err(|_| PairingError::Unavailable)?;
        let record = state.records.get(id).ok_or(PairingError::NotFound)?;
        if record.expires_at <= now && record.withdrawal.is_none() {
            return Err(PairingError::Expired);
        }
        if request.identity.person_id != record.controller.person_id
            || request.device_id != record.controller_device_id
            || body.get("transcriptHash").and_then(Value::as_str)
                != Some(record.transcript_hash.as_str())
        {
            return Err(PairingError::Forbidden);
        }
        if record.withdrawal.is_some() {
            return Err(PairingError::Conflict);
        }
        if record.controller_approved != Some(true) || record.operator_approved != Some(true) {
            return Err(PairingError::Forbidden);
        }
        let integration_id = record.challenge.payload["integrationId"]
            .as_str()
            .ok_or(PairingError::Invalid(
                "Pairing is missing integration identity",
            ))?
            .to_owned();
        if record
            .offer
            .pointer("/body/policy/futureBoards")
            .and_then(Value::as_bool)
            != Some(future_boards)
        {
            return Err(PairingError::Invalid(
                "Provision future-board policy differs from signed offer",
            ));
        }
        let approved_baseline_ids = record.offer["body"]["scopes"]
            .as_array()
            .ok_or(PairingError::Invalid("Pairing has no approved scopes"))?
            .iter()
            .map(|scope| {
                scope["workspaceId"]
                    .as_str()
                    .map(str::to_owned)
                    .ok_or(PairingError::Invalid("Invalid approved scope"))
            })
            .collect::<Result<Vec<_>, _>>()?;
        let approved_baseline = pairing_baseline(record)
            .map_err(|_| PairingError::Invalid("Pairing has no signed workspace baseline"))?;
        let requested_baseline = parse_baseline_workspace_ids(
            body.get("baselineWorkspaceIds"),
            &approved_baseline_ids,
            future_boards,
        )
        .map_err(|_| PairingError::Invalid("Missing or invalid provisioning workspace baseline"))?;
        if requested_baseline != approved_baseline {
            return Err(PairingError::Invalid(
                "Provision workspace baseline differs from signed offer",
            ));
        }
        let transcript_hash = record.transcript_hash.clone();
        let invitation: WorkspaceJoinInvitation = serde_json::from_value(
            body.get("invitation")
                .cloned()
                .ok_or(PairingError::Invalid("Missing workspace invitation"))?,
        )
        .map_err(|_| PairingError::Invalid("Invalid workspace invitation"))?;
        let offered = record.offer["body"]["scopes"]
            .as_array()
            .ok_or(PairingError::Invalid("Pairing has no approved scopes"))?;
        let mut scope_ids = Vec::with_capacity(offered.len());
        for (index, scope) in offered.iter().enumerate() {
            let workspace_id = scope["workspaceId"]
                .as_str()
                .filter(|value| !value.is_empty())
                .ok_or(PairingError::Invalid("Invalid approved scope"))?;
            if scope["mode"] != "replicate"
                || approved.get(index).is_none_or(|entry| {
                    entry["workspaceId"] != workspace_id || entry["mode"] != "replicate"
                })
            {
                return Err(PairingError::Invalid(
                    "Provision scopes differ from the approved transcript",
                ));
            }
            scope_ids.push(workspace_id.to_owned());
        }
        if approved.len() != scope_ids.len()
            || invitation.kind != "workspace-join"
            || invitation.version != 1
            || invitation.issuer_person_id != request.identity.person_id
            || invitation.issuer_device_id != request.device_id
            || invitation.issuer_public_key != device_key
            || invitation.role != "editor"
            || invitation.secret.len() < 32
            || invitation
                .workspaces
                .iter()
                .map(|scope| scope.id.clone())
                .collect::<Vec<_>>()
                != scope_ids
            || invitation.workspace_id != scope_ids.first().cloned().unwrap_or_default()
            || invitation.invitation_id.is_empty()
            || invitation.issuer_endpoint.is_empty()
            || invitation.expires_at.is_empty()
        {
            return Err(PairingError::Invalid(
                "Invitation does not match the approved owner and scopes",
            ));
        }
        let created_at = time::OffsetDateTime::parse(
            &invitation.created_at,
            &time::format_description::well_known::Rfc3339,
        )
        .map_err(|_| PairingError::Invalid("Invalid invitation creation time"))?;
        let expires_at = time::OffsetDateTime::parse(
            &invitation.expires_at,
            &time::format_description::well_known::Rfc3339,
        )
        .map_err(|_| PairingError::Invalid("Invalid invitation expiry"))?;
        let now = time::OffsetDateTime::now_utc();
        if created_at > now + time::Duration::seconds(30)
            || expires_at <= now
            || expires_at <= created_at
            || expires_at - created_at > time::Duration::minutes(10)
        {
            return Err(PairingError::Invalid(
                "Invitation must be valid and expire within 10 minutes",
            ));
        }
        if let Some(previous) = &record.provisioning {
            if previous.operation_id != operation_id || previous.request_hash != request_hash {
                return Err(PairingError::Conflict);
            }
            if matches!(previous.status.as_str(), "pending_cleanup" | "detached") {
                return Err(PairingError::Conflict);
            }
            if previous.status == "active" {
                return Ok(ProvisionRequest {
                    invitation,
                    scopes: scope_ids,
                    integration_id: integration_id.clone(),
                    operation_id,
                    transcript_hash,
                    future_boards,
                    baseline_workspace_ids: approved_baseline,
                    should_run: false,
                });
            }
        } else {
            let mut next = state.clone();
            next.records
                .get_mut(id)
                .ok_or(PairingError::NotFound)?
                .provisioning = Some(ProvisioningRecord {
                operation_id: operation_id.clone(),
                request_hash: request_hash.clone(),
                status: "provisioning".into(),
                scopes: scope_ids
                    .iter()
                    .map(|workspace_id| ProvisionedScope {
                        workspace_id: workspace_id.clone(),
                        status: "pending".into(),
                        grant_epoch: None,
                        error: None,
                        error_detail: None,
                    })
                    .collect(),
            });
            self.persist(&next)?;
            *state = next;
        }
        let mut running = self
            .provisioning_runs
            .lock()
            .map_err(|_| PairingError::Unavailable)?;
        let should_run = running.insert(id.to_owned());
        drop(running);
        drop(state);
        Ok(ProvisionRequest {
            invitation,
            scopes: scope_ids,
            integration_id,
            operation_id,
            transcript_hash,
            future_boards,
            baseline_workspace_ids: approved_baseline,
            should_run,
        })
    }

    pub fn complete_provision(
        &self,
        id: &str,
        mut scopes: Vec<ProvisionedScope>,
        active: bool,
    ) -> Result<(), PairingError> {
        let mut state = self.state.lock().map_err(|_| PairingError::Unavailable)?;
        let mut next = state.clone();
        let provisioning = next
            .records
            .get_mut(id)
            .ok_or(PairingError::NotFound)?
            .provisioning
            .as_mut()
            .ok_or(PairingError::Conflict)?;
        if scopes.len() != provisioning.scopes.len()
            || scopes
                .iter()
                .zip(&provisioning.scopes)
                .any(|(actual, expected)| actual.workspace_id != expected.workspace_id)
            || (active
                && scopes
                    .iter()
                    .any(|scope| scope.status != "active" || scope.error.is_some()))
        {
            return Err(PairingError::Conflict);
        }
        for (actual, previous) in scopes.iter_mut().zip(&provisioning.scopes) {
            if actual.grant_epoch.is_none() {
                actual.grant_epoch = previous.grant_epoch;
            }
        }
        provisioning.scopes = scopes;
        provisioning.status = if active { "active" } else { "provisioning" }.into();
        if let Err(error) = self.persist(&next) {
            self.provisioning_runs
                .lock()
                .map_err(|_| PairingError::Unavailable)?
                .remove(id);
            return Err(error);
        }
        *state = next;
        self.provisioning_runs
            .lock()
            .map_err(|_| PairingError::Unavailable)?
            .remove(id);
        Ok(())
    }

    pub fn complete_from_durable_activation(
        &self,
        id: &str,
        commit: &ProvisioningCommit,
    ) -> Result<(), PairingError> {
        let mut state = self.state.lock().map_err(|_| PairingError::Unavailable)?;
        let mut next = state.clone();
        let record = next.records.get_mut(id).ok_or(PairingError::NotFound)?;
        let approved_future_boards = record
            .offer
            .pointer("/body/policy/futureBoards")
            .and_then(Value::as_bool);
        let approved_baseline = pairing_baseline(record).ok();
        let provisioning = record.provisioning.as_mut().ok_or(PairingError::Conflict)?;
        if commit.pairing_id != id
            || commit.operation_id != provisioning.operation_id
            || commit.transcript_hash != record.transcript_hash
            || commit.future_boards != approved_future_boards.unwrap_or(false)
            || Some(commit.baseline_workspace_ids.as_slice()) != approved_baseline.as_deref()
            || commit.snapshot_hash.is_empty()
            || commit.workspace_ids
                != provisioning
                    .scopes
                    .iter()
                    .map(|scope| scope.workspace_id.clone())
                    .collect::<Vec<_>>()
        {
            return Err(PairingError::Conflict);
        }
        provisioning.status = "active".into();
        for scope in &mut provisioning.scopes {
            scope.status = "active".into();
            scope.error = None;
            scope.error_detail = None;
        }
        self.persist(&next)?;
        *state = next;
        self.provisioning_runs
            .lock()
            .map_err(|_| PairingError::Unavailable)?
            .remove(id);
        Ok(())
    }

    pub fn reconcile_durable_provisioning(
        &self,
        id: &str,
        operation_id: &str,
        status: &str,
    ) -> Result<(), PairingError> {
        if !matches!(status, "pending_cleanup" | "detached") {
            return Err(PairingError::Invalid("Invalid durable provisioning state"));
        }
        let mut state = self.state.lock().map_err(|_| PairingError::Unavailable)?;
        let mut next = state.clone();
        let provisioning = next
            .records
            .get_mut(id)
            .ok_or(PairingError::NotFound)?
            .provisioning
            .as_mut()
            .ok_or(PairingError::Conflict)?;
        if provisioning.operation_id != operation_id {
            return Err(PairingError::Conflict);
        }
        if provisioning.status == "detached" && status != "detached" {
            return Err(PairingError::Conflict);
        }
        let scope_status = if status == "detached" {
            "removed"
        } else {
            "pending"
        };
        provisioning.status = status.into();
        for scope in &mut provisioning.scopes {
            scope.status = scope_status.into();
            scope.error = None;
            scope.error_detail = None;
        }
        self.persist(&next)?;
        *state = next;
        Ok(())
    }

    pub fn status(
        &self,
        id: &str,
        request: ControllerRequest,
    ) -> Result<SignedEnvelope<Value>, PairingError> {
        let _ = self.verify_controller(&request)?;
        let now = now_seconds();
        let state = self.state.lock().map_err(|_| PairingError::Unavailable)?;
        let record = state.records.get(id).ok_or(PairingError::NotFound)?;
        if record.expires_at <= now && record.withdrawal.is_none() {
            return Err(PairingError::Expired);
        }
        validate_common(
            &request.signed.payload,
            "lighthouse-pairing-status",
            &request,
            &self.service_identity,
            &self.origin,
            now,
        )?;
        if request.identity.person_id != record.controller.person_id
            || request.device_id != record.controller_device_id
        {
            return Err(PairingError::Forbidden);
        }
        if request.signed.payload["kind"] != "lighthouse-pairing-status"
            || request.signed.payload["pairingId"] != id
            || request.signed.payload["transcriptHash"] != record.transcript_hash
        {
            return Err(PairingError::Invalid(
                "Status request does not match pairing",
            ));
        }
        self.sign_status_record(record)
    }

    pub fn signed_provision_status(&self, id: &str) -> Result<SignedEnvelope<Value>, PairingError> {
        let state = self.state.lock().map_err(|_| PairingError::Unavailable)?;
        let record = state.records.get(id).ok_or(PairingError::NotFound)?;
        self.sign_status_record(record)
    }

    pub fn verify_integration_status_request(
        &self,
        request: &ControllerRequest,
    ) -> Result<String, PairingError> {
        self.verify_controller(request)?;
        let now = now_seconds();
        let payload = &request.signed.payload;
        validate_common(
            payload,
            "lighthouse-integration-status-request",
            request,
            &self.service_identity,
            &self.origin,
            now,
        )?;
        if payload["serviceDeviceId"] != self.service_device_id {
            return Err(PairingError::Forbidden);
        }
        Ok(request.identity.person_id.clone())
    }

    pub fn integration_candidates(
        &self,
        controller_person_id: &str,
    ) -> Result<Vec<IntegrationCandidate>, PairingError> {
        let state = self.state.lock().map_err(|_| PairingError::Unavailable)?;
        let mut candidates = state
            .records
            .values()
            .filter_map(|record| {
                let provisioning = record.provisioning.as_ref()?;
                if record.controller.person_id != controller_person_id
                    || provisioning.status != "active"
                {
                    return None;
                }
                let integration_id = record.challenge.payload["integrationId"].as_str()?;
                Some(IntegrationCandidate {
                    integration_id: integration_id.to_owned(),
                    pairing_id: record.id.clone(),
                    controller_person_id: controller_person_id.to_owned(),
                    future_boards: provisioning_future_boards(record),
                })
            })
            .collect::<Vec<_>>();
        candidates.sort_by(|left, right| {
            left.integration_id
                .cmp(&right.integration_id)
                .then_with(|| left.pairing_id.cmp(&right.pairing_id))
        });
        candidates.dedup_by(|left, right| {
            if left.integration_id == right.integration_id {
                // Conflicting historical consent resolves to the restrictive value.
                left.future_boards &= right.future_boards;
                true
            } else {
                false
            }
        });
        Ok(candidates)
    }

    pub fn verify_disconnect_request(
        &self,
        path_integration_id: &str,
        request: &ControllerRequest,
    ) -> Result<VerifiedDisconnectRequest, PairingError> {
        self.verify_controller(request)?;
        let now = now_seconds();
        let payload = &request.signed.payload;
        validate_common(
            payload,
            "lighthouse-integration-disconnect",
            request,
            &self.service_identity,
            &self.origin,
            now,
        )?;
        let integration_id = string_field(payload, "integrationId")?;
        if integration_id != path_integration_id
            || payload["serviceDeviceId"] != self.service_device_id
        {
            return Err(PairingError::Forbidden);
        }
        let scopes = payload["scopes"]
            .as_array()
            .filter(|scopes| !scopes.is_empty() && scopes.len() <= MAX_SCOPES)
            .ok_or(PairingError::Invalid("Invalid disconnect scope list"))?
            .iter()
            .map(|scope| {
                let workspace_id = scope["workspaceId"]
                    .as_str()
                    .filter(|id| !id.is_empty() && id.len() <= 256)
                    .ok_or(PairingError::Invalid("Invalid disconnect scope"))?;
                let epoch = scope["expectedGrantEpoch"]
                    .as_u64()
                    .filter(|epoch| *epoch > 0)
                    .ok_or(PairingError::Invalid("Invalid disconnect grant epoch"))?;
                Ok((workspace_id.to_owned(), epoch))
            })
            .collect::<Result<Vec<_>, PairingError>>()?;
        let mut unique = std::collections::HashSet::new();
        if scopes.iter().any(|(id, _)| !unique.insert(id.as_str())) {
            return Err(PairingError::Invalid("Duplicate disconnect scope"));
        }
        let expected_revision = payload["expectedRevision"]
            .as_u64()
            .ok_or(PairingError::Invalid("Missing integration revision"))?;
        let mut semantic = payload.clone();
        if let Some(object) = semantic.as_object_mut() {
            object.remove("controllerDeviceId");
            object.remove("issuedAt");
            object.remove("expiresAt");
        }
        let canonical = canonicalize_json(&semantic)
            .map_err(|_| PairingError::Invalid("Invalid disconnect request"))?;
        let request_hash = URL_SAFE_NO_PAD.encode(Sha256::digest(canonical.as_bytes()));
        Ok(VerifiedDisconnectRequest {
            integration_id: integration_id.to_owned(),
            operation_id: string_field(payload, "operationId")?.to_owned(),
            controller_person_id: request.identity.person_id.clone(),
            controller_device_id: request.device_id.clone(),
            expected_revision,
            scopes,
            request_hash,
        })
    }

    pub fn sign_integration_status(
        &self,
        controller_person_id: &str,
        controller_device_id: &str,
        operation_id: &str,
        revision: u64,
        integrations: Value,
    ) -> Result<SignedEnvelope<Value>, PairingError> {
        sign_json_envelope(
            &self.service_seed,
            json!({
                "kind":"lighthouse-integration-status", "version":1,
                "servicePersonId":self.service_identity.person_id,
                "serviceDeviceId":self.service_device_id,
                "serviceOrigin":self.origin,
                "controllerPersonId":controller_person_id,
                "controllerDeviceId":controller_device_id,
                "operationId":operation_id,
                "revision":revision,
                "integrations":integrations,
                "issuedAt":now_seconds(),
            }),
            &self.service_device_id,
            CONTROL_DOMAIN,
        )
        .map_err(|_| PairingError::Unavailable)
    }

    pub fn sign_disconnect_receipt(
        &self,
        mut receipt: Value,
    ) -> Result<SignedEnvelope<Value>, PairingError> {
        receipt["servicePersonId"] = json!(self.service_identity.person_id);
        receipt["serviceDeviceId"] = json!(self.service_device_id);
        receipt["serviceOrigin"] = json!(self.origin);
        receipt["issuedAt"] = json!(now_seconds());
        sign_json_envelope(
            &self.service_seed,
            receipt,
            &self.service_device_id,
            CONTROL_DOMAIN,
        )
        .map_err(|_| PairingError::Unavailable)
    }

    fn sign_status_record(
        &self,
        record: &PairingRecord,
    ) -> Result<SignedEnvelope<Value>, PairingError> {
        let now = now_seconds();
        let approval_status = if record.controller_approved == Some(false)
            || record.operator_approved == Some(false)
        {
            "rejected"
        } else if record.controller_approved == Some(true) && record.operator_approved == Some(true)
        {
            "approved"
        } else {
            "pending"
        };
        let status = record
            .withdrawal
            .as_ref()
            .map(|withdrawal| withdrawal.status.as_str())
            .or_else(|| {
                record
                    .provisioning
                    .as_ref()
                    .map(|provisioning| provisioning.status.as_str())
            })
            .unwrap_or(approval_status);
        let provisioning = record
            .provisioning
            .as_ref()
            .map(serde_json::to_value)
            .transpose()
            .map_err(|_| PairingError::Unavailable)?
            .unwrap_or(Value::Bool(false));
        sign_json_envelope(&self.service_seed, json!({
            "kind":"lighthouse-pairing-status", "version":1, "pairingId":record.id,
            "integrationId":record.challenge.payload["integrationId"],
            "transcriptHash":record.transcript_hash, "servicePersonId":self.service_identity.person_id,
            "serviceDeviceId":self.service_device_id, "serviceOrigin":self.origin,
            "expiresAt":record.expires_at, "operatorApproved":record.operator_approved,
            "controllerApproved":record.controller_approved, "status":status,
            "provisioning":provisioning, "withdrawal":record.withdrawal,
            "issuedAt":now,
        }), &self.service_device_id, CONTROL_DOMAIN).map_err(|_| PairingError::Unavailable)
    }

    pub fn authorize_reset(
        &self,
        cookie: &str,
        csrf: &str,
        secret: &str,
    ) -> Result<(), PairingError> {
        self.require_operator(cookie, Some(csrf))?;
        if !constant_time_eq(secret.as_bytes(), self.admin_secret.as_bytes()) {
            return Err(PairingError::Forbidden);
        }
        Ok(())
    }

    pub fn login(&self, secret: &str) -> Result<(String, String), PairingError> {
        if !constant_time_eq(secret.as_bytes(), self.admin_secret.as_bytes()) {
            return Err(PairingError::Forbidden);
        }
        let cookie = random_token(32);
        let csrf = random_token(32);
        let mut state = self.state.lock().map_err(|_| PairingError::Unavailable)?;
        state.sessions.insert(
            cookie.clone(),
            AdminSession {
                csrf: csrf.clone(),
                expires_at: now_seconds() + 8 * 60 * 60,
                person_id: None,
                display_name: "Operator".into(),
                operator: true,
            },
        );
        Ok((cookie, csrf))
    }

    pub fn begin_login(
        &self,
        match_origin: &str,
    ) -> Result<(String, LoginChallengeResponse), PairingError> {
        let now = now_seconds();
        let challenge_id = random_token(24);
        let nonce = random_token(32);
        let intent_cookie = random_token(32);
        let expires_at = now + LOGIN_TTL_SECONDS;
        let mut url = reqwest::Url::parse(match_origin)
            .map_err(|_| PairingError::Invalid("Invalid Tincanban origin"))?;
        if url.origin().ascii_serialization() != match_origin
            || !matches!(url.scheme(), "https" | "http")
        {
            return Err(PairingError::Invalid("Invalid Tincanban origin"));
        }
        url.set_path("/login");
        url.set_query(None);
        url.set_fragment(None);
        url.query_pairs_mut()
            .append_pair("keeper", &self.origin)
            .append_pair("challenge", &challenge_id);
        let mut state = self.state.lock().map_err(|_| PairingError::Unavailable)?;
        prune_login_state(&mut state, now);
        if state.login_challenges.len() + state.login_codes.len() >= MAX_PENDING_LOGINS {
            return Err(PairingError::Unavailable);
        }
        state.login_challenges.insert(
            challenge_id.clone(),
            LoginChallenge {
                nonce,
                intent_cookie: intent_cookie.clone(),
                expires_at,
            },
        );
        Ok((
            intent_cookie,
            LoginChallengeResponse {
                challenge_id,
                match_url: url.to_string(),
                expires_at,
            },
        ))
    }

    pub fn login_challenge(&self, id: &str) -> Result<SignedEnvelope<Value>, PairingError> {
        let mut state = self.state.lock().map_err(|_| PairingError::Unavailable)?;
        prune_login_state(&mut state, now_seconds());
        let challenge = state
            .login_challenges
            .get(id)
            .ok_or(PairingError::NotFound)?;
        let now = now_seconds();
        let expires_at = challenge.expires_at;
        let nonce = challenge.nonce.clone();
        sign_json_envelope(
            &self.service_seed,
            json!({
                "kind":"lighthouse-login-challenge", "version":1,
                "challengeId":id, "nonce":nonce,
                "servicePersonId":self.service_identity.person_id,
                "serviceDeviceId":self.service_device_id, "serviceOrigin":self.origin,
                "issuedAt":now, "expiresAt":expires_at,
            }),
            &self.service_device_id,
            CONTROL_DOMAIN,
        )
        .map_err(|_| PairingError::Unavailable)
    }

    pub fn prove_login(
        &self,
        request: ControllerRequest,
        id: &str,
    ) -> Result<LoginProofResponse, PairingError> {
        let now = now_seconds();
        self.verify_controller(&request)?;
        let payload = &request.signed.payload;
        if payload["kind"] != "lighthouse-login-proof"
            || payload["version"] != 1
            || payload["protocolVersion"] != 1
            || payload["challengeId"] != id
            || payload["servicePersonId"] != self.service_identity.person_id
            || payload["serviceOrigin"] != self.origin
            || payload["controllerPersonId"] != request.identity.person_id
            || payload["controllerDeviceId"] != request.device_id
        {
            return Err(PairingError::Invalid(
                "Signed login proof identity or challenge mismatch",
            ));
        }
        let issued = payload["issuedAt"]
            .as_u64()
            .ok_or(PairingError::Invalid("Missing issuedAt"))?;
        let expires = payload["expiresAt"]
            .as_u64()
            .ok_or(PairingError::Invalid("Missing expiresAt"))?;
        let operation = string_field(payload, "operationId")?;
        if issued > now + 30
            || now.saturating_sub(issued) > LOGIN_TTL_SECONDS
            || expires <= now
            || expires > issued + LOGIN_TTL_SECONDS
            || operation.len() > 128
            || URL_SAFE_NO_PAD
                .decode(operation)
                .map_or(true, |bytes| bytes.len() < 16)
        {
            return Err(PairingError::Expired);
        }
        let mut state = self.state.lock().map_err(|_| PairingError::Unavailable)?;
        prune_login_state(&mut state, now);
        let challenge = state
            .login_challenges
            .get(id)
            .ok_or(PairingError::NotFound)?;
        if challenge.expires_at <= now
            || expires > challenge.expires_at
            || payload["challengeNonce"] != challenge.nonce
        {
            return Err(PairingError::Expired);
        }
        let intent_cookie = challenge.intent_cookie.clone();
        state.login_challenges.remove(id);
        let code = random_token(32);
        state.login_codes.insert(
            code.clone(),
            LoginCode {
                person_id: request.identity.person_id,
                display_name: request.identity.display_name,
                intent_cookie,
                expires_at: now + LOGIN_TTL_SECONDS,
            },
        );
        Ok(LoginProofResponse {
            code: code.clone(),
            redirect_url: format!("{}/admin/#login={code}", self.origin),
        })
    }

    pub fn exchange_login(
        &self,
        code: &str,
        intent_cookie: &str,
    ) -> Result<(String, SessionResponse), PairingError> {
        let now = now_seconds();
        let mut state = self.state.lock().map_err(|_| PairingError::Unavailable)?;
        prune_login_state(&mut state, now);
        let login = state.login_codes.get(code).ok_or(PairingError::Forbidden)?;
        if login.expires_at <= now
            || !constant_time_eq(login.intent_cookie.as_bytes(), intent_cookie.as_bytes())
        {
            return Err(PairingError::Forbidden);
        }
        let login = state
            .login_codes
            .remove(code)
            .ok_or(PairingError::Forbidden)?;
        let cookie = random_token(32);
        let csrf = random_token(32);
        let session = SessionResponse {
            csrf_token: csrf.clone(),
            person_id: Some(login.person_id.clone()),
            display_name: login.display_name.clone(),
            operator: false,
        };
        state.sessions.insert(
            cookie.clone(),
            AdminSession {
                csrf,
                expires_at: now + 8 * 60 * 60,
                person_id: Some(login.person_id),
                display_name: login.display_name,
                operator: false,
            },
        );
        Ok((cookie, session))
    }

    pub fn service_fingerprint(&self) -> String {
        public_key_fingerprint(&self.service_identity.public_key)
    }

    pub fn admin_session(&self, cookie: &str) -> Result<SessionResponse, PairingError> {
        let mut state = self.state.lock().map_err(|_| PairingError::Unavailable)?;
        self.require_session(&mut state, cookie, None)?;
        let session = state.sessions.get(cookie).ok_or(PairingError::Forbidden)?;
        Ok(SessionResponse {
            csrf_token: session.csrf.clone(),
            person_id: session.person_id.clone(),
            display_name: session.display_name.clone(),
            operator: session.operator,
        })
    }

    pub fn session_person_id(&self, cookie: &str) -> Result<Option<String>, PairingError> {
        let mut state = self.state.lock().map_err(|_| PairingError::Unavailable)?;
        self.require_session(&mut state, cookie, None)?;
        Ok(state
            .sessions
            .get(cookie)
            .and_then(|session| session.person_id.clone()))
    }

    pub fn logout(&self, cookie: &str, csrf: &str) -> Result<(), PairingError> {
        let mut state = self.state.lock().map_err(|_| PairingError::Unavailable)?;
        self.require_session(&mut state, cookie, Some(csrf))?;
        state.sessions.remove(cookie);
        Ok(())
    }

    pub fn require_operator(&self, cookie: &str, csrf: Option<&str>) -> Result<(), PairingError> {
        let mut state = self.state.lock().map_err(|_| PairingError::Unavailable)?;
        self.require_session(&mut state, cookie, csrf)?;
        if !state
            .sessions
            .get(cookie)
            .is_some_and(|session| session.operator)
        {
            return Err(PairingError::Forbidden);
        }
        Ok(())
    }

    pub fn mutation_owner(&self, cookie: &str, csrf: &str) -> Result<Option<String>, PairingError> {
        let mut state = self.state.lock().map_err(|_| PairingError::Unavailable)?;
        self.require_session(&mut state, cookie, Some(csrf))?;
        let session = state.sessions.get(cookie).ok_or(PairingError::Forbidden)?;
        if session.operator {
            return Ok(None);
        }
        session
            .person_id
            .clone()
            .map(Some)
            .ok_or(PairingError::Forbidden)
    }

    pub fn fingerprint(public_key: &str) -> String {
        public_key_fingerprint(public_key)
    }

    pub fn admin_list(&self, cookie: &str) -> Result<Vec<PairingRecord>, PairingError> {
        let mut state = self.state.lock().map_err(|_| PairingError::Unavailable)?;
        self.require_session(&mut state, cookie, None)?;
        let owner = state
            .sessions
            .get(cookie)
            .and_then(|session| session.person_id.as_deref());
        Ok(state
            .records
            .values()
            .filter(|record| {
                owner.is_none_or(|person_id| record.controller.person_id == person_id)
                    && (record.expires_at > now_seconds()
                        || record
                            .withdrawal
                            .as_ref()
                            .is_some_and(|withdrawal| withdrawal.status == "cancel_pending")
                        || record
                            .provisioning
                            .as_ref()
                            .is_some_and(|provisioning| provisioning.status == "active"))
            })
            .cloned()
            .collect())
    }

    pub fn admin_decision(
        &self,
        id: &str,
        cookie: &str,
        csrf: &str,
        decision: bool,
    ) -> Result<PairingRecord, PairingError> {
        let mut state = self.state.lock().map_err(|_| PairingError::Unavailable)?;
        self.require_session(&mut state, cookie, Some(csrf))?;
        if !state
            .sessions
            .get(cookie)
            .is_some_and(|session| session.operator)
        {
            return Err(PairingError::Forbidden);
        }
        let record = state.records.get(id).ok_or(PairingError::NotFound)?;
        if record.expires_at <= now_seconds() {
            return Err(PairingError::Expired);
        }
        if record.controller_approved == Some(false) {
            return Err(PairingError::Conflict);
        }
        if record
            .operator_approved
            .is_some_and(|previous| previous != decision)
        {
            return Err(PairingError::Conflict);
        }
        let mut next = state.clone();
        let record = next.records.get_mut(id).ok_or(PairingError::NotFound)?;
        record.operator_approved = Some(decision);
        if !decision {
            record.controller_approved = Some(false);
        }
        let result = record.clone();
        self.persist(&next)?;
        *state = next;
        Ok(result)
    }

    pub fn status_json(&self, id: &str) -> Result<Value, PairingError> {
        let state = self.state.lock().map_err(|_| PairingError::Unavailable)?;
        let record = state.records.get(id).ok_or(PairingError::NotFound)?;
        let approval_status = if record.expires_at <= now_seconds() {
            "expired"
        } else if record.controller_approved == Some(false)
            || record.operator_approved == Some(false)
        {
            "rejected"
        } else if record.controller_approved == Some(true) && record.operator_approved == Some(true)
        {
            "approved"
        } else {
            "pending"
        };
        let status = record
            .withdrawal
            .as_ref()
            .map(|withdrawal| withdrawal.status.as_str())
            .or_else(|| {
                record
                    .provisioning
                    .as_ref()
                    .map(|provisioning| provisioning.status.as_str())
            })
            .unwrap_or(approval_status);
        Ok(
            json!({ "id":record.id, "status":status, "expiresAt":record.expires_at, "controllerApproved":record.controller_approved, "operatorApproved":record.operator_approved, "provisioning":record.provisioning, "withdrawal":record.withdrawal }),
        )
    }

    fn verify_controller(&self, request: &ControllerRequest) -> Result<String, PairingError> {
        if request.certificates.len() > 32 {
            return Err(PairingError::Invalid("Invalid certificate chain"));
        }
        let key = verify_device_certificate_chain(
            &request.identity,
            &request.device_id,
            &request.certificates,
            "MATCH/1",
        )
        .map_err(|_| PairingError::Forbidden)?;
        if request.signed.signer_key_id != request.device_id
            || !verify_signed_envelope(&request.signed, &key, CONTROL_DOMAIN)
                .map_err(|_| PairingError::Forbidden)?
        {
            return Err(PairingError::Forbidden);
        }
        Ok(key)
    }

    fn require_session(
        &self,
        state: &mut PairingState,
        cookie: &str,
        csrf: Option<&str>,
    ) -> Result<(), PairingError> {
        let now = now_seconds();
        state.sessions.retain(|_, session| session.expires_at > now);
        let session = state.sessions.get(cookie).ok_or(PairingError::Forbidden)?;
        if let Some(csrf) = csrf {
            if !constant_time_eq(csrf.as_bytes(), session.csrf.as_bytes()) {
                return Err(PairingError::Forbidden);
            }
        }
        Ok(())
    }

    fn persist(&self, state: &PairingState) -> Result<(), PairingError> {
        let bytes = serde_json::to_vec(state).map_err(|_| PairingError::Unavailable)?;
        FileScopeStore::new(self.directory.join("pairings.json"))
            .write_validated(&bytes, None, |_, _| Ok(()))
            .map_err(|_| PairingError::Unavailable)
    }
}

fn validate_common(
    payload: &Value,
    kind: &str,
    request: &ControllerRequest,
    service: &PublicIdentity,
    origin: &str,
    now: u64,
) -> Result<(), PairingError> {
    if payload["kind"] != kind
        || payload["version"] != 1
        || payload["protocolVersion"] != 1
        || payload["servicePersonId"] != service.person_id
        || payload["serviceOrigin"] != origin
        || payload["controllerPersonId"] != request.identity.person_id
        || payload["controllerDeviceId"] != request.device_id
    {
        return Err(PairingError::Invalid(
            "Signed request identity or origin mismatch",
        ));
    }
    let issued = payload["issuedAt"]
        .as_u64()
        .ok_or(PairingError::Invalid("Missing issuedAt"))?;
    let expires = payload["expiresAt"]
        .as_u64()
        .ok_or(PairingError::Invalid("Missing expiresAt"))?;
    if issued > now + 30
        || now.saturating_sub(issued) > MAX_AGE_SECONDS
        || expires <= now
        || expires > issued + MAX_AGE_SECONDS
    {
        return Err(PairingError::Expired);
    }
    let operation = string_field(payload, "operationId")?;
    if operation.len() > 128
        || URL_SAFE_NO_PAD
            .decode(operation)
            .map_or(true, |bytes| bytes.len() < 16)
    {
        return Err(PairingError::Invalid(
            "operationId must contain at least 128 bits of randomness",
        ));
    }
    Ok(())
}

fn string_field<'a>(payload: &'a Value, field: &str) -> Result<&'a str, PairingError> {
    payload[field]
        .as_str()
        .filter(|value| !value.is_empty())
        .ok_or(PairingError::Invalid("Missing required field"))
}

fn comparison_code(offer: &Value, challenge: &Value) -> String {
    let transcript = canonicalize_json(
        &json!({"domain":"MESH-LIGHTHOUSE-COMPARISON/1", "offer":offer, "challenge":challenge}),
    )
    .unwrap_or_default();
    let bytes = Sha256::digest(transcript.as_bytes());
    let value = u32::from_be_bytes(bytes[..4].try_into().unwrap_or([0; 4])) % 1_000_000;
    format!("{value:06}")
}

fn public_key_fingerprint(public_key: &str) -> String {
    Sha256::digest(public_key.as_bytes())[..12]
        .chunks(2)
        .map(|bytes| format!("{:02x}{:02x}", bytes[0], bytes[1]))
        .collect::<Vec<_>>()
        .join(":")
}

fn now_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
fn prune_login_state(state: &mut PairingState, now: u64) {
    state
        .login_challenges
        .retain(|_, challenge| challenge.expires_at > now);
    state.login_codes.retain(|_, code| code.expires_at > now);
    state.sessions.retain(|_, session| session.expires_at > now);
}
fn random_token(length: usize) -> String {
    let mut bytes = vec![0; length];
    rand::rng().fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b).fold(0_u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

#[derive(Debug, Clone, Copy)]
pub enum PairingError {
    Invalid(&'static str),
    Forbidden,
    NotFound,
    Expired,
    Conflict,
    Unavailable,
}

impl PairingError {
    pub fn code(self) -> &'static str {
        match self {
            Self::Invalid(_) => "invalid_request",
            Self::Forbidden => "forbidden",
            Self::NotFound => "not_found",
            Self::Expired => "expired",
            Self::Conflict => "operation_conflict",
            Self::Unavailable => "unavailable",
        }
    }
    pub fn message(self) -> &'static str {
        match self {
            Self::Invalid(message) => message,
            Self::Forbidden => "Approval is not authorized",
            Self::NotFound => "Pairing was not found",
            Self::Expired => "Pairing has expired",
            Self::Conflict => "Pairing state or operation conflicts with a prior request",
            Self::Unavailable => "Pairing service is temporarily unavailable",
        }
    }
    pub fn status(self) -> axum::http::StatusCode {
        match self {
            Self::Invalid(_) => axum::http::StatusCode::BAD_REQUEST,
            Self::Forbidden => axum::http::StatusCode::FORBIDDEN,
            Self::NotFound => axum::http::StatusCode::NOT_FOUND,
            Self::Expired => axum::http::StatusCode::GONE,
            Self::Conflict => axum::http::StatusCode::CONFLICT,
            Self::Unavailable => axum::http::StatusCode::SERVICE_UNAVAILABLE,
        }
    }
}
