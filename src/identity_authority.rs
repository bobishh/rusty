//! Rusty-side verification of the portable Identity authority view.
//!
//! The view carries only public identity keys, device certificates, and signed
//! revocations. Identity itself remains responsible for validating encrypted
//! profile operation history before producing the view.
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use meta_mesh_core::{
    DeviceCertificate, PublicIdentity, ScopeAuthority, ScopeAuthoritySnapshot,
    ScopeSuccessionTransfer, SignedEnvelope, ValidatedScopeAuthority, WorkspaceGrant,
    WorkspaceRole, canonicalize_json, certificate_hash, merge_scope_authority_snapshots_at,
    public_key_id, validate_scope_authority_at, verify_device_certificate_chain,
    verify_signed_envelope, verify_workspace_grant,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashMap, HashSet};

pub(super) const SIGNATURE_DOMAIN: &str = "MATCH/1";
const MAX_CERTIFICATES: usize = 512;
const MAX_REVOCATIONS: usize = 256;
const MAX_CUTOFF_HASHES: usize = 512;
const MAX_DEVICE_ID: usize = 128;
pub(super) const MAX_RECENT_AUTHORITY_UPDATES: usize = 256;
pub(super) const AUTHORITY_REQUEST_TTL_MS: u64 = 120_000;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct RevocationHead {
    pub revision: u64,
    pub record_hash: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct EnforcementState {
    pub mode: String,
    pub epoch: u8,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct EnforcementMarkerPayload {
    pub kind: String,
    pub version: u8,
    pub service_id: String,
    pub mode: String,
    pub epoch: u8,
    pub enabled_at: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct IdentityAuthorityView {
    pub kind: String,
    pub version: u8,
    pub person_id: String,
    pub identity_public_key: String,
    pub certificates: Vec<DeviceCertificate>,
    pub revocations: Vec<SignedEnvelope<Value>>,
    pub revocation_head: RevocationHead,
    pub view_digest: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct AuthorityUpdateAuthorization {
    pub kind: String,
    pub version: u8,
    pub service_id: String,
    pub origin: String,
    pub person_id: String,
    pub device_id: String,
    pub authority_head: RevocationHead,
    pub view_digest: String,
    pub nonce: String,
    pub issued_at: u64,
    pub request_hash: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct AuthorityUpdateRequest {
    pub version: u8,
    pub view: IdentityAuthorityView,
    pub authorization: SignedEnvelope<AuthorityUpdateAuthorization>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct AuthorityStatusPayload {
    pub kind: String,
    pub version: u8,
    pub service_id: String,
    pub origin: String,
    pub person_id: String,
    pub state: String,
    pub request_nonce: String,
    pub request_hash: String,
    pub issued_at: u64,
    pub enforcement: EnforcementState,
    pub view: Option<IdentityAuthorityView>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct AuthorityReceiptPayload {
    pub kind: String,
    pub version: u8,
    pub service_id: String,
    pub origin: String,
    pub person_id: String,
    pub authority_head: RevocationHead,
    pub view_digest: String,
    pub request_hash: String,
    pub committed_at: u64,
    pub enforcement: EnforcementState,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct RecentAuthorityUpdate {
    pub nonce: String,
    pub request_hash: String,
    pub issued_at: u64,
    pub receipt: SignedEnvelope<Value>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct StoredIdentityAuthority {
    pub view: IdentityAuthorityView,
    pub recent_updates: Vec<RecentAuthorityUpdate>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct IdentityRootSuccessionAuthorization {
    pub kind: String,
    pub version: u8,
    pub succession_id: String,
    pub previous_person_id: String,
    pub previous_identity_public_key: String,
    pub successor_person_id: String,
    pub successor_identity_public_key: String,
    pub authority_head: RevocationHead,
    pub authority_view_digest: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct IdentityRootSuccessionAcceptance {
    pub kind: String,
    pub version: u8,
    pub succession_hash: String,
    pub previous_person_id: String,
    pub successor_person_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct IdentityRootSuccession {
    pub authorization: SignedEnvelope<IdentityRootSuccessionAuthorization>,
    pub acceptance: SignedEnvelope<IdentityRootSuccessionAcceptance>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct IdentityRootSuccessionRequest {
    pub version: u8,
    pub succession: IdentityRootSuccession,
    pub actor_device_id: String,
    pub actor_authorization: SignedEnvelope<IdentityRootSuccessionRequestAuthorization>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct IdentityRootSuccessionRequestAuthorization {
    pub kind: String,
    pub version: u8,
    pub service_id: String,
    pub origin: String,
    pub previous_person_id: String,
    pub successor_person_id: String,
    pub transition_hash: String,
    pub actor_device_id: String,
    pub request_id: String,
    pub issued_at: u64,
    pub expires_at: u64,
    pub request_hash: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct IdentityRootSuccessionStatusPayload {
    pub kind: String,
    pub version: u8,
    pub service_id: String,
    pub origin: String,
    pub previous_person_id: String,
    pub transition_hash: String,
    pub state: String,
    pub request_id: String,
    pub request_hash: String,
    pub issued_at: u64,
    pub successor_person_id: Option<String>,
    pub actor_device_id: Option<String>,
    pub retired: bool,
    pub enforcement: EnforcementState,
    pub transferred: Vec<IdentityRootSuccessionTargetReceipt>,
    #[serde(default)]
    pub receipt: Option<SignedEnvelope<Value>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct IdentityRootSuccessionTargetReceipt {
    pub kind: String,
    pub resource_id: String,
    pub evidence_hash: String,
    pub epoch: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct StoredIdentityRootSuccession {
    pub version: u8,
    pub request: IdentityRootSuccessionRequest,
    pub transition_hash: String,
    pub state: String,
    pub targets: Vec<IdentityRootSuccessionTargetReceipt>,
    pub retired: bool,
    pub committed_at: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub receipt: Option<SignedEnvelope<Value>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct IdentityRootSuccessionReceiptPayload {
    pub kind: String,
    pub version: u8,
    pub service_id: String,
    pub origin: String,
    pub previous_person_id: String,
    pub successor_person_id: String,
    pub transition_hash: String,
    pub actor_device_id: String,
    pub request_id: String,
    pub request_hash: String,
    pub committed_at: u64,
    pub retired: bool,
    pub transferred: Vec<IdentityRootSuccessionTargetReceipt>,
    pub enforcement: EnforcementState,
}

#[derive(Debug, Clone)]
pub(super) struct VerifiedIdentityRootSuccession {
    pub previous_person_id: String,
    pub previous_identity_public_key: String,
    pub successor_person_id: String,
    pub successor_identity_public_key: String,
    pub authority_head: RevocationHead,
    pub authority_view_digest: String,
    /// Hash used inside the successor acceptance; commits only to old-root authorization.
    pub authorization_hash: String,
    /// Idempotency key for the complete two-root transition request.
    pub transition_hash: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct IdentityRequestProof {
    pub kind: String,
    pub version: u8,
    pub service_id: String,
    pub origin: String,
    pub person_id: String,
    pub device_id: String,
    pub authority_head: RevocationHead,
    pub view_digest: String,
    pub resource_kind: String,
    pub resource_id: String,
    pub scope_id: String,
    pub action: String,
    pub grant_id: Option<String>,
    pub policy_epoch: u64,
    pub token_hash: String,
    pub method: String,
    pub path: String,
    pub body_hash: String,
    pub nonce: String,
    pub issued_at: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct ResourcePrincipalGrant {
    pub kind: String,
    pub version: u8,
    pub service_id: String,
    pub origin: String,
    pub workspace_id: String,
    pub resource_kind: String,
    pub resource_id: String,
    pub scope_id: String,
    pub owner_person_id: String,
    pub subject_person_id: String,
    pub subject_public_key: String,
    pub grant_id: String,
    pub policy_epoch: u64,
    pub read_token_hash: String,
    pub write_token_hash: String,
    pub actions: Vec<String>,
    pub workspace_grant: WorkspaceGrant,
    pub scope_authority: ScopeAuthoritySnapshot,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct ResourcePrincipalGrantRequest {
    pub version: u8,
    pub grant: SignedEnvelope<ResourcePrincipalGrant>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct StoredResourcePrincipalGrant {
    pub grant: SignedEnvelope<ResourcePrincipalGrant>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct ScopeAuthorityUpdateAuthorization {
    pub kind: String,
    pub version: u8,
    pub service_id: String,
    pub origin: String,
    pub scope_id: String,
    pub workspace_id: String,
    pub person_id: String,
    pub device_id: String,
    pub control_epoch: u64,
    pub request_id: String,
    pub issued_at: u64,
    pub expires_at: u64,
    pub request_hash: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct ScopeAuthorityUpdateRequest {
    pub version: u8,
    pub scope_authority: ScopeAuthoritySnapshot,
    pub authorization: SignedEnvelope<Value>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct ScopeAuthorityReceiptPayload {
    pub kind: String,
    pub version: u8,
    pub service_id: String,
    pub origin: String,
    pub scope_id: String,
    pub workspace_id: String,
    pub controller_person_id: String,
    pub control_epoch: u64,
    pub request_id: String,
    pub request_hash: String,
    pub merged_snapshot_hash: String,
    pub committed_at: u64,
    pub enforcement: EnforcementState,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct ScopeAuthorityStatusPayload {
    pub kind: String,
    pub version: u8,
    pub service_id: String,
    pub origin: String,
    pub scope_id: String,
    pub workspace_id: Option<String>,
    pub state: String,
    pub controller_person_id: Option<String>,
    pub control_epoch: Option<u64>,
    pub request_id: String,
    pub request_hash: String,
    pub issued_at: u64,
    pub enforcement: EnforcementState,
    pub scope_authority: Option<ScopeAuthoritySnapshot>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct RecentScopeAuthorityUpdate {
    pub request_id: String,
    pub request_hash: String,
    pub issued_at: u64,
    pub receipt: SignedEnvelope<Value>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct StoredScopeAuthority {
    pub snapshot: ScopeAuthoritySnapshot,
    pub recent_updates: Vec<RecentScopeAuthorityUpdate>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct ScopePurposeUpdateAuthorization {
    pub kind: String,
    pub version: u8,
    pub service_id: String,
    pub origin: String,
    pub scope_id: String,
    pub scope_purpose: String,
    pub person_id: String,
    pub device_id: String,
    pub policy_revision: u64,
    pub request_id: String,
    pub issued_at: u64,
    pub expires_at: u64,
    pub request_hash: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct ScopePurposeUpdateRequest {
    pub version: u8,
    pub scope_purpose: String,
    pub authorization: SignedEnvelope<Value>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct ScopePurposeReceiptPayload {
    pub kind: String,
    pub version: u8,
    pub service_id: String,
    pub origin: String,
    pub scope_id: String,
    pub scope_purpose: String,
    pub person_id: String,
    pub policy_revision: u64,
    pub request_id: String,
    pub request_hash: String,
    pub committed_at: u64,
    pub enforcement: EnforcementState,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RevocationPayload {
    kind: String,
    version: u8,
    person_id: String,
    device_id: String,
    revision: u64,
    profile_operation_hashes: BTreeMap<String, Vec<String>>,
}

#[derive(Debug, Clone)]
pub(super) struct VerifiedIdentityAuthorityView {
    pub view: IdentityAuthorityView,
    pub revoked_roots: HashSet<String>,
    pub(super) certificates_by_device: HashMap<String, DeviceCertificate>,
}

impl VerifiedIdentityAuthorityView {
    pub fn is_active_device(&self, device_id: &str) -> Result<bool, String> {
        if device_id.is_empty() || device_id.len() > MAX_DEVICE_ID {
            return Err("Invalid identity device".into());
        }
        let chain = certificate_chain(
            &self.view.identity(),
            device_id,
            &self.certificates_by_device,
        )?;
        Ok(!chain
            .iter()
            .any(|certificate| self.revoked_roots.contains(&certificate.payload.device_id)))
    }

    pub fn is_active_manager(&self, device_id: &str) -> Result<bool, String> {
        let Some(certificate) = self.certificates_by_device.get(device_id) else {
            return Ok(false);
        };
        Ok(certificate.payload.can_enroll_devices && self.is_active_device(device_id)?)
    }

    pub fn has_exact_certificate_chain(
        &self,
        device_id: &str,
        presented: &[DeviceCertificate],
    ) -> Result<bool, String> {
        Ok(certificate_chain(
            &self.view.identity(),
            device_id,
            &self.certificates_by_device,
        )? == presented)
    }
}

impl IdentityAuthorityView {
    pub(super) fn identity(&self) -> PublicIdentity {
        PublicIdentity {
            person_id: self.person_id.clone(),
            public_key: self.identity_public_key.clone(),
            display_name: String::new(),
        }
    }

    pub fn verify(&self) -> Result<VerifiedIdentityAuthorityView, String> {
        if self.kind != "mesh-identity-authority-view"
            || self.version != 1
            || self.certificates.is_empty()
            || self.certificates.len() > MAX_CERTIFICATES
            || self.revocations.len() > MAX_REVOCATIONS
            || public_key_id(&self.identity_public_key)? != self.person_id
            || !valid_digest(&self.view_digest)
            || !valid_digest(&self.revocation_head.record_hash)
        {
            return Err("Invalid Identity authority view".into());
        }

        let identity = self.identity();
        let mut certificates_by_device = HashMap::with_capacity(self.certificates.len());
        let mut previous_device_id: Option<&str> = None;
        for certificate in &self.certificates {
            let device_id = certificate.payload.device_id.as_str();
            if device_id.is_empty()
                || device_id.len() > MAX_DEVICE_ID
                || certificate.payload.person_id != self.person_id
                || previous_device_id.is_some_and(|previous| previous >= device_id)
                || certificates_by_device
                    .insert(device_id.to_owned(), certificate.clone())
                    .is_some()
            {
                return Err("Invalid Identity certificate catalog".into());
            }
            previous_device_id = Some(device_id);
        }

        for device_id in certificates_by_device.keys() {
            certificate_chain(&identity, device_id, &certificates_by_device)?;
        }

        let mut revoked_roots = HashSet::new();
        let mut covered_subtrees = HashSet::new();
        let mut expected_head = genesis_head(&self.person_id, &self.identity_public_key)?;
        let mut cutoff_hash_count = 0usize;
        for (index, signed) in self.revocations.iter().enumerate() {
            let payload: RevocationPayload = serde_json::from_value(signed.payload.clone())
                .map_err(|_| "Invalid Identity revocation".to_string())?;
            let expected_revision = (index as u64)
                .checked_add(1)
                .ok_or("Identity revocation revision exhausted")?;
            if payload.kind != "mesh-identity-device-revocation"
                || payload.version != 1
                || payload.person_id != self.person_id
                || payload.revision != expected_revision
                || payload.device_id.is_empty()
                || signed.signer_key_id == payload.device_id
                || !is_active_in_catalog(
                    &identity,
                    &payload.device_id,
                    &revoked_roots,
                    &certificates_by_device,
                )?
                || !is_active_in_catalog(
                    &identity,
                    &signed.signer_key_id,
                    &revoked_roots,
                    &certificates_by_device,
                )?
            {
                return Err("Invalid Identity revocation sequence".into());
            }

            let signer = certificates_by_device
                .get(&signed.signer_key_id)
                .ok_or("Identity revocation signer is unknown")?;
            if !signer.payload.can_enroll_devices {
                return Err("Identity revocation signer lacks management authority".into());
            }
            let signer_key = verify_device_certificate_chain(
                &identity,
                &signed.signer_key_id,
                &certificate_chain(&identity, &signed.signer_key_id, &certificates_by_device)?,
                SIGNATURE_DOMAIN,
            )?;
            if !verify_signed_envelope(signed, &signer_key, SIGNATURE_DOMAIN)? {
                return Err("Invalid Identity revocation signature".into());
            }

            for (device_id, hashes) in &payload.profile_operation_hashes {
                let Some(_) = certificates_by_device.get(device_id) else {
                    return Err("Identity revocation references an unknown device".into());
                };
                if !is_descendant_or_same(
                    &identity,
                    device_id,
                    &payload.device_id,
                    &certificates_by_device,
                )? {
                    return Err("Identity revocation cutoff escapes its device subtree".into());
                }
                for hash in hashes {
                    if !valid_digest(hash) {
                        return Err("Invalid Identity profile operation hash".into());
                    }
                }
                cutoff_hash_count = cutoff_hash_count
                    .checked_add(hashes.len())
                    .ok_or("Identity cutoff history is too large")?;
                if cutoff_hash_count > MAX_CUTOFF_HASHES {
                    return Err("Identity cutoff history is too large".into());
                }
            }
            let mut covered_devices = HashSet::new();
            for device_id in certificates_by_device.keys() {
                if is_descendant_or_same(
                    &identity,
                    device_id,
                    &payload.device_id,
                    &certificates_by_device,
                )? {
                    covered_devices.insert(device_id.clone());
                }
            }
            if covered_devices
                .iter()
                .any(|device_id| covered_subtrees.contains(device_id))
            {
                return Err("Identity revocation subtrees overlap".into());
            }
            if revoked_roots.contains(&payload.device_id) {
                return Err("Identity device was already revoked".into());
            }
            revoked_roots.insert(payload.device_id);
            covered_subtrees.extend(covered_devices);
            let mut has_active_manager = false;
            for certificate in certificates_by_device.values() {
                if certificate.payload.can_enroll_devices
                    && is_active_in_catalog(
                        &identity,
                        &certificate.payload.device_id,
                        &revoked_roots,
                        &certificates_by_device,
                    )?
                {
                    has_active_manager = true;
                    break;
                }
            }
            if !has_active_manager {
                return Err("Identity revocation removes the last management authority".into());
            }
            expected_head = RevocationHead {
                revision: expected_revision,
                record_hash: canonical_hash(signed)?,
            };
        }

        if expected_head != self.revocation_head || self.compute_view_digest()? != self.view_digest
        {
            return Err("Identity authority view digest or head mismatch".into());
        }

        Ok(VerifiedIdentityAuthorityView {
            view: self.clone(),
            revoked_roots,
            certificates_by_device,
        })
    }

    fn compute_view_digest(&self) -> Result<String, String> {
        let value = json!({
            "kind": self.kind,
            "version": self.version,
            "personId": self.person_id,
            "identityPublicKey": self.identity_public_key,
            "certificates": self.certificates,
            "revocations": self.revocations,
        });
        canonical_hash(&value)
    }
}

impl AuthorityUpdateRequest {
    pub fn verify(
        &self,
        service_id: &str,
        origin: &str,
        now: u64,
    ) -> Result<VerifiedIdentityAuthorityView, String> {
        if self.version != 1 {
            return Err("Unsupported Identity authority update version".into());
        }
        let authorization = &self.authorization;
        let payload = &authorization.payload;
        let expected_hash = canonical_hash(&json!({"version": 1, "view": self.view}))?;
        if payload.kind != "rusty-identity-authority-update"
            || payload.version != 1
            || payload.service_id != service_id
            || payload.origin != origin
            || payload.person_id != self.view.person_id
            || payload.authority_head != self.view.revocation_head
            || payload.view_digest != self.view.view_digest
            || payload.request_hash != expected_hash
            || authorization.signer_key_id != payload.device_id
            || !valid_nonce(&payload.nonce)
            || now.abs_diff(payload.issued_at) > AUTHORITY_REQUEST_TTL_MS
        {
            return Err("Invalid Identity authority update binding or expiry".into());
        }
        let verified = self.view.verify()?;
        if !verified.is_active_device(&payload.device_id)? {
            return Err("Identity authority update actor is revoked".into());
        }
        let device_key = verify_device_certificate_chain(
            &self.view.identity(),
            &payload.device_id,
            &certificate_chain(
                &self.view.identity(),
                &payload.device_id,
                &verified.certificates_by_device,
            )?,
            SIGNATURE_DOMAIN,
        )?;
        if !verify_signed_envelope(authorization, &device_key, SIGNATURE_DOMAIN)? {
            return Err("Invalid Identity authority update signature".into());
        }
        Ok(verified)
    }
}

impl ScopeAuthorityUpdateRequest {
    pub fn request_hash(&self) -> Result<String, String> {
        canonical_hash(&json!({
            "version": 1,
            "scopeAuthority": self.scope_authority,
        }))
    }

    pub fn verify(
        &self,
        path_scope_id: &str,
        expected_genesis_creator_person_id: Option<&str>,
        service_id: &str,
        origin: &str,
        authority_view: &IdentityAuthorityView,
        now: u64,
    ) -> Result<ValidatedScopeAuthority, String> {
        if self.version != 1 || !valid_scope_id(path_scope_id) {
            return Err("Unsupported scope authority update".into());
        }
        let payload: ScopeAuthorityUpdateAuthorization =
            serde_json::from_value(self.authorization.payload.clone())
                .map_err(|_| "Invalid scope authority update authorization")?;
        let expected_hash = self.request_hash()?;
        let validated = validate_scope_authority_at(&self.scope_authority, now as i128)?;
        if expected_genesis_creator_person_id
            .is_some_and(|person_id| validated.creator.person_id != person_id)
        {
            return Err("Scope authority creator does not match original resource owner".into());
        }
        if validated.scope_id.is_empty()
            || payload.kind != "rusty-scope-authority-update"
            || payload.version != 1
            || payload.service_id != service_id
            || payload.origin != origin
            || payload.scope_id != path_scope_id
            || payload.workspace_id != validated.scope_id
            || payload.person_id != validated.controller.person_id
            || payload.control_epoch != validated.control_epoch
            || payload.request_hash != expected_hash
            || !valid_nonce(&payload.request_id)
            || payload.issued_at.abs_diff(now) > AUTHORITY_REQUEST_TTL_MS
            || payload.expires_at <= now
            || payload.expires_at <= payload.issued_at
            || payload.expires_at.saturating_sub(payload.issued_at) > AUTHORITY_REQUEST_TTL_MS
            || now > payload.expires_at
            || self.authorization.signer_key_id != payload.device_id
        {
            return Err("Invalid scope authority update binding or expiry".into());
        }
        let verified_identity = authority_view.verify()?;
        if !verified_identity.is_active_device(&payload.device_id)?
            || !scope_authority_chain_matches(
                &verified_identity,
                &validated.controller,
                &payload.device_id,
            )?
        {
            return Err("Scope authority controller device is revoked or mismatched".into());
        }
        let device_key = verify_device_certificate_chain(
            &authority_view.identity(),
            &payload.device_id,
            &certificate_chain(
                &authority_view.identity(),
                &payload.device_id,
                &verified_identity.certificates_by_device,
            )?,
            SIGNATURE_DOMAIN,
        )?;
        if !verify_signed_envelope(&self.authorization, &device_key, SIGNATURE_DOMAIN)? {
            return Err("Invalid scope authority update signature".into());
        }
        Ok(validated)
    }

    /// Verify newly introduced scope-controller decisions against the current
    /// Identity ledgers. Previously accepted records remain valid history after
    /// their signer is revoked; a signed timestamp alone does not prove the
    /// service accepted a record before revocation.
    pub fn verify_new_controller_signers(
        &self,
        accepted: Option<&ScopeAuthoritySnapshot>,
        identity_view: impl Fn(&str) -> Result<Option<IdentityAuthorityView>, String>,
        now: u64,
    ) -> Result<ScopeAuthoritySnapshot, String> {
        let merged =
            merge_scope_authority_snapshots_at(accepted, &self.scope_authority, now as i128)?;
        validate_new_scope_authority_signers(&merged, accepted, identity_view, now)?;
        Ok(merged)
    }
}

fn validate_new_scope_authority_signers(
    snapshot: &ScopeAuthoritySnapshot,
    accepted: Option<&ScopeAuthoritySnapshot>,
    mut identity_view: impl FnMut(&str) -> Result<Option<IdentityAuthorityView>, String>,
    now: u64,
) -> Result<(), String> {
    let validated = validate_scope_authority_at(snapshot, now as i128)?;
    let previously_accepted_control =
        accepted.map_or(&[][..], |value| value.control_transfers.as_slice());
    let previously_accepted_successions =
        accepted.map_or(&[][..], |value| value.succession_transfers.as_slice());

    let mut controller = snapshot.genesis.payload.creator.clone();
    let mut epoch = snapshot.genesis.payload.control_epoch;
    let mut controllers = BTreeMap::new();
    controllers.insert(epoch, controller.clone());
    while epoch < validated.control_epoch {
        let control = snapshot
            .control_transfers
            .iter()
            .find(|record| record.payload.from_control_epoch == epoch);
        let succession = snapshot
            .succession_transfers
            .iter()
            .find(|record| record.from_control_epoch == epoch);
        match (control, succession) {
            (Some(transfer), None) => {
                if !previously_accepted_control.contains(transfer) {
                    verify_active_scope_signer(
                        &controller,
                        &transfer.signer_key_id,
                        &mut identity_view,
                    )?;
                }
                controller = transfer.payload.to_controller.clone();
            }
            (None, Some(transfer)) => {
                let next = succession_controller(transfer);
                let accepted_claim = previously_accepted_successions.iter().any(|previous| {
                    previous.from_control_epoch == transfer.from_control_epoch
                        && previous.claim == transfer.claim
                });
                if !accepted_claim {
                    verify_active_scope_signer(
                        &next,
                        &transfer.claim.signer_key_id,
                        &mut identity_view,
                    )?;
                    for vote in &transfer.claim.payload.votes {
                        verify_active_scope_signer(
                            &ScopeAuthority {
                                person_id: vote.voter_grant.payload.person_id.clone(),
                                public_key: vote.voter_public_key.clone(),
                                certificates: vote.voter_certificates.clone(),
                            },
                            &vote.signed.signer_key_id,
                            &mut identity_view,
                        )?;
                    }
                }
                for revocation in &transfer.revocations {
                    let was_accepted = previously_accepted_successions.iter().any(|previous| {
                        previous.from_control_epoch == transfer.from_control_epoch
                            && previous.claim == transfer.claim
                            && previous.revocations.contains(revocation)
                    });
                    if !was_accepted {
                        let issuer = controllers
                            .values()
                            .find(|candidate: &&ScopeAuthority| {
                                candidate.person_id == revocation.payload.owner_person_id
                            })
                            .ok_or("Scope revocation issuer is not in accepted control history")?;
                        verify_active_scope_signer(
                            issuer,
                            &revocation.signer_key_id,
                            &mut identity_view,
                        )?;
                    }
                }
                controller = next;
            }
            _ => return Err("Scope authority control history is forked or incomplete".into()),
        }
        epoch = epoch.checked_add(1).ok_or("Scope control epoch overflow")?;
        controllers.insert(epoch, controller.clone());
    }

    if let Some(accepted) = accepted {
        for revocation in &snapshot.revocations {
            if accepted.revocations.contains(revocation) {
                continue;
            }
            let issuer = controllers
                .get(&revocation.payload.control_epoch)
                .ok_or("Scope revocation issuer epoch is unavailable")?;
            verify_active_scope_signer(issuer, &revocation.signer_key_id, &mut identity_view)?;
        }
    } else {
        for revocation in &snapshot.revocations {
            let issuer = controllers
                .get(&revocation.payload.control_epoch)
                .ok_or("Scope revocation issuer epoch is unavailable")?;
            verify_active_scope_signer(issuer, &revocation.signer_key_id, &mut identity_view)?;
        }
    }
    Ok(())
}

fn succession_controller(transfer: &ScopeSuccessionTransfer) -> ScopeAuthority {
    ScopeAuthority {
        person_id: transfer.claim.payload.to_owner_person_id.clone(),
        public_key: transfer.claim.payload.to_owner_public_key.clone(),
        certificates: transfer.claim.payload.to_owner_certificates.clone(),
    }
}

fn valid_scope_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
}

fn verify_active_scope_signer(
    signer: &ScopeAuthority,
    device_id: &str,
    identity_view: &mut impl FnMut(&str) -> Result<Option<IdentityAuthorityView>, String>,
) -> Result<(), String> {
    let view = identity_view(&signer.person_id)?
        .ok_or("Scope decision signer has no registered Identity authority")?;
    if view.person_id != signer.person_id || view.identity_public_key != signer.public_key {
        return Err("Scope decision signer Identity binding changed".into());
    }
    let verified = view.verify()?;
    if !verified.is_active_device(device_id)?
        || !scope_authority_chain_matches(&verified, signer, device_id)?
    {
        return Err("New scope decision signer is revoked or mismatched".into());
    }
    let public_key = verify_device_certificate_chain(
        &view.identity(),
        device_id,
        &certificate_chain(
            &view.identity(),
            device_id,
            &verified.certificates_by_device,
        )?,
        SIGNATURE_DOMAIN,
    )?;
    if public_key_id(&public_key)? != device_id {
        return Err("New scope decision signer key is invalid".into());
    }
    Ok(())
}

impl IdentityRequestProof {
    pub fn verify(
        &self,
        envelope: &SignedEnvelope<Value>,
        view: &IdentityAuthorityView,
        service_id: &str,
        origin: &str,
        scope_id: &str,
        action: &str,
        token: &str,
        method: &str,
        path: &str,
        body: &[u8],
        now: u64,
    ) -> Result<(), String> {
        let body_hash = URL_SAFE_NO_PAD.encode(Sha256::digest(body));
        let token_hash = URL_SAFE_NO_PAD.encode(Sha256::digest(token.as_bytes()));
        if self.kind != "rusty-identity-request-proof"
            || self.version != 1
            || self.service_id != service_id
            || self.origin != origin
            || self.person_id != view.person_id
            || self.authority_head != view.revocation_head
            || self.view_digest != view.view_digest
            || self.resource_kind != "scope"
            || self.resource_id != scope_id
            || self.scope_id != scope_id
            || self.action != action
            || self.token_hash != token_hash
            || self.method != method
            || self.path != path
            || self.body_hash != body_hash
            || !valid_nonce(&self.nonce)
            || now.abs_diff(self.issued_at) > AUTHORITY_REQUEST_TTL_MS
            || envelope.signer_key_id != self.device_id
        {
            return Err("Identity request proof binding or expiry is invalid".into());
        }
        let verified_view = view.verify()?;
        if !verified_view.is_active_device(&self.device_id)? {
            return Err("Identity request device is revoked".into());
        }
        let chain = certificate_chain(
            &view.identity(),
            &self.device_id,
            &verified_view.certificates_by_device,
        )?;
        let public_key = verify_device_certificate_chain(
            &view.identity(),
            &self.device_id,
            &chain,
            SIGNATURE_DOMAIN,
        )?;
        if !verify_signed_envelope(envelope, &public_key, SIGNATURE_DOMAIN)? {
            return Err("Invalid Identity request proof signature".into());
        }
        Ok(())
    }
}

impl ResourcePrincipalGrant {
    pub fn verify(
        &self,
        envelope: &SignedEnvelope<Self>,
        owner: &VerifiedIdentityAuthorityView,
        service_id: &str,
        origin: &str,
        scope_id: &str,
        require_active_issuer: bool,
        now: u64,
    ) -> Result<(), String> {
        let workspace_grant = &self.workspace_grant;
        let scope_authority = validate_scope_authority_at(&self.scope_authority, now as i128)?;
        let expected_actions: &[&str] = match workspace_grant.payload.role {
            WorkspaceRole::Owner | WorkspaceRole::Editor => &["read", "write"],
            WorkspaceRole::Visitor => &["read"],
            WorkspaceRole::Automation => {
                return Err("Automation grant cannot access Rusty storage".into());
            }
        };
        if self.kind != "rusty-resource-principal-grant"
            || self.version != 1
            || self.service_id != service_id
            || self.origin != origin
            || self.resource_kind != "scope"
            || self.resource_id != scope_id
            || self.scope_id != scope_id
            || self.owner_person_id != scope_authority.controller.person_id
            || self.owner_person_id != owner.view.person_id
            || scope_authority.scope_id != scope_id
            || self.subject_person_id == self.owner_person_id
            || self.grant_id != workspace_grant.payload.grant_id
            || self.workspace_id != workspace_grant.payload.workspace_id
            || self.subject_person_id != workspace_grant.payload.person_id
            || self.policy_epoch != workspace_grant.payload.effective_access_epoch()
            || self.actions.iter().map(String::as_str).collect::<Vec<_>>() != expected_actions
            || !valid_digest(&self.read_token_hash)
            || !valid_digest(&self.write_token_hash)
            || public_key_id(&self.subject_public_key)? != self.subject_person_id
        {
            return Err("Invalid Rusty resource principal grant".into());
        }
        if require_active_issuer && !owner.is_active_device(&envelope.signer_key_id)? {
            return Err("Resource grant issuer is not an active Identity device".into());
        }
        if !scope_authority_chain_matches(
            owner,
            &scope_authority.controller,
            &envelope.signer_key_id,
        )? {
            return Err("Resource grant controller certificate history mismatch".into());
        }
        let owner_identity = owner.view.identity();
        verify_workspace_grant_from_scope_history(
            workspace_grant,
            &self.workspace_id,
            &self.subject_person_id,
            &self.scope_authority,
            now,
        )?;
        let chain = certificate_chain(
            &owner_identity,
            &envelope.signer_key_id,
            &owner.certificates_by_device,
        )?;
        let issuer_key = verify_device_certificate_chain(
            &owner_identity,
            &envelope.signer_key_id,
            &chain,
            SIGNATURE_DOMAIN,
        )?;
        if !verify_signed_envelope(envelope, &issuer_key, SIGNATURE_DOMAIN)? {
            return Err("Invalid Rusty resource principal grant signature".into());
        }
        Ok(())
    }
}

fn scope_authority_chain_matches(
    identity: &VerifiedIdentityAuthorityView,
    authority: &ScopeAuthority,
    device_id: &str,
) -> Result<bool, String> {
    if authority.person_id != identity.view.person_id
        || authority.public_key != identity.view.identity_public_key
    {
        return Ok(false);
    }
    let mut authority_certificates = HashMap::new();
    for certificate in &authority.certificates {
        let id = certificate.payload.device_id.clone();
        if authority_certificates
            .insert(id, certificate.clone())
            .is_some()
        {
            return Ok(false);
        }
    }
    let authority_chain = certificate_chain(
        &identity.view.identity(),
        device_id,
        &authority_certificates,
    )?;
    let registered_chain = certificate_chain(
        &identity.view.identity(),
        device_id,
        &identity.certificates_by_device,
    )?;
    Ok(authority_chain == registered_chain)
}

fn scope_controller_history(
    snapshot: &ScopeAuthoritySnapshot,
    now: u64,
) -> Result<Vec<ScopeAuthority>, String> {
    let validated = validate_scope_authority_at(snapshot, now as i128)?;
    let mut history = vec![snapshot.genesis.payload.creator.clone()];
    let mut epoch = snapshot.genesis.payload.control_epoch;
    while epoch < validated.control_epoch {
        let control = snapshot
            .control_transfers
            .iter()
            .find(|record| record.payload.from_control_epoch == epoch);
        let succession = snapshot
            .succession_transfers
            .iter()
            .find(|record| record.from_control_epoch == epoch);
        let next = match (control, succession) {
            (Some(transfer), None) => transfer.payload.to_controller.clone(),
            (None, Some(transfer)) => succession_controller(transfer),
            _ => return Err("Scope controller history is forked or incomplete".into()),
        };
        history.push(next);
        epoch = epoch.checked_add(1).ok_or("Scope control epoch overflow")?;
    }
    if history.last().is_none_or(|controller| {
        controller.person_id != validated.controller.person_id
            || controller.public_key != validated.controller.public_key
    }) {
        return Err("Scope controller history does not match current controller".into());
    }
    Ok(history)
}

fn verify_workspace_grant_from_scope_history(
    grant: &WorkspaceGrant,
    workspace_id: &str,
    member_person_id: &str,
    snapshot: &ScopeAuthoritySnapshot,
    now: u64,
) -> Result<(), String> {
    let history = scope_controller_history(snapshot, now)?;
    let mut verified_principals = HashSet::new();
    for controller in history {
        if verify_workspace_grant(
            grant,
            workspace_id,
            member_person_id,
            &PublicIdentity {
                person_id: controller.person_id.clone(),
                public_key: controller.public_key.clone(),
                display_name: String::new(),
            },
            &controller.certificates,
        )
        .is_ok()
        {
            verified_principals.insert((controller.person_id, controller.public_key));
        }
    }
    if verified_principals.len() == 1 {
        Ok(())
    } else {
        Err("Workspace grant signer is not a unique scope controller".into())
    }
}

impl IdentityRootSuccessionRequest {
    pub fn request_hash(&self) -> Result<String, String> {
        canonical_hash(&json!({
            "version": self.version,
            "succession": self.succession,
            "actorDeviceId": self.actor_device_id,
        }))
    }

    pub fn verify(
        &self,
        previous: &IdentityAuthorityView,
        successor: &IdentityAuthorityView,
        service_id: &str,
        origin: &str,
        now: u64,
    ) -> Result<VerifiedIdentityRootSuccession, String> {
        const ROOT_SUCCESSION_DOMAIN: &str = "MESH-IDENTITY-ROOT-SUCCESSION/1";
        if self.version != 1 {
            return Err("Unsupported Identity root succession version".into());
        }
        let previous_verified = previous.verify()?;
        let successor_verified = successor.verify()?;
        let authorization = &self.succession.authorization;
        let payload = &authorization.payload;
        if payload.kind != "mesh-identity-root-succession"
            || payload.version != 1
            || !valid_nonce(&payload.succession_id)
            || payload.previous_person_id != previous.person_id
            || payload.previous_identity_public_key != previous.identity_public_key
            || payload.successor_person_id != successor.person_id
            || payload.successor_identity_public_key != successor.identity_public_key
            || payload.previous_person_id == payload.successor_person_id
            || payload.authority_head != previous.revocation_head
            || payload.authority_view_digest != previous.view_digest
            || authorization.signer_key_id != payload.previous_person_id
            || public_key_id(&previous_verified.view.identity().public_key)?
                != payload.previous_person_id
            || public_key_id(&successor_verified.view.identity().public_key)?
                != payload.successor_person_id
            || !verify_signed_envelope(
                authorization,
                &previous.identity_public_key,
                ROOT_SUCCESSION_DOMAIN,
            )?
        {
            return Err("Identity root succession does not match current authority views".into());
        }

        let acceptance = &self.succession.acceptance;
        let accepted = &acceptance.payload;
        let authorization_hash = canonical_hash(authorization)?;
        if accepted.kind != "mesh-identity-root-succession-acceptance"
            || accepted.version != 1
            || accepted.succession_hash != authorization_hash
            || accepted.previous_person_id != payload.previous_person_id
            || accepted.successor_person_id != payload.successor_person_id
            || acceptance.signer_key_id != payload.successor_person_id
            || !verify_signed_envelope(
                acceptance,
                &successor.identity_public_key,
                ROOT_SUCCESSION_DOMAIN,
            )?
        {
            return Err("Identity root successor did not accept the exact transition".into());
        }
        let transition_hash = canonical_hash(&self.succession)?;
        let actor = &self.actor_authorization;
        let actor_payload = &actor.payload;
        let request_hash = self.request_hash()?;
        if actor_payload.kind != "rusty-identity-root-succession-request"
            || actor_payload.version != 1
            || actor_payload.service_id != service_id
            || actor_payload.origin != origin
            || actor_payload.previous_person_id != payload.previous_person_id
            || actor_payload.successor_person_id != payload.successor_person_id
            || actor_payload.transition_hash != transition_hash
            || actor_payload.actor_device_id != self.actor_device_id
            || actor_payload.request_hash != request_hash
            || !valid_nonce(&actor_payload.request_id)
            || now.abs_diff(actor_payload.issued_at) > AUTHORITY_REQUEST_TTL_MS
            || actor_payload.expires_at <= actor_payload.issued_at
            || actor_payload.expires_at - actor_payload.issued_at > AUTHORITY_REQUEST_TTL_MS
            || now > actor_payload.expires_at
            || actor.signer_key_id != self.actor_device_id
            || !successor_verified.is_active_device(&self.actor_device_id)?
        {
            return Err("Identity root succession request is not authorized".into());
        }
        let actor_chain = certificate_chain(
            &successor_verified.view.identity(),
            &self.actor_device_id,
            &successor_verified.certificates_by_device,
        )?;
        let actor_key = verify_device_certificate_chain(
            &successor_verified.view.identity(),
            &self.actor_device_id,
            &actor_chain,
            SIGNATURE_DOMAIN,
        )?;
        if !verify_signed_envelope(actor, &actor_key, SIGNATURE_DOMAIN)? {
            return Err("Invalid Identity root succession request signature".into());
        }
        Ok(VerifiedIdentityRootSuccession {
            previous_person_id: payload.previous_person_id.clone(),
            previous_identity_public_key: payload.previous_identity_public_key.clone(),
            successor_person_id: payload.successor_person_id.clone(),
            successor_identity_public_key: payload.successor_identity_public_key.clone(),
            authority_head: payload.authority_head.clone(),
            authority_view_digest: payload.authority_view_digest.clone(),
            authorization_hash,
            transition_hash,
        })
    }
}

pub(super) fn certificate_chain(
    identity: &PublicIdentity,
    device_id: &str,
    certificates: &HashMap<String, DeviceCertificate>,
) -> Result<Vec<DeviceCertificate>, String> {
    let mut chain = Vec::new();
    let mut seen = HashSet::new();
    let mut current = certificates
        .get(device_id)
        .ok_or("Identity device certificate unavailable")?;
    loop {
        if !seen.insert(current.payload.device_id.clone()) || chain.len() >= 32 {
            return Err("Invalid Identity certificate ancestry".into());
        }
        chain.push(current.clone());
        let Some(issuer_hash) = &current.payload.issuer_certificate_hash else {
            break;
        };
        current = certificates
            .values()
            .find(|candidate| certificate_hash(candidate).is_ok_and(|hash| hash == *issuer_hash))
            .ok_or("Identity certificate issuer unavailable")?;
    }
    verify_device_certificate_chain(identity, device_id, &chain, SIGNATURE_DOMAIN)?;
    Ok(chain)
}

fn is_active_in_catalog(
    identity: &PublicIdentity,
    device_id: &str,
    revoked_roots: &HashSet<String>,
    certificates: &HashMap<String, DeviceCertificate>,
) -> Result<bool, String> {
    let chain = certificate_chain(identity, device_id, certificates)?;
    Ok(!chain
        .iter()
        .any(|certificate| revoked_roots.contains(&certificate.payload.device_id)))
}

fn is_descendant_or_same(
    identity: &PublicIdentity,
    device_id: &str,
    ancestor_device_id: &str,
    certificates: &HashMap<String, DeviceCertificate>,
) -> Result<bool, String> {
    let chain = certificate_chain(identity, device_id, certificates)?;
    Ok(chain
        .iter()
        .any(|certificate| certificate.payload.device_id == ancestor_device_id))
}

fn genesis_head(person_id: &str, identity_public_key: &str) -> Result<RevocationHead, String> {
    Ok(RevocationHead {
        revision: 0,
        record_hash: canonical_hash(&json!({
            "kind": "mesh-identity-revocation-genesis",
            "version": 1,
            "personId": person_id,
            "identityPublicKey": identity_public_key,
        }))?,
    })
}

pub(super) fn canonical_hash<T: Serialize>(value: &T) -> Result<String, String> {
    let value = serde_json::to_value(value).map_err(|_| "Identity authority value invalid")?;
    let canonical = canonicalize_json(&value)?;
    Ok(URL_SAFE_NO_PAD.encode(Sha256::digest(canonical.as_bytes())))
}

fn valid_digest(value: &str) -> bool {
    value.len() == 43
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-')
}

pub(super) fn valid_nonce(value: &str) -> bool {
    URL_SAFE_NO_PAD
        .decode(value)
        .is_ok_and(|bytes| bytes.len() == 32)
}

pub(super) fn authority_view_hash(view: &IdentityAuthorityView) -> Result<String, String> {
    canonical_hash(&json!({"version": 1, "view": view}))
}

pub(super) fn status_request_hash(path_and_query: &str) -> Result<String, String> {
    canonical_hash(&json!({"method": "GET", "path": path_and_query}))
}

pub(super) fn identity_succession_status_request_hash(
    previous_person_id: &str,
    transition_hash: &str,
    request_id: &str,
) -> Result<String, String> {
    if !valid_scope_id(previous_person_id)
        || !valid_digest(transition_hash)
        || !valid_nonce(request_id)
    {
        return Err("Invalid Identity succession status request".into());
    }
    canonical_hash(&json!({
        "version": 1,
        "previousPersonId": previous_person_id,
        "transitionHash": transition_hash,
        "requestId": request_id,
    }))
}

pub(super) fn scope_authority_status_request_hash(
    scope_id: &str,
    request_id: &str,
) -> Result<String, String> {
    canonical_hash(&json!({"version": 1, "scopeId": scope_id, "requestId": request_id}))
}

pub(super) fn scope_authority_snapshot_hash(
    snapshot: &ScopeAuthoritySnapshot,
) -> Result<String, String> {
    canonical_hash(snapshot)
}

#[cfg(test)]
pub(super) fn test_authority_view(
    identity: &PublicIdentity,
    root_seed: &[u8; 32],
    device_seeds: &[u8],
) -> IdentityAuthorityView {
    test_authority_view_with_devices(
        identity,
        root_seed,
        &device_seeds
            .iter()
            .map(|seed| (*seed, true))
            .collect::<Vec<_>>(),
    )
}

#[cfg(test)]
pub(super) fn test_authority_view_with_devices(
    identity: &PublicIdentity,
    root_seed: &[u8; 32],
    devices: &[(u8, bool)],
) -> IdentityAuthorityView {
    use meta_mesh_core::{DeviceCertificatePayload, sign_device_certificate};
    let mut certificates = devices
        .iter()
        .map(|(seed, can_enroll_devices)| {
            let device_public_key = meta_mesh_core::public_key_from_seed(&[*seed; 32]).unwrap();
            let device_id = public_key_id(&device_public_key).unwrap();
            sign_device_certificate(
                root_seed,
                DeviceCertificatePayload {
                    kind: "device-certificate".into(),
                    version: 1,
                    person_id: identity.person_id.clone(),
                    device_id,
                    device_public_key,
                    issuer_certificate_hash: None,
                    can_enroll_devices: *can_enroll_devices,
                },
                &identity.person_id,
                SIGNATURE_DOMAIN,
            )
            .unwrap()
        })
        .collect::<Vec<_>>();
    certificates.sort_by(|left, right| left.payload.device_id.cmp(&right.payload.device_id));
    let mut view = IdentityAuthorityView {
        kind: "mesh-identity-authority-view".into(),
        version: 1,
        person_id: identity.person_id.clone(),
        identity_public_key: identity.public_key.clone(),
        certificates,
        revocations: Vec::new(),
        revocation_head: genesis_head(&identity.person_id, &identity.public_key).unwrap(),
        view_digest: String::new(),
    };
    view.view_digest = view.compute_view_digest().unwrap();
    view
}

#[cfg(test)]
pub(super) fn test_revoke_authority_device(
    mut view: IdentityAuthorityView,
    device_id: &str,
    manager_seed: &[u8; 32],
) -> IdentityAuthorityView {
    use meta_mesh_core::sign_json_envelope;

    let signer_id =
        public_key_id(&meta_mesh_core::public_key_from_seed(manager_seed).unwrap()).unwrap();
    let signed = sign_json_envelope(
        manager_seed,
        serde_json::to_value(RevocationPayload {
            kind: "mesh-identity-device-revocation".into(),
            version: 1,
            person_id: view.person_id.clone(),
            device_id: device_id.to_owned(),
            revision: view.revocations.len() as u64 + 1,
            profile_operation_hashes: BTreeMap::new(),
        })
        .unwrap(),
        signer_id,
        SIGNATURE_DOMAIN,
    )
    .unwrap();
    view.revocation_head = RevocationHead {
        revision: view.revocations.len() as u64 + 1,
        record_hash: canonical_hash(&signed).unwrap(),
    };
    view.revocations.push(signed);
    view.view_digest = view.compute_view_digest().unwrap();
    view
}

#[cfg(test)]
pub(super) fn test_signed_identity_request_proof(
    view: &IdentityAuthorityView,
    device_seed: &[u8; 32],
    origin: &str,
    service_id: &str,
    scope_id: &str,
    token: &str,
    method: &str,
    path: &str,
    body: &[u8],
    action: &str,
    policy_epoch: u64,
    grant_id: Option<String>,
    issued_at: u64,
) -> SignedEnvelope<Value> {
    use meta_mesh_core::sign_json_envelope;

    let device_id =
        public_key_id(&meta_mesh_core::public_key_from_seed(device_seed).unwrap()).unwrap();
    let proof = IdentityRequestProof {
        kind: "rusty-identity-request-proof".into(),
        version: 1,
        service_id: service_id.into(),
        origin: origin.into(),
        person_id: view.person_id.clone(),
        device_id: device_id.clone(),
        authority_head: view.revocation_head.clone(),
        view_digest: view.view_digest.clone(),
        resource_kind: "scope".into(),
        resource_id: scope_id.into(),
        scope_id: scope_id.into(),
        action: action.into(),
        grant_id,
        policy_epoch,
        token_hash: URL_SAFE_NO_PAD.encode(Sha256::digest(token.as_bytes())),
        method: method.into(),
        path: path.into(),
        body_hash: URL_SAFE_NO_PAD.encode(Sha256::digest(body)),
        nonce: URL_SAFE_NO_PAD.encode(rand::random::<[u8; 32]>()),
        issued_at,
    };
    sign_json_envelope(
        device_seed,
        serde_json::to_value(proof).unwrap(),
        device_id,
        SIGNATURE_DOMAIN,
    )
    .unwrap()
}

#[cfg(test)]
pub(super) fn test_authority_update_request(
    view: IdentityAuthorityView,
    device_seed: &[u8; 32],
    service_id: &str,
    origin: &str,
    issued_at: u64,
) -> AuthorityUpdateRequest {
    use meta_mesh_core::sign_json_envelope;

    let device_id =
        public_key_id(&meta_mesh_core::public_key_from_seed(device_seed).unwrap()).unwrap();
    let request_hash = authority_view_hash(&view).unwrap();
    let authorization = AuthorityUpdateAuthorization {
        kind: "rusty-identity-authority-update".into(),
        version: 1,
        service_id: service_id.into(),
        origin: origin.into(),
        person_id: view.person_id.clone(),
        device_id: device_id.clone(),
        authority_head: view.revocation_head.clone(),
        view_digest: view.view_digest.clone(),
        nonce: URL_SAFE_NO_PAD.encode(rand::random::<[u8; 32]>()),
        issued_at,
        request_hash,
    };
    let authorization = sign_json_envelope(
        device_seed,
        serde_json::to_value(authorization).unwrap(),
        device_id,
        SIGNATURE_DOMAIN,
    )
    .unwrap();
    AuthorityUpdateRequest {
        version: 1,
        view,
        authorization: serde_json::from_value(serde_json::to_value(authorization).unwrap())
            .unwrap(),
    }
}

#[cfg(test)]
pub(super) fn test_identity_root_succession_request(
    previous_identity: &PublicIdentity,
    previous_seed: &[u8; 32],
    previous_view: &IdentityAuthorityView,
    successor_identity: &PublicIdentity,
    successor_seed: &[u8; 32],
    actor_seed: &[u8; 32],
    service_id: &str,
    origin: &str,
    now: u64,
) -> IdentityRootSuccessionRequest {
    const ROOT_SUCCESSION_DOMAIN: &str = "MESH-IDENTITY-ROOT-SUCCESSION/1";
    use meta_mesh_core::sign_json_envelope;

    let authorization: SignedEnvelope<IdentityRootSuccessionAuthorization> =
        serde_json::from_value(
            serde_json::to_value(
                sign_json_envelope(
                    previous_seed,
                    serde_json::to_value(IdentityRootSuccessionAuthorization {
                        kind: "mesh-identity-root-succession".into(),
                        version: 1,
                        succession_id: URL_SAFE_NO_PAD.encode(rand::random::<[u8; 32]>()),
                        previous_person_id: previous_identity.person_id.clone(),
                        previous_identity_public_key: previous_identity.public_key.clone(),
                        successor_person_id: successor_identity.person_id.clone(),
                        successor_identity_public_key: successor_identity.public_key.clone(),
                        authority_head: previous_view.revocation_head.clone(),
                        authority_view_digest: previous_view.view_digest.clone(),
                    })
                    .unwrap(),
                    previous_identity.person_id.clone(),
                    ROOT_SUCCESSION_DOMAIN,
                )
                .unwrap(),
            )
            .unwrap(),
        )
        .unwrap();
    let acceptance: SignedEnvelope<IdentityRootSuccessionAcceptance> = serde_json::from_value(
        serde_json::to_value(
            sign_json_envelope(
                successor_seed,
                serde_json::to_value(IdentityRootSuccessionAcceptance {
                    kind: "mesh-identity-root-succession-acceptance".into(),
                    version: 1,
                    succession_hash: canonical_hash(&authorization).unwrap(),
                    previous_person_id: previous_identity.person_id.clone(),
                    successor_person_id: successor_identity.person_id.clone(),
                })
                .unwrap(),
                successor_identity.person_id.clone(),
                ROOT_SUCCESSION_DOMAIN,
            )
            .unwrap(),
        )
        .unwrap(),
    )
    .unwrap();
    let succession = IdentityRootSuccession {
        authorization,
        acceptance,
    };
    let actor_device_id =
        public_key_id(&meta_mesh_core::public_key_from_seed(actor_seed).unwrap()).unwrap();
    let request_hash = canonical_hash(&json!({
        "version": 1,
        "succession": &succession,
        "actorDeviceId": &actor_device_id,
    }))
    .unwrap();
    let request_id = URL_SAFE_NO_PAD.encode(rand::random::<[u8; 32]>());
    let transition_hash = canonical_hash(&succession).unwrap();
    let actor_authorization: SignedEnvelope<IdentityRootSuccessionRequestAuthorization> =
        serde_json::from_value(
            serde_json::to_value(
                sign_json_envelope(
                    actor_seed,
                    serde_json::to_value(IdentityRootSuccessionRequestAuthorization {
                        kind: "rusty-identity-root-succession-request".into(),
                        version: 1,
                        service_id: service_id.into(),
                        origin: origin.into(),
                        previous_person_id: previous_identity.person_id.clone(),
                        successor_person_id: successor_identity.person_id.clone(),
                        transition_hash,
                        actor_device_id: actor_device_id.clone(),
                        request_id,
                        issued_at: now,
                        expires_at: now.saturating_add(60_000),
                        request_hash,
                    })
                    .unwrap(),
                    actor_device_id.clone(),
                    SIGNATURE_DOMAIN,
                )
                .unwrap(),
            )
            .unwrap(),
        )
        .unwrap();
    IdentityRootSuccessionRequest {
        version: 1,
        succession,
        actor_device_id,
        actor_authorization,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use meta_mesh_core::{
        ScopeControlTransferPayload, ScopeGenesisPayloadInput, WorkspaceGrantPayload,
        create_scope_genesis_payload, public_key_from_seed, sign_json_envelope, sign_scope_record,
    };

    const FIXTURE: &str = include_str!("../tests/fixtures/identity-authority-view.json");

    fn fixture() -> Value {
        serde_json::from_str(FIXTURE).expect("valid public test fixture")
    }

    fn view(name: &str) -> IdentityAuthorityView {
        serde_json::from_value(fixture()[name].clone()).expect("valid authority view")
    }

    fn scope_identity(
        root_seed: u8,
        device_seeds: &[(u8, bool)],
    ) -> (ScopeAuthority, IdentityAuthorityView) {
        let root_seed = [root_seed; 32];
        let public_key = public_key_from_seed(&root_seed).unwrap();
        let identity = PublicIdentity {
            person_id: public_key_id(&public_key).unwrap(),
            public_key,
            display_name: String::new(),
        };
        let view = test_authority_view_with_devices(&identity, &root_seed, device_seeds);
        let authority = ScopeAuthority {
            person_id: identity.person_id,
            public_key: identity.public_key,
            certificates: view.certificates.clone(),
        };
        (authority, view)
    }

    fn scope_genesis(
        scope_id: &str,
        creator: &ScopeAuthority,
        device_seed: &[u8; 32],
    ) -> meta_mesh_core::SignedScopeGenesis {
        let payload = create_scope_genesis_payload(ScopeGenesisPayloadInput {
            scope_id: scope_id.into(),
            creator: creator.clone(),
        })
        .unwrap();
        sign_scope_record(
            device_seed,
            payload,
            public_key_id(&public_key_from_seed(device_seed).unwrap()).unwrap(),
        )
        .unwrap()
    }

    fn transfer(
        scope_id: &str,
        from: &ScopeAuthority,
        to: &ScopeAuthority,
        device_seed: &[u8; 32],
        from_epoch: u64,
    ) -> meta_mesh_core::ScopeControlTransfer {
        let payload = ScopeControlTransferPayload {
            kind: "scope-control-transfer".into(),
            version: 1,
            scope_id: scope_id.into(),
            from_controller_person_id: from.person_id.clone(),
            to_controller: to.clone(),
            from_control_epoch: from_epoch,
            to_control_epoch: from_epoch + 1,
        };
        sign_scope_record(
            device_seed,
            payload,
            public_key_id(&public_key_from_seed(device_seed).unwrap()).unwrap(),
        )
        .unwrap()
    }

    fn scope_snapshot(
        scope_id: &str,
        creator: &ScopeAuthority,
        creator_device_seed: &[u8; 32],
        control_transfers: Vec<meta_mesh_core::ScopeControlTransfer>,
    ) -> ScopeAuthoritySnapshot {
        ScopeAuthoritySnapshot {
            genesis: scope_genesis(scope_id, creator, creator_device_seed),
            grants: Vec::new(),
            grant_issuers: Vec::new(),
            revocations: Vec::new(),
            control_transfers,
            succession_transfers: Vec::new(),
        }
    }

    #[test]
    fn verifies_sdk_generated_genesis_authority_view_and_app_only_leaf() {
        let fixture = fixture();
        let view = view("genesis");
        let verified = view.verify().expect("SDK genesis view verifies");
        let ids = &fixture["ids"];

        assert_eq!(view.revocation_head.revision, 0);
        assert!(
            verified
                .is_active_device(ids["app"].as_str().unwrap())
                .unwrap()
        );
        assert!(
            verified
                .is_active_manager(ids["owner"].as_str().unwrap())
                .unwrap()
        );
        assert!(
            !verified
                .is_active_manager(ids["app"].as_str().unwrap())
                .unwrap()
        );
    }

    #[test]
    fn verifies_sdk_generated_revocation_and_blocks_only_revoked_leaf() {
        let fixture = fixture();
        let view = view("revision1");
        let verified = view.verify().expect("SDK revision-one view verifies");
        let ids = &fixture["ids"];

        assert_eq!(view.revocation_head.revision, 1);
        assert!(
            !verified
                .is_active_device(ids["target"].as_str().unwrap())
                .unwrap()
        );
        assert!(
            verified
                .is_active_device(ids["app"].as_str().unwrap())
                .unwrap()
        );
        assert!(
            verified
                .is_active_manager(ids["owner"].as_str().unwrap())
                .unwrap()
        );
    }

    #[test]
    fn rejects_authority_view_with_forged_digest_or_head() {
        let mut forged_digest = view("genesis");
        forged_digest.view_digest.replace_range(..1, "A");
        assert!(forged_digest.verify().is_err());

        let mut forged_head = view("revision1");
        forged_head
            .revocation_head
            .record_hash
            .replace_range(..1, "A");
        assert!(forged_head.verify().is_err());
    }

    #[test]
    fn rejects_same_device_id_with_root_and_delegated_certificate_paths() {
        use meta_mesh_core::{DeviceCertificatePayload, sign_device_certificate};

        let root_seed = [61; 32];
        let manager_seed = [62; 32];
        let app_seed = [63; 32];
        let root_key = public_key_from_seed(&root_seed).unwrap();
        let identity = PublicIdentity {
            person_id: public_key_id(&root_key).unwrap(),
            public_key: root_key,
            display_name: String::new(),
        };
        let manager_key = public_key_from_seed(&manager_seed).unwrap();
        let manager_id = public_key_id(&manager_key).unwrap();
        let manager = sign_device_certificate(
            &root_seed,
            DeviceCertificatePayload {
                kind: "device-certificate".into(),
                version: 1,
                person_id: identity.person_id.clone(),
                device_id: manager_id,
                device_public_key: manager_key,
                issuer_certificate_hash: None,
                can_enroll_devices: true,
            },
            &identity.person_id,
            SIGNATURE_DOMAIN,
        )
        .unwrap();
        let app_key = public_key_from_seed(&app_seed).unwrap();
        let app_id = public_key_id(&app_key).unwrap();
        let root_sibling = sign_device_certificate(
            &root_seed,
            DeviceCertificatePayload {
                kind: "device-certificate".into(),
                version: 1,
                person_id: identity.person_id.clone(),
                device_id: app_id.clone(),
                device_public_key: app_key.clone(),
                issuer_certificate_hash: None,
                can_enroll_devices: false,
            },
            &identity.person_id,
            SIGNATURE_DOMAIN,
        )
        .unwrap();
        let delegated = sign_device_certificate(
            &manager_seed,
            DeviceCertificatePayload {
                kind: "device-certificate".into(),
                version: 1,
                person_id: identity.person_id.clone(),
                device_id: app_id,
                device_public_key: app_key,
                issuer_certificate_hash: Some(certificate_hash(&manager).unwrap()),
                can_enroll_devices: false,
            },
            &manager.payload.device_id,
            SIGNATURE_DOMAIN,
        )
        .unwrap();

        let mut certificates = vec![manager, root_sibling, delegated];
        certificates.sort_by(|left, right| left.payload.device_id.cmp(&right.payload.device_id));
        let mut authority = IdentityAuthorityView {
            kind: "mesh-identity-authority-view".into(),
            version: 1,
            person_id: identity.person_id.clone(),
            identity_public_key: identity.public_key.clone(),
            certificates,
            revocations: Vec::new(),
            revocation_head: genesis_head(&identity.person_id, &identity.public_key).unwrap(),
            view_digest: String::new(),
        };
        authority.view_digest = authority.compute_view_digest().unwrap();

        assert!(authority.verify().is_err());
    }

    #[test]
    fn rejects_backdated_new_scope_transfer_signed_by_revoked_controller_device() {
        let revoked_owner_device = [42; 32];
        let active_owner_manager = [43; 32];
        let (owner, owner_genesis_view) = scope_identity(41, &[(42, true), (43, true)]);
        let revoked_device_id =
            public_key_id(&public_key_from_seed(&revoked_owner_device).unwrap()).unwrap();
        let owner_view = test_revoke_authority_device(
            owner_genesis_view,
            &revoked_device_id,
            &active_owner_manager,
        );
        let (attacker, attacker_view) = scope_identity(44, &[(45, true)]);
        let accepted = scope_snapshot(
            "scope-authority-transfer",
            &owner,
            &revoked_owner_device,
            Vec::new(),
        );
        let candidate = scope_snapshot(
            "scope-authority-transfer",
            &owner,
            &revoked_owner_device,
            vec![transfer(
                "scope-authority-transfer",
                &owner,
                &attacker,
                &revoked_owner_device,
                1,
            )],
        );

        let result = validate_new_scope_authority_signers(
            &candidate,
            Some(&accepted),
            |person_id| {
                Ok(if person_id == owner.person_id {
                    Some(owner_view.clone())
                } else if person_id == attacker.person_id {
                    Some(attacker_view.clone())
                } else {
                    None
                })
            },
            1_800_000_000_000,
        );

        assert!(
            result.is_err(),
            "revoked device must not append a transfer, even when attacker is active"
        );
    }

    #[test]
    fn accepted_scope_transfer_prefix_survives_issuer_revocation() {
        let owner_device = [52; 32];
        let owner_manager = [53; 32];
        let (owner, owner_genesis_view) = scope_identity(51, &[(52, true), (53, true)]);
        let revoked_device_id =
            public_key_id(&public_key_from_seed(&owner_device).unwrap()).unwrap();
        let owner_view =
            test_revoke_authority_device(owner_genesis_view, &revoked_device_id, &owner_manager);
        let (successor, successor_view) = scope_identity(54, &[(55, true)]);
        let successor_device = [55; 32];
        let (next_owner, next_owner_view) = scope_identity(56, &[(57, true)]);
        let accepted_transfer = transfer(
            "scope-authority-prefix",
            &owner,
            &successor,
            &owner_device,
            1,
        );
        let accepted = scope_snapshot(
            "scope-authority-prefix",
            &owner,
            &owner_device,
            vec![accepted_transfer.clone()],
        );
        let candidate = scope_snapshot(
            "scope-authority-prefix",
            &owner,
            &owner_device,
            vec![
                accepted_transfer,
                transfer(
                    "scope-authority-prefix",
                    &successor,
                    &next_owner,
                    &successor_device,
                    2,
                ),
            ],
        );

        let result = validate_new_scope_authority_signers(
            &candidate,
            Some(&accepted),
            |person_id| {
                Ok(if person_id == owner.person_id {
                    Some(owner_view.clone())
                } else if person_id == successor.person_id {
                    Some(successor_view.clone())
                } else if person_id == next_owner.person_id {
                    Some(next_owner_view.clone())
                } else {
                    None
                })
            },
            1_800_000_000_000,
        );

        assert!(
            result.is_ok(),
            "accepted old prefix must not be re-evaluated after revocation: {result:?}"
        );
    }

    #[test]
    fn current_controller_can_reattest_grant_signed_by_historical_controller() {
        let old_root_seed = [61; 32];
        let old_device_seed = [62; 32];
        let successor_device_seed = [64; 32];
        let (old_controller, _) = scope_identity(61, &[(62, true)]);
        let (successor, successor_view) = scope_identity(63, &[(62, false), (64, false)]);
        let subject_key = public_key_from_seed(&[65; 32]).unwrap();
        let subject_person_id = public_key_id(&subject_key).unwrap();
        let scope_id = "history-bound-grant";
        let snapshot = scope_snapshot(
            scope_id,
            &old_controller,
            &old_device_seed,
            vec![transfer(
                scope_id,
                &old_controller,
                &successor,
                &old_device_seed,
                1,
            )],
        );
        let workspace_grant: WorkspaceGrant = serde_json::from_value(
            serde_json::to_value(
                sign_json_envelope(
                    &old_root_seed,
                    serde_json::to_value(WorkspaceGrantPayload {
                        kind: "workspace-grant".into(),
                        version: 1,
                        grant_id: "member-grant".into(),
                        workspace_id: scope_id.into(),
                        person_id: subject_person_id.clone(),
                        role: WorkspaceRole::Editor,
                        access_epoch: Some(1),
                        automation: None,
                    })
                    .unwrap(),
                    old_controller.person_id.clone(),
                    SIGNATURE_DOMAIN,
                )
                .unwrap(),
            )
            .unwrap(),
        )
        .unwrap();
        let successor_device_id =
            public_key_id(&public_key_from_seed(&successor_device_seed).unwrap()).unwrap();
        let payload = ResourcePrincipalGrant {
            kind: "rusty-resource-principal-grant".into(),
            version: 1,
            service_id: "rusty-service".into(),
            origin: "https://rusty.test".into(),
            workspace_id: scope_id.into(),
            resource_kind: "scope".into(),
            resource_id: scope_id.into(),
            scope_id: scope_id.into(),
            owner_person_id: successor.person_id.clone(),
            subject_person_id,
            subject_public_key: subject_key,
            grant_id: "member-grant".into(),
            policy_epoch: 1,
            read_token_hash: URL_SAFE_NO_PAD.encode([7; 32]),
            write_token_hash: URL_SAFE_NO_PAD.encode([8; 32]),
            actions: vec!["read".into(), "write".into()],
            workspace_grant,
            scope_authority: snapshot,
        };
        let envelope: SignedEnvelope<ResourcePrincipalGrant> = serde_json::from_value(
            serde_json::to_value(
                sign_json_envelope(
                    &successor_device_seed,
                    serde_json::to_value(payload.clone()).unwrap(),
                    successor_device_id,
                    SIGNATURE_DOMAIN,
                )
                .unwrap(),
            )
            .unwrap(),
        )
        .unwrap();

        let result = payload.verify(
            &envelope,
            &successor_view.verify().unwrap(),
            "rusty-service",
            "https://rusty.test",
            scope_id,
            true,
            1_800_000_000_000,
        );
        assert!(result.is_ok(), "{result:?}");

        let mut ambiguous = payload.clone();
        ambiguous.workspace_grant = serde_json::from_value(
            serde_json::to_value(
                sign_json_envelope(
                    &old_device_seed,
                    serde_json::to_value(WorkspaceGrantPayload {
                        kind: "workspace-grant".into(),
                        version: 1,
                        grant_id: "member-grant".into(),
                        workspace_id: scope_id.into(),
                        person_id: ambiguous.subject_person_id.clone(),
                        role: WorkspaceRole::Editor,
                        access_epoch: Some(1),
                        automation: None,
                    })
                    .unwrap(),
                    public_key_id(&public_key_from_seed(&old_device_seed).unwrap()).unwrap(),
                    SIGNATURE_DOMAIN,
                )
                .unwrap(),
            )
            .unwrap(),
        )
        .unwrap();
        let ambiguous_envelope: SignedEnvelope<ResourcePrincipalGrant> = serde_json::from_value(
            serde_json::to_value(
                sign_json_envelope(
                    &successor_device_seed,
                    serde_json::to_value(ambiguous.clone()).unwrap(),
                    public_key_id(&public_key_from_seed(&successor_device_seed).unwrap()).unwrap(),
                    SIGNATURE_DOMAIN,
                )
                .unwrap(),
            )
            .unwrap(),
        )
        .unwrap();
        assert!(
            ambiguous
                .verify(
                    &ambiguous_envelope,
                    &successor_view.verify().unwrap(),
                    "rusty-service",
                    "https://rusty.test",
                    scope_id,
                    true,
                    1_800_000_000_000,
                )
                .is_err(),
            "a reused app key cannot make historical grant ownership ambiguous"
        );

        let rogue_root_seed = [66; 32];
        let (rogue, _) = scope_identity(66, &[]);
        let mut forged = payload.clone();
        forged.workspace_grant = serde_json::from_value(
            serde_json::to_value(
                sign_json_envelope(
                    &rogue_root_seed,
                    serde_json::to_value(WorkspaceGrantPayload {
                        kind: "workspace-grant".into(),
                        version: 1,
                        grant_id: "member-grant".into(),
                        workspace_id: scope_id.into(),
                        person_id: forged.subject_person_id.clone(),
                        role: WorkspaceRole::Editor,
                        access_epoch: Some(1),
                        automation: None,
                    })
                    .unwrap(),
                    rogue.person_id,
                    SIGNATURE_DOMAIN,
                )
                .unwrap(),
            )
            .unwrap(),
        )
        .unwrap();
        let forged_envelope: SignedEnvelope<ResourcePrincipalGrant> = serde_json::from_value(
            serde_json::to_value(
                sign_json_envelope(
                    &successor_device_seed,
                    serde_json::to_value(forged.clone()).unwrap(),
                    public_key_id(&public_key_from_seed(&successor_device_seed).unwrap()).unwrap(),
                    SIGNATURE_DOMAIN,
                )
                .unwrap(),
            )
            .unwrap(),
        )
        .unwrap();
        assert!(
            forged
                .verify(
                    &forged_envelope,
                    &successor_view.verify().unwrap(),
                    "rusty-service",
                    "https://rusty.test",
                    scope_id,
                    true,
                    1_800_000_000_000,
                )
                .is_err()
        );
    }

    #[test]
    fn verifies_two_root_signed_identity_succession_bound_to_current_view() {
        const ROOT_SUCCESSION_DOMAIN: &str = "MESH-IDENTITY-ROOT-SUCCESSION/1";
        let previous_seed = [81; 32];
        let successor_seed = [82; 32];
        let previous_key = public_key_from_seed(&previous_seed).unwrap();
        let successor_key = public_key_from_seed(&successor_seed).unwrap();
        let previous_identity = PublicIdentity {
            person_id: public_key_id(&previous_key).unwrap(),
            public_key: previous_key,
            display_name: String::new(),
        };
        let successor_identity = PublicIdentity {
            person_id: public_key_id(&successor_key).unwrap(),
            public_key: successor_key,
            display_name: String::new(),
        };
        let previous_view =
            test_authority_view_with_devices(&previous_identity, &previous_seed, &[(83, true)]);
        let successor_view =
            test_authority_view_with_devices(&successor_identity, &successor_seed, &[(84, false)]);
        let authorization: SignedEnvelope<IdentityRootSuccessionAuthorization> =
            serde_json::from_value(
                serde_json::to_value(
                    sign_json_envelope(
                        &previous_seed,
                        serde_json::to_value(IdentityRootSuccessionAuthorization {
                            kind: "mesh-identity-root-succession".into(),
                            version: 1,
                            succession_id: URL_SAFE_NO_PAD.encode(rand::random::<[u8; 32]>()),
                            previous_person_id: previous_identity.person_id.clone(),
                            previous_identity_public_key: previous_identity.public_key.clone(),
                            successor_person_id: successor_identity.person_id.clone(),
                            successor_identity_public_key: successor_identity.public_key.clone(),
                            authority_head: previous_view.revocation_head.clone(),
                            authority_view_digest: previous_view.view_digest.clone(),
                        })
                        .unwrap(),
                        previous_identity.person_id.clone(),
                        ROOT_SUCCESSION_DOMAIN,
                    )
                    .unwrap(),
                )
                .unwrap(),
            )
            .unwrap();
        let succession_hash = canonical_hash(&authorization).unwrap();
        let acceptance: SignedEnvelope<IdentityRootSuccessionAcceptance> = serde_json::from_value(
            serde_json::to_value(
                sign_json_envelope(
                    &successor_seed,
                    serde_json::to_value(IdentityRootSuccessionAcceptance {
                        kind: "mesh-identity-root-succession-acceptance".into(),
                        version: 1,
                        succession_hash,
                        previous_person_id: previous_identity.person_id.clone(),
                        successor_person_id: successor_identity.person_id.clone(),
                    })
                    .unwrap(),
                    public_key_id(&successor_identity.public_key).unwrap(),
                    ROOT_SUCCESSION_DOMAIN,
                )
                .unwrap(),
            )
            .unwrap(),
        )
        .unwrap();
        let succession = IdentityRootSuccession {
            authorization,
            acceptance,
        };
        let actor_device_id = public_key_id(&public_key_from_seed(&[84; 32]).unwrap()).unwrap();
        let service_id = "rusty-service";
        let origin = "https://rusty.test";
        let request_hash = canonical_hash(&json!({
            "version": 1,
            "succession": &succession,
            "actorDeviceId": &actor_device_id,
        }))
        .unwrap();
        let request = IdentityRootSuccessionRequest {
            version: 1,
            succession: succession.clone(),
            actor_device_id: actor_device_id.clone(),
            actor_authorization: serde_json::from_value(
                serde_json::to_value(
                    sign_json_envelope(
                        &[84; 32],
                        serde_json::to_value(IdentityRootSuccessionRequestAuthorization {
                            kind: "rusty-identity-root-succession-request".into(),
                            version: 1,
                            service_id: service_id.into(),
                            origin: origin.into(),
                            previous_person_id: previous_identity.person_id.clone(),
                            successor_person_id: successor_identity.person_id.clone(),
                            transition_hash: canonical_hash(&succession).unwrap(),
                            actor_device_id: actor_device_id.clone(),
                            request_id: URL_SAFE_NO_PAD.encode(rand::random::<[u8; 32]>()),
                            issued_at: 1_800_000_000_000,
                            expires_at: 1_800_000_100_000,
                            request_hash,
                        })
                        .unwrap(),
                        actor_device_id.clone(),
                        SIGNATURE_DOMAIN,
                    )
                    .unwrap(),
                )
                .unwrap(),
            )
            .unwrap(),
        };
        let verified = request
            .verify(
                &previous_view,
                &successor_view,
                service_id,
                origin,
                1_800_000_050_000,
            )
            .unwrap();
        assert_eq!(
            verified.authorization_hash,
            canonical_hash(&request.succession.authorization).unwrap()
        );
        assert_eq!(
            verified.transition_hash,
            canonical_hash(&request.succession).unwrap()
        );
        let mut stale_previous_view = previous_view.clone();
        stale_previous_view.view_digest = URL_SAFE_NO_PAD.encode([9; 32]);
        assert!(
            request
                .verify(
                    &stale_previous_view,
                    &successor_view,
                    service_id,
                    origin,
                    1_800_000_050_000,
                )
                .is_err()
        );
    }
}
