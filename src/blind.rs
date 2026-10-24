//! Durable opaque object replication. This module never loads application documents.
use crate::identity_authority::{
    AUTHORITY_REQUEST_TTL_MS, AuthorityReceiptPayload, AuthorityStatusPayload,
    AuthorityUpdateRequest, EnforcementMarkerPayload, EnforcementState, IdentityRequestProof,
    IdentityRootSuccessionReceiptPayload, IdentityRootSuccessionRequest,
    IdentityRootSuccessionStatusPayload, IdentityRootSuccessionTargetReceipt,
    RecentAuthorityUpdate, RecentScopeAuthorityUpdate, ResourcePrincipalGrantRequest,
    ResourcePrincipalRevocationReceiptPayload, ResourcePrincipalRevocationRequest,
    SIGNATURE_DOMAIN, ScopeAuthorityReceiptPayload, ScopeAuthorityStatusPayload,
    ScopeAuthorityUpdateAuthorization, ScopeAuthorityUpdateRequest, ScopePurposeReceiptPayload,
    ScopePurposeUpdateAuthorization, ScopePurposeUpdateRequest, StoredIdentityAuthority,
    StoredIdentityRootSuccession, StoredResourcePrincipalGrant, StoredResourcePrincipalRevocation,
    StoredScopeAuthority, authority_view_hash, certificate_chain, scope_authority_snapshot_hash,
    scope_authority_status_request_hash, status_request_hash, valid_nonce,
};
use crate::telemetry::{Level, Telemetry};
use axum::{
    Json, Router,
    body::{Body, to_bytes},
    extract::{DefaultBodyLimit, Path as RoutePath, Query, State},
    http::{HeaderMap, Request, StatusCode},
    middleware::{Next, from_fn_with_state},
    response::{IntoResponse, Response},
    routing::{get, put},
};
use base64::{
    Engine,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use hmac::{Hmac, Mac};
use meta_mesh_core::{
    DeviceCertificate, PublicIdentity, SignedEnvelope, WorkspaceGrant, WorkspaceRole,
    canonicalize_json, public_key_from_seed, public_key_id, sign_json_envelope,
    verify_device_certificate_chain, verify_signed_envelope, verify_workspace_grant,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::{HashMap, HashSet},
    fs::{self, File, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    time::{SystemTime, UNIX_EPOCH},
};
use tower_http::cors::CorsLayer;
#[cfg(test)]
#[path = "archive_tests.rs"]
mod archive_tests;
#[path = "archives.rs"]
mod archives;
#[path = "blobs.rs"]
mod blobs;
#[path = "checkpoint.rs"]
mod checkpoint;
#[path = "management.rs"]
mod management;

pub const DOMAIN: &str = "RUSTY/2";
const MAX_OBJECT_BYTES: usize = 16 * 1024 * 1024;
const MAX_PUBLICATION_BYTES: usize = 2 * 1024 * 1024;
const MAX_SCOPE_BYTES: u64 = 1024 * 1024 * 1024;
const MAX_SCOPE_OBJECTS: usize = 10_000;
const ENROLLMENT_CHALLENGE_TTL_MS: u64 = 120_000;
const MAX_PENDING_CHALLENGES: usize = 128;
const MAX_PENDING_CHALLENGES_PER_SCOPE: usize = 8;
const MAX_SAFE_JS_INTEGER: u64 = 9_007_199_254_740_991;
const CHECKPOINT_GENERATION_REQUIRED: &str =
    "checkpoint generation required; refresh storage inventory before uploading new objects";

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
fn valid_scope_purpose(value: &str) -> bool {
    matches!(value, "workspace" | "person-identity")
}
fn scope_snapshot_contains(
    candidate: &meta_mesh_core::ScopeAuthoritySnapshot,
    accepted: &meta_mesh_core::ScopeAuthoritySnapshot,
) -> bool {
    candidate.genesis == accepted.genesis
        && accepted
            .grants
            .iter()
            .all(|record| candidate.grants.contains(record))
        && accepted
            .grant_issuers
            .iter()
            .all(|record| candidate.grant_issuers.contains(record))
        && accepted
            .revocations
            .iter()
            .all(|record| candidate.revocations.contains(record))
        && accepted
            .control_transfers
            .iter()
            .all(|record| candidate.control_transfers.contains(record))
        && accepted.succession_transfers.iter().all(|record| {
            candidate
                .succession_transfers
                .iter()
                .find(|current| {
                    current.from_control_epoch == record.from_control_epoch
                        && current.claim == record.claim
                })
                .is_some_and(|current| {
                    record
                        .revocations
                        .iter()
                        .all(|revocation| current.revocations.contains(revocation))
                })
        })
}
fn validate_writer_version(version: u8) -> Result<(), String> {
    if matches!(version, 1 | 2) {
        Ok(())
    } else {
        Err("Unsupported writer version".into())
    }
}
fn require_writer_version(policy: &ScopePolicy, writer_version: u8) -> Result<(), String> {
    validate_writer_version(writer_version)?;
    if writer_version < policy.minimum_writer_version {
        return Err("Writer upgrade required".into());
    }
    Ok(())
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct WriterQuery {
    #[serde(default = "legacy_writer_version")]
    writer_version: u8,
    #[serde(default)]
    observed_sequence: u64,
}
fn exact_keys(value: &Value, expected: &[&str]) -> bool {
    value.as_object().is_some_and(|object| {
        object.len() == expected.len() && expected.iter().all(|key| object.contains_key(*key))
    })
}
fn exact_keys_with_optional(value: &Value, required: &[&str], optional: &[&str]) -> bool {
    value.as_object().is_some_and(|object| {
        required.iter().all(|key| object.contains_key(*key))
            && object
                .keys()
                .all(|key| required.contains(&key.as_str()) || optional.contains(&key.as_str()))
    })
}
fn optional_management_revision(value: &Value) -> Result<Option<u64>, String> {
    match value.get("managementRevision") {
        None => Ok(None),
        Some(revision) => revision
            .as_u64()
            .map(Some)
            .ok_or_else(|| "Invalid management revision".into()),
    }
}
fn public_string(value: &Value, max: usize) -> bool {
    value
        .as_str()
        .is_some_and(|text| text.encode_utf16().count() <= max)
}
fn valid_public_avatar_data(value: &Value) -> bool {
    let Some(data) = value.as_str() else {
        return false;
    };
    let Some((mime, encoded)) = data.split_once(",") else {
        return false;
    };
    if data.len() > 22_000 || !matches!(mime, "data:image/webp;base64" | "data:image/jpeg;base64") {
        return false;
    }
    let Ok(bytes) = STANDARD.decode(encoded) else {
        return false;
    };
    if bytes.len() > 16 * 1024 {
        return false;
    }
    if mime == "data:image/webp;base64" {
        bytes.len() >= 30 && &bytes[..4] == b"RIFF" && &bytes[8..12] == b"WEBP"
    } else {
        bytes.len() >= 4 && bytes[0..2] == [0xff, 0xd8] && bytes[bytes.len() - 2..] == [0xff, 0xd9]
    }
}
fn public_rank(value: &Value) -> bool {
    let Some(rank) = value.as_str().filter(|rank| rank.len() <= 128) else {
        return false;
    };
    let Some((numerator, denominator)) = rank.split_once('/') else {
        return false;
    };
    if denominator.contains('/') {
        return false;
    }
    let (Ok(numerator), Ok(denominator)) = (numerator.parse::<i128>(), denominator.parse::<i128>())
    else {
        return false;
    };
    if denominator <= 0 {
        return false;
    }
    let mut left = numerator.unsigned_abs();
    let mut right = denominator as u128;
    while right != 0 {
        let next = left % right;
        left = right;
        right = next;
    }
    if numerator == 0 {
        denominator == 1
    } else {
        left == 1
    }
}
fn validate_public_presentation(
    value: &Value,
    columns: &HashSet<String>,
    visible_ids: &HashSet<String>,
) -> Result<(), String> {
    if !exact_keys_with_optional(
        value,
        &[],
        &[
            "entityName",
            "archiveColumnId",
            "preset",
            "cardStageButtons",
            "cardAgingPolicy",
            "cardPresentation",
        ],
    ) || value
        .get("entityName")
        .is_some_and(|name| !public_string(name, 100) || name.as_str().unwrap_or("").is_empty())
    {
        return Err("Invalid public presentation".into());
    }
    if value
        .get("archiveColumnId")
        .is_some_and(|id| !id.is_null() && !id.as_str().is_some_and(|id| columns.contains(id)))
    {
        return Err("Invalid public archive column binding".into());
    }
    if let Some(config) = value.get("cardPresentation") {
        if !exact_keys_with_optional(
            config,
            &[],
            &[
                "openAfterSave",
                "titleFieldIds",
                "summaryFieldIds",
                "narrativeFieldId",
            ],
        ) || config
            .get("openAfterSave")
            .is_some_and(|flag| !flag.is_boolean())
        {
            return Err("Invalid public card presentation".into());
        }
        for key in ["titleFieldIds", "summaryFieldIds"] {
            if let Some(value) = config.get(key) {
                let ids = value
                    .as_array()
                    .filter(|ids| ids.len() <= 200)
                    .ok_or("Invalid public card field list")?;
                if ids
                    .iter()
                    .any(|id| !id.as_str().is_some_and(|id| visible_ids.contains(id)))
                {
                    return Err("Public card field is outside publication".into());
                }
            }
        }
        if config
            .get("narrativeFieldId")
            .is_some_and(|id| !id.as_str().is_some_and(|id| visible_ids.contains(id)))
        {
            return Err("Public narrative field is outside publication".into());
        }
    }
    if let Some(preset) = value.get("preset").filter(|preset| !preset.is_null()) {
        if !exact_keys(preset, &["key", "version", "bindings"])
            || !preset["key"]
                .as_str()
                .is_some_and(|key| !key.is_empty() && key.encode_utf16().count() <= 128)
            || preset["version"] != 1
        {
            return Err("Invalid public preset".into());
        }
        let bindings = preset["bindings"]
            .as_object()
            .ok_or("Invalid public bindings")?;
        if bindings.iter().any(|(key, id)| {
            key.encode_utf16().count() > 128
                || !id.as_str().is_some_and(|id| visible_ids.contains(id))
        }) {
            return Err("Public binding is outside publication".into());
        }
    }
    if let Some(buttons) = value.get("cardStageButtons") {
        let buttons = buttons
            .as_array()
            .filter(|buttons| buttons.len() <= 100)
            .ok_or("Invalid public stage buttons")?;
        if buttons.iter().any(|button| {
            !exact_keys_with_optional(button, &["columnId"], &["label"])
                || !button["columnId"]
                    .as_str()
                    .is_some_and(|id| columns.contains(id))
                || button.get("label").is_some_and(|label| {
                    !public_string(label, 4096) || label.as_str().unwrap_or("").is_empty()
                })
        }) {
            return Err("Invalid public stage button".into());
        }
    }
    if let Some(policy) = value.get("cardAgingPolicy") {
        if !exact_keys(policy, &["version", "thresholds"])
            || policy["version"] != 1
            || !exact_keys(&policy["thresholds"], &["watch", "aged", "overdue"])
        {
            return Err("Invalid public card aging".into());
        }
        let t = &policy["thresholds"];
        let (Some(watch), Some(aged), Some(overdue)) = (
            t["watch"].as_u64(),
            t["aged"].as_u64(),
            t["overdue"].as_u64(),
        ) else {
            return Err("Invalid public card aging thresholds".into());
        };
        if watch == 0 || watch >= aged || aged >= overdue {
            return Err("Invalid public card aging thresholds".into());
        }
    }
    Ok(())
}

#[derive(Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PublicBoardDeliveryPolicy {
    kind: String,
    version: u8,
    workspace_id: String,
    board_id: String,
    generation: u64,
    access_epoch: u64,
    enabled: bool,
    accepted_grants: Vec<WorkspaceGrant>,
    revoked_grant_ids: Vec<String>,
    revoked_device_ids: Vec<String>,
}

#[derive(Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PublicBoardDeliveryPolicyEvidence {
    policy: SignedEnvelope<PublicBoardDeliveryPolicy>,
    owner_certificates: Vec<DeviceCertificate>,
}

// A verified policy's meaning must not depend on randomized signature bytes.
// The existing wire hash still binds the exact signed command and receipt.
fn public_delivery_policy_content_hash(
    evidence: &PublicBoardDeliveryPolicyEvidence,
) -> Result<String, String> {
    let value = json!({
        "policy": {
            "payload": evidence.policy.payload,
            "signerKeyId": evidence.policy.signer_key_id,
        },
        "ownerCertificates": evidence.owner_certificates,
    });
    canonicalize_json(&value).map(|canonical| digest(canonical.as_bytes()))
}

fn validate_public_board_delivery_policy(
    evidence: &PublicBoardDeliveryPolicyEvidence,
    owner: &ResourceOwner,
    board_id: &str,
    expected_generation: Option<u64>,
    now: u64,
) -> Result<(), String> {
    let policy = &evidence.policy;
    let payload = &policy.payload;
    let owner_identity = &owner.identity;
    if payload.kind != "rusty-public-board-delivery-policy"
        || payload.version != 1
        || payload.workspace_id.is_empty()
        || payload.workspace_id.len() > 128
        || payload.board_id != board_id
        || payload.generation == 0
        || payload.access_epoch == 0
        || !payload.enabled
        || payload.accepted_grants.len() > 1024
        || payload.revoked_grant_ids.len() > 4096
        || payload.revoked_device_ids.len() > 4096
        || expected_generation
            .is_some_and(|current| current.checked_add(1) != Some(payload.generation))
    {
        return Err("Invalid public delivery policy".into());
    }

    let signer_key = if verify_signed_envelope(policy, &owner_identity.public_key, "MATCH/1")? {
        owner_identity.public_key.clone()
    } else {
        let key = verify_device_certificate_chain(
            owner_identity,
            &policy.signer_key_id,
            &evidence.owner_certificates,
            "MATCH/1",
        )?;
        if !verify_signed_envelope(policy, &key, "MATCH/1")? {
            return Err("Invalid public delivery policy signature".into());
        }
        key
    };
    if public_key_id(&signer_key)? != policy.signer_key_id {
        return Err("Public delivery policy signer mismatch".into());
    }

    let revoked_grants = payload.revoked_grant_ids.iter().collect::<HashSet<_>>();
    let revoked_devices = payload.revoked_device_ids.iter().collect::<HashSet<_>>();
    if revoked_grants.len() != payload.revoked_grant_ids.len()
        || revoked_devices.len() != payload.revoked_device_ids.len()
        || payload.revoked_grant_ids.iter().any(String::is_empty)
        || payload.revoked_device_ids.iter().any(String::is_empty)
    {
        return Err("Invalid public delivery policy revocations".into());
    }
    let mut grant_ids = HashSet::new();
    for grant in &payload.accepted_grants {
        let grant_payload = &grant.payload;
        let role = verify_workspace_grant(
            grant,
            &payload.workspace_id,
            &grant_payload.person_id,
            owner_identity,
            &evidence.owner_certificates,
        )?;
        if !matches!(role, WorkspaceRole::Editor | WorkspaceRole::Automation)
            || grant_payload.effective_access_epoch() != payload.access_epoch
            || !grant_ids.insert(grant_payload.grant_id.as_str())
            || revoked_grants.contains(&grant_payload.grant_id)
            || grant_payload
                .automation
                .as_ref()
                .is_some_and(|scope| scope.board_id != board_id || scope.expires_at <= now)
        {
            return Err("Invalid public delivery grant".into());
        }
    }
    Ok(())
}

fn validate_source_heads(source_heads: &[String]) -> Result<String, String> {
    if source_heads.is_empty()
        || source_heads.len() > 256
        || source_heads.iter().any(|head| {
            head.len() != 64
                || !head
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        })
        || source_heads.windows(2).any(|pair| pair[0] >= pair[1])
    {
        return Err("Invalid public source heads".into());
    }
    let bytes = serde_json::to_vec(source_heads).map_err(|_| "Invalid public source heads")?;
    Ok(digest(&bytes))
}

fn authorize_public_delivery_writer(
    publication: &PublicPublication,
    owner: &ResourceOwner,
    board_id: &str,
    identity: &PublicIdentity,
    device_id: &str,
    certificates: &[DeviceCertificate],
    grant: &WorkspaceGrant,
    source_heads: &[String],
    now: u64,
) -> Result<PublicDeliveryBinding, String> {
    let evidence = publication
        .delivery_policy
        .as_ref()
        .ok_or("Public delivery policy unavailable")?;
    validate_public_board_delivery_policy(evidence, owner, board_id, None, now)?;
    let policy = &evidence.policy.payload;
    if !policy.enabled
        || publication.withdrawn
        || !valid_id(device_id)
        || policy.revoked_device_ids.iter().any(|id| id == device_id)
    {
        return Err("Public delivery writer is not authorized".into());
    }
    let device_key = verify_device_certificate_chain(identity, device_id, certificates, "MATCH/1")?;
    if public_key_id(&device_key)? != device_id {
        return Err("Public delivery device mismatch".into());
    }
    let grant_payload = &grant.payload;
    let accepted = policy
        .accepted_grants
        .iter()
        .any(|accepted| accepted == grant);
    let role = verify_workspace_grant(
        grant,
        &policy.workspace_id,
        &identity.person_id,
        &owner.identity,
        &evidence.owner_certificates,
    )?;
    if !accepted
        || grant_payload.person_id != identity.person_id
        || !matches!(role, WorkspaceRole::Editor | WorkspaceRole::Automation)
        || grant_payload.effective_access_epoch() != policy.access_epoch
        || policy
            .revoked_grant_ids
            .iter()
            .any(|id| id == &grant_payload.grant_id)
        || grant_payload
            .automation
            .as_ref()
            .is_some_and(|scope| scope.board_id != board_id || scope.expires_at <= now)
    {
        return Err("Public delivery writer is not authorized".into());
    }
    let source_heads_hash = validate_source_heads(source_heads)?;
    Ok(PublicDeliveryBinding {
        generation: policy.generation,
        grant_id: grant_payload.grant_id.clone(),
        role,
        source_heads: source_heads.to_vec(),
        source_heads_hash,
    })
}

fn automation_board_entities(projection: &Value) -> Result<Value, String> {
    let board = projection
        .get("board")
        .and_then(Value::as_object)
        .ok_or("Invalid public board for automation")?;
    let board_id = board
        .get("id")
        .and_then(Value::as_str)
        .ok_or("Invalid public board for automation")?;
    let archive_column = board
        .get("presentation")
        .and_then(|presentation| presentation.get("archiveColumnId"))
        .filter(|value| !value.is_null());
    let mut entities = serde_json::Map::new();
    entities.insert(
        board_id.to_owned(),
        json!({"id":board_id,"kind":"board","archivedAt":null,
            "archiveColumnId":archive_column.cloned().unwrap_or(Value::Null)}),
    );
    for column in projection["columns"]
        .as_array()
        .ok_or("Invalid public board columns for automation")?
    {
        let id = column["id"]
            .as_str()
            .ok_or("Invalid public column for automation")?;
        entities.insert(
            id.to_owned(),
            json!({"id":id,"kind":"column","archivedAt":null,
                "placement":{"parentId":board_id,"rank":column["rank"]}}),
        );
    }
    for field in projection["fields"]
        .as_array()
        .ok_or("Invalid public board fields for automation")?
    {
        let id = field["id"]
            .as_str()
            .ok_or("Invalid public field for automation")?;
        entities.insert(
            id.to_owned(),
            json!({"id":id,"kind":"field",
                "placement":{"parentId":board_id,"rank":field["rank"]}}),
        );
    }
    for card in projection["cards"]
        .as_array()
        .ok_or("Invalid public board cards for automation")?
    {
        let id = card["id"]
            .as_str()
            .ok_or("Invalid public card for automation")?;
        let column_id = card["columnId"]
            .as_str()
            .ok_or("Invalid public card column for automation")?;
        let parent = card["parentId"].as_str().unwrap_or(column_id);
        let is_archived = archive_column.is_some_and(|archive| archive.as_str() == Some(column_id));
        entities.insert(
            id.to_owned(),
            json!({"id":id,"title":card["title"],"body":card["body"],
                "values":card["values"],"archivedAt":if is_archived {json!("public-archive")} else {Value::Null},
                "placement":{"parentId":parent,"rank":card["rank"]}}),
        );
    }
    Ok(json!({"entities":entities}))
}

fn validate_automation_publication_delta(
    before: &Value,
    after: &Value,
    board_id: &str,
    scope: &meta_mesh_core::AutomationGrantScope,
) -> Result<(), String> {
    for key in ["board", "columns", "fields", "discussions", "files"] {
        if before.get(key) != after.get(key) {
            return Err(format!("Automation cannot change public {key}"));
        }
    }
    if before["board"]["id"] != board_id || after["board"]["id"] != board_id {
        return Err("Automation board does not match delivery policy".into());
    }
    let before_entities = automation_board_entities(before)?;
    let after_entities = automation_board_entities(after)?;
    meta_mesh_core::validate_automation_board_transitions(&before_entities, &after_entities, scope)
}

fn validate_public_projection(value: &Value) -> Result<(), String> {
    if !exact_keys_with_optional(
        value,
        &[
            "kind",
            "version",
            "board",
            "columns",
            "fields",
            "cards",
            "discussions",
            "files",
        ],
        &["discussionAuthors"],
    ) || value["kind"] != "tincanban-public-board"
        || value["version"] != 1
        || !exact_keys_with_optional(&value["board"], &["id", "title"], &["presentation"])
        || !valid_id(value["board"]["id"].as_str().unwrap_or(""))
        || !public_string(&value["board"]["title"], 4096)
    {
        return Err("Invalid public projection envelope".into());
    }
    let columns = value["columns"]
        .as_array()
        .ok_or("Invalid public columns")?;
    let fields = value["fields"].as_array().ok_or("Invalid public fields")?;
    let cards = value["cards"].as_array().ok_or("Invalid public cards")?;
    if columns.len() > 100 || fields.len() > 200 || cards.len() > 5000 {
        return Err("Public projection collection limit exceeded".into());
    }
    let mut ids = HashSet::new();
    ids.insert(value["board"]["id"].as_str().unwrap().to_owned());
    let mut author_ids = HashSet::new();
    if let Some(authors) = value.get("discussionAuthors") {
        let authors = authors
            .as_array()
            .ok_or("Invalid public discussion authors")?;
        if authors.len() > 128 {
            return Err("Public projection collection limit exceeded".into());
        }
        for author in authors {
            if !exact_keys_with_optional(author, &["id"], &["avatarData"])
                || !valid_id(author["id"].as_str().unwrap_or(""))
                || !author_ids.insert(author["id"].as_str().unwrap().to_owned())
                || !ids.insert(author["id"].as_str().unwrap().to_owned())
                || author
                    .get("avatarData")
                    .is_some_and(|avatar| !valid_public_avatar_data(avatar))
            {
                return Err("Invalid public discussion author".into());
            }
        }
    }
    let mut column_ids = HashSet::new();
    let mut archive_column_ids = HashSet::new();
    for column in columns {
        if !exact_keys_with_optional(
            column,
            &["id", "title", "rank"],
            &["color", "collapsible", "archive"],
        ) || column.get("color").is_some_and(|color| {
            !color.as_str().is_some_and(|color| {
                color.len() == 7
                    && color.starts_with('#')
                    && color[1..].bytes().all(|byte| byte.is_ascii_hexdigit())
            })
        }) || column
            .get("collapsible")
            .is_some_and(|value| !value.is_boolean())
            || column.get("archive").is_some_and(|value| value != true)
            || !valid_id(column["id"].as_str().unwrap_or(""))
            || !public_string(&column["title"], 4096)
            || !public_rank(&column["rank"])
            || !ids.insert(column["id"].as_str().unwrap().to_owned())
        {
            return Err("Invalid or duplicate public column".into());
        }
        let id = column["id"].as_str().unwrap().to_owned();
        if column.get("archive") == Some(&Value::Bool(true)) {
            archive_column_ids.insert(id.clone());
        }
        column_ids.insert(id);
    }
    if archive_column_ids.len() > 1 {
        return Err("Public projection has multiple archive columns".into());
    }
    let mut field_ids = HashSet::new();
    let mut field_definitions: HashMap<String, (String, HashSet<String>)> = HashMap::new();
    for field in fields {
        if !exact_keys_with_optional(
            field,
            &["id", "title", "valueType", "required", "rank", "options"],
            &["min", "max", "format"],
        ) || ["min", "max"].iter().any(|key| {
            field.get(*key).is_some_and(|value| {
                !value.is_null() && !value.as_f64().is_some_and(f64::is_finite)
            })
        }) || !valid_id(field["id"].as_str().unwrap_or(""))
            || !public_string(&field["title"], 4096)
            || !public_rank(&field["rank"])
            || !field["required"].is_boolean()
            || !ids.insert(field["id"].as_str().unwrap().to_owned())
        {
            return Err("Invalid or duplicate public field".into());
        }
        let value_type = field["valueType"].as_str().unwrap_or("");
        if ![
            "text", "url", "date", "datetime", "boolean", "number", "select",
        ]
        .contains(&value_type)
        {
            return Err("Invalid public field type".into());
        }
        if let Some(format) = field.get("format") {
            if value_type != "text"
                || !matches!(
                    format.as_str(),
                    Some("plain" | "markdown" | "json" | "code")
                )
            {
                return Err("Invalid public text field format".into());
            }
        }
        let options = field["options"]
            .as_array()
            .ok_or("Invalid public field options")?;
        if options.len() > 200 || value_type != "select" && !options.is_empty() {
            return Err("Invalid public field options".into());
        }
        let mut options_seen = HashSet::new();
        for option in options {
            if !exact_keys(option, &["id", "title", "rank"])
                || !valid_id(option["id"].as_str().unwrap_or(""))
                || !public_string(&option["title"], 4096)
                || !public_rank(&option["rank"])
                || !ids.insert(option["id"].as_str().unwrap().to_owned())
                || !options_seen.insert(option["id"].as_str().unwrap().to_owned())
            {
                return Err("Invalid or duplicate public field option".into());
            }
        }
        field_definitions.insert(
            field["id"].as_str().unwrap().to_owned(),
            (value_type.to_owned(), options_seen),
        );
        field_ids.insert(field["id"].as_str().unwrap().to_owned());
    }
    if let Some(presentation) = value["board"].get("presentation") {
        let mut presentation_ids = ids.clone();
        presentation_ids.remove(value["board"]["id"].as_str().unwrap());
        validate_public_presentation(presentation, &column_ids, &presentation_ids)?;
    }
    let archive_column_binding = value["board"]["presentation"].get("archiveColumnId");
    match (archive_column_binding, archive_column_ids.iter().next()) {
        (Some(Value::String(id)), Some(marker)) if id == marker => {}
        (None, None) | (Some(Value::Null), None) => {}
        _ => return Err("Public archive column binding is inconsistent".into()),
    }
    let mut cards_seen: HashMap<String, (Option<String>, String)> = HashMap::new();
    for card in cards {
        if !exact_keys_with_optional(
            card,
            &[
                "id", "parentId", "columnId", "title", "body", "values", "rank",
            ],
            &["createdAt", "updatedAt", "lastActivityAt"],
        ) || ["createdAt", "updatedAt", "lastActivityAt"]
            .iter()
            .any(|key| {
                card.get(*key)
                    .is_some_and(|value| !public_string(value, 128))
            })
            || !valid_id(card["id"].as_str().unwrap_or(""))
            || !valid_id(card["columnId"].as_str().unwrap_or(""))
            || !column_ids.contains(card["columnId"].as_str().unwrap_or(""))
            || !public_string(&card["title"], 4096)
            || !public_string(&card["body"], 200_000)
            || !public_rank(&card["rank"])
            || !ids.insert(card["id"].as_str().unwrap().to_owned())
        {
            return Err("Invalid or duplicate public card".into());
        }
        let parent = match &card["parentId"] {
            Value::Null => None,
            Value::String(value) if valid_id(value) => Some(value.clone()),
            _ => return Err("Invalid public card parent".into()),
        };
        if archive_column_ids.contains(card["columnId"].as_str().unwrap()) && parent.is_some() {
            return Err("Archived public cards must be roots".into());
        }
        let values = card["values"]
            .as_object()
            .ok_or("Invalid public card values")?;
        if values.len() > field_ids.len()
            || values.iter().any(|(key, value)| {
                let Some((kind, options)) = field_definitions.get(key) else {
                    return true;
                };
                if value.is_null() {
                    return false;
                }
                match kind.as_str() {
                    "number" => value.as_number().is_none_or(|number| {
                        number.as_f64().is_none_or(|number| !number.is_finite())
                    }),
                    "boolean" => !value.is_boolean(),
                    "select" => value
                        .as_str()
                        .is_none_or(|option| !options.contains(option)),
                    _ => !value
                        .as_str()
                        .is_some_and(|text| text.encode_utf16().count() <= 200_000),
                }
            })
        {
            return Err("Invalid public card field values".into());
        }
        cards_seen.insert(
            card["id"].as_str().unwrap().to_owned(),
            (parent, card["columnId"].as_str().unwrap().to_owned()),
        );
    }
    for (card_id, (_, column)) in &cards_seen {
        let mut seen = HashSet::new();
        let mut current = Some(card_id.as_str());
        while let Some(id) = current {
            if !seen.insert(id) {
                return Err("Public card hierarchy contains a cycle".into());
            }
            current = cards_seen.get(id).and_then(|(parent, parent_column)| {
                if parent_column != column {
                    Some("__cross_column__")
                } else {
                    parent.as_deref()
                }
            });
            if current == Some("__cross_column__") {
                return Err("Public card parent is in another column".into());
            }
            if current.is_some_and(|id| !cards_seen.contains_key(id)) {
                return Err("Public card parent is missing".into());
            }
        }
    }
    let discussions = value["discussions"]
        .as_array()
        .ok_or("Invalid public discussions")?;
    let files = value["files"].as_array().ok_or("Invalid public files")?;
    if discussions.len() > 2000 || files.len() > 500 {
        return Err("Public projection collection limit exceeded".into());
    }
    let mut total_file_bytes = 0u64;
    let mut discussion_ids = HashSet::new();
    let mut discussion_author_ids = HashSet::new();
    let mut discussion_threads: HashMap<String, (String, Option<String>)> = HashMap::new();
    for discussion in discussions {
        if !exact_keys_with_optional(
            discussion,
            &[
                "id",
                "threadId",
                "replyTo",
                "targets",
                "author",
                "createdAt",
                "body",
            ],
            &["authorId"],
        ) || !valid_id(discussion["id"].as_str().unwrap_or(""))
            || !ids.insert(discussion["id"].as_str().unwrap().to_owned())
            || !valid_id(discussion["threadId"].as_str().unwrap_or(""))
            || !public_string(&discussion["author"], 500)
            || !public_string(&discussion["createdAt"], 128)
            || !public_string(&discussion["body"], 8000)
            || discussion
                .get("authorId")
                .is_some_and(|author| !author.as_str().is_some_and(|id| valid_id(id)))
        {
            return Err("Invalid public discussion".into());
        }
        if let Some(author_id) = discussion["authorId"].as_str() {
            discussion_author_ids.insert(author_id.to_owned());
        }
        if !discussion["replyTo"].is_null()
            && !valid_id(discussion["replyTo"].as_str().unwrap_or(""))
        {
            return Err("Invalid public discussion reply".into());
        }
        let targets = discussion["targets"]
            .as_array()
            .filter(|targets| !targets.is_empty() && targets.len() <= 8)
            .ok_or("Invalid public discussion targets")?;
        for target in targets {
            let Some(target_type) = target["type"].as_str() else {
                return Err("Invalid public discussion target".into());
            };
            let valid = match target_type {
                "board" => {
                    exact_keys(target, &["type", "id"]) && target["id"] == value["board"]["id"]
                }
                "card" => {
                    exact_keys(target, &["type", "id"])
                        && cards_seen.contains_key(target["id"].as_str().unwrap_or(""))
                }
                "field" => {
                    exact_keys(target, &["type", "id", "cardId"])
                        && field_ids.contains(target["id"].as_str().unwrap_or(""))
                        && target
                            .get("cardId")
                            .and_then(Value::as_str)
                            .is_some_and(|id| cards_seen.contains_key(id))
                }
                _ => false,
            };
            if !valid {
                return Err("Public discussion target is outside this board".into());
            }
        }
        discussion_ids.insert(discussion["id"].as_str().unwrap().to_owned());
        discussion_threads.insert(
            discussion["id"].as_str().unwrap().to_owned(),
            (
                discussion["threadId"].as_str().unwrap().to_owned(),
                discussion["replyTo"].as_str().map(str::to_owned),
            ),
        );
    }
    if author_ids
        .iter()
        .any(|id| !discussion_author_ids.contains(id))
    {
        return Err("Public discussion author metadata is not referenced".into());
    }
    for discussion in discussions {
        if discussion["replyTo"]
            .as_str()
            .is_some_and(|id| !discussion_ids.contains(id))
        {
            return Err("Public discussion reply is missing".into());
        }
        let id = discussion["id"].as_str().unwrap();
        let thread = discussion["threadId"].as_str().unwrap();
        let parent = discussion["replyTo"].as_str();
        let root = discussion_threads.get(thread);
        if parent.is_none() && id != thread
            || root.is_none_or(|(root_thread, root_parent)| {
                root_thread != thread || root_parent.is_some()
            })
            || parent.is_some_and(|parent_id| {
                discussion_threads
                    .get(parent_id)
                    .is_none_or(|(parent_thread, _)| parent_thread != thread)
            })
        {
            return Err("Invalid public discussion thread structure".into());
        }
        let mut seen = HashSet::new();
        let mut current = Some(id);
        while let Some(message_id) = current {
            if !seen.insert(message_id) {
                return Err("Public discussion reply cycle".into());
            }
            current = discussion_threads
                .get(message_id)
                .and_then(|(_, parent_id)| parent_id.as_deref());
        }
    }
    let mut file_ids = HashSet::new();
    for file in files {
        if !exact_keys(
            file,
            &[
                "id",
                "parentId",
                "title",
                "fileName",
                "mediaType",
                "byteLength",
                "sha256",
            ],
        ) || !valid_id(file["id"].as_str().unwrap_or(""))
            || !ids.insert(file["id"].as_str().unwrap().to_owned())
            || !valid_id(file["parentId"].as_str().unwrap_or(""))
            || file["parentId"] != value["board"]["id"]
                && !cards_seen.contains_key(file["parentId"].as_str().unwrap_or(""))
            || !public_string(&file["title"], 4096)
            || !public_string(&file["fileName"], 512)
            || !public_string(&file["mediaType"], 256)
            || !file["byteLength"]
                .as_u64()
                .is_some_and(|size| size <= 16 * 1024 * 1024)
            || !file["sha256"].as_str().is_some_and(|hash| {
                hash.len() == 43
                    && hash
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
            })
            || !file_ids.insert(file["id"].as_str().unwrap().to_owned())
        {
            return Err("Invalid public attachment manifest".into());
        }
        total_file_bytes = total_file_bytes
            .checked_add(file["byteLength"].as_u64().unwrap_or(u64::MAX))
            .ok_or("Public attachment total exceeds limit")?;
        if total_file_bytes > 64 * 1024 * 1024 {
            return Err("Public attachment total exceeds limit".into());
        }
    }
    Ok(())
}
fn recover_publication_temps(directory: &Path) -> Result<(), String> {
    let root = directory.join("publications");
    if !root.exists() {
        return Ok(());
    }
    for namespace in ["records", "challenges", "files"] {
        let path = root.join(namespace);
        if !path.exists() {
            continue;
        }
        for entry in fs::read_dir(&path).map_err(|_| "Publication storage unavailable")? {
            let entry = entry.map_err(|_| "Publication storage unavailable")?;
            let name = entry.file_name();
            let name = name.to_str().ok_or("Invalid publication state filename")?;
            if name.strip_prefix(".pending-").is_some_and(|suffix| {
                !suffix.is_empty() && suffix.bytes().all(|byte| byte.is_ascii_digit())
            }) {
                if !entry
                    .file_type()
                    .map_err(|_| "Invalid publication state file")?
                    .is_file()
                {
                    return Err("Invalid publication state file".into());
                }
                fs::remove_file(entry.path()).map_err(|_| "Publication recovery failed")?;
            }
        }
    }
    Ok(())
}
fn cleanup_orphan_public_files(directory: &Path) -> Result<(), String> {
    let root = directory.join("publications");
    let records = root.join("records");
    let files = root.join("files");
    if !records.exists() || !files.exists() {
        return Ok(());
    }
    let mut active = HashSet::new();
    for entry in fs::read_dir(records).map_err(|_| "Publication storage unavailable")? {
        let entry = entry.map_err(|_| "Publication storage unavailable")?;
        if !entry
            .file_type()
            .map_err(|_| "Invalid publication state file")?
            .is_file()
        {
            continue;
        }
        let record: PublicPublication = serde_json::from_slice(
            &fs::read(entry.path()).map_err(|_| "Publication storage unavailable")?,
        )
        .map_err(|_| "Invalid public publication")?;
        if let Some(projection) = record.projection.filter(|_| !record.withdrawn) {
            if let Some(manifest) = projection.get("files").and_then(Value::as_array) {
                for file in manifest {
                    if let Some(hash) = file.get("sha256").and_then(Value::as_str) {
                        active.insert(hash.to_owned());
                    }
                }
            }
        }
    }
    let now = SystemTime::now();
    let mut removed = 0usize;
    for entry in fs::read_dir(&files).map_err(|_| "Publication storage unavailable")? {
        if removed >= 32 {
            break;
        }
        let entry = entry.map_err(|_| "Publication storage unavailable")?;
        if !entry
            .file_type()
            .map_err(|_| "Invalid publication file")?
            .is_file()
        {
            continue;
        }
        let file_name = entry.file_name();
        let Some(hash) = file_name
            .to_str()
            .and_then(|name| name.strip_suffix(".bin"))
        else {
            continue;
        };
        if active.contains(hash) {
            continue;
        }
        let metadata = entry
            .metadata()
            .map_err(|_| "Publication file unavailable")?;
        if now
            .duration_since(metadata.modified().unwrap_or(now))
            .unwrap_or_default()
            .as_secs()
            < 24 * 60 * 60
        {
            continue;
        }
        fs::remove_file(entry.path()).map_err(|_| "Publication cleanup failed")?;
        removed += 1;
    }
    if removed > 0 {
        File::open(files)
            .and_then(|file| file.sync_all())
            .map_err(|_| "Publication durability failed")?;
    }
    Ok(())
}
fn validate_publication_namespace(directory: &Path) -> Result<(), String> {
    let root = directory.join("publications");
    if !root.exists() {
        return Ok(());
    }
    if !fs::symlink_metadata(&root)
        .map_err(|_| "Publication storage unavailable")?
        .file_type()
        .is_dir()
    {
        return Err("Invalid publication storage".into());
    }
    for entry in fs::read_dir(&root).map_err(|_| "Publication storage unavailable")? {
        let entry = entry.map_err(|_| "Publication storage unavailable")?;
        let name = entry.file_name();
        let name = name.to_str().ok_or("Invalid publication storage entry")?;
        if !["records", "challenges", "files"].contains(&name)
            || !entry
                .file_type()
                .map_err(|_| "Invalid publication storage entry")?
                .is_dir()
        {
            return Err("Unknown publication storage entry".into());
        }
        for file in fs::read_dir(entry.path()).map_err(|_| "Publication storage unavailable")? {
            let file = file.map_err(|_| "Publication storage unavailable")?;
            let file_name = file.file_name();
            let file_name = file_name
                .to_str()
                .ok_or("Invalid publication state filename")?;
            if let Some(suffix) = file_name.strip_prefix(".pending-") {
                if !suffix.is_empty()
                    && suffix.bytes().all(|byte| byte.is_ascii_digit())
                    && file
                        .file_type()
                        .map_err(|_| "Invalid publication state file")?
                        .is_file()
                {
                    continue;
                }
            }
            let files_namespace = name == "files";
            let valid_file = if files_namespace {
                file_name.strip_suffix(".bin").is_some_and(|digest| {
                    digest.len() == 43
                        && digest
                            .bytes()
                            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
                })
            } else {
                file_name.ends_with(".json") && valid_id(file_name.trim_end_matches(".json"))
            };
            if !file
                .file_type()
                .map_err(|_| "Invalid publication state file")?
                .is_file()
                || !valid_file
            {
                return Err("Unknown publication state file".into());
            }
        }
    }
    Ok(())
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
    #[serde(default = "legacy_writer_version")]
    minimum_writer_version: u8,
    read_mac: String,
    write_mac: String,
    revoked: bool,
    #[serde(default)]
    owner_person_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    scope_purpose: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    completed_scope_purpose_update: Option<CompletedScopePurposeUpdate>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    completed_enrollment: Option<CompletedScopeEnrollment>,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct CompletedScopeEnrollment {
    request_hash: String,
    receipt: SignedEnvelope<Value>,
}
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct CompletedScopePurposeUpdate {
    request_id: String,
    request_hash: String,
    receipt: SignedEnvelope<Value>,
}
fn legacy_writer_version() -> u8 {
    1
}
// Owner proof for one resource, derived from the request or stored policy.
#[derive(Clone)]
struct ResourceOwner {
    identity: PublicIdentity,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct EnrollmentChallengeRequest {
    version: u8,
    scope_id: String,
    identity: PublicIdentity,
    device_id: String,
    #[serde(default)]
    scope_purpose: Option<String>,
    certificates: Vec<DeviceCertificate>,
    management_capability: Option<SignedEnvelope<Value>>,
}
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ScopeEnrollmentRequest {
    challenge: SignedEnvelope<Value>,
    identity: PublicIdentity,
    device_id: String,
    certificates: Vec<DeviceCertificate>,
    management_capability: Option<SignedEnvelope<Value>>,
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    management_revision: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    minimum_writer_version: Option<u8>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    scope_purpose: Option<String>,
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
#[cfg(test)]
fn set_scope_writer_floor_for_test(store: &BlindStore, scope: &str, minimum_writer_version: u8) {
    let mut policy = store.policy(scope).unwrap();
    policy.minimum_writer_version = minimum_writer_version;
    atomic_write(
        &store.scope_dir(scope).unwrap().join("policy.json"),
        &serde_json::to_vec(&policy).unwrap(),
    )
    .unwrap();
}
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PendingChallenge {
    scope_id: String,
    person_id: String,
    device_id: String,
    #[serde(default)]
    scope_purpose: Option<String>,
    expires_at: u64,
    envelope: SignedEnvelope<Value>,
}

fn scope_enrollment_receipt_payload(
    scope: &str,
    request: &ScopeEnrollmentRequest,
    policy: &ScopePolicy,
    service_id: &str,
) -> Result<Value, String> {
    let authorization = serde_json::to_value(&request.authorization)
        .map_err(|_| "Controller authorization invalid")?;
    let authorization_hash = digest(canonicalize_json(&authorization)?.as_bytes());
    let mut receipt = json!({
        "kind": "rusty-scope-policy-receipt", "version": 1,
        "serviceId": service_id, "scopeId": scope,
        "personId": request.identity.person_id, "revision": policy.revision,
        "revoked": request.revoked,
        "challengeId": request.authorization.payload.challenge_id,
        "authorizationHash": authorization_hash
    });
    if request
        .authorization
        .payload
        .minimum_writer_version
        .is_some()
        || policy.minimum_writer_version > 1
    {
        receipt["minimumWriterVersion"] = json!(policy.minimum_writer_version);
    }
    if let Some(scope_purpose) = request.authorization.payload.scope_purpose.as_deref() {
        receipt["scopePurpose"] = json!(scope_purpose);
    }
    Ok(receipt)
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PublicChallengeRequest {
    version: u8,
    board_id: String,
    identity: PublicIdentity,
    device_id: String,
    certificates: Vec<DeviceCertificate>,
    management_capability: Option<SignedEnvelope<Value>>,
    #[serde(default)]
    delivery_grant: Option<WorkspaceGrant>,
    #[serde(default)]
    source_heads: Option<Vec<String>>,
}
#[derive(Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PendingPublicChallenge {
    board_id: String,
    person_id: String,
    device_id: String,
    expires_at: u64,
    #[serde(default)]
    delivery_generation: Option<u64>,
    #[serde(default)]
    delivery_grant_id: Option<String>,
    #[serde(default)]
    source_heads_hash: Option<String>,
    envelope: SignedEnvelope<Value>,
}
#[derive(Clone)]
struct PublicDeliveryBinding {
    generation: u64,
    grant_id: String,
    role: WorkspaceRole,
    source_heads: Vec<String>,
    source_heads_hash: String,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PublicMutationRequest {
    challenge: SignedEnvelope<Value>,
    identity: PublicIdentity,
    device_id: String,
    certificates: Vec<DeviceCertificate>,
    management_capability: Option<SignedEnvelope<Value>>,
    #[serde(default)]
    delivery_grant: Option<WorkspaceGrant>,
    #[serde(default)]
    source_heads: Option<Vec<String>>,
    #[serde(default)]
    delivery_policy: Option<PublicBoardDeliveryPolicyEvidence>,
    action: String,
    projection: Option<Value>,
    authorization: SignedEnvelope<Value>,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PublicAssetRequest {
    challenge: SignedEnvelope<Value>,
    identity: PublicIdentity,
    device_id: String,
    certificates: Vec<DeviceCertificate>,
    management_capability: Option<SignedEnvelope<Value>>,
    #[serde(default)]
    delivery_grant: Option<WorkspaceGrant>,
    #[serde(default)]
    source_heads: Option<Vec<String>>,
    sha256: String,
    byte_length: u64,
    bytes: String,
    authorization: SignedEnvelope<Value>,
}
#[derive(Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PublicPublication {
    board_id: String,
    controller_person_id: String,
    revision: u64,
    withdrawn: bool,
    projection: Option<Value>,
    projection_hash: String,
    #[serde(default)]
    delivery_policy: Option<PublicBoardDeliveryPolicyEvidence>,
    #[serde(default)]
    source_heads: Vec<String>,
}
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct StoredObject {
    sequence: u64,
    object_id: String,
    object: BlindObject,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    checkpoint: Option<checkpoint::CheckpointMarker>,
}
#[derive(Clone)]
struct ObjectMetadata {
    sequence: u64,
    object_id: String,
}

#[derive(Clone)]
pub struct BlindStore {
    telemetry: Telemetry,
    max_scope_bytes: u64,
    directory: Arc<PathBuf>,
    seed: [u8; 32],
    lock: Arc<Mutex<()>>,
    identity_authority_locks: Arc<Mutex<HashMap<String, Arc<tokio::sync::RwLock<()>>>>>,
    resource_scope_locks: Arc<Mutex<HashMap<String, Arc<tokio::sync::RwLock<()>>>>>,
    identity_authority_enforced: Arc<AtomicBool>,
    _process_lock: Arc<File>,
    inventories: Arc<Mutex<HashMap<String, Vec<ObjectMetadata>>>>,
    archive_usage: Arc<Mutex<HashMap<String, (u64, usize)>>>,
    #[cfg(test)]
    management_commit_failure: Arc<std::sync::atomic::AtomicBool>,
}
impl BlindStore {
    pub fn open(directory: PathBuf) -> Result<Self, String> {
        Self::open_with_scope_limit(directory, MAX_SCOPE_BYTES)
    }
    pub fn open_with_scope_limit(directory: PathBuf, max_scope_bytes: u64) -> Result<Self, String> {
        if max_scope_bytes == 0 {
            return Err("Storage scope byte limit must be positive".into());
        }
        if directory.exists() {
            for entry in fs::read_dir(&directory).map_err(|_| "Storage directory unavailable")? {
                let name = entry
                    .map_err(|_| "Storage directory unavailable")?
                    .file_name();
                let name = name.to_str().ok_or("Unknown file in storage directory")?;
                if ![
                    "service-key",
                    "scopes",
                    "storage.lock",
                    "enrollment",
                    "publications",
                    "management",
                    "identity-authorities",
                    "identity-successions",
                    "identity-authority-enforcement.json",
                ]
                .contains(&name)
                    && !name.starts_with(".pending-")
                {
                    return Err("Legacy or unknown state requires client re-encryption into a fresh directory".into());
                }
            }
            if (directory.join("scopes").exists()
                || directory.join("publications").exists()
                || directory.join("management").exists()
                || directory.join("identity-authorities").exists()
                || directory
                    .join("identity-authority-enforcement.json")
                    .exists()
                || directory.join("identity-successions").exists())
                && !directory.join("service-key").exists()
            {
                return Err(
                    "Existing blind storage lost its service key; restore the key before startup"
                        .into(),
                );
            }
        }
        validate_publication_namespace(&directory)?;
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
        recover_publication_temps(&directory)?;
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
        let service_public_key = public_key_from_seed(&seed)?;
        let service_id = public_key_id(&service_public_key)?;
        let enforcement_path = directory.join("identity-authority-enforcement.json");
        let identity_authority_enforced = if enforcement_path.exists() {
            let marker: SignedEnvelope<Value> = serde_json::from_slice(
                &fs::read(&enforcement_path)
                    .map_err(|_| "Identity enforcement state unavailable")?,
            )
            .map_err(|_| "Invalid Identity enforcement state")?;
            let payload: EnforcementMarkerPayload = serde_json::from_value(marker.payload.clone())
                .map_err(|_| "Invalid Identity enforcement state")?;
            if marker.signer_key_id != service_id
                || !verify_signed_envelope(&marker, &service_public_key, DOMAIN)?
                || payload.kind != "rusty-identity-authority-enforcement"
                || payload.version != 1
                || payload.service_id != service_id
                || payload.mode != "strict"
                || payload.epoch != 1
                || payload.enabled_at == 0
            {
                return Err("Identity enforcement state integrity failure".into());
            }
            true
        } else {
            false
        };
        let store = Self {
            telemetry: Telemetry::disabled(),
            directory: Arc::new(directory),
            seed,
            lock: Arc::new(Mutex::new(())),
            identity_authority_locks: Arc::new(Mutex::new(HashMap::new())),
            resource_scope_locks: Arc::new(Mutex::new(HashMap::new())),
            identity_authority_enforced: Arc::new(AtomicBool::new(identity_authority_enforced)),
            _process_lock: Arc::new(process_lock),
            inventories: Arc::new(Mutex::new(HashMap::new())),
            archive_usage: Arc::new(Mutex::new(HashMap::new())),
            #[cfg(test)]
            management_commit_failure: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            max_scope_bytes,
        };
        store.recover_checkpoint_scopes()?;
        store.recover_management()?;
        Ok(store)
    }
    pub fn public_key(&self) -> Result<String, String> {
        public_key_from_seed(&self.seed)
    }
    fn enforcement_state(&self) -> EnforcementState {
        if self.identity_authority_enforced.load(Ordering::SeqCst) {
            EnforcementState {
                mode: "strict".into(),
                epoch: 1,
            }
        } else {
            EnforcementState {
                mode: "additive".into(),
                epoch: 0,
            }
        }
    }
    pub fn identity_authority_enforcement(&self) -> Value {
        serde_json::to_value(self.enforcement_state()).expect("serializable enforcement state")
    }
    pub fn enable_identity_authority_enforcement(&self) -> Result<(), String> {
        if self.identity_authority_enforced.load(Ordering::SeqCst) {
            return Ok(());
        }
        let _guard = self.lock.lock().map_err(|_| "Storage lock unavailable")?;
        if self.identity_authority_enforced.load(Ordering::SeqCst) {
            return Ok(());
        }
        let service_id = public_key_id(&self.public_key()?)?;
        let marker = sign_json_envelope(
            &self.seed,
            serde_json::to_value(EnforcementMarkerPayload {
                kind: "rusty-identity-authority-enforcement".into(),
                version: 1,
                service_id,
                mode: "strict".into(),
                epoch: 1,
                enabled_at: now_ms()?,
            })
            .map_err(|_| "Identity enforcement state invalid")?,
            public_key_id(&self.public_key()?)?,
            DOMAIN,
        )?;
        atomic_write(
            &self.directory.join("identity-authority-enforcement.json"),
            &serde_json::to_vec(&marker).map_err(|_| "Identity enforcement state invalid")?,
        )?;
        self.identity_authority_enforced
            .store(true, Ordering::SeqCst);
        Ok(())
    }
    fn identity_authority_path(&self, person_id: &str) -> Result<PathBuf, String> {
        if !valid_id(person_id) {
            return Err("Invalid Identity person ID".into());
        }
        Ok(self
            .directory
            .join("identity-authorities")
            .join(format!("{person_id}.json")))
    }
    fn identity_succession_path(&self, previous_person_id: &str) -> Result<PathBuf, String> {
        if !valid_id(previous_person_id) {
            return Err("Invalid Identity person ID".into());
        }
        Ok(self
            .directory
            .join("identity-successions")
            .join(format!("{previous_person_id}.json")))
    }
    fn read_identity_succession(
        &self,
        previous_person_id: &str,
    ) -> Result<Option<StoredIdentityRootSuccession>, String> {
        let path = self.identity_succession_path(previous_person_id)?;
        if !path.exists() {
            return Ok(None);
        }
        if fs::metadata(&path)
            .map_err(|_| "Identity succession unavailable")?
            .len()
            > 4 * 1024 * 1024
        {
            return Err("Invalid Identity succession size".into());
        }
        let stored: StoredIdentityRootSuccession =
            serde_json::from_slice(&fs::read(path).map_err(|_| "Identity succession unavailable")?)
                .map_err(|_| "Invalid Identity succession")?;
        let service_key = self.public_key()?;
        let service_id = public_key_id(&service_key)?;
        let transition_hash =
            crate::identity_authority::canonical_hash(&stored.request.succession)?;
        if stored.version != 1
            || stored
                .request
                .succession
                .authorization
                .payload
                .previous_person_id
                != previous_person_id
            || stored.transition_hash != transition_hash
            || !matches!(stored.state.as_str(), "pending" | "ready")
            || stored.retired != (stored.state == "ready")
        {
            return Err("Identity succession integrity failure".into());
        }
        if let Some(receipt) = &stored.receipt {
            let payload: crate::identity_authority::IdentityRootSuccessionReceiptPayload =
                serde_json::from_value(receipt.payload.clone())
                    .map_err(|_| "Invalid Identity succession receipt")?;
            if receipt.signer_key_id != service_id
                || !verify_signed_envelope(receipt, &service_key, DOMAIN)?
                || payload.kind != "rusty-identity-root-succession-receipt"
                || payload.version != 1
                || payload.service_id != service_id
                || payload.origin != stored.request.actor_authorization.payload.origin
                || payload.previous_person_id != previous_person_id
                || payload.successor_person_id
                    != stored
                        .request
                        .succession
                        .authorization
                        .payload
                        .successor_person_id
                || payload.transition_hash != stored.transition_hash
                || payload.actor_device_id != stored.request.actor_device_id
                || payload.request_id != stored.request.actor_authorization.payload.request_id
                || payload.request_hash != stored.request.actor_authorization.payload.request_hash
                || Some(payload.committed_at) != stored.committed_at
                || payload.retired != stored.retired
                || payload.transferred != stored.targets
            {
                return Err("Identity succession receipt integrity failure".into());
            }
        } else if stored.state == "ready" || stored.retired || stored.committed_at.is_some() {
            return Err("Identity succession receipt is missing".into());
        }
        Ok(Some(stored))
    }
    fn identity_is_retired(&self, person_id: &str) -> Result<bool, String> {
        Ok(self
            .read_identity_succession(person_id)?
            .is_some_and(|stored| stored.retired))
    }
    fn scope_authority_path(&self, scope: &str) -> Result<PathBuf, String> {
        if !valid_id(scope) {
            return Err("Invalid opaque scope ID".into());
        }
        Ok(self.scope_dir(scope)?.join("authority.json"))
    }
    fn read_scope_authority(&self, scope: &str) -> Result<Option<StoredScopeAuthority>, String> {
        let path = self.scope_authority_path(scope)?;
        if !path.exists() {
            return Ok(None);
        }
        let stored: StoredScopeAuthority =
            serde_json::from_slice(&fs::read(path).map_err(|_| "Scope authority unavailable")?)
                .map_err(|_| "Invalid stored scope authority")?;
        let validated =
            meta_mesh_core::validate_scope_authority_at(&stored.snapshot, now_ms()? as i128)?;
        if stored.recent_updates.len() > 256 {
            return Err("Stored scope authority binding invalid".into());
        }
        // `scope` names this storage directory. The signed ledger's scope ID
        // names the workspace, and those identifiers are intentionally distinct.
        // Bind their durable association through the latest service-signed receipt.
        if let Some(update) = stored.recent_updates.last() {
            let receipt: ScopeAuthorityReceiptPayload =
                serde_json::from_value(update.receipt.payload.clone())
                    .map_err(|_| "Stored scope authority binding invalid")?;
            let service_key = self.public_key()?;
            let service_id = public_key_id(&service_key)?;
            if update.receipt.signer_key_id != service_id
                || !verify_signed_envelope(&update.receipt, &service_key, DOMAIN)?
                || receipt.kind != "rusty-scope-authority-receipt"
                || receipt.version != 1
                || receipt.service_id != service_id
                || receipt.scope_id != scope
                || receipt.workspace_id != validated.scope_id
                || receipt.controller_person_id != validated.controller.person_id
                || receipt.control_epoch != validated.control_epoch
                || receipt.request_id != update.request_id
                || receipt.request_hash != update.request_hash
                || receipt.merged_snapshot_hash != scope_authority_snapshot_hash(&stored.snapshot)?
            {
                return Err("Stored scope authority binding invalid".into());
            }
        }
        Ok(Some(stored))
    }
    fn signed_scope_authority_status(
        &self,
        scope: &str,
        origin: &str,
        request_id: &str,
        request_hash: &str,
    ) -> Result<SignedEnvelope<Value>, String> {
        if !valid_id(scope) || !valid_nonce(request_id) || request_hash.len() != 43 {
            return Err("Invalid scope authority status request".into());
        }
        let policy = self.policy(scope)?;
        if policy.scope_purpose.as_deref() == Some("person-identity") {
            return Err("Person Identity scopes do not have workspace authority".into());
        }
        let stored = self.read_scope_authority(scope)?;
        let validated = stored
            .as_ref()
            .map(|authority| {
                meta_mesh_core::validate_scope_authority_at(&authority.snapshot, now_ms()? as i128)
                    .map_err(|_| "Stored scope authority is invalid".to_string())
            })
            .transpose()?;
        let payload = ScopeAuthorityStatusPayload {
            kind: "rusty-scope-authority-status".into(),
            version: 1,
            service_id: public_key_id(&self.public_key()?)?,
            origin: origin.to_owned(),
            scope_id: scope.to_owned(),
            workspace_id: validated.as_ref().map(|value| value.scope_id.clone()),
            state: if stored.is_some() { "ready" } else { "missing" }.into(),
            controller_person_id: validated
                .as_ref()
                .map(|value| value.controller.person_id.clone()),
            control_epoch: validated.as_ref().map(|value| value.control_epoch),
            request_id: request_id.to_owned(),
            request_hash: request_hash.to_owned(),
            issued_at: now_ms()?,
            enforcement: self.enforcement_state(),
            scope_authority: stored.map(|value| value.snapshot),
        };
        sign_json_envelope(
            &self.seed,
            serde_json::to_value(payload).map_err(|_| "Invalid scope authority status")?,
            public_key_id(&self.public_key()?)?,
            DOMAIN,
        )
    }
    fn update_scope_authority(
        &self,
        scope: &str,
        request: ScopeAuthorityUpdateRequest,
        origin: &str,
    ) -> Result<SignedEnvelope<Value>, (String, Option<SignedEnvelope<Value>>)> {
        if !valid_id(scope) || request.version != 1 {
            return Err(("Invalid scope authority update".into(), None));
        }
        let scope_gate = self
            .resource_scope_gate(scope)
            .map_err(|message| (message, None))?;
        let _scope_guard = scope_gate
            .try_write()
            .map_err(|_| ("Resource scope lock unavailable".to_string(), None))?;
        let _guard = self
            .lock
            .lock()
            .map_err(|_| ("Storage lock unavailable".to_string(), None))?;
        let policy = self.policy(scope).map_err(|message| (message, None))?;
        if policy.scope_purpose.as_deref() == Some("person-identity") {
            return Err((
                "Person Identity scopes do not have workspace authority".into(),
                None,
            ));
        }
        let now = now_ms().map_err(|message| (message, None))?;
        let validated_candidate =
            meta_mesh_core::validate_scope_authority_at(&request.scope_authority, now as i128)
                .map_err(|message| (message, None))?;
        let mut existing = self
            .read_scope_authority(scope)
            .map_err(|message| (message, None))?;
        if let Some(stored) = &mut existing {
            stored
                .recent_updates
                .retain(|update| now.saturating_sub(update.issued_at) <= AUTHORITY_REQUEST_TTL_MS);
        }
        let authorization: ScopeAuthorityUpdateAuthorization =
            serde_json::from_value(request.authorization.payload.clone())
                .map_err(|_| ("Invalid scope authority authorization".into(), None))?;
        let request_id = authorization.request_id.clone();
        let request_hash = request.request_hash().map_err(|message| (message, None))?;
        if let Some(stored) = &existing {
            if let Some(prior) = stored
                .recent_updates
                .iter()
                .find(|update| update.request_id == request_id)
            {
                if prior.request_hash == request_hash {
                    return Ok(prior.receipt.clone());
                }
                return Err(("Scope authority request ID was already used".into(), None));
            }
        }

        if let Some(stored) = &existing {
            let current =
                meta_mesh_core::validate_scope_authority_at(&stored.snapshot, now as i128)
                    .map_err(|message| (message, None))?;
            if request.scope_authority.genesis != stored.snapshot.genesis
                || !scope_snapshot_contains(&request.scope_authority, &stored.snapshot)
                || validated_candidate.control_epoch < current.control_epoch
                || (validated_candidate.control_epoch == current.control_epoch
                    && validated_candidate.controller.person_id != current.controller.person_id)
            {
                let status = self
                    .signed_scope_authority_status(scope, origin, &request_id, &request_hash)
                    .map_err(|message| (message, None))?;
                return Err((
                    "Scope authority snapshot is stale or omits accepted history".into(),
                    Some(status),
                ));
            }
        }

        let owner_person_id = policy
            .owner_person_id
            .as_deref()
            .ok_or_else(|| ("Storage resource owner is unavailable".into(), None))?;
        if existing.is_none() && validated_candidate.controller.person_id != owner_person_id {
            return Err((
                "Initial workspace authority controller does not match the enrolled owner".into(),
                None,
            ));
        }
        let expected_genesis = if let Some(stored) = &existing {
            Some(stored.snapshot.genesis.payload.creator.person_id.as_str())
        } else if policy.scope_purpose.as_deref() == Some("workspace") {
            None
        } else {
            Some(owner_person_id)
        };
        let person_id = validated_candidate.controller.person_id.clone();
        if self
            .identity_is_retired(&person_id)
            .map_err(|message| (message, None))?
        {
            return Err((
                "Scope controller Identity root has been retired".into(),
                None,
            ));
        }
        let identity = self
            .read_identity_authority(&person_id)
            .map_err(|message| (message, None))?
            .ok_or_else(|| {
                (
                    "Workspace controller Identity authority is not registered".into(),
                    None,
                )
            })?;
        let service_id = public_key_id(&self.public_key().map_err(|message| (message, None))?)
            .map_err(|message| (message, None))?;
        request
            .verify(
                scope,
                expected_genesis,
                &service_id,
                origin,
                &identity.view,
                now,
            )
            .map_err(|message| (message, None))?;

        let accepted = existing.as_ref().map(|stored| &stored.snapshot);
        let merged = match request.verify_new_controller_signers(
            accepted,
            |signer_person_id| {
                Ok(self
                    .read_identity_authority(signer_person_id)?
                    .map(|stored| stored.view))
            },
            now,
        ) {
            Ok(merged) => merged,
            Err(message) => return Err((message, None)),
        };
        if existing
            .as_ref()
            .is_some_and(|stored| stored.recent_updates.len() >= 256)
        {
            return Err(("Scope authority update rate limit reached".into(), None));
        }
        let validated = meta_mesh_core::validate_scope_authority_at(&merged, now as i128)
            .map_err(|message| (message, None))?;
        if validated.controller.person_id != authorization.person_id
            || validated.control_epoch != authorization.control_epoch
        {
            return Err((
                "Scope authority update signer is not the current controller".into(),
                None,
            ));
        }
        let receipt_payload = ScopeAuthorityReceiptPayload {
            kind: "rusty-scope-authority-receipt".into(),
            version: 1,
            service_id: service_id.clone(),
            origin: origin.to_owned(),
            scope_id: scope.to_owned(),
            workspace_id: validated.scope_id.clone(),
            controller_person_id: validated.controller.person_id.clone(),
            control_epoch: validated.control_epoch,
            request_id: request_id.clone(),
            request_hash: request_hash.clone(),
            merged_snapshot_hash: scope_authority_snapshot_hash(&merged)
                .map_err(|message| (message, None))?,
            committed_at: now,
            enforcement: self.enforcement_state(),
        };
        let receipt = sign_json_envelope(
            &self.seed,
            serde_json::to_value(receipt_payload)
                .map_err(|_| ("Invalid scope authority receipt".into(), None))?,
            service_id,
            DOMAIN,
        )
        .map_err(|message| (message, None))?;
        let mut recent_updates = existing.map_or_else(Vec::new, |stored| stored.recent_updates);
        recent_updates.push(RecentScopeAuthorityUpdate {
            request_id,
            request_hash,
            issued_at: now,
            receipt: receipt.clone(),
        });
        if recent_updates.len() > 256 {
            recent_updates.drain(..recent_updates.len() - 256);
        }
        let stored = StoredScopeAuthority {
            snapshot: merged,
            recent_updates,
        };
        atomic_write(
            &self
                .scope_authority_path(scope)
                .map_err(|message| (message, None))?,
            &serde_json::to_vec(&stored)
                .map_err(|_| ("Scope authority state is invalid".into(), None))?,
        )
        .map_err(|message| (message, None))?;
        Ok(receipt)
    }
    fn identity_authority_gate(
        &self,
        person_id: &str,
    ) -> Result<Arc<tokio::sync::RwLock<()>>, String> {
        if !valid_id(person_id) {
            return Err("Invalid Identity person ID".into());
        }
        let mut gates = self
            .identity_authority_locks
            .lock()
            .map_err(|_| "Identity authority lock unavailable")?;
        Ok(gates
            .entry(person_id.to_owned())
            .or_insert_with(|| Arc::new(tokio::sync::RwLock::new(())))
            .clone())
    }
    fn resource_scope_gate(&self, scope_id: &str) -> Result<Arc<tokio::sync::RwLock<()>>, String> {
        if !valid_id(scope_id) {
            return Err("Invalid opaque scope ID".into());
        }
        let mut gates = self
            .resource_scope_locks
            .lock()
            .map_err(|_| "Resource scope lock unavailable")?;
        Ok(gates
            .entry(scope_id.to_owned())
            .or_insert_with(|| Arc::new(tokio::sync::RwLock::new(())))
            .clone())
    }
    fn read_identity_authority(
        &self,
        person_id: &str,
    ) -> Result<Option<StoredIdentityAuthority>, String> {
        let path = self.identity_authority_path(person_id)?;
        if !path.exists() {
            return Ok(None);
        }
        let stored: StoredIdentityAuthority =
            serde_json::from_slice(&fs::read(path).map_err(|_| "Identity authority unavailable")?)
                .map_err(|_| "Invalid stored Identity authority")?;
        if stored.view.person_id != person_id {
            return Err("Stored Identity authority person mismatch".into());
        }
        stored.view.verify()?;
        Ok(Some(stored))
    }
    fn identity_device_active(
        &self,
        identity: &PublicIdentity,
        device_id: &str,
    ) -> Result<bool, String> {
        if self.identity_is_retired(&identity.person_id)? {
            return Ok(false);
        }
        let Some(authority) = self.read_identity_authority(&identity.person_id)? else {
            return Ok(!self.identity_authority_enforced.load(Ordering::SeqCst));
        };
        if authority.view.identity_public_key != identity.public_key {
            return Ok(false);
        }
        authority.view.verify()?.is_active_device(device_id)
    }
    fn identity_device_certificate_matches(
        &self,
        identity: &PublicIdentity,
        device_id: &str,
        certificates: &[DeviceCertificate],
    ) -> Result<bool, String> {
        if self.identity_is_retired(&identity.person_id)? {
            return Ok(false);
        }
        let Some(authority) = self.read_identity_authority(&identity.person_id)? else {
            return Ok(!self.identity_authority_enforced.load(Ordering::SeqCst));
        };
        if authority.view.identity_public_key != identity.public_key {
            return Ok(false);
        }
        let verified = authority.view.verify()?;
        Ok(verified.is_active_device(device_id)?
            && verified.has_exact_certificate_chain(device_id, certificates)?)
    }
    fn signed_identity_authority_status(
        &self,
        person_id: &str,
        origin: &str,
        request_nonce: &str,
        request_hash: &str,
    ) -> Result<SignedEnvelope<Value>, String> {
        if !valid_nonce(request_nonce) || request_hash.len() != 43 {
            return Err("Invalid Identity authority status request".into());
        }
        let retired = self.identity_is_retired(person_id)?;
        let current = self.read_identity_authority(person_id)?;
        let payload = AuthorityStatusPayload {
            kind: "rusty-identity-authority-status".into(),
            version: 1,
            service_id: public_key_id(&self.public_key()?)?,
            origin: origin.to_owned(),
            person_id: person_id.to_owned(),
            state: if retired {
                "retired"
            } else if current.is_some() {
                "ready"
            } else {
                "missing"
            }
            .into(),
            request_nonce: request_nonce.to_owned(),
            request_hash: request_hash.to_owned(),
            issued_at: now_ms()?,
            enforcement: self.enforcement_state(),
            view: if retired {
                None
            } else {
                current.map(|stored| stored.view)
            },
        };
        sign_json_envelope(
            &self.seed,
            serde_json::to_value(payload).map_err(|_| "Invalid Identity authority status")?,
            public_key_id(&self.public_key()?)?,
            DOMAIN,
        )
    }
    fn signed_identity_succession_status(
        &self,
        previous_person_id: &str,
        transition_hash: &str,
        request_id: &str,
        request_hash: &str,
        origin: &str,
    ) -> Result<SignedEnvelope<Value>, String> {
        let expected_hash = crate::identity_authority::identity_succession_status_request_hash(
            previous_person_id,
            transition_hash,
            request_id,
        )?;
        if expected_hash != request_hash {
            return Err("Invalid Identity succession status request hash".into());
        }
        let stored = self.read_identity_succession(previous_person_id)?;
        let matching = stored.filter(|value| value.transition_hash == transition_hash);
        let (state, successor_person_id, actor_device_id, retired, transferred, receipt) =
            match matching {
                Some(value) => (
                    value.state,
                    Some(
                        value
                            .request
                            .succession
                            .authorization
                            .payload
                            .successor_person_id,
                    ),
                    Some(value.request.actor_device_id),
                    value.retired,
                    value.targets,
                    value.receipt,
                ),
                None => ("missing".into(), None, None, false, Vec::new(), None),
            };
        let service_id = public_key_id(&self.public_key()?)?;
        let payload = IdentityRootSuccessionStatusPayload {
            kind: "rusty-identity-root-succession-status".into(),
            version: 1,
            service_id: service_id.clone(),
            origin: origin.to_owned(),
            previous_person_id: previous_person_id.to_owned(),
            transition_hash: transition_hash.to_owned(),
            state,
            request_id: request_id.to_owned(),
            request_hash: request_hash.to_owned(),
            issued_at: now_ms()?,
            successor_person_id,
            actor_device_id,
            retired,
            enforcement: self.enforcement_state(),
            transferred,
            receipt,
        };
        sign_json_envelope(
            &self.seed,
            serde_json::to_value(payload).map_err(|_| "Invalid Identity succession status")?,
            service_id,
            DOMAIN,
        )
    }
    fn root_succession_targets(
        &self,
        previous_person_id: &str,
        successor_person_id: &str,
        now: u64,
    ) -> Result<Vec<IdentityRootSuccessionTargetReceipt>, String> {
        let scopes_dir = self.directory.join("scopes");
        let mut had_identity_scope = false;
        let mut has_successor_identity_scope = false;
        let mut targets = Vec::new();
        if scopes_dir.exists() {
            for entry in fs::read_dir(&scopes_dir).map_err(|_| "Storage scopes unavailable")? {
                let entry = entry.map_err(|_| "Storage scopes unavailable")?;
                let scope = entry
                    .file_name()
                    .into_string()
                    .map_err(|_| "Invalid storage scope name")?;
                if !valid_id(&scope) || !entry.path().is_dir() {
                    continue;
                }
                let policy = self.policy(&scope)?;
                let Some(owner) = policy.owner_person_id.as_deref() else {
                    continue;
                };
                if policy.scope_purpose.as_deref() == Some("person-identity") {
                    if owner == previous_person_id {
                        had_identity_scope = true;
                    }
                    if owner == successor_person_id
                        && !policy.revoked
                        && policy.scope_purpose.as_deref() == Some("person-identity")
                    {
                        has_successor_identity_scope = true;
                    }
                    continue;
                }
                if owner != previous_person_id {
                    continue;
                }
                if policy.scope_purpose.as_deref() != Some("workspace") {
                    return Err(
                        "Classify each previous-root-owned scope before retiring its Identity root"
                            .into(),
                    );
                }
                let Some(stored) = self.read_scope_authority(&scope)? else {
                    return Err("Owned workspace scope has no accepted controller history".into());
                };
                let validated =
                    meta_mesh_core::validate_scope_authority_at(&stored.snapshot, now as i128)
                        .map_err(|_| "Owned workspace scope authority is invalid")?;
                if validated.controller.person_id == previous_person_id {
                    return Err("Transfer each currently controlled workspace before retiring its Identity root".into());
                }
                if validated.controller.person_id == successor_person_id {
                    targets.push(IdentityRootSuccessionTargetReceipt {
                        kind: "scope-authority".into(),
                        resource_id: scope,
                        evidence_hash: crate::identity_authority::scope_authority_snapshot_hash(
                            &stored.snapshot,
                        )?,
                        epoch: Some(validated.control_epoch),
                    });
                }
            }
        }
        if had_identity_scope && !has_successor_identity_scope {
            return Err("Register and verify the successor Identity scope before retiring the previous root".into());
        }
        Ok(targets)
    }
    fn update_identity_root_succession(
        &self,
        request: IdentityRootSuccessionRequest,
        origin: &str,
    ) -> Result<SignedEnvelope<Value>, (String, Option<SignedEnvelope<Value>>)> {
        let previous_person_id = request
            .succession
            .authorization
            .payload
            .previous_person_id
            .clone();
        let successor_person_id = request
            .succession
            .authorization
            .payload
            .successor_person_id
            .clone();
        if !valid_id(&previous_person_id)
            || !valid_id(&successor_person_id)
            || previous_person_id == successor_person_id
        {
            return Err(("Invalid Identity root succession principals".into(), None));
        }
        let mut people = [previous_person_id.as_str(), successor_person_id.as_str()];
        people.sort_unstable();
        let first_gate = self
            .identity_authority_gate(people[0])
            .map_err(|e| (e, None))?;
        let second_gate = self
            .identity_authority_gate(people[1])
            .map_err(|e| (e, None))?;
        let _first_guard = first_gate
            .try_write()
            .map_err(|_| ("Identity authority lock unavailable".to_string(), None))?;
        let _second_guard = second_gate
            .try_write()
            .map_err(|_| ("Identity authority lock unavailable".to_string(), None))?;
        // Identity gates precede the shared storage lock everywhere. Holding both
        // gates through durable retirement prevents an old-device request from
        // committing after this response.
        let _guard = self
            .lock
            .lock()
            .map_err(|_| ("Storage lock unavailable".into(), None))?;
        let now = now_ms().map_err(|e| (e, None))?;
        let service_id =
            public_key_id(&self.public_key().map_err(|e| (e, None))?).map_err(|e| (e, None))?;
        let previous = self
            .read_identity_authority(&previous_person_id)
            .map_err(|e| (e, None))?
            .ok_or_else(|| ("Previous Identity authority is not registered".into(), None))?;
        let successor = self
            .read_identity_authority(&successor_person_id)
            .map_err(|e| (e, None))?
            .ok_or_else(|| {
                (
                    "Successor Identity authority is not registered".into(),
                    None,
                )
            })?;
        if self
            .identity_is_retired(&successor_person_id)
            .map_err(|e| (e, None))?
        {
            return Err(("Successor Identity root is already retired".into(), None));
        }
        let verified = request
            .verify(&previous.view, &successor.view, &service_id, origin, now)
            .map_err(|e| (e, None))?;
        if previous.view.revocation_head != verified.authority_head
            || previous.view.view_digest != verified.authority_view_digest
            || previous.view.identity_public_key != verified.previous_identity_public_key
            || successor.view.identity_public_key != verified.successor_identity_public_key
        {
            return Err((
                "Identity root succession does not match committed authority views".into(),
                None,
            ));
        }
        let path = self
            .identity_succession_path(&previous_person_id)
            .map_err(|e| (e, None))?;
        if let Some(existing) = self
            .read_identity_succession(&previous_person_id)
            .map_err(|e| (e, None))?
        {
            if existing.transition_hash != verified.transition_hash {
                return Err((
                    "Previous Identity root already has a different successor".into(),
                    None,
                ));
            }
            if existing.retired {
                return existing
                    .receipt
                    .ok_or_else(|| ("Completed root succession receipt is missing".into(), None));
            }
        }
        let scope_targets = self
            .root_succession_targets(&previous_person_id, &successor_person_id, now)
            .map_err(|e| (e, None))?;
        if self.enforcement_state().mode != "strict" || self.enforcement_state().epoch != 1 {
            return Err((
                "Identity root succession requires strict authority enforcement".into(),
                None,
            ));
        }
        let pending = StoredIdentityRootSuccession {
            version: 1,
            request: request.clone(),
            transition_hash: verified.transition_hash.clone(),
            state: "pending".into(),
            targets: scope_targets.clone(),
            retired: false,
            committed_at: None,
            receipt: None,
        };
        atomic_write(
            &path,
            &serde_json::to_vec(&pending)
                .map_err(|_| ("Invalid Identity succession state".into(), None))?,
        )
        .map_err(|e| (e, None))?;
        let mut targets = scope_targets;
        targets.extend(
            self.prepare_root_succession_management_transfers(
                &previous_person_id,
                &successor.view.identity(),
                &verified.transition_hash,
                origin,
            )
            .map_err(|e| (e, None))?,
        );
        targets.sort_by(|left, right| {
            left.kind
                .cmp(&right.kind)
                .then(left.resource_id.cmp(&right.resource_id))
        });
        let request_id = request.actor_authorization.payload.request_id.clone();
        let request_hash = request.actor_authorization.payload.request_hash.clone();
        let committed_at = now;
        let receipt_payload = IdentityRootSuccessionReceiptPayload {
            kind: "rusty-identity-root-succession-receipt".into(),
            version: 1,
            service_id: service_id.clone(),
            origin: origin.to_owned(),
            previous_person_id: previous_person_id.clone(),
            successor_person_id: successor_person_id.clone(),
            transition_hash: verified.transition_hash.clone(),
            actor_device_id: request.actor_device_id.clone(),
            request_id,
            request_hash,
            committed_at,
            retired: true,
            transferred: targets.clone(),
            enforcement: self.enforcement_state(),
        };
        let receipt = sign_json_envelope(
            &self.seed,
            serde_json::to_value(receipt_payload)
                .map_err(|_| ("Invalid Identity succession receipt".into(), None))?,
            service_id,
            DOMAIN,
        )
        .map_err(|e| (e, None))?;
        let stored = StoredIdentityRootSuccession {
            version: 1,
            request,
            transition_hash: verified.transition_hash,
            state: "ready".into(),
            targets,
            retired: true,
            committed_at: Some(committed_at),
            receipt: Some(receipt.clone()),
        };
        atomic_write(
            &path,
            &serde_json::to_vec(&stored)
                .map_err(|_| ("Invalid Identity succession state".into(), None))?,
        )
        .map_err(|e| (e, None))?;
        Ok(receipt)
    }
    fn update_identity_authority(
        &self,
        request: AuthorityUpdateRequest,
        origin: &str,
    ) -> Result<SignedEnvelope<Value>, (String, Option<SignedEnvelope<Value>>)> {
        let person_id = request.view.person_id.clone();
        let authority_gate = self
            .identity_authority_gate(&person_id)
            .map_err(|message| (message, None))?;
        let _authority_guard = authority_gate
            .try_write()
            .map_err(|_| ("Identity authority lock unavailable".to_string(), None))?;
        let _guard = self
            .lock
            .lock()
            .map_err(|_| ("Storage lock unavailable".to_string(), None))?;
        if self
            .identity_is_retired(&person_id)
            .map_err(|message| (message, None))?
        {
            return Err(("Identity root has been retired".into(), None));
        }
        let nonce = request.authorization.payload.nonce.clone();
        let request_hash = authority_view_hash(&request.view).map_err(|message| (message, None))?;
        let service_public_key = self.public_key().map_err(|message| (message, None))?;
        let service_id = public_key_id(&service_public_key).map_err(|message| (message, None))?;
        let now = now_ms().map_err(|message| (message, None))?;
        request
            .verify(&service_id, origin, now)
            .map_err(|message| (message, None))?;

        let mut existing = self
            .read_identity_authority(&person_id)
            .map_err(|message| (message, None))?;
        if let Some(stored) = &mut existing {
            stored
                .recent_updates
                .retain(|update| now.saturating_sub(update.issued_at) <= AUTHORITY_REQUEST_TTL_MS);
        }
        if let Some(stored) = &existing {
            if let Some(prior) = stored
                .recent_updates
                .iter()
                .find(|update| update.nonce == nonce)
            {
                if prior.request_hash == request_hash {
                    return Ok(prior.receipt.clone());
                }
                return Err(("Identity authority nonce was already used".into(), None));
            }
            let current = &stored.view;
            let incoming = &request.view;
            let stale = incoming.revocation_head.revision < current.revocation_head.revision
                || (incoming.revocation_head.revision == current.revocation_head.revision
                    && incoming.revocation_head.record_hash != current.revocation_head.record_hash)
                || current.revocations.len() > incoming.revocations.len()
                || !current
                    .revocations
                    .iter()
                    .zip(incoming.revocations.iter())
                    .all(|(old, new)| old == new)
                || current.certificates.iter().any(|old| {
                    !incoming
                        .certificates
                        .iter()
                        .any(|new| new.payload.device_id == old.payload.device_id && new == old)
                });
            if stale {
                let status = self
                    .signed_identity_authority_status(&person_id, origin, &nonce, &request_hash)
                    .map_err(|message| (message, None))?;
                return Err((
                    "Identity authority is stale or forks the committed head".into(),
                    Some(status),
                ));
            }
        }

        if existing
            .as_ref()
            .is_some_and(|stored| stored.recent_updates.len() >= 256)
        {
            return Err(("Identity authority update rate limit reached".into(), None));
        }
        let committed_at = now;
        let receipt_payload = AuthorityReceiptPayload {
            kind: "rusty-identity-authority-receipt".into(),
            version: 1,
            service_id: service_id.clone(),
            origin: origin.to_owned(),
            person_id: person_id.clone(),
            authority_head: request.view.revocation_head.clone(),
            view_digest: request.view.view_digest.clone(),
            request_hash: request_hash.clone(),
            committed_at,
            enforcement: self.enforcement_state(),
        };
        let receipt = sign_json_envelope(
            &self.seed,
            serde_json::to_value(receipt_payload)
                .map_err(|_| ("Invalid Identity authority receipt".into(), None))?,
            service_id,
            DOMAIN,
        )
        .map_err(|message| (message, None))?;
        let mut recent_updates = existing.map_or_else(Vec::new, |stored| stored.recent_updates);
        recent_updates.push(RecentAuthorityUpdate {
            nonce,
            request_hash,
            issued_at: request.authorization.payload.issued_at,
            receipt: receipt.clone(),
        });
        if recent_updates.len() > crate::identity_authority::MAX_RECENT_AUTHORITY_UPDATES {
            recent_updates.drain(
                ..recent_updates.len() - crate::identity_authority::MAX_RECENT_AUTHORITY_UPDATES,
            );
        }
        let stored = StoredIdentityAuthority {
            view: request.view,
            recent_updates,
        };
        let bytes = serde_json::to_vec(&stored)
            .map_err(|_| ("Invalid Identity authority state".into(), None))?;
        let path = self
            .identity_authority_path(&person_id)
            .map_err(|message| (message, None))?;
        atomic_write(&path, &bytes).map_err(|message| (message, None))?;
        Ok(receipt)
    }
    fn update_scope_purpose(
        &self,
        scope: &str,
        request: ScopePurposeUpdateRequest,
        origin: &str,
    ) -> Result<SignedEnvelope<Value>, String> {
        if request.version != 1 || !valid_id(scope) || request.scope_purpose != "person-identity" {
            return Err("Invalid one-time Identity scope classification".into());
        }
        let authorization: ScopePurposeUpdateAuthorization =
            serde_json::from_value(request.authorization.payload.clone())
                .map_err(|_| "Invalid scope purpose authorization")?;
        let request_hash = digest(
            canonicalize_json(&json!({
                "version": 1,
                "scopePurpose": request.scope_purpose,
            }))?
            .as_bytes(),
        );
        let now = now_ms()?;
        let service_id = public_key_id(&self.public_key()?)?;
        if authorization.kind != "rusty-scope-purpose-update"
            || authorization.version != 1
            || authorization.service_id != service_id
            || authorization.origin != origin
            || authorization.scope_id != scope
            || authorization.scope_purpose != request.scope_purpose
            || authorization.request_hash != request_hash
            || !valid_nonce(&authorization.request_id)
            || authorization.issued_at.abs_diff(now) > AUTHORITY_REQUEST_TTL_MS
            || authorization.expires_at <= now
            || authorization.expires_at <= authorization.issued_at
            || authorization
                .expires_at
                .saturating_sub(authorization.issued_at)
                > AUTHORITY_REQUEST_TTL_MS
            || request.authorization.signer_key_id != authorization.device_id
        {
            return Err("Scope purpose authorization binding or expiry is invalid".into());
        }
        let scope_gate = self.resource_scope_gate(scope)?;
        let _scope_guard = scope_gate
            .try_write()
            .map_err(|_| "Resource scope lock unavailable")?;
        let _guard = self.lock.lock().map_err(|_| "Storage lock unavailable")?;
        let mut policy = self.policy(scope)?;
        if let Some(completed) = &policy.completed_scope_purpose_update {
            if completed.request_id == authorization.request_id
                && completed.request_hash == request_hash
                && policy.scope_purpose.as_deref() == Some("person-identity")
            {
                return Ok(completed.receipt.clone());
            }
            if policy.scope_purpose.as_deref() != Some("person-identity") {
                return Err("Scope purpose is immutable".into());
            }
        }
        if policy
            .scope_purpose
            .as_deref()
            .is_some_and(|purpose| purpose != "person-identity")
            || policy.owner_person_id.as_deref() != Some(authorization.person_id.as_str())
            || policy.revision != authorization.policy_revision
            || self.scope_authority_path(scope)?.exists()
            || self.scope_has_principal_grants(scope)?
        {
            return Err("Scope is not eligible for one-time Identity classification".into());
        }
        let identity = self
            .read_identity_authority(&authorization.person_id)?
            .ok_or("Scope owner Identity authority is not registered")?;
        if self.identity_is_retired(&authorization.person_id)? {
            return Err("Scope owner Identity root has been retired".into());
        }
        let verified = identity.view.verify()?;
        if !verified.is_active_device(&authorization.device_id)? {
            return Err("Scope purpose signer is not an active Identity device".into());
        }
        let device_key = verify_device_certificate_chain(
            &identity.view.identity(),
            &authorization.device_id,
            &certificate_chain(
                &identity.view.identity(),
                &authorization.device_id,
                &verified.certificates_by_device,
            )?,
            SIGNATURE_DOMAIN,
        )?;
        if !verify_signed_envelope(&request.authorization, &device_key, SIGNATURE_DOMAIN)? {
            return Err("Invalid scope purpose owner signature".into());
        }
        let receipt = sign_json_envelope(
            &self.seed,
            serde_json::to_value(ScopePurposeReceiptPayload {
                kind: "rusty-scope-purpose-receipt".into(),
                version: 1,
                service_id,
                origin: origin.to_owned(),
                scope_id: scope.to_owned(),
                scope_purpose: "person-identity".into(),
                person_id: authorization.person_id,
                policy_revision: policy.revision,
                request_id: authorization.request_id.clone(),
                request_hash: request_hash.clone(),
                committed_at: now,
                enforcement: self.enforcement_state(),
            })
            .map_err(|_| "Invalid scope purpose receipt")?,
            public_key_id(&self.public_key()?)?,
            DOMAIN,
        )?;
        policy.scope_purpose = Some("person-identity".into());
        policy.completed_scope_purpose_update = Some(CompletedScopePurposeUpdate {
            request_id: authorization.request_id,
            request_hash,
            receipt: receipt.clone(),
        });
        atomic_write(
            &self.scope_dir(scope)?.join("policy.json"),
            &serde_json::to_vec(&policy).map_err(|_| "Scope purpose state invalid")?,
        )?;
        Ok(receipt)
    }
    fn verify_identity_request_proof(
        &self,
        envelope: &SignedEnvelope<Value>,
        scope: &str,
        action: &str,
        token: &str,
        method: &str,
        path: &str,
        body: &[u8],
        origin: &str,
    ) -> Result<(), String> {
        let proof: IdentityRequestProof = serde_json::from_value(envelope.payload.clone())
            .map_err(|_| "Invalid Identity request proof")?;
        let service_id = public_key_id(&self.public_key()?)?;
        let stored = self
            .read_identity_authority(&proof.person_id)?
            .ok_or("Identity authority is not registered")?;
        if self.identity_is_retired(&proof.person_id)? {
            return Err("Identity root has been retired".into());
        }
        proof.verify(
            envelope,
            &stored.view,
            &service_id,
            origin,
            scope,
            action,
            token,
            method,
            path,
            body,
            now_ms()?,
        )?;
        let policy = self.policy(scope)?;
        let fixed_owner_person_id = policy
            .owner_person_id
            .as_deref()
            .ok_or("Storage resource owner is unavailable")?;
        let current_scope_authority = if policy.scope_purpose.as_deref() == Some("workspace") {
            Some(
                self.read_scope_authority(scope)?
                    .ok_or("Workspace scope authority is unavailable")?,
            )
        } else {
            None
        };
        let effective_owner_person_id = if let Some(stored) = &current_scope_authority {
            meta_mesh_core::validate_scope_authority_at(&stored.snapshot, now_ms()? as i128)
                .map_err(|_| "Workspace scope authority is invalid")?
                .controller
                .person_id
        } else {
            fixed_owner_person_id.to_owned()
        };
        if effective_owner_person_id == proof.person_id {
            if proof.grant_id.is_some() || proof.policy_epoch != policy.revision {
                return Err("Invalid owner storage request epoch".into());
            }
            return Ok(());
        }
        let grant_id = proof
            .grant_id
            .as_deref()
            .ok_or("Storage principal grant is unavailable")?;
        if self
            .read_resource_principal_revocation(scope, grant_id, origin)?
            .is_some()
        {
            return Err("Storage principal grant has been revoked".into());
        }
        let stored_grant = self.read_resource_principal_grant(scope, &proof.person_id, origin)?;
        let grant = &stored_grant.grant;
        if let Some(current) = &current_scope_authority
            && !scope_snapshot_contains(&current.snapshot, &grant.payload.scope_authority)
        {
            return Err("Storage principal grant is outside accepted scope history".into());
        }
        if grant.payload.grant_id != grant_id
            || grant.payload.subject_person_id != proof.person_id
            || grant.payload.policy_epoch != proof.policy_epoch
            || grant.payload.subject_public_key != stored.view.identity_public_key
            || !grant
                .payload
                .actions
                .iter()
                .any(|candidate| candidate == action)
            || (action == "read" && grant.payload.read_token_hash != proof.token_hash)
            || (action == "write"
                && grant.payload.write_token_hash.as_deref() != Some(proof.token_hash.as_str()))
        {
            return Err("Storage principal grant does not authorize request".into());
        }
        Ok(())
    }
    fn resource_principal_path(&self, scope: &str, person_id: &str) -> Result<PathBuf, String> {
        if !valid_id(scope) || !valid_id(person_id) {
            return Err("Invalid storage principal".into());
        }
        Ok(self
            .scope_dir(scope)?
            .join("principals")
            .join(format!("{person_id}.json")))
    }
    fn resource_principal_revocation_path(
        &self,
        scope: &str,
        grant_id: &str,
    ) -> Result<PathBuf, String> {
        if !valid_id(scope) || !valid_id(grant_id) {
            return Err("Invalid storage principal revocation".into());
        }
        Ok(self
            .scope_dir(scope)?
            .join("principal-revocations")
            .join(format!("{grant_id}.json")))
    }
    fn scope_has_principal_grants(&self, scope: &str) -> Result<bool, String> {
        let path = self.scope_dir(scope)?.join("principals");
        if !path.exists() {
            return Ok(false);
        }
        let mut entries =
            fs::read_dir(path).map_err(|_| "Storage principal directory unavailable")?;
        Ok(entries
            .next()
            .transpose()
            .map_err(|_| "Storage principal directory unavailable")?
            .is_some())
    }
    fn read_resource_principal_grant(
        &self,
        scope: &str,
        subject_person_id: &str,
        origin: &str,
    ) -> Result<StoredResourcePrincipalGrant, String> {
        let path = self.resource_principal_path(scope, subject_person_id)?;
        let stored: StoredResourcePrincipalGrant = serde_json::from_slice(
            &fs::read(path).map_err(|_| "Storage principal grant is unavailable")?,
        )
        .map_err(|_| "Invalid stored storage principal grant")?;
        let grant = &stored.grant;
        let payload = &grant.payload;
        let accepted_scope_authority = self
            .read_scope_authority(scope)?
            .ok_or("Storage scope authority is not registered")?;
        let workspace_id = meta_mesh_core::validate_scope_authority_at(
            &accepted_scope_authority.snapshot,
            now_ms()? as i128,
        )
        .map_err(|_| "Workspace scope authority is invalid")?
        .scope_id;
        let owner = self
            .read_identity_authority(&payload.owner_person_id)?
            .ok_or("Storage owner Identity authority is unavailable")?
            .view
            .verify()?;
        payload.verify(
            grant,
            &owner,
            &public_key_id(&self.public_key()?)?,
            origin,
            scope,
            &workspace_id,
            false,
            now_ms()?,
        )?;
        if payload.subject_person_id != subject_person_id {
            return Err("Storage principal grant subject mismatch".into());
        }
        Ok(stored)
    }
    fn read_resource_principal_revocation(
        &self,
        scope: &str,
        grant_id: &str,
        origin: &str,
    ) -> Result<Option<StoredResourcePrincipalRevocation>, String> {
        let path = self.resource_principal_revocation_path(scope, grant_id)?;
        if !path.exists() {
            return Ok(None);
        }
        let stored: StoredResourcePrincipalRevocation = serde_json::from_slice(
            &fs::read(path).map_err(|_| "Storage principal revocation unavailable")?,
        )
        .map_err(|_| "Invalid stored storage principal revocation")?;
        let receipt = &stored.receipt;
        let payload: ResourcePrincipalRevocationReceiptPayload =
            serde_json::from_value(receipt.payload.clone())
                .map_err(|_| "Invalid stored storage principal revocation")?;
        let service_key = self.public_key()?;
        let service_id = public_key_id(&service_key)?;
        if receipt.signer_key_id != service_id
            || !verify_signed_envelope(receipt, &service_key, DOMAIN)?
            || payload.kind != "rusty-resource-principal-revocation-receipt"
            || payload.version != 1
            || payload.service_id != service_id
            || payload.origin != origin
            || payload.storage_scope_id != scope
            || payload.grant_id != grant_id
            || payload.workspace_id.is_empty()
            || payload.subject_person_id.is_empty()
            || payload.policy_epoch == 0
            || payload.request_hash.len() != 43
        {
            return Err("Stored storage principal revocation integrity failure".into());
        }
        Ok(Some(stored))
    }
    fn register_resource_principal_grant(
        &self,
        scope: &str,
        grant_id: &str,
        request: ResourcePrincipalGrantRequest,
        origin: &str,
    ) -> Result<(), String> {
        if request.version != 1 || !valid_id(scope) || !valid_id(grant_id) {
            return Err("Invalid storage principal grant request".into());
        }
        let payload = &request.grant.payload;
        let owner_gate = self.identity_authority_gate(&payload.owner_person_id)?;
        let _owner_guard = owner_gate
            .try_write()
            .map_err(|_| "Identity authority lock unavailable")?;
        let scope_gate = self.resource_scope_gate(scope)?;
        let _scope_guard = scope_gate
            .try_write()
            .map_err(|_| "Resource scope lock unavailable")?;
        let _guard = self.lock.lock().map_err(|_| "Storage lock unavailable")?;
        if self
            .read_resource_principal_revocation(scope, grant_id, origin)?
            .is_some()
        {
            return Err("Storage principal grant ID has been revoked".into());
        }
        if self.identity_is_retired(&payload.owner_person_id)? {
            return Err("Storage owner Identity root has been retired".into());
        }
        let policy = self.policy(scope)?;
        if policy.owner_person_id.is_none() {
            return Err("Storage resource owner is unavailable".into());
        }
        let accepted_scope_authority = self
            .read_scope_authority(scope)?
            .ok_or("Storage scope authority is not registered")?;
        if payload.scope_authority != accepted_scope_authority.snapshot {
            return Err("Storage principal grant does not use the accepted scope authority".into());
        }
        let validated_scope_authority = meta_mesh_core::validate_scope_authority_at(
            &accepted_scope_authority.snapshot,
            now_ms()? as i128,
        )
        .map_err(|_| "Workspace scope authority is invalid")?;
        if payload.workspace_id != validated_scope_authority.scope_id {
            return Err("Storage principal grant workspace mismatch".into());
        }
        let owner = self
            .read_identity_authority(&payload.owner_person_id)?
            .ok_or("Storage owner Identity authority is not registered")?
            .view
            .verify()?;
        payload.verify(
            &request.grant,
            &owner,
            &public_key_id(&self.public_key()?)?,
            origin,
            scope,
            &validated_scope_authority.scope_id,
            true,
            now_ms()?,
        )?;
        if payload.grant_id != grant_id {
            return Err("Storage principal grant ID mismatch".into());
        }
        let path = self.resource_principal_path(scope, &payload.subject_person_id)?;
        if path.exists() {
            let previous: StoredResourcePrincipalGrant = serde_json::from_slice(
                &fs::read(&path).map_err(|_| "Storage principal grant unavailable")?,
            )
            .map_err(|_| "Invalid stored storage principal grant")?;
            let previous_payload = &previous.grant.payload;
            if previous_payload.workspace_id != payload.workspace_id
                || previous_payload.subject_person_id != payload.subject_person_id
                || previous_payload.subject_public_key != payload.subject_public_key
            {
                return Err("Storage principal grant binding changed".into());
            }
            if previous_payload.grant_id == payload.grant_id {
                if previous_payload.owner_person_id != payload.owner_person_id {
                    return Err("Storage principal grant binding changed".into());
                }
                if previous_payload.policy_epoch > payload.policy_epoch {
                    return Err("Storage principal grant epoch is stale".into());
                }
                if previous_payload.policy_epoch == payload.policy_epoch {
                    if previous_payload != payload {
                        return Err("Storage principal grant epoch conflicts".into());
                    }
                    if previous.grant == request.grant {
                        return Ok(());
                    }
                }
            } else if self
                .read_resource_principal_revocation(scope, &previous_payload.grant_id, origin)?
                .is_none()
            {
                return Err("Storage principal grant replacement requires prior revocation".into());
            }
        }
        let stored = StoredResourcePrincipalGrant {
            grant: request.grant,
        };
        atomic_write(
            &path,
            &serde_json::to_vec(&stored).map_err(|_| "Invalid storage principal grant")?,
        )
    }
    fn revoke_resource_principal(
        &self,
        scope: &str,
        grant_id: &str,
        request: ResourcePrincipalRevocationRequest,
        origin: &str,
    ) -> Result<SignedEnvelope<Value>, String> {
        if request.version != 1 || !valid_id(scope) || !valid_id(grant_id) {
            return Err("Invalid storage principal revocation request".into());
        }
        let payload = &request.authorization.payload;
        if payload.storage_scope_id != scope || payload.grant_id != grant_id {
            return Err("Storage principal revocation route binding mismatch".into());
        }
        let request_hash = request.request_hash()?;
        if payload.request_hash != request_hash {
            return Err("Storage principal revocation request hash mismatch".into());
        }

        // The scope gate serializes this decision against scope controller and grant changes.
        let observed = self
            .read_scope_authority(scope)?
            .ok_or("Storage scope authority is not registered")?;
        let observed_authority =
            meta_mesh_core::validate_scope_authority_at(&observed.snapshot, now_ms()? as i128)
                .map_err(|_| "Workspace scope authority is invalid")?;
        let controller_person_id = observed_authority.controller.person_id.clone();
        let owner_gate = self.identity_authority_gate(&controller_person_id)?;
        let _owner_guard = owner_gate
            .try_write()
            .map_err(|_| "Identity authority lock unavailable")?;
        let scope_gate = self.resource_scope_gate(scope)?;
        let _scope_guard = scope_gate
            .try_write()
            .map_err(|_| "Resource scope lock unavailable")?;
        let _guard = self.lock.lock().map_err(|_| "Storage lock unavailable")?;

        if let Some(stored) = self.read_resource_principal_revocation(scope, grant_id, origin)? {
            if stored.receipt.payload["requestHash"] == request_hash {
                return Ok(stored.receipt);
            }
            return Err("Storage principal grant ID has a conflicting revocation".into());
        }

        let accepted = self
            .read_scope_authority(scope)?
            .ok_or("Storage scope authority is not registered")?;
        let authority =
            meta_mesh_core::validate_scope_authority_at(&accepted.snapshot, now_ms()? as i128)
                .map_err(|_| "Workspace scope authority is invalid")?;
        if authority.controller.person_id != controller_person_id {
            return Err("Storage scope controller changed during principal revocation".into());
        }
        if payload.workspace_id != authority.scope_id {
            return Err("Storage principal revocation workspace mismatch".into());
        }
        if self.identity_is_retired(&controller_person_id)? {
            return Err("Storage owner Identity root has been retired".into());
        }
        let owner = self
            .read_identity_authority(&controller_person_id)?
            .ok_or("Storage owner Identity authority is not registered")?;
        payload.verify(
            &request.authorization,
            &owner.view,
            &authority,
            &public_key_id(&self.public_key()?)?,
            origin,
            scope,
        )?;

        // If this principal is still registered, revoke only its exact workspace grant epoch.
        let principal_path = self.resource_principal_path(scope, &payload.subject_person_id)?;
        if principal_path.exists() {
            let stored: StoredResourcePrincipalGrant = serde_json::from_slice(
                &fs::read(principal_path).map_err(|_| "Storage principal grant unavailable")?,
            )
            .map_err(|_| "Invalid stored storage principal grant")?;
            let principal = &stored.grant.payload;
            if principal.workspace_id != payload.workspace_id
                || principal.grant_id != grant_id
                || principal.subject_person_id != payload.subject_person_id
                || principal.policy_epoch != payload.policy_epoch
            {
                return Err("Storage principal revocation target is stale".into());
            }
        }

        let service_id = public_key_id(&self.public_key()?)?;
        let receipt = sign_json_envelope(
            &self.seed,
            serde_json::to_value(ResourcePrincipalRevocationReceiptPayload {
                kind: "rusty-resource-principal-revocation-receipt".into(),
                version: 1,
                service_id: service_id.clone(),
                origin: origin.to_owned(),
                storage_scope_id: scope.to_owned(),
                workspace_id: payload.workspace_id.clone(),
                grant_id: payload.grant_id.clone(),
                subject_person_id: payload.subject_person_id.clone(),
                policy_epoch: payload.policy_epoch,
                request_hash,
                committed_at: now_ms()?,
            })
            .map_err(|_| "Invalid storage principal revocation receipt")?,
            service_id,
            DOMAIN,
        )?;
        atomic_write(
            &self.resource_principal_revocation_path(scope, grant_id)?,
            &serde_json::to_vec(&StoredResourcePrincipalRevocation {
                receipt: receipt.clone(),
            })
            .map_err(|_| "Invalid storage principal revocation")?,
        )?;
        Ok(receipt)
    }
    pub fn with_telemetry(mut self, telemetry: Telemetry) -> Self {
        self.telemetry = telemetry;
        self
    }
    fn publication_paths(&self, board_id: &str) -> Result<(PathBuf, PathBuf, PathBuf), String> {
        if !valid_id(board_id) {
            return Err("Invalid board ID".into());
        }
        let root = self.directory.join("publications");
        Ok((
            root.join("records").join(format!("{board_id}.json")),
            root.join("challenges"),
            root,
        ))
    }
    fn current_publication(&self, board_id: &str) -> Result<Option<PublicPublication>, String> {
        let (record_path, _, _) = self.publication_paths(board_id)?;
        if !record_path.exists() {
            return Ok(None);
        }
        let bytes = fs::read(record_path).map_err(|_| "Public publication unavailable")?;
        let record: PublicPublication =
            serde_json::from_slice(&bytes).map_err(|_| "Invalid public publication")?;
        if record.board_id != board_id
            || record.revision == 0
            || (record.withdrawn && record.projection.is_some())
            || (!record.withdrawn && record.projection.is_none())
            || record.projection.as_ref().is_some_and(|value| {
                validate_public_projection(value).is_err() || value["board"]["id"] != board_id
            })
        {
            return Err("Public publication integrity failure".into());
        }
        if let Some(projection) = &record.projection {
            if digest(canonicalize_json(projection)?.as_bytes()) != record.projection_hash {
                return Err("Public publication hash mismatch".into());
            }
        }
        Ok(Some(record))
    }
    fn publication_file(
        &self,
        board_id: &str,
        revision: u64,
        sha256: &str,
    ) -> Result<(Vec<u8>, String, String), String> {
        let _guard = self.lock.lock().map_err(|_| "Storage lock unavailable")?;
        let record = self
            .current_publication(board_id)?
            .filter(|record| !record.withdrawn)
            .ok_or("Public board unavailable")?;
        if revision == 0 || revision > record.revision {
            return Err("Public file revision is invalid or from the future".into());
        }
        let manifest = record
            .projection
            .as_ref()
            .and_then(|projection| projection["files"].as_array())
            .ok_or("Public file manifest unavailable")?;
        let entry = manifest
            .iter()
            .find(|entry| entry["sha256"] == sha256)
            .ok_or("Public file is not in the active manifest")?;
        let bytes = fs::read(
            self.directory
                .join("publications")
                .join("files")
                .join(format!("{sha256}.bin")),
        )
        .map_err(|_| "Public file unavailable")?;
        let size = entry["byteLength"]
            .as_u64()
            .ok_or("Invalid public file manifest")?;
        if bytes.len() as u64 != size || digest(&bytes) != sha256 {
            return Err("Public file integrity failure".into());
        }
        let media_type = entry["mediaType"]
            .as_str()
            .unwrap_or("application/octet-stream")
            .to_owned();
        let filename = entry["fileName"]
            .as_str()
            .ok_or("Invalid public file name")?
            .to_owned();
        Ok((bytes, media_type, filename))
    }
    #[cfg(test)]
    fn create_public_challenge(
        &self,
        board_id: &str,
        person_id: &str,
        device_id: &str,
        device_key_id: &str,
        origin: &str,
    ) -> Result<SignedEnvelope<Value>, String> {
        let _guard = self.lock.lock().map_err(|_| "Storage lock unavailable")?;
        self.create_public_challenge_unlocked(
            board_id,
            person_id,
            device_id,
            device_key_id,
            origin,
            None,
            None,
        )
    }
    fn create_public_challenge_unlocked(
        &self,
        board_id: &str,
        person_id: &str,
        device_id: &str,
        device_key_id: &str,
        origin: &str,
        delivery: Option<&PublicDeliveryBinding>,
        owner_source_heads: Option<&[String]>,
    ) -> Result<SignedEnvelope<Value>, String> {
        let (record_path, challenge_dir, root) = self.publication_paths(board_id)?;
        fs::create_dir_all(&challenge_dir).map_err(|_| "Publication storage unavailable")?;
        File::open(&root)
            .and_then(|file| file.sync_all())
            .map_err(|_| "Publication durability failed")?;
        File::open(root.parent().ok_or("Publication storage unavailable")?)
            .and_then(|file| file.sync_all())
            .map_err(|_| "Publication durability failed")?;
        let now = now_ms()?;
        let mut pending_count = 0usize;
        for entry in fs::read_dir(&challenge_dir).map_err(|_| "Publication storage unavailable")? {
            let path = entry.map_err(|_| "Publication storage unavailable")?.path();
            if path.extension().is_none_or(|extension| extension != "json") {
                return Err("Invalid publication challenge state".into());
            }
            let pending: PendingPublicChallenge = serde_json::from_slice(
                &fs::read(&path).map_err(|_| "Invalid publication challenge state")?,
            )
            .map_err(|_| "Invalid publication challenge state")?;
            if pending.expires_at <= now {
                fs::remove_file(path).map_err(|_| "Publication storage unavailable")?;
            } else {
                pending_count += 1;
            }
        }
        if pending_count >= MAX_PENDING_CHALLENGES {
            return Err("Publication challenge capacity exceeded".into());
        }
        let current = if record_path.exists() {
            self.current_publication(board_id)?
                .ok_or("Public publication unavailable")?
        } else {
            PublicPublication {
                board_id: board_id.into(),
                controller_person_id: String::new(),
                revision: 0,
                withdrawn: false,
                projection: None,
                projection_hash: digest(b"null"),
                delivery_policy: None,
                source_heads: Vec::new(),
            }
        };
        let revision = current.revision;
        let issued_at = now;
        let expires_at = issued_at
            .checked_add(ENROLLMENT_CHALLENGE_TTL_MS)
            .ok_or("Publication time overflow")?;
        let challenge_id = URL_SAFE_NO_PAD.encode(rand::random::<[u8; 32]>());
        let nonce = URL_SAFE_NO_PAD.encode(rand::random::<[u8; 32]>());
        let service_id = public_key_id(&self.public_key()?)?;
        let source_heads_hash = delivery
            .map(|binding| binding.source_heads_hash.clone())
            .or_else(|| owner_source_heads.and_then(|heads| validate_source_heads(heads).ok()));
        let current_delivery_policy_hash = current
            .delivery_policy
            .as_ref()
            .map(|policy| {
                serde_json::to_value(policy)
                    .map_err(|_| "Public delivery policy invalid".to_owned())
                    .and_then(|value| canonicalize_json(&value))
            })
            .transpose()?
            .map(|canonical| digest(canonical.as_bytes()));
        let delivery_generation = delivery.map(|binding| binding.generation).or_else(|| {
            current
                .delivery_policy
                .as_ref()
                .map(|policy| policy.policy.payload.generation)
        });
        let delivery_policy_content_hash = current
            .delivery_policy
            .as_ref()
            .map(public_delivery_policy_content_hash)
            .transpose()?;
        let envelope = sign_json_envelope(
            &self.seed,
            json!({
                "kind":"rusty-publication-challenge", "version":1, "challengeId":challenge_id, "nonce":nonce,
                "serviceId":service_id, "publicOrigin":origin, "boardId":board_id, "personId":person_id,
                "deviceId":device_id, "deviceKeyId":device_key_id, "expectedRevision":revision,
                "issuedAt":issued_at, "expiresAt":expires_at, "withdrawn":current.withdrawn, "projectionHash":current.projection_hash
                ,"deliveryGeneration":delivery_generation,
                "deliveryGrantId":delivery.map(|binding| binding.grant_id.as_str()),
                "sourceHeadsHash":source_heads_hash,
                "currentSourceHeads":current.source_heads,
                "deliveryPolicyHash":current_delivery_policy_hash,
                "deliveryPolicyContentHash":delivery_policy_content_hash
            }),
            service_id,
            DOMAIN,
        )?;
        let pending = PendingPublicChallenge {
            board_id: board_id.into(),
            person_id: person_id.into(),
            device_id: device_id.into(),
            expires_at,
            delivery_generation: delivery.map(|binding| binding.generation),
            delivery_grant_id: delivery.map(|binding| binding.grant_id.clone()),
            source_heads_hash,
            envelope: envelope.clone(),
        };
        atomic_write(
            &challenge_dir.join(format!("{challenge_id}.json")),
            &serde_json::to_vec(&pending).map_err(|_| "Publication challenge invalid")?,
        )?;
        File::open(&root)
            .and_then(|file| file.sync_all())
            .map_err(|_| "Publication durability failed")?;
        Ok(envelope)
    }
    fn stage_public_file(
        &self,
        board_id: &str,
        request: PublicAssetRequest,
        owner: &ResourceOwner,
        origin: &str,
    ) -> Result<SignedEnvelope<Value>, String> {
        let _guard = self.lock.lock().map_err(|_| "Storage lock unavailable")?;
        if !valid_id(board_id) || request.certificates.is_empty() {
            return Err("Untrusted publication controller or device".into());
        }
        let current = self.current_publication(board_id)?;
        let delivery_binding = if trusted_identity_matches(&request.identity, &owner.identity) {
            if request.delivery_grant.is_some() {
                return Err("Owner publication cannot use a delivery grant".into());
            }
            request
                .source_heads
                .as_deref()
                .map(validate_source_heads)
                .transpose()?;
            if current
                .as_ref()
                .is_some_and(|record| !record.source_heads.is_empty())
                && request.source_heads.is_none()
            {
                return Err("Publication file staging requires a source frontier".into());
            }
            if !self.management_authorized(
                owner,
                &request.identity,
                &request.device_id,
                &request.certificates,
                "board",
                board_id,
                "publication.stage-file",
                request.management_capability.as_ref(),
                origin,
            )? {
                return Err("Untrusted publication controller or device".into());
            }
            None
        } else {
            if request.management_capability.is_some() {
                return Err("Public delivery writers cannot manage publication".into());
            }
            if !self.identity_device_certificate_matches(
                &request.identity,
                &request.device_id,
                &request.certificates,
            )? {
                return Err("Public delivery device is revoked or not registered".into());
            }
            let publication = current.as_ref().ok_or("Public publication unavailable")?;
            let grant = request
                .delivery_grant
                .as_ref()
                .ok_or("Missing public delivery grant")?;
            let source_heads = request
                .source_heads
                .as_deref()
                .ok_or("Missing public source heads")?;
            Some(authorize_public_delivery_writer(
                publication,
                owner,
                board_id,
                &request.identity,
                &request.device_id,
                &request.certificates,
                grant,
                source_heads,
                now_ms()?,
            )?)
        };
        if request.sha256.len() != 43
            || !request
                .sha256
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
            || request.byte_length > 16 * 1024 * 1024
        {
            return Err("Invalid public asset digest or size".into());
        }
        let bytes = URL_SAFE_NO_PAD
            .decode(&request.bytes)
            .map_err(|_| "Invalid public asset bytes")?;
        if bytes.len() as u64 != request.byte_length || digest(&bytes) != request.sha256 {
            return Err("Public asset digest or size mismatch".into());
        }
        let device_public_key = verify_device_certificate_chain(
            &request.identity,
            &request.device_id,
            &request.certificates,
            "MATCH/1",
        )?;
        let device_key_id = public_key_id(&device_public_key)?;
        let (_, challenge_dir, root) = self.publication_paths(board_id)?;
        let challenge_id = request
            .challenge
            .payload
            .get("challengeId")
            .and_then(Value::as_str)
            .filter(|id| valid_id(id))
            .ok_or("Invalid publication challenge")?;
        let challenge_path = challenge_dir.join(format!("{challenge_id}.json"));
        let pending: PendingPublicChallenge = serde_json::from_slice(
            &fs::read(&challenge_path).map_err(|_| "Publication challenge expired or consumed")?,
        )
        .map_err(|_| "Publication challenge invalid")?;
        let service_id = public_key_id(&self.public_key()?)?;
        if pending.envelope != request.challenge
            || request.challenge.signer_key_id != service_id
            || !verify_signed_envelope(&request.challenge, &self.public_key()?, DOMAIN)?
            || pending.board_id != board_id
            || pending.person_id != request.identity.person_id
            || pending.device_id != request.device_id
            || pending.expires_at <= now_ms()?
        {
            return Err("Publication challenge binding, signature, or expiry invalid".into());
        }
        let challenge = &request.challenge.payload;
        let command = &request.authorization.payload;
        if !exact_keys_with_optional(
            command,
            &[
                "kind",
                "version",
                "challengeId",
                "nonce",
                "serviceId",
                "publicOrigin",
                "boardId",
                "action",
                "projectionHash",
                "expectedRevision",
                "expiresAt",
                "byteLength",
            ],
            &[
                "managementRevision",
                "deliveryGeneration",
                "deliveryGrantId",
                "sourceHeadsHash",
            ],
        ) || command["kind"] != "rusty-publication-command"
            || command["version"] != 1
            || command["challengeId"] != challenge["challengeId"]
            || command["nonce"] != challenge["nonce"]
            || command["serviceId"] != service_id
            || command["publicOrigin"] != origin
            || command["boardId"] != board_id
            || command["action"] != "stage-file"
            || command["projectionHash"] != request.sha256
            || command["expectedRevision"] != challenge["expectedRevision"]
            || command["expiresAt"] != challenge["expiresAt"]
            || command["byteLength"].as_u64() != Some(request.byte_length)
            || request.authorization.signer_key_id != device_key_id
            || !verify_signed_envelope(&request.authorization, &device_public_key, "MATCH/1")?
        {
            return Err("Public asset command signature or binding invalid".into());
        }
        match &delivery_binding {
            Some(binding)
                if pending.delivery_generation == Some(binding.generation)
                    && pending.delivery_grant_id.as_deref() == Some(&binding.grant_id)
                    && pending.source_heads_hash.as_deref()
                        == Some(binding.source_heads_hash.as_str())
                    && command.get("deliveryGeneration").and_then(Value::as_u64)
                        == Some(binding.generation)
                    && command.get("deliveryGrantId").and_then(Value::as_str)
                        == Some(binding.grant_id.as_str())
                    && command.get("sourceHeadsHash").and_then(Value::as_str)
                        == Some(binding.source_heads_hash.as_str()) => {}
            Some(_) => return Err("Public delivery binding mismatch".into()),
            None if pending.delivery_generation.is_none()
                && pending.delivery_grant_id.is_none()
                && command.get("deliveryGeneration").is_none()
                && command.get("deliveryGrantId").is_none() => {}
            None => return Err("Unexpected public delivery binding".into()),
        }
        let owner_source_heads_hash = if delivery_binding.is_none()
            && trusted_identity_matches(&request.identity, &owner.identity)
        {
            request
                .source_heads
                .as_deref()
                .map(validate_source_heads)
                .transpose()?
        } else {
            None
        };
        let expected_source_heads_hash = delivery_binding
            .as_ref()
            .map(|binding| binding.source_heads_hash.as_str())
            .or(owner_source_heads_hash.as_deref());
        if pending.source_heads_hash.as_deref() != expected_source_heads_hash
            || command.get("sourceHeadsHash").and_then(Value::as_str) != expected_source_heads_hash
        {
            return Err("Public source frontier binding mismatch".into());
        }
        let management_revision = optional_management_revision(command)?;
        if (delivery_binding.is_some() && management_revision.is_some())
            || (delivery_binding.is_none()
                && !self.management_revision_matches("board", board_id, management_revision)?)
        {
            return Err("Public asset management revision binding invalid".into());
        }
        let current_revision = current.as_ref().map(|record| record.revision).unwrap_or(0);
        if challenge["expectedRevision"].as_u64() != Some(current_revision) {
            return Err("Publication revision conflict".into());
        }
        let files = root.join("files");
        fs::create_dir_all(&files).map_err(|_| "Publication storage unavailable")?;
        File::open(&root)
            .and_then(|file| file.sync_all())
            .map_err(|_| "Publication durability failed")?;
        File::open(root.parent().ok_or("Publication storage unavailable")?)
            .and_then(|file| file.sync_all())
            .map_err(|_| "Publication durability failed")?;
        let path = files.join(format!("{}.bin", request.sha256));
        if path.exists() {
            let existing = fs::read(&path).map_err(|_| "Staged public asset unavailable")?;
            if existing != bytes {
                return Err("Staged public asset digest collision".into());
            }
            File::open(&path)
                .and_then(|file| {
                    file.set_times(fs::FileTimes::new().set_modified(SystemTime::now()))?;
                    file.sync_all()
                })
                .map_err(|_| "Staged public asset unavailable")?;
        } else {
            atomic_write(&path, &bytes)?;
        }
        fs::remove_file(&challenge_path).map_err(|_| "Publication challenge consume failed")?;
        File::open(&challenge_dir)
            .and_then(|file| file.sync_all())
            .map_err(|_| "Publication durability failed")?;
        File::open(&root)
            .and_then(|file| file.sync_all())
            .map_err(|_| "Publication durability failed")?;
        let authorization_value = serde_json::to_value(&request.authorization)
            .map_err(|_| "Publication command invalid")?;
        let authorization_hash = digest(canonicalize_json(&authorization_value)?.as_bytes());
        sign_json_envelope(
            &self.seed,
            json!({"kind":"rusty-public-asset-receipt", "version":1, "serviceId":service_id, "boardId":board_id,
            "sha256":request.sha256,"byteLength":request.byte_length,"challengeId":challenge_id,"authorizationHash":authorization_hash}),
            service_id,
            DOMAIN,
        )
    }
    fn mutate_publication(
        &self,
        board_id: &str,
        request: PublicMutationRequest,
        owner: &ResourceOwner,
        origin: &str,
    ) -> Result<SignedEnvelope<Value>, String> {
        let _guard = self.lock.lock().map_err(|_| "Storage lock unavailable")?;
        if !valid_id(board_id) || request.certificates.is_empty() {
            return Err("Untrusted publication controller or device".into());
        }
        let current = self.current_publication(board_id)?;
        let is_owner = trusted_identity_matches(&request.identity, &owner.identity);
        let delivery_binding = if is_owner {
            if request.delivery_grant.is_some() {
                return Err("Owner publication cannot use a delivery grant".into());
            }
            if !self.management_authorized(
                owner,
                &request.identity,
                &request.device_id,
                &request.certificates,
                "board",
                board_id,
                &format!("publication.{}", request.action),
                request.management_capability.as_ref(),
                origin,
            )? {
                return Err("Untrusted publication controller or device".into());
            }
            None
        } else {
            if request.action != "update"
                || request.management_capability.is_some()
                || request.delivery_policy.is_some()
            {
                return Err("Public delivery writers may only update content".into());
            }
            if !self.identity_device_certificate_matches(
                &request.identity,
                &request.device_id,
                &request.certificates,
            )? {
                return Err("Public delivery device is revoked or not registered".into());
            }
            let publication = current.as_ref().ok_or("Public publication unavailable")?;
            let grant = request
                .delivery_grant
                .as_ref()
                .ok_or("Missing public delivery grant")?;
            let source_heads = request
                .source_heads
                .as_deref()
                .ok_or("Missing public source heads")?;
            Some(authorize_public_delivery_writer(
                publication,
                owner,
                board_id,
                &request.identity,
                &request.device_id,
                &request.certificates,
                grant,
                source_heads,
                now_ms()?,
            )?)
        };
        let owner_source_heads_hash = if is_owner {
            request
                .source_heads
                .as_deref()
                .map(validate_source_heads)
                .transpose()?
        } else {
            None
        };
        if is_owner
            && request.action != "unpublish"
            && current
                .as_ref()
                .is_some_and(|record| !record.source_heads.is_empty())
            && request.source_heads.is_none()
        {
            return Err("Publication update requires a source frontier".into());
        }
        let device_public_key = verify_device_certificate_chain(
            &request.identity,
            &request.device_id,
            &request.certificates,
            "MATCH/1",
        )?;
        let device_key_id = public_key_id(&device_public_key)?;
        if device_key_id != request.device_id {
            return Err("Publication controller key mismatch".into());
        }
        if !["publish", "update", "unpublish"].contains(&request.action.as_str()) {
            return Err("Invalid publication action".into());
        }
        if request.action == "unpublish" && request.projection.is_some()
            || request.action != "unpublish" && request.projection.is_none()
        {
            return Err("Publication action and projection mismatch".into());
        }
        let projection = request.projection;
        let projection_hash = if let Some(value) = &projection {
            validate_public_projection(value)?;
            if value["board"]["id"] != board_id {
                return Err("Publication board ID does not match route".into());
            }
            let bytes = canonicalize_json(value)?.into_bytes();
            if bytes.len() > MAX_PUBLICATION_BYTES {
                return Err("Public projection exceeds size limit".into());
            }
            digest(&bytes)
        } else {
            digest(b"null")
        };
        if delivery_binding
            .as_ref()
            .is_some_and(|binding| binding.role == WorkspaceRole::Automation)
        {
            let before = current
                .as_ref()
                .and_then(|record| record.projection.as_ref())
                .ok_or("Automation delivery requires an existing public projection")?;
            let after = projection
                .as_ref()
                .ok_or("Automation delivery cannot withdraw publication")?;
            let scope = request
                .delivery_grant
                .as_ref()
                .and_then(|grant| grant.payload.automation.as_ref())
                .ok_or("Automation delivery grant scope missing")?;
            validate_automation_publication_delta(before, after, board_id, scope)?;
        }
        let (record_path, challenge_dir, root) = self.publication_paths(board_id)?;
        fs::create_dir_all(root.join("records")).map_err(|_| "Publication storage unavailable")?;
        File::open(&root)
            .and_then(|file| file.sync_all())
            .map_err(|_| "Publication durability failed")?;
        File::open(root.parent().ok_or("Publication storage unavailable")?)
            .and_then(|file| file.sync_all())
            .map_err(|_| "Publication durability failed")?;
        let challenge_id = request
            .challenge
            .payload
            .get("challengeId")
            .and_then(Value::as_str)
            .filter(|value| valid_id(value))
            .ok_or("Invalid publication challenge")?;
        let challenge_path = challenge_dir.join(format!("{challenge_id}.json"));
        let pending: PendingPublicChallenge = serde_json::from_slice(
            &fs::read(&challenge_path).map_err(|_| "Publication challenge expired or consumed")?,
        )
        .map_err(|_| "Publication challenge invalid")?;
        let service_public_key = self.public_key()?;
        let service_id = public_key_id(&service_public_key)?;
        if pending.envelope != request.challenge
            || request.challenge.signer_key_id != service_id
            || !verify_signed_envelope(&request.challenge, &service_public_key, DOMAIN)?
            || pending.board_id != board_id
            || pending.person_id != request.identity.person_id
            || pending.device_id != request.device_id
            || pending.expires_at <= now_ms()?
        {
            return Err("Publication challenge binding, signature, or expiry invalid".into());
        }
        let command = &request.authorization.payload;
        let challenge_payload = &request.challenge.payload;
        if !exact_keys_with_optional(
            command,
            &[
                "kind",
                "version",
                "challengeId",
                "nonce",
                "serviceId",
                "publicOrigin",
                "boardId",
                "action",
                "projectionHash",
                "expectedRevision",
                "expiresAt",
            ],
            &[
                "managementRevision",
                "deliveryGeneration",
                "deliveryGrantId",
                "sourceHeadsHash",
                "deliveryPolicyHash",
            ],
        ) || command.get("kind").and_then(Value::as_str) != Some("rusty-publication-command")
            || command.get("version").and_then(Value::as_u64) != Some(1)
            || command.get("challengeId").and_then(Value::as_str) != Some(challenge_id)
            || command.get("nonce") != challenge_payload.get("nonce")
            || command.get("serviceId").and_then(Value::as_str) != Some(service_id.as_str())
            || command.get("publicOrigin").and_then(Value::as_str) != Some(origin)
            || command.get("boardId").and_then(Value::as_str) != Some(board_id)
            || command.get("action").and_then(Value::as_str) != Some(request.action.as_str())
            || command.get("projectionHash").and_then(Value::as_str)
                != Some(projection_hash.as_str())
            || command.get("expectedRevision") != challenge_payload.get("expectedRevision")
            || command.get("expiresAt") != challenge_payload.get("expiresAt")
            || request.authorization.signer_key_id != device_key_id
            || !verify_signed_envelope(&request.authorization, &device_public_key, "MATCH/1")?
        {
            return Err("Publication command signature or binding invalid".into());
        }
        match &delivery_binding {
            Some(binding)
                if pending.delivery_generation == Some(binding.generation)
                    && pending.delivery_grant_id.as_deref() == Some(&binding.grant_id)
                    && pending.source_heads_hash.as_deref()
                        == Some(binding.source_heads_hash.as_str())
                    && command.get("deliveryGeneration").and_then(Value::as_u64)
                        == Some(binding.generation)
                    && command.get("deliveryGrantId").and_then(Value::as_str)
                        == Some(binding.grant_id.as_str())
                    && command.get("sourceHeadsHash").and_then(Value::as_str)
                        == Some(binding.source_heads_hash.as_str()) => {}
            Some(_) => return Err("Public delivery binding mismatch".into()),
            None if pending.delivery_generation.is_none()
                && pending.delivery_grant_id.is_none()
                && command.get("deliveryGeneration").is_none()
                && command.get("deliveryGrantId").is_none() => {}
            None => return Err("Unexpected public delivery binding".into()),
        }
        let expected_source_heads_hash = delivery_binding
            .as_ref()
            .map(|binding| binding.source_heads_hash.as_str())
            .or(owner_source_heads_hash.as_deref());
        if pending.source_heads_hash.as_deref() != expected_source_heads_hash
            || command.get("sourceHeadsHash").and_then(Value::as_str) != expected_source_heads_hash
        {
            return Err("Public source frontier binding mismatch".into());
        }
        let delivery_policy_hash = request
            .delivery_policy
            .as_ref()
            .map(|evidence| {
                canonicalize_json(&serde_json::to_value(evidence).unwrap_or(Value::Null))
            })
            .transpose()?
            .map(|canonical| digest(canonical.as_bytes()));
        if command.get("deliveryPolicyHash").and_then(Value::as_str)
            != delivery_policy_hash.as_deref()
        {
            return Err("Public delivery policy binding mismatch".into());
        }
        let management_revision = optional_management_revision(command)?;
        if (delivery_binding.is_some() && management_revision.is_some())
            || (delivery_binding.is_none()
                && !self.management_revision_matches("board", board_id, management_revision)?)
        {
            return Err("Publication management revision binding invalid".into());
        }
        let expected_revision = challenge_payload
            .get("expectedRevision")
            .and_then(Value::as_u64)
            .ok_or("Invalid publication revision")?;
        let current_revision = current.as_ref().map(|record| record.revision).unwrap_or(0);
        if current_revision != expected_revision {
            return Err("Publication revision conflict".into());
        }
        if current
            .as_ref()
            .is_some_and(|record| record.controller_person_id != owner.identity.person_id)
        {
            return Err("Publication controller conflict".into());
        }
        if expected_revision == 0 && request.action != "publish"
            || expected_revision > 0
                && request.action == "publish"
                && !current.as_ref().is_some_and(|record| record.withdrawn)
            || current.as_ref().is_some_and(|record| record.withdrawn) && request.action == "update"
        {
            return Err("Publication action does not match current state".into());
        }
        if current
            .as_ref()
            .is_some_and(|record| record.withdrawn && record.delivery_policy.is_some())
            && request.action == "publish"
            && request.delivery_policy.is_none()
        {
            return Err("Re-enabling publication requires a fresh delivery policy".into());
        }
        let next_delivery_policy = if let Some(evidence) = &request.delivery_policy {
            let current_generation = current
                .as_ref()
                .and_then(|record| record.delivery_policy.as_ref())
                .map(|policy| policy.policy.payload.generation);
            validate_public_board_delivery_policy(
                evidence,
                owner,
                board_id,
                current_generation,
                now_ms()?,
            )?;
            if current_generation.is_none() && evidence.policy.payload.generation != 1 {
                return Err("Public delivery policy generation conflict".into());
            }
            if current
                .as_ref()
                .and_then(|record| record.delivery_policy.as_ref())
                .is_some_and(|existing| {
                    existing.policy.payload.workspace_id != evidence.policy.payload.workspace_id
                        || evidence.policy.payload.access_epoch
                            < existing.policy.payload.access_epoch
                })
            {
                return Err("Public delivery policy authority regression".into());
            }
            Some(evidence.clone())
        } else {
            current
                .as_ref()
                .and_then(|record| record.delivery_policy.clone())
        };
        if let Some(value) = &projection {
            for file in value["files"].as_array().ok_or("Invalid public files")? {
                let sha256 = file["sha256"]
                    .as_str()
                    .ok_or("Invalid public attachment digest")?;
                let name = file["fileName"].as_str().unwrap_or("attachment");
                let bytes = fs::read(
                    self.directory
                        .join("publications")
                        .join("files")
                        .join(format!("{sha256}.bin")),
                )
                .map_err(|_| format!("Public attachment {name} has not been staged"))?;
                if bytes.len() as u64 != file["byteLength"].as_u64().unwrap_or(u64::MAX)
                    || digest(&bytes) != sha256
                {
                    return Err("Staged public attachment failed integrity validation".into());
                }
            }
        }
        let revision = expected_revision
            .checked_add(1)
            .ok_or("Publication revision exhausted")?;
        let withdrawn = request.action == "unpublish";
        let record = PublicPublication {
            board_id: board_id.into(),
            controller_person_id: current
                .as_ref()
                .map(|record| record.controller_person_id.clone())
                .unwrap_or_else(|| request.identity.person_id.clone()),
            revision,
            withdrawn,
            projection,
            projection_hash: projection_hash.clone(),
            delivery_policy: next_delivery_policy,
            source_heads: delivery_binding
                .as_ref()
                .map(|binding| binding.source_heads.clone())
                .or_else(|| request.source_heads.clone())
                .or_else(|| current.as_ref().map(|record| record.source_heads.clone()))
                .unwrap_or_default(),
        };
        let bytes = serde_json::to_vec(&record).map_err(|_| "Public publication invalid")?;
        self.retain_publication_owner(board_id, owner)?;
        atomic_write(&record_path, &bytes)?;
        fs::remove_file(&challenge_path).map_err(|_| "Publication challenge consume failed")?;
        File::open(&challenge_dir)
            .and_then(|file| file.sync_all())
            .map_err(|_| "Publication durability failed")?;
        let _ = cleanup_orphan_public_files(&self.directory);
        let authorization_value = serde_json::to_value(&request.authorization)
            .map_err(|_| "Publication command invalid")?;
        let authorization_hash = digest(canonicalize_json(&authorization_value)?.as_bytes());
        sign_json_envelope(
            &self.seed,
            json!({"kind":"rusty-publication-receipt", "version":1, "serviceId":service_id,
            "boardId":board_id,"controllerPersonId":request.identity.person_id,"revision":revision,"action":request.action,
            "projectionHash":projection_hash,"challengeId":challenge_id,"authorizationHash":authorization_hash,"withdrawn":withdrawn}),
            service_id,
            DOMAIN,
        )
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
        let policy: ScopePolicy = serde_json::from_slice(
            &fs::read(self.scope_dir(scope)?.join("policy.json"))
                .map_err(|_| "Scope unavailable")?,
        )
        .map_err(|_| "Invalid scope policy")?;
        if !matches!(policy.minimum_writer_version, 1 | 2) {
            return Err("Invalid scope writer policy".into());
        }
        Ok(policy)
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
        let existing_policy = if directory.join("policy.json").exists() {
            Some(self.policy(scope)?)
        } else {
            None
        };
        let revision = existing_policy.as_ref().map_or(0, |policy| policy.revision);
        if approval.expected_revision != revision {
            return Err("Storage policy revision conflict".into());
        }
        let next = revision
            .checked_add(1)
            .ok_or("Storage policy revision exhausted")?;
        let policy = ScopePolicy {
            revision: next,
            minimum_writer_version: existing_policy.map_or_else(legacy_writer_version, |policy| {
                policy.minimum_writer_version
            }),
            read_mac: self.token_mac(scope, &approval.read_token)?,
            write_mac: self.token_mac(scope, &approval.write_token)?,
            revoked: approval.revoked,
            owner_person_id: None,
            scope_purpose: None,
            completed_scope_purpose_update: None,
            completed_enrollment: None,
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
    fn create_challenge_unlocked(
        &self,
        scope: &str,
        person_id: &str,
        device_id: &str,
        device_key_id: &str,
        scope_purpose: Option<&str>,
        origin: &str,
    ) -> Result<SignedEnvelope<Value>, String> {
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
        let mut challenge_payload = json!({
            "kind": "rusty-enrollment-challenge", "version": 1,
            "challengeId": challenge_id, "nonce": nonce, "serviceId": service_id,
            "publicOrigin": origin, "scopeId": scope, "personId": person_id,
            "deviceId": device_id, "deviceKeyId": device_key_id,
            "expectedRevision": revision, "issuedAt": issued_at, "expiresAt": expires_at
        });
        if let Some(scope_purpose) = scope_purpose {
            challenge_payload["scopePurpose"] = json!(scope_purpose);
        }
        let envelope = sign_json_envelope(&self.seed, challenge_payload, service_id, DOMAIN)?;
        let pending = PendingChallenge {
            scope_id: scope.into(),
            person_id: person_id.into(),
            device_id: device_id.into(),
            scope_purpose: scope_purpose.map(str::to_owned),
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
        owner: &ResourceOwner,
        origin: &str,
    ) -> Result<SignedEnvelope<Value>, String> {
        let scope_gate = self.resource_scope_gate(scope)?;
        let _scope_guard = scope_gate
            .try_write()
            .map_err(|_| "Resource scope lock unavailable")?;
        let _guard = self.lock.lock().map_err(|_| "Storage lock unavailable")?;
        if !trusted_identity_matches(&request.identity, &owner.identity)
            || request.certificates.is_empty()
            || !self.management_authorized(
                owner,
                &request.identity,
                &request.device_id,
                &request.certificates,
                "scope",
                scope,
                "scope.policy",
                request.management_capability.as_ref(),
                origin,
            )?
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
        let service_public_key = self.public_key()?;
        let service_id = public_key_id(&service_public_key)?;
        if request.challenge.signer_key_id != service_id
            || !verify_signed_envelope(&request.challenge, &service_public_key, DOMAIN)?
        {
            return Err("Enrollment challenge signature invalid".into());
        }
        let proof = &request.authorization.payload;
        let payload_challenge_id = proof.challenge_id.as_str();
        let challenge_payload = &request.challenge.payload;
        let read_hash = digest(request.read_token.as_bytes());
        let write_hash = digest(request.write_token.as_bytes());
        if !self.management_revision_matches("scope", scope, proof.management_revision)? {
            return Err("Controller management revision binding invalid".into());
        }
        if proof.kind != "rusty-scope-enrollment"
            || proof.version != 1
            || proof.scope_purpose.as_deref()
                != challenge_payload
                    .get("scopePurpose")
                    .and_then(Value::as_str)
            || proof
                .scope_purpose
                .as_deref()
                .is_some_and(|purpose| !valid_scope_purpose(purpose))
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
                minimum_writer_version: legacy_writer_version(),
                read_mac: String::new(),
                write_mac: String::new(),
                revoked: false,
                owner_person_id: None,
                scope_purpose: None,
                completed_scope_purpose_update: None,
                completed_enrollment: None,
            }
        };
        if self.identity_authority_enforced.load(Ordering::SeqCst) && proof.scope_purpose.is_none()
        {
            return Err("Strict Identity enforcement requires a scope purpose".into());
        }
        if current.scope_purpose.as_deref().is_some_and(|purpose| {
            proof
                .scope_purpose
                .as_deref()
                .is_some_and(|requested| requested != purpose)
        }) || (current.revision > 0
            && current.scope_purpose.is_none()
            && proof.scope_purpose.is_some())
        {
            return Err("Scope purpose is immutable; use the one-time migration route".into());
        }
        let normalized_request =
            serde_json::to_value(&request).map_err(|_| "Enrollment request invalid")?;
        let request_hash = digest(canonicalize_json(&normalized_request)?.as_bytes());
        if let Some(completed) = &current.completed_enrollment {
            if completed.request_hash == request_hash {
                let expected_receipt =
                    scope_enrollment_receipt_payload(scope, &request, &current, &service_id)?;
                if expected_revision.checked_add(1) != Some(current.revision)
                    || current.owner_person_id.as_ref() != Some(&request.identity.person_id)
                    || current.revoked != request.revoked
                    || current.read_mac != self.token_mac(scope, &request.read_token)?
                    || current.write_mac != self.token_mac(scope, &request.write_token)?
                    || completed.receipt.payload != expected_receipt
                    || completed.receipt.signer_key_id != service_id
                    || !verify_signed_envelope(&completed.receipt, &service_public_key, DOMAIN)?
                {
                    return Err("Completed enrollment receipt binding invalid".into());
                }
                // A previous rename can succeed while directory fsync reports failure.
                sync_directory(&directory).map_err(|_| "Enrollment durability failed")?;
                return Ok(completed.receipt.clone());
            }
        }
        let pending: PendingChallenge = serde_json::from_slice(
            &fs::read(&challenge_path).map_err(|_| "Enrollment challenge expired or consumed")?,
        )
        .map_err(|_| "Enrollment challenge invalid")?;
        if pending.envelope != request.challenge
            || pending.scope_id != scope
            || pending.person_id != request.identity.person_id
            || pending.device_id != request.device_id
            || pending.scope_purpose.as_deref() != proof.scope_purpose.as_deref()
            || pending.expires_at <= now_ms()?
        {
            return Err("Enrollment challenge binding or expiry invalid".into());
        }
        let concurrent_confirmation = expected_revision.checked_add(1) == Some(current.revision);
        let current_floor_confirmation = current.revision == expected_revision
            && proof.minimum_writer_version == Some(2)
            && current.minimum_writer_version == 2;
        // Equivalent explicit floor-2 confirmations from another owner device
        // preserve the canonical policy revision instead of creating divergent client state.
        if (concurrent_confirmation || current_floor_confirmation)
            && current.owner_person_id.as_ref() == Some(&request.identity.person_id)
            && current.revoked == request.revoked
            && proof.minimum_writer_version == Some(current.minimum_writer_version)
            && current.read_mac == self.token_mac(scope, &request.read_token)?
            && current.write_mac == self.token_mac(scope, &request.write_token)?
        {
            sync_directory(&directory).map_err(|_| "Enrollment durability failed")?;
            return sign_json_envelope(
                &self.seed,
                scope_enrollment_receipt_payload(scope, &request, &current, &service_id)?,
                &service_id,
                DOMAIN,
            );
        }
        if current.revision != expected_revision {
            return Err("Storage policy revision conflict".into());
        }
        if proof
            .minimum_writer_version
            .is_some_and(|version| !matches!(version, 1 | 2))
        {
            return Err("Unsupported minimum writer version".into());
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
        let mut policy = ScopePolicy {
            revision,
            minimum_writer_version: current.minimum_writer_version.max(
                proof
                    .minimum_writer_version
                    .unwrap_or(current.minimum_writer_version),
            ),
            read_mac: self.token_mac(scope, &request.read_token)?,
            write_mac: self.token_mac(scope, &request.write_token)?,
            revoked: request.revoked,
            owner_person_id: Some(request.identity.person_id.clone()),
            scope_purpose: current
                .scope_purpose
                .clone()
                .or_else(|| proof.scope_purpose.clone()),
            completed_scope_purpose_update: current.completed_scope_purpose_update,
            completed_enrollment: None,
        };
        let receipt = sign_json_envelope(
            &self.seed,
            scope_enrollment_receipt_payload(scope, &request, &policy, &service_id)?,
            &service_id,
            DOMAIN,
        )?;
        policy.completed_enrollment = Some(CompletedScopeEnrollment {
            request_hash,
            receipt: receipt.clone(),
        });
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
        Ok(receipt)
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
        let manifest = self.checkpoint_manifest(scope)?;
        let floor = manifest.as_ref().map_or(0, |manifest| manifest.floor);
        let mut checkpoint_found = manifest.is_none();
        let mut scratch_sequence = None;
        for entry in fs::read_dir(self.scope_dir(scope)?.join("objects"))
            .map_err(|_| "Storage unavailable")?
        {
            let path = entry.map_err(|_| "Storage unavailable")?.path();
            if path
                .extension()
                .is_some_and(|extension| extension == "json")
            {
                let value: StoredObject =
                    serde_json::from_slice(&fs::read(&path).map_err(|_| "Storage unavailable")?)
                        .map_err(|_| "Invalid stored object")?;
                value.object.validate(scope)?;
                if value.object.id()? != value.object_id
                    || path.file_name().and_then(|name| name.to_str())
                        != Some(format!("{}.json", value.object_id).as_str())
                {
                    return Err("Stored object integrity failure".into());
                }
                if value.sequence <= floor {
                    continue;
                }
                if let Some(marker) = &value.checkpoint {
                    if !marker.valid_for(value.sequence) {
                        return Err("Checkpoint marker integrity failure".into());
                    }
                    scratch_sequence = Some(
                        scratch_sequence
                            .map_or(value.sequence, |previous: u64| previous.max(value.sequence)),
                    );
                }
                if let Some(manifest) = &manifest {
                    if value.sequence == manifest.sequence {
                        if !manifest.matches(&value) {
                            return Err("Checkpoint object integrity failure".into());
                        }
                        checkpoint_found = true;
                    }
                }
                objects.push(ObjectMetadata {
                    sequence: value.sequence,
                    object_id: value.object_id,
                });
                if objects.len() > MAX_SCOPE_OBJECTS + 1 {
                    return Err("Storage object capacity exceeded".into());
                }
            }
        }
        objects.sort_by_key(|value| value.sequence);
        if objects.len() > MAX_SCOPE_OBJECTS
            && scratch_sequence != objects.last().map(|object| object.sequence)
        {
            return Err("Storage object capacity exceeded".into());
        }
        if !checkpoint_found
            || objects
                .iter()
                .enumerate()
                .any(|(index, value)| floor.checked_add(index as u64 + 1) != Some(value.sequence))
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
        self.save_for_writer(scope, token, object, request_id, legacy_writer_version())
    }
    fn save_for_writer(
        &self,
        scope: &str,
        token: &str,
        object: BlindObject,
        request_id: &str,
        writer_version: u8,
    ) -> Result<SignedEnvelope<Value>, String> {
        self.save_for_writer_at_sequence(scope, token, object, request_id, writer_version, 0)
    }
    fn save_for_writer_at_sequence(
        &self,
        scope: &str,
        token: &str,
        object: BlindObject,
        request_id: &str,
        writer_version: u8,
        observed_sequence: u64,
    ) -> Result<SignedEnvelope<Value>, String> {
        object.validate(scope)?;
        if !valid_id(request_id) {
            return Err("Invalid receipt challenge".into());
        }
        if observed_sequence > MAX_SAFE_JS_INTEGER {
            return Err("Invalid observed storage sequence".into());
        }
        let _guard = self.lock.lock().map_err(|_| "Storage lock unavailable")?;
        let policy = self.authorize(scope, token, true)?;
        require_writer_version(&policy, writer_version)?;
        let object_id = object.id()?;
        let path = self
            .scope_dir(scope)?
            .join("objects")
            .join(format!("{object_id}.json"));
        let sequence = if self
            .objects(scope)?
            .iter()
            .any(|entry| entry.object_id == object_id)
        {
            let stored: StoredObject =
                serde_json::from_slice(&fs::read(&path).map_err(|_| "Storage unavailable")?)
                    .map_err(|_| "Invalid stored object")?;
            if stored.object != object || stored.object_id != object_id {
                return Err("Stored object mismatch".into());
            }
            // A failed atomic write may have renamed the file before directory
            // fsync failed. Visibility alone cannot authorize a durable receipt.
            sync_directory(path.parent().ok_or("Invalid object path")?)
                .map_err(|_| "Durable storage commit failed")?;
            self.telemetry.emit(
                Level::Debug,
                "storage.object.reused",
                "upload",
                "ok",
                scope,
                0.0,
                json!({"bytes": path.metadata().map_or(0, |value| value.len())}),
            );
            stored.sequence
        } else {
            if self
                .checkpoint_manifest(scope)?
                .is_some_and(|manifest| observed_sequence < manifest.sequence)
            {
                return Err(CHECKPOINT_GENERATION_REQUIRED.into());
            }
            let objects = self.objects(scope)?;
            let used = self.scope_storage_bytes(scope)?;
            let bytes = serde_json::to_vec(&object).map_err(|e| e.to_string())?;
            if objects.len() >= MAX_SCOPE_OBJECTS
                || used.saturating_add(bytes.len() as u64 + 1024) > self.max_scope_bytes
            {
                self.telemetry.emit(Level::Error, "storage.quota.exceeded", "upload", "error", scope, 0.0,
                    json!({"stored_bytes": used, "object_count": objects.len(), "scope_limit_bytes": self.max_scope_bytes, "bytes": bytes.len(), "error_code": "capacity_exceeded"}));
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
                checkpoint: None,
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
            self.telemetry.emit(Level::Info, "storage.object.stored", "upload", "ok", scope, 0.0,
                json!({"bytes": bytes.len(), "stored_bytes_before": used, "stored_bytes": used.saturating_add(path.metadata().map_or(0, |value| value.len())), "object_count": objects.len() + 1, "scope_limit_bytes": self.max_scope_bytes}));
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

#[cfg(test)]
thread_local! {
    static FAILED_DIRECTORY_SYNC: std::cell::RefCell<Option<PathBuf>> = const { std::cell::RefCell::new(None) };
}

fn sync_directory(path: &Path) -> std::io::Result<()> {
    #[cfg(test)]
    if FAILED_DIRECTORY_SYNC.with(|failure| failure.borrow().as_deref() == Some(path)) {
        return Err(std::io::Error::other("Injected directory sync failure"));
    }
    File::open(path)?.sync_all()
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
        sync_directory(parent)?;
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
pub fn router(store: BlindStore, origin: String, origins: Vec<String>) -> Result<Router, String> {
    router_with_telemetry(store, origin, origins, Telemetry::disabled())
}
pub fn router_with_telemetry(
    store: BlindStore,
    origin: String,
    origins: Vec<String>,
    telemetry: Telemetry,
) -> Result<Router, String> {
    let cors_origins = origins
        .iter()
        .map(|value| value.parse())
        .collect::<Result<Vec<axum::http::HeaderValue>, _>>()
        .map_err(|_| "Invalid CORS origin")?;
    let service_page = crate::service_ui::page(&origins)?;
    let state = HttpState { store, origin };
    Ok(Router::new()
        .route(
            "/",
            get(move || { let page = service_page.clone(); async move { axum::response::Html(page) } }),
        )
        .route("/assets/{name}", get(crate::service_ui::asset))
        .route(
            "/health",
            get(|State(state): State<HttpState>| async move { Json(json!({"status": "ok", "mode": "blind", "buildSha": crate::build_identity::build_sha(),
                "artifactSha256": crate::build_identity::artifact_sha256(), "sdkSha": crate::build_identity::sdk_sha(),
                "identityAuthorityEnforcement": state.store.identity_authority_enforcement(),
                "readers": {"scopePolicy": 2, "managementPolicy": 2, "archiveStorage": 1, "publicBoardPublication": 1}})) }),
        )
        .route("/.well-known/mesh-lighthouse", get(discovery))
        .route(
            "/v2/enrollment/challenge",
            axum::routing::post(enrollment_challenge),
        )
        .route("/v2/management/{kind}/{id}", put(management::update))
        .route(
            "/v2/management/{kind}/{id}/status",
            axum::routing::post(management::status),
        )
        .route(
            "/v2/identity/authority/{person_id}/status",
            get(identity_authority_status),
        )
        .route(
            "/v2/identity/authority",
            put(identity_authority_update).layer(DefaultBodyLimit::max(4 * 1024 * 1024)),
        )
        .route(
            "/v2/identity/succession/{previous_person_id}/{transition_hash}",
            get(identity_root_succession_status),
        )
        .route(
            "/v2/identity/succession",
            put(identity_root_succession_update)
                .layer(DefaultBodyLimit::max(4 * 1024 * 1024)),
        )
        .route(
            "/v2/scopes/{scope}/purpose",
            put(scope_purpose_update).layer(DefaultBodyLimit::max(128 * 1024)),
        )
        .route(
            "/v2/scopes/{scope}/authority/status",
            get(scope_authority_status),
        )
        .route(
            "/v2/scopes/{scope}/authority",
            put(scope_authority_update).layer(DefaultBodyLimit::max(4 * 1024 * 1024)),
        )
        .route("/v2/scopes/{scope}", put(approve_scope))
        .route(
            "/v2/scopes/{scope}/checkpoint",
            axum::routing::post(checkpoint::checkpoint),
        )
        .route(
            "/v2/scopes/{scope}/principals/{grant_id}",
            put(storage_principal_grant).layer(DefaultBodyLimit::max(512 * 1024)),
        )
        .route(
            "/v2/scopes/{scope}/principals/{grant_id}/revocation",
            put(storage_principal_revocation).layer(DefaultBodyLimit::max(64 * 1024)),
        )
        .route("/v2/scopes/{scope}/objects", get(inventory))
        .route(
            "/v2/scopes/{scope}/objects/{object_id}",
            get(download).put(upload),
        )
        .route(
            "/v2/scopes/{scope}/blobs/{object_id}",
            get(blobs::download).put(blobs::upload),
        )
        .route(
            "/v2/scopes/{scope}/blob-coverage",
            axum::routing::post(blobs::coverage).layer(DefaultBodyLimit::max(16 * 1024)),
        )
        .route(
            "/v2/scopes/{scope}/archives/{object_id}",
            get(archives::download)
                .put(archives::upload)
                .layer(DefaultBodyLimit::max(360 * 1024)),
        )
        .route(
            "/v2/scopes/{scope}/archive-coverage",
            axum::routing::post(archives::coverage).layer(DefaultBodyLimit::max(16 * 1024)),
        )
        .route(
            "/v2/scopes/{scope}/archive-coverage/aggregate",
            axum::routing::post(archives::aggregate).layer(DefaultBodyLimit::max(64 * 1024)),
        )
        .route(
            "/v1/public/challenges",
            axum::routing::post(public_challenge),
        )
        .route(
            "/v1/public/boards/{board_id}",
            get(public_board).put(public_mutation),
        )
        .route("/v1/public/boards/{board_id}/files", put(public_asset))
        .route(
            "/v1/public/boards/{board_id}/files/{revision}/{sha256}",
            get(public_file),
        )
        .layer(DefaultBodyLimit::max(MAX_OBJECT_BYTES * 2))
        .layer(from_fn_with_state(state.clone(), identity_request_gate))
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
                    axum::http::HeaderName::from_static("x-rusty-identity-proof"),
                    axum::http::HeaderName::from_static("x-rusty-client"),
                    axum::http::HeaderName::from_static("x-rusty-build"),
                    axum::http::HeaderName::from_static("traceparent"),
                    axum::http::HeaderName::from_static("tracestate"),
                ]),
        )
        .layer(axum::middleware::from_fn_with_state(
            telemetry,
            observe_request,
        ))
        .with_state(state))
}
async fn identity_request_gate(
    State(state): State<HttpState>,
    request: Request<Body>,
    next: Next,
) -> Response {
    let path = request.uri().path_and_query().map_or_else(
        || request.uri().path().to_owned(),
        |value| value.as_str().to_owned(),
    );
    let path_only = request.uri().path().to_owned();
    if !path_only.starts_with("/v2/scopes/") || !path_only.contains('/') {
        return next.run(request).await;
    }
    let segments = path_only.split('/').collect::<Vec<_>>();
    if segments.len() < 5 || segments[1] != "v2" || segments[2] != "scopes" {
        return next.run(request).await;
    }
    let scope = segments[3];
    if !valid_id(scope) || segments[4] == "principals" {
        return next.run(request).await;
    }
    if matches!(segments.get(4), Some(&"purpose") | Some(&"authority")) {
        return next.run(request).await;
    }
    if request.headers().get("x-rusty-identity-proof").is_none() {
        if !state
            .store
            .identity_authority_enforced
            .load(Ordering::SeqCst)
        {
            return next.run(request).await;
        }
        return failure(
            StatusCode::PRECONDITION_REQUIRED,
            "Signed Identity request proof required",
        )
        .into_response();
    }
    let method = request.method().as_str().to_owned();
    let action = match (method.as_str(), path_only.as_str()) {
        ("GET", _) => "read",
        ("PUT", _) => "write",
        ("POST", route) if route.ends_with("/checkpoint") => "write",
        ("POST", _) => "read",
        _ => {
            return failure(StatusCode::METHOD_NOT_ALLOWED, "Unsupported storage method")
                .into_response();
        }
    };
    let token = match request
        .headers()
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
        .filter(|value| !value.is_empty() && value.len() <= 256)
    {
        Some(token) => token.to_owned(),
        None => {
            return failure(StatusCode::UNAUTHORIZED, "Storage authentication required")
                .into_response();
        }
    };
    let proof_bytes = match request
        .headers()
        .get("x-rusty-identity-proof")
        .and_then(|value| value.to_str().ok())
        .filter(|value| value.len() <= 48 * 1024)
        .and_then(|value| URL_SAFE_NO_PAD.decode(value).ok())
    {
        Some(proof) => proof,
        None => {
            return failure(
                StatusCode::PRECONDITION_REQUIRED,
                "Signed Identity request proof required",
            )
            .into_response();
        }
    };
    let proof: SignedEnvelope<Value> = match serde_json::from_slice(&proof_bytes) {
        Ok(proof) => proof,
        Err(_) => {
            return failure(StatusCode::BAD_REQUEST, "Invalid Identity request proof")
                .into_response();
        }
    };
    let person_id = match proof.payload.get("personId").and_then(Value::as_str) {
        Some(person_id) if valid_id(person_id) => person_id.to_owned(),
        _ => {
            return failure(StatusCode::BAD_REQUEST, "Invalid Identity request proof")
                .into_response();
        }
    };
    let authority_gate = match state.store.identity_authority_gate(&person_id) {
        Ok(gate) => gate,
        Err(_) => {
            return failure(
                StatusCode::SERVICE_UNAVAILABLE,
                "Identity authority unavailable",
            )
            .into_response();
        }
    };
    let _authority_guard = authority_gate.read_owned().await;
    let scope_gate = match state.store.resource_scope_gate(scope) {
        Ok(gate) => gate,
        Err(_) => {
            return failure(StatusCode::SERVICE_UNAVAILABLE, "Storage scope unavailable")
                .into_response();
        }
    };
    let _scope_guard = scope_gate.read_owned().await;
    let (parts, request_body) = request.into_parts();
    let body = match to_bytes(request_body, (MAX_OBJECT_BYTES * 2) as usize).await {
        Ok(body) => body,
        Err(_) => {
            return failure(StatusCode::BAD_REQUEST, "Storage request body unavailable")
                .into_response();
        }
    };
    let verified = state.store.verify_identity_request_proof(
        &proof,
        scope,
        action,
        &token,
        &method,
        &path,
        &body,
        &state.origin,
    );
    if let Err(message) = verified {
        let status = if message.contains("not registered") {
            StatusCode::PRECONDITION_REQUIRED
        } else if message.contains("head") || message.contains("digest") {
            StatusCode::CONFLICT
        } else if message.contains("signature") || message.contains("revoked") {
            StatusCode::FORBIDDEN
        } else {
            StatusCode::FORBIDDEN
        };
        return failure(status, &message).into_response();
    }
    next.run(Request::from_parts(parts, Body::from(body))).await
}
async fn observe_request(
    State(telemetry): State<Telemetry>,
    request: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    let started = std::time::Instant::now();
    let segments: Vec<_> = request.uri().path().split('/').collect();
    let scope = if segments.get(1) == Some(&"v2") && segments.get(2) == Some(&"scopes") {
        segments
            .get(3)
            .filter(|scope| valid_id(scope))
            .copied()
            .unwrap_or("")
    } else {
        ""
    }
    .to_owned();
    let operation = if segments.get(2) == Some(&"scopes") && segments.get(4) == Some(&"objects") {
        if request.method() == axum::http::Method::PUT {
            "upload"
        } else if segments.len() > 5 {
            "download"
        } else {
            "inventory"
        }
    } else if segments.get(4) == Some(&"checkpoint") {
        "checkpoint"
    } else if segments.get(2) == Some(&"enrollment") {
        "enroll"
    } else {
        "request"
    };
    let bytes = request
        .headers()
        .get("content-length")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or(0);
    let client = request
        .headers()
        .get("x-rusty-client")
        .and_then(|value| value.to_str().ok())
        .filter(|value| matches!(*value, "tincanban" | "automation"))
        .map(str::to_owned);
    let client_build = request
        .headers()
        .get("x-rusty-build")
        .and_then(|value| value.to_str().ok())
        .filter(|value| {
            matches!(value.len(), 40 | 64) && value.bytes().all(|byte| byte.is_ascii_hexdigit())
        })
        .map(str::to_owned);
    let traceparent = request
        .headers()
        .get("traceparent")
        .and_then(|value| value.to_str().ok())
        .filter(|value| value.len() <= 128)
        .map(str::to_owned);
    let tracestate = request
        .headers()
        .get("tracestate")
        .and_then(|value| value.to_str().ok())
        .filter(|value| value.len() <= 512)
        .map(str::to_owned);
    let response = next.run(request).await;
    let status = response.status();
    let level = if status.is_server_error() {
        Level::Error
    } else if status.is_client_error() {
        Level::Warn
    } else if operation == "upload" || operation == "enroll" || operation == "checkpoint" {
        Level::Info
    } else if operation == "inventory" || operation == "download" {
        Level::Debug
    } else {
        Level::Trace
    };
    let mut attrs = json!({"bytes": bytes});
    if let Some(client) = client {
        attrs["client"] = json!(client);
    }
    if let Some(build) = client_build {
        attrs["client_build"] = json!(build);
    }
    if !status.is_success() {
        attrs["error_code"] = json!(format!("http_{}", status.as_u16()));
    }
    telemetry.emit_with_parent(
        level,
        if status.is_client_error() || status.is_server_error() {
            "http.request.failed"
        } else {
            "http.request.completed"
        },
        operation,
        if status.is_success() { "ok" } else { "error" },
        &scope,
        started.elapsed().as_secs_f64() * 1000.0,
        attrs,
        traceparent.as_deref(),
        tracestate.as_deref(),
    );
    response
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
        json!({"protocolVersions": [2], "publicOrigin": state.origin, "displayName": "Rusty", "buildSha": crate::build_identity::build_sha(),
            "artifactSha256": crate::build_identity::artifact_sha256(), "sdkSha": crate::build_identity::sdk_sha(),
            "readers": {"scopePolicy": 2, "managementPolicy": 2, "archiveStorage": 1, "publicBoardPublication": 1},
        "service": {"serviceId": service_id, "publicKey": public_key},
        "identityAuthorityEnforcement": state.store.identity_authority_enforcement(),
        "capabilities": {"modes": ["blind"], "encryptedObjectReplication": true, "applicationWrites": false, "classification": false, "publicBoardPublication":{"version":1,"presentationVersion":1,"fieldConfigurationVersion":1,"deliveryVersion":1},"snapshotCheckpoints":{"version":1,"observedSequence":true},"scopeManagement":{"version":1},"personManagement":{"version":1},"scopeEnrollmentRetry":{"version":1},"deviceAccessRestoration":{"version":1},"encryptedBlobs":{"version":1,"maximumCiphertextBytes":1048592},"blobCoverage":{"version":1,"maximumObjects":33},"encryptedArchives":{"version":1,"maximumCiphertextBytes":262160},"archiveCoverageBatches":{"version":1,"maximumObjects":64},"archiveCoverageAggregates":{"version":1,"maximumChildren":8,"maximumHeight":31},"writerPolicy":{"version":1,"maximumWriterVersion":2}}}),
    ))
}

async fn public_challenge(
    State(state): State<HttpState>,
    Json(request): Json<PublicChallengeRequest>,
) -> Result<Json<Value>, ApiError> {
    if request.version != 1 || !valid_id(&request.board_id) {
        return Err(failure(
            StatusCode::BAD_REQUEST,
            "Invalid publication challenge request",
        ));
    }
    let owner = state
        .store
        .publication_owner(&request.board_id, &request.identity)
        .map_err(|message| failure(StatusCode::FORBIDDEN, &message))?;
    if request.delivery_grant.is_some() {
        let store = state.store.clone();
        let owner = owner.clone();
        let origin = state.origin.clone();
        let challenge = tokio::task::spawn_blocking(move || {
            store.create_public_delivery_challenge(request, &owner, &origin)
        })
        .await
        .map_err(|_| {
            failure(
                StatusCode::SERVICE_UNAVAILABLE,
                "Publication storage unavailable",
            )
        })?
        .map_err(|message| {
            failure(
                if message.contains("capacity") {
                    StatusCode::TOO_MANY_REQUESTS
                } else if message.contains("authorized")
                    || message.contains("signature")
                    || message.contains("certificate")
                    || message.contains("device mismatch")
                {
                    StatusCode::FORBIDDEN
                } else {
                    StatusCode::CONFLICT
                },
                &message,
            )
        })?;
        return Ok(Json(json!({"challenge":challenge})));
    }
    if !state
        .store
        .management_authorized(
            &owner,
            &request.identity,
            &request.device_id,
            &request.certificates,
            "board",
            &request.board_id,
            "publication.status",
            request.management_capability.as_ref(),
            &state.origin,
        )
        .map_err(|message| failure(StatusCode::SERVICE_UNAVAILABLE, &message))?
    {
        return Err(failure(
            StatusCode::FORBIDDEN,
            "Untrusted publication controller or device",
        ));
    }
    let key = verify_device_certificate_chain(
        &request.identity,
        &request.device_id,
        &request.certificates,
        "MATCH/1",
    )
    .map_err(|_| {
        failure(
            StatusCode::FORBIDDEN,
            "Untrusted publication controller certificate",
        )
    })?;
    let device_key_id = public_key_id(&key)
        .map_err(|_| failure(StatusCode::FORBIDDEN, "Invalid publication controller key"))?;
    if device_key_id != request.device_id {
        return Err(failure(
            StatusCode::FORBIDDEN,
            "Publication controller key mismatch",
        ));
    }
    let challenge = tokio::task::spawn_blocking({
        let store = state.store.clone();
        let owner = owner.clone();
        let origin = state.origin;
        move || store.create_managed_public_challenge(request, &owner, &origin, &device_key_id)
    })
    .await
    .map_err(|_| {
        failure(
            StatusCode::SERVICE_UNAVAILABLE,
            "Publication storage unavailable",
        )
    })?
    .map_err(|message| {
        failure(
            if message.contains("Unauthorized") {
                StatusCode::FORBIDDEN
            } else if message.contains("capacity") {
                StatusCode::TOO_MANY_REQUESTS
            } else {
                StatusCode::CONFLICT
            },
            &message,
        )
    })?;
    Ok(Json(json!({"challenge":challenge})))
}

async fn public_mutation(
    State(state): State<HttpState>,
    RoutePath(board_id): RoutePath<String>,
    Json(request): Json<PublicMutationRequest>,
) -> Result<Json<SignedEnvelope<Value>>, ApiError> {
    let owner = state
        .store
        .publication_owner(&board_id, &request.identity)
        .map_err(|message| failure(StatusCode::FORBIDDEN, &message))?;
    let origin = state.origin.clone();
    let receipt = tokio::task::spawn_blocking(move || {
        state
            .store
            .mutate_publication(&board_id, request, &owner, &origin)
    })
    .await
    .map_err(|_| {
        failure(
            StatusCode::SERVICE_UNAVAILABLE,
            "Publication storage unavailable",
        )
    })?
    .map_err(|message| {
        let status = if message.contains("expired") || message.contains("consumed") {
            StatusCode::GONE
        } else if message.contains("Untrusted")
            || message.contains("signature")
            || message.contains("binding")
            || message.contains("key mismatch")
        {
            StatusCode::FORBIDDEN
        } else if message.contains("revision conflict")
            || message.contains("action does not match")
            || message.contains("controller conflict")
        {
            StatusCode::CONFLICT
        } else if message.contains("size limit") {
            StatusCode::PAYLOAD_TOO_LARGE
        } else {
            StatusCode::BAD_REQUEST
        };
        failure(status, &message)
    })?;
    Ok(Json(receipt))
}
async fn public_asset(
    State(state): State<HttpState>,
    RoutePath(board_id): RoutePath<String>,
    Json(request): Json<PublicAssetRequest>,
) -> Result<Json<SignedEnvelope<Value>>, ApiError> {
    let owner = state
        .store
        .publication_owner(&board_id, &request.identity)
        .map_err(|message| failure(StatusCode::FORBIDDEN, &message))?;
    let origin = state.origin.clone();
    let receipt = tokio::task::spawn_blocking(move || {
        state
            .store
            .stage_public_file(&board_id, request, &owner, &origin)
    })
    .await
    .map_err(|_| {
        failure(
            StatusCode::SERVICE_UNAVAILABLE,
            "Publication storage unavailable",
        )
    })?
    .map_err(|message| {
        let status = if message.contains("expired") || message.contains("consumed") {
            StatusCode::GONE
        } else if message.contains("Untrusted")
            || message.contains("signature")
            || message.contains("binding")
            || message.contains("key mismatch")
        {
            StatusCode::FORBIDDEN
        } else if message.contains("revision conflict") {
            StatusCode::CONFLICT
        } else if message.contains("size") {
            StatusCode::PAYLOAD_TOO_LARGE
        } else {
            StatusCode::BAD_REQUEST
        };
        failure(status, &message)
    })?;
    Ok(Json(receipt))
}
fn safe_content_disposition(filename: &str) -> String {
    let fallback: String = filename
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || " ._-".contains(ch) {
                ch
            } else {
                '_'
            }
        })
        .collect();
    let encoded: String = filename
        .as_bytes()
        .iter()
        .map(|byte| {
            if byte.is_ascii_alphanumeric() || b"!#$&+-.^_`|~".contains(byte) {
                (*byte as char).to_string()
            } else {
                format!("%{byte:02X}")
            }
        })
        .collect();
    format!(
        "attachment; filename=\"{}\"; filename*=UTF-8''{}",
        fallback.chars().take(120).collect::<String>(),
        encoded
    )
}
async fn public_file(
    State(state): State<HttpState>,
    RoutePath((board_id, revision, sha256)): RoutePath<(String, u64, String)>,
) -> axum::response::Response {
    if !valid_id(&board_id)
        || revision == 0
        || sha256.len() != 43
        || !sha256
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    {
        return public_json(
            StatusCode::BAD_REQUEST,
            json!({"message":"Invalid public file URL"}),
        );
    }
    let result = tokio::task::spawn_blocking(move || {
        state.store.publication_file(&board_id, revision, &sha256)
    })
    .await;
    let Ok(Ok((bytes, media_type, filename))) = result else {
        return public_json(
            StatusCode::NOT_FOUND,
            json!({"message":"Public file unavailable"}),
        );
    };
    let mut response = (StatusCode::OK, axum::body::Body::from(bytes)).into_response();
    response.headers_mut().insert(
        axum::http::header::CACHE_CONTROL,
        "no-store, max-age=0".parse().unwrap(),
    );
    response
        .headers_mut()
        .insert(axum::http::header::PRAGMA, "no-cache".parse().unwrap());
    response.headers_mut().insert(
        axum::http::header::X_CONTENT_TYPE_OPTIONS,
        "nosniff".parse().unwrap(),
    );
    response.headers_mut().insert(
        axum::http::header::CONTENT_TYPE,
        media_type
            .parse()
            .unwrap_or_else(|_| "application/octet-stream".parse().unwrap()),
    );
    response.headers_mut().insert(
        axum::http::header::CONTENT_DISPOSITION,
        safe_content_disposition(&filename)
            .parse()
            .unwrap_or_else(|_| "attachment".parse().unwrap()),
    );
    response
}

fn public_json(status: StatusCode, value: Value) -> axum::response::Response {
    let mut response = (status, Json(value)).into_response();
    response.headers_mut().insert(
        axum::http::header::CACHE_CONTROL,
        "no-store, max-age=0".parse().unwrap(),
    );
    response
        .headers_mut()
        .insert(axum::http::header::PRAGMA, "no-cache".parse().unwrap());
    response
}
async fn public_board(
    State(state): State<HttpState>,
    RoutePath(board_id): RoutePath<String>,
) -> axum::response::Response {
    if !valid_id(&board_id) {
        return public_json(
            StatusCode::BAD_REQUEST,
            json!({"message":"Invalid board ID"}),
        );
    }
    let publication = match tokio::task::spawn_blocking({
        let store = state.store.clone();
        let id = board_id.clone();
        move || store.current_publication(&id)
    })
    .await
    {
        Ok(Ok(record)) => record,
        _ => {
            return public_json(
                StatusCode::SERVICE_UNAVAILABLE,
                json!({"message":"Public publication could not be validated"}),
            );
        }
    };
    let Some(record) = publication else {
        return public_json(
            StatusCode::NOT_FOUND,
            json!({"message":"Public board unavailable","revision":0,"withdrawn":false}),
        );
    };
    if record.withdrawn {
        return public_json(
            StatusCode::NOT_FOUND,
            json!({"message":"Public board unavailable","revision":record.revision,"withdrawn":true}),
        );
    }
    public_json(
        StatusCode::OK,
        json!({"boardId":record.board_id,"revision":record.revision,"projection":record.projection,"hash":record.projection_hash}),
    )
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
    let owner = ResourceOwner {
        identity: request.identity.clone(),
    };
    if !state
        .store
        .management_authorized(
            &owner,
            &request.identity,
            &request.device_id,
            &request.certificates,
            "scope",
            &request.scope_id,
            "scope.policy",
            request.management_capability.as_ref(),
            &state.origin,
        )
        .map_err(|message| failure(StatusCode::SERVICE_UNAVAILABLE, &message))?
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
    let owner = owner.clone();
    let origin = state.origin.clone();
    let challenge = tokio::task::spawn_blocking(move || {
        store.create_managed_enrollment_challenge(request, &owner, &origin, &device_key_id)
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
            if message.contains("Unauthorized") {
                StatusCode::FORBIDDEN
            } else if message.contains("capacity") {
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
    let owner = ResourceOwner {
        identity: request.identity.clone(),
    };
    let origin = state.origin.clone();
    let receipt = tokio::task::spawn_blocking(move || {
        state.store.approve_signed(&scope, request, &owner, &origin)
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

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct IdentityAuthorityStatusQuery {
    nonce: String,
}

async fn identity_authority_status(
    State(state): State<HttpState>,
    RoutePath(person_id): RoutePath<String>,
    Query(query): Query<IdentityAuthorityStatusQuery>,
) -> Result<Json<Value>, ApiError> {
    if !valid_id(&person_id) || !valid_nonce(&query.nonce) {
        return Err(failure(
            StatusCode::BAD_REQUEST,
            "Identity authority status nonce required",
        ));
    }
    let path_and_query = format!(
        "/v2/identity/authority/{person_id}/status?nonce={}",
        query.nonce
    );
    let request_hash = status_request_hash(&path_and_query).map_err(|_| {
        failure(
            StatusCode::BAD_REQUEST,
            "Invalid Identity authority status request",
        )
    })?;
    let status = tokio::task::spawn_blocking(move || {
        state.store.signed_identity_authority_status(
            &person_id,
            &state.origin,
            &query.nonce,
            &request_hash,
        )
    })
    .await
    .map_err(|_| {
        failure(
            StatusCode::SERVICE_UNAVAILABLE,
            "Identity authority unavailable",
        )
    })?
    .map_err(|_| {
        failure(
            StatusCode::SERVICE_UNAVAILABLE,
            "Identity authority unavailable",
        )
    })?;
    Ok(Json(json!({"status": status})))
}

async fn identity_authority_update(
    State(state): State<HttpState>,
    Json(request): Json<AuthorityUpdateRequest>,
) -> Result<Json<Value>, ApiError> {
    let origin = state.origin.clone();
    match tokio::task::spawn_blocking(move || {
        state.store.update_identity_authority(request, &origin)
    })
    .await
    .map_err(|_| {
        failure(
            StatusCode::SERVICE_UNAVAILABLE,
            "Identity authority unavailable",
        )
    })? {
        Ok(receipt) => Ok(Json(json!({"receipt": receipt}))),
        Err((message, Some(authority_status))) => Err((
            StatusCode::CONFLICT,
            Json(json!({
                "code": "identity_authority_stale",
                "message": message,
                "authorityStatus": authority_status,
            })),
        )),
        Err((message, None)) => {
            let normalized = message.to_ascii_lowercase();
            let status = if normalized.contains("signature")
                || normalized.contains("revoked")
                || normalized.contains("active")
                || normalized.contains("authority")
                || normalized.contains("retired")
            {
                StatusCode::FORBIDDEN
            } else if normalized.contains("nonce") || normalized.contains("expiry") {
                StatusCode::CONFLICT
            } else {
                StatusCode::BAD_REQUEST
            };
            Err(failure(status, &message))
        }
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct IdentityRootSuccessionStatusQuery {
    request_id: String,
    request_hash: String,
}

async fn identity_root_succession_status(
    State(state): State<HttpState>,
    RoutePath((previous_person_id, transition_hash)): RoutePath<(String, String)>,
    Query(query): Query<IdentityRootSuccessionStatusQuery>,
) -> Result<Json<Value>, ApiError> {
    let valid_transition_hash = URL_SAFE_NO_PAD
        .decode(&transition_hash)
        .is_ok_and(|bytes| bytes.len() == 32);
    if !valid_id(&previous_person_id) || !valid_transition_hash || !valid_nonce(&query.request_id) {
        return Err(failure(
            StatusCode::BAD_REQUEST,
            "Identity succession status request is invalid",
        ));
    }
    let origin = state.origin.clone();
    let status = tokio::task::spawn_blocking(move || {
        state.store.signed_identity_succession_status(
            &previous_person_id,
            &transition_hash,
            &query.request_id,
            &query.request_hash,
            &origin,
        )
    })
    .await
    .map_err(|_| {
        failure(
            StatusCode::SERVICE_UNAVAILABLE,
            "Identity succession unavailable",
        )
    })?
    .map_err(|_| {
        failure(
            StatusCode::BAD_REQUEST,
            "Identity succession status binding is invalid",
        )
    })?;
    Ok(Json(json!({"status": status})))
}

async fn identity_root_succession_update(
    State(state): State<HttpState>,
    Json(request): Json<IdentityRootSuccessionRequest>,
) -> Result<Json<Value>, ApiError> {
    let origin = state.origin.clone();
    match tokio::task::spawn_blocking(move || {
        state
            .store
            .update_identity_root_succession(request, &origin)
    })
    .await
    .map_err(|_| {
        failure(
            StatusCode::SERVICE_UNAVAILABLE,
            "Identity succession unavailable",
        )
    })? {
        Ok(receipt) => Ok(Json(json!({"receipt": receipt}))),
        Err((message, _status)) => {
            let code = if message.contains("signature")
                || message.contains("active")
                || message.contains("revoked")
                || message.contains("root has been retired")
            {
                StatusCode::FORBIDDEN
            } else if message.contains("stale")
                || message.contains("already")
                || message.contains("requires strict")
            {
                StatusCode::CONFLICT
            } else if message.contains("unavailable") || message.contains("Storage lock") {
                StatusCode::SERVICE_UNAVAILABLE
            } else {
                StatusCode::BAD_REQUEST
            };
            Err(failure(code, &message))
        }
    }
}

async fn scope_purpose_update(
    State(state): State<HttpState>,
    RoutePath(scope): RoutePath<String>,
    Json(request): Json<ScopePurposeUpdateRequest>,
) -> Result<Json<Value>, ApiError> {
    match tokio::task::spawn_blocking({
        let store = state.store.clone();
        let origin = state.origin.clone();
        move || store.update_scope_purpose(&scope, request, &origin)
    })
    .await
    .map_err(|_| {
        failure(
            StatusCode::SERVICE_UNAVAILABLE,
            "Scope classification unavailable",
        )
    })? {
        Ok(receipt) => Ok(Json(json!({"receipt": receipt}))),
        Err(message) => {
            let status = if message.contains("signature")
                || message.contains("active")
                || message.contains("owner")
                || message.contains("Identity authority")
            {
                StatusCode::FORBIDDEN
            } else if message.contains("immutable") || message.contains("eligible") {
                StatusCode::CONFLICT
            } else {
                StatusCode::BAD_REQUEST
            };
            Err(failure(status, &message))
        }
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ScopeAuthorityStatusQuery {
    request_id: String,
    request_hash: String,
}

async fn scope_authority_status(
    State(state): State<HttpState>,
    RoutePath(scope): RoutePath<String>,
    Query(query): Query<ScopeAuthorityStatusQuery>,
) -> Result<Json<Value>, ApiError> {
    if !valid_id(&scope)
        || !valid_nonce(&query.request_id)
        || query.request_hash.len() != 43
        || scope_authority_status_request_hash(&scope, &query.request_id).map_err(|_| {
            failure(
                StatusCode::BAD_REQUEST,
                "Invalid scope authority status request",
            )
        })? != query.request_hash
    {
        return Err(failure(
            StatusCode::BAD_REQUEST,
            "Invalid scope authority status request",
        ));
    }
    let status = tokio::task::spawn_blocking(move || {
        state.store.signed_scope_authority_status(
            &scope,
            &state.origin,
            &query.request_id,
            &query.request_hash,
        )
    })
    .await
    .map_err(|_| {
        failure(
            StatusCode::SERVICE_UNAVAILABLE,
            "Scope authority unavailable",
        )
    })?
    .map_err(|message| {
        let status = if message.contains("Person Identity") {
            StatusCode::CONFLICT
        } else {
            StatusCode::BAD_REQUEST
        };
        failure(status, &message)
    })?;
    Ok(Json(json!({"status": status})))
}

async fn scope_authority_update(
    State(state): State<HttpState>,
    RoutePath(scope): RoutePath<String>,
    Json(request): Json<ScopeAuthorityUpdateRequest>,
) -> Result<Json<Value>, ApiError> {
    let origin = state.origin.clone();
    match tokio::task::spawn_blocking(move || {
        state.store.update_scope_authority(&scope, request, &origin)
    })
    .await
    .map_err(|_| {
        failure(
            StatusCode::SERVICE_UNAVAILABLE,
            "Scope authority unavailable",
        )
    })? {
        Ok(receipt) => Ok(Json(json!({"receipt": receipt}))),
        Err((message, Some(authority_status))) => Err((
            StatusCode::CONFLICT,
            Json(json!({
                "code": "scope_authority_stale",
                "message": message,
                "authorityStatus": authority_status,
            })),
        )),
        Err((message, None)) => {
            let status = if message.contains("signature")
                || message.contains("active")
                || message.contains("revoked")
                || message.contains("Identity authority")
            {
                StatusCode::FORBIDDEN
            } else if message.contains("immutable") || message.contains("already used") {
                StatusCode::CONFLICT
            } else {
                StatusCode::BAD_REQUEST
            };
            Err(failure(status, &message))
        }
    }
}

async fn storage_principal_grant(
    State(state): State<HttpState>,
    RoutePath((scope, grant_id)): RoutePath<(String, String)>,
    Json(request): Json<ResourcePrincipalGrantRequest>,
) -> Result<StatusCode, ApiError> {
    let origin = state.origin.clone();
    tokio::task::spawn_blocking(move || {
        state
            .store
            .register_resource_principal_grant(&scope, &grant_id, request, &origin)
    })
    .await
    .map_err(|_| failure(StatusCode::SERVICE_UNAVAILABLE, "Storage grant unavailable"))?
    .map_err(|message| {
        let status = if message.contains("not registered") {
            StatusCode::PRECONDITION_REQUIRED
        } else if message.contains("stale") || message.contains("conflict") {
            StatusCode::CONFLICT
        } else if message.contains("signature") || message.contains("active") {
            StatusCode::FORBIDDEN
        } else {
            StatusCode::BAD_REQUEST
        };
        failure(status, &message)
    })?;
    Ok(StatusCode::NO_CONTENT)
}

async fn storage_principal_revocation(
    State(state): State<HttpState>,
    RoutePath((scope, grant_id)): RoutePath<(String, String)>,
    Json(request): Json<ResourcePrincipalRevocationRequest>,
) -> Result<Json<Value>, ApiError> {
    let origin = state.origin.clone();
    let receipt = tokio::task::spawn_blocking(move || {
        state
            .store
            .revoke_resource_principal(&scope, &grant_id, request, &origin)
    })
    .await
    .map_err(|_| {
        failure(
            StatusCode::SERVICE_UNAVAILABLE,
            "Storage revocation unavailable",
        )
    })?
    .map_err(|message| {
        let status = if message.contains("not registered") {
            StatusCode::PRECONDITION_REQUIRED
        } else if message.contains("stale")
            || message.contains("conflict")
            || message.contains("changed")
        {
            StatusCode::CONFLICT
        } else if message.contains("signature")
            || message.contains("active")
            || message.contains("retired")
        {
            StatusCode::FORBIDDEN
        } else {
            StatusCode::BAD_REQUEST
        };
        failure(status, &message)
    })?;
    Ok(Json(json!({ "receipt": receipt })))
}

async fn upload(
    State(state): State<HttpState>,
    RoutePath((scope, object_id)): RoutePath<(String, String)>,
    headers: HeaderMap,
    Query(query): Query<WriterQuery>,
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
    let writer_version = query.writer_version;
    if query.observed_sequence > MAX_SAFE_JS_INTEGER {
        return Err(failure(
            StatusCode::BAD_REQUEST,
            "Invalid observed storage sequence",
        ));
    }
    let observed_sequence = query.observed_sequence;
    let receipt = tokio::task::spawn_blocking(move || {
        state.store.save_for_writer_at_sequence(
            &scope,
            &token,
            object,
            &request_id,
            writer_version,
            observed_sequence,
        )
    })
    .await
    .map_err(|_| failure(StatusCode::SERVICE_UNAVAILABLE, "Storage unavailable"))?
    .map_err(|message| {
        if message == CHECKPOINT_GENERATION_REQUIRED {
            return (
                StatusCode::CONFLICT,
                Json(json!({"code":"checkpoint_generation_required","message":message})),
            );
        }
        if message.contains("Writer") || message.contains("writer") {
            return (
                StatusCode::UPGRADE_REQUIRED,
                Json(json!({"code":"writer_upgrade_required","message":message})),
            );
        }
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
        let manifest = state.store.checkpoint_manifest(&scope)?;
        Ok::<Value, String>(json!({"objects": page, "cursor": cursor, "hasMore": objects.last().is_some_and(|o| o.sequence > cursor),
            "compactedThrough":manifest.as_ref().map_or(0,|value|value.floor),"checkpointSequence":manifest.as_ref().map(|value|value.sequence),
            "maxSequence":objects.last().map_or(0,|value|value.sequence),"objectCount":objects.len()}))
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
        if state
            .store
            .checkpoint_manifest(&scope)?
            .is_some_and(|manifest| stored.sequence <= manifest.floor)
        {
            return Err("Object unavailable after checkpoint".into());
        }
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
#[path = "checkpoint_tests.rs"]
mod checkpoint_tests;
#[cfg(test)]
#[path = "blind_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "publication_security_tests.rs"]
mod publication_security_tests;

#[cfg(test)]
#[path = "management_tests.rs"]
mod management_tests;
