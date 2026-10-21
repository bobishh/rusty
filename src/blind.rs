//! Durable opaque object replication. This module never loads application documents.
use crate::telemetry::{Level, Telemetry};
use axum::{
    Json, Router,
    extract::{DefaultBodyLimit, Path as RoutePath, Query, State},
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
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
    sync::{Arc, Mutex},
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
    completed_enrollment: Option<CompletedScopeEnrollment>,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct CompletedScopeEnrollment {
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
                ]
                .contains(&name)
                    && !name.starts_with(".pending-")
                {
                    return Err("Legacy or unknown state requires client re-encryption into a fresh directory".into());
                }
            }
            if (directory.join("scopes").exists()
                || directory.join("publications").exists()
                || directory.join("management").exists())
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
        public_key_from_seed(&seed)?;
        let store = Self {
            telemetry: Telemetry::disabled(),
            directory: Arc::new(directory),
            seed,
            lock: Arc::new(Mutex::new(())),
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
        owner: &ResourceOwner,
        origin: &str,
    ) -> Result<SignedEnvelope<Value>, String> {
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
                completed_enrollment: None,
            }
        };
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
            get(|| async { Json(json!({"status": "ok", "mode": "blind", "buildSha": crate::build_identity::build_sha(),
                "artifactSha256": crate::build_identity::artifact_sha256(), "sdkSha": crate::build_identity::sdk_sha(),
                "readers": {"scopePolicy": 2, "managementPolicy": 1, "archiveStorage": 1, "publicBoardPublication": 1}})) }),
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
        .route("/v2/scopes/{scope}", put(approve_scope))
        .route(
            "/v2/scopes/{scope}/checkpoint",
            axum::routing::post(checkpoint::checkpoint),
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
            "readers": {"scopePolicy": 2, "managementPolicy": 1, "archiveStorage": 1, "publicBoardPublication": 1},
        "service": {"serviceId": service_id, "publicKey": public_key},
        "capabilities": {"modes": ["blind"], "encryptedObjectReplication": true, "applicationWrites": false, "classification": false, "publicBoardPublication":{"version":1,"presentationVersion":1,"fieldConfigurationVersion":1,"deliveryVersion":1},"snapshotCheckpoints":{"version":1,"observedSequence":true},"scopeManagement":{"version":1},"personManagement":{"version":1},"scopeEnrollmentRetry":{"version":1},"encryptedBlobs":{"version":1,"maximumCiphertextBytes":1048592},"blobCoverage":{"version":1,"maximumObjects":33},"encryptedArchives":{"version":1,"maximumCiphertextBytes":262160},"archiveCoverageBatches":{"version":1,"maximumObjects":64},"archiveCoverageAggregates":{"version":1,"maximumChildren":8,"maximumHeight":31},"writerPolicy":{"version":1,"maximumWriterVersion":2}}}),
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
