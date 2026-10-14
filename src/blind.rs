//! Durable opaque object replication. This module never loads application documents.
use crate::telemetry::{Level, Telemetry};
use axum::{
    Json, Router,
    extract::{DefaultBodyLimit, Path as RoutePath, Query, State},
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
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
    collections::{HashMap, HashSet},
    fs::{self, File, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::{SystemTime, UNIX_EPOCH},
};
use tower_http::cors::CorsLayer;
#[path = "checkpoint.rs"]
mod checkpoint;

pub const DOMAIN: &str = "RUSTY/2";
const MAX_OBJECT_BYTES: usize = 16 * 1024 * 1024;
const MAX_PUBLICATION_BYTES: usize = 2 * 1024 * 1024;
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
fn exact_keys(value: &Value, expected: &[&str]) -> bool {
    value.as_object().is_some_and(|object| {
        object.len() == expected.len() && expected.iter().all(|key| object.contains_key(*key))
    })
}
fn public_string(value: &Value, max: usize) -> bool {
    value
        .as_str()
        .is_some_and(|text| text.encode_utf16().count() <= max)
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
fn validate_public_projection(value: &Value) -> Result<(), String> {
    if !exact_keys(
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
    ) || value["kind"] != "tincanban-public-board"
        || value["version"] != 1
        || !exact_keys(&value["board"], &["id", "title"])
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
    let mut column_ids = HashSet::new();
    for column in columns {
        if !exact_keys(column, &["id", "title", "rank"])
            || !valid_id(column["id"].as_str().unwrap_or(""))
            || !public_string(&column["title"], 4096)
            || !public_rank(&column["rank"])
            || !ids.insert(column["id"].as_str().unwrap().to_owned())
        {
            return Err("Invalid or duplicate public column".into());
        }
        column_ids.insert(column["id"].as_str().unwrap().to_owned());
    }
    let mut field_ids = HashSet::new();
    let mut field_definitions: HashMap<String, (String, HashSet<String>)> = HashMap::new();
    for field in fields {
        if !exact_keys(
            field,
            &["id", "title", "valueType", "required", "rank", "options"],
        ) || !valid_id(field["id"].as_str().unwrap_or(""))
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
    let mut cards_seen: HashMap<String, (Option<String>, String)> = HashMap::new();
    for card in cards {
        if !exact_keys(
            card,
            &[
                "id", "parentId", "columnId", "title", "body", "values", "rank",
            ],
        ) || !valid_id(card["id"].as_str().unwrap_or(""))
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
    let mut discussion_threads: HashMap<String, (String, Option<String>)> = HashMap::new();
    for discussion in discussions {
        if !exact_keys(
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
        ) || !valid_id(discussion["id"].as_str().unwrap_or(""))
            || !ids.insert(discussion["id"].as_str().unwrap().to_owned())
            || !valid_id(discussion["threadId"].as_str().unwrap_or(""))
            || !public_string(&discussion["author"], 500)
            || !public_string(&discussion["createdAt"], 128)
            || !public_string(&discussion["body"], 8000)
        {
            return Err("Invalid public discussion".into());
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

// A confirmed device enrollment delegates from a pinned controller. An unrelated
// root-signed device, or an appended certificate outside that chain, does not.
fn trusted_controller_device(
    owner: &TrustedOwner,
    identity: &PublicIdentity,
    device_id: &str,
    certificates: &[DeviceCertificate],
) -> bool {
    if !trusted_identity_matches(identity, &owner.identity)
        || verify_device_certificate_chain(identity, device_id, certificates, "MATCH/1").is_err()
    {
        return false;
    }
    let mut current = certificates
        .iter()
        .find(|certificate| certificate.payload.device_id == device_id);
    for _ in 0..32 {
        let Some(certificate) = current else {
            return false;
        };
        if owner
            .allowed_controller_device_ids
            .contains(&certificate.payload.device_id)
        {
            return true;
        }
        let Some(issuer_hash) = certificate.payload.issuer_certificate_hash.as_ref() else {
            return false;
        };
        current = certificates.iter().find(|candidate| {
            meta_mesh_core::certificate_hash(candidate).as_ref() == Ok(issuer_hash)
        });
    }
    false
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
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PublicChallengeRequest {
    version: u8,
    board_id: String,
    identity: PublicIdentity,
    device_id: String,
    certificates: Vec<DeviceCertificate>,
}
#[derive(Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PendingPublicChallenge {
    board_id: String,
    person_id: String,
    device_id: String,
    expires_at: u64,
    envelope: SignedEnvelope<Value>,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PublicMutationRequest {
    challenge: SignedEnvelope<Value>,
    identity: PublicIdentity,
    device_id: String,
    certificates: Vec<DeviceCertificate>,
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
                ]
                .contains(&name)
                    && !name.starts_with(".pending-")
                {
                    return Err("Legacy or unknown state requires client re-encryption into a fresh directory".into());
                }
            }
            if (directory.join("scopes").exists() || directory.join("publications").exists())
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
            max_scope_bytes,
        };
        store.recover_checkpoint_scopes()?;
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
        if record.revision != revision {
            return Err("Public file revision is no longer active".into());
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
    fn create_public_challenge(
        &self,
        board_id: &str,
        person_id: &str,
        device_id: &str,
        device_key_id: &str,
        origin: &str,
    ) -> Result<SignedEnvelope<Value>, String> {
        let _guard = self.lock.lock().map_err(|_| "Storage lock unavailable")?;
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
        let envelope = sign_json_envelope(
            &self.seed,
            json!({
                "kind":"rusty-publication-challenge", "version":1, "challengeId":challenge_id, "nonce":nonce,
                "serviceId":service_id, "publicOrigin":origin, "boardId":board_id, "personId":person_id,
                "deviceId":device_id, "deviceKeyId":device_key_id, "expectedRevision":revision,
                "issuedAt":issued_at, "expiresAt":expires_at, "withdrawn":current.withdrawn, "projectionHash":current.projection_hash
            }),
            service_id,
            DOMAIN,
        )?;
        let pending = PendingPublicChallenge {
            board_id: board_id.into(),
            person_id: person_id.into(),
            device_id: device_id.into(),
            expires_at,
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
        trusted_owner: &TrustedOwner,
        origin: &str,
    ) -> Result<SignedEnvelope<Value>, String> {
        let _guard = self.lock.lock().map_err(|_| "Storage lock unavailable")?;
        if !valid_id(board_id)
            || !trusted_identity_matches(&request.identity, &trusted_owner.identity)
            || request.certificates.is_empty()
            || !trusted_controller_device(
                trusted_owner,
                &request.identity,
                &request.device_id,
                &request.certificates,
            )
        {
            return Err("Untrusted publication controller or device".into());
        }
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
        let (record_path, challenge_dir, root) = self.publication_paths(board_id)?;
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
        if !exact_keys(
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
        let current_revision = if record_path.exists() {
            self.current_publication(board_id)?
                .ok_or("Publication unavailable")?
                .revision
        } else {
            0
        };
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
        trusted_owner: &TrustedOwner,
        origin: &str,
    ) -> Result<SignedEnvelope<Value>, String> {
        let _guard = self.lock.lock().map_err(|_| "Storage lock unavailable")?;
        if !valid_id(board_id)
            || !trusted_identity_matches(&request.identity, &trusted_owner.identity)
            || request.certificates.is_empty()
            || !trusted_controller_device(
                trusted_owner,
                &request.identity,
                &request.device_id,
                &request.certificates,
            )
        {
            return Err("Untrusted publication controller or device".into());
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
        if !exact_keys(
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
        let expected_revision = challenge_payload
            .get("expectedRevision")
            .and_then(Value::as_u64)
            .ok_or("Invalid publication revision")?;
        let current = self.current_publication(board_id)?;
        let current_revision = current.as_ref().map(|record| record.revision).unwrap_or(0);
        if current_revision != expected_revision {
            return Err("Publication revision conflict".into());
        }
        if current
            .as_ref()
            .is_some_and(|record| record.controller_person_id != request.identity.person_id)
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
            controller_person_id: request.identity.person_id.clone(),
            revision,
            withdrawn,
            projection,
            projection_hash: projection_hash.clone(),
        };
        let bytes = serde_json::to_vec(&record).map_err(|_| "Public publication invalid")?;
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
            || !trusted_controller_device(
                trusted_owner,
                &request.identity,
                &request.device_id,
                &request.certificates,
            )
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
    router_with_telemetry(store, origin, trusted_owner, origins, Telemetry::disabled())
}
pub fn router_with_telemetry(
    store: BlindStore,
    origin: String,
    trusted_owner: Option<TrustedOwner>,
    origins: Vec<String>,
    telemetry: Telemetry,
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
            "/",
            get(|| async { axum::response::Html(include_str!("service.html")) }),
        )
        .route("/assets/{name}", get(crate::service_ui::asset))
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
    telemetry.emit(
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
        json!({"protocolVersions": [2], "publicOrigin": state.origin, "displayName": "Rusty",
        "service": {"serviceId": service_id, "publicKey": public_key},
        "capabilities": {"modes": ["blind"], "encryptedObjectReplication": true, "applicationWrites": false, "classification": false, "publicBoardPublication":{"version":1},"snapshotCheckpoints":{"version":1}}}),
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
    let owner = state.trusted_owner.as_ref().ok_or_else(|| {
        failure(
            StatusCode::FORBIDDEN,
            "No publication controller configured",
        )
    })?;
    if !trusted_identity_matches(&request.identity, &owner.identity)
        || !trusted_controller_device(
            owner,
            &request.identity,
            &request.device_id,
            &request.certificates,
        )
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
        let board_id = request.board_id;
        let person_id = request.identity.person_id;
        let device_id = request.device_id;
        let origin = state.origin;
        move || {
            store.create_public_challenge(
                &board_id,
                &person_id,
                &device_id,
                &device_key_id,
                &origin,
            )
        }
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
    let owner = state.trusted_owner.clone().ok_or_else(|| {
        failure(
            StatusCode::FORBIDDEN,
            "No publication controller configured",
        )
    })?;
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
    let owner = state.trusted_owner.clone().ok_or_else(|| {
        failure(
            StatusCode::FORBIDDEN,
            "No publication controller configured",
        )
    })?;
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
    let trusted_owner = state.trusted_owner.as_ref().ok_or_else(|| {
        failure(
            StatusCode::FORBIDDEN,
            "No trusted owner controller configured",
        )
    })?;
    if !trusted_identity_matches(&request.identity, &trusted_owner.identity)
        || !trusted_controller_device(
            trusted_owner,
            &request.identity,
            &request.device_id,
            &request.certificates,
        )
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
