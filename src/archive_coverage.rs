//! Compose prior durable archive attestations. This is not a fresh byte-availability check.
use super::*;

const MAX_SAFE: u64 = 9_007_199_254_740_991;
const MAX_CHILDREN: usize = 8;
const HEADER: &[&str] = &[
    "kind",
    "version",
    "serviceId",
    "scopeId",
    "policyRevision",
    "requestId",
];
const SUMMARY: &[&str] = &[
    "height",
    "objectCount",
    "firstObjectId",
    "lastObjectId",
    "setDigest",
    "rootCovered",
];

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct AggregateRequest {
    version: u8,
    request_id: String,
    archive_root_id: String,
    children: Vec<Value>,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Summary {
    height: u8,
    object_count: u64,
    first_object_id: String,
    last_object_id: String,
    set_digest: String,
    root_covered: bool,
}

fn invalid() -> String {
    "Invalid archive coverage evidence".into()
}
fn exact(value: &Value, keys: &[&str]) -> Result<(), String> {
    let map = value.as_object().ok_or_else(invalid)?;
    if map.len() != keys.len() || keys.iter().any(|key| !map.contains_key(*key)) {
        return Err(invalid());
    }
    Ok(())
}
fn digest(value: Value) -> Result<String, String> {
    let mut hash = Sha256::new();
    hash.update(b"MESH-HISTORY/1/coverage-set\0");
    hash.update(canonicalize_json(&value)?.as_bytes());
    Ok(URL_SAFE_NO_PAD.encode(hash.finalize()))
}
impl Summary {
    fn validate(&self, root: &str) -> Result<(), String> {
        if self.height >= 32
            || self.object_count == 0
            || self.object_count > MAX_SAFE
            || self.height == 0 && self.object_count > 64
            || !canonical_id(&self.first_object_id)
            || !canonical_id(&self.last_object_id)
            || !canonical_id(&self.set_digest)
            || self.first_object_id > self.last_object_id
            || (self.object_count == 1) != (self.first_object_id == self.last_object_id)
            || self.root_covered
                && (root < self.first_object_id.as_str() || root > self.last_object_id.as_str())
            || !self.root_covered && (root == self.first_object_id || root == self.last_object_id)
        {
            return Err(invalid());
        }
        Ok(())
    }
}
fn child_summary(
    child: Value,
    root: &str,
    pin: &str,
    scope: &str,
    revision: u64,
) -> Result<Summary, String> {
    exact(&child, &["payload", "signerKeyId", "signature"])?;
    let signature = child["signature"].as_str().ok_or_else(invalid)?;
    if signature.len() != 86 {
        return Err(invalid());
    }
    let decoded = URL_SAFE_NO_PAD.decode(signature).map_err(|_| invalid())?;
    if decoded.len() != 64 || URL_SAFE_NO_PAD.encode(decoded) != signature {
        return Err(invalid());
    }
    let payload = &child["payload"];
    let leaf = match payload["kind"].as_str() {
        Some("blind-archive-coverage-batch-receipt") => true,
        Some("blind-archive-coverage-aggregate-receipt") => false,
        _ => return Err(invalid()),
    };
    let mut keys = HEADER.to_vec();
    if leaf {
        keys.push("objects");
    } else {
        keys.push("archiveRootId");
        keys.extend_from_slice(SUMMARY);
    }
    exact(payload, &keys)?;
    let request_id = payload["requestId"].as_str().ok_or_else(invalid)?;
    let service_id = public_key_id(pin)?;
    if payload["version"] != 1
        || payload["serviceId"] != service_id
        || child["signerKeyId"] != service_id
        || payload["scopeId"] != scope
        || payload["policyRevision"].as_u64() != Some(revision)
        || !(20..=64).contains(&request_id.len())
        || !valid_id(request_id)
    {
        return Err(invalid());
    }
    if serde_json::to_vec(&child).map_err(|_| invalid())?.len() > 8192 {
        return Err(invalid());
    }
    let receipt: SignedEnvelope<Value> =
        serde_json::from_value(child.clone()).map_err(|_| invalid())?;
    if !verify_signed_envelope(&receipt, pin, DOMAIN)? {
        return Err(invalid());
    }
    let result = if leaf {
        let objects: Vec<CoverageObject> =
            serde_json::from_value(payload["objects"].clone()).map_err(|_| invalid())?;
        let batch = CoverageRequest {
            version: 1,
            request_id: request_id.to_owned(),
            objects,
        };
        batch.validate()?;
        Summary {
            height: 0,
            object_count: batch.objects.len() as u64,
            first_object_id: batch.objects[0].object_id.clone(),
            last_object_id: batch.objects.last().unwrap().object_id.clone(),
            set_digest: digest(
                json!({"kind":"archive-coverage-set-leaf","version":1,"objects":batch.objects}),
            )?,
            root_covered: batch.objects.iter().any(|object| object.object_id == root),
        }
    } else {
        if payload["archiveRootId"] != root {
            return Err(invalid());
        }
        let summary: Summary = serde_json::from_value(Value::Object(
            SUMMARY
                .iter()
                .map(|key| ((*key).to_owned(), payload[*key].clone()))
                .collect(),
        ))
        .map_err(|_| invalid())?;
        if summary.height == 0 {
            return Err(invalid());
        }
        summary
    };
    result.validate(root)?;
    Ok(result)
}
fn branch(root: &str, children: Vec<Summary>) -> Result<Summary, String> {
    let first = children.first().ok_or_else(invalid)?;
    if children.len() > MAX_CHILDREN || first.height >= 31 {
        return Err(invalid());
    }
    let mut count = 0u64;
    for (i, child) in children.iter().enumerate() {
        child.validate(root)?;
        if child.height != first.height
            || i > 0 && children[i - 1].last_object_id >= child.first_object_id
        {
            return Err(invalid());
        }
        count = count
            .checked_add(child.object_count)
            .filter(|sum| *sum <= MAX_SAFE)
            .ok_or_else(invalid)?;
    }
    Ok(Summary {
        height: first.height + 1,
        object_count: count,
        first_object_id: first.first_object_id.clone(),
        last_object_id: children.last().unwrap().last_object_id.clone(),
        root_covered: children.iter().any(|child| child.root_covered),
        set_digest: digest(
            json!({"kind":"archive-coverage-set-branch","version":1,"archiveRootId":root,"children":children}),
        )?,
    })
}

pub(crate) async fn aggregate(
    State(state): State<HttpState>,
    RoutePath(scope): RoutePath<String>,
    headers: HeaderMap,
    Json(request): Json<AggregateRequest>,
) -> Result<impl IntoResponse, ApiError> {
    if request.version != 1
        || !(20..=64).contains(&request.request_id.len())
        || !valid_id(&request.request_id)
        || !canonical_id(&request.archive_root_id)
        || request.children.is_empty()
        || request.children.len() > MAX_CHILDREN
    {
        return Err(failure(StatusCode::BAD_REQUEST, &invalid()));
    }
    let token = bearer(&headers)?;
    let receipt = tokio::task::spawn_blocking(move || {
        let _guard = state.store.lock.lock().map_err(|_| storage_failure("Storage lock unavailable".into()))?;
        let policy = state.store.authorize(&scope, &token, false).map_err(storage_failure)?;
        let pin = state.store.public_key().map_err(storage_failure)?;
        let root = &request.archive_root_id;
        let children = request.children.into_iter().map(|child| child_summary(child, root, &pin, &scope, policy.revision))
            .collect::<Result<Vec<_>, _>>().map_err(|e| failure(StatusCode::BAD_REQUEST, &e))?;
        let summary = branch(root, children).map_err(|e| failure(StatusCode::BAD_REQUEST, &e))?;
        let mut payload = serde_json::to_value(summary).map_err(|_| storage_failure("Invalid archive summary".into()))?;
        let fields = payload.as_object_mut().unwrap();
        fields.extend(json!({"kind":"blind-archive-coverage-aggregate-receipt","version":1,
            "serviceId":public_key_id(&pin).map_err(storage_failure)?,"scopeId":scope,"policyRevision":policy.revision,
            "requestId":request.request_id,"archiveRootId":request.archive_root_id}).as_object().unwrap().clone());
        sign_json_envelope(&state.store.seed, payload, public_key_id(&pin).map_err(storage_failure)?, DOMAIN).map_err(storage_failure)
    }).await.map_err(|_| storage_failure("Archive aggregation unavailable".into()))??;
    Ok((
        [(axum::http::header::CACHE_CONTROL, "no-store")],
        Json(receipt),
    ))
}
