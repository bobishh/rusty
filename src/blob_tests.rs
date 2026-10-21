use super::*;
use crate::blind::tests::{approve_fixture, encrypted_fixture};

async fn coverage_response(
    store: BlindStore,
    request: Value,
    token: &str,
) -> (StatusCode, axum::http::HeaderMap, Value) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin = format!("http://{}", listener.local_addr().unwrap());
    let app = router(store, origin.clone(), vec![]).unwrap();
    let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    let response = reqwest::Client::new()
        .post(format!("{origin}/v2/scopes/opaque-scope/blob-coverage"))
        .bearer_auth(token)
        .json(&request)
        .send()
        .await
        .unwrap();
    let status = response.status();
    let headers = response.headers().clone();
    let body = response.text().await.unwrap();
    let body = serde_json::from_str(&body).unwrap_or(Value::String(body));
    server.abort();
    let _ = server.await;
    (status, headers, body)
}

// Given a cold read-only recipient, a bounded proof confirms every immutable object without uploading or reading the file body.
#[tokio::test]
async fn blob_coverage_http_receipt_is_read_only_signed_and_restart_safe() {
    let (path, store, first) = fixture(MAX_SCOPE_BYTES);
    let mut second = first.clone();
    second.nonce = URL_SAFE_NO_PAD.encode([7; 12]);
    let mut objects = vec![first, second];
    objects.sort_by_key(|object| object.id().unwrap());
    for object in &objects {
        store
            .save_blob_for_writer(
                "opaque-scope",
                &"w".repeat(43),
                object.clone(),
                "prepared",
                2,
            )
            .unwrap();
    }
    let expected: Vec<Value> = objects
        .iter()
        .map(|object| json!({"objectId":object.id().unwrap(),"keyEpoch":object.key_epoch}))
        .collect();
    let directory = path.join("scopes/opaque-scope/blobs");
    let before = directory_usage(&directory).unwrap();
    let request = json!({"version":1,"requestId":"coverage-request-00000001","objects":expected});
    let (status, headers, body) =
        coverage_response(store.clone(), request.clone(), &"r".repeat(43)).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "read-only coverage endpoint must be available: {body}"
    );
    assert_eq!(headers[axum::http::header::CACHE_CONTROL], "no-store");
    let receipt: SignedEnvelope<Value> = serde_json::from_value(body).unwrap();
    assert!(verify_signed_envelope(&receipt, &store.public_key().unwrap(), DOMAIN).unwrap());
    assert_eq!(
        receipt.payload,
        json!({"kind":"blind-blob-coverage-receipt","version":1,
        "serviceId":public_key_id(&store.public_key().unwrap()).unwrap(),"scopeId":"opaque-scope",
        "policyRevision":1,"requestId":"coverage-request-00000001","objects":expected})
    );
    assert_eq!(directory_usage(&directory).unwrap(), before);
    assert_eq!(store.scope_storage_bytes("opaque-scope").unwrap(), before.0);
    drop(store);
    let restarted = BlindStore::open(path.clone()).unwrap();
    let (status, _, body) = coverage_response(restarted.clone(), request, &"r".repeat(43)).await;
    assert_eq!(status, StatusCode::OK);
    let repeated: SignedEnvelope<Value> = serde_json::from_value(body).unwrap();
    assert!(verify_signed_envelope(&repeated, &restarted.public_key().unwrap(), DOMAIN).unwrap());
    assert_eq!(repeated.payload, receipt.payload);
    assert_eq!(directory_usage(&directory).unwrap(), before);
    drop(restarted);
    fs::remove_dir_all(path).unwrap();
}

// Given any missing, substituted or unauthorized part, never issue a partial coverage proof.
#[tokio::test]
async fn blob_coverage_http_rejects_missing_corrupt_wrong_epoch_and_denied_access() {
    let (path, store, object) = fixture(MAX_SCOPE_BYTES);
    let id = object.id().unwrap();
    store
        .save_blob_for_writer(
            "opaque-scope",
            &"w".repeat(43),
            object.clone(),
            "prepared",
            2,
        )
        .unwrap();
    let request = json!({"version":1,"requestId":"coverage-request-00000002",
        "objects":[{"objectId":id,"keyEpoch":object.key_epoch}]});
    assert_eq!(
        coverage_response(store.clone(), request.clone(), "invalid-token")
            .await
            .0,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        coverage_response(store.clone(), request.clone(), &"w".repeat(43))
            .await
            .0,
        StatusCode::FORBIDDEN
    );
    let mut wrong_epoch = request.clone();
    wrong_epoch["objects"][0]["keyEpoch"] = json!(object.key_epoch + 1);
    assert_ne!(
        coverage_response(store.clone(), wrong_epoch, &"r".repeat(43))
            .await
            .0,
        StatusCode::OK
    );
    let mut missing = request.clone();
    missing["objects"][0]["objectId"] = json!("A".repeat(43));
    assert_eq!(
        coverage_response(store.clone(), missing, &"r".repeat(43))
            .await
            .0,
        StatusCode::NOT_FOUND
    );
    fs::write(
        path.join(format!("scopes/opaque-scope/blobs/{id}.json")),
        b"corrupt ciphertext",
    )
    .unwrap();
    assert_eq!(
        coverage_response(store.clone(), request, &"r".repeat(43))
            .await
            .0,
        StatusCode::SERVICE_UNAVAILABLE
    );
    drop(store);
    fs::remove_dir_all(path).unwrap();
}

// Given untrusted request JSON, do not authorize an oversized, ambiguous or substituted manifest set.
#[tokio::test]
async fn blob_coverage_http_rejects_unbounded_duplicate_unsorted_and_extra_fields() {
    let (path, store, object) = fixture(MAX_SCOPE_BYTES);
    let entry = json!({"objectId":object.id().unwrap(),"keyEpoch":object.key_epoch});
    let base = json!({"version":1,"requestId":"coverage-request-00000003","objects":[entry]});
    let mut requests = vec![
        json!({"version":1,"requestId":"coverage-request-00000003","objects":[]}),
        json!({"version":1,"requestId":"coverage-request-00000003","objects":vec![entry.clone();34]}),
        json!({"version":1,"requestId":"coverage-request-00000003","objects":[entry.clone(),entry]}),
        json!({"version":2,"requestId":"coverage-request-00000003","objects":[]}),
        json!({"version":1,"requestId":"coverage-request-00000003","objects":[{"objectId":"Z".repeat(43),"keyEpoch":1},{"objectId":"A".repeat(43),"keyEpoch":1}]}),
    ];
    let mut extra = base.clone();
    extra["contentKey"] = json!("must-not-be-accepted");
    requests.push(extra);
    let mut extra_object = base;
    extra_object["objects"][0]["name"] = json!("private-file-name");
    requests.push(extra_object);
    for key_epoch in [
        json!(0),
        json!(-1),
        json!(1.5),
        json!(9_007_199_254_740_992u64),
    ] {
        requests.push(json!({"version":1,"requestId":"coverage-request-00000003",
            "objects":[{"objectId":object.id().unwrap(),"keyEpoch":key_epoch}]}));
    }
    requests.push(json!({"version":1,"requestId":"short",
        "objects":[{"objectId":object.id().unwrap(),"keyEpoch":1}]}));
    for request in requests {
        let (status, _, _) = coverage_response(store.clone(), request, &"r".repeat(43)).await;
        assert!(status == StatusCode::BAD_REQUEST || status == StatusCode::UNPROCESSABLE_ENTITY);
    }
    let (status, _, _) = coverage_response(
        store.clone(),
        json!({"padding":"x".repeat(16 * 1024)}),
        &"r".repeat(43),
    )
    .await;
    assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE);
    drop(store);
    fs::remove_dir_all(path).unwrap();
}

fn fixture(limit: u64) -> (PathBuf, BlindStore, BlindObject) {
    let path = std::env::temp_dir().join(format!("rusty-blobs-{}", rand::random::<u64>()));
    let store = BlindStore::open_with_scope_limit(path.clone(), limit).unwrap();
    approve_fixture(&store);
    set_scope_writer_floor_for_test(&store, "opaque-scope", 2);
    (path, store, encrypted_fixture())
}

// Given an interrupted namespace commit, coverage cannot attest durability until both links are synced.
#[test]
fn blob_coverage_durability_requires_scope_and_blob_links() {
    let (path, store, object) = fixture(MAX_SCOPE_BYTES);
    store
        .save_blob_for_writer(
            "opaque-scope",
            &"w".repeat(43),
            object.clone(),
            "prepared",
            2,
        )
        .unwrap();
    let request = json!({"version":1,"requestId":"coverage-durability-00001",
        "objects":[{"objectId":object.id().unwrap(),"keyEpoch":object.key_epoch}]});
    for directory in [
        path.join("scopes/opaque-scope"),
        path.join("scopes/opaque-scope/blobs"),
    ] {
        FAILED_DIRECTORY_SYNC.with(|failure| *failure.borrow_mut() = Some(directory));
        let result = store.blob_coverage(
            "opaque-scope",
            &"r".repeat(43),
            serde_json::from_value(request.clone()).unwrap(),
        );
        FAILED_DIRECTORY_SYNC.with(|failure| *failure.borrow_mut() = None);
        assert_eq!(result.unwrap_err(), "Durable storage commit failed");
    }
    assert!(
        store
            .blob_coverage(
                "opaque-scope",
                &"r".repeat(43),
                serde_json::from_value(request).unwrap()
            )
            .is_ok()
    );
    drop(store);
    fs::remove_dir_all(path).unwrap();
}

// Given changed policy, fresh receipts bind its current revision and revoked access produces no receipt.
#[tokio::test]
async fn blob_coverage_http_uses_live_policy_and_rejects_revocation() {
    let (path, store, object) = fixture(MAX_SCOPE_BYTES);
    store
        .save_blob_for_writer(
            "opaque-scope",
            &"w".repeat(43),
            object.clone(),
            "prepared",
            2,
        )
        .unwrap();
    let request = json!({"version":1,"requestId":"coverage-live-policy-001",
        "objects":[{"objectId":object.id().unwrap(),"keyEpoch":object.key_epoch}]});
    let policy_path = path.join("scopes/opaque-scope/policy.json");
    let mut policy: Value = serde_json::from_slice(&fs::read(&policy_path).unwrap()).unwrap();
    policy["revision"] = json!(2);
    atomic_write(&policy_path, &serde_json::to_vec(&policy).unwrap()).unwrap();
    let (status, _, receipt) =
        coverage_response(store.clone(), request.clone(), &"r".repeat(43)).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(receipt["payload"]["policyRevision"], 2);
    policy["revoked"] = json!(true);
    atomic_write(&policy_path, &serde_json::to_vec(&policy).unwrap()).unwrap();
    assert_eq!(
        coverage_response(store.clone(), request, &"r".repeat(43))
            .await
            .0,
        StatusCode::FORBIDDEN
    );
    drop(store);
    fs::remove_dir_all(path).unwrap();
}

// Given a completed blob, snapshot cleanup never addresses it, including restart.
#[test]
fn snapshot_cleanup_cannot_prune_attachment_namespace() {
    let (path, store, blob) = fixture(MAX_SCOPE_BYTES);
    let id = blob.id().unwrap();
    store
        .save_blob_for_writer("opaque-scope", &"w".repeat(43), blob.clone(), "blob", 2)
        .unwrap();
    let mut snapshot = blob.clone();
    snapshot.nonce = URL_SAFE_NO_PAD.encode([9; 12]);
    store
        .save_for_writer("opaque-scope", &"w".repeat(43), snapshot, "snapshot", 2)
        .unwrap();
    // This is the actual checkpoint deletion primitive, not a simulated cleanup.
    store.prune_checkpoint_objects("opaque-scope", 1).unwrap();
    assert_eq!(store.read_blob("opaque-scope", &id).unwrap(), blob);
    drop(store);
    let restarted = BlindStore::open(path.clone()).unwrap();
    assert_eq!(restarted.read_blob("opaque-scope", &id).unwrap(), blob);
    drop(restarted);
    fs::remove_dir_all(path).unwrap();
}

// Given combined byte capacity, neither namespace can use the other's quota twice.
#[test]
fn attachment_and_snapshot_writes_share_scope_quota_but_retries_survive() {
    let blob = encrypted_fixture();
    let blob_bytes = serde_json::to_vec(&blob).unwrap().len() as u64;
    let (path, store, blob) = fixture(blob_bytes + 1024);
    store
        .save_blob_for_writer("opaque-scope", &"w".repeat(43), blob.clone(), "first", 2)
        .unwrap();
    assert_eq!(
        store
            .save_for_writer("opaque-scope", &"w".repeat(43), blob.clone(), "snapshot", 2)
            .unwrap_err(),
        "Storage capacity exceeded"
    );
    let mut large = blob.clone();
    large.ciphertext = URL_SAFE_NO_PAD.encode(vec![4; 2048]);
    assert_eq!(
        store
            .save_blob_for_writer("opaque-scope", &"w".repeat(43), large, "too-large", 2)
            .unwrap_err(),
        "Storage capacity exceeded"
    );
    store
        .save_blob_for_writer("opaque-scope", &"w".repeat(43), blob.clone(), "retry", 2)
        .unwrap();
    assert_eq!(
        store.scope_storage_bytes("opaque-scope").unwrap(),
        blob_bytes
    );
    assert_eq!(
        directory_usage(&path.join("scopes/opaque-scope/blobs"))
            .unwrap()
            .1,
        1
    );
    drop(store);
    fs::remove_dir_all(path).unwrap();
}

// Given a rename without directory durability, no storage receipt is issued.
#[test]
fn attachment_durability_failure_retries_exact_ciphertext_without_growth() {
    let (path, store, blob) = fixture(MAX_SCOPE_BYTES);
    let directory = path.join("scopes/opaque-scope/blobs");
    FAILED_DIRECTORY_SYNC.with(|failure| *failure.borrow_mut() = Some(directory.clone()));
    let result = store.save_blob_for_writer(
        "opaque-scope",
        &"w".repeat(43),
        blob.clone(),
        "uncertain",
        2,
    );
    FAILED_DIRECTORY_SYNC.with(|failure| *failure.borrow_mut() = None);
    assert_eq!(result.unwrap_err(), "Durable storage commit failed");
    let receipt = store
        .save_blob_for_writer(
            "opaque-scope",
            &"w".repeat(43),
            blob.clone(),
            "uncertain",
            2,
        )
        .unwrap();
    assert_eq!(receipt.payload["objectId"], blob.id().unwrap());
    assert_eq!(directory_usage(&directory).unwrap().1, 1);
    assert_eq!(
        store
            .read_blob("opaque-scope", &blob.id().unwrap())
            .unwrap(),
        blob
    );
    drop(store);
    fs::remove_dir_all(path).unwrap();
}

// Given unreadable/substituted ciphertext, do not acknowledge or return a blob.
#[test]
fn attachment_integrity_size_scope_and_revoked_access_fail_closed() {
    let (path, store, blob) = fixture(MAX_SCOPE_BYTES);
    assert!(
        store
            .save_blob("other-scope", &"w".repeat(43), blob.clone(), "wrong-scope")
            .is_err()
    );
    let mut oversized = blob.clone();
    oversized.ciphertext = URL_SAFE_NO_PAD.encode(vec![0; MAX_BLOB_CIPHERTEXT_BYTES + 1]);
    assert!(
        store
            .save_blob("opaque-scope", &"w".repeat(43), oversized, "oversized")
            .is_err()
    );
    store
        .save_blob_for_writer("opaque-scope", &"w".repeat(43), blob.clone(), "first", 2)
        .unwrap();
    let id = blob.id().unwrap();
    let mut altered = blob.clone();
    altered.nonce = URL_SAFE_NO_PAD.encode([7; 12]);
    fs::write(
        path.join(format!("scopes/opaque-scope/blobs/{id}.json")),
        serde_json::to_vec(&altered).unwrap(),
    )
    .unwrap();
    assert_eq!(
        store.read_blob("opaque-scope", &id).unwrap_err(),
        "Attachment object integrity failure"
    );
    assert!(
        store
            .save_blob_for_writer(
                "opaque-scope",
                &"w".repeat(43),
                blob.clone(),
                "retry-corrupt",
                2
            )
            .is_err()
    );
    store
        .approve(
            "opaque-scope",
            ScopeApproval {
                expected_revision: 1,
                read_token: "r".repeat(43),
                write_token: "w".repeat(43),
                revoked: true,
            },
        )
        .unwrap();
    assert_eq!(
        store
            .save_blob("opaque-scope", &"w".repeat(43), blob, "revoked")
            .unwrap_err(),
        "Storage access revoked"
    );
    drop(store);
    fs::remove_dir_all(path).unwrap();
}
