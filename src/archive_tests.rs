use super::tests::{approve_fixture, encrypted_fixture};
use super::*;

async fn server(store: BlindStore) -> (String, tokio::task::JoinHandle<()>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin = format!("http://{}", listener.local_addr().unwrap());
    let app = router(store, origin.clone(), None, vec![]).unwrap();
    (
        origin,
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() }),
    )
}
fn fixture() -> (PathBuf, BlindStore, BlindObject) {
    let path = std::env::temp_dir().join(format!("rusty-archives-{}", rand::random::<u64>()));
    let store = BlindStore::open(path.clone()).unwrap();
    approve_fixture(&store);
    set_scope_writer_floor_for_test(&store, "opaque-scope", 2);
    (path, store, encrypted_fixture())
}
async fn upload(origin: &str, object: &BlindObject, token: &str, writer: u8) -> reqwest::Response {
    reqwest::Client::new()
        .put(format!(
            "{origin}/v2/scopes/opaque-scope/archives/{}?writerVersion={writer}",
            object.id().unwrap()
        ))
        .bearer_auth(token)
        .header("x-rusty-request-id", "archive-upload-request-00001")
        .json(object)
        .send()
        .await
        .unwrap()
}

#[tokio::test]
async fn given_opaque_archive_when_uploaded_and_retried_after_restart_then_return_durable_distinct_receipts_and_exact_bytes()
 {
    let (path, store, object) = fixture();
    let pin = store.public_key().unwrap();
    let (origin, task) = server(store.clone()).await;
    let discovery: Value = reqwest::get(format!("{origin}/.well-known/mesh-lighthouse"))
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(
        discovery["capabilities"]["encryptedArchives"],
        json!({"version":1,"maximumCiphertextBytes":262160})
    );
    assert_eq!(
        discovery["capabilities"]["archiveCoverageBatches"],
        json!({"version":1,"maximumObjects":64})
    );
    assert!(
        discovery["capabilities"].get("historyBaselines").is_none(),
        "Storage support must not advertise baseline activation"
    );
    let response = upload(&origin, &object, &"w".repeat(43), 2).await;
    let status = response.status();
    let headers = response.headers().clone();
    let body = response.text().await.unwrap();
    assert_eq!(status, StatusCode::OK, "Archive endpoint missing: {body}");
    assert_eq!(headers[axum::http::header::CACHE_CONTROL], "no-store");
    let receipt: SignedEnvelope<Value> = serde_json::from_str(&body).unwrap();
    assert!(verify_signed_envelope(&receipt, &pin, DOMAIN).unwrap());
    assert_eq!(
        receipt.payload,
        json!({ "kind":"blind-archive-storage-receipt", "version":1,
        "serviceId":public_key_id(&pin).unwrap(),"scopeId":"opaque-scope","keyEpoch":object.key_epoch,
        "objectId":object.id().unwrap(),"policyRevision":1,"requestId":"archive-upload-request-00001" })
    );
    assert!(
        store.objects("opaque-scope").unwrap().is_empty(),
        "Archive objects entered snapshot inventory"
    );
    let disk = path.join(format!(
        "scopes/opaque-scope/archives/{}.json",
        object.id().unwrap()
    ));
    let exact = fs::read(&disk).unwrap();
    task.abort();
    let _ = task.await;
    drop(store);
    let reopened = BlindStore::open(path.clone()).unwrap();
    let (origin, task) = server(reopened.clone()).await;
    let response = upload(&origin, &object, &"w".repeat(43), 2).await;
    assert_eq!(response.status(), StatusCode::OK);
    let retry: SignedEnvelope<Value> = response.json().await.unwrap();
    assert_eq!(retry, receipt);
    assert_eq!(fs::read(disk).unwrap(), exact);
    let response = reqwest::Client::new()
        .get(format!(
            "{origin}/v2/scopes/opaque-scope/archives/{}",
            object.id().unwrap()
        ))
        .bearer_auth("r".repeat(43))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.headers()[axum::http::header::CACHE_CONTROL],
        "no-store"
    );
    assert_eq!(response.json::<BlindObject>().await.unwrap(), object);
    task.abort();
    let _ = task.await;
    drop(reopened);
    fs::remove_dir_all(path).unwrap();
}

#[tokio::test]
async fn given_archive_namespace_when_tokens_versions_and_chunk_sizes_are_wrong_then_reject_without_changing_prior_evidence()
 {
    let (path, store, object) = fixture();
    let (origin, task) = server(store.clone()).await;
    assert_eq!(
        upload(&origin, &object, &"w".repeat(43), 2).await.status(),
        StatusCode::OK
    );
    for token in ["invalid".to_owned(), "r".repeat(43)] {
        assert_eq!(
            upload(&origin, &object, &token, 2).await.status(),
            StatusCode::FORBIDDEN
        );
    }
    assert_eq!(
        upload(&origin, &object, &"w".repeat(43), 1).await.status(),
        StatusCode::UPGRADE_REQUIRED
    );
    let mut maximum = object.clone();
    maximum.ciphertext = URL_SAFE_NO_PAD.encode(vec![17; 256 * 1024 + 16]);
    assert_eq!(
        upload(&origin, &maximum, &"w".repeat(43), 2).await.status(),
        StatusCode::OK
    );
    maximum.ciphertext = URL_SAFE_NO_PAD.encode(vec![17; 256 * 1024 + 17]);
    assert_eq!(
        upload(&origin, &maximum, &"w".repeat(43), 2).await.status(),
        StatusCode::BAD_REQUEST
    );
    let mut noncanonical = object.clone();
    noncanonical.nonce.push('=');
    assert_eq!(
        upload(&origin, &noncanonical, &"w".repeat(43), 2)
            .await
            .status(),
        StatusCode::BAD_REQUEST
    );
    assert!(store.objects("opaque-scope").unwrap().is_empty());
    assert_eq!(
        fs::read_dir(path.join("scopes/opaque-scope/archives"))
            .unwrap()
            .count(),
        2
    );
    task.abort();
    let _ = task.await;
    drop(store);
    fs::remove_dir_all(path).unwrap();
}

#[tokio::test]
async fn given_archive_coverage_request_when_every_named_object_is_durable_then_sign_only_archive_namespace_batch()
 {
    let (path, store, object) = fixture();
    let (origin, task) = server(store.clone()).await;
    assert_eq!(
        upload(&origin, &object, &"w".repeat(43), 2).await.status(),
        StatusCode::OK
    );
    let request = json!({"version":1,"requestId":"archive-coverage-request-0001",
        "objects":[{"objectId":object.id().unwrap(),"keyEpoch":object.key_epoch}]});
    let endpoint = format!("{origin}/v2/scopes/opaque-scope/archive-coverage");
    let client = reqwest::Client::new();
    let response = client
        .post(&endpoint)
        .bearer_auth("r".repeat(43))
        .json(&request)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let receipt: SignedEnvelope<Value> = response.json().await.unwrap();
    assert!(verify_signed_envelope(&receipt, &store.public_key().unwrap(), DOMAIN).unwrap());
    assert_eq!(
        receipt.payload["kind"],
        "blind-archive-coverage-batch-receipt"
    );
    assert_eq!(receipt.payload["objects"], request["objects"]);
    assert_eq!(receipt.payload["requestId"], request["requestId"]);
    assert_eq!(receipt.payload["policyRevision"], 1);
    assert_eq!(
        client
            .post(&endpoint)
            .bearer_auth("w".repeat(43))
            .json(&request)
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::FORBIDDEN
    );
    let mut wrong = request.clone();
    wrong["objects"][0]["keyEpoch"] = json!(object.key_epoch + 1);
    assert_ne!(
        client
            .post(&endpoint)
            .bearer_auth("r".repeat(43))
            .json(&wrong)
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::OK
    );
    let blob = client
        .get(format!(
            "{origin}/v2/scopes/opaque-scope/blobs/{}",
            object.id().unwrap()
        ))
        .bearer_auth("r".repeat(43))
        .send()
        .await
        .unwrap();
    assert_eq!(
        blob.status(),
        StatusCode::NOT_FOUND,
        "Archive silently shared attachment namespace"
    );
    fs::write(
        path.join(format!(
            "scopes/opaque-scope/archives/{}.json",
            object.id().unwrap()
        )),
        b"corrupt",
    )
    .unwrap();
    assert_eq!(
        client
            .post(&endpoint)
            .bearer_auth("r".repeat(43))
            .json(&request)
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::SERVICE_UNAVAILABLE
    );
    task.abort();
    let _ = task.await;
    drop(store);
    fs::remove_dir_all(path).unwrap();
}

#[path = "archive_adversarial_tests.rs"]
mod adversarial_tests;
#[path = "archive_aggregate_tests.rs"]
mod aggregate_tests;
