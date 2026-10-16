use super::*;

fn otlp_log_records(payload: &Value) -> Vec<Value> {
    payload["resourceLogs"]
        .as_array()
        .into_iter()
        .flatten()
        .flat_map(|resource| resource["scopeLogs"].as_array().into_iter().flatten())
        .flat_map(|scope| {
            scope["logRecords"]
                .as_array()
                .into_iter()
                .flatten()
                .cloned()
        })
        .collect()
}

fn log_attribute(record: &Value, key: &str) -> Option<String> {
    record["attributes"]
        .as_array()?
        .iter()
        .find(|attribute| attribute["key"] == key)?["value"]["stringValue"]
        .as_str()
        .map(str::to_owned)
}

fn log_event(record: &Value) -> Option<String> {
    log_attribute(record, "event.name")
}

// Given durable writes and a duplicate retry, telemetry reports actual disk growth
// and quota refusal, while ciphertext and bearer credentials remain absent.
#[tokio::test(flavor = "multi_thread")]
async fn storage_growth_logs_distinguish_new_objects_retries_and_quota() {
    let received = Arc::new(Mutex::new(Vec::<Value>::new()));
    let records = received.clone();
    let sink = Router::new()
        .route(
            "/v1/logs",
            axum::routing::post(move |Json(body): Json<Value>| {
                let records = records.clone();
                async move {
                    records.lock().unwrap().extend(otlp_log_records(&body));
                    Json(serde_json::json!({}))
                }
            }),
        )
        .route(
            "/v1/traces",
            axum::routing::post(|| async { Json(serde_json::json!({})) }),
        );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = format!("http://{}", listener.local_addr().unwrap());
    let server = tokio::spawn(async move { axum::serve(listener, sink).await.unwrap() });
    tokio::time::sleep(std::time::Duration::from_millis(25)).await;
    let telemetry = Telemetry::start(
        crate::telemetry::Config::new(
            "debug",
            Some(endpoint),
            Some("test-private-key".into()),
            "rusty".into(),
        )
        .unwrap(),
    );
    let directory = std::env::temp_dir().join(format!("rusty-growth-{}", rand::random::<u64>()));
    let object = encrypted_fixture();
    let limit = serde_json::to_vec(&object).unwrap().len() as u64 + 1024;
    let store = BlindStore::open_with_scope_limit(directory.clone(), limit)
        .unwrap()
        .with_telemetry(telemetry);
    approve_fixture(&store);
    store
        .save("opaque-scope", &"w".repeat(43), object.clone(), "write-one")
        .unwrap();
    store
        .save("opaque-scope", &"w".repeat(43), object.clone(), "retry-one")
        .unwrap();
    let mut next = object.clone();
    next.nonce = URL_SAFE_NO_PAD.encode([3; 12]);
    assert!(
        store
            .save("opaque-scope", &"w".repeat(43), next, "write-two")
            .is_err()
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin = format!("http://{}", listener.local_addr().unwrap());
    let app = router_with_telemetry(
        store.clone(),
        origin.clone(),
        None,
        vec![],
        store.telemetry.clone(),
    )
    .unwrap();
    let native_server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    for (producer, build) in [
        ("tincanban", "a".repeat(40)),
        ("private-must-not-log", "private-must-not-log".into()),
    ] {
        let response = reqwest::Client::new()
            .put(format!(
                "{origin}/v2/scopes/opaque-scope/objects/{}",
                object.id().unwrap()
            ))
            .bearer_auth("private-must-not-log")
            .header("x-rusty-request-id", "metadata-only")
            .header("x-rusty-client", producer)
            .header("x-rusty-build", build)
            .json(&object)
            .send()
            .await
            .unwrap();
        assert_eq!(
            response.status(),
            StatusCode::FORBIDDEN,
            "Diagnostic labels cannot grant write access"
        );
    }
    store.telemetry.force_flush();
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        loop {
            if received
                .lock()
                .unwrap()
                .iter()
                .filter(|record| log_event(record).as_deref() == Some("http.request.failed"))
                .count()
                >= 2
            {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    let records = received.lock().unwrap();
    let expected_build = "a".repeat(40);
    assert!(records.iter().any(|record| {
        log_event(record).as_deref() == Some("http.request.failed")
            && log_attribute(record, "rusty.client").as_deref() == Some("tincanban")
            && log_attribute(record, "rusty.client_build").as_deref()
                == Some(expected_build.as_str())
    }));
    assert!(records.iter().any(|record| {
        log_event(record).as_deref() == Some("http.request.failed")
            && log_attribute(record, "rusty.client").is_none()
            && log_attribute(record, "rusty.client_build").is_none()
    }));
    assert!(
        !serde_json::to_string(&*records)
            .unwrap()
            .contains("private-must-not-log")
    );
    let stored = records
        .iter()
        .find(|value| log_event(value).as_deref() == Some("storage.object.stored"))
        .unwrap();
    assert_eq!(
        log_attribute(stored, "rusty.stored_bytes_before").as_deref(),
        Some("0")
    );
    assert!(
        log_attribute(stored, "rusty.stored_bytes")
            .unwrap()
            .parse::<u64>()
            .unwrap()
            > 0
    );
    assert_eq!(
        log_attribute(stored, "rusty.object_count").as_deref(),
        Some("1")
    );
    assert!(
        records
            .iter()
            .any(|value| log_event(value).as_deref() == Some("storage.object.reused"))
    );
    assert!(
        records
            .iter()
            .any(|value| log_event(value).as_deref() == Some("storage.quota.exceeded"))
    );
    assert!(
        !serde_json::to_string(&*records)
            .unwrap()
            .contains(&object.ciphertext)
    );
    assert!(
        !serde_json::to_string(&*records)
            .unwrap()
            .contains(&"w".repeat(43))
    );
    drop(records);
    native_server.abort();
    let _ = native_server.await;
    drop(store);
    server.abort();
    fs::remove_dir_all(directory).unwrap();
}

#[tokio::test]
async fn service_root_opens_connection_instructions_without_exposing_storage() {
    let directory = std::env::temp_dir().join(format!("rusty-root-{}", rand::random::<u64>()));
    let store = BlindStore::open(directory.clone()).unwrap();
    let app = router(store, "https://rusty.example".into(), None, vec![]).unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin = format!("http://{}", listener.local_addr().unwrap());
    let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    let expected_build_sha = crate::build_identity::build_sha()
        .map(Value::from)
        .unwrap_or(Value::Null);
    let health: Value = reqwest::get(format!("{origin}/health"))
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(health["status"], "ok");
    assert_eq!(health["mode"], "blind");
    assert_eq!(health["buildSha"], expected_build_sha);
    assert_eq!(
        health["artifactSha256"],
        serde_json::json!(crate::build_identity::artifact_sha256())
    );
    assert_eq!(
        health["sdkSha"],
        serde_json::json!(crate::build_identity::sdk_sha())
    );
    assert_eq!(
        health["readers"],
        serde_json::json!({"scopePolicy": 2, "managementPolicy": 1, "archiveStorage": 1, "publicBoardPublication": 1})
    );
    let response = reqwest::get(format!("{origin}/")).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let html = response.text().await.unwrap();
    assert!(html.contains("Board storage is available"));
    assert!(html.contains("View Rusty logs"));
    let discovery: Value = reqwest::get(format!("{origin}/.well-known/mesh-lighthouse"))
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(discovery["protocolVersions"], json!([2]));
    assert_eq!(discovery["buildSha"], expected_build_sha);
    assert_eq!(discovery["artifactSha256"], health["artifactSha256"]);
    assert_eq!(discovery["sdkSha"], health["sdkSha"]);
    assert_eq!(discovery["readers"], health["readers"]);
    assert_eq!(discovery["capabilities"]["scopeManagement"]["version"], 1);
    assert_eq!(
        discovery["capabilities"]["scopeEnrollmentRetry"]["version"],
        1
    );
    assert_eq!(
        discovery["capabilities"]["snapshotCheckpoints"]["version"],
        1
    );
    assert_eq!(
        discovery["capabilities"]["snapshotCheckpoints"]["observedSequence"],
        json!(true)
    );
    assert_eq!(
        discovery["capabilities"]["publicBoardPublication"]["version"],
        1
    );
    assert_eq!(
        discovery["capabilities"]["writerPolicy"],
        json!({"version":1,"maximumWriterVersion":2})
    );
    assert_eq!(
        discovery["capabilities"]["blobCoverage"],
        json!({"version":1,"maximumObjects":33})
    );
    assert_eq!(
        reqwest::get(format!("{origin}/unknown"))
            .await
            .unwrap()
            .status(),
        StatusCode::NOT_FOUND
    );
    server.abort();
    let _ = server.await;
    fs::remove_dir_all(directory).unwrap();
}

// Given a full scope, when its deployment quota increases and storage restarts,
// then immutable retries and existing objects survive and new writes resume.
#[test]
fn configured_scope_quota_preserves_objects_and_recovers_after_increase() {
    let directory = std::env::temp_dir().join(format!("rusty-quota-{}", rand::random::<u64>()));
    let first = encrypted_fixture();
    let limit = serde_json::to_vec(&first).unwrap().len() as u64 + 1024;
    let store = BlindStore::open_with_scope_limit(directory.clone(), limit).unwrap();
    approve_fixture(&store);
    store
        .save(
            "opaque-scope",
            &"w".repeat(43),
            first.clone(),
            "request-one",
        )
        .unwrap();
    let mut second = first.clone();
    second.nonce = URL_SAFE_NO_PAD.encode([3u8; 12]);
    assert_eq!(
        store
            .save(
                "opaque-scope",
                &"w".repeat(43),
                second.clone(),
                "request-two"
            )
            .unwrap_err(),
        "Storage capacity exceeded"
    );
    assert!(
        store
            .save("opaque-scope", &"w".repeat(43), first, "request-retry")
            .is_ok()
    );
    let key = store.public_key().unwrap();
    drop(store);
    let store = BlindStore::open_with_scope_limit(directory.clone(), limit * 4).unwrap();
    assert_eq!(store.public_key().unwrap(), key);
    assert_eq!(store.objects("opaque-scope").unwrap().len(), 1);
    assert!(
        store
            .save("opaque-scope", &"w".repeat(43), second, "request-two")
            .is_ok()
    );
    assert_eq!(store.objects("opaque-scope").unwrap().len(), 2);
    drop(store);
    fs::remove_dir_all(directory).unwrap();
}

// Given a new independent storage directory, when Rusty starts its blind store,
// then it initializes without reading a legacy board config or any content key.
#[test]
fn blind_store_starts_without_a_document_or_content_key() {
    let directory = std::env::temp_dir().join(format!("rusty-blind-{}", rand::random::<u64>()));
    std::fs::create_dir_all(&directory).unwrap();
    let result = BlindStore::open(directory.clone());
    std::fs::remove_dir_all(directory).unwrap();
    assert!(result.is_ok(), "Blind store must initialize independently");
}

pub(super) fn encrypted_fixture() -> BlindObject {
    BlindObject {
        version: 1,
        scope_id: "opaque-scope".into(),
        key_epoch: 1,
        nonce: URL_SAFE_NO_PAD.encode([1u8; 12]),
        ciphertext: URL_SAFE_NO_PAD.encode([2u8; 48]),
    }
}

pub(super) fn owner_controller_fixture() -> (Value, String, Value, String) {
    use meta_mesh_core::{
        DEFAULT_SIGNATURE_DOMAIN, DeviceCertificatePayload, public_key_from_seed, public_key_id,
        sign_device_certificate,
    };
    let owner_public_key = public_key_from_seed(&[31; 32]).unwrap();
    let owner_person_id = public_key_id(&owner_public_key).unwrap();
    let device_public_key = public_key_from_seed(&[32; 32]).unwrap();
    let device_id = public_key_id(&device_public_key).unwrap();
    let certificate = sign_device_certificate(
        &[31; 32],
        DeviceCertificatePayload {
            kind: "device-certificate".into(),
            version: 1,
            person_id: owner_person_id.clone(),
            device_id: device_id.clone(),
            device_public_key,
            issuer_certificate_hash: None,
            can_enroll_devices: true,
        },
        &owner_person_id,
        DEFAULT_SIGNATURE_DOMAIN,
    )
    .unwrap();
    let identity = json!({
        "personId": owner_person_id,
        "publicKey": owner_public_key,
        "displayName": "Test owner"
    });
    let certificate = serde_json::to_value(certificate).unwrap();
    (identity, device_id, certificate, owner_person_id)
}

fn signed_scope_request(
    challenge: Value,
    identity: Value,
    device_id: &str,
    certificate: Value,
    read_token: &str,
    write_token: &str,
    revoked: bool,
) -> Value {
    signed_scope_request_with_minimum_writer_version(
        challenge,
        identity.clone(),
        device_id,
        certificate.clone(),
        read_token,
        write_token,
        revoked,
        None,
    )
}

fn signed_scope_request_with_minimum_writer_version(
    challenge: Value,
    identity: Value,
    device_id: &str,
    certificate: Value,
    read_token: &str,
    write_token: &str,
    revoked: bool,
    minimum_writer_version: Option<u8>,
) -> Value {
    use meta_mesh_core::sign_json_envelope;
    let payload = &challenge["payload"];
    let mut authorization = json!({
        "kind": "rusty-scope-enrollment", "version": 1,
        "challengeId": payload["challengeId"], "nonce": payload["nonce"],
        "serviceId": payload["serviceId"], "publicOrigin": payload["publicOrigin"],
        "scopeId": payload["scopeId"], "personId": payload["personId"],
        "deviceId": device_id, "deviceKeyId": device_id,
        "expectedRevision": payload["expectedRevision"],
        "readTokenHash": digest(read_token.as_bytes()),
        "writeTokenHash": digest(write_token.as_bytes()),
        "revoked": revoked, "expiresAt": payload["expiresAt"]
    });
    if let Some(version) = minimum_writer_version {
        authorization["minimumWriterVersion"] = json!(version);
    }
    let authorization = sign_json_envelope(&[32; 32], authorization, device_id, "MATCH/1").unwrap();
    json!({
        "challenge": challenge,
        "identity": identity,
        "deviceId": device_id,
        "certificates": [certificate],
        "readToken": read_token,
        "writeToken": write_token,
        "revoked": revoked,
        "authorization": authorization
    })
}

#[tokio::test]
async fn writer_policy_floor_rejects_old_snapshot_writes_after_signed_scope_migration() {
    let directory =
        std::env::temp_dir().join(format!("rusty-writer-floor-{}", rand::random::<u64>()));
    let store = BlindStore::open(directory.clone()).unwrap();
    let (identity, device_id, certificate, _) = owner_controller_fixture();
    let trusted = TrustedOwner {
        identity: serde_json::from_value(identity.clone()).unwrap(),
        allowed_controller_device_ids: vec![device_id.clone()],
    };
    let app = router(
        store.clone(),
        "https://rusty.example".into(),
        Some(trusted),
        vec![],
    )
    .unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin = format!("http://{}", listener.local_addr().unwrap());
    let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    let client = reqwest::Client::new();
    let challenge: Value = client.post(format!("{origin}/v2/enrollment/challenge"))
        .json(&json!({"version":1,"scopeId":"opaque-scope","identity":identity,"deviceId":device_id,"certificates":[certificate]}))
        .send().await.unwrap().json().await.unwrap();
    let signed = signed_scope_request_with_minimum_writer_version(
        challenge["challenge"].clone(),
        identity.clone(),
        &device_id,
        certificate.clone(),
        &"r".repeat(43),
        &"w".repeat(43),
        false,
        Some(2),
    );
    let enrolled = client
        .put(format!("{origin}/v2/scopes/opaque-scope"))
        .json(&signed)
        .send()
        .await
        .unwrap();
    assert_eq!(enrolled.status(), StatusCode::OK);
    let enrolled: Value = enrolled.json().await.unwrap();
    assert_eq!(enrolled["receipt"]["payload"]["minimumWriterVersion"], 2);

    let object = encrypted_fixture();
    let object_path = format!(
        "{origin}/v2/scopes/opaque-scope/objects/{}",
        object.id().unwrap()
    );
    let response = client
        .put(&object_path)
        .bearer_auth("w".repeat(43))
        .header("x-rusty-request-id", "writer-floor-old-request")
        .json(&object)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UPGRADE_REQUIRED);
    assert_eq!(
        response.json::<Value>().await.unwrap()["code"],
        "writer_upgrade_required"
    );
    assert!(store.objects("opaque-scope").unwrap().is_empty());

    let capable = client
        .put(format!("{object_path}?writerVersion=2"))
        .bearer_auth("w".repeat(43))
        .header("x-rusty-request-id", "writer-floor-capable-request")
        .json(&object)
        .send()
        .await
        .unwrap();
    assert_eq!(capable.status(), StatusCode::OK);

    let second_challenge: Value = client.post(format!("{origin}/v2/enrollment/challenge"))
        .json(&json!({"version":1,"scopeId":"opaque-scope","identity":identity,"deviceId":device_id,"certificates":[certificate]}))
        .send().await.unwrap().json().await.unwrap();
    let downgrade = signed_scope_request_with_minimum_writer_version(
        second_challenge["challenge"].clone(),
        identity,
        &device_id,
        certificate,
        &"r".repeat(43),
        &"w".repeat(43),
        false,
        Some(1),
    );
    let updated = client
        .put(format!("{origin}/v2/scopes/opaque-scope"))
        .json(&downgrade)
        .send()
        .await
        .unwrap();
    assert_eq!(updated.status(), StatusCode::OK);
    let updated: Value = updated.json().await.unwrap();
    assert_eq!(updated["receipt"]["payload"]["minimumWriterVersion"], 2);
    assert_eq!(
        store.policy("opaque-scope").unwrap().minimum_writer_version,
        2
    );

    let denied_blob = client
        .put(format!(
            "{origin}/v2/scopes/opaque-scope/blobs/{}",
            object.id().unwrap()
        ))
        .bearer_auth("w".repeat(43))
        .header("x-rusty-request-id", "writer-floor-blob-policy")
        .json(&object)
        .send()
        .await
        .unwrap();
    assert_eq!(denied_blob.status(), StatusCode::UPGRADE_REQUIRED);
    assert_eq!(
        denied_blob.json::<Value>().await.unwrap()["code"],
        "writer_upgrade_required"
    );
    let capable_blob = client
        .put(format!(
            "{origin}/v2/scopes/opaque-scope/blobs/{}?writerVersion=2",
            object.id().unwrap()
        ))
        .bearer_auth("w".repeat(43))
        .header("x-rusty-request-id", "writer-floor-blob-capable")
        .json(&object)
        .send()
        .await
        .unwrap();
    assert_eq!(capable_blob.status(), StatusCode::OK);

    server.abort();
    let _ = server.await;
    drop(store);
    let restarted = BlindStore::open(directory.clone()).unwrap();
    assert_eq!(
        restarted
            .policy("opaque-scope")
            .unwrap()
            .minimum_writer_version,
        2
    );
    assert!(
        restarted
            .save(
                "opaque-scope",
                &"w".repeat(43),
                encrypted_fixture(),
                "restart-old-writer"
            )
            .is_err()
    );
    let capable_object = encrypted_fixture();
    assert!(
        restarted
            .save_for_writer(
                "opaque-scope",
                &"w".repeat(43),
                capable_object,
                "restart-new-writer",
                2
            )
            .is_ok()
    );
    drop(restarted);
    let _ = fs::remove_dir_all(directory);
}

// Given a certificate chain rooted in the configured owner identity, when a
// browser connects by address, then Rusty issues a short-lived signed challenge
// without an operator bearer token.
#[tokio::test]
async fn address_only_owner_connection_gets_signed_enrollment_challenge() {
    let directory =
        std::env::temp_dir().join(format!("rusty-enroll-red-{}", rand::random::<u64>()));
    let store = BlindStore::open(directory.clone()).unwrap();
    let (identity, device_id, certificate, _person_id) = owner_controller_fixture();
    let trusted = TrustedOwner {
        identity: serde_json::from_value(identity.clone()).unwrap(),
        allowed_controller_device_ids: vec![device_id.clone()],
    };
    let app = router(store, "https://rusty.example".into(), Some(trusted), vec![]).unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin = format!("http://{}", listener.local_addr().unwrap());
    let server = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    let response = reqwest::Client::new()
        .post(format!("{origin}/v2/enrollment/challenge"))
        .header("content-type", "application/json")
        .body(
            json!({
                "version": 1,
                "scopeId": "opaque-scope",
                "identity": identity,
                "deviceId": device_id,
                "certificates": [certificate]
            })
            .to_string(),
        )
        .send()
        .await
        .unwrap();
    assert_eq!(
        response.status(),
        StatusCode::OK,
        "owner device connects without a global operator secret"
    );
    let body: Value = serde_json::from_slice(&response.bytes().await.unwrap()).unwrap();
    assert_eq!(
        body["challenge"]["payload"]["kind"],
        "rusty-enrollment-challenge"
    );
    assert_eq!(
        body["challenge"]["payload"]["expiresAt"].as_u64().unwrap()
            - body["challenge"]["payload"]["issuedAt"].as_u64().unwrap(),
        120_000
    );
    server.abort();
    let _ = server.await;
    fs::remove_dir_all(directory).unwrap();
}

#[tokio::test]
async fn parallel_equivalent_scope_enrollments_confirm_without_rewriting_policy() {
    let directory =
        std::env::temp_dir().join(format!("rusty-parallel-enroll-{}", rand::random::<u64>()));
    let store = BlindStore::open(directory.clone()).unwrap();
    let service_key = store.public_key().unwrap();
    let (identity, device_id, certificate, _) = owner_controller_fixture();
    let trusted = TrustedOwner {
        identity: serde_json::from_value(identity.clone()).unwrap(),
        allowed_controller_device_ids: vec![device_id.clone()],
    };
    let read_token = "r".repeat(43);
    let write_token = "w".repeat(43);
    store
        .approve(
            "opaque-scope",
            ScopeApproval {
                expected_revision: 0,
                read_token: read_token.clone(),
                write_token: write_token.clone(),
                revoked: false,
            },
        )
        .unwrap();
    let app = router(
        store.clone(),
        "https://rusty.example".into(),
        Some(trusted),
        vec![],
    )
    .unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin = format!("http://{}", listener.local_addr().unwrap());
    let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    let client = reqwest::Client::new();
    let mut challenges = Vec::new();
    for _ in 0..2 {
        let response = client
            .post(format!("{origin}/v2/enrollment/challenge"))
            .json(
                &json!({ "version": 1, "scopeId": "opaque-scope", "identity": identity,
                "deviceId": device_id, "certificates": [certificate] }),
            )
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body: Value = response.json().await.unwrap();
        assert_eq!(body["challenge"]["payload"]["expectedRevision"], 1);
        challenges.push(body["challenge"].clone());
    }
    let request = |challenge: Value, read: &str, write: &str, revoked: bool, floor| {
        signed_scope_request_with_minimum_writer_version(
            challenge,
            identity.clone(),
            &device_id,
            certificate.clone(),
            read,
            write,
            revoked,
            floor,
        )
    };
    let first = request(
        challenges[0].clone(),
        &read_token,
        &write_token,
        false,
        Some(2),
    );
    let second = request(
        challenges[1].clone(),
        &read_token,
        &write_token,
        false,
        Some(2),
    );
    let response = client
        .put(format!("{origin}/v2/scopes/opaque-scope"))
        .json(&first)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let first: Value = response.json().await.unwrap();
    assert_eq!(first["receipt"]["payload"]["revision"], 2);
    let policy_path = directory.join("scopes/opaque-scope/policy.json");
    let original_policy = fs::read(&policy_path).unwrap();
    for _ in 0..2 {
        let response = client
            .put(format!("{origin}/v2/scopes/opaque-scope"))
            .json(&second)
            .send()
            .await
            .unwrap();
        assert_eq!(
            response.status(),
            StatusCode::OK,
            "equivalent concurrent intent confirms current policy"
        );
        let body: Value = response.json().await.unwrap();
        let receipt: SignedEnvelope<Value> =
            serde_json::from_value(body["receipt"].clone()).unwrap();
        assert!(verify_signed_envelope(&receipt, &service_key, DOMAIN).unwrap());
        assert_eq!(receipt.payload["revision"], 2);
        assert_eq!(receipt.payload["minimumWriterVersion"], 2);
        assert_eq!(
            receipt.payload["challengeId"],
            second["challenge"]["payload"]["challengeId"]
        );
        assert_eq!(
            receipt.payload["authorizationHash"],
            digest(
                canonicalize_json(&second["authorization"])
                    .unwrap()
                    .as_bytes()
            )
        );
        assert_ne!(body["receipt"], first["receipt"]);
        assert_eq!(
            fs::read(&policy_path).unwrap(),
            original_policy,
            "confirmation must not rewrite durable policy"
        );
    }
    for conflicting in [
        request(
            challenges[1].clone(),
            &"x".repeat(43),
            &write_token,
            false,
            Some(2),
        ),
        request(
            challenges[1].clone(),
            &read_token,
            &"x".repeat(43),
            false,
            Some(2),
        ),
        request(
            challenges[1].clone(),
            &read_token,
            &write_token,
            true,
            Some(2),
        ),
        request(
            challenges[1].clone(),
            &read_token,
            &write_token,
            false,
            Some(1),
        ),
        request(
            challenges[1].clone(),
            &read_token,
            &write_token,
            false,
            None,
        ),
    ] {
        let response = client
            .put(format!("{origin}/v2/scopes/opaque-scope"))
            .json(&conflicting)
            .send()
            .await
            .unwrap();
        assert_eq!(
            response.status(),
            StatusCode::CONFLICT,
            "different desired policy must retain CAS conflict"
        );
        assert_eq!(fs::read(&policy_path).unwrap(), original_policy);
    }
    let response = client
        .post(format!("{origin}/v2/enrollment/challenge"))
        .json(
            &json!({ "version": 1, "scopeId": "opaque-scope", "identity": identity,
            "deviceId": device_id, "certificates": [certificate] }),
        )
        .send()
        .await
        .unwrap();
    let fresh: Value = response.json().await.unwrap();
    // Legacy unspecified-floor requests retain +1 semantics. Keep the target
    // identical so the following rejection isolates an older revision, not a token mismatch.
    let advanced = request(
        fresh["challenge"].clone(),
        &read_token,
        &write_token,
        false,
        None,
    );
    let response = client
        .put(format!("{origin}/v2/scopes/opaque-scope"))
        .json(&advanced)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let response = client
        .put(format!("{origin}/v2/scopes/opaque-scope"))
        .json(&second)
        .send()
        .await
        .unwrap();
    assert_eq!(
        response.status(),
        StatusCode::CONFLICT,
        "older generations cannot bypass policy CAS"
    );
    server.abort();
    let _ = server.await;
    fs::remove_dir_all(directory).unwrap();
}

// Given two authorized owner devices observe the same floor at different times,
// confirming floor 2 must not create concurrent client revisions for identical credentials.
#[tokio::test]
async fn fresh_equivalent_floor_two_enrollments_keep_current_policy_revision() {
    use meta_mesh_core::{DeviceCertificatePayload, sign_device_certificate};
    let directory =
        std::env::temp_dir().join(format!("rusty-current-floor-{}", rand::random::<u64>()));
    let store = BlindStore::open(directory.clone()).unwrap();
    let service_key = store.public_key().unwrap();
    let (identity, desktop_id, desktop_certificate, person_id) = owner_controller_fixture();
    let phone_key = public_key_from_seed(&[33; 32]).unwrap();
    let phone_id = public_key_id(&phone_key).unwrap();
    let phone_certificate = serde_json::to_value(
        sign_device_certificate(
            &[31; 32],
            DeviceCertificatePayload {
                kind: "device-certificate".into(),
                version: 1,
                person_id: person_id.clone(),
                device_id: phone_id.clone(),
                device_public_key: phone_key,
                issuer_certificate_hash: None,
                can_enroll_devices: true,
            },
            &person_id,
            "MATCH/1",
        )
        .unwrap(),
    )
    .unwrap();
    let trusted = TrustedOwner {
        identity: serde_json::from_value(identity.clone()).unwrap(),
        allowed_controller_device_ids: vec![desktop_id.clone(), phone_id.clone()],
    };
    let read_token = "r".repeat(43);
    let write_token = "w".repeat(43);
    store
        .approve(
            "opaque-scope",
            ScopeApproval {
                expected_revision: 0,
                read_token: read_token.clone(),
                write_token: write_token.clone(),
                revoked: false,
            },
        )
        .unwrap();
    let app = router(
        store.clone(),
        "https://rusty.example".into(),
        Some(trusted),
        vec![],
    )
    .unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin = format!("http://{}", listener.local_addr().unwrap());
    let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    let client = reqwest::Client::new();
    let policy_path = directory.join("scopes/opaque-scope/policy.json");
    let mut first_request = None;
    let mut first_receipt = None;
    let mut confirmed_policy = None;
    let mut no_op_request = None;
    for (seed, device_id, certificate, expected_revision) in [
        (32, desktop_id, desktop_certificate, 1),
        (33, phone_id, phone_certificate, 2),
    ] {
        let response = client
            .post(format!("{origin}/v2/enrollment/challenge"))
            .json(
                &json!({ "version": 1, "scopeId": "opaque-scope", "identity": identity,
                "deviceId": device_id, "certificates": [certificate] }),
            )
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let challenge: Value = response.json().await.unwrap();
        assert_eq!(
            challenge["challenge"]["payload"]["expectedRevision"],
            expected_revision
        );
        let mut request = signed_scope_request_with_minimum_writer_version(
            challenge["challenge"].clone(),
            identity.clone(),
            &device_id,
            certificate,
            &read_token,
            &write_token,
            false,
            Some(2),
        );
        request["authorization"] = serde_json::to_value(
            sign_json_envelope(
                &[seed; 32],
                request["authorization"]["payload"].clone(),
                &device_id,
                "MATCH/1",
            )
            .unwrap(),
        )
        .unwrap();
        for _ in 0..2 {
            let response = client
                .put(format!("{origin}/v2/scopes/opaque-scope"))
                .json(&request)
                .send()
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::OK);
            let body: Value = response.json().await.unwrap();
            let receipt: SignedEnvelope<Value> =
                serde_json::from_value(body["receipt"].clone()).unwrap();
            assert!(verify_signed_envelope(&receipt, &service_key, DOMAIN).unwrap());
            assert_eq!(
                receipt.payload["revision"], 2,
                "fresh equivalent floor confirmation must not advance policy"
            );
            assert_eq!(receipt.payload["minimumWriterVersion"], 2);
            assert_eq!(receipt.payload["personId"], person_id);
            assert_eq!(
                receipt.payload["challengeId"],
                request["challenge"]["payload"]["challengeId"]
            );
            assert_eq!(
                receipt.payload["authorizationHash"],
                digest(
                    canonicalize_json(&request["authorization"])
                        .unwrap()
                        .as_bytes()
                )
            );
            if let Some(original) = &confirmed_policy {
                assert_eq!(&fs::read(&policy_path).unwrap(), original);
            } else {
                confirmed_policy = Some(fs::read(&policy_path).unwrap());
            }
            if first_receipt.is_none() {
                first_receipt = Some(body["receipt"].clone());
            }
        }
        if first_request.is_none() {
            first_request = Some(request);
        } else {
            no_op_request = Some(request);
        }
    }
    let replay = client
        .put(format!("{origin}/v2/scopes/opaque-scope"))
        .json(first_request.as_ref().unwrap())
        .send()
        .await
        .unwrap();
    assert_eq!(replay.status(), StatusCode::OK);
    assert_eq!(
        replay.json::<Value>().await.unwrap()["receipt"],
        first_receipt.unwrap(),
        "no-op preserves original completed receipt"
    );
    assert_eq!(fs::read(&policy_path).unwrap(), confirmed_policy.unwrap());
    let no_op_request = no_op_request.unwrap();
    let challenge_path = directory.join("enrollment").join(format!(
        "{}.json",
        no_op_request["challenge"]["payload"]["challengeId"]
            .as_str()
            .unwrap()
    ));
    let mut pending: Value = serde_json::from_slice(&fs::read(&challenge_path).unwrap()).unwrap();
    pending["expiresAt"] = json!(0);
    fs::write(&challenge_path, serde_json::to_vec(&pending).unwrap()).unwrap();
    let expired = client
        .put(format!("{origin}/v2/scopes/opaque-scope"))
        .json(&no_op_request)
        .send()
        .await
        .unwrap();
    assert_ne!(
        expired.status(),
        StatusCode::OK,
        "fresh no-op never bypasses challenge expiry"
    );
    let original = first_request.unwrap();
    for (floor, read, write, revoked, next_revision) in [
        (Some(1), read_token.clone(), write_token.clone(), false, 3),
        (None, read_token.clone(), write_token.clone(), false, 4),
        (Some(2), "x".repeat(43), write_token.clone(), false, 5),
        (Some(2), "x".repeat(43), "y".repeat(43), false, 6),
        (Some(2), "x".repeat(43), "y".repeat(43), true, 7),
    ] {
        let device_id = original["deviceId"].as_str().unwrap();
        let certificate = original["certificates"][0].clone();
        let response = client
            .post(format!("{origin}/v2/enrollment/challenge"))
            .json(
                &json!({ "version": 1, "scopeId": "opaque-scope", "identity": identity,
                "deviceId": device_id, "certificates": [certificate] }),
            )
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let challenge: Value = response.json().await.unwrap();
        let request = signed_scope_request_with_minimum_writer_version(
            challenge["challenge"].clone(),
            identity.clone(),
            device_id,
            certificate,
            &read,
            &write,
            revoked,
            floor,
        );
        let response = client
            .put(format!("{origin}/v2/scopes/opaque-scope"))
            .json(&request)
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body: Value = response.json().await.unwrap();
        assert_eq!(
            body["receipt"]["payload"]["revision"], next_revision,
            "legacy requests and real target changes retain increment semantics"
        );
        assert_eq!(body["receipt"]["payload"]["minimumWriterVersion"], 2);
        assert_eq!(body["receipt"]["payload"]["revoked"], revoked);
        assert_eq!(
            store.policy("opaque-scope").unwrap().read_mac,
            store.token_mac("opaque-scope", &read).unwrap()
        );
        assert_eq!(
            store.policy("opaque-scope").unwrap().write_mac,
            store.token_mac("opaque-scope", &write).unwrap()
        );
    }
    server.abort();
    let _ = server.await;
    fs::remove_dir_all(directory).unwrap();
}

#[tokio::test]
async fn signed_scope_enrollment_retries_exactly_without_reauthorizing_consumed_challenges() {
    let directory = std::env::temp_dir().join(format!("rusty-enroll-{}", rand::random::<u64>()));
    let store = BlindStore::open(directory.clone()).unwrap();
    let service_key = store.public_key().unwrap();
    let (identity, device_id, certificate, owner_id) = owner_controller_fixture();
    let trusted = TrustedOwner {
        identity: serde_json::from_value(identity.clone()).unwrap(),
        allowed_controller_device_ids: vec![device_id.clone()],
    };
    let app = router(
        store.clone(),
        "https://rusty.example".into(),
        Some(trusted.clone()),
        vec![],
    )
    .unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin = format!("http://{}", listener.local_addr().unwrap());
    let server = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    let client = reqwest::Client::new();
    let challenge_response = client.post(format!("{origin}/v2/enrollment/challenge"))
        .header("content-type", "application/json")
        .body(json!({"version":1,"scopeId":"opaque-scope","identity":identity,"deviceId":device_id,"certificates":[certificate]}).to_string())
        .send().await.unwrap();
    assert_eq!(challenge_response.status(), StatusCode::OK);
    let body: Value = serde_json::from_slice(&challenge_response.bytes().await.unwrap()).unwrap();
    let challenge = body["challenge"].clone();
    let challenge_envelope: SignedEnvelope<Value> =
        serde_json::from_value(challenge.clone()).unwrap();
    assert!(verify_signed_envelope(&challenge_envelope, &service_key, DOMAIN).unwrap());
    let request = signed_scope_request(
        challenge.clone(),
        identity.clone(),
        &device_id,
        certificate.clone(),
        &"r".repeat(43),
        &"w".repeat(43),
        false,
    );
    let mut unsafe_request = request.clone();
    unsafe_request["authorization"]["payload"]["contentKey"] = json!("sentinel-content-key");
    let rejected_extra = client
        .put(format!("{origin}/v2/scopes/opaque-scope"))
        .header("content-type", "application/json")
        .body(unsafe_request.to_string())
        .send()
        .await
        .unwrap();
    assert_eq!(
        rejected_extra.status(),
        StatusCode::UNPROCESSABLE_ENTITY,
        "enrollment payload rejects application keys"
    );
    let authorization_hash = digest(
        canonicalize_json(&request["authorization"])
            .unwrap()
            .as_bytes(),
    );
    assert_eq!(request["authorization"].as_object().unwrap().len(), 3);
    let accepted = client
        .put(format!("{origin}/v2/scopes/opaque-scope"))
        .header("content-type", "application/json")
        .body(request.to_string())
        .send()
        .await
        .unwrap();
    assert_eq!(accepted.status(), StatusCode::OK);
    let accepted: Value = serde_json::from_slice(&accepted.bytes().await.unwrap()).unwrap();
    let receipt: SignedEnvelope<Value> =
        serde_json::from_value(accepted["receipt"].clone()).unwrap();
    assert!(verify_signed_envelope(&receipt, &service_key, DOMAIN).unwrap());
    assert_eq!(receipt.payload["personId"], owner_id);
    assert_eq!(receipt.payload["revision"], 1);
    assert_eq!(
        receipt.payload["authorizationHash"], authorization_hash,
        "receipt commits to exact three-field signed envelope expected by the browser"
    );
    let replay = client
        .put(format!("{origin}/v2/scopes/opaque-scope"))
        .header("content-type", "application/json")
        .body(request.to_string())
        .send()
        .await
        .unwrap();
    assert_eq!(
        replay.status(),
        StatusCode::OK,
        "exact retry returns the completed enrollment"
    );
    let replay: Value = serde_json::from_slice(&replay.bytes().await.unwrap()).unwrap();
    assert_eq!(
        replay["receipt"],
        serde_json::to_value(&receipt).unwrap(),
        "retry returns byte-equivalent signed receipt"
    );
    let challenge_id = challenge["payload"]["challengeId"].as_str().unwrap();
    assert!(
        !directory
            .join("enrollment")
            .join(format!("{challenge_id}.json"))
            .exists(),
        "successful approval already deleted the challenge"
    );

    server.abort();
    let _ = server.await;
    drop(store);
    let store = BlindStore::open(directory.clone()).unwrap();
    let app = router(
        store.clone(),
        "https://rusty.example".into(),
        Some(trusted.clone()),
        vec![],
    )
    .unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin = format!("http://{}", listener.local_addr().unwrap());
    let server = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    let restarted = client
        .put(format!("{origin}/v2/scopes/opaque-scope"))
        .header("content-type", "application/json")
        .body(request.to_string())
        .send()
        .await
        .unwrap();
    assert_eq!(
        restarted.status(),
        StatusCode::OK,
        "exact retry survives restart"
    );
    let restarted: Value = serde_json::from_slice(&restarted.bytes().await.unwrap()).unwrap();
    assert_eq!(
        restarted["receipt"],
        serde_json::to_value(&receipt).unwrap()
    );

    let mut substituted_token = request.clone();
    substituted_token["readToken"] = json!("x".repeat(43));
    let token_retry = client
        .put(format!("{origin}/v2/scopes/opaque-scope"))
        .header("content-type", "application/json")
        .body(substituted_token.to_string())
        .send()
        .await
        .unwrap();
    assert!(
        token_retry.status().is_client_error(),
        "token substitution cannot reuse the completed receipt"
    );

    let foreign_key = public_key_from_seed(&[45; 32]).unwrap();
    let mut foreign_identity_retry = request.clone();
    foreign_identity_retry["identity"] = json!({ "personId": public_key_id(&foreign_key).unwrap(),
        "publicKey": foreign_key, "displayName": "Foreign controller" });
    let foreign_retry = client
        .put(format!("{origin}/v2/scopes/opaque-scope"))
        .header("content-type", "application/json")
        .body(foreign_identity_retry.to_string())
        .send()
        .await
        .unwrap();
    assert!(
        foreign_retry.status().is_client_error(),
        "current owner authorization is checked before replay"
    );

    let mut substituted_signature = request.clone();
    let signature = substituted_signature["authorization"]["signature"]
        .as_str()
        .unwrap()
        .to_owned();
    substituted_signature["authorization"]["signature"] = json!(format!(
        "{}{}",
        if signature.starts_with('A') { "B" } else { "A" },
        &signature[1..]
    ));
    let signature_retry = client
        .put(format!("{origin}/v2/scopes/opaque-scope"))
        .header("content-type", "application/json")
        .body(substituted_signature.to_string())
        .send()
        .await
        .unwrap();
    assert!(
        signature_retry.status().is_client_error(),
        "signature substitution cannot reuse the completed receipt"
    );

    let policy_path = directory.join("scopes/opaque-scope/policy.json");
    let original_policy = fs::read(&policy_path).unwrap();
    let mut tampered_policy: Value = serde_json::from_slice(&original_policy).unwrap();
    let completed_receipt = &mut tampered_policy["completedEnrollment"]["receipt"];
    let receipt_signature = completed_receipt["signature"].as_str().unwrap().to_owned();
    completed_receipt["signature"] = json!(format!(
        "{}{}",
        if receipt_signature.starts_with('A') {
            "B"
        } else {
            "A"
        },
        &receipt_signature[1..]
    ));
    fs::write(&policy_path, serde_json::to_vec(&tampered_policy).unwrap()).unwrap();
    let tampered_receipt_retry = client
        .put(format!("{origin}/v2/scopes/opaque-scope"))
        .header("content-type", "application/json")
        .body(request.to_string())
        .send()
        .await
        .unwrap();
    assert!(
        tampered_receipt_retry.status().is_client_error(),
        "tampered durable receipt cannot be replayed"
    );
    fs::write(&policy_path, &original_policy).unwrap();

    let mut stale_policy: Value = serde_json::from_slice(&original_policy).unwrap();
    stale_policy["revision"] = json!(2);
    fs::write(&policy_path, serde_json::to_vec(&stale_policy).unwrap()).unwrap();
    let stale_retry = client
        .put(format!("{origin}/v2/scopes/opaque-scope"))
        .header("content-type", "application/json")
        .body(request.to_string())
        .send()
        .await
        .unwrap();
    assert!(
        stale_retry.status().is_client_error(),
        "superseded policy revision cannot replay the old receipt"
    );
    fs::write(&policy_path, &original_policy).unwrap();

    let fault_challenge: Value = client
        .post(format!("{origin}/v2/enrollment/challenge"))
        .json(
            &json!({"version":1,"scopeId":"fault-scope","identity":identity.clone(),
            "deviceId":device_id.clone(),"certificates":[certificate.clone()]}),
        )
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let fault_request = signed_scope_request(
        fault_challenge["challenge"].clone(),
        serde_json::from_value(
            json!({"personId":owner_id,"publicKey":public_key_from_seed(&[31;32]).unwrap(),
            "displayName":"Test owner"}),
        )
        .unwrap(),
        &device_id,
        serde_json::from_value(json!(certificate.clone())).unwrap(),
        &"f".repeat(43),
        &"g".repeat(43),
        false,
    );
    let fault_path = directory.join("scopes/fault-scope");
    struct ResetEnrollmentDirectoryFailure;
    impl Drop for ResetEnrollmentDirectoryFailure {
        fn drop(&mut self) {
            FAILED_DIRECTORY_SYNC.with(|failure| *failure.borrow_mut() = None);
        }
    }
    let _reset = ResetEnrollmentDirectoryFailure;
    FAILED_DIRECTORY_SYNC.with(|failure| *failure.borrow_mut() = Some(fault_path));
    let fault_typed: ScopeEnrollmentRequest =
        serde_json::from_value(fault_request.clone()).unwrap();
    let first_failure = match store.approve_signed(
        "fault-scope",
        fault_typed,
        &trusted,
        "https://rusty.example",
    ) {
        Ok(_) => panic!("injected scope directory sync failure must withhold the first response"),
        Err(error) => error,
    };
    assert!(
        first_failure.contains("Durable storage commit failed"),
        "directory-sync fault occurs after policy rename and withholds the first response"
    );
    FAILED_DIRECTORY_SYNC.with(|failure| *failure.borrow_mut() = None);
    let retry_typed: ScopeEnrollmentRequest =
        serde_json::from_value(fault_request.clone()).unwrap();
    let recovered_receipt = store
        .approve_signed(
            "fault-scope",
            retry_typed,
            &trusted,
            "https://rusty.example",
        )
        .unwrap();
    assert!(verify_signed_envelope(&recovered_receipt, &service_key, DOMAIN).unwrap());
    assert_eq!(recovered_receipt.payload["revision"], 1);

    let second = client.post(format!("{origin}/v2/enrollment/challenge"))
        .header("content-type", "application/json")
        .body(json!({"version":1,"scopeId":"opaque-scope","identity":identity,"deviceId":device_id,"certificates":[certificate]}).to_string())
        .send().await.unwrap();
    let second: Value = serde_json::from_slice(&second.bytes().await.unwrap()).unwrap();
    let revoke = client.put(format!("{origin}/v2/scopes/opaque-scope"))
        .header("content-type", "application/json").body(signed_scope_request(
            second["challenge"].clone(),
            serde_json::from_value(json!({"personId":owner_id,"publicKey":public_key_from_seed(&[31;32]).unwrap(),"displayName":"Test owner"})).unwrap(),
            &device_id, certificate, &"r".repeat(43), &"w".repeat(43), true
        ).to_string()).send().await.unwrap();
    assert_eq!(revoke.status(), StatusCode::OK);
    let revoked_replay = client
        .put(format!("{origin}/v2/scopes/opaque-scope"))
        .header("content-type", "application/json")
        .body(request.to_string())
        .send()
        .await
        .unwrap();
    assert!(
        revoked_replay.status().is_client_error(),
        "old enrollment cannot replay after revocation"
    );
    assert!(
        store
            .save(
                "opaque-scope",
                &"w".repeat(43),
                encrypted_fixture(),
                "revoked"
            )
            .is_err()
    );
    server.abort();
    let _ = server.await;
    fs::remove_dir_all(directory).unwrap();
}

#[tokio::test]
async fn enrollment_rejects_foreign_controller_expired_nonce_and_excess_pending_challenges() {
    let directory =
        std::env::temp_dir().join(format!("rusty-enroll-bounds-{}", rand::random::<u64>()));
    let store = BlindStore::open(directory.clone()).unwrap();
    let (identity, device_id, certificate, _owner_id) = owner_controller_fixture();
    let trusted = TrustedOwner {
        identity: serde_json::from_value(identity.clone()).unwrap(),
        allowed_controller_device_ids: vec![device_id.clone()],
    };
    let app = router(
        store.clone(),
        "https://rusty.example".into(),
        Some(trusted),
        vec![],
    )
    .unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin = format!("http://{}", listener.local_addr().unwrap());
    let server = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    let client = reqwest::Client::new();
    let challenge_body = |identity: Value| {
        json!({
            "version":1,"scopeId":"bounded-scope","identity":identity,
            "deviceId":device_id,"certificates":[certificate]
        })
    };
    let foreign_public_key = public_key_from_seed(&[45; 32]).unwrap();
    let foreign_identity = json!({
        "personId": public_key_id(&foreign_public_key).unwrap(),
        "publicKey": foreign_public_key,
        "displayName": "Foreign controller"
    });
    let foreign = client
        .post(format!("{origin}/v2/enrollment/challenge"))
        .header("content-type", "application/json")
        .body(challenge_body(foreign_identity).to_string())
        .send()
        .await
        .unwrap();
    assert_eq!(foreign.status(), StatusCode::FORBIDDEN);

    let mut last_challenge = Value::Null;
    for _ in 0..MAX_PENDING_CHALLENGES_PER_SCOPE {
        let response = client
            .post(format!("{origin}/v2/enrollment/challenge"))
            .header("content-type", "application/json")
            .body(challenge_body(identity.clone()).to_string())
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        last_challenge = serde_json::from_slice::<Value>(&response.bytes().await.unwrap()).unwrap()
            ["challenge"]
            .clone();
    }
    let over_limit = client
        .post(format!("{origin}/v2/enrollment/challenge"))
        .header("content-type", "application/json")
        .body(challenge_body(identity.clone()).to_string())
        .send()
        .await
        .unwrap();
    assert_eq!(over_limit.status(), StatusCode::TOO_MANY_REQUESTS);

    let id = last_challenge["payload"]["challengeId"].as_str().unwrap();
    let path = directory.join("enrollment").join(format!("{id}.json"));
    let mut pending: PendingChallenge = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    pending.expires_at = now_ms().unwrap() - 1;
    atomic_write(&path, &serde_json::to_vec(&pending).unwrap()).unwrap();
    let expired = client
        .put(format!("{origin}/v2/scopes/bounded-scope"))
        .header("content-type", "application/json")
        .body(
            signed_scope_request(
                last_challenge,
                identity,
                &device_id,
                certificate,
                &"r".repeat(43),
                &"w".repeat(43),
                false,
            )
            .to_string(),
        )
        .send()
        .await
        .unwrap();
    assert_eq!(expired.status(), StatusCode::GONE);
    server.abort();
    let _ = server.await;
    fs::remove_dir_all(directory).unwrap();
}
pub(super) fn approve_fixture(store: &BlindStore) {
    store
        .approve(
            "opaque-scope",
            ScopeApproval {
                expected_revision: 0,
                read_token: "r".repeat(43),
                write_token: "w".repeat(43),
                revoked: false,
            },
        )
        .unwrap();
}

#[test]
fn scope_policy_defaults_pre_writer_version_disks_to_one_and_rejects_unknown_floors() {
    let directory = std::env::temp_dir().join(format!(
        "rusty-writer-policy-disk-{}",
        rand::random::<u64>()
    ));
    let store = BlindStore::open(directory.clone()).unwrap();
    approve_fixture(&store);
    let path = store.scope_dir("opaque-scope").unwrap().join("policy.json");
    let mut old: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    old.as_object_mut().unwrap().remove("minimumWriterVersion");
    atomic_write(&path, &serde_json::to_vec(&old).unwrap()).unwrap();
    assert_eq!(
        store.policy("opaque-scope").unwrap().minimum_writer_version,
        1
    );
    old["minimumWriterVersion"] = json!(3);
    atomic_write(&path, &serde_json::to_vec(&old).unwrap()).unwrap();
    assert_eq!(
        store.policy("opaque-scope").err().as_deref(),
        Some("Invalid scope writer policy")
    );
    drop(store);
    fs::remove_dir_all(directory).unwrap();
}

// Given opaque attachment bytes, when clients retry and Rusty restarts, then
// receipt-bound bytes survive outside the snapshot inventory and its cleanup.
#[tokio::test]
async fn attachment_http_namespace_is_durable_and_independent_of_snapshots() {
    let directory = std::env::temp_dir().join(format!("rusty-blob-http-{}", rand::random::<u64>()));
    let store = BlindStore::open(directory.clone()).unwrap();
    approve_fixture(&store);
    let object = encrypted_fixture();
    let id = object.id().unwrap();
    let key = store.public_key().unwrap();
    let client = reqwest::Client::new();
    let app = router(store.clone(), "https://rusty.example".into(), None, vec![]).unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin = format!("http://{}", listener.local_addr().unwrap());
    let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    let endpoint = format!("{origin}/v2/scopes/opaque-scope/blobs/{id}");

    let policy_required = client
        .put(format!("{endpoint}?writerVersion=2"))
        .bearer_auth("w".repeat(43))
        .header("x-rusty-request-id", "policy-required-blob")
        .json(&object)
        .send()
        .await
        .unwrap();
    assert_eq!(policy_required.status(), StatusCode::CONFLICT);
    assert_eq!(
        policy_required.json::<Value>().await.unwrap()["code"],
        "writer_policy_required"
    );
    set_scope_writer_floor_for_test(&store, "opaque-scope", 2);

    for request_id in ["first-blob-request", "same-blob-retry"] {
        let response = client
            .put(format!("{endpoint}?writerVersion=2"))
            .bearer_auth("w".repeat(43))
            .header("x-rusty-request-id", request_id)
            .json(&object)
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let receipt: SignedEnvelope<Value> = response.json().await.unwrap();
        assert!(verify_signed_envelope(&receipt, &key, DOMAIN).unwrap());
        assert_eq!(receipt.payload["kind"], "blind-blob-storage-receipt");
        assert_eq!(receipt.payload["version"], 1);
        assert_eq!(receipt.payload["objectId"], id);
        assert_eq!(receipt.payload["scopeId"], "opaque-scope");
        assert_eq!(receipt.payload["keyEpoch"], object.key_epoch);
        assert_eq!(receipt.payload["policyRevision"], 1);
        assert_eq!(receipt.payload["requestId"], request_id);
        assert!(receipt.payload.get("sequence").is_none());
    }
    assert!(store.objects("opaque-scope").unwrap().is_empty());
    let snapshot = client
        .get(format!("{origin}/v2/scopes/opaque-scope/objects/{id}"))
        .bearer_auth("r".repeat(43))
        .send()
        .await
        .unwrap();
    assert_ne!(snapshot.status(), StatusCode::OK);
    let denied = client.get(&endpoint).send().await.unwrap();
    assert_eq!(denied.status(), StatusCode::UNAUTHORIZED);
    let read_only = client
        .put(format!("{endpoint}?writerVersion=2"))
        .bearer_auth("r".repeat(43))
        .header("x-rusty-request-id", "reader-write")
        .json(&object)
        .send()
        .await
        .unwrap();
    assert_eq!(read_only.status(), StatusCode::FORBIDDEN);
    server.abort();
    let _ = server.await;
    drop(store);

    let restarted = BlindStore::open(directory.clone()).unwrap();
    assert_eq!(restarted.public_key().unwrap(), key);
    assert!(restarted.objects("opaque-scope").unwrap().is_empty());
    let app = router(
        restarted.clone(),
        "https://rusty.example".into(),
        None,
        vec![],
    )
    .unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin = format!("http://{}", listener.local_addr().unwrap());
    let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    let restored = client
        .get(format!("{origin}/v2/scopes/opaque-scope/blobs/{id}"))
        .bearer_auth("r".repeat(43))
        .send()
        .await
        .unwrap();
    assert_eq!(restored.status(), StatusCode::OK);
    assert_eq!(restored.json::<BlindObject>().await.unwrap(), object);
    let stored =
        fs::read_to_string(directory.join(format!("scopes/opaque-scope/blobs/{id}.json"))).unwrap();
    assert!(!stored.contains(&"r".repeat(43)));
    assert!(!stored.contains(&"w".repeat(43)));
    assert!(!stored.contains("contentKey"));
    server.abort();
    let _ = server.await;
    drop(restarted);
    fs::remove_dir_all(directory).unwrap();
}
#[test]
fn opaque_replication_survives_restart_and_retry_without_plaintext_or_tokens() {
    let directory = std::env::temp_dir().join(format!("rusty-restart-{}", rand::random::<u64>()));
    let store = BlindStore::open(directory.clone()).unwrap();
    approve_fixture(&store);
    let fixture = encrypted_fixture();
    let first = store
        .save(
            "opaque-scope",
            &"w".repeat(43),
            fixture.clone(),
            "first-request",
        )
        .unwrap();
    let public_key = store.public_key().unwrap();
    assert!(meta_mesh_core::verify_signed_envelope(&first, &public_key, DOMAIN).unwrap());
    assert!(
        BlindStore::open(directory.clone()).is_err(),
        "Concurrent writers must be excluded"
    );
    drop(store);
    let restarted = BlindStore::open(directory.clone()).unwrap();
    assert_eq!(restarted.public_key().unwrap(), public_key);
    let retried = restarted
        .save(
            "opaque-scope",
            &"w".repeat(43),
            fixture.clone(),
            "retry-request",
        )
        .unwrap();
    assert_eq!(first.payload["objectId"], retried.payload["objectId"]);
    assert_eq!(first.payload["sequence"], retried.payload["sequence"]);
    assert_eq!(retried.payload["requestId"], "retry-request");
    assert_eq!(restarted.objects("opaque-scope").unwrap().len(), 1);
    let disk = fs::read_to_string(directory.join("scopes/opaque-scope/policy.json")).unwrap();
    assert!(!disk.contains(&"w".repeat(43)));
    assert!(!disk.contains(&"r".repeat(43)));
    assert!(!disk.contains("contentKey"));
    assert!(
        restarted
            .save(
                "opaque-scope",
                &"r".repeat(43),
                fixture.clone(),
                "read-only-upload"
            )
            .is_err()
    );
    assert!(
        restarted
            .save(
                "another-scope",
                &"w".repeat(43),
                fixture.clone(),
                "wrong-scope"
            )
            .is_err()
    );
    restarted
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
    assert!(
        restarted
            .save("opaque-scope", &"w".repeat(43), fixture, "revoked-upload")
            .is_err()
    );
    fs::remove_dir_all(directory).unwrap();
}

#[tokio::test]
async fn two_http_clients_replicate_ciphertext_and_plaintext_intake_is_absent() {
    let directory = std::env::temp_dir().join(format!("rusty-http-{}", rand::random::<u64>()));
    let store = BlindStore::open(directory.clone()).unwrap();
    approve_fixture(&store);
    let app = router(store.clone(), "https://rusty.example".into(), None, vec![]).unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin = format!("http://{}", listener.local_addr().unwrap());
    let server = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    let client_a = reqwest::Client::new();
    let client_b = reqwest::Client::new();
    let fixture = encrypted_fixture();
    let id = fixture.id().unwrap();
    let upload = client_a
        .put(format!("{origin}/v2/scopes/opaque-scope/objects/{id}"))
        .bearer_auth("w".repeat(43))
        .header("x-rusty-request-id", "client-a-request")
        .header("content-type", "application/json")
        .body(serde_json::to_vec(&fixture).unwrap())
        .send()
        .await
        .unwrap();
    assert_eq!(upload.status(), StatusCode::OK);
    let receipt: SignedEnvelope<Value> =
        serde_json::from_slice(&upload.bytes().await.unwrap()).unwrap();
    assert!(
        meta_mesh_core::verify_signed_envelope(&receipt, &store.public_key().unwrap(), DOMAIN)
            .unwrap()
    );
    let download = client_b
        .get(format!("{origin}/v2/scopes/opaque-scope/objects/{id}"))
        .bearer_auth("r".repeat(43))
        .send()
        .await
        .unwrap();
    assert_eq!(download.status(), StatusCode::OK);
    assert_eq!(
        serde_json::from_slice::<BlindObject>(&download.bytes().await.unwrap()).unwrap(),
        fixture
    );
    let denied = client_b
        .get(format!("{origin}/v2/scopes/opaque-scope/objects/{id}"))
        .send()
        .await
        .unwrap();
    assert_eq!(denied.status(), StatusCode::UNAUTHORIZED);
    for path in ["/ingest", "/challenge", "/v1/pairings", "/admin/"] {
        assert_eq!(
            client_a
                .get(format!("{origin}{path}"))
                .send()
                .await
                .unwrap()
                .status(),
            StatusCode::NOT_FOUND
        );
    }
    let wrong_hash = client_a
        .put(format!("{origin}/v2/scopes/opaque-scope/objects/wrong-id"))
        .bearer_auth("w".repeat(43))
        .header("x-rusty-request-id", "wrong-hash")
        .header("content-type", "application/json")
        .body(serde_json::to_vec(&fixture).unwrap())
        .send()
        .await
        .unwrap();
    assert_eq!(wrong_hash.status(), StatusCode::BAD_REQUEST);
    server.abort();
    let _ = server.await;
    fs::remove_dir_all(directory).unwrap();
}

#[tokio::test]
async fn anonymous_public_board_route_serves_a_confirmed_projection() {
    use meta_mesh_core::sign_json_envelope;
    let directory =
        std::env::temp_dir().join(format!("rusty-public-board-{}", rand::random::<u64>()));
    let store = BlindStore::open(directory.clone()).unwrap();
    let (identity, device_id, certificate, _) = owner_controller_fixture();
    let trusted = TrustedOwner {
        identity: serde_json::from_value(identity.clone()).unwrap(),
        allowed_controller_device_ids: vec![device_id.clone()],
    };
    let app = router(
        store.clone(),
        "https://rusty.example".into(),
        Some(trusted),
        vec![],
    )
    .unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin = format!("http://{}", listener.local_addr().unwrap());
    let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    let client = reqwest::Client::new();
    let board = "public-board-fixture";
    let projection = json!({
        "kind":"tincanban-public-board", "version":1,
        "board":{"id":board,"title":"Confirmed public board"},
        "columns":[],"fields":[],"cards":[],"discussions":[],"files":[]
    });
    let challenge_request = json!({"version":1,"boardId":board,"identity":identity,"deviceId":device_id,"certificates":[certificate]});
    let challenge_response = send_public_json(
        client.post(format!("{origin}/v1/public/challenges")),
        challenge_request,
    )
    .await;
    assert_eq!(challenge_response.status(), StatusCode::OK);
    let challenge: Value =
        serde_json::from_slice(&challenge_response.bytes().await.unwrap()).unwrap();
    let challenge = challenge["challenge"].clone();
    let payload = &challenge["payload"];
    let projection_hash = digest(canonicalize_json(&projection).unwrap().as_bytes());
    let authorization = sign_json_envelope(&[32; 32], json!({
        "kind":"rusty-publication-command","version":1,"challengeId":payload["challengeId"],"nonce":payload["nonce"],
        "serviceId":payload["serviceId"],"publicOrigin":"https://rusty.example","boardId":board,"action":"publish",
        "projectionHash":projection_hash,"expectedRevision":0,"expiresAt":payload["expiresAt"]
    }), &device_id, "MATCH/1").unwrap();
    let publication = json!({"challenge":challenge,"identity":identity,"deviceId":device_id,"certificates":[certificate],"action":"publish","projection":projection,"authorization":authorization});
    let published = send_public_json(
        client.put(format!("{origin}/v1/public/boards/{board}")),
        publication,
    )
    .await;
    assert_eq!(
        published.status(),
        StatusCode::OK,
        "{}",
        published.text().await.unwrap_or_default()
    );
    let response = client
        .get(format!("{origin}/v1/public/boards/{board}"))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let value: Value = serde_json::from_slice(&response.bytes().await.unwrap()).unwrap();
    assert_eq!(value["projection"]["board"]["id"], board);
    assert_eq!(
        value["projection"]["board"]["title"],
        "Confirmed public board"
    );
    server.abort();
    let _ = server.await;
    drop(store);
    fs::remove_dir_all(directory).unwrap();
}

#[test]
fn legacy_plaintext_state_cannot_be_started_as_blind() {
    let directory = std::env::temp_dir().join(format!("rusty-legacy-{}", rand::random::<u64>()));
    fs::create_dir_all(&directory).unwrap();
    fs::write(directory.join("config.json"), b"{}").unwrap();
    assert!(BlindStore::open(directory.clone()).is_err());
    fs::remove_dir_all(directory).unwrap();
}

#[test]
fn legacy_http_inbox_cannot_be_mistaken_for_blind_storage() {
    let directory = std::env::temp_dir().join(format!("rusty-old-inbox-{}", rand::random::<u64>()));
    fs::create_dir_all(directory.join("inbox")).unwrap();
    fs::write(directory.join("inbox/private.json"), b"private message").unwrap();
    assert!(BlindStore::open(directory.clone()).is_err());
    assert_eq!(
        fs::read(directory.join("inbox/private.json")).unwrap(),
        b"private message"
    );
    fs::remove_dir_all(directory).unwrap();
}

#[test]
fn failed_durable_commit_cannot_issue_a_receipt_and_retry_can_recover() {
    let directory =
        std::env::temp_dir().join(format!("rusty-failed-save-{}", rand::random::<u64>()));
    let store = BlindStore::open(directory.clone()).unwrap();
    approve_fixture(&store);
    let fixture = encrypted_fixture();
    let path = directory
        .join("scopes/opaque-scope/objects")
        .join(format!("{}.json", fixture.id().unwrap()));
    fs::create_dir(&path).unwrap();
    assert!(
        store
            .save(
                "opaque-scope",
                &"w".repeat(43),
                fixture.clone(),
                "failed-request"
            )
            .is_err()
    );
    fs::remove_dir(&path).unwrap();
    let recovered = store
        .save(
            "opaque-scope",
            &"w".repeat(43),
            fixture,
            "recovered-request",
        )
        .unwrap();
    assert_eq!(recovered.payload["sequence"], 1);
    assert_eq!(recovered.payload["requestId"], "recovered-request");
    fs::remove_dir_all(directory).unwrap();
}

#[test]
fn visible_object_retry_requires_directory_durability_before_receipt() {
    struct ClearFailure;
    impl Drop for ClearFailure {
        fn drop(&mut self) {
            FAILED_DIRECTORY_SYNC.with(|failure| *failure.borrow_mut() = None);
        }
    }
    let directory =
        std::env::temp_dir().join(format!("rusty-rename-failure-{}", rand::random::<u64>()));
    let store = BlindStore::open(directory.clone()).unwrap();
    approve_fixture(&store);
    let object = encrypted_fixture();
    let objects = directory.join("scopes/opaque-scope/objects");
    let path = objects.join(format!("{}.json", object.id().unwrap()));
    let _reset = ClearFailure;
    FAILED_DIRECTORY_SYNC.with(|failure| *failure.borrow_mut() = Some(objects));
    assert!(
        store
            .save(
                "opaque-scope",
                &"w".repeat(43),
                object.clone(),
                "failed-rename"
            )
            .is_err()
    );
    assert!(
        path.is_file(),
        "Rename happened before the directory sync failed"
    );
    let bytes = fs::read(&path).unwrap();
    let modified = path.metadata().unwrap().modified().unwrap();
    assert!(
        store
            .save(
                "opaque-scope",
                &"w".repeat(43),
                object.clone(),
                "failed-retry"
            )
            .is_err(),
        "Visible bytes must not produce a durable receipt while directory sync still fails"
    );
    FAILED_DIRECTORY_SYNC.with(|failure| *failure.borrow_mut() = None);
    let receipt = store
        .save("opaque-scope", &"w".repeat(43), object, "durable-retry")
        .unwrap();
    assert_eq!(receipt.payload["sequence"], 1);
    assert_eq!(fs::read(&path).unwrap(), bytes);
    assert_eq!(path.metadata().unwrap().modified().unwrap(), modified);
    assert_eq!(store.objects("opaque-scope").unwrap().len(), 1);
    fs::remove_dir_all(directory).unwrap();
}

// Given staged selected-board bytes and an authenticated publication controller,
// when Rusty activates then restarts then withdraws a snapshot, anonymous readers
// receive exact content only while its revision remains active.
#[tokio::test]
async fn public_assets_and_discussions_survive_restart_and_withdrawal() {
    use meta_mesh_core::sign_json_envelope;
    let directory =
        std::env::temp_dir().join(format!("rusty-public-assets-{}", rand::random::<u64>()));
    let store = BlindStore::open(directory.clone()).unwrap();
    let (identity, device_id, certificate, _) = owner_controller_fixture();
    let trusted = TrustedOwner {
        identity: serde_json::from_value(identity.clone()).unwrap(),
        allowed_controller_device_ids: vec![device_id.clone()],
    };
    let app = router(
        store.clone(),
        "https://rusty.example".into(),
        Some(trusted.clone()),
        vec![],
    )
    .unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin = format!("http://{}", listener.local_addr().unwrap());
    let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    let client = reqwest::Client::new();
    let certificates = vec![certificate];
    let board = "public-board-fixture";
    let bytes = b"independent public attachment";
    let sha256 = digest(bytes);
    let projection = json!({
        "kind":"tincanban-public-board", "version":1,
        "board":{"id":board,"title":"Public board"},
        "columns":[],"fields":[],"cards":[],
        "discussions":[{"id":"opaque-thread","threadId":"opaque-thread","replyTo":null,"targets":[{"type":"board","id":board}],"author":"Published author","createdAt":"2026-10-10T10:00:00Z","body":"Selected board discussion"}],
        "files":[{"id":"opaque-file","parentId":board,"title":"Handout","fileName":"handout.txt","mediaType":"text/plain","byteLength":bytes.len(),"sha256":sha256}]
    });
    let challenge_request = json!({"version":1,"boardId":board,"identity":identity,"deviceId":device_id,"certificates":certificates});
    let request_challenge = || {
        let client = client.clone();
        let origin = origin.clone();
        let body = challenge_request.clone();
        async move {
            let response =
                send_public_json(client.post(format!("{origin}/v1/public/challenges")), body).await;
            assert_eq!(response.status(), StatusCode::OK);
            serde_json::from_slice::<Value>(&response.bytes().await.unwrap()).unwrap()["challenge"]
                .clone()
        }
    };
    let stage_challenge = request_challenge().await;
    let stage_payload = &stage_challenge["payload"];
    let asset_authorization = sign_json_envelope(&[32; 32], json!({
        "kind":"rusty-publication-command","version":1,"challengeId":stage_payload["challengeId"],"nonce":stage_payload["nonce"],
        "serviceId":stage_payload["serviceId"],"publicOrigin":"https://rusty.example","boardId":board,"action":"stage-file",
        "projectionHash":sha256,"expectedRevision":stage_payload["expectedRevision"],"expiresAt":stage_payload["expiresAt"],"byteLength":bytes.len()
    }), &device_id, "MATCH/1").unwrap();
    let staged_body = json!({
        "challenge":stage_challenge,"identity":identity,"deviceId":device_id,"certificates":certificates,
        "sha256":sha256,"byteLength":bytes.len(),"bytes":URL_SAFE_NO_PAD.encode(bytes),"authorization":asset_authorization
    });
    let staged = send_public_json(
        client.put(format!("{origin}/v1/public/boards/{board}/files")),
        staged_body,
    )
    .await;
    assert_eq!(staged.status(), StatusCode::OK);
    assert_eq!(
        client
            .get(format!(
                "{origin}/v1/public/boards/{board}/files/1/{sha256}"
            ))
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::NOT_FOUND
    );
    let publish_challenge = request_challenge().await;
    let publish_payload = &publish_challenge["payload"];
    let projection_hash = digest(canonicalize_json(&projection).unwrap().as_bytes());
    let authorization = sign_json_envelope(&[32; 32], json!({
        "kind":"rusty-publication-command","version":1,"challengeId":publish_payload["challengeId"],"nonce":publish_payload["nonce"],
        "serviceId":publish_payload["serviceId"],"publicOrigin":"https://rusty.example","boardId":board,"action":"publish",
        "projectionHash":projection_hash,"expectedRevision":0,"expiresAt":publish_payload["expiresAt"]
    }), &device_id, "MATCH/1").unwrap();
    let publish_body = json!({
        "challenge":publish_challenge,"identity":identity,"deviceId":device_id,"certificates":certificates,"action":"publish","projection":projection,"authorization":authorization
    });
    let published = send_public_json(
        client.put(format!("{origin}/v1/public/boards/{board}")),
        publish_body,
    )
    .await;
    assert_eq!(
        published.status(),
        StatusCode::OK,
        "{}",
        published.text().await.unwrap_or_default()
    );
    let body: Value = serde_json::from_slice(
        &client
            .get(format!("{origin}/v1/public/boards/{board}"))
            .send()
            .await
            .unwrap()
            .bytes()
            .await
            .unwrap(),
    )
    .unwrap();
    assert_eq!(
        body["projection"]["discussions"][0]["body"],
        "Selected board discussion"
    );
    assert_eq!(body["revision"], 1);
    server.abort();
    let _ = server.await;
    drop(store);

    let restarted = BlindStore::open(directory.clone()).unwrap();
    let app = router(
        restarted.clone(),
        "https://rusty.example".into(),
        Some(trusted),
        vec![],
    )
    .unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin = format!("http://{}", listener.local_addr().unwrap());
    let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    let download = client
        .get(format!(
            "{origin}/v1/public/boards/{board}/files/1/{sha256}"
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(download.status(), StatusCode::OK);
    assert_eq!(download.headers()["x-content-type-options"], "nosniff");
    assert!(
        download.headers()["content-disposition"]
            .to_str()
            .unwrap()
            .starts_with("attachment;")
    );
    assert_eq!(download.bytes().await.unwrap().as_ref(), bytes);
    let challenge_response = send_public_json(
        client.post(format!("{origin}/v1/public/challenges")),
        challenge_request.clone(),
    )
    .await;
    let challenge_response: Value =
        serde_json::from_slice(&challenge_response.bytes().await.unwrap()).unwrap();
    let challenge = challenge_response["challenge"].clone();
    let payload = &challenge["payload"];
    let authorization = sign_json_envelope(&[32; 32], json!({
        "kind":"rusty-publication-command","version":1,"challengeId":payload["challengeId"],"nonce":payload["nonce"],
        "serviceId":payload["serviceId"],"publicOrigin":"https://rusty.example","boardId":board,"action":"unpublish",
        "projectionHash":digest(b"null"),"expectedRevision":1,"expiresAt":payload["expiresAt"]
    }), &device_id, "MATCH/1").unwrap();
    let withdrawal = json!({"challenge":challenge,"identity":identity,"deviceId":device_id,"certificates":certificates,"action":"unpublish","projection":null,"authorization":authorization});
    let withdrawn = send_public_json(
        client.put(format!("{origin}/v1/public/boards/{board}")),
        withdrawal,
    )
    .await;
    assert_eq!(withdrawn.status(), StatusCode::OK);
    assert_eq!(
        client
            .get(format!("{origin}/v1/public/boards/{board}"))
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        client
            .get(format!(
                "{origin}/v1/public/boards/{board}/files/1/{sha256}"
            ))
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::NOT_FOUND
    );
    server.abort();
    let _ = server.await;
    drop(restarted);
    fs::remove_dir_all(directory).unwrap();
}

async fn send_public_json(request: reqwest::RequestBuilder, value: Value) -> reqwest::Response {
    request
        .header("content-type", "application/json")
        .body(serde_json::to_vec(&value).unwrap())
        .send()
        .await
        .unwrap()
}
