use super::*;

// Given durable writes and a duplicate retry, telemetry reports actual disk growth
// and quota refusal, while ciphertext and bearer credentials remain absent.
#[tokio::test]
async fn storage_growth_logs_distinguish_new_objects_retries_and_quota() {
    let received = Arc::new(Mutex::new(Vec::<Value>::new()));
    let records = received.clone();
    let sink = Router::new().route(
        "/events",
        axum::routing::post(move |Json(body): Json<Value>| {
            let records = records.clone();
            async move {
                records
                    .lock()
                    .unwrap()
                    .extend(body["events"].as_array().unwrap().iter().cloned());
                StatusCode::OK
            }
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = format!("http://{}/events", listener.local_addr().unwrap());
    let server = tokio::spawn(async move { axum::serve(listener, sink).await.unwrap() });
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
    tokio::time::timeout(std::time::Duration::from_secs(3), async {
        loop {
            if received
                .lock()
                .unwrap()
                .iter()
                .filter(|event| event["event"] == "http.request.failed")
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
    assert!(
        records
            .iter()
            .any(|record| record["attrs"]["client"] == "tincanban"
                && record["attrs"]["client_build"] == "a".repeat(40))
    );
    assert!(
        records
            .iter()
            .any(|record| record["event"] == "http.request.failed"
                && record["attrs"].get("client").is_none()
                && record["attrs"].get("client_build").is_none())
    );
    assert!(
        !serde_json::to_string(&*records)
            .unwrap()
            .contains("private-must-not-log")
    );
    let stored = records
        .iter()
        .find(|value| value["event"] == "storage.object.stored")
        .unwrap();
    assert_eq!(stored["attrs"]["stored_bytes_before"], 0);
    assert!(stored["attrs"]["stored_bytes"].as_u64().unwrap() > 0);
    assert_eq!(stored["attrs"]["object_count"], 1);
    assert!(
        records
            .iter()
            .any(|value| value["event"] == "storage.object.reused")
    );
    assert!(
        records
            .iter()
            .any(|value| value["event"] == "storage.quota.exceeded")
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
    let response = reqwest::get(format!("{origin}/")).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let html = response.text().await.unwrap();
    assert!(html.contains("Board storage is available"));
    assert!(html.contains("View Rusty logs"));
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
    use meta_mesh_core::sign_json_envelope;
    let payload = &challenge["payload"];
    let authorization = sign_json_envelope(
        &[32; 32],
        json!({
            "kind": "rusty-scope-enrollment", "version": 1,
            "challengeId": payload["challengeId"], "nonce": payload["nonce"],
            "serviceId": payload["serviceId"], "publicOrigin": payload["publicOrigin"],
            "scopeId": payload["scopeId"], "personId": payload["personId"],
            "deviceId": device_id, "deviceKeyId": device_id,
            "expectedRevision": payload["expectedRevision"],
            "readTokenHash": digest(read_token.as_bytes()),
            "writeTokenHash": digest(write_token.as_bytes()),
            "revoked": revoked, "expiresAt": payload["expiresAt"]
        }),
        device_id,
        "MATCH/1",
    )
    .unwrap();
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
async fn signed_scope_enrollment_is_single_use_owner_bound_and_supports_revocation() {
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
        .body(
            signed_scope_request(
                challenge,
                identity.clone(),
                &device_id,
                certificate.clone(),
                &"r".repeat(43),
                &"w".repeat(43),
                false,
            )
            .to_string(),
        )
        .send()
        .await
        .unwrap();
    assert_eq!(
        replay.status(),
        StatusCode::GONE,
        "successful challenge cannot be replayed"
    );

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
