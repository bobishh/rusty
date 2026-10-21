use super::*;
use meta_mesh_core::{DeviceCertificatePayload, sign_device_certificate};

#[path = "person_management_tests.rs"]
mod person_management_tests;

const ORIGIN: &str = "https://rusty.example";
const RESOURCE: &str = "opaque-scope";

fn device(seed: u8, identity: &PublicIdentity) -> (String, DeviceCertificate) {
    let public_key = public_key_from_seed(&[seed; 32]).unwrap();
    let id = public_key_id(&public_key).unwrap();
    let certificate = sign_device_certificate(
        &[31; 32],
        DeviceCertificatePayload {
            kind: "device-certificate".into(),
            version: 1,
            person_id: identity.person_id.clone(),
            device_id: id.clone(),
            device_public_key: public_key,
            issuer_certificate_hash: None,
            can_enroll_devices: true,
        },
        &identity.person_id,
        "MATCH/1",
    )
    .unwrap();
    (id, certificate)
}

struct Fixture {
    directory: PathBuf,
    store: Option<BlindStore>,
    owner: ResourceOwner,
    client: reqwest::Client,
    url: String,
    server: Option<tokio::task::JoinHandle<()>>,
}
impl Fixture {
    async fn new() -> Self {
        let directory =
            std::env::temp_dir().join(format!("rusty-management-{}", rand::random::<u64>()));
        let store = BlindStore::open(directory.clone()).unwrap();
        let (identity, _, _, _) = super::tests::owner_controller_fixture();
        let owner = ResourceOwner {
            identity: serde_json::from_value(identity).unwrap(),
        };
        let mut fixture = Self {
            directory,
            store: Some(store),
            owner,
            client: reqwest::Client::new(),
            url: String::new(),
            server: None,
        };
        fixture.start_server().await;
        fixture
    }
    async fn start_server(&mut self) {
        let app = router(self.store().clone(), ORIGIN.into(), vec![]).unwrap();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        self.url = format!("http://{}", listener.local_addr().unwrap());
        self.server = Some(tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap()
        }));
    }
    async fn stop_server(&mut self) {
        if let Some(server) = self.server.take() {
            server.abort();
            let _ = server.await;
        }
    }
    async fn restart(&mut self) {
        self.stop_server().await;
        self.store.take();
        self.store = Some(BlindStore::open(self.directory.clone()).unwrap());
        self.start_server().await;
    }
    fn update(
        &self,
        revision: u64,
        revoked: Vec<String>,
        capability: Option<Value>,
        seed: u8,
    ) -> Value {
        self.update_resource(
            "scope",
            RESOURCE,
            revision,
            revoked,
            capability,
            seed,
            vec!["management.update", "scope.policy", "snapshot.checkpoint"],
        )
    }
    fn update_resource(
        &self,
        kind: &str,
        id: &str,
        revision: u64,
        revoked: Vec<String>,
        capability: Option<Value>,
        seed: u8,
        operations: Vec<&str>,
    ) -> Value {
        let (device_id, certificate) = device(seed, &self.owner.identity);
        let issued_at = now_ms().unwrap();
        let service_id = public_key_id(&self.store().public_key().unwrap()).unwrap();
        let authorization = sign_json_envelope(&[seed; 32], json!({
            "kind":"rusty-management-policy-update", "version":1, "serviceId":service_id, "origin":ORIGIN,
            "personId":self.owner.identity.person_id, "deviceId":device_id, "resourceKind":kind, "resourceId":id,
            "expectedRevision":revision, "operations":operations,
            "revokedDeviceIds":revoked, "requestId":URL_SAFE_NO_PAD.encode(rand::random::<[u8;32]>()),
            "issuedAt":issued_at, "expiresAt":issued_at+60000,
        }), &device_id, "MATCH/1").unwrap();
        json!({"version":1, "identity":self.owner.identity, "deviceId":device_id, "certificates":[certificate],
            "managementCapability":capability, "authorization":authorization})
    }
    async fn put_resource(&self, kind: &str, id: &str, body: &Value) -> reqwest::Response {
        self.client
            .put(format!("{}/v2/management/{kind}/{id}", self.url))
            .json(body)
            .send()
            .await
            .unwrap()
    }
    fn status_request(&self, certificate_seed: u8, signing_seed: u8) -> Value {
        let (id, certificate) = device(certificate_seed, &self.owner.identity);
        let issued_at = now_ms().unwrap();
        let service_id = public_key_id(&self.store().public_key().unwrap()).unwrap();
        let authorization = sign_json_envelope(&[signing_seed; 32], json!({
            "kind":"rusty-management-policy-status", "version":1, "serviceId":service_id, "origin":ORIGIN,
            "personId":self.owner.identity.person_id, "deviceId":id, "resourceKind":"scope", "resourceId":RESOURCE,
            "requestId":URL_SAFE_NO_PAD.encode(rand::random::<[u8;32]>()),
            "issuedAt":issued_at, "expiresAt":issued_at+60000,
        }), &id, "MATCH/1").unwrap();
        json!({"version":1, "identity":self.owner.identity, "deviceId":id, "certificates":[certificate],
            "authorization":authorization})
    }
    fn status_as(&self, seed: u8) -> reqwest::RequestBuilder {
        self.client
            .post(format!(
                "{}/v2/management/scope/{RESOURCE}/status",
                self.url
            ))
            .json(&self.status_request(seed, seed))
    }
    fn status(&self) -> reqwest::RequestBuilder {
        self.status_as(32)
    }
    fn unsigned_status(&self) -> reqwest::RequestBuilder {
        self.client
            .get(format!("{}/v2/management/scope/{RESOURCE}", self.url))
    }
    fn store(&self) -> &BlindStore {
        self.store.as_ref().unwrap()
    }
    fn resign(&self, body: &mut Value, seed: u8) {
        let payload = body["authorization"]["payload"].clone();
        let device_id = body["deviceId"].as_str().unwrap();
        body["authorization"] = serde_json::to_value(
            sign_json_envelope(&[seed; 32], payload, device_id, "MATCH/1").unwrap(),
        )
        .unwrap();
    }
    async fn put(&self, body: &Value) -> reqwest::Response {
        self.client
            .put(format!("{}/v2/management/scope/{RESOURCE}", self.url))
            .json(body)
            .send()
            .await
            .unwrap()
    }
    async fn challenge(
        &self,
        seed: u8,
        capability: Option<Value>,
        resource: &str,
    ) -> reqwest::Response {
        let (id, certificate) = device(seed, &self.owner.identity);
        self.client
            .post(format!("{}/v2/enrollment/challenge", self.url))
            .json(&json!({
                "version":1, "scopeId":resource, "identity":self.owner.identity, "deviceId":id,
                "certificates":[certificate], "managementCapability":capability,
            }))
            .send()
            .await
            .unwrap()
    }
}

fn unrelated_certificate() -> DeviceCertificate {
    use meta_mesh_core::{public_key_from_seed, public_key_id};
    let person_public_key = public_key_from_seed(&[61; 32]).unwrap();
    let person_id = public_key_id(&person_public_key).unwrap();
    let device_public_key = public_key_from_seed(&[62; 32]).unwrap();
    let device_id = public_key_id(&device_public_key).unwrap();
    sign_device_certificate(
        &[61; 32],
        DeviceCertificatePayload {
            kind: "device-certificate".into(),
            version: 1,
            person_id,
            device_id,
            device_public_key,
            issuer_certificate_hash: None,
            can_enroll_devices: true,
        },
        &public_key_id(&person_public_key).unwrap(),
        "MATCH/1",
    )
    .unwrap()
}

#[tokio::test]
async fn given_signed_private_status_when_replayed_after_restart_then_deny_and_bind_original_receipt_to_exact_request()
 {
    let mut fixture = Fixture::new().await;
    let update = fixture.update(0, vec![], None, 32);
    assert_eq!(fixture.put(&update).await.status(), StatusCode::OK);
    let body = fixture.status_request(33, 33);
    let endpoint = format!("{}/v2/management/scope/{RESOURCE}/status", fixture.url);
    let response = fixture
        .client
        .post(&endpoint)
        .json(&body)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.headers()["cache-control"], "no-store");
    let result: Value = response.json().await.unwrap();
    let receipt: SignedEnvelope<Value> = serde_json::from_value(result["receipt"].clone()).unwrap();
    assert!(
        verify_signed_envelope(&receipt, &fixture.store().public_key().unwrap(), DOMAIN).unwrap()
    );
    assert_eq!(
        receipt.payload["requestId"],
        body["authorization"]["payload"]["requestId"]
    );
    assert_eq!(
        receipt.payload["authorizationHash"],
        digest(
            canonicalize_json(&body["authorization"])
                .unwrap()
                .as_bytes()
        )
    );
    assert_eq!(
        receipt.payload["capabilityHash"],
        digest(canonicalize_json(&result["capability"]).unwrap().as_bytes())
    );
    assert_eq!(
        receipt.payload["revision"],
        result["capability"]["payload"]["revision"]
    );
    fixture.restart().await;
    let replay = fixture
        .client
        .post(format!(
            "{}/v2/management/scope/{RESOURCE}/status",
            fixture.url
        ))
        .json(&body)
        .send()
        .await
        .unwrap();
    assert_eq!(replay.status(), StatusCode::FORBIDDEN);
    assert!(replay.json::<Value>().await.unwrap()["capability"].is_null());
    assert_eq!(
        fixture.status_as(33).send().await.unwrap().status(),
        StatusCode::OK
    );
}
impl Drop for Fixture {
    fn drop(&mut self) {
        if let Some(server) = self.server.take() {
            server.abort();
        }
        let _ = fs::remove_dir_all(&self.directory);
    }
}

#[tokio::test]
async fn given_confirmed_person_capability_when_unrelated_owner_device_connects_then_ancestry_does_not_change_rights()
 {
    let fixture = Fixture::new().await;
    let response = fixture.put(&fixture.update(0, vec![], None, 32)).await;
    assert_eq!(
        response.status(),
        StatusCode::OK,
        "explicit owner migration must be implemented"
    );
    let body: Value = response.json().await.unwrap();
    let capability = body["capability"].clone();
    assert_eq!(capability["payload"]["resourceId"], RESOURCE);
    assert_eq!(
        fixture
            .challenge(32, Some(capability.clone()), RESOURCE)
            .await
            .status(),
        StatusCode::OK
    );
    assert_eq!(
        fixture
            .challenge(33, Some(capability.clone()), RESOURCE)
            .await
            .status(),
        StatusCode::OK,
        "root-issued owner device needs no ancestor from the controller allowlist"
    );
    assert_eq!(
        fixture.challenge(32, None, RESOURCE).await.status(),
        StatusCode::FORBIDDEN,
        "migrated resources must not fall back to legacy controller privileges"
    );
    assert_eq!(
        fixture
            .challenge(33, Some(capability), "different-scope")
            .await
            .status(),
        StatusCode::FORBIDDEN
    );
}

#[tokio::test]
async fn given_policy_revocation_when_old_capability_or_removed_device_retries_then_reject_and_preserve_exact_completed_retry()
 {
    let fixture = Fixture::new().await;
    let first = fixture.put(&fixture.update(0, vec![], None, 32)).await;
    assert_eq!(first.status(), StatusCode::OK);
    let old = first.json::<Value>().await.unwrap()["capability"].clone();
    let removed = device(33, &fixture.owner.identity).0;
    let update = fixture.update(1, vec![removed], Some(old.clone()), 32);
    let next = fixture.put(&update).await;
    assert_eq!(next.status(), StatusCode::OK);
    let confirmed: Value = next.json().await.unwrap();
    assert_eq!(
        fixture.put(&update).await.json::<Value>().await.unwrap(),
        confirmed
    );
    let current = confirmed["capability"].clone();
    assert_eq!(
        fixture
            .challenge(33, Some(current.clone()), RESOURCE)
            .await
            .status(),
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        fixture.challenge(32, Some(old), RESOURCE).await.status(),
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        fixture
            .put(&fixture.update(2, vec![], Some(current), 32))
            .await
            .status(),
        StatusCode::CONFLICT,
        "new policy cannot undo an existing device revocation"
    );
}

#[tokio::test]
async fn given_forged_device_signature_when_bootstrapping_management_then_no_policy_is_created() {
    let fixture = Fixture::new().await;
    let mut request = fixture.update(0, vec![], None, 33);
    request["authorization"]["signature"] = json!(URL_SAFE_NO_PAD.encode([0u8; 64]));
    assert_eq!(fixture.put(&request).await.status(), StatusCode::FORBIDDEN);
    assert!(!fixture.directory.join("management/policy.json").exists());
    let read = fixture.unsigned_status().send().await.unwrap();
    assert!(
        !read.status().is_success(),
        "unsigned status must not disclose management capability"
    );
}

#[tokio::test]
async fn given_existing_policy_when_other_certified_owner_device_reads_status_after_restart_then_authorize()
 {
    let mut fixture = Fixture::new().await;
    let created = fixture.put(&fixture.update(0, vec![], None, 32)).await;
    assert_eq!(created.status(), StatusCode::OK);
    let capability = created.json::<Value>().await.unwrap()["capability"].clone();
    fixture.restart().await;

    let response = fixture.status_as(33).send().await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.json::<Value>().await.unwrap()["capability"],
        capability
    );
}

#[tokio::test]
async fn given_revoked_owner_device_when_reading_management_status_then_deny_without_disclosure() {
    let fixture = Fixture::new().await;
    let created = fixture.put(&fixture.update(0, vec![], None, 32)).await;
    assert_eq!(created.status(), StatusCode::OK);
    let previous = created.json::<Value>().await.unwrap()["capability"].clone();
    let revoked_device_id = device(33, &fixture.owner.identity).0;
    let update = fixture.update(1, vec![revoked_device_id], Some(previous), 32);
    assert_eq!(fixture.put(&update).await.status(), StatusCode::OK);

    let denied = fixture.status_as(33).send().await.unwrap();
    assert_eq!(denied.status(), StatusCode::FORBIDDEN);
    assert!(!denied.text().await.unwrap().contains("capability"));
}

#[tokio::test]
async fn given_invalid_status_signature_when_reading_management_status_then_deny_without_disclosure()
 {
    let fixture = Fixture::new().await;
    assert_eq!(
        fixture
            .put(&fixture.update(0, vec![], None, 32))
            .await
            .status(),
        StatusCode::OK
    );

    let wrong_key = fixture.status_request(32, 33);
    let wrong_key_response = fixture
        .client
        .post(format!(
            "{}/v2/management/scope/{RESOURCE}/status",
            fixture.url
        ))
        .json(&wrong_key)
        .send()
        .await
        .unwrap();
    assert_eq!(wrong_key_response.status(), StatusCode::FORBIDDEN);
    assert!(
        !wrong_key_response
            .text()
            .await
            .unwrap()
            .contains("capability")
    );

    let mut forged = fixture.status_request(32, 32);
    forged["authorization"]["signature"] = json!(URL_SAFE_NO_PAD.encode([0u8; 64]));
    let forged_response = fixture
        .client
        .post(format!(
            "{}/v2/management/scope/{RESOURCE}/status",
            fixture.url
        ))
        .json(&forged)
        .send()
        .await
        .unwrap();
    assert_eq!(forged_response.status(), StatusCode::FORBIDDEN);
    assert!(!forged_response.text().await.unwrap().contains("capability"));
}

#[tokio::test]
async fn given_migrated_scope_management_when_enrolling_then_require_signed_management_revision() {
    let fixture = Fixture::new().await;
    let migration = fixture.put(&fixture.update(0, vec![], None, 32)).await;
    assert_eq!(migration.status(), StatusCode::OK);
    let capability = migration.json::<Value>().await.unwrap()["capability"].clone();
    let challenge_response = fixture
        .challenge(32, Some(capability.clone()), RESOURCE)
        .await;
    assert_eq!(challenge_response.status(), StatusCode::OK);
    let challenge: Value = challenge_response.json().await.unwrap();
    let challenge = challenge["challenge"].clone();
    let (device_id, certificate) = device(32, &fixture.owner.identity);
    let read_token = "r".repeat(43);
    let write_token = "w".repeat(43);
    let payload = &challenge["payload"];
    let authorization = sign_json_envelope(&[32; 32], json!({
        "kind":"rusty-scope-enrollment", "version":1,
        "challengeId":payload["challengeId"], "nonce":payload["nonce"],
        "serviceId":payload["serviceId"], "publicOrigin":ORIGIN, "scopeId":RESOURCE,
        "personId":fixture.owner.identity.person_id, "deviceId":device_id, "deviceKeyId":device_id,
        "expectedRevision":payload["expectedRevision"],
        "readTokenHash":digest(read_token.as_bytes()), "writeTokenHash":digest(write_token.as_bytes()),
        "revoked":false, "expiresAt":payload["expiresAt"]
    }), &device_id, "MATCH/1").unwrap();
    let mut request = json!({"challenge":challenge,"identity":fixture.owner.identity,"deviceId":device_id,
        "certificates":[certificate],"managementCapability":capability,
        "readToken":read_token,"writeToken":write_token,"revoked":false,"authorization":authorization});
    let response = fixture
        .client
        .put(format!("{}/v2/scopes/{RESOURCE}", fixture.url))
        .json(&request)
        .send()
        .await
        .unwrap();
    assert_eq!(
        response.status(),
        StatusCode::FORBIDDEN,
        "migrated scope operation must bind current capability revision in its own signed authorization"
    );

    let mut authorized_payload = request["authorization"]["payload"].clone();
    authorized_payload["managementRevision"] = json!(1);
    request["authorization"] = serde_json::to_value(
        sign_json_envelope(&[32; 32], authorized_payload, &device_id, "MATCH/1").unwrap(),
    )
    .unwrap();
    let response = fixture
        .client
        .put(format!("{}/v2/scopes/{RESOURCE}", fixture.url))
        .json(&request)
        .send()
        .await
        .unwrap();
    assert_eq!(
        response.status(),
        StatusCode::OK,
        "matching revision should pass"
    );

    let object = super::tests::encrypted_fixture();
    let service_id = public_key_id(&fixture.store().public_key().unwrap()).unwrap();
    let issued_at = now_ms().unwrap();
    let checkpoint_authorization = sign_json_envelope(
        &[32; 32],
        json!({
            "kind":"rusty-snapshot-checkpoint", "version":1, "serviceId":service_id,
            "origin":ORIGIN, "scopeId":RESOURCE, "keyEpoch":object.key_epoch,
            "policyRevision":1, "expectedSequence":0, "objectId":object.id().unwrap(),
            "requestId":URL_SAFE_NO_PAD.encode(rand::random::<[u8;32]>()),
            "issuedAt":issued_at, "expiresAt":issued_at+60000
        }),
        &device_id,
        "MATCH/1",
    )
    .unwrap();
    let checkpoint_request = json!({
        "object":object,"identity":fixture.owner.identity,"deviceId":device_id,
        "certificates":[device(32, &fixture.owner.identity).1],"managementCapability":capability,
        "authorization":checkpoint_authorization
    });
    let checkpoint_url = format!("{}/v2/scopes/{RESOURCE}/checkpoint", fixture.url);
    let response = fixture
        .client
        .post(&checkpoint_url)
        .bearer_auth(&write_token)
        .json(&checkpoint_request)
        .send()
        .await
        .unwrap();
    assert_eq!(
        response.status(),
        StatusCode::BAD_REQUEST,
        "migrated checkpoint must bind current management revision"
    );

    let mut checkpoint_payload = checkpoint_request["authorization"]["payload"].clone();
    checkpoint_payload["managementRevision"] = json!(1);
    let mut checkpoint_request = checkpoint_request;
    checkpoint_request["authorization"] = serde_json::to_value(
        sign_json_envelope(&[32; 32], checkpoint_payload, &device_id, "MATCH/1").unwrap(),
    )
    .unwrap();
    let response = fixture
        .client
        .post(&checkpoint_url)
        .bearer_auth(&write_token)
        .json(&checkpoint_request)
        .send()
        .await
        .unwrap();
    assert_eq!(
        response.status(),
        StatusCode::OK,
        "matching checkpoint revision should pass"
    );

    let latest = fixture
        .put(&fixture.update(1, vec![], Some(capability.clone()), 32))
        .await;
    assert_eq!(latest.status(), StatusCode::OK);
    let latest_capability = latest.json::<Value>().await.unwrap()["capability"].clone();
    let second_challenge = fixture
        .challenge(32, Some(latest_capability.clone()), RESOURCE)
        .await;
    assert_eq!(second_challenge.status(), StatusCode::OK);
    let second_challenge: Value = second_challenge.json().await.unwrap();
    let second_challenge = second_challenge["challenge"].clone();
    let second_payload = &second_challenge["payload"];
    let stale_authorization = sign_json_envelope(
        &[32; 32],
        json!({
            "kind":"rusty-scope-enrollment", "version":1,
            "challengeId":second_payload["challengeId"], "nonce":second_payload["nonce"],
            "serviceId":second_payload["serviceId"], "publicOrigin":ORIGIN, "scopeId":RESOURCE,
            "personId":fixture.owner.identity.person_id, "deviceId":device_id, "deviceKeyId":device_id,
            "expectedRevision":second_payload["expectedRevision"],
            "managementRevision":1,
            "readTokenHash":digest(read_token.as_bytes()), "writeTokenHash":digest(write_token.as_bytes()),
            "revoked":false, "expiresAt":second_payload["expiresAt"]
        }),
        &device_id,
        "MATCH/1",
    )
    .unwrap();
    let stale_request = json!({
        "challenge":second_challenge,"identity":fixture.owner.identity,"deviceId":device_id,
        "certificates":[device(32, &fixture.owner.identity).1],"managementCapability":latest_capability,
        "readToken":read_token,"writeToken":write_token,"revoked":false,"authorization":stale_authorization
    });
    let response = fixture
        .client
        .put(format!("{}/v2/scopes/{RESOURCE}", fixture.url))
        .json(&stale_request)
        .send()
        .await
        .unwrap();
    assert_eq!(
        response.status(),
        StatusCode::FORBIDDEN,
        "newer outer capability cannot substitute for the revision signed by the operation"
    );
}

#[tokio::test]
async fn given_migrated_board_management_when_publishing_or_staging_then_require_signed_revision() {
    let fixture = Fixture::new().await;
    let board = "public-board";
    let operations = vec![
        "management.update",
        "publication.publish",
        "publication.stage-file",
        "publication.status",
        "publication.unpublish",
        "publication.update",
    ];
    let migration = fixture
        .put_resource(
            "board",
            board,
            &fixture.update_resource("board", board, 0, vec![], None, 32, operations),
        )
        .await;
    assert_eq!(migration.status(), StatusCode::OK);
    let capability = migration.json::<Value>().await.unwrap()["capability"].clone();
    let (device_id, certificate) = device(32, &fixture.owner.identity);
    let challenge_response = fixture
        .client
        .post(format!("{}/v1/public/challenges", fixture.url))
        .json(
            &json!({"version":1,"boardId":board,"identity":fixture.owner.identity,
            "deviceId":device_id,"certificates":[certificate],"managementCapability":capability}),
        )
        .send()
        .await
        .unwrap();
    assert_eq!(challenge_response.status(), StatusCode::OK);
    let challenge: Value = challenge_response.json().await.unwrap();
    let challenge = challenge["challenge"].clone();
    let challenge_payload = &challenge["payload"];
    let bytes = b"small public fixture";
    let sha256 = digest(bytes);
    let asset_payload = json!({
        "kind":"rusty-publication-command","version":1,
        "challengeId":challenge_payload["challengeId"],"nonce":challenge_payload["nonce"],
        "serviceId":challenge_payload["serviceId"],"publicOrigin":ORIGIN,"boardId":board,
        "action":"stage-file","projectionHash":sha256,"expectedRevision":0,
        "expiresAt":challenge_payload["expiresAt"],"byteLength":bytes.len()
    });
    let sign = |payload: Value| {
        serde_json::to_value(sign_json_envelope(&[32; 32], payload, &device_id, "MATCH/1").unwrap())
            .unwrap()
    };
    let mut asset_request = json!({"challenge":challenge,"identity":fixture.owner.identity,
        "deviceId":device_id,"certificates":[certificate],"managementCapability":capability,
        "sha256":sha256,"byteLength":bytes.len(),"bytes":URL_SAFE_NO_PAD.encode(bytes),
        "authorization":sign(asset_payload.clone())});
    let send_asset = |request: &Value| {
        let body = request.clone();
        let client = fixture.client.clone();
        let url = format!("{}/v1/public/boards/{board}/files", fixture.url);
        async move { client.put(url).json(&body).send().await.unwrap() }
    };
    assert_eq!(
        send_asset(&asset_request).await.status(),
        StatusCode::FORBIDDEN,
        "migrated staging command without managementRevision must fail"
    );
    let mut bound_asset = asset_payload;
    bound_asset["managementRevision"] = json!(1);
    asset_request["authorization"] = sign(bound_asset);
    assert_eq!(send_asset(&asset_request).await.status(), StatusCode::OK);

    let challenge_response = fixture
        .client
        .post(format!("{}/v1/public/challenges", fixture.url))
        .json(
            &json!({"version":1,"boardId":board,"identity":fixture.owner.identity,
            "deviceId":device_id,"certificates":[certificate],"managementCapability":capability}),
        )
        .send()
        .await
        .unwrap();
    assert_eq!(challenge_response.status(), StatusCode::OK);
    let challenge: Value = challenge_response.json().await.unwrap();
    let challenge = challenge["challenge"].clone();
    let challenge_payload = &challenge["payload"];
    let projection = json!({
        "kind":"tincanban-public-board","version":1,
        "board":{"id":board,"title":"Board"},"columns":[],"fields":[],
        "cards":[],"discussions":[],"files":[]
    });
    let projection_hash = digest(canonicalize_json(&projection).unwrap().as_bytes());
    let mut publish_payload = json!({
        "kind":"rusty-publication-command","version":1,
        "challengeId":challenge_payload["challengeId"],"nonce":challenge_payload["nonce"],
        "serviceId":challenge_payload["serviceId"],"publicOrigin":ORIGIN,"boardId":board,
        "action":"publish","projectionHash":projection_hash,"expectedRevision":0,
        "expiresAt":challenge_payload["expiresAt"]
    });
    let mut publication = json!({"challenge":challenge,"identity":fixture.owner.identity,
        "deviceId":device_id,"certificates":[certificate],"managementCapability":capability,
        "action":"publish","projection":projection,
        "authorization":sign(publish_payload.clone())});
    let send_publication = |request: &Value| {
        let body = request.clone();
        let client = fixture.client.clone();
        let url = format!("{}/v1/public/boards/{board}", fixture.url);
        async move { client.put(url).json(&body).send().await.unwrap() }
    };
    assert_eq!(
        send_publication(&publication).await.status(),
        StatusCode::FORBIDDEN,
        "migrated publication command without managementRevision must fail"
    );
    publish_payload["managementRevision"] = json!(1);
    publication["authorization"] = sign(publish_payload);
    assert_eq!(
        send_publication(&publication).await.status(),
        StatusCode::OK
    );
}

#[tokio::test]
async fn given_interrupted_first_migration_when_pointer_is_not_published_then_keep_evidence_pending_and_retry_exact_policy()
 {
    let mut fixture = Fixture::new().await;
    fixture
        .store()
        .management_commit_failure
        .store(true, std::sync::atomic::Ordering::SeqCst);
    let update = fixture.update(0, vec![], None, 32);
    assert_eq!(
        fixture.put(&update).await.status(),
        StatusCode::SERVICE_UNAVAILABLE
    );
    let status: Value = fixture.status().send().await.unwrap().json().await.unwrap();
    assert_eq!(
        status["migrationPending"], true,
        "interrupted migration must remain explicit"
    );
    fixture.restart().await;
    assert_eq!(
        fixture
            .status()
            .send()
            .await
            .unwrap()
            .json::<Value>()
            .await
            .unwrap()["migrationPending"],
        true,
        "migration pending marker must survive a server restart"
    );
    assert_eq!(
        fixture.challenge(32, None, RESOURCE).await.status(),
        StatusCode::FORBIDDEN,
        "pending migration cannot silently fall back to legacy management"
    );
    assert_eq!(fixture.put(&update).await.status(), StatusCode::OK);
    assert_eq!(
        fixture
            .status()
            .send()
            .await
            .unwrap()
            .json::<Value>()
            .await
            .unwrap()["migrationPending"],
        false
    );
}

#[tokio::test]
async fn given_old_completed_retry_after_new_migration_pointer_fault_then_preserve_the_new_pending_marker()
 {
    let fixture = Fixture::new().await;
    let first_request = fixture.update(0, vec![], None, 32);
    let first_receipt = fixture
        .put(&first_request)
        .await
        .json::<Value>()
        .await
        .unwrap()["capability"]
        .clone();
    let pending_request = fixture.update(1, vec![], Some(first_receipt.clone()), 32);
    fixture
        .store()
        .management_commit_failure
        .store(true, std::sync::atomic::Ordering::SeqCst);
    assert_eq!(
        fixture.put(&pending_request).await.status(),
        StatusCode::SERVICE_UNAVAILABLE
    );
    assert_eq!(
        fixture
            .status()
            .send()
            .await
            .unwrap()
            .json::<Value>()
            .await
            .unwrap()["migrationPending"],
        true
    );

    let replayed = fixture.put(&first_request).await;
    assert_eq!(replayed.status(), StatusCode::OK);
    assert_eq!(
        replayed.json::<Value>().await.unwrap()["capability"],
        first_receipt
    );
    assert_eq!(
        fixture
            .status()
            .send()
            .await
            .unwrap()
            .json::<Value>()
            .await
            .unwrap()["migrationPending"],
        true,
        "retry for earlier request must not erase another request's pending marker"
    );

    let second = fixture.put(&pending_request).await;
    assert_eq!(second.status(), StatusCode::OK);
    assert_eq!(
        second.json::<Value>().await.unwrap()["capability"]["payload"]["revision"],
        2
    );
    assert_eq!(
        fixture
            .status()
            .send()
            .await
            .unwrap()
            .json::<Value>()
            .await
            .unwrap()["migrationPending"],
        false
    );
}

#[tokio::test]
async fn given_policy_and_receipt_after_restart_then_preserve_latest_retry_and_ignore_legacy_controller_allowlist()
 {
    let mut fixture = Fixture::new().await;
    let first_request = fixture.update(0, vec![], None, 32);
    let first_receipt = fixture
        .put(&first_request)
        .await
        .json::<Value>()
        .await
        .unwrap()["capability"]
        .clone();
    let latest_request = fixture.update(1, vec![], Some(first_receipt), 32);
    let latest_receipt = fixture
        .put(&latest_request)
        .await
        .json::<Value>()
        .await
        .unwrap()["capability"]
        .clone();

    fixture.restart().await;

    let status = fixture
        .status()
        .send()
        .await
        .unwrap()
        .json::<Value>()
        .await
        .unwrap();
    assert_eq!(
        status["capability"], latest_receipt,
        "restart must preserve the current policy"
    );
    let exact_retry = fixture.put(&latest_request).await;
    assert_eq!(exact_retry.status(), StatusCode::OK);
    assert_eq!(
        exact_retry.json::<Value>().await.unwrap()["capability"],
        latest_receipt,
        "restart must preserve the exact completed receipt"
    );

    let (device_id, certificate) = device(32, &fixture.owner.identity);
    let capability: SignedEnvelope<Value> = serde_json::from_value(latest_receipt.clone()).unwrap();
    assert!(
        fixture
            .store()
            .management_authorized(
                &fixture.owner,
                &fixture.owner.identity,
                &device_id,
                &[certificate],
                "scope",
                RESOURCE,
                "scope.policy",
                Some(&capability),
                ORIGIN
            )
            .unwrap(),
        "current person capability must work when legacy controller allowlist is empty"
    );
    assert_eq!(
        fixture
            .challenge(32, Some(latest_receipt), RESOURCE)
            .await
            .status(),
        StatusCode::OK
    );
}

#[tokio::test]
async fn given_invalid_signed_policy_mutations_when_submitted_then_publish_no_management_capability()
 {
    for (field, replacement) in [
        ("serviceId", json!("another-service")),
        ("origin", json!("https://attacker.example")),
        ("resourceId", json!("another-resource")),
    ] {
        let fixture = Fixture::new().await;
        let mut body = fixture.update(0, vec![], None, 32);
        body["authorization"]["payload"][field] = replacement;
        fixture.resign(&mut body, 32);
        let response = fixture.put(&body).await;
        assert!(
            !response.status().is_success(),
            "signed {field} substitution must fail"
        );
        assert!(
            fixture
                .status()
                .send()
                .await
                .unwrap()
                .json::<Value>()
                .await
                .unwrap()["capability"]
                .is_null(),
            "failed {field} substitution must publish no capability"
        );
    }

    let fixture = Fixture::new().await;
    let mut forged = fixture.update(0, vec![], None, 32);
    forged["authorization"]["signature"] = json!(URL_SAFE_NO_PAD.encode([0u8; 64]));
    assert!(
        !fixture.put(&forged).await.status().is_success(),
        "forged policy signature must fail"
    );
    assert!(
        fixture
            .status()
            .send()
            .await
            .unwrap()
            .json::<Value>()
            .await
            .unwrap()["capability"]
            .is_null(),
        "forged policy signature must publish no capability"
    );

    let fixture = Fixture::new().await;
    let mut appended = fixture.update(0, vec![], None, 32);
    appended["certificates"]
        .as_array_mut()
        .unwrap()
        .push(serde_json::to_value(unrelated_certificate()).unwrap());
    let response = fixture.put(&appended).await;
    assert!(
        !response.status().is_success(),
        "unrelated-person certificate must not be accepted as management evidence"
    );
    assert!(
        fixture
            .status()
            .send()
            .await
            .unwrap()
            .json::<Value>()
            .await
            .unwrap()["capability"]
            .is_null(),
        "unrelated-person certificate must publish no capability"
    );
}

#[tokio::test]
async fn given_migrated_management_capability_when_stale_update_or_removed_operation_is_used_then_reject_without_overwrite()
 {
    let fixture = Fixture::new().await;
    let first = fixture.put(&fixture.update(0, vec![], None, 32)).await;
    assert_eq!(first.status(), StatusCode::OK);
    let current = first.json::<Value>().await.unwrap()["capability"].clone();

    let stale = fixture.update(0, vec![], Some(current.clone()), 32);
    assert_eq!(fixture.put(&stale).await.status(), StatusCode::CONFLICT);
    assert_eq!(
        fixture
            .status()
            .send()
            .await
            .unwrap()
            .json::<Value>()
            .await
            .unwrap()["capability"],
        current,
        "stale expectedRevision cannot replace the published capability"
    );

    let mut restricted = fixture.update(1, vec![], Some(current), 32);
    restricted["authorization"]["payload"]["operations"] =
        json!(["management.update", "snapshot.checkpoint"]);
    fixture.resign(&mut restricted, 32);
    let response = fixture.put(&restricted).await;
    assert_eq!(response.status(), StatusCode::OK);
    let capability = response.json::<Value>().await.unwrap()["capability"].clone();
    assert_eq!(
        fixture
            .challenge(32, Some(capability), RESOURCE)
            .await
            .status(),
        StatusCode::FORBIDDEN,
        "controller ancestry cannot restore the removed scope.policy operation"
    );
}

fn independent_owner_request(mut request: Value, root_seed: u8) -> Value {
    let public_key = public_key_from_seed(&[root_seed; 32]).unwrap();
    let identity = PublicIdentity {
        person_id: public_key_id(&public_key).unwrap(),
        public_key,
        display_name: "Independent owner".into(),
    };
    let device_key = public_key_from_seed(&[32; 32]).unwrap();
    let device_id = public_key_id(&device_key).unwrap();
    let certificate = sign_device_certificate(
        &[root_seed; 32],
        DeviceCertificatePayload {
            kind: "device-certificate".into(),
            version: 1,
            person_id: identity.person_id.clone(),
            device_id: device_id.clone(),
            device_public_key: device_key,
            issuer_certificate_hash: None,
            can_enroll_devices: true,
        },
        &identity.person_id,
        "MATCH/1",
    )
    .unwrap();
    request["identity"] = serde_json::to_value(&identity).unwrap();
    request["certificates"] = json!([certificate]);
    request["authorization"]["payload"]["personId"] = json!(identity.person_id);
    if request["authorization"]["payload"]["resourceKind"] == "person" {
        request["authorization"]["payload"]["resourceId"] = json!(identity.person_id);
    }
    request["authorization"] = serde_json::to_value(
        sign_json_envelope(
            &[32; 32],
            request["authorization"]["payload"].clone(),
            &device_id,
            "MATCH/1",
        )
        .unwrap(),
    )
    .unwrap();
    request
}

#[tokio::test]
async fn given_independent_owners_when_using_one_rusty_then_each_controls_only_own_resources_after_restart()
 {
    let mut f = Fixture::new().await;
    // Given two unrelated identities, each bootstraps its own person authority.
    let mut capabilities = Vec::new();
    for (root_seed, scope) in [(31, "first-owner-scope"), (61, "second-owner-scope")] {
        let person = independent_owner_request(
            f.update_resource(
                "person",
                &f.owner.identity.person_id,
                0,
                vec![],
                None,
                32,
                vec!["management.update", "resource.create"],
            ),
            root_seed,
        );
        let person_id = person["identity"]["personId"].as_str().unwrap();
        let response = f.put_resource("person", person_id, &person).await;
        let status = response.status();
        let body = response.text().await.unwrap();
        assert_eq!(
            status,
            StatusCode::OK,
            "independent owner must bootstrap: {body}"
        );
        let parent = serde_json::from_str::<Value>(&body).unwrap()["capability"].clone();
        let mut request = independent_owner_request(
            f.update_resource(
                "scope",
                scope,
                0,
                vec![],
                None,
                32,
                vec!["management.update", "scope.policy", "snapshot.checkpoint"],
            ),
            root_seed,
        );
        request["personManagementCapability"] = parent.clone();
        request["authorization"]["payload"]["personManagementRevision"] =
            parent["payload"]["revision"].clone();
        f.resign(&mut request, 32);
        let response = f.put_resource("scope", scope, &request).await;
        assert_eq!(response.status(), StatusCode::OK);
        capabilities.push(response.json::<Value>().await.unwrap()["capability"].clone());
    }
    // When storage is reopened, ownership remains bound to each exact resource.
    f.restart().await;
    for (index, (root_seed, scope)) in [(31, "first-owner-scope"), (61, "second-owner-scope")]
        .into_iter()
        .enumerate()
    {
        let mut status = independent_owner_request(f.status_request(32, 32), root_seed);
        status["authorization"]["payload"]["resourceId"] = json!(scope);
        f.resign(&mut status, 32);
        let url = format!("{}/v2/management/scope/{scope}/status", f.url);
        let response = f.client.post(&url).json(&status).send().await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.json::<Value>().await.unwrap()["capability"],
            capabilities[index]
        );
        // Then another valid owner cannot read management rights or replace policy,
        // even if it presents the victim's valid service capability.
        let mut foreign =
            independent_owner_request(status.clone(), if root_seed == 31 { 61 } else { 31 });
        f.resign(&mut foreign, 32);
        assert_eq!(
            f.client
                .post(&url)
                .json(&foreign)
                .send()
                .await
                .unwrap()
                .status(),
            StatusCode::FORBIDDEN
        );
        let takeover = independent_owner_request(
            f.update_resource(
                "scope",
                scope,
                1,
                vec![],
                Some(capabilities[index].clone()),
                32,
                vec!["management.update", "scope.policy", "snapshot.checkpoint"],
            ),
            if root_seed == 31 { 61 } else { 31 },
        );
        assert_eq!(
            f.put_resource("scope", scope, &takeover).await.status(),
            StatusCode::FORBIDDEN
        );
        let mut forged = status;
        forged["authorization"]["signature"] = json!(URL_SAFE_NO_PAD.encode([0u8; 64]));
        assert_eq!(
            f.client
                .post(&url)
                .json(&forged)
                .send()
                .await
                .unwrap()
                .status(),
            StatusCode::FORBIDDEN
        );
    }
}

#[tokio::test]
async fn given_conflicting_signed_owner_records_when_resolving_publication_owner_then_reject_instead_of_selecting_one()
 {
    let fixture = Fixture::new().await;
    let update = fixture.update_resource(
        "board",
        RESOURCE,
        0,
        vec![],
        None,
        32,
        vec![
            "management.update",
            "publication.status",
            "publication.update",
        ],
    );
    assert_eq!(
        fixture
            .put_resource("board", RESOURCE, &update)
            .await
            .status(),
        StatusCode::OK
    );
    fixture
        .store()
        .retain_publication_owner(RESOURCE, &fixture.owner)
        .unwrap();
    let foreign_key = public_key_from_seed(&[71; 32]).unwrap();
    let foreign = PublicIdentity {
        person_id: public_key_id(&foreign_key).unwrap(),
        public_key: foreign_key,
        display_name: String::new(),
    };
    let evidence = sign_json_envelope(
        &fixture.store().seed,
        json!({
            "kind":"rusty-publication-owner", "version":1, "boardId":RESOURCE, "identity":foreign
        }),
        &public_key_id(&fixture.store().public_key().unwrap()).unwrap(),
        DOMAIN,
    )
    .unwrap();
    atomic_write(
        &fixture
            .directory
            .join("management/publication-owners")
            .join(format!("{RESOURCE}.json")),
        &serde_json::to_vec(&evidence).unwrap(),
    )
    .unwrap();
    assert!(
        fixture
            .store()
            .publication_owner(RESOURCE, &fixture.owner.identity)
            .err()
            .expect("conflicting signed ownership must fail")
            .contains("owner management evidence conflict")
    );
}
