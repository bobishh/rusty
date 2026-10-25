use super::*;
use crate::identity_authority::{
    IdentityAuthorityView, StoredIdentityAuthority, test_authority_view_with_devices,
    test_revoke_authority_device,
};

const APPLICATION_ORIGIN: &str = "https://boards.example";
const RUSTY_ORIGIN: &str = "https://rusty.example";

struct Fixture {
    directory: PathBuf,
    store: Option<BlindStore>,
    identity: PublicIdentity,
    authority: IdentityAuthorityView,
    client: reqwest::Client,
    url: String,
    server: Option<tokio::task::JoinHandle<()>>,
}

impl Fixture {
    async fn new() -> Self {
        let directory =
            std::env::temp_dir().join(format!("rusty-catalog-access-{}", rand::random::<u64>()));
        let store = BlindStore::open(directory.clone()).unwrap();
        let root_seed = [31; 32];
        let root_public_key = public_key_from_seed(&root_seed).unwrap();
        let identity = PublicIdentity {
            person_id: public_key_id(&root_public_key).unwrap(),
            public_key: root_public_key,
            display_name: "Catalog owner".into(),
        };
        let authority = test_authority_view_with_devices(
            &identity,
            &root_seed,
            &[(32, true), (33, false), (34, true)],
        );
        let authority_path = store.identity_authority_path(&identity.person_id).unwrap();
        fs::create_dir_all(authority_path.parent().unwrap()).unwrap();
        fs::write(
            &authority_path,
            serde_json::to_vec(&StoredIdentityAuthority {
                view: authority.clone(),
                recent_updates: Vec::new(),
            })
            .unwrap(),
        )
        .unwrap();
        let mut fixture = Self {
            directory,
            store: Some(store),
            identity,
            authority,
            client: reqwest::Client::new(),
            url: String::new(),
            server: None,
        };
        fixture.start_server().await;
        fixture
    }

    fn store(&self) -> &BlindStore {
        self.store.as_ref().unwrap()
    }

    async fn start_server(&mut self) {
        let app = router(
            self.store().clone(),
            RUSTY_ORIGIN.into(),
            vec![APPLICATION_ORIGIN.into()],
        )
        .unwrap();
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

    fn publisher_envelope(&self, catalog_id: &str, revision: u64, ciphertext: &str) -> Value {
        self.publisher_envelope_with_request_person(
            catalog_id,
            revision,
            ciphertext,
            json!(self.identity.person_id),
        )
    }

    fn publisher_envelope_with_request_person(
        &self,
        catalog_id: &str,
        revision: u64,
        ciphertext: &str,
        request_person_id: Value,
    ) -> Value {
        let service_public_key = self.store().public_key().unwrap();
        let service_id = public_key_id(&service_public_key).unwrap();
        let app_seed = [33; 32];
        let app_public_key = public_key_from_seed(&app_seed).unwrap();
        let app_device_id = public_key_id(&app_public_key).unwrap();
        let manager_seed = [32; 32];
        let manager_id = public_key_id(&public_key_from_seed(&manager_seed).unwrap()).unwrap();
        let recipient_seed = [34; 32];
        let recipient_public_key = public_key_from_seed(&recipient_seed).unwrap();
        let recipient_device_id = public_key_id(&recipient_public_key).unwrap();
        let app_certificate = self
            .authority
            .certificates
            .iter()
            .find(|certificate| certificate.payload.device_id == app_device_id)
            .unwrap();
        let now = now_ms().unwrap();
        let request_issued_at = now.saturating_sub(90_000);
        let request_expires_at = now.saturating_sub(30_000);
        let challenge = format!("{:064x}", rand::random::<u128>());
        let pins = json!([{
            "origin": RUSTY_ORIGIN,
            "serviceId": service_id,
            "servicePublicKey": service_public_key,
        }]);
        let request_payload = json!({
            "kind": "mesh-device-authorization-request", "version": 3,
            "applicationOrigin": APPLICATION_ORIGIN, "challenge": challenge,
            "expiresAt": request_expires_at, "personId": request_person_id,
            "deviceId": app_device_id, "devicePublicKey": app_public_key,
            "includeIdentityCatalogAccess": true,
        });
        let request = sign_json_envelope(
            &app_seed,
            request_payload,
            &app_device_id,
            "MESH-DEVICE-AUTHORIZATION/1",
        )
        .unwrap();
        let pins_hash =
            URL_SAFE_NO_PAD.encode(Sha256::digest(canonicalize_json(&pins).unwrap().as_bytes()));
        let approval_payload = json!({
            "kind": "mesh-device-authorization-approval", "version": 5,
            "request": request,
            "certificateHash": meta_mesh_core::certificate_hash(app_certificate).unwrap(),
            "issuedAt": request_issued_at, "expiresAt": request_expires_at,
            "authorityViewDigest": self.authority.view_digest,
            "revocationHead": self.authority.revocation_head,
            "rustyServicePinsDigest": pins_hash,
            "profileStateDigest": URL_SAFE_NO_PAD.encode(rand::random::<[u8; 32]>()),
            "identityCatalogAccessDigest": URL_SAFE_NO_PAD.encode(rand::random::<[u8; 32]>()),
        });
        let approval_proof = sign_json_envelope(
            &manager_seed,
            approval_payload,
            &manager_id,
            "MESH-APP-DEVICE-AUTHORIZATION/1",
        )
        .unwrap();
        let publisher_authorization = json!({
            "request": request,
            "proof": approval_proof,
            "certificate": app_certificate,
            "rustyServicePins": pins,
        });
        let now = now_ms().unwrap();
        serde_json::to_value(sign_json_envelope(&app_seed, json!({
            "kind": "mesh-identity-catalog-access-publication", "version": 1,
            "serviceId": service_id, "personId": self.identity.person_id,
            "applicationOrigin": APPLICATION_ORIGIN, "catalogId": catalog_id,
            "sourceRevision": revision, "recipientDeviceId": recipient_device_id,
            "recipientPublicKeyId": recipient_device_id, "recipientPublicKey": recipient_public_key,
            "ciphertext": ciphertext, "issuedAt": now,
            "publisherAuthorization": publisher_authorization,
        }), &app_device_id, "MESH-IDENTITY-CATALOG-ACCESS-PUBLISH/1").unwrap()).unwrap()
    }

    fn resign_publication(&self, publication: Value) -> Value {
        let app_public_key = public_key_from_seed(&[33; 32]).unwrap();
        let app_device_id = public_key_id(&app_public_key).unwrap();
        serde_json::to_value(
            sign_json_envelope(
                &[33; 32],
                publication["payload"].clone(),
                &app_device_id,
                "MESH-IDENTITY-CATALOG-ACCESS-PUBLISH/1",
            )
            .unwrap(),
        )
        .unwrap()
    }

    fn store_authority(&self, authority: IdentityAuthorityView) {
        let path = self
            .store()
            .identity_authority_path(&self.identity.person_id)
            .unwrap();
        fs::write(
            path,
            serde_json::to_vec(&StoredIdentityAuthority {
                view: authority,
                recent_updates: Vec::new(),
            })
            .unwrap(),
        )
        .unwrap();
    }

    fn list_request(&self, signer_seed: u8, challenge: &str) -> Value {
        let device_public_key = public_key_from_seed(&[signer_seed; 32]).unwrap();
        let device_id = public_key_id(&device_public_key).unwrap();
        let now = now_ms().unwrap();
        serde_json::to_value(
            sign_json_envelope(
                &[signer_seed; 32],
                json!({
                    "kind": "mesh-identity-catalog-access-list-request", "version": 1,
                    "serviceId": public_key_id(&self.store().public_key().unwrap()).unwrap(),
                    "personId": self.identity.person_id, "applicationOrigin": APPLICATION_ORIGIN,
                    "recipientDeviceId": device_id, "recipientPublicKeyId": device_id,
                    "recipientPublicKey": device_public_key, "challenge": challenge,
                    "issuedAt": now, "expiresAt": now + 60_000,
                }),
                &device_id,
                "MESH-IDENTITY-CATALOG-ACCESS-REQUEST/1",
            )
            .unwrap(),
        )
        .unwrap()
    }
}

#[tokio::test]
async fn given_valid_v3_catalog_request_without_selected_person_then_publication_succeeds() {
    let fixture = Fixture::new().await;
    let publication = fixture.publisher_envelope_with_request_person(
        "catalog_unselected_person",
        1,
        &URL_SAFE_NO_PAD.encode([99_u8; 32]),
        Value::Null,
    );
    let url = format!("{}/v2/identity/catalog-access", fixture.url);
    let response = fixture
        .client
        .put(&url)
        .json(&publication)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn given_catalog_publisher_binding_mismatches_then_rejects_them() {
    let fixture = Fixture::new().await;
    let base = fixture.publisher_envelope("catalog_1", 1, &URL_SAFE_NO_PAD.encode([99_u8; 32]));
    let manager_certificate = fixture
        .authority
        .certificates
        .iter()
        .find(|certificate| certificate.payload.can_enroll_devices)
        .unwrap();
    let app_device_id = public_key_id(&public_key_from_seed(&[33; 32]).unwrap()).unwrap();
    let mut invalid = Vec::new();

    let mut wrong_person = base.clone();
    wrong_person["payload"]["personId"] =
        json!(public_key_id(&public_key_from_seed(&[77; 32]).unwrap()).unwrap());
    invalid.push(fixture.resign_publication(wrong_person));

    let explicit_foreign_request = fixture.publisher_envelope_with_request_person(
        "catalog_1",
        1,
        &URL_SAFE_NO_PAD.encode([99_u8; 32]),
        json!(public_key_id(&public_key_from_seed(&[77; 32]).unwrap()).unwrap()),
    );
    invalid.push(explicit_foreign_request);

    let mut wrong_origin = base.clone();
    wrong_origin["payload"]["applicationOrigin"] = json!("https://other.example");
    invalid.push(fixture.resign_publication(wrong_origin));

    let mut wrong_certificate = base.clone();
    wrong_certificate["payload"]["publisherAuthorization"]["certificate"] =
        serde_json::to_value(manager_certificate).unwrap();
    invalid.push(fixture.resign_publication(wrong_certificate));

    let mut wrong_issuer = base;
    wrong_issuer["payload"]["publisherAuthorization"]["proof"]["signerKeyId"] =
        json!(app_device_id);
    invalid.push(fixture.resign_publication(wrong_issuer));

    let url = format!("{}/v2/identity/catalog-access", fixture.url);
    for publication in invalid {
        let response = fixture
            .client
            .put(&url)
            .json(&publication)
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }
}

#[tokio::test]
async fn given_pending_or_missing_identity_authority_then_catalog_reads_fail_closed() {
    let fixture = Fixture::new().await;
    let request = fixture.list_request(34, &URL_SAFE_NO_PAD.encode(rand::random::<[u8; 32]>()));
    let url = format!("{}/v2/identity/catalog-access/request", fixture.url);
    let pending_path = fixture
        .directory
        .join("management/pending/person")
        .join(format!("{}.json", fixture.identity.person_id));
    fs::create_dir_all(pending_path.parent().unwrap()).unwrap();
    fs::write(
        &pending_path,
        serde_json::to_vec(&json!({
            "version": 1, "resourceKind": "person", "resourceId": fixture.identity.person_id,
            "expectedRevision": 1, "requestId": "pending_catalog_read",
            "authorizationHash": URL_SAFE_NO_PAD.encode([1_u8; 32]),
            "recordHash": URL_SAFE_NO_PAD.encode([2_u8; 32]),
        }))
        .unwrap(),
    )
    .unwrap();
    let pending = fixture
        .client
        .post(&url)
        .json(&request)
        .send()
        .await
        .unwrap();
    assert_eq!(pending.status(), StatusCode::FORBIDDEN);

    fs::remove_file(pending_path).unwrap();
    let authority_path = fixture
        .store()
        .identity_authority_path(&fixture.identity.person_id)
        .unwrap();
    fs::remove_file(authority_path).unwrap();
    let missing_authority = fixture
        .client
        .post(&url)
        .json(&request)
        .send()
        .await
        .unwrap();
    assert_eq!(
        missing_authority.status(),
        StatusCode::PRECONDITION_REQUIRED
    );
}

#[tokio::test]
async fn given_revoked_recipient_manager_then_catalog_read_is_denied() {
    let fixture = Fixture::new().await;
    let recipient_id = public_key_id(&public_key_from_seed(&[34; 32]).unwrap()).unwrap();
    let revoked = test_revoke_authority_device(fixture.authority.clone(), &recipient_id, &[32; 32]);
    fixture.store_authority(revoked);
    let request = fixture.list_request(34, &URL_SAFE_NO_PAD.encode(rand::random::<[u8; 32]>()));
    let url = format!("{}/v2/identity/catalog-access/request", fixture.url);
    let response = fixture
        .client
        .post(&url)
        .json(&request)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn given_ninth_catalog_for_recipient_then_publication_is_rejected() {
    let fixture = Fixture::new().await;
    let url = format!("{}/v2/identity/catalog-access", fixture.url);
    let ciphertext = URL_SAFE_NO_PAD.encode([99_u8; 32]);
    for index in 0..8 {
        let publication = fixture.publisher_envelope(&format!("catalog_{index}"), 1, &ciphertext);
        let response = fixture
            .client
            .put(&url)
            .json(&publication)
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }
    let ninth = fixture.publisher_envelope("catalog_8", 1, &ciphertext);
    let response = fixture.client.put(&url).json(&ninth).send().await.unwrap();
    assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
}

impl Drop for Fixture {
    fn drop(&mut self) {
        if let Some(server) = self.server.take() {
            server.abort();
        }
        self.store.take();
        let _ = fs::remove_dir_all(&self.directory);
    }
}

#[tokio::test]
async fn given_approved_app_catalog_when_published_and_retried_after_restart_then_active_manager_recovers_opaque_entry()
 {
    let mut fixture = Fixture::new().await;
    let ciphertext = URL_SAFE_NO_PAD.encode([99_u8; 192]);
    let publication = fixture.publisher_envelope("catalog_1", 1, &ciphertext);
    let publish_url = format!("{}/v2/identity/catalog-access", fixture.url);
    let mut forged_publication = publication.clone();
    forged_publication["signature"] = json!(URL_SAFE_NO_PAD.encode([0_u8; 64]));
    let forged_response = fixture
        .client
        .put(&publish_url)
        .json(&forged_publication)
        .send()
        .await
        .unwrap();
    assert_eq!(forged_response.status(), StatusCode::FORBIDDEN);

    let first = fixture
        .client
        .put(&publish_url)
        .json(&publication)
        .send()
        .await
        .unwrap();
    assert_eq!(first.status(), StatusCode::OK);
    let first_body: Value = first.json().await.unwrap();
    let first_receipt = first_body["receipt"].clone();
    let publication_receipt: SignedEnvelope<Value> =
        serde_json::from_value(first_receipt.clone()).unwrap();
    assert!(
        verify_signed_envelope(
            &publication_receipt,
            &fixture.store().public_key().unwrap(),
            DOMAIN
        )
        .unwrap()
    );
    assert_eq!(publication_receipt.payload["catalogId"], "catalog_1");
    assert_eq!(publication_receipt.payload["sourceRevision"], 1);

    fixture.restart().await;
    let publish_url = format!("{}/v2/identity/catalog-access", fixture.url);
    let retry = fixture
        .client
        .put(&publish_url)
        .json(&publication)
        .send()
        .await
        .unwrap();
    assert_eq!(retry.status(), StatusCode::OK);
    let retry_body: Value = retry.json().await.unwrap();
    assert_eq!(retry_body["receipt"], first_receipt);

    let conflict =
        fixture.publisher_envelope("catalog_1", 1, &URL_SAFE_NO_PAD.encode([100_u8; 192]));
    let response = fixture
        .client
        .put(&publish_url)
        .json(&conflict)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CONFLICT);

    let challenge = URL_SAFE_NO_PAD.encode(rand::random::<[u8; 32]>());
    let request = fixture.list_request(34, &challenge);
    let list_url = format!("{}/v2/identity/catalog-access/request", fixture.url);
    let list = fixture
        .client
        .post(&list_url)
        .json(&request)
        .send()
        .await
        .unwrap();
    assert_eq!(list.status(), StatusCode::OK);
    let list_body: Value = list.json().await.unwrap();
    assert_eq!(list_body["envelopes"].as_array().unwrap().len(), 1);
    assert_eq!(list_body["envelopes"][0], publication);
    let receipt: SignedEnvelope<Value> =
        serde_json::from_value(list_body["receipt"].clone()).unwrap();
    assert!(
        verify_signed_envelope(&receipt, &fixture.store().public_key().unwrap(), DOMAIN).unwrap()
    );
    assert_eq!(receipt.payload["challenge"], challenge);
    let repeated = fixture
        .client
        .post(&list_url)
        .json(&request)
        .send()
        .await
        .unwrap();
    assert_eq!(repeated.status(), StatusCode::OK);
    let repeated_body: Value = repeated.json().await.unwrap();
    assert_eq!(repeated_body["envelopes"], list_body["envelopes"]);

    let unauthorized =
        fixture.list_request(33, &URL_SAFE_NO_PAD.encode(rand::random::<[u8; 32]>()));
    let response = fixture
        .client
        .post(&list_url)
        .json(&unauthorized)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}
