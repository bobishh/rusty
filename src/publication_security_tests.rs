use super::*;
use meta_mesh_core::{DeviceCertificatePayload, sign_device_certificate};

const ORIGIN: &str = "https://rusty.example";
const BOARD: &str = "selected-public-board";

#[test]
fn given_enrolled_device_when_publishing_then_trusted_controller_delegation_is_accepted() {
    let fixture = Fixture::new();
    let public_key = public_key_from_seed(&[63; 32]).unwrap();
    let device_id = public_key_id(&public_key).unwrap();
    let certificate = sign_device_certificate(
        &[62; 32],
        DeviceCertificatePayload {
            kind: "device-certificate".into(),
            version: 1,
            person_id: fixture.owner.identity.person_id.clone(),
            device_id: device_id.clone(),
            device_public_key: public_key,
            issuer_certificate_hash: Some(
                meta_mesh_core::certificate_hash(&fixture.certificate).unwrap(),
            ),
            can_enroll_devices: true,
        },
        &fixture.device_id,
        "MATCH/1",
    )
    .unwrap();
    let challenge = fixture
        .store
        .create_public_challenge(
            BOARD,
            &fixture.owner.identity.person_id,
            &device_id,
            &device_id,
            ORIGIN,
        )
        .unwrap();
    let mut request = fixture.request("publish", Some(projection()), challenge);
    request["deviceId"] = json!(device_id);
    request["certificates"] = json!([certificate, fixture.certificate]);
    request["authorization"] = serde_json::to_value(
        sign_json_envelope(
            &[63; 32],
            request["authorization"]["payload"].clone(),
            &device_id,
            "MATCH/1",
        )
        .unwrap(),
    )
    .unwrap();
    assert!(fixture.mutate(request).is_ok());
}

#[test]
fn given_unlisted_root_device_when_trusted_certificate_is_appended_then_publication_stays_denied() {
    let fixture = Fixture::new();
    let public_key = public_key_from_seed(&[63; 32]).unwrap();
    let device_id = public_key_id(&public_key).unwrap();
    let certificate = sign_device_certificate(
        &[61; 32],
        DeviceCertificatePayload {
            kind: "device-certificate".into(),
            version: 1,
            person_id: fixture.owner.identity.person_id.clone(),
            device_id: device_id.clone(),
            device_public_key: public_key,
            issuer_certificate_hash: None,
            can_enroll_devices: true,
        },
        &fixture.owner.identity.person_id,
        "MATCH/1",
    )
    .unwrap();
    let challenge = fixture
        .store
        .create_public_challenge(
            BOARD,
            &fixture.owner.identity.person_id,
            &device_id,
            &device_id,
            ORIGIN,
        )
        .unwrap();
    let mut request = fixture.request("publish", Some(projection()), challenge);
    request["deviceId"] = json!(device_id);
    request["certificates"] = json!([certificate, fixture.certificate]);
    request["authorization"] = serde_json::to_value(
        sign_json_envelope(
            &[63; 32],
            request["authorization"]["payload"].clone(),
            &device_id,
            "MATCH/1",
        )
        .unwrap(),
    )
    .unwrap();
    assert!(fixture.mutate(request).is_err());
}

struct Fixture {
    directory: PathBuf,
    store: BlindStore,
    owner: TrustedOwner,
    device_id: String,
    certificate: DeviceCertificate,
}

impl Fixture {
    fn new() -> Self {
        let directory =
            std::env::temp_dir().join(format!("rusty-public-security-{}", rand::random::<u64>()));
        let public_key = public_key_from_seed(&[61; 32]).unwrap();
        let person_id = public_key_id(&public_key).unwrap();
        let device_public_key = public_key_from_seed(&[62; 32]).unwrap();
        let device_id = public_key_id(&device_public_key).unwrap();
        let certificate = sign_device_certificate(
            &[61; 32],
            DeviceCertificatePayload {
                kind: "device-certificate".into(),
                version: 1,
                person_id: person_id.clone(),
                device_id: device_id.clone(),
                device_public_key,
                issuer_certificate_hash: None,
                can_enroll_devices: true,
            },
            &person_id,
            "MATCH/1",
        )
        .unwrap();
        let identity = serde_json::from_value(
            json!({"personId":person_id,"publicKey":public_key,"displayName":"Controller"}),
        )
        .unwrap();
        let store = BlindStore::open(directory.clone()).unwrap();
        Self {
            directory,
            store,
            owner: TrustedOwner {
                identity,
                allowed_controller_device_ids: vec![device_id.clone()],
            },
            device_id,
            certificate,
        }
    }
    fn challenge(&self) -> SignedEnvelope<Value> {
        self.store
            .create_public_challenge(
                BOARD,
                &self.owner.identity.person_id,
                &self.device_id,
                &self.device_id,
                ORIGIN,
            )
            .unwrap()
    }
    fn request(
        &self,
        action: &str,
        projection: Option<Value>,
        challenge: SignedEnvelope<Value>,
    ) -> Value {
        let hash = projection
            .as_ref()
            .map(|value| digest(canonicalize_json(value).unwrap().as_bytes()))
            .unwrap_or_else(|| digest(b"null"));
        let payload = &challenge.payload;
        let command = json!({"kind":"rusty-publication-command","version":1,"challengeId":payload["challengeId"],"nonce":payload["nonce"],
            "serviceId":payload["serviceId"],"publicOrigin":ORIGIN,"boardId":BOARD,"action":action,"projectionHash":hash,
            "expectedRevision":payload["expectedRevision"],"expiresAt":payload["expiresAt"]});
        let authorization =
            sign_json_envelope(&[62; 32], command, &self.device_id, "MATCH/1").unwrap();
        json!({"challenge":challenge,"identity":self.owner.identity,"deviceId":self.device_id,"certificates":[self.certificate],"action":action,"projection":projection,"authorization":authorization})
    }
    fn mutate(&self, request: Value) -> Result<SignedEnvelope<Value>, String> {
        self.store.mutate_publication(
            BOARD,
            serde_json::from_value(request).unwrap(),
            &self.owner,
            ORIGIN,
        )
    }
    fn sign_modified(&self, request: &mut Value) {
        request["authorization"] = serde_json::to_value(
            sign_json_envelope(
                &[62; 32],
                request["authorization"]["payload"].clone(),
                &self.device_id,
                "MATCH/1",
            )
            .unwrap(),
        )
        .unwrap();
    }
    fn publish(&self) {
        let result = self
            .mutate(self.request("publish", Some(projection()), self.challenge()))
            .unwrap();
        assert_eq!(result.payload["revision"], 1);
        assert!(
            verify_signed_envelope(&result, &self.store.public_key().unwrap(), DOMAIN).unwrap()
        );
    }
    fn asset_request(&self, bytes: &[u8]) -> Value {
        let challenge = self.challenge();
        let payload = &challenge.payload;
        let hash = digest(bytes);
        let command = json!({"kind":"rusty-publication-command","version":1,"challengeId":payload["challengeId"],"nonce":payload["nonce"],
            "serviceId":payload["serviceId"],"publicOrigin":ORIGIN,"boardId":BOARD,"action":"stage-file","projectionHash":hash,
            "expectedRevision":payload["expectedRevision"],"expiresAt":payload["expiresAt"],"byteLength":bytes.len()});
        let authorization =
            sign_json_envelope(&[62; 32], command, &self.device_id, "MATCH/1").unwrap();
        json!({"challenge":challenge,"identity":self.owner.identity,"deviceId":self.device_id,"certificates":[self.certificate],
            "sha256":hash,"byteLength":bytes.len(),"bytes":URL_SAFE_NO_PAD.encode(bytes),"authorization":authorization})
    }
    fn stage(&self, request: Value) -> Result<SignedEnvelope<Value>, String> {
        self.store.stage_public_file(
            BOARD,
            serde_json::from_value(request).unwrap(),
            &self.owner,
            ORIGIN,
        )
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.directory);
    }
}
fn projection() -> Value {
    json!({"kind":"tincanban-public-board","version":1,"board":{"id":BOARD,"title":"Confirmed content"},
        "columns":[],"fields":[],"cards":[],"discussions":[],"files":[]})
}

#[test]
fn signed_publication_rejects_wrong_hash_origin_service_signature_and_device() {
    let fixture = Fixture::new();
    fixture.publish();
    for failure in [
        "hash",
        "origin",
        "service",
        "signature",
        "device",
        "certificate",
        "controller",
        "nonce",
    ] {
        let mut request = fixture.request("update", Some(projection()), fixture.challenge());
        match failure {
            "hash" => {
                request["authorization"]["payload"]["projectionHash"] =
                    json!(digest(b"wrong content"))
            }
            "origin" => {
                request["authorization"]["payload"]["publicOrigin"] = json!("https://other.example")
            }
            "service" => {
                request["authorization"]["payload"]["serviceId"] = json!("foreign-service")
            }
            "device" => request["deviceId"] = json!("untrusted-device"),
            "certificate" => request["certificates"] = json!([]),
            "controller" => request["identity"]["personId"] = json!("foreign-controller"),
            "nonce" => request["authorization"]["payload"]["nonce"] = json!("different-challenge"),
            _ => {}
        }
        fixture.sign_modified(&mut request);
        if failure == "signature" {
            request["authorization"]["signature"] = json!(URL_SAFE_NO_PAD.encode([0u8; 64]));
        }
        assert!(fixture.mutate(request).is_err(), "Accepted {failure}");
        let current = fixture.store.current_publication(BOARD).unwrap().unwrap();
        assert_eq!(current.revision, 1);
        assert_eq!(
            current.projection.unwrap()["board"]["title"],
            "Confirmed content"
        );
    }
}

#[test]
fn signed_publication_rejects_cross_board_payload_expired_challenge_replay_and_stale_revision() {
    let fixture = Fixture::new();
    let first = fixture.request("publish", Some(projection()), fixture.challenge());
    let stale = fixture.request("publish", Some(projection()), fixture.challenge());
    let mut foreign = projection();
    foreign["board"]["id"] = json!("another-board");
    assert!(
        fixture
            .mutate(fixture.request("publish", Some(foreign), fixture.challenge()))
            .is_err()
    );
    let expired = fixture.challenge();
    let pending_path = fixture
        .directory
        .join("publications/challenges")
        .join(format!(
            "{}.json",
            expired.payload["challengeId"].as_str().unwrap()
        ));
    let mut pending: Value = serde_json::from_slice(&fs::read(&pending_path).unwrap()).unwrap();
    pending["expiresAt"] = json!(0);
    fs::write(pending_path, serde_json::to_vec(&pending).unwrap()).unwrap();
    assert!(
        fixture
            .mutate(fixture.request("publish", Some(projection()), expired))
            .is_err()
    );
    fixture.mutate(first.clone()).unwrap();
    assert!(
        fixture.mutate(first).is_err(),
        "Consumed command replay accepted"
    );
    assert!(fixture.mutate(stale).is_err(), "Stale revision accepted");
    assert_eq!(
        fixture
            .store
            .current_publication(BOARD)
            .unwrap()
            .unwrap()
            .revision,
        1
    );
}

#[test]
fn incomplete_attachment_manifest_and_invalid_threads_preserve_confirmed_snapshot() {
    let fixture = Fixture::new();
    fixture.publish();
    let mut missing_file = projection();
    missing_file["files"] = json!([{"id":"public-file","parentId":BOARD,"title":"Missing","fileName":"missing.txt","mediaType":"text/plain","byteLength":1,"sha256":digest(b"x")}]);
    assert!(
        fixture
            .mutate(fixture.request("update", Some(missing_file), fixture.challenge()))
            .is_err()
    );
    let mut invalid_thread = projection();
    invalid_thread["discussions"] = json!([{"id":"message","threadId":"missing-root","replyTo":null,"targets":[{"type":"board","id":BOARD}],"author":"Author","createdAt":"2026-10-10T10:00:00Z","body":"Invalid thread"}]);
    assert!(
        fixture
            .mutate(fixture.request("update", Some(invalid_thread), fixture.challenge()))
            .is_err()
    );
    assert_eq!(
        fixture
            .store
            .current_publication(BOARD)
            .unwrap()
            .unwrap()
            .revision,
        1
    );
}

#[test]
fn withdrawal_keeps_revision_continuity_and_prevents_stale_resurrection() {
    let fixture = Fixture::new();
    fixture.publish();
    let stale = fixture.request("update", Some(projection()), fixture.challenge());
    let withdrawn = fixture
        .mutate(fixture.request("unpublish", None, fixture.challenge()))
        .unwrap();
    assert_eq!(withdrawn.payload["revision"], 2);
    assert!(fixture.mutate(stale).is_err());
    assert!(
        fixture
            .mutate(fixture.request("update", Some(projection()), fixture.challenge()))
            .is_err()
    );
    let republished = fixture
        .mutate(fixture.request("publish", Some(projection()), fixture.challenge()))
        .unwrap();
    assert_eq!(republished.payload["revision"], 3);
}

#[test]
fn competing_opener_cannot_remove_active_writer_temp_file() {
    let fixture = Fixture::new();
    fixture.publish();
    let pending = fixture.directory.join("publications/records/.pending-123");
    fs::write(&pending, b"in-flight first writer").unwrap();
    assert!(BlindStore::open(fixture.directory.clone()).is_err());
    assert_eq!(fs::read(&pending).unwrap(), b"in-flight first writer");
}

#[test]
fn restart_recovers_owned_temp_files_but_rejects_unknown_state_and_missing_service_key() {
    let fixture = Fixture::new();
    fixture.publish();
    let path = fixture.directory.clone();
    let pending = path.join("publications/records/.pending-123");
    fs::write(&pending, b"interrupted write").unwrap();
    drop(fixture.store.clone());
    // Release the writer lock while preserving the fixture's owned directory.
    let replacement_path = std::env::temp_dir().join(format!(
        "rusty-security-replacement-{}",
        rand::random::<u64>()
    ));
    let replacement = BlindStore::open(replacement_path.clone()).unwrap();
    let mut fixture = fixture;
    let old = std::mem::replace(&mut fixture.store, replacement);
    drop(old);
    fs::remove_dir_all(replacement_path).unwrap();
    let restarted = BlindStore::open(path.clone()).unwrap();
    assert!(!pending.exists());
    assert_eq!(
        restarted
            .current_publication(BOARD)
            .unwrap()
            .unwrap()
            .revision,
        1
    );
    drop(restarted);
    let unknown = path.join("publications/records/private.txt");
    fs::write(&unknown, b"preserved").unwrap();
    assert!(BlindStore::open(path.clone()).is_err());
    assert_eq!(fs::read(&unknown).unwrap(), b"preserved");
    fs::remove_file(unknown).unwrap();
    fs::remove_file(path.join("service-key")).unwrap();
    assert!(BlindStore::open(path).is_err());
}

#[cfg(unix)]
#[test]
fn failed_durable_update_issues_no_receipt_and_keeps_previous_publication() {
    use std::os::unix::fs::PermissionsExt;
    let fixture = Fixture::new();
    fixture.publish();
    let request = fixture.request("update", Some(projection()), fixture.challenge());
    let records = fixture.directory.join("publications/records");
    let original = fs::metadata(&records).unwrap().permissions();
    fs::set_permissions(&records, fs::Permissions::from_mode(0o500)).unwrap();
    let result = fixture.mutate(request.clone());
    fs::set_permissions(&records, original).unwrap();
    assert!(
        result.is_err(),
        "Write failure produced a successful receipt"
    );
    assert_eq!(
        fixture
            .store
            .current_publication(BOARD)
            .unwrap()
            .unwrap()
            .revision,
        1
    );
    let recovered = fixture.mutate(request).unwrap();
    assert_eq!(recovered.payload["revision"], 2);
}

#[test]
fn public_asset_staging_checks_exact_bytes_signature_and_replay_but_allows_fresh_idempotent_retry()
{
    let fixture = Fixture::new();
    let request = fixture.asset_request(b"selected bytes");
    let mut corrupted = request.clone();
    corrupted["bytes"] = json!(URL_SAFE_NO_PAD.encode(b"altered bytes"));
    assert!(fixture.stage(corrupted).is_err());
    let mut unsigned = request.clone();
    unsigned["authorization"]["signature"] = json!(URL_SAFE_NO_PAD.encode([0u8; 64]));
    assert!(fixture.stage(unsigned).is_err());
    let receipt = fixture.stage(request.clone()).unwrap();
    assert_eq!(receipt.payload["sha256"], digest(b"selected bytes"));
    assert!(
        verify_signed_envelope(&receipt, &fixture.store.public_key().unwrap(), DOMAIN).unwrap()
    );
    assert!(fixture.stage(request).is_err());
    assert!(
        fixture
            .stage(fixture.asset_request(b"selected bytes"))
            .is_ok()
    );
    assert!(
        fixture
            .store
            .publication_file(BOARD, 1, &digest(b"selected bytes"))
            .is_err()
    );
}

fn age_file(path: &Path) {
    let modified = SystemTime::now() - std::time::Duration::from_secs(25 * 60 * 60);
    File::options()
        .write(true)
        .open(path)
        .unwrap()
        .set_times(std::fs::FileTimes::new().set_modified(modified))
        .unwrap();
}

#[test]
fn freshly_restaged_old_orphan_remains_available_for_an_in_flight_commit() {
    let fixture = Fixture::new();
    fixture.publish();
    let bytes = b"retry an older staged file";
    fixture.stage(fixture.asset_request(bytes)).unwrap();
    let path = fixture
        .directory
        .join("publications/files")
        .join(format!("{}.bin", digest(bytes)));
    age_file(&path);
    fixture.stage(fixture.asset_request(bytes)).unwrap();
    cleanup_orphan_public_files(&fixture.directory).unwrap();
    assert!(
        path.exists(),
        "Cleanup erased a freshly restaged in-flight asset"
    );
}

#[test]
fn orphan_cleanup_is_bounded_and_preserves_active_and_recent_files() {
    let fixture = Fixture::new();
    let bytes = b"active published attachment";
    fixture.stage(fixture.asset_request(bytes)).unwrap();
    let mut active = projection();
    active["files"] = json!([{"id":"file","parentId":BOARD,"title":"Active","fileName":"active.txt","mediaType":"text/plain","byteLength":bytes.len(),"sha256":digest(bytes)}]);
    fixture
        .mutate(fixture.request("publish", Some(active), fixture.challenge()))
        .unwrap();
    let files = fixture.directory.join("publications/files");
    let active_path = files.join(format!("{}.bin", digest(bytes)));
    age_file(&active_path);
    fixture
        .stage(fixture.asset_request(b"recent orphan"))
        .unwrap();
    let fresh_path = files.join(format!("{}.bin", digest(b"recent orphan")));
    for index in 0..34 {
        let bytes = format!("old orphan {index}");
        let path = files.join(format!("{}.bin", digest(bytes.as_bytes())));
        fs::write(&path, bytes.as_bytes()).unwrap();
        age_file(&path);
    }
    cleanup_orphan_public_files(&fixture.directory).unwrap();
    assert!(active_path.exists());
    assert!(fresh_path.exists());
    assert_eq!(
        fs::read_dir(files).unwrap().count(),
        4,
        "Cleanup must remove only 32 of 34 old orphans"
    );
    assert_eq!(
        fixture
            .store
            .publication_file(BOARD, 1, &digest(bytes))
            .unwrap()
            .0,
        bytes
    );
}
