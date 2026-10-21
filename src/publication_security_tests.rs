use super::*;
use meta_mesh_core::{
    AutomationGrantColumns, AutomationGrantScope, DeviceCertificatePayload, WorkspaceGrant,
    WorkspaceGrantPayload, WorkspaceRole, sign_device_certificate,
};

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
fn given_forged_root_certificate_when_valid_certificate_is_appended_then_publication_stays_denied()
{
    let fixture = Fixture::new();
    let public_key = public_key_from_seed(&[63; 32]).unwrap();
    let device_id = public_key_id(&public_key).unwrap();
    let certificate = sign_device_certificate(
        &[60; 32],
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
    owner: ResourceOwner,
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
            owner: ResourceOwner { identity },
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
fn automation_projection(card: Option<Value>) -> Value {
    let mut cards = vec![json!({
        "id":"existing-card", "parentId":null, "columnId":"lead", "title":"Existing",
        "body":"Existing role", "values":{"source":"old", "private":null}, "rank":"0/1"
    })];
    if let Some(card) = card {
        cards.push(card);
    }
    json!({"kind":"tincanban-public-board","version":1,
        "board":{"id":BOARD,"title":"Automation board","presentation":{"archiveColumnId":null}},
        "columns":[
            {"id":"lead","title":"Lead","rank":"0/1"},
            {"id":"applied","title":"Applied","rank":"1/2"},
            {"id":"interview","title":"Interview","rank":"1/1"},
            {"id":"rejected","title":"Rejected","rank":"3/2"}
        ],
        "fields":[
            {"id":"source","title":"Source","valueType":"text","required":false,"rank":"0/1","options":[]},
            {"id":"private","title":"Private","valueType":"text","required":false,"rank":"1/2","options":[]}
        ],
        "cards":cards,"discussions":[],"files":[]})
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

#[test]
fn public_file_links_remain_current_only_while_their_hash_is_in_the_active_manifest() {
    let fixture = Fixture::new();
    let bytes = b"stable public attachment";
    let sha256 = digest(bytes);
    fixture.stage(fixture.asset_request(bytes)).unwrap();

    let mut published = projection();
    published["files"] = json!([{"id":"file","parentId":BOARD,"title":"Handout",
        "fileName":"handout.txt","mediaType":"text/plain","byteLength":bytes.len(),"sha256":sha256}]);
    fixture
        .mutate(fixture.request("publish", Some(published.clone()), fixture.challenge()))
        .unwrap();

    published["board"]["title"] = json!("Updated board title");
    fixture
        .mutate(fixture.request("update", Some(published), fixture.challenge()))
        .unwrap();

    // Revision is a cache-busting hint. Existing links keep working while the
    // same bytes remain part of the active, non-withdrawn projection.
    assert_eq!(
        fixture.store.publication_file(BOARD, 1, &sha256).unwrap().0,
        bytes
    );
    assert_eq!(
        fixture.store.publication_file(BOARD, 2, &sha256).unwrap().0,
        bytes
    );
    assert!(fixture.store.publication_file(BOARD, 0, &sha256).is_err());
    assert!(fixture.store.publication_file(BOARD, 3, &sha256).is_err());

    let mut without_file = projection();
    without_file["board"]["title"] = json!("File removed");
    fixture
        .mutate(fixture.request("update", Some(without_file), fixture.challenge()))
        .unwrap();
    assert!(fixture.store.publication_file(BOARD, 1, &sha256).is_err());

    fixture
        .mutate(fixture.request("unpublish", None, fixture.challenge()))
        .unwrap();
    assert!(fixture.store.publication_file(BOARD, 1, &sha256).is_err());
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

#[test]
fn given_visitor_presentation_when_validating_publication_then_keep_only_public_references() {
    let mut projection = json!({"kind":"tincanban-public-board","version":1,
        "board":{"id":BOARD,"title":"Jobs","presentation":{"entityName":"lead",
            "preset":{"key":"job-search","version":1,"bindings":{"status.applied":"column","field.company":"company"}}}},
        "columns":[{"id":"column","title":"Applied","rank":"0/1","color":"#66b3ff","collapsible":true}],
        "fields":[{"id":"company","title":"Company","valueType":"text","required":true,"rank":"0/1","options":[]}],
        "cards":[{"id":"card","parentId":null,"columnId":"column","title":"Acme","body":"","values":{"company":"Acme"},"rank":"0/1","createdAt":"2026-10-15","updatedAt":"2026-10-15"}],
        "discussions":[],"files":[]});
    assert!(validate_public_projection(&projection).is_ok());
    let fixture = Fixture::new();
    let request = fixture.request("publish", Some(projection.clone()), fixture.challenge());
    assert!(fixture.mutate(request).is_ok());
    assert_eq!(
        fixture
            .store
            .current_publication(BOARD)
            .unwrap()
            .unwrap()
            .projection,
        Some(projection.clone())
    );
    projection["board"]["presentation"]["preset"]["bindings"]["field.company"] =
        json!("private-field");
    assert!(validate_public_projection(&projection).is_err());
    projection["board"]["presentation"]["preset"]["bindings"]["field.company"] = json!("company");
    projection["board"]["presentation"]["ownerKey"] = json!("private");
    assert!(validate_public_projection(&projection).is_err());
}

#[test]
fn given_public_discussion_author_metadata_when_validating_publication_then_accept_bounded_avatar_links()
 {
    let author_id = "A".repeat(43);
    let mut projection = json!({"kind":"tincanban-public-board","version":1,
        "board":{"id":BOARD,"title":"Jobs"},"columns":[],"fields":[],"cards":[],
        "discussions":[{"id":"message","threadId":"message","replyTo":null,
            "targets":[{"type":"board","id":BOARD}],"authorId":author_id,"author":"Alice",
            "createdAt":"2026-10-16T10:00:00Z","body":"Hi"}],
        "discussionAuthors":[{"id":author_id,
            "avatarData":"data:image/webp;base64,UklGRhYAAABXRUJQVlA4WAoAAAAAAAAAfwAAfwAA"}],
        "files":[]});
    assert!(validate_public_projection(&projection).is_ok());

    projection["discussionAuthors"] = json!([]);
    assert!(validate_public_projection(&projection).is_ok());
    projection["discussionAuthors"] = json!([{"id":author_id,
        "avatarData":"data:image/webp;base64,UklGRhYAAABXRUJQVlA4WAoAAAAAAAAAfwAAfwAA"}]);
    projection["discussionAuthors"][0]["avatarData"] = json!("data:image/svg+xml;base64,PHN2Zz4=");
    assert!(validate_public_projection(&projection).is_err());

    projection["discussionAuthors"][0]["avatarData"] =
        json!("data:image/webp;base64,UklGRhYAAABXRUJQVlA4WAoAAAAAAAAAfwAAfwAA");
    projection["discussions"][0]["authorId"] = json!("unknown-author");
    assert!(validate_public_projection(&projection).is_err());
}

#[test]
fn given_shared_archive_surface_when_validating_projection_then_require_archive_roots() {
    let projection = json!({"kind":"tincanban-public-board","version":1,
        "board":{"id":BOARD,"title":"Jobs","presentation":{"archiveColumnId":"archive"}},
        "columns":[{"id":"archive","title":"Archive","rank":"1/1","archive":true}],
        "fields":[],
        "cards":[{"id":"archived","parentId":null,"columnId":"archive","title":"Old","body":"","values":{},"rank":"0/1"}],
        "discussions":[],"files":[]});
    assert!(validate_public_projection(&projection).is_ok());

    let mut nested = projection;
    nested["cards"][0]["parentId"] = json!("parent");
    assert!(validate_public_projection(&nested).is_err());
}

#[test]
fn given_owner_challenge_when_source_frontier_is_supplied_then_bind_it_privately() {
    let fixture = Fixture::new();
    let source_heads = vec!["a".repeat(64), "b".repeat(64)];
    let challenge = fixture
        .store
        .create_public_challenge_unlocked(
            BOARD,
            &fixture.owner.identity.person_id,
            &fixture.device_id,
            &fixture.device_id,
            ORIGIN,
            None,
            Some(&source_heads),
        )
        .unwrap();
    assert_eq!(challenge.payload["currentSourceHeads"], json!([]));
    assert_eq!(
        challenge.payload["sourceHeadsHash"],
        json!(digest(&serde_json::to_vec(&source_heads).unwrap()))
    );
    assert!(validate_source_heads(&source_heads).is_ok());
    assert!(
        validate_source_heads(&source_heads.iter().rev().cloned().collect::<Vec<_>>()).is_err()
    );
}

#[test]
fn given_owner_signed_board_policy_when_editor_grant_is_current_then_delivery_is_authorized() {
    let fixture = Fixture::new();
    let editor_key = public_key_from_seed(&[71; 32]).unwrap();
    let editor_id = public_key_id(&editor_key).unwrap();
    let grant_payload = WorkspaceGrantPayload {
        kind: "workspace-grant".into(),
        version: 1,
        grant_id: "editor-grant-1".into(),
        workspace_id: "workspace-one".into(),
        person_id: editor_id,
        role: WorkspaceRole::Editor,
        access_epoch: Some(3),
        automation: None,
    };
    let grant = sign_json_envelope(
        &[61; 32],
        serde_json::to_value(&grant_payload).unwrap(),
        &fixture.owner.identity.person_id,
        "MATCH/1",
    )
    .unwrap();
    let grant: WorkspaceGrant =
        serde_json::from_value(serde_json::to_value(grant).unwrap()).unwrap();
    let payload = PublicBoardDeliveryPolicy {
        kind: "rusty-public-board-delivery-policy".into(),
        version: 1,
        workspace_id: "workspace-one".into(),
        board_id: BOARD.into(),
        generation: 1,
        access_epoch: 3,
        enabled: true,
        accepted_grants: vec![grant],
        revoked_grant_ids: vec![],
        revoked_device_ids: vec![],
    };
    let policy = sign_json_envelope(
        &[61; 32],
        serde_json::to_value(payload).unwrap(),
        &fixture.owner.identity.person_id,
        "MATCH/1",
    )
    .unwrap();
    let evidence = PublicBoardDeliveryPolicyEvidence {
        policy: serde_json::from_value(serde_json::to_value(policy).unwrap()).unwrap(),
        owner_certificates: vec![],
    };
    assert!(
        validate_public_board_delivery_policy(
            &evidence,
            &fixture.owner,
            BOARD,
            None,
            1_800_000_000_000,
        )
        .is_ok()
    );
}

#[test]
fn given_revoked_or_out_of_scope_grant_when_validating_delivery_policy_then_reject() {
    let fixture = Fixture::new();
    let editor_id = public_key_id(&public_key_from_seed(&[71; 32]).unwrap()).unwrap();
    let automation_payload = WorkspaceGrantPayload {
        kind: "workspace-grant".into(),
        version: 1,
        grant_id: "automation-grant-1".into(),
        workspace_id: "workspace-one".into(),
        person_id: editor_id,
        role: WorkspaceRole::Automation,
        access_epoch: Some(3),
        automation: Some(AutomationGrantScope {
            version: 1,
            board_id: "another-board".into(),
            columns: AutomationGrantColumns {
                lead: "lead".into(),
                applied: None,
                interview: "interview".into(),
                rejected: "rejected".into(),
            },
            field_ids: vec!["field".into()],
            expires_at: 1_900_000_000_000,
        }),
    };
    let grant = sign_json_envelope(
        &[61; 32],
        serde_json::to_value(automation_payload).unwrap(),
        &fixture.owner.identity.person_id,
        "MATCH/1",
    )
    .unwrap();
    let grant: WorkspaceGrant =
        serde_json::from_value(serde_json::to_value(grant).unwrap()).unwrap();
    let payload = PublicBoardDeliveryPolicy {
        kind: "rusty-public-board-delivery-policy".into(),
        version: 1,
        workspace_id: "workspace-one".into(),
        board_id: BOARD.into(),
        generation: 1,
        access_epoch: 3,
        enabled: true,
        accepted_grants: vec![grant],
        revoked_grant_ids: vec!["automation-grant-1".into()],
        revoked_device_ids: vec![],
    };
    let policy = sign_json_envelope(
        &[61; 32],
        serde_json::to_value(payload).unwrap(),
        &fixture.owner.identity.person_id,
        "MATCH/1",
    )
    .unwrap();
    let evidence = PublicBoardDeliveryPolicyEvidence {
        policy: serde_json::from_value(serde_json::to_value(policy).unwrap()).unwrap(),
        owner_certificates: vec![],
    };
    assert!(
        validate_public_board_delivery_policy(
            &evidence,
            &fixture.owner,
            BOARD,
            None,
            1_800_000_000_000,
        )
        .is_err()
    );
}

#[test]
fn given_active_delivery_policy_when_editor_updates_then_allow_content_but_reject_withdrawal() {
    let fixture = Fixture::new();
    let writer = DeliveryWriter::editor(&fixture);
    let mut publish = fixture.request("publish", Some(projection()), fixture.challenge());
    attach_delivery_policy(&fixture, &mut publish, &writer.policy);
    fixture.mutate(publish).unwrap();

    let updated = fixture
        .mutate(writer.request(&fixture, "update", Some(projection())))
        .unwrap();
    assert_eq!(updated.payload["revision"], 2);
    let asset = fixture
        .stage(writer.asset_request(&fixture, b"writer selected bytes"))
        .unwrap();
    assert_eq!(asset.payload["kind"], "rusty-public-asset-receipt");
    assert_eq!(
        fixture
            .store
            .current_publication(BOARD)
            .unwrap()
            .unwrap()
            .controller_person_id,
        fixture.owner.identity.person_id
    );

    let withdrawal = writer.request(&fixture, "unpublish", None);
    assert!(fixture.mutate(withdrawal).is_err());
    assert_eq!(
        fixture
            .store
            .current_publication(BOARD)
            .unwrap()
            .unwrap()
            .revision,
        2
    );
}

#[test]
fn given_automation_scope_when_public_board_delta_stays_scoped_then_allow_but_reject_extra_field() {
    let fixture = Fixture::new();
    let writer = DeliveryWriter::automation(&fixture);
    let before = automation_projection(None);
    let mut publish = fixture.request("publish", Some(before.clone()), fixture.challenge());
    attach_delivery_policy(&fixture, &mut publish, &writer.policy);
    fixture.mutate(publish).unwrap();

    let scoped = automation_projection(Some(json!({
        "id":"automated-card", "parentId":null, "columnId":"lead", "title":"Acme",
        "body":"Role", "values":{"source":"https://example.test"}, "rank":"0/1"
    })));
    let accepted = fixture.mutate(writer.request(&fixture, "update", Some(scoped.clone())));
    assert!(
        accepted.is_ok(),
        "scoped automation update should pass: {accepted:?}"
    );

    let unscoped = automation_projection(Some(json!({
        "id":"automated-card", "parentId":null, "columnId":"lead", "title":"Acme",
        "body":"Role", "values":{"source":"https://example.test", "private":"leak"}, "rank":"0/1"
    })));
    assert!(
        fixture
            .mutate(writer.request(&fixture, "update", Some(unscoped)))
            .is_err()
    );
}

#[test]
fn given_signed_delivery_policy_when_reading_status_then_content_hash_ignores_resigning_but_binds_rights()
 {
    let fixture = Fixture::new();
    let writer = DeliveryWriter::editor(&fixture);
    let mut publish = fixture.request("publish", Some(projection()), fixture.challenge());
    attach_delivery_policy(&fixture, &mut publish, &writer.policy);
    fixture.mutate(publish).unwrap();

    let challenge = fixture.challenge();
    let expected = public_delivery_policy_content_hash(&writer.policy).unwrap();
    assert_eq!(challenge.payload["deliveryPolicyContentHash"], expected);
    let mut resigned = writer.policy.clone();
    // Stored policies are already authenticated. Signature bytes identify the wire
    // envelope, not the policy's meaning (CryptoKit randomizes Ed25519 signatures).
    resigned.policy.signature = "different-signature".into();
    assert_eq!(
        public_delivery_policy_content_hash(&resigned).unwrap(),
        expected
    );
    resigned
        .policy
        .payload
        .revoked_grant_ids
        .push("revoked-grant".into());
    assert_ne!(
        public_delivery_policy_content_hash(&resigned).unwrap(),
        expected
    );
    resigned = writer.policy.clone();
    resigned.policy.signer_key_id = "different-device".into();
    assert_ne!(
        public_delivery_policy_content_hash(&resigned).unwrap(),
        expected
    );
}

fn attach_delivery_policy(
    fixture: &Fixture,
    request: &mut Value,
    policy: &PublicBoardDeliveryPolicyEvidence,
) {
    let evidence = serde_json::to_value(policy).unwrap();
    request["deliveryPolicy"] = evidence.clone();
    let mut command = request["authorization"]["payload"].clone();
    command["deliveryPolicyHash"] = json!(digest(canonicalize_json(&evidence).unwrap().as_bytes()));
    request["authorization"] = serde_json::to_value(
        sign_json_envelope(&[62; 32], command, &fixture.device_id, "MATCH/1").unwrap(),
    )
    .unwrap();
}

struct DeliveryWriter {
    identity: PublicIdentity,
    device_id: String,
    device_seed: [u8; 32],
    certificate: meta_mesh_core::DeviceCertificate,
    grant: WorkspaceGrant,
    policy: PublicBoardDeliveryPolicyEvidence,
    source_heads: Vec<String>,
}

impl DeliveryWriter {
    fn editor(fixture: &Fixture) -> Self {
        Self::new(fixture, WorkspaceRole::Editor)
    }

    fn automation(fixture: &Fixture) -> Self {
        Self::new(fixture, WorkspaceRole::Automation)
    }

    fn new(fixture: &Fixture, role: WorkspaceRole) -> Self {
        let person_key = public_key_from_seed(&[71; 32]).unwrap();
        let person_id = public_key_id(&person_key).unwrap();
        let device_seed = [72; 32];
        let device_key = public_key_from_seed(&device_seed).unwrap();
        let device_id = public_key_id(&device_key).unwrap();
        let certificate = sign_device_certificate(
            &[71; 32],
            DeviceCertificatePayload {
                kind: "device-certificate".into(),
                version: 1,
                person_id: person_id.clone(),
                device_id: device_id.clone(),
                device_public_key: device_key,
                issuer_certificate_hash: None,
                can_enroll_devices: true,
            },
            &person_id,
            "MATCH/1",
        )
        .unwrap();
        let identity = serde_json::from_value(json!({
            "personId": person_id,
            "publicKey": person_key,
            "displayName": "Editor"
        }))
        .unwrap();
        let grant_payload = WorkspaceGrantPayload {
            kind: "workspace-grant".into(),
            version: 1,
            grant_id: "editor-grant-1".into(),
            workspace_id: "workspace-one".into(),
            person_id,
            role,
            access_epoch: Some(3),
            automation: (role == WorkspaceRole::Automation).then_some(AutomationGrantScope {
                version: 1,
                board_id: BOARD.into(),
                columns: AutomationGrantColumns {
                    lead: "lead".into(),
                    applied: Some("applied".into()),
                    interview: "interview".into(),
                    rejected: "rejected".into(),
                },
                field_ids: vec!["source".into()],
                expires_at: 1_900_000_000_000,
            }),
        };
        let grant: WorkspaceGrant = serde_json::from_value(
            serde_json::to_value(
                sign_json_envelope(
                    &[61; 32],
                    serde_json::to_value(&grant_payload).unwrap(),
                    &fixture.owner.identity.person_id,
                    "MATCH/1",
                )
                .unwrap(),
            )
            .unwrap(),
        )
        .unwrap();
        let policy_payload = PublicBoardDeliveryPolicy {
            kind: "rusty-public-board-delivery-policy".into(),
            version: 1,
            workspace_id: "workspace-one".into(),
            board_id: BOARD.into(),
            generation: 1,
            access_epoch: 3,
            enabled: true,
            accepted_grants: vec![grant.clone()],
            revoked_grant_ids: vec![],
            revoked_device_ids: vec![],
        };
        let policy = PublicBoardDeliveryPolicyEvidence {
            policy: serde_json::from_value(
                serde_json::to_value(
                    sign_json_envelope(
                        &[61; 32],
                        serde_json::to_value(policy_payload).unwrap(),
                        &fixture.owner.identity.person_id,
                        "MATCH/1",
                    )
                    .unwrap(),
                )
                .unwrap(),
            )
            .unwrap(),
            owner_certificates: vec![],
        };
        Self {
            identity,
            device_id,
            device_seed,
            certificate,
            grant,
            policy,
            source_heads: vec!["a".repeat(64), "b".repeat(64)],
        }
    }

    fn challenge(&self, fixture: &Fixture) -> SignedEnvelope<Value> {
        let request: PublicChallengeRequest = serde_json::from_value(json!({
            "version": 1,
            "boardId": BOARD,
            "identity": self.identity,
            "deviceId": self.device_id,
            "certificates": [self.certificate],
            "deliveryGrant": self.grant,
            "sourceHeads": self.source_heads,
        }))
        .unwrap();
        fixture
            .store
            .create_public_delivery_challenge(request, &fixture.owner, ORIGIN)
            .unwrap()
    }

    fn request(&self, fixture: &Fixture, action: &str, projection: Option<Value>) -> Value {
        self.request_with_challenge(self.challenge(fixture), action, projection)
    }

    fn request_with_challenge(
        &self,
        challenge: SignedEnvelope<Value>,
        action: &str,
        projection: Option<Value>,
    ) -> Value {
        let projection_hash = projection
            .as_ref()
            .map(|value| digest(canonicalize_json(value).unwrap().as_bytes()))
            .unwrap_or_else(|| digest(b"null"));
        let source_heads_hash = digest(&serde_json::to_vec(&self.source_heads).unwrap());
        let payload = &challenge.payload;
        let authorization = sign_json_envelope(
            &self.device_seed,
            json!({
                "kind":"rusty-publication-command", "version":1,
                "challengeId":payload["challengeId"], "nonce":payload["nonce"],
                "serviceId":payload["serviceId"], "publicOrigin":ORIGIN, "boardId":BOARD,
                "action":action, "projectionHash":projection_hash,
                "expectedRevision":payload["expectedRevision"], "expiresAt":payload["expiresAt"],
                "deliveryGeneration":1, "deliveryGrantId":"editor-grant-1",
                "sourceHeadsHash":source_heads_hash
            }),
            &self.device_id,
            "MATCH/1",
        )
        .unwrap();
        json!({
            "challenge":challenge,
            "identity":self.identity,
            "deviceId":self.device_id,
            "certificates":[self.certificate],
            "deliveryGrant":self.grant,
            "sourceHeads":self.source_heads,
            "action":action,
            "projection":projection,
            "authorization":authorization
        })
    }

    fn asset_request(&self, fixture: &Fixture, bytes: &[u8]) -> Value {
        let challenge = self.challenge(fixture);
        let hash = digest(bytes);
        let payload = &challenge.payload;
        let source_heads_hash = digest(&serde_json::to_vec(&self.source_heads).unwrap());
        let authorization = sign_json_envelope(
            &self.device_seed,
            json!({
                "kind":"rusty-publication-command", "version":1,
                "challengeId":payload["challengeId"], "nonce":payload["nonce"],
                "serviceId":payload["serviceId"], "publicOrigin":ORIGIN, "boardId":BOARD,
                "action":"stage-file", "projectionHash":hash,
                "expectedRevision":payload["expectedRevision"], "expiresAt":payload["expiresAt"],
                "byteLength":bytes.len(), "deliveryGeneration":1,
                "deliveryGrantId":"editor-grant-1", "sourceHeadsHash":source_heads_hash
            }),
            &self.device_id,
            "MATCH/1",
        )
        .unwrap();
        json!({
            "challenge":challenge,
            "identity":self.identity,
            "deviceId":self.device_id,
            "certificates":[self.certificate],
            "deliveryGrant":self.grant,
            "sourceHeads":self.source_heads,
            "sha256":hash,
            "byteLength":bytes.len(),
            "bytes":URL_SAFE_NO_PAD.encode(bytes),
            "authorization":authorization
        })
    }
}

#[test]
fn given_configured_card_fields_when_publishing_then_preserve_declared_formats_and_reject_private_references()
 {
    let mut projection = json!({"kind":"tincanban-public-board","version":1,
        "board":{"id":BOARD,"title":"Configured board","presentation":{
            "preset":{"key":"custom","version":1,"bindings":{}},
            "cardPresentation":{"titleFieldIds":["source"],"summaryFieldIds":["source"],"narrativeFieldId":"source","openAfterSave":true}}},
        "columns":[{"id":"column","title":"Queue","rank":"0/1"}],
        "fields":[{"id":"source","title":"Source text","valueType":"text","format":"plain","required":false,"rank":"0/1","options":[]}],
        "cards":[],"discussions":[],"files":[]});
    for format in ["plain", "markdown", "json", "code"] {
        projection["fields"][0]["format"] = json!(format);
        assert!(validate_public_projection(&projection).is_ok());
    }
    projection["fields"][0]["format"] = json!("script");
    assert!(validate_public_projection(&projection).is_err());
    projection["fields"][0]["format"] = json!("plain");
    projection["fields"][0]["valueType"] = json!("boolean");
    assert!(validate_public_projection(&projection).is_err());
    projection["fields"][0]["valueType"] = json!("text");
    projection["board"]["presentation"]["cardPresentation"]["narrativeFieldId"] =
        json!("private-field");
    assert!(validate_public_projection(&projection).is_err());
}

#[tokio::test]
async fn given_stored_board_owner_when_editor_delivers_over_http_then_use_scoped_owner_without_global_pin()
 {
    let fixture = Fixture::new();
    let writer = DeliveryWriter::editor(&fixture);
    let mut publication = fixture.request("publish", Some(projection()), fixture.challenge());
    attach_delivery_policy(&fixture, &mut publication, &writer.policy);
    fixture.mutate(publication).unwrap();
    let app = router(fixture.store.clone(), ORIGIN.into(), vec![]).unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    let client = reqwest::Client::new();
    let now = now_ms().unwrap();
    let authorization = sign_json_envelope(&[62;32], json!({
        "kind":"rusty-management-policy-update", "version":1,
        "serviceId":public_key_id(&fixture.store.public_key().unwrap()).unwrap(), "origin":ORIGIN,
        "personId":fixture.owner.identity.person_id, "deviceId":fixture.device_id,
        "resourceKind":"board", "resourceId":BOARD, "expectedRevision":0,
        "operations":["management.update", "publication.status", "publication.update"],
        "revokedDeviceIds":[], "requestId":URL_SAFE_NO_PAD.encode(rand::random::<[u8;32]>()),
        "issuedAt":now, "expiresAt":now+60000,
    }), &fixture.device_id, "MATCH/1").unwrap();
    let owner_request = json!({
        "version":1, "identity":fixture.owner.identity, "deviceId":fixture.device_id,
        "certificates":[fixture.certificate], "authorization":authorization,
    });
    let mut foreign_request = owner_request.clone();
    foreign_request["identity"] = serde_json::to_value(&writer.identity).unwrap();
    foreign_request["deviceId"] = json!(writer.device_id);
    foreign_request["certificates"] = json!([writer.certificate]);
    foreign_request["authorization"]["payload"]["personId"] = json!(writer.identity.person_id);
    foreign_request["authorization"]["payload"]["deviceId"] = json!(writer.device_id);
    foreign_request["authorization"] = serde_json::to_value(
        sign_json_envelope(
            &writer.device_seed,
            foreign_request["authorization"]["payload"].clone(),
            &writer.device_id,
            "MATCH/1",
        )
        .unwrap(),
    )
    .unwrap();
    assert_eq!(
        client
            .put(format!("{url}/v2/management/board/{BOARD}"))
            .json(&foreign_request)
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::FORBIDDEN,
        "an existing legacy publication cannot be claimed by another identity during first management setup"
    );
    let response = client
        .put(format!("{url}/v2/management/board/{BOARD}"))
        .json(&owner_request)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let response = client
        .post(format!("{url}/v1/public/challenges"))
        .json(&json!({
            "version":1, "boardId":BOARD, "identity":writer.identity, "deviceId":writer.device_id,
            "certificates":[writer.certificate], "deliveryGrant":writer.grant,
            "sourceHeads":writer.source_heads,
        }))
        .send()
        .await
        .unwrap();
    let status = response.status();
    let body = response.text().await.unwrap();
    assert_eq!(
        status,
        StatusCode::OK,
        "editor challenge must use recorded owner: {body}"
    );
    let challenge =
        serde_json::from_value(serde_json::from_str::<Value>(&body).unwrap()["challenge"].clone())
            .unwrap();
    let request = writer.request_with_challenge(challenge, "update", Some(projection()));
    let response = client
        .put(format!("{url}/v1/public/boards/{BOARD}"))
        .json(&request)
        .send()
        .await
        .unwrap();
    let status = response.status();
    let body = response.text().await.unwrap();
    assert_eq!(
        status,
        StatusCode::OK,
        "editor content delivery remains authorized: {body}"
    );
    assert_eq!(
        serde_json::from_str::<Value>(&body).unwrap()["payload"]["revision"],
        2
    );
    let asset = writer.asset_request(&fixture, b"scoped editor bytes");
    let response = client
        .put(format!("{url}/v1/public/boards/{BOARD}/files"))
        .json(&asset)
        .send()
        .await
        .unwrap();
    let status = response.status();
    let body = response.text().await.unwrap();
    assert_eq!(
        status,
        StatusCode::OK,
        "editor staging does not require owner's management capability: {body}"
    );
    let takeover = writer.request(&fixture, "unpublish", None);
    assert!(
        client
            .put(format!("{url}/v1/public/boards/{BOARD}"))
            .json(&takeover)
            .send()
            .await
            .unwrap()
            .status()
            .is_client_error()
    );
    assert_eq!(
        fixture
            .store
            .current_publication(BOARD)
            .unwrap()
            .unwrap()
            .controller_person_id,
        fixture.owner.identity.person_id
    );
    server.abort();
    let _ = server.await;
}
