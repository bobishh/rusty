use super::tests::{approve_fixture, encrypted_fixture, owner_controller_fixture};
use super::*;

fn checkpoint_fixture() -> (PathBuf, BlindStore, TrustedOwner, Value) {
    let directory =
        std::env::temp_dir().join(format!("rusty-checkpoint-crash-{}", rand::random::<u64>()));
    let store = BlindStore::open(directory.clone()).unwrap();
    approve_fixture(&store);
    let (identity, device_id, certificate, person_id) = owner_controller_fixture();
    let mut policy = store.policy("opaque-scope").unwrap();
    policy.owner_person_id = Some(person_id);
    atomic_write(
        &store.scope_dir("opaque-scope").unwrap().join("policy.json"),
        &serde_json::to_vec(&policy).unwrap(),
    )
    .unwrap();
    for nonce in [1u8, 3] {
        let mut object = encrypted_fixture();
        object.nonce = URL_SAFE_NO_PAD.encode([nonce; 12]);
        store
            .save("opaque-scope", &"w".repeat(43), object, "ordinary")
            .unwrap();
    }
    let mut object = encrypted_fixture();
    object.nonce = URL_SAFE_NO_PAD.encode([4u8; 12]);
    let issued = now_ms().unwrap();
    let proof = sign_json_envelope(&[32;32], json!({"kind":"rusty-snapshot-checkpoint","version":1,
        "serviceId":public_key_id(&store.public_key().unwrap()).unwrap(),"origin":"https://rusty.example",
        "scopeId":"opaque-scope","keyEpoch":1,"policyRevision":1,"expectedSequence":2,
        "objectId":object.id().unwrap(),"requestId":"checkpoint-crash","issuedAt":issued,"expiresAt":issued+120000}), &device_id,"MATCH/1").unwrap();
    let trusted = TrustedOwner {
        identity: serde_json::from_value(identity.clone()).unwrap(),
        allowed_controller_device_ids: vec![device_id.clone()],
    };
    (
        directory,
        store,
        trusted,
        json!({"object":object,"identity":identity,"deviceId":device_id,"certificates":[certificate],"authorization":proof}),
    )
}

#[test]
fn checkpoint_owner_signature_binding_expiry_and_current_policy_fail_closed() {
    let (directory, store, trusted, request) = checkpoint_fixture();
    for patch in [
        json!({"origin":"https://foreign.example"}),
        json!({"scopeId":"foreign-scope"}),
        json!({"serviceId":"foreign-service"}),
        json!({"keyEpoch":2}),
        json!({"policyRevision":2}),
        json!({"issuedAt":0,"expiresAt":1}),
        json!({"expiresAt":now_ms().unwrap()+600_000}),
    ] {
        let mut altered = request.clone();
        let mut payload = altered["authorization"]["payload"].clone();
        for (key, value) in patch.as_object().unwrap() {
            payload[key] = value.clone();
        }
        altered["authorization"] = serde_json::to_value(
            sign_json_envelope(
                &[32; 32],
                payload,
                request["deviceId"].as_str().unwrap(),
                "MATCH/1",
            )
            .unwrap(),
        )
        .unwrap();
        assert!(
            store
                .checkpoint(
                    "opaque-scope",
                    &"w".repeat(43),
                    serde_json::from_value(altered).unwrap(),
                    &trusted,
                    "https://rusty.example"
                )
                .is_err()
        );
        assert_eq!(store.objects("opaque-scope").unwrap().len(), 2);
    }
    let mut forged = request.clone();
    forged["authorization"]["signature"] = json!(URL_SAFE_NO_PAD.encode([0; 64]));
    assert!(
        store
            .checkpoint(
                "opaque-scope",
                &"w".repeat(43),
                serde_json::from_value(forged).unwrap(),
                &trusted,
                "https://rusty.example"
            )
            .is_err()
    );
    assert!(
        store
            .checkpoint(
                "opaque-scope",
                &"r".repeat(43),
                serde_json::from_value(request.clone()).unwrap(),
                &trusted,
                "https://rusty.example"
            )
            .is_err()
    );
    let mut wrong_root = trusted.clone();
    wrong_root.identity.public_key = public_key_from_seed(&[55; 32]).unwrap();
    assert!(
        store
            .checkpoint(
                "opaque-scope",
                &"w".repeat(43),
                serde_json::from_value(request.clone()).unwrap(),
                &wrong_root,
                "https://rusty.example"
            )
            .is_err()
    );
    let mut unlisted = trusted.clone();
    unlisted.allowed_controller_device_ids.clear();
    assert!(
        store
            .checkpoint(
                "opaque-scope",
                &"w".repeat(43),
                serde_json::from_value(request).unwrap(),
                &unlisted,
                "https://rusty.example"
            )
            .is_err()
    );
    assert_eq!(store.objects("opaque-scope").unwrap().len(), 2);
    drop(store);
    fs::remove_dir_all(directory).unwrap();
}

#[test]
fn concurrent_checkpoint_candidates_have_one_winner_and_an_explicit_conflict() {
    let (directory, store, trusted, request) = checkpoint_fixture();
    let barrier = Arc::new(std::sync::Barrier::new(3));
    let mut threads = Vec::new();
    for nonce in [8u8, 9] {
        let store = store.clone();
        let trusted = trusted.clone();
        let barrier = barrier.clone();
        let mut request = request.clone();
        request["object"]["nonce"] = json!(URL_SAFE_NO_PAD.encode([nonce; 12]));
        let object: BlindObject = serde_json::from_value(request["object"].clone()).unwrap();
        let mut payload = request["authorization"]["payload"].clone();
        payload["objectId"] = json!(object.id().unwrap());
        request["authorization"] = serde_json::to_value(
            sign_json_envelope(
                &[32; 32],
                payload,
                request["deviceId"].as_str().unwrap(),
                "MATCH/1",
            )
            .unwrap(),
        )
        .unwrap();
        threads.push(std::thread::spawn(move || {
            barrier.wait();
            store.checkpoint(
                "opaque-scope",
                &"w".repeat(43),
                serde_json::from_value(request).unwrap(),
                &trusted,
                "https://rusty.example",
            )
        }));
    }
    barrier.wait();
    let results = threads
        .into_iter()
        .map(|thread| thread.join().unwrap())
        .collect::<Vec<_>>();
    assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
    assert_eq!(
        results
            .iter()
            .filter(|result| result
                .as_ref()
                .err()
                .is_some_and(|error| error.starts_with("Checkpoint inventory changed:")))
            .count(),
        1
    );
    assert_eq!(store.objects("opaque-scope").unwrap().len(), 1);
    drop(store);
    fs::remove_dir_all(directory).unwrap();
}

#[test]
fn checkpoint_manifest_failure_retains_old_objects_and_recovers_the_same_durable_ciphertext() {
    for raced in [false, true] {
        let (directory, store, trusted, request) = checkpoint_fixture();
        let manifest = store
            .scope_dir("opaque-scope")
            .unwrap()
            .join("compaction.json");
        fs::create_dir(&manifest).unwrap();
        assert!(
            store
                .checkpoint(
                    "opaque-scope",
                    &"w".repeat(43),
                    serde_json::from_value(request.clone()).unwrap(),
                    &trusted,
                    "https://rusty.example"
                )
                .is_err()
        );
        assert_eq!(store.objects("opaque-scope").unwrap().len(), 2);
        fs::remove_dir(&manifest).unwrap();
        // Reproduce the durable state at a crash after object fsync, before manifest commit.
        let object: BlindObject = serde_json::from_value(request["object"].clone()).unwrap();
        let object_id = object.id().unwrap();
        let record: StoredObject = serde_json::from_value(json!({"sequence":3,"objectId":object_id,"object":object,
        "checkpoint":{"expectedSequence":2,"authorizationHash":digest(canonicalize_json(&request["authorization"]).unwrap().as_bytes())}})).unwrap();
        atomic_write(
            &store
                .scope_dir("opaque-scope")
                .unwrap()
                .join("objects")
                .join(format!("{object_id}.json")),
            &serde_json::to_vec(&record).unwrap(),
        )
        .unwrap();
        store.inventories.lock().unwrap().remove("opaque-scope");
        if raced {
            let mut branch = encrypted_fixture();
            branch.nonce = URL_SAFE_NO_PAD.encode([7u8; 12]);
            store
                .save("opaque-scope", &"w".repeat(43), branch, "after-orphan")
                .unwrap();
        }
        drop(store);
        let store = BlindStore::open(directory.clone()).unwrap();
        let before = store
            .objects("opaque-scope")
            .unwrap()
            .iter()
            .find(|object| object.sequence == 3)
            .unwrap()
            .object_id
            .clone();
        let receipt = store
            .checkpoint(
                "opaque-scope",
                &"w".repeat(43),
                serde_json::from_value(request).unwrap(),
                &trusted,
                "https://rusty.example",
            )
            .unwrap();
        assert_eq!(receipt.payload["objectId"], before);
        assert_eq!(receipt.payload["sequence"], 3);
        assert_eq!(
            store.objects("opaque-scope").unwrap().len(),
            if raced { 2 } else { 1 }
        );
        drop(store);
        fs::remove_dir_all(directory).unwrap();
    }
}

#[test]
fn checkpoint_retry_confirms_visible_replacement_and_manifest_before_pruning() {
    struct ClearFailure;
    impl Drop for ClearFailure {
        fn drop(&mut self) {
            FAILED_DIRECTORY_SYNC.with(|failure| *failure.borrow_mut() = None);
        }
    }
    for replacement_failure in [false, true] {
        let (directory, store, trusted, request) = checkpoint_fixture();
        let scope = store.scope_dir("opaque-scope").unwrap();
        let old_paths: Vec<_> = store
            .objects("opaque-scope")
            .unwrap()
            .iter()
            .map(|object| {
                scope
                    .join("objects")
                    .join(format!("{}.json", object.object_id))
            })
            .collect();
        let _reset = ClearFailure;
        FAILED_DIRECTORY_SYNC.with(|failure| {
            *failure.borrow_mut() = Some(if replacement_failure {
                scope.join("objects")
            } else {
                scope
            })
        });
        for _ in 0..2 {
            assert!(
                store
                    .checkpoint(
                        "opaque-scope",
                        &"w".repeat(43),
                        serde_json::from_value(request.clone()).unwrap(),
                        &trusted,
                        "https://rusty.example"
                    )
                    .is_err(),
                "A visible checkpoint cannot bypass failed durability on retry"
            );
            assert!(
                old_paths.iter().all(|path| path.is_file()),
                "Unconfirmed checkpoint must retain previous objects"
            );
        }
        FAILED_DIRECTORY_SYNC.with(|failure| *failure.borrow_mut() = None);
        let receipt = store
            .checkpoint(
                "opaque-scope",
                &"w".repeat(43),
                serde_json::from_value(request).unwrap(),
                &trusted,
                "https://rusty.example",
            )
            .unwrap();
        assert_eq!(receipt.payload["sequence"], 3);
        assert!(old_paths.iter().all(|path| !path.exists()));
        fs::remove_dir_all(directory).unwrap();
    }
}

#[test]
fn completed_checkpoint_retry_survives_expiry_but_never_bypasses_current_device_authority() {
    let (directory, store, trusted, mut request) = checkpoint_fixture();
    let now = now_ms().unwrap();
    let mut proof = request["authorization"]["payload"].clone();
    proof["issuedAt"] = json!(now);
    proof["expiresAt"] = json!(now + 1000);
    request["authorization"] = serde_json::to_value(
        sign_json_envelope(
            &[32; 32],
            proof,
            request["deviceId"].as_str().unwrap(),
            "MATCH/1",
        )
        .unwrap(),
    )
    .unwrap();
    store
        .checkpoint(
            "opaque-scope",
            &"w".repeat(43),
            serde_json::from_value(request.clone()).unwrap(),
            &trusted,
            "https://rusty.example",
        )
        .unwrap();
    std::thread::sleep(std::time::Duration::from_millis(1100));
    assert_eq!(
        store
            .checkpoint(
                "opaque-scope",
                &"w".repeat(43),
                serde_json::from_value(request.clone()).unwrap(),
                &trusted,
                "https://rusty.example"
            )
            .unwrap()
            .payload["sequence"],
        3
    );
    let mut revoked = trusted.clone();
    revoked.allowed_controller_device_ids.clear();
    assert!(
        store
            .checkpoint(
                "opaque-scope",
                &"w".repeat(43),
                serde_json::from_value(request).unwrap(),
                &revoked,
                "https://rusty.example"
            )
            .is_err()
    );
    assert_eq!(store.objects("opaque-scope").unwrap().len(), 1);
    drop(store);
    fs::remove_dir_all(directory).unwrap();
}

#[test]
fn expired_orphan_checkpoint_requires_fresh_owner_proof_and_never_rolls_back_a_newer_floor() {
    let (directory, store, trusted, mut request) = checkpoint_fixture();
    let device = request["deviceId"].as_str().unwrap().to_owned();
    let mut proof = request["authorization"]["payload"].clone();
    proof["issuedAt"] = json!(0);
    proof["expiresAt"] = json!(1);
    request["authorization"] =
        serde_json::to_value(sign_json_envelope(&[32; 32], proof, &device, "MATCH/1").unwrap())
            .unwrap();
    let original_hash = digest(
        canonicalize_json(&request["authorization"])
            .unwrap()
            .as_bytes(),
    );
    let object: BlindObject = serde_json::from_value(request["object"].clone()).unwrap();
    let object_id = object.id().unwrap();
    let record: StoredObject =
        serde_json::from_value(json!({"sequence":3,"objectId":object_id,"object":object,
        "checkpoint":{"expectedSequence":2,"authorizationHash":original_hash}}))
        .unwrap();
    atomic_write(
        &store
            .scope_dir("opaque-scope")
            .unwrap()
            .join("objects")
            .join(format!("{object_id}.json")),
        &serde_json::to_vec(&record).unwrap(),
    )
    .unwrap();
    store.inventories.lock().unwrap().remove("opaque-scope");
    assert!(
        store
            .checkpoint(
                "opaque-scope",
                &"w".repeat(43),
                serde_json::from_value(request.clone()).unwrap(),
                &trusted,
                "https://rusty.example"
            )
            .unwrap_err()
            .contains("expired")
    );
    assert_eq!(store.objects("opaque-scope").unwrap().len(), 3);
    let mut renewed = request.clone();
    let mut proof = renewed["authorization"]["payload"].clone();
    let now = now_ms().unwrap();
    proof["issuedAt"] = json!(now);
    proof["expiresAt"] = json!(now + 120000);
    proof["requestId"] = json!("renewed-orphan");
    renewed["authorization"] =
        serde_json::to_value(sign_json_envelope(&[32; 32], proof, &device, "MATCH/1").unwrap())
            .unwrap();
    let receipt = store
        .checkpoint(
            "opaque-scope",
            &"w".repeat(43),
            serde_json::from_value(renewed.clone()).unwrap(),
            &trusted,
            "https://rusty.example",
        )
        .unwrap();
    assert_eq!(receipt.payload["objectId"], object_id);
    assert_eq!(
        receipt.payload["authorizationHash"],
        digest(
            canonicalize_json(&renewed["authorization"])
                .unwrap()
                .as_bytes()
        )
    );
    assert_eq!(store.objects("opaque-scope").unwrap().len(), 1);
    let mut newer = renewed.clone();
    newer["object"]["nonce"] = json!(URL_SAFE_NO_PAD.encode([10u8; 12]));
    let object: BlindObject = serde_json::from_value(newer["object"].clone()).unwrap();
    let mut proof = newer["authorization"]["payload"].clone();
    proof["expectedSequence"] = json!(3);
    proof["objectId"] = json!(object.id().unwrap());
    proof["requestId"] = json!("newer-checkpoint");
    newer["authorization"] =
        serde_json::to_value(sign_json_envelope(&[32; 32], proof, &device, "MATCH/1").unwrap())
            .unwrap();
    store
        .checkpoint(
            "opaque-scope",
            &"w".repeat(43),
            serde_json::from_value(newer).unwrap(),
            &trusted,
            "https://rusty.example",
        )
        .unwrap();
    assert!(
        store
            .checkpoint(
                "opaque-scope",
                &"w".repeat(43),
                serde_json::from_value(request).unwrap(),
                &trusted,
                "https://rusty.example"
            )
            .unwrap_err()
            .starts_with("Checkpoint inventory changed:")
    );
    assert_eq!(
        store
            .objects("opaque-scope")
            .unwrap()
            .iter()
            .map(|object| object.sequence)
            .collect::<Vec<_>>(),
        vec![4]
    );
    drop(store);
    fs::remove_dir_all(directory).unwrap();
}

#[test]
fn checkpoint_restart_prunes_leftovers_only_after_validating_the_retained_checkpoint() {
    for corruption in ["none", "missing", "misnamed"] {
        let (directory, store, trusted, request) = checkpoint_fixture();
        let objects_dir = store.scope_dir("opaque-scope").unwrap().join("objects");
        let previous = fs::read_dir(&objects_dir)
            .unwrap()
            .map(|entry| {
                let path = entry.unwrap().path();
                let bytes = fs::read(&path).unwrap();
                (path, bytes)
            })
            .collect::<Vec<_>>();
        let receipt = store
            .checkpoint(
                "opaque-scope",
                &"w".repeat(43),
                serde_json::from_value(request).unwrap(),
                &trusted,
                "https://rusty.example",
            )
            .unwrap();
        for (path, bytes) in &previous {
            fs::write(path, bytes).unwrap();
        }
        if corruption == "missing" {
            fs::remove_file(objects_dir.join(format!(
                "{}.json",
                receipt.payload["objectId"].as_str().unwrap()
            )))
            .unwrap();
        }
        if corruption == "misnamed" {
            fs::rename(
                objects_dir.join(format!(
                    "{}.json",
                    receipt.payload["objectId"].as_str().unwrap()
                )),
                objects_dir.join("misplaced.json"),
            )
            .unwrap();
        }
        drop(store);
        let result = BlindStore::open(directory.clone());
        if corruption != "none" {
            assert!(result.is_err());
            assert!(
                previous.iter().all(|(path, _)| path.exists()),
                "Recovery must not delete old bytes without a valid checkpoint"
            );
        } else {
            let store = result.unwrap();
            assert_eq!(store.objects("opaque-scope").unwrap().len(), 1);
            assert!(previous.iter().all(|(path, _)| !path.exists()));
            drop(store);
        }
        fs::remove_dir_all(directory).unwrap();
    }
}

#[test]
fn checkpoint_can_recover_a_full_scope_without_deleting_before_the_new_object_is_durable() {
    let (directory, store, trusted, request) = checkpoint_fixture();
    let limit = fs::read_dir(store.scope_dir("opaque-scope").unwrap().join("objects"))
        .unwrap()
        .map(|entry| entry.unwrap().metadata().unwrap().len())
        .sum::<u64>();
    drop(store);
    let store = BlindStore::open_with_scope_limit(directory.clone(), limit).unwrap();
    let object: BlindObject = serde_json::from_value(request["object"].clone()).unwrap();
    assert!(
        store
            .save("opaque-scope", &"w".repeat(43), object, "ordinary-full")
            .is_err()
    );
    store
        .checkpoint(
            "opaque-scope",
            &"w".repeat(43),
            serde_json::from_value(request).unwrap(),
            &trusted,
            "https://rusty.example",
        )
        .unwrap();
    assert_eq!(store.objects("opaque-scope").unwrap().len(), 1);
    drop(store);
    fs::remove_dir_all(directory).unwrap();
}

// Given admitted owner checkpoints, storage stays bounded without losing a racing writer.
#[tokio::test]
async fn owner_checkpoint_prunes_confirmed_frontier_retries_and_preserves_concurrent_writes() {
    let directory =
        std::env::temp_dir().join(format!("rusty-checkpoint-{}", rand::random::<u64>()));
    let store = BlindStore::open(directory.clone()).unwrap();
    approve_fixture(&store);
    let (identity, device_id, certificate, person_id) = owner_controller_fixture();
    let policy_path = store.scope_dir("opaque-scope").unwrap().join("policy.json");
    let mut policy = store.policy("opaque-scope").unwrap();
    policy.owner_person_id = Some(person_id);
    atomic_write(&policy_path, &serde_json::to_vec(&policy).unwrap()).unwrap();
    for nonce in [1u8, 3] {
        let mut object = encrypted_fixture();
        object.nonce = URL_SAFE_NO_PAD.encode([nonce; 12]);
        store
            .save("opaque-scope", &"w".repeat(43), object, "ordinary")
            .unwrap();
    }
    let service_key = store.public_key().unwrap();
    let trusted = TrustedOwner {
        identity: serde_json::from_value(identity.clone()).unwrap(),
        allowed_controller_device_ids: vec![device_id.clone()],
    };
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin = format!("http://{}", listener.local_addr().unwrap());
    let app = router(store.clone(), origin.clone(), Some(trusted), vec![]).unwrap();
    let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    let client = reqwest::Client::new();
    let endpoint = format!("{origin}/v2/scopes/opaque-scope/checkpoint");
    let mut object = encrypted_fixture();
    object.nonce = URL_SAFE_NO_PAD.encode([4u8; 12]);
    let issued_at = now_ms().unwrap();
    let payload = json!({"kind":"rusty-snapshot-checkpoint","version":1,
        "serviceId":public_key_id(&service_key).unwrap(), "origin":origin, "scopeId":"opaque-scope",
        "keyEpoch":1,"policyRevision":1,"expectedSequence":2,"objectId":object.id().unwrap(),
        "requestId":"checkpoint-one","issuedAt":issued_at,"expiresAt":issued_at+120_000});
    let authorization = sign_json_envelope(&[32; 32], payload, &device_id, "MATCH/1").unwrap();
    let request = json!({"object":object,"identity":identity,"deviceId":device_id,
        "certificates":[certificate],"authorization":authorization});
    let mut unsigned = request.clone();
    unsigned["certificates"] = json!([]);
    assert_eq!(
        client
            .post(&endpoint)
            .bearer_auth("w".repeat(43))
            .json(&unsigned)
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::FORBIDDEN
    );
    let response = client
        .post(&endpoint)
        .bearer_auth("w".repeat(43))
        .json(&request)
        .send()
        .await
        .unwrap();
    assert_eq!(
        response.status(),
        StatusCode::OK,
        "{}",
        response.text().await.unwrap()
    );
    let receipt: SignedEnvelope<Value> = client
        .post(&endpoint)
        .bearer_auth("w".repeat(43))
        .json(&request)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(verify_signed_envelope(&receipt, &service_key, DOMAIN).unwrap());
    assert_eq!(receipt.payload["kind"], "rusty-snapshot-checkpoint-receipt");
    assert_eq!(receipt.payload["sequence"], 3);
    assert_eq!(receipt.payload["supersedesThrough"], 2);
    assert_eq!(store.objects("opaque-scope").unwrap().len(), 1);
    let mut racing = encrypted_fixture();
    racing.nonce = URL_SAFE_NO_PAD.encode([5u8; 12]);
    assert_eq!(
        store
            .save("opaque-scope", &"w".repeat(43), racing, "racing")
            .unwrap()
            .payload["sequence"],
        4
    );
    let replay: SignedEnvelope<Value> = client
        .post(&endpoint)
        .bearer_auth("w".repeat(43))
        .json(&request)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(replay.payload["sequence"], 3);
    assert_eq!(store.objects("opaque-scope").unwrap().len(), 2);
    let mut stale = request.clone();
    stale["object"]["nonce"] = json!(URL_SAFE_NO_PAD.encode([6u8; 12]));
    let stale_object: BlindObject = serde_json::from_value(stale["object"].clone()).unwrap();
    let mut stale_payload = authorization.payload.clone();
    stale_payload["objectId"] = json!(stale_object.id().unwrap());
    stale["authorization"] = serde_json::to_value(
        sign_json_envelope(&[32; 32], stale_payload, &device_id, "MATCH/1").unwrap(),
    )
    .unwrap();
    let conflict = client
        .post(&endpoint)
        .bearer_auth("w".repeat(43))
        .json(&stale)
        .send()
        .await
        .unwrap();
    assert_eq!(conflict.status(), StatusCode::CONFLICT);
    assert_eq!(
        conflict.json::<Value>().await.unwrap()["code"],
        "checkpoint_conflict"
    );
    server.abort();
    let _ = server.await;
    drop(store);
    let restarted = BlindStore::open(directory.clone()).unwrap();
    assert_eq!(restarted.public_key().unwrap(), service_key);
    assert_eq!(
        restarted
            .objects("opaque-scope")
            .unwrap()
            .iter()
            .map(|o| o.sequence)
            .collect::<Vec<_>>(),
        vec![3, 4]
    );
    drop(restarted);
    fs::remove_dir_all(directory).unwrap();
}
