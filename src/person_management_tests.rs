use super::*;

async fn person_policy(
    f: &Fixture,
    revoked: Vec<String>,
    ops: Vec<&str>,
    current: Option<Value>,
) -> Value {
    let revision = current
        .as_ref()
        .map_or(0, |v| v["payload"]["revision"].as_u64().unwrap());
    let request = f.update_resource(
        "person",
        &f.owner.identity.person_id,
        revision,
        revoked,
        current,
        32,
        ops,
    );
    let response = f
        .put_resource("person", &f.owner.identity.person_id, &request)
        .await;
    assert_eq!(
        response.status(),
        StatusCode::OK,
        "person policy must be explicitly migratable"
    );
    response.json::<Value>().await.unwrap()["capability"].clone()
}

fn creation(f: &Fixture, kind: &str, id: &str, seed: u8, parent: &Value) -> Value {
    let ops = if kind == "scope" {
        vec!["management.update", "scope.policy", "snapshot.checkpoint"]
    } else {
        vec!["management.update", "publication.status"]
    };
    let mut request = f.update_resource(kind, id, 0, vec![], None, seed, ops);
    request["personManagementCapability"] = parent.clone();
    request["authorization"]["payload"]["personManagementRevision"] =
        parent["payload"]["revision"].clone();
    f.resign(&mut request, seed);
    request
}

#[tokio::test]
async fn given_person_policy_when_other_certified_devices_create_resources_after_restart_then_authority_remains_scoped()
 {
    let mut f = Fixture::new().await;
    let parent = person_policy(
        &f,
        vec![],
        vec!["management.update", "resource.create"],
        None,
    )
    .await;
    assert_eq!(
        parent["payload"]["kind"],
        "rusty-person-management-capability"
    );
    f.restart().await;
    for (seed, scope) in [(41, "new-scope-a"), (42, "new-scope-b")] {
        let request = creation(&f, "scope", scope, seed, &parent);
        let response = f.put_resource("scope", scope, &request).await;
        assert_eq!(
            response.status(),
            StatusCode::OK,
            "unrelated certified owner device must create scope"
        );
        let cap = response.json::<Value>().await.unwrap()["capability"].clone();
        assert_eq!(cap["payload"]["kind"], "rusty-scope-management-capability");
        assert_eq!(
            f.challenge(seed, Some(cap), scope).await.status(),
            StatusCode::OK
        );
    }
    f.restart().await;
    assert_eq!(
        f.put_resource(
            "board",
            "new-board",
            &creation(&f, "board", "new-board", 41, &parent)
        )
        .await
        .status(),
        StatusCode::OK
    );
}

#[tokio::test]
async fn given_person_authority_when_missing_stale_substituted_or_unsigned_parent_revision_is_used_then_no_scope_is_created()
 {
    let mut f = Fixture::new().await;
    let old = person_policy(
        &f,
        vec![],
        vec!["management.update", "resource.create"],
        None,
    )
    .await;
    let current = person_policy(
        &f,
        vec![],
        vec!["management.update", "resource.create"],
        Some(old.clone()),
    )
    .await;
    f.restart().await;
    let mut requests = vec![creation(&f, "scope", "denied", 41, &old)];
    let mut missing = creation(&f, "scope", "denied", 41, &current);
    missing
        .as_object_mut()
        .unwrap()
        .remove("personManagementCapability");
    requests.push(missing);
    let mut unsigned = creation(&f, "scope", "denied", 41, &current);
    unsigned["authorization"]["payload"]
        .as_object_mut()
        .unwrap()
        .remove("personManagementRevision");
    f.resign(&mut unsigned, 41);
    requests.push(unsigned);
    let mut substituted = creation(&f, "scope", "denied", 41, &old);
    substituted["personManagementCapability"] = current.clone();
    requests.push(substituted);
    let mut forged = creation(&f, "scope", "denied", 41, &current);
    forged["personManagementCapability"]["payload"]["origin"] = json!("https://another.example");
    requests.push(forged);
    for request in requests {
        assert!(
            f.put_resource("scope", "denied", &request)
                .await
                .status()
                .is_client_error()
        );
        assert!(
            !f.directory
                .join("management/pending/scope/denied.json")
                .exists()
        );
    }
}

#[tokio::test]
async fn given_person_creation_right_is_removed_then_owner_device_cannot_bypass_it_and_existing_scope_rights_are_not_broadened()
 {
    let mut f = Fixture::new().await;
    let parent = person_policy(
        &f,
        vec![],
        vec!["management.update", "resource.create"],
        None,
    )
    .await;
    let created = f
        .put_resource(
            "scope",
            RESOURCE,
            &creation(&f, "scope", RESOURCE, 41, &parent),
        )
        .await
        .json::<Value>()
        .await
        .unwrap()["capability"]
        .clone();
    let person = person_policy(&f, vec![], vec!["management.update"], Some(parent.clone())).await;
    assert_eq!(
        f.put_resource(
            "scope",
            "denied",
            &creation(&f, "scope", "denied", 32, &person)
        )
        .await
        .status(),
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        f.put_resource(
            "scope",
            "denied",
            &f.update_resource(
                "scope",
                "denied",
                0,
                vec![],
                None,
                32,
                vec!["management.update", "scope.policy"]
            )
        )
        .await
        .status(),
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        f.challenge(41, Some(parent), RESOURCE).await.status(),
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        f.challenge(41, Some(created), RESOURCE).await.status(),
        StatusCode::OK
    );
    f.restart().await;
}

#[tokio::test]
async fn given_global_device_revocation_then_existing_scope_status_enrollment_and_completed_retries_reject_that_device()
 {
    let mut f = Fixture::new().await;
    let initial = f.update(0, vec![], None, 32);
    let scope = f.put(&initial).await.json::<Value>().await.unwrap()["capability"].clone();
    let parent = person_policy(
        &f,
        vec![],
        vec!["management.update", "resource.create"],
        None,
    )
    .await;
    let removed = device(41, &f.owner.identity).0;
    let original = creation(&f, "scope", "created-by-removed", 41, &parent);
    assert_eq!(
        f.put_resource("scope", "created-by-removed", &original)
            .await
            .status(),
        StatusCode::OK
    );
    person_policy(
        &f,
        vec![removed],
        vec!["management.update", "resource.create"],
        Some(parent),
    )
    .await;
    f.restart().await;
    assert_eq!(
        f.status_as(41).send().await.unwrap().status(),
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        f.challenge(41, Some(scope.clone()), RESOURCE)
            .await
            .status(),
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        f.put_resource("scope", "created-by-removed", &original)
            .await
            .status(),
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        f.challenge(42, Some(scope), RESOURCE).await.status(),
        StatusCode::OK
    );
}

#[tokio::test]
async fn given_person_policy_pointer_fault_then_resources_stop_until_exact_retry_recovers_without_retiring_old_evidence()
 {
    let mut f = Fixture::new().await;
    let request = f.update_resource(
        "person",
        &f.owner.identity.person_id,
        0,
        vec![],
        None,
        32,
        vec!["management.update", "resource.create"],
    );
    f.store()
        .management_commit_failure
        .store(true, std::sync::atomic::Ordering::SeqCst);
    assert_eq!(
        f.put_resource("person", &f.owner.identity.person_id, &request)
            .await
            .status(),
        StatusCode::SERVICE_UNAVAILABLE
    );
    let evidence_count = fs::read_dir(f.directory.join("management/records"))
        .unwrap()
        .count();
    assert_eq!(evidence_count, 1);
    assert_eq!(
        f.challenge(32, None, RESOURCE).await.status(),
        StatusCode::FORBIDDEN
    );
    f.restart().await;
    let mut status = f.status_request(32, 32);
    status["authorization"]["payload"]["resourceKind"] = json!("person");
    status["authorization"]["payload"]["resourceId"] = json!(f.owner.identity.person_id);
    f.resign(&mut status, 32);
    let response = f
        .client
        .post(format!(
            "{}/v2/management/person/{}/status",
            f.url, f.owner.identity.person_id
        ))
        .json(&status)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.json::<Value>().await.unwrap()["migrationPending"],
        true
    );
    let response = f
        .put_resource("person", &f.owner.identity.person_id, &request)
        .await;
    assert_eq!(response.status(), StatusCode::OK);
    let first = response.json::<Value>().await.unwrap();
    assert_eq!(
        f.put_resource("person", &f.owner.identity.person_id, &request)
            .await
            .json::<Value>()
            .await
            .unwrap(),
        first
    );
    assert_eq!(
        fs::read_dir(f.directory.join("management/records"))
            .unwrap()
            .count(),
        evidence_count
    );
}

#[tokio::test]
async fn given_global_person_revocation_then_valid_resource_capabilities_cannot_status_challenge_stage_or_checkpoint()
 {
    let f = Fixture::new().await;
    let person = person_policy(
        &f,
        vec![],
        vec!["management.update", "resource.create"],
        None,
    )
    .await;

    let scope_request = creation(&f, "scope", RESOURCE, 32, &person);
    let scope_capability = f
        .put_resource("scope", RESOURCE, &scope_request)
        .await
        .json::<Value>()
        .await
        .unwrap()["capability"]
        .clone();

    let board_id = "person-policy-board";
    let mut board_request = f.update_resource(
        "board",
        board_id,
        0,
        vec![],
        None,
        32,
        vec![
            "management.update",
            "publication.publish",
            "publication.stage-file",
            "publication.status",
        ],
    );
    board_request["personManagementCapability"] = person.clone();
    board_request["authorization"]["payload"]["personManagementRevision"] =
        person["payload"]["revision"].clone();
    f.resign(&mut board_request, 32);
    let board_capability = f
        .put_resource("board", board_id, &board_request)
        .await
        .json::<Value>()
        .await
        .unwrap()["capability"]
        .clone();

    let (removed_device, removed_certificate) = device(41, &f.owner.identity);
    let public_challenge = f
        .client
        .post(format!("{}/v1/public/challenges", f.url))
        .json(&json!({"version":1,"boardId":board_id,"identity":f.owner.identity,
            "deviceId":removed_device,"certificates":[removed_certificate],"managementCapability":board_capability}))
        .send()
        .await
        .unwrap();
    assert_eq!(public_challenge.status(), StatusCode::OK);
    let public_challenge: Value = public_challenge.json().await.unwrap();
    let public_challenge = public_challenge["challenge"].clone();

    // Enroll the still-authorized owner device so checkpoint requests reach management authorization.
    let enrollment = f
        .challenge(32, Some(scope_capability.clone()), RESOURCE)
        .await;
    assert_eq!(enrollment.status(), StatusCode::OK);
    let enrollment: Value = enrollment.json().await.unwrap();
    let enrollment = enrollment["challenge"].clone();
    let enrollment_payload = &enrollment["payload"];
    let read_token = "r".repeat(43);
    let write_token = "w".repeat(43);
    let enrollment_auth = sign_json_envelope(
        &[32; 32],
        json!({
            "kind":"rusty-scope-enrollment", "version":1,
            "challengeId":enrollment_payload["challengeId"], "nonce":enrollment_payload["nonce"],
            "serviceId":enrollment_payload["serviceId"], "publicOrigin":ORIGIN, "scopeId":RESOURCE,
            "personId":f.owner.identity.person_id, "deviceId":device(32, &f.owner.identity).0,
            "deviceKeyId":device(32, &f.owner.identity).0,
            "expectedRevision":enrollment_payload["expectedRevision"],
            "readTokenHash":digest(read_token.as_bytes()), "writeTokenHash":digest(write_token.as_bytes()),
            "revoked":false, "expiresAt":enrollment_payload["expiresAt"], "managementRevision":1
        }),
        &device(32, &f.owner.identity).0,
        "MATCH/1",
    )
    .unwrap();
    let approval = f.client.put(format!("{}/v2/scopes/{RESOURCE}", f.url))
        .json(&json!({"challenge":enrollment,"identity":f.owner.identity,"deviceId":device(32, &f.owner.identity).0,
            "certificates":[device(32, &f.owner.identity).1],"managementCapability":scope_capability,
            "readToken":read_token,"writeToken":write_token,"revoked":false,"authorization":enrollment_auth}))
        .send().await.unwrap();
    assert_eq!(approval.status(), StatusCode::OK);

    let removed_id = removed_device;
    let next_person = person_policy(
        &f,
        vec![removed_id.clone()],
        vec!["management.update", "resource.create"],
        Some(person),
    )
    .await;
    assert_eq!(next_person["payload"]["revision"], 2);

    let mut status = f.status_request(41, 41);
    status["authorization"]["payload"]["resourceKind"] = json!("board");
    status["authorization"]["payload"]["resourceId"] = json!(board_id);
    f.resign(&mut status, 41);
    let response = f
        .client
        .post(format!("{}/v2/management/board/{board_id}/status", f.url))
        .json(&status)
        .send()
        .await
        .unwrap();
    assert_eq!(
        response.status(),
        StatusCode::FORBIDDEN,
        "global revocation denies board policy status despite a valid board capability"
    );

    let response = f.client.post(format!("{}/v1/public/challenges", f.url))
        .json(&json!({"version":1,"boardId":board_id,"identity":f.owner.identity,
            "deviceId":removed_id,"certificates":[removed_certificate],"managementCapability":board_capability}))
        .send().await.unwrap();
    assert_eq!(
        response.status(),
        StatusCode::FORBIDDEN,
        "global revocation denies public publication challenge"
    );

    let bytes = b"revoked actor must not stage";
    let sha256 = digest(bytes);
    let challenge_payload = &public_challenge["payload"];
    let stage_payload = json!({
        "kind":"rusty-publication-command", "version":1,
        "challengeId":challenge_payload["challengeId"], "nonce":challenge_payload["nonce"],
        "serviceId":challenge_payload["serviceId"], "publicOrigin":ORIGIN, "boardId":board_id,
        "action":"stage-file", "projectionHash":sha256, "expectedRevision":challenge_payload["expectedRevision"],
        "expiresAt":challenge_payload["expiresAt"], "byteLength":bytes.len(), "managementRevision":1
    });
    let stage_auth = sign_json_envelope(&[41; 32], stage_payload, &removed_id, "MATCH/1").unwrap();
    let response = f.client.put(format!("{}/v1/public/boards/{board_id}/files", f.url))
        .json(&json!({"challenge":public_challenge,"identity":f.owner.identity,"deviceId":removed_id,
            "certificates":[removed_certificate],"managementCapability":board_capability,"sha256":sha256,
            "byteLength":bytes.len(),"bytes":URL_SAFE_NO_PAD.encode(bytes),"authorization":stage_auth}))
        .send().await.unwrap();
    assert_eq!(
        response.status(),
        StatusCode::FORBIDDEN,
        "global revocation denies staging against a pre-revocation challenge"
    );

    let object = super::tests::encrypted_fixture();
    let service_id = public_key_id(&f.store().public_key().unwrap()).unwrap();
    let issued_at = now_ms().unwrap();
    let checkpoint_auth = sign_json_envelope(&[41; 32], json!({
        "kind":"rusty-snapshot-checkpoint", "version":1, "serviceId":service_id,
        "origin":ORIGIN, "scopeId":RESOURCE, "keyEpoch":object.key_epoch,
        "policyRevision":1, "managementRevision":1, "expectedSequence":0,
        "objectId":object.id().unwrap(), "requestId":URL_SAFE_NO_PAD.encode(rand::random::<[u8;32]>()),
        "issuedAt":issued_at, "expiresAt":issued_at+60000
    }), &removed_id, "MATCH/1").unwrap();
    let response = f.client.post(format!("{}/v2/scopes/{RESOURCE}/checkpoint", f.url))
        .bearer_auth(&write_token)
        .json(&json!({"object":object,"identity":f.owner.identity,"deviceId":removed_id,
            "certificates":[removed_certificate],"managementCapability":scope_capability,"authorization":checkpoint_auth}))
        .send().await.unwrap();
    assert_eq!(
        response.status(),
        StatusCode::FORBIDDEN,
        "global revocation denies checkpoint despite a valid scope capability and storage token"
    );
}
