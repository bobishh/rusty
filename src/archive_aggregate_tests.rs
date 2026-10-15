use super::super::*;
use super::{fixture, server, upload};
use meta_mesh_core::{
    public_key_from_seed, public_key_id, sign_json_envelope, verify_signed_envelope,
};
use sha2::{Digest, Sha256};

const READ_TOKEN: &str = "rrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrr";
const WRITE_TOKEN: &str = "wwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwww";
const AGGREGATE_PATH: &str = "/v2/scopes/opaque-scope/archive-coverage/aggregate";

async fn leaf(
    client: &reqwest::Client,
    origin: &str,
    object: &BlindObject,
    request_id: &str,
) -> Value {
    assert_eq!(
        upload(origin, object, WRITE_TOKEN, 2).await.status(),
        StatusCode::OK
    );
    let response = client
        .post(format!("{origin}/v2/scopes/opaque-scope/archive-coverage"))
        .bearer_auth(READ_TOKEN)
        .json(&json!({"version":1,"requestId":request_id,
            "objects":[{"objectId":object.id().unwrap(),"keyEpoch":object.key_epoch}]}))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    response.json().await.unwrap()
}

fn aggregate_request(root: &str, children: Vec<Value>, request_id: &str) -> Value {
    json!({"version":1,"requestId":request_id,"archiveRootId":root,"children":children})
}

async fn post_aggregate(
    client: &reqwest::Client,
    origin: &str,
    token: &str,
    body: &Value,
) -> reqwest::Response {
    client
        .post(format!("{origin}{AGGREGATE_PATH}"))
        .bearer_auth(token)
        .json(body)
        .send()
        .await
        .unwrap()
}

fn expected_digest(value: &Value) -> String {
    let canonical = canonicalize_json(value).unwrap();
    URL_SAFE_NO_PAD.encode(Sha256::digest(
        [
            b"MESH-HISTORY/1/coverage-set\0".as_slice(),
            canonical.as_bytes(),
        ]
        .concat(),
    ))
}

#[tokio::test]
async fn given_durable_leaf_receipts_when_aggregated_then_sign_root_bound_summary_without_claiming_completeness()
 {
    let (path, store, mut first) = fixture();
    first.nonce = URL_SAFE_NO_PAD.encode([41u8; 12]);
    let mut second = first.clone();
    second.nonce = URL_SAFE_NO_PAD.encode([42u8; 12]);
    let root = first.id().unwrap();
    let mut objects = vec![first, second];
    objects.sort_by_key(|object| object.id().unwrap());

    let (origin, task) = server(store.clone()).await;
    let client = reqwest::Client::new();
    let discovery: Value = client
        .get(format!("{origin}/.well-known/mesh-lighthouse"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(
        discovery["capabilities"]["archiveCoverageAggregates"],
        json!({"version":1,"maximumChildren":8,"maximumHeight":31})
    );
    let leaves = vec![
        leaf(&client, &origin, &objects[0], "aggregate-leaf-request-0001").await,
        leaf(&client, &origin, &objects[1], "aggregate-leaf-request-0002").await,
    ];
    let body = aggregate_request(&root, leaves.clone(), "aggregate-root-request-0001");
    let response = post_aggregate(&client, &origin, READ_TOKEN, &body).await;
    assert_eq!(
        response.status(),
        StatusCode::OK,
        "aggregate endpoint: {}",
        response.text().await.unwrap()
    );
    assert_eq!(
        response.headers()[axum::http::header::CACHE_CONTROL],
        "no-store"
    );
    let receipt: SignedEnvelope<Value> = response.json().await.unwrap();
    let pin = store.public_key().unwrap();
    assert!(verify_signed_envelope(&receipt, &pin, DOMAIN).unwrap());
    let payload = &receipt.payload;
    assert_eq!(payload["kind"], "blind-archive-coverage-aggregate-receipt");
    assert_eq!(payload["version"], 1);
    assert_eq!(payload["serviceId"], public_key_id(&pin).unwrap());
    assert_eq!(payload["scopeId"], "opaque-scope");
    assert_eq!(payload["policyRevision"], 1);
    assert_eq!(payload["requestId"], body["requestId"]);
    assert_eq!(payload["archiveRootId"], root);
    assert_eq!(payload["height"], 1);
    assert_eq!(payload["objectCount"], 2);
    let ids = objects
        .iter()
        .map(|object| object.id().unwrap())
        .collect::<Vec<_>>();
    assert_eq!(payload["firstObjectId"], ids[0]);
    assert_eq!(payload["lastObjectId"], ids[1]);
    assert_eq!(payload["rootCovered"], ids.contains(&root));
    let summaries = objects
        .iter()
        .map(|object| {
            let object_id = object.id().unwrap();
            let leaf_objects = json!([{"objectId":object_id,"keyEpoch":object.key_epoch}]);
            json!({"height":0,"objectCount":1,"firstObjectId":object_id,
                "lastObjectId":object_id,"setDigest":expected_digest(&json!({
                    "kind":"archive-coverage-set-leaf","version":1,"objects":leaf_objects
                })),"rootCovered":object_id == root})
        })
        .collect::<Vec<_>>();
    assert_eq!(
        payload["setDigest"],
        expected_digest(&json!({
            "kind":"archive-coverage-set-branch","version":1,
            "archiveRootId":root,"children":summaries
        }))
    );
    let wrapped = post_aggregate(
        &client,
        &origin,
        READ_TOKEN,
        &aggregate_request(
            &root,
            vec![serde_json::to_value(&receipt).unwrap()],
            "aggregate-unary-wrap-0001",
        ),
    )
    .await;
    assert_eq!(wrapped.status(), StatusCode::OK);
    let wrapped_receipt: SignedEnvelope<Value> = wrapped.json().await.unwrap();
    assert!(verify_signed_envelope(&wrapped_receipt, &pin, DOMAIN).unwrap());
    assert_eq!(wrapped_receipt.payload["height"], 2);
    assert_eq!(wrapped_receipt.payload["objectCount"], 2);
    assert_eq!(wrapped_receipt.payload["rootCovered"], true);

    let omitted_root = URL_SAFE_NO_PAD.encode([250u8; 32]);
    assert!(!ids.contains(&omitted_root));
    let omitted = post_aggregate(
        &client,
        &origin,
        READ_TOKEN,
        &aggregate_request(&omitted_root, leaves.clone(), "aggregate-omitted-root-0001"),
    )
    .await;
    assert_eq!(omitted.status(), StatusCode::OK);
    let omitted_receipt: SignedEnvelope<Value> = omitted.json().await.unwrap();
    assert_eq!(omitted_receipt.payload["rootCovered"], false);
    assert_ne!(omitted_receipt.payload["rootCovered"], true);

    let mut outsider = objects[0].clone();
    let mut outsider_id = outsider.id().unwrap();
    for byte in 1..=u8::MAX {
        outsider.nonce = URL_SAFE_NO_PAD.encode([byte; 12]);
        outsider_id = outsider.id().unwrap();
        if outsider_id > ids[1] && !ids.contains(&outsider_id) {
            break;
        }
    }
    assert!(outsider_id > ids[1]);
    let outsider_leaf = leaf(&client, &origin, &outsider, "aggregate-height-leaf-0001").await;
    let mut substituted_payload = receipt.payload.clone();
    substituted_payload["archiveRootId"] = json!(omitted_root);
    let substituted = serde_json::to_value(
        sign_json_envelope(
            &store.seed,
            substituted_payload,
            &public_key_id(&pin).unwrap(),
            DOMAIN,
        )
        .unwrap(),
    )
    .unwrap();
    assert_eq!(
        post_aggregate(
            &client,
            &origin,
            READ_TOKEN,
            &aggregate_request(&root, vec![substituted], "aggregate-root-substitution-0001"),
        )
        .await
        .status(),
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        post_aggregate(
            &client,
            &origin,
            READ_TOKEN,
            &aggregate_request(
                &root,
                vec![serde_json::to_value(&receipt).unwrap(), outsider_leaf],
                "aggregate-mixed-height-0001"
            ),
        )
        .await
        .status(),
        StatusCode::BAD_REQUEST
    );
    task.abort();
    let _ = task.await;
    drop(store);
    fs::remove_dir_all(path).unwrap();
}

#[tokio::test]
async fn given_invalid_aggregate_children_or_authority_when_posted_then_reject_without_receipt() {
    let (path, store, mut first) = fixture();
    first.nonce = URL_SAFE_NO_PAD.encode([51u8; 12]);
    let mut second = first.clone();
    second.nonce = URL_SAFE_NO_PAD.encode([52u8; 12]);
    let root = first.id().unwrap();
    let mut objects = vec![first, second];
    objects.sort_by_key(|object| object.id().unwrap());
    let (origin, task) = server(store.clone()).await;
    let client = reqwest::Client::new();
    let leaves = vec![
        leaf(
            &client,
            &origin,
            &objects[0],
            "aggregate-negative-leaf-0001",
        )
        .await,
        leaf(
            &client,
            &origin,
            &objects[1],
            "aggregate-negative-leaf-0002",
        )
        .await,
    ];
    let valid = aggregate_request(&root, leaves.clone(), "aggregate-negative-request-0001");
    let service_id = public_key_id(&store.public_key().unwrap()).unwrap();
    let make_signed_leaf = |seed: &[u8; 32], identity: &str, scope: &str, revision: u64| {
        sign_json_envelope(
            seed,
            json!({"kind":"blind-archive-coverage-batch-receipt","version":1,
                "serviceId":service_id,"scopeId":scope,"policyRevision":revision,
                "requestId":"aggregate-context-leaf-0001",
                "objects":[{"objectId":objects[0].id().unwrap(),"keyEpoch":objects[0].key_epoch}]}),
            identity,
            DOMAIN,
        )
        .unwrap()
    };
    let service_bound_wrong_scope = serde_json::to_value(make_signed_leaf(
        &store.seed,
        &service_id,
        "foreign-scope",
        1,
    ))
    .unwrap();
    let service_bound_old_policy = serde_json::to_value(make_signed_leaf(
        &store.seed,
        &service_id,
        "opaque-scope",
        0,
    ))
    .unwrap();
    let foreign_service_id = public_key_from_seed(&[77; 32]).unwrap();
    let foreign_service = serde_json::to_value(make_signed_leaf(
        &[77; 32],
        &foreign_service_id,
        "opaque-scope",
        1,
    ))
    .unwrap();

    let mut forged = leaves[0].clone();
    forged["signature"] = json!("A".repeat(86));
    let bad_cases = vec![
        aggregate_request(
            &root,
            vec![forged, leaves[1].clone()],
            "aggregate-negative-forged-0001",
        ),
        aggregate_request(
            &root,
            vec![
                json!({"payload":{"kind":"other-purpose"},"signature":"x"}),
                leaves[1].clone(),
            ],
            "aggregate-negative-purpose-0001",
        ),
        aggregate_request(
            &"Z".repeat(43),
            leaves.clone(),
            "aggregate-negative-root-0001",
        ),
        aggregate_request(
            &root,
            vec![leaves[1].clone(), leaves[0].clone()],
            "aggregate-negative-order-0001",
        ),
        aggregate_request(
            &root,
            vec![leaves[0].clone(), leaves[0].clone()],
            "aggregate-negative-overlap-0001",
        ),
        aggregate_request(
            &root,
            vec![service_bound_wrong_scope, leaves[1].clone()],
            "aggregate-negative-scope-0001",
        ),
        aggregate_request(
            &root,
            vec![service_bound_old_policy, leaves[1].clone()],
            "aggregate-negative-policy-0001",
        ),
        aggregate_request(
            &root,
            vec![foreign_service, leaves[1].clone()],
            "aggregate-negative-service-0001",
        ),
    ];
    for body in bad_cases {
        assert_eq!(
            post_aggregate(&client, &origin, READ_TOKEN, &body)
                .await
                .status(),
            StatusCode::BAD_REQUEST
        );
    }
    assert_eq!(
        post_aggregate(&client, &origin, "x", &valid).await.status(),
        StatusCode::FORBIDDEN
    );

    let mut extra = valid.clone();
    extra["unexpected"] = json!(true);
    assert_eq!(
        post_aggregate(&client, &origin, READ_TOKEN, &extra)
            .await
            .status(),
        StatusCode::UNPROCESSABLE_ENTITY
    );
    let too_many = aggregate_request(
        &root,
        vec![leaves[0].clone(); 9],
        "aggregate-negative-many-0001",
    );
    assert_eq!(
        post_aggregate(&client, &origin, READ_TOKEN, &too_many)
            .await
            .status(),
        StatusCode::BAD_REQUEST
    );
    let too_large = json!({"version":1,"requestId":"aggregate-negative-large-0001",
        "archiveRootId":root,"children":[],"padding":"x".repeat(66 * 1024)});
    assert_eq!(
        post_aggregate(&client, &origin, READ_TOKEN, &too_large)
            .await
            .status(),
        StatusCode::PAYLOAD_TOO_LARGE
    );
    store
        .approve(
            "opaque-scope",
            ScopeApproval {
                expected_revision: 1,
                read_token: READ_TOKEN.to_owned(),
                write_token: WRITE_TOKEN.to_owned(),
                revoked: true,
            },
        )
        .unwrap();
    assert_eq!(
        post_aggregate(&client, &origin, READ_TOKEN, &valid)
            .await
            .status(),
        StatusCode::FORBIDDEN
    );
    task.abort();
    let _ = task.await;
    drop(store);
    fs::remove_dir_all(path).unwrap();
}

#[tokio::test]
async fn given_signed_but_invalid_summary_metadata_when_aggregated_then_reject_unsafe_depth_counts_ranges_and_schema()
 {
    let (path, store, _) = fixture();
    let (origin, task) = server(store.clone()).await;
    let client = reqwest::Client::new();
    let service_id = public_key_id(&store.public_key().unwrap()).unwrap();
    let root = URL_SAFE_NO_PAD.encode([64u8; 32]);
    let first = URL_SAFE_NO_PAD.encode([0u8; 32]);
    let last = URL_SAFE_NO_PAD.encode([128u8; 32]);
    let base = json!({"kind":"blind-archive-coverage-aggregate-receipt","version":1,
        "serviceId":service_id,"scopeId":"opaque-scope","policyRevision":1,
        "requestId":"aggregate-summary-child-0001","archiveRootId":root,
        "height":1,"objectCount":2,"firstObjectId":first,"lastObjectId":last,
        "setDigest":URL_SAFE_NO_PAD.encode([19u8;32]),"rootCovered":true});
    let mut invalid = Vec::new();
    for (field, value) in [
        ("height", json!(0)),
        ("height", json!(31)),
        ("height", json!(32)),
        ("objectCount", json!(0)),
        ("objectCount", json!(9_007_199_254_740_992u64)),
        ("objectCount", json!(1)),
        ("setDigest", json!("-".repeat(43))),
        ("rootCovered", json!("true")),
        ("unexpected", json!(true)),
    ] {
        let mut payload = base.clone();
        payload[field] = value;
        invalid.push(payload);
    }
    let mut reversed = base.clone();
    reversed["firstObjectId"] = json!(last);
    reversed["lastObjectId"] = json!(first);
    invalid.push(reversed);
    for payload in invalid {
        let receipt = sign_json_envelope(&store.seed, payload, service_id.clone(), DOMAIN).unwrap();
        let response = post_aggregate(
            &client,
            &origin,
            READ_TOKEN,
            &aggregate_request(
                &root,
                vec![serde_json::to_value(receipt).unwrap()],
                "aggregate-summary-invalid-0001",
            ),
        )
        .await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }
    let mut large = base;
    large["objectCount"] = json!(9_007_199_254_740_991u64);
    let mut next = large.clone();
    next["objectCount"] = json!(2);
    next["firstObjectId"] = json!(URL_SAFE_NO_PAD.encode([160u8; 32]));
    next["lastObjectId"] = json!(URL_SAFE_NO_PAD.encode([200u8; 32]));
    next["rootCovered"] = json!(false);
    let children = [large, next]
        .into_iter()
        .map(|payload| {
            serde_json::to_value(
                sign_json_envelope(&store.seed, payload, service_id.clone(), DOMAIN).unwrap(),
            )
            .unwrap()
        })
        .collect();
    assert_eq!(
        post_aggregate(
            &client,
            &origin,
            READ_TOKEN,
            &aggregate_request(&root, children, "aggregate-unsafe-total-0001")
        )
        .await
        .status(),
        StatusCode::BAD_REQUEST
    );
    task.abort();
    let _ = task.await;
    drop(store);
    fs::remove_dir_all(path).unwrap();
}
