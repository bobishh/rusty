use super::blobs::directory_usage;
use super::tests::{approve_fixture, encrypted_fixture};
use super::*;

fn adversarial_archive_fixture() -> (PathBuf, BlindStore, BlindObject) {
    let path = std::env::temp_dir().join(format!(
        "rusty-archive-adversarial-{}",
        rand::random::<u64>()
    ));
    let store = BlindStore::open(path.clone()).unwrap();
    approve_fixture(&store);
    set_scope_writer_floor_for_test(&store, "opaque-scope", 2);
    (path, store, encrypted_fixture())
}

fn coverage_value(objects: Value) -> Value {
    json!({"version":1,"requestId":"archive-adversarial-coverage-0001","objects":objects})
}

#[test]
fn given_missing_or_malformed_coverage_batch_when_checked_then_reject_without_receipt() {
    let (path, store, mut archive) = adversarial_archive_fixture();
    archive.nonce = URL_SAFE_NO_PAD.encode([31u8; 12]);
    let id = archive.id().unwrap();
    store
        .save_archive_for_writer(
            "opaque-scope",
            &"w".repeat(43),
            archive,
            "archive-adversarial-save-0001",
            2,
        )
        .unwrap();

    let missing = URL_SAFE_NO_PAD.encode([111u8; 32]);
    assert_ne!(missing, id);
    let absent = store.archive_coverage(
        "opaque-scope",
        &"r".repeat(43),
        serde_json::from_value(coverage_value(json!([{"objectId":missing,"keyEpoch":1}]))).unwrap(),
    );
    assert_eq!(absent.unwrap_err(), "Archive object unavailable");

    let mut ids = (0..65u8)
        .map(|value| URL_SAFE_NO_PAD.encode([value; 32]))
        .collect::<Vec<_>>();
    ids.sort();
    let too_many = coverage_value(Value::Array(
        ids.iter()
            .map(|object_id| json!({"objectId":object_id,"keyEpoch":1}))
            .collect(),
    ));
    let repeated = coverage_value(json!([
        {"objectId":id,"keyEpoch":1}, {"objectId":id,"keyEpoch":1}
    ]));
    let high = URL_SAFE_NO_PAD.encode([255u8; 32]);
    let low = URL_SAFE_NO_PAD.encode([0u8; 32]);
    let out_of_order = coverage_value(json!([
        {"objectId":high,"keyEpoch":1}, {"objectId":low,"keyEpoch":1}
    ]));
    let unsafe_epoch = coverage_value(json!([{
        "objectId":id,"keyEpoch":9_007_199_254_740_992u64
    }]));
    let invalid_id = coverage_value(json!([{"objectId":"x".repeat(43),"keyEpoch":1}]));

    for value in [too_many, repeated, out_of_order, unsafe_epoch, invalid_id] {
        let request = serde_json::from_value(value).unwrap();
        assert!(
            store
                .archive_coverage("opaque-scope", &"r".repeat(43), request)
                .is_err()
        );
    }
    let mut unknown = coverage_value(json!([{"objectId":id,"keyEpoch":1,"unexpected":true}]));
    assert!(serde_json::from_value::<archives::CoverageRequest>(unknown.clone()).is_err());
    unknown["objects"] = json!([{"objectId":id,"keyEpoch":1}]);
    unknown["unexpected"] = json!(true);
    assert!(serde_json::from_value::<archives::CoverageRequest>(unknown).is_err());

    drop(store);
    fs::remove_dir_all(path).unwrap();
}

#[test]
fn given_archive_rename_without_directory_durability_when_retried_then_reuse_exact_bytes_once() {
    let (path, store, mut archive) = adversarial_archive_fixture();
    archive.nonce = URL_SAFE_NO_PAD.encode([32u8; 12]);
    let id = archive.id().unwrap();
    let directory = path.join("scopes/opaque-scope/archives");
    let object_path = directory.join(format!("{id}.json"));

    FAILED_DIRECTORY_SYNC.with(|failure| *failure.borrow_mut() = Some(directory.clone()));
    let first = store.save_archive_for_writer(
        "opaque-scope",
        &"w".repeat(43),
        archive.clone(),
        "archive-durable-retry-0001",
        2,
    );
    FAILED_DIRECTORY_SYNC.with(|failure| *failure.borrow_mut() = None);
    assert_eq!(first.unwrap_err(), "Durable storage commit failed");
    assert!(
        object_path.is_file(),
        "rename must happen before injected directory-sync failure"
    );
    let exact = fs::read(&object_path).unwrap();
    assert_eq!(directory_usage(&directory).unwrap().1, 1);

    let receipt = store
        .save_archive_for_writer(
            "opaque-scope",
            &"w".repeat(43),
            archive.clone(),
            "archive-durable-retry-0001",
            2,
        )
        .unwrap();
    assert_eq!(receipt.payload["objectId"], id);
    assert_eq!(fs::read(&object_path).unwrap(), exact);
    assert_eq!(directory_usage(&directory).unwrap().1, 1);
    assert_eq!(store.read_archive("opaque-scope", &id).unwrap(), archive);

    drop(store);
    fs::remove_dir_all(path).unwrap();
}
