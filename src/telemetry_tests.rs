use super::*;
use axum::{Json, Router, routing::post};
use std::sync::{Arc, Mutex};

// Given configured diagnostics, when sink delivery fails once, storage-facing
// emit stays nonblocking and retries preserve event identity and level filtering.
#[tokio::test]
async fn delivery_is_nonblocking_level_filtered_and_retries_stable_events() {
    let received = Arc::new(Mutex::new(Vec::<Value>::new()));
    let records = received.clone();
    let app = Router::new().route(
        "/events",
        post(
            move |headers: axum::http::HeaderMap, Json(body): Json<Value>| {
                let records = records.clone();
                async move {
                    assert_eq!(headers["authorization"], "Bearer private-test-key");
                    let mut requests = records.lock().unwrap();
                    requests.push(body.clone());
                    if requests.len() == 1 {
                        axum::http::StatusCode::SERVICE_UNAVAILABLE
                    } else {
                        axum::http::StatusCode::OK
                    }
                }
            },
        ),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = format!("http://{}/events", listener.local_addr().unwrap());
    let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    let telemetry = Telemetry::start(
        Config::new(
            "warn",
            Some(endpoint),
            Some("private-test-key".into()),
            "rusty".into(),
        )
        .unwrap(),
    );
    let started = std::time::Instant::now();
    telemetry.emit(
        Level::Debug,
        "storage.inventory.completed",
        "inventory",
        "ok",
        "opaque",
        1.0,
        json!({}),
    );
    telemetry.emit(
        Level::Error,
        "storage.quota.exceeded",
        "upload",
        "error",
        "opaque",
        2.0,
        json!({"stored_bytes": 100, "object_count": 2, "scope_limit_bytes": 100}),
    );
    assert!(started.elapsed() < std::time::Duration::from_millis(50));
    tokio::time::timeout(std::time::Duration::from_secs(3), async {
        loop {
            if received.lock().unwrap().len() >= 2 {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    let requests = received.lock().unwrap();
    assert_eq!(requests[0], requests[1]);
    assert_eq!(requests[0]["source"], "server");
    assert_eq!(requests[0]["events"].as_array().unwrap().len(), 1);
    assert_eq!(requests[0]["events"][0]["event"], "storage.quota.exceeded");
    assert_eq!(requests[0]["events"][0]["attrs"]["stored_bytes"], 100);
    assert!(!requests[0].to_string().contains("private-test-key"));
    server.abort();
}

#[test]
fn invalid_or_partial_telemetry_configuration_fails_closed() {
    assert!(Config::new("all", None, None, "rusty".into()).is_err());
    assert!(
        Config::new(
            "debug",
            Some("https://sink.example/events".into()),
            None,
            "rusty".into()
        )
        .is_err()
    );
    assert!(
        Config::new(
            "debug",
            Some("http://public.example/events".into()),
            Some("key".into()),
            "rusty".into()
        )
        .is_err()
    );
    assert!(Config::new("off", None, None, "rusty".into()).is_ok());
}
