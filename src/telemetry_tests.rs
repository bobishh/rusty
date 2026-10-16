use super::*;
use axum::{Json, Router, http::HeaderMap, routing::post};
use std::sync::{Arc, Mutex};

#[tokio::test(flavor = "multi_thread")]
async fn official_otlp_exporters_send_standard_logs_and_spans_with_gateway_auth() {
    let captured = Arc::new(Mutex::new(Vec::<(String, HeaderMap, Value)>::new()));
    let output = captured.clone();
    let trace_output = captured.clone();
    let app = Router::new()
        .route(
            "/v1/logs",
            post(move |headers: HeaderMap, Json(body): Json<Value>| {
                output.lock().unwrap().push(("logs".into(), headers, body));
                async { Json(serde_json::json!({})) }
            }),
        )
        .route(
            "/v1/traces",
            post(move |headers: HeaderMap, Json(body): Json<Value>| {
                trace_output
                    .lock()
                    .unwrap()
                    .push(("traces".into(), headers, body));
                async { Json(serde_json::json!({})) }
            }),
        );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = format!("http://{}", listener.local_addr().unwrap());
    let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    let telemetry = Telemetry::start(
        Config::new(
            "warn",
            Some(endpoint),
            Some("private-test-key".into()),
            "rusty-test".into(),
        )
        .unwrap(),
    );
    telemetry.emit_with_parent(Level::Error, "storage.quota.exceeded", "upload", "error", "opaque-scope", 2.0,
        serde_json::json!({"stored_bytes": 100, "privateKey": "must-not-export", "content": "private board text"}),
        Some("00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"), Some("vendor=value"));
    telemetry.force_flush();

    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if captured.lock().unwrap().len() >= 2 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .unwrap();

    let requests = captured.lock().unwrap();
    let logs = &requests
        .iter()
        .find(|(signal, _, _)| signal == "logs")
        .unwrap()
        .2;
    let traces = &requests
        .iter()
        .find(|(signal, _, _)| signal == "traces")
        .unwrap()
        .2;
    assert!(logs["resourceLogs"][0]["scopeLogs"][0]["logRecords"].is_array());
    let log_json = logs.to_string();
    assert!(log_json.contains("storage.quota.exceeded"));
    assert!(log_json.contains("stored_bytes"));
    assert!(!log_json.contains("private board text"));
    assert!(!log_json.contains("must-not-export"));
    assert!(traces["resourceSpans"][0]["scopeSpans"][0]["spans"].is_array());
    assert_eq!(
        traces["resourceSpans"][0]["scopeSpans"][0]["spans"][0]["parentSpanId"],
        "00f067aa0ba902b7"
    );
    for (_, headers, _) in requests.iter() {
        assert_eq!(headers["authorization"], "Bearer private-test-key");
        assert_eq!(headers["x-tinsink-project"], "rusty-test");
        assert_eq!(headers["x-tinsink-source"], "server");
    }
    assert!(
        !requests
            .iter()
            .any(|(_, _, body)| body.to_string().contains("private-test-key"))
    );
    drop(requests);
    telemetry.shutdown();
    server.abort();
}

#[test]
fn invalid_or_partial_otlp_configuration_fails_closed() {
    assert!(Config::new("all", None, None, "rusty".into()).is_err());
    assert!(
        Config::new(
            "debug",
            Some("https://collector.example".into()),
            None,
            "rusty".into()
        )
        .is_err()
    );
    assert!(
        Config::new(
            "debug",
            Some("http://public.example".into()),
            Some("key".into()),
            "rusty".into()
        )
        .is_err()
    );
    assert!(
        Config::new(
            "debug",
            Some("https://collector.example?token=secret".into()),
            Some("key".into()),
            "rusty".into()
        )
        .is_err()
    );
    assert!(Config::new("off", None, None, "rusty".into()).is_ok());
}

#[test]
fn optional_diagnostic_configuration_never_blocks_service_startup() {
    let telemetry = Telemetry::start_optional(Config::new(
        "debug",
        Some("https://collector.example".into()),
        None,
        "rusty".into(),
    ));
    assert!(telemetry.0.logger.is_none());
    assert!(telemetry.0.tracer.is_none());
    telemetry.emit(
        Level::Error,
        "startup.probe",
        "start",
        "error",
        "",
        0.0,
        serde_json::json!({}),
    );
}

#[test]
fn signal_urls_follow_standard_otlp_http_json_paths() {
    assert_eq!(
        signal_endpoint("https://collector.example/otlp/", "logs"),
        "https://collector.example/otlp/v1/logs"
    );
    assert_eq!(
        signal_endpoint("http://127.0.0.1:4318", "traces"),
        "http://127.0.0.1:4318/v1/traces"
    );
}

#[test]
fn https_collector_builds_otlp_exporters() {
    let config = Config::new(
        "debug",
        Some("https://collector.example/otlp".into()),
        Some("test-private-key".into()),
        "rusty-test".into(),
    )
    .unwrap();
    let telemetry = Telemetry::start(config);
    assert!(telemetry.0.logger.is_some());
    assert!(telemetry.0.tracer.is_some());
    telemetry.shutdown();
}

#[test]
fn standard_exception_attributes_keep_bounded_context_and_redact_credentials() {
    let long_stack = format!("{}tail", "frame ".repeat(100));
    let attributes = safe_attributes(&serde_json::json!({
        "exception.type": "StorageError",
        "exception.message": "write failed; Bearer top-secret password=hidden; Basic c2VjcmV0; \"access token\": \"quoted value with spaces\"; privateKeys={\"one\":\"secret\",\"two\":\"secret2\"}; https://user:pass@example.com; -----BEGIN PRIVATE KEY-----\\nKEYDATA\\n-----END PRIVATE KEY-----",
        "exception.stacktrace": long_stack,
        "bytes": 12,
        "privateKey": "never-export",
    }));
    let fields: std::collections::HashMap<_, _> = attributes.into_iter().collect();
    assert_eq!(fields["exception.type"], "StorageError");
    assert_eq!(
        fields["exception.message"],
        "write failed; Bearer [REDACTED] password=[REDACTED]; Basic [REDACTED]; \"access token\": \"[REDACTED]\"; privateKeys=[REDACTED]; https://[REDACTED]@example.com; [REDACTED PRIVATE KEY]"
    );
    assert_eq!(fields["exception.stacktrace"].len(), 604);
    assert!(fields["exception.stacktrace"].ends_with("tail"));
    assert_eq!(fields["rusty.bytes"], "12");
    assert!(!fields.contains_key("rusty.exception.message"));
    assert!(!fields.contains_key("rusty.privateKey"));
}

#[test]
fn standard_exception_fields_respect_message_and_stack_limits() {
    let attributes = safe_attributes(&serde_json::json!({
        "exception.type": "T".repeat(130),
        "exception.message": "m".repeat(2_100),
        "exception.stacktrace": "s".repeat(16_500),
    }));
    let fields: std::collections::HashMap<_, _> = attributes.into_iter().collect();
    assert_eq!(fields["exception.type"].chars().count(), 128);
    assert_eq!(fields["exception.message"].chars().count(), 2_048);
    assert!(fields["exception.message"].ends_with('…'));
    assert_eq!(fields["exception.stacktrace"].chars().count(), 16_384);
    assert!(fields["exception.stacktrace"].ends_with('…'));
}
