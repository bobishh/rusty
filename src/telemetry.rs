#[cfg(test)]
#[path = "telemetry_tests.rs"]
mod tests;

use opentelemetry::{
    Context, KeyValue, global,
    logs::{AnyValue, LogRecord as _, Logger, LoggerProvider, Severity},
    propagation::Extractor,
    trace::{Span, Status, Tracer as _, TracerProvider},
};
use opentelemetry_otlp::{LogExporter, Protocol, SpanExporter, WithExportConfig, WithHttpConfig};
use opentelemetry_sdk::{
    Resource,
    logs::{BatchLogProcessor, SdkLoggerProvider},
    trace::{BatchSpanProcessor, SdkTracerProvider},
};
use serde_json::Value;
use std::{
    collections::HashMap,
    sync::Arc,
    time::{Duration, SystemTime},
};

struct TraceCarrier<'a> {
    traceparent: Option<&'a str>,
    tracestate: Option<&'a str>,
}
impl Extractor for TraceCarrier<'_> {
    fn get(&self, key: &str) -> Option<&str> {
        match key.to_ascii_lowercase().as_str() {
            "traceparent" => self.traceparent,
            "tracestate" => self.tracestate,
            _ => None,
        }
    }
    fn keys(&self) -> Vec<&str> {
        vec!["traceparent", "tracestate"]
    }
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Level {
    Off,
    Error,
    Warn,
    Info,
    Debug,
    Trace,
}
impl Level {
    fn parse(value: &str) -> Result<Self, String> {
        match value {
            "off" => Ok(Self::Off),
            "error" => Ok(Self::Error),
            "warn" => Ok(Self::Warn),
            "info" => Ok(Self::Info),
            "debug" => Ok(Self::Debug),
            "trace" => Ok(Self::Trace),
            _ => Err("RUSTY_LOG must be off, error, warn, info, debug or trace".into()),
        }
    }
    fn severity(self) -> Severity {
        match self {
            Self::Error => Severity::Error,
            Self::Warn => Severity::Warn,
            Self::Info => Severity::Info,
            Self::Debug => Severity::Debug,
            Self::Trace | Self::Off => Severity::Trace,
        }
    }
    fn name(self) -> &'static str {
        match self {
            Self::Off => "off",
            Self::Error => "error",
            Self::Warn => "warn",
            Self::Info => "info",
            Self::Debug => "debug",
            Self::Trace => "trace",
        }
    }
}

pub struct Config {
    level: Level,
    endpoint: Option<String>,
    token: Option<String>,
    project: String,
}
impl Config {
    pub fn new(
        level: &str,
        endpoint: Option<String>,
        token: Option<String>,
        project: String,
    ) -> Result<Self, String> {
        let level = Level::parse(level)?;
        if project.is_empty()
            || project.len() > 64
            || !project
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        {
            return Err("Invalid RUSTY_TELEMETRY_PROJECT".into());
        }
        match (&endpoint, &token) {
            (Some(endpoint), Some(token)) if !token.is_empty() && token.len() <= 256 => {
                let url = reqwest::Url::parse(endpoint)
                    .map_err(|_| "Invalid OTEL_EXPORTER_OTLP_ENDPOINT")?;
                let loopback = matches!(url.host_str(), Some("localhost" | "127.0.0.1" | "[::1]"));
                if !url.username().is_empty()
                    || url.password().is_some()
                    || url.query().is_some()
                    || url.fragment().is_some()
                    || !(url.scheme() == "https" || (url.scheme() == "http" && loopback))
                {
                    return Err(
                        "OTLP requires HTTPS or loopback HTTP without URL credentials".into(),
                    );
                }
            }
            (None, None) => {}
            _ => {
                return Err(
                    "Configure both OTEL_EXPORTER_OTLP_ENDPOINT and RUSTY_TELEMETRY_TOKEN".into(),
                );
            }
        }
        Ok(Self {
            level,
            endpoint,
            token,
            project,
        })
    }
    pub fn from_env() -> Result<Self, String> {
        Self::new(
            &std::env::var("RUSTY_LOG").unwrap_or_else(|_| "info".into()),
            std::env::var("OTEL_EXPORTER_OTLP_ENDPOINT").ok(),
            std::env::var("RUSTY_TELEMETRY_TOKEN").ok(),
            std::env::var("RUSTY_TELEMETRY_PROJECT").unwrap_or_else(|_| "rusty".into()),
        )
    }
}

struct Inner {
    level: Level,
    logger: Option<opentelemetry_sdk::logs::SdkLogger>,
    tracer: Option<opentelemetry_sdk::trace::SdkTracer>,
    logs: Option<SdkLoggerProvider>,
    traces: Option<SdkTracerProvider>,
}
#[derive(Clone)]
pub struct Telemetry(Arc<Inner>);
impl Telemetry {
    pub fn disabled() -> Self {
        Self(Arc::new(Inner {
            level: Level::Off,
            logger: None,
            tracer: None,
            logs: None,
            traces: None,
        }))
    }

    /// Diagnostics are optional; invalid telemetry settings must never block service startup.
    pub fn start_optional(config: Result<Config, String>) -> Self {
        match config {
            Ok(config) => Self::start(config),
            Err(_) => {
                eprintln!("{{\"event\":\"rusty.telemetry.configuration_invalid\"}}");
                Self::disabled()
            }
        }
    }

    pub fn start(config: Config) -> Self {
        global::set_text_map_propagator(
            opentelemetry_sdk::propagation::TraceContextPropagator::new(),
        );
        let mut inner = Inner {
            level: config.level,
            logger: None,
            tracer: None,
            logs: None,
            traces: None,
        };
        if let (Some(endpoint), Some(token)) = (config.endpoint, config.token) {
            if config.level != Level::Off {
                let headers = HashMap::from([
                    ("authorization".to_string(), format!("Bearer {token}")),
                    ("x-tinsink-project".to_string(), config.project),
                    ("x-tinsink-source".to_string(), "server".to_string()),
                ]);
                let resource = Resource::builder()
                    .with_service_name("mesh-lighthouse")
                    .with_attributes([
                        KeyValue::new(
                            "service.version",
                            option_env!("RUSTY_BUILD_SHA").unwrap_or("unknown"),
                        ),
                        KeyValue::new("deployment.environment.name", "production"),
                    ])
                    .build();
                let logs_exporter = LogExporter::builder()
                    .with_http()
                    .with_endpoint(signal_endpoint(&endpoint, "logs"))
                    .with_protocol(Protocol::HttpJson)
                    .with_headers(headers.clone())
                    .with_timeout(Duration::from_secs(2))
                    .build();
                let spans_exporter = SpanExporter::builder()
                    .with_http()
                    .with_endpoint(signal_endpoint(&endpoint, "traces"))
                    .with_protocol(Protocol::HttpJson)
                    .with_headers(headers)
                    .with_timeout(Duration::from_secs(2))
                    .build();
                match (logs_exporter, spans_exporter) {
                    (Ok(logs_exporter), Ok(spans_exporter)) => {
                        let logs = SdkLoggerProvider::builder()
                            .with_resource(resource.clone())
                            .with_log_processor(BatchLogProcessor::builder(logs_exporter).build())
                            .build();
                        let traces = SdkTracerProvider::builder()
                            .with_resource(resource)
                            .with_span_processor(
                                BatchSpanProcessor::builder(spans_exporter).build(),
                            )
                            .build();
                        inner.logger = Some(logs.logger("rusty"));
                        inner.tracer = Some(traces.tracer("rusty"));
                        inner.logs = Some(logs);
                        inner.traces = Some(traces);
                    }
                    _ => eprintln!("{{\"event\":\"rusty.telemetry.exporter_init_failed\"}}"),
                }
            }
        }
        Self(Arc::new(inner))
    }

    #[allow(clippy::too_many_arguments)]
    pub fn emit(
        &self,
        level: Level,
        event: &str,
        operation: &str,
        status: &str,
        scope: &str,
        duration_ms: f64,
        attrs: Value,
    ) {
        self.emit_with_parent(
            level,
            event,
            operation,
            status,
            scope,
            duration_ms,
            attrs,
            None,
            None,
        );
    }

    #[allow(clippy::too_many_arguments)]
    pub fn emit_with_parent(
        &self,
        level: Level,
        event: &str,
        operation: &str,
        status: &str,
        scope: &str,
        duration_ms: f64,
        attrs: Value,
        traceparent: Option<&str>,
        tracestate: Option<&str>,
    ) {
        if level == Level::Off || level > self.0.level {
            return;
        }
        let now = SystemTime::now();
        let carrier = TraceCarrier {
            traceparent,
            tracestate,
        };
        let parent_context = if traceparent.is_some() || tracestate.is_some() {
            global::get_text_map_propagator(|propagator| propagator.extract(&carrier))
        } else {
            Context::current()
        };
        let mut span_context = None;
        if let Some(tracer) = &self.0.tracer {
            let elapsed = Duration::from_secs_f64((duration_ms.max(0.0).min(3_600_000.0)) / 1000.0);
            let started = now.checked_sub(elapsed).unwrap_or(now);
            let mut span = tracer.build_with_context(
                tracer
                    .span_builder(event.to_owned())
                    .with_start_time(started),
                &parent_context,
            );
            span.set_attribute(KeyValue::new("operation", operation.to_owned()));
            span.set_attribute(KeyValue::new("operation.status", status.to_owned()));
            span.set_attribute(KeyValue::new("duration_ms", duration_ms));
            span.set_attribute(KeyValue::new("service.name", "mesh-lighthouse"));
            if !scope.is_empty() {
                span.set_attribute(KeyValue::new("server.scope_id", scope.to_owned()));
            }
            if status == "error" {
                span.set_status(Status::error(event.to_owned()));
            }
            for (key, value) in safe_attributes(&attrs) {
                span.set_attribute(KeyValue::new(key, value));
            }
            span_context = Some(span.span_context().clone());
            span.end();
        }
        if let Some(logger) = &self.0.logger {
            let mut record = logger.create_log_record();
            record.set_timestamp(now);
            record.set_observed_timestamp(now);
            record.set_event_name("rusty.operation");
            record.set_severity_number(level.severity());
            record.set_severity_text(level.name());
            record.set_body(AnyValue::String(format!("{event}: {status}").into()));
            if let Some(span_context) = span_context {
                record.set_trace_context(
                    span_context.trace_id(),
                    span_context.span_id(),
                    Some(span_context.trace_flags()),
                );
            }
            record.add_attribute("event.name", event.to_owned());
            record.add_attribute("operation", operation.to_owned());
            record.add_attribute("operation.status", status.to_owned());
            record.add_attribute("service.name", "mesh-lighthouse");
            if !scope.is_empty() {
                record.add_attribute("server.scope_id", scope.to_owned());
            }
            record.add_attribute("duration_ms", duration_ms);
            for (key, value) in safe_attributes(&attrs) {
                record.add_attribute(key, value);
            }
            logger.emit(record);
        }
        if self.0.logger.is_none() && self.0.tracer.is_none() {
            eprintln!(
                "{{\"service\":\"mesh-lighthouse\",\"event\":{},\"operation\":{},\"status\":{},\"level\":{}}}",
                serde_json::to_string(event).unwrap_or_default(),
                serde_json::to_string(operation).unwrap_or_default(),
                serde_json::to_string(status).unwrap_or_default(),
                serde_json::to_string(level.name()).unwrap_or_default()
            );
        }
    }

    pub fn shutdown(&self) {
        if let Some(logs) = &self.0.logs {
            let _ = logs.shutdown_with_timeout(Duration::from_secs(2));
        }
        if let Some(traces) = &self.0.traces {
            let _ = traces.shutdown_with_timeout(Duration::from_secs(2));
        }
    }

    pub fn force_flush(&self) {
        if let Some(logs) = &self.0.logs {
            if let Err(error) = logs.force_flush() {
                eprintln!(
                    "{{\"event\":\"rusty.telemetry.logs_flush_failed\",\"error\":{}}}",
                    serde_json::to_string(&error.to_string()).unwrap_or_default()
                );
            }
        }
        if let Some(traces) = &self.0.traces {
            if let Err(error) = traces.force_flush() {
                eprintln!(
                    "{{\"event\":\"rusty.telemetry.traces_flush_failed\",\"error\":{}}}",
                    serde_json::to_string(&error.to_string()).unwrap_or_default()
                );
            }
        }
    }
}

fn signal_endpoint(base: &str, signal: &str) -> String {
    format!("{}/v1/{signal}", base.trim_end_matches('/'))
}

fn safe_attributes(value: &Value) -> Vec<(String, String)> {
    value
        .as_object()
        .into_iter()
        .flat_map(|attrs| attrs.iter())
        .filter_map(|(key, value)| {
            let normalized = key.to_ascii_lowercase();
            let exception_limit = match normalized.as_str() {
                "exception.type" => Some(128),
                "exception.message" => Some(2_048),
                "exception.stacktrace" => Some(16_384),
                _ => None,
            };
            if exception_limit.is_none()
                && (normalized.contains("token")
                    || normalized.contains("secret")
                    || normalized.contains("password")
                    || normalized.contains("private")
                    || normalized.contains("key")
                    || normalized.contains("content")
                    || normalized.contains("body")
                    || normalized.contains("payload"))
            {
                return None;
            }
            let text = match value {
                Value::String(text) => text,
                Value::Number(_) | Value::Bool(_) => {
                    return Some((format!("rusty.{key}"), value.to_string()));
                }
                _ => return None,
            };
            let sanitized = redact_credentials(text);
            let limit = exception_limit.unwrap_or(256);
            let bounded = bounded_text(&sanitized, limit);
            Some((
                if exception_limit.is_some() {
                    key.clone()
                } else {
                    format!("rusty.{key}")
                },
                bounded,
            ))
        })
        .collect()
}

fn bounded_text(input: &str, limit: usize) -> String {
    let cleaned: String = input
        .chars()
        .filter(|character| !character.is_control() || *character == '\n' || *character == '\t')
        .collect();
    let mut characters = cleaned.chars();
    let bounded: String = characters.by_ref().take(limit).collect();
    if characters.next().is_some() {
        let mut truncated: String = bounded.chars().take(limit.saturating_sub(1)).collect();
        truncated.push('…');
        truncated
    } else {
        bounded
    }
}

fn redact_credentials(input: &str) -> String {
    let mut value = redact_private_key_blocks(input);
    value = redact_bearer_values(&value);
    value = redact_named_values(&value);
    redact_url_credentials(&value)
}

fn redact_private_key_blocks(input: &str) -> String {
    let mut output = String::with_capacity(input.len());
    let mut remaining = input;
    while let Some(start) = remaining.find("-----BEGIN ") {
        let label_start = start + "-----BEGIN ".len();
        let Some(header_end) = remaining[label_start..].find("-----") else {
            break;
        };
        let header_end = label_start + header_end;
        let label = &remaining[label_start..header_end];
        if !label.ends_with("PRIVATE KEY")
            || !label
                .bytes()
                .all(|byte| byte.is_ascii_uppercase() || byte == b' ')
        {
            output.push_str(&remaining[..label_start]);
            remaining = &remaining[label_start..];
            continue;
        }
        let end_marker = format!("-----END {label}-----");
        let Some(end_offset) = remaining[header_end + 5..].find(&end_marker) else {
            break;
        };
        let end = header_end + 5 + end_offset + end_marker.len();
        output.push_str(&remaining[..start]);
        output.push_str("[REDACTED PRIVATE KEY]");
        remaining = &remaining[end..];
    }
    output.push_str(remaining);
    output
}

fn redact_bearer_values(input: &str) -> String {
    let lower = input.to_ascii_lowercase();
    let mut output = String::with_capacity(input.len());
    let mut copied = 0;
    let mut cursor = 0;
    while cursor < input.len() {
        let scheme = ["bearer", "basic"].into_iter().find(|scheme| {
            lower[cursor..].starts_with(scheme)
                && (cursor == 0 || !input.as_bytes()[cursor - 1].is_ascii_alphanumeric())
        });
        let Some(scheme) = scheme else {
            cursor += input[cursor..].chars().next().map_or(1, char::len_utf8);
            continue;
        };
        let mut token_start = cursor + scheme.len();
        if token_start >= input.len() || !input.as_bytes()[token_start].is_ascii_whitespace() {
            cursor += scheme.len();
            continue;
        }
        while token_start < input.len() && input.as_bytes()[token_start].is_ascii_whitespace() {
            token_start += 1;
        }
        let mut token_end = token_start;
        while token_end < input.len()
            && !matches!(
                input.as_bytes()[token_end],
                b' ' | b'\t' | b'\n' | b'\r' | b',' | b';' | b'"' | b'\''
            )
        {
            token_end += 1;
        }
        if token_end == token_start {
            cursor += scheme.len();
            continue;
        }
        output.push_str(&input[copied..cursor]);
        output.push_str(&input[cursor..cursor + scheme.len()]);
        output.push_str(" [REDACTED]");
        copied = token_end;
        cursor = token_end;
    }
    output.push_str(&input[copied..]);
    output
}

fn redact_named_values(input: &str) -> String {
    const NAMES: &[&str] = &[
        "identity_private_key",
        "identity-private-key",
        "identity private key",
        "identityprivatekey",
        "device_private_key",
        "device-private-key",
        "device private key",
        "deviceprivatekey",
        "private_key",
        "private-key",
        "private key",
        "privatekey",
        "privatekeys",
        "private_keys",
        "private-keys",
        "private keys",
        "access_token",
        "access-token",
        "access token",
        "accesstoken",
        "refresh_token",
        "refresh-token",
        "refresh token",
        "refreshtoken",
        "read_token",
        "read-token",
        "read token",
        "readtoken",
        "write_token",
        "write-token",
        "write token",
        "writetoken",
        "id_token",
        "id-token",
        "id token",
        "idtoken",
        "api_key",
        "api-key",
        "api key",
        "apikey",
        "client_secret",
        "client-secret",
        "client secret",
        "clientsecret",
        "content_key",
        "content-key",
        "content key",
        "contentkey",
        "authorization",
        "credential",
        "password",
        "passwd",
        "secret",
        "token",
    ];
    let lower = input.to_ascii_lowercase();
    let bytes = input.as_bytes();
    let mut output = String::with_capacity(input.len());
    let mut copied = 0;
    let mut cursor = 0;
    while cursor < bytes.len() {
        let quoted = matches!(bytes[cursor], b'"' | b'\'');
        let key_start = cursor + usize::from(quoted);
        let boundary = cursor == 0
            || !(bytes[cursor - 1].is_ascii_alphanumeric() || bytes[cursor - 1] == b'_');
        let name = if boundary {
            NAMES.iter().find(|name| {
                lower[key_start..].starts_with(**name) && {
                    let end = key_start + name.len();
                    end == bytes.len()
                        || !(bytes[end].is_ascii_alphanumeric() || bytes[end] == b'_')
                }
            })
        } else {
            None
        };
        let Some(name) = name else {
            cursor += input[cursor..].chars().next().map_or(1, char::len_utf8);
            continue;
        };
        let mut separator = key_start + name.len();
        if quoted {
            if separator >= bytes.len() || bytes[separator] != bytes[cursor] {
                cursor += 1;
                continue;
            }
            separator += 1;
        }
        while separator < bytes.len() && bytes[separator].is_ascii_whitespace() {
            separator += 1;
        }
        if separator >= bytes.len() || !matches!(bytes[separator], b':' | b'=') {
            cursor += 1;
            continue;
        }
        separator += 1;
        while separator < bytes.len() && bytes[separator].is_ascii_whitespace() {
            separator += 1;
        }
        if separator >= bytes.len() {
            break;
        }
        let value_quoted = matches!(bytes[separator], b'"' | b'\'');
        let value_start = separator + usize::from(value_quoted);
        let mut value_end = value_start;
        let private_key_collection =
            name.contains("private") && name.contains("key") && name.ends_with('s');
        if private_key_collection && !value_quoted && bytes.get(value_start) == Some(&b'{') {
            let mut depth = 0usize;
            let mut quoted = false;
            let mut escaped = false;
            while value_end < bytes.len() {
                let byte = bytes[value_end];
                if quoted {
                    if byte == b'"' && !escaped {
                        quoted = false;
                    }
                    if byte == b'\\' && !escaped {
                        escaped = true;
                    } else {
                        escaped = false;
                    }
                } else if byte == b'"' {
                    quoted = true;
                } else if byte == b'{' {
                    depth += 1;
                } else if byte == b'}' {
                    depth = depth.saturating_sub(1);
                    if depth == 0 {
                        value_end += 1;
                        break;
                    }
                }
                value_end += 1;
            }
        } else if value_quoted {
            let quote = bytes[separator];
            let mut escaped = false;
            while value_end < bytes.len() {
                if bytes[value_end] == quote && !escaped {
                    break;
                }
                if bytes[value_end] == b'\\' && !escaped {
                    escaped = true;
                } else {
                    escaped = false;
                }
                value_end += 1;
            }
        } else {
            while value_end < bytes.len()
                && !matches!(
                    bytes[value_end],
                    b' ' | b'\t' | b'\n' | b'\r' | b',' | b';' | b'&' | b'}' | b'#'
                )
            {
                value_end += 1;
            }
        }
        if value_end == value_start {
            cursor += 1;
            continue;
        }
        output.push_str(&input[copied..value_start]);
        output.push_str("[REDACTED]");
        if value_quoted && value_end < bytes.len() {
            output.push(bytes[separator] as char);
            value_end += 1;
        }
        copied = value_end;
        cursor = value_end;
    }
    output.push_str(&input[copied..]);
    output
}

fn redact_url_credentials(input: &str) -> String {
    let mut output = String::with_capacity(input.len());
    let mut copied = 0;
    let mut cursor = 0;
    while cursor < input.len() {
        let rest = &input[cursor..];
        let next_https = rest.find("https://").map(|offset| (offset, 8));
        let next_http = rest.find("http://").map(|offset| (offset, 7));
        let next = match (next_https, next_http) {
            (Some(https), Some(http)) => Some(if https.0 <= http.0 { https } else { http }),
            (Some(https), None) => Some(https),
            (None, Some(http)) => Some(http),
            (None, None) => None,
        };
        let Some((offset, scheme_length)) = next else {
            break;
        };
        let url_start = cursor + offset;
        let authority_start = url_start + scheme_length;
        let authority_end = input[authority_start..]
            .find(['/', '?', '#', ' ', '\n', '\t'])
            .map_or(input.len(), |offset| authority_start + offset);
        let authority = &input[authority_start..authority_end];
        if let Some(at) = authority.find('@') {
            let user_info = &authority[..at];
            if user_info.contains(':') {
                output.push_str(&input[copied..authority_start]);
                output.push_str("[REDACTED]@");
                copied = authority_start + at + 1;
                cursor = authority_start + at + 1;
                continue;
            }
        }
        cursor = authority_end;
    }
    output.push_str(&input[copied..]);
    output
}

impl Drop for Inner {
    fn drop(&mut self) {
        if let Some(provider) = self.logs.take() {
            let _ = provider.shutdown();
        }
        if let Some(provider) = self.traces.take() {
            let _ = provider.shutdown();
        }
    }
}
