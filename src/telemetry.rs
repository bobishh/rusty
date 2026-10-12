#[cfg(test)]
#[path = "telemetry_tests.rs"]
mod tests;
// Bounded diagnostic delivery, independent of encrypted storage operations.
use serde_json::{Value, json};
use std::{sync::Arc, time::Duration};
use tokio::sync::mpsc;

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
                let url =
                    reqwest::Url::parse(endpoint).map_err(|_| "Invalid RUSTY_TELEMETRY_URL")?;
                let loopback = matches!(url.host_str(), Some("localhost" | "127.0.0.1" | "[::1]"));
                if !url.username().is_empty()
                    || url.password().is_some()
                    || url.query().is_some()
                    || url.fragment().is_some()
                    || !(url.scheme() == "https" || (url.scheme() == "http" && loopback))
                {
                    return Err(
                        "Telemetry requires HTTPS or loopback HTTP without URL credentials".into(),
                    );
                }
            }
            (None, None) => {}
            _ => return Err("Configure both RUSTY_TELEMETRY_URL and RUSTY_TELEMETRY_TOKEN".into()),
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
            std::env::var("RUSTY_TELEMETRY_URL").ok(),
            std::env::var("RUSTY_TELEMETRY_TOKEN").ok(),
            std::env::var("RUSTY_TELEMETRY_PROJECT").unwrap_or_else(|_| "rusty".into()),
        )
    }
}

struct Inner {
    level: Level,
    sender: Option<mpsc::Sender<Value>>,
    session: String,
}
#[derive(Clone)]
pub struct Telemetry(Arc<Inner>);
impl Telemetry {
    pub fn disabled() -> Self {
        Self(Arc::new(Inner {
            level: Level::Off,
            sender: None,
            session: String::new(),
        }))
    }
    pub fn start(config: Config) -> Self {
        let sender = match (config.endpoint, config.token) {
            (Some(endpoint), Some(token)) if config.level != Level::Off => {
                let (sender, receiver) = mpsc::channel(256);
                tokio::spawn(deliver(endpoint, token, config.project, receiver));
                Some(sender)
            }
            _ => None,
        };
        Self(Arc::new(Inner {
            level: config.level,
            sender,
            session: event_id(),
        }))
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
        mut attrs: Value,
    ) {
        if level == Level::Off || level > self.0.level {
            return;
        }
        let occurred_at = time::OffsetDateTime::now_utc()
            .format(&time::format_description::well_known::Rfc3339)
            .unwrap_or_default();
        attrs["level"] = json!(level.name());
        let record = json!({
            "event_id": event_id(), "occurred_at": occurred_at, "event": event,
            "build": option_env!("RUSTY_BUILD_SHA").unwrap_or("unknown"),
            "session_id": self.0.session, "device_id": "", "workspace_id": "",
            "entity_type": if scope.is_empty() { "" } else { "scope" }, "entity_id": scope,
            "trace_id": "", "span_id": "", "parent_span_id": "", "component": "rusty",
            "operation": operation, "status": status, "duration_ms": duration_ms, "attrs": attrs,
        });
        eprintln!("{record}");
        if let Some(sender) = &self.0.sender {
            if sender.try_send(record).is_err() {
                eprintln!("{{\"event\":\"rusty.telemetry.queue_full\",\"level\":\"warn\"}}");
            }
        }
    }
}

fn event_id() -> String {
    let mut bytes: [u8; 16] = rand::random();
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    let hex: String = bytes.iter().map(|byte| format!("{byte:02x}")).collect();
    format!(
        "{}-{}-{}-{}-{}",
        &hex[..8],
        &hex[8..12],
        &hex[12..16],
        &hex[16..20],
        &hex[20..]
    )
}

async fn deliver(
    endpoint: String,
    token: String,
    project: String,
    mut receiver: mpsc::Receiver<Value>,
) {
    let client = match reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(2))
        .connect_timeout(Duration::from_secs(1))
        .build()
    {
        Ok(client) => client,
        Err(_) => {
            eprintln!("{{\"event\":\"rusty.telemetry.client_failed\"}}");
            return;
        }
    };
    while let Some(first) = receiver.recv().await {
        tokio::time::sleep(Duration::from_millis(50)).await;
        let mut events = vec![first];
        while events.len() < 25 {
            match receiver.try_recv() {
                Ok(event) => events.push(event),
                Err(_) => break,
            }
        }
        let body = json!({ "schema_version": 2, "stream": "telemetry", "source": "server", "project": project, "events": events });
        let mut accepted = false;
        for attempt in 0..3 {
            let response = client
                .post(&endpoint)
                .bearer_auth(&token)
                .json(&body)
                .send()
                .await;
            if let Ok(response) = response {
                if response.status().is_success() {
                    accepted = true;
                    break;
                }
                if response.status().is_client_error()
                    && response.status() != reqwest::StatusCode::TOO_MANY_REQUESTS
                {
                    break;
                }
            }
            tokio::time::sleep(Duration::from_millis(100 * (attempt + 1))).await;
        }
        if !accepted {
            eprintln!(
                "{{\"event\":\"rusty.telemetry.delivery_failed\",\"level\":\"warn\",\"count\":{}}}",
                body["events"].as_array().map_or(0, Vec::len)
            );
        }
    }
}
