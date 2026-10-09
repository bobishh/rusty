//! Rusty is a blind storage peer. Application execution lives outside this binary.
use match_lighthouse::blind;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let mut args = std::env::args().skip(1);
    let first = args.next().ok_or(
        "Usage: mesh-lighthouse STATE_DIR [BIND] | mesh-lighthouse serve-http STATE_DIR [BIND]",
    )?;
    let directory = if first == "serve-http" {
        args.next().ok_or("Missing storage directory")?
    } else {
        first
    };
    if directory == "join" || directory.ends_with(".json") {
        return Err("Rusty no longer accepts readable workspace invitations/configs. Re-encrypt with an authorized client into a fresh storage directory.".into());
    }
    let bind = args
        .next()
        .or_else(|| std::env::var("RUSTY_HTTP_BIND").ok())
        .unwrap_or_else(|| "0.0.0.0:8080".into());
    if args.next().is_some() {
        return Err("Too many arguments".into());
    }
    let listener = tokio::net::TcpListener::bind(&bind).await?;
    let address = listener.local_addr()?;
    let origin = std::env::var("RUSTY_PUBLIC_ORIGIN")
        .or_else(|_| std::env::var("LIGHTHOUSE_PUBLIC_ORIGIN"))
        .unwrap_or_else(|_| format!("http://{address}"));
    let public_origin = reqwest::Url::parse(&origin)?;
    let loopback = matches!(
        public_origin.host_str(),
        Some("localhost" | "127.0.0.1" | "[::1]")
    );
    if (!public_origin.username().is_empty())
        || public_origin.password().is_some()
        || public_origin.path() != "/"
        || public_origin.query().is_some()
        || public_origin.fragment().is_some()
        || !(public_origin.scheme() == "https" || (public_origin.scheme() == "http" && loopback))
    {
        return Err("Set RUSTY_PUBLIC_ORIGIN to the external HTTPS origin; HTTP is allowed only on loopback".into());
    }
    let origin = public_origin.origin().ascii_serialization();
    let trusted_owner = std::env::var("RUSTY_TRUSTED_OWNER")
        .ok()
        .map(|value| serde_json::from_str::<blind::TrustedOwner>(&value))
        .transpose()?;
    if let Some(owner) = &trusted_owner {
        if meta_mesh_core::public_key_id(&owner.identity.public_key)? != owner.identity.person_id
            || owner.allowed_controller_device_ids.is_empty()
            || owner.allowed_controller_device_ids.len() > 32
            || owner.allowed_controller_device_ids.iter().any(|id| {
                id.is_empty()
                    || id.len() > 128
                    || !id
                        .bytes()
                        .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
            })
        {
            return Err(
                "RUSTY_TRUSTED_OWNER has invalid identity or controller device allowlist".into(),
            );
        }
    }
    let origins = std::env::var("RUSTY_CORS_ORIGINS")
        .or_else(|_| std::env::var("LIGHTHOUSE_CORS_ORIGINS"))
        .unwrap_or_default()
        .split(',')
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
        .collect();
    let store = blind::BlindStore::open(directory.into())?;
    println!(
        "Rusty blind storage listening on {address}; public key {}",
        store.public_key()?
    );
    let app = blind::router(store, origin, trusted_owner, origins)?;
    axum::serve(listener, app)
        .with_graceful_shutdown(async {
            let _ = tokio::signal::ctrl_c().await;
        })
        .await?;
    Ok(())
}
