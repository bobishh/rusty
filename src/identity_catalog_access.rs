//! Opaque encrypted Identity catalog access, independent of workspace storage tokens.
use super::*;
use crate::identity_authority::VerifiedIdentityAuthorityView;

pub(super) const PUBLISH_MAX_BYTES: usize = 128 * 1024;
const CIPHERTEXT_MAX_BYTES: usize = 48 * 1024;
pub(super) const LIST_REQUEST_MAX_BYTES: usize = 16 * 1024;
const LIST_MAX_ENTRIES: usize = 8;
const LIST_MAX_BYTES: usize = 384 * 1024;
const MAX_ORIGIN_BYTES: usize = 512;
const MAX_PIN_COUNT: usize = 64;
const LIST_TTL_MS: u64 = 120_000;
const REQUEST_DOMAIN: &str = "MESH-IDENTITY-CATALOG-ACCESS-REQUEST/1";
const CATALOG_ACCESS_PENDING_MESSAGE: &str =
    "Identity catalog publication is pending for this manager";

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct CatalogPublicationReceipt {
    kind: String,
    version: u8,
    service_id: String,
    origin: String,
    publisher_device_id: String,
    person_id: String,
    application_origin: String,
    catalog_id: String,
    source_revision: u64,
    recipient_device_id: String,
    recipient_public_key_id: String,
    envelope_hash: String,
    issued_at: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct CatalogListReceipt {
    kind: String,
    version: u8,
    service_id: String,
    origin: String,
    request_hash: String,
    person_id: String,
    application_origin: String,
    recipient_device_id: String,
    recipient_public_key_id: String,
    challenge: String,
    envelope_count: u8,
    envelope_list_hash: String,
    issued_at: u64,
    expires_at: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct StoredCatalogAccess {
    version: u8,
    envelope: SignedEnvelope<Value>,
    receipt: SignedEnvelope<CatalogPublicationReceipt>,
}

struct PublicationBinding {
    service_id: String,
    publisher_device_id: String,
    person_id: String,
    application_origin: String,
    catalog_id: String,
    source_revision: u64,
    recipient_device_id: String,
    recipient_public_key_id: String,
    recipient_public_key: String,
}

#[derive(Debug)]
struct CatalogAccessError(StatusCode, &'static str);

type CatalogResult<T> = Result<T, CatalogAccessError>;

fn valid_hash(value: &str) -> bool {
    value.len() == 43
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-')
}

fn valid_application_challenge(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn reject<T>(status: StatusCode, message: &'static str) -> CatalogResult<T> {
    Err(CatalogAccessError(status, message))
}

fn exact_keys(value: &Value, keys: &[&str]) -> bool {
    value.as_object().is_some_and(|object| {
        object.len() == keys.len() && keys.iter().all(|key| object.contains_key(*key))
    })
}

fn envelope_shape(value: &Value) -> bool {
    exact_keys(value, &["payload", "signerKeyId", "signature"])
        && value["payload"].is_object()
        && value["signerKeyId"].as_str().is_some_and(valid_id)
        && value["signature"].as_str().is_some_and(|signature| {
            URL_SAFE_NO_PAD
                .decode(signature)
                .is_ok_and(|bytes| bytes.len() == 64)
        })
}

fn canonical_origin(value: &str) -> bool {
    if value.is_empty()
        || value.len() > MAX_ORIGIN_BYTES
        || value.bytes().any(|byte| !byte.is_ascii())
    {
        return false;
    }
    let (scheme, authority_text) = if let Some(authority) = value.strip_prefix("https://") {
        ("https", authority)
    } else if let Some(authority) = value.strip_prefix("http://") {
        ("http", authority)
    } else {
        return false;
    };
    if authority_text.is_empty()
        || authority_text
            .bytes()
            .any(|byte| matches!(byte, b'/' | b'?' | b'#' | b'@'))
    {
        return false;
    }
    let Ok(authority) = authority_text.parse::<axum::http::uri::Authority>() else {
        return false;
    };
    let host = authority.host();
    if host.is_empty() || host != host.to_ascii_lowercase() || authority.as_str() != authority_text
    {
        return false;
    }
    let default_port = if scheme == "https" { 443 } else { 80 };
    if authority.port_u16() == Some(default_port) {
        return false;
    }
    if scheme == "http" && !matches!(host, "localhost" | "127.0.0.1" | "[::1]") {
        return false;
    }
    true
}

fn digest_value(value: &Value) -> Result<String, String> {
    Ok(digest(canonicalize_json(value)?.as_bytes()))
}

fn certificate_json_shape(value: &Value) -> bool {
    exact_keys(value, &["payload", "signerKeyId", "signature"])
        && exact_keys(
            &value["payload"],
            &[
                "kind",
                "version",
                "personId",
                "deviceId",
                "devicePublicKey",
                "issuerCertificateHash",
                "canEnrollDevices",
            ],
        )
}

fn publication_binding(
    envelope: &SignedEnvelope<Value>,
    store: &BlindStore,
    origin: &str,
) -> CatalogResult<PublicationBinding> {
    let value = serde_json::to_value(envelope)
        .map_err(|_| CatalogAccessError(StatusCode::BAD_REQUEST, "Invalid catalog publication"))?;
    if !envelope_shape(&value)
        || !exact_keys(
            &value["payload"],
            &[
                "kind",
                "version",
                "serviceId",
                "personId",
                "applicationOrigin",
                "catalogId",
                "sourceRevision",
                "recipientDeviceId",
                "recipientPublicKeyId",
                "recipientPublicKey",
                "ciphertext",
                "issuedAt",
                "publisherAuthorization",
            ],
        )
    {
        return reject(StatusCode::BAD_REQUEST, "Invalid catalog publication");
    }
    let payload = &envelope.payload;
    let service_id = public_key_id(&store.public_key().map_err(|_| {
        CatalogAccessError(
            StatusCode::SERVICE_UNAVAILABLE,
            "Rusty identity unavailable",
        )
    })?)
    .map_err(|_| {
        CatalogAccessError(
            StatusCode::SERVICE_UNAVAILABLE,
            "Rusty identity unavailable",
        )
    })?;
    let person_id = payload["personId"]
        .as_str()
        .filter(|value| valid_id(value))
        .ok_or(CatalogAccessError(
            StatusCode::BAD_REQUEST,
            "Invalid catalog publication",
        ))?;
    let application_origin = payload["applicationOrigin"]
        .as_str()
        .filter(|value| canonical_origin(value))
        .ok_or(CatalogAccessError(
            StatusCode::BAD_REQUEST,
            "Invalid catalog publication",
        ))?;
    let catalog_id = payload["catalogId"]
        .as_str()
        .filter(|value| valid_id(value))
        .ok_or(CatalogAccessError(
            StatusCode::BAD_REQUEST,
            "Invalid catalog publication",
        ))?;
    let source_revision = payload["sourceRevision"]
        .as_u64()
        .filter(|value| *value > 0 && *value <= MAX_SAFE_JS_INTEGER)
        .ok_or(CatalogAccessError(
            StatusCode::BAD_REQUEST,
            "Invalid catalog publication",
        ))?;
    let recipient_device_id = payload["recipientDeviceId"]
        .as_str()
        .filter(|value| valid_id(value))
        .ok_or(CatalogAccessError(
            StatusCode::BAD_REQUEST,
            "Invalid catalog publication",
        ))?;
    let recipient_public_key_id = payload["recipientPublicKeyId"]
        .as_str()
        .filter(|value| valid_id(value))
        .ok_or(CatalogAccessError(
            StatusCode::BAD_REQUEST,
            "Invalid catalog publication",
        ))?;
    let recipient_public_key = payload["recipientPublicKey"]
        .as_str()
        .filter(|value| !value.is_empty() && value.len() <= 128)
        .ok_or(CatalogAccessError(
            StatusCode::BAD_REQUEST,
            "Invalid catalog publication",
        ))?;
    payload["ciphertext"]
        .as_str()
        .filter(|value| {
            !value.is_empty()
                && value.len() <= CIPHERTEXT_MAX_BYTES
                && URL_SAFE_NO_PAD.decode(value).is_ok()
        })
        .ok_or(CatalogAccessError(
            StatusCode::BAD_REQUEST,
            "Invalid catalog publication",
        ))?;
    let issued_at = payload["issuedAt"]
        .as_u64()
        .filter(|value| *value <= MAX_SAFE_JS_INTEGER)
        .ok_or(CatalogAccessError(
            StatusCode::BAD_REQUEST,
            "Invalid catalog publication",
        ))?;
    let publisher_device_id = envelope.signer_key_id.as_str();
    if payload["kind"] != "mesh-identity-catalog-access-publication"
        || payload["version"] != 1
        || payload["serviceId"] != service_id
        || envelope.signer_key_id != publisher_device_id
        || payload["recipientPublicKeyId"] != recipient_public_key_id
        || payload["recipientDeviceId"] != recipient_device_id
        || payload["applicationOrigin"] != application_origin
        || !valid_id(publisher_device_id)
        || issued_at
            > now_ms()
                .map_err(|_| {
                    CatalogAccessError(StatusCode::SERVICE_UNAVAILABLE, "System clock unavailable")
                })?
                .saturating_add(30_000)
        || origin.is_empty()
    {
        return reject(
            StatusCode::BAD_REQUEST,
            "Catalog publication binding is invalid",
        );
    }
    let authorization = &payload["publisherAuthorization"];
    if !exact_keys(
        authorization,
        &["request", "proof", "certificate", "rustyServicePins"],
    ) || !envelope_shape(&authorization["request"])
        || !envelope_shape(&authorization["proof"])
        || !certificate_json_shape(&authorization["certificate"])
    {
        return reject(
            StatusCode::BAD_REQUEST,
            "Catalog publisher authorization is invalid",
        );
    }
    Ok(PublicationBinding {
        service_id,
        publisher_device_id: publisher_device_id.to_owned(),
        person_id: person_id.to_owned(),
        application_origin: application_origin.to_owned(),
        catalog_id: catalog_id.to_owned(),
        source_revision,
        recipient_device_id: recipient_device_id.to_owned(),
        recipient_public_key_id: recipient_public_key_id.to_owned(),
        recipient_public_key: recipient_public_key.to_owned(),
    })
}

fn verify_publisher_authorization(
    envelope: &SignedEnvelope<Value>,
    binding: &PublicationBinding,
    store: &BlindStore,
    origin: &str,
) -> CatalogResult<()> {
    let payload = &envelope.payload;
    let authorization = &payload["publisherAuthorization"];
    let request: SignedEnvelope<Value> = serde_json::from_value(authorization["request"].clone())
        .map_err(|_| {
        CatalogAccessError(StatusCode::BAD_REQUEST, "Invalid catalog publisher request")
    })?;
    let proof: SignedEnvelope<Value> = serde_json::from_value(authorization["proof"].clone())
        .map_err(|_| {
            CatalogAccessError(StatusCode::BAD_REQUEST, "Invalid catalog approval proof")
        })?;
    let certificate: DeviceCertificate =
        serde_json::from_value(authorization["certificate"].clone()).map_err(|_| {
            CatalogAccessError(StatusCode::BAD_REQUEST, "Invalid catalog app certificate")
        })?;
    let request_payload = &request.payload;
    let request_keys = request_payload
        .as_object()
        .map(|object| object.keys().map(String::as_str).collect::<HashSet<_>>());
    let request_keys_match = request_keys.as_ref().is_some_and(|keys| {
        keys.contains("kind")
            && keys.contains("version")
            && keys.contains("applicationOrigin")
            && keys.contains("challenge")
            && keys.contains("expiresAt")
            && keys.contains("personId")
            && keys.contains("deviceId")
            && keys.contains("devicePublicKey")
            && keys.contains("includeIdentityCatalogAccess")
            && (keys.len() == 9 || keys.len() == 10 && keys.contains("rustyServicePins"))
    });
    if !request_keys_match
        || request_payload["kind"] != "mesh-device-authorization-request"
        || request_payload["version"] != 3
        || request_payload["includeIdentityCatalogAccess"] != true
        || request_payload["applicationOrigin"] != binding.application_origin
        || (!request_payload["personId"].is_null()
            && request_payload["personId"] != binding.person_id)
        || request_payload["deviceId"] != binding.publisher_device_id
        || request.signer_key_id != binding.publisher_device_id
        || !valid_application_challenge(request_payload["challenge"].as_str().unwrap_or_default())
    {
        return reject(
            StatusCode::FORBIDDEN,
            "Catalog publisher is not authorized for this application",
        );
    }
    let pins = authorization["rustyServicePins"]
        .as_array()
        .ok_or(CatalogAccessError(
            StatusCode::BAD_REQUEST,
            "Invalid catalog Rusty pin",
        ))?;
    let service_public_key = store.public_key().map_err(|_| {
        CatalogAccessError(
            StatusCode::SERVICE_UNAVAILABLE,
            "Rusty identity unavailable",
        )
    })?;
    let mut pin_origins = Vec::with_capacity(pins.len());
    for pin in pins {
        if !exact_keys(pin, &["origin", "serviceId", "servicePublicKey"]) {
            return reject(StatusCode::BAD_REQUEST, "Invalid catalog Rusty pin");
        }
        let pin_origin = pin["origin"]
            .as_str()
            .filter(|value| canonical_origin(value))
            .ok_or(CatalogAccessError(
                StatusCode::BAD_REQUEST,
                "Invalid catalog Rusty pin",
            ))?;
        let pin_service_id = pin["serviceId"]
            .as_str()
            .filter(|value| valid_id(value))
            .ok_or(CatalogAccessError(
                StatusCode::BAD_REQUEST,
                "Invalid catalog Rusty pin",
            ))?;
        let pin_public_key = pin["servicePublicKey"]
            .as_str()
            .filter(|value| !value.is_empty() && value.len() <= 128)
            .ok_or(CatalogAccessError(
                StatusCode::BAD_REQUEST,
                "Invalid catalog Rusty pin",
            ))?;
        if public_key_id(pin_public_key).ok().as_deref() != Some(pin_service_id) {
            return reject(StatusCode::BAD_REQUEST, "Invalid catalog Rusty pin");
        }
        pin_origins.push(pin_origin);
    }
    let pins_hash = digest_value(&authorization["rustyServicePins"])
        .map_err(|_| CatalogAccessError(StatusCode::BAD_REQUEST, "Invalid catalog Rusty pin"))?;
    let request_pins_match = request_payload
        .get("rustyServicePins")
        .map(|requested| {
            requested.as_array().is_some_and(|requested| {
                requested.iter().all(|requested_pin| {
                    pins.iter().any(|pin| {
                        canonicalize_json(pin).ok() == canonicalize_json(requested_pin).ok()
                    })
                })
            })
        })
        .unwrap_or(true);
    if pins.is_empty()
        || pins.len() > MAX_PIN_COUNT
        || pin_origins.windows(2).any(|pair| pair[0] >= pair[1])
        || !request_pins_match
        || !pins.iter().any(|pin| {
            pin["origin"] == origin
                && pin["serviceId"] == binding.service_id
                && pin["servicePublicKey"] == service_public_key
        })
    {
        return reject(
            StatusCode::FORBIDDEN,
            "Application approval does not pin this Rusty service",
        );
    }
    let proof_payload = &proof.payload;
    if !exact_keys(
        proof_payload,
        &[
            "kind",
            "version",
            "request",
            "certificateHash",
            "issuedAt",
            "expiresAt",
            "authorityViewDigest",
            "revocationHead",
            "rustyServicePinsDigest",
            "profileStateDigest",
            "identityCatalogAccessDigest",
        ],
    ) || proof_payload["kind"] != "mesh-device-authorization-approval"
        || proof_payload["version"] != 5
        || canonicalize_json(&proof_payload["request"]).ok()
            != canonicalize_json(&authorization["request"]).ok()
    {
        return reject(
            StatusCode::FORBIDDEN,
            "Catalog manager approval does not match the application request",
        );
    }
    let certificate_hash = meta_mesh_core::certificate_hash(&certificate).map_err(|_| {
        CatalogAccessError(StatusCode::BAD_REQUEST, "Invalid catalog app certificate")
    })?;
    let approval_issued_at = proof_payload["issuedAt"]
        .as_u64()
        .ok_or(CatalogAccessError(
            StatusCode::BAD_REQUEST,
            "Invalid catalog approval time",
        ))?;
    let approval_expires_at = proof_payload["expiresAt"]
        .as_u64()
        .ok_or(CatalogAccessError(
            StatusCode::BAD_REQUEST,
            "Invalid catalog approval expiry",
        ))?;
    let request_expires_at = request_payload["expiresAt"]
        .as_u64()
        .ok_or(CatalogAccessError(
            StatusCode::BAD_REQUEST,
            "Invalid catalog request expiry",
        ))?;
    let approval_now = now_ms().map_err(|_| {
        CatalogAccessError(StatusCode::SERVICE_UNAVAILABLE, "System clock unavailable")
    })?;
    let revocation_revision =
        proof_payload["revocationHead"]["revision"]
            .as_u64()
            .ok_or(CatalogAccessError(
                StatusCode::BAD_REQUEST,
                "Invalid catalog approval authority head",
            ))?;
    if proof_payload["certificateHash"] != certificate_hash
        || approval_expires_at != request_expires_at
        || approval_issued_at > approval_now.saturating_add(30_000)
        || approval_expires_at > MAX_SAFE_JS_INTEGER
        || approval_issued_at > approval_expires_at
        || approval_expires_at - approval_issued_at > LIST_TTL_MS
        || !valid_hash(
            proof_payload["authorityViewDigest"]
                .as_str()
                .unwrap_or_default(),
        )
        || proof_payload["rustyServicePinsDigest"] != pins_hash
        || !valid_hash(
            proof_payload["identityCatalogAccessDigest"]
                .as_str()
                .unwrap_or_default(),
        )
        || !valid_hash(
            proof_payload["profileStateDigest"]
                .as_str()
                .unwrap_or_default(),
        )
        || !exact_keys(
            &proof_payload["revocationHead"],
            &["revision", "recordHash"],
        )
        || revocation_revision > MAX_SAFE_JS_INTEGER
        || !valid_hash(
            proof_payload["revocationHead"]["recordHash"]
                .as_str()
                .unwrap_or_default(),
        )
    {
        return reject(
            StatusCode::FORBIDDEN,
            "Catalog manager approval evidence is invalid",
        );
    }
    if certificate.payload.person_id != binding.person_id
        || certificate.payload.device_id != binding.publisher_device_id
        || certificate.payload.device_public_key
            != request_payload["devicePublicKey"]
                .as_str()
                .unwrap_or_default()
        || public_key_id(&binding.recipient_public_key).ok().as_deref()
            != Some(&binding.recipient_public_key_id)
    {
        return reject(
            StatusCode::FORBIDDEN,
            "Catalog application or recipient device binding is invalid",
        );
    }
    let authority = store
        .read_identity_authority(&binding.person_id)
        .map_err(|_| {
            CatalogAccessError(
                StatusCode::SERVICE_UNAVAILABLE,
                "Identity authority unavailable",
            )
        })?
        .ok_or(CatalogAccessError(
            StatusCode::PRECONDITION_REQUIRED,
            "Identity authority is not registered",
        ))?;
    if store.identity_is_retired(&binding.person_id).map_err(|_| {
        CatalogAccessError(
            StatusCode::SERVICE_UNAVAILABLE,
            "Identity authority unavailable",
        )
    })? {
        return reject(StatusCode::FORBIDDEN, "Identity root has been retired");
    }
    if !authority
        .view
        .certificates
        .iter()
        .any(|current| current == &certificate)
    {
        return reject(
            StatusCode::FORBIDDEN,
            "Catalog app certificate is not current",
        );
    }
    let verified = authority
        .view
        .verify()
        .map_err(|_| CatalogAccessError(StatusCode::FORBIDDEN, "Identity authority is invalid"))?;
    if !verified
        .is_active_device(&binding.publisher_device_id)
        .map_err(|_| CatalogAccessError(StatusCode::FORBIDDEN, "Catalog app device is invalid"))?
    {
        return reject(StatusCode::FORBIDDEN, "Catalog app device is revoked");
    }
    let app_chain = certificate_chain(
        &authority.view.identity(),
        &binding.publisher_device_id,
        &verified.certificates_by_device,
    )
    .map_err(|_| {
        CatalogAccessError(
            StatusCode::FORBIDDEN,
            "Catalog app certificate chain is invalid",
        )
    })?;
    let app_public_key = verify_device_certificate_chain(
        &authority.view.identity(),
        &binding.publisher_device_id,
        &app_chain,
        SIGNATURE_DOMAIN,
    )
    .map_err(|_| {
        CatalogAccessError(
            StatusCode::FORBIDDEN,
            "Catalog app certificate chain is invalid",
        )
    })?;
    if app_public_key
        != request_payload["devicePublicKey"]
            .as_str()
            .unwrap_or_default()
        || !verify_signed_envelope(&request, &app_public_key, "MESH-DEVICE-AUTHORIZATION/1")
            .unwrap_or(false)
        || !verify_signed_envelope(
            envelope,
            &app_public_key,
            "MESH-IDENTITY-CATALOG-ACCESS-PUBLISH/1",
        )
        .unwrap_or(false)
    {
        return reject(
            StatusCode::FORBIDDEN,
            "Catalog app publication or request signature is invalid",
        );
    }
    let manager_id = proof.signer_key_id.as_str();
    if !valid_id(manager_id)
        || !verified.is_active_manager(manager_id).map_err(|_| {
            CatalogAccessError(
                StatusCode::FORBIDDEN,
                "Catalog approving manager is invalid",
            )
        })?
    {
        return reject(
            StatusCode::FORBIDDEN,
            "Catalog approval requires an active Identity manager",
        );
    }
    let manager_chain = certificate_chain(
        &authority.view.identity(),
        manager_id,
        &verified.certificates_by_device,
    )
    .map_err(|_| {
        CatalogAccessError(
            StatusCode::FORBIDDEN,
            "Catalog manager certificate chain is invalid",
        )
    })?;
    let manager_public_key = verify_device_certificate_chain(
        &authority.view.identity(),
        manager_id,
        &manager_chain,
        SIGNATURE_DOMAIN,
    )
    .map_err(|_| {
        CatalogAccessError(
            StatusCode::FORBIDDEN,
            "Catalog manager certificate chain is invalid",
        )
    })?;
    if !verify_signed_envelope(
        &proof,
        &manager_public_key,
        "MESH-APP-DEVICE-AUTHORIZATION/1",
    )
    .unwrap_or(false)
    {
        return reject(
            StatusCode::FORBIDDEN,
            "Catalog manager approval signature is invalid",
        );
    }
    if !verified
        .is_active_manager(&binding.recipient_device_id)
        .map_err(|_| {
            CatalogAccessError(
                StatusCode::FORBIDDEN,
                "Catalog recipient manager is invalid",
            )
        })?
    {
        return reject(
            StatusCode::FORBIDDEN,
            "Catalog recipient must be an active Identity manager",
        );
    }
    let recipient_chain = certificate_chain(
        &authority.view.identity(),
        &binding.recipient_device_id,
        &verified.certificates_by_device,
    )
    .map_err(|_| {
        CatalogAccessError(
            StatusCode::FORBIDDEN,
            "Catalog recipient manager chain is invalid",
        )
    })?;
    let recipient_key = verify_device_certificate_chain(
        &authority.view.identity(),
        &binding.recipient_device_id,
        &recipient_chain,
        SIGNATURE_DOMAIN,
    )
    .map_err(|_| {
        CatalogAccessError(
            StatusCode::FORBIDDEN,
            "Catalog recipient manager chain is invalid",
        )
    })?;
    if recipient_key != binding.recipient_public_key {
        return reject(
            StatusCode::FORBIDDEN,
            "Catalog recipient key is not current",
        );
    }
    if !store
        .person_device_allowed(&authority.view.identity(), manager_id, origin, false)
        .map_err(|_| {
            CatalogAccessError(
                StatusCode::SERVICE_UNAVAILABLE,
                "Identity management state unavailable",
            )
        })?
        || !store
            .person_device_allowed(
                &authority.view.identity(),
                &binding.publisher_device_id,
                origin,
                false,
            )
            .map_err(|_| {
                CatalogAccessError(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "Identity management state unavailable",
                )
            })?
        || !store
            .person_device_allowed(
                &authority.view.identity(),
                &binding.recipient_device_id,
                origin,
                false,
            )
            .map_err(|_| {
                CatalogAccessError(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "Identity management state unavailable",
                )
            })?
    {
        return reject(
            StatusCode::FORBIDDEN,
            "Catalog publisher or approving manager is revoked",
        );
    }
    Ok(())
}

fn catalog_directory(
    store: &BlindStore,
    person_id: &str,
    application_origin: &str,
    recipient_id: &str,
) -> PathBuf {
    store
        .directory
        .join("identity-catalog-access")
        .join(person_id)
        .join(digest(application_origin.as_bytes()))
        .join(recipient_id)
}

fn catalog_entry_path(store: &BlindStore, binding: &PublicationBinding) -> PathBuf {
    catalog_directory(
        store,
        &binding.person_id,
        &binding.application_origin,
        &binding.recipient_device_id,
    )
    .join(format!("{}.json", binding.catalog_id))
}

fn ensure_durable_catalog_directory(
    store: &BlindStore,
    binding: &PublicationBinding,
) -> CatalogResult<()> {
    let base = store.directory.join("identity-catalog-access");
    let person = base.join(&binding.person_id);
    let application = person.join(digest(binding.application_origin.as_bytes()));
    let recipient = application.join(&binding.recipient_device_id);
    for (directory, parent) in [
        (&base, store.directory.as_path()),
        (&person, base.as_path()),
        (&application, person.as_path()),
        (&recipient, application.as_path()),
    ] {
        if !directory.exists() {
            fs::create_dir(&directory).map_err(|_| {
                CatalogAccessError(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "Catalog storage directory unavailable",
                )
            })?;
            sync_directory(parent).map_err(|_| {
                CatalogAccessError(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "Catalog directory durability unavailable",
                )
            })?;
            sync_directory(&directory).map_err(|_| {
                CatalogAccessError(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "Catalog directory durability unavailable",
                )
            })?;
        }
    }
    Ok(())
}

fn load_stored(
    path: &Path,
    store: &BlindStore,
    expected: Option<&PublicationBinding>,
) -> CatalogResult<Option<StoredCatalogAccess>> {
    if !path.exists() {
        return Ok(None);
    }
    let metadata = fs::metadata(path).map_err(|_| {
        CatalogAccessError(
            StatusCode::SERVICE_UNAVAILABLE,
            "Catalog storage unavailable",
        )
    })?;
    if metadata.len() > (PUBLISH_MAX_BYTES + 16 * 1024) as u64 {
        return reject(
            StatusCode::SERVICE_UNAVAILABLE,
            "Stored catalog entry exceeds its limit",
        );
    }
    let bytes = fs::read(path).map_err(|_| {
        CatalogAccessError(
            StatusCode::SERVICE_UNAVAILABLE,
            "Catalog storage unavailable",
        )
    })?;
    let stored: StoredCatalogAccess = serde_json::from_slice(&bytes).map_err(|_| {
        CatalogAccessError(
            StatusCode::SERVICE_UNAVAILABLE,
            "Stored catalog entry is invalid",
        )
    })?;
    if stored.version != 1 {
        return reject(
            StatusCode::SERVICE_UNAVAILABLE,
            "Stored catalog entry is invalid",
        );
    }
    let service_key = store.public_key().map_err(|_| {
        CatalogAccessError(
            StatusCode::SERVICE_UNAVAILABLE,
            "Rusty identity unavailable",
        )
    })?;
    let envelope_value = serde_json::to_value(&stored.envelope).map_err(|_| {
        CatalogAccessError(
            StatusCode::SERVICE_UNAVAILABLE,
            "Stored catalog entry is invalid",
        )
    })?;
    let envelope_hash = digest_value(&envelope_value).map_err(|_| {
        CatalogAccessError(
            StatusCode::SERVICE_UNAVAILABLE,
            "Stored catalog entry is invalid",
        )
    })?;
    if stored.receipt.payload.envelope_hash != envelope_hash
        || !verify_signed_envelope(&stored.receipt, &service_key, DOMAIN).unwrap_or(false)
    {
        return reject(
            StatusCode::SERVICE_UNAVAILABLE,
            "Stored catalog entry integrity failure",
        );
    }
    let payload = &stored.envelope.payload;
    if payload["personId"] != stored.receipt.payload.person_id
        || payload["applicationOrigin"] != stored.receipt.payload.application_origin
        || payload["catalogId"] != stored.receipt.payload.catalog_id
        || payload["sourceRevision"] != stored.receipt.payload.source_revision
        || payload["recipientDeviceId"] != stored.receipt.payload.recipient_device_id
        || payload["recipientPublicKeyId"] != stored.receipt.payload.recipient_public_key_id
    {
        return reject(
            StatusCode::SERVICE_UNAVAILABLE,
            "Stored catalog entry binding failure",
        );
    }
    if let Some(expected) = expected {
        if stored.receipt.payload.person_id != expected.person_id
            || stored.receipt.payload.application_origin != expected.application_origin
            || (!expected.catalog_id.is_empty()
                && stored.receipt.payload.catalog_id != expected.catalog_id)
            || stored.receipt.payload.recipient_device_id != expected.recipient_device_id
            || stored.receipt.payload.recipient_public_key_id != expected.recipient_public_key_id
            || stored.receipt.payload.source_revision
                != stored.envelope.payload["sourceRevision"]
                    .as_u64()
                    .unwrap_or(0)
        {
            return reject(
                StatusCode::SERVICE_UNAVAILABLE,
                "Stored catalog entry binding failure",
            );
        }
    }
    Ok(Some(stored))
}

fn parse_publication(
    request: &SignedEnvelope<Value>,
    store: &BlindStore,
    origin: &str,
) -> CatalogResult<PublicationBinding> {
    if request.payload["kind"] != "mesh-identity-catalog-access-publication" {
        return reject(StatusCode::BAD_REQUEST, "Invalid catalog publication");
    }
    publication_binding(request, store, origin)
}

impl BlindStore {
    fn publish_identity_catalog_access(
        &self,
        request: SignedEnvelope<Value>,
        origin: &str,
    ) -> CatalogResult<SignedEnvelope<CatalogPublicationReceipt>> {
        let _guard = self.lock.lock().map_err(|_| {
            CatalogAccessError(
                StatusCode::SERVICE_UNAVAILABLE,
                "Catalog storage unavailable",
            )
        })?;
        let binding = parse_publication(&request, self, origin)?;
        verify_publisher_authorization(&request, &binding, self, origin)?;
        let path = catalog_entry_path(self, &binding);
        if let Some(previous) = load_stored(&path, self, Some(&binding))? {
            let previous_revision = previous.receipt.payload.source_revision;
            if binding.source_revision < previous_revision {
                return reject(StatusCode::CONFLICT, "Catalog source revision is stale");
            }
            if binding.source_revision == previous_revision {
                if previous.envelope == request {
                    return Ok(previous.receipt);
                }
                return reject(
                    StatusCode::CONFLICT,
                    "Catalog revision conflicts with stored ciphertext",
                );
            }
        }
        let envelope_value = serde_json::to_value(&request).map_err(|_| {
            CatalogAccessError(StatusCode::BAD_REQUEST, "Invalid catalog publication")
        })?;
        let envelope_hash = digest_value(&envelope_value).map_err(|_| {
            CatalogAccessError(StatusCode::BAD_REQUEST, "Invalid catalog publication")
        })?;
        let now = now_ms().map_err(|_| {
            CatalogAccessError(StatusCode::SERVICE_UNAVAILABLE, "System clock unavailable")
        })?;
        let receipt_value = sign_json_envelope(
            &self.seed,
            serde_json::to_value(CatalogPublicationReceipt {
                kind: "rusty-identity-catalog-access-publish-receipt".into(),
                version: 1,
                service_id: binding.service_id.clone(),
                origin: origin.into(),
                publisher_device_id: binding.publisher_device_id.clone(),
                person_id: binding.person_id.clone(),
                application_origin: binding.application_origin.clone(),
                catalog_id: binding.catalog_id.clone(),
                source_revision: binding.source_revision,
                recipient_device_id: binding.recipient_device_id.clone(),
                recipient_public_key_id: binding.recipient_public_key_id.clone(),
                envelope_hash,
                issued_at: now,
            })
            .map_err(|_| {
                CatalogAccessError(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Catalog receipt unavailable",
                )
            })?,
            &binding.service_id,
            DOMAIN,
        )
        .map_err(|_| {
            CatalogAccessError(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Catalog receipt unavailable",
            )
        })?;
        let receipt: SignedEnvelope<CatalogPublicationReceipt> =
            serde_json::from_value(serde_json::to_value(receipt_value).map_err(|_| {
                CatalogAccessError(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Catalog receipt unavailable",
                )
            })?)
            .map_err(|_| {
                CatalogAccessError(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Catalog receipt unavailable",
                )
            })?;
        let stored = StoredCatalogAccess {
            version: 1,
            envelope: request,
            receipt: receipt.clone(),
        };
        let bytes = serde_json::to_vec(&stored).map_err(|_| {
            CatalogAccessError(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Catalog storage unavailable",
            )
        })?;
        if bytes.len() > PUBLISH_MAX_BYTES + 16 * 1024 {
            return reject(
                StatusCode::BAD_REQUEST,
                "Catalog publication exceeds its storage limit",
            );
        }
        ensure_durable_catalog_directory(self, &binding)?;
        let directory = path.parent().ok_or(CatalogAccessError(
            StatusCode::INTERNAL_SERVER_ERROR,
            "Catalog storage unavailable",
        ))?;
        let entries = match fs::read_dir(directory) {
            Ok(entries) => entries.count(),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => 0,
            Err(_) => {
                return reject(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "Catalog storage unavailable",
                );
            }
        };
        if entries == 0 || !path.exists() {
            if entries >= LIST_MAX_ENTRIES {
                return reject(
                    StatusCode::PAYLOAD_TOO_LARGE,
                    "Catalog list entry limit reached",
                );
            }
        }
        let mut total_bytes = bytes.len();
        match fs::read_dir(directory) {
            Ok(entries) => {
                for entry in entries {
                    let entry = entry.map_err(|_| {
                        CatalogAccessError(
                            StatusCode::SERVICE_UNAVAILABLE,
                            "Catalog storage unavailable",
                        )
                    })?;
                    if entry.path() == path {
                        continue;
                    }
                    let len = entry
                        .metadata()
                        .map_err(|_| {
                            CatalogAccessError(
                                StatusCode::SERVICE_UNAVAILABLE,
                                "Catalog storage unavailable",
                            )
                        })?
                        .len() as usize;
                    total_bytes = total_bytes.saturating_add(len);
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => {
                return reject(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "Catalog storage unavailable",
                );
            }
        }
        if total_bytes > LIST_MAX_BYTES {
            return reject(
                StatusCode::PAYLOAD_TOO_LARGE,
                "Catalog list byte limit reached",
            );
        }
        atomic_write(&path, &bytes).map_err(|_| {
            CatalogAccessError(
                StatusCode::SERVICE_UNAVAILABLE,
                "Catalog storage commit failed",
            )
        })?;
        Ok(receipt)
    }

    fn list_identity_catalog_access(
        &self,
        request: SignedEnvelope<Value>,
        origin: &str,
    ) -> CatalogResult<(
        Vec<SignedEnvelope<Value>>,
        SignedEnvelope<CatalogListReceipt>,
    )> {
        let _guard = self.lock.lock().map_err(|_| {
            CatalogAccessError(
                StatusCode::SERVICE_UNAVAILABLE,
                "Catalog storage unavailable",
            )
        })?;
        let value = serde_json::to_value(&request).map_err(|_| {
            CatalogAccessError(StatusCode::BAD_REQUEST, "Invalid catalog list request")
        })?;
        if !envelope_shape(&value)
            || !exact_keys(
                &request.payload,
                &[
                    "kind",
                    "version",
                    "serviceId",
                    "personId",
                    "applicationOrigin",
                    "recipientDeviceId",
                    "recipientPublicKeyId",
                    "recipientPublicKey",
                    "challenge",
                    "issuedAt",
                    "expiresAt",
                ],
            )
        {
            return reject(StatusCode::BAD_REQUEST, "Invalid catalog list request");
        }
        let payload = &request.payload;
        let person_id = payload["personId"]
            .as_str()
            .filter(|id| valid_id(id))
            .ok_or(CatalogAccessError(
                StatusCode::BAD_REQUEST,
                "Invalid catalog list request",
            ))?;
        let application_origin = payload["applicationOrigin"]
            .as_str()
            .filter(|value| canonical_origin(value))
            .ok_or(CatalogAccessError(
                StatusCode::BAD_REQUEST,
                "Invalid catalog application origin",
            ))?;
        let recipient_device_id = payload["recipientDeviceId"]
            .as_str()
            .filter(|id| valid_id(id))
            .ok_or(CatalogAccessError(
                StatusCode::BAD_REQUEST,
                "Invalid catalog recipient",
            ))?;
        let recipient_key_id = payload["recipientPublicKeyId"]
            .as_str()
            .filter(|id| valid_id(id))
            .ok_or(CatalogAccessError(
                StatusCode::BAD_REQUEST,
                "Invalid catalog recipient",
            ))?;
        let recipient_public_key = payload["recipientPublicKey"]
            .as_str()
            .filter(|key| !key.is_empty() && key.len() <= 128)
            .ok_or(CatalogAccessError(
                StatusCode::BAD_REQUEST,
                "Invalid catalog recipient",
            ))?;
        let service_id = public_key_id(&self.public_key().map_err(|_| {
            CatalogAccessError(
                StatusCode::SERVICE_UNAVAILABLE,
                "Rusty identity unavailable",
            )
        })?)
        .map_err(|_| {
            CatalogAccessError(
                StatusCode::SERVICE_UNAVAILABLE,
                "Rusty identity unavailable",
            )
        })?;
        let now = now_ms().map_err(|_| {
            CatalogAccessError(StatusCode::SERVICE_UNAVAILABLE, "System clock unavailable")
        })?;
        let issued_at = payload["issuedAt"].as_u64().ok_or(CatalogAccessError(
            StatusCode::BAD_REQUEST,
            "Invalid catalog list request",
        ))?;
        let expires_at = payload["expiresAt"].as_u64().ok_or(CatalogAccessError(
            StatusCode::BAD_REQUEST,
            "Invalid catalog list request",
        ))?;
        let challenge = payload["challenge"]
            .as_str()
            .filter(|value| valid_nonce(value))
            .ok_or(CatalogAccessError(
                StatusCode::BAD_REQUEST,
                "Invalid catalog challenge",
            ))?;
        if payload["kind"] != "mesh-identity-catalog-access-list-request"
            || payload["version"] != 1
            || payload["serviceId"] != service_id
            || !canonical_origin(application_origin)
            || issued_at > MAX_SAFE_JS_INTEGER
            || issued_at > now.saturating_add(30_000)
            || expires_at <= now
            || expires_at > MAX_SAFE_JS_INTEGER
            || expires_at <= issued_at
            || expires_at - issued_at > LIST_TTL_MS
            || request.signer_key_id != recipient_device_id
            || public_key_id(recipient_public_key).ok().as_deref() != Some(recipient_key_id)
        {
            return reject(
                StatusCode::FORBIDDEN,
                "Catalog list request binding or expiry is invalid",
            );
        }
        let authority = self
            .read_identity_authority(person_id)
            .map_err(|_| {
                CatalogAccessError(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "Identity authority unavailable",
                )
            })?
            .ok_or(CatalogAccessError(
                StatusCode::PRECONDITION_REQUIRED,
                "Identity authority is not registered",
            ))?;
        if self.identity_is_retired(person_id).map_err(|_| {
            CatalogAccessError(
                StatusCode::SERVICE_UNAVAILABLE,
                "Identity authority unavailable",
            )
        })? {
            return reject(StatusCode::FORBIDDEN, "Identity root has been retired");
        }
        let verified = authority.view.verify().map_err(|_| {
            CatalogAccessError(StatusCode::FORBIDDEN, "Identity authority is invalid")
        })?;
        if !verified
            .is_active_manager(recipient_device_id)
            .map_err(|_| CatalogAccessError(StatusCode::FORBIDDEN, "Identity manager is invalid"))?
        {
            return reject(
                StatusCode::FORBIDDEN,
                "Catalog access requires an active Identity manager",
            );
        }
        let manager_chain = certificate_chain(
            &authority.view.identity(),
            recipient_device_id,
            &verified.certificates_by_device,
        )
        .map_err(|_| {
            CatalogAccessError(
                StatusCode::FORBIDDEN,
                "Identity manager certificate chain is invalid",
            )
        })?;
        let manager_public_key = verify_device_certificate_chain(
            &authority.view.identity(),
            recipient_device_id,
            &manager_chain,
            SIGNATURE_DOMAIN,
        )
        .map_err(|_| {
            CatalogAccessError(
                StatusCode::FORBIDDEN,
                "Identity manager certificate chain is invalid",
            )
        })?;
        if manager_public_key != recipient_public_key
            || !verify_signed_envelope(&request, &manager_public_key, REQUEST_DOMAIN)
                .unwrap_or(false)
        {
            return reject(
                StatusCode::FORBIDDEN,
                "Catalog list request signature is invalid",
            );
        }
        if !self
            .person_device_allowed(
                &authority.view.identity(),
                recipient_device_id,
                origin,
                false,
            )
            .map_err(|_| {
                CatalogAccessError(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "Identity management state unavailable",
                )
            })?
        {
            return reject(StatusCode::FORBIDDEN, "Identity manager is revoked");
        }
        let directory = catalog_directory(self, person_id, application_origin, recipient_device_id);
        let mut rows = Vec::<(String, SignedEnvelope<Value>)>::new();
        if directory.exists() {
            let entries = fs::read_dir(&directory).map_err(|_| {
                CatalogAccessError(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "Catalog storage unavailable",
                )
            })?;
            for entry in entries {
                let entry = entry.map_err(|_| {
                    CatalogAccessError(
                        StatusCode::SERVICE_UNAVAILABLE,
                        "Catalog storage unavailable",
                    )
                })?;
                if !entry
                    .file_type()
                    .map_err(|_| {
                        CatalogAccessError(
                            StatusCode::SERVICE_UNAVAILABLE,
                            "Catalog storage unavailable",
                        )
                    })?
                    .is_file()
                {
                    return reject(
                        StatusCode::SERVICE_UNAVAILABLE,
                        "Catalog storage index is invalid",
                    );
                }
                let name = entry.file_name().to_string_lossy().into_owned();
                let catalog_id = name
                    .strip_suffix(".json")
                    .filter(|id| valid_id(id))
                    .ok_or(CatalogAccessError(
                        StatusCode::SERVICE_UNAVAILABLE,
                        "Catalog storage index is invalid",
                    ))?
                    .to_owned();
                let binding = PublicationBinding {
                    service_id: service_id.clone(),
                    publisher_device_id: String::new(),
                    person_id: person_id.into(),
                    application_origin: application_origin.into(),
                    catalog_id: String::new(),
                    source_revision: 0,
                    recipient_device_id: recipient_device_id.into(),
                    recipient_public_key_id: recipient_key_id.into(),
                    recipient_public_key: recipient_public_key.into(),
                };
                let stored =
                    load_stored(&entry.path(), self, Some(&binding))?.ok_or(CatalogAccessError(
                        StatusCode::SERVICE_UNAVAILABLE,
                        "Catalog storage entry disappeared",
                    ))?;
                if stored.receipt.payload.catalog_id != catalog_id {
                    return reject(
                        StatusCode::SERVICE_UNAVAILABLE,
                        "Catalog storage path binding failure",
                    );
                }
                rows.push((catalog_id, stored.envelope));
                if rows.len() > LIST_MAX_ENTRIES {
                    return reject(
                        StatusCode::SERVICE_UNAVAILABLE,
                        "Catalog storage exceeds its entry limit",
                    );
                }
            }
        }
        if rows.is_empty()
            && other_active_manager_has_catalog(
                self,
                &verified,
                person_id,
                application_origin,
                recipient_device_id,
                service_id.as_str(),
            )?
        {
            return Err(CatalogAccessError(
                StatusCode::SERVICE_UNAVAILABLE,
                CATALOG_ACCESS_PENDING_MESSAGE,
            ));
        }
        rows.sort_by(|left, right| left.0.cmp(&right.0));
        let envelopes = rows
            .into_iter()
            .map(|(_, envelope)| envelope)
            .collect::<Vec<_>>();
        let envelope_values = serde_json::to_value(&envelopes).map_err(|_| {
            CatalogAccessError(
                StatusCode::SERVICE_UNAVAILABLE,
                "Catalog response unavailable",
            )
        })?;
        let list_hash = digest_value(&envelope_values).map_err(|_| {
            CatalogAccessError(
                StatusCode::SERVICE_UNAVAILABLE,
                "Catalog response unavailable",
            )
        })?;
        let request_hash = digest_value(&value).map_err(|_| {
            CatalogAccessError(StatusCode::BAD_REQUEST, "Invalid catalog list request")
        })?;
        let receipt_value = sign_json_envelope(
            &self.seed,
            serde_json::to_value(CatalogListReceipt {
                kind: "rusty-identity-catalog-access-list-receipt".into(),
                version: 1,
                service_id,
                origin: origin.into(),
                request_hash,
                person_id: person_id.into(),
                application_origin: application_origin.into(),
                recipient_device_id: recipient_device_id.into(),
                recipient_public_key_id: recipient_key_id.into(),
                challenge: challenge.into(),
                envelope_count: envelopes.len() as u8,
                envelope_list_hash: list_hash,
                issued_at: now,
                expires_at,
            })
            .map_err(|_| {
                CatalogAccessError(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Catalog receipt unavailable",
                )
            })?,
            public_key_id(&self.public_key().map_err(|_| {
                CatalogAccessError(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "Rusty identity unavailable",
                )
            })?)
            .map_err(|_| {
                CatalogAccessError(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "Rusty identity unavailable",
                )
            })?
            .as_str(),
            DOMAIN,
        )
        .map_err(|_| {
            CatalogAccessError(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Catalog receipt unavailable",
            )
        })?;
        let receipt: SignedEnvelope<CatalogListReceipt> =
            serde_json::from_value(serde_json::to_value(receipt_value).map_err(|_| {
                CatalogAccessError(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Catalog receipt unavailable",
                )
            })?)
            .map_err(|_| {
                CatalogAccessError(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Catalog receipt unavailable",
                )
            })?;
        let response = json!({"envelopes": &envelopes, "receipt": &receipt});
        if serde_json::to_vec(&response).map_or(true, |bytes| bytes.len() > LIST_MAX_BYTES) {
            return reject(
                StatusCode::SERVICE_UNAVAILABLE,
                "Catalog response exceeds its limit",
            );
        }
        Ok((envelopes, receipt))
    }
}

fn other_active_manager_has_catalog(
    store: &BlindStore,
    authority: &VerifiedIdentityAuthorityView,
    person_id: &str,
    application_origin: &str,
    recipient_device_id: &str,
    service_id: &str,
) -> CatalogResult<bool> {
    let identity = authority.view.identity();
    for manager_id in authority.certificates_by_device.keys() {
        if manager_id == recipient_device_id
            || !authority.is_active_manager(manager_id).map_err(|_| {
                CatalogAccessError(StatusCode::FORBIDDEN, "Identity manager is invalid")
            })?
        {
            continue;
        }
        let chain = certificate_chain(&identity, manager_id, &authority.certificates_by_device)
            .map_err(|_| {
                CatalogAccessError(
                    StatusCode::FORBIDDEN,
                    "Identity manager certificate chain is invalid",
                )
            })?;
        let manager_public_key =
            verify_device_certificate_chain(&identity, manager_id, &chain, SIGNATURE_DOMAIN)
                .map_err(|_| {
                    CatalogAccessError(
                        StatusCode::FORBIDDEN,
                        "Identity manager certificate chain is invalid",
                    )
                })?;
        let manager_key_id = public_key_id(&manager_public_key).map_err(|_| {
            CatalogAccessError(StatusCode::FORBIDDEN, "Identity manager key is invalid")
        })?;
        let directory = catalog_directory(store, person_id, application_origin, manager_id);
        if !directory.exists() {
            continue;
        }
        for entry in fs::read_dir(&directory).map_err(|_| {
            CatalogAccessError(
                StatusCode::SERVICE_UNAVAILABLE,
                "Catalog storage unavailable",
            )
        })? {
            let entry = entry.map_err(|_| {
                CatalogAccessError(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "Catalog storage unavailable",
                )
            })?;
            if !entry
                .file_type()
                .map_err(|_| {
                    CatalogAccessError(
                        StatusCode::SERVICE_UNAVAILABLE,
                        "Catalog storage unavailable",
                    )
                })?
                .is_file()
            {
                return reject(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "Catalog storage index is invalid",
                );
            }
            let catalog_id = entry
                .file_name()
                .to_string_lossy()
                .into_owned()
                .strip_suffix(".json")
                .filter(|id| valid_id(id))
                .ok_or(CatalogAccessError(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "Catalog storage index is invalid",
                ))?
                .to_owned();
            let binding = PublicationBinding {
                service_id: service_id.into(),
                publisher_device_id: String::new(),
                person_id: person_id.into(),
                application_origin: application_origin.into(),
                catalog_id: String::new(),
                source_revision: 0,
                recipient_device_id: manager_id.clone(),
                recipient_public_key_id: manager_key_id.clone(),
                recipient_public_key: manager_public_key.clone(),
            };
            let stored =
                load_stored(&entry.path(), store, Some(&binding))?.ok_or(CatalogAccessError(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "Catalog storage entry disappeared",
                ))?;
            if stored.receipt.payload.catalog_id != catalog_id {
                return reject(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "Catalog storage path binding failure",
                );
            }
            return Ok(true);
        }
    }
    Ok(false)
}

pub(super) async fn publish(
    State(state): State<HttpState>,
    Json(request): Json<SignedEnvelope<Value>>,
) -> Result<Json<Value>, ApiError> {
    let person_id = request.payload["personId"]
        .as_str()
        .filter(|id| valid_id(id))
        .ok_or_else(|| failure(StatusCode::BAD_REQUEST, "Invalid catalog publication"))?
        .to_owned();
    let gate = state
        .store
        .identity_authority_gate(&person_id)
        .map_err(|_| {
            failure(
                StatusCode::SERVICE_UNAVAILABLE,
                "Identity authority unavailable",
            )
        })?;
    let _guard = gate.read_owned().await;
    let origin = state.origin.clone();
    let receipt = tokio::task::spawn_blocking(move || {
        state
            .store
            .publish_identity_catalog_access(request, &origin)
    })
    .await
    .map_err(|_| {
        failure(
            StatusCode::SERVICE_UNAVAILABLE,
            "Catalog publication unavailable",
        )
    })?
    .map_err(|CatalogAccessError(status, message)| failure(status, message))?;
    Ok(Json(json!({"receipt": receipt})))
}

pub(super) async fn request_list(
    State(state): State<HttpState>,
    Json(request): Json<SignedEnvelope<Value>>,
) -> Result<Json<Value>, ApiError> {
    let person_id = request.payload["personId"]
        .as_str()
        .filter(|id| valid_id(id))
        .ok_or_else(|| failure(StatusCode::BAD_REQUEST, "Invalid catalog list request"))?
        .to_owned();
    let gate = state
        .store
        .identity_authority_gate(&person_id)
        .map_err(|_| {
            failure(
                StatusCode::SERVICE_UNAVAILABLE,
                "Identity authority unavailable",
            )
        })?;
    let _guard = gate.read_owned().await;
    let origin = state.origin.clone();
    let (envelopes, receipt) = tokio::task::spawn_blocking(move || {
        state.store.list_identity_catalog_access(request, &origin)
    })
    .await
    .map_err(|_| {
        failure(
            StatusCode::SERVICE_UNAVAILABLE,
            "Catalog request unavailable",
        )
    })?
    .map_err(catalog_list_failure)?;
    Ok(Json(json!({"envelopes": envelopes, "receipt": receipt})))
}

fn catalog_list_failure(CatalogAccessError(status, message): CatalogAccessError) -> ApiError {
    if message == CATALOG_ACCESS_PENDING_MESSAGE {
        (
            status,
            Json(json!({
                "code": "catalog_access_pending",
                "message": CATALOG_ACCESS_PENDING_MESSAGE,
            })),
        )
    } else {
        failure(status, message)
    }
}
