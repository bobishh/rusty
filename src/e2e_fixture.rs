use std::{fs, path::Path};

use automerge::{AutoCommit, ROOT, transaction::Transactable};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use match_lighthouse::MatchLighthouseState;
use meta_mesh_core::{
    DEFAULT_SIGNATURE_DOMAIN, DeviceCertificate, DeviceCertificatePayload,
    WorkspaceChangeAuthorizationPayload, WorkspaceGrantPayload, WorkspaceItem,
    WorkspaceJoinInvitation, WorkspaceRole, WorkspaceSetEntry, public_key_from_seed, public_key_id,
    sign_device_certificate, sign_json_envelope,
};
use serde_json::{Value, json};

use crate::{Config, join, keeper::KeeperHost};

type FixtureError = Box<dyn std::error::Error + Send + Sync>;

struct FixtureIdentity {
    identity_seed: [u8; 32],
    device_seed: [u8; 32],
    endpoint_secret: [u8; 32],
    person_id: String,
    device_id: String,
    public_key: String,
    endpoint: String,
    certificate: DeviceCertificate,
}

impl FixtureIdentity {
    fn new() -> Result<Self, FixtureError> {
        let identity_seed: [u8; 32] = rand::random();
        let device_seed: [u8; 32] = rand::random();
        let public_key = public_key_from_seed(&identity_seed).map_err(std::io::Error::other)?;
        let person_id = public_key_id(&public_key).map_err(std::io::Error::other)?;
        let device_public_key =
            public_key_from_seed(&device_seed).map_err(std::io::Error::other)?;
        let device_id = public_key_id(&device_public_key).map_err(std::io::Error::other)?;
        let certificate = sign_device_certificate(
            &identity_seed,
            DeviceCertificatePayload {
                kind: "device-certificate".into(),
                version: 1,
                person_id: person_id.clone(),
                device_id: device_id.clone(),
                device_public_key,
                issuer_certificate_hash: None,
                can_enroll_devices: false,
            },
            &person_id,
            DEFAULT_SIGNATURE_DOMAIN,
        )
        .map_err(std::io::Error::other)?;
        let endpoint_secret: [u8; 32] = rand::random();
        let endpoint = iroh::SecretKey::from(endpoint_secret).public().to_string();
        Ok(Self {
            identity_seed,
            device_seed,
            endpoint_secret,
            person_id,
            device_id,
            public_key,
            endpoint,
            certificate,
        })
    }

    fn bundle(&self, workspace_id: &str) -> Result<Value, FixtureError> {
        join::guest_bundle(
            workspace_id,
            &self.person_id,
            &self.device_id,
            &self.public_key,
            &self.certificate,
            &self.device_seed,
            &self.endpoint,
        )
    }
}

fn initial_workspace(
    owner: &FixtureIdentity,
    workspace_id: &str,
) -> Result<(MatchLighthouseState, String, Value), FixtureError> {
    let mut document = AutoCommit::new();
    document.put(ROOT, "id", workspace_id)?;
    document.put(ROOT, "ownerPersonId", owner.person_id.clone())?;
    let title = document.put_object(ROOT, "title", automerge::ObjType::Text)?;
    document.splice_text(&title, 0, 0, workspace_id)?;
    let bytes = document.save();
    let hashes = document
        .get_changes(&[])
        .iter()
        .map(|change| change.hash().to_string())
        .collect::<Vec<_>>();
    let signed = sign_json_envelope(
        &owner.device_seed,
        json!(WorkspaceChangeAuthorizationPayload {
            kind: "workspace-changes".into(),
            version: 1,
            workspace_id: workspace_id.into(),
            hashes,
            person_id: owner.person_id.clone(),
            device_id: owner.device_id.clone(),
        }),
        &owner.device_id,
        DEFAULT_SIGNATURE_DOMAIN,
    )
    .map_err(std::io::Error::other)?;
    let authorization = json!({
        "version": 1,
        "records": [{
            "signed": signed,
            "publicKey": owner.public_key,
            "certificates": [owner.certificate],
        }],
        "authority": {
            "genesisOwner": {
                "personId": owner.person_id,
                "publicKey": owner.public_key,
                "certificates": [owner.certificate],
            },
            "genesisEpoch": 1,
            "currentOwner": {
                "personId": owner.person_id,
                "publicKey": owner.public_key,
                "certificates": [owner.certificate],
            },
            "currentEpoch": 1,
            "ownershipTransfers": [],
            "successionClaims": [],
            "revocations": [],
            "deviceRevocations": [],
            "departures": [],
        }
    });
    let entry = json!(WorkspaceSetEntry {
        id: workspace_id.into(),
        bytes: URL_SAFE_NO_PAD.encode(bytes),
        authorization: Some(authorization.clone()),
        chat: Some(json!({"version":1,"messages":[],"profiles":[],"typing":[]})),
        mesh: None,
    });
    Ok((
        MatchLighthouseState {
            document: document.save(),
            authorization,
            chat: json!({"version":1,"messages":[],"profiles":[],"typing":[]}),
            mesh: None,
        },
        URL_SAFE_NO_PAD.encode(serde_json::to_vec(std::slice::from_ref(&entry))?),
        entry,
    ))
}

fn signed_peer_bundle(
    identity: &FixtureIdentity,
    workspace_id: &str,
) -> Result<Value, FixtureError> {
    let mut peer = identity.bundle(workspace_id)?;
    peer["ownerPublicKey"] = json!(identity.public_key);
    peer["ownerCertificates"] = json!([identity.certificate]);
    Ok(peer)
}

pub(crate) fn write_empty_service(
    directory: &Path,
) -> Result<Value, Box<dyn std::error::Error + Send + Sync>> {
    fs::create_dir_all(directory)?;
    let config_path = directory.join("config.json");
    if config_path.exists() {
        return Err("Fixture config already exists; choose a new directory".into());
    }

    let owner = FixtureIdentity::new()?;
    let service = FixtureIdentity::new()?;
    let workspace_id = "fixture-primary";
    let (state, snapshot, entry) = initial_workspace(&owner, workspace_id)?;
    let grant = sign_json_envelope(
        &owner.identity_seed,
        json!(WorkspaceGrantPayload {
            kind: "workspace-grant".into(),
            version: 1,
            grant_id: format!("grant-{workspace_id}-{}", service.person_id),
            workspace_id: workspace_id.into(),
            person_id: service.person_id.clone(),
            role: WorkspaceRole::Editor,
            access_epoch: Some(2),
        }),
        &owner.person_id,
        DEFAULT_SIGNATURE_DOMAIN,
    )?;
    let mut invitation = WorkspaceJoinInvitation {
        version: 1,
        kind: "workspace-join".into(),
        invitation_id: format!("fixture-invite-{workspace_id}"),
        issuer_person_id: owner.person_id.clone(),
        issuer_device_id: owner.device_id.clone(),
        issuer_public_key: public_key_from_seed(&owner.device_seed)
            .map_err(std::io::Error::other)?,
        issuer_endpoint: owner.endpoint.clone(),
        workspace_id: workspace_id.into(),
        workspace_title: workspace_id.into(),
        workspaces: vec![WorkspaceItem {
            id: workspace_id.into(),
            title: workspace_id.into(),
        }],
        role: "editor".into(),
        created_at: String::new(),
        expires_at: String::new(),
        secret: "fixture-join-secret-long-enough".into(),
    };
    let now = time::OffsetDateTime::now_utc();
    invitation.created_at = now.format(&time::format_description::well_known::Rfc3339)?;
    invitation.expires_at = (now + time::Duration::minutes(5))
        .format(&time::format_description::well_known::Rfc3339)?;
    let envelope = json!({
        "workspaceId": workspace_id,
        "ownerPersonId": owner.person_id,
        "ownerPublicKey": owner.public_key,
        "ownerCertificates": [owner.certificate],
        "transportSecret": "fixture-transport-secret-long-enough",
        "peers": [signed_peer_bundle(&owner, workspace_id)?],
    });
    let response = serde_json::to_vec(&json!({
        "grants": [grant],
        "meshWorkspaces": [envelope],
        "snapshot": snapshot,
    }))?;
    let bundle = service.bundle(workspace_id)?;
    let mut config = join::prepare_config(
        &invitation,
        &response,
        directory,
        &service.person_id,
        &service.device_id,
        &bundle,
        service.identity_seed,
        &service.device_seed,
        service.endpoint_secret,
    )
    .map_err(|error| std::io::Error::other(error.to_string()))?;
    config.controller_person_id = Some(owner.person_id.clone());
    fs::write(&config_path, serde_json::to_vec(&config)?)?;

    let host = KeeperHost::open(config, config_path.clone())?;
    host.unsubscribe(workspace_id, Some(&owner.person_id))?;
    let persisted: Config = serde_json::from_slice(&fs::read(&config_path)?)?;
    let reopened = KeeperHost::open(persisted, config_path.clone())?;
    if !reopened.scopes()?.is_empty() {
        return Err("Fixture service still has an active scope".into());
    }

    Ok(json!({
        "configPath": config_path,
        "servicePersonId": service.person_id,
        "serviceDeviceId": service.device_id,
        "servicePublicKey": service.public_key,
        "serviceCertificate": service.certificate,
        "initialOwnerPersonId": owner.person_id,
        "initialDocumentBytes": state.document.len(),
        "fixtureWorkspaceId": workspace_id,
        "fixtureEntryId": entry["id"],
        "status": "detached",
    }))
}
