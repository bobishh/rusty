use std::{fs, path::PathBuf, sync::Arc};

use automerge::{AutoCommit, ROOT, transaction::Transactable};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use iroh::RelayMode;
use match_lighthouse::MatchLighthouseState;
use meta_mesh_core::{
    DEFAULT_SIGNATURE_DOMAIN, DeviceCertificate, DeviceCertificatePayload, MeshHandshake,
    MeshPeerAdmission, PublicIdentity, SignedEnvelope, WorkspaceAuthority,
    WorkspaceChangeAuthorizationPayload, WorkspaceGrantPayload, WorkspaceItem,
    WorkspaceJoinInvitation, WorkspaceRole, WorkspaceSetEntry, public_key_from_seed, public_key_id,
    sign_device_certificate, sign_json_envelope, verify_signed_envelope,
};
use meta_mesh_native::{NativeNode, NativeNodeOptions, NativeScopeHost, NativeScopeServiceHost};
use serde_json::{Value, json};

use super::KeeperHost;
use crate::{
    Config, ProvisioningCommit, join,
    pairing::{
        CONTROL_DOMAIN, ControllerRequest, IntegrationCandidate, PairingService,
        VerifiedDisconnectRequest,
    },
    provisioning::ProvisioningService,
};

struct Identity {
    identity_seed: [u8; 32],
    device_seed: [u8; 32],
    person_id: String,
    device_id: String,
    public_key: String,
    endpoint_secret: [u8; 32],
    endpoint: String,
    certificate: DeviceCertificate,
}

impl Identity {
    fn new(identity_seed: u8, device_seed: u8, endpoint_seed: u8) -> Self {
        let identity_seed = [identity_seed; 32];
        let device_seed = [device_seed; 32];
        let public_key = public_key_from_seed(&identity_seed).unwrap();
        let person_id = public_key_id(&public_key).unwrap();
        let device_public_key = public_key_from_seed(&device_seed).unwrap();
        let device_id = public_key_id(&device_public_key).unwrap();
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
        .unwrap();
        let endpoint_secret = [endpoint_seed; 32];
        Self {
            identity_seed,
            device_seed,
            person_id,
            device_id,
            public_key,
            endpoint_secret,
            endpoint: iroh::SecretKey::from(endpoint_secret).public().to_string(),
            certificate,
        }
    }

    fn bundle(&self, workspace_id: &str) -> Value {
        join::guest_bundle(
            workspace_id,
            &self.person_id,
            &self.device_id,
            &self.public_key,
            &self.certificate,
            &self.device_seed,
            &self.endpoint,
        )
        .unwrap()
    }

    fn authority(&self) -> WorkspaceAuthority {
        WorkspaceAuthority {
            person_id: self.person_id.clone(),
            public_key: self.public_key.clone(),
            certificates: vec![self.certificate.clone()],
        }
    }

    fn additional_device(&self, device_seed: u8) -> Self {
        let device_seed = [device_seed; 32];
        let device_public_key = public_key_from_seed(&device_seed).unwrap();
        let device_id = public_key_id(&device_public_key).unwrap();
        let certificate = sign_device_certificate(
            &self.identity_seed,
            DeviceCertificatePayload {
                kind: "device-certificate".into(),
                version: 1,
                person_id: self.person_id.clone(),
                device_id: device_id.clone(),
                device_public_key,
                issuer_certificate_hash: None,
                can_enroll_devices: false,
            },
            &self.person_id,
            DEFAULT_SIGNATURE_DOMAIN,
        )
        .unwrap();
        Self {
            identity_seed: self.identity_seed,
            device_seed,
            person_id: self.person_id.clone(),
            device_id,
            public_key: self.public_key.clone(),
            endpoint_secret: self.endpoint_secret,
            endpoint: self.endpoint.clone(),
            certificate,
        }
    }
}

struct ScopeFixture {
    invitation: WorkspaceJoinInvitation,
    response: Vec<u8>,
    grant: Value,
    envelope: Value,
    entry: Value,
}

fn signed_grant(owner: &Identity, person_id: &str, workspace_id: &str, epoch: u64) -> Value {
    serde_json::to_value(
        sign_json_envelope(
            &owner.identity_seed,
            json!(WorkspaceGrantPayload {
                kind: "workspace-grant".into(),
                version: 1,
                grant_id: format!("grant-{workspace_id}-{person_id}"),
                workspace_id: workspace_id.into(),
                person_id: person_id.into(),
                role: WorkspaceRole::Editor,
                access_epoch: Some(epoch),
            }),
            &owner.person_id,
            DEFAULT_SIGNATURE_DOMAIN,
        )
        .unwrap(),
    )
    .unwrap()
}

fn signed_state_with_preset(
    owner: &Identity,
    workspace_id: &str,
    preset: Option<&str>,
) -> MatchLighthouseState {
    let mut document = AutoCommit::new();
    document.put(ROOT, "id", workspace_id).unwrap();
    document
        .put(ROOT, "ownerPersonId", owner.person_id.clone())
        .unwrap();
    // Automerge JS 3 uses Text objects for ordinary string properties.
    let title = document
        .put_object(ROOT, "title", automerge::ObjType::Text)
        .unwrap();
    document.splice_text(&title, 0, 0, workspace_id).unwrap();
    if let Some(preset) = preset {
        let entities = document
            .put_object(ROOT, "entities", automerge::ObjType::Map)
            .unwrap();
        let board = document
            .put_object(&entities, "board", automerge::ObjType::Map)
            .unwrap();
        document.put(&board, "kind", "board").unwrap();
        let preset_object = document
            .put_object(&board, "preset", automerge::ObjType::Map)
            .unwrap();
        document.put(&preset_object, "key", preset).unwrap();
    }
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
    .unwrap();
    MatchLighthouseState {
        document: bytes,
        authorization: json!({
            "version": 1,
            "records": [{
                "signed": signed,
                "publicKey": owner.public_key,
                "certificates": [owner.certificate],
            }],
            "authority": {
                "genesisOwner": owner.authority(),
                "genesisEpoch": 1,
                "currentOwner": owner.authority(),
                "currentEpoch": 1,
                "ownershipTransfers": [],
                "successionClaims": [],
                "revocations": [],
                "deviceRevocations": [],
                "departures": [],
            }
        }),
        chat: json!({"version":1,"messages":[],"profiles":[],"typing":[]}),
        mesh: None,
    }
}

fn fixture(owner: &Identity, keeper: &Identity, workspace_id: &str) -> ScopeFixture {
    fixture_with_preset(owner, keeper, workspace_id, None)
}

fn fixture_with_preset(
    owner: &Identity,
    keeper: &Identity,
    workspace_id: &str,
    preset: Option<&str>,
) -> ScopeFixture {
    fixture_with_preset_at_epoch(owner, keeper, workspace_id, preset, 2)
}

fn fixture_with_preset_at_epoch(
    owner: &Identity,
    keeper: &Identity,
    workspace_id: &str,
    preset: Option<&str>,
    epoch: u64,
) -> ScopeFixture {
    let state = signed_state_with_preset(owner, workspace_id, preset);
    let grant = signed_grant(owner, &keeper.person_id, workspace_id, epoch);
    let owner_bundle = owner.bundle(workspace_id);
    let owner_peer = {
        let mut peer = owner_bundle.clone();
        peer["ownerPublicKey"] = json!(owner.public_key);
        peer["ownerCertificates"] = json!([owner.certificate]);
        peer
    };
    let envelope = json!({
        "workspaceId": workspace_id,
        "ownerPersonId": owner.person_id,
        "ownerPublicKey": owner.public_key,
        "ownerCertificates": [owner.certificate],
        "transportSecret": format!("transport-secret-{workspace_id}"),
        "peers": [owner_peer],
    });
    let entry = json!(WorkspaceSetEntry {
        id: workspace_id.into(),
        bytes: URL_SAFE_NO_PAD.encode(&state.document),
        authorization: Some(state.authorization.clone()),
        chat: Some(state.chat.clone()),
        mesh: None,
    });
    let response = serde_json::to_vec(&json!({
        "grants": [grant],
        "meshWorkspaces": [envelope],
        "snapshot": URL_SAFE_NO_PAD.encode(serde_json::to_vec(std::slice::from_ref(&entry)).unwrap()),
    }))
    .unwrap();
    let invitation = WorkspaceJoinInvitation {
        version: 1,
        kind: "workspace-join".into(),
        invitation_id: format!("invite-{workspace_id}"),
        issuer_person_id: owner.person_id.clone(),
        issuer_device_id: owner.device_id.clone(),
        issuer_public_key: public_key_from_seed(&owner.device_seed).unwrap(),
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
        secret: "invite-secret".into(),
    };
    ScopeFixture {
        invitation,
        response,
        grant,
        envelope,
        entry,
    }
}

struct TestKeeper {
    host: KeeperHost,
    owner: Identity,
    keeper: Identity,
    config_path: PathBuf,
    directory: PathBuf,
}

impl TestKeeper {
    fn new() -> Self {
        let owner = Identity::new(11, 12, 13);
        let keeper = Identity::new(21, 22, 23);
        let primary = fixture(&owner, &keeper, "primary-board");
        let directory = std::env::temp_dir().join(format!(
            "keeper-native-test-{}-{}",
            std::process::id(),
            rand::random::<u128>()
        ));
        fs::create_dir_all(&directory).unwrap();
        let config = join::prepare_config(
            &primary.invitation,
            &primary.response,
            &directory,
            &keeper.person_id,
            &keeper.device_id,
            &keeper.bundle("primary-board"),
            keeper.identity_seed,
            &keeper.device_seed,
            keeper.endpoint_secret,
        )
        .unwrap();
        let mut config = config;
        config.controller_person_id = Some(owner.person_id.clone());
        let config_path = directory.join("config.json");
        fs::write(&config_path, serde_json::to_vec(&config).unwrap()).unwrap();
        let host = KeeperHost::open(config, config_path.clone()).unwrap();
        Self {
            host,
            owner,
            keeper,
            config_path,
            directory,
        }
    }

    fn peer(&self, identity: &Identity, workspace_id: &str) -> MeshPeerAdmission {
        MeshPeerAdmission {
            workspace_id: workspace_id.into(),
            person_id: identity.person_id.clone(),
            device_id: identity.device_id.clone(),
            endpoint: identity.endpoint.clone(),
            instance_id: None,
            role: WorkspaceRole::Owner,
        }
    }

    fn offer(&self, fixture: &ScopeFixture) -> Value {
        json!({
            "version": 1,
            "controllerPersonId": self.owner.person_id,
            "workspaceId": fixture.invitation.workspace_id,
            "grant": fixture.grant,
            "envelope": fixture.envelope,
            "workspace": fixture.entry,
        })
    }

    fn merge_offer(&self, peer: MeshPeerAdmission, offer: &Value) -> Result<(), String> {
        let mut host = self.host.clone();
        let mut scope = host.open_scope(&peer)?;
        scope.merge_owner_offer(offer.to_string().as_bytes())
    }

    fn staged_scope(&self, workspace_id: &str) -> Config {
        self.staged_scope_at_epoch(workspace_id, 2)
    }

    fn staged_scope_at_epoch(&self, workspace_id: &str, epoch: u64) -> Config {
        let fixture =
            fixture_with_preset_at_epoch(&self.owner, &self.keeper, workspace_id, None, epoch);
        let directory = self.directory.join(format!(".provisioning-{workspace_id}"));
        let mut config = join::prepare_config(
            &fixture.invitation,
            &fixture.response,
            &directory,
            &self.keeper.person_id,
            &self.keeper.device_id,
            &self.keeper.bundle(workspace_id),
            self.keeper.identity_seed,
            &self.keeper.device_seed,
            self.keeper.endpoint_secret,
        )
        .unwrap();
        config.controller_person_id = Some(self.owner.person_id.clone());
        config
    }
}

fn controller_request(
    controller: &Identity,
    service: &Identity,
    service_origin: &str,
    mut payload: Value,
) -> ControllerRequest {
    let now = time::OffsetDateTime::now_utc().unix_timestamp() as u64;
    let object = payload.as_object_mut().unwrap();
    object.insert("version".into(), json!(1));
    object.insert("protocolVersion".into(), json!(1));
    object.insert("servicePersonId".into(), json!(service.person_id));
    object.insert("serviceOrigin".into(), json!(service_origin));
    object.insert("controllerPersonId".into(), json!(controller.person_id));
    object.insert("controllerDeviceId".into(), json!(controller.device_id));
    object.insert("issuedAt".into(), json!(now));
    object.insert("expiresAt".into(), json!(now + 300));
    let identity = PublicIdentity {
        person_id: controller.person_id.clone(),
        public_key: controller.public_key.clone(),
        display_name: "Test owner".into(),
    };
    ControllerRequest {
        identity,
        device_id: controller.device_id.clone(),
        certificates: vec![controller.certificate.clone()],
        signed: sign_json_envelope(
            &controller.device_seed,
            payload,
            &controller.device_id,
            CONTROL_DOMAIN,
        )
        .unwrap(),
    }
}

fn operation_id(byte: u8) -> String {
    URL_SAFE_NO_PAD.encode([byte; 16])
}

fn approved_active_pairing(
    keeper: &TestKeeper,
    service_origin: &str,
    grant_epoch: u64,
) -> (
    PairingService,
    String,
    String,
    String,
    String,
    ControllerRequest,
) {
    let pairings = PairingService::open(
        keeper.directory.join("pairings"),
        &keeper.keeper.bundle("primary-board"),
        service_origin.into(),
        keeper.keeper.device_seed,
        "test-operator-token-that-is-long-enough".into(),
    )
    .unwrap();
    let offer = controller_request(
        &keeper.owner,
        &keeper.keeper,
        service_origin,
        json!({
            "kind": "lighthouse-pairing-offer",
            "operationId": operation_id(rand::random()),
            "body": {
                "policy": {"futureBoards": false},
                "scopes": [{
                    "workspaceId": "second-board",
                    "title": "Second board",
                    "genesisAnchor": "second-board-genesis",
                    "mode": "replicate"
                }]
            }
        }),
    );
    let record = pairings.create(offer).unwrap();
    let (cookie, csrf) = pairings
        .login("test-operator-token-that-is-long-enough")
        .unwrap();
    pairings
        .admin_decision(&record.id, &cookie, &csrf, true)
        .unwrap();
    let approve = controller_request(
        &keeper.owner,
        &keeper.keeper,
        service_origin,
        json!({
            "kind": "lighthouse-pairing-decision",
            "operationId": operation_id(rand::random()),
            "pairingId": record.id,
            "transcriptHash": record.transcript_hash,
            "challengeNonce": record.challenge.payload["nonce"],
            "decision": "approve"
        }),
    );
    pairings.controller_decision(&record.id, approve).unwrap();

    let mut invitation = fixture_with_preset_at_epoch(
        &keeper.owner,
        &keeper.keeper,
        "second-board",
        None,
        grant_epoch,
    )
    .invitation;
    let created = time::OffsetDateTime::now_utc();
    invitation.created_at = created
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap();
    invitation.expires_at = (created + time::Duration::minutes(5))
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap();
    invitation.secret = "invite-secret-that-is-long-enough-123".into();
    let provision_operation = operation_id(rand::random());
    let provision = controller_request(
        &keeper.owner,
        &keeper.keeper,
        service_origin,
        json!({
            "kind": "lighthouse-pairing-provision",
            "operationId": provision_operation,
            "body": {
                "pairingId": record.id,
                "transcriptHash": record.transcript_hash,
                "servicePersonId": keeper.keeper.person_id,
                "futureBoards": false,
                "approvedScopes": [{"workspaceId":"second-board", "mode":"replicate"}],
                "invitation": invitation
            }
        }),
    );
    let provision_request = pairings
        .begin_provision(&record.id, provision.clone())
        .unwrap();
    let commit = ProvisioningCommit {
        pairing_id: record.id.clone(),
        integration_id: provision_request.integration_id.clone(),
        operation_id: provision_operation,
        transcript_hash: record.transcript_hash.clone(),
        invitation_id: provision_request.invitation.invitation_id.clone(),
        workspace_ids: vec!["second-board".into()],
        snapshot_hash: "http-contract-snapshot".into(),
        future_boards: false,
        controller_person_id: Some(keeper.owner.person_id.clone()),
    };
    keeper
        .host
        .activate_provisioned_scopes(
            vec![keeper.staged_scope_at_epoch("second-board", grant_epoch)],
            commit.clone(),
        )
        .unwrap();
    pairings
        .complete_from_durable_activation(&record.id, &commit)
        .unwrap();
    (
        pairings,
        record.id,
        provision_request.integration_id,
        commit.operation_id,
        record.transcript_hash,
        provision,
    )
}

fn controller_request_json(request: &ControllerRequest) -> Value {
    json!({
        "identity": request.identity,
        "deviceId": request.device_id,
        "certificates": request.certificates,
        "signed": request.signed,
    })
}

fn status_request(
    controller: &Identity,
    service: &Identity,
    service_origin: &str,
    operation_id: &str,
) -> ControllerRequest {
    controller_request(
        controller,
        service,
        service_origin,
        json!({
            "kind": "lighthouse-integration-status-request",
            "serviceDeviceId": service.device_id,
            "operationId": operation_id,
        }),
    )
}

fn pairing_status_request(
    controller: &Identity,
    service: &Identity,
    service_origin: &str,
    pairing_id: &str,
    transcript_hash: &str,
    operation_id: &str,
) -> ControllerRequest {
    controller_request(
        controller,
        service,
        service_origin,
        json!({
            "kind": "lighthouse-pairing-status",
            "pairingId": pairing_id,
            "transcriptHash": transcript_hash,
            "operationId": operation_id,
        }),
    )
}

fn disconnect_request(
    controller: &Identity,
    service: &Identity,
    service_origin: &str,
    integration_id: &str,
    operation_id: &str,
    expected_revision: u64,
    expected_epoch: u64,
) -> ControllerRequest {
    controller_request(
        controller,
        service,
        service_origin,
        json!({
            "kind": "lighthouse-integration-disconnect",
            "serviceDeviceId": service.device_id,
            "integrationId": integration_id,
            "operationId": operation_id,
            "expectedRevision": expected_revision,
            "scopes": [{"workspaceId":"second-board", "expectedGrantEpoch":expected_epoch}],
        }),
    )
}

async fn start_integration_http(
    directory: &std::path::Path,
    host: KeeperHost,
    service: &Identity,
    service_origin: &str,
    pairings: PairingService,
) -> (std::net::SocketAddr, tokio::task::JoinHandle<()>) {
    let node = Arc::new(
        NativeNode::start_with_options(NativeNodeOptions {
            relay_mode: RelayMode::Disabled,
            ..NativeNodeOptions::default()
        })
        .await
        .unwrap(),
    );
    let discovery =
        crate::http::Discovery::from_peer(&service.bundle("primary-board"), service_origin)
            .unwrap()
            .with_pairings(pairings)
            .with_provisioner(ProvisioningService::new(host.clone(), node));
    let app = crate::http::operator_test_router(directory, discovery, host).await;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    (address, server)
}

fn verify_service_response(value: Value, service: &Identity) -> Value {
    let envelope: SignedEnvelope<Value> = serde_json::from_value(value).unwrap();
    let public_key = public_key_from_seed(&service.device_seed).unwrap();
    verify_signed_envelope(&envelope, &public_key, CONTROL_DOMAIN).unwrap();
    assert_eq!(envelope.signer_key_id, service.device_id);
    envelope.payload
}

async fn post_controller_request(
    client: &reqwest::Client,
    url: &str,
    request: &ControllerRequest,
) -> (reqwest::StatusCode, Value) {
    let response = client
        .post(url)
        .json(&controller_request_json(request))
        .send()
        .await
        .unwrap();
    let status = response.status();
    let body = response.json().await.unwrap();
    (status, body)
}

impl Drop for TestKeeper {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.directory);
    }
}

#[test]
fn unsubscribe_primary_survives_restart_and_keeps_service_identity() {
    let keeper = TestKeeper::new();
    let before = keeper.host.configuration().unwrap();
    keeper
        .host
        .unsubscribe("primary-board", Some(&keeper.owner.person_id))
        .unwrap();
    assert!(keeper.host.scopes().unwrap().is_empty());
    let persisted: Config =
        serde_json::from_slice(&fs::read(&keeper.config_path).unwrap()).unwrap();
    assert!(persisted.primary_detached);
    assert!(persisted.initial_state.document.is_empty());
    assert!(persisted.initial_state.authorization.is_null());
    assert_eq!(persisted.identity_seed, before.identity_seed);
    assert_eq!(persisted.device_seed, before.device_seed);
    assert_eq!(persisted.iroh_secret, before.iroh_secret);
    let reopened = KeeperHost::open(persisted, keeper.config_path.clone()).unwrap();
    assert!(reopened.scopes().unwrap().is_empty());
    assert!(
        reopened.admin_overview().unwrap()["keeper"]["boards"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    assert!(reopened.intake_store().unwrap().is_none());
}

#[test]
fn unsubscribe_rejects_another_owner_without_changing_registry() {
    let keeper = TestKeeper::new();
    let before = fs::read(&keeper.config_path).unwrap();
    assert!(
        keeper
            .host
            .unsubscribe("primary-board", Some("another-owner"))
            .is_err()
    );
    assert_eq!(fs::read(&keeper.config_path).unwrap(), before);
    assert_eq!(keeper.host.scopes().unwrap().len(), 1);
}

#[test]
fn unsubscribe_cannot_hide_board_when_registry_write_fails() {
    let keeper = TestKeeper::new();
    fs::remove_file(&keeper.config_path).unwrap();
    fs::create_dir(&keeper.config_path).unwrap();
    assert!(keeper.host.unsubscribe("primary-board", None).is_err());
    assert_eq!(keeper.host.scopes().unwrap().len(), 1);
    assert!(!keeper.host.configuration().unwrap().primary_detached);
}

#[test]
fn unsubscribed_primary_can_be_added_again_by_fresh_provisioning() {
    let keeper = TestKeeper::new();
    keeper.host.unsubscribe("primary-board", None).unwrap();
    let scope = keeper.staged_scope_at_epoch("primary-board", 3);
    let commit = ProvisioningCommit {
        pairing_id: "new-pairing".into(),
        integration_id: crate::integration_id(&keeper.owner.person_id, &keeper.keeper.person_id),
        operation_id: "new-operation".into(),
        transcript_hash: "new-transcript".into(),
        invitation_id: "new-invitation".into(),
        workspace_ids: vec!["primary-board".into()],
        snapshot_hash: "new-snapshot".into(),
        future_boards: true,
        controller_person_id: Some(keeper.owner.person_id.clone()),
    };
    keeper
        .host
        .activate_provisioned_scopes(vec![scope], commit)
        .unwrap();
    let persisted: Config =
        serde_json::from_slice(&fs::read(&keeper.config_path).unwrap()).unwrap();
    assert!(!persisted.primary_detached);
    assert!(persisted.additional_scopes.is_empty());
    assert_eq!(
        KeeperHost::open(persisted, keeper.config_path.clone())
            .unwrap()
            .scopes()
            .unwrap()
            .len(),
        1
    );
}

#[test]
fn unsubscribed_additional_board_can_receive_a_fresh_grant() {
    let keeper = TestKeeper::new();
    let mut commit = ProvisioningCommit {
        pairing_id: "first-pairing".into(),
        integration_id: crate::integration_id(&keeper.owner.person_id, &keeper.keeper.person_id),
        operation_id: "first-operation".into(),
        transcript_hash: "transcript".into(),
        invitation_id: "invitation".into(),
        workspace_ids: vec!["second-board".into()],
        snapshot_hash: "snapshot".into(),
        future_boards: false,
        controller_person_id: Some(keeper.owner.person_id.clone()),
    };
    keeper
        .host
        .activate_provisioned_scopes(vec![keeper.staged_scope("second-board")], commit.clone())
        .unwrap();
    let old_path = keeper.host.configuration().unwrap().additional_scopes[0]
        .state_path
        .clone();
    keeper.host.unsubscribe("second-board", None).unwrap();
    assert!(!old_path.exists());
    commit.pairing_id = "fresh-pairing".into();
    commit.operation_id = "fresh-operation".into();
    keeper
        .host
        .activate_provisioned_scopes(
            vec![keeper.staged_scope_at_epoch("second-board", 3)],
            commit,
        )
        .unwrap();
    let config = keeper.host.configuration().unwrap();
    assert_ne!(config.additional_scopes[0].state_path, old_path);
    assert_eq!(
        KeeperHost::open(config, keeper.config_path.clone())
            .unwrap()
            .scopes()
            .unwrap()
            .len(),
        2
    );
}

#[test]
fn unsubscribe_removes_only_the_owned_scope_files() {
    let keeper = TestKeeper::new();
    let commit = ProvisioningCommit {
        pairing_id: "first-pairing".into(),
        integration_id: crate::integration_id(&keeper.owner.person_id, &keeper.keeper.person_id),
        operation_id: "first-operation".into(),
        transcript_hash: "transcript".into(),
        invitation_id: "invitation".into(),
        workspace_ids: vec!["second-board".into()],
        snapshot_hash: "snapshot".into(),
        future_boards: false,
        controller_person_id: Some(keeper.owner.person_id.clone()),
    };
    keeper
        .host
        .activate_provisioned_scopes(vec![keeper.staged_scope("second-board")], commit.clone())
        .unwrap();
    let config = keeper.host.configuration().unwrap();
    let owned_scope = config
        .additional_scopes
        .iter()
        .find(|scope| scope.workspace_id == "second-board")
        .unwrap();
    let owned_state_path = owned_scope.state_path.clone();
    let owned_directory = owned_state_path.parent().unwrap().to_path_buf();
    let proof_cache = owned_directory.join("state.json.proof-staging");
    fs::create_dir_all(&proof_cache).unwrap();
    fs::write(proof_cache.join("page.bin"), b"owned proof cache").unwrap();
    let unrelated_state = config.state_path.clone();
    let unrelated_bytes = fs::read(&unrelated_state).unwrap();

    keeper
        .host
        .unsubscribe("second-board", Some(&keeper.owner.person_id))
        .unwrap();

    assert!(!owned_state_path.exists());
    assert!(!proof_cache.exists());
    assert_eq!(fs::read(&unrelated_state).unwrap(), unrelated_bytes);
    assert_eq!(
        keeper
            .host
            .configuration()
            .unwrap()
            .provisioning_commits
            .len(),
        1
    );
    assert!(!owned_directory.exists());
}

#[test]
fn signed_disconnect_replay_cannot_remove_a_freshly_readded_scope() {
    let keeper = TestKeeper::new();
    let integration_id = crate::integration_id(&keeper.owner.person_id, &keeper.keeper.person_id);
    let commit = ProvisioningCommit {
        pairing_id: "first-pairing".into(),
        integration_id: integration_id.clone(),
        operation_id: "first-operation".into(),
        transcript_hash: "transcript".into(),
        invitation_id: "invitation".into(),
        workspace_ids: vec!["second-board".into()],
        snapshot_hash: "snapshot".into(),
        future_boards: true,
        controller_person_id: Some(keeper.owner.person_id.clone()),
    };
    keeper
        .host
        .activate_provisioned_scopes(
            vec![keeper.staged_scope_at_epoch("second-board", 2)],
            commit,
        )
        .unwrap();
    let old_path = keeper.host.configuration().unwrap().additional_scopes[0]
        .state_path
        .clone();
    let request = VerifiedDisconnectRequest {
        integration_id: integration_id.clone(),
        operation_id: URL_SAFE_NO_PAD.encode([7_u8; 16]),
        controller_person_id: keeper.owner.person_id.clone(),
        controller_device_id: keeper.owner.device_id.clone(),
        expected_revision: 1,
        scopes: vec![("second-board".into(), 2)],
        request_hash: "first-intent".into(),
    };
    let receipt = keeper.host.disconnect_integration(&request).unwrap();
    assert_eq!(receipt["status"], "removed");
    assert_eq!(receipt["scopes"][0]["cleanup"], "complete");
    assert!(!old_path.exists());

    let readd = ProvisioningCommit {
        pairing_id: "second-pairing".into(),
        integration_id: integration_id.clone(),
        operation_id: "second-operation".into(),
        transcript_hash: "new-transcript".into(),
        invitation_id: "new-invitation".into(),
        workspace_ids: vec!["second-board".into()],
        snapshot_hash: "new-snapshot".into(),
        future_boards: false,
        controller_person_id: Some(keeper.owner.person_id.clone()),
    };
    keeper
        .host
        .activate_provisioned_scopes(
            vec![keeper.staged_scope_at_epoch("second-board", 3)],
            readd.clone(),
        )
        .unwrap();
    let replay = keeper.host.disconnect_integration(&request).unwrap();
    assert_eq!(replay["status"], "removed");
    let active_path = keeper.host.configuration().unwrap().additional_scopes[0]
        .state_path
        .clone();
    assert!(active_path.exists());
    assert_eq!(keeper.host.scopes().unwrap().len(), 2);

    let candidate = IntegrationCandidate {
        integration_id,
        pairing_id: "second-pairing".into(),
        controller_person_id: keeper.owner.person_id.clone(),
        future_boards: false,
    };
    let (_, status) = keeper
        .host
        .integration_status(&[candidate], &keeper.owner.person_id)
        .unwrap();
    let current = status
        .iter()
        .find(|entry| entry["integrationId"] == request.integration_id)
        .unwrap();
    assert_eq!(current["scopes"][0]["state"], "active");
    assert_eq!(current["scopes"][0]["grantEpoch"], 3);
    assert_eq!(current["tombstones"][0]["state"], "removed");
}

#[cfg(unix)]
#[test]
fn disconnect_cleanup_failure_stays_pending_and_retries_after_restart() {
    use std::os::unix::fs::symlink;

    let keeper = TestKeeper::new();
    let integration_id = crate::integration_id(&keeper.owner.person_id, &keeper.keeper.person_id);
    let commit = ProvisioningCommit {
        pairing_id: "pending-pairing".into(),
        integration_id: integration_id.clone(),
        operation_id: "pending-activation".into(),
        transcript_hash: "transcript".into(),
        invitation_id: "invitation".into(),
        workspace_ids: vec!["second-board".into()],
        snapshot_hash: "snapshot".into(),
        future_boards: false,
        controller_person_id: Some(keeper.owner.person_id.clone()),
    };
    keeper
        .host
        .activate_provisioned_scopes(
            vec![keeper.staged_scope_at_epoch("second-board", 2)],
            commit,
        )
        .unwrap();
    let config = keeper.host.configuration().unwrap();
    let owned_dir = config.additional_scopes[0]
        .state_path
        .parent()
        .unwrap()
        .to_path_buf();
    let detached_dir = keeper.directory.join("detached-scope");
    fs::rename(&owned_dir, &detached_dir).unwrap();
    symlink(&detached_dir, &owned_dir).unwrap();
    let external_bytes = fs::read(detached_dir.join("state.json")).unwrap();

    let request = VerifiedDisconnectRequest {
        integration_id: integration_id.clone(),
        operation_id: URL_SAFE_NO_PAD.encode([8_u8; 16]),
        controller_person_id: keeper.owner.person_id.clone(),
        controller_device_id: keeper.owner.device_id.clone(),
        expected_revision: 1,
        scopes: vec![("second-board".into(), 2)],
        request_hash: "pending-intent".into(),
    };
    let receipt = keeper.host.disconnect_integration(&request).unwrap();
    assert_eq!(receipt["status"], "pending");
    assert_eq!(receipt["scopes"][0]["cleanup"], "pending");
    assert_eq!(
        fs::read(detached_dir.join("state.json")).unwrap(),
        external_bytes
    );
    assert!(
        keeper
            .host
            .scopes()
            .unwrap()
            .iter()
            .all(|scope| scope.0 != "second-board")
    );

    fs::remove_file(&owned_dir).unwrap();
    fs::rename(&detached_dir, &owned_dir).unwrap();
    let persisted = keeper.host.configuration().unwrap();
    let restarted = KeeperHost::open(persisted, keeper.config_path.clone()).unwrap();
    assert!(!owned_dir.exists());
    assert_eq!(restarted.scopes().unwrap().len(), 1);
    let persisted = restarted.configuration().unwrap();
    let record = persisted
        .integrations
        .iter()
        .find(|record| record.integration_id == integration_id)
        .unwrap();
    assert!(record.pending_disconnect.is_none());
    assert_eq!(
        record.disconnect_history[0].operation_id,
        request.operation_id
    );
}

#[cfg(unix)]
#[test]
fn local_unsubscribe_retries_the_same_scope_cleanup_without_restart() {
    use std::os::unix::fs::symlink;

    let keeper = TestKeeper::new();
    let commit = ProvisioningCommit {
        pairing_id: "local-retry-pairing".into(),
        integration_id: crate::integration_id(&keeper.owner.person_id, &keeper.keeper.person_id),
        operation_id: "local-retry-activation".into(),
        transcript_hash: "transcript".into(),
        invitation_id: "invitation".into(),
        workspace_ids: vec!["second-board".into()],
        snapshot_hash: "snapshot".into(),
        future_boards: false,
        controller_person_id: Some(keeper.owner.person_id.clone()),
    };
    keeper
        .host
        .activate_provisioned_scopes(vec![keeper.staged_scope("second-board")], commit)
        .unwrap();
    let config = keeper.host.configuration().unwrap();
    let owned_dir = config.additional_scopes[0]
        .state_path
        .parent()
        .unwrap()
        .to_path_buf();
    let detached_dir = keeper.directory.join("local-retry-scope");
    fs::rename(&owned_dir, &detached_dir).unwrap();
    symlink(&detached_dir, &owned_dir).unwrap();

    assert!(
        keeper
            .host
            .unsubscribe("second-board", Some(&keeper.owner.person_id))
            .is_err()
    );
    assert!(
        keeper
            .host
            .scopes()
            .unwrap()
            .iter()
            .all(|scope| scope.0 != "second-board")
    );
    let pending = keeper.host.configuration().unwrap();
    let operation = pending.integrations[0]
        .pending_disconnect
        .as_ref()
        .expect("failed cleanup stays pending");
    assert!(operation.operation_id.starts_with("local-"));
    assert_eq!(operation.workspace_ids, vec!["second-board"]);

    fs::remove_file(&owned_dir).unwrap();
    fs::rename(&detached_dir, &owned_dir).unwrap();
    keeper
        .host
        .unsubscribe("second-board", Some(&keeper.owner.person_id))
        .unwrap();

    assert!(!owned_dir.exists());
    let config = keeper.host.configuration().unwrap();
    assert!(config.additional_scopes.is_empty());
    assert!(config.integrations[0].pending_disconnect.is_none());
    assert_eq!(config.integrations[0].disconnect_history.len(), 1);
    assert!(
        keeper
            .host
            .scopes()
            .unwrap()
            .iter()
            .any(|scope| scope.0 == "primary-board")
    );
}

#[cfg(unix)]
#[test]
fn local_unsubscribe_cannot_drop_another_scope_during_pending_cleanup() {
    use std::os::unix::fs::symlink;

    let keeper = TestKeeper::new();
    let integration_id = crate::integration_id(&keeper.owner.person_id, &keeper.keeper.person_id);
    let first = ProvisioningCommit {
        pairing_id: "scope-b-pairing".into(),
        integration_id: integration_id.clone(),
        operation_id: "scope-b-operation".into(),
        transcript_hash: "transcript-b".into(),
        invitation_id: "invitation-b".into(),
        workspace_ids: vec!["second-board".into()],
        snapshot_hash: "snapshot-b".into(),
        future_boards: false,
        controller_person_id: Some(keeper.owner.person_id.clone()),
    };
    keeper
        .host
        .activate_provisioned_scopes(vec![keeper.staged_scope("second-board")], first)
        .unwrap();
    let second = ProvisioningCommit {
        pairing_id: "scope-c-pairing".into(),
        integration_id: integration_id.clone(),
        operation_id: "scope-c-operation".into(),
        transcript_hash: "transcript-c".into(),
        invitation_id: "invitation-c".into(),
        workspace_ids: vec!["third-board".into()],
        snapshot_hash: "snapshot-c".into(),
        future_boards: false,
        controller_person_id: Some(keeper.owner.person_id.clone()),
    };
    keeper
        .host
        .activate_provisioned_scopes(vec![keeper.staged_scope("third-board")], second)
        .unwrap();
    let config = keeper.host.configuration().unwrap();
    let owned_dir = config.additional_scopes[0]
        .state_path
        .parent()
        .unwrap()
        .to_path_buf();
    let detached_dir = keeper.directory.join("pending-scope");
    fs::rename(&owned_dir, &detached_dir).unwrap();
    symlink(&detached_dir, &owned_dir).unwrap();
    let pending = VerifiedDisconnectRequest {
        integration_id,
        operation_id: URL_SAFE_NO_PAD.encode([9_u8; 16]),
        controller_person_id: keeper.owner.person_id.clone(),
        controller_device_id: keeper.owner.device_id.clone(),
        expected_revision: 2,
        scopes: vec![("second-board".into(), 2)],
        request_hash: "pending-b-intent".into(),
    };
    assert_eq!(
        keeper.host.disconnect_integration(&pending).unwrap()["status"],
        "pending"
    );

    assert!(
        keeper
            .host
            .unsubscribe("third-board", Some(&keeper.owner.person_id))
            .is_err()
    );
    let scopes = keeper.host.scopes().unwrap();
    assert!(scopes.iter().any(|scope| scope.0 == "primary-board"));
    assert!(scopes.iter().any(|scope| scope.0 == "third-board"));
    assert!(
        keeper
            .host
            .configuration()
            .unwrap()
            .additional_scopes
            .iter()
            .any(|scope| scope.workspace_id == "third-board")
    );
}

#[cfg(unix)]
#[tokio::test]
async fn signed_http_status_disconnect_retry_and_restart_preserve_scope_authority() {
    use std::os::unix::fs::symlink;

    let keeper = TestKeeper::new();
    let service_origin = "https://rusty.example";
    let (pairings, pairing_id, integration_id, _, transcript_hash, old_provision) =
        approved_active_pairing(&keeper, service_origin, 2);
    let config = keeper.host.configuration().unwrap();
    let owned_dir = config.additional_scopes[0]
        .state_path
        .parent()
        .unwrap()
        .to_path_buf();
    let detached_dir = keeper.directory.join("http-contract-scope");
    fs::rename(&owned_dir, &detached_dir).unwrap();
    symlink(&detached_dir, &owned_dir).unwrap();

    let (address, server) = start_integration_http(
        &keeper.directory,
        keeper.host.clone(),
        &keeper.keeper,
        service_origin,
        pairings.clone(),
    )
    .await;
    let client = reqwest::Client::new();
    let status_url = format!("http://{address}/v1/integrations/status");
    let disconnect_url = format!("http://{address}/v1/integrations/{integration_id}/disconnect");
    let initial_status = status_request(
        &keeper.owner,
        &keeper.keeper,
        service_origin,
        &operation_id(44),
    );
    let (status, body) = post_controller_request(&client, &status_url, &initial_status).await;
    assert!(status.is_success());
    let payload = verify_service_response(body, &keeper.keeper);
    assert_eq!(payload["kind"], "lighthouse-integration-status");
    assert_eq!(payload["controllerPersonId"], keeper.owner.person_id);
    assert_eq!(payload["controllerDeviceId"], keeper.owner.device_id);
    assert_eq!(
        payload["operationId"],
        initial_status.signed.payload["operationId"]
    );
    let integration = payload["integrations"].as_array().unwrap().first().unwrap();
    assert_eq!(integration["integrationId"], integration_id);
    assert_eq!(integration["scopes"][0]["workspaceId"], "second-board");
    assert_eq!(integration["scopes"][0]["grantEpoch"], 2);
    assert_eq!(integration["scopes"][0]["state"], "active");
    let revision = integration["revision"].as_u64().unwrap();
    assert_eq!(payload["servicePersonId"], keeper.keeper.person_id);
    assert_eq!(payload["serviceDeviceId"], keeper.keeper.device_id);
    assert_eq!(payload["serviceOrigin"], service_origin);
    let wrong_service = status_request(
        &keeper.owner,
        &keeper.keeper,
        "https://different-rusty.example",
        &operation_id(51),
    );
    assert!(
        !post_controller_request(&client, &status_url, &wrong_service)
            .await
            .0
            .is_success()
    );

    let attacker = Identity::new(31, 32, 33);
    let wrong_owner = disconnect_request(
        &attacker,
        &keeper.keeper,
        service_origin,
        &integration_id,
        &operation_id(45),
        revision,
        2,
    );
    let (status, _) = post_controller_request(&client, &disconnect_url, &wrong_owner).await;
    assert!(!status.is_success());
    let mut wrong_device = disconnect_request(
        &keeper.owner,
        &keeper.keeper,
        service_origin,
        &integration_id,
        &operation_id(46),
        revision,
        2,
    );
    wrong_device.device_id = "uncertified-device".into();
    let (status, _) = post_controller_request(&client, &disconnect_url, &wrong_device).await;
    assert_eq!(status, reqwest::StatusCode::FORBIDDEN);
    let stale_revision = disconnect_request(
        &keeper.owner,
        &keeper.keeper,
        service_origin,
        &integration_id,
        &operation_id(47),
        revision.saturating_sub(1),
        2,
    );
    assert!(
        !post_controller_request(&client, &disconnect_url, &stale_revision)
            .await
            .0
            .is_success()
    );
    let stale_epoch = disconnect_request(
        &keeper.owner,
        &keeper.keeper,
        service_origin,
        &integration_id,
        &operation_id(48),
        revision,
        1,
    );
    assert!(
        !post_controller_request(&client, &disconnect_url, &stale_epoch)
            .await
            .0
            .is_success()
    );
    assert_eq!(keeper.host.scopes().unwrap().len(), 2);

    let remove = disconnect_request(
        &keeper.owner,
        &keeper.keeper,
        service_origin,
        &integration_id,
        &operation_id(49),
        revision,
        2,
    );
    let verified_remove = pairings
        .verify_disconnect_request(&integration_id, &remove)
        .unwrap();
    let (status, body) = post_controller_request(&client, &disconnect_url, &remove).await;
    assert!(status.is_success());
    let pending = verify_service_response(body, &keeper.keeper);
    assert_eq!(pending["status"], "pending");
    assert_eq!(pending["operationId"], remove.signed.payload["operationId"]);
    assert_eq!(pending["integrationId"], integration_id);
    assert_eq!(pending["controllerPersonId"], keeper.owner.person_id);
    assert_eq!(pending["servicePersonId"], keeper.keeper.person_id);
    assert_eq!(pending["scopes"][0]["state"], "pending");
    assert_eq!(pending["scopes"][0]["cleanup"], "pending");
    let pending_hash = pending["requestHash"].clone();
    assert_eq!(pending_hash, verified_remove.request_hash);

    let pending_status = status_request(
        &keeper.owner,
        &keeper.keeper,
        service_origin,
        &operation_id(50),
    );
    let (status, body) = post_controller_request(&client, &status_url, &pending_status).await;
    assert!(status.is_success());
    let payload = verify_service_response(body, &keeper.keeper);
    let pending_record = &payload["integrations"][0];
    assert!(pending_record["scopes"].as_array().unwrap().is_empty());
    assert_eq!(pending_record["tombstones"][0]["state"], "pending");
    assert_eq!(
        pending_record["pendingOperation"]["requestHash"],
        pending_hash
    );
    assert_eq!(
        pending_record["pendingOperation"]["operationId"],
        remove.signed.payload["operationId"]
    );

    fs::remove_file(&owned_dir).unwrap();
    fs::rename(&detached_dir, &owned_dir).unwrap();
    let retry_device = keeper.owner.additional_device(33);
    let retry = disconnect_request(
        &retry_device,
        &keeper.keeper,
        service_origin,
        &integration_id,
        remove.signed.payload["operationId"].as_str().unwrap(),
        revision,
        2,
    );
    assert_eq!(
        pairings
            .verify_disconnect_request(&integration_id, &retry)
            .unwrap()
            .request_hash,
        pending_hash
    );
    let (status, body) = post_controller_request(&client, &disconnect_url, &retry).await;
    assert!(status.is_success());
    let removed = verify_service_response(body, &keeper.keeper);
    assert_eq!(removed["status"], "removed");
    assert_eq!(removed["requestHash"], pending_hash);
    assert_eq!(removed["operationId"], remove.signed.payload["operationId"]);
    assert_eq!(removed["controllerPersonId"], keeper.owner.person_id);
    assert_eq!(removed["controllerDeviceId"], retry_device.device_id);
    assert_eq!(removed["integrationId"], integration_id);
    assert_eq!(removed["scopes"][0]["cleanup"], "complete");
    assert!(!owned_dir.exists());

    let pairing_status_url = format!("http://{address}/v1/pairings/{pairing_id}/status");
    let old_pairing_status = pairing_status_request(
        &keeper.owner,
        &keeper.keeper,
        service_origin,
        &pairing_id,
        &transcript_hash,
        &operation_id(52),
    );
    let (status, body) =
        post_controller_request(&client, &pairing_status_url, &old_pairing_status).await;
    assert!(status.is_success());
    let old_status = verify_service_response(body, &keeper.keeper);
    assert_eq!(old_status["status"], "detached");
    let old_provision_url = format!("http://{address}/v1/pairings/{pairing_id}/provision");
    let (status, _) = post_controller_request(&client, &old_provision_url, &old_provision).await;
    assert_eq!(status, reqwest::StatusCode::CONFLICT);
    server.abort();
    let _ = server.await;

    let persisted: Config =
        serde_json::from_slice(&fs::read(&keeper.config_path).unwrap()).unwrap();
    let restarted_host = KeeperHost::open(persisted, keeper.config_path.clone()).unwrap();
    assert_eq!(restarted_host.scopes().unwrap().len(), 1);
    let restarted_pairings = PairingService::open(
        keeper.directory.join("pairings"),
        &keeper.keeper.bundle("primary-board"),
        service_origin.into(),
        keeper.keeper.device_seed,
        "test-operator-token-that-is-long-enough".into(),
    )
    .unwrap();
    let (address, _server) = start_integration_http(
        &keeper.directory,
        restarted_host,
        &keeper.keeper,
        service_origin,
        restarted_pairings,
    )
    .await;
    let status_url = format!("http://{address}/v1/integrations/status");
    let (status, body) = post_controller_request(&client, &status_url, &pending_status).await;
    assert!(status.is_success());
    let payload = verify_service_response(body, &keeper.keeper);
    assert_eq!(payload["controllerPersonId"], keeper.owner.person_id);
    assert_eq!(payload["integrations"][0]["integrationId"], integration_id);
    assert!(
        payload["integrations"][0]["scopes"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    assert_eq!(
        payload["integrations"][0]["tombstones"][0]["state"],
        "removed"
    );
    assert_eq!(
        payload["integrations"][0]["tombstones"][0]["cleanup"],
        "complete"
    );
    assert!(payload["integrations"][0]["pendingOperation"].is_null());
    let pairing_status_url = format!("http://{address}/v1/pairings/{pairing_id}/status");
    let (status, body) =
        post_controller_request(&client, &pairing_status_url, &old_pairing_status).await;
    assert!(status.is_success());
    let old_status = verify_service_response(body, &keeper.keeper);
    assert_eq!(old_status["status"], "detached");
    assert_eq!(
        keeper.host.configuration().unwrap().provisioning_commits[0].pairing_id,
        pairing_id
    );
}

#[test]
fn readding_tombstoned_scope_requires_a_fresh_pairing_and_newer_grant() {
    let keeper = TestKeeper::new();
    let origin = "https://rusty.example";
    let (old_pairings, old_pairing_id, _, old_operation_id, _, _) =
        approved_active_pairing(&keeper, origin, 2);
    let old_commit = keeper
        .host
        .provisioning_commit(&old_pairing_id)
        .unwrap()
        .unwrap();
    assert_eq!(
        keeper
            .host
            .provisioning_lifecycle_status(&old_pairing_id)
            .unwrap(),
        Some(crate::keeper::ProvisioningLifecycleStatus::Active)
    );

    keeper
        .host
        .unsubscribe("second-board", Some(&keeper.owner.person_id))
        .unwrap();
    assert_eq!(
        keeper
            .host
            .provisioning_lifecycle_status(&old_pairing_id)
            .unwrap(),
        Some(crate::keeper::ProvisioningLifecycleStatus::Detached)
    );

    let (new_pairings, new_pairing_id, _, new_operation_id, _, _) =
        approved_active_pairing(&keeper, origin, 3);
    assert_ne!(new_pairing_id, old_pairing_id);
    assert_ne!(new_operation_id, old_operation_id);
    assert_eq!(
        keeper
            .host
            .provisioning_lifecycle_status(&old_pairing_id)
            .unwrap(),
        Some(crate::keeper::ProvisioningLifecycleStatus::Detached)
    );
    assert_eq!(
        keeper
            .host
            .provisioning_lifecycle_status(&new_pairing_id)
            .unwrap(),
        Some(crate::keeper::ProvisioningLifecycleStatus::Active)
    );
    let record = keeper
        .host
        .configuration()
        .unwrap()
        .integrations
        .into_iter()
        .find(|record| record.controller_person_id == keeper.owner.person_id)
        .unwrap();
    assert_eq!(record.scopes.len(), 1);
    assert_eq!(record.scopes[0].workspace_id, "second-board");
    assert_eq!(record.scopes[0].grant_epoch, 3);
    assert_eq!(record.scopes[0].activation_operation_id, new_operation_id);

    old_pairings
        .reconcile_durable_provisioning(&old_pairing_id, &old_commit.operation_id, "detached")
        .unwrap();
    let old_status = verify_service_response(
        serde_json::to_value(
            old_pairings
                .signed_provision_status(&old_pairing_id)
                .unwrap(),
        )
        .unwrap(),
        &keeper.keeper,
    );
    assert_eq!(old_status["status"], "detached");
    let new_status = verify_service_response(
        serde_json::to_value(
            new_pairings
                .signed_provision_status(&new_pairing_id)
                .unwrap(),
        )
        .unwrap(),
        &keeper.keeper,
    );
    assert_eq!(new_status["status"], "active");
}

#[test]
fn scope_cleanup_refuses_the_scopes_root_itself() {
    let keeper = TestKeeper::new();
    let config = keeper.host.configuration().unwrap();
    let scopes_root = keeper.directory.join("scopes");
    fs::create_dir_all(&scopes_root).unwrap();
    let survivor = scopes_root.join("unrelated-scope");
    fs::create_dir_all(&survivor).unwrap();
    fs::write(survivor.join("state.json"), b"keep this board").unwrap();
    let mut invalid_scope = config;
    invalid_scope.state_path = scopes_root.join("state.json");
    fs::write(&invalid_scope.state_path, b"not a scope directory").unwrap();

    assert!(super::cleanup_scope_storage(&keeper.directory, &invalid_scope, false).is_err());
    assert_eq!(
        fs::read(survivor.join("state.json")).unwrap(),
        b"keep this board"
    );
}

#[path = "keeper_owner_tests.rs"]
mod owner_tests;

#[test]
fn intake_follows_the_job_search_preset_across_keeper_scopes() {
    let keeper = TestKeeper::new();
    assert!(keeper.host.intake_store().unwrap().is_none());
    let jobs = fixture_with_preset(
        &keeper.owner,
        &keeper.keeper,
        "jobs-board",
        Some("job-search"),
    );
    keeper
        .merge_offer(
            keeper.peer(&keeper.owner, "primary-board"),
            &keeper.offer(&jobs),
        )
        .unwrap();
    let (workspace_id, store, _) = keeper.host.intake_store().unwrap().unwrap();
    assert_eq!(workspace_id, "jobs-board");
    assert!(store.has_board_preset("job-search").unwrap());
}

#[tokio::test]
async fn loco_overview_authenticates_operator_and_reports_existing_boards_and_jev_without_invites()
{
    use crate::{http, pairing::PairingService};
    use axum::http::{StatusCode, header};
    let keeper = TestKeeper::new();
    let staged = keeper.staged_scope("second-board");
    keeper
        .host
        .activate_provisioned_scopes(
            vec![staged],
            ProvisioningCommit {
                pairing_id: "overview-pairing".into(),
                integration_id: crate::integration_id(
                    &keeper.owner.person_id,
                    &keeper.keeper.person_id,
                ),
                operation_id: "overview-operation".into(),
                transcript_hash: "overview-transcript".into(),
                invitation_id: "overview-invitation".into(),
                workspace_ids: vec!["second-board".into()],
                snapshot_hash: "overview-snapshot".into(),
                future_boards: false,
                controller_person_id: Some(keeper.owner.person_id.clone()),
            },
        )
        .unwrap();
    let config = keeper.host.configuration().unwrap();
    let admin_secret = "test-operator-token-that-is-long-enough";
    let pairings = PairingService::open(
        keeper.directory.join("pairings"),
        &config.local_handshake.peer,
        "http://127.0.0.1:4283".into(),
        keeper.keeper.device_seed,
        admin_secret.into(),
    )
    .unwrap();
    let discovery =
        http::Discovery::from_peer(&config.local_handshake.peer, "http://127.0.0.1:4283")
            .unwrap()
            .with_pairings(pairings);
    let app = http::operator_test_router(&keeper.directory, discovery, keeper.host.clone()).await;
    fs::write(
        keeper.directory.join("inbox/pending.json"),
        "private incoming lead content",
    )
    .unwrap();
    for (index, status) in ["awaiting_mesh", "chat_queued", "card_created_v2"]
        .iter()
        .enumerate()
    {
        fs::write(keeper.directory.join(format!("results/{index}.json")), json!({
            "assessment": {"choice":"qualified", "confidence":0.9,"probabilities":{}, "model":"test-model"},
            "status":status,"company":"private employer", "role":"private lead role",
        }).to_string()).unwrap();
    }
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin = format!("http://{}", listener.local_addr().unwrap());
    let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    // Given the public hostname, entering at its root reaches the admin UI.
    let entry_client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap();
    for (path, target) in [
        ("/", "/admin/"),
        ("/?pairing=test-code", "/admin/?pairing=test-code"),
    ] {
        let response = entry_client
            .get(format!("{origin}{path}"))
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::TEMPORARY_REDIRECT);
        assert_eq!(response.headers()[header::LOCATION], target);
    }
    let client = reqwest::Client::new();
    let url = format!("{origin}/admin/api/overview");
    assert_eq!(
        client.get(&url).send().await.unwrap().status(),
        StatusCode::FORBIDDEN
    );
    let session_url = format!("{origin}/admin/api/session");
    for cookie in [None, Some("mesh_lighthouse_admin=invalid-session")] {
        let mut request = client.get(&session_url);
        if let Some(cookie) = cookie {
            request = request.header(header::COOKIE, cookie);
        }
        assert_eq!(
            request.send().await.unwrap().status(),
            StatusCode::FORBIDDEN
        );
    }
    let login = client
        .post(format!("{origin}/admin/api/session"))
        .json(&json!({"secret":admin_secret}))
        .send()
        .await
        .unwrap();
    assert_eq!(login.status(), StatusCode::OK);
    let cookie = login.headers()[header::SET_COOKIE]
        .to_str()
        .unwrap()
        .split(';')
        .next()
        .unwrap()
        .to_owned();
    let original_session = login.json::<Value>().await.unwrap();
    let restored = client
        .get(&session_url)
        .header(header::COOKIE, &cookie)
        .send()
        .await
        .unwrap();
    assert_eq!(restored.status(), StatusCode::OK);
    assert_eq!(restored.headers()[header::CACHE_CONTROL], "no-store");
    assert!(!restored.headers().contains_key(header::SET_COOKIE));
    assert_eq!(restored.json::<Value>().await.unwrap(), original_session);
    let response = client
        .get(&url)
        .header(header::COOKIE, &cookie)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let overview = response.json::<Value>().await.unwrap();
    let boards = overview["keeper"]["boards"].as_array().unwrap();
    assert_eq!(boards.len(), 2);
    assert_eq!(boards[0]["workspaceId"], "primary-board");
    assert_eq!(boards[0]["title"], "primary-board");
    assert_eq!(boards[0]["isPrimary"], true);
    assert_eq!(boards[1]["workspaceId"], "second-board");
    assert!(
        boards
            .iter()
            .all(|board| !board["heads"].as_array().unwrap().is_empty())
    );
    assert_eq!(overview["keeper"]["personId"], keeper.keeper.person_id);
    assert_eq!(overview["keeper"]["deviceId"], keeper.keeper.device_id);
    assert_eq!(overview["replication"]["state"], "idle");
    assert_eq!(overview["replication"]["activePeers"], 0);
    assert!(overview["triggers"][0]["targetWorkspaceId"].is_null());
    assert_eq!(overview["triggers"][0]["pendingCount"], 1);
    assert!(overview["triggers"][0]["lastResultAt"].as_u64().is_some());
    assert_eq!(
        overview["triggers"][0]["outcomes"],
        json!({"awaitingMesh":1,"chatQueued":1,"cardCreated":1})
    );
    let body = overview.to_string();
    for private in [
        admin_secret,
        "private incoming lead content",
        "private employer",
        "transport-secret",
        "identitySeed",
        "deviceSeed",
        "irohSecret",
    ] {
        assert!(!body.contains(private));
    }
    let detach_url = format!("{origin}/admin/api/boards/second-board/unsubscribe");
    let denied = client
        .post(&detach_url)
        .header(header::COOKIE, &cookie)
        .send()
        .await
        .unwrap();
    assert_eq!(denied.status(), StatusCode::FORBIDDEN);
    assert_eq!(keeper.host.scopes().unwrap().len(), 2);
    let detached = client
        .post(&detach_url)
        .header(header::COOKIE, &cookie)
        .header(
            "x-csrf-token",
            original_session["csrfToken"].as_str().unwrap(),
        )
        .header(header::ORIGIN, "http://127.0.0.1:4283")
        .send()
        .await
        .unwrap();
    assert_eq!(detached.status(), StatusCode::OK);
    assert_eq!(keeper.host.scopes().unwrap().len(), 1);
    assert!(
        keeper
            .host
            .configuration()
            .unwrap()
            .additional_scopes
            .is_empty()
    );
    for id in ["jobs-a", "jobs-b"] {
        let jobs = fixture_with_preset(&keeper.owner, &keeper.keeper, id, Some("job-search"));
        keeper
            .merge_offer(
                keeper.peer(&keeper.owner, "primary-board"),
                &keeper.offer(&jobs),
            )
            .unwrap();
    }
    let ambiguous = client
        .get(&url)
        .header(header::COOKIE, &cookie)
        .send()
        .await
        .unwrap();
    assert_eq!(ambiguous.status(), StatusCode::OK);
    let ambiguous = ambiguous.json::<Value>().await.unwrap();
    assert_eq!(ambiguous["keeper"]["boards"].as_array().unwrap().len(), 3);
    assert_eq!(
        ambiguous["triggers"][0]["errorDetail"],
        "Multiple job-search boards in keeper scopes"
    );
    assert!(ambiguous["triggers"][0]["targetWorkspaceId"].is_null());
    // Missing durable result storage is a sanitized failure, never an empty
    // success that hides lost intake data or leaked filesystem diagnostics.
    fs::remove_dir_all(keeper.directory.join("results")).unwrap();
    let failed = client
        .get(&url)
        .header(header::COOKIE, &cookie)
        .send()
        .await
        .unwrap();
    assert_eq!(failed.status(), StatusCode::SERVICE_UNAVAILABLE);
    let failure = failed.text().await.unwrap();
    assert!(!failure.contains(keeper.directory.to_str().unwrap()));
    assert!(!failure.contains("private employer"));
    let reset_url = format!("{origin}/admin/api/reset");
    for (secret, csrf, status) in [
        (
            "wrong-token",
            original_session["csrfToken"].as_str().unwrap(),
            StatusCode::FORBIDDEN,
        ),
        (admin_secret, "wrong-csrf", StatusCode::FORBIDDEN),
        (
            admin_secret,
            original_session["csrfToken"].as_str().unwrap(),
            StatusCode::ACCEPTED,
        ),
    ] {
        let response = client
            .post(&reset_url)
            .header(header::COOKIE, &cookie)
            .header("x-csrf-token", csrf)
            .header(header::ORIGIN, "http://127.0.0.1:4283")
            .json(&json!({"secret":secret}))
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), status);
        assert_eq!(
            keeper.directory.join("reset-request.json").exists(),
            status == StatusCode::ACCEPTED
        );
    }
    server.abort();
    crate::reset::apply_pending(&keeper.config_path).unwrap();
    let reset_config: Config =
        serde_json::from_slice(&fs::read(&keeper.config_path).unwrap()).unwrap();
    assert_eq!(reset_config.identity_seed, config.identity_seed);
    assert_eq!(reset_config.device_seed, config.device_seed);
    assert_eq!(reset_config.iroh_secret, config.iroh_secret);
    assert!(
        KeeperHost::open(reset_config, keeper.config_path.clone())
            .unwrap()
            .scopes()
            .unwrap()
            .is_empty()
    );
    assert!(!keeper.directory.join("state.json").exists());
    assert!(!keeper.directory.join("inbox").exists());
    assert!(!keeper.directory.join("reset-request.json").exists());
    assert_eq!(
        fs::read_dir(keeper.directory.join("reset-backups"))
            .unwrap()
            .count(),
        1
    );
    crate::reset::apply_pending(&keeper.config_path).unwrap();
}

#[test]
fn approved_owner_offer_activates_and_persists_scope_with_shared_service_identity() {
    let keeper = TestKeeper::new();
    let scope_fixture = fixture(&keeper.owner, &keeper.keeper, "second-board");
    let offer = keeper.offer(&scope_fixture);

    keeper
        .merge_offer(keeper.peer(&keeper.owner, "primary-board"), &offer)
        .unwrap();

    let scopes = keeper.host.scopes().unwrap();
    assert_eq!(scopes.len(), 2);
    assert!(scopes.iter().any(|(id, _, _)| id == "second-board"));
    let persisted: Config =
        serde_json::from_slice(&fs::read(&keeper.config_path).unwrap()).unwrap();
    let added = persisted
        .additional_scopes
        .iter()
        .find(|scope| scope.workspace_id == "second-board")
        .unwrap();
    assert_eq!(
        added.controller_person_id.as_deref(),
        Some(keeper.owner.person_id.as_str())
    );
    assert_eq!(added.device_id, keeper.keeper.device_id);
    assert_eq!(added.iroh_secret, keeper.keeper.endpoint_secret);
    assert_eq!(added.identity_seed, keeper.keeper.identity_seed);
    assert_eq!(added.device_seed, keeper.keeper.device_seed);
}

#[test]
fn offer_from_wrong_remote_or_claimed_controller_cannot_activate_scope() {
    let keeper = TestKeeper::new();
    let other = Identity::new(31, 32, 33);
    let scope_fixture = fixture(&keeper.owner, &keeper.keeper, "second-board");
    let offer = keeper.offer(&scope_fixture);

    assert!(
        keeper
            .merge_offer(keeper.peer(&other, "primary-board"), &offer)
            .is_err()
    );
    assert_eq!(keeper.host.scopes().unwrap().len(), 1);

    let mut forged_claim = offer;
    forged_claim["controllerPersonId"] = json!(other.person_id);
    assert!(
        keeper
            .merge_offer(keeper.peer(&keeper.owner, "primary-board"), &forged_claim)
            .is_err()
    );
    assert_eq!(keeper.host.scopes().unwrap().len(), 1);
}

#[test]
fn invalid_grant_or_document_never_activates_offered_scope() {
    let keeper = TestKeeper::new();
    let scope_fixture = fixture(&keeper.owner, &keeper.keeper, "second-board");
    let peer = keeper.peer(&keeper.owner, "primary-board");

    let mut tampered_grant = keeper.offer(&scope_fixture);
    tampered_grant["grant"]["payload"]["role"] = json!("owner");
    assert!(keeper.merge_offer(peer.clone(), &tampered_grant).is_err());
    assert_eq!(keeper.host.scopes().unwrap().len(), 1);

    let mut tampered_document = keeper.offer(&scope_fixture);
    tampered_document["workspace"]["bytes"] =
        json!(URL_SAFE_NO_PAD.encode(b"not an automerge document"));
    assert!(keeper.merge_offer(peer, &tampered_document).is_err());
    assert_eq!(keeper.host.scopes().unwrap().len(), 1);
}

#[test]
fn repeated_offer_is_idempotent_but_revalidates_signed_grant() {
    let keeper = TestKeeper::new();
    let scope_fixture = fixture(&keeper.owner, &keeper.keeper, "second-board");
    let peer = keeper.peer(&keeper.owner, "primary-board");
    let offer = keeper.offer(&scope_fixture);

    keeper.merge_offer(peer.clone(), &offer).unwrap();
    let before = keeper.host.scopes().unwrap();
    keeper.merge_offer(peer.clone(), &offer).unwrap();
    assert_eq!(keeper.host.scopes().unwrap(), before);

    let mut tampered = offer;
    tampered["grant"]["signature"] = json!("forged-signature");
    assert!(keeper.merge_offer(peer, &tampered).is_err());
    assert_eq!(keeper.host.scopes().unwrap(), before);
}

#[test]
fn owner_scope_inventory_is_withheld_from_unrelated_peer() {
    let keeper = TestKeeper::new();
    let scope_fixture = fixture(&keeper.owner, &keeper.keeper, "second-board");
    keeper
        .merge_offer(
            keeper.peer(&keeper.owner, "primary-board"),
            &keeper.offer(&scope_fixture),
        )
        .unwrap();

    let request: MeshHandshake = serde_json::from_value(json!({
        "workspaceId": "primary-board",
        "peer": {"advertisement": {"payload": {"personId": "unrelated-person"}}},
        "revocations": [],
        "deviceRevocations": [],
        "departures": [],
        "ownershipTransfers": [],
        "successionVotes": [],
        "successionClaims": [],
        "capabilities": ["causal-write-admission-v1"],
    }))
    .unwrap();
    let mut host = keeper.host.clone();
    let (_, response) = host.prepare_handshake("primary-board", &request).unwrap();
    assert!(response.get("ownerWorkspaceIds").is_none());

    let request: MeshHandshake = serde_json::from_value(json!({
        "workspaceId": "primary-board",
        "peer": keeper.owner.bundle("primary-board"),
        "revocations": [],
        "deviceRevocations": [],
        "departures": [],
        "ownershipTransfers": [],
        "successionVotes": [],
        "successionClaims": [],
        "capabilities": ["causal-write-admission-v1"],
    }))
    .unwrap();
    let (_, response) = host.prepare_handshake("primary-board", &request).unwrap();
    assert_eq!(
        response["ownerWorkspaceIds"],
        json!(["primary-board", "second-board"])
    );
}

#[test]
fn handshake_requires_causal_admission_before_exchange() {
    let keeper = TestKeeper::new();
    let mut host = keeper.host.clone();
    let legacy: MeshHandshake = serde_json::from_value(json!({
        "workspaceId": "primary-board", "peer": {}, "capabilities": [],
        "revocations": [], "deviceRevocations": [], "departures": [],
        "ownershipTransfers": [], "successionVotes": [], "successionClaims": [],
    }))
    .unwrap();
    assert!(
        host.prepare_handshake("primary-board", &legacy)
            .unwrap_err()
            .contains("causal write admission support")
    );

    let supported: MeshHandshake = serde_json::from_value(json!({
        "workspaceId": "primary-board", "peer": {},
        "capabilities": ["causal-write-admission-v1"],
        "revocations": [], "deviceRevocations": [], "departures": [],
        "ownershipTransfers": [], "successionVotes": [], "successionClaims": [],
    }))
    .unwrap();
    assert!(host.prepare_handshake("primary-board", &supported).is_ok());
}

#[test]
fn persisted_legacy_handshake_is_upgraded_without_repairing_scope() {
    let keeper = TestKeeper::new();
    {
        let mut registry = keeper.host.registry.lock().unwrap();
        registry
            .scopes
            .get_mut("primary-board")
            .unwrap()
            .local_handshake
            .capabilities
            .retain(|value| value != "causal-write-admission-v1");
    }
    let mut host = keeper.host.clone();
    let handshake = host.outgoing_handshake("primary-board").unwrap();
    assert!(
        handshake["capabilities"]
            .as_array()
            .unwrap()
            .iter()
            .any(|value| value == "causal-write-admission-v1")
    );
    assert_eq!(host.scopes().unwrap().len(), 1);
}

#[test]
fn registry_write_failure_does_not_activate_or_leave_new_scope_storage() {
    let keeper = TestKeeper::new();
    let offered = fixture(&keeper.owner, &keeper.keeper, "second-board");
    fs::remove_file(&keeper.config_path).unwrap();
    fs::create_dir(&keeper.config_path).unwrap();
    assert!(
        keeper
            .merge_offer(
                keeper.peer(&keeper.owner, "primary-board"),
                &keeper.offer(&offered)
            )
            .is_err()
    );
    assert_eq!(keeper.host.scopes().unwrap().len(), 1);
    assert!(!fs::read_dir(&keeper.directory).unwrap().any(|entry| {
        entry
            .unwrap()
            .file_name()
            .to_string_lossy()
            .starts_with("scope-")
    }));
}

#[test]
fn provisioned_scopes_activate_atomically_and_retry_by_durable_marker() {
    let keeper = TestKeeper::new();
    let commit = ProvisioningCommit {
        pairing_id: "pairing-test".into(),
        integration_id: crate::integration_id(&keeper.owner.person_id, &keeper.keeper.person_id),
        operation_id: "operation-test".into(),
        transcript_hash: "transcript-test".into(),
        invitation_id: "invitation-test".into(),
        workspace_ids: vec!["selected-board-a".into(), "selected-board-b".into()],
        snapshot_hash: "snapshot-test".into(),
        future_boards: false,
        controller_person_id: Some(keeper.owner.person_id.clone()),
    };
    let mut orphaned = vec![keeper.staged_scope("selected-board-a")];
    super::relocate_provisioned_scope_dirs(&keeper.directory, &mut orphaned, &commit).unwrap();
    let staged = vec![
        keeper.staged_scope("selected-board-a"),
        keeper.staged_scope("selected-board-b"),
    ];

    keeper
        .host
        .activate_provisioned_scopes(staged.clone(), commit.clone())
        .unwrap();
    assert_eq!(
        keeper
            .host
            .scopes()
            .unwrap()
            .iter()
            .map(|(id, _, _)| id.clone())
            .collect::<Vec<_>>(),
        vec![
            "primary-board".to_string(),
            "selected-board-a".to_string(),
            "selected-board-b".to_string()
        ]
    );
    keeper
        .host
        .activate_provisioned_scopes(staged, commit.clone())
        .unwrap();
    assert!(keeper.host.configuration().unwrap().provisioning_commits == vec![commit]);
    let mut changed = keeper.host.configuration().unwrap().provisioning_commits[0].clone();
    changed.snapshot_hash = "different-snapshot".into();
    assert!(
        keeper
            .host
            .activate_provisioned_scopes(vec![], changed)
            .is_err()
    );
    let persisted = keeper.host.configuration().unwrap();
    let added = persisted
        .additional_scopes
        .iter()
        .find(|scope| scope.workspace_id == "selected-board-a")
        .unwrap();
    assert!(added.state_path.exists());
    assert!(
        !added
            .state_path
            .starts_with(keeper.directory.join(".provisioning-"))
    );
    for workspace_id in ["selected-board-a", "selected-board-b"] {
        let _ = fs::remove_dir_all(
            keeper
                .directory
                .join(format!(".provisioning-{workspace_id}")),
        );
    }
    let reopened = KeeperHost::open(persisted, keeper.config_path.clone()).unwrap();
    assert_eq!(reopened.scopes().unwrap().len(), 3);
    assert!(reopened.primary_store().unwrap().0.snapshot().is_ok());
}

#[test]
fn failed_scope_validation_never_activates_a_subset_of_provisioned_scopes() {
    let keeper = TestKeeper::new();
    let first = keeper.staged_scope("selected-board-a");
    let mut second = keeper.staged_scope("selected-board-b");
    second.controller_person_id = Some("wrong-controller".into());
    let commit = ProvisioningCommit {
        pairing_id: "pairing-test".into(),
        integration_id: crate::integration_id(&keeper.owner.person_id, &keeper.keeper.person_id),
        operation_id: "operation-test".into(),
        transcript_hash: "transcript-test".into(),
        invitation_id: "invitation-test".into(),
        workspace_ids: vec!["selected-board-a".into(), "selected-board-b".into()],
        snapshot_hash: "snapshot-test".into(),
        future_boards: false,
        controller_person_id: Some(keeper.owner.person_id.clone()),
    };

    assert!(
        keeper
            .host
            .activate_provisioned_scopes(vec![first, second], commit)
            .is_err()
    );
    assert_eq!(keeper.host.scopes().unwrap().len(), 1);
    assert!(
        keeper
            .host
            .configuration()
            .unwrap()
            .additional_scopes
            .is_empty()
    );
    assert!(
        keeper
            .host
            .configuration()
            .unwrap()
            .provisioning_commits
            .is_empty()
    );
}

#[test]
fn outbound_inventory_uses_signed_route_person_field_and_only_targets_owner() {
    let keeper = TestKeeper::new();
    let mut host = keeper.host.clone();
    let handshake = host.outgoing_handshake("primary-board").unwrap();
    let frame = meta_mesh_core::encode_mesh_handshake(
        "mesh-handshake-request",
        "transport-secret-primary-board",
        handshake,
    )
    .unwrap();
    let owner_frame = host
        .attach_owner_inventory(
            "primary-board",
            &keeper.owner.endpoint,
            "transport-secret-primary-board",
            frame.clone(),
        )
        .unwrap();
    let decoded = meta_mesh_core::decode_mesh_handshake(
        &owner_frame,
        "mesh-handshake-request",
        "transport-secret-primary-board",
        "primary-board",
    )
    .unwrap();
    assert!(
        decoded
            .capabilities
            .iter()
            .any(|capability| capability == "causal-write-admission-v1")
    );
    assert_eq!(
        decoded.owner_workspace_ids,
        Some(vec!["primary-board".into()])
    );
    let other = Identity::new(31, 32, 33);
    let other_frame = host
        .attach_owner_inventory(
            "primary-board",
            &other.endpoint,
            "transport-secret-primary-board",
            frame,
        )
        .unwrap();
    let decoded = meta_mesh_core::decode_mesh_handshake(
        &other_frame,
        "mesh-handshake-request",
        "transport-secret-primary-board",
        "primary-board",
    )
    .unwrap();
    assert!(decoded.owner_workspace_ids.is_none());
}

/// Runs the actual config-mode process, including HTTP and Mesh workers.
/// Build frontend assets and binary first: cargo build --locked && cargo test --locked
/// config_mode_sigterm_drains_http_and_exits_without_losing_durable_state -- --ignored
#[tokio::test]
#[ignore = "requires the separately built mesh-lighthouse executable"]
async fn config_mode_sigterm_drains_http_and_exits_without_losing_durable_state() {
    use std::{process::Command, time::Duration};

    struct ChildGuard(std::process::Child);
    impl Drop for ChildGuard {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }

    let keeper = TestKeeper::new();
    let before = keeper.host.admin_overview().unwrap();
    let port = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let binary = std::env::var_os("LIGHTHOUSE_TEST_BINARY")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("target/debug/mesh-lighthouse")
        });
    let output = fs::File::create(keeper.directory.join("lifecycle.log")).unwrap();
    let mut child = ChildGuard(
        Command::new(binary)
            .arg(&keeper.config_path)
            .env("LIGHTHOUSE_HTTP_BIND", format!("127.0.0.1:{port}"))
            .env(
                "LIGHTHOUSE_PUBLIC_ORIGIN",
                format!("http://127.0.0.1:{port}"),
            )
            .stdout(output.try_clone().unwrap())
            .stderr(output)
            .spawn()
            .unwrap(),
    );
    let client = reqwest::Client::new();
    tokio::time::timeout(Duration::from_secs(15), async {
        loop {
            assert!(
                child.0.try_wait().unwrap().is_none(),
                "service exited before HTTP ready"
            );
            if client
                .get(format!("http://127.0.0.1:{port}/health"))
                .send()
                .await
                .is_ok_and(|response| response.status().is_success())
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    })
    .await
    .expect("HTTP should become ready");
    for path in ["/admin", "/admin/", "/admin/index.html"] {
        let response = client
            .get(format!("http://127.0.0.1:{port}{path}"))
            .send()
            .await
            .unwrap();
        assert!(
            response.status().is_success(),
            "{path} must serve Vue index"
        );
        assert!(
            response.headers()[reqwest::header::CONTENT_TYPE]
                .to_str()
                .unwrap()
                .starts_with("text/html")
        );
        assert!(response.text().await.unwrap().contains("/admin/assets/"));
    }
    let assets = crate::app::frontend_directory().join("assets");
    let mut checked_js = false;
    let mut checked_css = false;
    for asset in fs::read_dir(&assets).expect("build frontend before process smoke test") {
        let path = asset.unwrap().path();
        let filename = path.file_name().unwrap().to_str().unwrap();
        if filename.ends_with(".js") || filename.ends_with(".css") {
            let response = client
                .get(format!("http://127.0.0.1:{port}/admin/assets/{filename}"))
                .send()
                .await
                .unwrap();
            assert!(
                response.status().is_success(),
                "built asset {filename} must be served"
            );
            assert_eq!(
                response.headers()[reqwest::header::CACHE_CONTROL],
                "public, max-age=31536000, immutable"
            );
            checked_js |= filename.ends_with(".js");
            checked_css |= filename.ends_with(".css");
        }
    }
    assert!(
        checked_js && checked_css,
        "Vue JS and CSS build output required"
    );
    assert!(
        client
            .get(format!(
                "http://127.0.0.1:{port}/assets/inter-latin-wght-normal.woff2"
            ))
            .send()
            .await
            .unwrap()
            .status()
            .is_success()
    );
    assert!(
        Command::new("/bin/kill")
            .args(["-TERM", &child.0.id().to_string()])
            .status()
            .unwrap()
            .success()
    );
    let exit = tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            if let Some(exit) = child.0.try_wait().unwrap() {
                break exit;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    })
    .await
    .expect("SIGTERM must stop HTTP, Mesh workers and the complete process");
    assert!(
        exit.success(),
        "service must close node and return successfully: {exit}"
    );
    assert!(
        client
            .get(format!("http://127.0.0.1:{port}/health"))
            .send()
            .await
            .is_err()
    );
    let config: Config = serde_json::from_slice(&fs::read(&keeper.config_path).unwrap()).unwrap();
    let reopened = KeeperHost::open(config, keeper.config_path.clone()).unwrap();
    let after = reopened.admin_overview().unwrap();
    assert_eq!(
        before["boards"][0]["workspaceId"],
        after["boards"][0]["workspaceId"]
    );
    assert_eq!(before["boards"][0]["heads"], after["boards"][0]["heads"]);
    let mut host = reopened;
    let peer = keeper.peer(&keeper.keeper, "primary-board");
    host.open_scope(&peer)
        .expect("signed durable snapshot remains admissible after SIGTERM");
}

#[tokio::test]
#[ignore = "requires the separately built mesh-lighthouse executable"]
async fn detached_identity_starts_with_empty_boards_and_provisioning_enabled() {
    use std::{process::Command, time::Duration};
    let keeper = TestKeeper::new();
    keeper.host.unsubscribe("primary-board", None).unwrap();
    fs::remove_file(keeper.directory.join("state.json")).ok();
    let port = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let origin = format!("http://127.0.0.1:{port}");
    let binary = std::env::var_os("LIGHTHOUSE_TEST_BINARY")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("target/debug/mesh-lighthouse")
        });
    let output = fs::File::create(keeper.directory.join("empty-runtime.log")).unwrap();
    let mut child = Command::new(binary)
        .arg(&keeper.config_path)
        .env("LIGHTHOUSE_HTTP_BIND", format!("127.0.0.1:{port}"))
        .env("LIGHTHOUSE_PUBLIC_ORIGIN", &origin)
        .env(
            "LIGHTHOUSE_ADMIN_TOKEN",
            "test-detached-runtime-token-20261006",
        )
        .stdout(output.try_clone().unwrap())
        .stderr(output)
        .spawn()
        .unwrap();
    let client = reqwest::Client::new();
    let result = tokio::time::timeout(Duration::from_secs(15), async {
        loop {
            if let Ok(response) = client
                .get(format!("{origin}/.well-known/mesh-lighthouse"))
                .send()
                .await
            {
                if response.status().is_success() {
                    return response.json::<Value>().await.unwrap();
                }
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await;
    let discovery = match result {
        Ok(value) => value,
        Err(error) => {
            let _ = child.kill();
            let _ = child.wait();
            panic!(
                "Empty runtime failed: {error}: {}",
                fs::read_to_string(keeper.directory.join("empty-runtime.log")).unwrap()
            );
        }
    };
    let login = client
        .post(format!("{origin}/admin/api/session"))
        .header("content-type", "application/json")
        .header("origin", &origin)
        .body(r#"{"secret":"test-detached-runtime-token-20261006"}"#)
        .send()
        .await
        .unwrap();
    let cookie = login.headers()[reqwest::header::SET_COOKIE]
        .to_str()
        .unwrap()
        .split(';')
        .next()
        .unwrap()
        .to_owned();
    let overview = client
        .get(format!("{origin}/admin/api/overview"))
        .header("cookie", &cookie)
        .send()
        .await
        .unwrap()
        .json::<Value>()
        .await
        .unwrap();
    let csrf = login.json::<Value>().await.unwrap()["csrfToken"]
        .as_str()
        .unwrap()
        .to_owned();
    fs::write(
        keeper.directory.join("inbox/reset-fixture.json"),
        "private intake fixture",
    )
    .unwrap();
    let reset = client
        .post(format!("{origin}/admin/api/reset"))
        .header("cookie", &cookie)
        .header("x-csrf-token", csrf)
        .header("origin", &origin)
        .json(&json!({"secret":"test-detached-runtime-token-20261006"}))
        .send()
        .await
        .unwrap();
    assert_eq!(reset.status(), reqwest::StatusCode::ACCEPTED);
    let stopped = tokio::time::timeout(Duration::from_secs(15), async {
        loop {
            if let Some(status) = child.try_wait().unwrap() {
                return status;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await;
    if stopped.is_err() {
        let _ = child.kill();
        let _ = child.wait();
    }
    assert!(
        stopped
            .expect("Reset must drain and stop runtime")
            .success()
    );
    assert!(keeper.directory.join("reset-request.json").exists());
    let binary = std::env::var_os("LIGHTHOUSE_TEST_BINARY")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("target/debug/mesh-lighthouse")
        });
    let mut restarted = Command::new(binary);
    let output = fs::File::create(keeper.directory.join("reset-restart.log")).unwrap();
    let mut restarted = restarted
        .arg(&keeper.config_path)
        .env("LIGHTHOUSE_HTTP_BIND", format!("127.0.0.1:{port}"))
        .env("LIGHTHOUSE_PUBLIC_ORIGIN", &origin)
        .env(
            "LIGHTHOUSE_ADMIN_TOKEN",
            "test-detached-runtime-token-20261006",
        )
        .stdout(output.try_clone().unwrap())
        .stderr(output)
        .spawn()
        .unwrap();
    let ready = tokio::time::timeout(Duration::from_secs(15), async {
        loop {
            if client
                .get(format!("{origin}/health"))
                .send()
                .await
                .is_ok_and(|response| response.status().is_success())
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await;
    let _ = restarted.kill();
    let _ = restarted.wait();
    ready.expect("Reset runtime restarts with preserved identity");
    assert!(!keeper.directory.join("reset-request.json").exists());
    assert!(!keeper.directory.join("inbox/reset-fixture.json").exists());
    assert_eq!(
        fs::read_dir(keeper.directory.join("reset-backups"))
            .unwrap()
            .count(),
        1
    );
    assert_eq!(discovery["capabilities"]["provisioning"], true);
    assert_eq!(overview["keeper"]["personId"], keeper.keeper.person_id);
    assert!(overview["keeper"]["boards"].as_array().unwrap().is_empty());
}
