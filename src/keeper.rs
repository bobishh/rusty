use std::{
    collections::BTreeMap,
    fs,
    io::Write,
    path::PathBuf,
    sync::{Arc, Mutex},
};

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use match_lighthouse::{MatchLighthouseHost, MatchScopeStore};
use meta_mesh_core::{
    DeviceCertificate, MeshHandshake, MeshPeerAdmission, PublicIdentity,
    VerifyWorkspaceMemberOptions, WorkspaceGrant, WorkspaceItem, WorkspaceJoinInvitation,
    WorkspaceRole, WorkspaceWriteAuthorizationSnapshot, public_key_id, verify_workspace_grant,
    verify_workspace_member_bundle,
};
use meta_mesh_native::{
    FileScopeStore, NativeOwnerOfferSnapshot, NativeScopeCredential, NativeScopeHost,
    NativeScopeServiceHost, NativeScopeSnapshot,
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use crate::{
    Config, DisconnectOperation, IntegrationRecord, IntegrationScope, IntegrationSettingsOperation,
    ProvisioningCommit, ScopeTombstone, join,
    pairing::{
        IntegrationCandidate, PolicyActivationFailure, VerifiedDisconnectRequest,
        VerifiedIntegrationSettingsRequest,
    },
};

pub(crate) struct Registry {
    config: Config,
    config_path: PathBuf,
    scopes: BTreeMap<String, MatchLighthouseHost>,
}

#[derive(Clone)]
pub(crate) struct KeeperHost {
    device_id: String,
    registry: Arc<Mutex<Registry>>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ProvisioningLifecycleStatus {
    Active,
    PendingCleanup,
    Detached,
}

#[derive(Debug)]
pub(crate) enum DisconnectError {
    Conflict,
    Forbidden,
    Unavailable,
}

impl From<String> for DisconnectError {
    fn from(_: String) -> Self {
        Self::Unavailable
    }
}

impl From<&str> for DisconnectError {
    fn from(_: &str) -> Self {
        Self::Unavailable
    }
}

fn current_owner(scope: &MatchLighthouseHost) -> Result<String, String> {
    Ok(scope.store.authority()?.expected_current_owner.person_id)
}

fn scope_grant_epoch(config: &Config) -> Result<u64, String> {
    let peer = &config.local_handshake.peer;
    let grant = peer
        .get("grant")
        .ok_or("Missing signed integration workspace grant")?;
    if grant.pointer("/payload/role").and_then(Value::as_str) != Some("editor") {
        return Err("Keeper integration requires a signed editor grant".into());
    }
    let epoch = grant
        .pointer("/payload/accessEpoch")
        .and_then(Value::as_u64)
        .unwrap_or(1);
    if epoch == 0 {
        return Err("Invalid integration grant epoch".into());
    }
    Ok(epoch)
}

fn scope_grant_id(config: &Config) -> Result<&str, String> {
    config
        .local_handshake
        .peer
        .pointer("/grant/payload/grantId")
        .and_then(Value::as_str)
        .filter(|grant_id| !grant_id.is_empty())
        .ok_or_else(|| "Missing signed integration grant id".into())
}

fn verified_editor_grant_epoch(
    config: &Config,
    host: &MatchLighthouseHost,
    service_person_id: &str,
) -> Result<u64, String> {
    let authority = host.store.authority()?;
    let owner = authority.expected_current_owner;
    let peer = &config.local_handshake.peer;
    if peer.get("ownerPublicKey").and_then(Value::as_str) != Some(owner.public_key.as_str()) {
        return Err("Persisted integration owner differs from current workspace owner".into());
    }
    let grant: WorkspaceGrant = serde_json::from_value(
        peer.get("grant")
            .cloned()
            .ok_or("Missing persisted signed integration grant")?,
    )
    .map_err(|_| "Invalid persisted signed integration grant")?;
    if verify_workspace_grant(
        &grant,
        &config.workspace_id,
        service_person_id,
        &PublicIdentity {
            person_id: owner.person_id,
            public_key: owner.public_key,
            display_name: String::new(),
        },
        &owner.certificates,
    )? != WorkspaceRole::Editor
    {
        return Err("Persisted keeper scope lacks a signed editor grant".into());
    }
    Ok(grant.payload.effective_access_epoch())
}

fn scope_epoch_for_legacy_removal(config: &Config) -> u64 {
    config
        .local_handshake
        .peer
        .pointer("/grant/payload/accessEpoch")
        .and_then(Value::as_u64)
        .unwrap_or(1)
        .max(1)
}

fn service_person_id(config: &Config) -> Result<String, String> {
    config
        .local_handshake
        .peer
        .pointer("/advertisement/payload/personId")
        .and_then(Value::as_str)
        .map(str::to_owned)
        .ok_or_else(|| "Missing configured service person".into())
}

fn owner_workspace_ids(registry: &Registry, owner_person_id: &str) -> Result<Vec<String>, String> {
    let mut workspace_ids = registry
        .scopes
        .iter()
        .filter_map(|(workspace_id, scope)| match current_owner(scope) {
            Ok(owner) if owner == owner_person_id => Some(Ok(workspace_id.clone())),
            Ok(_) => None,
            Err(error) => Some(Err(error)),
        })
        .collect::<Result<Vec<_>, _>>()?;
    workspace_ids.sort();
    Ok(workspace_ids)
}

fn owner_follows_future_boards(
    registry: &Registry,
    owner_person_id: &str,
    route_workspace_id: &str,
    offered_workspace_id: &str,
) -> Result<bool, String> {
    let configured_owner = std::iter::once(&registry.config)
        .chain(registry.config.additional_scopes.iter())
        .find(|config| config.workspace_id == route_workspace_id)
        .and_then(|config| config.controller_person_id.as_deref());
    let service_id = service_person_id(&registry.config)?;
    let has_current_board = if let Some(scope) = registry.scopes.get(route_workspace_id) {
        let config = configured_scope(&registry.config, route_workspace_id);
        current_owner(scope)? == owner_person_id
            && configured_owner == Some(owner_person_id)
            && config.is_some_and(|config| {
                verified_editor_grant_epoch(config, scope, &service_id).is_ok()
            })
    } else {
        false
    };
    let matching_integrations = registry
        .config
        .integrations
        .iter()
        .filter(|integration| {
            integration.controller_person_id == owner_person_id
                && integration.service_person_id == service_id
                && integration.future_boards
                && !integration.baseline_workspace_ids.is_empty()
                && !integration
                    .baseline_workspace_ids
                    .iter()
                    .any(|id| id == offered_workspace_id)
                && integration.pending_disconnect.is_none()
                && integration.pending_settings.is_none()
                && integration.scopes.iter().any(|scope| {
                    scope.workspace_id == route_workspace_id && scope.state == "active"
                })
        })
        .count();
    if registry.config.integrations.iter().any(|integration| {
        integration.controller_person_id == owner_person_id
            && integration.service_person_id == service_id
    }) {
        return Ok(has_current_board && matching_integrations == 1);
    }
    Ok(future_policy_matches_owner(
        owner_person_id,
        has_current_board,
        offered_workspace_id,
        &registry.config.provisioning_commits,
    ))
}

fn future_integration_index(
    config: &mut Config,
    registry: &Registry,
    owner_person_id: &str,
    route_workspace_id: &str,
    offered_workspace_id: &str,
) -> Result<usize, String> {
    let service_id = service_person_id(config)?;
    let matching = config
        .integrations
        .iter()
        .enumerate()
        .filter(|(_, integration)| {
            integration.controller_person_id == owner_person_id
                && integration.service_person_id == service_id
                && integration.future_boards
                && !integration.baseline_workspace_ids.is_empty()
                && !integration
                    .baseline_workspace_ids
                    .iter()
                    .any(|id| id == offered_workspace_id)
                && integration.pending_disconnect.is_none()
                && integration.pending_settings.is_none()
                && integration.scopes.iter().any(|scope| {
                    scope.workspace_id == route_workspace_id && scope.state == "active"
                })
        })
        .map(|(index, _)| index)
        .collect::<Vec<_>>();
    match matching.as_slice() {
        [index] => return Ok(*index),
        [] => {}
        _ => return Err("Keeper future-board policy has ambiguous active integrations".into()),
    }
    if config.integrations.iter().any(|integration| {
        integration.controller_person_id == owner_person_id
            && integration.service_person_id == service_id
    }) {
        return Err("Keeper future-board integration is inactive or pending removal".into());
    }
    let legacy_commit = config
        .provisioning_commits
        .iter()
        .rev()
        .find(|commit| {
            commit.future_boards
                && !commit.baseline_workspace_ids.is_empty()
                && !commit
                    .baseline_workspace_ids
                    .iter()
                    .any(|id| id == offered_workspace_id)
                && commit.controller_person_id.as_deref() == Some(owner_person_id)
                && commit
                    .workspace_ids
                    .iter()
                    .any(|id| id == route_workspace_id)
        })
        .ok_or("Keeper future-board consent is not recorded")?;
    let integration_id = if legacy_commit.integration_id.is_empty() {
        crate::integration_id(owner_person_id, &service_id)
    } else {
        legacy_commit.integration_id.clone()
    };
    let mut scopes = Vec::new();
    for (workspace_id, host) in &registry.scopes {
        if !legacy_commit
            .workspace_ids
            .iter()
            .any(|committed_id| committed_id == workspace_id)
            || current_owner(host)? != owner_person_id
        {
            continue;
        }
        let Some(scope) = configured_scope(config, workspace_id) else {
            continue;
        };
        if scope.controller_person_id.as_deref() != Some(owner_person_id) {
            continue;
        }
        let grant_id = scope_grant_id(scope)?;
        let grant_epoch = verified_editor_grant_epoch(scope, host, &service_id)?;
        let activation_operation_id = config
            .provisioning_commits
            .iter()
            .rev()
            .find(|commit| {
                commit.controller_person_id.as_deref() == Some(owner_person_id)
                    && commit.workspace_ids.iter().any(|id| id == workspace_id)
            })
            .map(|commit| commit.operation_id.clone())
            .unwrap_or_else(|| format!("legacy-owner-scope:{grant_id}"));
        scopes.push(IntegrationScope {
            workspace_id: workspace_id.clone(),
            grant_epoch,
            state: "active".into(),
            activation_operation_id,
        });
    }
    if !scopes
        .iter()
        .any(|scope| scope.workspace_id == route_workspace_id)
    {
        return Err("Keeper future-board route is not in the owner's active scopes".into());
    }
    scopes.sort_by(|left, right| left.workspace_id.cmp(&right.workspace_id));
    config.integrations.push(IntegrationRecord {
        integration_id,
        controller_person_id: owner_person_id.to_owned(),
        service_person_id: service_id,
        revision: 0,
        future_boards: legacy_commit.future_boards,
        baseline_workspace_ids: legacy_commit.baseline_workspace_ids.clone(),
        scopes,
        tombstones: Vec::new(),
        pending_disconnect: None,
        pending_settings: None,
        disconnect_history: Vec::new(),
        settings_history: Vec::new(),
    });
    Ok(config.integrations.len() - 1)
}

fn future_policy_matches_owner(
    owner_person_id: &str,
    has_current_board: bool,
    offered_workspace_id: &str,
    commits: &[ProvisioningCommit],
) -> bool {
    has_current_board
        && commits.iter().any(|commit| {
            commit.future_boards
                && !commit.baseline_workspace_ids.is_empty()
                && !commit
                    .baseline_workspace_ids
                    .iter()
                    .any(|id| id == offered_workspace_id)
                && commit.controller_person_id.as_deref() == Some(owner_person_id)
        })
}

fn owner_baseline_contains(
    registry: &Registry,
    owner_person_id: &str,
    service_person_id: &str,
    workspace_id: &str,
) -> bool {
    registry.config.integrations.iter().any(|integration| {
        integration.controller_person_id == owner_person_id
            && integration.service_person_id == service_person_id
            && integration
                .baseline_workspace_ids
                .iter()
                .any(|id| id == workspace_id)
    })
}

fn scope_host(config: &Config) -> Result<MatchLighthouseHost, String> {
    if config.local_handshake.workspace_id != config.workspace_id {
        return Err("Keeper handshake targets another scope".into());
    }
    let store = MatchScopeStore::open(
        config.workspace_id.clone(),
        config.genesis_person_id.clone(),
        config.state_path.clone(),
        config.initial_state.clone(),
    )?;
    let authority = store.authority()?;
    let verified = meta_mesh_core::verify_workspace_member_bundle(
        config.local_handshake.peer.clone(),
        meta_mesh_core::VerifyWorkspaceMemberOptions {
            workspace_id: Some(config.workspace_id.clone()),
            owner_person_id: Some(authority.expected_current_owner.person_id.clone()),
            owner_public_key: Some(authority.expected_current_owner.public_key.clone()),
            owner_certificates: authority.expected_current_owner.certificates.clone(),
            owner_history: vec![authority.genesis_owner.clone()],
            allow_stale_route: true,
            ..Default::default()
        },
        match_lighthouse::now_ms()?,
    )?;
    let secret: [u8; 32] = config
        .iroh_secret
        .as_slice()
        .try_into()
        .map_err(|_| "Invalid keeper endpoint seed")?;
    if verified.payload.device_id != config.device_id
        || verified.payload.endpoint != iroh::SecretKey::from(secret).public().to_string()
    {
        return Err("Keeper advertisement does not match service device and endpoint".into());
    }
    Ok(MatchLighthouseHost {
        workspace_id: config.workspace_id.clone(),
        secret: config.transport_secret.clone(),
        local_device_id: config.device_id.clone(),
        local_handshake: config.local_handshake.clone(),
        store,
    })
}

impl KeeperHost {
    pub(crate) fn open(mut config: Config, config_path: PathBuf) -> Result<Self, String> {
        // Prior releases had one controller identity for all future-board commits.
        // Import that identity before any new per-scope owner metadata is written.
        if let Some(legacy_owner) = config.controller_person_id.clone() {
            for commit in &mut config.provisioning_commits {
                if commit.future_boards && commit.controller_person_id.is_none() {
                    commit.controller_person_id = Some(legacy_owner.clone());
                }
            }
        }
        let mut scopes = BTreeMap::new();
        for scope in std::iter::once(&config).chain(config.additional_scopes.iter()) {
            if scope.primary_detached || scope_has_pending_removal(&config, &scope.workspace_id) {
                continue;
            }
            if scope_has_superseding_tombstone(&config, scope) {
                continue;
            }
            let host = scope_host(scope)?;
            if scope.device_id != config.device_id
                || scope.iroh_secret != config.iroh_secret
                || scope.device_seed != config.device_seed
                || scope.identity_seed != config.identity_seed
            {
                return Err("All keeper scopes must use one service identity and device".into());
            }
            if scopes
                .values()
                .any(|host: &MatchLighthouseHost| host.secret == scope.transport_secret)
            {
                return Err("Keeper scope secrets must be distinct".into());
            }
            if scopes.insert(scope.workspace_id.clone(), host).is_some() {
                return Err("Duplicate keeper scope".into());
            }
        }
        let host = Self {
            device_id: config.device_id.clone(),
            registry: Arc::new(Mutex::new(Registry {
                config,
                config_path,
                scopes,
            })),
        };
        host.retry_pending_disconnects();
        Ok(host)
    }

    fn retry_pending_disconnects(&self) {
        let Ok(mut registry) = self.registry.lock() else {
            return;
        };
        let pending = registry
            .config
            .integrations
            .iter()
            .enumerate()
            .filter_map(|(index, record)| {
                record
                    .pending_disconnect
                    .as_ref()
                    .is_some_and(|operation| operation.status == "pending")
                    .then_some(index)
            })
            .collect::<Vec<_>>();
        for index in pending {
            let _ = finish_disconnect_cleanup(&mut registry, index);
        }
    }

    pub(crate) fn scopes(&self) -> Result<Vec<(String, String, Vec<String>)>, String> {
        let registry = self
            .registry
            .lock()
            .map_err(|_| "Keeper registry lock poisoned")?;
        registry
            .scopes
            .values()
            .map(|scope| {
                Ok((
                    scope.workspace_id.clone(),
                    scope.secret.clone(),
                    scope.store.authorized_peer_endpoints()?,
                ))
            })
            .collect()
    }

    pub(crate) fn intake_store(&self) -> Result<Option<(String, MatchScopeStore, Value)>, String> {
        let registry = self
            .registry
            .lock()
            .map_err(|_| "Keeper registry lock poisoned")?;
        let mut selected = None;
        for (workspace_id, scope) in &registry.scopes {
            if !scope.store.has_board_preset("job-search")? {
                continue;
            }
            if selected.is_some() {
                return Err("Multiple job-search boards in keeper scopes".into());
            }
            selected = Some((
                workspace_id.clone(),
                scope.store.clone(),
                scope.local_handshake.peer.clone(),
            ));
        }
        Ok(selected)
    }

    #[cfg(test)]
    pub(crate) fn primary_store(&self) -> Result<(MatchScopeStore, Value), String> {
        let registry = self
            .registry
            .lock()
            .map_err(|_| "Keeper registry lock poisoned")?;
        let scope = registry
            .scopes
            .get(&registry.config.workspace_id)
            .ok_or("Missing primary scope")?;
        Ok((scope.store.clone(), scope.local_handshake.peer.clone()))
    }

    pub(crate) fn configuration(&self) -> Result<Config, String> {
        Ok(self
            .registry
            .lock()
            .map_err(|_| "Keeper registry lock poisoned")?
            .config
            .clone())
    }

    pub(crate) fn request_reset(&self) -> Result<(), String> {
        let registry = self
            .registry
            .lock()
            .map_err(|_| "Keeper registry lock poisoned")?;
        crate::reset::request(&registry.config_path)
    }

    /// Persist a scope tombstone before detaching routes and removing its stored replica.
    pub(crate) fn unsubscribe(
        &self,
        workspace_id: &str,
        owner: Option<&str>,
    ) -> Result<(), String> {
        let mut registry = self
            .registry
            .lock()
            .map_err(|_| "Keeper registry lock poisoned")?;
        let Some(scope) = registry.scopes.get(workspace_id) else {
            let pending = registry
                .config
                .integrations
                .iter()
                .enumerate()
                .filter(|(_, record)| {
                    owner.is_none_or(|owner| record.controller_person_id == owner)
                })
                .filter(|(_, record)| {
                    record.pending_disconnect.as_ref().is_some_and(|operation| {
                        operation.status == "pending"
                            && operation.operation_id.starts_with("local-")
                            && operation.workspace_ids == [workspace_id]
                            && record.tombstones.iter().any(|tombstone| {
                                tombstone.workspace_id == workspace_id
                                    && tombstone.operation_id == operation.operation_id
                            })
                    })
                })
                .map(|(index, _)| index)
                .collect::<Vec<_>>();
            return match pending.as_slice() {
                [index] => finish_disconnect_cleanup(&mut registry, *index),
                [] => Err("Board is not attached".into()),
                _ => Err("Multiple local removals are pending for this board".into()),
            };
        };
        let scope_owner = current_owner(scope)?;
        if owner.is_some_and(|owner| owner != scope_owner) {
            return Err("Board belongs to another owner".into());
        }
        let service_id = service_person_id(&registry.config)?;
        let integration_id = crate::integration_id(&scope_owner, &service_id);
        let scope_config = configured_scope(&registry.config, workspace_id)
            .cloned()
            .ok_or("Missing configured board")?;
        let mut next = registry.config.clone();
        let index = match next
            .integrations
            .iter()
            .position(|record| record.integration_id == integration_id)
        {
            Some(index) => index,
            None => {
                next.integrations.push(IntegrationRecord {
                    integration_id: integration_id.clone(),
                    controller_person_id: scope_owner.clone(),
                    service_person_id: service_id,
                    revision: 0,
                    future_boards: false,
                    baseline_workspace_ids: Vec::new(),
                    scopes: Vec::new(),
                    tombstones: Vec::new(),
                    pending_disconnect: None,
                    pending_settings: None,
                    disconnect_history: Vec::new(),
                    settings_history: Vec::new(),
                });
                next.integrations.len() - 1
            }
        };
        let record = &mut next.integrations[index];
        if record.controller_person_id != scope_owner {
            return Err("Integration belongs to another owner".into());
        }
        if record.pending_disconnect.as_ref().is_some_and(|operation| {
            operation.status == "pending"
                && !operation.workspace_ids.iter().any(|id| id == workspace_id)
        }) {
            return Err("Another scope removal is pending for this integration".into());
        }
        if record.pending_disconnect.is_none() {
            let expected_revision = record.revision;
            let operation_id = format!("local-{}", random_operation_id());
            let request_hash = disconnect_request_hash(
                &integration_id,
                &operation_id,
                expected_revision,
                &[workspace_id.to_owned()],
                &[scope_epoch_for_legacy_removal(&scope_config)],
            );
            record
                .scopes
                .retain(|item| item.workspace_id != workspace_id);
            record
                .tombstones
                .retain(|item| item.workspace_id != workspace_id);
            record.tombstones.push(ScopeTombstone {
                workspace_id: workspace_id.to_owned(),
                grant_epoch: scope_epoch_for_legacy_removal(&scope_config),
                operation_id: operation_id.clone(),
            });
            record.pending_disconnect = Some(DisconnectOperation {
                operation_id,
                request_hash,
                expected_revision,
                workspace_ids: vec![workspace_id.to_owned()],
                status: "pending".into(),
            });
            record.future_boards = false;
            record.revision = record.revision.saturating_add(1);
        }
        persist_config(&registry.config_path, &next)?;
        registry.config = next;
        registry.scopes.remove(workspace_id);
        let integration_index = registry
            .config
            .integrations
            .iter()
            .position(|record| record.integration_id == integration_id)
            .ok_or("Missing integration lifecycle")?;
        finish_disconnect_cleanup(&mut registry, integration_index)
    }

    pub(crate) fn admin_overview(&self) -> Result<Value, String> {
        self.overview_for_owner(None)
    }

    fn overview_for_owner(&self, owner_filter: Option<&str>) -> Result<Value, String> {
        let registry = self
            .registry
            .lock()
            .map_err(|_| "Keeper registry lock poisoned")?;
        let mut boards = Vec::with_capacity(registry.scopes.len());
        let peer = serde_json::to_value(&registry.config.local_handshake.peer)
            .map_err(|error| error.to_string())?;
        for (workspace_id, scope) in &registry.scopes {
            let owner_person_id = current_owner(scope)?;
            if owner_filter.is_some_and(|owner| owner != owner_person_id) {
                continue;
            }
            let (title, heads) = scope.store.document_overview()?;
            let config = std::iter::once(&registry.config)
                .chain(registry.config.additional_scopes.iter())
                .find(|config| config.workspace_id == *workspace_id)
                .ok_or("Missing keeper board configuration")?;
            let modified = fs::metadata(&config.state_path)
                .and_then(|metadata| metadata.modified())
                .ok()
                .and_then(|modified| modified.duration_since(std::time::UNIX_EPOCH).ok())
                .map(|duration| duration.as_secs());
            let title = title
                .filter(|title| !title.trim().is_empty())
                .unwrap_or_else(|| {
                    if *workspace_id == registry.config.workspace_id {
                        "Primary workspace".into()
                    } else {
                        format!("Board {}", workspace_id.get(..8).unwrap_or(workspace_id))
                    }
                });
            boards.push(json!({
                "workspaceId": workspace_id,
                "ownerPersonId": owner_person_id,
                "title": title,
                "isPrimary": *workspace_id == registry.config.workspace_id,
                "heads": heads,
                "peerCount": scope.store.authorized_peer_endpoints()?.len(),
                "lastSavedAt": modified,
            }));
        }
        boards.sort_by_key(|board| !board["isPrimary"].as_bool().unwrap_or(false));
        Ok(json!({
            "keeper": {
                "displayName": crate::keeper_display_name(peer.pointer("/advertisement/payload/deviceName").and_then(Value::as_str)),
                "personId": peer.pointer("/advertisement/payload/personId").and_then(Value::as_str).unwrap_or_default(),
                "deviceId": registry.config.device_id,
                "boards": boards,
            }
        }))
    }

    /// Owner view contains only boards whose verified current authority belongs to owner.
    pub(crate) fn owner_overview(&self, owner_person_id: &str) -> Result<Value, String> {
        self.overview_for_owner(Some(owner_person_id))
    }

    pub(crate) fn provisioning_commit(
        &self,
        pairing_id: &str,
    ) -> Result<Option<ProvisioningCommit>, String> {
        Ok(self
            .registry
            .lock()
            .map_err(|_| "Keeper registry lock poisoned")?
            .config
            .provisioning_commits
            .iter()
            .find(|commit| commit.pairing_id == pairing_id)
            .cloned())
    }

    pub(crate) fn provisioning_lifecycle_status(
        &self,
        pairing_id: &str,
    ) -> Result<Option<ProvisioningLifecycleStatus>, String> {
        let registry = self
            .registry
            .lock()
            .map_err(|_| "Keeper registry lock poisoned")?;
        let Some(commit) = registry
            .config
            .provisioning_commits
            .iter()
            .find(|commit| commit.pairing_id == pairing_id)
        else {
            return Ok(None);
        };
        if commit.workspace_ids.is_empty() {
            return Ok(Some(ProvisioningLifecycleStatus::Detached));
        }
        let controller = commit
            .controller_person_id
            .as_deref()
            .or(registry.config.controller_person_id.as_deref());
        let service = service_person_id(&registry.config)?;
        let integration_id = if commit.integration_id.is_empty() {
            controller.map(|owner| crate::integration_id(owner, &service))
        } else {
            Some(commit.integration_id.clone())
        };
        let Some(integration) = integration_id.and_then(|id| {
            registry
                .config
                .integrations
                .iter()
                .find(|record| record.integration_id == id)
        }) else {
            return Ok(Some(ProvisioningLifecycleStatus::Detached));
        };
        let mut pending_cleanup = false;
        for workspace_id in &commit.workspace_ids {
            let active = integration.scopes.iter().any(|scope| {
                scope.workspace_id == *workspace_id
                    && scope.state == "active"
                    && scope.activation_operation_id == commit.operation_id
            }) && registry
                .scopes
                .get(workspace_id)
                .is_some_and(|scope| current_owner(scope).ok().as_deref() == controller);
            if active {
                continue;
            }
            let pending = integration
                .pending_disconnect
                .as_ref()
                .is_some_and(|operation| {
                    operation.status == "pending"
                        && operation.workspace_ids.iter().any(|id| id == workspace_id)
                        && integration.tombstones.iter().any(|tombstone| {
                            tombstone.workspace_id == *workspace_id
                                && tombstone.operation_id == operation.operation_id
                        })
                });
            if pending {
                pending_cleanup = true;
            } else {
                return Ok(Some(ProvisioningLifecycleStatus::Detached));
            }
        }
        Ok(Some(if pending_cleanup {
            ProvisioningLifecycleStatus::PendingCleanup
        } else {
            ProvisioningLifecycleStatus::Active
        }))
    }

    pub(crate) fn integration_status(
        &self,
        candidates: &[IntegrationCandidate],
        controller_person_id: &str,
    ) -> Result<(u64, Vec<Value>), String> {
        let mut registry = self
            .registry
            .lock()
            .map_err(|_| "Keeper registry lock poisoned")?;
        let service_id = service_person_id(&registry.config)?;
        let pending_for_owner = registry
            .config
            .integrations
            .iter()
            .enumerate()
            .filter_map(|(index, record)| {
                (record.controller_person_id == controller_person_id
                    && (record
                        .pending_disconnect
                        .as_ref()
                        .is_some_and(|operation| operation.status == "pending")
                        || record
                            .pending_settings
                            .as_ref()
                            .is_some_and(|operation| operation.status == "pending")))
                .then_some(index)
            })
            .collect::<Vec<_>>();
        for index in pending_for_owner {
            if registry.config.integrations[index]
                .pending_disconnect
                .as_ref()
                .is_some_and(|item| item.status == "pending")
            {
                let _ = finish_disconnect_cleanup(&mut registry, index);
            } else {
                let _ = finish_settings_cleanup(&mut registry, index);
            }
        }
        let canonical_integration_id = crate::integration_id(controller_person_id, &service_id);
        let mut changed = false;
        for candidate in candidates {
            if candidate.controller_person_id != controller_person_id {
                continue;
            }
            if registry
                .config
                .integrations
                .iter()
                .any(|record| record.integration_id == canonical_integration_id)
            {
                continue;
            }
            let commit = registry
                .config
                .provisioning_commits
                .iter()
                .find(|commit| commit.pairing_id == candidate.pairing_id)
                .cloned()
                .ok_or("Pairing has no verified durable scope activation")?;
            if commit
                .controller_person_id
                .as_deref()
                .is_some_and(|owner| owner != controller_person_id)
                || commit.workspace_ids.is_empty()
            {
                return Err("Pairing activation does not match the requested owner".into());
            }
            let legacy_record_index = registry.config.integrations.iter().position(|record| {
                record.controller_person_id == controller_person_id
                    && record.service_person_id == service_id
                    && (record.scopes.iter().any(|scope| {
                        commit
                            .workspace_ids
                            .iter()
                            .any(|id| id == &scope.workspace_id)
                    }) || record.tombstones.iter().any(|tombstone| {
                        commit
                            .workspace_ids
                            .iter()
                            .any(|id| id == &tombstone.workspace_id)
                    }))
            });
            if let Some(index) = legacy_record_index {
                let record = &mut registry.config.integrations[index];
                if record.integration_id != canonical_integration_id {
                    record.integration_id = canonical_integration_id.clone();
                    changed = true;
                }
                continue;
            }
            let mut scopes = Vec::new();
            let mut tombstones = Vec::new();
            for workspace_id in &commit.workspace_ids {
                let configured = configured_scope(&registry.config, workspace_id);
                if let Some(configured) = configured.filter(|scope| !scope.primary_detached) {
                    let host = scope_host(configured)?;
                    if current_owner(&host)? != controller_person_id {
                        return Err(
                            "Pairing activation scope is not owned by the controller".into()
                        );
                    }
                    scopes.push(IntegrationScope {
                        workspace_id: workspace_id.clone(),
                        grant_epoch: scope_epoch_for_legacy_removal(configured),
                        state: "active".into(),
                        activation_operation_id: commit.operation_id.clone(),
                    });
                } else {
                    // A historical durable activation with no configured scope is detached,
                    // never an instruction to scan storage or reconstruct its old authority.
                    tombstones.push(ScopeTombstone {
                        workspace_id: workspace_id.clone(),
                        grant_epoch: 1,
                        operation_id: format!("legacy-{}", commit.operation_id),
                    });
                }
            }
            let future_boards = candidate.future_boards
                && commit.future_boards
                && !commit.baseline_workspace_ids.is_empty()
                && !scopes.is_empty();
            registry.config.integrations.push(IntegrationRecord {
                integration_id: canonical_integration_id.clone(),
                controller_person_id: controller_person_id.to_owned(),
                service_person_id: service_id.clone(),
                revision: 1,
                future_boards,
                baseline_workspace_ids: commit.baseline_workspace_ids.clone(),
                scopes,
                tombstones,
                pending_disconnect: None,
                pending_settings: None,
                disconnect_history: Vec::new(),
                settings_history: Vec::new(),
            });
            changed = true;
        }
        if changed {
            persist_config(&registry.config_path, &registry.config)?;
        }
        let values = registry
            .config
            .integrations
            .iter()
            .filter(|record| {
                record.controller_person_id == controller_person_id
                    && record.service_person_id == service_id
            })
            .map(integration_status_value)
            .collect::<Vec<_>>();
        let revision = values
            .iter()
            .filter_map(|value| value["revision"].as_u64())
            .max()
            .unwrap_or(0);
        Ok((revision, values))
    }

    pub(crate) fn disconnect_integration(
        &self,
        request: &VerifiedDisconnectRequest,
    ) -> Result<Value, DisconnectError> {
        let mut registry = self
            .registry
            .lock()
            .map_err(|_| "Keeper registry lock poisoned")?;
        let index = registry
            .config
            .integrations
            .iter()
            .position(|record| record.integration_id == request.integration_id)
            .ok_or("Unknown integration")?;
        let current = registry.config.integrations[index].clone();
        if current.controller_person_id != request.controller_person_id
            || current.service_person_id != service_person_id(&registry.config)?
        {
            return Err("Integration owner or service binding mismatch".into());
        }
        if let Some(completed) = current
            .disconnect_history
            .iter()
            .find(|operation| operation.operation_id == request.operation_id)
        {
            if completed.request_hash != request.request_hash {
                return Err(DisconnectError::Conflict);
            }
            if request.scopes.iter().any(|(workspace_id, _)| {
                current
                    .scopes
                    .iter()
                    .any(|scope| scope.workspace_id == *workspace_id && scope.state == "active")
            }) {
                return Err(DisconnectError::Conflict);
            }
            return Ok(disconnect_receipt_value(request, completed, &current));
        }
        if let Some(pending) = &current.pending_disconnect {
            if pending.operation_id != request.operation_id
                || pending.request_hash != request.request_hash
            {
                return Err("Another disconnect operation is pending".into());
            }
        } else {
            if current
                .pending_settings
                .as_ref()
                .is_some_and(|operation| operation.status == "pending")
            {
                return Err("Integration settings cleanup is pending".into());
            }
            if current.revision != request.expected_revision {
                return Err("Integration revision changed".into());
            }
            let requested_ids = request
                .scopes
                .iter()
                .map(|(workspace_id, _)| workspace_id.as_str())
                .collect::<std::collections::HashSet<_>>();
            for (workspace_id, expected_epoch) in &request.scopes {
                let active = current
                    .scopes
                    .iter()
                    .find(|scope| scope.workspace_id == *workspace_id && scope.state == "active")
                    .ok_or("Disconnect scope is not active")?;
                if active.grant_epoch != *expected_epoch {
                    return Err("Disconnect grant epoch changed".into());
                }
                if configured_scope(&registry.config, workspace_id).is_none() {
                    return Err("Disconnect scope is not configured".into());
                }
                let host = registry
                    .scopes
                    .get(workspace_id)
                    .ok_or("Disconnect scope is not currently routable")?;
                if current_owner(host)? != request.controller_person_id {
                    return Err(
                        "Disconnect scope is not owned by the authenticated controller".into(),
                    );
                }
            }
            if requested_ids.len() != request.scopes.len() {
                return Err("Duplicate disconnect scope".into());
            }
            let record = &mut registry.config.integrations[index];
            for (workspace_id, grant_epoch) in &request.scopes {
                record
                    .scopes
                    .retain(|scope| scope.workspace_id != *workspace_id);
                record
                    .tombstones
                    .retain(|scope| scope.workspace_id != *workspace_id);
                record.tombstones.push(ScopeTombstone {
                    workspace_id: workspace_id.clone(),
                    grant_epoch: *grant_epoch,
                    operation_id: request.operation_id.clone(),
                });
            }
            record.pending_disconnect = Some(DisconnectOperation {
                operation_id: request.operation_id.clone(),
                request_hash: request.request_hash.clone(),
                expected_revision: request.expected_revision,
                workspace_ids: requested_ids.into_iter().map(str::to_owned).collect(),
                status: "pending".into(),
            });
            record.future_boards = false;
            record.revision = record.revision.saturating_add(1);
            let next = registry.config.clone();
            persist_config(&registry.config_path, &next)?;
            registry.config = next;
            for (workspace_id, _) in &request.scopes {
                registry.scopes.remove(workspace_id);
            }
        }
        let cleanup = finish_disconnect_cleanup(&mut registry, index);
        let record = &registry.config.integrations[index];
        let operation = record
            .pending_disconnect
            .as_ref()
            .or_else(|| {
                record
                    .disconnect_history
                    .iter()
                    .find(|item| item.operation_id == request.operation_id)
            })
            .ok_or("Disconnect operation was not recorded")?;
        if cleanup.is_err() && operation.status != "pending" {
            return Err("Disconnect cleanup state is inconsistent".into());
        }
        Ok(disconnect_receipt_value(request, operation, record))
    }

    pub(crate) fn update_integration_settings(
        &self,
        request: &VerifiedIntegrationSettingsRequest,
    ) -> Result<Value, DisconnectError> {
        let mut registry = self
            .registry
            .lock()
            .map_err(|_| "Keeper registry lock poisoned")?;
        let index = registry
            .config
            .integrations
            .iter()
            .position(|record| record.integration_id == request.integration_id)
            .ok_or("Unknown integration")?;
        let current = registry.config.integrations[index].clone();
        if current.controller_person_id != request.controller_person_id
            || current.service_person_id != service_person_id(&registry.config)?
        {
            return Err(DisconnectError::Forbidden);
        }
        if let Some(completed) = current
            .settings_history
            .iter()
            .find(|operation| operation.operation_id == request.operation_id)
        {
            if completed.request_hash != request.request_hash {
                return Err(DisconnectError::Conflict);
            }
            if completed.status == "pending" {
                let _ = finish_settings_cleanup(&mut registry, index);
            }
            let record = &registry.config.integrations[index];
            let completed = record
                .settings_history
                .iter()
                .find(|operation| operation.operation_id == request.operation_id)
                .ok_or(DisconnectError::Unavailable)?;
            return Ok(integration_settings_receipt(request, completed, record));
        }
        if current
            .pending_disconnect
            .as_ref()
            .is_some_and(|operation| operation.status == "pending")
            || current
                .pending_settings
                .as_ref()
                .is_some_and(|operation| operation.status == "pending")
        {
            return Err("Integration has pending board cleanup".into());
        }
        if current.revision != request.expected_revision {
            return Err(DisconnectError::Conflict);
        }
        if request.future_boards && !current.future_boards {
            return Err("Future-board expansion requires a new dual-approved pairing".into());
        }
        for (workspace_id, epoch) in &request.scopes {
            let active = current
                .scopes
                .iter()
                .find(|scope| scope.workspace_id == *workspace_id && scope.state == "active")
                .ok_or("Settings scope is not active")?;
            if active.grant_epoch != *epoch {
                return Err(DisconnectError::Conflict);
            }
            let host = registry
                .scopes
                .get(workspace_id)
                .ok_or("Settings scope is not routable")?;
            if current_owner(host)? != request.controller_person_id {
                return Err(DisconnectError::Forbidden);
            }
        }
        let mut next = registry.config.clone();
        let record = &mut next.integrations[index];
        let scope_ids = request
            .scopes
            .iter()
            .map(|(id, _)| id.clone())
            .collect::<Vec<_>>();
        for (workspace_id, epoch) in &request.scopes {
            record
                .scopes
                .retain(|scope| scope.workspace_id != *workspace_id);
            record
                .tombstones
                .retain(|scope| scope.workspace_id != *workspace_id);
            record.tombstones.push(ScopeTombstone {
                workspace_id: workspace_id.clone(),
                grant_epoch: *epoch,
                operation_id: request.operation_id.clone(),
            });
            if current.future_boards && !record.baseline_workspace_ids.contains(workspace_id) {
                record.baseline_workspace_ids.push(workspace_id.clone());
            }
        }
        record.baseline_workspace_ids.sort();
        record.future_boards = request.future_boards;
        record.revision = record.revision.saturating_add(1);
        let settings_scopes = request.scopes.clone();
        let operation = IntegrationSettingsOperation {
            operation_id: request.operation_id.clone(),
            request_hash: request.request_hash.clone(),
            expected_revision: request.expected_revision,
            result_revision: record.revision,
            future_boards: request.future_boards,
            baseline_workspace_ids: record.baseline_workspace_ids.clone(),
            status: if scope_ids.is_empty() {
                "updated"
            } else {
                "pending"
            }
            .into(),
            scopes: settings_scopes,
        };
        record.settings_history.push(operation.clone());
        if !scope_ids.is_empty() {
            record.pending_settings = Some(DisconnectOperation {
                operation_id: request.operation_id.clone(),
                request_hash: request.request_hash.clone(),
                expected_revision: request.expected_revision,
                workspace_ids: scope_ids.clone(),
                status: "pending".into(),
            });
        } else {
            record.revision = record.revision.saturating_add(1);
            if let Some(history) = record.settings_history.last_mut() {
                history.result_revision = record.revision;
            }
        }
        persist_config(&registry.config_path, &next).map_err(|_| DisconnectError::Unavailable)?;
        registry.config = next;
        for workspace_id in &scope_ids {
            registry.scopes.remove(workspace_id);
        }
        if !scope_ids.is_empty() {
            let _ = finish_settings_cleanup(&mut registry, index);
        }
        let record = &registry.config.integrations[index];
        let operation = record
            .settings_history
            .iter()
            .find(|item| item.operation_id == request.operation_id)
            .ok_or(DisconnectError::Unavailable)?;
        Ok(integration_settings_receipt(request, operation, record))
    }

    pub(crate) fn activate_integration_future_policy(
        &self,
        integration_id: &str,
        expected_revision: u64,
        controller_person_id: &str,
        operation_id: &str,
        request_hash: &str,
        baseline_workspace_ids: &[String],
    ) -> Result<(), PolicyActivationFailure> {
        let mut registry = self
            .registry
            .lock()
            .map_err(|_| "Keeper registry lock poisoned")?;
        let index = registry
            .config
            .integrations
            .iter()
            .position(|record| record.integration_id == integration_id)
            .ok_or("Policy-only approval requires an existing integration")?;
        let current = registry.config.integrations[index].clone();
        if let Some(previous) = current
            .settings_history
            .iter()
            .find(|operation| operation.operation_id == operation_id)
        {
            if previous.request_hash != request_hash {
                return Err("Policy-only operation ID was reused".into());
            }
            return Ok(());
        }
        let service_id = service_person_id(&registry.config)?;
        if current.controller_person_id != controller_person_id
            || current.service_person_id != service_id
            || !current
                .pending_settings
                .as_ref()
                .is_none_or(|item| item.status != "pending")
            || !current
                .pending_disconnect
                .as_ref()
                .is_none_or(|item| item.status != "pending")
        {
            return Err("Policy-only approval does not match active integration".into());
        }
        if current.revision != expected_revision {
            return Err("Integration revision changed after dual approval".into());
        }
        let mut required_baseline = current
            .scopes
            .iter()
            .filter(|scope| scope.state == "active")
            .map(|scope| scope.workspace_id.clone())
            .collect::<Vec<_>>();
        required_baseline.extend(
            current
                .tombstones
                .iter()
                .map(|tombstone| tombstone.workspace_id.clone()),
        );
        required_baseline.sort();
        required_baseline.dedup();
        if current.future_boards
            || expected_revision == 0
            || baseline_workspace_ids.is_empty()
            || baseline_workspace_ids.len() > 512
            || baseline_workspace_ids
                .windows(2)
                .any(|pair| pair[0] >= pair[1])
            || required_baseline
                .iter()
                .any(|id| baseline_workspace_ids.binary_search(id).is_err())
        {
            return Err("Policy-only baseline omits a currently known board".into());
        }
        for workspace_id in current
            .scopes
            .iter()
            .filter(|scope| scope.state == "active")
            .map(|scope| &scope.workspace_id)
        {
            let host = registry
                .scopes
                .get(workspace_id)
                .ok_or("Active integration board is not routable")?;
            if current_owner(host)? != controller_person_id {
                return Err("Policy-only board ownership changed after approval".into());
            }
        }
        let mut next = registry.config.clone();
        let record = &mut next.integrations[index];
        record.future_boards = true;
        record.baseline_workspace_ids = baseline_workspace_ids.to_vec();
        record.revision = record.revision.saturating_add(1);
        record.settings_history.push(IntegrationSettingsOperation {
            operation_id: operation_id.to_owned(),
            request_hash: request_hash.to_owned(),
            expected_revision,
            result_revision: record.revision,
            future_boards: true,
            baseline_workspace_ids: baseline_workspace_ids.to_vec(),
            status: "updated".into(),
            scopes: Vec::new(),
        });
        persist_config(&registry.config_path, &next)
            .map_err(PolicyActivationFailure::OutcomeUnknown)?;
        registry.config = next;
        Ok(())
    }

    /// Make fully staged scopes visible in one durable config replacement.
    /// Caller sends the workspace-join ACK only after this returns success.
    pub(crate) fn activate_provisioned_scopes(
        &self,
        mut staged: Vec<Config>,
        mut commit: ProvisioningCommit,
    ) -> Result<(), String> {
        let mut registry = self
            .registry
            .lock()
            .map_err(|_| "Keeper registry lock poisoned")?;
        let mut next = registry.config.clone();
        if let Some(previous) = next
            .provisioning_commits
            .iter()
            .find(|previous| previous.pairing_id == commit.pairing_id)
        {
            let same_operation = previous.pairing_id == commit.pairing_id
                && previous.integration_id == commit.integration_id
                && previous.expected_integration_revision == commit.expected_integration_revision
                && previous.operation_id == commit.operation_id
                && previous.transcript_hash == commit.transcript_hash
                && previous.invitation_id == commit.invitation_id
                && previous.workspace_ids == commit.workspace_ids
                && previous.snapshot_hash == commit.snapshot_hash
                && previous.future_boards == commit.future_boards
                && previous.baseline_workspace_ids == commit.baseline_workspace_ids
                && (previous.controller_person_id.is_none()
                    || previous.controller_person_id == commit.controller_person_id);
            return if same_operation {
                Ok(())
            } else {
                Err("Provisioning operation conflicts with durable activation".into())
            };
        }
        if staged.is_empty() {
            return Err("Provisioning has no staged scopes".into());
        }
        let mut staged_hosts = Vec::with_capacity(staged.len());
        let mut staged_owner: Option<String> = None;
        for scope in &mut staged {
            if scope.device_id != next.device_id
                || scope.iroh_secret != next.iroh_secret
                || scope.device_seed != next.device_seed
                || scope.identity_seed != next.identity_seed
            {
                return Err("Staged scope does not use this keeper identity".into());
            }
            if registry.scopes.contains_key(&scope.workspace_id)
                || staged_hosts
                    .iter()
                    .any(|(workspace_id, _): &(String, MatchLighthouseHost)| {
                        workspace_id == &scope.workspace_id
                    })
            {
                return Err("Provisioned scope already exists".into());
            }
            let host = scope_host(scope)?;
            let owner = host.store.authority()?.expected_current_owner.person_id;
            if staged_owner
                .as_deref()
                .is_some_and(|staged_owner| staged_owner != owner)
            {
                return Err("Provisioning cannot mix owners in one activation".into());
            }
            staged_owner = Some(owner.clone());
            if scope
                .controller_person_id
                .as_deref()
                .is_some_and(|controller| controller != owner)
            {
                return Err("Staged scope controller is not its verified current owner".into());
            }
            // Persist original owner identity for policy lineage, even when future following is off.
            scope.controller_person_id = Some(owner);
            staged_hosts.push((scope.workspace_id.clone(), host));
        }
        if commit
            .controller_person_id
            .as_deref()
            .is_some_and(|controller| staged_owner.as_deref() != Some(controller))
        {
            return Err("Provisioning controller is not the verified staged owner".into());
        }
        commit.controller_person_id = staged_owner;
        let staged_ids = staged
            .iter()
            .map(|scope| scope.workspace_id.clone())
            .collect::<Vec<_>>();
        if commit.workspace_ids != staged_ids {
            return Err("Provisioning commit does not match staged scopes".into());
        }
        let config_directory = registry
            .config_path
            .parent()
            .ok_or("Invalid keeper registry path")?;
        let moved = relocate_provisioned_scope_dirs(config_directory, &mut staged, &commit)?;
        let relocated_hosts = staged
            .iter()
            .map(|scope| scope_host(scope).map(|host| (scope.workspace_id.clone(), host)))
            .collect::<Result<Vec<_>, _>>();
        staged_hosts = match relocated_hosts {
            Ok(hosts) => hosts,
            Err(error) => {
                rollback_provisioned_scope_dirs(&moved);
                return Err(error);
            }
        };
        for scope in &staged {
            if next.primary_detached && scope.workspace_id == next.workspace_id {
                let additional = std::mem::take(&mut next.additional_scopes);
                let commits = std::mem::take(&mut next.provisioning_commits);
                let integrations = std::mem::take(&mut next.integrations);
                next = scope.clone();
                next.additional_scopes = additional;
                next.provisioning_commits = commits;
                next.integrations = integrations;
            } else {
                next.additional_scopes.push(scope.clone());
            }
        }
        next.provisioning_commits.push(commit);
        if let Err(error) = record_activated_integration(&mut next, &staged) {
            rollback_provisioned_scope_dirs(&moved);
            return Err(error);
        }
        let bytes = match serde_json::to_vec(&next) {
            Ok(bytes) => bytes,
            Err(error) => {
                rollback_provisioned_scope_dirs(&moved);
                return Err(error.to_string());
            }
        };
        if let Err(error) =
            FileScopeStore::new(&registry.config_path).write_validated(&bytes, None, |_, _| Ok(()))
        {
            rollback_provisioned_scope_dirs(&moved);
            return Err(error);
        }
        for scope in &staged {
            let _ = fs::remove_file(
                scope
                    .state_path
                    .parent()
                    .unwrap_or(config_directory)
                    .join(".lighthouse-provisioning.json"),
            );
        }
        registry.config = next;
        registry.scopes.extend(staged_hosts);
        Ok(())
    }

    pub(crate) fn attach_owner_inventory(
        &self,
        workspace: &str,
        route: &str,
        secret: &str,
        frame: Vec<u8>,
    ) -> Result<Vec<u8>, String> {
        let registry = self
            .registry
            .lock()
            .map_err(|_| "Keeper registry lock poisoned")?;
        let scope = registry
            .scopes
            .get(workspace)
            .ok_or("Unknown keeper scope")?;
        let owner = current_owner(scope)?;
        let snapshot = scope.store.clone().snapshot()?;
        // Catalog entries were verified against signed authority by MatchScopeStore.
        let owner_route = snapshot
            .mesh
            .as_ref()
            .and_then(|mesh| mesh["peers"].as_array())
            .is_some_and(|peers| {
                peers.iter().any(|peer| {
                    peer.pointer("/advertisement/payload/personId")
                        .and_then(Value::as_str)
                        == Some(owner.as_str())
                        && peer
                            .pointer("/advertisement/payload/endpoint")
                            .and_then(Value::as_str)
                            == Some(route)
                })
            });
        if !owner_route {
            return Ok(frame);
        }
        let mut handshake = meta_mesh_core::decode_mesh_handshake(
            &frame,
            "mesh-handshake-request",
            secret,
            workspace,
        )?;
        handshake.owner_workspace_ids = Some(owner_workspace_ids(&registry, &owner)?);
        meta_mesh_core::encode_mesh_handshake(
            "mesh-handshake-request",
            secret,
            serde_json::to_value(handshake).map_err(|error| error.to_string())?,
        )
    }

    pub(crate) fn refresh_routes(&self, sequence: u64) -> Result<(), String> {
        let mut registry = self
            .registry
            .lock()
            .map_err(|_| "Keeper registry lock poisoned")?;
        let seed: [u8; 32] = registry
            .config
            .device_seed
            .as_slice()
            .try_into()
            .map_err(|_| "Invalid keeper device seed")?;
        for scope in registry.scopes.values_mut() {
            crate::refresh_route(&mut scope.local_handshake, &seed, sequence)?;
        }
        Ok(())
    }
}

fn record_activated_integration(next: &mut Config, staged: &[Config]) -> Result<(), String> {
    let Some(commit) = next.provisioning_commits.last() else {
        return Err("Missing durable integration activation record".into());
    };
    let service_id = service_person_id(next)?;
    let integration_id = if commit.integration_id.is_empty() {
        crate::integration_id(
            commit
                .controller_person_id
                .as_deref()
                .ok_or("Missing integration owner")?,
            &service_id,
        )
    } else {
        commit.integration_id.clone()
    };
    let controller = commit
        .controller_person_id
        .as_deref()
        .ok_or("Missing integration owner")?;
    let record_index = next
        .integrations
        .iter()
        .position(|record| record.integration_id == integration_id);
    let index = match record_index {
        Some(index) => {
            let record = &next.integrations[index];
            if record.controller_person_id != controller || record.service_person_id != service_id {
                return Err(
                    "Integration identity conflicts with its recorded owner or service".into(),
                );
            }
            if commit.expected_integration_revision != Some(record.revision) {
                return Err("Integration revision changed after dual approval".into());
            }
            if record.pending_disconnect.is_some() || record.pending_settings.is_some() {
                return Err("Integration has pending removal or settings cleanup".into());
            }
            index
        }
        None => {
            if commit.expected_integration_revision.is_some() {
                return Err("Expected integration no longer exists".into());
            }
            next.integrations.push(IntegrationRecord {
                integration_id: integration_id.clone(),
                controller_person_id: controller.to_owned(),
                service_person_id: service_id,
                revision: 0,
                future_boards: commit.future_boards,
                baseline_workspace_ids: commit.baseline_workspace_ids.clone(),
                scopes: Vec::new(),
                tombstones: Vec::new(),
                pending_disconnect: None,
                pending_settings: None,
                disconnect_history: Vec::new(),
                settings_history: Vec::new(),
            });
            next.integrations.len() - 1
        }
    };
    let record = &mut next.integrations[index];
    if record.pending_disconnect.is_some() || record.pending_settings.is_some() {
        return Err("Integration has a pending disconnect operation".into());
    }
    for scope in staged {
        let grant_epoch = scope_grant_epoch(scope)?;
        if let Some(tombstone_epoch) = record
            .tombstones
            .iter()
            .filter(|tombstone| tombstone.workspace_id == scope.workspace_id)
            .map(|tombstone| tombstone.grant_epoch)
            .max()
        {
            if grant_epoch <= tombstone_epoch {
                return Err("Re-added scope requires a newer signed owner grant".into());
            }
        }
        let active = IntegrationScope {
            workspace_id: scope.workspace_id.clone(),
            grant_epoch,
            state: "active".into(),
            activation_operation_id: commit.operation_id.clone(),
        };
        if let Some(existing) = record
            .scopes
            .iter_mut()
            .find(|existing| existing.workspace_id == scope.workspace_id)
        {
            if existing.state == "active" {
                return Err("Integration scope is already active".into());
            }
            *existing = active;
        } else {
            record.scopes.push(active);
        }
    }
    record
        .scopes
        .sort_by(|left, right| left.workspace_id.cmp(&right.workspace_id));
    record.future_boards = commit.future_boards && !commit.baseline_workspace_ids.is_empty();
    record.baseline_workspace_ids = commit.baseline_workspace_ids.clone();
    record.revision = record.revision.saturating_add(1);
    if record
        .pending_disconnect
        .as_ref()
        .is_some_and(|operation| operation.status == "removed")
    {
        record.pending_disconnect = None;
    }
    Ok(())
}

fn configured_scope<'a>(config: &'a Config, workspace_id: &str) -> Option<&'a Config> {
    std::iter::once(config)
        .chain(config.additional_scopes.iter())
        .find(|scope| scope.workspace_id == workspace_id)
}

fn scope_has_pending_removal(config: &Config, workspace_id: &str) -> bool {
    config.integrations.iter().any(|integration| {
        integration
            .pending_disconnect
            .as_ref()
            .is_some_and(|operation| {
                operation.status == "pending"
                    && operation.workspace_ids.iter().any(|id| id == workspace_id)
            })
    })
}

fn scope_has_superseding_tombstone(config: &Config, scope: &Config) -> bool {
    let Some(controller) = scope.controller_person_id.as_deref() else {
        return false;
    };
    let Ok(service_id) = service_person_id(config) else {
        return false;
    };
    let integration_id = crate::integration_id(controller, &service_id);
    let Some(integration) = config
        .integrations
        .iter()
        .find(|record| record.integration_id == integration_id)
    else {
        return false;
    };
    let tombstone_epoch = integration
        .tombstones
        .iter()
        .filter(|tombstone| tombstone.workspace_id == scope.workspace_id)
        .map(|tombstone| tombstone.grant_epoch)
        .max();
    let Some(tombstone_epoch) = tombstone_epoch else {
        return false;
    };
    scope_epoch_for_legacy_removal(scope) <= tombstone_epoch
        || !integration.scopes.iter().any(|active| {
            active.workspace_id == scope.workspace_id
                && active.state == "active"
                && active.grant_epoch > tombstone_epoch
        })
}

fn random_operation_id() -> String {
    format!("{:032x}", rand::random::<u128>())
}

fn disconnect_request_hash(
    integration_id: &str,
    operation_id: &str,
    expected_revision: u64,
    workspace_ids: &[String],
    grant_epochs: &[u64],
) -> String {
    let bytes = serde_json::to_vec(&json!({
        "integrationId": integration_id,
        "operationId": operation_id,
        "expectedRevision": expected_revision,
        "workspaceIds": workspace_ids,
        "grantEpochs": grant_epochs,
    }))
    .unwrap_or_default();
    URL_SAFE_NO_PAD.encode(Sha256::digest(bytes))
}

fn persist_config(path: &PathBuf, config: &Config) -> Result<(), String> {
    let bytes = serde_json::to_vec(config).map_err(|error| error.to_string())?;
    FileScopeStore::new(path).write_validated(&bytes, None, |_, _| Ok(()))
}

fn integration_status_value(record: &IntegrationRecord) -> Value {
    let mut scopes = record
        .scopes
        .iter()
        .map(|scope| {
            json!({
                "workspaceId":scope.workspace_id,
                "grantEpoch":scope.grant_epoch,
                "state":scope.state,
                "activationOperationId":scope.activation_operation_id,
            })
        })
        .collect::<Vec<_>>();
    let mut tombstones = record
        .tombstones
        .iter()
        .map(|tombstone| {
            let pending = record.pending_disconnect.as_ref().is_some_and(|operation| {
                operation.status == "pending" && operation.operation_id == tombstone.operation_id
            }) || record.pending_settings.as_ref().is_some_and(|operation| {
                operation.status == "pending" && operation.operation_id == tombstone.operation_id
            });
            json!({
                "workspaceId":tombstone.workspace_id,
                "grantEpoch":tombstone.grant_epoch,
                "state":if pending { "pending" } else { "removed" },
                "cleanup":if pending { "pending" } else { "complete" },
                "operationId":tombstone.operation_id,
            })
        })
        .collect::<Vec<_>>();
    scopes.sort_by(|left, right| {
        left["workspaceId"]
            .as_str()
            .cmp(&right["workspaceId"].as_str())
    });
    tombstones.sort_by(|left, right| {
        left["workspaceId"]
            .as_str()
            .cmp(&right["workspaceId"].as_str())
    });
    let pending_operation = record
        .pending_disconnect
        .as_ref()
        .or(record.pending_settings.as_ref())
        .filter(|operation| {
            operation.status == "pending" && !operation.operation_id.starts_with("local-")
        })
        .map(|operation| {
            let operation_scopes = record
                .tombstones
                .iter()
                .filter(|tombstone| tombstone.operation_id == operation.operation_id)
                .map(|tombstone| {
                    json!({
                        "workspaceId": tombstone.workspace_id,
                        "expectedGrantEpoch": tombstone.grant_epoch,
                    })
                })
                .collect::<Vec<_>>();
            json!({
                "operationId": operation.operation_id,
                "requestHash": operation.request_hash,
                "expectedRevision": operation.expected_revision,
                "scopes": operation_scopes,
                "status": operation.status,
            })
        });
    json!({
        "integrationId":record.integration_id,
        "controllerPersonId":record.controller_person_id,
        "servicePersonId":record.service_person_id,
        "revision":record.revision,
        "policy":{"futureBoards":record.future_boards && !record.baseline_workspace_ids.is_empty(),
            "baselineWorkspaceIds":record.baseline_workspace_ids},
        "scopes":scopes,
        "tombstones":tombstones,
        "pendingOperation":pending_operation,
    })
}

fn disconnect_receipt_value(
    request: &VerifiedDisconnectRequest,
    operation: &DisconnectOperation,
    record: &IntegrationRecord,
) -> Value {
    let removed = operation.status == "removed";
    let scopes = request
        .scopes
        .iter()
        .map(|(workspace_id, epoch)| {
            json!({
                "workspaceId":workspace_id,
                "grantEpoch":epoch,
                "state":if removed { "removed" } else { "pending" },
                "cleanup":if removed { "complete" } else { "pending" },
            })
        })
        .collect::<Vec<_>>();
    json!({
        "kind":"lighthouse-integration-disconnect-receipt",
        "version":1,
        "integrationId":request.integration_id,
        "operationId":request.operation_id,
        "requestHash":request.request_hash,
        "controllerPersonId":request.controller_person_id,
        "controllerDeviceId":request.controller_device_id,
        "revision":record.revision,
        "status":if removed { "removed" } else { "pending" },
        "scopes":scopes,
    })
}

fn integration_settings_receipt(
    request: &VerifiedIntegrationSettingsRequest,
    operation: &IntegrationSettingsOperation,
    record: &IntegrationRecord,
) -> Value {
    json!({
        "kind":"lighthouse-integration-settings-receipt", "version":1,
        "integrationId":record.integration_id,
        "operationId":operation.operation_id,
        "requestHash":operation.request_hash,
        "controllerPersonId":request.controller_person_id,
        "controllerDeviceId":request.controller_device_id,
        "revision":operation.result_revision,
        "status":operation.status,
        "policy":{"futureBoards":operation.future_boards,
            "baselineWorkspaceIds":operation.baseline_workspace_ids},
        "scopes":operation.scopes.iter().map(|(workspace_id, grant_epoch)| json!({
            "workspaceId":workspace_id, "grantEpoch":grant_epoch,
            "state":if operation.status == "pending" { "pending_cleanup" } else { "removed" },
            "cleanup":if operation.status == "pending" { "pending" } else { "complete" },
        })).collect::<Vec<_>>(),
    })
}

fn finish_disconnect_cleanup(
    registry: &mut Registry,
    integration_index: usize,
) -> Result<(), String> {
    let operation = registry.config.integrations[integration_index]
        .pending_disconnect
        .clone()
        .ok_or("No disconnect cleanup is pending")?;
    if operation.status == "removed" {
        return Ok(());
    }
    let config_directory = registry
        .config_path
        .parent()
        .ok_or("Invalid keeper registry path")?
        .to_path_buf();
    let scope_configs = operation
        .workspace_ids
        .iter()
        .map(|id| {
            configured_scope(&registry.config, id)
                .cloned()
                .ok_or_else(|| format!("Missing configured scope for pending removal: {id}"))
        })
        .collect::<Result<Vec<_>, _>>()?;
    for scope in &scope_configs {
        cleanup_scope_storage(
            &config_directory,
            scope,
            scope.workspace_id == registry.config.workspace_id,
        )?;
    }
    let mut next = registry.config.clone();
    for scope in &scope_configs {
        if scope.workspace_id == next.workspace_id {
            next.primary_detached = true;
            next.initial_state.document.clear();
            next.initial_state.authorization = Value::Null;
            next.initial_state.chat =
                json!({"version": 1, "messages": [], "profiles": [], "typing": []});
            next.initial_state.mesh = None;
            next.transport_secret.clear();
            next.controller_person_id = None;
            clear_primary_workspace_credential(&mut next);
        } else {
            next.additional_scopes
                .retain(|configured| configured.workspace_id != scope.workspace_id);
        }
    }
    let record = next
        .integrations
        .get_mut(integration_index)
        .ok_or("Missing integration lifecycle")?;
    let mut completed = record
        .pending_disconnect
        .take()
        .ok_or("No disconnect cleanup is pending")?;
    completed.status = "removed".into();
    record.disconnect_history.push(completed);
    record.future_boards = false;
    record.revision = record.revision.saturating_add(1);
    persist_config(&registry.config_path, &next)?;
    registry.config = next;
    Ok(())
}

fn finish_settings_cleanup(
    registry: &mut Registry,
    integration_index: usize,
) -> Result<(), String> {
    let operation = registry.config.integrations[integration_index]
        .pending_settings
        .clone()
        .ok_or("No integration settings cleanup is pending")?;
    let config_directory = registry
        .config_path
        .parent()
        .ok_or("Invalid keeper registry path")?
        .to_path_buf();
    let scope_configs = operation
        .workspace_ids
        .iter()
        .map(|id| {
            configured_scope(&registry.config, id)
                .cloned()
                .ok_or_else(|| format!("Missing configured scope for settings removal: {id}"))
        })
        .collect::<Result<Vec<_>, _>>()?;
    for scope in &scope_configs {
        cleanup_scope_storage(
            &config_directory,
            scope,
            scope.workspace_id == registry.config.workspace_id,
        )?;
    }
    let mut next = registry.config.clone();
    for scope in &scope_configs {
        if scope.workspace_id == next.workspace_id {
            next.primary_detached = true;
            next.initial_state.document.clear();
            next.initial_state.authorization = Value::Null;
            next.initial_state.chat = json!({"version":1,"messages":[],"profiles":[],"typing":[]});
            next.initial_state.mesh = None;
            next.transport_secret.clear();
            next.controller_person_id = None;
            clear_primary_workspace_credential(&mut next);
        } else {
            next.additional_scopes
                .retain(|configured| configured.workspace_id != scope.workspace_id);
        }
    }
    let record = next
        .integrations
        .get_mut(integration_index)
        .ok_or("Missing integration settings record")?;
    record.pending_settings = None;
    record.revision = record.revision.saturating_add(1);
    if let Some(history) = record
        .settings_history
        .iter_mut()
        .find(|item| item.operation_id == operation.operation_id)
    {
        history.status = "updated".into();
        history.result_revision = record.revision;
    }
    persist_config(&registry.config_path, &next)?;
    registry.config = next;
    Ok(())
}

fn cleanup_scope_storage(
    config_directory: &std::path::Path,
    scope: &Config,
    primary: bool,
) -> Result<(), String> {
    let state_path = &scope.state_path;
    if state_path.file_name().and_then(|name| name.to_str()) != Some("state.json") {
        return Err("Refusing to remove an unrecognized scope state path".into());
    }
    let parent = state_path.parent().ok_or("Invalid scope state path")?;
    let canonical_config = fs::canonicalize(config_directory).map_err(|error| error.to_string())?;
    if !primary {
        let parent_name = parent
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or("Invalid configured scope directory")?;
        let metadata = match fs::symlink_metadata(parent) {
            Ok(metadata) => Some(metadata),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
            Err(error) => return Err(error.to_string()),
        };
        if metadata
            .as_ref()
            .is_some_and(|metadata| !metadata.file_type().is_dir())
        {
            return Err("Configured scope directory is not a real directory".into());
        }
        let scopes_root = config_directory.join("scopes");
        let canonical_scopes_root = match fs::symlink_metadata(&scopes_root) {
            Ok(metadata) if metadata.file_type().is_dir() => {
                let root = fs::canonicalize(&scopes_root).map_err(|error| error.to_string())?;
                if root.parent() != Some(canonical_config.as_path()) {
                    return Err("Configured scopes directory escaped its storage root".into());
                }
                Some(root)
            }
            Ok(_) => return Err("Configured scopes path is not a real directory".into()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
            Err(error) => return Err(error.to_string()),
        };
        let legacy_scope_name = is_legacy_scope_directory(parent_name);
        let valid_location = if metadata.is_some() {
            let canonical_parent = fs::canonicalize(parent).map_err(|error| error.to_string())?;
            let managed_child = canonical_scopes_root.as_ref().is_some_and(|root| {
                canonical_parent != *root && canonical_parent.parent() == Some(root.as_path())
            });
            let legacy_child = legacy_scope_name
                && canonical_parent != canonical_config
                && canonical_parent.parent() == Some(canonical_config.as_path());
            managed_child || legacy_child
        } else {
            let ancestor = parent
                .parent()
                .ok_or("Invalid configured scope directory")?;
            let canonical_ancestor =
                fs::canonicalize(ancestor).map_err(|error| error.to_string())?;
            let managed_child = canonical_scopes_root
                .as_ref()
                .is_some_and(|root| canonical_ancestor == *root);
            let legacy_child = legacy_scope_name && canonical_ancestor == canonical_config;
            managed_child || legacy_child
        };
        if !valid_location {
            return Err("Refusing to remove scope data outside its configured storage root".into());
        }
        if metadata.is_some() {
            fs::remove_dir_all(parent).map_err(|error| error.to_string())?;
        }
    } else {
        let canonical_parent = fs::canonicalize(parent).map_err(|error| error.to_string())?;
        if canonical_parent != canonical_config {
            return Err(
                "Refusing to remove primary scope outside its configured storage root".into(),
            );
        }
        remove_file_if_present(state_path)?;
        let cache = state_path.with_file_name(format!(
            "{}.proof-staging",
            state_path
                .file_name()
                .and_then(|name| name.to_str())
                .unwrap_or("state.json")
        ));
        remove_dir_if_present(&cache)?;
    }
    let scopes_root = canonical_config.join("scopes");
    let sync_directory = if !primary && scopes_root.is_dir() {
        scopes_root
    } else {
        canonical_config
    };
    fs::File::open(sync_directory)
        .and_then(|directory| directory.sync_all())
        .map_err(|error| error.to_string())?;
    Ok(())
}

fn is_legacy_scope_directory(name: &str) -> bool {
    name.strip_prefix("scope-").is_some_and(|suffix| {
        suffix.len() == 32 && suffix.bytes().all(|byte| byte.is_ascii_hexdigit())
    })
}

fn ensure_scopes_storage_root(config_directory: &std::path::Path) -> Result<PathBuf, String> {
    let canonical_config = fs::canonicalize(config_directory).map_err(|error| error.to_string())?;
    let scopes_root = canonical_config.join("scopes");
    match fs::symlink_metadata(&scopes_root) {
        Ok(metadata) if metadata.file_type().is_dir() => {}
        Ok(_) => return Err("Configured scopes path is not a real directory".into()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            join::create_private_directory(&scopes_root).map_err(|error| error.to_string())?;
        }
        Err(error) => return Err(error.to_string()),
    }
    let canonical_root = fs::canonicalize(&scopes_root).map_err(|error| error.to_string())?;
    if canonical_root.parent() != Some(canonical_config.as_path()) {
        return Err("Configured scopes directory escaped its storage root".into());
    }
    Ok(canonical_root)
}

fn remove_file_if_present(path: &std::path::Path) -> Result<(), String> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.to_string()),
    }
}

fn remove_dir_if_present(path: &std::path::Path) -> Result<(), String> {
    match fs::remove_dir_all(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.to_string()),
    }
}

fn clear_primary_workspace_credential(config: &mut Config) {
    if let Some(peer) = config.local_handshake.peer.as_object_mut() {
        peer.remove("grant");
        peer.remove("ownerPublicKey");
        peer.remove("ownerCertificates");
    }
}

fn relocate_provisioned_scope_dirs(
    service_directory: &std::path::Path,
    staged: &mut [Config],
    commit: &ProvisioningCommit,
) -> Result<Vec<(PathBuf, PathBuf)>, String> {
    let scopes_root = service_directory.join("scopes");
    if !scopes_root.exists() {
        join::create_private_directory(&scopes_root).map_err(|error| error.to_string())?;
    }
    // Persist the scopes entry before the registry can durably reference it.
    // Repeat on retry: a prior attempt may have created it before sync failed.
    fs::File::open(service_directory)
        .and_then(|directory| directory.sync_all())
        .map_err(|error| error.to_string())?;
    let mut moved = Vec::new();
    for scope in staged {
        let staging = scope
            .state_path
            .parent()
            .ok_or("Invalid staged scope state path")?
            .to_path_buf();
        // Fresh grants receive separate storage, so detached snapshots cannot
        // block re-adding a board. Retries still select the same destination.
        let marker = ScopeActivationMarker::new(commit, &scope.workspace_id);
        let activation = serde_json::to_vec(&marker).map_err(|error| error.to_string())?;
        let key = URL_SAFE_NO_PAD.encode(Sha256::digest(&activation));
        let mut destination = scopes_root.join(key);
        // Recover an orphan created before activation-specific directories.
        let legacy_key = URL_SAFE_NO_PAD.encode(Sha256::digest(scope.workspace_id.as_bytes()));
        let legacy = scopes_root.join(legacy_key);
        if !destination.exists()
            && fs::read(legacy.join(".lighthouse-provisioning.json"))
                .ok()
                .and_then(|bytes| serde_json::from_slice::<ScopeActivationMarker>(&bytes).ok())
                .is_some_and(|existing| existing == marker)
        {
            destination = legacy;
        }
        if destination.exists() {
            let marker_path = destination.join(".lighthouse-provisioning.json");
            let marker_bytes = match fs::read(&marker_path) {
                Ok(bytes) => bytes,
                Err(_) => {
                    rollback_provisioned_scope_dirs(&moved);
                    return Err(
                        "Persistent scope directory already exists without registry entry".into(),
                    );
                }
            };
            let marker: ScopeActivationMarker = match serde_json::from_slice(&marker_bytes) {
                Ok(marker) => marker,
                Err(_) => {
                    rollback_provisioned_scope_dirs(&moved);
                    return Err("Invalid orphaned scope activation marker".into());
                }
            };
            if marker != ScopeActivationMarker::new(commit, &scope.workspace_id)
                || !destination.join("state.json").is_file()
            {
                rollback_provisioned_scope_dirs(&moved);
                return Err("Persistent scope directory belongs to another activation".into());
            }
            if let Err(error) = fs::remove_dir_all(&staging) {
                rollback_provisioned_scope_dirs(&moved);
                return Err(error.to_string());
            }
            scope.state_path = destination.join("state.json");
            continue;
        }
        let marker =
            match serde_json::to_vec(&ScopeActivationMarker::new(commit, &scope.workspace_id)) {
                Ok(marker) => marker,
                Err(error) => {
                    rollback_provisioned_scope_dirs(&moved);
                    return Err(error.to_string());
                }
            };
        if let Err(error) =
            write_scope_marker(&staging.join(".lighthouse-provisioning.json"), &marker)
        {
            rollback_provisioned_scope_dirs(&moved);
            return Err(error);
        }
        if let Err(error) = fs::rename(&staging, &destination) {
            rollback_provisioned_scope_dirs(&moved);
            return Err(error.to_string());
        }
        moved.push((staging, destination.clone()));
        scope.state_path = destination.join("state.json");
    }
    if let Err(error) = fs::File::open(&scopes_root).and_then(|directory| directory.sync_all()) {
        rollback_provisioned_scope_dirs(&moved);
        return Err(error.to_string());
    }
    Ok(moved)
}

#[derive(serde::Serialize, serde::Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
struct ScopeActivationMarker {
    pairing_id: String,
    integration_id: String,
    operation_id: String,
    transcript_hash: String,
    invitation_id: String,
    snapshot_hash: String,
    future_boards: bool,
    workspace_id: String,
}

impl ScopeActivationMarker {
    fn new(commit: &ProvisioningCommit, workspace_id: &str) -> Self {
        Self {
            pairing_id: commit.pairing_id.clone(),
            integration_id: commit.integration_id.clone(),
            operation_id: commit.operation_id.clone(),
            transcript_hash: commit.transcript_hash.clone(),
            invitation_id: commit.invitation_id.clone(),
            snapshot_hash: commit.snapshot_hash.clone(),
            future_boards: commit.future_boards,
            workspace_id: workspace_id.to_owned(),
        }
    }
}

fn write_scope_marker(path: &std::path::Path, bytes: &[u8]) -> Result<(), String> {
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path).map_err(|error| error.to_string())?;
    file.write_all(bytes).map_err(|error| error.to_string())?;
    file.sync_all().map_err(|error| error.to_string())
}

fn rollback_provisioned_scope_dirs(moved: &[(PathBuf, PathBuf)]) {
    for (staging, destination) in moved.iter().rev() {
        if std::fs::rename(destination, staging).is_err() {
            let _ = std::fs::remove_dir_all(destination);
        }
    }
}

impl NativeScopeServiceHost for KeeperHost {
    type ScopeHost = KeeperScope;
    fn local_device_id(&self) -> &str {
        &self.device_id
    }

    fn credential(&mut self, secret: &str) -> Result<Option<NativeScopeCredential>, String> {
        let registry = self
            .registry
            .lock()
            .map_err(|_| "Keeper registry lock poisoned")?;
        Ok(registry
            .scopes
            .values()
            .find(|scope| scope.secret == secret)
            .map(|scope| NativeScopeCredential {
                workspace_id: scope.workspace_id.clone(),
                secret: scope.secret.clone(),
            }))
    }

    fn prepare_handshake(
        &mut self,
        workspace_id: &str,
        request: &MeshHandshake,
    ) -> Result<(WorkspaceWriteAuthorizationSnapshot, Value), String> {
        if !request
            .capabilities
            .iter()
            .any(|capability| capability == "causal-write-admission-v1")
        {
            return Err(
                "Peer needs causal write admission support. Upgrade the peer and reconnect.".into(),
            );
        }
        let mut response = self.outgoing_handshake(workspace_id)?;
        let registry = self
            .registry
            .lock()
            .map_err(|_| "Keeper registry lock poisoned")?;
        // Native admission verifies this signed request before sending response.
        // Unauthenticated claims never receive the owner's scope inventory.
        if let Some(owner) = registry
            .scopes
            .get(workspace_id)
            .map(current_owner)
            .transpose()?
        {
            if request
                .peer
                .pointer("/advertisement/payload/personId")
                .and_then(Value::as_str)
                == Some(owner.as_str())
            {
                response["ownerWorkspaceIds"] = json!(owner_workspace_ids(&registry, &owner)?);
            }
        }
        drop(registry);
        Ok((self.authority(workspace_id)?, response))
    }

    fn authority(
        &mut self,
        workspace_id: &str,
    ) -> Result<WorkspaceWriteAuthorizationSnapshot, String> {
        self.registry
            .lock()
            .map_err(|_| "Keeper registry lock poisoned")?
            .scopes
            .get(workspace_id)
            .ok_or("Unknown keeper scope")?
            .store
            .authority()
    }

    fn outgoing_handshake(&mut self, workspace_id: &str) -> Result<Value, String> {
        let registry = self
            .registry
            .lock()
            .map_err(|_| "Keeper registry lock poisoned")?;
        let scope = registry
            .scopes
            .get(workspace_id)
            .ok_or("Unknown keeper scope")?;
        let mut handshake = scope.local_handshake.clone();
        handshake.owner_workspace_ids = None;
        if !handshake
            .capabilities
            .iter()
            .any(|capability| capability == "causal-write-admission-v1")
        {
            handshake
                .capabilities
                .push("causal-write-admission-v1".into());
        }
        serde_json::to_value(handshake).map_err(|error| error.to_string())
    }

    fn open_scope(&mut self, peer: &MeshPeerAdmission) -> Result<KeeperScope, String> {
        let registry = self
            .registry
            .lock()
            .map_err(|_| "Keeper registry lock poisoned")?;
        let store = registry
            .scopes
            .get(&peer.workspace_id)
            .ok_or("Unknown keeper scope")?
            .store
            .clone();
        Ok(KeeperScope {
            store,
            registry: Arc::clone(&self.registry),
            peer: peer.clone(),
        })
    }
}

pub(crate) struct KeeperScope {
    store: MatchScopeStore,
    registry: Arc<Mutex<Registry>>,
    peer: MeshPeerAdmission,
}

impl NativeScopeHost for KeeperScope {
    fn read_proof_page(&mut self, key: &str) -> Result<Option<Vec<u8>>, String> {
        self.store.read_proof_page(key)
    }
    fn write_proof_page(&mut self, key: &str, payload: &[u8]) -> Result<(), String> {
        self.store.write_proof_page(key, payload)
    }
    fn clear_proof_pages(&mut self) -> Result<(), String> {
        self.store.clear_proof_pages()
    }
    fn prepare_owner_offer(
        &mut self,
        bytes: &[u8],
    ) -> Result<Option<NativeOwnerOfferSnapshot>, String> {
        let value: Value =
            serde_json::from_slice(bytes).map_err(|_| "Invalid keeper owner offer")?;
        let mut registry = self
            .registry
            .lock()
            .map_err(|_| "Keeper registry lock poisoned")?;
        let workspace_id = value["workspaceId"]
            .as_str()
            .filter(|id| !id.is_empty())
            .ok_or("Missing keeper scope id")?;
        let controller = self.peer.person_id.as_str();
        if value["controllerPersonId"].as_str() != Some(controller) || value["version"] != 1 {
            return Err("Keeper owner offer does not match authenticated owner".into());
        }
        let service_id = service_person_id(&registry.config)?;
        if owner_baseline_contains(&registry, controller, &service_id, workspace_id) {
            return Err("Pre-existing board is outside future-board consent".into());
        }
        let known_owner = registry
            .scopes
            .get(workspace_id)
            .map(current_owner)
            .transpose()?;
        let authorized = if let Some(owner) = known_owner {
            owner == controller
        } else {
            owner_follows_future_boards(
                &registry,
                controller,
                &self.peer.workspace_id,
                workspace_id,
            )?
        };
        if !authorized {
            return Err("Keeper owner offer is not authorized by this owner's policy".into());
        }
        let envelope = &value["envelope"];
        let workspace = &value["workspace"];
        if envelope["workspaceId"] != workspace_id
            || workspace["id"] != workspace_id
            || envelope["ownerPersonId"] != controller
        {
            return Err("Keeper offer scope or owner mismatch".into());
        }
        if let Some(existing) = registry.scopes.get(workspace_id)
            && existing.secret != envelope["transportSecret"].as_str().unwrap_or("")
        {
            return Err("Keeper scope conflicts with existing trust".into());
        }
        let owner_public_key = envelope["ownerPublicKey"]
            .as_str()
            .ok_or("Missing owner public key")?;
        if public_key_id(owner_public_key)? != controller {
            return Err("Keeper offer owner key mismatch".into());
        }
        let owner_certificates: Vec<DeviceCertificate> =
            serde_json::from_value(envelope["ownerCertificates"].clone())
                .map_err(|_| "Invalid owner certificates")?;
        let owner = PublicIdentity {
            person_id: controller.to_owned(),
            public_key: owner_public_key.to_owned(),
            display_name: String::new(),
        };
        let issuer = envelope["peers"]
            .as_array()
            .ok_or("Missing owner peers")?
            .iter()
            .find(|peer| {
                peer.pointer("/advertisement/payload/deviceId")
                    .and_then(Value::as_str)
                    == Some(self.peer.device_id.as_str())
            })
            .ok_or("Keeper offer omits its authenticated owner device")?;
        let verified_issuer = verify_workspace_member_bundle(
            issuer.clone(),
            VerifyWorkspaceMemberOptions {
                workspace_id: Some(workspace_id.to_owned()),
                owner_person_id: Some(controller.to_owned()),
                owner_public_key: Some(owner_public_key.to_owned()),
                owner_certificates: owner_certificates.clone(),
                ..Default::default()
            },
            match_lighthouse::now_ms()?,
        )?;
        if verified_issuer.role != WorkspaceRole::Owner
            || verified_issuer.payload.person_id != controller
            || verified_issuer.payload.endpoint != self.peer.endpoint
        {
            return Err("Keeper offer issuer differs from authenticated owner".into());
        }
        let service_identity_seed: [u8; 32] = registry
            .config
            .identity_seed
            .as_slice()
            .try_into()
            .map_err(|_| "Invalid keeper identity seed")?;
        let service_person_id = public_key_id(&meta_mesh_core::public_key_from_seed(
            &service_identity_seed,
        )?)?;
        let grant: meta_mesh_core::WorkspaceGrant = serde_json::from_value(value["grant"].clone())
            .map_err(|_| "Missing signed keeper scope grant")?;
        if verify_workspace_grant(
            &grant,
            workspace_id,
            &service_person_id,
            &owner,
            &owner_certificates,
        )? != WorkspaceRole::Editor
        {
            return Err("Keeper offer grant does not authorize editor access".into());
        }
        let manifest = workspace
            .get("authorization")
            .cloned()
            .ok_or("Missing authorization manifest")?;
        if manifest["kind"] != "workspace-authorization-manifest"
            || manifest["version"] != 2
            || manifest["workspaceId"] != workspace_id
        {
            return Ok(None);
        }
        let candidate = URL_SAFE_NO_PAD
            .decode(
                workspace["bytes"]
                    .as_str()
                    .ok_or("Missing owner document")?,
            )
            .map_err(|_| "Invalid owner document encoding")?;
        let local = if let Some(scope) = registry.scopes.get_mut(workspace_id) {
            scope.store.snapshot()?.document
        } else {
            automerge::AutoCommit::new().save()
        };
        Ok(Some(NativeOwnerOfferSnapshot {
            workspace_id: workspace_id.to_owned(),
            candidate,
            local,
            manifest,
        }))
    }

    fn snapshot(&mut self) -> Result<NativeScopeSnapshot, String> {
        self.store.snapshot()
    }
    fn persist_document(
        &mut self,
        document: &[u8],
        proof: Option<&Value>,
        accepted_hashes: &[String],
    ) -> Result<(), String> {
        self.store
            .persist_document(document, proof, accepted_hashes)
    }
    fn merge_authorization(&mut self, value: &Value) -> Result<(), String> {
        self.store.merge_authorization(value)
    }
    fn merge_chat(&mut self, value: &Value) -> Result<(), String> {
        self.store.merge_chat(value)
    }
    fn merge_mesh(&mut self, value: &Value) -> Result<(), String> {
        self.store.merge_mesh(value)
    }
    fn merge_durable_batch(&mut self, bytes: &[u8]) -> Result<(), String> {
        self.store.merge_durable_batch(bytes)
    }
    fn receive_gossip(&mut self, bytes: &[u8]) -> Result<(), String> {
        self.store.receive_gossip(bytes)
    }

    fn merge_owner_offer(&mut self, bytes: &[u8]) -> Result<(), String> {
        let value: Value =
            serde_json::from_slice(bytes).map_err(|_| "Invalid keeper owner offer")?;
        let mut registry = self
            .registry
            .lock()
            .map_err(|_| "Keeper registry lock poisoned")?;
        let workspace_id = value["workspaceId"]
            .as_str()
            .filter(|id| !id.is_empty())
            .ok_or("Missing keeper scope id")?;
        let controller = self.peer.person_id.as_str();
        if value["controllerPersonId"].as_str() != Some(controller)
            || value["version"] != 1
            || self.store.authority()?.expected_current_owner.person_id != controller
        {
            return Err("Keeper offer is not from this scope's verified owner".into());
        }
        if registry
            .scopes
            .get(workspace_id)
            .map(current_owner)
            .transpose()?
            .is_some_and(|owner| owner != controller)
        {
            return Err("Keeper offer targets another owner's scope".into());
        }
        let is_new_scope = !registry.scopes.contains_key(workspace_id);
        if is_new_scope
            && !owner_follows_future_boards(
                &registry,
                controller,
                &self.peer.workspace_id,
                workspace_id,
            )?
        {
            return Err("Keeper owner offer is not authorized by this owner's policy".into());
        }
        let envelope = &value["envelope"];
        let workspace = &value["workspace"];
        if envelope["workspaceId"] != workspace_id
            || workspace["id"] != workspace_id
            || envelope["ownerPersonId"] != controller
        {
            return Err("Keeper offer scope or owner mismatch".into());
        }
        if let Some(existing) = registry.scopes.get(workspace_id)
            && existing.secret != envelope["transportSecret"].as_str().unwrap_or("")
        {
            return Err("Keeper scope conflicts with existing trust".into());
        }
        let issuer = envelope["peers"]
            .as_array()
            .ok_or("Missing owner peers")?
            .iter()
            .find(|peer| {
                peer.pointer("/advertisement/payload/deviceId")
                    .and_then(Value::as_str)
                    == Some(self.peer.device_id.as_str())
            })
            .ok_or("Keeper offer omits its authenticated owner device")?;
        let device_seed: [u8; 32] = registry
            .config
            .device_seed
            .as_slice()
            .try_into()
            .map_err(|_| "Invalid device seed")?;
        let identity_seed: [u8; 32] = registry
            .config
            .identity_seed
            .as_slice()
            .try_into()
            .map_err(|_| "Invalid identity seed")?;
        let iroh_secret: [u8; 32] = registry
            .config
            .iroh_secret
            .as_slice()
            .try_into()
            .map_err(|_| "Invalid endpoint seed")?;
        let certificate = registry.config.local_handshake.peer["certificates"]
            .as_array()
            .and_then(|certificates| certificates.first())
            .ok_or("Missing keeper certificate")?;
        let certificate = serde_json::from_value(certificate.clone())
            .map_err(|_| "Invalid keeper certificate")?;
        let public_key = meta_mesh_core::public_key_from_seed(&identity_seed)?;
        let person_id = meta_mesh_core::public_key_id(&public_key)?;
        let endpoint = registry
            .config
            .local_handshake
            .peer
            .pointer("/advertisement/payload/endpoint")
            .and_then(Value::as_str)
            .ok_or("Missing keeper endpoint")?;
        let bundle = join::guest_bundle(
            workspace_id,
            &person_id,
            &registry.config.device_id,
            &public_key,
            &certificate,
            &device_seed,
            endpoint,
        )
        .map_err(|error| error.to_string())?;
        let issuer_key = issuer["certificates"]
            .as_array()
            .and_then(|certificates| {
                certificates.iter().find(|certificate| {
                    certificate
                        .pointer("/payload/deviceId")
                        .and_then(Value::as_str)
                        == Some(self.peer.device_id.as_str())
                })
            })
            .and_then(|certificate| certificate.pointer("/payload/devicePublicKey"))
            .and_then(Value::as_str)
            .ok_or("Missing owner device public key")?;
        let invite = WorkspaceJoinInvitation {
            version: 1,
            kind: "workspace-join".into(),
            invitation_id: String::new(),
            issuer_person_id: controller.into(),
            issuer_device_id: self.peer.device_id.clone(),
            issuer_public_key: issuer_key.into(),
            issuer_endpoint: self.peer.endpoint.clone(),
            workspace_id: workspace_id.into(),
            workspace_title: String::new(),
            workspaces: vec![WorkspaceItem {
                id: workspace_id.into(),
                title: String::new(),
            }],
            role: String::new(),
            created_at: String::new(),
            expires_at: String::new(),
            secret: String::new(),
        };
        let response = serde_json::to_vec(&json!({ "grants": [value["grant"]], "meshWorkspaces": [envelope],
            "snapshot": URL_SAFE_NO_PAD.encode(serde_json::to_vec(&vec![workspace]).map_err(|error| error.to_string())?) }))
            .map_err(|error| error.to_string())?;
        let config_directory = registry
            .config_path
            .parent()
            .ok_or("Invalid keeper registry path")?;
        let directory = ensure_scopes_storage_root(config_directory)?
            .join(format!("scope-{:032x}", rand::random::<u128>()));
        join::create_private_directory(&directory).map_err(|error| error.to_string())?;
        let mut pending = PendingScopeDirectory(Some(directory.clone()));
        let mut scope = join::prepare_config(
            &invite,
            &response,
            &directory,
            &person_id,
            &registry.config.device_id,
            &bundle,
            identity_seed,
            &device_seed,
            iroh_secret,
        )
        .map_err(|error| error.to_string())?;
        scope.controller_person_id = Some(controller.to_owned());
        let offered_scope_epoch = scope_grant_epoch(&scope)?;
        let offered_scope_operation = format!("owner-offer:{}", scope_grant_id(&scope)?);
        if let Some(existing) = registry.scopes.get(workspace_id) {
            let mut store = existing.store.clone();
            let state = &scope.initial_state;
            let mut doc = automerge::AutoCommit::load(&store.snapshot()?.document)
                .map_err(|error| error.to_string())?;
            let heads = doc.get_heads();
            let mut incoming =
                automerge::AutoCommit::load(&state.document).map_err(|error| error.to_string())?;
            doc.merge(&mut incoming)
                .map_err(|error| error.to_string())?;
            let hashes = doc
                .get_changes(&heads)
                .iter()
                .map(|change| change.hash().to_string())
                .collect::<Vec<_>>();
            store.persist_document(&doc.save(), Some(&state.authorization), &hashes)?;
            store.merge_authorization(&state.authorization)?;
            store.merge_chat(&state.chat)?;
            if let Some(mesh) = &state.mesh {
                store.merge_mesh(mesh)?;
            }
            return Ok(());
        }
        let host = scope_host(&scope)?;
        let mut next = registry.config.clone();
        let integration_index = future_integration_index(
            &mut next,
            &registry,
            controller,
            &self.peer.workspace_id,
            workspace_id,
        )?;
        let integration = &mut next.integrations[integration_index];
        if integration
            .tombstones
            .iter()
            .filter(|tombstone| tombstone.workspace_id == workspace_id)
            .map(|tombstone| tombstone.grant_epoch)
            .max()
            .is_some_and(|epoch| offered_scope_epoch <= epoch)
        {
            return Err("Re-added future scope requires a newer signed owner grant".into());
        }
        if integration
            .scopes
            .iter()
            .any(|existing| existing.workspace_id == workspace_id && existing.state == "active")
        {
            return Err("Future scope is already active in its integration".into());
        }
        integration.scopes.push(IntegrationScope {
            workspace_id: workspace_id.to_owned(),
            grant_epoch: offered_scope_epoch,
            state: "active".into(),
            activation_operation_id: offered_scope_operation,
        });
        integration
            .scopes
            .sort_by(|left, right| left.workspace_id.cmp(&right.workspace_id));
        integration.revision = integration.revision.saturating_add(1);
        next.additional_scopes.push(scope);
        FileScopeStore::new(&registry.config_path).write_validated(
            &serde_json::to_vec(&next).map_err(|error| error.to_string())?,
            None,
            |_, _| Ok(()),
        )?;
        pending.0 = None;
        registry.config = next;
        registry.scopes.insert(workspace_id.into(), host);
        eprintln!("Lighthouse activated workspace {workspace_id}");
        Ok(())
    }
}

// Only directories created by this offer are removed on failed validation/commit.
struct PendingScopeDirectory(Option<PathBuf>);
impl Drop for PendingScopeDirectory {
    fn drop(&mut self) {
        if let Some(path) = &self.0 {
            let _ = std::fs::remove_dir_all(path);
        }
    }
}

#[cfg(test)]
#[path = "keeper_tests.rs"]
mod tests;
