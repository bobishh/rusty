use std::sync::Arc;

use meta_mesh_native::NativeNode;

use crate::{
    Config, ProvisioningCommit, join,
    keeper::{KeeperHost, ProvisioningLifecycleStatus},
    pairing::{
        IntegrationCandidate, PairingService, ProvisionedScope, VerifiedDisconnectRequest,
        VerifiedIntegrationSettingsRequest,
    },
};

#[derive(Clone)]
pub(crate) struct ProvisioningService {
    host: KeeperHost,
    node: Arc<NativeNode>,
}

impl ProvisioningService {
    pub(crate) fn new(host: KeeperHost, node: Arc<NativeNode>) -> Self {
        Self { host, node }
    }

    pub(crate) fn durable_commit(
        &self,
        pairing_id: &str,
    ) -> Result<Option<ProvisioningCommit>, String> {
        self.host.provisioning_commit(pairing_id)
    }

    pub(crate) fn durable_lifecycle_status(
        &self,
        pairing_id: &str,
    ) -> Result<Option<ProvisioningLifecycleStatus>, String> {
        self.host.provisioning_lifecycle_status(pairing_id)
    }

    pub(crate) fn integration_status(
        &self,
        candidates: &[IntegrationCandidate],
        controller_person_id: &str,
    ) -> Result<(u64, Vec<serde_json::Value>), String> {
        self.host
            .integration_status(candidates, controller_person_id)
    }

    pub(crate) fn disconnect_integration(
        &self,
        request: &VerifiedDisconnectRequest,
    ) -> Result<serde_json::Value, crate::keeper::DisconnectError> {
        self.host.disconnect_integration(request)
    }

    pub(crate) fn update_integration_settings(
        &self,
        request: &VerifiedIntegrationSettingsRequest,
    ) -> Result<serde_json::Value, crate::keeper::DisconnectError> {
        self.host.update_integration_settings(request)
    }

    pub(crate) fn activate_integration_future_policy(
        &self,
        integration_id: &str,
        expected_revision: u64,
        controller_person_id: &str,
        operation_id: &str,
        request_hash: &str,
        baseline_workspace_ids: &[String],
    ) -> Result<(), crate::pairing::PolicyActivationFailure> {
        self.host.activate_integration_future_policy(
            integration_id,
            expected_revision,
            controller_person_id,
            operation_id,
            request_hash,
            baseline_workspace_ids,
        )
    }

    pub(crate) async fn provision(
        &self,
        integration_id: &str,
        pairing_id: &str,
        operation_id: &str,
        transcript_hash: &str,
        invitation: meta_mesh_core::WorkspaceJoinInvitation,
        workspace_ids: Vec<String>,
        future_boards: bool,
        baseline_workspace_ids: Vec<String>,
        expected_integration_revision: Option<u64>,
        pairings: PairingService,
    ) -> Result<Vec<ProvisionedScope>, String> {
        let invitation_id = invitation.invitation_id.clone();
        let controller_person_id = invitation.issuer_person_id.clone();
        let expected_commit = ProvisioningCommit {
            pairing_id: pairing_id.into(),
            integration_id: integration_id.into(),
            expected_integration_revision,
            operation_id: operation_id.into(),
            transcript_hash: transcript_hash.into(),
            invitation_id: invitation_id.clone(),
            workspace_ids: workspace_ids.clone(),
            snapshot_hash: String::new(),
            future_boards,
            baseline_workspace_ids: baseline_workspace_ids.clone(),
            controller_person_id: Some(controller_person_id.clone()),
        };
        if let Some(previous) = self.host.provisioning_commit(pairing_id)? {
            if previous.pairing_id != expected_commit.pairing_id
                || previous.integration_id != expected_commit.integration_id
                || previous.expected_integration_revision
                    != expected_commit.expected_integration_revision
                || previous.operation_id != expected_commit.operation_id
                || previous.transcript_hash != expected_commit.transcript_hash
                || previous.invitation_id != expected_commit.invitation_id
                || previous.workspace_ids != expected_commit.workspace_ids
                || previous.future_boards != expected_commit.future_boards
                || previous.baseline_workspace_ids != expected_commit.baseline_workspace_ids
                || previous
                    .controller_person_id
                    .as_deref()
                    .is_some_and(|owner| owner != controller_person_id)
                || previous.snapshot_hash.is_empty()
            {
                return Err("Provisioning retry conflicts with durable activation".into());
            }
        }

        let config: Config = self.host.configuration()?;
        let service_directory = config
            .state_path
            .parent()
            .ok_or("Invalid Lighthouse state directory")?
            .to_path_buf();
        let host = self.host.clone();
        let result = join::provision_existing_identity(
            invitation,
            &workspace_ids,
            integration_id,
            pairing_id,
            operation_id,
            transcript_hash,
            future_boards,
            &baseline_workspace_ids,
            expected_integration_revision,
            &config,
            &self.node,
            &service_directory,
            {
                let pairings = pairings.clone();
                move |workspace_id, grant_epoch| {
                    pairings.record_issued_grant_epoch(pairing_id, workspace_id, grant_epoch)
                }
            },
            move |staged, mut commit| {
                if commit
                    .controller_person_id
                    .as_deref()
                    .is_some_and(|owner| owner != controller_person_id)
                {
                    return Err("Provisioning controller differs from accepted invitation".into());
                }
                commit.controller_person_id = Some(controller_person_id);
                pairings.commit_activation_if_not_withdrawn(pairing_id, || {
                    host.activate_provisioned_scopes(staged, commit)
                })
            },
        )
        .await
        .map_err(|error| error.to_string())?;
        Ok(active_scopes(result))
    }
}

fn active_scopes(workspace_ids: Vec<String>) -> Vec<ProvisionedScope> {
    workspace_ids
        .into_iter()
        .map(|workspace_id| ProvisionedScope {
            workspace_id,
            status: "active".into(),
            grant_epoch: None,
            error: None,
            error_detail: None,
        })
        .collect()
}
