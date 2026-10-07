//! Reset runs before the native runtime opens stores, after HTTP drained and
//! Docker restarted the process. No old worker can write into fresh storage.
use crate::Config;
use meta_mesh_native::FileScopeStore;
use serde::{Deserialize, Serialize};
use std::{fs, path::Path};

#[derive(Serialize, Deserialize)]
struct Request {
    backup: String,
}

pub(crate) fn request(config_path: &Path) -> Result<(), String> {
    let directory = config_path.parent().ok_or("Invalid keeper config path")?;
    let marker = directory.join("reset-request.json");
    if marker.exists() {
        return Ok(());
    }
    let nonce: u64 = rand::random();
    let request = Request {
        backup: format!("reset-backups/{nonce:016x}"),
    };
    FileScopeStore::new(marker).write_validated(
        &serde_json::to_vec(&request).map_err(|e| e.to_string())?,
        None,
        |_, _| Ok(()),
    )
}

pub(crate) fn apply_pending(config_path: &Path) -> Result<(), String> {
    let directory = config_path.parent().ok_or("Invalid keeper config path")?;
    let marker = directory.join("reset-request.json");
    if !marker.exists() {
        return Ok(());
    }
    let request: Request = serde_json::from_slice(&fs::read(&marker).map_err(|e| e.to_string())?)
        .map_err(|e| e.to_string())?;
    let suffix = request
        .backup
        .strip_prefix("reset-backups/")
        .ok_or("Invalid reset backup path")?;
    if suffix.len() != 16 || !suffix.bytes().all(|c| c.is_ascii_hexdigit()) {
        return Err("Invalid reset backup path".into());
    }
    let backup = directory.join(&request.backup);
    fs::create_dir_all(backup.join("data")).map_err(|e| e.to_string())?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(
            directory.join("reset-backups"),
            fs::Permissions::from_mode(0o700),
        )
        .map_err(|e| e.to_string())?;
    }
    let original = backup.join("config.json");
    if !original.exists() {
        FileScopeStore::new(&original).write_validated(
            &fs::read(config_path).map_err(|e| e.to_string())?,
            None,
            |_, _| Ok(()),
        )?;
    }
    let mut config: Config =
        serde_json::from_slice(&fs::read(original).map_err(|e| e.to_string())?)
            .map_err(|e| e.to_string())?;
    config.primary_detached = true;
    config.additional_scopes.clear();
    config.provisioning_commits.clear();
    config.integrations.clear();
    config.controller_person_id = None;
    config.transport_secret.clear();
    config.initial_state.document.clear();
    config.initial_state.authorization = serde_json::Value::Null;
    config.initial_state.chat =
        serde_json::json!({"version":1,"messages":[],"profiles":[],"typing":[]});
    config.initial_state.mesh = None;
    FileScopeStore::new(config_path).write_validated(
        &serde_json::to_vec(&config).map_err(|e| e.to_string())?,
        None,
        |_, _| Ok(()),
    )?;
    for entry in fs::read_dir(directory).map_err(|e| e.to_string())? {
        let entry = entry.map_err(|e| e.to_string())?;
        let name = entry.file_name();
        if [
            config_path.file_name().unwrap(),
            "route-sequence".as_ref(),
            "cors-origins.json".as_ref(),
            "reset-backups".as_ref(),
            "reset-request.json".as_ref(),
        ]
        .contains(&name.as_os_str())
        {
            continue;
        }
        fs::rename(entry.path(), backup.join("data").join(name)).map_err(|e| e.to_string())?;
    }
    fs::File::open(&backup)
        .and_then(|dir| dir.sync_all())
        .map_err(|e| e.to_string())?;
    fs::File::open(directory)
        .and_then(|dir| dir.sync_all())
        .map_err(|e| e.to_string())?;
    fs::remove_file(marker).map_err(|e| e.to_string())?;
    fs::File::open(directory)
        .and_then(|dir| dir.sync_all())
        .map_err(|e| e.to_string())?;
    eprintln!(
        "Keeper reset completed; private recovery snapshot: {}",
        backup.display()
    );
    Ok(())
}
