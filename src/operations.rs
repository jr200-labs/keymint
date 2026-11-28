use anyhow::{Context, Result, ensure};
use base64::{Engine, engine::general_purpose::STANDARD};
use chrono::{DateTime, Utc};
use rusqlite::{Connection, OpenFlags};
use serde::Serialize;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{fs, io::Write, path::Path, time::Duration};

#[derive(Serialize)]
struct CleanupStatus {
    pending: Vec<String>,
    quarantined: Vec<QuarantinedCleanup>,
}

#[derive(Serialize)]
struct QuarantinedCleanup {
    session_id: String,
    quarantined_at: DateTime<Utc>,
}

fn open_state(path: &Path, mode: OpenFlags) -> Result<Connection> {
    ensure!(
        !path.as_os_str().is_empty(),
        "an existing emergency state file is required"
    );
    let connection = Connection::open_with_flags(path, mode).context("open emergency state")?;
    connection.busy_timeout(Duration::from_secs(5))?;
    Ok(connection)
}

pub fn cleanup_status(path: &Path) -> Result<String> {
    let mut connection = open_state(path, OpenFlags::SQLITE_OPEN_READ_ONLY)?;
    let transaction = connection.transaction()?;
    let pending = transaction
        .prepare("SELECT session_id FROM emergency_cleanup ORDER BY session_id")?
        .query_map([], |row| row.get(0))?
        .collect::<rusqlite::Result<_>>()?;
    let has_quarantine = transaction.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE type='table' AND name='emergency_cleanup_quarantine')",
        [],
        |row| row.get::<_, bool>(0),
    )?;
    let mut quarantined = Vec::new();
    if has_quarantine {
        let mut statement = transaction.prepare(
            "SELECT session_id, quarantined_at FROM emergency_cleanup_quarantine ORDER BY id",
        )?;
        let mut rows = statement.query([])?;
        while let Some(row) = rows.next()? {
            quarantined.push(QuarantinedCleanup {
                session_id: row.get(0)?,
                quarantined_at: DateTime::from_timestamp(row.get(1)?, 0)
                    .context("invalid quarantine timestamp")?,
            });
        }
    }
    Ok(serde_json::to_string(&CleanupStatus {
        pending,
        quarantined,
    })?)
}

pub fn quarantine_cleanup(path: &Path, session_id: Option<&str>) -> Result<usize> {
    let mut connection = open_state(path, OpenFlags::SQLITE_OPEN_READ_WRITE)?;
    let transaction =
        connection.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
    transaction.execute_batch("CREATE TABLE IF NOT EXISTS emergency_cleanup_quarantine (
        id INTEGER PRIMARY KEY, session_id TEXT NOT NULL, sealed BLOB NOT NULL, quarantined_at INTEGER NOT NULL
    )")?;
    let count = transaction.execute(
        "INSERT INTO emergency_cleanup_quarantine(session_id, sealed, quarantined_at)
         SELECT session_id, sealed, unixepoch() FROM emergency_cleanup
         WHERE ?1 IS NULL OR session_id = ?1",
        [session_id],
    )?;
    if let Some(id) = session_id {
        ensure!(count > 0, "no pending cleanup record for session {id:?}");
    }
    transaction.execute(
        "DELETE FROM emergency_cleanup WHERE ?1 IS NULL OR session_id = ?1",
        [session_id],
    )?;
    transaction.commit()?;
    Ok(count)
}

pub fn read_passkeys(path: &Path) -> Result<Value> {
    ensure!(
        !path.as_os_str().is_empty(),
        "a passkey state file is required"
    );
    let data = fs::read(path).context("read passkey state")?;
    let user: Value = serde_json::from_slice(&data).context("decode passkey state")?;
    ensure!(
        user["id"]
            .as_str()
            .and_then(|id| STANDARD.decode(id).ok())
            .is_some_and(|id| !id.is_empty())
            && ["name", "display_name"]
                .iter()
                .all(|key| user[key].as_str().is_some_and(|name| !name.is_empty())),
        "passkey state is incomplete"
    );
    Ok(user)
}

pub fn credential_id(credential: &Value) -> Result<String> {
    let id = credential["id"]
        .as_str()
        .context("missing passkey credential ID")?;
    let bytes = STANDARD
        .decode(id)
        .context("decode passkey credential ID")?;
    Ok(format!("{:x}", Sha256::digest(bytes)))
}

#[derive(Serialize)]
struct PasskeyInfo<'a> {
    id: String,
    #[serde(skip_serializing_if = "str::is_empty")]
    label: &'a str,
    clone_warning: bool,
}

pub fn list_passkeys(path: &Path) -> Result<String> {
    let user = read_passkeys(path)?;
    let mut items = Vec::new();
    for credential in user["credentials"].as_array().into_iter().flatten() {
        let id = credential_id(credential)?;
        items.push(PasskeyInfo {
            label: user["credential_labels"][&id].as_str().unwrap_or_default(),
            clone_warning: credential["authenticator"]["cloneWarning"]
                .as_bool()
                .unwrap_or(false),
            id,
        });
    }
    Ok(serde_json::to_string(&items)?)
}

pub fn revoke_passkey(path: &Path, id: &str) -> Result<()> {
    let mut state = read_passkeys(path)?;
    let credentials = state["credentials"]
        .as_array_mut()
        .context("passkey credential was not found")?;
    let mut matching = None;
    for (index, credential) in credentials.iter().enumerate() {
        if credential_id(credential)? == id {
            matching = Some(index);
            break;
        }
    }
    credentials.remove(matching.context("passkey credential was not found")?);
    if let Some(labels) = state["credential_labels"].as_object_mut() {
        labels.remove(id);
    }
    write_passkeys(path, &state)
}

pub fn write_passkeys(path: &Path, state: &Value) -> Result<()> {
    let parent = path
        .parent()
        .filter(|dir| !dir.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let mut temporary = tempfile::Builder::new()
        .prefix(".passkeys-")
        .tempfile_in(parent)?;
    serde_json::to_writer(&mut temporary, state)?;
    temporary.flush()?;
    temporary.as_file().sync_all()?;
    temporary.persist(path).context("replace passkey state")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn quarantines_selected_record_and_preserves_ciphertext() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("emergency.db");
        let connection = Connection::open(&path)?;
        connection.execute_batch(
            "CREATE TABLE emergency_cleanup (session_id TEXT PRIMARY KEY, sealed BLOB NOT NULL);
            INSERT INTO emergency_cleanup VALUES ('first', X'010203'), ('second', X'040506');",
        )?;
        assert_eq!(quarantine_cleanup(&path, Some("first"))?, 1);
        assert!(quarantine_cleanup(&path, Some("first")).is_err());
        let status: Value = serde_json::from_str(&cleanup_status(&path)?)?;
        assert_eq!(status["pending"], json!(["second"]));
        assert_eq!(status["quarantined"][0]["session_id"], "first");
        let sealed: Vec<u8> = connection.query_row(
            "SELECT sealed FROM emergency_cleanup_quarantine WHERE session_id='first'",
            [],
            |row| row.get(0),
        )?;
        assert_eq!(sealed, [1, 2, 3]);
        Ok(())
    }

    #[test]
    fn preserves_other_credentials_when_revoking_a_passkey() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("passkeys.json");
        let first = json!({"id":"YQ==", "authenticator":{"cloneWarning":true,"signCount":11}});
        let second = json!({"id":"Yg==", "authenticator":{"signCount":21}, "publicKey":"Yw=="});
        let id = credential_id(&first)?;
        let mut fixture = json!({
            "id": "ZA==",
            "name": "operator",
            "display_name": "Emergency operator",
            "credentials": [first,second],
            "credential_labels": {},
        });
        fixture["credential_labels"][&id] = json!("operator");
        fs::write(&path, serde_json::to_vec(&fixture)?)?;
        let items: Value = serde_json::from_str(&list_passkeys(&path)?)?;
        assert_eq!(
            items[0],
            json!({"id": id, "label":"operator", "clone_warning":true})
        );
        revoke_passkey(&path, &id)?;
        let state = read_passkeys(&path)?;
        assert_eq!(state["credentials"], json!([second]));
        assert_eq!(state["credential_labels"], json!({}));
        Ok(())
    }
}
