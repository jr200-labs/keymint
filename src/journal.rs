use anyhow::{Context, Result, ensure};
use chrono::{DateTime, Utc};
use ring::rand::{SecureRandom, SystemRandom};
use rusqlite::{Connection, OptionalExtension, params};
use serde::Serialize;
use std::{
    fs,
    path::Path,
    sync::{Arc, Mutex},
    time::Duration,
};

const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS emergency_session_state (
    session_id TEXT PRIMARY KEY, subject TEXT NOT NULL, profile TEXT NOT NULL,
    provider TEXT NOT NULL, state TEXT NOT NULL, expires_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS emergency_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT, subject TEXT NOT NULL, type TEXT NOT NULL,
    session_id TEXT NOT NULL, profile TEXT NOT NULL, provider TEXT NOT NULL,
    state TEXT NOT NULL, expires_at INTEGER NOT NULL, occurred_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS emergency_approvals (
    session_id TEXT PRIMARY KEY, digest TEXT NOT NULL, redeemed INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS emergency_totp (
    identity TEXT PRIMARY KEY, started INTEGER NOT NULL, attempts INTEGER NOT NULL, last_step INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS emergency_totp_failures (
    identity TEXT PRIMARY KEY, started INTEGER NOT NULL, failures INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS emergency_metadata (key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS emergency_cleanup (session_id TEXT PRIMARY KEY, sealed BLOB NOT NULL);
CREATE INDEX IF NOT EXISTS emergency_events_subject_id ON emergency_events(subject, id);
CREATE INDEX IF NOT EXISTS emergency_events_session_time ON emergency_events(session_id, occurred_at);
";

#[derive(Clone)]
pub struct Journal {
    db: Arc<Mutex<Connection>>,
    stream: String,
    updates: tokio::sync::watch::Sender<()>,
}

#[derive(Serialize)]
struct Event {
    id: i64,
    #[serde(rename = "type")]
    kind: String,
    session_id: String,
    profile: String,
    provider: String,
    state: String,
    expires_at: DateTime<Utc>,
    occurred_at: DateTime<Utc>,
}

#[derive(Serialize)]
pub struct Page {
    events: Vec<Event>,
    next_cursor: String,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    history_truncated: bool,
}

pub struct SessionEvent<'a> {
    pub subject: &'a str,
    pub kind: &'a str,
    pub id: &'a str,
    pub profile: &'a str,
    pub provider: &'a str,
    pub state: &'a str,
    pub expires: i64,
    pub approval_digest: Option<&'a str>,
}

impl Journal {
    pub fn open(path: &Path) -> Result<Self> {
        let mut db = if path.as_os_str().is_empty() {
            Connection::open_in_memory()?
        } else {
            if let Some(parent) = path
                .parent()
                .filter(|parent| !parent.as_os_str().is_empty())
            {
                #[cfg(unix)]
                {
                    use std::os::unix::fs::DirBuilderExt;
                    fs::DirBuilder::new()
                        .recursive(true)
                        .mode(0o700)
                        .create(parent)?;
                }
                #[cfg(not(unix))]
                fs::create_dir_all(parent)?;
            }
            Connection::open(path)?
        };
        db.busy_timeout(Duration::from_secs(5))?;
        if !path.as_os_str().is_empty() {
            db.pragma_update(None, "journal_mode", "WAL")?;
        }
        db.execute_batch(SCHEMA)?;
        let transaction = db.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        let stream = match transaction
            .query_row(
                "SELECT value FROM emergency_metadata WHERE key = 'stream_id'",
                [],
                |row| row.get::<_, String>(0),
            )
            .optional()?
        {
            Some(stream) => stream,
            None => {
                let mut id = [0u8; 16];
                SystemRandom::new()
                    .fill(&mut id)
                    .map_err(|_| anyhow::anyhow!("generate event stream ID"))?;
                let stream: String = id.iter().map(|byte| format!("{byte:02x}")).collect();
                transaction.execute(
                    "INSERT INTO emergency_metadata(key, value) VALUES ('stream_id', ?)",
                    [&stream],
                )?;
                stream
            }
        };
        transaction.execute(
            "INSERT INTO emergency_events(subject,type,session_id,profile,provider,state,expires_at,occurred_at)
             SELECT subject,'session.invalidated',session_id,profile,provider,'invalidated',expires_at,?1
             FROM emergency_session_state WHERE state NOT IN ('expired', 'revoked', 'invalidated')",
            [Utc::now().timestamp_millis()],
        )?;
        transaction.execute(
            "UPDATE emergency_session_state SET state = 'invalidated'
             WHERE state NOT IN ('expired', 'revoked', 'invalidated')",
            [],
        )?;
        transaction.commit()?;
        Ok(Self {
            db: Arc::new(Mutex::new(db)),
            stream,
            updates: tokio::sync::watch::channel(()).0,
        })
    }

    pub fn write<T>(
        &self,
        operation: impl FnOnce(&rusqlite::Transaction<'_>) -> Result<T>,
    ) -> Result<T> {
        let mut db = self
            .db
            .lock()
            .map_err(|_| anyhow::anyhow!("lock emergency journal"))?;
        let tx = db.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        let value = operation(&tx)?;
        tx.commit()?;
        Ok(value)
    }

    pub fn record(&self, event: SessionEvent<'_>) -> Result<()> {
        self.write(|tx| {
            tx.execute("INSERT INTO emergency_events(subject,type,session_id,profile,provider,state,expires_at,occurred_at)
                VALUES (?1,?2,?3,?4,?5,?6,?7,?8)",
                params![event.subject, event.kind, event.id, event.profile, event.provider, event.state, event.expires, Utc::now().timestamp_millis()])?;
            tx.execute("INSERT INTO emergency_session_state(session_id,subject,profile,provider,state,expires_at)
                VALUES (?1,?2,?3,?4,?5,?6)
                ON CONFLICT(session_id) DO UPDATE SET state=excluded.state,expires_at=excluded.expires_at",
                params![event.id, event.subject, event.profile, event.provider, event.state, event.expires])?;
            if let Some(digest) = event.approval_digest {
                if event.kind == "session.created" {
                    tx.execute("INSERT INTO emergency_approvals(session_id,digest) VALUES (?1,?2)", params![event.id,digest])?;
                }
                if event.kind == "approval.redeemed" {
                    let changed = tx.execute(
                        "UPDATE emergency_approvals SET redeemed=1 WHERE session_id=?1 AND digest=?2 AND redeemed=0",
                        params![event.id,digest],
                    )?;
                    ensure!(changed == 1, "approval redemption was not recorded");
                }
            }
            Ok(())
        })?;
        self.updates.send_replace(());
        Ok(())
    }

    pub async fn watch(&self, subject: String, after: String, wait: Duration) -> Result<Page> {
        let mut updates = self.updates.subscribe();
        let journal = self.clone();
        let (journal, subject, after, page) = tokio::task::spawn_blocking(move || {
            let after = journal.parse_cursor(&after);
            let page = journal.list(&subject, after)?;
            Ok::<_, anyhow::Error>((journal, subject, after, page))
        })
        .await??;
        if !page.events.is_empty() || page.history_truncated || wait.is_zero() {
            return Ok(page);
        }
        let _ = tokio::time::timeout(wait.min(Duration::from_secs(30)), updates.changed()).await;
        tokio::task::spawn_blocking(move || journal.list(&subject, after)).await?
    }

    fn parse_cursor(&self, cursor: &str) -> i64 {
        cursor
            .split_once(':')
            .filter(|(stream, _)| *stream == self.stream)
            .and_then(|(_, cursor)| cursor.parse::<i64>().ok())
            .unwrap_or(0)
            .max(0)
    }

    fn list(&self, subject: &str, after: i64) -> Result<Page> {
        let mut db = self
            .db
            .lock()
            .map_err(|_| anyhow::anyhow!("lock emergency journal"))?;
        let transaction = db.transaction()?;
        let floor: i64 = transaction.query_row(
            "SELECT COALESCE((SELECT CAST(value AS INTEGER) FROM emergency_metadata WHERE key='pruned_through'), 0)",
            [], |row| row.get(0),
        )?;
        let mut statement = transaction.prepare(
            "SELECT id,type,session_id,profile,provider,state,expires_at,occurred_at
             FROM emergency_events WHERE subject = ?1 AND id > ?2 ORDER BY id LIMIT 100",
        )?;
        let mut rows = statement.query(params![subject, after])?;
        let mut events = Vec::new();
        while let Some(row) = rows.next()? {
            let timestamp = |index| -> Result<DateTime<Utc>> {
                DateTime::from_timestamp_millis(row.get(index)?).context("invalid event timestamp")
            };
            events.push(Event {
                id: row.get(0)?,
                kind: row.get(1)?,
                session_id: row.get(2)?,
                profile: row.get(3)?,
                provider: row.get(4)?,
                state: row.get(5)?,
                expires_at: timestamp(6)?,
                occurred_at: timestamp(7)?,
            });
        }
        let next = events.last().map_or(after.max(floor), |event| event.id);
        Ok(Page {
            events,
            next_cursor: format!("{}:{next}", self.stream),
            history_truncated: after < floor,
        })
    }

    pub fn reserve_cleanup(&self, id: &str, sealed: &[u8]) -> Result<()> {
        self.write(|tx| {
            tx.execute(
                "INSERT INTO emergency_cleanup(session_id,sealed) VALUES (?1,?2)
                ON CONFLICT(session_id) DO UPDATE SET sealed=excluded.sealed",
                params![id, sealed],
            )?;
            Ok(())
        })
    }

    pub fn cleanup_record(&self, id: &str) -> Result<Option<Vec<u8>>> {
        let db = self
            .db
            .lock()
            .map_err(|_| anyhow::anyhow!("lock emergency journal"))?;
        Ok(db
            .query_row(
                "SELECT sealed FROM emergency_cleanup WHERE session_id=?1",
                [id],
                |row| row.get(0),
            )
            .optional()?)
    }

    pub async fn cleanup_records(&self) -> Result<Vec<(String, Vec<u8>)>> {
        let journal = self.clone();
        tokio::task::spawn_blocking(move || {
            let db = journal
                .db
                .lock()
                .map_err(|_| anyhow::anyhow!("lock emergency journal"))?;
            let mut statement =
                db.prepare("SELECT c.session_id, c.sealed FROM emergency_cleanup c
                WHERE NOT EXISTS (SELECT 1 FROM emergency_session_state s WHERE s.session_id = c.session_id
                AND s.state IN ('active','awaiting_totp','awaiting_passkey','awaiting_github','revocation_pending'))
                ORDER BY c.session_id")?;
            Ok(statement
                .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))?
                .collect::<rusqlite::Result<_>>()?)
        })
        .await?
    }

    pub async fn cleanup_count(&self) -> Result<i64> {
        let journal = self.clone();
        tokio::task::spawn_blocking(move || {
            let db = journal
                .db
                .lock()
                .map_err(|_| anyhow::anyhow!("lock emergency journal"))?;
            Ok(
                db.query_row("SELECT COUNT(*) FROM emergency_cleanup", [], |row| {
                    row.get(0)
                })?,
            )
        })
        .await?
    }

    pub async fn remove_cleanup(&self, id: String) -> Result<()> {
        let journal = self.clone();
        tokio::task::spawn_blocking(move || {
            let db = journal
                .db
                .lock()
                .map_err(|_| anyhow::anyhow!("lock emergency journal"))?;
            db.execute("DELETE FROM emergency_cleanup WHERE session_id=?1", [id])?;
            Ok(())
        })
        .await?
    }

    pub async fn prune(&self, retention: Duration) -> Result<()> {
        let journal = self.clone();
        tokio::task::spawn_blocking(move || {
            let cutoff = Utc::now()
                .checked_sub_signed(chrono::Duration::from_std(retention)?)
                .context("journal retention out of range")?
                .timestamp_millis();
            journal.prune_before(cutoff)
        })
        .await?
    }

    fn prune_before(&self, cutoff: i64) -> Result<()> {
        let mut db = self
            .db
            .lock()
            .map_err(|_| anyhow::anyhow!("lock emergency journal"))?;
        let transaction = db.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        transaction.execute_batch(
            "CREATE TEMP TABLE IF NOT EXISTS prune_candidates (session_id TEXT PRIMARY KEY);
             DELETE FROM prune_candidates;",
        )?;
        transaction.execute(
            "INSERT INTO prune_candidates
             SELECT s.session_id FROM emergency_session_state AS s
             WHERE s.state IN ('expired','revoked','invalidated')
             AND NOT EXISTS (SELECT 1 FROM emergency_cleanup AS c WHERE c.session_id=s.session_id)
             AND NOT EXISTS (SELECT 1 FROM emergency_events AS e WHERE e.session_id=s.session_id AND e.occurred_at>=?1)
             ORDER BY s.session_id LIMIT 1000",
            [cutoff],
        )?;
        let highest: i64 = transaction.query_row(
            "SELECT COALESCE(MAX(id),0) FROM emergency_events WHERE session_id IN (SELECT session_id FROM prune_candidates)",
            [], |row| row.get(0),
        )?;
        ensure!(highest >= 0, "invalid emergency event ID");
        if highest > 0 {
            transaction.execute(
                "INSERT INTO emergency_metadata(key,value) VALUES ('pruned_through',?1)
                 ON CONFLICT(key) DO UPDATE SET value=MAX(CAST(value AS INTEGER), CAST(excluded.value AS INTEGER))",
                [highest],
            )?;
        }
        for table in [
            "emergency_approvals",
            "emergency_events",
            "emergency_session_state",
        ] {
            transaction.execute(
                &format!("DELETE FROM {table} WHERE session_id IN (SELECT session_id FROM prune_candidates)"),
                [],
            )?;
        }
        transaction.commit()?;
        if highest > 0 {
            self.updates.send_replace(());
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn existing_stream_preserves_cursor_and_invalidates_live_sessions() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("journal.db");
        let conn = Connection::open(&path)?;
        conn.execute_batch(SCHEMA)?;
        conn.execute_batch("
            INSERT INTO emergency_metadata VALUES ('stream_id','existing-stream');
            INSERT INTO emergency_session_state VALUES ('E-one','caller','profile','kubernetes','active',123);
            INSERT INTO emergency_events VALUES (32,'caller','session.activated','E-one','profile','kubernetes','active',123,100);
            INSERT INTO emergency_events VALUES (33,'other','session.activated','E-two','profile','kubernetes','active',123,100);
        ")?;
        let journal = Journal::open(&path)?;
        let page = journal
            .watch("caller".into(), "existing-stream:32".into(), Duration::ZERO)
            .await?;
        assert_eq!(page.events.len(), 1);
        assert_eq!(page.events[0].kind, "session.invalidated");
        assert_eq!(page.events[0].session_id, "E-one");
        assert_eq!(page.next_cursor, "existing-stream:34");
        let state: String = conn.query_row(
            "SELECT state FROM emergency_session_state WHERE session_id='E-one'",
            [],
            |row| row.get(0),
        )?;
        assert_eq!(state, "invalidated");
        drop(journal);
        let reopened = Journal::open(&path)?;
        assert!(reopened.list("caller", 34)?.events.is_empty());
        Ok(())
    }

    #[test]
    fn pruning_keeps_pending_cleanup_and_reports_cursor_floor() -> Result<()> {
        let journal = Journal::open(Path::new(""))?;
        {
            let db = journal.db.lock().unwrap();
            db.execute_batch("
                INSERT INTO emergency_session_state VALUES ('E-one','caller','profile','approval','expired',123);
                INSERT INTO emergency_session_state VALUES ('E-two','caller','profile','kubernetes','revoked',123);
                INSERT INTO emergency_events VALUES (9,'caller','session.expired','E-one','profile','approval','expired',123,100);
                INSERT INTO emergency_events VALUES (10,'caller','session.revoked','E-two','profile','kubernetes','revoked',123,100);
                INSERT INTO emergency_approvals VALUES ('E-one','digest',1);
                INSERT INTO emergency_cleanup VALUES ('E-two',X'01');
            ")?;
        }
        journal.prune_before(200)?;
        let page = journal.list("caller", 0)?;
        assert!(page.history_truncated);
        assert_eq!(page.events.len(), 1);
        assert_eq!(page.events[0].session_id, "E-two");
        assert_eq!(
            journal.list("other", 0)?.next_cursor,
            format!("{}:9", journal.stream)
        );
        let approvals: i64 = journal.db.lock().unwrap().query_row(
            "SELECT COUNT(*) FROM emergency_approvals",
            [],
            |row| row.get(0),
        )?;
        assert_eq!(approvals, 0);
        Ok(())
    }
}
