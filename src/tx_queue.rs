use anyhow::{anyhow, Context, Result};
use rusqlite::{params, Connection, OptionalExtension, TransactionBehavior};
use serde::Serialize;
use sha2::{Digest as Sha2Digest, Sha256};
use sha3::Keccak256;
use std::fmt;
use std::path::Path;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

pub const STATUS_QUEUED: &str = "queued";
pub const STATUS_PREPARED: &str = "prepared";
pub const STATUS_PENDING: &str = "pending";
pub const STATUS_CONFIRMED: &str = "confirmed";
pub const STATUS_REVERTED: &str = "reverted";
pub const STATUS_FAILED: &str = "failed";

#[derive(Clone, Debug)]
pub struct NewTxRequest {
    pub kind: String,
    pub target: String,
    pub value: u64,
    pub calldata: Vec<u8>,
    pub gas_cap: u64,
    pub gas_margin_bps: u64,
    pub nullifiers: Vec<(String, [u8; 32])>,
}

#[derive(Clone, Debug)]
pub struct QueueJob {
    pub request_id: String,
    pub kind: String,
    pub target: String,
    pub value: u64,
    pub calldata: Vec<u8>,
    pub gas_cap: u64,
    pub gas_margin_bps: u64,
    pub prepare_failures: u32,
}

#[derive(Clone, Debug)]
pub struct PreparedJob {
    pub request_id: String,
    pub nonce: u64,
    pub raw_tx: Vec<u8>,
    pub tx_hash: String,
    pub broadcast_failures: u32,
}

#[derive(Clone, Debug)]
pub struct PendingJob {
    pub request_id: String,
    pub target: String,
    pub value: u64,
    pub calldata: Vec<u8>,
    pub nonce: u64,
    pub gas_limit: u64,
    pub max_priority_fee: u128,
    pub max_fee: u128,
    pub attempt: u32,
    pub tx_hashes: Vec<String>,
}

#[derive(Clone, Debug, Serialize)]
pub struct TxRequestView {
    pub request_id: String,
    pub kind: String,
    pub status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tx_hash: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub tx_hashes: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    pub created_at: u64,
    pub updated_at: u64,
}

#[derive(Clone, Debug, Serialize)]
pub struct QueueStats {
    pub capacity: usize,
    pub queued: u64,
    pub prepared: u64,
    pub pending: u64,
    pub oldest_queued_age_secs: u64,
}

#[derive(Debug)]
pub enum EnqueueError {
    Full { capacity: usize },
    NullifierReserved { request_id: String },
    Storage(anyhow::Error),
}

impl fmt::Display for EnqueueError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Full { capacity } => write!(f, "transaction queue is full (capacity {capacity})"),
            Self::NullifierReserved { request_id } => write!(
                f,
                "one or more input nullifiers are already reserved by request {request_id}"
            ),
            Self::Storage(error) => write!(f, "transaction queue storage error: {error:#}"),
        }
    }
}

impl std::error::Error for EnqueueError {}

impl From<anyhow::Error> for EnqueueError {
    fn from(value: anyhow::Error) -> Self {
        Self::Storage(value)
    }
}

pub struct TxQueue {
    connection: Mutex<Connection>,
    capacity: usize,
    chain_id: u64,
}

impl TxQueue {
    pub fn open(path: &Path, capacity: usize, chain_id: u64, signer: &str) -> Result<Self> {
        if capacity == 0 {
            return Err(anyhow!(
                "transaction queue capacity must be greater than zero"
            ));
        }
        if capacity > 1_000_000 {
            return Err(anyhow!(
                "transaction queue capacity must not exceed 1,000,000"
            ));
        }
        if let Some(parent) = path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
        {
            std::fs::create_dir_all(parent).with_context(|| {
                format!("create transaction queue directory {}", parent.display())
            })?;
        }
        let connection = Connection::open(path)
            .with_context(|| format!("open transaction queue {}", path.display()))?;
        Self::from_connection(connection, capacity, chain_id, signer)
    }

    #[cfg(test)]
    pub fn in_memory(capacity: usize, chain_id: u64, signer: &str) -> Result<Self> {
        Self::from_connection(Connection::open_in_memory()?, capacity, chain_id, signer)
    }

    fn from_connection(
        mut connection: Connection,
        capacity: usize,
        chain_id: u64,
        signer: &str,
    ) -> Result<Self> {
        connection.busy_timeout(std::time::Duration::from_secs(5))?;
        connection.execute_batch(
            "PRAGMA journal_mode=WAL;
             PRAGMA synchronous=FULL;
             PRAGMA foreign_keys=ON;
             CREATE TABLE IF NOT EXISTS queue_meta (
               key TEXT PRIMARY KEY,
               value TEXT NOT NULL
             );
             CREATE TABLE IF NOT EXISTS tx_requests (
               request_id TEXT PRIMARY KEY,
               fingerprint TEXT NOT NULL UNIQUE,
               kind TEXT NOT NULL,
               target TEXT NOT NULL,
               value_wei TEXT NOT NULL,
               calldata BLOB NOT NULL,
               gas_cap INTEGER NOT NULL,
               gas_margin_bps INTEGER NOT NULL,
               status TEXT NOT NULL,
               prepare_failures INTEGER NOT NULL DEFAULT 0,
               broadcast_failures INTEGER NOT NULL DEFAULT 0,
               next_attempt_at INTEGER NOT NULL DEFAULT 0,
               nonce INTEGER,
               gas_limit INTEGER,
               max_priority_fee TEXT,
               max_fee TEXT,
               raw_tx BLOB,
               tx_hash TEXT,
               accepted_tx_hash TEXT,
               attempt INTEGER NOT NULL DEFAULT 0,
               last_error TEXT,
               created_at INTEGER NOT NULL,
               updated_at INTEGER NOT NULL,
               broadcast_at INTEGER
             );
             CREATE INDEX IF NOT EXISTS tx_requests_status_idx
               ON tx_requests(status, next_attempt_at, created_at);
             CREATE TABLE IF NOT EXISTS tx_hashes (
               request_id TEXT NOT NULL REFERENCES tx_requests(request_id) ON DELETE CASCADE,
               tx_hash TEXT NOT NULL UNIQUE,
               attempt INTEGER NOT NULL,
               created_at INTEGER NOT NULL,
               PRIMARY KEY(request_id, tx_hash)
             );
             CREATE TABLE IF NOT EXISTS nullifier_reservations (
               pool TEXT NOT NULL,
               nullifier BLOB NOT NULL,
               request_id TEXT NOT NULL REFERENCES tx_requests(request_id) ON DELETE CASCADE,
               created_at INTEGER NOT NULL,
               PRIMARY KEY(pool, nullifier)
             );
             CREATE INDEX IF NOT EXISTS nullifier_request_idx
               ON nullifier_reservations(request_id);
             CREATE TABLE IF NOT EXISTS worker_leases (
               name TEXT PRIMARY KEY,
               owner TEXT NOT NULL,
               expires_at INTEGER NOT NULL
             );",
        )?;

        let tx = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        bind_identity(&tx, "chain_id", &chain_id.to_string())?;
        bind_identity(&tx, "signer", &signer.to_ascii_lowercase())?;
        // Reconcile once at startup, then maintain this counter in the same transactions as
        // state changes. This keeps admission O(1) even when the durable history is large.
        let active: u64 = tx.query_row(
            "SELECT COUNT(*) FROM tx_requests WHERE status IN ('queued','prepared','pending')",
            [],
            |row| row.get(0),
        )?;
        set_meta(&tx, "active_count", &active.to_string())?;
        tx.commit()?;

        Ok(Self {
            connection: Mutex::new(connection),
            capacity,
            chain_id,
        })
    }

    pub fn enqueue(
        &self,
        request: NewTxRequest,
    ) -> std::result::Result<TxRequestView, EnqueueError> {
        let fingerprint = request_fingerprint(
            self.chain_id,
            &request.target,
            request.value,
            &request.calldata,
        );
        let request_id = format!("txreq_{fingerprint}");
        let now = now_secs();
        let mut connection = self
            .connection
            .lock()
            .map_err(|_| EnqueueError::Storage(anyhow!("transaction queue mutex poisoned")))?;
        let tx = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|error| EnqueueError::Storage(error.into()))?;

        if let Some(existing_id) = tx
            .query_row(
                "SELECT request_id FROM tx_requests WHERE fingerprint = ?1",
                params![fingerprint],
                |row| row.get::<_, String>(0),
            )
            .optional()
            .map_err(|error| EnqueueError::Storage(error.into()))?
        {
            let view = request_view(&tx, &existing_id)
                .map_err(EnqueueError::Storage)?
                .ok_or_else(|| {
                    EnqueueError::Storage(anyhow!("deduplicated request disappeared"))
                })?;
            tx.commit()
                .map_err(|error| EnqueueError::Storage(error.into()))?;
            return Ok(view);
        }

        let active = meta_u64(&tx, "active_count")
            .map_err(EnqueueError::Storage)?
            .ok_or_else(|| EnqueueError::Storage(anyhow!("queue active counter is missing")))?;
        if active >= self.capacity as u64 {
            return Err(EnqueueError::Full {
                capacity: self.capacity,
            });
        }

        for (pool, nullifier) in &request.nullifiers {
            if let Some(existing_id) = tx
                .query_row(
                    "SELECT request_id FROM nullifier_reservations WHERE pool = ?1 AND nullifier = ?2",
                    params![pool, nullifier.as_slice()],
                    |row| row.get::<_, String>(0),
                )
                .optional()
                .map_err(|error| EnqueueError::Storage(error.into()))?
            {
                return Err(EnqueueError::NullifierReserved {
                    request_id: existing_id,
                });
            }
        }

        tx.execute(
            "INSERT INTO tx_requests (
               request_id, fingerprint, kind, target, value_wei, calldata,
               gas_cap, gas_margin_bps, status, created_at, updated_at
             ) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,'queued',?9,?9)",
            params![
                request_id,
                fingerprint,
                request.kind,
                request.target,
                request.value.to_string(),
                request.calldata,
                to_i64(request.gas_cap, "gas cap").map_err(EnqueueError::Storage)?,
                to_i64(request.gas_margin_bps, "gas margin").map_err(EnqueueError::Storage)?,
                to_i64(now, "timestamp").map_err(EnqueueError::Storage)?,
            ],
        )
        .map_err(|error| EnqueueError::Storage(error.into()))?;
        for (pool, nullifier) in request.nullifiers {
            tx.execute(
                "INSERT INTO nullifier_reservations(pool,nullifier,request_id,created_at)
                 VALUES (?1,?2,?3,?4)",
                params![
                    pool,
                    nullifier.as_slice(),
                    request_id,
                    to_i64(now, "timestamp").map_err(EnqueueError::Storage)?
                ],
            )
            .map_err(|error| EnqueueError::Storage(error.into()))?;
        }
        set_meta(&tx, "active_count", &active.saturating_add(1).to_string())
            .map_err(EnqueueError::Storage)?;
        let view = request_view(&tx, &request_id)
            .map_err(EnqueueError::Storage)?
            .ok_or_else(|| EnqueueError::Storage(anyhow!("new request disappeared")))?;
        tx.commit()
            .map_err(|error| EnqueueError::Storage(error.into()))?;
        Ok(view)
    }

    pub fn request(&self, request_id: &str) -> Result<Option<TxRequestView>> {
        let connection = self.lock()?;
        request_view(&connection, request_id)
    }

    pub fn stats(&self) -> Result<QueueStats> {
        let connection = self.lock()?;
        let count = |status: &str| -> Result<u64> {
            Ok(connection.query_row(
                "SELECT COUNT(*) FROM tx_requests WHERE status = ?1",
                params![status],
                |row| row.get(0),
            )?)
        };
        let oldest: Option<u64> = connection.query_row(
            "SELECT MIN(created_at) FROM tx_requests WHERE status = 'queued'",
            [],
            |row| row.get(0),
        )?;
        Ok(QueueStats {
            capacity: self.capacity,
            queued: count(STATUS_QUEUED)?,
            prepared: count(STATUS_PREPARED)?,
            pending: count(STATUS_PENDING)?,
            oldest_queued_age_secs: oldest
                .map(|timestamp| now_secs().saturating_sub(timestamp))
                .unwrap_or(0),
        })
    }

    pub fn active_inflight(&self) -> Result<u64> {
        let connection = self.lock()?;
        Ok(connection.query_row(
            "SELECT COUNT(*) FROM tx_requests WHERE status IN ('prepared','pending')",
            [],
            |row| row.get(0),
        )?)
    }

    pub fn next_queued(&self) -> Result<Option<QueueJob>> {
        let connection = self.lock()?;
        connection
            .query_row(
                "SELECT request_id,kind,target,value_wei,calldata,gas_cap,gas_margin_bps,prepare_failures
                 FROM tx_requests
                 WHERE status = 'queued' AND next_attempt_at <= ?1
                 ORDER BY created_at ASC LIMIT 1",
                params![to_i64(now_secs(), "timestamp")?],
                queue_job_from_row,
            )
            .optional()
            .map_err(Into::into)
    }

    pub fn next_prepared(&self) -> Result<Option<PreparedJob>> {
        let connection = self.lock()?;
        connection
            .query_row(
                "SELECT request_id,nonce,raw_tx,tx_hash,broadcast_failures
                 FROM tx_requests
                 WHERE status = 'prepared' AND next_attempt_at <= ?1
                 ORDER BY updated_at ASC LIMIT 1",
                params![to_i64(now_secs(), "timestamp")?],
                |row| {
                    Ok(PreparedJob {
                        request_id: row.get(0)?,
                        nonce: from_i64(row.get(1)?, "nonce").map_err(sql_conversion_error)?,
                        raw_tx: row.get(2)?,
                        tx_hash: row.get(3)?,
                        broadcast_failures: row.get(4)?,
                    })
                },
            )
            .optional()
            .map_err(Into::into)
    }

    pub fn prepare<F>(
        &self,
        request_id: &str,
        chain_pending_nonce: u64,
        gas_limit: u64,
        max_priority_fee: u128,
        max_fee: u128,
        build: F,
    ) -> Result<Option<PreparedJob>>
    where
        F: FnOnce(u64) -> Result<Vec<u8>>,
    {
        let mut connection = self.lock()?;
        let tx = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let status: Option<String> = tx
            .query_row(
                "SELECT status FROM tx_requests WHERE request_id = ?1",
                params![request_id],
                |row| row.get(0),
            )
            .optional()?;
        if status.as_deref() != Some(STATUS_QUEUED) {
            tx.commit()?;
            return Ok(None);
        }
        let persisted_nonce = meta_u64(&tx, "next_nonce")?.unwrap_or(chain_pending_nonce);
        let nonce = persisted_nonce.max(chain_pending_nonce);
        let raw_tx = build(nonce)?;
        let tx_hash = evm_tx_hash(&raw_tx);
        let now = now_secs();
        set_meta(&tx, "next_nonce", &nonce.saturating_add(1).to_string())?;
        tx.execute(
            "UPDATE tx_requests SET
               status='prepared', nonce=?2, gas_limit=?3,
               max_priority_fee=?4, max_fee=?5, raw_tx=?6, tx_hash=?7,
               last_error=NULL, next_attempt_at=0, updated_at=?8
             WHERE request_id=?1 AND status='queued'",
            params![
                request_id,
                to_i64(nonce, "nonce")?,
                to_i64(gas_limit, "gas limit")?,
                max_priority_fee.to_string(),
                max_fee.to_string(),
                raw_tx,
                tx_hash,
                to_i64(now, "timestamp")?,
            ],
        )?;
        tx.execute(
            "INSERT OR IGNORE INTO tx_hashes(request_id,tx_hash,attempt,created_at)
             VALUES (?1,?2,0,?3)",
            params![request_id, tx_hash, to_i64(now, "timestamp")?],
        )?;
        tx.commit()?;
        Ok(Some(PreparedJob {
            request_id: request_id.to_string(),
            nonce,
            raw_tx,
            tx_hash,
            broadcast_failures: 0,
        }))
    }

    pub fn record_prepare_error(
        &self,
        request_id: &str,
        error: &str,
        max_attempts: u32,
    ) -> Result<()> {
        let mut connection = self.lock()?;
        let tx = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let failures: Option<u32> = tx
            .query_row(
                "SELECT prepare_failures FROM tx_requests WHERE request_id=?1 AND status='queued'",
                params![request_id],
                |row| row.get(0),
            )
            .optional()?;
        let Some(failures) = failures else {
            tx.commit()?;
            return Ok(());
        };
        let failures = failures.saturating_add(1);
        let now = now_secs();
        if failures >= max_attempts.max(1) {
            let changed = tx.execute(
                "UPDATE tx_requests SET status='failed',prepare_failures=?2,last_error=?3,updated_at=?4
                 WHERE request_id=?1 AND status='queued'",
                params![request_id, failures, truncate_error(error), to_i64(now, "timestamp")?],
            )?;
            if changed == 1 {
                decrement_active_count(&tx)?;
            }
            tx.execute(
                "DELETE FROM nullifier_reservations WHERE request_id=?1",
                params![request_id],
            )?;
        } else {
            let retry_at = now.saturating_add(retry_delay_secs(failures));
            tx.execute(
                "UPDATE tx_requests SET prepare_failures=?2,last_error=?3,next_attempt_at=?4,updated_at=?5
                 WHERE request_id=?1 AND status='queued'",
                params![
                    request_id,
                    failures,
                    truncate_error(error),
                    to_i64(retry_at, "retry timestamp")?,
                    to_i64(now, "timestamp")?,
                ],
            )?;
        }
        tx.commit()?;
        Ok(())
    }

    pub fn mark_pending(&self, request_id: &str) -> Result<()> {
        let connection = self.lock()?;
        let now = now_secs();
        connection.execute(
            "UPDATE tx_requests SET status='pending',broadcast_at=?2,updated_at=?2,
             accepted_tx_hash=tx_hash,last_error=NULL,next_attempt_at=0
             WHERE request_id=?1 AND status='prepared'",
            params![request_id, to_i64(now, "timestamp")?],
        )?;
        Ok(())
    }

    pub fn record_broadcast_error(&self, request_id: &str, error: &str) -> Result<()> {
        let connection = self.lock()?;
        let failures: Option<u32> = connection
            .query_row(
                "SELECT broadcast_failures FROM tx_requests WHERE request_id=?1 AND status='prepared'",
                params![request_id],
                |row| row.get(0),
            )
            .optional()?;
        let Some(failures) = failures else {
            return Ok(());
        };
        let failures = failures.saturating_add(1);
        let now = now_secs();
        let retry_at = now.saturating_add(retry_delay_secs(failures));
        connection.execute(
            "UPDATE tx_requests SET broadcast_failures=?2,last_error=?3,next_attempt_at=?4,updated_at=?5
             WHERE request_id=?1 AND status='prepared'",
            params![
                request_id,
                failures,
                truncate_error(error),
                to_i64(retry_at, "retry timestamp")?,
                to_i64(now, "timestamp")?,
            ],
        )?;
        Ok(())
    }

    pub fn pending_jobs(&self, limit: usize) -> Result<Vec<PendingJob>> {
        let connection = self.lock()?;
        let mut statement = connection.prepare(
            "SELECT request_id,target,value_wei,calldata,nonce,gas_limit,
                    max_priority_fee,max_fee,attempt
             FROM tx_requests WHERE status='pending'
             ORDER BY broadcast_at ASC LIMIT ?1",
        )?;
        let rows = statement.query_map(params![limit as i64], pending_job_from_row)?;
        let mut jobs = Vec::new();
        for row in rows {
            let mut job = row?;
            job.tx_hashes = hashes_for_request(&connection, &job.request_id)?;
            jobs.push(job);
        }
        Ok(jobs)
    }

    pub fn stale_pending(
        &self,
        older_than_secs: u64,
        max_replacements: u32,
    ) -> Result<Option<PendingJob>> {
        let connection = self.lock()?;
        let cutoff = now_secs().saturating_sub(older_than_secs);
        let mut job = connection
            .query_row(
                "SELECT request_id,target,value_wei,calldata,nonce,gas_limit,
                        max_priority_fee,max_fee,attempt
                 FROM tx_requests
                 WHERE status='pending' AND broadcast_at <= ?1 AND attempt < ?2
                 ORDER BY broadcast_at ASC LIMIT 1",
                params![to_i64(cutoff, "replacement cutoff")?, max_replacements],
                pending_job_from_row,
            )
            .optional()?;
        if let Some(job) = job.as_mut() {
            job.tx_hashes = hashes_for_request(&connection, &job.request_id)?;
        }
        Ok(job)
    }

    pub fn prepare_replacement<F>(
        &self,
        request_id: &str,
        max_priority_fee: u128,
        max_fee: u128,
        build: F,
    ) -> Result<Option<PreparedJob>>
    where
        F: FnOnce(&PendingJob) -> Result<Vec<u8>>,
    {
        let mut connection = self.lock()?;
        let tx = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let mut job = tx
            .query_row(
                "SELECT request_id,target,value_wei,calldata,nonce,gas_limit,
                        max_priority_fee,max_fee,attempt
                 FROM tx_requests WHERE request_id=?1 AND status='pending'",
                params![request_id],
                pending_job_from_row,
            )
            .optional()?;
        let Some(mut job) = job.take() else {
            tx.commit()?;
            return Ok(None);
        };
        job.max_priority_fee = max_priority_fee;
        job.max_fee = max_fee;
        let raw_tx = build(&job)?;
        let tx_hash = evm_tx_hash(&raw_tx);
        let attempt = job.attempt.saturating_add(1);
        let now = now_secs();
        tx.execute(
            "UPDATE tx_requests SET status='prepared',max_priority_fee=?2,max_fee=?3,
             raw_tx=?4,tx_hash=?5,attempt=?6,broadcast_failures=0,broadcast_at=NULL,
             next_attempt_at=0,last_error=NULL,updated_at=?7
             WHERE request_id=?1 AND status='pending'",
            params![
                request_id,
                max_priority_fee.to_string(),
                max_fee.to_string(),
                raw_tx,
                tx_hash,
                attempt,
                to_i64(now, "timestamp")?,
            ],
        )?;
        tx.execute(
            "INSERT OR IGNORE INTO tx_hashes(request_id,tx_hash,attempt,created_at)
             VALUES (?1,?2,?3,?4)",
            params![request_id, tx_hash, attempt, to_i64(now, "timestamp")?],
        )?;
        tx.commit()?;
        Ok(Some(PreparedJob {
            request_id: request_id.to_string(),
            nonce: job.nonce,
            raw_tx,
            tx_hash,
            broadcast_failures: 0,
        }))
    }

    pub fn mark_terminal(&self, request_id: &str, status: &str, error: Option<&str>) -> Result<()> {
        if !matches!(status, STATUS_CONFIRMED | STATUS_REVERTED | STATUS_FAILED) {
            return Err(anyhow!("invalid terminal queue status {status}"));
        }
        let mut connection = self.lock()?;
        let tx = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let now = now_secs();
        let changed = tx.execute(
            "UPDATE tx_requests SET status=?2,last_error=?3,updated_at=?4,
             calldata=X'',raw_tx=NULL
             WHERE request_id=?1 AND status IN ('queued','prepared','pending')",
            params![
                request_id,
                status,
                error.map(truncate_error),
                to_i64(now, "timestamp")?
            ],
        )?;
        if changed == 1 {
            decrement_active_count(&tx)?;
        }
        if changed == 1 && matches!(status, STATUS_REVERTED | STATUS_FAILED) {
            tx.execute(
                "DELETE FROM nullifier_reservations WHERE request_id=?1",
                params![request_id],
            )?;
        }
        tx.commit()?;
        Ok(())
    }

    pub fn acquire_or_renew_lease(&self, owner: &str, ttl_secs: u64) -> Result<bool> {
        if ttl_secs == 0 {
            return Err(anyhow!("worker lease TTL must be greater than zero"));
        }
        let mut connection = self.lock()?;
        let tx = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let now = now_secs();
        let existing: Option<(String, u64)> = tx
            .query_row(
                "SELECT owner,expires_at FROM worker_leases WHERE name='evm-signer'",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?;
        let allowed = existing
            .as_ref()
            .is_none_or(|(current, expires_at)| current == owner || *expires_at <= now);
        if allowed {
            tx.execute(
                "INSERT INTO worker_leases(name,owner,expires_at) VALUES ('evm-signer',?1,?2)
                 ON CONFLICT(name) DO UPDATE SET owner=excluded.owner,expires_at=excluded.expires_at",
                params![owner, to_i64(now.saturating_add(ttl_secs), "lease expiry")?],
            )?;
        }
        tx.commit()?;
        Ok(allowed)
    }

    fn lock(&self) -> Result<std::sync::MutexGuard<'_, Connection>> {
        self.connection
            .lock()
            .map_err(|_| anyhow!("transaction queue mutex poisoned"))
    }
}

fn bind_identity(tx: &rusqlite::Transaction<'_>, key: &str, expected: &str) -> Result<()> {
    let actual: Option<String> = tx
        .query_row(
            "SELECT value FROM queue_meta WHERE key=?1",
            params![key],
            |row| row.get(0),
        )
        .optional()?;
    match actual {
        Some(actual) if actual != expected => Err(anyhow!(
            "transaction queue identity mismatch for {key}: stored {actual}, configured {expected}"
        )),
        Some(_) => Ok(()),
        None => {
            tx.execute(
                "INSERT INTO queue_meta(key,value) VALUES (?1,?2)",
                params![key, expected],
            )?;
            Ok(())
        }
    }
}

fn set_meta(tx: &rusqlite::Transaction<'_>, key: &str, value: &str) -> Result<()> {
    tx.execute(
        "INSERT INTO queue_meta(key,value) VALUES (?1,?2)
         ON CONFLICT(key) DO UPDATE SET value=excluded.value",
        params![key, value],
    )?;
    Ok(())
}

fn meta_u64(tx: &rusqlite::Transaction<'_>, key: &str) -> Result<Option<u64>> {
    tx.query_row(
        "SELECT value FROM queue_meta WHERE key=?1",
        params![key],
        |row| row.get::<_, String>(0),
    )
    .optional()?
    .map(|value| {
        value
            .parse::<u64>()
            .with_context(|| format!("bad queue_meta {key}"))
    })
    .transpose()
}

fn decrement_active_count(tx: &rusqlite::Transaction<'_>) -> Result<()> {
    let active =
        meta_u64(tx, "active_count")?.ok_or_else(|| anyhow!("queue active counter is missing"))?;
    let next = active
        .checked_sub(1)
        .ok_or_else(|| anyhow!("queue active counter underflow"))?;
    set_meta(tx, "active_count", &next.to_string())
}

fn request_view(connection: &Connection, request_id: &str) -> Result<Option<TxRequestView>> {
    let mut view = connection
        .query_row(
            "SELECT request_id,kind,status,accepted_tx_hash,last_error,created_at,updated_at
             FROM tx_requests WHERE request_id=?1",
            params![request_id],
            |row| {
                Ok(TxRequestView {
                    request_id: row.get(0)?,
                    kind: row.get(1)?,
                    status: row.get(2)?,
                    tx_hash: row.get(3)?,
                    tx_hashes: Vec::new(),
                    error: row.get(4)?,
                    created_at: row.get(5)?,
                    updated_at: row.get(6)?,
                })
            },
        )
        .optional()?;
    if let Some(view) = view.as_mut() {
        view.tx_hashes = hashes_for_request(connection, request_id)?;
    }
    Ok(view)
}

fn hashes_for_request(connection: &Connection, request_id: &str) -> Result<Vec<String>> {
    let mut statement = connection
        .prepare("SELECT tx_hash FROM tx_hashes WHERE request_id=?1 ORDER BY attempt ASC")?;
    let hashes = statement
        .query_map(params![request_id], |row| row.get::<_, String>(0))?
        .collect::<std::result::Result<Vec<_>, _>>()?;
    Ok(hashes)
}

fn queue_job_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<QueueJob> {
    let value: String = row.get(3)?;
    Ok(QueueJob {
        request_id: row.get(0)?,
        kind: row.get(1)?,
        target: row.get(2)?,
        value: value.parse().map_err(sql_conversion_error)?,
        calldata: row.get(4)?,
        gas_cap: from_i64(row.get(5)?, "gas cap").map_err(sql_conversion_error)?,
        gas_margin_bps: from_i64(row.get(6)?, "gas margin").map_err(sql_conversion_error)?,
        prepare_failures: row.get(7)?,
    })
}

fn pending_job_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<PendingJob> {
    let value: String = row.get(2)?;
    let priority: String = row.get(6)?;
    let max_fee: String = row.get(7)?;
    Ok(PendingJob {
        request_id: row.get(0)?,
        target: row.get(1)?,
        value: value.parse().map_err(sql_conversion_error)?,
        calldata: row.get(3)?,
        nonce: from_i64(row.get(4)?, "nonce").map_err(sql_conversion_error)?,
        gas_limit: from_i64(row.get(5)?, "gas limit").map_err(sql_conversion_error)?,
        max_priority_fee: priority.parse().map_err(sql_conversion_error)?,
        max_fee: max_fee.parse().map_err(sql_conversion_error)?,
        attempt: row.get(8)?,
        tx_hashes: Vec::new(),
    })
}

fn sql_conversion_error(error: impl fmt::Display) -> rusqlite::Error {
    rusqlite::Error::FromSqlConversionFailure(
        0,
        rusqlite::types::Type::Text,
        Box::new(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            error.to_string(),
        )),
    )
}

fn request_fingerprint(chain_id: u64, target: &str, value: u64, calldata: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"PERC20_RELAYER_TX_V1\0");
    hasher.update(chain_id.to_be_bytes());
    hasher.update((target.len() as u64).to_be_bytes());
    hasher.update(target.as_bytes());
    hasher.update(value.to_be_bytes());
    hasher.update((calldata.len() as u64).to_be_bytes());
    hasher.update(calldata);
    hex::encode(hasher.finalize())
}

fn evm_tx_hash(raw_tx: &[u8]) -> String {
    format!("0x{}", hex::encode(Keccak256::digest(raw_tx)))
}

fn truncate_error(error: &str) -> String {
    error.chars().take(2_000).collect()
}

fn retry_delay_secs(failures: u32) -> u64 {
    1u64.checked_shl(failures.min(6)).unwrap_or(60).min(60)
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn to_i64(value: u64, field: &str) -> Result<i64> {
    i64::try_from(value).with_context(|| format!("{field} exceeds SQLite i64"))
}

fn from_i64(value: i64, field: &str) -> Result<u64> {
    u64::try_from(value).with_context(|| format!("{field} is negative"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request(byte: u8) -> NewTxRequest {
        NewTxRequest {
            kind: "transfer".into(),
            target: "0x1111111111111111111111111111111111111111".into(),
            value: 0,
            calldata: vec![byte; 32],
            gas_cap: 5_000_000,
            gas_margin_bps: 200,
            nullifiers: vec![(
                "0x2222222222222222222222222222222222222222".into(),
                [byte; 32],
            )],
        }
    }

    fn unique_request(index: u64) -> NewTxRequest {
        NewTxRequest {
            kind: "transfer".into(),
            target: "0x1111111111111111111111111111111111111111".into(),
            value: 0,
            calldata: index.to_be_bytes().to_vec(),
            gas_cap: 5_000_000,
            gas_margin_bps: 200,
            nullifiers: Vec::new(),
        }
    }

    #[test]
    fn enqueue_is_idempotent_and_reserves_nullifiers() {
        let queue = TxQueue::in_memory(2, 143, "0xabc").unwrap();
        let first = queue.enqueue(request(1)).unwrap();
        let duplicate = queue.enqueue(request(1)).unwrap();
        assert_eq!(first.request_id, duplicate.request_id);
        assert_eq!(queue.stats().unwrap().queued, 1);

        let mut conflicting = request(2);
        conflicting.nullifiers[0].1 = [1u8; 32];
        assert!(matches!(
            queue.enqueue(conflicting),
            Err(EnqueueError::NullifierReserved { .. })
        ));
    }

    #[test]
    fn terminal_transition_frees_capacity_and_reverted_nullifier_reservation() {
        let queue = TxQueue::in_memory(1, 143, "0xabc").unwrap();
        let first = queue.enqueue(request(1)).unwrap();
        assert!(matches!(
            queue.enqueue(request(2)),
            Err(EnqueueError::Full { capacity: 1 })
        ));

        queue
            .mark_terminal(&first.request_id, STATUS_REVERTED, Some("test revert"))
            .unwrap();
        assert_eq!(queue.stats().unwrap().queued, 0);

        let mut retry = request(2);
        retry.nullifiers[0].1 = [1u8; 32];
        assert_eq!(queue.enqueue(retry).unwrap().status, STATUS_QUEUED);
    }

    #[test]
    fn confirmed_request_keeps_its_nullifier_reserved() {
        let queue = TxQueue::in_memory(1, 143, "0xabc").unwrap();
        let first = queue.enqueue(request(1)).unwrap();
        queue
            .mark_terminal(&first.request_id, STATUS_CONFIRMED, None)
            .unwrap();

        // A stale/later terminal update must neither rewrite the confirmed result nor release
        // the spent nullifier reservation.
        queue
            .mark_terminal(&first.request_id, STATUS_REVERTED, Some("stale result"))
            .unwrap();
        let mut conflicting = request(2);
        conflicting.nullifiers[0].1 = [1u8; 32];
        assert!(matches!(
            queue.enqueue(conflicting),
            Err(EnqueueError::NullifierReserved { .. })
        ));
        assert_eq!(
            queue.request(&first.request_id).unwrap().unwrap().status,
            STATUS_CONFIRMED
        );
    }

    #[test]
    fn signed_raw_transaction_is_durable_before_broadcast() {
        let path = std::env::temp_dir().join(format!(
            "privacy-relayer-queue-{}-{}.sqlite",
            std::process::id(),
            now_secs()
        ));
        let _ = std::fs::remove_file(&path);
        let request_id = {
            let queue = TxQueue::open(&path, 10, 143, "0xabc").unwrap();
            let request_id = queue.enqueue(request(3)).unwrap().request_id;
            let prepared = queue
                .prepare(&request_id, 7, 100_000, 1, 2, |nonce| {
                    Ok(vec![nonce as u8, 0xaa, 0xbb])
                })
                .unwrap()
                .unwrap();
            assert_eq!(prepared.raw_tx, vec![7, 0xaa, 0xbb]);
            request_id
        };

        let reopened = TxQueue::open(&path, 10, 143, "0xabc").unwrap();
        let prepared = reopened.next_prepared().unwrap().unwrap();
        assert_eq!(prepared.request_id, request_id);
        assert_eq!(prepared.raw_tx, vec![7, 0xaa, 0xbb]);
        drop(reopened);
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(path.with_extension("sqlite-wal"));
        let _ = std::fs::remove_file(path.with_extension("sqlite-shm"));
    }

    #[test]
    fn queue_file_is_bound_to_chain_and_signer() {
        let path = std::env::temp_dir().join(format!(
            "privacy-relayer-identity-{}-{}.sqlite",
            std::process::id(),
            now_secs()
        ));
        let _ = std::fs::remove_file(&path);
        drop(TxQueue::open(&path, 10, 143, "0xabc").unwrap());
        assert!(TxQueue::open(&path, 10, 1, "0xabc").is_err());
        assert!(TxQueue::open(&path, 10, 143, "0xdef").is_err());
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn concurrent_duplicate_storm_creates_one_request() {
        let queue = std::sync::Arc::new(TxQueue::in_memory(10, 143, "0xabc").unwrap());
        let mut threads = Vec::new();
        for _ in 0..32 {
            let queue = queue.clone();
            threads.push(std::thread::spawn(move || {
                let mut ids = Vec::new();
                for _ in 0..32 {
                    ids.push(queue.enqueue(request(9)).unwrap().request_id);
                }
                ids
            }));
        }
        let ids: Vec<String> = threads
            .into_iter()
            .flat_map(|thread| thread.join().unwrap())
            .collect();
        assert_eq!(ids.len(), 1_024);
        assert!(ids.iter().all(|id| id == &ids[0]));
        assert_eq!(queue.stats().unwrap().queued, 1);
    }

    #[test]
    fn persistent_nonce_allocation_has_no_gaps_or_duplicates() {
        let queue = TxQueue::in_memory(200, 143, "0xabc").unwrap();
        for byte in 1..=100u8 {
            queue.enqueue(request(byte)).unwrap();
        }
        let mut nonces = Vec::new();
        for _ in 0..100 {
            let job = queue.next_queued().unwrap().unwrap();
            let prepared = queue
                .prepare(&job.request_id, 50, 100_000, 1, 2, |nonce| {
                    Ok(vec![nonce as u8, 0xaa])
                })
                .unwrap()
                .unwrap();
            nonces.push(prepared.nonce);
            queue.mark_pending(&job.request_id).unwrap();
        }
        assert_eq!(nonces, (50..150).collect::<Vec<_>>());
    }

    #[test]
    fn replacement_keeps_nonce_and_records_hash_aliases() {
        let queue = TxQueue::in_memory(10, 143, "0xabc").unwrap();
        let request_id = queue.enqueue(request(7)).unwrap().request_id;
        let first = queue
            .prepare(&request_id, 4, 100_000, 10, 20, |nonce| {
                Ok(vec![nonce as u8, 1])
            })
            .unwrap()
            .unwrap();
        assert!(queue
            .request(&request_id)
            .unwrap()
            .unwrap()
            .tx_hash
            .is_none());
        queue.mark_pending(&request_id).unwrap();
        assert_eq!(
            queue
                .request(&request_id)
                .unwrap()
                .unwrap()
                .tx_hash
                .as_deref(),
            Some(first.tx_hash.as_str())
        );
        let pending = queue.pending_jobs(1).unwrap().remove(0);
        assert_eq!(pending.nonce, 4);
        let replacement = queue
            .prepare_replacement(&request_id, 12, 24, |job| Ok(vec![job.nonce as u8, 2]))
            .unwrap()
            .unwrap();

        assert_eq!(first.nonce, replacement.nonce);
        assert_ne!(first.tx_hash, replacement.tx_hash);
        let view = queue.request(&request_id).unwrap().unwrap();
        // A replacement hash is not advertised as accepted until the RPC node accepts it.
        assert_eq!(view.tx_hash.as_deref(), Some(first.tx_hash.as_str()));
        assert_eq!(view.tx_hashes, vec![first.tx_hash, replacement.tx_hash]);
    }

    #[test]
    #[ignore = "explicit 100k admission/load gate"]
    fn load_gate_queues_100_000_unique_requests_without_loss() {
        let queue = TxQueue::in_memory(100_000, 143, "0xabc").unwrap();
        for index in 0..100_000 {
            queue.enqueue(unique_request(index)).unwrap();
        }
        let stats = queue.stats().unwrap();
        assert_eq!(stats.queued, 100_000);
        assert!(matches!(
            queue.enqueue(unique_request(100_000)),
            Err(EnqueueError::Full { capacity: 100_000 })
        ));
    }
}
