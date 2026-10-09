//! Audit trail: every decision is recorded, with the action, the verdict,
//! and the timestamp — never the secret, never the payload.
//!
//! The [`AuditSink`] trait keeps the crate I/O-free: production sinks can
//! write to a file, a ledger, or a remote collector; tests use [`VecSink`].
//! [`Governor`](crate::Governor) records on every [`decide`](crate::Governor::decide)
//! call, including allows — an audit trail with holes is not an audit trail.

use serde::{Deserialize, Serialize};

use crate::action::{Action, Verdict};
use crate::error::GovernorError;

/// One recorded decision: what was asked, what was decided, when.
///
/// Serializable to JSON for ledger ingestion. The timestamp is seconds since
/// the Unix epoch, from the governor's injected clock.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditEntry {
    /// The action that was evaluated.
    pub action: Action,
    /// The verdict it received.
    pub verdict: Verdict,
    /// Seconds since 1970-01-01T00:00:00Z, from the governor's clock.
    pub ts_unix_secs: u64,
}

impl AuditEntry {
    /// Builds an entry. Prefer [`Governor`](crate::Governor::decide), which
    /// stamps time automatically, over constructing these by hand.
    pub fn new(action: Action, verdict: Verdict, ts_unix_secs: u64) -> Self {
        Self {
            action,
            verdict,
            ts_unix_secs,
        }
    }
}

/// Destination for audit entries.
///
/// `record` takes `&mut self` so sinks can batch, flush, or rotate without
/// interior mutability. A failing sink fails the decision — silently dropping
/// audit records would be worse than refusing the action.
pub trait AuditSink: Send {
    /// Records one entry. Failing here fails the whole decision.
    fn record(&mut self, entry: AuditEntry) -> Result<(), GovernorError>;
}

/// In-memory sink for tests and embedding: appends to a vector.
///
/// Cheap, deterministic, inspectable. Not durable — production deployments
/// should use a file or ledger-backed sink.
#[derive(Debug, Default)]
pub struct VecSink {
    /// Recorded entries, in decision order.
    pub entries: Vec<AuditEntry>,
}

impl VecSink {
    /// Creates an empty sink.
    pub fn new() -> Self {
        Self::default()
    }

    /// Entries with the given verdict.
    pub fn of_verdict(&self, verdict: &Verdict) -> Vec<&AuditEntry> {
        self.entries.iter().filter(|e| &e.verdict == verdict).collect()
    }
}

impl AuditSink for VecSink {
    fn record(&mut self, entry: AuditEntry) -> Result<(), GovernorError> {
        self.entries.push(entry);
        Ok(())
    }
}
