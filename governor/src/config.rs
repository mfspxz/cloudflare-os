//! TOML configuration: policies as data.
//!
//! A config file declares an ordered policy chain; [`GovernorConfig::build`]
//! turns it into a [`CompositePolicy`](crate::CompositePolicy). Policy order
//! in the file is evaluation order — order is the policy.
//!
//! ```toml
//! [[policy]]
//! type = "read_only"
//! name = "ro"
//! read_ops = ["read", "list", "get"]
//!
//! [[policy]]
//! type = "approval"
//! name = "appr"
//! queued_ops = ["send", "delete"]
//!
//! [[policy]]
//! type = "time_window"
//! name = "biz-hours"
//! start_hour = 9
//! end_hour = 17
//!
//! [[policy]]
//! type = "rate_limit"
//! name = "rl"
//! max_calls = 100
//! window_secs = 60
//! ```

use serde::{Deserialize, Serialize};

use crate::clock::SystemClock;
use crate::error::GovernorError;
use crate::policy::{ApprovalPolicy, CompositePolicy, Policy, RateLimitPolicy, ReadOnlyPolicy, TimeWindowPolicy};

/// One policy declaration in the config file.
///
/// Only the fields relevant to `type` are read; unknown `type` values are a
/// [`GovernorError::InvalidPolicy`], not a silent skip — a config that names
/// a policy that doesn't exist must fail loudly.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum PolicyDecl {
    /// [`ReadOnlyPolicy`]: `read_ops` is the closed allow-set.
    ReadOnly {
        /// Policy name, pinned into refusals.
        name: String,
        /// Operations that are allowed; everything else is denied.
        read_ops: Vec<String>,
    },
    /// [`ApprovalPolicy`]: `queued_ops` are parked for approval.
    Approval {
        /// Policy name, pinned into refusals.
        name: String,
        /// Operations queued for approval; everything else passes through.
        queued_ops: Vec<String>,
    },
    /// [`TimeWindowPolicy`]: allow only inside `[start_hour, end_hour)` UTC.
    TimeWindow {
        /// Policy name, pinned into refusals.
        name: String,
        /// Opening hour, 0–23 UTC.
        start_hour: u8,
        /// Closing hour, 0–23 UTC, must exceed `start_hour`.
        end_hour: u8,
    },
    /// [`RateLimitPolicy`]: cap calls per domain per sliding window.
    RateLimit {
        /// Policy name, pinned into refusals.
        name: String,
        /// Max allowed calls per window, per domain.
        max_calls: u32,
        /// Window length in seconds.
        window_secs: u64,
    },
}

/// A full governor configuration: an ordered chain of policy declarations.
///
/// Deserialize from TOML with [`GovernorConfig::from_toml_str`] or
/// [`GovernorConfig::from_file`], then materialize with [`GovernorConfig::build`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GovernorConfig {
    /// Policy chain, evaluated in order. First non-allow verdict wins.
    #[serde(default)]
    pub policy: Vec<PolicyDecl>,
}

impl GovernorConfig {
    /// Parses a TOML string into a config.
    ///
    /// # Errors
    ///
    /// [`GovernorError::ConfigParse`] on invalid TOML or a shape mismatch.
    pub fn from_toml_str(s: &str) -> Result<Self, GovernorError> {
        Ok(toml::from_str(s)?)
    }

    /// Reads and parses a TOML config file.
    ///
    /// # Errors
    ///
    /// [`GovernorError::ConfigRead`] if the file can't be read,
    /// [`GovernorError::ConfigParse`] if it isn't valid config.
    pub fn from_file(path: &str) -> Result<Self, GovernorError> {
        let text = std::fs::read_to_string(path).map_err(|source| GovernorError::ConfigRead {
            path: path.to_string(),
            source,
        })?;
        Self::from_toml_str(&text)
    }

    /// Materializes the declared chain into a [`CompositePolicy`].
    ///
    /// Time-based policies get a [`SystemClock`]. Declaration order is
    /// evaluation order.
    ///
    /// # Errors
    ///
    /// [`GovernorError::InvalidPolicy`] on bad parameters (inverted hours,
    /// zero limits). An empty chain builds a composite that allows
    /// everything — construct that deliberately, not by accident.
    pub fn build(self) -> Result<CompositePolicy, GovernorError> {
        let mut policies: Vec<Box<dyn Policy>> = Vec::with_capacity(self.policy.len());
        for decl in self.policy {
            let boxed: Box<dyn Policy> = match decl {
                PolicyDecl::ReadOnly { name, read_ops } => {
                    let refs: Vec<&str> = read_ops.iter().map(String::as_str).collect();
                    Box::new(ReadOnlyPolicy::new(&name, &refs))
                }
                PolicyDecl::Approval { name, queued_ops } => {
                    let refs: Vec<&str> = queued_ops.iter().map(String::as_str).collect();
                    Box::new(ApprovalPolicy::new(&name, &refs))
                }
                PolicyDecl::TimeWindow { name, start_hour, end_hour } => {
                    Box::new(TimeWindowPolicy::new(&name, start_hour, end_hour, SystemClock)?)
                }
                PolicyDecl::RateLimit { name, max_calls, window_secs } => {
                    Box::new(RateLimitPolicy::new(&name, max_calls, window_secs, SystemClock)?)
                }
            };
            policies.push(boxed);
        }
        Ok(CompositePolicy::new("config", policies))
    }
}
