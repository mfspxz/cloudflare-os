//! The action model: what an agent wants to do, and the verdict it gets.
//!
//! Policy is a pure function of the [`Action`] triple `(domain, operation,
//! resource)`. Nothing else — no caller identity, no LLM judgment, no
//! self-declared annotations — may influence the verdict. This keeps every
//! decision re-derivable from the policy set alone.

use serde::{Deserialize, Serialize};

/// What an agent wants to do. The only input policy may consider.
///
/// The triple is deliberately coarse: `domain` scopes the integration
/// (`"github"`, `"email"`), `operation` names the verb (`"read"`, `"send"`),
/// `resource` names the target (`"repo:foo"`, `"to:bar@x.com"`).
/// Finer distinctions belong in policy configuration, not in the type.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Action {
    /// Integration or subsystem, e.g. `"github"`, `"email"`.
    pub domain: String,
    /// Verb, e.g. `"read"`, `"send"`, `"delete"`.
    pub operation: String,
    /// Target, e.g. `"repo:foo"`, `"to:bar@x.com"`.
    pub resource: String,
}

impl Action {
    /// Builds an [`Action`] from string slices.
    ///
    /// # Example
    ///
    /// ```
    /// # use governor::Action;
    /// let a = Action::new("github", "read", "repo:foo");
    /// assert_eq!(a.domain, "github");
    /// ```
    pub fn new(domain: &str, operation: &str, resource: &str) -> Self {
        Self {
            domain: domain.to_string(),
            operation: operation.to_string(),
            resource: resource.to_string(),
        }
    }
}

/// A structured refusal: which policy decided, and why.
///
/// Reasons are human-readable but machine-pinned: `policy` always names the
/// deciding policy, so audit consumers can attribute every non-allow verdict
/// without parsing prose.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Refusal {
    /// Name of the policy that produced this refusal.
    pub policy: String,
    /// Human-readable reason, e.g. `` operation `send` is not in the read set ``.
    pub reason: String,
}

impl Refusal {
    /// Builds a [`Refusal`] pinning the deciding `policy` with a `reason`.
    pub fn new(policy: &str, reason: impl Into<String>) -> Self {
        Self {
            policy: policy.to_string(),
            reason: reason.into(),
        }
    }
}

/// The exhaustive verdict for an action. Every action gets exactly one.
///
/// Serialized as `{"verdict":"allow"}` or
/// `{"verdict":"deny","policy":"ro","reason":"…"}` — flat, greppable, stable.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "verdict", rename_all = "snake_case")]
pub enum Verdict {
    /// The action may proceed.
    Allow,
    /// The action is refused. See [`Refusal`].
    Deny(Refusal),
    /// The action is parked for a human (or a higher policy) to decide.
    /// Reads against a queued action's effects should be simulated rather
    /// than blocked, so agents keep working while approval is pending.
    QueueForApproval(Refusal),
}

impl Verdict {
    /// True only for [`Verdict::Allow`].
    ///
    /// Used by composite policies to find the first decisive policy in the
    /// chain: the first non-allow verdict wins.
    pub fn is_allow(&self) -> bool {
        matches!(self, Verdict::Allow)
    }

    /// The deciding policy's name, or `None` for [`Verdict::Allow`].
    pub fn deciding_policy(&self) -> Option<&str> {
        match self {
            Verdict::Allow => None,
            Verdict::Deny(r) | Verdict::QueueForApproval(r) => Some(&r.policy),
        }
    }
}
