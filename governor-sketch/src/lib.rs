//! governor-sketch: a minimal deterministic policy engine.
//!
//! The kernel of the LUCIDOTA governor idea: policy is a pure function of
//! (domain, operation, resource). No LLM in the decision path, no
//! self-declared annotations, no judgment calls. Every action gets exactly
//! one verdict, and any verdict can be re-derived from the policy set.
//!
//! Compare: cloudflare-os's Gatekeeper model classifies tools from server
//! self-declared `readOnlyHint` annotations (see GATEKEEPER-ANALYSIS.md §6).
//! Here, classification is a closed function of the action triple.

use std::collections::HashSet;

/// The exhaustive verdict for an action. Every action gets exactly one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    /// The action may proceed.
    Allow,
    /// The action is refused. The String names the reason (and the policy).
    Deny(String),
    /// The action is parked for a human (or higher policy) to decide.
    /// The String names the reason. Reads against a queued action's effects
    /// should be simulated (cf. Gatekeeper "simulation", SKILL.md Phase 2).
    QueueForApproval(String),
}

impl Verdict {
    /// True only for `Allow`. Used by [`CompositePolicy`] to find the first
    /// decisive policy in the chain.
    pub fn is_allow(&self) -> bool {
        matches!(self, Verdict::Allow)
    }
}

/// What an agent wants to do. The only input policy may consider.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Action {
    /// e.g. "github", "email"
    pub domain: String,
    /// e.g. "read", "send"
    pub operation: String,
    /// e.g. "repo:foo", "to:bar@x.com"
    pub resource: String,
}

impl Action {
    pub fn new(domain: &str, operation: &str, resource: &str) -> Self {
        Self {
            domain: domain.to_string(),
            operation: operation.to_string(),
            resource: resource.to_string(),
        }
    }
}

/// A deterministic policy: pure function from action to verdict.
pub trait Policy {
    fn evaluate(&self, action: &Action) -> Verdict;
    /// Human-readable name, pinned to verdicts for audit.
    fn name(&self) -> &str;
}

/// Allows a fixed set of read operations; denies everything else.
///
/// The read set is explicit and closed: anything not in it is a write by
/// definition. There is no "the server said it's read-only" branch.
pub struct ReadOnlyPolicy {
    name: String,
    read_ops: HashSet<String>,
}

impl ReadOnlyPolicy {
    pub fn new(name: &str, read_ops: &[&str]) -> Self {
        Self {
            name: name.to_string(),
            read_ops: read_ops.iter().map(|s| s.to_string()).collect(),
        }
    }
}

impl Policy for ReadOnlyPolicy {
    fn name(&self) -> &str {
        &self.name
    }

    fn evaluate(&self, action: &Action) -> Verdict {
        if self.read_ops.contains(&action.operation) {
            Verdict::Allow
        } else {
            Verdict::Deny(format!(
                "[{}] operation `{}` on `{}` is not in the read set",
                self.name, action.operation, action.resource
            ))
        }
    }
}

/// Queues a fixed set of operations for approval; passes everything else through.
///
/// The queued set is explicit. Matching actions are parked, never silently
/// allowed and never silently denied — a human (or a higher policy) decides.
pub struct ApprovalPolicy {
    name: String,
    queued_ops: HashSet<String>,
}

impl ApprovalPolicy {
    pub fn new(name: &str, queued_ops: &[&str]) -> Self {
        Self {
            name: name.to_string(),
            queued_ops: queued_ops.iter().map(|s| s.to_string()).collect(),
        }
    }
}

impl Policy for ApprovalPolicy {
    fn name(&self) -> &str {
        &self.name
    }

    fn evaluate(&self, action: &Action) -> Verdict {
        if self.queued_ops.contains(&action.operation) {
            Verdict::QueueForApproval(format!(
                "[{}] operation `{}` on `{}` requires approval",
                self.name, action.operation, action.resource
            ))
        } else {
            Verdict::Allow
        }
    }
}

/// Chains policies in a fixed order. The first non-`Allow` verdict wins.
///
/// Order is the policy. A `Deny` earlier in the chain shadows a later
/// `QueueForApproval`, and vice versa — both directions are tested below.
/// If every policy allows, the composite allows.
pub struct CompositePolicy {
    name: String,
    policies: Vec<Box<dyn Policy>>,
}

impl CompositePolicy {
    pub fn new(name: &str, policies: Vec<Box<dyn Policy>>) -> Self {
        Self {
            name: name.to_string(),
            policies,
        }
    }
}

impl Policy for CompositePolicy {
    fn name(&self) -> &str {
        &self.name
    }

    fn evaluate(&self, action: &Action) -> Verdict {
        for policy in &self.policies {
            let verdict = policy.evaluate(action);
            if !verdict.is_allow() {
                return verdict;
            }
        }
        Verdict::Allow
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn read_action() -> Action {
        Action::new("github", "read", "repo:foo")
    }

    #[test]
    fn read_only_allows_reads() {
        let p = ReadOnlyPolicy::new("ro", &["read", "list", "get"]);
        assert_eq!(p.evaluate(&read_action()), Verdict::Allow);
        assert_eq!(
            p.evaluate(&Action::new("github", "list", "repo:foo")),
            Verdict::Allow
        );
    }

    #[test]
    fn read_only_denies_writes_with_reason() {
        let p = ReadOnlyPolicy::new("ro", &["read"]);
        let v = p.evaluate(&Action::new("email", "send", "to:bar@x.com"));
        match v {
            Verdict::Deny(reason) => {
                assert!(reason.contains("send"), "reason names the operation");
                assert!(reason.contains("to:bar@x.com"), "reason names the resource");
                assert!(reason.contains("ro"), "reason pins the policy");
            }
            other => panic!("expected Deny, got {other:?}"),
        }
    }

    #[test]
    fn read_only_empty_set_denies_everything() {
        let p = ReadOnlyPolicy::new("locked", &[]);
        assert!(matches!(p.evaluate(&read_action()), Verdict::Deny(_)));
    }

    #[test]
    fn approval_queues_listed_ops() {
        let p = ApprovalPolicy::new("ap", &["send", "delete"]);
        match p.evaluate(&Action::new("email", "send", "to:bar@x.com")) {
            Verdict::QueueForApproval(reason) => {
                assert!(reason.contains("send"));
                assert!(reason.contains("ap"));
            }
            other => panic!("expected QueueForApproval, got {other:?}"),
        }
    }

    #[test]
    fn approval_passes_through_unlisted_ops() {
        let p = ApprovalPolicy::new("ap", &["send"]);
        assert_eq!(p.evaluate(&read_action()), Verdict::Allow);
    }

    #[test]
    fn composite_first_non_allow_wins() {
        let c = CompositePolicy::new(
            "chain",
            vec![
                Box::new(ApprovalPolicy::new("ap", &["send"])),
                Box::new(ReadOnlyPolicy::new("ro", &["read"])),
            ],
        );
        // "send": first policy queues -> queue wins over second policy's deny.
        assert!(matches!(
            c.evaluate(&Action::new("email", "send", "to:x")),
            Verdict::QueueForApproval(_)
        ));
        // "write": first allows (pass-through), second denies -> deny.
        assert!(matches!(
            c.evaluate(&Action::new("github", "write", "repo:foo")),
            Verdict::Deny(_)
        ));
        // "read": both allow -> allow.
        assert_eq!(c.evaluate(&read_action()), Verdict::Allow);
    }

    #[test]
    fn composite_order_matters_deny_shadows_queue() {
        // Same policies, reversed: the deny now comes first and shadows the queue.
        let c = CompositePolicy::new(
            "chain-rev",
            vec![
                Box::new(ReadOnlyPolicy::new("ro", &["read"])),
                Box::new(ApprovalPolicy::new("ap", &["send"])),
            ],
        );
        assert!(matches!(
            c.evaluate(&Action::new("email", "send", "to:x")),
            Verdict::Deny(_)
        ));
    }

    #[test]
    fn composite_empty_allows() {
        let c = CompositePolicy::new("empty", vec![]);
        assert_eq!(c.evaluate(&read_action()), Verdict::Allow);
    }

    #[test]
    fn verdict_is_allow_only_for_allow() {
        assert!(Verdict::Allow.is_allow());
        assert!(!Verdict::Deny("x".into()).is_allow());
        assert!(!Verdict::QueueForApproval("x".into()).is_allow());
    }
}
