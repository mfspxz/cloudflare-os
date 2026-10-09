//! governor: a deterministic policy engine.
//!
//! Policy is a pure function of `(domain, operation, resource)`. No LLM in
//! the decision path, no self-declared annotations, no judgment calls. Every
//! action gets exactly one [`Verdict`], every verdict is audited, and any
//! verdict can be re-derived from the policy set.

#![warn(missing_docs)]
//!
//! # The model
//!
//! - [`Action`] is the only input policy may consider.
//! - [`Policy`] maps an action to a [`Verdict`]. Built-ins:
//!   [`ReadOnlyPolicy`], [`ApprovalPolicy`], [`TimeWindowPolicy`],
//!   [`RateLimitPolicy`], composed with [`CompositePolicy`].
//! - [`Governor`] evaluates actions through a policy and records every
//!   decision — allows included — to an [`AuditSink`].
//! - [`GovernorConfig`] declares the policy chain as TOML; declaration order
//!   is evaluation order.
//!
//! # Example
//!
//! ```
//! # use governor::{Action, ApprovalPolicy, Clock, CompositePolicy, Governor, ManualClock, ReadOnlyPolicy, VecSink};
//! let policy = CompositePolicy::new("chain", vec![
//!     Box::new(ApprovalPolicy::new("appr", &["send"])),
//!     Box::new(ReadOnlyPolicy::new("ro", &["read"])),
//! ]);
//! let mut gov = Governor::new(policy, VecSink::new(), ManualClock::new(0));
//! let v = gov.decide(&Action::new("email", "send", "to:a@x.com")).unwrap();
//! assert!(matches!(v, governor::Verdict::QueueForApproval(_)));
//! assert_eq!(gov.sink().entries.len(), 1);
//! ```

mod action;
mod audit;
mod clock;
mod config;
mod error;
mod policy;

pub use action::{Action, Refusal, Verdict};
pub use audit::{AuditEntry, AuditSink, VecSink};
pub use clock::{Clock, ManualClock, SystemClock};
pub use config::{GovernorConfig, PolicyDecl};
pub use error::GovernorError;
pub use policy::{ApprovalPolicy, CompositePolicy, Policy, RateLimitPolicy, ReadOnlyPolicy, TimeWindowPolicy};

/// The decision point: a policy, an audit sink, and a clock.
///
/// [`Governor::decide`] is the only way actions get verdicts in production
/// use: it evaluates the policy and records the decision atomically-ish —
/// a failing sink fails the decision, because an audit trail with holes is
/// not an audit trail.
///
/// The clock stamps audit entries. Inject [`ManualClock`] in tests,
/// [`SystemClock`] in production.
///
/// Generic over the three collaborators so tests keep concrete access to the
/// sink (e.g. [`VecSink::entries`]) without downcasting.
pub struct Governor<P: Policy, S: AuditSink, C: Clock> {
    policy: P,
    sink: S,
    clock: C,
}

impl<P: Policy, S: AuditSink, C: Clock> Governor<P, S, C> {
    /// Builds a governor from a policy, a sink, and a clock.
    pub fn new(policy: P, sink: S, clock: C) -> Self {
        Self { policy, sink, clock }
    }

    /// Evaluates `action` and records the decision.
    ///
    /// Returns the verdict. The audit entry is written before returning, so a
    /// caller holding the verdict knows it was recorded.
    ///
    /// # Errors
    ///
    /// [`GovernorError::Audit`] if the sink fails. The policy itself is
    /// infallible by construction — policies return verdicts, not results.
    pub fn decide(&mut self, action: &Action) -> Result<Verdict, GovernorError> {
        let verdict = self.policy.evaluate(action);
        self.sink.record(AuditEntry::new(
            action.clone(),
            verdict.clone(),
            self.clock.now_unix_secs(),
        ))?;
        Ok(verdict)
    }

    /// Names the policy chain backing this governor.
    pub fn policy_name(&self) -> &str {
        self.policy.name()
    }

    /// The audit sink, for inspecting recorded entries in tests.
    pub fn sink(&self) -> &S {
        &self.sink
    }

    /// The clock, for advancing time in tests.
    pub fn clock(&self) -> &C {
        &self.clock
    }
}
