//! Built-in policies. Each is a deterministic, pure function of the action
//! (plus its own configuration and, for time-based policies, the clock).
//!
//! Policies compose via [`CompositePolicy`]: the first non-allow verdict in
//! chain order wins. **Order is the policy** — put hard denies before soft
//! queues when a refusal must beat a parking decision, and vice versa.

use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::Mutex;

use crate::action::{Action, Refusal, Verdict};
use crate::clock::Clock;
use crate::error::GovernorError;

/// A deterministic policy: pure function from action to verdict.
///
/// Implementations must not perform I/O, consult the network, or depend on
/// ambient state beyond their configuration and injected clock. Object-safe
/// so policies can be boxed and composed dynamically.
pub trait Policy: Send + Sync {
    /// Evaluates `action`, returning exactly one [`Verdict`].
    fn evaluate(&self, action: &Action) -> Verdict;
    /// Human-readable name, pinned into every [`Refusal`] this policy emits.
    fn name(&self) -> &str;
}

/// Allows a fixed set of operations; denies everything else.
///
/// The set is explicit and closed: anything not listed is refused by
/// definition. There is no "the caller claimed it's safe" branch — compare
/// annotation-driven classification, which trusts the thing being classified.
pub struct ReadOnlyPolicy {
    name: String,
    allowed_ops: HashSet<String>,
}

impl ReadOnlyPolicy {
    /// Builds a policy allowing exactly `allowed_ops`.
    ///
    /// Despite the name, the operation list need not be reads — it is simply
    /// the closed allow-set. An empty set denies everything ("locked" mode).
    pub fn new(name: &str, allowed_ops: &[&str]) -> Self {
        Self {
            name: name.to_string(),
            allowed_ops: allowed_ops.iter().map(|s| s.to_string()).collect(),
        }
    }
}

impl Policy for ReadOnlyPolicy {
    fn name(&self) -> &str {
        &self.name
    }

    fn evaluate(&self, action: &Action) -> Verdict {
        if self.allowed_ops.contains(&action.operation) {
            Verdict::Allow
        } else {
            Verdict::Deny(Refusal::new(
                &self.name,
                format!(
                    "operation `{}` on `{}` is not in the allow set",
                    action.operation, action.resource
                ),
            ))
        }
    }
}

/// Queues a fixed set of operations for approval; passes everything else through.
///
/// Listed operations are parked, never silently allowed and never silently
/// denied — a human (or a higher policy) decides. Unlisted operations pass
/// through untouched, so this policy composes safely at any chain position.
pub struct ApprovalPolicy {
    name: String,
    queued_ops: HashSet<String>,
}

impl ApprovalPolicy {
    /// Builds a policy queueing exactly `queued_ops` for approval.
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
            Verdict::QueueForApproval(Refusal::new(
                &self.name,
                format!(
                    "operation `{}` on `{}` requires approval",
                    action.operation, action.resource
                ),
            ))
        } else {
            Verdict::Allow
        }
    }
}

/// Allows actions only inside a daily UTC time window; denies the rest.
///
/// The window is `[start_hour, end_hour)` in hours since UTC midnight.
/// Useful for "business hours only" write policies or maintenance blackouts
/// (invert by placing it before a permissive policy — order is the policy).
pub struct TimeWindowPolicy<C: Clock> {
    name: String,
    start_hour: u8,
    end_hour: u8,
    clock: C,
}

impl<C: Clock> TimeWindowPolicy<C> {
    /// Builds a policy allowing actions when the UTC hour is in
    /// `[start_hour, end_hour)`.
    ///
    /// # Errors
    ///
    /// Returns [`GovernorError::InvalidPolicy`] if either hour exceeds 23 or
    /// `start_hour >= end_hour`. Windows may not wrap midnight — split them
    /// into two policies instead; explicit beats clever.
    pub fn new(name: &str, start_hour: u8, end_hour: u8, clock: C) -> Result<Self, GovernorError> {
        if start_hour > 23 || end_hour > 23 {
            return Err(GovernorError::InvalidPolicy(format!(
                "[{name}] hours must be 0..=23, got {start_hour}..{end_hour}"
            )));
        }
        if start_hour >= end_hour {
            return Err(GovernorError::InvalidPolicy(format!(
                "[{name}] start_hour ({start_hour}) must be < end_hour ({end_hour}); split wrapping windows in two"
            )));
        }
        Ok(Self {
            name: name.to_string(),
            start_hour,
            end_hour,
            clock,
        })
    }
}

impl<C: Clock> Policy for TimeWindowPolicy<C> {
    fn name(&self) -> &str {
        &self.name
    }

    fn evaluate(&self, action: &Action) -> Verdict {
        let hour = (self.clock.now_unix_secs() % 86_400 / 3_600) as u8;
        if hour >= self.start_hour && hour < self.end_hour {
            Verdict::Allow
        } else {
            Verdict::Deny(Refusal::new(
                &self.name,
                format!(
                    "action on `{}` outside allowed window {:02}:00–{:02}:00 UTC (now {:02}:00)",
                    action.resource, self.start_hour, self.end_hour, hour
                ),
            ))
        }
    }
}

/// Caps actions per domain to `max_calls` per `window_secs` sliding window.
///
/// Buckets are per-domain, so one noisy integration can't starve the others.
/// Attempts count against the budget whether allowed or denied — probing the
/// limit is itself load, and a client hammering a denied endpoint stays
/// throttled rather than getting a fresh budget to probe with.
///
/// Window semantics: a timestamp exactly `window_secs` old is expired (the
/// window is `[now - window_secs + 1, now]`). Time resolution is whole
/// seconds — bursts within one second share a timestamp, which is fine for
/// policy gating but not for sub-second traffic shaping.
///
/// Clock skew: if the clock moves backwards, affected entries linger until
/// time catches up (the limiter stays conservative — it denies more, never
/// less). Prefer a monotonic source where available.
///
/// State lives behind a mutex; lock poisoning is recovered rather than
/// panicked — a wedged limiter must fail closed (deny), not crash the
/// governor.
pub struct RateLimitPolicy<C: Clock> {
    name: String,
    max_calls: u32,
    window_secs: u64,
    clock: C,
    hits: Mutex<HashMap<String, VecDeque<u64>>>,
}

impl<C: Clock> RateLimitPolicy<C> {
    /// Builds a policy allowing `max_calls` actions per `window_secs` seconds,
    /// tracked separately per action domain.
    ///
    /// # Errors
    ///
    /// Returns [`GovernorError::InvalidPolicy`] if `max_calls` is 0 or
    /// `window_secs` is 0.
    pub fn new(
        name: &str,
        max_calls: u32,
        window_secs: u64,
        clock: C,
    ) -> Result<Self, GovernorError> {
        if max_calls == 0 {
            return Err(GovernorError::InvalidPolicy(format!(
                "[{name}] max_calls must be > 0"
            )));
        }
        if window_secs == 0 {
            return Err(GovernorError::InvalidPolicy(format!(
                "[{name}] window_secs must be > 0"
            )));
        }
        Ok(Self {
            name: name.to_string(),
            max_calls,
            window_secs,
            clock,
            hits: Mutex::new(HashMap::new()),
        })
    }
}

impl<C: Clock> Policy for RateLimitPolicy<C> {
    fn name(&self) -> &str {
        &self.name
    }

    fn evaluate(&self, action: &Action) -> Verdict {
        let now = self.clock.now_unix_secs();
        // Recover from poisoning: a wedged bucket denies, it never crashes.
        let mut hits = self.hits.lock().unwrap_or_else(|e| e.into_inner());
        let bucket = hits.entry(action.domain.clone()).or_default();
        while bucket.front().is_some_and(|&t| now.saturating_sub(t) >= self.window_secs) {
            bucket.pop_front();
        }
        bucket.push_back(now);
        if bucket.len() as u32 > self.max_calls {
            Verdict::Deny(Refusal::new(
                &self.name,
                format!(
                    "domain `{}` exceeded {} calls per {}s",
                    action.domain, self.max_calls, self.window_secs
                ),
            ))
        } else {
            Verdict::Allow
        }
    }
}

/// Chains policies in a fixed order. The first non-allow verdict wins.
///
/// Order is the policy: a [`ReadOnlyPolicy`] deny placed before an
/// [`ApprovalPolicy`] shadows that policy's queue for the same action, and
/// vice versa. If every policy allows, the composite allows. An empty chain
/// allows everything (useful as a documented "no policy" default, not as an
/// accident — construct it deliberately).
pub struct CompositePolicy {
    name: String,
    policies: Vec<Box<dyn Policy>>,
}

impl CompositePolicy {
    /// Builds a chain evaluated in `policies` order.
    pub fn new(name: &str, policies: Vec<Box<dyn Policy>>) -> Self {
        Self {
            name: name.to_string(),
            policies,
        }
    }

    /// Names of the chained policies, in evaluation order.
    pub fn policy_names(&self) -> Vec<&str> {
        self.policies.iter().map(|p| p.name()).collect()
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
