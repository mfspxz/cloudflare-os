//! Integration tests: the governor as a whole system.
//!
//! Covers config loading from TOML, audit log contents, composite ordering,
//! rate limiting with a manual clock, time windows, and serde round-trips.
//! Time-dependent tests use [`ManualClock`] — nothing here waits on real time.

use governor::{
    Action, ApprovalPolicy, AuditSink, CompositePolicy, Governor, GovernorConfig,
    GovernorError, ManualClock, Policy, RateLimitPolicy, ReadOnlyPolicy, Refusal,
    SystemClock, TimeWindowPolicy, VecSink, Verdict,
};

fn read_action() -> Action {
    Action::new("github", "read", "repo:foo")
}

fn send_action() -> Action {
    Action::new("email", "send", "to:bar@x.com")
}

// ---------------------------------------------------------------------------
// core verdicts
// ---------------------------------------------------------------------------

#[test]
fn read_only_allows_listed_ops() {
    let p = ReadOnlyPolicy::new("ro", &["read", "list", "get"]);
    assert_eq!(p.evaluate(&read_action()), Verdict::Allow);
    assert_eq!(
        p.evaluate(&Action::new("github", "list", "repo:foo")),
        Verdict::Allow
    );
}

#[test]
fn read_only_denies_with_structured_refusal() {
    let p = ReadOnlyPolicy::new("ro", &["read"]);
    match p.evaluate(&send_action()) {
        Verdict::Deny(Refusal { policy, reason }) => {
            assert_eq!(policy, "ro");
            assert!(reason.contains("send"), "reason names the operation");
            assert!(reason.contains("to:bar@x.com"), "reason names the resource");
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
fn approval_queues_listed_ops_and_passes_rest() {
    let p = ApprovalPolicy::new("appr", &["send", "delete"]);
    match p.evaluate(&send_action()) {
        Verdict::QueueForApproval(r) => assert_eq!(r.policy, "appr"),
        other => panic!("expected QueueForApproval, got {other:?}"),
    }
    assert_eq!(p.evaluate(&read_action()), Verdict::Allow);
}

#[test]
fn composite_first_non_allow_wins_both_directions() {
    // queue-first: queue shadows deny
    let c = CompositePolicy::new(
        "q-first",
        vec![
            Box::new(ApprovalPolicy::new("appr", &["send"])),
            Box::new(ReadOnlyPolicy::new("ro", &["read"])),
        ],
    );
    assert!(matches!(
        c.evaluate(&send_action()),
        Verdict::QueueForApproval(_)
    ));
    // deny-first: deny shadows queue
    let c = CompositePolicy::new(
        "d-first",
        vec![
            Box::new(ReadOnlyPolicy::new("ro", &["read"])),
            Box::new(ApprovalPolicy::new("appr", &["send"])),
        ],
    );
    match c.evaluate(&send_action()) {
        Verdict::Deny(r) => assert_eq!(r.policy, "ro"),
        other => panic!("expected Deny from ro, got {other:?}"),
    }
    // all allow -> allow
    assert_eq!(c.evaluate(&read_action()), Verdict::Allow);
}

#[test]
fn composite_empty_allows_and_names_policies() {
    let c = CompositePolicy::new("empty", vec![]);
    assert_eq!(c.evaluate(&read_action()), Verdict::Allow);
    let c2 = CompositePolicy::new(
        "named",
        vec![
            Box::new(ReadOnlyPolicy::new("ro", &["read"])),
            Box::new(ApprovalPolicy::new("appr", &["send"])),
        ],
    );
    assert_eq!(c2.policy_names(), vec!["ro", "appr"]);
}

#[test]
fn verdict_helpers() {
    assert!(Verdict::Allow.is_allow());
    assert!(Verdict::Allow.deciding_policy().is_none());
    let d = Verdict::Deny(Refusal::new("ro", "nope"));
    assert!(!d.is_allow());
    assert_eq!(d.deciding_policy(), Some("ro"));
}

// ---------------------------------------------------------------------------
// time window
// ---------------------------------------------------------------------------

/// 2026-10-09T10:00:00Z — 10:00 UTC.
const TEN_AM: u64 = 1_791_540_000;
/// 2026-10-09T20:00:00Z — 20:00 UTC.
const EIGHT_PM: u64 = 1_791_576_000;

#[test]
fn time_window_allows_inside_denies_outside() {
    let clock = ManualClock::new(TEN_AM);
    let p = TimeWindowPolicy::new("biz", 9, 17, &clock).unwrap();
    assert_eq!(p.evaluate(&read_action()), Verdict::Allow);
    clock.set(EIGHT_PM);
    match p.evaluate(&read_action()) {
        Verdict::Deny(r) => {
            assert_eq!(r.policy, "biz");
            assert!(r.reason.contains("09:00"));
        }
        other => panic!("expected Deny outside window, got {other:?}"),
    }
}

#[test]
fn time_window_rejects_bad_hours() {
    let clock = ManualClock::new(TEN_AM);
    assert!(matches!(
        TimeWindowPolicy::new("bad", 17, 9, &clock),
        Err(GovernorError::InvalidPolicy(_))
    ));
    assert!(matches!(
        TimeWindowPolicy::new("bad", 0, 24, &clock),
        Err(GovernorError::InvalidPolicy(_))
    ));
}

// ---------------------------------------------------------------------------
// rate limit
// ---------------------------------------------------------------------------

#[test]
fn rate_limit_allows_budget_then_denies_then_recovers() {
    let clock = ManualClock::new(1_000_000);
    let p = RateLimitPolicy::new("rl", 2, 60, &clock).unwrap();
    assert_eq!(p.evaluate(&read_action()), Verdict::Allow);
    assert_eq!(p.evaluate(&read_action()), Verdict::Allow);
    match p.evaluate(&read_action()) {
        Verdict::Deny(r) => assert!(r.reason.contains("github")),
        other => panic!("expected Deny over budget, got {other:?}"),
    }
    // other domains have their own budget
    assert_eq!(
        p.evaluate(&Action::new("email", "read", "inbox")),
        Verdict::Allow
    );
    // window slides: advance past 60s, budget returns
    clock.advance(61);
    assert_eq!(p.evaluate(&read_action()), Verdict::Allow);
}

#[test]
fn rate_limit_rejects_zero_params() {
    let clock = ManualClock::new(0);
    assert!(matches!(
        RateLimitPolicy::new("rl", 0, 60, &clock),
        Err(GovernorError::InvalidPolicy(_))
    ));
    assert!(matches!(
        RateLimitPolicy::new("rl", 5, 0, &clock),
        Err(GovernorError::InvalidPolicy(_))
    ));
}

// ---------------------------------------------------------------------------
// governor + audit
// ---------------------------------------------------------------------------

#[test]
fn governor_records_every_decision_with_timestamp() {
    let clock = ManualClock::new(5_000);
    let mut gov = Governor::new(
        CompositePolicy::new(
            "chain",
            vec![
                Box::new(ApprovalPolicy::new("appr", &["send"])),
                Box::new(ReadOnlyPolicy::new("ro", &["read"])),
            ],
        ),
        VecSink::new(),
        clock,
    );
    gov.decide(&read_action()).unwrap();
    gov.clock().advance(10);
    gov.decide(&send_action()).unwrap();

    let entries = &gov.sink().entries;
    assert_eq!(entries.len(), 2);
    assert_eq!(entries[0].action, read_action());
    assert_eq!(entries[0].verdict, Verdict::Allow);
    assert_eq!(entries[0].ts_unix_secs, 5_000);
    assert_eq!(entries[1].ts_unix_secs, 5_010);
    match &entries[1].verdict {
        Verdict::QueueForApproval(r) => assert_eq!(r.policy, "appr"),
        other => panic!("expected queue, got {other:?}"),
    }
}

#[test]
fn governor_names_its_policy() {
    let gov = Governor::new(
        ReadOnlyPolicy::new("ro", &["read"]),
        VecSink::new(),
        SystemClock,
    );
    assert_eq!(gov.policy_name(), "ro");
}

struct FailingSink;

impl AuditSink for FailingSink {
    fn record(&mut self, _e: governor::AuditEntry) -> Result<(), GovernorError> {
        Err(GovernorError::Audit("disk full".into()))
    }
}

#[test]
fn failing_sink_fails_the_decision() {
    let mut gov = Governor::new(
        ReadOnlyPolicy::new("ro", &["read"]),
        FailingSink,
        SystemClock,
    );
    assert!(matches!(
        gov.decide(&read_action()),
        Err(GovernorError::Audit(_))
    ));
}

// ---------------------------------------------------------------------------
// config
// ---------------------------------------------------------------------------

const SAMPLE_TOML: &str = r#"
[[policy]]
type = "read_only"
name = "ro"
read_ops = ["read", "list"]

[[policy]]
type = "approval"
name = "appr"
queued_ops = ["send", "delete"]
"#;

#[test]
fn config_loads_and_builds_ordered_chain() {
    let cfg = GovernorConfig::from_toml_str(SAMPLE_TOML).unwrap();
    let chain = cfg.build().unwrap();
    assert_eq!(chain.policy_names(), vec!["ro", "appr"]);

    let mut gov = Governor::new(chain, VecSink::new(), SystemClock);
    // read: ro allows
    assert_eq!(gov.decide(&read_action()).unwrap(), Verdict::Allow);
    // send: ro denies first (deny shadows queue — file order is the policy)
    match gov.decide(&send_action()).unwrap() {
        Verdict::Deny(r) => assert_eq!(r.policy, "ro"),
        other => panic!("expected Deny, got {other:?}"),
    }
    // every decision audited
    assert_eq!(gov.sink().entries.len(), 2);
}

#[test]
fn config_rejects_bad_toml_and_bad_params() {
    assert!(matches!(
        GovernorConfig::from_toml_str("[[policy]"),
        Err(GovernorError::ConfigParse(_))
    ));
    let bad = r#"
[[policy]]
type = "time_window"
name = "bad"
start_hour = 18
end_hour = 9
"#;
    let cfg = GovernorConfig::from_toml_str(bad).unwrap();
    assert!(matches!(
        cfg.build(),
        Err(GovernorError::InvalidPolicy(_))
    ));
}

#[test]
fn config_from_file_round_trip() {
    // NOTE: /tmp is a 512M tmpfs that fills up; use the crate dir instead.
    // Cargo runs integration tests with CWD = the crate root.
    let dir = std::env::current_dir()
        .unwrap()
        .join(format!("test-tmp-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("gov.toml");
    std::fs::write(&path, SAMPLE_TOML).unwrap();

    let cfg = GovernorConfig::from_file(path.to_str().unwrap()).unwrap();
    assert_eq!(cfg.policy.len(), 2);

    assert!(matches!(
        GovernorConfig::from_file("/nonexistent/governor.toml"),
        Err(GovernorError::ConfigRead { .. })
    ));
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn config_with_time_and_rate_policies() {
    let toml = r#"
[[policy]]
type = "time_window"
name = "biz"
start_hour = 9
end_hour = 17

[[policy]]
type = "rate_limit"
name = "rl"
max_calls = 100
window_secs = 60
"#;
    let chain = GovernorConfig::from_toml_str(toml).unwrap().build().unwrap();
    assert_eq!(chain.policy_names(), vec!["biz", "rl"]);
}

// ---------------------------------------------------------------------------
// serde
// ---------------------------------------------------------------------------

#[test]
fn action_and_verdict_json_round_trip() {
    let a = read_action();
    let json = serde_json::to_string(&a).unwrap();
    assert!(json.contains("\"domain\":\"github\""));
    let back: Action = serde_json::from_str(&json).unwrap();
    assert_eq!(a, back);

    let v = Verdict::Deny(Refusal::new("ro", "nope"));
    let json = serde_json::to_string(&v).unwrap();
    assert!(json.contains("\"verdict\":\"deny\""));
    assert!(json.contains("\"policy\":\"ro\""));
    let back: Verdict = serde_json::from_str(&json).unwrap();
    assert_eq!(v, back);

    let v = Verdict::QueueForApproval(Refusal::new("appr", "wait"));
    let json = serde_json::to_string(&v).unwrap();
    assert!(json.contains("\"verdict\":\"queue_for_approval\""));
    let back: Verdict = serde_json::from_str(&json).unwrap();
    assert_eq!(v, back);

    let json = serde_json::to_string(&Verdict::Allow).unwrap();
    assert_eq!(json, r#"{"verdict":"allow"}"#);
}

#[test]
fn audit_entry_json_shape() {
    let e = governor::AuditEntry::new(read_action(), Verdict::Allow, 12345);
    let json = serde_json::to_string(&e).unwrap();
    assert!(json.contains("\"ts_unix_secs\":12345"));
    let back: governor::AuditEntry = serde_json::from_str(&json).unwrap();
    assert_eq!(e, back);
}
