# SPEC: Gatekeeper Analysis + Rust Governor Sketch

**Fork:** mfspxz/cloudflare-os · **Branch:** lucidota · **Budget:** 50 iterations

## Goal

Two parts: (1) a real comparative analysis of the Gatekeeper pattern vs our governor
concept, and (2) a minimal deterministic Rust policy engine that implements the
Gatekeeper interface. Understand theirs, sketch ours.

## Non-goals

- Modifying cloudflare-os. Analysis + standalone sketch only.
- A full governor. This is the kernel of the idea, not the product.

## Part 1: Analysis — `GATEKEEPER-ANALYSIS.md`

Read the actual code (not just docs) and answer:

1. **Policy model**: How does a Gatekeeper express policy? (per-integration packages,
   `provisioning-policy.ts` three-state modes, `getGatekeeperClassFor()` chokepoint)
2. **Trust boundaries**: Where are the trust boundaries? (The `tools.ts` readOnlyHint
   rule, the capability-as-authority model, `connectHandoffPageHtml` flow)
3. **Ambient authority**: How do "ambient" gatekeepers work? What prevents a gatekeeper
   from asserting its own ambience?
4. **Approval flow**: How do queued actions work? What's the UX for approval?
5. **What we'd steal**: The 3 most valuable architectural decisions, with file references.
6. **What we'd do differently**: Where determinism (our governor) beats their model.

Minimum 1500 words. Cite files. No vibes.

## Part 2: Rust governor sketch — `governor-sketch/`

A standalone Rust crate (not in their workspace — put it at `governor-sketch/`):

```rust
pub enum Verdict { Allow, Deny(String), QueueForApproval(String) }

pub trait Policy {
    fn evaluate(&self, action: &Action) -> Verdict;
}

pub struct Action {
    pub domain: String,    // e.g. "github", "email"
    pub operation: String, // e.g. "read", "send"
    pub resource: String,  // e.g. "repo:foo", "to:bar@x.com"
}
```

- Three example policies:
  - `ReadOnlyPolicy` — allows reads, denies writes with a reason
  - `ApprovalPolicy` — queues specified operations for approval
  - `CompositePolicy` — chains policies (first non-Allow wins)
- Unit tests for each policy + the composite.
- `cargo test` green.

## Acceptance criteria

- [ ] `GATEKEEPER-ANALYSIS.md` — 1500+ words, file-cited, covers all 6 questions
- [ ] `governor-sketch/` — Rust crate, `cargo test` green, all three policies + composite tested
- [ ] No changes to cloudflare-os core

## Constraints

- The sketch is standalone Rust (not pnpm workspace). `cargo` only.
- Never `reset`/`force-push`. Commit on the `lucidota` branch only.
