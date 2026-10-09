# LUCIDOTA on Cloudflare OS

We fork Cloudflare OS to study — and out-build — the closest thing to our thesis
from a major player.

## Why we forked

Agent chat + sandboxed gadgets + Gatekeepers. That's our stack with different names:
- Their **gadgets** are our **organelles**
- Their **Gatekeepers** are our **governor**
- Their **skills** are our distributable units

They validated the thesis. Now we build the Rust-first, receipt-grade version.

## What we're stealing (with respect)

- **The Gatekeeper package structure** — per-domain policy packages with a common
  framework. Ours will be leaner and deterministic-first.
- **The skills navigator UX** — for our organelle registry.
- **Hook patterns** — event-driven agent triggers, same instinct as our eventd.

## What we're building

- A Rust governor that enforces Gatekeeper-equivalent policy deterministically.
- Gadgets that produce proof-ledger receipts for everything they do.
- The CuteCity take: same shape, harder guarantees.

## Branches

- `main` — pure upstream mirror, auto-synced daily. Don't touch.
- `lucidota` — our direction. You're here.

## Road to total conversion

The AI productivity OS where every agent action is bounded, auditable, and reproducible —
and the user holds the keys, not the platform.
