# Gatekeeper Analysis: cloudflare-os vs. the Governor

**Date:** 2026-10-09 · **Fork:** mfspxz/cloudflare-os · **Branch:** lucidota
**Scope:** Read the actual code, not the marketing. Six questions, file-cited, no vibes.

---

## 1. Policy model: how a Gatekeeper expresses policy

A Gatekeeper is a Cloudflare Worker that mediates **all** access between a Gadget
(an agent-built app) and an external service. The architecture is a strict
three-tier hierarchy, spelled out in `.agents/skills/write-gatekeeper/SKILL.md`:

- **Vendor** (`GatekeeperVendor`, a `WorkerEntrypoint`) — the top-level entry for one
  service. One per service.
- **User** (`GatekeeperUser`, a `WorkerEntrypoint` with `ctx.props`) — one human user's
  authenticated connection: token storage, refresh, revocation, all in a `UserAccount`
  Durable Object.
- **Instance** (`Gatekeeper<Session>`, a DO facet of the Overseer) — a per-resource,
  per-Gadget binding exposing the Session API.

Each integration is its own package: `packages/gatekeeper-github/`,
`packages/gatekeeper-gitlab/`, `packages/gatekeeper-google/`,
`packages/gatekeeper-email/`, `packages/mcp-shared/`, and about fifteen others.
Policy is therefore **expressed per integration, in code, not in config**. There is
no central policy language. The "policy" of the GitHub gatekeeper is whatever
`packages/gatekeeper-github/src/` implements: which URL patterns map to which
resource granularities, which operations are observations vs. actions, which
observer-verification strategy it uses. This is deliberate — the SKILL.md insists
the API design is "the most important and delicate part" and requires the operator
to review the proposed `types.d.ts` before any implementation proceeds. Policy
lives in the type signatures.

Two cross-cutting policy mechanisms sit above the per-integration code:

**Provisioning policy** (`packages/workshop-backend/src/provisioning-policy.ts`).
For auto-provisioning ("ambient") vendors — those whose `VendorDescription`
declares `autoProvisionsAccount`, e.g. the Context Library — the deployment admin
sets a three-state mode in `AdminConfig.ambientGatekeeperModes`:

- `disabled` — not offered; existing accounts go dormant.
- `optional` — users opt in from the Connectors page. **The default.** The file's
  own comment: "we don't impose ambient authority on every user unless an admin
  explicitly turns it on."
- `enabled` — auto-provisioned for every user, forced, not user-removable, hidden
  from the Connectors list.

The helpers (`ambientGatekeeperMode()`, `shouldAutoProvisionAccount()`) are
described as "the single chokepoint for that decision."

**The capability-minting chokepoint** (`packages/workshop-backend/src/user.ts`,
`getGatekeeperClassFor()`, ~line 1892). This is where a `resourceUrl` becomes a
capability, and the code comments say exactly what it is: "Block whole gatekeepers
+ disabled resources at this single core-side chokepoint where a resourceUrl
becomes a capability (reached only via the user/UI-facing Overseer.newGatekeeper
and blueprint instantiation — never from gadget or agent code)." It checks
`config.disabledGatekeepers` and the ambient mode, then `isResourceDisabled()`,
and throws otherwise. The comment is explicit about the threat model: "Blocking
here prevents minting a new capability to a disabled resource even if the request
bypasses the (separately filtered) picker/agent listings." In other words: UI
filtering is defense-in-depth; the chokepoint is the real enforcement.

So the policy model is: **per-integration code policy** (API shape, observation/
action classification, observer strategy) + **deployment-level admin policy**
(disabled gatekeepers, disabled resources, ambient modes) + **one hard chokepoint**
where URLs become capabilities. There is no declarative policy DSL anywhere.

## 2. Trust boundaries

The sharpest trust boundary in the codebase is stated in one line at the top of
`packages/mcp-shared/src/tools.ts`: *"The trust boundary: what an MCP server says
about its own tools becomes what a Gadget may do. Nothing outside this file reads
a tool's `annotations`."*

`classifyTool()` is the single place a server's self-description becomes a policy
decision, and its logic is worth quoting in full because it encodes the entire
trust model:

- `readOnlyHint === true` → `mode: "read"` — runs immediately, recorded as an
  observation. Honored on **both** trust tiers.
- Anything else → `mode: "action"` — goes to the approval queue.
- `autoApprovable` (no prompt at all) requires **all of**: not read-only,
  `trust === "vetted"`, `destructiveHint === false`, `idempotentHint === true`.

The two tiers (`ServerTrust = "vetted" | "byo"`): `vetted` means an administrator
asserted the endpoint's annotations are reliable; `byo` means a user pasted the
URL in. The file is admirably honest about the tradeoff: "Honouring `readOnlyHint`
on `byo` is a knowing departure from treating annotations as wholly untrusted…
a tool the server mislabels runs with no approval, where an unlabelled one would
have been queued." Every test is `=== true`/`=== false`, never truthiness, so an
unannotated tool "comes out as an action that can never auto-apply."

Two more boundary mechanisms deserve mention. `catalogRevision()` builds a
SHA-256 fingerprint over each tool's name plus every annotation that feeds a
policy decision (`policyClaims()` covers `readOnlyHint`, `destructiveHint`,
`idempotentHint` in tri-state, so a server *starting or stopping* a claim is
visible). Descriptions are excluded so copy edits don't fire the signal. This is
change-detection on the trust boundary itself: if the endpoint changes under you,
the deployment knows.

And the capability-as-authority model runs through everything. The overseer's
`ensureAmbientCapsules()` comment states it plainly: "The session is reached
through the owner's stored connected account, not by asserting the owner's
identity to the vendor — so the capability is the account the user actually
holds." Authority is the unforgeable reference you hold, never a claim about who
you are.

The connect flow (`docs/connect-handoff.md`) is a masterclass in capability
hygiene. A connect URL is a bearer capability, so finishing the flow must
activate nothing by itself. The defense is a **ticket + nonce** pair: the ticket
is a fresh 256-bit secret (only its SHA-256 hash stored, single-use, two-minute
expiry); the nonce lives in the *popup's* sessionStorage, never the opener's.
The ticket is redeemed over the initiating user's own authenticated session
(`AuthenticatedApi.completeConnectHandoff`), and the nonce binds redemption to
the exact popup the Workshop opened — a handoff link opened any other way holds
no nonce and redeems nothing. The ticket travels only in the URL fragment (never
sent to a server, never in Referer, stripped via `history.replaceState` on read).
The doc even explains why not `postMessage`/opener/`BroadcastChannel`: reverse
tabnabbing through provider pages, COOP isolation, and a second transport to
secure. This is the level of care the trust boundaries get.

## 3. Ambient authority

"Ambient" gatekeepers are the auto-provisioning kind: vendors whose
`VendorDescription` declares `autoProvisionsAccount` mint a connected account
with no OAuth flow (the Context Library is the canonical example). Whether that
account actually materializes for a user is governed by the three-state
provisioning policy (§1), defaulting to `optional`.

When active, `ensureAmbientCapsules()` in
`packages/workshop-backend/src/overseer.ts` (~line 6940) provisions each
singleton account "for this gadget as an ambient gatekeeper record, folded into
each chat's env (named by the gatekeeper's suggested binding name; see
`prepareChatBindings`) so the agent can read it in `executeCode`." Reads are
recorded as observations. The agent may wire it into a gadget via
`setGadgetBinding` if the gadget's persistent code needs it — but "most gadgets
never call the library programmatically, so a gadget binding would just be
noise." The records are reconciled idempotently: keyed to specific accountIds,
stale records (disconnected or replaced accounts) are removed so a capsule never
points at a deleted account.

What prevents a gatekeeper from asserting its own ambience? The AGENTS.md states
the rule as a capability-security invariant: *"a resource becomes 'ambient'
(auto-injected) only by user/admin configuration — a gatekeeper must never
assert its own ambience."* Mechanically: ambience is decided by
`AdminConfig.ambientGatekeeperModes` (admin) and the Connectors opt-in (user),
read through the `provisioning-policy.ts` chokepoint. The gatekeeper's own
`VendorDescription.autoProvisionsAccount` is merely a *declaration of
capability* ("I can mint accounts without OAuth"); the *decision* to do so, for
whom, and in what mode, lives entirely outside the gatekeeper's code. A
gatekeeper cannot reach into `prepareChatBindings` or `ensureAmbientCapsules`
— those are overseer functions. The trust flows one way: configuration grants,
code obeys.

## 4. Approval flow

The `ApprovalQueue` interface (`packages/workshop-shared/src/gatekeeper.ts`,
~line 1070) is the contract every gatekeeper implements. Three primitives:

- `authorizeObservation()` — for reads. Must be awaited before returning data to
  the caller (it may be called after fetching, so the description can include
  what was fetched). Records what the *caller* learned, not what the gatekeeper
  read internally. The SKILL.md's "what counts as an observation" section is a
  careful epistemology: reads that only prepare an action aren't observations;
  session setup isn't; existence checks on high-entropy IDs aren't (one bit that
  encodes nothing); but a returned boolean or count *is* data when it's the
  answer asked for.
- `submitAction()` — for anything with externally-visible side effects. Fully
  asynchronous: "returns immediately… but the action may not actually be carried
  out until much later… hours or days later." Nothing is performed until
  `applyAction()` is called. Rejection calls `rejectAction()`.
- `bindHook()` — for persistent push-notification callbacks, themselves subject
  to approval before `controller.enable()`.

The killer feature is **simulation** (SKILL.md, Phase 2): "Actions submitted but
not yet applied should be simulated as if they already occurred, to the maximum
extent reasonable." Two implementations: mutate the cache on submit (revert on
reject), or overlay pending actions at read time. The point is that *the agent
doesn't know the approval queue exists* — it keeps working, reads see the
pending state, and the user batch-approves later. The agent-facing `types.d.ts`
never mentions approvals; "correct simulation keeps this invisible."

The approval prompt itself is rendered by `describeCall()` in `tools.ts`: server
name, tool name, endpoint, full arguments as JSON, and a provenance paragraph
that tells the approver exactly whose word the classification rests on ("The
server declares this tool read-only… That claim comes from the server itself."
vs. "Treated as an action because the server did not declare it read-only.
Nothing has been sent yet."). The arguments are the agent's text — "the agent
is who this prompt protects the user from" — so the approver sees every byte.

UX summary: reads flow immediately (logged); writes queue; the agent works
against simulated state; the human approves in batches, possibly much later.
Approval is the slow path and the system is designed so nothing blocks on it.

## 5. What we'd steal

**Steal #1: The single chokepoint where URLs become capabilities.**
`getGatekeeperClassFor()` in `user.ts` is the pattern to copy verbatim in
spirit: one function, reachable only from user/UI-facing paths, never from
agent code, where every disable list and mode check runs before a capability is
minted. Our governor needs exactly this shape — a `Policy::evaluate()` that is
the *only* path from "agent wants to do X" to "X is authorized." The comment
"reached only via the user/UI-facing Overseer.newGatekeeper and blueprint
instantiation — never from gadget or agent code" is the invariant we must
preserve: the policy engine must not be callable by the thing being policed.

**Steal #2: Simulation of pending actions.** The insight that the approval queue
should be invisible to the agent — reads reflect submitted-but-unapplied state —
is what makes human-in-the-loop approval not destroy agent throughput. Our
governor's `QueueForApproval` verdict needs the same property: the agent's
world model must include the queued action's effects, or every approval becomes
a pipeline stall. Their two implementations (cache mutation vs. read-time
overlay) are both worth copying; the overlay is cleaner.

**Steal #3: The trust-tier model + catalog fingerprinting.** `ServerTrust`
(`vetted`/`byo`) with the honest comment about the `readOnlyHint` tradeoff, plus
`catalogRevision()` detecting when an endpoint's claims change under you, is the
right way to handle third-party policy inputs: trust is *declared by the
deployment*, never self-asserted by the server, and changes to the claims are
themselves observable events. Our governor will take policy inputs from less
trusted sources (agent-suggested rules, imported packs); we should fingerprint
them the same way and treat claim-changes as policy events.

## 6. What we'd do differently: where determinism beats their model

Their model is excellent *engineering* with a judgment-shaped hole at its
center, and the hole is load-bearing.

First, the classification of a tool as read-vs-action rests on a server's
self-declared annotation, honored even for untrusted (`byo`) endpoints as "a
knowing departure." That's a policy decision made by the party being policed.
Our governor inverts this: classification is a pure function of (domain,
operation, resource) against an explicit policy set. No annotation, no
self-description, no trust tier can widen a grant — the policy says what a
`read` is, and anything not matching is denied or queued. The `Verdict` enum is
exhaustive: every action gets exactly one of `Allow`, `Deny(reason)`,
`QueueForApproval(reason)`. There is no "the server said so" branch.

Second, their observation model contains acknowledged judgment calls ("Existence
checks are a judgment call, but usually not an observation"). Judgment calls
don't compose and don't audit. Our equivalent — what crosses the membrane gets
logged — is mechanical: if bytes reached the caller, it's an observation. The
governor doesn't decide what "counts"; the membrane does.

Third, their approval queue is human-paced and asynchronous by design ("hours
or days later"). That's correct for their product, but our governor also needs
the *machine-paced* path: policies that decide in microseconds without a human
in the loop, with the decision itself receipted into the proof ledger. Their
`ApprovalQueue` records; ours must also *decide* — deterministically, replayably,
with the policy version pinned to the verdict so any decision can be re-derived
later.

Fourth, policy composition. Their per-integration packages are silos — the
GitHub gatekeeper's policy can't reference the email gatekeeper's. Our
`CompositePolicy` (first non-`Allow` wins, fixed order) gives us cross-domain
rules: "deny `send` on `email` when a `write` on `github` is queued in the same
session" is expressible as a composite, not as fifteen packages that don't know
about each other.

None of this is a criticism of their engineering — the ticket/nonce handoff,
the chokepoint discipline, the simulation design are genuinely excellent. It's a
difference in what the system must guarantee. They guarantee a careful human
stays in control. We guarantee the machine's decisions are reproducible without
one.

---

*Word count: ~2,100. All file references verified against the tree at
`4f55124` + lucidota commits.*
