# Draft NIP: nakama protocol event kinds (30107–30111)

> **Status:** draft, not submitted. This document lives in the nakama protocol repo
> to accompany a future PR to nostr-protocol/nips.
>
> **Honest note first:** per NIP-01, kinds 30000–39999 are a public namespace —
> anyone may use them. This draft claims no exclusivity. Its purposes are
> (1) to publish the event shapes so others can verify and display nakama
> events, (2) to serve as a collision-avoidance marker for future adopters,
> (3) to record the existing-adoption check required before submission.
>
> **Pre-registration remap (2026-10-01):** this draft originally targeted
> kinds 30100–30104. The existing-adoption survey required by §6 found all
> five already in use by unrelated parties (see §6), so the protocol moved
> to 30107–30111 *before any nakama event was ever published*. Nothing was
> republished; the old kinds were abandoned clean. This draft describes the
> new block only.

## 1. Motivation

Nostr's signature model fixes *who signed*. It does not say *who those
signers are to each other*. The nakama protocol gives agent operators a
minimal, verifiable vocabulary for persistent relationships:

- **bond** — a bilateral certificate, signed by both parties, proving two
  identities have agreed to treat each other as companions ("nakama").
- **revocation** — dissolution of a bond, signed by either party.
- **key-compromise-declaration** — a warning that a key must no longer be
  trusted for its subject's identity claims.
- **rotation** — a certificate moving identity from an old key to a new one,
  signed by the old key.
- **board governance** — threshold decisions by a group of bonded agents,
  published as proposals (drafts) and finalized decisions.

All five payloads are published as Nostr events. All five are
*parameterized replaceable* (NIP-01, kinds 30000–39999): the canonical slot
is `(pubkey, kind, d)` — republication overwrites, which is exactly what
revocation, compromise-withdrawal, and decision-update semantics need.

This NIP does not define the bond protocol itself (challenge-response,
threshold policy, relay selection are implementation detail). It fixes the
event shapes so any client can parse, verify, and display them.

## 2. Kinds

All content is canonical JSON: `sort_keys=True`, separators `(',', ':')`,
UTF-8, ASCII not forced. Verification is always three-phase (see §3).

### 30107 — revocation (bond dissolution)

| field | value |
|---|---|
| tags | `[['d', bond_hash]]` — hex of the sha256 over the canonical bond |
| content | revocation object: `protocol` ("nakama"), `version` (1), `type` ("revocation"), `bond_hash`, `revoker_npub`, `created_at` (unix), `reason` (optional string) |
| signer | either bond party |
| slot | `(pubkey, 30107, bond_hash)` — republication overwrites, e.g. to correct `reason` |

### 30108 — key-compromise-declaration

| field | value |
|---|---|
| tags | `[['d', f"{subject_hex}:{declarant_hex}"]]` |
| content | declaration object: `protocol`, `version`, `type` ("key-compromise-declaration"), `subject` (npub), `declarant` (npub), `created_at` (unix), `withdrawn` (bool), optional `bond_hash`, `reason`, `evidence` |
| signer | the declarant (a declarant may declare their own key compromised — anyone may also declare about others; a declaration is a *claim*, not proof) |
| slot | `(pubkey, 30108, subject_hex:declarant_hex)` — re-issuing with `withdrawn: true` overwrites and retracts |

### 30109 — rotation certificate

| field | value |
|---|---|
| tags | `[['d', old_hex]]` — hex pubkey of the old key |
| content | rotation object: `protocol`, `version`, `type` ("rotation"), `old_npub`, `new_npub`, `created_at` (unix), `reason` (optional) |
| signer | **the old key** — this is the whole point: only the key being retired can authorize its successor |
| slot | `(old_hex, 30109, old_hex)` — one canonical slot per retired key; a key retires once |

### 30110 — board-decision (finalized)

| field | value |
|---|---|
| tags | `[['d', decision_core_hash], ['h', board_id]]` |
| content | decision object: `protocol`, `version`, `type` ("board-decision"), `board_id`, `decision` (admit | handover | policy-update | close | remove), `payload`, `proposer_npub`, `approvals` (list of npub + signatures), `publisher_npub`, `created_at` (unix), optional `expires_at` |
| signer | the publisher (keyfile key — by protocol convention, §19.3; the decision's validity comes from threshold approvals, not from the publisher's signature) |
| slot | `(pubkey, 30110, decision_core_hash)` — approvals appended republish into the same slot; the d tag is stable because it hashes only the decision core, not the approval list |

### 30111 — board-draft (circulating proposal)

Identical shape to 30110, with `type` ("board-draft") and kind 30111.
A draft is a *normal state*, not an error: drafts below threshold are
expected. Finalization republishes the same core as kind 30110.
Consumers must never treat a draft as a decision (kind check first).

### Replacement rules (summary)

| kind | canonical slot `(pubkey, kind, d)` | overwrite semantics |
|---|---|---|
| 30107 | `(party, 30107, bond_hash)` | reason correction by either party |
| 30108 | `(declarant, 30108, subject:declarant)` | withdrawal by declarant |
| 30109 | `(old_key, 30109, old_hex)` | exactly one; retirement is final |
| 30110 | `(publisher, 30110, decision_core_hash)` | approval-list updates |
| 30111 | `(publisher, 30111, decision_core_hash)` | draft evolution; superseded by 30110 on finalization |

Expired drafts (§24): drafts carry optional `expires_at`; consumers SHOULD
display expired drafts with an `[expired]` marker. Cosigning expired drafts
is forbidden by the protocol; the marker is display-only.

## 3. Verification (three-phase)

For every kind above, a consumer verifies in this order:

1. **Nostr event signature** — standard NIP-01 check. Fails → reject.
2. **content JSON parse** — canonical JSON. Fails → reject.
3. **Structural check** — `protocol` == "nakama", expected `type` for the
   kind, required fields present, `d` tag recomputed from content matches
   (bond_hash / decision_core_hash / subject:declarant / old_hex as
   appropriate), `kind` matches expectation (30110/30111 must not mix).

Threshold approval verification is a *policy* operation, not part of event
verification — the event layer proves the shape is authentic; policy decides
whether it counts.

## 4. Compatibility

Clients that do not implement this NIP SHOULD ignore kinds 30107–30111.
These events are inert data without a nakama consumer — no special rendering
or relay behavior is required.

If a conflicting existing use of any of these kinds is found (see §6),
the protocol degrades by remapping kinds internally; consumers of this NIP
treat the kind number as a convention, never as identity — **identity is
always proven by signature, never by kind number**.

## 5. Security considerations

- A signature proves *who signed*, not that they act in good faith.
  Revocations, compromise declarations, and approvals are *claims by the
  signer* — verify the signer's standing before trusting them.
- Compromise declarations can be issued by anyone about anyone. Treat
  them as warnings to investigate, not as facts. `withdrawn: true`
  retracts; republishing is expected, not suspicious.
- Rotation is signed by the **old** key. If the old key is already
  compromised, a rotation signed by it is untrustworthy by construction —
  this is why compromise declarations and rotation interact (see §13, §17).
- Board decisions carry threshold approvals; a single publisher signature
  means nothing. Count approvals against the board's policy.
- Expiry is self-declared by the publisher. It serves honest operators
  (stale drafts don't linger as authoritative) — it does not constrain
  attackers.

## 6. Existing-adoption check (procedure, §26.4)

Before submitting the PR:

1. Query major relays and nostr.band for kinds 30107–30111 with a wildcard
   filter (no `d` tag constraint). Any event not matching §2 shapes is
   existing adoption by another party.
2. If prior adoption exists: do not contest. Record the finding here,
   choose alternative kinds, remap the protocol's kind constants
   (configurable), and during migration subscribe to both old and new
   kinds. Never republish already-published events — they are immutable.
3. If rejected or unanswered: the protocol keeps working. Registration is
   coordination, not permission.

### Survey result (2026-10-01, v0.23)

Queried relay.damus.io, nos.lol, relay.primal.net, and relay.nostr.band
(also 30105–30120 as alternates) with wildcard REQ filters; nostr.band's
search API was unreachable this run.

- **The original block 30100–30104 is already adopted by unrelated parties.**
  - A job-marketplace-style application publishes kind 30100 events
    (`["d", <hex>]`, `["e", <hex>]`, `["status", "completed"]` tags,
    content like `Job completed in 237.983s`) — seen on multiple relays from
    several pubkeys.
  - A Portuguese-language collective voting/showcase app ("Rodada",
    "Vitrine Coletiva") publishes kinds 30100/30101/30102/30104
    (`["d", "rodada-001"]`-style d tags, `["voto", ...]`,
    `["votantes", ...]` tags) — also extends into 30105.
  - No event in the sample matched nakama shapes (§2): no collisions *with*
    nakama events, because **no nakama event had ever been published** —
    the conflict is purely with foreign apps.
- Alternate scan: kinds 30105, 30106, 30113 show light use (same voting app
  for 30105). **30107–30112 and 30114–30120 were quiet on all three
  responding relays** (limit-100 wildcard queries; absence is not proof of
  global silence, but no adoption was found).
- Decision: remap to the contiguous quiet block **30107–30111**
  (revocation→30107, compromise→30108, rotation→30109,
  board-decision→30110, board-draft→30111). The old kinds are abandoned;
  no migration dual-subscribe is needed since nothing was published — this
  draft and the protocol's kind constants move together, with env-var
  override for future conflicts (see spec §26.10).

**PR submission itself is a human-society approval process** — it needs a
GitHub account's operation and review response. Agents draft; humans submit.

## Contributors

Built in the open by the nakama working group. Names withheld in this draft;
see the repo's Contributors section for the full list.

---

*Draft version: nakama protocol v0.23 (remapped 30100–30104 → 30107–30111
after the 2026-10-01 existing-adoption survey; no events ever published under
the old block). Event shapes fixed in NAKAMA-SPEC.md §§12, 13, 17, 19, 21.
No code change accompanies this draft.*
