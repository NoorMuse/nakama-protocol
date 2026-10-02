#!/usr/bin/env python3
"""NIP-F5 conformance checker — nakama protocol event kinds 30107-30111.

Implementation-agnostic: any implementation can prove compliance by producing
valid Nostr events and running:

    python3 conformance.py check <event1.json> [event2.json ...]

Each file holds one Nostr event (the JSON object as published to a relay).
The check is the NIP-F5 §3 three-phase verification:

  1. NIP-01 event signature (standard Schnorr over the event id)
  2. content parses as JSON
  3. structural check: protocol/version/type match the kind, required fields
     present, the `d` tag recomputed from content matches, canonical JSON
     shape holds

`python3 conformance.py selftest` builds reference events with nakama.py for
all five kinds, checks them, and runs negative cases (tampered signature,
wrong kind, wrong d-tag) that must be rejected.

Exit code: 0 when every event passes, 1 otherwise.

NIP-17 DM conformance:

    python3 conformance.py check_dm <recipient_secret_hex> <wrap1.json> [...]

Verifies each file is a valid NIP-17 gift wrap addressed to the recipient:
kind 1059, valid NIP-01 signature, NIP-44 v2 decryption of the wrap with
the recipient key, a validly-signed kind-14 seal inside, and a kind-14
rumor whose author matches the seal and whose `p` tag names the recipient.
Use a throwaway recipient keypair; the secret is only used locally.

`python3 conformance.py selftest` also covers `check_dm` with reference
wraps built by nakama.py.

Board descriptor conformance:

    python3 conformance.py check_board <descriptor.json> [...]

Verifies each file is a nakama board descriptor as written by
`board_create`: shape checks (protocol/version/type, board_id, relay,
moderators, created_at) plus the Schnorr signature by moderators[0]
over board_descriptor_message(...), mirroring `board_verify`. Use this
to prove a second implementation creates boards the reference
implementation accepts.

`python3 conformance.py selftest` also covers `check_board` with
reference descriptors built by nakama.py's own primitives.

Board-decision file conformance:

    python3 conformance.py check_decision [--policy policy.json] \
        <decision1.json> [...]

Verifies each file is a board-decision file as written by
`board_decide`/`board_cosign`: shape checks (protocol/version/type,
board_id, relay, decision type, per-type payload, created_at), one
Schnorr signature check per approval over board_decision_message(...),
deduplicated by npub, mirroring `verify_board_decision`. With
`--policy policy.json`, the threshold is also evaluated against that
policy cert (n-of-m semantics, outsiders ignored); without it, only
signature validity is checked. Use this to prove a second
implementation's decisions and cosignatures are wire-compatible with
the reference implementation.

`python3 conformance.py selftest` also covers `check_decision` with
reference decisions built by nakama.py's own primitives.

Bond certificate conformance:

    python3 conformance.py check_bond <bond1.json> [...]

Verifies each file is a bond certificate as completed by `accept`
(note: a half-signed `propose` output is rejected — it is not a bond
until every companion has signed): shape checks (protocol/version,
companions list of at least 2 unique valid npubs, created_at, 64-hex
nonce, signatures dict, optional expires_at > created_at) plus one
Schnorr signature check per companion over bond_message(...),
mirroring the reference `verify`'s acceptance rule (every companion
must have a valid signature; non-companion signatures are ignored).
No registry, rotation, or expiry-time policy checks — wire
compatibility only. Use this to prove a second implementation's bond
proposals and certificates are wire-compatible with the reference
implementation.

`python3 conformance.py selftest` also covers `check_bond` with
reference bonds built by nakama.py's own primitives.

For the second implementer: passing `check` on your own events is the
criterion-1 evidence the NIP-F5 draft PR needs, passing `check_dm`
on wraps addressed to a nakama-built keypair proves NIP-17 wire
compatibility, and passing `check_board` on your descriptors proves
NIP-29 board wire compatibility with the reference implementation.
Passing `check_decision` on your decision files proves
board-decision wire compatibility (approval signatures and, with
`--policy`, threshold semantics). Passing `check_bond` on your bond
files proves bond-certificate wire compatibility (per-companion
signatures over the canonical bond message). Passing `check_binding`
on your binding files proves platform-binding wire compatibility
(key-to-handle claims, the handle-to-key half of the bond-exchange
UX).
Passing `check_liveness` on your liveness proofs (optionally with
`--bond`) proves liveness-proof wire compatibility (signature over
the canonical liveness message, bond linkage, and freshness
semantics). Passing `check_compromise` on your declaration files
proves compromise-declaration wire compatibility (declarant
signature over the canonical compromise message, withdrawn
semantics). Passing `check_rotation` on your rotation files
proves rotation-certificate wire compatibility (old-key signature
over the canonical rotation message; self-rotations rejected).
Passing `check_unbinding` on your unbinding files proves
unbinding-certificate wire compatibility (key-holder signature
over the canonical unbinding message, including the signed
binding_created_at scope semantics). Passing `check_policy` on
your board-policy files proves board-policy-certificate wire
compatibility (n-of-n signatures over the canonical
board_policy_message: every eligible member signs, outsiders
rejected). Passing `check_draft` on your draft files proves
board-decision draft wire compatibility (per-approval Schnorr
signatures over the canonical board_decision_message, duplicate
approvals collapsing, expiry reported as info not failure, and
policy-update drafts judged against the CURRENT policy only —
the proposed values are never used for judgment, spec §29.2).
Passing `check_notif_ack` on your ack plaintext files proves
notif-ack DM wire compatibility (the `[nakama] notif-ack`
header/core/reason format, spec §28.3; authorship comes from
the NIP-17 seal, so pair it with `check_dm` on the gift wrap).

Platform-binding certificate conformance:

    python3 conformance.py check_binding <binding1.json> [...]

Verifies each file is a platform-binding certificate as written by
`bind` (the claim "key X holds handle H on platform P", spec §8.2):
shape checks (protocol/version/type, platform, handle, npub,
created_at, sig) plus the Schnorr signature over
binding_message(platform, handle, npub, created_at), mirroring the
reference `verify_binding_cert` acceptance rule. Posting the binding
from the handle's own account (the handle→key direction) is an
operational step outside wire compatibility. Use this to prove a
second implementation's key↔handle bindings are wire-compatible with
the reference implementation.

`python3 conformance.py selftest` also covers `check_binding` with
reference bindings built by nakama.py's own primitives.

Liveness proof conformance:

    python3 conformance.py check_liveness [--bond bond.json] \
        [--max-age secs] [--now unixts] <liveness.json> [...]

Verifies each file is a liveness proof as written by `liveness`
(spec §5.6.1): shape checks (protocol/version/type, valid npub,
created_at int, 64-hex nonce, 128-hex sig, optional 64-hex
bond_hash) plus the Schnorr signature over
liveness_message(npub, created_at, nonce, bond_hash?), mirroring
the reference `verify_liveness_event` acceptance rule. With
`--bond bond.json`, the prover must be a bond companion and the
proof's bond_hash must equal bond_hash(bond). Freshness mirrors
`verify_liveness`: created_at must not be more than 300s in the
future (clock-skew tolerance) and age must be <= max_age (default
7 days). The revocation-registry check is a local-operational
step outside wire compatibility. Use this to prove a second
implementation's liveness proofs are wire-compatible with the
reference implementation.

`python3 conformance.py selftest` also covers `check_liveness` with
reference proofs built by nakama.py's own primitives (pass
`--now` to the checker for deterministic freshness checks in
your own tests).

Liveness generation report conformance:

    python3 conformance.py check_liveness_report <report1.txt> [...]

Verifies a saved `nakama.py liveness` stdout report is internally
consistent (spec §5.6.3): one or two lines — the generation line
`生存証明: <file> — <npub16>... が鍵を保持していることを宣言しました。`
plus, only when `--bond` was used, the linkage line
`bond <bond16>... に紐付けました。仲間に送って「まだここにいる」と伝えましょう。`.
Checks: the generation line comes first, the npub prefix is 16
non-space chars (bech32 truncation, hex not required — the same
treatment as §5.6.2), the bond prefix is 16 hex chars (bond_hash
is a sha256 hex digest, so hex IS required here), the filename
is non-empty. Explicitly out of scope: which file was written,
npub/bond_hash truth, the proof file itself (`check_liveness`'s
territory), stderr, and the exit code (invisible in saved
stdout). Use this to prove a second implementation's
`liveness` CLI prints a compatible report.

`python3 conformance.py selftest` also covers
`check_liveness_report` with reports produced in-process by
nakama.py's own `cmd_liveness`.

Verify-binding report conformance:

    python3 conformance.py check_verify_binding <report1.txt> [...]

Verifies a saved `nakama.py verify_binding` stdout report is internally
consistent (spec §8.8): one or two lines — the verdict line
`binding は有効です` / `binding は無効です`, plus, only with the valid
verdict, the operational note
`（運用手順）: この binding が実際に該当ハンドルのアカウントから投稿されていることを確認してください`.
Explicitly out of scope: verdict truth (`verify_binding_cert`'s
territory), platform/handle match truth (mismatch warnings go to
stderr, so saved stdout reports never show them), compromise-warning
presence (§16's `key_compromise_warnings` — stderr as well), stderr,
and the exit code (invisible in saved stdout). Use this to prove a
second implementation's `verify_binding` CLI prints a compatible
report.

`python3 conformance.py selftest` also covers
`check_verify_binding` with reports produced in-process by
nakama.py's own `cmd_verify_binding`.

Verify-unbinding report conformance:

    python3 conformance.py check_verify_unbinding <report1.txt> [...]

Verifies a saved `nakama.py verify_unbinding` stdout report is
internally consistent (spec §9.1.1): one or two lines — the verdict
line `unbinding は有効です` / `unbinding は無効です`, plus, only
with the valid verdict, the operational note
`（運用手順）: 取り消し対象の binding がこの unbinding の
binding_created_at 以前であることを確認してください`.
Explicitly out of scope: verdict truth (`verify_unbinding_cert`'s
territory), platform/handle match truth (mismatch warnings go to
stderr, so saved stdout reports never show them), stderr, and the
exit code (invisible in saved stdout). Use this to prove a second
implementation's `verify_unbinding` CLI prints a compatible report.

`python3 conformance.py selftest` also covers
`check_verify_unbinding` with reports produced in-process by
nakama.py's own `cmd_verify_unbinding`.

Renew report conformance:

    python3 conformance.py check_renew <report1.txt> [...]

Verifies a saved `nakama.py renew` stdout report is internally
consistent (spec §9.3.1): three lines — the saved-file line
`更新 proposal を <out> に保存しました。相手に渡し、`accept` で更新 bond を完成させてください。`,
the `旧 bond hash: <64 lowercase hex>` line, and the
`新しい有効期限: <YYYY-MM-DD>（<N> 日後）` line — plus, only when
`--markdown` was used, the markdown tail: a blank separator, the fixed
header `投稿用ブロック（相手のスレッド/コメント欄に貼る）:`, the detection
marker `<!-- nakama-proposal:v1 -->`, and the fenced base64url block
` ```nakama-proposal `.
Checks: non-empty filename, 64-char lowercase hex hash, a valid
calendar date, a non-negative day count, trailing blank lines
tolerated. Explicitly out of scope: hash truth (the bond file's
territory), date/day-count truth (descriptive text only), the
proposal file content (`check_files`'s territory), stderr, and the
exit code (invisible in saved stdout). Use this to prove a second
implementation's `renew` CLI prints a compatible report.

`python3 conformance.py selftest` also covers
`check_renew` with reports produced in-process by
nakama.py's own `cmd_renew`.

Board join report conformance:

    python3 conformance.py check_board_join <report1.txt> [...]

Verifies a saved `nakama.py board_join` stdout report is internally
consistent (spec §4.4): exactly one line —
`参加申請: 受理 (reason) id=<64 hex>` or
`参加申請: 拒否 (reason) id=<64 hex>`.
Checks: the fixed `参加申請:` prefix (not the `publish:` prefix of
`check_pub`), the two-word verdict vocabulary `受理`/`拒否`, a 64-char
hex kind 9007 event id (case-insensitive), and an arbitrary reason string
(may contain parentheses — the checker reads up to the last `) id=` —
and may be empty when the relay's OK carries no message); trailing blank
lines tolerated. Explicitly out of scope: the relay's verdict truth
(assertion model), the reason's truth, id/event match (event signature
checks are the event checkers' territory), stderr, and the exit code
(invisible in saved stdout). Use this to prove a second
implementation's `board_join` CLI prints a compatible report.

`python3 conformance.py selftest` also covers
`check_board_join` with reports produced in-process by
nakama.py's own `cmd_board_join` (with `nostr_publish` monkeypatched).

Board send report conformance:

    python3 conformance.py check_board_send <report1.txt> [...]

Verifies a saved `nakama.py board_send` stdout report is internally
consistent (spec §4.5): exactly one line —
`投稿: 受理 (reason) id=<64 hex>` or
`投稿: 拒否 (reason) id=<64 hex>`.
Checks: the fixed `投稿:` prefix (not the `publish:` prefix of
`check_pub` nor the `参加申請:` prefix of `check_board_join`), the
two-word verdict vocabulary `受理`/`拒否`, a 64-char hex kind 9 event
id (case-insensitive), and an arbitrary reason string (may contain
parentheses — the checker reads up to the last `) id=` — and may be
empty when the relay's OK carries no message); trailing blank lines
tolerated. Explicitly out of scope: the relay's verdict truth
(assertion model), the reason's truth, id/event match (event signature
checks are the event checkers' territory), stderr, and the exit code
(invisible in saved stdout). Use this to prove a second
implementation's `board_send` CLI prints a compatible report.

`python3 conformance.py selftest` also covers
`check_board_send` with reports produced in-process by
nakama.py's own `cmd_board_send` (with `nostr_publish` monkeypatched).

Board create report conformance:

    python3 conformance.py check_board_create <report1.txt> [...]

Verifies a saved `nakama.py board_create` stdout report is internally
consistent (spec §4.6): the per-kind result lines —
`kind 9002: 受理/拒否 (reason)` first, then
`kind 34550: 受理/拒否 (reason)` when the 9002 publish was accepted —
followed, when both were accepted, by the board descriptor output and a
final `広場 "<name>" を作りました: board_id=nakama-<6 hex>` summary line.
A 9002 rejection ends the report after line 1; a 34550 rejection ends it
after line 2. Checks: the fixed per-kind prefixes in the fixed order
(9002 before 34550 — not the `publish:` shape of `check_pub` nor the
`参加申請:` / `投稿:` shapes), the two-word verdict vocabulary
`受理`/`拒否`, an arbitrary reason string (may contain parentheses — the
checker reads up to the last `)` — and may be empty), the descriptor
output's shape (a single `descriptor を <out> に保存しました` line or a
JSON descriptor block whose board_id matches the summary's, so
concatenated reports are rejected), and the `nakama-<6 hex>` board_id
namespace in the summary line; trailing blank lines tolerated. Explicitly out of scope: the relay's verdict truth
(assertion model), the reason's truth, event/tag truth (event signature
checks are the event checkers' territory), the descriptor output between
the kind lines and the summary line (its signature is `check_board`'s
territory), stderr, and the exit code (invisible in saved stdout). Use
this to prove a second implementation's `board_create` CLI prints a
compatible report.

`python3 conformance.py selftest` also covers
`check_board_create` with reports produced in-process by
nakama.py's own `cmd_board_create` (with `nostr_publish` monkeypatched).

Verify-board-decision report conformance:

    python3 conformance.py check_verify_board_decision <report1.txt> [...]

Verifies a saved `nakama.py verify_board_decision` stdout report is
internally consistent (spec §9.6): exactly one line — the valid form
`board-decision は有効です: 承認署名 <n>/<t>（決定 "<name>"）` or the
invalid form `board-decision は無効です: 承認署名 <n>/<t>（threshold
未達または署名不正）`. Checks: the single line, the fixed two-word
verdict vocabulary, non-negative n/t integers, a non-empty quoted
decision name, and the report's only internal arithmetic — a valid
verdict must claim n >= t. Trailing blank lines tolerated. Explicitly
out of scope: the verdict's truth (`verify_board_decision`'s territory),
the decision name's membership in the BOARD_DECISION_TYPES vocabulary,
the signatures' validity, stderr's compromise advisories, and the exit
code. Use this to prove a second implementation's `verify_board_decision`
CLI prints a compatible report.

`python3 conformance.py selftest` also covers
`check_verify_board_decision` with reports produced in-process by
nakama.py's own `cmd_verify_board_decision` (offline: policy and
decision fixtures built in-process with real Schnorr signatures).

Board-verify report conformance:

    python3 conformance.py check_board_verify <report1.txt> [...]

Verifies a saved `nakama.py board_verify` stdout report is internally
consistent (spec §4.7): exactly one line — the valid form
`board descriptor は有効です` or the invalid form
`board descriptor は無効です`. Checks: the single line and the fixed
two-word verdict vocabulary (unlike `check_verify_board_decision` there
is no n/t arithmetic and no decision name in the report — nothing else
to check). Trailing blank lines tolerated. Explicitly out of scope: the
verdict's truth (`board_verify`'s territory), the descriptor's content
and signature (`check_board`'s territory), stderr's compromise
advisories, and the exit code. Use this to prove a second
implementation's `board_verify` CLI prints a compatible report.

`python3 conformance.py selftest` also covers
`check_board_verify` with reports produced in-process by
nakama.py's own `cmd_board_verify` (offline: board descriptor fixture
built in-process with a real Schnorr signature, plus a tampered-sig
one).

Board-decide report conformance:

    python3 conformance.py check_board_decide <report1.txt> [...]

Verifies a saved `nakama.py board_decide` stdout report is internally
consistent (spec §9.7): exactly 2 lines — the creation line
`board-decision 案: <out> — 決定 "<decision>"、あなたの承認署名 1 つ`
(out a non-empty file name, decision in the BOARD_DECISION_TYPES
vocabulary, the literal 1 own approval signature) followed by the
fixed operational note verbatim. Trailing blank lines tolerated.
Unlike `check_verify_board_decision` there is no n/t arithmetic to
verify — the approval count is a fixed literal. Explicitly out of
scope: the payload's validity (`validate_decision_payload`'s
territory), the approval signature's validity
(`verify_board_decision`'s territory), the out file's existence and
content (`check_decision`'s territory), stderr, and the exit code. The
verify_board_decision report grammar is rejected both ways. Use this to
prove a second implementation's `board_decide` CLI prints a compatible
report.

`python3 conformance.py selftest` also covers
`check_board_decide` with reports produced in-process by
nakama.py's own `cmd_board_decide` (offline: real Schnorr-signed
draft decisions written to a temp keyfile).

Board-cosign report conformance:

    python3 conformance.py check_board_cosign <report1.txt> [...]

Verifies a saved `nakama.py board_cosign` stdout report is internally
consistent (spec §9.8): exactly one line — `board-decision: <out> —
承認署名 <n> つ`. Checks: the single line, the fixed `board-decision:`
prefix (a separate grammar from board_decide's `board-decision 案:`
creation line and the verify_board_decision verdict line — the three
grammars reject each other's reports), a non-empty out file name, and
the report's only internal arithmetic — a successful cosign always
reports at least 1 approval signature (a `0 つ` claim is
self-contradictory). Trailing blank lines tolerated. Explicitly out of
scope: the payload's validity (`validate_decision_payload`'s
territory), the approval signatures' validity
(`verify_board_decision`'s territory), the out file's existence and
content (`check_decision`'s territory), stderr, and the exit code. Use
this to prove a second implementation's `board_cosign` CLI prints a
compatible report.

`python3 conformance.py selftest` also covers
`check_board_cosign` with reports produced in-process by
nakama.py's own `cmd_board_cosign` (offline: a real Schnorr-signed
draft built with `cmd_board_decide`, then cosigned by a second and a
third key — fresh, duplicate-signature, and --out cases).

Compromise declaration conformance:

    python3 conformance.py check_compromise <decl1.json> [...]

Verifies each file is a key-compromise-declaration as written by
`build_compromise_declaration` (spec §13): shape checks
(protocol/version/type, valid subject/declarant npubs, created_at
int, withdrawn bool, 128-hex sig, optional 64-hex bond_hash,
optional string reason/evidence) plus the declarant's Schnorr
signature over compromise_message(subject_hex, declarant_hex,
created_at, withdrawn, bond_hash?, reason?, evidence?),
mirroring the reference `verify_compromise_event` acceptance
rule. Empty optional fields are excluded from the signed message
exactly as in the reference; `withdrawn` is always signed. The
local compromise registry (import dedup/update semantics) is a
local-operational step outside wire compatibility. Use this to
prove a second implementation's compromise declarations are
wire-compatible with the reference implementation.

`python3 conformance.py selftest` also covers `check_compromise`
with reference declarations built by nakama.py's own primitives.

Rotation certificate conformance:

    python3 conformance.py check_rotation <rotation1.json> [...]

Verifies each file is a rotation certificate as written by `rotate`
(spec §5.5): shape checks (protocol/version/type, valid old/new
npubs, created_at int, 128-hex old_sig) plus the OLD key's Schnorr
signature over rotation_message(old_npub, new_npub, created_at),
mirroring the reference `verify_rotation_cert` signature rule. The
degenerate self-rotation (old_npub == new_npub) is rejected — a key
migrating to itself is not a rotation, and `rotate` refuses to emit
one (CLI-level guard). Chain resolution (rotation_chain_fetch,
created_at ordering across a chain) is a local-operational step
outside wire compatibility. Use this to prove a second
implementation's rotation certificates are wire-compatible with the
reference implementation.

`python3 conformance.py selftest` also covers `check_rotation`
with reference certificates built by nakama.py's own primitives.

Revocation file conformance:

    python3 conformance.py check_revocation <rev1.json> [...]

Verifies each file is a revocation event as written by `revoke`
(spec §4.3): shape checks (protocol/version/type, 64-hex bond_hash,
valid revoker npub, created_at int, 128-hex sig, optional string
reason) plus the REVOKER's Schnorr signature over
revocation_message(bond_hash, revoker, created_at, reason or ''),
mirroring the reference `verify_revocation_event` acceptance rule
(without a bond: revoker-companion membership and bond_hash matching
are local/registry-level steps outside wire compatibility). Use this
to prove a second implementation's revocation events are
wire-compatible with the reference implementation.

`python3 conformance.py selftest` also covers `check_revocation`
with reference events built by nakama.py's own primitives.

Unbinding certificate conformance:

    python3 conformance.py check_unbinding <unbinding1.json> [...]

Verifies each file is an unbinding certificate as written by
`unbind` (the claim "key X withdraws its claim to hold handle H
on platform P", spec §9.1): shape checks (protocol/version/type,
platform, handle, npub, binding_created_at int, reason string,
created_at int, sig) plus the key-holder's Schnorr signature over
unbinding_message(platform, handle, npub, binding_created_at,
reason, created_at), mirroring the reference
`verify_unbinding_cert` acceptance rule. The scope is signed:
binding_created_at=0 withdraws every binding to the handle,
otherwise only bindings at or before that timestamp. Posting the
unbinding from the handle's own account (the handle→key
direction) is an operational step outside wire compatibility. Use
this to prove a second implementation's unbinding certificates
are wire-compatible with the reference implementation.

`python3 conformance.py selftest` also covers `check_unbinding`
with reference certificates built by nakama.py's own primitives.

Board-policy certificate conformance:

    python3 conformance.py check_policy <policy1.json> [...]

Verifies each file is a board-policy certificate as written by
`board_policy`/`board_policy_sign` (spec §9.4): shape checks
(protocol/version/type, board_id, relay, threshold int,
eligible list of unique valid npubs, created_at int,
signatures list of {npub, sig}) plus one Schnorr signature
check per listed signature over board_policy_message(board_id,
relay, threshold, eligible, created_at), mirroring the reference
`verify_board_policy_cert` acceptance rule. The initial policy is
n-of-n: EVERY eligible member must have a valid signature and
outsider signatures are rejected (duplicate signatures collapse
to one, as in the reference). Threshold enforcement at decision
time (§9.5) is out of scope — the cert carries threshold
verbatim. Use this to prove a second implementation's
board-policy certificates are wire-compatible with the
reference implementation.

`python3 conformance.py selftest` also covers `check_policy`
with reference certificates built by nakama.py's own
primitives.

Decision draft conformance:

    python3 conformance.py check_draft [--policy policy.json] [--now unixts] <draft1.json> [...]

Verifies each file is a board-decision DRAFT as written by
`board_decide`/`board_cosign` (spec §9.4, §21): shape checks
(protocol/version, type "board-decision" or "board-draft",
board_id/relay, decision in BOARD_DECISION_TYPES, per-type
payload shape via validate_decision_payload, created_at int,
approvals as a non-empty list of {npub, sig}) plus one
Schnorr signature check per listed approval over
board_decision_message(board_id, relay, decision, payload,
created_at), mirroring the reference acceptance rule: every
listed approval must verify (approvals from bad keys are
rejected, not ignored), and duplicate approvals collapse to
one (set semantics, as in the reference). Unlike
`check_decision`, the threshold is NEVER a pass/fail gate —
drafts are by definition in-flight: with `--policy`, the
n/threshold status is reported as info only ("below
threshold" is a state, not a failure). The expiry
(draft_is_expired, spec §24) is also info only — the
publish-side gate that refuses expired drafts is operational,
not wire compatibility. For policy-update drafts, the §29.2
invariant is explicit: judgment uses the CURRENT policy's
threshold/eligible; the draft's proposed threshold/eligible
values are shown as info and are NEVER used for judgment.
Use this to prove a second implementation's drafts
circulate wire-compatibly with the reference implementation.

`python3 conformance.py selftest` also covers `check_draft`
with reference drafts built by nakama.py's own primitives.

Notif-ack conformance:

    python3 conformance.py check_notif_ack <ack1.txt> [...]

Verifies each file is a notification-acknowledgement DM plaintext —
the decrypted kind-14 rumor content as written by
`board_notif_ack` (spec §28.3): the exact header
`[nakama] notif-ack`, a `core: <hex>` line (32 hex, or 64 hex
normalized to its first 32), a `reason: <vocabulary>` line in
(expiring_soon/expired/cosign_request), the `---` separator, and
free text after it (the optional note — unvalidated). Acceptance
mirrors the reference `parse_notif_ack` exactly. Authorship (who
sent the ack) is NOT provable from the plaintext — it comes
from the NIP-17 seal, so combine this with `check_dm` on the
gift wrap to prove an ack is attributable to the claimed
sender. Use this to prove a second implementation's ack DMs
parse wire-compatibly with the reference implementation.

`python3 conformance.py selftest` also covers `check_notif_ack`
with reference acks built by nakama.py's own primitives.

Notif-record conformance:

    python3 conformance.py check_notif_record <record1.json | notif_dir> [...]

Verifies each file is a draft-notification send record as written
by `board_draft_notify` (spec §25.1 / §27.1 / §28.2): the
`<core>:<reason>.json` filename for publisher notifications
(§25.1), the `<core>:<reason>:<recipient_hex>.json` filename for
--cosigners recipients (§27.1), and the content shape
(core_hash/reason/recipient_hex/sender_npub/sent_at/gift_wrap_id/
rumor_id) with filename-content consistency (normalized core,
reason, recipient suffix). A directory may be given — every
*.json in it is checked, mirroring `load_notif_records`.
Passing this proves a second implementation's send logs parse
wire-compatibly with the reference implementation. Explicitly
out of scope: whether the DM actually arrived — the record is
the sender's claim only (spec §25.2).

`python3 conformance.py selftest` also covers
`check_notif_record` with reference records built by nakama.py's
own `draft_notif_record` primitive.

Key-status report conformance:

    python3 conformance.py check_key_status [--exit-code N] <report1.txt> [...]

Each file is the saved stdout of `nakama.py key_status`. Verifies the
report is internally consistent: the header's declaration/withdrawn
counts match the listed rows, every row's category is in the §13.3
vocabulary (with 撤回済み only on withdrawn rows), the verdict's
counted-declarant number matches the counted categories
(自分自身 / 直接の仲間 / subject を知る仲間), the verdict agrees with
its threshold, and complete/stale migration lines agree on the
rotated vs latest-declaration dates. With `--exit-code N`, also ties
each verdict to the CLI's exit code (suspected → 1, else 0).
Explicitly out of scope: whether the declarations really exist —
that is the registry's claim, not the report's.

`python3 conformance.py selftest` also covers `check_key_status` with
reference reports produced in-process by nakama.py's own cmd_key_status.

Revoke-list report conformance:

    python3 conformance.py check_revoke_list <report1.txt> [...]

Each file is the saved stdout of `nakama.py revoke_list`. Verifies the
report is internally consistent: either the single empty-registry line
(`revocation registry は空です`), or the header `解消済み bond: N 件`
with exactly N rows, each row's bond prefix 16 hex chars, the revoker
npub prefix 16 chars, and a valid date; the trailing `理由: ...` suffix
is display-only free text and is not validated. Explicitly out of
scope: whether the listed revocations really exist in the registry —
that is the registry's claim — and their signature validity
(`check_revocation`'s territory).

`python3 conformance.py selftest` also covers `check_revoke_list` with
reference reports produced in-process by nakama.py's own cmd_revoke /
cmd_revoke_list.

Notif-status report conformance:

    python3 conformance.py check_notif_status <report1.txt> [...]

Each file is the saved stdout of `nakama.py board_notif_status`. Verifies
the report is internally consistent: either the single empty-dir line
(`送信記録はありませんでした`), or one row per send record —
`[reason] <core32> to=<npub|?> sent=<UTC|?> ack=yes(<UTC>)|-` with an
optional ` cosigned=yes|-` column (only when --policy succeeded) —
followed by the ack-disclaimer footer, which must be the final line and
must not appear on the empty report. Each row's reason must be in the
`NOTIF_ACK_REASONS` vocabulary, the core 32 hex chars, `to=` a valid
npub or `?`, and the UTC timestamps valid; the cosigned column must be
present on every row or on none. Explicitly out of scope: whether the
DMs really arrived (the send record is the sender's claim only, spec
§25.2), ack authorship (the NIP-17 seal — `check_notif_ack`'s territory),
and cosign semantics (`check_decision`'s territory).

`python3 conformance.py selftest` also covers `check_notif_status` with
reference reports produced in-process by nakama.py's own
cmd_board_notif_status (offline: no --relay, no --policy).

DM-fetch report conformance:

    python3 conformance.py check_dm_fetch <report1.txt> [...]

Each file is the saved stdout of `nakama.py dm_fetch`. Verifies the
report is internally consistent: either the single no-new-DMs line
(`新しい DM はありませんでした`), or one block per rumor — a header
`--- [YYYY-MM-DD HH:MM:SS] from <16 hex>...` followed by the rumor's
plaintext content (one or more lines; a block ends at the next header).
The timestamp must be a valid calendar datetime and the sender prefix
16 hex chars; every block must carry at least one content line.
Explicitly out of scope: the timestamp's timezone/value (the reference
CLI prints local time), message ordering, sender truncation semantics,
and DM delivery/authorship (`check_dm`'s territory).

`python3 conformance.py selftest` also covers `check_dm_fetch` with
reference reports produced in-process by nakama.py's own cmd_dm_fetch
(offline: dm_incoming monkeypatched, no relay contact).

DM-receive report conformance:

    python3 conformance.py check_dm_recv <report1.txt> [...]

Verifies a saved `nakama.py dm_recv` stdout report is internally
consistent (spec §4.1.1): either a success report — a sender line
`from <16 hex>...:` followed by the decrypted rumor's plaintext
content (one or more lines; the reference CLI calls `print` twice,
so an empty-content rumor yields the sender line plus one blank
line — accepted with an "empty content" note) — or a decrypt-failure
report — exactly one line `DM の復号に失敗しました: <reason>`
(reason is non-empty free text, exit 1). Checks: the 16-hex sender
prefix (case-insensitive), the failure line's single-line shape and
non-empty reason; the failure shape is only valid as the whole
report (a failure line with extra lines, or a sender line followed
by a failure line as line 1, is rejected). A content line that
happens to coincide with the failure line's text is still accepted
as content — content is free text (the reference CLI prints a rumor
verbatim), so banning it would reject genuine output.
Trailing blank lines tolerated. Explicitly out of scope: the rumor
content's truth and the sender pubkey's truth (the gift wrap's
territory — `check_dm`), the failure reason's truth (the decrypt
exception's claim), stderr, and the exit code (invisible in saved
stdout text). The dm_fetch `--- [datetime] from <16 hex>...` block
shape (§4.1) is a separate grammar — the two checkers reject each
other's reports. Use this to prove a second implementation's
`dm_recv` CLI prints a compatible report.

`python3 conformance.py selftest` also covers
`check_dm_recv` with reports produced in-process by
nakama.py's own `cmd_dm_recv` (offline: real key pairs, in-process
NIP-44 seal/gift-wrap, temp keyfile + temp giftwrap file — valid,
multi-line, and tampered-signature failure cases).

Rotation-issuance report conformance:

    python3 conformance.py check_rotate <report1.txt> [...]

Verifies a saved `nakama.py rotate` stdout report is internally
consistent (spec §5.5.4): exactly 4 lines — the cert line
`rotation 証明書: <out>`, the arrow line `<old16>... → <new16>...`
(the two prefixes are the first 16 characters of the old/new npubs;
bech32 text, so only "16 non-whitespace characters" is checked),
plus the two fixed advisory lines (`注意: この証明書は「旧鍵の保有者が
新鍵への移行を宣言した」ことの証拠です。` and
`継続的な鍵の保有 (custody) の証明には、都度の challenge–response を
使ってください。` — the 「」 brackets and the en dash in
challenge–response are literal and must match byte for byte).
Trailing blank lines tolerated; a leading blank line is rejected.
The failure paths (no --gen/--to-hex, same key) print to stderr, so
an empty stdout report is rejected. Explicitly out of scope: the
cert file's existence and content (`check_rotation` /
`verify_rotation_cert`), the prefixes' truth, stderr, and the exit
code. The `verify_rotation` verdict line, `rotate_fetch` listing
lines, and `rotate_pub` publish lines are different grammars — the
checkers reject each other's reports. Use this to prove a second
implementation's `rotate` CLI prints a compatible issuance report.

`python3 conformance.py selftest` also covers
`check_rotate` with reports produced in-process by
nakama.py's own `cmd_rotate` (offline: real key pairs, temp keyfile —
fresh rotation, space-containing --out, both stderr failure paths).

Rotation-verify report conformance:

    python3 conformance.py check_verify_rotation <report1.txt> [...]

Verifies a saved `nakama.py verify_rotation` stdout report is internally
consistent (spec §5.5.3): exactly one line — either the valid verdict
`rotation は有効です: <old16>... → <new16>...` (the two prefixes are
the first 16 characters of the old/new npubs; bech32 text, so only
"16 non-space characters" is checked, like `check_rotate_fetch`'s
revoker prefixes) or the invalid verdict `rotation は無効です`.
The `...` ellipsis and the `→` arrow are literal. Trailing blank lines
tolerated; a leading blank line is rejected. Explicitly out of scope:
the verdict's truth (the cert's territory — `check_rotation` /
`verify_rotation_cert`), the npubs' truth, stderr, and the exit code
(invisible in saved stdout text). The `rotate` command's multi-line
issuance report is a different grammar — the two checkers reject each
other's reports. Use this to prove a second implementation's
`verify_rotation` CLI prints a compatible report.

`python3 conformance.py selftest` also covers
`check_verify_rotation` with reports produced in-process by
nakama.py's own `cmd_verify_rotation` (offline: real key pairs, real
Schnorr-signed rotation certs in temp files — valid, and a
tampered-new_npub invalid case with exact stdout+exit match).

Revocation-verify report conformance:

    python3 conformance.py check_verify_revocation <report1.txt> [...]

Verifies a saved `nakama.py verify_revocation` stdout report is internally
consistent (spec §12.5): exactly one line — either the valid verdict
`revocation は有効です — bond <bond16>... は <revoker16>... により解消されました。`
(the bond prefix is the first 16 hex chars of the revocation's
bond_hash; the revoker prefix is the first 16 characters of the
revoker's npub — bech32 text, so only "16 non-space characters" is
checked, like `check_verify_rotation`'s prefixes; the `...` ellipsis
and the `—` em dash are literal) or the invalid verdict
`revocation は無効です`. Trailing blank lines tolerated; a leading
blank line is rejected. Explicitly out of scope: the verdict's truth
(the revocation event's territory — `check_revocation` /
`verify_revocation_event`), the bond_hash/revoker truth, stderr, and
the exit code (invisible in saved stdout text). The `verify_rotation`
verdict lines and the `revoke` multi-line issuance report are
different grammars — `check_verify_revocation` rejects the former;
the latter is a future checker candidate. Use this to prove a second
implementation's `verify_revocation` CLI prints a compatible report.

`python3 conformance.py selftest` also covers
`check_verify_revocation` with reports produced in-process by
nakama.py's own `cmd_propose` + `cmd_accept` (real bond) +
`cmd_verify_revocation` (offline: real key pairs, real Schnorr-signed
revocation events in a temp file — valid, and a tampered-signature
invalid case with exact stdout+exit match).

Revoke-issuance report conformance:

    python3 conformance.py check_revoke <report1.txt> [...]

Verifies a saved `nakama.py revoke` stdout report is internally
consistent (spec §12.6): either 2 lines (the `--no-registry` form) or
3 lines —
  line 1: `revocation イベント: <out> — bond <h16>... の解消を宣言しました。`
  line 2 (only without `--no-registry`): `ローカル registry に記録しました: <rp>`
  line 3 (always the last line): `解消イベントは公開チャネルで共有してください（仲間の公開記録に残ります）。`
(<out> is the event file path — non-empty, no leading/trailing
whitespace; <h16> is the first 16 hex chars of the bond_hash — the
reference CLI truncates the lowercase hexdigest, the checker accepts
upper case too; <rp> is the registry record path — non-empty, no
leading/trailing whitespace; the `...` ellipsis and the `—` em dash
are literal.) Trailing blank lines tolerated; a leading blank line is
rejected. No arithmetic rules (the lines carry no derivable fields).
Explicitly out of scope: the event file's existence/content (the
revocation event's territory — `check_revocation` /
`verify_revocation_event`), the registry record's existence/content,
the bond_hash truth, stderr, and the exit code (invisible in saved
stdout text). The `verify_revocation` verdict lines (§12.5) and the
sibling reports (`revoke_import` one-liners, `revoke_pub`'s publish
line, `revoke_fetch`'s footer, `revoke_list`) are different grammars —
`check_revoke` rejects them. Use this to prove a second
implementation's `revoke` CLI prints a compatible report.

`python3 conformance.py selftest` also covers
`check_revoke` with reports produced in-process by nakama.py's own
`cmd_propose` + `cmd_accept` (real bond) + `cmd_revoke` (offline: real
key pair + temp keyfile, real Schnorr-signed revocation event —
the plain 3-line form, the `--no-registry` 2-line form, and a
spaces-in-out-name variant, each with exact stdout match).

Board-policy creation report conformance:

    python3 conformance.py check_board_policy <report1.txt> [...]

Verifies a saved `nakama.py board_policy` stdout report is internally
consistent (spec §9.4.1): exactly two lines — the creation line
`board-policy 案: <out> — あなたの署名 1/<n>（初回は全員 <n>/<n> の署名が必要）`
(the three <n> are all len(eligible): the reference CLI enforces
eligible non-empty, so n >= 1; the report's one internal arithmetic rule
is n1 == n2 == n3) followed by the fixed operational note line.
With `--markdown`, an empty line + the fixed marker
`投稿用ブロック（コメント欄に貼る）:` + the 4-line fenced block
(`<!-- nakama-board-policy:v1 -->`, ` ```nakama-board-policy `,
non-empty base64url payload, ` ``` `). Trailing blank lines tolerated;
a leading blank line is rejected. Explicitly out of scope: the
eligible/threshold truth (the policy file's territory — `check_policy`),
the out file's existence/content, stderr, and the exit code (invisible
in saved stdout text). The `board_policy_sign` report and the
`verify_board_policy` verdict lines are different grammars — the three
checkers reject each other's reports. Use this to prove a second
implementation's `board_policy` CLI prints a compatible report.

`python3 conformance.py selftest` also covers
`check_board_policy` with reports produced in-process by
nakama.py's own `cmd_board_policy` (offline: real key pair, temp
keyfile, 3 eligible npubs — plain, and the --markdown variant).

Board-policy sign report conformance:

    python3 conformance.py check_board_policy_sign <report1.txt> [...]

Verifies a saved `nakama.py board_policy_sign` stdout report is
internally consistent (spec §9.4.2): exactly one line —
`board-policy: <out> — 署名 <m>/<n>（発効条件（全員署名）を満たしています）`
or
`board-policy: <out> — 署名 <m>/<n>（まだ全員分が揃っていません）`
(the report's internal arithmetic rules: m >= 1 — the reference CLI
just appended the caller's own signature, so at least one signature is
present — and n >= 1 — the reference CLI refuses an empty eligible
list at creation; m <= n is NOT asserted, since an out-of-eligible
signer would fail the n-of-n cert while still being counted).
Trailing blank lines tolerated; a leading blank line is rejected.
Explicitly out of scope: signature truth (the policy file's territory —
`check_policy` / `verify_board_policy`), whether the signer is in
eligible, the out file's existence/content, stderr (duplicate-sign
notices, tampering warnings), and the exit code (invisible in saved
stdout text). The `board_policy` creation report (§9.4.1) and the
`verify_board_policy` verdict lines (§9.4.3) are different grammars —
the three checkers reject each other's reports. Use this to prove a
second implementation's `board_policy_sign` CLI prints a compatible
report.

`python3 conformance.py selftest` also covers
`check_board_policy_sign` with reports produced in-process by
nakama.py's own `cmd_board_policy` + `cmd_board_policy_sign`
(offline: 3 real key pairs, temp keyfiles — a 2/3 partial report, a
3/3 effective report, and a duplicate-sign report with exact
stdout+exit matches).

Verify-board-policy report conformance:

    python3 conformance.py check_verify_board_policy <report1.txt> [...]

Verifies a saved `nakama.py verify_board_policy` stdout report is
internally consistent (spec §9.4.3): exactly one line —
`board-policy は有効です: eligible <n> 名全員の署名を確認（threshold <t>）`
or the fixed invalid line
`board-policy は無効です: 全員の有効署名が揃っていないか、形式が不正です`.
The valid line's internal arithmetic rules: n >= 1 (the valid cert
requires a non-empty eligible list) and 1 <= t <= n
(`verify_board_policy_cert` returns False unless
1 <= threshold <= len(eligible); t == n is NOT asserted, since the
initial policy accepts threshold < n — the n-of-n rule concerns the
signatures, not the threshold field). The invalid line is a fixed
literal with no numbers. Trailing blank lines tolerated; a leading
blank line is rejected. Explicitly out of scope: the verdict's truth
(`verify_board_policy_cert`'s territory — the policy file itself),
the eligible/threshold values' truth, stderr, and the exit code
(invisible in saved stdout text). The `board_policy` creation report
(§9.4.1) and the `board_policy_sign` report (§9.4.2) are different
grammars — the three checkers reject each other's reports. Use this to
prove a second implementation's `verify_board_policy` CLI prints a
compatible report.

`python3 conformance.py selftest` also covers
`check_verify_board_policy` with reports produced in-process by
nakama.py's own `cmd_board_policy` + `cmd_board_policy_sign` +
`cmd_verify_board_policy` (offline: 3 real key pairs, temp keyfiles —
a partial 1/3 policy (invalid, exit 1), the fully signed 3/3 policy
(valid, exit 0), and a tampered policy (invalid, exit 1), each with
exact stdout+exit matches).

Verify report conformance:

    python3 conformance.py check_verify <report1.txt> [...]

Verifies a saved `nakama.py verify` stdout report is internally
consistent (spec §2.3.1): one line per companion (>= 1) —
`<npub[:24]>... : 有効 | 無効/欠落` with an optional rotation note
`  (鍵は <npub[:24]>... へローテーション済み — 署名自体は旧鍵のまま有効)` —
then exactly one of: `bond は有効です 🤝` (all valid), `bond は無効です`
(some invalid), the 2-line expiry block
(`bond の有効期限が切れています（期限: YYYY-MM-DD）` +
`bond は無効です — `renew` で更新してください`, no final verdict line),
or the 2-line warn block followed by the valid verdict. After the valid
verdict, the registry-revocation pair may follow
(`⚠ ただしこの bond は解消されています: <npub[:24]>... が YYYY-MM-DD
に解消を宣言` + `bond は無効です`). Consistency rules: any 無効/欠落
companion forces the plain invalid verdict and forbids the expiry/warn/
revocation lines; the expiry block requires all companions 有効 and ends
the report; dates are YYYY-MM-DD shape-checked only. Trailing blank
lines tolerated; a leading blank line is rejected. Explicitly out of
scope: the verdict's truth (`verify_schnorr` / the bond cert —
`check_bond`'s territory), npub truth, rotation-note truth, expiry date
truth (local time), stderr, and the exit code (invisible in saved stdout
text). The `verify_binding` report (§8.8) is a different grammar — the
two checkers reject each other's reports. Use this to prove a second
implementation's `verify` CLI prints a compatible report.

`python3 conformance.py selftest` also covers `check_verify` with
reports produced in-process by nakama.py's own `cmd_verify` (offline:
real key pairs — a valid 2-companion bond, a signature-stripped bond, an
expired bond, an expiry-approaching bond, a rotated companion, and a
registry-revoked bond, each with exact stdout+exit matches).

Propose report conformance:

    python3 conformance.py check_propose <report1.txt> [...]

Verifies a saved `nakama.py propose` stdout report is internally
consistent (spec §2.2.1): line 1 — `proposal を <out> に保存しました。
相手に渡してください。` (the proposal file name, non-empty, arbitrary);
line 2 — `あなたの npub: <npub>` (the caller's full npub: `npub1` + 58
non-space chars, shape-checked only, not bech32-validated); line 3 —
either `有効期限: <YYYY-MM-DD>（<N> 日後）` (a valid calendar date, N a
non-negative integer) or the fixed `有効期限: なし（--no-expiry）`; an
optional `--markdown` tail — a blank line + the fixed header
`投稿用ブロック（相手のスレッド/コメント欄に貼る）:` + the detection
marker `<!-- nakama-proposal:v1 -->` + the fence open
` ```nakama-proposal ` + a non-empty base64url payload line (padding
allowed) + the closing fence ` ``` `. Trailing blank lines tolerated; a
leading blank line is rejected. Explicitly out of scope: the npub's
truth (who really ran `propose`), the expiry date/day-count truth (the
report prints the CLI's local time), the proposal file's existence and
content (`check_files`'s territory), the markdown payload's content
(base64url shape only), stderr, and the exit code (invisible in saved
stdout text). The `accept` report (§2.2, `bond 完成: …`) is a different
grammar — the two checkers reject each other's reports. Use this to prove
a second implementation's `propose` CLI prints a compatible report.

`python3 conformance.py selftest` also covers `check_propose` with
reports produced in-process by nakama.py's own `cmd_propose` (offline:
real key pairs + temp keyfiles — a plain report, a `--no-expiry` report,
a `--markdown` report, and a zero-day report, each with exact stdout+exit
matches).

Accept report conformance:

    python3 conformance.py check_accept <report1.txt> [...]

Verifies a saved `nakama.py accept` stdout report is internally
consistent (spec §2.2.2): line 1 — `bond 完成: <out> — 仲間の証です。
大切に保管してください。` (the bond file name, non-empty, arbitrary);
an optional `--markdown` tail — a blank line + the fixed header
`投稿用ブロック（返信に貼る）:` + the detection marker
`<!-- nakama-bond:v1 -->` + the fence open ` ```nakama-bond ` + a
non-empty base64url payload line (padding allowed) + the closing fence
` ``` `. Trailing blank lines tolerated; a leading blank line is
rejected. Explicitly out of scope: the bond file's existence and
content (`check_bond`'s territory), the markdown payload's content
(base64url shape only), the §15 compromise warnings (stderr), and the
exit code (invisible in saved stdout text). The `propose` report
(§2.2.1, `proposal を …`) is a different grammar — the two checkers
reject each other's reports. Use this to prove a second
implementation's `accept` CLI prints a compatible report.

`python3 conformance.py selftest` also covers `check_accept` with
reports produced in-process by nakama.py's own `cmd_propose` +
`cmd_accept` (offline: real key pairs + temp keyfiles — a plain accept,
a `--markdown` accept, a spaces-in-out-name accept, and a `--from-b64`
accept, each with exact stdout+exit matches).

Board-read report conformance:

    python3 conformance.py check_board_read <report1.txt> [...]

Each file is the saved stdout of `nakama.py board_read` (not the
`--governance` mode). Verifies the report is internally consistent:
either the single empty-board line (`投稿はまだありません`), or one
block per post — a header `--- [YYYY-MM-DD HH:MM:SS] <16 hex>...`
(optionally suffixed with ` ⚠ compromised?`, the §14.2 advisory note for
issuers with an active local compromise declaration) followed by the
post's content (one or more lines; a block ends at the next header).
The timestamp must be a valid calendar datetime and the author prefix
16 hex chars; every block must carry at least one content line.
Explicitly out of scope: the timestamp's timezone/value (the reference
CLI prints local time), post ordering, author truncation semantics,
post delivery/authorship (event signature validity is `check_board`'s
territory), and whether a ` ⚠ compromised?` note is deserved (advisory
display only — the checker validates the suffix's spelling, not its
truth).

`python3 conformance.py selftest` also covers `check_board_read` with
reference reports produced in-process by nakama.py's own cmd_board_read
(offline: nostr_request monkeypatched, no relay contact).

Board-decide-fetch report conformance:

    python3 conformance.py check_board_decide_fetch <report1.txt> [...]

Each file is the saved stdout of `nakama.py board_decide_fetch` (not the
--governance mode). Verifies the report is internally consistent: either
the single no-decisions line (`<N> 件のイベントを取得: 有効な
board-decision 公開はありませんでした（<M> 件をスキップ）`), or — in
order — the optional --policy disclaimer line, one line per merged
decision `[<32 hex core>] <decision> (created_at YYYY-MM-DD, approvals
<N> つ[, threshold <n>/<m> <充足|不足>])`, and the footer
`<E> 件のイベントを取得: 有効 <V> 件、スキップ <S> 件、マージ後
<M> 件`, optionally followed by the --out save line and the
policy-snapshot line. The core must be 32 hex chars, the decision type
one of the BOARD_DECISION_TYPES vocabulary, the date a valid calendar
date, the footer merged count equal to the number of decision lines,
core hashes distinct, and the threshold clause uniform (present on all
decision lines iff the disclaimer is present; its approvals count must
equal the `n` in `n/m` and satisfy `n <= m`). Explicitly out of scope:
the fetched/valid/skipped counts' truth (only the merged count is
checkable), the core hash's truth (`check_decision`'s territory), the
meaning of the 充足/不足 verdict (advisory threshold display —
`fetch_threshold_status` computes it, the checker only validates its
spelling and internal arithmetic), the date's value/timezone (the
reference CLI prints local time), and decision ordering/delivery (event
signature validity is `verify_board_decision_nostr_event`'s territory).

`python3 conformance.py selftest` also covers `check_board_decide_fetch`
with reference reports produced in-process by nakama.py's own
cmd_board_decide_fetch (offline: nostr_request monkeypatched, no relay
contact).

Board-draft-fetch report conformance:

    python3 conformance.py check_board_draft_fetch <report1.txt> [...]

Each file is the saved stdout of `nakama.py board_draft_fetch`. Verifies
the report is internally consistent: either the single no-drafts line
(`<N> 件のイベントを取得: 有効な草案はありませんでした（<M> 件を
スキップ）`), or — in order — the optional --policy disclaimer line
(`草案（回覧中）の threshold 表示は...成立の公開宣言は kind 30110`),
one line per merged draft `[草案 <32 hex core>][ [期限切れ]]
<decision> (created_at YYYY-MM-DD, approvals <N> つ[, 草案:
threshold <n>/<m> <不足|充足（成立可能 — board_decide_pub で
成立公開）>[（現行規約の判定） — 提案値: threshold <pt>/<pe>]])`,
and the footer `<E> 件のイベントを取得: 有効 <V> 件、スキップ <S> 件、
マージ後 <M> 件`, optionally followed by the --out save line and the
policy-snapshot line. The core must be 32 hex chars, the decision type one
of the BOARD_DECISION_TYPES vocabulary, the date a valid calendar date,
the footer merged count equal to the number of draft lines, core hashes
distinct, and the threshold clause uniform (present on all draft lines iff
the disclaimer is present; its approvals count must equal the `n` in
`n/m` and satisfy `n <= m`; the policy-update proposal clause is only
accepted on policy-update drafts and must satisfy `pt <= pe`). Explicitly
out of scope: the fetched/valid/skipped counts' truth (only the merged
count is checkable), the core hash's truth (`check_draft`'s territory),
the meaning of the 充足/不足 verdict (advisory threshold display —
`fetch_threshold_status` computes it, the checker only validates its
spelling and internal arithmetic), expiry truth (the [期限切れ] marker is
a display-only marker — `draft_is_expired`'s territory), the date's
value/timezone (the reference CLI prints local time), and draft
ordering/delivery (event signature validity is
`verify_board_decision_nostr_event`'s territory).

`python3 conformance.py selftest` also covers `check_board_draft_fetch`
with reference reports produced in-process by nakama.py's own
cmd_board_draft_fetch (offline: nostr_request monkeypatched, no relay
contact).

Board-fetch-all report conformance:

    python3 conformance.py check_board_fetch_all <report1.txt> [...]

Each file is the saved stdout of `nakama.py board_fetch_all`. Verifies
the report is internally consistent: either the single no-decisions line
(`<N> 件のイベントを取得: 有効な決定（30110/30111）はありませんでした（<M>
件をスキップ）`), or — in order — the optional --policy disclaimer lines
(the second draft disclaimer appears only when at least one
草案（回覧中） record is listed), one line per merged record
(`[成立済み <32 hex core>] <decision> (created_at YYYY-MM-DD, approvals
<N> つ[, threshold <n>/<m> <充足|不足>])` or `[草案（回覧中） <32 hex
core>][ [期限切れ]] <decision> (created_at YYYY-MM-DD, approvals <N> つ[,
草案: threshold <n>/<m> <不足|充足（成立可能 — board_decide_pub で
成立公開）>[（現行規約の判定） — 提案値: threshold <pt>/<pe>]])`, and the
footer `<E> 件のイベントを取得: 有効 <V> 件、スキップ <S> 件、マージ後
<M> 件`, optionally followed by the --out save line and the
policy-snapshot line. The state tag must be one of the two vocabulary
tags, the [期限切れ] marker only on 草案（回覧中） lines, the core 32 hex
chars and distinct across lines, the decision type one of the
BOARD_DECISION_TYPES vocabulary, the date a valid calendar date, the
footer merged count equal to the number of record lines, core hashes
distinct, and the threshold clause uniform (present on all record lines
iff the first disclaimer is present; its approvals count must equal the
`n` in `n/m` and satisfy `n <= m`; the `草案: threshold` form only on
draft records, the plain form only on finalized records; the policy-update
proposal clause only on policy-update drafts and must satisfy `pt <=
pe`). Explicitly out of scope: the fetched/valid/skipped counts' truth
(only the merged count is checkable), the core hash's truth
(`check_draft`'s territory), the state tag's truth (which Nostr kinds were
merged is not visible in the report — the checker validates the tag's
spelling, never its truth), the meaning of the 充足/不足 verdict
(advisory threshold display — `fetch_threshold_status` computes it, the
checker only validates its spelling and internal arithmetic), expiry truth
(the [期限切れ] marker is display-only — `draft_is_expired`'s territory),
the date's value/timezone (the reference CLI prints local time), and
record ordering/delivery (event signature validity is
`verify_board_decision_nostr_event`'s territory).

`python3 conformance.py selftest` also covers `check_board_fetch_all`
with reference reports produced in-process by nakama.py's own
cmd_board_fetch_all (offline: nostr_request monkeypatched, no relay
contact).

`python3 conformance.py selftest` also covers `check_pub` with reference
reports produced in-process by nakama.py's own cmd_rotate_pub /
cmd_revoke_pub / cmd_compromise_pub / cmd_dm_pub / cmd_board_decide_pub /
cmd_board_draft_pub (offline: nostr_publish monkeypatched, no relay
contact).

`python3 conformance.py selftest` also covers `check_governance` with
reference reports produced in-process by nakama.py's own
cmd_board_governance (offline: nostr_request monkeypatched, no relay
contact; management events signed in-process with nakama.sign_event).

Revoke-fetch report conformance:

    python3 conformance.py check_revoke_fetch <report.txt> [...]

Each file is the saved stdout of `nakama.py revoke_fetch`. Verifies the
report is internally consistent: zero or more `取り込み:` lines —
`取り込み: revocation を registry に記録しました (bond <16 hex>...,
revoker <16 chars>...)` — followed by the footer `<E> 件のイベントを
取得: <S> 件を取り込み、<K> 件をスキップ`, which must be the final
line. The bond prefix must be 16 hex chars (case-insensitive), the
revoker prefix 16 non-space chars (the reference CLI prints an npub
truncation); the number of `取り込み:` lines must equal S, and E must
equal S + K. Explicitly out of scope: the counts' truth (the relay's
event set is the relay's claim — the checker only validates the
display's internal arithmetic), why each event was skipped (invalid
Nostr signature, non-JSON content, bond_hash mismatch, duplicate, or
invalid revocation signature — the import path's territory),
bond_hash/revoker truth (`check_revocation`'s territory), event
signature validity (`verify_revocation_event`'s territory), ordering,
and stderr.

`python3 conformance.py selftest` also covers `check_revoke_fetch` with
reference reports produced in-process by nakama.py's own
cmd_revoke_fetch (offline: nostr_request monkeypatched, no relay
contact; revocation events signed in-process with
nakama.revocation_nostr_event).

Rotate-fetch report conformance:

    python3 conformance.py check_rotate_fetch <report.txt> [...]

Each file is the saved stdout of `nakama.py rotate_fetch`. Verifies the
report is internally consistent: either the single no-publications line
`<E> 件のイベントを取得: 有効な rotation 公開はありませんでした（<K>
件をスキップ）`, or — in order — the link line `rotation 公開: <old16>...
→ <new16>... (created_at YYYY-MM-DD)`, the footer `<E> 件のイベントを
取得: 有効 1 件、スキップ <K> 件`, and (with --out) the save line
`rotation を <file> に保存しました（mode 600）`. With --chain: one `[i]`
line per chain link (indices sequential from 0), optionally followed by
the save line `最新の rotation を <file> に保存しました（mode 600）`;
the empty-chain report is the single line `rotation 公開イベントは
見つかりませんでした`. The npub prefixes must be 16 non-space chars
(the reference CLI prints an npub truncation, which is bech32, not hex),
the date a valid calendar date, and a report that shows a valid rotation
must have fetched at least 1 event. Explicitly out of scope: the counts'
truth (the relay's event set is the relay's claim), npub truth
(`check_rotation`'s territory), the date's value/timezone, chain-link
continuity (only 16-char prefixes are printed), event signature validity
(`verify_rotation_nostr_event`'s territory), ordering, and stderr.
"""

import json
import os
import re
import secrets
import sys
import time
import datetime

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import nakama  # noqa: E402

KIND_TYPE = {
    30107: 'revocation',
    30108: 'key-compromise-declaration',
    30109: 'rotation',
    30110: 'board-decision',
    30111: 'board-draft',
}

REQUIRED = {
    30107: ('bond_hash', 'revoker_npub', 'created_at'),
    30108: ('subject', 'declarant', 'created_at', 'withdrawn'),
    30109: ('old_npub', 'new_npub', 'created_at'),
    30110: ('board_id', 'decision', 'payload', 'proposer_npub', 'approvals',
            'publisher_npub', 'created_at'),
    30111: ('board_id', 'decision', 'payload', 'proposer_npub', 'approvals',
            'publisher_npub', 'created_at'),
}


def canonical_ok(content_str: str) -> tuple[bool, str]:
    """content must be compact sorted-key JSON (whichever ascii escaping)."""
    try:
        obj = json.loads(content_str)
    except Exception:
        return False, 'content is not JSON'
    if not isinstance(obj, dict):
        return False, 'content is not a JSON object'
    for ascii_flag in (True, False):
        if json.dumps(obj, sort_keys=True, separators=(',', ':'),
                      ensure_ascii=ascii_flag) == content_str:
            return True, ''
    return False, 'content is not canonical JSON (sort_keys + compact)'


def dtag(ev: dict) -> str | None:
    for t in ev.get('tags', []) or []:
        if isinstance(t, list) and len(t) >= 2 and t[0] == 'd':
            return t[1]
    return None


def conform(ev: dict) -> tuple[bool, list[str]]:
    """Three-phase NIP-F5 verification. Returns (ok, [reasons])."""
    errs: list[str] = []
    if not isinstance(ev, dict):
        return False, ['event is not a JSON object']

    kind = ev.get('kind')
    if kind not in KIND_TYPE:
        return False, [f'kind {kind!r} is not a nakama kind (30107-30111)']
    want_type = KIND_TYPE[kind]

    # phase 1: Nostr event signature
    if not nakama.verify_event_sig(ev):
        errs.append('NIP-01 event signature invalid')

    # phase 2: content JSON
    content = None
    ok_canon, canon_msg = canonical_ok(ev.get('content', ''))
    if not ok_canon:
        errs.append(f'content: {canon_msg}')
    else:
        content = json.loads(ev['content'])

    # phase 3: structural
    if content is not None:
        if content.get('protocol') != 'nakama':
            errs.append('content.protocol != "nakama"')
        if content.get('version') != 1:
            errs.append('content.version != 1')
        if content.get('type') != want_type:
            errs.append(
                f"content.type {content.get('type')!r} != {want_type!r} "
                f'for kind {kind}')
        missing = [f for f in REQUIRED[kind] if f not in content]
        if missing:
            errs.append(f'missing fields: {missing}')
        d = dtag(ev)
        if kind == 30107:
            want = content.get('bond_hash')
            if not (isinstance(want, str) and len(want) == 64):
                errs.append('bond_hash must be 64 hex chars')
            elif d != want:
                errs.append(f'd tag {d!r} != bond_hash {want!r}')
        elif kind == 30108:
            try:
                want = (f"{nakama.npub_to_hex(content['subject'])}:"
                        f"{nakama.npub_to_hex(content['declarant'])}")
            except Exception as e:
                want = None
                errs.append(f'npub decode failed: {e}')
            if want is not None and d != want:
                errs.append(f'd tag {d!r} != subject:declarant {want!r}')
        elif kind == 30109:
            try:
                want = nakama.npub_to_hex(content['old_npub'])
            except Exception as e:
                want = None
                errs.append(f'old_npub decode failed: {e}')
            if want is not None and d != want:
                errs.append(f'd tag {d!r} != old_hex {want!r}')
        else:  # 30110 / 30111
            try:
                want = nakama.decision_core_hash(content)
            except Exception as e:
                want = None
                errs.append(f'core hash failed: {e}')
            if want is not None and d != want:
                errs.append(f'd tag {d!r} != decision_core_hash {want!r}')
            htags = [t[1] for t in ev.get('tags', []) or []
                     if isinstance(t, list) and len(t) >= 2 and t[0] == 'h']
            if content.get('board_id') not in htags:
                errs.append("h tag must carry content['board_id']")
    return (len(errs) == 0), errs


def check_files(paths: list[str]) -> int:
    failures = 0
    for p in paths:
        try:
            ev = json.load(open(p))
        except Exception as e:
            print(f'{p}: FAIL (unreadable: {e})')
            failures += 1
            continue
        ok, errs = conform(ev)
        if ok:
            print(f'{p}: PASS (kind {ev.get("kind")}, '
                  f'{KIND_TYPE[ev.get("kind")]})')
        else:
            print(f'{p}: FAIL')
            for e in errs:
                print(f'    - {e}')
            failures += 1
    print(f'--- {len(paths) - failures}/{len(paths)} passed ---')
    return 0 if failures == 0 else 1


# ---------- check_dm: NIP-17 gift-wrap conformance ----------

def conform_dm(wrap: dict, recipient_secret: bytes) -> tuple[bool, list[str]]:
    """The three-phase NIP-17 check for one gift wrap."""
    errs: list[str] = []
    if wrap.get('kind') != 1059:
        return False, [f"expected kind 1059, got {wrap.get('kind')}"]
    try:
        rumor = nakama.nip17_unwrap(wrap, recipient_secret)
    except Exception as e:
        return False, [f'unwrap failed: {e}']
    # reached only when: wrap sig ok, wrap decrypts, seal is kind 14 with a
    # valid signature, rumor decrypts as kind 14 from the seal author and
    # names the recipient in a `p` tag.
    sender_npub = nakama.npub_of(bytes.fromhex(rumor['pubkey']))
    return True, [f'rumor from {sender_npub[:16]}… '
                   f'at {rumor["created_at"]}: {rumor["content"][:48]!r}']


def check_dm_files(secret_hex: str, paths: list[str]) -> int:
    try:
        secret = bytes.fromhex(secret_hex)
    except ValueError:
        print('FAIL (recipient secret must be 64 hex chars)')
        return 1
    if len(secret) != 32:
        print('FAIL (recipient secret must be 64 hex chars)')
        return 1
    failures = 0
    for p in paths:
        try:
            wrap = json.load(open(p))
        except Exception as e:
            print(f'{p}: FAIL (unreadable: {e})')
            failures += 1
            continue
        ok, info = conform_dm(wrap, secret)
        if ok:
            print(f'{p}: PASS ({info[0]})')
        else:
            print(f'{p}: FAIL')
            for e in info:
                print(f'    - {e}')
            failures += 1
    print(f'--- {len(paths) - failures}/{len(paths)} passed ---')
    return 0 if failures == 0 else 1


# ---------- check_board: nakama board descriptor conformance ----------

_BOARD_ID_RE = re.compile(r'^nakama-[0-9a-f]{1,64}$')


def conform_board(d: dict) -> tuple[bool, list[str]]:
    """Verify a nakama board descriptor (as written by `board_create`).

    Shape checks first, then the Schnorr signature by moderators[0] over
    board_descriptor_message(...). Same acceptance rule as
    `board_verify`, minus the compromise-warning advisory.
    """
    errs: list[str] = []
    if not isinstance(d, dict):
        return False, ['descriptor is not a JSON object']
    if d.get('protocol') != 'nakama':
        errs.append('protocol != "nakama"')
    if d.get('version') != 1:
        errs.append('version != 1')
    if d.get('type') != 'board':
        errs.append('type != "board"')
    board_id = d.get('board_id')
    if not (isinstance(board_id, str) and _BOARD_ID_RE.match(board_id)):
        errs.append(f'board_id {board_id!r} must be nakama-<hex>')
    relay = d.get('relay')
    if not (isinstance(relay, str)
            and relay.startswith(('ws://', 'wss://'))):
        errs.append(f'relay {relay!r} must be a ws(s):// URL')
    mods = d.get('moderators')
    if not (isinstance(mods, list) and len(mods) >= 1):
        errs.append('moderators must be a non-empty list')
    else:
        for m in mods:
            if nakama.npub_to_hex(m) is None:
                errs.append(f'moderator {m!r} is not a valid npub')
    if not isinstance(d.get('created_at'), int):
        errs.append('created_at must be an int')
    sig = d.get('sig')
    sig_b = None
    if isinstance(sig, str):
        try:
            sig_b = bytes.fromhex(sig)
        except ValueError:
            sig_b = None
    if sig_b is None or len(sig_b) != 64:
        errs.append('sig must be 128 hex chars')
    if not errs:
        try:
            msg = nakama.board_descriptor_message(board_id, relay, mods,
                                                 d['created_at'])
            if not nakama.verify_schnorr(mods[0], sig_b, msg):
                errs.append('signature invalid (moderators[0] did not sign '
                            'this descriptor)')
        except Exception as e:
            errs.append(f'signature check failed: {e}')
    return (len(errs) == 0), errs


def check_board_files(paths: list[str]) -> int:
    failures = 0
    for p in paths:
        try:
            d = json.load(open(p))
        except Exception as e:
            print(f'{p}: FAIL (unreadable: {e})')
            failures += 1
            continue
        ok, errs = conform_board(d)
        if ok:
            print(f'{p}: PASS (board {d.get("board_id")}, '
                  f'{len(d.get("moderators") or [])} moderator(s))')
        else:
            print(f'{p}: FAIL')
            for e in errs:
                print(f'    - {e}')
            failures += 1
    print(f'--- {len(paths) - failures}/{len(paths)} passed ---')
    return 0 if failures == 0 else 1


# ---------- check_decision: board-decision file conformance ----------

def conform_decision(d: dict, policy: dict | None = None):
    """Verify a board-decision file as written by `board_decide`/`board_cosign`.

    Shape checks (protocol/version/type, board_id, relay, decision type,
    per-type payload via validate_decision_payload, created_at) plus one
    Schnorr signature check per approval over board_decision_message(...),
    with approvals deduplicated by npub. Same signature acceptance rule as
    `verify_board_decision`. If `policy` is given, the threshold is also
    evaluated (policy cert must verify, and policy's board_id/relay must
    match the decision); without it, signature validity alone decides.
    Returns (ok, errs, info_lines).
    """
    errs: list[str] = []
    info: list[str] = []
    if not isinstance(d, dict):
        return False, ['decision is not a JSON object'], info
    if d.get('protocol') != 'nakama':
        errs.append('protocol != "nakama"')
    if d.get('version') != 1:
        errs.append('version != 1')
    if d.get('type') not in ('board-decision', 'board-draft'):
        errs.append('type must be "board-decision" or "board-draft"')
    board_id = d.get('board_id')
    if not isinstance(board_id, str):
        errs.append(f'board_id {board_id!r} must be a string')
    relay = d.get('relay')
    if not (isinstance(relay, str)
            and relay.startswith(('ws://', 'wss://'))):
        errs.append(f'relay {relay!r} must be a ws(s):// URL')
    decision = d.get('decision')
    if decision not in nakama.BOARD_DECISION_TYPES:
        errs.append(f'decision {decision!r} is not a known decision type')
    else:
        try:
            if not nakama.validate_decision_payload(decision, d.get('payload')):
                errs.append(f'payload shape invalid for decision {decision!r}')
        except Exception as e:
            errs.append(f'payload check failed: {e}')
    if not isinstance(d.get('created_at'), int) \
            or isinstance(d.get('created_at'), bool):
        errs.append('created_at must be an int')

    good: set[str] = set()
    msg: bytes | None = None
    approvals = d.get('approvals')
    if not (isinstance(approvals, list) and approvals):
        errs.append('approvals must be a non-empty list')
    else:
        try:
            msg = nakama.board_decision_message(
                board_id, relay, decision, d.get('payload'),
                int(d.get('created_at')))
        except Exception as e:
            errs.append(f'decision message build failed: {e}')
        if msg is not None:
            seen: set[str] = set()
            for i, a in enumerate(approvals):
                if not isinstance(a, dict):
                    errs.append(f'approval #{i} is not a dict')
                    continue
                npub = a.get('npub')
                if npub in seen:
                    continue  # dedup: one npub counts once (verify_board_decision rule)
                seen.add(npub)
                if nakama.npub_to_hex(npub) is None:
                    errs.append(f'approval #{i} npub {npub!r} is not a valid npub')
                    continue
                sig_b = None
                if isinstance(a.get('sig'), str):
                    try:
                        sig_b = bytes.fromhex(a['sig'])
                    except ValueError:
                        sig_b = None
                if sig_b is None or len(sig_b) != 64:
                    errs.append(f'approval #{i} ({npub[:16]}…): '
                                'sig must be 128 hex chars')
                    continue
                try:
                    if not nakama.verify_schnorr(npub, sig_b, msg):
                        errs.append(f'approval #{i} ({npub[:16]}…): '
                                    'invalid signature')
                    else:
                        good.add(npub)
                except Exception as e:
                    errs.append(f'approval #{i} ({npub[:16]}…): '
                                f'signature check failed: {e}')
    info.append(f'{len(good)} valid approval(s) from {len(approvals) if isinstance(approvals, list) else 0} entr(ies)')

    if policy is not None:
        if d.get('type') != 'board-decision':
            errs.append('policy check is for board-decision files only')
        elif not isinstance(policy, dict):
            errs.append('policy is not a JSON object')
        elif not nakama.verify_board_policy_cert(policy):
            errs.append('policy cert invalid (signature rule: all eligible '
                        'must sign, no outsiders)')
        else:
            ok_t, n, th = nakama.verify_board_decision(d, policy)
            info.append(f'threshold: {n}/{th}')
            if not ok_t:
                errs.append(f'threshold not met: {n}/{th} (or board_id/relay '
                            'mismatch with policy)')
    return (len(errs) == 0), errs, info


def check_decision_files(policy_path: str | None,
                         paths: list[str]) -> int:
    policy = None
    if policy_path is not None:
        try:
            policy = json.load(open(policy_path))
        except Exception as e:
            print(f'FAIL (policy unreadable: {e})')
            return 1
    failures = 0
    for p in paths:
        try:
            d = json.load(open(p))
        except Exception as e:
            print(f'{p}: FAIL (unreadable: {e})')
            failures += 1
            continue
        ok, errs, info = conform_decision(d, policy)
        if ok:
            print(f'{p}: PASS ({d.get("decision")!r} on {d.get("board_id")}; '
                  f'{"; ".join(info)})')
        else:
            print(f'{p}: FAIL')
            for e in errs:
                print(f'    - {e}')
            failures += 1
    print(f'--- {len(paths) - failures}/{len(paths)} passed ---')
    return 0 if failures == 0 else 1


# ---------- check_bond: bond certificate conformance ----------

def conform_bond(d: dict):
    """Verify a bond certificate file as completed by `accept`.

    A half-signed `propose` output is rejected (it is not a bond until
    every companion has signed). Shape checks (protocol/version,
    companions list of >= 2 unique valid npubs, created_at int, 64-hex
    nonce, signatures dict, optional expires_at int > created_at)
    plus one Schnorr signature check per companion over
    bond_message(companions, created_at, nonce, expires_at) — same
    acceptance rule as the reference `verify`: every companion must
    have a valid signature; signatures from non-companions are ignored
    (noted in info). No registry, rotation, or expiry-time policy
    checks — wire compatibility only. Returns (ok, errs, info).
    """
    errs: list[str] = []
    info: list[str] = []
    if not isinstance(d, dict):
        return False, ['bond is not a JSON object'], info
    if d.get('protocol') != 'nakama':
        errs.append('protocol != "nakama"')
    if d.get('version') != 1:
        errs.append('version != 1')

    companions = d.get('companions')
    comp_ok = True
    if not (isinstance(companions, list) and len(companions) >= 2):
        errs.append('companions must be a list of at least 2 npubs')
        comp_ok = False
    elif len(set(companions)) != len(companions):
        errs.append('companions contains duplicates')
        comp_ok = False
    elif not all(isinstance(c, str) and nakama.npub_to_hex(c) is not None
                 for c in companions):
        errs.append('every companion must be a valid npub')
        comp_ok = False
    if not isinstance(d.get('created_at'), int) \
            or isinstance(d.get('created_at'), bool):
        errs.append('created_at must be an int')
        comp_ok = False
    nonce = d.get('nonce')
    if not isinstance(nonce, str):
        errs.append('nonce must be a 64-hex string')
        comp_ok = False
    else:
        try:
            nb = bytes.fromhex(nonce)
            if len(nb) != 32:
                raise ValueError
        except ValueError:
            errs.append('nonce must be 64 hex chars')
            comp_ok = False
    expires_at = d.get('expires_at')
    if expires_at is not None:
        if not isinstance(expires_at, int) or isinstance(expires_at, bool):
            errs.append('expires_at must be an int')
            comp_ok = False
        elif isinstance(d.get('created_at'), int) \
                and expires_at <= d['created_at']:
            errs.append('expires_at must be greater than created_at')
            comp_ok = False

    msg: bytes | None = None
    sigs = d.get('signatures')
    if not (isinstance(sigs, dict) and sigs):
        errs.append('signatures must be a non-empty dict')
    elif comp_ok:
        try:
            msg = nakama.bond_message(companions, int(d['created_at']),
                                     nonce, expires_at)
        except Exception as e:
            errs.append(f'bond message build failed: {e}')
        if msg is not None:
            for npub in companions:
                sig_b = None
                if isinstance(sigs.get(npub), str):
                    try:
                        sig_b = bytes.fromhex(sigs[npub])
                    except ValueError:
                        sig_b = None
                if sig_b is None or len(sig_b) != 64:
                    errs.append(f'({npub[:16]}…): missing or malformed '
                                'signature (128 hex chars)')
                    continue
                try:
                    if not nakama.verify_schnorr(npub, sig_b, msg):
                        errs.append(f'({npub[:16]}…): invalid signature')
                except Exception as e:
                    errs.append(f'({npub[:16]}…): '
                                f'signature check failed: {e}')
            extra = [k for k in sigs if k not in companions]
            if extra:
                info.append(f'{len(extra)} non-companion signature(s) '
                            'ignored')
    info.append(f'{len(companions) if isinstance(companions, list) else 0} '
                'companion(s)'
                + (f', expires_at {expires_at}'
                   if expires_at is not None else ', no expiry'))
    return (len(errs) == 0), errs, info


def check_bond_files(paths: list[str]) -> int:
    failures = 0
    for p in paths:
        try:
            d = json.load(open(p))
        except Exception as e:
            print(f'{p}: FAIL (unreadable: {e})')
            failures += 1
            continue
        ok, errs, info = conform_bond(d)
        if ok:
            print(f'{p}: PASS ({"; ".join(info)})')
        else:
            print(f'{p}: FAIL')
            for e in errs:
                print(f'    - {e}')
            failures += 1
    print(f'--- {len(paths) - failures}/{len(paths)} passed ---')
    return 0 if failures == 0 else 1


# ---------- check_binding: platform-binding certificate conformance ----------

def conform_binding(b: dict):
    """Verify a platform-binding certificate as written by `bind`
    (spec §8.2): the claim "key X holds handle H on platform P".

    Shape checks (protocol/version/type, platform and handle as
    non-empty strings, npub valid, created_at int, sig 128 hex)
    plus the Schnorr signature over
    binding_message(platform, handle, npub, created_at) — same
    acceptance rule as the reference `verify_binding_cert`.
    Posting the binding from the handle's own account (handle→key
    direction) is operational and out of scope — wire compatibility
    only. Returns (ok, errs, info).
    """
    errs: list[str] = []
    info: list[str] = []
    if not isinstance(b, dict):
        return False, ['binding is not a JSON object'], info
    if b.get('protocol') != 'nakama':
        errs.append('protocol != "nakama"')
    if b.get('version') != 1:
        errs.append('version != 1')
    if b.get('type') != 'platform-binding':
        errs.append('type != "platform-binding"')
    shape_ok = True
    if not isinstance(b.get('platform'), str) or not b['platform'].strip():
        errs.append('platform must be a non-empty string')
        shape_ok = False
    if not isinstance(b.get('handle'), str) or not b['handle'].strip():
        errs.append('handle must be a non-empty string')
        shape_ok = False
    npub = b.get('npub')
    if not isinstance(npub, str) or nakama.npub_to_hex(npub) is None:
        errs.append('npub must be a valid npub')
        shape_ok = False
    if not isinstance(b.get('created_at'), int) \
            or isinstance(b.get('created_at'), bool):
        errs.append('created_at must be an int')
        shape_ok = False
    sig_hex = b.get('sig')
    sig_b = None
    if not isinstance(sig_hex, str):
        errs.append('sig must be a 128-hex-char string')
        shape_ok = False
    else:
        try:
            sig_b = bytes.fromhex(sig_hex)
            if len(sig_b) != 64:
                raise ValueError
        except ValueError:
            errs.append('sig must be 128 hex chars (64 bytes)')
            sig_b = None
            shape_ok = False
    if shape_ok:
        try:
            msg = nakama.binding_message(b['platform'], b['handle'],
                                         npub, int(b['created_at']))
            if not nakama.verify_schnorr(npub, sig_b, msg):
                errs.append('invalid signature over '
                            'binding_message(platform, handle, npub, '
                            'created_at)')
        except Exception as e:
            errs.append(f'signature check failed: {e}')
    info.append(f"{b.get('platform', '?')}:{b.get('handle', '?')}")
    return (len(errs) == 0), errs, info


def check_binding_files(paths: list[str]) -> int:
    failures = 0
    for p in paths:
        try:
            b = json.load(open(p))
        except Exception as e:
            print(f'{p}: FAIL (unreadable: {e})')
            failures += 1
            continue
        ok, errs, info = conform_binding(b)
        if ok:
            print(f'{p}: PASS ({"; ".join(info)})')
        else:
            print(f'{p}: FAIL')
            for e in errs:
                print(f'    - {e}')
            failures += 1
    print(f'--- {len(paths) - failures}/{len(paths)} passed ---')
    return 0 if failures == 0 else 1


# ---------- check_unbinding: unbinding certificate conformance ----------

def conform_unbinding(u: dict):
    """Verify an unbinding certificate as written by `unbind`
    (spec §9.1): the claim "key X withdraws its claim to hold handle
    H on platform P" (binding_created_at=0 withdraws every binding
    to that handle; otherwise only bindings created at or before
    that timestamp).

    Shape checks (protocol/version/type, platform and handle as
    non-empty strings, npub valid, binding_created_at int,
    reason a string — may be empty, created_at int, sig 128 hex)
    plus the key-holder's Schnorr signature over
    unbinding_message(platform, handle, npub, binding_created_at,
    reason, created_at) — same acceptance rule as the reference
    `verify_unbinding_cert`. Posting the unbinding from the handle's
    own account (handle→key direction) is operational and out of
    scope — wire compatibility only. Returns (ok, errs, info).
    """
    errs: list[str] = []
    info: list[str] = []
    if not isinstance(u, dict):
        return False, ['unbinding is not a JSON object'], info
    if u.get('protocol') != 'nakama':
        errs.append('protocol != "nakama"')
    if u.get('version') != 1:
        errs.append('version != 1')
    if u.get('type') != 'platform-binding-revocation':
        errs.append('type != "platform-binding-revocation"')
    shape_ok = True
    if not isinstance(u.get('platform'), str) or not u['platform'].strip():
        errs.append('platform must be a non-empty string')
        shape_ok = False
    if not isinstance(u.get('handle'), str) or not u['handle'].strip():
        errs.append('handle must be a non-empty string')
        shape_ok = False
    npub = u.get('npub')
    if not isinstance(npub, str) or nakama.npub_to_hex(npub) is None:
        errs.append('npub must be a valid npub')
        shape_ok = False
    bca = u.get('binding_created_at')
    if not isinstance(bca, int) or isinstance(bca, bool):
        errs.append('binding_created_at must be an int')
        shape_ok = False
    reason = u.get('reason')
    if not isinstance(reason, str):
        errs.append('reason must be a string')
        shape_ok = False
    if not isinstance(u.get('created_at'), int) \
            or isinstance(u.get('created_at'), bool):
        errs.append('created_at must be an int')
        shape_ok = False
    sig_hex = u.get('sig')
    sig_b = None
    if not isinstance(sig_hex, str):
        errs.append('sig must be a 128-hex-char string')
        shape_ok = False
    else:
        try:
            sig_b = bytes.fromhex(sig_hex)
            if len(sig_b) != 64:
                raise ValueError
        except ValueError:
            errs.append('sig must be 128 hex chars (64 bytes)')
            sig_b = None
            shape_ok = False
    if shape_ok:
        try:
            msg = nakama.unbinding_message(u['platform'], u['handle'],
                                           npub, int(bca), reason,
                                           int(u['created_at']))
            if not nakama.verify_schnorr(npub, sig_b, msg):
                errs.append('invalid signature over '
                            'unbinding_message(platform, handle, npub, '
                            'binding_created_at, reason, created_at)')
        except Exception as e:
            errs.append(f'signature check failed: {e}')
    info.append(f"{u.get('platform', '?')}:{u.get('handle', '?')}")
    if shape_ok:
        scope = 'all' if int(bca) == 0 else f'binding_created_at<={bca}'
        info.append(f'scope {scope}')
    return (len(errs) == 0), errs, info


def check_unbinding_files(paths: list[str]) -> int:
    failures = 0
    for p in paths:
        try:
            u = json.load(open(p))
        except Exception as e:
            print(f'{p}: FAIL (unreadable: {e})')
            failures += 1
            continue
        ok, errs, info = conform_unbinding(u)
        if ok:
            print(f'{p}: PASS ({"; ".join(info)})')
        else:
            print(f'{p}: FAIL')
            for e in errs:
                print(f'    - {e}')
            failures += 1
    print(f'--- {len(paths) - failures}/{len(paths)} passed ---')
    return 0 if failures == 0 else 1


# ---------- check_liveness: liveness proof conformance ----------

def conform_liveness(p: dict, bond: dict | None = None,
                     max_age: int = 7 * 86400,
                     now: int | None = None):
    """Verify a liveness proof as written by `liveness` (spec §5.6.1).

    Shape checks (protocol/version/type, valid npub, created_at int,
    64-hex nonce, 128-hex sig, optional 64-hex bond_hash) plus the
    Schnorr signature over liveness_message(npub, created_at, nonce,
    bond_hash?) — same acceptance rule as the reference
    `verify_liveness_event`. With bond given, additionally requires
    the prover npub to be a bond companion and the proof's
    bond_hash to equal bond_hash(bond), mirroring the reference.
    Freshness mirrors `verify_liveness`: created_at must not be more
    than 300s in the future (clock-skew tolerance) and age must be
    <= max_age. The revocation-registry check is local-operational
    and out of scope — wire compatibility only.
    Returns (ok, errs, info).
    """
    if now is None:
        now = int(time.time())
    errs: list[str] = []
    info: list[str] = []
    if not isinstance(p, dict):
        return False, ['liveness proof is not a JSON object'], info
    if p.get('protocol') != 'nakama':
        errs.append('protocol != "nakama"')
    if p.get('version') != 1:
        errs.append('version != 1')
    if p.get('type') != 'liveness':
        errs.append('type != "liveness"')
    shape_ok = True
    npub = p.get('npub')
    if not isinstance(npub, str) or nakama.npub_to_hex(npub) is None:
        errs.append('npub must be a valid npub')
        shape_ok = False
    if not isinstance(p.get('created_at'), int) \
            or isinstance(p.get('created_at'), bool):
        errs.append('created_at must be an int')
        shape_ok = False
    nonce = p.get('nonce')
    if not isinstance(nonce, str) \
            or not re.fullmatch(r'[0-9a-f]{64}', nonce):
        errs.append('nonce must be 64 hex chars (32 bytes)')
        shape_ok = False
    sig_hex = p.get('sig')
    sig_b = None
    if not isinstance(sig_hex, str):
        errs.append('sig must be a 128-hex-char string')
        shape_ok = False
    else:
        try:
            sig_b = bytes.fromhex(sig_hex)
            if len(sig_b) != 64:
                raise ValueError
        except ValueError:
            errs.append('sig must be 128 hex chars (64 bytes)')
            sig_b = None
            shape_ok = False
    bh = p.get('bond_hash')
    if bh is not None and not (isinstance(bh, str)
                               and re.fullmatch(r'[0-9a-f]{64}', bh)):
        errs.append('bond_hash must be 64 hex chars when present')
        shape_ok = False
    if shape_ok:
        try:
            msg = nakama.liveness_message(npub, int(p['created_at']),
                                          nonce, bh)
            if not nakama.verify_schnorr(npub, sig_b, msg):
                errs.append('invalid signature over '
                            'liveness_message(npub, created_at, nonce, '
                            'bond_hash?)')
        except Exception as e:
            errs.append(f'signature check failed: {e}')
    if bond is not None and not errs:
        companions = bond.get('companions') or []
        if npub not in companions:
            errs.append('prover npub is not a bond companion')
        elif bh != nakama.bond_hash(bond):
            errs.append('bond_hash does not match bond_hash(bond)')
    if shape_ok:
        ca = p['created_at']
        if ca > now + 300:
            errs.append('created_at is more than 300s in the future')
        elif now - ca > max_age:
            errs.append(f'proof too old ({now - ca}s > max_age {max_age}s)')
    info.append(npub if isinstance(npub, str) else '?')
    if isinstance(p.get('created_at'), int) \
            and not isinstance(p.get('created_at'), bool):
        info.append(f'age {now - p["created_at"]}s')
    return (len(errs) == 0), errs, info


def check_liveness_files(bond_path: str | None, max_age: int,
                         now: int | None, paths: list[str]) -> int:
    bond = None
    if bond_path is not None:
        try:
            bond = json.load(open(bond_path))
        except Exception as e:
            print(f'FAIL (bond unreadable: {e})')
            return 1
    failures = 0
    for p_ in paths:
        try:
            p = json.load(open(p_))
        except Exception as e:
            print(f'{p_}: FAIL (unreadable: {e})')
            failures += 1
            continue
        ok, errs, info = conform_liveness(p, bond, max_age, now)
        if ok:
            print(f"{p_}: PASS ({'; '.join(info)})")
        else:
            print(f'{p_}: FAIL')
            for e in errs:
                print(f'    - {e}')
            failures += 1
    print(f'--- {len(paths) - failures}/{len(paths)} passed ---')
    return 0 if failures == 0 else 1


# ---------- check_compromise: key-compromise-declaration conformance ----------

def conform_compromise(d: dict):
    """Verify a key-compromise-declaration as written by
    `build_compromise_declaration` (spec §13).

    Shape checks (protocol/version/type, valid subject/declarant
    npubs, created_at int, withdrawn bool, 128-hex sig, optional
    64-hex bond_hash, optional string reason/evidence) plus the
    declarant's Schnorr signature over
    compromise_message(subject_hex, declarant_hex, created_at,
    withdrawn, bond_hash?, reason?, evidence?) — same acceptance
    rule as the reference `verify_compromise_event`. Empty optional
    fields are excluded from the signed message exactly as in the
    reference; withdrawn is always included. The local compromise
    registry (import_compromise_event dedup/update semantics) is a
    local-operational step outside wire compatibility.
    Returns (ok, errs, info).
    """
    errs: list[str] = []
    info: list[str] = []
    if not isinstance(d, dict):
        return False, ['compromise declaration is not a JSON object'], info
    if d.get('protocol') != 'nakama':
        errs.append('protocol != "nakama"')
    if d.get('version') != 1:
        errs.append('version != 1')
    if d.get('type') != 'key-compromise-declaration':
        errs.append('type != "key-compromise-declaration"')
    shape_ok = True
    subject = d.get('subject')
    declarant = d.get('declarant')
    for label, v in (('subject', subject), ('declarant', declarant)):
        if not isinstance(v, str) or nakama.npub_to_hex(v) is None:
            errs.append(f'{label} must be a valid npub')
            shape_ok = False
    if not isinstance(d.get('created_at'), int) \
            or isinstance(d.get('created_at'), bool):
        errs.append('created_at must be an int')
        shape_ok = False
    withdrawn = d.get('withdrawn')
    if not isinstance(withdrawn, bool):
        errs.append('withdrawn must be a bool')
        shape_ok = False
    sig_hex = d.get('sig')
    sig_b = None
    if not isinstance(sig_hex, str):
        errs.append('sig must be a 128-hex-char string')
        shape_ok = False
    else:
        try:
            sig_b = bytes.fromhex(sig_hex)
            if len(sig_b) != 64:
                raise ValueError
        except ValueError:
            errs.append('sig must be 128 hex chars (64 bytes)')
            sig_b = None
            shape_ok = False
    bh = d.get('bond_hash', '')
    if bh and not (isinstance(bh, str)
                   and re.fullmatch(r'[0-9a-f]{64}', bh)):
        errs.append('bond_hash must be 64 hex chars when present')
        shape_ok = False
    reason = d.get('reason', '')
    evidence = d.get('evidence', '')
    for label, v in (('reason', reason), ('evidence', evidence)):
        if not isinstance(v, str):
            errs.append(f'{label} must be a string when present')
            shape_ok = False
    if shape_ok:
        try:
            msg = nakama.compromise_message(
                nakama.npub_to_hex(subject),
                nakama.npub_to_hex(declarant),
                int(d['created_at']), withdrawn, bh, reason, evidence)
            if not nakama.verify_schnorr(declarant, sig_b, msg):
                errs.append('invalid signature over '
                            'compromise_message(subject_hex, declarant_hex, '
                            'created_at, withdrawn, bond_hash?, reason?, '
                            'evidence?)')
        except Exception as e:
            errs.append(f'signature check failed: {e}')
    info.append(subject if isinstance(subject, str) else '?')
    info.append('withdrawn' if withdrawn is True else 'active')
    return (len(errs) == 0), errs, info


def conform_rotation(d: dict):
    """Verify a rotation certificate as written by `rotate` (spec §5.5).

    Shape checks (protocol/version/type, valid old/new npubs,
    created_at int, 128-hex old_sig) plus the OLD key's Schnorr
    signature over rotation_message(old_npub, new_npub, created_at) —
    the same signature rule as the reference `verify_rotation_cert`.
    The degenerate self-rotation (old_npub == new_npub) is rejected:
    a key migrating to itself proves no migration, and `rotate`
    refuses to emit one (stricter than the bare reference check,
    which only guards this at creation time — same stance as
    `conform_bond`'s expires_at > created_at rule). Chain resolution
    (rotation_chain_fetch, created_at ordering across a chain) is a
    local-operational step outside wire compatibility.
    Returns (ok, errs, info).
    """
    errs: list[str] = []
    info: list[str] = []
    if not isinstance(d, dict):
        return False, ['rotation certificate is not a JSON object'], info
    if d.get('protocol') != 'nakama':
        errs.append('protocol != "nakama"')
    if d.get('version') != 1:
        errs.append('version != 1')
    if d.get('type') != 'rotation':
        errs.append('type != "rotation"')
    shape_ok = True
    old = d.get('old_npub')
    new = d.get('new_npub')
    for label, v in (('old_npub', old), ('new_npub', new)):
        if not isinstance(v, str) or nakama.npub_to_hex(v) is None:
            errs.append(f'{label} must be a valid npub')
            shape_ok = False
    if shape_ok and old == new:
        errs.append('old_npub == new_npub: self-rotation is degenerate '
                    '(not a migration)')
        shape_ok = False
    if not isinstance(d.get('created_at'), int) \
            or isinstance(d.get('created_at'), bool):
        errs.append('created_at must be an int')
        shape_ok = False
    sig_hex = d.get('old_sig')
    sig_b = None
    if not isinstance(sig_hex, str):
        errs.append('old_sig must be a 128-hex-char string')
        shape_ok = False
    else:
        try:
            sig_b = bytes.fromhex(sig_hex)
            if len(sig_b) != 64:
                raise ValueError
        except ValueError:
            errs.append('old_sig must be 128 hex chars (64 bytes)')
            sig_b = None
            shape_ok = False
    if shape_ok:
        try:
            msg = nakama.rotation_message(old, new, int(d['created_at']))
            if not nakama.verify_schnorr(old, sig_b, msg):
                errs.append('invalid signature: the OLD key must sign '
                            'rotation_message(old_npub, new_npub, '
                            'created_at)')
        except Exception as e:
            errs.append(f'signature check failed: {e}')
    if isinstance(old, str) and isinstance(new, str):
        info.append(f'{old[:12]}... -> {new[:12]}...')
    return (len(errs) == 0), errs, info


def check_compromise_files(paths: list[str]) -> int:
    failures = 0
    for p in paths:
        try:
            d = json.load(open(p))
        except Exception as e:
            print(f'{p}: FAIL (unreadable: {e})')
            failures += 1
            continue
        ok, errs, info = conform_compromise(d)
        if ok:
            print(f"{p}: PASS ({'; '.join(info)})")
        else:
            print(f'{p}: FAIL')
            for e in errs:
                print(f'    - {e}')
            failures += 1
    print(f'--- {len(paths) - failures}/{len(paths)} passed ---')
    return 0 if failures == 0 else 1


def check_rotation_files(paths: list[str]) -> int:
    failures = 0
    for p in paths:
        try:
            d = json.load(open(p))
        except Exception as e:
            print(f'{p}: FAIL (unreadable: {e})')
            failures += 1
            continue
        ok, errs, info = conform_rotation(d)
        if ok:
            print(f"{p}: PASS ({'; '.join(info)})")
        else:
            print(f'{p}: FAIL')
            for e in errs:
                print(f'    - {e}')
            failures += 1
    print(f'--- {len(paths) - failures}/{len(paths)} passed ---')
    return 0 if failures == 0 else 1


def conform_revocation(d: dict):
    """Verify a revocation event as written by `revoke` (spec §4.3).

    Shape checks (protocol/version/type, 64-hex bond_hash, valid
    revoker npub, created_at int, 128-hex sig, optional string
    reason) plus the REVOKER's Schnorr signature over
    revocation_message(bond_hash, revoker, created_at, reason or
    '') — the same signature rule as the reference
    `verify_revocation_event` with no bond argument. bond linkage
    (revoker is a companion of the referenced bond, bond_hash matches
    bond_hash(bond)) is a local/registry-level step, like the
    registry dedup excluded from `conform_compromise`: a standalone
    file check cannot resolve the referenced bond, and the wire
    event itself is self-contained either way.
    Returns (ok, errs, info).
    """
    errs: list[str] = []
    info: list[str] = []
    if not isinstance(d, dict):
        return False, ['revocation event is not a JSON object'], info
    if d.get('protocol') != 'nakama':
        errs.append('protocol != "nakama"')
    if d.get('version') != 1:
        errs.append('version != 1')
    if d.get('type') != 'revocation':
        errs.append('type != "revocation"')
    shape_ok = True
    bh = d.get('bond_hash')
    if not (isinstance(bh, str) and re.fullmatch(r'[0-9a-f]{64}', bh)):
        errs.append('bond_hash must be 64 hex chars')
        shape_ok = False
    revoker = d.get('revoker')
    if not isinstance(revoker, str) or nakama.npub_to_hex(revoker) is None:
        errs.append('revoker must be a valid npub')
        shape_ok = False
    if not isinstance(d.get('created_at'), int) \
            or isinstance(d.get('created_at'), bool):
        errs.append('created_at must be an int')
        shape_ok = False
    sig_hex = d.get('sig')
    sig_b = None
    if not isinstance(sig_hex, str):
        errs.append('sig must be a 128-hex-char string')
        shape_ok = False
    else:
        try:
            sig_b = bytes.fromhex(sig_hex)
            if len(sig_b) != 64:
                raise ValueError
        except ValueError:
            errs.append('sig must be 128 hex chars (64 bytes)')
            sig_b = None
            shape_ok = False
    reason = d.get('reason', '')
    if not isinstance(reason, str):
        errs.append('reason must be a string when present')
        shape_ok = False
    if shape_ok:
        try:
            msg = nakama.revocation_message(bh, revoker,
                                            int(d['created_at']), reason)
            if not nakama.verify_schnorr(revoker, sig_b, msg):
                errs.append('invalid signature: the REVOKER must sign '
                            'revocation_message(bond_hash, revoker, '
                            'created_at, reason or \'\')')
        except Exception as e:
            errs.append(f'signature check failed: {e}')
    info.append(bh[:16] + '...' if isinstance(bh, str) else '?')
    if isinstance(revoker, str):
        info.append(f'revoker {revoker[:12]}...')
    if reason:
        info.append(f'reason: {reason[:40]}' if isinstance(reason, str)
                    else 'reason: <non-string>')
    return (len(errs) == 0), errs, info


def check_revocation_files(paths: list[str]) -> int:
    failures = 0
    for p in paths:
        try:
            d = json.load(open(p))
        except Exception as e:
            print(f'{p}: FAIL (unreadable: {e})')
            failures += 1
            continue
        ok, errs, info = conform_revocation(d)
        if ok:
            print(f"{p}: PASS ({'; '.join(info)})")
        else:
            print(f'{p}: FAIL')
            for e in errs:
                print(f'    - {e}')
            failures += 1
    print(f'--- {len(paths) - failures}/{len(paths)} passed ---')
    return 0 if failures == 0 else 1


# ---------- selftest: reference events built by nakama.py ----------

def conform_policy(p: dict):
    """Verify a board-policy certificate as written by `board_policy`
    / `board_policy_sign` (spec §9.4).

    Shape checks (protocol/version/type, board_id/relay non-empty
    strings, threshold int, eligible non-empty list of unique valid
    npubs, created_at int, signatures list of {npub, sig}) plus one
    Schnorr signature check per listed signature over
    board_policy_message(board_id, relay, threshold, eligible,
    created_at) — the same acceptance rule as the reference
    `verify_board_policy_cert`: the initial policy is n-of-n, so
    EVERY eligible member must have a valid signature, outsiders'
    signatures are rejected, and duplicate signatures collapse to
    one (set semantics, as in the reference). Threshold
    enforcement at decision time (§9.5) is out of scope — the cert
    carries threshold verbatim, only range-checked.
    Returns (ok, errs, info).
    """
    errs: list[str] = []
    info: list[str] = []
    if not isinstance(p, dict):
        return False, ['policy cert is not a JSON object'], info
    if p.get('protocol') != 'nakama':
        errs.append('protocol != "nakama"')
    if p.get('version') != 1:
        errs.append('version != 1')
    if p.get('type') != 'board-policy':
        errs.append('type != "board-policy"')
    shape_ok = True
    if not (isinstance(p.get('board_id'), str) and p.get('board_id')):
        errs.append('board_id must be a non-empty string')
        shape_ok = False
    if not (isinstance(p.get('relay'), str) and p.get('relay')):
        errs.append('relay must be a non-empty string')
        shape_ok = False
    threshold = p.get('threshold')
    if not isinstance(threshold, int) or isinstance(threshold, bool):
        errs.append('threshold must be an int')
        shape_ok = False
    eligible = p.get('eligible')
    if not isinstance(eligible, list) or not eligible:
        errs.append('eligible must be a non-empty list')
        shape_ok = False
    else:
        for npub in eligible:
            if not isinstance(npub, str) or nakama.npub_to_hex(npub) is None:
                errs.append('eligible must contain valid npubs only')
                shape_ok = False
                break
        else:
            if len(set(eligible)) != len(eligible):
                errs.append('eligible must contain unique npubs')
                shape_ok = False
    if isinstance(threshold, int) and not isinstance(threshold, bool) \
            and isinstance(eligible, list) and eligible:
        if not (1 <= threshold <= len(eligible)):
            errs.append('threshold must be within 1..len(eligible)')
            shape_ok = False
    if not isinstance(p.get('created_at'), int) \
            or isinstance(p.get('created_at'), bool):
        errs.append('created_at must be an int')
        shape_ok = False
    sigs = p.get('signatures')
    if not isinstance(sigs, list):
        errs.append('signatures must be a list of {npub, sig}')
        shape_ok = False
    else:
        for s in sigs:
            if not isinstance(s, dict):
                errs.append('each signature must be a {npub, sig} object')
                shape_ok = False
                break
            if not isinstance(s.get('npub'), str) \
                    or nakama.npub_to_hex(s['npub']) is None:
                errs.append('each signature must name a valid signer npub')
                shape_ok = False
                break
            sh = s.get('sig')
            try:
                if not isinstance(sh, str):
                    raise ValueError
                sb = bytes.fromhex(sh)
                if len(sb) != 64:
                    raise ValueError
            except ValueError:
                errs.append('each signature sig must be 128 hex chars '
                            '(64 bytes)')
                shape_ok = False
                break
    if shape_ok:
        try:
            msg = nakama.board_policy_message(p['board_id'], p['relay'],
                                              threshold, list(eligible),
                                              int(p['created_at']))
            for s in sigs:
                sb = bytes.fromhex(s['sig'])
                if not nakama.verify_schnorr(s['npub'], sb, msg):
                    errs.append(f'invalid signature by {s["npub"][:12]}...: '
                                'every listed signature must verify over '
                                'board_policy_message(board_id, relay, '
                                'threshold, eligible, created_at)')
            signers = {s['npub'] for s in sigs}
            if signers != set(eligible):
                missing = set(eligible) - signers
                extra = signers - set(eligible)
                if missing:
                    errs.append('n-of-n not met: missing signatures from '
                                + ', '.join(n[:12] + '...' for n in missing))
                if extra:
                    errs.append('outsider signatures rejected: '
                                + ', '.join(n[:12] + '...' for n in extra))
        except Exception as e:
            errs.append(f'signature check failed: {e}')
    info.append(f'{p.get("board_id", "?")}/{threshold}of'
                f'{len(eligible) if isinstance(eligible, list) else "?"}')
    if isinstance(sigs, list):
        info.append(f'{len(sigs)} signatures listed')
    return (len(errs) == 0), errs, info


def check_policy_files(paths: list[str]) -> int:
    failures = 0
    for p in paths:
        try:
            d = json.load(open(p))
        except Exception as e:
            print(f'{p}: FAIL (unreadable: {e})')
            failures += 1
            continue
        ok, errs, info = conform_policy(d)
        if ok:
            print(f'{p}: PASS ({"; ".join(info)})')
        else:
            print(f'{p}: FAIL')
            for e in errs:
                print(f'    - {e}')
            failures += 1
    print(f'--- {len(paths) - failures}/{len(paths)} passed ---')
    return 0 if failures == 0 else 1


# ---------- check_draft: board-decision draft conformance ----------

def conform_draft(d: dict, policy: dict | None = None,
                  now: int | None = None):
    """Verify a board-decision DRAFT as written by `board_decide` /
    `board_cosign` (spec §9.4, §21).

    Shape checks (protocol/version/type, board_id/relay,
    decision in BOARD_DECISION_TYPES, per-type payload shape,
    created_at int, approvals non-empty list of {npub, sig})
    plus one Schnorr signature check per listed approval over
    board_decision_message(board_id, relay, decision, payload,
    created_at) — the reference acceptance rule: every listed
    approval must verify; duplicate approvals collapse (set
    semantics, as in verify_board_decision via conform_decision).
    Threshold is NEVER a gate: with a policy, n/threshold is
    reported as info only. Expiry (draft_is_expired, spec §24)
    is info only — the publish-side refusal is operational.
    For policy-update drafts the §29.2 invariant holds: the
    CURRENT policy judges; proposed threshold/eligible are
    shown as info and never used for judgment. Returns
    (ok, errs, info).
    """
    errs: list[str] = []
    info: list[str] = []
    if not isinstance(d, dict):
        return False, ['draft is not a JSON object'], info
    if d.get('protocol') != 'nakama':
        errs.append('protocol != "nakama"')
    if d.get('version') != 1:
        errs.append('version != 1')
    if d.get('type') not in ('board-decision', 'board-draft'):
        errs.append('type must be "board-decision" or "board-draft"')
    board_id = d.get('board_id')
    if not (isinstance(board_id, str) and board_id):
        errs.append('board_id must be a non-empty string')
    relay = d.get('relay')
    if not (isinstance(relay, str)
            and relay.startswith(('ws://', 'wss://'))):
        errs.append(f'relay {relay!r} must be a ws(s):// URL')
    decision = d.get('decision')
    if decision not in nakama.BOARD_DECISION_TYPES:
        errs.append(f'decision {decision!r} is not a known decision type')
        decision = None
    else:
        try:
            if not nakama.validate_decision_payload(decision, d.get('payload')):
                errs.append(f'payload shape invalid for decision {decision!r}')
        except Exception as e:
            errs.append(f'payload check failed: {e}')
    if not isinstance(d.get('created_at'), int) \
            or isinstance(d.get('created_at'), bool):
        errs.append('created_at must be an int')

    good: set[str] = set()
    approvals = d.get('approvals')
    if not (isinstance(approvals, list) and approvals):
        errs.append('approvals must be a non-empty list')
    elif decision is None or not (isinstance(board_id, str)
                                  and isinstance(relay, str)):
        errs.append('approval signatures unverifiable (shape errors above)')
    else:
        try:
            msg = nakama.board_decision_message(
                board_id, relay, decision, d.get('payload'),
                int(d.get('created_at')))
        except Exception as e:
            msg = None
            errs.append(f'decision message build failed: {e}')
        if msg is not None:
            seen: set[str] = set()
            for i, a in enumerate(approvals):
                if not isinstance(a, dict):
                    errs.append(f'approval #{i} is not a dict')
                    continue
                npub = a.get('npub')
                if npub in seen:
                    continue  # dedup: one npub counts once (reference rule)
                seen.add(npub)
                if not isinstance(npub, str) \
                        or nakama.npub_to_hex(npub) is None:
                    errs.append(f'approval #{i} npub {npub!r} is not '
                                'a valid npub')
                    continue
                sb = None
                if isinstance(a.get('sig'), str):
                    try:
                        sb = bytes.fromhex(a['sig'])
                    except ValueError:
                        sb = None
                if sb is None or len(sb) != 64:
                    errs.append(f'approval #{i} ({npub[:12]}...): sig must '
                                'be 128 hex chars')
                    continue
                try:
                    if nakama.verify_schnorr(npub, sb, msg):
                        good.add(npub)
                    else:
                        errs.append(f'approval #{i} ({npub[:12]}...): '
                                    'invalid signature')
                except Exception as e:
                    errs.append(f'approval #{i} ({npub[:12]}...): '
                                f'signature check failed: {e}')
    try:
        core = nakama.decision_core_hash(d)
        info.append(f'core {core[:12]}...')
    except Exception:
        pass
    info.append(f'{len(good)} valid approval(s)')
    if now is None:
        now = int(time.time())
    if d.get('decision') in nakama.BOARD_DECISION_TYPES:
        try:
            expired = nakama.draft_is_expired(d, now)
        except Exception:
            expired = False
        if expired:
            info.append('EXPIRED (publish refused by board_draft_pub; '
                        'operational gate, not wire failure)')
    if policy is not None:
        if d.get('type') != 'board-decision':
            errs.append('policy judgment is for board-decision drafts only')
        elif not isinstance(policy, dict):
            errs.append('policy is not a JSON object')
        elif not nakama.verify_board_policy_cert(policy):
            errs.append('policy cert invalid (signature rule: all eligible '
                        'must sign, no outsiders)')
        else:
            try:
                ok_t, n, th = nakama.verify_board_decision(d, policy)
            except Exception as e:
                errs.append(f'policy judgment failed: {e}')
                ok_t, n, th = False, 0, 0
            state = 'met (enactable)' if ok_t else \
                'below threshold (draft state, not a failure)'
            info.append(f'current-policy judgment: {n}/{th} — {state}')
            if d.get('decision') == 'policy-update':
                pl = d.get('payload') or {}
                info.append('proposed values (never used for judgment, '
                            f'§29.2): threshold {pl.get("threshold")}/'
                            f'{len(pl.get("eligible", [])) if isinstance(pl.get("eligible"), list) else "?"}')
    return (len(errs) == 0), errs, info


def check_draft_files(policy_path: str | None, now: int | None,
                       paths: list[str]) -> int:
    policy = None
    if policy_path is not None:
        try:
            policy = json.load(open(policy_path))
        except Exception as e:
            print(f'FAIL (policy unreadable: {e})')
            return 1
    failures = 0
    for p in paths:
        try:
            d = json.load(open(p))
        except Exception as e:
            print(f'{p}: FAIL (unreadable: {e})')
            failures += 1
            continue
        ok, errs, info = conform_draft(d, policy, now)
        if ok:
            print(f'{p}: PASS ({d.get("decision")!r} draft on '
                  f'{d.get("board_id")}; {"; ".join(info)})')
        else:
            print(f'{p}: FAIL')
            for e in errs:
                print(f'    - {e}')
            failures += 1
    print(f'--- {len(paths) - failures}/{len(paths)} passed ---')
    return 0 if failures == 0 else 1

def conform_notif_ack(content) -> tuple[bool, list, list]:
    """Verify a notif-ack DM plaintext as written by `board_notif_ack`
    (spec §28.3).

    Acceptance mirrors the reference `parse_notif_ack` exactly:
    stripped line 0 is the `[nakama] notif-ack` header, line 1 is
    `core: <hex>` (32 hex, or 64 hex normalized to its first 32 —
    the reference normalizes both, so the checker does too),
    line 2 is `reason: <vocabulary>` in NOTIF_ACK_REASONS, line 3
    is the `---` separator. Free text (the optional note) after
    the separator is accepted without validation. Anything that
    would not parse is wire-incompatible; malformed acks are
    ignored by `board_notif_status` (spam resistance, §28.4).

    This proves format compatibility only: the plaintext itself
    carries no authorship — the seal (NIP-17, signed by the ack
    sender's real key) is what binds an ack to a sender. Pair
    with `check_dm` on the gift wrap for attributable acks.
    Returns (ok, errs, info).
    """
    errs: list[str] = []
    info: list[str] = []
    if not isinstance(content, str):
        return False, ['ack content is not text'], info
    lines = [(l or '').strip() for l in content.split('\n')]
    if len(lines) < 4:
        return False, ['ack content has fewer than 4 lines'], info
    if lines[0] != nakama.NOTIF_ACK_HEADER:
        errs.append(f'header must be {nakama.NOTIF_ACK_HEADER!r}')
    core = None
    m = re.fullmatch(r'core:\s*(\S+)', lines[1])
    if not m:
        errs.append('line 2 must be "core: <hex>"')
    else:
        core = m.group(1)
        norm = nakama.normalize_notif_core(core)
        if norm is None:
            errs.append('core must be 32 or 64 lowercase hex chars')
            core = None
        else:
            core = norm
    reason = None
    m = re.fullmatch(r'reason:\s*(\S+)', lines[2])
    if not m:
        errs.append('line 3 must be "reason: <vocabulary>"')
    else:
        reason = m.group(1)
        if reason not in nakama.NOTIF_ACK_REASONS:
            errs.append('reason must be one of '
                        f'{" / ".join(nakama.NOTIF_ACK_REASONS)}')
            reason = None
    if lines[3] != '---':
        errs.append('line 4 must be the "---" separator')
    if len(errs) == 0:
        info.append(f'core {core[:12]}...')
        info.append(f'reason: {reason}')
        note = '\n'.join(lines[4:]).strip()
        if note:
            info.append(f'note: {len(note)} chars (free text, unvalidated)')
    return (len(errs) == 0), errs, info


def check_notif_ack_files(paths: list[str]) -> int:
    failures = 0
    for p in paths:
        try:
            with open(p, encoding='utf-8') as f:
                content = f.read()
        except Exception as e:
            print(f'{p}: FAIL (unreadable: {e})')
            failures += 1
            continue
        ok, errs, info = conform_notif_ack(content)
        if ok:
            print(f"{p}: PASS ({'; '.join(info)})")
        else:
            print(f'{p}: FAIL')
            for e in errs:
                print(f'    - {e}')
            failures += 1
    print(f'--- {len(paths) - failures}/{len(paths)} passed ---')
    return 0 if failures == 0 else 1


def conform_notif_record(path: str, rec) -> tuple[bool, list, list]:
    """Verify a draft-notification send record as written by
    `draft_notif_record` (spec §25.1 / §27.1 / §28.2).

    The record is the sender's local log of a NIP-17 notification
    DM: `board_draft_notify` writes
    `<notif_dir>/<core>:<reason>.json` for the draft publisher
    (§25.1) and `<core>:<reason>:<recipient_hex>.json` for each
    --cosigners recipient (§27.1), with fields
    {core_hash, reason, recipient_hex, sender_npub, sent_at,
    gift_wrap_id, rumor_id}.

    Checks: the filename is one of the two reference forms (core
    32 or 64 hex — normalized to 32, the same rule
    `load_notif_records` applies — reason in NOTIF_ACK_REASONS,
    optional recipient suffix 64 hex); the JSON is a dict;
    core_hash normalizes to the filename's core, reason matches
    the filename's reason, and for cosigner records the
    recipient_hex field matches the filename suffix; recipient_hex
    is 64 hex, sender_npub is a valid npub, sent_at is an int (not
    bool), gift_wrap_id/rumor_id are strings when present (absent
    is accepted — pre-§28.2 records default to empty in
    `draft_notif_read_record`). Extra fields are allowed.

    Explicitly out of scope: whether the DM actually arrived —
    the record is the sender's claim only (spec §25.2), so empty
    gift_wrap_id/rumor_id and the freshness of sent_at are not
    failures. Returns (ok, errs, info).
    """
    errs: list[str] = []
    info: list[str] = []
    name = os.path.basename(path)
    fn_core = fn_reason = fn_rhx = None
    if not name.endswith('.json'):
        errs.append('record filename must end with .json')
    else:
        parts = name[:-5].split(':')
        if len(parts) not in (2, 3):
            errs.append('filename must be <core>:<reason>.json or '
                        '<core>:<reason>:<recipient_hex>.json')
        else:
            fn_core = nakama.normalize_notif_core(parts[0])
            if fn_core is None:
                errs.append('filename core must be 32 or 64 hex '
                            '(normalized to 32)')
            fn_reason = parts[1]
            if fn_reason not in nakama.NOTIF_ACK_REASONS:
                errs.append(f'filename reason must be one of '
                            f'{" / ".join(nakama.NOTIF_ACK_REASONS)}')
                fn_reason = None
            if len(parts) == 3:
                fn_rhx = parts[2].lower()
                if not re.fullmatch(r'[0-9a-f]{64}', fn_rhx):
                    errs.append('filename recipient suffix must be '
                                '64 lowercase hex')
                    fn_rhx = None
    if not isinstance(rec, dict):
        return False, errs + ['record is not a JSON object'], info
    core = nakama.normalize_notif_core(rec.get('core_hash', ''))
    if core is None:
        errs.append('core_hash must be 32 or 64 hex (normalized to 32)')
    elif fn_core is not None and core != fn_core:
        errs.append('core_hash does not match the filename core')
    reason = rec.get('reason')
    if reason not in nakama.NOTIF_ACK_REASONS:
        errs.append(f'reason must be one of '
                    f'{" / ".join(nakama.NOTIF_ACK_REASONS)}')
    elif fn_reason is not None and reason != fn_reason:
        errs.append('reason does not match the filename reason')
    rhx = rec.get('recipient_hex')
    if not isinstance(rhx, str) or not re.fullmatch(r'[0-9a-f]{64}',
                                                    rhx.lower()):
        errs.append('recipient_hex must be 64 hex')
    elif fn_rhx is not None and rhx.lower() != fn_rhx:
        errs.append('recipient_hex does not match the filename '
                    'recipient suffix')
    snpub = rec.get('sender_npub')
    if not isinstance(snpub, str) or nakama.npub_to_hex(snpub) is None:
        errs.append('sender_npub must be a valid npub')
    sent_at = rec.get('sent_at')
    if not isinstance(sent_at, int) or isinstance(sent_at, bool):
        errs.append('sent_at must be an int')
    for f in ('gift_wrap_id', 'rumor_id'):
        v = rec.get(f)
        if v is not None and not isinstance(v, str):
            errs.append(f'{f} must be a string')
    if rec.get('gift_wrap_id') is None or rec.get('rumor_id') is None:
        info.append('pre-§28.2 record: gift_wrap_id/rumor_id absent '
                    '(defaults to empty per draft_notif_read_record)')
    elif not rec['gift_wrap_id'] and not rec['rumor_id']:
        info.append('no delivery ids recorded (sender-side claim only, '
                    '§25.2)')
    known = {'core_hash', 'reason', 'recipient_hex', 'sender_npub',
             'sent_at', 'gift_wrap_id', 'rumor_id'}
    extra = sorted(set(rec) - known)
    if extra:
        info.append(f'extra fields allowed: {", ".join(extra)}')
    if len(errs) == 0:
        info.insert(0, f'core {core[:12]}... ({reason})')
        info.insert(1, f'recipient {rhx[:12]}...')
    return (len(errs) == 0), errs, info


def check_notif_record_files(paths: list[str]) -> int:
    files: list[str] = []
    for p in paths:
        if os.path.isdir(p):
            for fn in sorted(os.listdir(p)):
                if fn.endswith('.json'):
                    files.append(os.path.join(p, fn))
        else:
            files.append(p)
    failures = 0
    for p in files:
        try:
            with open(p, encoding='utf-8') as f:
                rec = json.load(f)
        except Exception as e:
            print(f'{p}: FAIL (unreadable: {e})')
            failures += 1
            continue
        ok, errs, info = conform_notif_record(p, rec)
        if ok:
            print(f'{p}: PASS ({"; ".join(info)})')
        else:
            print(f'{p}: FAIL')
            for e in errs:
                print(f'    - {e}')
            failures += 1
    print(f'--- {len(files) - failures}/{len(files)} passed ---')
    return 0 if failures == 0 else 1


# ---------- check_key_status: key_status report consistency ----------

# key_status's stdout is a human-readable report, but its sections follow a
# fixed grammar (spec §13.5 / §14.3). check_key_status verifies that a saved
# report is internally consistent: row counts match the header, withdrawn
# counts match, every category is in the §13.3 vocabulary, the verdict's
# counted-declarant number matches the counted categories
# (自分自身 / 直接の仲間 / subject を知る仲間), the verdict agrees with the
# threshold, and complete/stale migration lines agree on the rotated vs
# latest-declaration dates. Explicitly out of scope: whether the declarations
# really exist, bond-graph membership, and the exit code — unless
# --exit-code is given, which ties each verdict to the CLI's exit code.

_KEY_STATUS_CATS = ('自分自身', '直接の仲間', 'subject を知る仲間', '参考情報', '撤回済み')
_KEY_STATUS_COUNTED = ('自分自身', '直接の仲間', 'subject を知る仲間')

_RE_KS_HDR = re.compile(
    r'^subject: (\S+)\.\.\. の侵害宣言: (\d+) 件（有効な宣言、撤回済み (\d+) 件を除く）$')
_RE_KS_ROW = re.compile(
    r'^  (\S+)\.\.\.  \[(.+?)\] \((\d{4})-(\d{2})-(\d{2})\)(（撤回済み）)?(  理由: (.*))?$')
_RE_KS_INVALID = re.compile(r'^  ※ 署名無効な宣言 (\d+) 件は無視しました$')
_RE_KS_MIG_C = re.compile(
    r'^migration: complete \((.+?)\) — rotated at (\d{4}-\d{2}-\d{2}), '
    r'after latest declaration at (\d{4}-\d{2}-\d{2})( — .*)?$')
_RE_KS_MIG_S = re.compile(
    r'^migration: stale \((.+?)\) — rotation は (\d{4}-\d{2}-\d{2})、'
    r'最新の宣言は (\d{4}-\d{2}-\d{2}) より新しい。今回の移行の証拠になりません$')
_RE_KS_MIG_B = re.compile(r'^migration: broken — (.+) \(link (\d+)\)$')
_RE_KS_CNT1 = re.compile(
    r'^反証あり: subject の新しい生存証明（(\d+) 秒前）が宣言より新しい — 判断はあなたに委ねます。$')
_RE_KS_CNT2 = re.compile(r'^生存証明は宣言より古いため反証になりません。$')
_RE_KS_CNT3 = re.compile(r'^生存証明は無効または期限切れです（反証として使えません）。$')
_RE_KS_VERDICT_SUS = re.compile(
    r'^判定: 疑わしい（compromised suspected）— bond graph 内の宣言者 (\d+) 人 ≥ 閾値 (\d+)$')
_RE_KS_VERDICT_WARN = re.compile(
    r'^判定: 宣言はあるが閾値未満（(\d+) / (\d+)）— 警告として扱ってください。$')
_RE_KS_VERDICT_NONE = re.compile(r'^判定: 侵害宣言はありません。$')
_RE_KS_ARROW_SEG = re.compile(r'^[a-z0-9]{12}\.\.\.$')


def _ks_valid_date(s: str) -> bool:
    try:
        time.strptime(s, '%Y-%m-%d')
        return True
    except ValueError:
        return False


def conform_key_status_report(text: str, exit_code: int | None = None):
    """Verify a saved `nakama.py key_status` stdout report is internally
    consistent. Returns (ok, errs, info)."""
    errs: list[str] = []
    info: list[str] = []
    lines = text.splitlines()
    while lines and lines[-1] == '':
        lines.pop()
    if not lines:
        return False, ['report is empty'], info
    m = _RE_KS_HDR.match(lines[0])
    if not m:
        return False, ['header line does not match key_status grammar'], info
    subj_prefix, n_str, w_str = m.groups()
    if len(subj_prefix) != 16:
        errs.append(f'subject npub prefix is {len(subj_prefix)} chars, want 16')
    n_decl, n_withdrawn = int(n_str), int(w_str)
    rows = []
    i = 1
    while i < len(lines):
        rm = _RE_KS_ROW.match(lines[i])
        if not rm:
            break
        decl_prefix, cat, yy, mm, dd, wd, _r, reason = rm.groups()
        if len(decl_prefix) != 16:
            errs.append(f'line {i + 1}: declarant npub prefix is '
                        f'{len(decl_prefix)} chars, want 16')
        if cat not in _KEY_STATUS_CATS:
            errs.append(f'line {i + 1}: unknown category [{cat}] '
                        f'(want one of {_KEY_STATUS_CATS})')
        if not _ks_valid_date(f'{yy}-{mm}-{dd}'):
            errs.append(f'line {i + 1}: invalid date {yy}-{mm}-{dd}')
        is_wd = wd is not None
        if is_wd and cat != '撤回済み':
            errs.append(f'line {i + 1}: marked （撤回済み） but category is '
                        f'[{cat}] (want [撤回済み])')
        if not is_wd and cat == '撤回済み':
            errs.append(f'line {i + 1}: category [撤回済み] without '
                        f'（撤回済み） marker')
        rows.append({'withdrawn': is_wd, 'category': cat})
        i += 1
    if len(rows) != n_decl:
        errs.append(f'header says {n_decl} declarations but '
                    f'{len(rows)} rows listed')
    wd_rows = sum(1 for r in rows if r['withdrawn'])
    if wd_rows != n_withdrawn:
        errs.append(f'header says {n_withdrawn} withdrawn but {wd_rows} rows '
                    f'marked （撤回済み）')
    active = [r for r in rows if not r['withdrawn']]
    suspected_count = sum(1 for r in active
                          if r['category'] in _KEY_STATUS_COUNTED)
    if i < len(lines) and _RE_KS_INVALID.match(lines[i]):
        k = int(_RE_KS_INVALID.match(lines[i]).group(1))
        if k < 1:
            errs.append(f'line {i + 1}: invalid-declaration note with '
                        f'count {k} (< 1)')
        info.append(f'{k} invalid ignored')
        i += 1
    if i < len(lines) and lines[i].startswith('migration: '):
        mc = _RE_KS_MIG_C.match(lines[i])
        ms = _RE_KS_MIG_S.match(lines[i])
        mb = _RE_KS_MIG_B.match(lines[i])
        if not (mc or ms or mb):
            errs.append(f'line {i + 1}: unrecognized migration line')
        else:
            kind = 'complete' if mc else 'stale' if ms else 'broken'
            if kind != 'broken':
                mg = mc or ms
                arrow = mg.group(1)
                if any(not _RE_KS_ARROW_SEG.match(s)
                       for s in arrow.split(' -> ')):
                    errs.append(f'line {i + 1}: migration arrow malformed: '
                                f'{arrow!r}')
                rot_d, decl_d = mg.group(2), mg.group(3)
                if not _ks_valid_date(rot_d):
                    errs.append(f'line {i + 1}: invalid rotated date {rot_d}')
                if not _ks_valid_date(decl_d):
                    errs.append(f'line {i + 1}: invalid declaration date '
                                f'{decl_d}')
                if kind == 'stale' and rot_d >= decl_d:
                    errs.append(f'line {i + 1}: stale but rotated {rot_d} >= '
                                f'latest declaration {decl_d}')
                if kind == 'complete' and rot_d < decl_d:
                    errs.append(f'line {i + 1}: complete but rotated {rot_d} '
                                f'< latest declaration {decl_d}')
            info.append(f'migration {kind}')
        i += 1
    cnt1 = i < len(lines) and _RE_KS_CNT1.match(lines[i])
    if cnt1 or (i < len(lines) and
                (_RE_KS_CNT2.match(lines[i]) or _RE_KS_CNT3.match(lines[i]))):
        if cnt1 and not active:
            errs.append('counter-evidence 反証あり but no active declarations')
        info.append('counter-evidence section')
        i += 1
    if i >= len(lines):
        errs.append('missing 判定 verdict line')
    else:
        v = lines[i]
        if any(ln != '' for ln in lines[i + 1:]):
            errs.append('verdict is not the final line')
        ms = _RE_KS_VERDICT_SUS.match(v)
        mw = _RE_KS_VERDICT_WARN.match(v)
        mn = _RE_KS_VERDICT_NONE.match(v)
        if not (ms or mw or mn):
            errs.append(f'verdict line unrecognized: {v!r}')
        elif ms:
            s, t = int(ms.group(1)), int(ms.group(2))
            if s != suspected_count:
                errs.append(f'verdict says {s} counted declarants but report '
                            f'has {suspected_count}')
            if s < t:
                errs.append(f'verdict says suspected but {s} < threshold {t}')
            info.append(f'suspected ({s} >= {t})')
            if exit_code is not None and exit_code != 1:
                errs.append(f'suspected verdict requires exit code 1, '
                            f'got {exit_code}')
        elif mw:
            s, t = int(mw.group(1)), int(mw.group(2))
            if s != suspected_count:
                errs.append(f'verdict says {s} counted declarants but report '
                            f'has {suspected_count}')
            if s >= t:
                errs.append(f'verdict says below threshold but '
                            f'{s} >= threshold {t}')
            if not active:
                errs.append('verdict says declarations below threshold but '
                            'no active declarations')
            info.append(f'below threshold ({s} / {t})')
            if exit_code is not None and exit_code != 0:
                errs.append(f'below-threshold verdict requires exit code 0, '
                            f'got {exit_code}')
        else:
            if active:
                errs.append(f'verdict says no declarations but '
                            f'{len(active)} active rows listed')
            info.append('no declarations')
            if exit_code is not None and exit_code != 0:
                errs.append(f'no-declaration verdict requires exit code 0, '
                            f'got {exit_code}')
    return (not errs), errs, info


def check_key_status_files(paths: list[str], exit_code: int | None) -> int:
    failures = 0
    for p in paths:
        try:
            with open(p, encoding='utf-8') as f:
                text = f.read()
        except Exception as e:
            print(f'{p}: FAIL (unreadable: {e})')
            failures += 1
            continue
        ok, errs, info = conform_key_status_report(text, exit_code)
        if ok:
            print(f'{p}: PASS ({"; ".join(info)})')
        else:
            print(f'{p}: FAIL')
            for e in errs:
                print(f'    - {e}')
            failures += 1
    print(f'--- {len(paths) - failures}/{len(paths)} passed ---')
    return 0 if failures == 0 else 1


# ---------- check_revoke_list: revoke_list report consistency ----------

# revoke_list's stdout is a short human-readable listing, but its grammar is
# fixed (spec §12.4d). check_revoke_list verifies that a saved report is
# internally consistent: either the single empty-registry line, or the
# header '解消済み bond: N 件' (N >= 1) with exactly N rows; each row's bond
# prefix must be 16 hex chars, the revoker npub prefix 16 chars, and the date
# valid. The trailing '  理由: ...' suffix is display-only free text
# (unvalidated). Explicitly out of scope: whether the listed revocations
# really exist in the registry (the registry's claim), and their signature
# validity — check_revocation's territory.

_RE_RL_HDR = re.compile(r'^解消済み bond: (\d+) 件$')
_RE_RL_EMPTY = 'revocation registry は空です'
_RE_RL_ROW = re.compile(
    r'^  (\S+)\.\.\.  解消: (\S+)\.\.\.  '
    r'\((\d{4})-(\d{2})-(\d{2})\)(  理由: (.*))?$')
_RE_RL_HEX = frozenset('0123456789abcdefABCDEF')


def conform_revoke_list_report(text: str):
    """Verify a saved `nakama.py revoke_list` stdout report is internally
    consistent. Returns (ok, errs, info)."""
    errs: list[str] = []
    info: list[str] = []
    lines = text.splitlines()
    while lines and lines[-1] == '':
        lines.pop()
    if not lines:
        return False, ['report is empty'], info
    if len(lines) == 1 and lines[0] == _RE_RL_EMPTY:
        info.append('empty registry')
        return True, errs, info
    m = _RE_RL_HDR.match(lines[0])
    if not m:
        return False, ['header line does not match revoke_list grammar '
                       '(want "解消済み bond: N 件" or the empty-registry '
                       'line)'], info
    n = int(m.group(1))
    if n == 0:
        errs.append('header says 0 but the reference CLI prints the '
                    'empty-registry line instead of a 0-row listing')
    rows = lines[1:]
    for j, ln in enumerate(rows):
        rm = _RE_RL_ROW.match(ln)
        if not rm:
            errs.append(f'line {j + 2}: does not match revoke_list row '
                        'grammar')
            continue
        bh, rv, yy, mm, dd, _rs, _reason = rm.groups()
        if len(bh) != 16 or any(c not in _RE_RL_HEX for c in bh):
            errs.append(f'line {j + 2}: bond prefix {bh!r} is not '
                        '16 hex chars')
        if len(rv) != 16:
            errs.append(f'line {j + 2}: revoker prefix is {len(rv)} chars, '
                        'want 16')
        try:
            time.strptime(f'{yy}-{mm}-{dd}', '%Y-%m-%d')
        except ValueError:
            errs.append(f'line {j + 2}: invalid date {yy}-{mm}-{dd}')
    if len(rows) != n:
        errs.append(f'header says {n} revocations but {len(rows)} rows '
                    'listed')
    if not errs:
        info.append(f'{n} revocations listed')
    return (not errs), errs, info


def check_revoke_list_files(paths: list[str]) -> int:
    failures = 0
    for p in paths:
        try:
            with open(p, encoding='utf-8') as f:
                text = f.read()
        except Exception as e:
            print(f'{p}: FAIL (unreadable: {e})')
            failures += 1
            continue
        ok, errs, info = conform_revoke_list_report(text)
        if ok:
            print(f'{p}: PASS ({"; ".join(info)})')
        else:
            print(f'{p}: FAIL')
            for e in errs:
                print(f'    - {e}')
            failures += 1
    print(f'--- {len(paths) - failures}/{len(paths)} passed ---')
    return 0 if failures == 0 else 1


# ---------- check_notif_status: board_notif_status report consistency ----------

# board_notif_status's stdout is a short human-readable listing, but its
# grammar is fixed (spec §28.4). check_notif_status verifies that a saved
# report is internally consistent: either the single empty-dir line
# ('送信記録はありませんでした'), or one row per send record —
# '[reason] <core32> to=<npub|?> sent=<UTC|?> ack=yes(<UTC>)|-' with an
# optional ' cosigned=yes|-' column (only when --policy succeeded) —
# followed by the ack-disclaimer footer, which must be the final line and
# must not appear on the empty report. Each row's reason must be in the
# NOTIF_ACK_REASONS vocabulary, the core 32 hex chars, the to= field a
# valid npub (npub_to_hex) or '?', and the UTC timestamps valid; the
# cosigned column must be present on every row or on none. Explicitly
# out of scope: whether the DMs really arrived (the send record is the
# sender's claim only, spec §25.2), ack authorship (the NIP-17 seal —
# check_notif_ack's territory), and cosign semantics (check_decision's
# territory).

_RE_NS_EMPTY = '送信記録はありませんでした'
_RE_NS_FOOTER = ('注: ack は「読んだ」の証明ではなく、'
                 '受信者本人の主張の記録です（§28.5）')
_RE_NS_TS = r'\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2} UTC'
_RE_NS_TS_DATE = r'\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}'
_RE_NS_ROW = re.compile(
    r'^\[([a-z_]+)\] ([0-9a-fA-F]{32}) to=(\S+) '
    r'sent=(\?|' + _RE_NS_TS + r') '
    r'ack=(-|yes\((' + _RE_NS_TS_DATE + r') UTC\))'
    r'( cosigned=(yes|-))?$')


def _ns_valid_ts(s: str) -> bool:
    try:
        time.strptime(s, '%Y-%m-%d %H:%M:%S')
        return True
    except ValueError:
        return False


def _ns_valid_date(s: str) -> bool:
    """YYYY-MM-DD が暦として有効な日付か（board_decide_fetch 表示用）。"""
    try:
        time.strptime(s, '%Y-%m-%d')
        return True
    except ValueError:
        return False


def conform_notif_status_report(text: str):
    """Verify a saved `nakama.py board_notif_status` stdout report is
    internally consistent. Returns (ok, errs, info)."""
    errs: list[str] = []
    info: list[str] = []
    lines = text.splitlines()
    while lines and lines[-1] == '':
        lines.pop()
    if not lines:
        return False, ['report is empty'], info
    if len(lines) == 1 and lines[0] == _RE_NS_EMPTY:
        info.append('no send records')
        return True, errs, info
    if lines[-1] != _RE_NS_FOOTER:
        return False, ['final line is not the ack-disclaimer footer '
                       '(want the §28.5 note as the last line)'], info
    rows = lines[:-1]
    cos_col = None
    for j, ln in enumerate(rows):
        m = _RE_NS_ROW.match(ln)
        if not m:
            errs.append(f'line {j + 1}: does not match notif_status row '
                        'grammar')
            continue
        reason, core, to, sent, ack, ack_ts, _cs, cos = m.groups()
        if reason not in nakama.NOTIF_ACK_REASONS:
            errs.append(f'line {j + 1}: reason {reason!r} is not in the '
                        'NOTIF_ACK_REASONS vocabulary')
        if to != '?' and nakama.npub_to_hex(to) is None:
            errs.append(f'line {j + 1}: to={to!r} is neither a valid '
                        'npub nor ?')
        if sent != '?' and not _ns_valid_ts(sent[:-4]):
            errs.append(f'line {j + 1}: invalid sent timestamp {sent!r}')
        if ack != '-' and not _ns_valid_ts(ack_ts):
            errs.append(f'line {j + 1}: invalid ack timestamp {ack!r}')
        if cos_col is None:
            cos_col = cos is not None
        elif (cos is not None) != cos_col:
            errs.append(f'line {j + 1}: cosigned column present on some '
                        'rows but not all (reference CLI prints it on '
                        'every row or on none)')
    if not errs:
        info.append(f'{len(rows)} notif rows, footer ok')
    return (not errs), errs, info


def check_notif_status_files(paths: list[str]) -> int:
    failures = 0
    for p in paths:
        try:
            with open(p, encoding='utf-8') as f:
                text = f.read()
        except Exception as e:
            print(f'{p}: FAIL (unreadable: {e})')
            failures += 1
            continue
        ok, errs, info = conform_notif_status_report(text)
        if ok:
            print(f'{p}: PASS ({"; ".join(info)})')
        else:
            print(f'{p}: FAIL')
            for e in errs:
                print(f'    - {e}')
            failures += 1
    print(f'--- {len(paths) - failures}/{len(paths)} passed ---')
    return 0 if failures == 0 else 1


# ---------- check_board_read: board_read report consistency ----------

# board_read's stdout is a short human-readable listing of kind-9 board
# posts, and its grammar is fixed (spec §4). check_board_read verifies
# that a saved report is internally consistent: either the single
# empty-board line ('投稿はまだありません'), or one block per post — a
# header '--- [YYYY-MM-DD HH:MM:SS] <author pubkey first 16 hex>...'
# (optionally suffixed with ' ⚠ compromised?' when the local compromise
# registry holds an active declaration for the issuer, §14.2) followed by
# the post's content (one or more lines; blank lines and multi-line
# content are fine — a block ends at the next header line). The timestamp
# must parse as a calendar datetime; the author prefix must be 16 hex
# chars (case-insensitive). Every block must carry at least one content
# line: a header immediately followed by another header (or EOF) is an
# empty-content block and is rejected. Explicitly out of scope: the
# timestamp's timezone/value (the reference CLI prints local time — the
# checker validates grammar, never the zone or the instant), post
# ordering (the reference CLI sorts by event created_at), author
# truncation semantics, post delivery (spec §25.2's claim model), event
# signature validity (check_board's territory), and whether a
# ' ⚠ compromised?' note is deserved (advisory display — the checker only
# validates the suffix's spelling, not its truth).

_BRD_EMPTY = '投稿はまだありません'
_BRD_HEADER = re.compile(
    r'^--- \[(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})\] '
    r'([0-9a-fA-F]{16})\.\.\.( ⚠ compromised\?)?$')


def conform_board_read_report(text: str):
    """Verify a saved `nakama.py board_read` stdout report is internally
    consistent. Returns (ok, errs, info)."""
    errs: list[str] = []
    info: list[str] = []
    lines = text.splitlines()
    while lines and lines[-1] == '':
        lines.pop()
    if not lines:
        return False, ['report is empty'], info
    if len(lines) == 1 and lines[0] == _BRD_EMPTY:
        info.append('no posts')
        return True, errs, info
    if lines[0] == _BRD_EMPTY:
        return False, ['empty-report line appears together with '
                       'post blocks'], info
    blocks: list[list] = []
    for j, ln in enumerate(lines):
        m = _BRD_HEADER.match(ln)
        if m:
            blocks.append([j + 1, m.group(1), m.group(2), []])
            continue
        if not blocks:
            return False, [f'line {j + 1}: first line must be a post '
                           'header or the empty-board line'], info
        blocks[-1][3].append(ln)
    for lineno, ts, author, content in blocks:
        if not _ns_valid_ts(ts):
            errs.append(f'line {lineno}: invalid display timestamp '
                        f'{ts!r}')
        if not content:
            errs.append(f'line {lineno}: post block has no content '
                        'lines')
    if not errs:
        info.append(f'{len(blocks)} post blocks')
    return (not errs), errs, info


def check_board_read_files(paths: list[str]) -> int:
    failures = 0
    for p in paths:
        try:
            with open(p, encoding='utf-8') as f:
                text = f.read()
        except Exception as e:
            print(f'{p}: FAIL (unreadable: {e})')
            failures += 1
            continue
        ok, errs, info = conform_board_read_report(text)
        if ok:
            print(f'{p}: PASS ({"; ".join(info)})')
        else:
            print(f'{p}: FAIL')
            for e in errs:
                print(f'    - {e}')
            failures += 1
    print(f'--- {len(paths) - failures}/{len(paths)} passed ---')
    return 0 if failures == 0 else 1


# ---------- check_board_decide_fetch: board_decide_fetch report consistency ----------

# board_decide_fetch's stdout is a short human-readable listing of
# published board decisions fetched from a relay (kind 30110, #h=board_id),
# and its grammar is fixed (spec §19). check_board_decide_fetch verifies
# that a saved report is internally consistent: either the single
# no-decisions line, or — in order — the optional --policy disclaimer
# line, one line per merged decision, the summary footer, and (with
# --out) the save line plus the policy-snapshot line. Verified: core is
# 32 hex chars and distinct across lines (merge_decision_approvals emits
# one line per core), decision type is in BOARD_DECISION_TYPES, the
# created_at date is a valid calendar date, the footer merged count equals
# the number of decision lines, the --out save line's count matches the
# footer, the threshold clause is uniform (all lines iff the disclaimer
# is present; its approvals count equals the n in n/m and satisfies
# n <= m), and the optional post-footer lines appear only in their fixed
# order. Explicitly out of scope: the fetched/valid/skipped counts' truth
# (only the merged count is checkable from the report), the core hash's
# truth (check_decision's territory), the 充足/不足 verdict's meaning
# (advisory display — fetch_threshold_status computes it, the checker
# only validates spelling and internal arithmetic), the date's
# value/timezone (the reference CLI prints local time — the checker
# validates grammar, never the zone or the instant), decision ordering,
# and event signature validity (verify_board_decision_nostr_event's
# territory).

_BDF_EMPTY = re.compile(
    r'^(\d+) 件のイベントを取得: 有効な board-decision 公開はありませんでした'
    r'（(\d+) 件をスキップ）$')
_BDF_DISCLAIMER = ('threshold 表示は取得できた決定に基づく暫定です'
                   '（権威ある判定は board_read --governance）')
_BDF_LINE_PLAIN = re.compile(
    r'^\[([0-9a-fA-F]{32})\] (\S+) \(created_at (\d{4}-\d{2}-\d{2}), '
    r'approvals (\d+) つ\)$')
_BDF_LINE_POLICY = re.compile(
    r'^\[([0-9a-fA-F]{32})\] (\S+) \(created_at (\d{4}-\d{2}-\d{2}), '
    r'approvals (\d+) つ, threshold (\d+)/(\d+) (充足|不足)\)$')
_BDF_FOOTER = re.compile(
    r'^(\d+) 件のイベントを取得: 有効 (\d+) 件、スキップ (\d+) 件、'
    r'マージ後 (\d+) 件$')
_BDF_SAVED = re.compile(
    r'^(\d+) 件の決定を (.+)/ に保存しました'
    r'（board_read --governance --decisions にそのまま渡せます）$')
_BDF_SNAPSHOT = re.compile(
    r'^fetch 時点の政策スナップショットを (.+) に保存しました'
    r'（検証者はこのファイルを --policy に指定して threshold 判定を再現できます）$')


def conform_board_decide_fetch_report(text: str):
    """Verify a saved `nakama.py board_decide_fetch` stdout report is
    internally consistent. Returns (ok, errs, info)."""
    errs: list[str] = []
    info: list[str] = []
    lines = text.splitlines()
    while lines and lines[-1] == '':
        lines.pop()
    if not lines:
        return False, ['report is empty'], info
    if len(lines) == 1 and _BDF_EMPTY.match(lines[0]):
        info.append('no published decisions')
        return True, errs, info
    if _BDF_EMPTY.match(lines[0]):
        return False, ['empty-report line appears together with '
                       'decision lines'], info
    pos = 0
    with_policy = False
    if lines[0] == _BDF_DISCLAIMER:
        with_policy = True
        pos = 1
        info.append('policy threshold display')
    decs: list[tuple] = []
    while pos < len(lines):
        m = (_BDF_LINE_POLICY if with_policy else _BDF_LINE_PLAIN).match(lines[pos])
        if with_policy and not m:
            break
        if not with_policy and not m:
            break
        decs.append((pos + 1, m.group(1), m.group(2), m.group(3),
                     int(m.group(4)), m.groups()[4:] if with_policy else ()))
        pos += 1
    if not decs:
        return False, [f'line {pos + 1}: expected a decision line'], info
    seen_cores: set[str] = set()
    for lineno, core, dtype, date, approvals, thr in decs:
        if dtype not in nakama.BOARD_DECISION_TYPES:
            errs.append(f'line {lineno}: unknown decision type {dtype!r}')
        if not _ns_valid_date(date):
            errs.append(f'line {lineno}: invalid display date {date!r}')
        if core.lower() in seen_cores:
            errs.append(f'line {lineno}: duplicate decision core {core}')
        seen_cores.add(core.lower())
        if thr:
            tn, tm = int(thr[0]), int(thr[1])
            if approvals != tn:
                errs.append(f'line {lineno}: approvals count {approvals} '
                            f'does not match threshold numerator {tn}')
            if tn > tm:
                errs.append(f'line {lineno}: threshold {tn}/{tm} has '
                            f'numerator larger than denominator')
    if pos >= len(lines):
        return False, errs + [f'line {pos + 1}: missing summary footer'], info
    fm = _BDF_FOOTER.match(lines[pos])
    if not fm:
        return False, [f'line {pos + 1}: expected the summary footer, '
                       f'got {lines[pos]!r}'], info
    merged = int(fm.group(4))
    if merged != len(decs):
        errs.append(f'line {pos + 1}: footer says merged {merged} '
                    f'but {len(decs)} decision lines were listed')
    pos += 1
    saved = None
    if pos < len(lines):
        sm = _BDF_SAVED.match(lines[pos])
        if sm:
            saved = sm
            if int(sm.group(1)) != merged:
                errs.append(f'line {pos + 1}: save line says {sm.group(1)} '
                            f'decisions but footer merged count is {merged}')
            pos += 1
    if pos < len(lines):
        if not saved:
            return False, [f'line {pos + 1}: unexpected line after the '
                           f'summary footer: {lines[pos]!r}'], info
        if not _BDF_SNAPSHOT.match(lines[pos]):
            return False, [f'line {pos + 1}: expected the policy-snapshot '
                           f'line, got {lines[pos]!r}'], info
        pos += 1
    if pos != len(lines):
        return False, [f'line {pos + 1}: unexpected trailing line '
                       f'{lines[pos]!r}'], info
    if not errs:
        info.append(f'{len(decs)} decision lines, merged {merged}')
    return (not errs), errs, info


def check_board_decide_fetch_files(paths: list[str]) -> int:
    failures = 0
    for p in paths:
        try:
            with open(p, encoding='utf-8') as f:
                text = f.read()
        except Exception as e:
            print(f'{p}: FAIL (unreadable: {e})')
            failures += 1
            continue
        ok, errs, info = conform_board_decide_fetch_report(text)
        if ok:
            print(f'{p}: PASS ({"; ".join(info)})')
        else:
            print(f'{p}: FAIL')
            for e in errs:
                print(f'    - {e}')
            failures += 1
    print(f'--- {len(paths) - failures}/{len(paths)} passed ---')
    return 0 if failures == 0 else 1

# ---------- check_board_draft_fetch: board_draft_fetch report consistency ----------

# board_draft_fetch's stdout is a short human-readable listing of published
# board drafts fetched from a relay (kind 30111, #h=board_id),
# and its grammar is fixed (spec §21). check_board_draft_fetch verifies
# that a saved report is internally consistent: either the single
# no-drafts line, or — in order — the optional --policy disclaimer line,
# one line per merged draft, the summary footer, and (with --out) the save
# line plus the policy-snapshot line. Each draft line carries the [草案]
# prefix (so 30110 decide-fetch reports are never accepted here) and the
# optional [期限切れ] marker (expiry is a display-only marker, §24.2).
# Verified: core is 32 hex chars and distinct across lines (the reference
# CLI prints one line per merged core), decision type is in
# BOARD_DECISION_TYPES, the created_at date is a valid calendar date, the
# footer merged count equals the number of draft lines, the --out save
# line's count matches the footer, and the threshold clause is uniform
# (present on all draft lines iff the disclaimer is present; its
# approvals count equals the n in n/m and satisfies n <= m; a policy-update
# draft's proposal clause `（現行規約の判定） — 提案値: threshold pt/pe`
# is only accepted on policy-update drafts and must satisfy pt <= pe).
# Explicitly out of scope: the fetched/valid/skipped counts' truth (only
# the merged count is checkable), the core hash's truth (check_draft's
# territory), the 充足/不足 verdict's meaning (advisory display —
# fetch_threshold_status computes it, the checker only validates spelling
# and internal arithmetic), expiry truth (draft_is_expired's territory —
# the checker validates the marker's spelling only), the date's
# value/timezone (the reference CLI prints local time), draft ordering,
# and event signature validity (verify_board_decision_nostr_event's
# territory).

_BRF_EMPTY = re.compile(
    r'^(\d+) 件のイベントを取得: 有効な草案はありませんでした'
    r'（(\d+) 件をスキップ）$')
_BRF_DISCLAIMER = ('草案（回覧中）の threshold 表示は取得できた草案に基づく暫定です'
                   '（草案は成立の証拠ではありません — 成立の公開宣言は kind 30110）')
_BRF_LINE_PLAIN = re.compile(
    r'^\[草案 ([0-9a-fA-F]{32})\]( \[期限切れ\])? (\S+) '
    r'\(created_at (\d{4}-\d{2}-\d{2}), approvals (\d+) つ\)$')
_BRF_LINE_POLICY = re.compile(
    r'^\[草案 ([0-9a-fA-F]{32})\]( \[期限切れ\])? (\S+) '
    r'\(created_at (\d{4}-\d{2}-\d{2}), approvals (\d+) つ, '
    r'草案: threshold (\d+)/(\d+) (不足|充足（成立可能 — '
    r'board_decide_pub で成立公開）)'
    r'(（現行規約の判定） — 提案値: threshold (\d+)/(\d+))?\)$')
_BRF_FOOTER = re.compile(
    r'^(\d+) 件のイベントを取得: 有効 (\d+) 件、スキップ (\d+) 件、'
    r'マージ後 (\d+) 件$')
_BRF_SAVED = re.compile(
    r'^(\d+) 件の草案を (.+)/ に保存しました'
    r'（board_cosign で追記 → board_draft_pub にそのまま渡せます）$')
_BRF_SNAPSHOT = re.compile(
    r'^fetch 時点の政策スナップショットを (.+) に保存しました'
    r'（検証者はこのファイルを --policy に指定して threshold 判定を再現できます）$')


def conform_board_draft_fetch_report(text: str):
    """Verify a saved `nakama.py board_draft_fetch` stdout report is
    internally consistent. Returns (ok, errs, info)."""
    errs: list[str] = []
    info: list[str] = []
    lines = text.splitlines()
    while lines and lines[-1] == '':
        lines.pop()
    if not lines:
        return False, ['report is empty'], info
    if len(lines) == 1 and _BRF_EMPTY.match(lines[0]):
        info.append('no published drafts')
        return True, errs, info
    if _BRF_EMPTY.match(lines[0]):
        return False, ['empty-report line appears together with '
                       'draft lines'], info
    pos = 0
    with_policy = False
    if lines[0] == _BRF_DISCLAIMER:
        with_policy = True
        pos = 1
        info.append('policy threshold display')
    decs: list[tuple] = []
    while pos < len(lines):
        m = (_BRF_LINE_POLICY if with_policy else _BRF_LINE_PLAIN).match(lines[pos])
        if not m:
            break
        decs.append((pos + 1, m.group(1), m.group(3), m.group(4),
                     int(m.group(5)), m.groups()[5:] if with_policy else ()))
        pos += 1
    if not decs:
        return False, [f'line {pos + 1}: expected a draft line'], info
    seen_cores: set[str] = set()
    for lineno, core, dtype, date, approvals, thr in decs:
        if dtype not in nakama.BOARD_DECISION_TYPES:
            errs.append(f'line {lineno}: unknown decision type {dtype!r}')
        if not _ns_valid_date(date):
            errs.append(f'line {lineno}: invalid display date {date!r}')
        if core.lower() in seen_cores:
            errs.append(f'line {lineno}: duplicate draft core {core}')
        seen_cores.add(core.lower())
        if thr:
            tn, tm = int(thr[0]), int(thr[1])
            if approvals != tn:
                errs.append(f'line {lineno}: approvals count {approvals} '
                            f'does not match threshold numerator {tn}')
            if tn > tm:
                errs.append(f'line {lineno}: threshold {tn}/{tm} has '
                            f'numerator larger than denominator')
            if thr[3] is not None:
                if dtype != 'policy-update':
                    errs.append(f'line {lineno}: proposal clause on a '
                                f'non-policy-update draft ({dtype!r})')
                else:
                    pt, pe = int(thr[4]), int(thr[5])
                    if pt > pe:
                        errs.append(f'line {lineno}: proposed threshold '
                                    f'{pt}/{pe} has numerator larger '
                                    f'than denominator')
    if pos >= len(lines):
        return False, errs + [f'line {pos + 1}: missing summary footer'], info
    fm = _BRF_FOOTER.match(lines[pos])
    if not fm:
        return False, [f'line {pos + 1}: expected the summary footer, '
                       f'got {lines[pos]!r}'], info
    merged = int(fm.group(4))
    if merged != len(decs):
        errs.append(f'line {pos + 1}: footer says merged {merged} '
                    f'but {len(decs)} draft lines were listed')
    pos += 1
    saved = None
    if pos < len(lines):
        sm = _BRF_SAVED.match(lines[pos])
        if sm:
            saved = sm
            if int(sm.group(1)) != merged:
                errs.append(f'line {pos + 1}: save line says {sm.group(1)} '
                            f'drafts but footer merged count is {merged}')
            pos += 1
    if pos < len(lines):
        if not saved:
            return False, [f'line {pos + 1}: unexpected line after the '
                           f'summary footer: {lines[pos]!r}'], info
        if not _BRF_SNAPSHOT.match(lines[pos]):
            return False, [f'line {pos + 1}: expected the policy-snapshot '
                           f'line, got {lines[pos]!r}'], info
        pos += 1
    if pos != len(lines):
        return False, [f'line {pos + 1}: unexpected trailing line '
                       f'{lines[pos]!r}'], info
    if not errs:
        info.append(f'{len(decs)} draft lines, merged {merged}')
    return (not errs), errs, info


def check_board_draft_fetch_files(paths: list[str]) -> int:
    failures = 0
    for p in paths:
        try:
            with open(p, encoding='utf-8') as f:
                text = f.read()
        except Exception as e:
            print(f'{p}: FAIL (unreadable: {e})')
            failures += 1
            continue
        ok, errs, info = conform_board_draft_fetch_report(text)
        if ok:
            print(f'{p}: PASS ({"; ".join(info)})')
        else:
            print(f'{p}: FAIL')
            for e in errs:
                print(f'    - {e}')
            failures += 1
    print(f'--- {len(paths) - failures}/{len(paths)} passed ---')
    return 0 if failures == 0 else 1


# ---------- check_board_fetch_all: board_fetch_all report consistency ----------

# board_fetch_all's stdout is a short human-readable cross-kind listing of
# published board decisions (kind 30110) and circulating drafts (kind 30111)
# fetched from a relay in a single REQ (#h=board_id), merged by decision
# core hash, and its grammar is fixed (spec §22). check_board_fetch_all
# verifies that a saved report is internally consistent: either the single
# no-decisions line, or — in order — the optional --policy disclaimer lines
# (the second draft disclaimer appears only when at least one 草案（回覧中）
# record is listed), one line per merged record, the summary footer, and
# (with --out) the save line plus the policy-snapshot line. A record line is
# '[成立済み <32 hex core>] <decision> (created_at YYYY-MM-DD, approvals <N>
# つ[, threshold <n>/<m> <充足|不足>])' for finalized records, or
# '[草案（回覧中） <32 hex core>][ [期限切れ]] <decision> (created_at
# YYYY-MM-DD, approvals <N> つ[, 草案: threshold <n>/<m> <不足|充足（成立可能
# — board_decide_pub で成立公開）>[（現行規約の判定） — 提案値: threshold
# <pt>/<pe>]])' for drafts. Verified: the state tag is one of the two
# vocabulary tags, the [期限切れ] marker appears only on 草案（回覧中） lines
# (the reference CLI never prints it on a 成立済み line — §24.2), the core is
# 32 hex chars and distinct across lines, the decision type is in
# BOARD_DECISION_TYPES, the created_at date is a valid calendar date, the
# footer merged count equals the number of record lines, the --out save
# line's count matches the footer, the threshold clause is uniform (present
# on all record lines iff the first disclaimer is present; its approvals
# count must equal the `n` in `n/m` and satisfy `n <= m`; the `草案:
# threshold` form is only accepted on 草案（回覧中） lines, the plain
# `threshold` form only on 成立済み lines; the policy-update proposal clause
# is only accepted on policy-update drafts and must satisfy `pt <= pe`), the
# second draft disclaimer is present exactly when the first disclaimer and at
# least one draft record are, and the optional post-footer lines appear only
# in their fixed order. Explicitly out of scope: the fetched/valid/skipped
# counts' truth (only the merged count is checkable from the report), the
# core hash's truth (check_draft's territory), the state tag's truth (which
# Nostr kinds were merged is not visible in the report — the checker
# validates the tag's spelling, never its truth), the 充足/不足 verdict's
# meaning (advisory display — fetch_threshold_status computes it, the checker
# only validates spelling and internal arithmetic), expiry truth (the
# [期限切れ] marker is display-only — draft_is_expired's territory), the
# date's value/timezone (the reference CLI prints local time — the checker
# validates grammar, never the zone or the instant), record ordering, and
# event signature validity (verify_board_decision_nostr_event's territory).

_BFA_EMPTY = re.compile(
    r'^(\d+) 件のイベントを取得: 有効な決定（30110/30111）はありませんでした'
    r'（(\d+) 件をスキップ）$')
_BFA_DISCLAIMER1 = ('threshold 表示は取得できた決定に基づく暫定です'
                   '（権威ある判定は board_read --governance）')
_BFA_DISCLAIMER2 = ('草案（回覧中）の threshold 表示は取得できた草案に基づく暫定です'
                   '（草案は成立の証拠ではありません — 成立の公開宣言は kind 30110）')
_BFA_LINE = re.compile(
    r'^\[(成立済み|草案（回覧中）) ([0-9a-fA-F]{32})\]( \[期限切れ\])? '
    r'(\S+) \(created_at (\d{4}-\d{2}-\d{2}), approvals (\d+) つ'
    r'(, (?:(草案: ))?threshold (\d+)/(\d+) '
    r'(充足（成立可能 — board_decide_pub で成立公開）|充足|不足)'
    r'(（現行規約の判定） — 提案値: threshold (\d+)/(\d+))?)?'
    r'\)$')
_BFA_FOOTER = _BDF_FOOTER  # same summary footer text as the two sibling fetchers
_BFA_SAVED = re.compile(
    r'^(\d+) 件の決定を (.+)/ に保存しました'
    r'（board_read --governance --decisions / board_cosign にそのまま渡せます。'
    r'fetch 時点のスナップショット — 草案の approvals は増える可能性があります）$')
_BFA_SNAPSHOT = _BRF_SNAPSHOT  # same policy-snapshot line text as the siblings


def conform_board_fetch_all_report(text: str):
    """Verify a saved `nakama.py board_fetch_all` stdout report is
    internally consistent. Returns (ok, errs, info)."""
    errs: list[str] = []
    info: list[str] = []
    lines = text.splitlines()
    while lines and lines[-1] == '':
        lines.pop()
    if not lines:
        return False, ['report is empty'], info
    if len(lines) == 1 and _BFA_EMPTY.match(lines[0]):
        info.append('no published decisions/drafts')
        return True, errs, info
    if _BFA_EMPTY.match(lines[0]):
        return False, ['empty-report line appears together with '
                       'record lines'], info
    pos = 0
    with_policy = False
    if lines[0] == _BFA_DISCLAIMER1:
        with_policy = True
        pos = 1
        info.append('policy threshold display')
    elif lines[0] == _BFA_DISCLAIMER2:
        return False, ['draft disclaimer line without the policy '
                       'disclaimer line'], info
    with_draft_disclaimer = False
    if pos < len(lines) and lines[pos] == _BFA_DISCLAIMER2:
        with_draft_disclaimer = True
        pos += 1
        info.append('draft threshold disclaimer')
    recs: list[tuple] = []
    while pos < len(lines):
        m = _BFA_LINE.match(lines[pos])
        if not m:
            break
        recs.append((pos + 1, m))
        pos += 1
    if not recs:
        return False, [f'line {pos + 1}: expected a record line'], info
    has_draft = any(m.group(1) == '草案（回覧中）' for _, m in recs)
    if with_policy and has_draft and not with_draft_disclaimer:
        errs.append('draft records are listed but the draft disclaimer '
                    'line is missing')
    if with_draft_disclaimer and not has_draft:
        errs.append('draft disclaimer line is present but no draft records '
                    'are listed')
    seen_cores: set[str] = set()
    for lineno, m in recs:
        tag, core, expired = m.group(1), m.group(2), m.group(3)
        dtype, date, approvals = m.group(4), m.group(5), int(m.group(6))
        thr, draft_prefix = m.group(7), m.group(8)
        if tag == '成立済み' and expired:
            errs.append(f'line {lineno}: [期限切れ] marker on a finalized '
                        'record (the marker is draft-phase only)')
        if with_policy and not thr:
            errs.append(f'line {lineno}: threshold clause missing under the '
                        'policy disclaimer')
        if not with_policy and thr:
            errs.append(f'line {lineno}: threshold clause without the policy '
                        'disclaimer')
        if dtype not in nakama.BOARD_DECISION_TYPES:
            errs.append(f'line {lineno}: unknown decision type {dtype!r}')
        if not _ns_valid_date(date):
            errs.append(f'line {lineno}: invalid display date {date!r}')
        if core.lower() in seen_cores:
            errs.append(f'line {lineno}: duplicate record core {core}')
        seen_cores.add(core.lower())
        if thr:
            tn, tm = int(m.group(9)), int(m.group(10))
            status, prop = m.group(11), m.group(12)
            if tag == '成立済み':
                if draft_prefix:
                    errs.append(f'line {lineno}: draft threshold form on a '
                                'finalized record')
                if prop:
                    errs.append(f'line {lineno}: proposal clause on a '
                                'finalized record')
                if status not in ('充足', '不足'):
                    errs.append(f'line {lineno}: unexpected status '
                                f'{status!r} on a finalized record')
            else:
                if not draft_prefix:
                    errs.append(f'line {lineno}: plain threshold form on a '
                                'draft record')
                if status not in ('不足',
                                  '充足（成立可能 — board_decide_pub で成立公開）'):
                    errs.append(f'line {lineno}: unexpected status '
                                f'{status!r} on a draft record')
                if prop:
                    if dtype != 'policy-update':
                        errs.append(f'line {lineno}: proposal clause on a '
                                    f'non-policy-update draft ({dtype!r})')
                    else:
                        pt, pe = int(m.group(13)), int(m.group(14))
                        if pt > pe:
                            errs.append(f'line {lineno}: proposed threshold '
                                        f'{pt}/{pe} has numerator larger '
                                        'than denominator')
            if approvals != tn:
                errs.append(f'line {lineno}: approvals count {approvals} '
                            f'does not match threshold numerator {tn}')
            if tn > tm:
                errs.append(f'line {lineno}: threshold {tn}/{tm} has '
                            'numerator larger than denominator')
    if pos >= len(lines):
        return False, errs + [f'line {pos + 1}: missing summary footer'], info
    fm = _BFA_FOOTER.match(lines[pos])
    if not fm:
        return False, [f'line {pos + 1}: expected the summary footer, '
                       f'got {lines[pos]!r}'], info
    merged = int(fm.group(4))
    if merged != len(recs):
        errs.append(f'line {pos + 1}: footer says merged {merged} '
                    f'but {len(recs)} record lines were listed')
    pos += 1
    saved = None
    if pos < len(lines):
        sm = _BFA_SAVED.match(lines[pos])
        if sm:
            saved = sm
            if int(sm.group(1)) != merged:
                errs.append(f'line {pos + 1}: save line says {sm.group(1)} '
                            f'records but footer merged count is {merged}')
            pos += 1
    if pos < len(lines):
        if not saved:
            return False, [f'line {pos + 1}: unexpected line after the '
                           f'summary footer: {lines[pos]!r}'], info
        if not _BFA_SNAPSHOT.match(lines[pos]):
            return False, [f'line {pos + 1}: expected the policy-snapshot '
                           f'line, got {lines[pos]!r}'], info
        pos += 1
    if pos != len(lines):
        return False, [f'line {pos + 1}: unexpected trailing line '
                       f'{lines[pos]!r}'], info
    if not errs:
        info.append(f'{len(recs)} record lines, merged {merged}')
    return (not errs), errs, info


def check_board_fetch_all_files(paths: list[str]) -> int:
    failures = 0
    for p in paths:
        try:
            with open(p, encoding='utf-8') as f:
                text = f.read()
        except Exception as e:
            print(f'{p}: FAIL (unreadable: {e})')
            failures += 1
            continue
        ok, errs, info = conform_board_fetch_all_report(text)
        if ok:
            print(f'{p}: PASS ({"; ".join(info)})')
        else:
            print(f'{p}: FAIL')
            for e in errs:
                print(f'    - {e}')
            failures += 1
    print(f'--- {len(paths) - failures}/{len(paths)} passed ---')
    return 0 if failures == 0 else 1


# dm_fetch's stdout is a short human-readable listing of decrypted rumors,
# but its grammar is fixed (spec §4.1). check_dm_fetch verifies that a
# saved report is internally consistent: either the single no-new-DMs line
# ('新しい DM はありませんでした'), or one block per rumor — a header
# '--- [YYYY-MM-DD HH:MM:SS] from <sender pubkey first 16 hex>...' followed
# by the rumor's plaintext content (one or more lines; blank lines and
# multi-line content are fine — a block ends at the next header line).
# The timestamp must parse as a calendar datetime; the sender prefix must
# be 16 hex chars (case-insensitive). Every block must carry at least one
# content line: a header immediately followed by another header (or EOF)
# is an empty-content block and is rejected. Explicitly out of scope:
# the timestamp's timezone/value (the reference CLI prints local time —
# the checker validates grammar, never the zone or the instant), message
# ordering (the reference CLI sorts by gift-wrap created_at, not display
# time), sender truncation semantics, DM delivery (spec §25.2's claim
# model), and ack/seal authorship (check_dm's and check_notif_ack's
# territory).

_RE_DMF_EMPTY = '新しい DM はありませんでした'
_RE_DMF_HEADER = re.compile(
    r'^--- \[(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})\] '
    r'from ([0-9a-fA-F]{16})\.\.\.$')


def conform_dm_fetch_report(text: str):
    """Verify a saved `nakama.py dm_fetch` stdout report is internally
    consistent. Returns (ok, errs, info)."""
    errs: list[str] = []
    info: list[str] = []
    lines = text.splitlines()
    while lines and lines[-1] == '':
        lines.pop()
    if not lines:
        return False, ['report is empty'], info
    if len(lines) == 1 and lines[0] == _RE_DMF_EMPTY:
        info.append('no new DMs')
        return True, errs, info
    if lines[0] == _RE_DMF_EMPTY:
        return False, ['empty-report line appears together with '
                       'message blocks'], info
    blocks: list[list] = []
    for j, ln in enumerate(lines):
        m = _RE_DMF_HEADER.match(ln)
        if m:
            blocks.append([j + 1, m.group(1), m.group(2), []])
            continue
        if not blocks:
            return False, [f'line {j + 1}: first line must be a message '
                           'header or the no-new-DMs line'], info
        blocks[-1][3].append(ln)
    for lineno, ts, sender, content in blocks:
        if not _ns_valid_ts(ts):
            errs.append(f'line {lineno}: invalid display timestamp '
                        f'{ts!r}')
        if not content:
            errs.append(f'line {lineno}: message block has no content '
                        'lines')
    if not errs:
        info.append(f'{len(blocks)} dm blocks')
    return (not errs), errs, info


def check_dm_fetch_files(paths: list[str]) -> int:
    failures = 0
    for p in paths:
        try:
            with open(p, encoding='utf-8') as f:
                text = f.read()
        except Exception as e:
            print(f'{p}: FAIL (unreadable: {e})')
            failures += 1
            continue
        ok, errs, info = conform_dm_fetch_report(text)
        if ok:
            print(f'{p}: PASS ({"; ".join(info)})')
        else:
            print(f'{p}: FAIL')
            for e in errs:
                print(f'    - {e}')
            failures += 1
    print(f'--- {len(paths) - failures}/{len(paths)} passed ---')
    return 0 if failures == 0 else 1


# ---------- check_dm_recv: dm_recv report consistency ----------

# A saved `nakama.py dm_recv` stdout report. Its grammar is fixed
# (spec §4.1.1). check_dm_recv verifies that the report is internally
# consistent. Two mutually exclusive shapes:
#   success:  from <16 hex>...:            (sender line, line 1)
#             <rumor content line 1>
#             [<content line 2> ...]        (multi-line / blank lines ok;
#              an empty-content rumor prints the sender line plus one
#              blank line — accepted, noted as 'empty content')
#   failure:  DM の復号に失敗しました: <reason>   (exactly one line;
#              reason is the decrypt exception's message, non-empty)
# The sender prefix is 16 hex chars (case-insensitive) — the rumor
# pubkey's truncation. Explicitly out of scope: the rumor content's
# truth and the sender pubkey's truth (the gift wrap's territory:
# check_dm), the failure reason's truth (the decrypt exception's
# claim), stderr, and the exit code (invisible in saved stdout text).
# The dm_fetch block header `--- [datetime] from <16 hex>...` (§4.1)
# is a different grammar and is rejected (the two checkers reject
# each other's reports).

_RE_DR_HEADER = re.compile(r'^from ([0-9a-fA-F]{16})\.\.\.:$')
_RE_DR_FAIL = re.compile(r'^DM の復号に失敗しました: (.+)$')


def conform_dm_recv_report(text: str):
    """Verify a saved `nakama.py dm_recv` stdout report is internally
    consistent. Returns (ok, errs, info)."""
    errs: list[str] = []
    info: list[str] = []
    lines = text.splitlines()
    while lines and lines[-1] == '':
        lines.pop()
    if not lines:
        return False, ['report is empty'], info
    if _RE_DR_FAIL.match(lines[0]):
        if len(lines) != 1:
            return False, ['decrypt-failure report must be a single '
                           f'line, found {len(lines)} lines'], info
        info.append('decrypt failure')
        return True, errs, info
    m = _RE_DR_HEADER.match(lines[0])
    if not m:
        return False, ['line 1: not a dm_recv sender line '
                       '(`from <16 hex>...:`) and not a decrypt-failure '
                       'line'], info
    sender = m.group(1)
    if len(lines) == 1:
        info.append(f'empty content (sender {sender}…)')
    else:
        info.append(f'sender {sender}…, '
                    f'{len(lines) - 1} content line(s)')
    return (not errs), errs, info


def check_dm_recv_files(paths: list[str]) -> int:
    failures = 0
    for p in paths:
        try:
            with open(p, encoding='utf-8') as f:
                text = f.read()
        except Exception as e:
            print(f'{p}: FAIL (unreadable: {e})')
            failures += 1
            continue
        ok, errs, info = conform_dm_recv_report(text)
        if ok:
            print(f'{p}: PASS ({"; ".join(info)})')
        else:
            print(f'{p}: FAIL')
            for e in errs:
                print(f'    - {e}')
            failures += 1
    print(f'--- {len(paths) - failures}/{len(paths)} passed ---')
    return 0 if failures == 0 else 1


# ---------- check_dm_send: dm_send report consistency ----------

# A saved `nakama.py dm_send --out <file>` stdout report. Its grammar is
# fixed (spec §4.1.2). check_dm_send verifies that the report is internally
# consistent: exactly one line,
#   gift wrap (kind 1059) を <out> に保存しました。publish は dm_pub で実行してください。
# where <out> is the --out path: non-empty, no leading/trailing
# whitespace. Trailing blank lines are tolerated; a leading blank line
# is rejected. The no-`--out` form prints the raw gift wrap JSON to
# stdout — a different grammar, rejected here (and this report is
# rejected there). The stale pre-v0.73 sentence `リレー publish は
# 未実装（次の単位）。` (the report once claimed publish was not yet
# implemented; `dm_pub` now exists, spec v0.73) is explicitly rejected.
# Explicitly out of scope: the gift wrap file's existence/content
# (the wire's territory: `check_dm`), the §14.2 compromise warnings
# (stderr, exit code unchanged), and the exit code (invisible in saved
# stdout text). dm_recv reports (`from <16 hex>...:` sender lines /
# `DM の復号に失敗しました:` failure lines) are a different grammar and
# are rejected naturally.

_RE_DS_REPORT = re.compile(
    r'^gift wrap \(kind 1059\) を (.+) に保存しました。'
    r'publish は dm_pub で実行してください。$')


def conform_dm_send_report(text: str):
    """Verify a saved `nakama.py dm_send --out` stdout report is
    internally consistent. Returns (ok, errs, info)."""
    errs: list[str] = []
    info: list[str] = []
    lines = text.splitlines()
    while lines and lines[-1] == '':
        lines.pop()
    if not lines:
        return False, ['report is empty'], info
    if len(lines) != 1:
        return False, ['report must be a single confirmation line, '
                       f'found {len(lines)} lines'], info
    m = _RE_DS_REPORT.match(lines[0])
    if not m:
        return False, ['line 1: not a dm_send --out confirmation line '
                       '(`gift wrap (kind 1059) を <out> に保存しました。'
                       'publish は dm_pub で実行してください。`)'], info
    out = m.group(1)
    if out != out.strip():
        return False, ['<out> has leading/trailing whitespace'], info
    info.append(f'saved to {out!r}')
    return (not errs), errs, info


def check_dm_send_files(paths: list[str]) -> int:
    failures = 0
    for p in paths:
        try:
            with open(p, encoding='utf-8') as f:
                text = f.read()
        except Exception as e:
            print(f'{p}: FAIL (unreadable: {e})')
            failures += 1
            continue
        ok, errs, info = conform_dm_send_report(text)
        if ok:
            print(f'{p}: PASS ({ "; ".join(info) })')
        else:
            print(f'{p}: FAIL')
            for e in errs:
                print(f'    - {e}')
            failures += 1
    print(f'--- {len(paths) - failures}/{len(paths)} passed ---')
    return 0 if failures == 0 else 1


# ---------- check_verify_rotation: verify_rotation report consistency ----------

# A saved `nakama.py verify_rotation` stdout report. Its grammar is fixed
# (spec §5.5.3). check_verify_rotation verifies that the report is internally
# consistent. Exactly one line, either:
#   valid:    rotation は有効です: <old16>... → <new16>...
#   invalid:  rotation は無効です
# The prefixes are the first 16 characters of the old/new npubs — bech32
# text, not hex, so only "16 non-space characters" is checked (the same
# rule as `check_rotate_fetch`'s revoker prefixes, §12.4). The `...`
# ellipsis and the `→` arrow are literal parts of the reference grammar.
# Explicitly out of scope: the verdict's truth (the cert's territory:
# `check_rotation`/`verify_rotation_cert`), the npubs' truth, stderr, and
# the exit code (invisible in saved stdout text). The `rotate` command's
# multi-line issuance report (`rotation 証明書: <out>` + the same
# `<old16>... → <new16>...` arrow line + notes) is a different grammar
# and is rejected (the two checkers reject each other's reports).

_RE_VR_VALID = re.compile(
    r'^rotation は有効です: (\S{16})\.\.\. → (\S{16})\.\.\.$')
_RE_VR_INVALID = re.compile(r'^rotation は無効です$')


def conform_verify_rotation_report(text: str):
    """Verify a saved `nakama.py verify_rotation` stdout report is
    internally consistent. Returns (ok, errs, info)."""
    errs: list[str] = []
    info: list[str] = []
    lines = text.splitlines()
    while lines and lines[-1] == '':
        lines.pop()
    if not lines:
        return False, ['report is empty'], info
    if len(lines) != 1:
        return False, [f'report must be a single verdict line, '
                       f'found {len(lines)} lines'], info
    m = _RE_VR_INVALID.match(lines[0])
    if m:
        info.append('invalid verdict')
        return (not errs), errs, info
    m = _RE_VR_VALID.match(lines[0])
    if not m:
        return False, ['line 1: not a verify_rotation verdict line '
                       '(`rotation は有効です: <old16>... → <new16>...` '
                       'or `rotation は無効です`)'], info
    old, new = m.group(1), m.group(2)
    info.append(f'valid verdict: {old}… → {new}…')
    return (not errs), errs, info


def check_verify_rotation_files(paths: list[str]) -> int:
    failures = 0
    for p in paths:
        try:
            with open(p, encoding='utf-8') as f:
                text = f.read()
        except Exception as e:
            print(f'{p}: FAIL (unreadable: {e})')
            failures += 1
            continue
        ok, errs, info = conform_verify_rotation_report(text)
        if ok:
            print(f'{p}: PASS ({"; ".join(info)})')
        else:
            print(f'{p}: FAIL')
            for e in errs:
                print(f'    - {e}')
            failures += 1
    print(f'--- {len(paths) - failures}/{len(paths)} passed ---')
    return 0 if failures == 0 else 1


# ---------- check_verify_revocation: verify_revocation report consistency ----------

# A saved `nakama.py verify_revocation` stdout report. Its grammar is fixed
# (spec §12.5). check_verify_revocation verifies that the report is internally
# consistent. Exactly one line:
#   valid:   revocation は有効です — bond <bond16>... は <revoker16>... により解消されました。
#   invalid: revocation は無効です
# <bond16> is the first 16 hex chars of the revocation's bond_hash (the
# reference CLI truncates the lowercase hexdigest — the checker accepts
# upper case too, like check_revoke_fetch's bond prefix). <revoker16> is
# the first 16 characters of the revoker's npub — bech32 text, so only
# "16 non-space characters" is checked, like check_verify_rotation's
# prefixes. The `...` ellipsis and the `—` em dash are literal. Trailing
# blank lines tolerated; a leading blank line is rejected. No arithmetic
# rules (a verdict is a 2-vocabulary fixed sentence plus two truncated
# display prefixes). Explicitly out of scope: the verdict's truth (the
# revocation event's territory — `check_revocation` / `verify_revocation_event`
# on the event JSON itself), the bond_hash/revoker truth, stderr, and the
# exit code (invisible in saved stdout text). The `verify_rotation` verdict
# lines (`rotation は有効です: <old16>... → <new16>...` /
# `rotation は無効です`) are a different grammar — the two checkers reject
# each other's reports. The `revoke` issuance report (`revocation イベント:
# <out> — bond <16>... の解消を宣言しました。` + registry lines) is a
# different grammar too and is a future checker candidate. Use this to
# prove a second implementation's `verify_revocation` CLI prints a
# compatible report.

_RE_VRV_VALID = re.compile(
    r'^revocation は有効です — bond ([0-9a-fA-F]{16})\.\.\. は '
    r'(\S{16})\.\.\. により解消されました。$')
_RE_VRV_INVALID = re.compile(r'^revocation は無効です$')


def conform_verify_revocation_report(text: str):
    """Verify a saved `nakama.py verify_revocation` stdout report is
    internally consistent. Returns (ok, errs, info)."""
    errs: list[str] = []
    info: list[str] = []
    lines = text.splitlines()
    while lines and lines[-1] == '':
        lines.pop()
    if not lines:
        return False, ['report is empty'], info
    if len(lines) != 1:
        return False, [f'report must be a single verdict line, '
                       f'found {len(lines)} lines'], info
    m = _RE_VRV_INVALID.match(lines[0])
    if m:
        info.append('invalid verdict')
        return (not errs), errs, info
    m = _RE_VRV_VALID.match(lines[0])
    if not m:
        return False, ['line 1: not a verify_revocation verdict line '
                       '(`revocation は有効です — bond <16hex>... は '
                       '<revoker16>... により解消されました。` or '
                       '`revocation は無効です`)'], info
    bond, revoker = m.group(1), m.group(2)
    info.append(f'valid verdict: bond {bond}… revoker {revoker}…')
    return (not errs), errs, info


def check_verify_revocation_files(paths: list[str]) -> int:
    failures = 0
    for p in paths:
        try:
            with open(p, encoding='utf-8') as f:
                text = f.read()
        except Exception as e:
            print(f'{p}: FAIL (unreadable: {e})')
            failures += 1
            continue
        ok, errs, info = conform_verify_revocation_report(text)
        if ok:
            print(f'{p}: PASS ({"; ".join(info)})')
        else:
            print(f'{p}: FAIL')
            for e in errs:
                print(f'    - {e}')
            failures += 1
    print(f'--- {len(paths) - failures}/{len(paths)} passed ---')
    return 0 if failures == 0 else 1


# ---------- check_revoke: revoke issuance report consistency ----------

# A saved `nakama.py revoke` stdout report. Its grammar is fixed
# (spec §12.6). check_revoke verifies that the report is internally
# consistent:
#   line 1: revocation イベント: <out> — bond <h16>... の解消を宣言しました。
#   line 2 (only without --no-registry): ローカル registry に記録しました: <rp>
#   line 3 (always the last line): 解消イベントは公開チャネルで共有してください（仲間の公開記録に残ります）。
# So the report is either 2 lines (the --no-registry form: lines 1 and
# 3) or 3 lines (all three). <out> is the event file path (args.out or
# the default 'revocation.json' — non-empty, no leading/trailing
# whitespace, like check_dm_send's <out>); <h16> is the first 16 hex
# chars of the revocation's bond_hash (the reference CLI truncates the
# lowercase hexdigest — the checker accepts upper case too, like
# check_verify_revocation's bond prefix); <rp> is the registry record
# path (non-empty, no leading/trailing whitespace). The `...` ellipsis
# and the `—` em dash are literal. Trailing blank lines tolerated; a
# leading blank line is rejected. No arithmetic rules (the lines carry
# no derivable fields — only the 16-char bond prefix is printed, so the
# registry filename cannot be derived). Explicitly out of scope: the
# event file's existence/content (the revocation event's territory —
# `check_revocation` / `verify_revocation_event`), the registry
# record's existence/content, the bond_hash truth, stderr, and the exit
# code (invisible in saved stdout text). The `verify_revocation` verdict
# lines (§12.5) are a different grammar — the two checkers reject each
# other's reports; so are the sibling reports: the `revoke_import`
# one-liners (`revocation を registry に記録しました: ...` /
# `既に registry に記録済みです: ...`), the `revoke_pub` publish line
# (`publish: <受理|拒否> (...) id=<id>`), the `revoke_fetch` footer, and
# the `revoke_list` report. Use this to prove a second implementation's
# `revoke` CLI prints a compatible report.

_RE_RVK_LINE1 = re.compile(
    r'^revocation イベント: (.+) — bond ([0-9a-fA-F]{16})\.\.\. の解消を宣言しました。$')
_RE_RVK_LINE2 = re.compile(
    r'^ローカル registry に記録しました: (.+)$')
_RVK_LINE3 = '解消イベントは公開チャネルで共有してください（仲間の公開記録に残ります）。'


def conform_revoke_report(text: str):
    """Verify a saved `nakama.py revoke` stdout report is internally
    consistent. Returns (ok, errs, info)."""
    errs: list[str] = []
    info: list[str] = []
    lines = text.splitlines()
    while lines and lines[-1] == '':
        lines.pop()
    if not lines:
        return False, ['report is empty'], info
    if lines[0] == '':
        return False, ['report starts with a blank line'], info
    m = _RE_RVK_LINE1.match(lines[0])
    if not m:
        return False, ['line 1: not a revoke issuance line '
                       '(`revocation イベント: <out> — bond <16hex>... '
                       'の解消を宣言しました。`)'], info
    out, bh16 = m.group(1), m.group(2)
    if out.strip() != out:
        return False, ['line 1: <out> has leading/trailing whitespace'], info
    info.append(f'issuance report: out={out} bond {bh16}…')
    if len(lines) not in (2, 3):
        return False, [f'report must be 2 lines (--no-registry) or 3 lines, '
                       f'found {len(lines)} lines'], info
    if lines[-1] != _RVK_LINE3:
        return False, ['last line: not the fixed share-reminder line '
                       '(解消イベントは公開チャネルで共有してください'
                       '（仲間の公開記録に残ります）。)'], info
    if len(lines) == 3:
        m2 = _RE_RVK_LINE2.match(lines[1])
        if not m2:
            return False, ['line 2: not the registry record line '
                           '(`ローカル registry に記録しました: <rp>`)'], info
        rp = m2.group(1)
        if rp.strip() != rp:
            return False, ['line 2: <rp> has leading/trailing '
                           'whitespace'], info
        info.append(f'registry record: {rp}')
    else:
        info.append('no registry line (--no-registry form)')
    return (not errs), errs, info


def check_revoke_files(paths: list[str]) -> int:
    failures = 0
    for p in paths:
        try:
            with open(p, encoding='utf-8') as f:
                text = f.read()
        except Exception as e:
            print(f'{p}: FAIL (unreadable: {e})')
            failures += 1
            continue
        ok, errs, info = conform_revoke_report(text)
        if ok:
            print(f'{p}: PASS ({"; ".join(info)})')
        else:
            print(f'{p}: FAIL')
            for e in errs:
                print(f'    - {e}')
            failures += 1
    print(f'--- {len(paths) - failures}/{len(paths)} passed ---')
    return 0 if failures == 0 else 1


# ---------- check_revoke_import: revoke_import report consistency ----------

# A saved `nakama.py revoke_import <revocation.json> [--bond] [--registry]`
# stdout report. Its grammar is fixed (spec §12.7).
# check_revoke_import verifies that the report is internally consistent.
# Exactly one line:
#   stored:    `revocation を registry に記録しました: <path>`
#   duplicate: `既に registry に記録済みです: <path>`
# where <path> is the registry record path `<registry>/<bond_hash>.json`
# (the reference CLI prints `revocation_registry_path(registry, bond_hash)`
# verbatim). The report's one internal rule: the basename is
# `<64 hex>.json` — bond_hash is the sha256 hexdigest of the bond (§12.2),
# and the registry file layout is `<registry>/<bond_hash>.json`; the
# registry directory part is free (user-controlled --registry), so only
# the basename is constrained. Uppercase hex is accepted, as with the
# §12.5/§12.6 prefix checkers. <path> must be non-empty with no
# leading/trailing whitespace (§4.1.2's <out> rule). Trailing blank lines
# are tolerated; a leading blank line is rejected. The sibling revoke
# reports are different grammars and are rejected: the `revoke` issuance
# report (`revocation イベント: ...` — 2-3 lines, check_revoke's
# territory), the `verify_revocation` verdicts (`revocation は有効です` /
# `revocation は無効です` — check_verify_revocation), the `revoke_pub`
# publish line (`publish: <受理|拒否> (...) id=<id>`), the `revoke_fetch`
# footer (`<N> 件のイベントを取得: ...`), and the `revoke_list` report.
# Explicitly out of scope: whether the record file exists and what it
# contains (the revocation event's territory: `check_revocation` /
# `verify_revocation_event`), the bond_hash truth, whether 'stored' vs
# 'duplicate' was the right call (import_revocation_event's territory —
# the registry's first-win rule), stderr, and the exit code. Use this to
# prove a second implementation's `revoke_import` CLI prints a compatible
# report.

_RE_RVI_LINE = re.compile(
    r'^(?:revocation を registry に記録しました|既に registry に記録済みです): (.+)$')
_RE_RVI_BASENAME = re.compile(r'^[0-9a-fA-F]{64}\.json$')


def conform_revoke_import_report(text: str):
    """Verify a saved `nakama.py revoke_import` stdout report is internally
    consistent. Returns (ok, errs, info)."""
    errs: list[str] = []
    info: list[str] = []
    lines = text.splitlines()
    while lines and lines[-1] == '':
        lines.pop()
    if not lines:
        return False, ['report is empty'], info
    if lines[0] == '':
        return False, ['report starts with a blank line'], info
    if len(lines) != 1:
        return False, [f'report must be exactly 1 line, '
                       f'found {len(lines)}'], info
    m = _RE_RVI_LINE.match(lines[0])
    if not m:
        return False, ['line 1: not a revoke_import report line '
                       '(`revocation を registry に記録しました: <path>` / '
                       '`既に registry に記録済みです: <path>`)'], info
    path = m.group(1)
    if path.strip() != path:
        return False, ['<path> has leading/trailing whitespace'], info
    base = os.path.basename(path)
    if not _RE_RVI_BASENAME.match(base):
        return False, [f'<path> basename `{base}` is not `<64 hex>.json` '
                       '(the registry record filename is the bond_hash '
                       'sha256 hexdigest)'], info
    kind = 'stored' if lines[0].startswith('revocation を') else 'duplicate'
    info.append(f'{kind}: {base[:16]}...')
    return (not errs), errs, info


def check_revoke_import_files(paths: list[str]) -> int:
    failures = 0
    for p in paths:
        try:
            with open(p, encoding='utf-8') as f:
                text = f.read()
        except Exception as e:
            print(f'{p}: FAIL (unreadable: {e})')
            failures += 1
            continue
        ok, errs, info = conform_revoke_import_report(text)
        if ok:
            print(f'{p}: PASS ({"; ".join(info)})')
        else:
            print(f'{p}: FAIL')
            for e in errs:
                print(f'    - {e}')
            failures += 1
    print(f'--- {len(paths) - failures}/{len(paths)} passed ---')
    return 0 if failures == 0 else 1


# ---------- check_compromise_import: compromise_import report consistency ----------

# A saved `nakama.py compromise_import <declaration.json> [--subject <npub>]`
# `[--registry DIR]` stdout report. Its grammar is fixed (spec §13.9).
# check_compromise_import verifies that the report is internally
# consistent: exactly one line, one of three fixed forms:
#   stored:    `侵害宣言を registry に記録しました: <path>`
#   duplicate: `既に registry に記録済みです: <path>`
#   updated:   `registry を更新しました（撤回・復活）: <path>`
# where <path> is the registry record path `<registry>/<subject_hex>.json`
# (the reference CLI prints `compromise_registry_path(registry,
# subject_hex)` verbatim). The report's one internal rule: the basename
# is `<64 hex>.json` — subject_hex is the subject's x-only pubkey
# (§13.2/§13.4), and the registry file layout is
# `<registry>/<subject_hex>.json`; the registry directory part is free
# (user-controlled --registry), so only the basename is constrained.
# Uppercase hex is accepted, as with the §12.7 revoke_import checker.
# <path> must be non-empty with no leading/trailing whitespace (§4.1.2's
# <out> rule). Trailing blank lines are tolerated; a leading blank line is
# rejected.
# Note: the duplicate line is grammatically identical to revoke_import's
# duplicate line (`既に registry に記録済みです: <path>` — both registry
# record files are `<64 hex>.json` basenames), so check_compromise_import
# does NOT reject revoke_import duplicate reports (like challenge/respond
# and init/whoami — the two reports are indistinguishable from the saved
# text). The `revoke_import` stored line (`revocation を registry に記録
# しました: ...`) differs by verb and is rejected. The other sibling
# compromise reports are different grammars and are rejected: the
# `compromise_declare` issuance report (`侵害宣言: ...` — 2-3 lines), the
# `compromise_withdraw` report (`侵害宣言を撤回しました: ...`),
# `compromise_fetch`'s footer (`<N> 件のイベントを取得: ...` —
# check_compromise_fetch's territory), and the `compromise_pub` publish
# line (`publish: <受理|拒否> (...) id=<id>` — check_pub's territory).
# Explicitly out of scope: whether the record file exists and what it
# contains (the declaration's territory: `check_compromise` /
# `verify_compromise_event`), the subject's truth, whether 'stored' vs
# 'duplicate' vs 'updated' was the right call (import_compromise_event's
# territory — the registry's declarant+created_at first-win rule), stderr,
# and the exit code. Use this to prove a second implementation's
# `compromise_import` CLI prints a compatible report.

_RE_CPI_LINE = re.compile(
    r'^(?:侵害宣言を registry に記録しました|既に registry に記録済みです|'
    r'registry を更新しました（撤回・復活）): (.+)$')
_RE_CPI_BASENAME = re.compile(r'^[0-9a-fA-F]{64}\.json$')


def conform_compromise_import_report(text: str):
    """Verify a saved `nakama.py compromise_import` stdout report is
    internally consistent. Returns (ok, errs, info)."""
    errs: list[str] = []
    info: list[str] = []
    lines = text.splitlines()
    while lines and lines[-1] == '':
        lines.pop()
    if not lines:
        return False, ['report is empty'], info
    if lines[0] == '':
        return False, ['report starts with a blank line'], info
    if len(lines) != 1:
        return False, [f'report must be exactly 1 line, '
                       f'found {len(lines)}'], info
    m = _RE_CPI_LINE.match(lines[0])
    if not m:
        return False, ['line 1: not a compromise_import report line '
                       '(`侵害宣言を registry に記録しました: <path>` / '
                       '`既に registry に記録済みです: <path>` / '
                       '`registry を更新しました（撤回・復活）: <path>`)'], info
    path = m.group(1)
    if path.strip() != path:
        return False, ['<path> has leading/trailing whitespace'], info
    base = os.path.basename(path)
    if not _RE_CPI_BASENAME.match(base):
        return False, [f'<path> basename `{base}` is not `<64 hex>.json` '
                       '(the registry record filename is the subject '
                       'x-only pubkey hex)'], info
    if lines[0].startswith('侵害宣言を'):
        kind = 'stored'
    elif lines[0].startswith('既に'):
        kind = 'duplicate'
    else:
        kind = 'updated'
    info.append(f'{kind}: {base[:16]}...')
    return (not errs), errs, info


def check_compromise_import_files(paths: list[str]) -> int:
    failures = 0
    for p in paths:
        try:
            with open(p, encoding='utf-8') as f:
                text = f.read()
        except Exception as e:
            print(f'{p}: FAIL (unreadable: {e})')
            failures += 1
            continue
        ok, errs, info = conform_compromise_import_report(text)
        if ok:
            print(f'{p}: PASS ({"; ".join(info)})')
        else:
            print(f'{p}: FAIL')
            for e in errs:
                print(f'    - {e}')
            failures += 1
    print(f'--- {len(paths) - failures}/{len(paths)} passed ---')
    return 0 if failures == 0 else 1


# ---------- check_compromise_declare: compromise_declare report consistency ----------

# A saved `nakama.py compromise_declare --subject <npub> [--reason ...]`
# `[--evidence ...] [--bond bond.json] [--out OUT] [--no-registry]`
# `[--registry DIR]` stdout report. Its grammar is fixed (spec §13.10).
# check_compromise_declare verifies that the report is internally
# consistent: 2 or 3 lines —
#   line 1 (always): `侵害宣言: <out> — <declarant16>... が
#                     <subject16>... の鍵は危ないと宣言しました。`
#   line 2 (only when the registry recorded the declaration — a fresh
#            declare without --no-registry):
#            `ローカル registry に記録しました: <path>`
#   final line (always): `宣言は公開チャネルで共有してください（仲間の
#            公開記録に残ります）。虚偽の宣言はあなたの署名付きで
#            残ることを忘れずに。`
# <out> is the declaration JSON path verbatim (`--out`, default
# `compromise.json`; user-controlled, so it must be non-empty with no
# leading/trailing whitespace — §4.1.2's <out> rule). <declarant16> and
# <subject16> are the first 16 chars of the declarant's and the subject's
# npubs (16 non-whitespace chars; the reference truncates real npubs —
# the §12.4 revoker / §13.8 declarant convention; bech32 checksum
# validity is out of scope, as everywhere). The `—` is an em dash
# (U+2014), the `...` are ASCII three dots, the final `。` and the
# full-width parens `（）` in the advisory line are literals. <path> is
# `compromise_registry_path(registry, subject_hex)` verbatim; the
# report's one internal rule is §13.9's: basename == `<64 hex>.json`
# (the subject's x-only pubkey; uppercase accepted).
# Note the verbs: the registry line reads `ローカル registry に記録し
# ました: ` while compromise_import's stored line reads `侵害宣言を
# registry に記録しました: ` — different verbs, so the two are mutually
# rejected (like the check_board_send / check_pub / check_board_join
# prefix split: check_compromise_declare rejects an import stored line
# as its middle line, and a 1-line import report fails line 1). The
# other sibling compromise reports are different grammars and are
# rejected: the compromise_withdraw report (`侵害宣言を撤回しました:
# ...` — verb differs on line 1), compromise_fetch's footer (`<N> 件の
# イベントを取得: ...` — check_compromise_fetch's territory), and the
# compromise_pub publish line (`publish: <受理|拒否> (...) id=<id>` —
# check_pub's territory).
# Explicitly out of scope: whether the declaration JSON exists and what
# it contains (the declaration's territory: `check_compromise` /
# `verify_compromise_event`), the subject's truth, whether the registry
# line was the right call (import_compromise_event's territory — a fresh
# declare normally stores, --no-registry drops line 2), the
# declaration's signature, stderr, and the exit code. Use this to prove
# a second implementation's `compromise_declare` CLI prints a compatible
# issuance report.

_CPD_L1 = re.compile(
    r'^侵害宣言: (.+) — (\S{16})\.\.\. が (\S{16})\.\.\. の鍵は危ないと宣言しました。$')
_CPD_L2 = re.compile(r'^ローカル registry に記録しました: (.+)$')
_CPD_L3 = ('宣言は公開チャネルで共有してください（仲間の公開記録に残ります）。'
          '虚偽の宣言はあなたの署名付きで残ることを忘れずに。')
_CPD_BASENAME = re.compile(r'^[0-9a-fA-F]{64}\.json$')


def conform_compromise_declare_report(text: str):
    """Verify a saved `nakama.py compromise_declare` stdout report is
    internally consistent. Returns (ok, errs, info)."""
    errs: list[str] = []
    info: list[str] = []
    lines = text.splitlines()
    while lines and lines[-1] == '':
        lines.pop()
    if not lines:
        return False, ['report is empty'], info
    if lines[0] == '':
        return False, ['report starts with a blank line'], info
    if len(lines) not in (2, 3):
        return False, [f'report must be 2 or 3 lines (issuance line, '
                       f'optional registry line, advisory line), '
                       f'found {len(lines)}'], info
    m1 = _CPD_L1.match(lines[0])
    if not m1:
        return False, ['line 1: not a compromise_declare issuance line '
                       '(`侵害宣言: <out> — <declarant16>... が '
                       '<subject16>... の鍵は危ないと宣言しました。`)'], info
    out, decl_p, subj_p = m1.group(1), m1.group(2), m1.group(3)
    if not out or out.strip() != out:
        return False, ['<out> is empty or has leading/trailing '
                       'whitespace'], info
    has_reg = False
    if len(lines) == 3:
        m2 = _CPD_L2.match(lines[1])
        if not m2:
            return False, ['line 2: not the registry line '
                           '(`ローカル registry に記録しました: <path>`)'], info
        path = m2.group(1)
        if not path or path.strip() != path:
            return False, ['<path> is empty or has leading/trailing '
                           'whitespace'], info
        base = os.path.basename(path)
        if not _CPD_BASENAME.match(base):
            return False, [f'<path> basename `{base}` is not `<64 hex>.json` '
                           '(the registry record filename is the subject '
                           'x-only pubkey hex)'], info
        has_reg = True
        info.append(f'registry: {base[:16]}...')
    if lines[-1] != _CPD_L3:
        return False, ['final line: not the advisory line (byte-exact: '
                       '`宣言は公開チャネルで共有してください（仲間の公開'
                       '記録に残ります）。虚偽の宣言はあなたの署名付きで'
                       '残ることを忘れずに。`)'], info
    info.append(f'out={out} decl={decl_p}... subj={subj_p}... '
                f'{"registry" if has_reg else "no-registry"}')
    return (not errs), errs, info


def check_compromise_declare_files(paths: list[str]) -> int:
    failures = 0
    for p in paths:
        try:
            with open(p, encoding='utf-8') as f:
                text = f.read()
        except Exception as e:
            print(f'{p}: FAIL (unreadable: {e})')
            failures += 1
            continue
        ok, errs, info = conform_compromise_declare_report(text)
        if ok:
            print(f'{p}: PASS ({ "; ".join(info)})')
        else:
            print(f'{p}: FAIL')
            for e in errs:
                print(f'    - {e}')
            failures += 1
    print(f'--- {len(paths) - failures}/{len(paths)} passed ---')
    return 0 if failures == 0 else 1


# ---------- check_init: init report consistency ----------

# A saved `nakama.py init [--from-hex HEX] [--force] <keyfile>` stdout
# report. Its grammar is fixed (spec §1.1). check_init verifies that
# the report is internally consistent: exactly one line — the new
# identity's npub, printed verbatim by the reference CLI:
#   npub1<58 bech32 chars>
# The npub of a 32-byte key is always exactly 63 chars (`npub1` + 58
# bech32 chars) — shape-checked only, the bech32 checksum is not
# validated (the same rule as the §2.2.1 `あなたの npub:` line and the
# §14.2.1 warn lines' npub shape). Trailing blank lines are tolerated;
# a leading blank line is rejected. There is no internal arithmetic to
# check — a lone npub has no derivable fields.
# Note: `nakama.py whoami <keyfile>` prints the same single-npub line
# to stdout — grammatically identical (like challenge/respond), so
# check_init does not reject whoami reports; the two commands are
# indistinguishable from the saved text. The init refusal
# (`既に鍵があります: ... --force で上書き`, exit 1) goes to stderr,
# so it never appears in a saved stdout report.
# Explicitly out of scope: whether the npub really belongs to the
# keyfile (an ownership claim — the checker sees only the saved text),
# the npub's checksum, stderr, and the exit code. Use this to prove a
# second implementation's `init` CLI prints a compatible npub line.

_RE_INIT_BECH32 = r'[023456789acdefghjklmnpqrstuvwxyz]'
_RE_INIT_NPUB = re.compile(r'^npub1' + _RE_INIT_BECH32 + r'{58}$')


def conform_init_report(text: str):
    """Verify a saved `nakama.py init` stdout report is internally
    consistent. Returns (ok, errs, info)."""
    errs: list[str] = []
    info: list[str] = []
    lines = text.splitlines()
    while lines and lines[-1] == '':
        lines.pop()
    if not lines:
        return False, ['report is empty'], info
    if lines[0] == '':
        return False, ['report starts with a blank line'], info
    if len(lines) != 1:
        return False, [f'report must be exactly 1 line (the new npub), '
                       f'found {len(lines)} lines'], info
    if not _RE_INIT_NPUB.match(lines[0]):
        return False, ['line 1: not an npub line '
                       '(`npub1` + 58 bech32 chars, 63 chars total)'], info
    info.append(f'npub {lines[0][:12]}...')
    return (not errs), errs, info


def check_init_files(paths: list[str]) -> int:
    failures = 0
    for p in paths:
        try:
            with open(p, encoding='utf-8') as f:
                text = f.read()
        except Exception as e:
            print(f'{p}: FAIL (unreadable: {e})')
            failures += 1
            continue
        ok, errs, info = conform_init_report(text)
        if ok:
            print(f'{p}: PASS ("{"; ".join(info)}")')
        else:
            print(f'{p}: FAIL')
            for e in errs:
                print(f'    - {e}')
            failures += 1
    print(f'--- {len(paths) - failures}/{len(paths)} passed ---')
    return 0 if failures == 0 else 1


# ---------- check_draft_notify: board_draft_notify report consistency ----------

# A saved `nakama.py board_draft_notify <relay> <board_id> [opts]` stdout
# report. Its grammar is fixed (spec §25.5). check_draft_notify verifies
# that the report is internally consistent. The reference CLI prints one
# stdout line per target draft, in two independent loops: first the
# issuer loop (the draft event's publisher), then — only with
# `--cosigners` — the cosigner loop (unsigned eligible approvers).
#
# Line grammars:
#   no targets (early return — never mixed with other lines):
#     通知対象の草案はありませんでした
#   issuer lines:
#     [dry-run] <core12> (<reason>) → <hex16>... (<decision>)
#     [skip]    <core12> (<reason>) — <N>s 以内に送信済み
#     [sent]    <core12> (<reason>) → <hex16>... (id=<id64>)
#   cosigner lines (with --cosigners): the same three forms with
#   `cosigner ` inserted right after the tag, e.g.:
#     [dry-run] cosigner <core12> (<reason>) → <hex16>... (<decision>)
# Notes on the fixed grammar:
#   - the arrow is U+2192 (`→`), never ASCII `->`;
#   - the ellipsis after the 16-hex recipient prefix is three literal
#     ASCII dots `...`;
#   - the dash in a skip line is an em dash (U+2014), literal;
#   - <reason> is `expiring_soon` | `expired` (issuer and cosigner share
#     the vocabulary — the notification vocabulary of §25/§27);
#   - <core12> is the decision_core_hash (32 hex) head, <hex16> the
#     recipient pubkey (64 hex) head, both hex-case-insensitive;
#   - <decision> is one of BOARD_DECISION_TYPES and appears only on
#     dry-run lines; <id64> (the kind-1059 gift wrap event id, 64 hex,
#     case-insensitive) only on sent lines; <N> only on skip lines.
# Internal rules the checker derives:
#   R1 mode consistency: if any `[dry-run]` line is present, every line
#      is `[dry-run]` (--dry-run neither sends nor records, so it never
#      mixes with sent/skip);
#   R2 skip N consistency: every `[skip]` line carries the same <N>
#      (the one run's `--within` value);
#   R3 order: the issuer-line block comes before the cosigner-line
#      block (two independent loops — an issuer line never follows a
#      cosigner line);
#   R4 the no-target line stands alone (the CLI returns early).
# An empty stdout is rejected: the reference CLI never finishes silently
# — every fail-fast path goes to stderr. Trailing blank lines are
# tolerated; a leading blank line is rejected.
# Explicitly out of scope: whether anything was really sent (the gift
# wrap's content is the DM layer's territory), the truth of
# core/hex/id fields (R2 checks only N consistency, not its value), the
# mapping of <hex16> to an npub, stderr, and the exit code. Use this to
# prove a second implementation's `board_draft_notify` CLI prints a
# compatible report.

_DNO_HEX = r'[0-9a-fA-F]'
_DNO_MIDDLE = (r'\[(dry-run|skip|sent)\] (cosigner )?('
               + _DNO_HEX + r'{12}) \((expiring_soon|expired)\) ')
_DNO_TAIL = {
    # dry-run: the decision type is shown instead of a wrap id (nothing
    # was sent)
    'dry-run': r'→ ' + _DNO_HEX + r'{16}\.\.\. '
               r'\((?:admit|handover|policy-update|close|remove)\)',
    # skip: the already-sent record's suppression window, printed with
    # an em dash — captured as group 5 so R2 can compare N across lines
    'skip': r'— ([0-9]+)s 以内に送信済み',
    # sent: the accepted gift wrap (kind 1059) event id
    'sent': r'→ ' + _DNO_HEX + r'{16}\.\.\. \(id=' + _DNO_HEX + r'{64}\)',
}
_DNO_LINE = {mode: re.compile(r'^' + _DNO_MIDDLE + tail + r'$')
             for mode, tail in _DNO_TAIL.items()}
_DNO_NO_TARGETS = '通知対象の草案はありませんでした'


def conform_draft_notify_report(text: str):
    """Verify a saved `nakama.py board_draft_notify` stdout report is
    internally consistent. Returns (ok, errs, info)."""
    errs: list[str] = []
    info: list[str] = []
    lines = text.splitlines()
    while lines and lines[-1] == '':
        lines.pop()
    if not lines:
        return False, ['report is empty (the CLI never finishes silently '
                       '— every fail-fast path goes to stderr)'], info
    if lines[0] == '':
        return False, ['report starts with a blank line'], info
    if lines[0] == _DNO_NO_TARGETS:
        if len(lines) != 1:
            return False, ['the no-target line must stand alone (the CLI '
                           'returns early when there is nothing to '
                           'notify)'], info
        return True, [], ['no notification targets']
    parsed = []
    for i, line in enumerate(lines):
        m = None
        mode = None
        for cand, rx in _DNO_LINE.items():
            m = rx.match(line)
            if m:
                mode = cand
                break
        if m is None or mode is None:
            return False, [f'line {i + 1}: not a draft-notify report line '
                           f'(`{line}`)'], info
        parsed.append((i, mode, m))
    modes = [mode for _, mode, _ in parsed]
    # R1: mode consistency — a dry-run line never mixes with sent/skip
    if 'dry-run' in modes and any(m != 'dry-run' for m in modes):
        return False, ['R1 violated: a [dry-run] line mixed with '
                       '[sent]/[skip] lines (--dry-run neither sends nor '
                       'records)'], info
    # R2: skip N consistency — one run, one --within
    skip_ns = [m.group(5) for _, mode, m in parsed if mode == 'skip']
    if len(set(skip_ns)) > 1:
        return False, [f'R2 violated: [skip] lines carry different N '
                       f'({", ".join(sorted(set(skip_ns)))}) — one run '
                       f'has one --within'], info
    # R3: order — issuer block first, cosigner block second
    seen_cosigner = False
    for i, mode, m in parsed:
        if m.group(2) is not None:
            seen_cosigner = True
        elif seen_cosigner:
            return False, [f'R3 violated: issuer line after a cosigner '
                           f'line (line {i + 1} — the CLI runs the issuer '
                           f'loop first, the cosigner loop second)'], info
    for i, mode, m in parsed:
        who = ' (cosigner)' if m.group(2) is not None else ''
        info.append(f'{mode} line {i + 1}: {m.group(3)}... '
                    f'{m.group(4)}{who}')
    return (not errs), errs, info


def check_draft_notify_files(paths: list[str]) -> int:
    failures = 0
    for p in paths:
        try:
            with open(p, encoding='utf-8') as f:
                text = f.read()
        except Exception as e:
            print(f'{p}: FAIL (unreadable: {e})')
            failures += 1
            continue
        ok, errs, info = conform_draft_notify_report(text)
        if ok:
            print(f'{p}: PASS ("{"; ".join(info)}")')
        else:
            print(f'{p}: FAIL')
            for e in errs:
                print(f'    - {e}')
            failures += 1
    print(f'--- {len(paths) - failures}/{len(paths)} passed ---')
    return 0 if failures == 0 else 1


# ---------- check_compromise_withdraw: compromise_withdraw report consistency ----------

# A saved `nakama.py compromise_withdraw --subject <npub> [--out OUT]
# [--registry DIR]` stdout report. Its grammar is fixed (spec §13.11).
# check_compromise_withdraw verifies that the report is internally
# consistent: exactly 2 lines —
#   line 1 (always): `侵害宣言を撤回しました: <out>（registry の記録を
#                     withdrawn: true に更新）`
#   line 2 (always): `公開済みの宣言は compromise_pub で上書きしてくだ
#                     さい（kind 30108 の replaceable で撤回が効きます）。`
# <out> is the withdrawal JSON path verbatim (`--out`, default
# `compromise_withdrawn.json`; user-controlled, so it must be non-empty
# with no leading/trailing whitespace — §4.1.2's <out> rule). The `（）`
# are full-width parens (U+FF08/U+FF09), the final `。` is a literal;
# `withdrawn: true` and `kind 30108` are literals. No registry path is
# printed, so there is no basename rule here (unlike §13.9/§13.10).
# The failure paths (invalid subject, no matching declaration in the
# registry) print to stderr, not stdout — the report exists only for
# the success path.
# Note the verbs: line 1 reads `侵害宣言を撤回しました: ` while
# compromise_declare's line 1 reads `侵害宣言: ... — ` and
# compromise_import's stored line reads `侵害宣言を registry に記録し
# ました: ` — different verbs, so the sibling reports are mutually
# rejected (like the check_board_send / check_pub / check_board_join
# prefix split). The other sibling compromise reports are different
# grammars and are rejected: compromise_fetch's footer (`<N> 件のイベン
# トを取得: ...` — check_compromise_fetch's territory), and the
# compromise_pub publish line (`publish: <受理|拒否> (...) id=<id>` —
# check_pub's territory).
# Explicitly out of scope: whether the withdrawal JSON exists and what
# it contains (the declaration's territory: `check_compromise` /
# `verify_compromise_event`), whether the registry update was the right
# call (import_compromise_event's territory — the 'updated' return is
# what produces the report), stderr, and the exit code. Use this to
# prove a second implementation's `compromise_withdraw` CLI prints a
# compatible withdrawal report.

_CPW_L1 = re.compile(
    r'^侵害宣言を撤回しました: (.+)（registry の記録を withdrawn: true に更新）$')
_CPW_L2 = ('公開済みの宣言は compromise_pub で上書きしてください'
          '（kind 30108 の replaceable で撤回が効きます）。')


def conform_compromise_withdraw_report(text: str):
    """Verify a saved `nakama.py compromise_withdraw` stdout report is
    internally consistent. Returns (ok, errs, info)."""
    errs: list[str] = []
    info: list[str] = []
    lines = text.splitlines()
    while lines and lines[-1] == '':
        lines.pop()
    if not lines:
        return False, ['report is empty'], info
    if lines[0] == '':
        return False, ['report starts with a blank line'], info
    if len(lines) != 2:
        return False, [f'report must be exactly 2 lines (withdrawal line, '
                       f'pub-reminder line), found {len(lines)}'], info
    m1 = _CPW_L1.match(lines[0])
    if not m1:
        return False, ['line 1: not a compromise_withdraw withdrawal line '
                       '(`侵害宣言を撤回しました: <out>（registry の記録を '
                       'withdrawn: true に更新）`)'], info
    out = m1.group(1)
    if not out or out.strip() != out:
        return False, ['<out> is empty or has leading/trailing '
                       'whitespace'], info
    if lines[1] != _CPW_L2:
        return False, ['line 2: not the pub-reminder line (byte-exact: '
                       '`公開済みの宣言は compromise_pub で上書きしてくだ'
                       'さい（kind 30108 の replaceable で撤回が効きます）。`)'], info
    info.append(f'out={out}')
    return (not errs), errs, info


def check_compromise_withdraw_files(paths: list[str]) -> int:
    failures = 0
    for p in paths:
        try:
            with open(p, encoding='utf-8') as f:
                text = f.read()
        except Exception as e:
            print(f'{p}: FAIL (unreadable: {e})')
            failures += 1
            continue
        ok, errs, info = conform_compromise_withdraw_report(text)
        if ok:
            print(f'{p}: PASS ({ "; ".join(info)})')
        else:
            print(f'{p}: FAIL')
            for e in errs:
                print(f'    - {e}')
            failures += 1
    print(f'--- {len(paths) - failures}/{len(paths)} passed ---')
    return 0 if failures == 0 else 1


# ---------- check_compromise_warnings: compromise WARN-line consistency ----------

# A saved stderr capture of the compromise-declaration warnings the
# reference CLI prints (§14.2 verify/challenge/check/board_verify/
# board_send/dm_send, §15 accept, §16 verify_binding). Its grammar is
# fixed (spec §14.2.1). check_compromise_warnings verifies that the
# capture is internally consistent. Zero or more lines, each:
#   WARN: <npub[:12]>... has <N> active compromise declaration(s) — see: nakama.py key_status <npub>
# Notes on the fixed grammar:
#   - the ellipsis after the 12-char prefix is three literal ASCII
#     dots `...` (the spec prose elsewhere uses `…`, but the reference
#     CLI prints `...` — that is what a second implementation must
#     match byte for byte);
#   - the dash before `see:` is an em dash (U+2014), literal;
#   - the npub prefix is the first 12 characters of the full npub
#     printed at the end of the line (`npub1` + 7 bech32 chars) — the
#     checker's one internal arithmetic rule is prefix == npub[:12];
#   - N is the count of active (non-withdrawn) declarations, always
#     >= 1 here (the helper returns no line when there are none), so
#     `N=0` and leading-zero forms are rejected.
# Trailing blank lines are tolerated; a leading blank line is rejected.
# An empty capture is valid: it is the "no active declarations"
# (no-warnings) case, which the reference CLI produces for most keys —
# rejecting it would make the common case fail. The two sibling
# warning grammars are different and are rejected: the INFO rotation
# downgrade (`INFO: <npub[:12]>... has <N> active compromise
# declaration(s) — see: nakama.py key_status <npub> — 旧鍵への宣言
# （ローテーション済みのため情報扱い）` — the downgrade line is the
# WARN line's body verbatim plus the Japanese suffix; covered by
# `check_rotation_downgrade`) and the board_read display note
# (`⚠ compromised?`). Explicitly out of scope: the declaration count's
# truth (the registry's territory: `key_status` /
# `active_compromise_declarations`), the npub checksum (shape-checked
# only, not bech32-validated), stdout, and the exit code (always 0 —
# warnings never block).

_RE_CMW_BECH32 = r'[023456789acdefghjklmnpqrstuvwxyz]'
# full npub: an npub of a 32-byte key is always exactly 63 chars
# ('npub1' + 58 bech32 chars) — shape-checked only, not checksum-validated
_RE_CMW_LINE = re.compile(
    r'^WARN: (npub1' + _RE_CMW_BECH32 + r'{7})\.\.\. has ([1-9][0-9]*) '
    r'active compromise declaration\(s\) — see: nakama\.py key_status '
    r'((npub1)' + _RE_CMW_BECH32 + r'{58})$')


def conform_compromise_warnings(text: str):
    """Verify a saved stderr capture of compromise warnings is internally
    consistent. Returns (ok, errs, info)."""
    errs: list[str] = []
    info: list[str] = []
    lines = text.splitlines()
    while lines and lines[-1] == '':
        lines.pop()
    if not lines:
        return True, [], ['no warnings emitted (no active declarations)']
    if lines[0] == '':
        return False, ['capture starts with a blank line'], info
    for i, line in enumerate(lines):
        m = _RE_CMW_LINE.match(line)
        if not m:
            return False, [f'line {i + 1}: not a compromise-warning line '
                           '(`WARN: <npub[:12]>... has <N> active '
                           'compromise declaration(s) — see: nakama.py '
                           'key_status <npub>`)'], info
        prefix, n, npub = m.group(1), m.group(2), m.group(3)
        if prefix != npub[:12]:
            return False, [f'line {i + 1}: npub prefix `{prefix}` does not '
                           f'match the first 12 chars of `{npub[:12]}`'], info
        info.append(f'warn {i + 1}: {prefix}... N={n}')
    return (not errs), errs, info


def check_compromise_warnings_files(paths: list[str]) -> int:
    failures = 0
    for p in paths:
        try:
            with open(p, encoding='utf-8') as f:
                text = f.read()
        except Exception as e:
            print(f'{p}: FAIL (unreadable: {e})')
            failures += 1
            continue
        ok, errs, info = conform_compromise_warnings(text)
        if ok:
            print(f'{p}: PASS ({"; ".join(info)})')
        else:
            print(f'{p}: FAIL')
            for e in errs:
                print(f'    - {e}')
            failures += 1
    print(f'--- {len(paths) - failures}/{len(paths)} passed ---')
    return 0 if failures == 0 else 1


# ---------- check_rotation_downgrade: INFO rotation-downgrade consistency ----------

# Reference CLI emits, in `nakama.py verify --rotation` stderr, one INFO
# line per active compromise declaration against an old (rotated-from)
# key:
#   INFO: <npub[:12]>... has <N> active compromise declaration(s) — see: nakama.py key_status <npub> — 旧鍵への宣言（ローテーション済みのため情報扱い）
# The line is the corresponding WARN line's body verbatim (INFO: in place
# of WARN:, then the Japanese suffix appended after the key_status
# pointer). Notes on the fixed grammar (spec §14.2.2):
#   - the ellipsis after the 12-char prefix is three literal ASCII
#     dots `...` (the spec prose elsewhere used `…` — the reference CLI
#     prints `...`; match byte for byte);
#   - both dashes before `see:` and before the Japanese suffix are em
#     dashes (U+2014), literal;
#   - the Japanese suffix is full literal:
#     `— 旧鍵への宣言（ローテーション済みのため情報扱い）` (em dash +
#     full-width parens — second implementations must copy it
#     character for character);
#   - the npub prefix is the first 12 characters of the full npub
#     printed before the Japanese suffix (`npub1` + 7 bech32 chars) —
#     the checker's one internal arithmetic rule is prefix == npub[:12];
#   - N is the count of active (non-withdrawn) declarations, always
#     >= 1 here (the downgrade loop only runs over warnings that exist),
#     so `N=0` and leading-zero forms are rejected.
# Trailing blank lines are tolerated; a leading blank line is rejected.
# An empty capture is valid: it is the "no declarations on any old key"
# (no-downgrade) case, which the reference CLI produces for most verify
# runs — rejecting it would make the common case fail. Sibling warning
# grammars are different and are rejected: the WARN compromise line
# (`check_warnings`' territory), the board_read display note
# (`⚠ compromised?`), and the abbreviated INFO form from old spec prose
# (missing the `— see: nakama.py key_status <npub>` middle — that was
# the prose's abbreviation, never the CLI output). Explicitly out of
# scope: the declaration count's truth (the registry's territory:
# `key_status` / `active_compromise_declarations`), the npub checksum
# (shape-checked only, not bech32-validated), stdout, and the exit code
# (verify's exit is bond validity — INFO never blocks).

_RE_CRGD_BECH32 = r'[023456789acdefghjklmnpqrstuvwxyz]'
_RE_CRGD_LINE = re.compile(
    r'^INFO: (npub1' + _RE_CRGD_BECH32 + r'{7})\.\.\. has ([1-9][0-9]*) '
    r'active compromise declaration\(s\) — see: nakama\.py key_status '
    r'(npub1' + _RE_CRGD_BECH32 + r'{58}) — 旧鍵への宣言'
    r'（ローテーション済みのため情報扱い）$')


def conform_rotation_downgrade(text: str):
    """Verify a saved `verify --rotation` stderr capture of rotation
    downgrades is internally consistent. Returns (ok, errs, info)."""
    errs: list[str] = []
    info: list[str] = []
    lines = text.splitlines()
    while lines and lines[-1] == '':
        lines.pop()
    if not lines:
        return True, [], ['no downgrades emitted (no declarations on old keys)']
    if lines[0] == '':
        return False, ['capture starts with a blank line'], info
    for i, line in enumerate(lines):
        m = _RE_CRGD_LINE.match(line)
        if not m:
            return False, [f'line {i + 1}: not a rotation-downgrade line '
                           '(`INFO: <npub[:12]>... has <N> active '
                           'compromise declaration(s) — see: nakama.py '
                           'key_status <npub> — 旧鍵への宣言'
                           '（ローテーション済みのため情報扱い）`)'], info
        prefix, n, npub = m.group(1), m.group(2), m.group(3)
        if prefix != npub[:12]:
            return False, [f'line {i + 1}: npub prefix `{prefix}` does not '
                           f'match the first 12 chars of `{npub[:12]}`'], info
        info.append(f'downgrade {i + 1}: {prefix}... N={n}')
    return (not errs), errs, info


def check_rotation_downgrade_files(paths: list[str]) -> int:
    failures = 0
    for p in paths:
        try:
            with open(p, encoding='utf-8') as f:
                text = f.read()
        except Exception as e:
            print(f'{p}: FAIL (unreadable: {e})')
            failures += 1
            continue
        ok, errs, info = conform_rotation_downgrade(text)
        if ok:
            print(f'{p}: PASS ({"; ".join(info)})')
        else:
            print(f'{p}: FAIL')
            for e in errs:
                print(f'    - {e}')
            failures += 1
    print(f'--- {len(paths) - failures}/{len(paths)} passed ---')
    return 0 if failures == 0 else 1


# ---------- check_board_policy: board_policy creation-report consistency ----------

# A saved `nakama.py board_policy` stdout report. Its grammar is fixed
# (spec §9.4.1). check_board_policy verifies that the report is internally
# consistent. Exactly two lines:
#   line 1: board-policy 案: <out> — あなたの署名 1/<n>（初回は全員 <n>/<n> の署名が必要）
#   line 2: 運用: このファイルを eligible 全員に回覧し、`board_policy_sign` で署名を集めてください。
# The three <n> are all len(eligible) (the reference CLI enforces
# eligible non-empty and threshold 1..len(eligible), so n >= 1); the
# report's one internal arithmetic rule is n1 == n2 == n3.
# With `--markdown` the reference CLI appends an empty line, the fixed
# marker line `投稿用ブロック（コメント欄に貼る）:`, and the 4-line fenced
# block produced by `markdown_block`:
#   <!-- nakama-board-policy:v1 -->
#   ```nakama-board-policy
#   <base64url JSON, non-empty>
#   ```
# (the payload line is checked for non-empty base64url shape only — its
# content is the policy file's territory: `check_policy`). Trailing blank
# lines tolerated; a leading blank line is rejected. Explicitly out of
# scope: the eligible/threshold truth (the policy file's territory:
# `check_policy`), whether the signer is in eligible (stderr advisory),
# the out file's existence/content, stderr, and the exit code (invisible
# in saved stdout text). The `board_policy_sign` report
# (`board-policy: <out> — 署名 <m>/<n>（...）`) and the
# `verify_board_policy` verdict lines (`board-policy は有効です: ...` /
# `board-policy は無効です: ...`) are different grammars — the three
# checkers reject each other's reports. Use this to prove a second
# implementation's `board_policy` CLI prints a compatible report.

_RE_BPL_LINE1 = re.compile(
    r'^board-policy 案: (.+) — あなたの署名 1/(\d+)（初回は全員 (\d+)/(\d+) の署名が必要）$')
_BPL_LINE2 = '運用: このファイルを eligible 全員に回覧し、`board_policy_sign` で署名を集めてください。'
_BPL_MD_HEADER = '投稿用ブロック（コメント欄に貼る）:'
_BPL_MD_MARKER = '<!-- nakama-board-policy:v1 -->'
_BPL_MD_FENCE = '```nakama-board-policy'
_BPL_MD_CLOSE = '```'
_RE_BPL_B64U = re.compile(r'^[A-Za-z0-9_-]+={0,2}$')


def conform_board_policy_report(text: str):
    """Verify a saved `nakama.py board_policy` stdout report is internally
    consistent. Returns (ok, errs, info)."""
    errs: list[str] = []
    info: list[str] = []
    lines = text.splitlines()
    while lines and lines[-1] == '':
        lines.pop()
    if not lines:
        return False, ['report is empty'], info
    if lines[0] == '':
        return False, ['report starts with a blank line'], info
    m = _RE_BPL_LINE1.match(lines[0])
    if not m:
        return False, ['line 1: not a board_policy creation line '
                       '(`board-policy 案: <out> — あなたの署名 1/<n>'
                       '（初回は全員 <n>/<n> の署名が必要）`)'], info
    out, n1, n2, n3 = m.group(1), int(m.group(2)), int(m.group(3)), \
        int(m.group(4))
    if out.strip() != out:
        return False, ['line 1: <out> has leading/trailing whitespace'], info
    if not (n1 >= 1 and n1 == n2 == n3):
        return False, [f'line 1: inconsistent eligible counts '
                       f'(1/{n1}, 全員 {n2}/{n3} — all three must be equal '
                       f'and >= 1)'], info
    info.append(f'creation report: out={out} eligible={n1}')
    if len(lines) < 2:
        return False, ['line 2: missing the operational note'], info
    if lines[1] != _BPL_LINE2:
        return False, ['line 2: not the fixed operational note'], info
    if len(lines) == 2:
        info.append('no markdown block')
        return (not errs), errs, info
    # --markdown variant: empty line + marker line + 4-line fenced block
    rest = lines[2:]
    if len(rest) != 6:
        return False, [f'markdown section must be 6 lines '
                       f'(empty + marker + 4 fenced lines), '
                       f'found {len(rest)}'], info
    if rest[0] != '':
        return False, ['markdown section: line 3 must be empty'], info
    if rest[1] != _BPL_MD_HEADER:
        return False, ['markdown section: not the fixed header line '
                       '(`投稿用ブロック（コメント欄に貼る）:`)' ], info
    if rest[2] != _BPL_MD_MARKER:
        return False, ['markdown section: not the fixed marker line '
                       f'(`{_BPL_MD_MARKER}`)'], info
    if rest[3] != _BPL_MD_FENCE:
        return False, ['markdown section: not the fixed fence-open line '
                       f'(`{_BPL_MD_FENCE}`)'], info
    if not _RE_BPL_B64U.match(rest[4]):
        return False, ['markdown section: payload line is not non-empty '
                       'base64url'], info
    if rest[5] != _BPL_MD_CLOSE:
        return False, ['markdown section: not the fence-close line '
                       '(` ``` `)'], info
    info.append('markdown block present')
    return (not errs), errs, info


# ---------- check_rotate: rotate issuance report consistency ----------

# A saved `nakama.py rotate [--gen|--to-hex HEX] [--out OUT]` stdout
# report. Its grammar is fixed (spec §5.5.4). check_rotate verifies that
# the report is internally consistent: exactly 4 lines —
#   line 1 (always): `rotation 証明書: <out>`
#   line 2 (always): `<old16>... → <new16>...` (old/new npub prefixes)
#   line 3 (always): `注意: この証明書は「旧鍵の保有者が新鍵への移行を宣言した」ことの証拠です。`
#   line 4 (always): `継続的な鍵の保有 (custody) の証明には、都度の challenge–response を使ってください。`
# <out> is the cert JSON path verbatim (`--out`, default
# `rotation.json`; user-controlled, so it must be non-empty with no
# leading/trailing whitespace — §4.1.2's <out> rule). The line-2
# prefixes are the first 16 characters of the old/new npubs (bech32
# text, so only "16 non-whitespace characters" is checked — the same
# treatment as §5.5.3's verify_rotation prefixes and §12.4's
# revoke_fetch revoker). The `...` is three ASCII dots, the `→` is
# U+2192 (literal); line 3's 「」 are full-width corner brackets
# (U+300C/U+300D), line 4's `challenge–response` uses an en dash
# (U+2013) — a second implementation must match these byte for byte.
# The failure paths (neither --gen nor --to-hex, same old/new key)
# print to stderr with exit 1, so the report exists only for the
# success path — an empty stdout is rejected by the checker. The
# --gen key-generation note (`新しい鍵を生成しました: ...`) is also
# stderr, so it is not part of the report grammar.
# The sibling rotation reports are different grammars and are
# rejected: verify_rotation's verdict line (`rotation は有効です:
# <old16>... → <new16>...` — check_verify_rotation's territory),
# rotate_fetch's listing lines (`rotation 公開: ...` —
# check_rotate_fetch's territory), and the rotate_pub publish line
# (`publish: <受理|拒否> (...) id=<id>` — check_pub's territory).
# Note: even if the line-2 prefixes are equal, the report is NOT
# rejected — the full npubs never appear in the report, so a genuine
# same-key report cannot be derived from it (the real same-key case
# is a stderr refusal with exit 1 and leaves no stdout report).
# Explicitly out of scope: whether the cert JSON exists and what it
# contains (the cert's territory: `check_rotation` /
# `verify_rotation_cert`), the old/new prefixes' truth, stderr, and
# the exit code. Use this to prove a second implementation's
# `rotate` CLI prints a compatible issuance report.

_ROT_L1 = re.compile(r'^rotation 証明書: (.+)$')
_ROT_L2 = re.compile(r'^(\S{16})\.\.\. → (\S{16})\.\.\.$')
_ROT_L3 = ('注意: この証明書は「旧鍵の保有者が新鍵への移行を宣言した」'
          'ことの証拠です。')
_ROT_L4 = ('継続的な鍵の保有 (custody) の証明には、都度の challenge–response '
          'を使ってください。')


def conform_rotate_report(text: str):
    """Verify a saved `nakama.py rotate` stdout report is internally
    consistent. Returns (ok, errs, info)."""
    errs: list[str] = []
    info: list[str] = []
    lines = text.splitlines()
    while lines and lines[-1] == '':
        lines.pop()
    if not lines:
        return False, ['report is empty'], info
    if lines[0] == '':
        return False, ['report starts with a blank line'], info
    if len(lines) != 4:
        return False, [f'report must be exactly 4 lines (cert line, '
                       f'arrow line, 2 advisory lines), found {len(lines)}'], info
    m1 = _ROT_L1.match(lines[0])
    if not m1:
        return False, ['line 1: not a rotate cert line '
                       '(`rotation 証明書: <out>`)'], info
    out = m1.group(1)
    if not out or out.strip() != out:
        return False, ['<out> is empty or has leading/trailing '
                       'whitespace'], info
    m2 = _ROT_L2.match(lines[1])
    if not m2:
        return False, ['line 2: not an arrow line '
                       '(`<old16>... → <new16>...`)'], info
    if lines[2] != _ROT_L3:
        return False, ['line 3: not the advisory line (byte-exact: '
                       '`注意: この証明書は「旧鍵の保有者が新鍵への移行を'
                       '宣言した」ことの証拠です。`)'], info
    if lines[3] != _ROT_L4:
        return False, ['line 4: not the custody-advisory line (byte-exact: '
                       '`継続的な鍵の保有 (custody) の証明には、都度の '
                       'challenge–response を使ってください。`)'], info
    info.append(f'out={out} old16={m2.group(1)} new16={m2.group(2)}')
    return (not errs), errs, info


def check_rotate_files(paths: list[str]) -> int:
    failures = 0
    for p in paths:
        try:
            with open(p, encoding='utf-8') as f:
                text = f.read()
        except Exception as e:
            print(f'{p}: FAIL (unreadable: {e})')
            failures += 1
            continue
        ok, errs, info = conform_rotate_report(text)
        if ok:
            print(f'{p}: PASS ({"; ".join(info)})')
        else:
            print(f'{p}: FAIL')
            for e in errs:
                print(f'    - {e}')
            failures += 1
    print(f'--- {len(paths) - failures}/{len(paths)} passed ---')
    return 0 if failures == 0 else 1


def check_board_policy_files(paths: list[str]) -> int:
    failures = 0
    for p in paths:
        try:
            with open(p, encoding='utf-8') as f:
                text = f.read()
        except Exception as e:
            print(f'{p}: FAIL (unreadable: {e})')
            failures += 1
            continue
        ok, errs, info = conform_board_policy_report(text)
        if ok:
            print(f'{p}: PASS ({"; ".join(info)})')
        else:
            print(f'{p}: FAIL')
            for e in errs:
                print(f'    - {e}')
            failures += 1
    print(f'--- {len(paths) - failures}/{len(paths)} passed ---')
    return 0 if failures == 0 else 1


# ---------- check_board_policy_sign: board_policy_sign report consistency ----------

# A saved `nakama.py board_policy_sign` stdout report. Its grammar is fixed
# (spec §9.4.2). check_board_policy_sign verifies that the report is
# internally consistent. Exactly one line:
#   board-policy: <out> — 署名 <m>/<n>（発効条件（全員署名）を満たしています）
# or
#   board-policy: <out> — 署名 <m>/<n>（まだ全員分が揃っていません）
# The report's internal arithmetic rules: m >= 1 (the reference CLI just
# appended the caller's own signature, so at least one signature is
# present — even on a duplicate-sign run the caller was already a signer),
# n >= 1 (the reference CLI refuses an empty eligible list at creation).
# (m <= n is NOT asserted: a signer outside eligible fails the n-of-n
# cert while still being counted, so the reference can print e.g. 4/3.)
# Trailing blank lines tolerated; a leading blank line is rejected.
# Explicitly out of scope: signature truth (the policy file's territory:
# `check_policy` / `verify_board_policy`), whether the signer is in
# eligible, the out file's existence/content, stderr (duplicate-sign
# notices, tampering warnings), and the exit code (invisible in saved
# stdout text). The `board_policy` creation report (§9.4.1) and the
# `verify_board_policy` verdict lines (§9.4.3) are different grammars —
# the three checkers reject each other's reports. Use this to prove a
# second implementation's `board_policy_sign` CLI prints a compatible
# report.

_RE_BPS_LINE = re.compile(
    r'^board-policy: (.+) — 署名 (\d+)/(\d+)'
    r'（(発効条件（全員署名）を満たしています|'
    r'まだ全員分が揃っていません)）$')


def conform_board_policy_sign_report(text: str):
    """Verify a saved `nakama.py board_policy_sign` stdout report is
    internally consistent. Returns (ok, errs, info)."""
    errs: list[str] = []
    info: list[str] = []
    lines = text.splitlines()
    while lines and lines[-1] == '':
        lines.pop()
    if not lines:
        return False, ['report is empty'], info
    if lines[0] == '':
        return False, ['report starts with a blank line'], info
    if len(lines) != 1:
        return False, [f'report must be exactly one line, '
                       f'found {len(lines)}'], info
    m = _RE_BPS_LINE.match(lines[0])
    if not m:
        return False, ['line 1: not a board_policy_sign report line '
                       '(`board-policy: <out> — 署名 <m>/<n>'
                       '（発効条件（全員署名）を満たしています）` or '
                       '`board-policy: <out> — 署名 <m>/<n>'
                       '（まだ全員分が揃っていません）`)'], info
    out, ms, ns = m.group(1), int(m.group(2)), int(m.group(3))
    if out.strip() != out:
        return False, ['line 1: <out> has leading/trailing whitespace'], info
    if not (ms >= 1 and ns >= 1):
        return False, [f'line 1: inconsistent signature counts '
                       f'({ms}/{ns} — m >= 1 and n >= 1 required)'], info
    state = ('effective'
             if m.group(4).startswith('発効条件') else 'pending')
    info.append(f'sign report: out={out} signatures={ms}/{ns} ({state})')
    return (not errs), errs, info


def check_board_policy_sign_files(paths: list[str]) -> int:
    failures = 0
    for p in paths:
        try:
            with open(p, encoding='utf-8') as f:
                text = f.read()
        except Exception as e:
            print(f'{p}: FAIL (unreadable: {e})')
            failures += 1
            continue
        ok, errs, info = conform_board_policy_sign_report(text)
        if ok:
            print(f'{p}: PASS ({"; ".join(info)})')
        else:
            print(f'{p}: FAIL')
            for e in errs:
                print(f'    - {e}')
            failures += 1
    print(f'--- {len(paths) - failures}/{len(paths)} passed ---')
    return 0 if failures == 0 else 1


# ---------- check_verify_board_policy: verify_board_policy report consistency ----------

# A saved `nakama.py verify_board_policy` stdout report. Its grammar is fixed
# (spec §9.4.3). check_verify_board_policy verifies that the report is
# internally consistent. Exactly one line:
#   board-policy は有効です: eligible <n> 名全員の署名を確認（threshold <t>）
# or
#   board-policy は無効です: 全員の有効署名が揃っていないか、形式が不正です
# The valid line's internal arithmetic rules: n >= 1 (the valid cert
# requires a non-empty eligible list) and 1 <= t <= n
# (verify_board_policy_cert returns False unless 1 <= threshold <=
# len(eligible); the reference CLI prints the valid line only when the
# cert is True). t == n is NOT asserted: the initial policy accepts
# threshold < n (the n-of-n rule concerns the signatures, not the
# threshold field — the reference CLI prints the policy's threshold
# verbatim). The invalid line is a fixed literal with no numbers, so no
# arithmetic applies there. Trailing blank lines tolerated; a leading
# blank line is rejected.
# Explicitly out of scope: the verdict's truth (verify_board_policy_cert's
# territory — the policy file itself), the eligible/threshold values'
# truth, stderr, and the exit code (invisible in saved stdout text). The
# `board_policy` creation report (§9.4.1) and the `board_policy_sign`
# report (§9.4.2) are different grammars — the three checkers reject each
# other's reports. Use this to prove a second implementation's
# `verify_board_policy` CLI prints a compatible report.

_RE_VBP_VALID = re.compile(
    r'^board-policy は有効です: eligible (\d+) 名全員の署名を確認'
    r'（threshold (\d+)）$')
_RE_VBP_INVALID = ('board-policy は無効です: '
                   '全員の有効署名が揃っていないか、形式が不正です')


def conform_verify_board_policy_report(text: str):
    """Verify a saved `nakama.py verify_board_policy` stdout report is
    internally consistent. Returns (ok, errs, info)."""
    errs: list[str] = []
    info: list[str] = []
    lines = text.splitlines()
    while lines and lines[-1] == '':
        lines.pop()
    if not lines:
        return False, ['report is empty'], info
    if lines[0] == '':
        return False, ['report starts with a blank line'], info
    if len(lines) != 1:
        return False, [f'report must be exactly one verdict line, '
                       f'found {len(lines)} lines'], info
    line = lines[0]
    if line == _RE_VBP_INVALID:
        info.append('verdict: invalid')
        return (not errs), errs, info
    m = _RE_VBP_VALID.match(line)
    if not m:
        return False, ['line 1: not a verify_board_policy verdict line '
                       '(`board-policy は有効です: eligible <n> '
                       '名全員の署名を確認（threshold <t>）` or '
                       '`board-policy は無効です: 全員の有効署名が揃っていない'
                       'か、形式が不正です`)'], info
    n, t = int(m.group(1)), int(m.group(2))
    if n < 1:
        return False, [f'line 1: inconsistent counts '
                       f'(eligible {n} — n >= 1 required)'], info
    if not (1 <= t <= n):
        return False, [f'line 1: inconsistent counts '
                       f'(threshold {t} — 1 <= t <= n (n={n}) required)'], info
    info.append(f'verdict: valid, eligible={n}, threshold={t}')
    return (not errs), errs, info


def check_verify_board_policy_files(paths: list[str]) -> int:
    failures = 0
    for p in paths:
        try:
            with open(p, encoding='utf-8') as f:
                text = f.read()
        except Exception as e:
            print(f'{p}: FAIL (unreadable: {e})')
            failures += 1
            continue
        ok, errs, info = conform_verify_board_policy_report(text)
        if ok:
            print(f'{p}: PASS ({"; ".join(info)})')
        else:
            print(f'{p}: FAIL')
            for e in errs:
                print(f'    - {e}')
            failures += 1
    print(f'--- {len(paths) - failures}/{len(paths)} passed ---')
    return 0 if failures == 0 else 1


# ---------- check_verify: verify (bond verification) report consistency ----------

# A saved `nakama.py verify` stdout report. Its grammar is fixed (spec
# §2.3.1). check_verify verifies that the report is internally consistent.
# One line per companion (>= 1):
#   <npub[:24]>... : 有効 | 無効/欠落
#     [  (鍵は <npub[:24]>... へローテーション済み — 署名自体は旧鍵のまま有効)]
# then exactly one of:
#   (a) bond は有効です 🤝                                  (all valid — exit 0)
#   (b) bond は無効です                                    (some invalid — exit 1)
#   (c) bond の有効期限が切れています（期限: YYYY-MM-DD）
#       bond は無効です — `renew` で更新してください            (expired — exit 1,
#       no final verdict line)
# The warn variant: (a) may be preceded by the two warning lines:
#   ⚠ bond の有効期限が近づいています（期限: YYYY-MM-DD）
#     `renew` で更新し、更新後 `liveness --bond` で生存証明を取り直すと良いでしょう
# and (a) may be followed by the registry-revocation pair:
#   ⚠ ただしこの bond は解消されています: <npub[:24]>... が YYYY-MM-DD に解消を宣言
#   bond は無効です
# Internal consistency rules: the npub prefix is 24 non-space chars (bech32 —
# the same convention as the other checkers); the rotation note may only
# appear on a companion line, verbatim; any 無効/欠落 companion forces the
# final line (b) and forbids the expiry/warn/revocation lines; the expiry
# 2-line block requires all companions 有効 (the reference CLI checks expiry
# only while ok is still True) and is NOT followed by a final verdict line;
# the warn 2-line block is always followed by (a); the revocation 2-line
# block may only follow (a), and its last line is the plain `bond は無効です`
# (distinct from the expiry block's `bond は無効です — `renew` で更新してください`).
# Dates are YYYY-MM-DD shape-checked only (the value is the checker's local
# time — its truth is out of scope). Trailing blank lines tolerated; a
# leading blank line is rejected.
# Explicitly out of scope: the verdict's truth (verify_schnorr / the bond
# cert — check_bond's territory), npub truth, rotation-note truth, expiry
# date truth (local time), stderr (§14.2 compromise warnings, the registry
# failure note), and the exit code (invisible in saved stdout text). The
# `verify_binding` report (§8.8, `binding は有効です` ...) is a different
# grammar — the two checkers reject each other's reports. Use this to prove a
# second implementation's `verify` CLI prints a compatible report.

_RE_VERIFY_COMPANION = re.compile(
    r'^(\S{24})\.\.\. : (有効|無効/欠落)'
    r'(  \(鍵は (\S{24})\.\.\. へローテーション済み — 署名自体は旧鍵のまま有効\))?$')
_RE_VERIFY_REVOKED = re.compile(
    r'^⚠ ただしこの bond は解消されています: (\S{24})\.\.\. が '
    r'(\d{4})-(\d{2})-(\d{2}) に解消を宣言$')
_VRF_VALID = 'bond は有効です 🤝'
_VRF_INVALID = 'bond は無効です'
_VRF_EXPIRY_1 = 'bond の有効期限が切れています（期限: '
_VRF_EXPIRY_2 = 'bond は無効です — `renew` で更新してください'
_VRF_WARN_1 = '⚠ bond の有効期限が近づいています（期限: '
_VRF_WARN_2 = ('  `renew` で更新し、更新後 `liveness --bond` '
               'で生存証明を取り直すと良いでしょう')


def _vrf_date_ok(y: str, mo: str, d: str) -> bool:
    return 1 <= int(mo) <= 12 and 1 <= int(d) <= 31


def conform_verify_report(text: str):
    """Verify a saved `nakama.py verify` stdout report is internally
    consistent. Returns (ok, errs, info)."""
    errs: list[str] = []
    info: list[str] = []
    lines = text.splitlines()
    while lines and lines[-1] == '':
        lines.pop()
    if not lines:
        return False, ['report is empty'], info
    if lines[0] == '':
        return False, ['report starts with a blank line'], info
    i = 0
    invalid = 0
    while i < len(lines) and _RE_VERIFY_COMPANION.match(lines[i]):
        m = _RE_VERIFY_COMPANION.match(lines[i])
        if m.group(2) == '無効/欠落':
            invalid += 1
        i += 1
    n_comp = i
    if n_comp == 0:
        return False, ['line 1: not a verify companion line '
                       '(`<npub24>... : 有効|無効/欠落` ...)'], info
    rest = lines[i:]
    if not rest:
        return False, [f'line {i + 1}: report ends after the companion '
                       'lines — no verdict'], info
    first = rest[0]

    def _paren_date(prefix: str, line: str):
        # '…（期限: YYYY-MM-DD）' -> date string or None
        if not (line.startswith(prefix) and line.endswith('）')):
            return None
        d = line[len(prefix):-1]
        if not re.fullmatch(r'\d{4}-\d{2}-\d{2}', d):
            return None
        return d

    if first.startswith(_VRF_EXPIRY_1):
        # expired: all companions must be 有効, exactly 2 lines, no verdict
        if invalid:
            errs.append(f'line {i + 1}: expiry block with {invalid} '
                        '無効/欠落 companion(s) — the reference CLI checks '
                        'expiry only while all signatures are valid')
        d = _paren_date(_VRF_EXPIRY_1, first)
        if d is None:
            errs.append(f'line {i + 1}: malformed expiry date '
                        '(expected `…（期限: YYYY-MM-DD）`)')
        elif not _vrf_date_ok(*d.split('-')):
            errs.append(f'line {i + 1}: impossible expiry date {d}')
        if len(rest) != 2 or rest[1] != _VRF_EXPIRY_2:
            errs.append(f'line {i + 2}: the expiry block is exactly 2 lines '
                        '(`bond の有効期限が切れています（期限: …）` + '
                        '`bond は無効です — `renew` で更新してください`), '
                        'with no final verdict line')
        info.append(f'companions={n_comp}, verdict: expired')
        return (not errs), errs, info

    j = 0
    if first.startswith(_VRF_WARN_1):
        # warn block: always followed by the valid verdict
        d = _paren_date(_VRF_WARN_1, first)
        if d is None:
            errs.append(f'line {i + 1}: malformed warn date '
                        '(expected `…（期限: YYYY-MM-DD）`)')
        elif not _vrf_date_ok(*d.split('-')):
            errs.append(f'line {i + 1}: impossible warn date {d}')
        if invalid:
            errs.append(f'line {i + 1}: warn block with {invalid} '
                        '無効/欠落 companion(s) — the reference CLI warns '
                        'only while all signatures are valid')
        if len(rest) < 2 or rest[1] != _VRF_WARN_2:
            errs.append(f'line {i + 2}: the warn block is exactly 2 lines '
                        'followed by the valid verdict line')
            return False, errs, info
        j = 2
        info.append('warn: expiry approaching')
    if j >= len(rest):
        return False, [f'line {i + j + 1}: missing verdict line'], info
    verdict = rest[j]
    if verdict == _VRF_VALID:
        if invalid:
            errs.append(f'line {i + j + 1}: verdict `{_VRF_VALID}` with '
                        f'{invalid} 無効/欠落 companion(s) — inconsistent')
        info.append(f'companions={n_comp}, verdict: valid')
    elif verdict == _VRF_INVALID:
        if not invalid:
            errs.append(f'line {i + j + 1}: verdict `{_VRF_INVALID}` with all '
                        'companions 有効 — inconsistent (no expiry or '
                        'revocation block present)')
        info.append(f'companions={n_comp}, invalid={invalid}, verdict: invalid')
    else:
        return False, [f'line {i + j + 1}: not a verify verdict line '
                       f'(`{_VRF_VALID}` / `{_VRF_INVALID}`)'], info
    tail = rest[j + 1:]
    if not tail:
        return (not errs), errs, info
    # optional registry-revocation pair, only after the valid verdict
    if verdict != _VRF_VALID:
        errs.append(f'line {i + j + 2}: lines after the invalid verdict — '
                    'the revocation pair may only follow the valid verdict')
        return False, errs, info
    if len(tail) != 2 or tail[1] != _VRF_INVALID:
        errs.append(f'line {i + j + 2}: after the valid verdict only the '
                    'registry-revocation pair is allowed '
                    '(`⚠ ただしこの bond は解消されています: …` + '
                    f'`{_VRF_INVALID}`)')
        return False, errs, info
    m = _RE_VERIFY_REVOKED.match(tail[0])
    if not m:
        return False, [f'line {i + j + 2}: malformed revocation line '
                       '(expected `⚠ ただしこの bond は解消されています: '
                       '<npub24>... が YYYY-MM-DD に解消を宣言`)'], info
    if not _vrf_date_ok(m.group(2), m.group(3), m.group(4)):
        errs.append(f'line {i + j + 2}: impossible revocation date')
    info.append('verdict: revoked-in-registry')
    return (not errs), errs, info


def check_verify_files(paths: list[str]) -> int:
    failures = 0
    for p in paths:
        try:
            with open(p, encoding='utf-8') as f:
                text = f.read()
        except Exception as e:
            print(f'{p}: FAIL (unreadable: {e})')
            failures += 1
            continue
        ok, errs, info = conform_verify_report(text)
        if ok:
            print(f'{p}: PASS ({"; ".join(info)})')
        else:
            print(f'{p}: FAIL')
            for e in errs:
                print(f'    - {e}')
            failures += 1
    print(f'--- {len(paths) - failures}/{len(paths)} passed ---')
    return 0 if failures == 0 else 1


# ---------- check_propose: propose report consistency ----------

# `nakama.py propose <npub> [--out <file>] [--expires-days N] [--no-expiry]
# [--markdown]` prints a short report to stdout whose grammar is fixed
# (spec §2.2.1): three lines, plus an optional markdown block only when
# --markdown was used:
#   proposal を <out> に保存しました。相手に渡してください。
#   あなたの npub: <npub>
#   有効期限: <YYYY-MM-DD>（<N> 日後）        (or `有効期限: なし（--no-expiry）`)
#   (blank)
#   投稿用ブロック（相手のスレッド/コメント欄に貼る）:
#   <!-- nakama-proposal:v1 -->
#   ```nakama-proposal
#   <base64url of the proposal JSON>
#   ```
# check_propose verifies that a saved report is internally consistent:
# the first line names the proposal file (non-empty, arbitrary), the
# second line carries the caller's full npub (`npub1` + 58 non-space
# chars — shape-checked only, not bech32-validated), the third line
# carries either a valid calendar date and a non-negative day count or
# the fixed no-expiry line, and the optional markdown tail is exactly
# the fixed header + detection marker + fenced base64url block. Trailing
# blank lines tolerated; a leading blank line is rejected.
# Explicitly out of scope: the npub's truth (who really ran propose),
# the expiry date/day-count truth (the report prints the CLI's local
# time), the proposal file's existence and content (`check_files`'s
# territory), the markdown payload's content (base64url shape only —
# decoding it is the proposal file's territory), stderr, and the exit
# code (invisible in saved stdout text). The `accept` report (§2.2,
# `bond 完成: …`) is a different grammar — the two checkers reject each
# other's reports. Use this to prove a second implementation's `propose`
# CLI prints a compatible report.

_RE_PR_L1 = re.compile(
    r'^proposal を (.+) に保存しました。相手に渡してください。$')
_RE_PR_L2 = re.compile(r'^あなたの npub: (npub1\S{58})$')
_RE_PR_L3_EXP = re.compile(
    r'^有効期限: (\d{4})-(\d{2})-(\d{2})（(\d+) 日後）$')
_PR_L3_NOEXP = '有効期限: なし（--no-expiry）'
_PR_MD_HEADER = '投稿用ブロック（相手のスレッド/コメント欄に貼る）:'
_PR_MD_MARKER = '<!-- nakama-proposal:v1 -->'
_PR_MD_FENCE = '```nakama-proposal'


def conform_propose_report(text: str):
    """Verify a saved `nakama.py propose` stdout report is internally
    consistent. Returns (ok, errs, info)."""
    errs: list[str] = []
    info: list[str] = []
    lines = text.splitlines()
    while lines and lines[-1] == '':
        lines.pop()
    if not lines:
        return False, ['report is empty'], info
    if lines[0] == '':
        return False, ['report starts with a blank line'], info
    m = _RE_PR_L1.match(lines[0])
    if not m:
        return False, ['line 1: not a propose saved-file line '
                       '(`proposal を <out> に保存しました。'
                       '相手に渡してください。`)'], info
    info.append(f'proposal file: {m.group(1)}')
    if len(lines) < 3:
        return False, [f'report must be at least three lines, '
                       f'got {len(lines)}'], info
    m = _RE_PR_L2.match(lines[1])
    if not m:
        return False, ['line 2: not a `あなたの npub: <npub>` line '
                       '(a full npub: `npub1` + 58 non-space chars)'], info
    info.append(f'npub: {m.group(1)[:16]}…')
    l3 = lines[2]
    if l3 == _PR_L3_NOEXP:
        info.append('no expiry')
    else:
        m = _RE_PR_L3_EXP.match(l3)
        if not m:
            return False, ['line 3: not an expiry line '
                           '(`有効期限: <YYYY-MM-DD>（<N> 日後）` or '
                           '`有効期限: なし（--no-expiry）`)'], info
        try:
            datetime.date(int(m.group(1)), int(m.group(2)), int(m.group(3)))
        except ValueError:
            return False, ['line 3: not a valid calendar date'], info
        info.append(f'expiry: {m.group(1)}-{m.group(2)}-{m.group(3)} '
                    f'({m.group(4)} days)')
    if len(lines) == 3:
        info.append('no markdown block')
        return True, errs, info
    tail = lines[3:]
    if len(tail) != 6:
        return False, [f'markdown tail must be exactly six lines, '
                       f'got {len(tail)}'], info
    if tail[0] != '':
        return False, ['line 4: blank separator expected before the '
                       'markdown block'], info
    if tail[1] != _PR_MD_HEADER:
        return False, ['markdown header line mismatch '
                       '(`投稿用ブロック（相手のスレッド/コメント欄に貼る）:` '
                       'expected)'], info
    if tail[2] != _PR_MD_MARKER:
        return False, ['markdown detection marker mismatch '
                       '(`<!-- nakama-proposal:v1 -->` expected)'], info
    if tail[3] != _PR_MD_FENCE:
        return False, ['markdown fence mismatch '
                       '(` ```nakama-proposal ` expected)'], info
    if not _RE_B64U.match(tail[4]):
        return False, ['markdown body is not base64url'], info
    if tail[5] != '```':
        return False, ['markdown closing fence missing'], info
    info.append('markdown block present')
    return True, errs, info


def check_propose_files(paths: list[str]) -> int:
    failures = 0
    for p in paths:
        try:
            with open(p, encoding='utf-8') as f:
                text = f.read()
        except Exception as e:
            print(f'{p}: FAIL (unreadable: {e})')
            failures += 1
            continue
        ok, errs, info = conform_propose_report(text)
        if ok:
            print(f'{p}: PASS ({"; ".join(info)})')
        else:
            print(f'{p}: FAIL')
            for e in errs:
                print(f'    - {e}')
            failures += 1
    print(f'--- {len(paths) - failures}/{len(paths)} passed ---')
    return 0 if failures == 0 else 1


# ---------- check_accept: accept report consistency ----------

# `nakama.py accept <proposal> [--out <file>] [--from-b64 <base64url>]
# [--markdown]` prints a short report to stdout whose grammar is fixed
# (spec §2.2.2): one line, plus an optional markdown block only when
# --markdown was used:
#   bond 完成: <out> — 仲間の証です。大切に保管してください。
#   (blank)
#   投稿用ブロック（返信に貼る）:
#   <!-- nakama-bond:v1 -->
#   ```nakama-bond
#   <base64url of the completed bond JSON>
#   ```
# check_accept verifies that a saved report is internally consistent:
# the first line names the bond file (non-empty, arbitrary), and the
# optional markdown tail is exactly the fixed header + detection marker
# + fenced base64url block. Trailing blank lines tolerated; a leading
# blank line is rejected.
# Explicitly out of scope: the bond file's existence and content
# (`check_bond`'s territory), the markdown payload's content (base64url
# shape only — decoding it is the bond file's territory), the §15
# compromise warnings (stderr), and the exit code (invisible in saved
# stdout text). The `propose` report (§2.2.1, `proposal を …`) is a
# different grammar — the two checkers reject each other's reports. Use
# this to prove a second implementation's `accept` CLI prints a
# compatible report.

_RE_AC_L1 = re.compile(
    r'^bond 完成: (.+) — 仲間の証です。大切に保管してください。$')
_AC_MD_HEADER = '投稿用ブロック（返信に貼る）:'
_AC_MD_MARKER = '<!-- nakama-bond:v1 -->'
_AC_MD_FENCE = '```nakama-bond'


def conform_accept_report(text: str):
    """Verify a saved `nakama.py accept` stdout report is internally
    consistent. Returns (ok, errs, info)."""
    errs: list[str] = []
    info: list[str] = []
    lines = text.splitlines()
    while lines and lines[-1] == '':
        lines.pop()
    if not lines:
        return False, ['report is empty'], info
    if lines[0] == '':
        return False, ['report starts with a blank line'], info
    m = _RE_AC_L1.match(lines[0])
    if not m:
        return False, ['line 1: not an accept completion line '
                       '(`bond 完成: <out> — 仲間の証です。'
                       '大切に保管してください。`)'], info
    info.append(f'bond file: {m.group(1)}')
    if len(lines) == 1:
        info.append('no markdown block')
        return True, errs, info
    tail = lines[1:]
    if len(tail) != 6:
        return False, [f'markdown tail must be exactly six lines, '
                       f'got {len(tail)}'], info
    if tail[0] != '':
        return False, ['line 2: blank separator expected before the '
                       'markdown block'], info
    if tail[1] != _AC_MD_HEADER:
        return False, ['markdown header line mismatch '
                       '(`投稿用ブロック（返信に貼る）:` expected)'], info
    if tail[2] != _AC_MD_MARKER:
        return False, ['markdown detection marker mismatch '
                       '(`<!-- nakama-bond:v1 -->` expected)'], info
    if tail[3] != _AC_MD_FENCE:
        return False, ['markdown fence mismatch '
                       '(` ```nakama-bond ` expected)'], info
    if not _RE_B64U.match(tail[4]):
        return False, ['markdown body is not base64url'], info
    if tail[5] != '```':
        return False, ['markdown closing fence missing'], info
    info.append('markdown block present')
    return True, errs, info


def check_accept_files(paths: list[str]) -> int:
    failures = 0
    for p in paths:
        try:
            with open(p, encoding='utf-8') as f:
                text = f.read()
        except Exception as e:
            print(f'{p}: FAIL (unreadable: {e})')
            failures += 1
            continue
        ok, errs, info = conform_accept_report(text)
        if ok:
            print(f'{p}: PASS ("{"; ".join(info)}")')
        else:
            print(f'{p}: FAIL')
            for e in errs:
                print(f'    - {e}')
            failures += 1
    print(f'--- {len(paths) - failures}/{len(paths)} passed ---')
    return 0 if failures == 0 else 1


# ---------- check_challenge: challenge report consistency ----------

# `nakama.py challenge [<npub>] [--to <npub>]` prints a one-line report to
# stdout whose grammar is fixed (spec §3.1): the 32-byte random nonce as
# 64 lowercase hex chars (`secrets.token_hex(32)`):
#   <64 lowercase hex>
# check_challenge verifies that a saved report is internally consistent:
# exactly one line, exactly 64 lowercase hex chars. Trailing blank lines
# are tolerated; a leading blank line is rejected. There is no internal
# arithmetic to check — a nonce has no derivable fields.
# Note: `respond`'s report is grammatically identical — a single line of
# 64 lowercase hex (the Schnorr signature over the nonce). The two reports
# cannot be distinguished by grammar alone, so check_challenge does NOT
# reject respond reports (unlike e.g. the propose/accept pair, which do
# reject each other). `check`'s reports (`本人です 🤝` / `検証失敗`) are a
# different grammar and are naturally rejected.
# Explicitly out of scope: the nonce's freshness and randomness (a
# cryptographic claim — the checker sees only the saved text), whether
# the line came from `challenge` or `respond`, the `--to` compromise
# warnings (§14.2 — stderr), and the exit code (invisible in saved stdout
# text). Use this to prove a second implementation's `challenge` CLI
# prints a compatible nonce report.

_RE_CHAL = re.compile(r'^[0-9a-f]{64}$')


def conform_challenge_report(text: str):
    """Verify a saved `nakama.py challenge` stdout report is internally
    consistent. Returns (ok, errs, info)."""
    errs: list[str] = []
    info: list[str] = []
    lines = text.splitlines()
    while lines and lines[-1] == '':
        lines.pop()
    if not lines:
        return False, ['report is empty'], info
    if lines[0] == '':
        return False, ['report starts with a blank line'], info
    if len(lines) != 1:
        return False, [f'report must be a single nonce line, '
                       f'found {len(lines)} lines'], info
    if not _RE_CHAL.match(lines[0]):
        return False, ['line 1: not a 64-char lowercase hex nonce '
                       '(`secrets.token_hex(32)`)'], info
    info.append(f'nonce {lines[0][:16]}…')
    return True, errs, info


def check_challenge_files(paths: list[str]) -> int:
    failures = 0
    for p in paths:
        try:
            with open(p, encoding='utf-8') as f:
                text = f.read()
        except Exception as e:
            print(f'{p}: FAIL (unreadable: {e})')
            failures += 1
            continue
        ok, errs, info = conform_challenge_report(text)
        if ok:
            print(f'{p}: PASS ("{"; ".join(info)}")')
        else:
            print(f'{p}: FAIL')
            for e in errs:
                print(f'    - {e}')
            failures += 1
    print(f'--- {len(paths) - failures}/{len(paths)} passed ---')
    return 0 if failures == 0 else 1


# ---------- check_check: check report consistency ----------

# `nakama.py check <npub> <nonce> <sig>` prints a one-line verdict report
# to stdout whose grammar is fixed (spec §3.2):
#   本人です 🤝   (signature verifies — exit 0)
#   検証失敗       (signature does not verify — exit 1)
# check_check verifies that a saved report is internally consistent:
# exactly one line, and that line is one of the two fixed literals.
# Trailing blank lines are tolerated; a leading blank line is rejected.
# There is no internal arithmetic to check — the verdict is a two-word
# vocabulary with no derivable fields.
# The `challenge`/`respond` reports (a single line of 64 lowercase hex)
# are a different grammar and are naturally rejected here, just as
# `check`'s reports were naturally rejected by check_challenge.
# Explicitly out of scope: the verdict's truth (a cryptographic claim —
# `verify_schnorr`'s territory, the checker sees only the saved text),
# the npub/nonce/sig truth, the §14.2 compromise warnings (stderr), and
# the exit code (invisible in saved stdout text). Use this to prove a
# second implementation's `check` CLI prints a compatible verdict line.

_CHECK_VERDICTS = ('本人です 🤝', '検証失敗')


def conform_check_report(text: str):
    """Verify a saved `nakama.py check` stdout report is internally
    consistent. Returns (ok, errs, info)."""
    errs: list[str] = []
    info: list[str] = []
    lines = text.splitlines()
    while lines and lines[-1] == '':
        lines.pop()
    if not lines:
        return False, ['report is empty'], info
    if lines[0] == '':
        return False, ['report starts with a blank line'], info
    if len(lines) != 1:
        return False, [f'report must be a single verdict line, '
                       f'found {len(lines)} lines'], info
    if lines[0] not in _CHECK_VERDICTS:
        return False, ['line 1: not a check verdict line '
                       '(`本人です 🤝` or `検証失敗`)'], info
    info.append(f'verdict {"本人" if lines[0] == "本人です 🤝" else "失敗"}')
    return True, errs, info


def check_check_files(paths: list[str]) -> int:
    failures = 0
    for p in paths:
        try:
            with open(p, encoding='utf-8') as f:
                text = f.read()
        except Exception as e:
            print(f'{p}: FAIL (unreadable: {e})')
            failures += 1
            continue
        ok, errs, info = conform_check_report(text)
        if ok:
            print(f'{p}: PASS ("{"; ".join(info)}")')
        else:
            print(f'{p}: FAIL')
            for e in errs:
                print(f'    - {e}')
            failures += 1
    print(f'--- {len(paths) - failures}/{len(paths)} passed ---')
    return 0 if failures == 0 else 1


# ---------- check_pub: publish-result line consistency ----------

# Every Nostr publish command (rotate_pub, revoke_pub, compromise_pub,
# dm_pub, board_decide_pub, board_draft_pub) prints the same single-line
# result to stdout, and its grammar is fixed (spec §4.3). check_pub verifies
# that a saved report is internally consistent:
#   publish: 受理 (<reason>) id=<64 hex>   (relay accepted — exit 0)
#   publish: 拒否 (<reason>) id=<64 hex>   (relay rejected — exit 1)
# The verdict is the two-word vocabulary 受理/拒否; the id is 64 hex chars
# (case-insensitive) — the published event's id; the reason is the relay's
# free-text response, kept verbatim inside the parens (it may be empty when
# the relay's OK carries no message — the reference CLI prints it as-is).
# Explicitly out of scope: whether the relay really accepted the event
# (claim model — the reference CLI prints the relay's response verbatim),
# the reason's truth, the id's match with the published event (the event
# wire checkers' territory: check_rotation, check_revocation,
# check_compromise, check_dm, check_decision), the exit code (invisible in
# saved stdout text), and board_create's per-kind lines (a different shape).

_RE_PUB = re.compile(r'^publish: (受理|拒否) \((.*)\) id=([0-9a-fA-F]{64})$')


def conform_pub_report(text: str):
    """Verify a saved `<cmd>_pub` stdout report is internally consistent.
    Returns (ok, errs, info)."""
    errs: list[str] = []
    info: list[str] = []
    lines = text.splitlines()
    while lines and lines[-1] == '':
        lines.pop()
    if not lines:
        return False, ['report is empty'], info
    if len(lines) != 1:
        return False, [f'report must be a single publish-result line, '
                       f'found {len(lines)} lines'], info
    m = _RE_PUB.match(lines[0])
    if not m:
        return False, ['line 1: not a publish-result line '
                       '(`publish: 受理/拒否 (reason) id=<64 hex>`)'], info
    verdict, eid = m.group(1), m.group(3)
    info.append(f'{verdict} id={eid[:16]}…')
    return (not errs), errs, info


def check_pub_files(paths: list[str]) -> int:
    failures = 0
    for p in paths:
        try:
            with open(p, encoding='utf-8') as f:
                text = f.read()
        except Exception as e:
            print(f'{p}: FAIL (unreadable: {e})')
            failures += 1
            continue
        ok, errs, info = conform_pub_report(text)
        if ok:
            print(f'{p}: PASS ({"; ".join(info)})')
        else:
            print(f'{p}: FAIL')
            for e in errs:
                print(f'    - {e}')
            failures += 1
    print(f'--- {len(paths) - failures}/{len(paths)} passed ---')
    return 0 if failures == 0 else 1


# ---------- check_governance: governance report consistency ----------

# `board_read --governance <policy.json>` prints a report whose grammar is
# fixed (spec §9.5): two header lines, one block per management event
# (a `--- [...]` line plus 1+ indented detail lines), and a footer carrying
# event and warn counts. check_governance verifies that a saved report is
# internally consistent:
#   ガバナンス照合: <board_id> @ <relay>
#   規約: eligible <n> 名、threshold <t>、決定 <d> 件を読み込み
#   --- [<YYYY-MM-DD HH:MM:SS>] kind <num> (<name>) 発行: <16hex>... 対象: <16hex>...|?... [<mark>]
#       <free-text detail, 1+ lines>
#   管理イベント <R> 件中、要確認 <W> 件
# The verdict is the four-word vocabulary OK/警告/情報/署名無効; the kind
# name must match the NIP-29 vocabulary (Add User / Remove User / Edit
# Group / Delete Group / Add Permission / Remove Permission / Join Request /
# Leave Group), or fall back to `kind <num>` for kinds outside the reference
# CLI's check set. W must equal the number of warn-signature blocks
# (警告 + 署名無効 — the reference CLI counts statuses other than ok/info).
# Explicitly out of scope: whether the verdicts are right (the matching
# logic is governance_match_events' territory — the checker only looks at
# display consistency, like conform_decision), the subject pubkey's truth
# (a truncated `p`-tag display), the detail lines' meaning and content,
# timestamp values and ordering (the reference CLI prints local time), event
# signature validity, and the stderr "注: 無効な board-decision" notes
# (not stdout, so not part of the report grammar).

_RE_GOV_H1 = re.compile(r'^ガバナンス照合: (.+?) @ (.+)$')
_RE_GOV_H2 = re.compile(
    r'^規約: eligible (\d+) 名、threshold (\d+)、決定 (\d+) 件を読み込み$')
_RE_GOV_EV = re.compile(
    r'^--- \[(.+?)\] kind (\d+) \((.+?)\) 発行: ([0-9a-fA-F]{16})\.\.\. '
    r'対象: ((?:[0-9a-fA-F]{16})\.\.\.|\?\.\.\.) '
    r'\[(OK|警告|情報|署名無効)\]$')
_RE_GOV_FOOT = re.compile(r'^管理イベント (\d+) 件中、要確認 (\d+) 件$')
_GOV_KIND_NAMES = {
    '9000': 'Add User', '9001': 'Remove User', '9003': 'Edit Group',
    '9004': 'Delete Group', '9005': 'Add Permission',
    '9006': 'Remove Permission', '9007': 'Join Request',
    '9008': 'Leave Group'}


def conform_governance_report(text: str):
    """Verify a saved `board_read --governance` stdout report is
    internally consistent. Returns (ok, errs, info)."""
    errs: list[str] = []
    info: list[str] = []
    lines = text.splitlines()
    while lines and lines[-1] == '':
        lines.pop()
    if not lines:
        return False, ['report is empty'], info
    m = _RE_GOV_H1.match(lines[0])
    if not m:
        return False, ['line 1: not a governance header line '
                       '(`ガバナンス照合: <board_id> @ <relay>`)'], info
    board_id, relay = m.group(1), m.group(2)
    if len(lines) < 3:
        return False, ['report too short: need header, policy line, '
                       'and footer'], info
    m2 = _RE_GOV_H2.match(lines[1])
    if not m2:
        return False, ['line 2: not a policy line '
                       '(`規約: eligible <n> 名、threshold <t>、決定 <d> '
                       '件を読み込み`)'], info
    n, t, d = int(m2.group(1)), int(m2.group(2)), int(m2.group(3))
    if n < 1:
        errs.append('line 2: eligible count must be >= 1')
    if t < 1:
        errs.append('line 2: threshold must be >= 1')
    info.append(f'board {board_id} @ {relay}, eligible {n}, '
                f'threshold {t}, decisions {d}')
    blocks: list[list] = []
    j = 2
    while j < len(lines):
        m3 = _RE_GOV_EV.match(lines[j])
        if m3:
            blocks.append([j + 1, m3.group(1), m3.group(2), m3.group(3),
                           m3.group(4), m3.group(5), m3.group(6), []])
            j += 1
            continue
        m4 = _RE_GOV_FOOT.match(lines[j])
        if m4:
            break
        if not blocks:
            return False, [f'line {j + 1}: expected an event line or the '
                           'footer'], info
        if not lines[j].startswith('    ') or not lines[j].strip():
            return False, [f'line {j + 1}: detail lines must start with '
                           '4 spaces'], info
        blocks[-1][7].append(lines[j])
        j += 1
    if j >= len(lines):
        return False, ['report has no footer line '
                       '(`管理イベント <R> 件中、要確認 <W> 件`)'], info
    r_ev, r_warn = int(_RE_GOV_FOOT.match(lines[j]).group(1)), \
        int(_RE_GOV_FOOT.match(lines[j]).group(2))
    if j != len(lines) - 1:
        errs.append(f'line {j + 1}: footer must be the last line')
    if r_ev != len(blocks):
        errs.append(f'line {j + 1}: footer event count {r_ev} != '
                    f'{len(blocks)} event blocks')
    warns = sum(1 for b in blocks if b[6] in ('警告', '署名無効'))
    if r_warn != warns:
        errs.append(f'line {j + 1}: footer warn count {r_warn} != '
                    f'{warns} warn/signature-invalid blocks')
    if r_warn > r_ev:
        errs.append(f'line {j + 1}: warn count > event count')
    for lineno, ts, kind, name, issuer, subject, mark, detail in blocks:
        if not _ns_valid_ts(ts):
            errs.append(f'line {lineno}: invalid display timestamp {ts!r}')
        want = _GOV_KIND_NAMES.get(kind, f'kind {kind}')
        if name != want:
            errs.append(f'line {lineno}: kind name {name!r} does not match '
                        f'kind {kind} (expected {want!r})')
        if not detail:
            errs.append(f'line {lineno}: event block has no detail lines')
    if not errs:
        info.append(f'{len(blocks)} events, {warns} to check')
    return (not errs), errs, info


def check_governance_files(paths: list[str]) -> int:
    failures = 0
    for p in paths:
        try:
            with open(p, encoding='utf-8') as f:
                text = f.read()
        except Exception as e:
            print(f'{p}: FAIL (unreadable: {e})')
            failures += 1
            continue
        ok, errs, info = conform_governance_report(text)
        if ok:
            print(f'{p}: PASS ({"; ".join(info)})')
        else:
            print(f'{p}: FAIL')
            for e in errs:
                print(f'    - {e}')
            failures += 1
    print(f'--- {len(paths) - failures}/{len(paths)} passed ---')
    return 0 if failures == 0 else 1


# ---------- check_revoke_fetch: revoke_fetch report consistency ----------

# `nakama.py revoke_fetch <bond_hash>` prints one `取り込み:` line per
# revocation it imports into the local registry, then a footer with the
# fetched/stored/skipped counts. The grammar is fixed (spec §12.4).
# check_revoke_fetch verifies that a saved report is internally
# consistent:
#   取り込み: revocation を registry に記録しました (bond <16hex>..., revoker <16chars>...)
#   <E> 件のイベントを取得: <S> 件を取り込み、<K> 件をスキップ
# The bond prefix must be 16 hex chars (case-insensitive — second
# implementers may print uppercase); the revoker prefix is 16
# non-space chars (the reference CLI prints an npub truncation, which
# is bech32, not hex — so hex is deliberately not required). The number
# of `取り込み:` lines must equal S, E must equal S + K, and the footer
# must be the last line. Explicitly out of scope: the counts' truth
# (the relay's event set is the relay's claim — display consistency
# only), why each event was skipped (invalid Nostr signature, non-JSON
# content, bond_hash mismatch, duplicate, or invalid revocation
# signature — the import path's territory), bond_hash/revoker truth
# (check_revocation's territory), event signature validity
# (verify_revocation_event's territory), ordering, and stderr notes.

_RE_RF_TAKE = re.compile(
    r'^取り込み: revocation を registry に記録しました '
    r'\(bond ([0-9a-fA-F]{16})\.\.\., revoker (\S{16})\.\.\.\)$')
_RE_RF_FOOT = re.compile(
    r'^(\d+) 件のイベントを取得: (\d+) 件を取り込み、(\d+) 件をスキップ$')


def conform_revoke_fetch_report(text: str):
    """Verify a saved `nakama.py revoke_fetch` stdout report is
    internally consistent. Returns (ok, errs, info)."""
    errs: list[str] = []
    info: list[str] = []
    lines = text.splitlines()
    while lines and lines[-1] == '':
        lines.pop()
    if not lines:
        return False, ['report is empty'], info
    m = _RE_RF_FOOT.match(lines[-1])
    if not m:
        return False, ['last line: not a revoke_fetch footer line '
                       '(`<E> 件のイベントを取得: <S> 件を取り込み、'
                       '<K> 件をスキップ`)'], info
    e, s, k = int(m.group(1)), int(m.group(2)), int(m.group(3))
    takes = lines[:-1]
    for j, ln in enumerate(takes):
        if not _RE_RF_TAKE.match(ln):
            errs.append(f'line {j + 1}: does not match the 取り込み line '
                        'grammar (`取り込み: revocation を registry に'
                        '記録しました (bond <16 hex>..., revoker '
                        '<16 chars>...)`)')
    if len(takes) != s:
        errs.append(f'footer says {s} stored but {len(takes)} 取り込み '
                    'lines listed')
    if e != s + k:
        errs.append(f'footer counts do not add up: {e} fetched != '
                    f'{s} stored + {k} skipped')
    if not errs:
        info.append(f'{e} fetched, {s} stored, {k} skipped')
    return (not errs), errs, info


def check_revoke_fetch_files(paths: list[str]) -> int:
    failures = 0
    for p in paths:
        try:
            with open(p, encoding='utf-8') as f:
                text = f.read()
        except Exception as e:
            print(f'{p}: FAIL (unreadable: {e})')
            failures += 1
            continue
        ok, errs, info = conform_revoke_fetch_report(text)
        if ok:
            print(f'{p}: PASS ({"; ".join(info)})')
        else:
            print(f'{p}: FAIL')
            for e in errs:
                print(f'    - {e}')
            failures += 1
    print(f'--- {len(paths) - failures}/{len(paths)} passed ---')
    return 0 if failures == 0 else 1


# ---------- check_rotate_fetch: rotate_fetch report consistency ----------

# `nakama.py rotate_fetch <relay> <old_npub>` (kind 30109, #d=old_hex)
# prints either the single no-publications line, or — in order — one
# `rotation 公開:` link line, the summary footer, and (with --out) the
# save line. With --chain it prints one `[i]` line per chain link (oldest
# first) and optionally the latest-save line; the empty-chain report is
# the single `rotation 公開イベントは見つかりませんでした` line. The
# grammar is fixed (spec §17.9). check_rotate_fetch verifies that a saved
# report is internally consistent:
#   rotation 公開: <old16>... → <new16>... (created_at YYYY-MM-DD)
#   <E> 件のイベントを取得: 有効 1 件、スキップ <K> 件
#   rotation を <file> に保存しました（mode 600）        (only with --out)
#   [<i>] <old16>... → <new16>... (created_at YYYY-MM-DD)  (--chain)
# The npub prefixes are 16 non-space chars (the reference CLI prints an
# npub truncation, which is bech32, not hex — so hex is deliberately not
# required, unlike board-decision core hashes). The date must be a valid
# calendar date. Chain indices must be sequential starting at 0. A report
# that shows a valid rotation must have fetched at least 1 event.
# Explicitly out of scope: the counts' truth (the relay's event set is
# the relay's claim — display consistency only), npub truth
# (check_rotation's territory), the date's value/timezone (the reference
# CLI prints local time — the checker validates grammar, never the zone
# or the instant), chain-link continuity (only 16-char prefixes are
# printed, so full-key equality cannot be verified), ordering beyond the
# index sequence, event signature validity
# (verify_rotation_nostr_event's territory), and stderr notes.

_RTF_LINK = re.compile(
    r'^rotation 公開: (\S{16})\.\.\. → (\S{16})\.\.\. '
    r'\(created_at (\d{4}-\d{2}-\d{2})\)$')
_RTF_CHAIN_LINK = re.compile(
    r'^\[(\d+)\] (\S{16})\.\.\. → (\S{16})\.\.\. '
    r'\(created_at (\d{4}-\d{2}-\d{2})\)$')
_RTF_EMPTY = re.compile(
    r'^(\d+) 件のイベントを取得: 有効な rotation 公開はありませんでした'
    r'（(\d+) 件をスキップ）$')
_RTF_CHAIN_EMPTY = 'rotation 公開イベントは見つかりませんでした'
_RTF_FOOT = re.compile(
    r'^(\d+) 件のイベントを取得: 有効 1 件、スキップ (\d+) 件$')
_RTF_SAVED = re.compile(
    r'^rotation を (.+) に保存しました（mode 600）$')
_RTF_SAVED_LATEST = re.compile(
    r'^最新の rotation を (.+) に保存しました（mode 600）$')


def conform_rotate_fetch_report(text: str):
    """Verify a saved `nakama.py rotate_fetch` stdout report is
    internally consistent. Returns (ok, errs, info)."""
    errs: list[str] = []
    info: list[str] = []
    lines = text.splitlines()
    while lines and lines[-1] == '':
        lines.pop()
    if not lines:
        return False, ['report is empty'], info
    if len(lines) == 1 and lines[0] == _RTF_CHAIN_EMPTY:
        info.append('no published rotations (chain)')
        return True, errs, info
    if _RTF_EMPTY.match(lines[0]):
        if len(lines) != 1:
            return False, ['empty-report line appears together with '
                           'link lines'], info
        m = _RTF_EMPTY.match(lines[0])
        info.append(f'no published rotations ({m.group(1)} fetched, '
                    f'{m.group(2)} skipped)')
        return True, errs, info
    if _RTF_CHAIN_LINK.match(lines[0]):
        links = []
        pos = 0
        while pos < len(lines):
            m = _RTF_CHAIN_LINK.match(lines[pos])
            if not m:
                break
            links.append((pos + 1, int(m.group(1)), m.group(2),
                          m.group(3), m.group(4)))
            pos += 1
        for j, (lineno, idx, _old, _new, date) in enumerate(links):
            if idx != j:
                errs.append(f'line {lineno}: chain index {idx} is not '
                            f'sequential (expected {j})')
            if not _ns_valid_date(date):
                errs.append(f'line {lineno}: invalid display date '
                            f'{date!r}')
        if pos < len(lines):
            if not _RTF_SAVED_LATEST.match(lines[pos]):
                return False, [f'line {pos + 1}: expected the chain save '
                               f'line, got {lines[pos]!r}'], info
            pos += 1
        if pos != len(lines):
            return False, [f'line {pos + 1}: unexpected trailing line '
                           f'{lines[pos]!r}'], info
        if not errs:
            info.append(f'{len(links)} chain links')
        return (not errs), errs, info
    m = _RTF_LINK.match(lines[0])
    if not m:
        return False, [f'line 1: not a rotate_fetch report line '
                       f'({lines[0]!r})'], info
    _old, _new, date = m.group(1), m.group(2), m.group(3)
    if not _ns_valid_date(date):
        errs.append(f'line 1: invalid display date {date!r}')
    if len(lines) < 2:
        return False, errs + ['line 2: missing summary footer'], info
    fm = _RTF_FOOT.match(lines[1])
    if not fm:
        return False, [f'line 2: expected the summary footer, '
                       f'got {lines[1]!r}'], info
    e, k = int(fm.group(1)), int(fm.group(2))
    if e < 1:
        errs.append(f'line 2: footer fetched {e} but a valid rotation '
                    'was shown')
    pos = 2
    if pos < len(lines):
        if not _RTF_SAVED.match(lines[pos]):
            return False, [f'line {pos + 1}: unexpected line after the '
                           f'summary footer: {lines[pos]!r}'], info
        pos += 1
    if pos != len(lines):
        return False, [f'line {pos + 1}: unexpected trailing line '
                       f'{lines[pos]!r}'], info
    if not errs:
        info.append(f'1 rotation shown, {e} fetched, {k} skipped')
    return (not errs), errs, info


def check_rotate_fetch_files(paths: list[str]) -> int:
    failures = 0
    for p in paths:
        try:
            with open(p, encoding='utf-8') as f:
                text = f.read()
        except Exception as e:
            print(f'{p}: FAIL (unreadable: {e})')
            failures += 1
            continue
        ok, errs, info = conform_rotate_fetch_report(text)
        if ok:
            print(f'{p}: PASS ({"; ".join(info)})')
        else:
            print(f'{p}: FAIL')
            for e in errs:
                print(f'    - {e}')
            failures += 1
    print(f'--- {len(paths) - failures}/{len(paths)} passed ---')
    return 0 if failures == 0 else 1

# ---------- check_compromise_fetch: compromise_fetch report consistency ----------

# `nakama.py compromise_fetch <relay> <npub>` prints one `取り込み:` line
# per compromise declaration it imports into the local registry, one
# `更新:` line per withdrawn-flag update, then a footer with the
# fetched/stored/updated/skipped counts. The grammar is fixed
# (spec §13.8). check_compromise_fetch verifies that a saved report is
# internally consistent:
#   取り込み: 侵害宣言を registry に記録しました (subject <16hex>..., declarant <16chars>...)
#   更新: 侵害宣言の撤回・復活を反映しました (declarant <16chars>...)
#   <E> 件のイベントを取得: <S> 件を取り込み、<U> 件を更新、<K> 件をスキップ
# The subject prefix is the x-only pubkey truncation, so 16 hex chars
# (case-insensitive — second implementers may print uppercase); the
# declarant prefix is 16 non-space chars (the reference CLI prints an
# npub truncation, which is bech32, not hex — so hex is deliberately not
# required). The number of `取り込み:` lines must equal S, the number of
# `更新:` lines must equal U, E must equal S + U + K, and the footer
# must be the last line. Explicitly out of scope: the counts' truth
# (the relay's event set is the relay's claim — display consistency
# only), why each event was skipped (invalid Nostr signature, d-tag
# prefix mismatch, non-JSON content, subject mismatch, duplicate, or
# invalid declaration signature — the import path's territory),
# subject/declarant truth (check_compromise's territory), event
# signature validity (verify_compromise_event's territory), ordering,
# and stderr notes.

_CF_TAKE = re.compile(
    r'^取り込み: 侵害宣言を registry に記録しました '
    r'\(subject ([0-9a-fA-F]{16})\.\.\., declarant (\S{16})\.\.\.\)$')
_CF_UPDATE = re.compile(
    r'^更新: 侵害宣言の撤回・復活を反映しました '
    r'\(declarant (\S{16})\.\.\.\)$')
_CF_FOOT = re.compile(
    r'^(\d+) 件のイベントを取得: (\d+) 件を取り込み、(\d+) 件を更新、'
    r'(\d+) 件をスキップ$')


def conform_compromise_fetch_report(text: str):
    """Verify a saved `nakama.py compromise_fetch` stdout report is
    internally consistent. Returns (ok, errs, info)."""
    errs: list[str] = []
    info: list[str] = []
    lines = text.splitlines()
    while lines and lines[-1] == '':
        lines.pop()
    if not lines:
        return False, ['report is empty'], info
    m = _CF_FOOT.match(lines[-1])
    if not m:
        return False, ['last line: not a compromise_fetch footer line '
                       '(`<E> 件のイベントを取得: <S> 件を取り込み、'
                       '<U> 件を更新、<K> 件をスキップ`)'], info
    e, s, u, k = (int(m.group(i)) for i in range(1, 5))
    body = lines[:-1]
    takes = updates = 0
    for j, ln in enumerate(body):
        if _CF_TAKE.match(ln):
            takes += 1
        elif _CF_UPDATE.match(ln):
            updates += 1
        else:
            errs.append(f'line {j + 1}: does not match the 取り込み/更新 '
                        'line grammar (`取り込み: 侵害宣言を registry に'
                        '記録しました (subject <16 hex>..., declarant '
                        '<16 chars>...)` or `更新: 侵害宣言の撤回・復活を'
                        '反映しました (declarant <16 chars>...)`)')
    if takes != s:
        errs.append(f'footer says {s} stored but {takes} 取り込み '
                    'lines listed')
    if updates != u:
        errs.append(f'footer says {u} updated but {updates} 更新 '
                    'lines listed')
    if e != s + u + k:
        errs.append(f'footer counts do not add up: {e} fetched != '
                    f'{s} stored + {u} updated + {k} skipped')
    if not errs:
        info.append(f'{e} fetched, {s} stored, {u} updated, {k} skipped')
    return (not errs), errs, info


def check_compromise_fetch_files(paths: list[str]) -> int:
    failures = 0
    for p in paths:
        try:
            with open(p, encoding='utf-8') as f:
                text = f.read()
        except Exception as e:
            print(f'{p}: FAIL (unreadable: {e})')
            failures += 1
            continue
        ok, errs, info = conform_compromise_fetch_report(text)
        if ok:
            print(f'{p}: PASS ({"; ".join(info)})')
        else:
            print(f'{p}: FAIL')
            for e in errs:
                print(f'    - {e}')
            failures += 1
    print(f'--- {len(paths) - failures}/{len(paths)} passed ---')
    return 0 if failures == 0 else 1

# ---------- check_liveness_verify: verify_liveness report consistency ----------

# `nakama.py verify_liveness <proof.json>` prints exactly one report line
# to stdout and exits: the success line when the proof verifies and is
# fresh, or one of four fixed error lines (invalid signature / future
# timestamp / too old / bond already revoked). The grammar is fixed
# (spec §5.6.2). check_liveness_verify verifies that a saved report is
# internally consistent:
#   生存証明は有効です — <16chars>... が <n> 秒前に鍵を保持していたことを確認。
#   生存証明は無効です
#   生存証明の日付が未来です（時計のずれの許容範囲を超えています）
#   生存証明は古すぎます（<n> 秒前、許容 <m> 秒）
#   bond は解消済みです — 生存証明は無効です
# The npub prefix is 16 non-space chars (the reference CLI prints an
# npub truncation, which is bech32, not hex — so hex is deliberately not
# required). The age in the success line may be negative: the reference
# CLI allows up to 300s of future clock skew, so a slightly-future
# created_at prints a negative age (display-consistency only).
# Explicitly out of scope: the verdict's truth (verify_liveness_event's
# territory), the age value's freshness semantics (--max-age policy),
# npub truth (check_liveness's territory), bond_hash truth, the
# revocation-registry's content (check_revocation's territory), ordering
# (a single line), stderr notes, and the exit code (invisible in saved
# stdout).

_LV_OK = re.compile(
    r'^生存証明は有効です — (\S{16})\.\.\. が (-?\d+) 秒前に'
    r'鍵を保持していたことを確認。$')
_LV_OLD = re.compile(
    r'^生存証明は古すぎます（(\d+) 秒前、許容 (\d+) 秒）$')
_LV_INVALID = '生存証明は無効です'
_LV_FUTURE = '生存証明の日付が未来です（時計のずれの許容範囲を超えています）'
_LV_REVOKED = 'bond は解消済みです — 生存証明は無効です'


def conform_liveness_verify_report(text: str):
    """Verify a saved `nakama.py verify_liveness` stdout report is
    internally consistent. Returns (ok, errs, info)."""
    errs: list[str] = []
    info: list[str] = []
    lines = text.splitlines()
    while lines and lines[-1] == '':
        lines.pop()
    if not lines:
        return False, ['report is empty'], info
    if len(lines) != 1:
        return False, [f'report must be exactly one line, '
                       f'got {len(lines)}'], info
    ln = lines[0]
    m = _LV_OK.match(ln)
    if m:
        info.append(f'valid proof by {m.group(1)}..., age {m.group(2)}s')
        return True, errs, info
    m = _LV_OLD.match(ln)
    if m:
        info.append(f'too-old report: age {m.group(1)}s, '
                    f'max-age {m.group(2)}s')
        return True, errs, info
    if ln in (_LV_INVALID, _LV_FUTURE, _LV_REVOKED):
        info.append(f'error report: {ln}')
        return True, errs, info
    return False, ['line: does not match any verify_liveness report form '
                   '(`生存証明は有効です — <16 chars>... が <n> 秒前に'
                   '鍵を保持していたことを確認。` or one of the four '
                   'fixed error lines)'], info


def check_liveness_verify_files(paths: list[str]) -> int:
    failures = 0
    for p in paths:
        try:
            with open(p, encoding='utf-8') as f:
                text = f.read()
        except Exception as e:
            print(f'{p}: FAIL (unreadable: {e})')
            failures += 1
            continue
        ok, errs, info = conform_liveness_verify_report(text)
        if ok:
            print(f'{p}: PASS ({"; ".join(info)})')
        else:
            print(f'{p}: FAIL')
            for e in errs:
                print(f'    - {e}')
            failures += 1
    print(f'--- {len(paths) - failures}/{len(paths)} passed ---')
    return 0 if failures == 0 else 1


# ---------- check_liveness_report: liveness generation report consistency ----------

# `nakama.py liveness [--bond bond.json] [--out proof.json]` writes the
# proof file and prints a short report to stdout: exactly one line when
# no bond is attached, two lines when it is. The grammar is fixed
# (spec §5.6.3). check_liveness_report verifies that a saved report is
# internally consistent:
#   生存証明: <file> — <16chars>... が鍵を保持していることを宣言しました。
#   bond <16hex>... に紐付けました。仲間に送って「まだここにいる」と伝えましょう。
# The npub prefix is 16 non-space chars (the reference CLI prints an
# npub truncation, which is bech32, not hex — hex is deliberately not
# required, the same treatment as the §5.6.2 verify report). The bond
# prefix is 16 hex chars (bond_hash is a sha256 hex digest, so hex IS
# required here — unlike the npub). The filename is the --out path
# (any non-empty text; which file was actually written is out of
# scope). Explicitly out of scope: the proof file's content
# (check_liveness's territory), npub/bond_hash truth, stderr notes,
# and the exit code (invisible in saved stdout).

_LR_GEN = re.compile(
    r'^生存証明: (.+?) — (\S{16})\.\.\. '
    r'が鍵を保持していることを宣言しました。$')
_LR_BOND = re.compile(
    r'^bond ([0-9a-fA-F]{16})\.\.\. に紐付けました。'
    r'仲間に送って「まだここにいる」と伝えましょう。$')


def conform_liveness_report(text: str):
    """Verify a saved `nakama.py liveness` stdout report is internally
    consistent. Returns (ok, errs, info)."""
    errs: list[str] = []
    info: list[str] = []
    lines = text.splitlines()
    while lines and lines[-1] == '':
        lines.pop()
    if not lines:
        return False, ['report is empty'], info
    if len(lines) not in (1, 2):
        return False, [f'report must be one or two lines, '
                       f'got {len(lines)}'], info
    m = _LR_GEN.match(lines[0])
    if not m:
        return False, ['line 1: not a liveness generation line '
                       '(`生存証明: <file> — <16 chars>... '
                       'が鍵を保持していることを宣言しました。`)'], info
    info.append(f'proof written to {m.group(1)} by {m.group(2)}...')
    if len(lines) == 2:
        mb = _LR_BOND.match(lines[1])
        if not mb:
            return False, ['line 2: not a bond linkage line '
                           '(`bond <16 hex>... に紐付けました。'
                           '仲間に送って「まだここにいる」と伝えましょう。`)'], info
        info.append(f'bond linkage: {mb.group(1)}...')
    return True, errs, info


def check_liveness_report_files(paths: list[str]) -> int:
    failures = 0
    for p in paths:
        try:
            with open(p, encoding='utf-8') as f:
                text = f.read()
        except Exception as e:
            print(f'{p}: FAIL (unreadable: {e})')
            failures += 1
            continue
        ok, errs, info = conform_liveness_report(text)
        if ok:
            print(f'{p}: PASS ({"; ".join(info)})')
        else:
            print(f'{p}: FAIL')
            for e in errs:
                print(f'    - {e}')
            failures += 1
    print(f'--- {len(paths) - failures}/{len(paths)} passed ---')
    return 0 if failures == 0 else 1


# ---------- check_verify_binding: verify_binding report consistency ----------

# `nakama.py verify_binding <binding.json> [--platform <name> --handle <name>]`
# prints a short report to stdout whose grammar is fixed (spec §8.8):
# one line when the binding is invalid, two lines when it is valid:
#   binding は有効です
#   （運用手順）: この binding が実際に該当ハンドルのアカウントから投稿されていることを確認してください
# or
#   binding は無効です
# check_verify_binding verifies that a saved report is internally
# consistent. The first line is one of the two fixed verdict words; the
# second (operational) line is only ever present with the valid verdict.
# Explicitly out of scope: whether the verdict is right (that's
# verify_binding_cert's territory — signature/platform/handle content),
# platform/handle match truth (the mismatch warnings go to stderr, so a
# saved stdout report never shows them), the compromise-warning presence
# (§16's key_compromise_warnings — stderr as well), stderr in general,
# and the exit code (invisible in saved stdout). Use this to prove a
# second implementation's `verify_binding` CLI prints a compatible
# report.

_VB_VALID = 'binding は有効です'
_VB_INVALID = 'binding は無効です'
_VB_NOTE = ('（運用手順）: この binding が実際に該当ハンドルの'
            'アカウントから投稿されていることを確認してください')


def conform_verify_binding_report(text: str):
    """Verify a saved `nakama.py verify_binding` stdout report is
    internally consistent. Returns (ok, errs, info)."""
    errs: list[str] = []
    info: list[str] = []
    lines = text.splitlines()
    while lines and lines[-1] == '':
        lines.pop()
    if not lines:
        return False, ['report is empty'], info
    if len(lines) not in (1, 2):
        return False, [f'report must be one or two lines, '
                       f'got {len(lines)}'], info
    verdict = lines[0]
    if verdict == _VB_VALID:
        info.append('verdict: valid')
    elif verdict == _VB_INVALID:
        info.append('verdict: invalid')
    else:
        return False, ['line 1: not a verify_binding verdict line '
                       '(`binding は有効です` / `binding は無効です`)'], info
    if len(lines) == 2:
        if verdict != _VB_VALID:
            return False, ['line 2: operational note only allowed '
                           'with a valid verdict'], info
        if lines[1] != _VB_NOTE:
            return False, ['line 2: not the fixed operational note '
                           '(`（運用手順）: この binding が実際に該当ハンドルの'
                           'アカウントから投稿されていることを確認してください`)'], info
        info.append('operational note present')
    return True, errs, info


def check_verify_binding_files(paths: list[str]) -> int:
    failures = 0
    for p in paths:
        try:
            with open(p, encoding='utf-8') as f:
                text = f.read()
        except Exception as e:
            print(f'{p}: FAIL (unreadable: {e})')
            failures += 1
            continue
        ok, errs, info = conform_verify_binding_report(text)
        if ok:
            print(f'{p}: PASS ({"; ".join(info)})')
        else:
            print(f'{p}: FAIL')
            for e in errs:
                print(f'    - {e}')
            failures += 1
    print(f'--- {len(paths) - failures}/{len(paths)} passed ---')
    return 0 if failures == 0 else 1


# ---------- check_verify_unbinding: verify_unbinding report consistency ----------

# `nakama.py verify_unbinding <unbinding.json> [--platform <name> --handle <name>]`
# prints a short report to stdout whose grammar is fixed (spec §9.1.1):
# one line when the unbinding is invalid, two lines when it is valid:
#   unbinding は有効です
#   （運用手順）: 取り消し対象の binding がこの unbinding の binding_created_at 以前であることを確認してください
# or
#   unbinding は無効です
# check_verify_unbinding verifies that a saved report is internally
# consistent. The first line is one of the two fixed verdict words; the
# second (operational) line is only ever present with the valid verdict.
# Explicitly out of scope: whether the verdict is right (that's
# verify_unbinding_cert's territory — signature/platform/handle content),
# platform/handle match truth (the mismatch warnings go to stderr, so a
# saved stdout report never shows them), stderr in general, and the
# exit code (invisible in saved stdout). Use this to prove a second
# implementation's `verify_unbinding` CLI prints a compatible report.

_VU_VALID = 'unbinding は有効です'
_VU_INVALID = 'unbinding は無効です'
_VU_NOTE = ('（運用手順）: 取り消し対象の binding がこの unbinding の '
            'binding_created_at 以前であることを確認してください')


def conform_verify_unbinding_report(text: str):
    """Verify a saved `nakama.py verify_unbinding` stdout report is
    internally consistent. Returns (ok, errs, info)."""
    errs: list[str] = []
    info: list[str] = []
    lines = text.splitlines()
    while lines and lines[-1] == '':
        lines.pop()
    if not lines:
        return False, ['report is empty'], info
    if len(lines) not in (1, 2):
        return False, [f'report must be one or two lines, '
                       f'got {len(lines)}'], info
    verdict = lines[0]
    if verdict == _VU_VALID:
        info.append('verdict: valid')
    elif verdict == _VU_INVALID:
        info.append('verdict: invalid')
    else:
        return False, ['line 1: not a verify_unbinding verdict line '
                       '(`unbinding は有効です` / `unbinding は無効です`)'], info
    if len(lines) == 2:
        if verdict != _VU_VALID:
            return False, ['line 2: operational note only allowed '
                           'with a valid verdict'], info
        if lines[1] != _VU_NOTE:
            return False, ['line 2: not the fixed operational note '
                           '(`（運用手順）: 取り消し対象の binding がこの '
                           'unbinding の binding_created_at 以前であること'
                           'を確認してください`)'], info
        info.append('operational note present')
    return True, errs, info


def check_verify_unbinding_files(paths: list[str]) -> int:
    failures = 0
    for p in paths:
        try:
            with open(p, encoding='utf-8') as f:
                text = f.read()
        except Exception as e:
            print(f'{p}: FAIL (unreadable: {e})')
            failures += 1
            continue
        ok, errs, info = conform_verify_unbinding_report(text)
        if ok:
            print(f'{p}: PASS ({"; ".join(info)})')
        else:
            print(f'{p}: FAIL')
            for e in errs:
                print(f'    - {e}')
            failures += 1
    print(f'--- {len(paths) - failures}/{len(paths)} passed ---')
    return 0 if failures == 0 else 1


# ---------- check_renew: renew report consistency ----------

# `nakama.py renew <bond> [--expires-days N] [--out <file>] [--markdown]`
# prints a short report to stdout whose grammar is fixed (spec §9.3.1):
# three lines, plus an optional markdown block only when --markdown was used:
#   更新 proposal を <out> に保存しました。相手に渡し、`accept` で更新 bond を完成させてください。
#   旧 bond hash: <64 lowercase hex>
#   新しい有効期限: <YYYY-MM-DD>（<N> 日後）
#   (blank)
#   投稿用ブロック（相手のスレッド/コメント欄に貼る）:
#   <!-- nakama-proposal:v1 -->
#   ```nakama-proposal
#   <base64url of the proposal JSON>
#   ```
# check_renew verifies that a saved report is internally consistent: the
# first line names the proposal file, the second line carries a 64-char
# lowercase hex bond hash, the third line carries a valid calendar date
# and a non-negative day count, and the optional markdown tail is exactly
# the fixed header + detection marker + fenced base64url block.
# Explicitly out of scope: whether the hash is the bond's real hash, the
# date/day count truth (they describe expires_at, checked by `accept`'s
# and `verify`'s territory — actually they're descriptive text only),
# the proposal file content (`check_files`'s territory), stderr, and the
# exit code (invisible in saved stdout). Use this to prove a second
# implementation's `renew` CLI prints a compatible report.

_RE_L1 = re.compile(
    r'^更新 proposal を (.+) に保存しました。相手に渡し、`accept` で'
    r'更新 bond を完成させてください。$')
_RE_L2 = re.compile(r'^旧 bond hash: ([0-9a-f]{64})$')
_RE_L3 = re.compile(r'^新しい有効期限: (\d{4})-(\d{2})-(\d{2})（(\d+) 日後）$')
_RE_B64U = re.compile(r'^[A-Za-z0-9_-]+={0,2}$')
_RN_MD_HEADER = '投稿用ブロック（相手のスレッド/コメント欄に貼る）:'
_RN_MD_MARKER = '<!-- nakama-proposal:v1 -->'
_RN_MD_FENCE = '```nakama-proposal'


def conform_renew_report(text: str):
    """Verify a saved `nakama.py renew` stdout report is internally
    consistent. Returns (ok, errs, info)."""
    errs: list[str] = []
    info: list[str] = []
    lines = text.splitlines()
    while lines and lines[-1] == '':
        lines.pop()
    if not lines:
        return False, ['report is empty'], info
    if len(lines) < 3:
        return False, [f'report must be at least three lines, '
                       f'got {len(lines)}'], info
    m = _RE_L1.match(lines[0])
    if not m:
        return False, ['line 1: not a renew saved-file line '
                       '(`更新 proposal を <out> に保存しました。相手に渡し、'
                       '`accept` で更新 bond を完成させてください。`)'], info
    info.append(f'proposal file: {m.group(1)}')
    m = _RE_L2.match(lines[1])
    if not m:
        return False, ['line 2: not a `旧 bond hash: <64 lowercase hex>` '
                       'line'], info
    info.append('old bond hash present')
    m = _RE_L3.match(lines[2])
    if not m:
        return False, ['line 3: not a `新しい有効期限: <YYYY-MM-DD>（<N> '
                       '日後）` line'], info
    try:
        datetime.date(int(m.group(1)), int(m.group(2)), int(m.group(3)))
    except ValueError:
        return False, ['line 3: not a valid calendar date'], info
    info.append(f'expiry: {m.group(1)}-{m.group(2)}-{m.group(3)} '
                f'({m.group(4)} days)')
    if len(lines) == 3:
        info.append('no markdown block')
        return True, errs, info
    tail = lines[3:]
    if len(tail) != 6:
        return False, [f'markdown tail must be exactly six lines, '
                       f'got {len(tail)}'], info
    if tail[0] != '':
        return False, ['line 4: blank separator expected before the '
                       'markdown block'], info
    if tail[1] != _RN_MD_HEADER:
        return False, ['markdown header line mismatch '
                       '(`投稿用ブロック（相手のスレッド/コメント欄に貼る）:` '
                       'expected)'], info
    if tail[2] != _RN_MD_MARKER:
        return False, ['markdown detection marker mismatch '
                       '(`<!-- nakama-proposal:v1 -->` expected)'], info
    if tail[3] != _RN_MD_FENCE:
        return False, ['markdown fence mismatch '
                       '(` ```nakama-proposal ` expected)'], info
    if not _RE_B64U.match(tail[4]):
        return False, ['markdown body is not base64url'], info
    if tail[5] != '```':
        return False, ['markdown closing fence missing'], info
    info.append('markdown block present')
    return True, errs, info


def check_renew_files(paths: list[str]) -> int:
    failures = 0
    for p in paths:
        try:
            with open(p, encoding='utf-8') as f:
                text = f.read()
        except Exception as e:
            print(f'{p}: FAIL (unreadable: {e})')
            failures += 1
            continue
        ok, errs, info = conform_renew_report(text)
        if ok:
            print(f'{p}: PASS ({"; ".join(info)})')
        else:
            print(f'{p}: FAIL')
            for e in errs:
                print(f'    - {e}')
            failures += 1
    print(f'--- {len(paths) - failures}/{len(paths)} passed ---')
    return 0 if failures == 0 else 1


# ---------- check_board_join: board_join report consistency ----------

# `nakama.py board_join <relay> <board_id>` prints a single publish-result
# line to stdout whose grammar is fixed (spec §4.4):
#   参加申請: 受理 (reason) id=<64 hex>      (exit 0)
#   参加申請: 拒否 (reason) id=<64 hex>      (exit 1)
# `参加申請:` is this command's fixed prefix — it is NOT the `publish:`
# line checked by `check_pub` (v0.46, §4.3), and `check_board_join` rejects
# `publish:`-prefixed lines (and vice versa: `check_pub` rejects
# `参加申請:`-prefixed lines), so a saved report can only satisfy the
# checker for the command that actually produced it.
# check_board_join verifies that a saved report is internally consistent:
# exactly one line, the fixed `参加申請:` prefix, the two-word verdict
# vocabulary `受理`/`拒否`, an arbitrary reason string taken verbatim from
# the relay (may contain parentheses — the checker reads up to the LAST
# `) id=`, and may be empty when the relay's OK carries no message), and
# a 64-char hex kind 9007 event id (case-insensitive, like `check_pub`).
# Trailing blank lines are tolerated.
# Explicitly out of scope: the relay's accept/reject truth (assertion
# model — the reference implementation prints the relay's response
# verbatim), the reason's truth, whether the id matches the published
# event (event signature checks are the event checkers' territory),
# stderr, and the exit code (invisible in saved stdout). Use this to prove
# a second implementation's `board_join` CLI prints a compatible report.

_RE_BJ = re.compile(r'^参加申請: (受理|拒否) \((.*)\) id=([0-9a-fA-F]{64})$')


def conform_board_join_report(text: str):
    """Verify a saved `nakama.py board_join` stdout report is internally
    consistent. Returns (ok, errs, info)."""
    errs: list[str] = []
    info: list[str] = []
    lines = text.splitlines()
    while lines and lines[-1] == '':
        lines.pop()
    if not lines:
        return False, ['report is empty'], info
    if len(lines) != 1:
        return False, [f'report must be a single board_join result line, '
                       f'found {len(lines)} lines'], info
    m = _RE_BJ.match(lines[0])
    if not m:
        return False, ['line 1: not a board_join result line '
                       '(`参加申請: 受理/拒否 (reason) id=<64 hex>`)'], info
    verdict, reason, eid = m.group(1), m.group(2), m.group(3)
    info.append(f'{verdict} id={eid[:16]}…')
    if reason:
        info.append(f'reason: {reason[:32]}')
    else:
        info.append('reason: (empty)')
    return (not errs), errs, info


def check_board_join_files(paths: list[str]) -> int:
    failures = 0
    for p in paths:
        try:
            with open(p, encoding='utf-8') as f:
                text = f.read()
        except Exception as e:
            print(f'{p}: FAIL (unreadable: {e})')
            failures += 1
            continue
        ok, errs, info = conform_board_join_report(text)
        if ok:
            print(f'{p}: PASS ({"; ".join(info)})')
        else:
            print(f'{p}: FAIL')
            for e in errs:
                print(f'    - {e}')
            failures += 1
    print(f'--- {len(paths) - failures}/{len(paths)} passed ---')
    return 0 if failures == 0 else 1


# ---------- check_board_send: board_send report consistency ----------

# `nakama.py board_send <relay> <board_id> "MSG"` prints a single
# publish-result line to stdout whose grammar is fixed (spec §4.5):
#   投稿: 受理 (reason) id=<64 hex>      (exit 0)
#   投稿: 拒否 (reason) id=<64 hex>      (exit 1)
# `投稿:` is this command's fixed prefix — it is NOT the `publish:`
# line checked by `check_pub` (v0.46, §4.3) nor the `参加申請:` line
# checked by `check_board_join` (v0.56, §4.4); `check_board_send`
# rejects both other prefixes (and both those checkers reject
# `投稿:`-prefixed lines), so a saved report can only satisfy the
# checker for the command that actually produced it.
# check_board_send verifies that a saved report is internally consistent:
# exactly one line, the fixed `投稿:` prefix, the two-word verdict
# vocabulary `受理`/`拒否`, an arbitrary reason string taken verbatim from
# the relay (may contain parentheses — the checker reads up to the LAST
# `) id=`, and may be empty when the relay's OK carries no message), and
# a 64-char hex kind 9 event id (case-insensitive, like `check_pub`).
# Trailing blank lines are tolerated.
# Explicitly out of scope: the relay's accept/reject truth (assertion
# model — the reference implementation prints the relay's response
# verbatim), the reason's truth, whether the id matches the published
# event (event signature checks are the event checkers' territory),
# stderr, and the exit code (invisible in saved stdout). Use this to prove
# a second implementation's `board_send` CLI prints a compatible report.

_RE_BS = re.compile(r'^投稿: (受理|拒否) \((.*)\) id=([0-9a-fA-F]{64})$')


def conform_board_send_report(text: str):
    """Verify a saved `nakama.py board_send` stdout report is internally
    consistent. Returns (ok, errs, info)."""
    errs: list[str] = []
    info: list[str] = []
    lines = text.splitlines()
    while lines and lines[-1] == '':
        lines.pop()
    if not lines:
        return False, ['report is empty'], info
    if len(lines) != 1:
        return False, [f'report must be a single board_send result line, '
                       f'found {len(lines)} lines'], info
    m = _RE_BS.match(lines[0])
    if not m:
        return False, ['line 1: not a board_send result line '
                       '(`投稿: 受理/拒否 (reason) id=<64 hex>`)'], info
    verdict, reason, eid = m.group(1), m.group(2), m.group(3)
    info.append(f'{verdict} id={eid[:16]}…')
    if reason:
        info.append(f'reason: {reason[:32]}')
    else:
        info.append('reason: (empty)')
    return (not errs), errs, info


def check_board_send_files(paths: list[str]) -> int:
    failures = 0
    for p in paths:
        try:
            with open(p, encoding='utf-8') as f:
                text = f.read()
        except Exception as e:
            print(f'{p}: FAIL (unreadable: {e})')
            failures += 1
            continue
        ok, errs, info = conform_board_send_report(text)
        if ok:
            print(f'{p}: PASS ({"; ".join(info)})')
        else:
            print(f'{p}: FAIL')
            for e in errs:
                print(f'    - {e}')
            failures += 1
    print(f'--- {len(paths) - failures}/{len(paths)} passed ---')
    return 0 if failures == 0 else 1


# ---------- check_board_create: board_create report consistency ----------

# `nakama.py board_create <relay> [--out FILE]` prints a multi-line
# report to stdout whose grammar is fixed (spec §4.6):
#   kind 9002: 受理 (reason)        <- create-group result line
#   kind 34550: 受理 (reason)       <- metadata result line (only when 9002
#                                     was accepted)
#   <board descriptor output>       <- either a single
#                                      `descriptor を <out> に保存しました`
#                                      line (--out), or the JSON descriptor
#                                      block (stdout mode) — its
#                                      signature/content is `check_board`'s
#                                      territory, but its *shape* (save
#                                      line or JSON with a matching
#                                      board_id) is checked, so two
#                                      concatenated reports cannot pass
#   広場 "<name>" を作りました: board_id=nakama-<6 hex>
# If the kind 9002 publish is rejected, the report is exactly that one
# line (the CLI exits 1 before publishing kind 34550). If kind 34550 is
# rejected, the report is exactly the two kind lines (the CLI exits 1
# before printing the descriptor).
# `kind 9002:` / `kind 34550:` are this command's fixed per-kind prefixes —
# they are NOT the single-line `publish:` shape checked by `check_pub`
# (v0.46, §4.3, which explicitly excludes board_create's per-kind lines),
# nor the `参加申請:` shape of `check_board_join` (v0.56, §4.4) nor the
# `投稿:` shape of `check_board_send` (v0.57, §4.5); `check_board_create`
# rejects any report whose first line is not a `kind 9002:` result line,
# so a saved report can only satisfy the checker for the command that
# actually produced it.
# check_board_create verifies that a saved report is internally consistent:
# the fixed per-kind line grammar `kind <9002|34550>: 受理/拒否 (reason)`
# with the two-word verdict vocabulary `受理`/`拒否`, an arbitrary reason
# string taken verbatim from the relay (may contain parentheses — the
# checker reads up to the LAST `)` — and may be empty when the relay's
# OK carries no message), the kind order 9002-before-34550, early-exit
# shape (rejection at 9002 ends the report; rejection at 34550 ends it
# after the second line), and — when both publishes were accepted — a
# final `広場 "<name>" を作りました: board_id=nakama-<6 hex>` summary
# line. The board_id hex namespace (`nakama-<3 random bytes>` in the
# reference implementation) is checked structurally.
# Trailing blank lines are tolerated.
# Explicitly out of scope: the relay's accept/reject truth (assertion
# model — the reference implementation prints the relay's response
# verbatim), the reason's truth, whether the published events carry the
# right tags (event signature checks are the event checkers' territory),
# the descriptor content between the kind lines and the summary line
# (its signature is checked by `check_board`), stderr, and the exit code
# (invisible in saved stdout). Use this to prove a second implementation's
# `board_create` CLI prints a compatible report.

_RE_BC_KIND = re.compile(r'^kind (9002|34550): (受理|拒否) \((.*)\)$')
_RE_BC_DONE = re.compile(
    r'^広場 "(.*)" を作りました: board_id=(nakama-[0-9a-f]{6})$')


def conform_board_create_report(text: str):
    """Verify a saved `nakama.py board_create` stdout report is internally
    consistent. Returns (ok, errs, info)."""
    errs: list[str] = []
    info: list[str] = []
    lines = text.splitlines()
    while lines and lines[-1] == '':
        lines.pop()
    if not lines:
        return False, ['report is empty'], info
    m = _RE_BC_KIND.match(lines[0])
    if not m or m.group(1) != '9002':
        return False, ['line 1: not a create-group result line '
                       '(`kind 9002: 受理/拒否 (reason)`)'], info
    v1, reason1 = m.group(2), m.group(3)
    info.append(f'9002 {v1}')
    if v1 == '拒否':
        if len(lines) != 1:
            return False, [f'kind 9002 was rejected, so the report must end '
                           f'here — found {len(lines)} lines'], info
        return (not errs), errs, info
    if len(lines) < 2:
        return False, ['line 2: missing metadata result line '
                       '(`kind 34550: 受理/拒否 (reason)`)'], info
    m2 = _RE_BC_KIND.match(lines[1])
    if not m2 or m2.group(1) != '34550':
        return False, ['line 2: not a metadata result line '
                       '(`kind 34550: 受理/拒否 (reason)`)'], info
    v2, reason2 = m2.group(2), m2.group(3)
    info.append(f'34550 {v2}')
    if v2 == '拒否':
        if len(lines) != 2:
            return False, [f'kind 34550 was rejected, so the report must end '
                           f'after line 2 — found {len(lines)} lines'], info
        return (not errs), errs, info
    # both accepted: the last line must be the creation summary; the
    # descriptor output between the kind lines and the summary must be
    # the single save line (--out mode) or the descriptor JSON block
    # (stdout mode). The descriptor's own signature/content stays out of
    # scope (`check_board`'s territory), but its *shape* pins the report
    # down so two concatenated reports cannot pass.
    md = _RE_BC_DONE.match(lines[-1])
    if not md:
        return False, ['last line: not a board creation summary line '
                       '(`広場 "<name>" を作りました: '
                       'board_id=nakama-<6 hex>`)'], info
    info.append(f'board_id={md.group(2)}')
    mid = lines[2:-1]
    if not mid:
        return False, ['both publishes accepted, but no descriptor output '
                       'between the kind lines and the summary line'], info
    if len(mid) == 1 and mid[0].startswith('descriptor を ') \
            and mid[0].endswith(' に保存しました'):
        pass  # --out mode: single save confirmation line
    else:
        try:
            desc = json.loads('\n'.join(mid))
        except Exception:
            return False, ['descriptor output between the kind lines and '
                           'the summary line is neither a '
                           '`descriptor を <out> に保存しました` line '
                           'nor a JSON descriptor block'], info
        if isinstance(desc, dict) and desc.get('board_id') \
                and desc['board_id'] != md.group(2):
            return False, [f'descriptor board_id {desc["board_id"]!r} does '
                           f'not match the summary board_id '
                           f'{md.group(2)}'], info
    if reason1:
        info.append(f'9002 reason: {reason1[:24]}')
    if reason2:
        info.append(f'34550 reason: {reason2[:24]}')
    return (not errs), errs, info


def check_board_create_files(paths: list[str]) -> int:
    failures = 0
    for p in paths:
        try:
            with open(p, encoding='utf-8') as f:
                text = f.read()
        except Exception as e:
            print(f'{p}: FAIL (unreadable: {e})')
            failures += 1
            continue
        ok, errs, info = conform_board_create_report(text)
        if ok:
            print(f'{p}: PASS ({ "; ".join(info) })')
        else:
            print(f'{p}: FAIL')
            for e in errs:
                print(f'    - {e}')
            failures += 1
    print(f'--- {len(paths) - failures}/{len(paths)} passed ---')
    return 0 if failures == 0 else 1


# ---------- check_verify_board_decision: verify_board_decision report consistency ----------

# verify_board_decision's stdout is a single line stating the threshold
# verdict, and its grammar is fixed (spec §9.6). check_verify_board_decision
# verifies that a saved report is internally consistent:
#
#   valid:   board-decision は有効です: 承認署名 <n>/<t>（決定 "<name>"）
#   invalid: board-decision は無効です: 承認署名 <n>/<t>（threshold 未達または署名不正）
#
# Checks: exactly one line, the fixed two-word verdict vocabulary,
# n/t non-negative integers, the quoted decision name non-empty, and —
# the only piece of internal arithmetic the report supports — a valid
# verdict claims n >= t (a "valid" claim with fewer approvals than the
# threshold is self-contradictory). The decision name is free text; its
# membership in BOARD_DECISION_TYPES is verify_board_decision's territory
# (like the verdict truth itself, the signatures' validity, stderr's
# compromise advisories, and the exit code). Use this to prove a second
# implementation's verify_board_decision CLI prints a compatible report.

_RE_VBD_VALID = re.compile(
    r'^board-decision は有効です: 承認署名 (\d+)/(\d+)（決定 "([^"\n]+)"）$')
_RE_VBD_INVALID = re.compile(
    r'^board-decision は無効です: 承認署名 '
    r'(\d+)/(\d+)（threshold 未達または署名不正）$')


def conform_verify_board_decision_report(text: str):
    """Verify a saved `nakama.py verify_board_decision` stdout report is
    internally consistent. Returns (ok, errors, info)."""
    info = []
    lines = [l for l in text.split('\n') if l.strip() != '']
    if len(lines) != 1:
        return False, [f'expected exactly 1 report line, found {len(lines)}'], \
            info
    line = lines[0]
    m = _RE_VBD_VALID.match(line)
    if m:
        n, t = int(m.group(1)), int(m.group(2))
        if n < t:
            return False, [f'valid verdict claims {n}/{t} approvals: '
                           f'fewer approvals than the threshold'], info
        info.append(f'verdict=valid, signatures={n}/{t}, '
                    f'decision={m.group(3)!r}')
        return True, [], info
    m = _RE_VBD_INVALID.match(line)
    if m:
        info.append(f'verdict=invalid, signatures={m.group(1)}/'
                    f'{m.group(2)}')
        return True, [], info
    return False, ['line matches neither the valid nor the invalid '
                   'verify_board_decision report form'], info


def check_verify_board_decision_files(paths: list[str]) -> int:
    failures = 0
    for p in paths:
        try:
            with open(p, encoding='utf-8') as f:
                text = f.read()
        except Exception as e:
            print(f'{p}: FAIL (unreadable: {e})')
            failures += 1
            continue
        ok, errs, info = conform_verify_board_decision_report(text)
        if ok:
            print(f'{p}: PASS ({ "; ".join(info) })')
        else:
            print(f'{p}: FAIL')
            for e in errs:
                print(f'    - {e}')
            failures += 1
    print(f'--- {len(paths) - failures}/{len(paths)} passed ---')
    return 0 if failures == 0 else 1


# ---------- check_board_verify: board_verify report consistency ----------

# board_verify's stdout is a single line stating the descriptor-signature
# verdict, and its grammar is fixed (spec §4.7). check_board_verify
# verifies that a saved report is internally consistent:
#
#   valid:   board descriptor は有効です
#   invalid: board descriptor は無効です
#
# Checks: exactly one line and the fixed two-word verdict vocabulary
# 有効です/無効です. Unlike check_verify_board_decision, the report
# carries no n/t counts and no decision name, so there is no internal
# arithmetic to verify. Trailing blank lines tolerated. Out of scope:
# the verdict's truth (board_verify's territory), the descriptor's
# content and signature (check_board's territory), stderr's compromise
# advisories (§16), and the exit code (invisible in saved stdout). Use
# this to prove a second implementation's board_verify CLI prints a
# compatible report.

_RE_BV_VALID = re.compile(r'^board descriptor は有効です$')
_RE_BV_INVALID = re.compile(r'^board descriptor は無効です$')


def conform_board_verify_report(text: str):
    """Verify a saved `nakama.py board_verify` stdout report is
    internally consistent. Returns (ok, errors, info)."""
    info = []
    lines = [l for l in text.split('\n') if l.strip() != '']
    if len(lines) != 1:
        return False, [f'expected exactly 1 report line, found {len(lines)}'], \
            info
    line = lines[0]
    if _RE_BV_VALID.match(line):
        info.append('verdict=valid')
        return True, [], info
    if _RE_BV_INVALID.match(line):
        info.append('verdict=invalid')
        return True, [], info
    return False, ['line matches neither the valid nor the invalid '
                   'board_verify report form'], info


def check_board_verify_files(paths: list[str]) -> int:
    failures = 0
    for p in paths:
        try:
            with open(p, encoding='utf-8') as f:
                text = f.read()
        except Exception as e:
            print(f'{p}: FAIL (unreadable: {e})')
            failures += 1
            continue
        ok, errs, info = conform_board_verify_report(text)
        if ok:
            print(f'{p}: PASS ({ "; ".join(info) })')
        else:
            print(f'{p}: FAIL')
            for e in errs:
                print(f'    - {e}')
            failures += 1
    print(f'--- {len(paths) - failures}/{len(paths)} passed ---')
    return 0 if failures == 0 else 1


# ---------- check_board_decide: board_decide report consistency ----------

# board_decide's stdout is a two-line report confirming the created draft
# decision, and its grammar is fixed (spec §9.7):
#
#   line 1: board-decision 案: <out> — 決定 "<decision>"、あなたの承認署名 1 つ
#   line 2: 運用: このファイルを回覧し、`board_cosign` で承認署名を
#           threshold 分まで集めてください。
#
# check_board_decide verifies that a saved report is internally
# consistent. Checks: exactly 2 lines (trailing blank lines tolerated);
# line 1 names a non-empty out file, quotes a decision name belonging to
# the BOARD_DECISION_TYPES vocabulary (the reference argparse
# --decision choices — a creation report can only echo what the command
# accepted), and states exactly the literal 1 own approval signature
# (the reference implementation always self-signs once at creation);
# line 2 must be the fixed operational note verbatim. Unlike
# check_verify_board_decision the report carries no n/t arithmetic —
# the approval count is a fixed literal, so there is no internal
# arithmetic to verify. Out of scope: the payload's validity
# (validate_decision_payload's territory), the approval signature's
# validity (verify_board_decision's territory), the out file's existence
# and content (check_decision's territory), stderr, and the exit code.
# The verify_board_decision report (`board-decision は有効です: ...`,
# §9.6) is a separate grammar and is rejected both ways. Use this to
# prove a second implementation's board_decide CLI prints a compatible
# report.

_RE_BD_LINE1 = re.compile(
    r'^board-decision 案: (.+?) — 決定 "([^"]+)"、あなたの承認署名 1 つ$')
_BD_LINE2 = ('運用: このファイルを回覧し、`board_cosign` で承認署名を '
             'threshold 分まで集めてください。')


def conform_board_decide_report(text: str):
    """Verify a saved `nakama.py board_decide` stdout report is
    internally consistent. Returns (ok, errors, info)."""
    info = []
    lines = [l for l in text.split('\n') if l.strip() != '']
    if len(lines) != 2:
        return False, [f'expected exactly 2 report lines, found {len(lines)}'], \
            info
    m = _RE_BD_LINE1.match(lines[0])
    if not m:
        return False, ['line 1 does not match the board_decide report form'], \
            info
    out, decision = m.group(1), m.group(2)
    if not out.strip():
        return False, ['out file name is empty'], info
    if decision not in nakama.BOARD_DECISION_TYPES:
        return False, [f'decision name {decision!r} is not in the '
                       'BOARD_DECISION_TYPES vocabulary'], info
    if lines[1] != _BD_LINE2:
        return False, ['line 2 is not the fixed operational note'], info
    info.append(f'decision={decision}')
    info.append(f'out={out}')
    return True, [], info


def check_board_decide_files(paths: list[str]) -> int:
    failures = 0
    for p in paths:
        try:
            with open(p, encoding='utf-8') as f:
                text = f.read()
        except Exception as e:
            print(f'{p}: FAIL (unreadable: {e})')
            failures += 1
            continue
        ok, errs, info = conform_board_decide_report(text)
        if ok:
            print(f'{p}: PASS ({ "; ".join(info) })')
        else:
            print(f'{p}: FAIL')
            for e in errs:
                print(f'    - {e}')
            failures += 1
    print(f'--- {len(paths) - failures}/{len(paths)} passed ---')
    return 0 if failures == 0 else 1


# ---------- check_board_cosign: board_cosign report consistency ----------

# board_cosign's stdout is a single-line report naming the (possibly
# re-saved) decision file and the total approval signature count, and
# its grammar is fixed (spec §9.8):
#
#   board-decision: <out> — 承認署名 <n> つ
#
# check_board_cosign verifies that a saved report is internally
# consistent. Checks: exactly 1 line (trailing blank lines tolerated);
# the fixed `board-decision:` prefix — a separate grammar from
# board_decide's `board-decision 案:` creation line (§9.7) and from the
# verify_board_decision verdict line (§9.6); the three grammars are
# rejected across checkers; a non-empty out file name; n is a
# non-negative integer, and the report's only internal arithmetic: a
# successful cosign always reports at least 1 approval (the reference
# either appends its own signature or was already signed — a `0 つ`
# claim is self-contradictory, mirroring check_verify_board_decision's
# n >= t rule). Out of scope: the payload's validity
# (validate_decision_payload's territory), the approval signatures'
# validity (verify_board_decision's territory), the out file's
# existence and content (check_decision's territory), stderr (the
# duplicate-approval and tampering warnings live there, not in
# stdout), and the exit code. Use this to prove a second
# implementation's board_cosign CLI prints a compatible report.

_RE_BCOSIGN = re.compile(r'^board-decision: (.+?) — 承認署名 (\d+) つ$')


def conform_board_cosign_report(text: str):
    """Verify a saved `nakama.py board_cosign` stdout report is
    internally consistent. Returns (ok, errors, info)."""
    info = []
    lines = [l for l in text.split('\n') if l.strip() != '']
    if len(lines) != 1:
        return False, [f'expected exactly 1 report line, found {len(lines)}'], \
            info
    m = _RE_BCOSIGN.match(lines[0])
    if not m:
        return False, ['line does not match the board_cosign report form'], \
            info
    out, n_s = m.group(1), m.group(2)
    if not out.strip():
        return False, ['out file name is empty'], info
    n = int(n_s)
    if n < 1:
        return False, [f'approval count {n} is self-contradictory: a '
                       'successful board_cosign always reports at least 1'], \
            info
    info.append(f'out={out}')
    info.append(f'approvals={n}')
    return True, [], info


def check_board_cosign_files(paths: list[str]) -> int:
    failures = 0
    for p in paths:
        try:
            with open(p, encoding='utf-8') as f:
                text = f.read()
        except Exception as e:
            print(f'{p}: FAIL (unreadable: {e})')
            failures += 1
            continue
        ok, errs, info = conform_board_cosign_report(text)
        if ok:
            print(f'{p}: PASS ({ "; ".join(info) })')
        else:
            print(f'{p}: FAIL')
            for e in errs:
                print(f'    - {e}')
            failures += 1
    print(f'--- {len(paths) - failures}/{len(paths)} passed ---')
    return 0 if failures == 0 else 1


def _key() -> tuple[bytes, str]:
    s = secrets.token_bytes(32)
    return s, nakama.npub_of(s)


def selftest() -> int:
    now = int(time.time())
    s_a, np_a = _key()
    s_b, np_b = _key()

    events: list[tuple[str, dict]] = []

    rev = {'protocol': 'nakama', 'version': 1, 'type': 'revocation',
           'bond_hash': 'ab' * 32, 'revoker_npub': np_a,
           'created_at': now, 'reason': 'conformance selftest'}
    events.append(('30107 revocation', nakama.revocation_nostr_event(rev, s_a)))

    decl = nakama.build_compromise_declaration(s_a, np_b, now)
    events.append(('30108 compromise',
                   nakama.compromise_nostr_event(decl, s_a)))

    rot = {'protocol': 'nakama', 'version': 1, 'type': 'rotation',
           'old_npub': np_a, 'new_npub': np_b, 'created_at': now,
           'reason': 'conformance selftest'}
    events.append(('30109 rotation', nakama.rotation_nostr_event(rot, s_a)))

    for k, nm in ((30110, 'board-decision'), (30111, 'board-draft')):
        d = {'protocol': 'nakama', 'version': 1, 'type': nm,
             'board_id': 'conformance-board', 'decision': 'policy-update',
             'payload': {'threshold': 2}, 'proposer_npub': np_a,
             'approvals': [], 'publisher_npub': np_a, 'created_at': now}
        events.append((f'{k} {nm}',
                       nakama.decision_nostr_event(d, s_a, kind=k)))

    fails = 0
    for name, ev in events:
        ok, errs = conform(ev)
        print(f'{name}: {"PASS" if ok else "FAIL"}')
        for e in errs:
            print(f'    - {e}')
        fails += 0 if ok else 1

    # negative cases — all must be rejected
    neg = []
    tampered = json.loads(json.dumps(events[0][1]))
    tampered['sig'] = '00' * 64
    neg.append(('tampered signature', tampered))
    wrongkind = json.loads(json.dumps(events[4][1]))  # 30111 board-draft
    wrongkind['kind'] = 30110  # content says board-draft, kind says 30110
    neg.append(('kind/type mismatch', wrongkind))
    wrongd = json.loads(json.dumps(events[0][1]))
    for t in wrongd['tags']:
        if t[0] == 'd':
            t[1] = '00' * 32
    neg.append(('wrong d tag', wrongd))

    for name, ev in neg:
        ok, errs = conform(ev)
        good = not ok
        print(f'negative/{name}: {"PASS (rejected)" if good else "FAIL (accepted!)"}')
        if not good:
            fails += 1

    total = len(events) + len(neg)
    print(f'--- {total - fails}/{total} passed ---')

    # NIP-17 DM conformance: wraps built by nakama.py must verify, and
    # tampered wraps must be rejected.
    dm_fails = 0
    s_sender, _ = _key()
    s_recv, _ = _key()
    recv_hexpub = nakama.hexpub_of(s_recv)
    seal = nakama.nip17_build_seal(s_sender, recv_hexpub,
                                   'conformance dm selftest')
    wrap = nakama.nip17_build_gift_wrap(seal, recv_hexpub)

    ok, info = conform_dm(wrap, s_recv)
    print(f'dm/valid wrap: {"PASS" if ok else "FAIL"}'
          f'{" (" + info[0] + ")" if ok else ""}')
    for e in info:
        if not ok:
            print(f'    - {e}')
    dm_fails += 0 if ok else 1

    dm_neg = []
    bad_sig = json.loads(json.dumps(wrap))
    bad_sig['sig'] = '00' * 64
    dm_neg.append(('tampered wrap signature', bad_sig))
    bad_kind = json.loads(json.dumps(wrap))
    bad_kind['kind'] = 1
    dm_neg.append(('non-1059 kind', bad_kind))
    bad_ct = json.loads(json.dumps(wrap))
    bad_ct['content'] = bad_ct['content'][:-4] + 'AAAA'
    dm_neg.append(('tampered ciphertext', bad_ct))

    for name, w in dm_neg:
        ok, errs = conform_dm(w, s_recv)
        good = not ok
        print(f'dm-negative/{name}: {"PASS (rejected)" if good else "FAIL (accepted!)"}')
        if not good:
            dm_fails += 1

    dm_total = 1 + len(dm_neg)
    print(f'--- dm {dm_total - dm_fails}/{dm_total} passed ---')
    fails += dm_fails

    # Board descriptor conformance: reference descriptor built with
    # nakama.py primitives must verify; tampered ones must be rejected.
    board_fails = 0
    s_mod, np_mod = _key()
    b_now = int(time.time())
    b_id = 'nakama-' + secrets.token_hex(3)
    b_relay = 'wss://relay.damus.io'
    desc = {
        'protocol': 'nakama', 'version': 1, 'type': 'board',
        'board_id': b_id, 'relay': b_relay,
        'moderators': [np_mod], 'admission': 'open',
        'created_at': b_now,
    }
    b_msg = nakama.board_descriptor_message(b_id, b_relay, [np_mod], b_now)
    desc['sig'] = nakama.sign_schnorr(s_mod, b_msg).hex()

    ok, errs = conform_board(desc)
    print(f'board/valid descriptor: {"PASS" if ok else "FAIL"}')
    for e in errs:
        print(f'    - {e}')
    board_fails += 0 if ok else 1

    board_neg = []
    bad_sig = dict(desc)
    bad_sig['sig'] = '00' * 128
    board_neg.append(('tampered signature', bad_sig))
    s_other, np_other = _key()
    wrong_signer = dict(desc)
    wrong_signer['sig'] = nakama.sign_schnorr(
        s_other, b_msg).hex()
    board_neg.append(('sig from a different key', wrong_signer))
    tampered_id = dict(desc)
    tampered_id['board_id'] = 'nakama-' + secrets.token_hex(3)
    board_neg.append(('board_id changed after signing', tampered_id))
    bad_id = dict(desc)
    bad_id['board_id'] = 'other-board'
    board_neg.append(('non-nakama board_id', bad_id))
    no_mods = dict(desc)
    no_mods['moderators'] = []
    board_neg.append(('empty moderators', no_mods))
    wrong_type = dict(desc)
    wrong_type['type'] = 'bond'
    board_neg.append(('wrong type', wrong_type))

    for name, b in board_neg:
        ok, errs = conform_board(b)
        good = not ok
        print(f'board-negative/{name}: '
              f'{"PASS (rejected)" if good else "FAIL (accepted!)"}')
        if not good:
            board_fails += 1

    board_total = 1 + len(board_neg)
    print(f'--- board {board_total - board_fails}/{board_total} passed ---')
    fails += board_fails

    # Board-decision file conformance: reference decisions built with
    # nakama.py primitives must verify; malformed ones must be rejected.
    dec_fails = 0
    s_c, np_c = _key()
    s_d, np_d = _key()
    d_now = int(time.time())
    d_id = 'nakama-' + secrets.token_hex(3)
    d_relay = 'wss://relay.damus.io'
    d_payload = {'candidate': np_d}
    d_msg = nakama.board_decision_message(d_id, d_relay, 'admit',
                                          d_payload, d_now)
    dec = {
        'protocol': 'nakama', 'version': 1, 'type': 'board-decision',
        'board_id': d_id, 'relay': d_relay, 'decision': 'admit',
        'payload': d_payload, 'created_at': d_now,
        'approvals': [{'npub': np_c,
                       'sig': nakama.sign_schnorr(s_c, d_msg).hex()}],
    }
    dec_cosigned = json.loads(json.dumps(dec))
    dec_cosigned['approvals'].append(
        {'npub': np_d, 'sig': nakama.sign_schnorr(s_d, d_msg).hex()})

    # policy cert signed by both eligible members (n-of-n for first policy)
    p_msg = nakama.board_policy_message(d_id, d_relay, 2, [np_c, np_d],
                                        d_now)
    pol = {
        'protocol': 'nakama', 'version': 1, 'type': 'board-policy',
        'board_id': d_id, 'relay': d_relay,
        'threshold': 2, 'eligible': [np_c, np_d], 'created_at': d_now,
        'signatures': [{'npub': np_c,
                        'sig': nakama.sign_schnorr(s_c, p_msg).hex()},
                       {'npub': np_d,
                        'sig': nakama.sign_schnorr(s_d, p_msg).hex()}],
    }
    # same relay/board, stricter policy: exposes duplicate counting
    s_e, np_e = _key()
    pol3 = {
        'protocol': 'nakama', 'version': 1, 'type': 'board-policy',
        'board_id': d_id, 'relay': d_relay,
        'threshold': 3, 'eligible': [np_c, np_d, np_e],
        'created_at': d_now, 'signatures': [],
    }
    p3_msg = nakama.board_policy_message(d_id, d_relay, 3, [np_c, np_d, np_e],
                                         d_now)
    pol3['signatures'] = [
        {'npub': np_, 'sig': nakama.sign_schnorr(s_, p3_msg).hex()}
        for np_, s_ in ((np_c, s_c), (np_d, s_d), (np_e, s_e))]

    dec_pos = []
    dec_pos.append(('single approval, no policy', (dec, None)))
    dec_pos.append(('two approvals, policy 2/2', (dec_cosigned, pol)))

    for name, (dd, pp) in dec_pos:
        ok, errs, info = conform_decision(dd, pp)
        print(f'decision/{name}: {"PASS" if ok else "FAIL"}'
              f' ({ "; ".join(info)})')
        for e in errs:
            print(f'    - {e}')
        dec_fails += 0 if ok else 1

    dec_neg = []
    bad_appr = json.loads(json.dumps(dec_cosigned))
    bad_appr['approvals'][0]['sig'] = '00' * 128
    dec_neg.append(('tampered approval signature', (bad_appr, None)))
    bad_payload = json.loads(json.dumps(dec))
    bad_payload['payload'] = {'threshold': 2}  # admit needs candidate
    dec_neg.append(('payload/type mismatch', (bad_payload, None)))
    dup = json.loads(json.dumps(dec_cosigned))
    dup['approvals'].append(json.loads(json.dumps(dup['approvals'][0])))
    dec_neg.append(('duplicate approval with policy 3/2 (counts once, '
                    'not inflated)',
                    (dup, pol3)))
    outsider = json.loads(json.dumps(dec))
    s_out, np_out = _key()
    outsider['approvals'].append(
        {'npub': np_out, 'sig': nakama.sign_schnorr(s_out, d_msg).hex()})
    dec_neg.append(('outsider approval ignored, threshold not met',
                    (outsider, pol)))
    bad_type = json.loads(json.dumps(dec))
    bad_type['decision'] = 'elect-pope'
    dec_neg.append(('unknown decision type', (bad_type, None)))
    no_approvals = json.loads(json.dumps(dec))
    no_approvals['approvals'] = []
    dec_neg.append(('empty approvals', (no_approvals, None)))

    for name, (dd, pp) in dec_neg:
        ok, errs, info = conform_decision(dd, pp)
        good = not ok
        print(f'decision-negative/{name}: '
              f'{"PASS (rejected)" if good else "FAIL (accepted!)"}')
        if not good:
            dec_fails += 1

    dec_total = len(dec_pos) + len(dec_neg)
    print(f'--- decision {dec_total - dec_fails}/{dec_total} passed ---')
    fails += dec_fails

    # Bond certificate conformance: reference bonds built with nakama.py
    # primitives must verify; malformed ones must be rejected.
    bond_fails = 0
    s_f, np_f = _key()
    s_g, np_g = _key()
    b_now = int(time.time())
    b_nonce = secrets.token_hex(32)
    b_exp = b_now + 365 * 86400
    b_msg = nakama.bond_message([np_f, np_g], b_now, b_nonce, b_exp)
    bond = {
        'protocol': 'nakama', 'version': 1,
        'companions': sorted([np_f, np_g]),
        'created_at': b_now, 'nonce': b_nonce, 'expires_at': b_exp,
        'signatures': {np_f: nakama.sign_schnorr(s_f, b_msg).hex(),
                       np_g: nakama.sign_schnorr(s_g, b_msg).hex()},
    }
    s_h, np_h = _key()
    b2_msg = nakama.bond_message([np_f, np_g, np_h], b_now, b_nonce, None)
    bond3 = {
        'protocol': 'nakama', 'version': 1,
        'companions': sorted([np_f, np_g, np_h]),
        'created_at': b_now, 'nonce': b_nonce,
        'signatures': {n_: nakama.sign_schnorr(s_, b2_msg).hex()
                       for n_, s_ in ((np_f, s_f), (np_g, s_g), (np_h, s_h))},
    }

    bond_pos = [('2-party with expiry', bond),
                ('3-party, no expiry (backward compat)', bond3)]
    for name, bb in bond_pos:
        ok, errs, info = conform_bond(bb)
        print(f'bond/{name}: {"PASS" if ok else "FAIL"} '
              f'({"; ".join(info)})')
        for e in errs:
            print(f'    - {e}')
        bond_fails += 0 if ok else 1

    bond_neg = []
    bad_sig = json.loads(json.dumps(bond))
    bad_sig['signatures'][np_f] = '00' * 128
    bond_neg.append(('tampered signature', bad_sig))
    missing = json.loads(json.dumps(bond))
    del missing['signatures'][np_g]
    bond_neg.append(('missing signature', missing))
    bad_nonce = json.loads(json.dumps(bond))
    bad_nonce['nonce'] = 'ff' * 32
    bond_neg.append(('nonce mismatch (sigs no longer match)', bad_nonce))
    bad_exp = json.loads(json.dumps(bond))
    bad_exp['expires_at'] = bad_exp['created_at']
    bond_neg.append(('expires_at <= created_at', bad_exp))
    bad_npub = json.loads(json.dumps(bond))
    bad_npub['companions'] = sorted([np_f, 'npub1invalid'])
    bond_neg.append(('non-npub companion', bad_npub))
    bad_ver = json.loads(json.dumps(bond))
    bad_ver['version'] = 2
    bond_neg.append(('wrong version', bad_ver))

    for name, bb in bond_neg:
        ok, errs, info = conform_bond(bb)
        good = not ok
        print(f'bond-negative/{name}: '
              f'{"PASS (rejected)" if good else "FAIL (accepted!)"}')
        if not good:
            bond_fails += 1

    bond_total = len(bond_pos) + len(bond_neg)
    print(f'--- bond {bond_total - bond_fails}/{bond_total} passed ---')
    fails += bond_fails

    # Platform-binding certificate conformance: reference bindings built
    # with nakama.py primitives must verify; malformed ones must be
    # rejected.
    binding_fails = 0
    s_i, np_i = _key()
    bd_now = int(time.time())
    bd_msg = nakama.binding_message('moltbook', 'alice_test', np_i, bd_now)
    binding = {
        'protocol': 'nakama', 'version': 1, 'type': 'platform-binding',
        'platform': 'moltbook', 'handle': 'alice_test', 'npub': np_i,
        'created_at': bd_now,
        'sig': nakama.sign_schnorr(s_i, bd_msg).hex(),
    }

    binding_pos = [('valid binding', binding)]
    for name, bb in binding_pos:
        ok, errs, info = conform_binding(bb)
        print(f'binding/{name}: {"PASS" if ok else "FAIL"} '
              f'({"; ".join(info)})')
        for e in errs:
            print(f'    - {e}')
        binding_fails += 0 if ok else 1

    binding_neg = []
    bad_sig = json.loads(json.dumps(binding))
    bad_sig['sig'] = '00' * 128
    binding_neg.append(('tampered signature', bad_sig))
    bad_handle = json.loads(json.dumps(binding))
    bad_handle['handle'] = 'mallory_test'
    binding_neg.append(('handle mismatch (sig no longer matches)',
                        bad_handle))
    bad_platform = json.loads(json.dumps(binding))
    bad_platform['platform'] = 'othernet'
    binding_neg.append(('platform mismatch (sig no longer matches)',
                        bad_platform))
    bad_type = json.loads(json.dumps(binding))
    bad_type['type'] = 'platform-binding-revocation'
    binding_neg.append(('wrong type', bad_type))
    bad_npub = json.loads(json.dumps(binding))
    bad_npub['npub'] = 'npub1invalid'
    binding_neg.append(('invalid npub', bad_npub))
    no_sig = json.loads(json.dumps(binding))
    del no_sig['sig']
    binding_neg.append(('missing sig', no_sig))

    for name, bb in binding_neg:
        ok, errs, info = conform_binding(bb)
        good = not ok
        print(f'binding-negative/{name}: '
              f'{"PASS (rejected)" if good else "FAIL (accepted!)"}')
        if not good:
            binding_fails += 1

    binding_total = len(binding_pos) + len(binding_neg)
    print(f'--- binding {binding_total - binding_fails}/'
          f'{binding_total} passed ---')
    fails += binding_fails

    # Liveness proof conformance: reference proofs built with
    # nakama.py primitives must verify; malformed, stale, future,
    # and bond-mismatched ones must be rejected. --now is passed
    # explicitly for deterministic freshness checks.
    live_fails = 0
    s_j, np_j = _key()
    s_k, np_k = _key()
    s_m, np_m = _key()
    lv_now = int(time.time())
    lv_nonce = secrets.token_hex(32)
    live = {
        'protocol': 'nakama', 'version': 1, 'type': 'liveness',
        'npub': np_j, 'created_at': lv_now, 'nonce': lv_nonce,
        'sig': nakama.sign_schnorr(
            s_j, nakama.liveness_message(np_j, lv_now, lv_nonce, None)
        ).hex(),
    }
    # minimal bond for the --bond linkage cases
    lv_bond = {
        'protocol': 'nakama', 'version': 1,
        'companions': sorted([np_j, np_k]),
        'created_at': lv_now, 'nonce': secrets.token_hex(32),
    }
    lv_bh = nakama.bond_hash(lv_bond)
    live_bonded = dict(live)
    live_bonded['bond_hash'] = lv_bh
    live_bonded['sig'] = nakama.sign_schnorr(
        s_j, nakama.liveness_message(np_j, lv_now, lv_nonce, lv_bh)
    ).hex()

    live_pos = [('valid liveness (no bond)', live, None, 7 * 86400),
                ('valid liveness with bond linkage',
                 live_bonded, lv_bond, 7 * 86400)]
    for name, pp, bb, ma in live_pos:
        ok, errs, info = conform_liveness(pp, bb, ma, lv_now)
        print(f'liveness/{name}: {"PASS" if ok else "FAIL"} '
              f'({"; ".join(info)})')
        for e in errs:
            print(f'    - {e}')
        live_fails += 0 if ok else 1

    live_neg = []
    bad_sig = json.loads(json.dumps(live))
    bad_sig['sig'] = '00' * 128
    live_neg.append(('tampered signature', bad_sig, None, 7 * 86400))
    bad_type = json.loads(json.dumps(live))
    bad_type['type'] = 'aliveness'
    live_neg.append(('wrong type', bad_type, None, 7 * 86400))
    bad_nonce = json.loads(json.dumps(live))
    bad_nonce['nonce'] = 'zz' * 32
    live_neg.append(('nonce not hex', bad_nonce, None, 7 * 86400))
    no_sig = json.loads(json.dumps(live))
    del no_sig['sig']
    live_neg.append(('missing sig', no_sig, None, 7 * 86400))
    other_bond = {
        'protocol': 'nakama', 'version': 1,
        'companions': sorted([np_k, np_m]),
        'created_at': lv_now, 'nonce': secrets.token_hex(32),
    }
    live_neg.append(('--bond: prover not a companion',
                     live_bonded, other_bond, 7 * 86400))
    other_hash_bond = dict(lv_bond)
    other_hash_bond['nonce'] = secrets.token_hex(32)
    live_neg.append(('--bond: bond_hash mismatch',
                     live_bonded, other_hash_bond, 7 * 86400))
    future = json.loads(json.dumps(live))
    future['created_at'] = lv_now + 601
    future['sig'] = nakama.sign_schnorr(
        s_j, nakama.liveness_message(np_j, future['created_at'],
                                     lv_nonce, None)).hex()
    live_neg.append(('future-dated beyond 300s skew',
                     future, None, 7 * 86400))
    stale = json.loads(json.dumps(live))
    stale['created_at'] = lv_now - 61
    stale['sig'] = nakama.sign_schnorr(
        s_j, nakama.liveness_message(np_j, stale['created_at'],
                                     lv_nonce, None)).hex()
    live_neg.append(('older than max_age', stale, None, 60))

    for name, pp, bb, ma in live_neg:
        ok, errs, info = conform_liveness(pp, bb, ma, lv_now)
        good = not ok
        print(f'liveness-negative/{name}: '
              f'{"PASS (rejected)" if good else "FAIL (accepted!)"}')
        if not good:
            live_fails += 1

    live_total = len(live_pos) + len(live_neg)
    print(f'--- liveness {live_total - live_fails}/{live_total} passed ---')
    fails += live_fails

    # Compromise declaration conformance: reference declarations
    # built with nakama.py's build_compromise_declaration must verify;
    # malformed, wrong-signer, and wrong-type ones must be rejected.
    # withdrawn=True is a signed field (always included in the
    # message), so it is tested as a positive case, not an exception.
    cp_fails = 0
    s_n, np_n = _key()
    s_o, np_o = _key()
    cp_now = int(time.time())
    decl = nakama.build_compromise_declaration(
        s_n, np_o, cp_now, reason='conformance selftest',
        evidence='https://example.invalid/evidence',
        bond_hash_hex='cd' * 32)
    decl_wd = nakama.build_compromise_declaration(
        s_n, np_o, cp_now, withdrawn=True,
        reason='conformance selftest (withdrawn)')

    cp_pos = [('valid declaration', decl),
              ('valid withdrawn declaration', decl_wd)]
    for name, dd in cp_pos:
        ok, errs, info = conform_compromise(dd)
        print(f'compromise/{name}: {"PASS" if ok else "FAIL"} '
              f'({"; ".join(info)})')
        for e in errs:
            print(f'    - {e}')
        cp_fails += 0 if ok else 1

    cp_neg = []
    bad_sig = json.loads(json.dumps(decl))
    bad_sig['sig'] = '00' * 128
    cp_neg.append(('tampered signature', bad_sig))
    wrong_signer = json.loads(json.dumps(decl))
    wrong_signer['sig'] = nakama.sign_schnorr(
        s_o, nakama.compromise_message(
            nakama.npub_to_hex(np_o), nakama.npub_to_hex(np_n),
            cp_now, False, 'cd' * 32,
            'conformance selftest', 'https://example.invalid/evidence')
    ).hex()
    cp_neg.append(('sig from subject instead of declarant', wrong_signer))
    bad_type = json.loads(json.dumps(decl))
    bad_type['type'] = 'key-compromise-accusation'
    cp_neg.append(('wrong type', bad_type))
    bad_subject = json.loads(json.dumps(decl))
    bad_subject['subject'] = 'npub1invalid'
    cp_neg.append(('invalid subject npub', bad_subject))
    bad_declarant = json.loads(json.dumps(decl))
    bad_declarant['declarant'] = 'npub1invalid'
    cp_neg.append(('invalid declarant npub', bad_declarant))
    bad_ca = json.loads(json.dumps(decl))
    bad_ca['created_at'] = 'not-a-time'
    cp_neg.append(('created_at not an int', bad_ca))
    bad_wd = json.loads(json.dumps(decl))
    bad_wd['withdrawn'] = 1
    cp_neg.append(('withdrawn not a bool', bad_wd))
    bad_bh = json.loads(json.dumps(decl))
    bad_bh['bond_hash'] = 'zz' * 32
    cp_neg.append(('bond_hash not hex', bad_bh))
    no_sig = json.loads(json.dumps(decl))
    del no_sig['sig']
    cp_neg.append(('missing sig', no_sig))

    for name, dd in cp_neg:
        ok, errs, info = conform_compromise(dd)
        good = not ok
        print(f'compromise-negative/{name}: '
              f'{"PASS (rejected)" if good else "FAIL (accepted!)"}')
        if not good:
            cp_fails += 1

    cp_total = len(cp_pos) + len(cp_neg)
    print(f'--- compromise {cp_total - cp_fails}/{cp_total} passed ---')
    fails += cp_fails

    # Rotation certificate conformance: reference certificates built
    # with nakama.py's own primitives must verify; tampered,
    # wrong-signer, wrong-type, malformed, and degenerate ones must be
    # rejected. The signature must come from the OLD key (the party
    # authorizing the migration) — a signature by the new key proves
    # nothing about the old key's custody and is rejected.
    rt_fails = 0
    s_p, np_p = _key()
    s_q, np_q = _key()
    rt_now = int(time.time())
    rotc = {
        'protocol': 'nakama', 'version': 1, 'type': 'rotation',
        'old_npub': np_p, 'new_npub': np_q, 'created_at': rt_now,
    }
    rotc['old_sig'] = nakama.sign_schnorr(
        s_p, nakama.rotation_message(np_p, np_q, rt_now)).hex()
    rotc_extra = json.loads(json.dumps(rotc))
    rotc_extra['note'] = 'extra unknown field tolerated'

    rt_pos = [('valid rotation', rotc),
              ('valid rotation with extra field', rotc_extra)]
    for name, dd in rt_pos:
        ok, errs, info = conform_rotation(dd)
        print(f'rotation/{name}: {"PASS" if ok else "FAIL"} '
              f'({"; ".join(info)})')
        for e in errs:
            print(f'    - {e}')
        rt_fails += 0 if ok else 1

    rt_neg = []
    bad_sig = json.loads(json.dumps(rotc))
    bad_sig['old_sig'] = '00' * 128
    rt_neg.append(('tampered signature', bad_sig))
    wrong_signer = json.loads(json.dumps(rotc))
    wrong_signer['old_sig'] = nakama.sign_schnorr(
        s_q, nakama.rotation_message(np_p, np_q, rt_now)).hex()
    rt_neg.append(('sig from the new key instead of the old key',
                   wrong_signer))
    old_changed = json.loads(json.dumps(rotc))
    _, np_r = _key()
    old_changed['old_npub'] = np_r
    rt_neg.append(('old_npub changed after signing', old_changed))
    new_changed = json.loads(json.dumps(rotc))
    new_changed['new_npub'] = np_r
    rt_neg.append(('new_npub changed after signing', new_changed))
    self_rot = json.loads(json.dumps(rotc))
    self_rot['new_npub'] = np_p
    self_rot['old_sig'] = nakama.sign_schnorr(
        s_p, nakama.rotation_message(np_p, np_p, rt_now)).hex()
    rt_neg.append(('self-rotation (old == new)', self_rot))
    bad_type = json.loads(json.dumps(rotc))
    bad_type['type'] = 'key-change'
    rt_neg.append(('wrong type', bad_type))
    bad_old = json.loads(json.dumps(rotc))
    bad_old['old_npub'] = 'npub1invalid'
    rt_neg.append(('invalid old_npub', bad_old))
    bad_new = json.loads(json.dumps(rotc))
    bad_new['new_npub'] = 'npub1invalid'
    rt_neg.append(('invalid new_npub', bad_new))
    bad_ca = json.loads(json.dumps(rotc))
    bad_ca['created_at'] = 'not-a-time'
    rt_neg.append(('created_at not an int', bad_ca))
    no_sig = json.loads(json.dumps(rotc))
    del no_sig['old_sig']
    rt_neg.append(('missing old_sig', no_sig))

    for name, dd in rt_neg:
        ok, errs, info = conform_rotation(dd)
        good = not ok
        print(f'rotation-negative/{name}: '
              f'{"PASS (rejected)" if good else "FAIL (accepted!)"}')
        if not good:
            rt_fails += 1

    rt_total = len(rt_pos) + len(rt_neg)
    print(f'--- rotation {rt_total - rt_fails}/{rt_total} passed ---')
    fails += rt_fails

    # Revocation file conformance: reference events built with
    # nakama.py's own primitives (revocation_message + sign_schnorr,
    # the same fields `revoke` writes) must verify; tampered,
    # wrong-signer, wrong-type, and malformed ones must be rejected.
    # The signature must come from the revoker named in the event —
    # a signature by any other key proves nothing about the revoker's
    # intent and is rejected.
    rv_fails = 0
    rv_now = int(time.time())
    rv_bh = 'ab' * 32
    rv = {
        'protocol': 'nakama', 'version': 1, 'type': 'revocation',
        'bond_hash': rv_bh, 'revoker': np_a, 'created_at': rv_now,
    }
    rv['sig'] = nakama.sign_schnorr(
        s_a, nakama.revocation_message(rv_bh, np_a, rv_now)).hex()
    rv_reason = json.loads(json.dumps(rv))
    rv_reason['reason'] = 'conformance selftest'
    rv_reason['sig'] = nakama.sign_schnorr(
        s_a, nakama.revocation_message(
            rv_bh, np_a, rv_now, 'conformance selftest')).hex()
    rv_extra = json.loads(json.dumps(rv))
    rv_extra['note'] = 'extra unknown field tolerated'

    rv_pos = [('valid revocation', rv),
              ('valid revocation with reason', rv_reason),
              ('valid revocation with extra field', rv_extra)]
    for name, dd in rv_pos:
        ok, errs, info = conform_revocation(dd)
        print(f'revocation/{name}: {"PASS" if ok else "FAIL"} '
              f'({"; ".join(info)})')
        for e in errs:
            print(f'    - {e}')
        rv_fails += 0 if ok else 1

    rv_neg = []
    bad_sig = json.loads(json.dumps(rv))
    bad_sig['sig'] = '00' * 128
    rv_neg.append(('tampered signature', bad_sig))
    wrong_signer = json.loads(json.dumps(rv))
    wrong_signer['sig'] = nakama.sign_schnorr(
        s_b, nakama.revocation_message(rv_bh, np_a, rv_now)).hex()
    rv_neg.append(('sig from a non-revoker key', wrong_signer))
    revoker_changed = json.loads(json.dumps(rv))
    revoker_changed['revoker'] = np_b
    rv_neg.append(('revoker changed after signing', revoker_changed))
    bh_changed = json.loads(json.dumps(rv))
    bh_changed['bond_hash'] = 'cd' * 32
    rv_neg.append(('bond_hash changed after signing', bh_changed))
    bad_type = json.loads(json.dumps(rv))
    bad_type['type'] = 'dissolution'
    rv_neg.append(('wrong type', bad_type))
    bad_revoker = json.loads(json.dumps(rv))
    bad_revoker['revoker'] = 'npub1invalid'
    rv_neg.append(('invalid revoker npub', bad_revoker))
    bad_bh = json.loads(json.dumps(rv))
    bad_bh['bond_hash'] = 'zz' * 32
    rv_neg.append(('bond_hash not hex', bad_bh))
    bad_ca = json.loads(json.dumps(rv))
    bad_ca['created_at'] = 'not-a-time'
    rv_neg.append(('created_at not an int', bad_ca))
    bad_reason = json.loads(json.dumps(rv_reason))
    bad_reason['reason'] = 123
    rv_neg.append(('reason not a string', bad_reason))
    no_sig = json.loads(json.dumps(rv))
    del no_sig['sig']
    rv_neg.append(('missing sig', no_sig))

    for name, dd in rv_neg:
        ok, errs, info = conform_revocation(dd)
        good = not ok
        print(f'revocation-negative/{name}: '
              f'{"PASS (rejected)" if good else "FAIL (accepted!)"}')
        if not good:
            rv_fails += 1

    rv_total = len(rv_pos) + len(rv_neg)
    print(f'--- revocation {rv_total - rv_fails}/{rv_total} passed ---')
    fails += rv_fails

    # Unbinding certificate conformance: reference unbindings built
    # with nakama.py's unbinding_message must verify; malformed,
    # re-scoped, and wrong-type ones must be rejected. The
    # binding_created_at scope (0 = withdraw every binding to the
    # handle, otherwise only bindings at or before that timestamp)
    # is signed, so changing it must break the signature.
    ub_fails = 0
    s_l, np_l = _key()
    ub_now = int(time.time())
    ub_msg = nakama.unbinding_message('moltbook', 'alice_test', np_l,
                                      0, '', ub_now)
    unbinding = {
        'protocol': 'nakama', 'version': 1,
        'type': 'platform-binding-revocation',
        'platform': 'moltbook', 'handle': 'alice_test', 'npub': np_l,
        'binding_created_at': 0, 'reason': '',
        'created_at': ub_now,
        'sig': nakama.sign_schnorr(s_l, ub_msg).hex(),
    }
    ub_scoped_ca = ub_now - 86400
    ub_scoped_msg = nakama.unbinding_message(
        'moltbook', 'alice_test', np_l, ub_scoped_ca, 'handle moved',
        ub_now)
    ub_scoped = {
        'protocol': 'nakama', 'version': 1,
        'type': 'platform-binding-revocation',
        'platform': 'moltbook', 'handle': 'alice_test', 'npub': np_l,
        'binding_created_at': ub_scoped_ca, 'reason': 'handle moved',
        'created_at': ub_now,
        'sig': nakama.sign_schnorr(s_l, ub_scoped_msg).hex(),
    }
    ub_extra = json.loads(json.dumps(unbinding))
    ub_extra['note'] = 'extra unknown field tolerated'

    ub_pos = [('valid unbinding (scope: all bindings)', unbinding),
              ('valid scoped unbinding with reason', ub_scoped),
              ('valid unbinding with extra field', ub_extra)]
    for name, uu in ub_pos:
        ok, errs, info = conform_unbinding(uu)
        print(f'unbinding/{name}: {"PASS" if ok else "FAIL"} '
              f'({"; ".join(info)})')
        for e in errs:
            print(f'    - {e}')
        ub_fails += 0 if ok else 1

    ub_neg = []
    bad_sig = json.loads(json.dumps(unbinding))
    bad_sig['sig'] = '00' * 128
    ub_neg.append(('tampered signature', bad_sig))
    bad_handle = json.loads(json.dumps(unbinding))
    bad_handle['handle'] = 'mallory_test'
    ub_neg.append(('handle mismatch (sig no longer matches)',
                   bad_handle))
    bad_platform = json.loads(json.dumps(unbinding))
    bad_platform['platform'] = 'othernet'
    ub_neg.append(('platform mismatch (sig no longer matches)',
                   bad_platform))
    bad_bca = json.loads(json.dumps(ub_scoped))
    bad_bca['binding_created_at'] = ub_scoped_ca - 1
    ub_neg.append(('binding_created_at changed after signing',
                   bad_bca))
    bad_reason = json.loads(json.dumps(ub_scoped))
    bad_reason['reason'] = 'handle hijacked'
    ub_neg.append(('reason changed after signing', bad_reason))
    bad_type = json.loads(json.dumps(unbinding))
    bad_type['type'] = 'platform-binding'
    ub_neg.append(('wrong type', bad_type))
    bad_npub = json.loads(json.dumps(unbinding))
    bad_npub['npub'] = 'npub1invalid'
    ub_neg.append(('invalid npub', bad_npub))
    bad_bca_type = json.loads(json.dumps(unbinding))
    bad_bca_type['binding_created_at'] = '0'
    ub_neg.append(('binding_created_at not an int', bad_bca_type))
    bad_reason_type = json.loads(json.dumps(unbinding))
    bad_reason_type['reason'] = 0
    ub_neg.append(('reason not a string', bad_reason_type))
    bad_ca = json.loads(json.dumps(unbinding))
    bad_ca['created_at'] = 'not-a-time'
    ub_neg.append(('created_at not an int', bad_ca))
    no_sig = json.loads(json.dumps(unbinding))
    del no_sig['sig']
    ub_neg.append(('missing sig', no_sig))

    for name, uu in ub_neg:
        ok, errs, info = conform_unbinding(uu)
        good = not ok
        print(f'unbinding-negative/{name}: '
              f'{"PASS (rejected)" if good else "FAIL (accepted!)"}')
        if not good:
            ub_fails += 1

    ub_total = len(ub_pos) + len(ub_neg)
    print(f'--- unbinding {ub_total - ub_fails}/{ub_total} passed ---')
    fails += ub_fails

    # Board-policy certificate conformance: reference policies
    # built with nakama.py's board_policy_message/sign_schnorr must
    # verify; malformed, re-scoped, and wrong-type ones must be
    # rejected. The initial policy is n-of-n: every eligible member
    # signs, outsiders are rejected, duplicate signatures collapse
    # (set semantics, mirroring verify_board_policy_cert).
    pl_fails = 0
    s_c, np_c = _key()
    pl_now = int(time.time())
    pl_board, pl_relay = 'test-board', 'wss://relay.test'
    pl_eligible = [np_a, np_b, np_c]
    pl_thr = 2

    def _policy(eligible, thr, created_at):
        msg = nakama.board_policy_message(pl_board, pl_relay, thr,
                                          eligible, created_at)
        return {'protocol': 'nakama', 'version': 1,
                'type': 'board-policy', 'board_id': pl_board,
                'relay': pl_relay, 'threshold': thr,
                'eligible': eligible, 'created_at': created_at,
                'signatures': [{'npub': np, 'sig': ''} for np in eligible]}

    def _sign(pl, keys):
        msg = nakama.board_policy_message(pl['board_id'], pl['relay'],
                                          pl['threshold'], pl['eligible'],
                                          pl['created_at'])
        pl['signatures'] = [{'npub': np, 'sig': nakama.sign_schnorr(
            sec, msg).hex()} for sec, np in keys]
        return pl

    policy = _sign(_policy(pl_eligible, pl_thr, pl_now),
                   [(s_a, np_a), (s_b, np_b), (s_c, np_c)])
    solo = _sign(_policy([np_a], 1, pl_now), [(s_a, np_a)])
    dup = _sign(_policy(pl_eligible, pl_thr, pl_now),
                [(s_a, np_a), (s_b, np_b), (s_c, np_c), (s_a, np_a)])

    pl_pos = [('valid 2-of-3 n-of-n policy', policy),
              ('valid 1-of-1 single-member policy', solo),
              ('valid n-of-n with duplicate signature (collapses)',
               dup)]
    for name, pp in pl_pos:
        ok, errs, info = conform_policy(pp)
        print(f'policy/{name}: {"PASS" if ok else "FAIL"} '
              f'({"; ".join(info)})')
        for e in errs:
            print(f'    - {e}')
        pl_fails += 0 if ok else 1

    pl_neg = []
    bad_sig = json.loads(json.dumps(policy))
    bad_sig['signatures'][0]['sig'] = '00' * 128
    pl_neg.append(('tampered signature', bad_sig))
    outsider = json.loads(json.dumps(policy))
    s_x, np_x = _key()
    outsider['signatures'][0] = {
        'npub': np_x, 'sig': nakama.sign_schnorr(
            s_x, nakama.board_policy_message(
                pl_board, pl_relay, pl_thr, pl_eligible,
                pl_now)).hex()}
    pl_neg.append(('outsider signature (valid sig, not eligible)',
                   outsider))
    missing = json.loads(json.dumps(policy))
    missing['signatures'] = missing['signatures'][1:]
    pl_neg.append(('one eligible signer missing (n-of-n not met)',
                   missing))
    thr0 = json.loads(json.dumps(policy))
    thr0['threshold'] = 0
    pl_neg.append(('threshold 0 (invalid after resigning)',
                   _sign(thr0, [(s_a, np_a), (s_b, np_b),
                                (s_c, np_c)])))
    thr_big = json.loads(json.dumps(policy))
    thr_big['threshold'] = 4
    pl_neg.append(('threshold > len(eligible)', thr_big))
    dup_elig = _sign(_policy([np_a, np_a, np_c], pl_thr, pl_now),
                     [(s_a, np_a), (s_a, np_a), (s_c, np_c)])
    pl_neg.append(('duplicate npub in eligible', dup_elig))
    bad_elig = json.loads(json.dumps(policy))
    bad_elig['eligible'] = ['npub1invalid', np_b, np_c]
    pl_neg.append(('invalid npub in eligible', bad_elig))
    bad_bid = json.loads(json.dumps(policy))
    bad_bid['board_id'] = 'other-board'
    pl_neg.append(('board_id changed after signing', bad_bid))
    bad_thr_type = json.loads(json.dumps(policy))
    bad_thr_type['threshold'] = '2'
    pl_neg.append(('threshold not an int', bad_thr_type))
    bad_ca = json.loads(json.dumps(policy))
    bad_ca['created_at'] = 'not-a-time'
    pl_neg.append(('created_at not an int', bad_ca))
    bad_type = json.loads(json.dumps(policy))
    bad_type['type'] = 'board-decision'
    pl_neg.append(('wrong type', bad_type))
    no_sigs = json.loads(json.dumps(policy))
    del no_sigs['signatures']
    pl_neg.append(('missing signatures', no_sigs))

    for name, pp in pl_neg:
        ok, errs, info = conform_policy(pp)
        good = not ok
        print(f'policy-negative/{name}: '
              f'{"PASS (rejected)" if good else "FAIL (accepted!)"}')
        if not good:
            pl_fails += 1

    pl_total = len(pl_pos) + len(pl_neg)
    print(f'--- policy {pl_total - pl_fails}/{pl_total} passed ---')
    fails += pl_fails

    # Board-decision draft conformance: reference drafts built with
    # nakama.py's board_decide/board_cosign primitives (board_decision
    # message + per-approval Schnorr signatures) must verify;
    # tampered, re-scoped, and wrong-type drafts must be rejected.
    # Threshold is never a gate (drafts are in-flight); expiry is
    # info-only; policy-update drafts are judged against the CURRENT
    # policy (proposed values never used for judgment, §29.2).
    dr_fails = 0
    dr_now = int(time.time())
    dr_board, dr_relay = 'draft-board', 'wss://relay.test'
    s_d, np_d = _key()
    s_e, np_e = _key()

    def _draft(decision, payload, signers, created_at=None, extra=None):
        ca = dr_now if created_at is None else created_at
        d = {'protocol': 'nakama', 'version': 1,
             'type': 'board-decision', 'board_id': dr_board,
             'relay': dr_relay, 'decision': decision,
             'payload': payload, 'created_at': ca, 'approvals': []}
        if extra:
            d.update(extra)
        msg = nakama.board_decision_message(dr_board, dr_relay, decision,
                                           payload, ca)
        for sec, npub in signers:
            d['approvals'].append(
                {'npub': npub, 'sig': nakama.sign_schnorr(sec, msg).hex()})
        return d

    dr_pos = [
        ('valid single-approval admit draft',
         _draft('admit', {'candidate': np_b}, [(s_a, np_a)])),
        ('valid cosign draft (2 unique signers, duplicate collapses)',
         _draft('handover', {'new_moderators': [np_c]},
                [(s_a, np_a), (s_b, np_b), (s_a, np_a)])),
        ('valid policy-update draft judged against current policy',
         _draft('policy-update',
                {'threshold': 2,
                 'eligible': [np_a, np_b, np_c, np_d, np_e]},
                [(s_a, np_a), (s_b, np_b)])),
        ('valid but expired draft (info-only, not failure)',
         _draft('close', {'reason': 'done',
                          'expires_at': dr_now - 60},
                [(s_a, np_a)])),
    ]
    # a current policy for the judgment info: 3 eligible, threshold 2
    pl_keys = [(s_a, np_a), (s_b, np_b), (s_c, np_c)]
    dr_policy_msg = nakama.board_policy_message(
        dr_board, dr_relay, 2, [np_a, np_b, np_c], dr_now)
    dr_policy = {'protocol': 'nakama', 'version': 1, 'type': 'board-policy',
                 'board_id': dr_board, 'relay': dr_relay, 'threshold': 2,
                 'eligible': [np_a, np_b, np_c], 'created_at': dr_now,
                 'signatures': [{'npub': np,
                                 'sig': nakama.sign_schnorr(sec,
                                                            dr_policy_msg).hex()}
                                for sec, np in pl_keys]}
    for name, dd in dr_pos:
        ok, errs, info = conform_draft(dd, dr_policy, dr_now)
        print(f'draft/{name}: {"PASS" if ok else "FAIL"} '
              f'({"; ".join(info)})')
        for e in errs:
            print(f'    - {e}')
        dr_fails += 0 if ok else 1

    dr_neg = []
    bad_sig = json.loads(json.dumps(dr_pos[0][1]))
    bad_sig['approvals'][0]['sig'] = '00' * 128
    dr_neg.append(('tampered approval signature', bad_sig, None))
    wrong_key = json.loads(json.dumps(dr_pos[0][1]))
    s_x, np_x = _key()
    msg0 = nakama.board_decision_message(
        dr_board, dr_relay, 'admit', {'candidate': np_b}, dr_now)
    wrong_key['approvals'][0] = {
        'npub': np_a, 'sig': nakama.sign_schnorr(s_x, msg0).hex()}
    dr_neg.append(('approval sig from a different key', wrong_key, None))
    retarget = json.loads(json.dumps(dr_pos[0][1]))
    retarget['payload'] = {'candidate': np_c}
    dr_neg.append(('payload changed after signing', retarget, None))
    reboard = json.loads(json.dumps(dr_pos[0][1]))
    reboard['board_id'] = 'other-board'
    dr_neg.append(('board_id changed after signing', reboard, None))
    bad_ca = json.loads(json.dumps(dr_pos[0][1]))
    bad_ca['created_at'] = 'not-a-time'
    dr_neg.append(('created_at not an int', bad_ca, None))
    bad_dec = json.loads(json.dumps(dr_pos[0][1]))
    bad_dec['decision'] = 'delete-everything'
    dr_neg.append(('unknown decision type', bad_dec, None))
    bad_pl = json.loads(json.dumps(dr_pos[0][1]))
    bad_pl['payload'] = {'candidate': np_b, 'extra': 1}
    dr_neg.append(('payload shape invalid for decision', bad_pl, None))
    bad_npub = json.loads(json.dumps(dr_pos[0][1]))
    bad_npub['approvals'][0]['npub'] = 'npub1invalid'
    dr_neg.append(('approval with invalid npub', bad_npub, None))
    no_appr = json.loads(json.dumps(dr_pos[0][1]))
    del no_appr['approvals']
    dr_neg.append(('missing approvals', no_appr, None))
    bad_ver = json.loads(json.dumps(dr_pos[0][1]))
    bad_ver['version'] = 2
    dr_neg.append(('version != 1', bad_ver, None))
    bad_type = json.loads(json.dumps(dr_pos[0][1]))
    bad_type['type'] = 'board-policy'
    dr_neg.append(('wrong type', bad_type, None))
    bad_pol = json.loads(json.dumps(dr_pos[0][1]))
    tampered_policy = json.loads(json.dumps(dr_policy))
    tampered_policy['signatures'][0]['sig'] = '00' * 128
    dr_neg.append(('invalid policy cert given', bad_pol, tampered_policy))

    for name, dd, pol in dr_neg:
        ok, errs, info = conform_draft(dd, pol, dr_now)
        good = not ok
        print(f'draft-negative/{name}: '
              f'{"PASS (rejected)" if good else "FAIL (accepted!)"}')
        if not good:
            dr_fails += 1

    dr_total = len(dr_pos) + len(dr_neg)
    print(f'--- draft {dr_total - dr_fails}/{dr_total} passed ---')
    fails += dr_fails

    # Notif-ack DM plaintext conformance: reference acks built by
    # nakama.py's notif_ack_message must verify; malformed ones
    # must be rejected. Acceptance mirrors parse_notif_ack
    # exactly (spec §28.3): the '[nakama] notif-ack' header,
    # 'core: <hex>' (32 hex, or 64 hex normalized to its first
    # 32 — the reference normalizes both), 'reason: <vocabulary>'
    # in (expiring_soon/expired/cosign_request), the '---'
    # separator. Free text after the separator (the optional note)
    # is accepted without validation. Authorship is NOT provable
    # from the plaintext — it comes from the NIP-17 seal
    # (check_dm's territory); this checker proves format wire
    # compatibility only.
    ack_fails = 0
    CORE32 = 'ab' * 16
    ack_pos = [
        ('valid ack (no note)',
         nakama.notif_ack_message(CORE32, 'cosign_request')),
        ('valid ack with multi-line note',
         nakama.notif_ack_message(CORE32, 'expiring_soon',
                                  note='今夜 cosign します\nsecond line')),
        ('valid ack, 64-hex core (normalized to 32)',
         f'[nakama] notif-ack\ncore: {"ab" * 32}\nreason: expired\n---'),
        ('valid ack, uppercase core hex',
         nakama.notif_ack_message(CORE32.upper(), 'cosign_request')),
    ]
    for name, content in ack_pos:
        ok, errs, info = conform_notif_ack(content)
        print(f'ack/{name}: {"PASS" if ok else "FAIL"} '
              f'({"; ".join(info)})')
        for e in errs:
            print(f'    - {e}')
        ack_fails += 0 if ok else 1

    ack_neg = []
    valid_ack = nakama.notif_ack_message(CORE32, 'cosign_request')
    ack_neg.append(('wrong header',
                    valid_ack.replace('[nakama] notif-ack',
                                      '[nakama] notif')))
    _l = valid_ack.split('\n')
    _bad = _l.copy()
    _bad[1] = 'core: ' + 'zz' * 16
    ack_neg.append(('core not hex', '\n'.join(_bad)))
    _bad = _l.copy()
    _bad[1] = 'core: ' + 'ab' * 15 + 'a'
    ack_neg.append(('core 31 hex chars (not 32/64)', '\n'.join(_bad)))
    _bad = _l.copy()
    _bad[2] = 'reason: read_it'
    ack_neg.append(('reason outside vocabulary', '\n'.join(_bad)))
    _bad = _l.copy()
    _bad[1] = 'Core: ' + CORE32
    ack_neg.append(('core keyword capitalized', '\n'.join(_bad)))
    _bad = _l.copy()
    _bad[2] = 'reason'
    ack_neg.append(('reason line malformed', '\n'.join(_bad)))
    ack_neg.append(('missing separator', '\n'.join(_l[:3])))
    ack_neg.append(('fewer than 4 lines',
                    '[nakama] notif-ack\ncore: ' + CORE32))
    ack_neg.append(('empty content', ''))

    for name, content in ack_neg:
        ok, errs, info = conform_notif_ack(content)
        good = not ok
        print(f'ack-negative/{name}: '
              f'{"PASS (rejected)" if good else "FAIL (accepted!)"}')
        if not good:
            ack_fails += 1

    # E2E: the real CLI (board_notif_ack, publish mocked) builds
    # an ack DM; the decrypted rumor content must pass
    # check_notif_ack, and the seal must be the ack sender's key.
    import tempfile
    from types import SimpleNamespace
    s_issuer, np_issuer = _key()
    s_me, np_me = _key()
    with tempfile.TemporaryDirectory() as tmpd:
        keyfile = f'{tmpd}/key.json'
        nakama.save_key(keyfile, s_me)
        captured = {}

        def _fake_pub(url, event, timeout=15, auth_secret=None):
            captured['wrap'] = event
            return True, ''

        real_pub = nakama.nostr_publish
        nakama.nostr_publish = _fake_pub
        try:
            args = SimpleNamespace(relay='wss://relay.test',
                                   npub=np_issuer, keyfile=keyfile,
                                   core=CORE32, reason='cosign_request',
                                   note='e2e note', auth=False,
                                   from_npub=None)
            try:
                nakama.cmd_board_notif_ack(args)
            except SystemExit as e:
                assert e.code == 0, \
                    f'cmd_board_notif_ack exited {e.code}'
        finally:
            nakama.nostr_publish = real_pub
        rumor = nakama.nip17_unwrap(captured['wrap'], s_issuer)
        if rumor['pubkey'] != nakama.hexpub_of(s_me):
            print('ack/e2e: FAIL (seal signer is not the ack sender)')
            ack_fails += 1
        else:
            p = f'{tmpd}/ack.txt'
            with open(p, 'w', encoding='utf-8') as f:
                f.write(rumor['content'])
            rc = check_notif_ack_files([p])
            print(f'ack/e2e real CLI ack DM: '
                  f'{"PASS" if rc == 0 else "FAIL"}')
            ack_fails += 0 if rc == 0 else 1

    ack_total = len(ack_pos) + len(ack_neg) + 1
    print(f'--- ack {ack_total - ack_fails}/{ack_total} passed ---')
    fails += ack_fails

    # Notif-record conformance: records written by nakama.py's
    # draft_notif_record must verify; malformed, filename-mismatched,
    # and re-scoped records must be rejected. The record proves
    # sender-side send-log wire compatibility only — whether the
    # DM arrived is NOT provable from the record (spec §25.2).
    rec_fails = 0
    rec_now = int(time.time())
    rec_core = 'ab' * 16
    rec_core2 = 'cd' * 16
    s_r, np_r = _key()
    rhex = nakama.hexpub_of(s_r)

    def _mkrec(core, reason, rhx, sender, sent_at, **kw):
        d = {'core_hash': core, 'reason': reason, 'recipient_hex': rhx,
             'sender_npub': sender, 'sent_at': sent_at,
             'gift_wrap_id': 'gw' * 16, 'rumor_id': 'rm' * 16}
        d.update(kw)
        return d

    noids = _mkrec(rec_core, 'expired', rhex, np_r, rec_now)
    del noids['gift_wrap_id']
    del noids['rumor_id']
    rec_pos = [
        ('valid publisher record',
         f'{rec_core}:expiring_soon.json',
         _mkrec(rec_core, 'expiring_soon', rhex, np_r, rec_now)),
        ('valid cosigner record',
         f'{rec_core}:cosign_request:{rhex}.json',
         _mkrec(rec_core, 'cosign_request', rhex, np_r, rec_now)),
        ('pre-§28.2 record (no delivery ids)', f'{rec_core}:expired.json',
         noids),
        ('extra fields allowed', f'{rec_core}:expired.json',
         _mkrec(rec_core, 'expired', rhex, np_r, rec_now,
                relay='wss://relay.test')),
        ('64-hex core normalized to 32', f'{rec_core}:expired.json',
         _mkrec(rec_core + rec_core, 'expired', rhex, np_r, rec_now)),
    ]
    for name, fn, rec in rec_pos:
        ok, errs, info = conform_notif_record(fn, rec)
        print(f'record/{name}: {"PASS" if ok else "FAIL"} '
              f'({"; ".join(info)})')
        for e in errs:
            print(f'    - {e}')
        rec_fails += 0 if ok else 1

    rec_neg = []
    rec_neg.append(('filename not .json',
                    'notjson.txt',
                    _mkrec(rec_core, 'expired', rhex, np_r, rec_now)))
    rec_neg.append(('filename single part', f'{rec_core}.json',
                    _mkrec(rec_core, 'expired', rhex, np_r, rec_now)))
    rec_neg.append(('filename core not hex', f'zz:expired.json',
                    _mkrec(rec_core, 'expired', rhex, np_r, rec_now)))
    rec_neg.append(('filename reason out of vocabulary',
                    f'{rec_core}:nonsense.json',
                    _mkrec(rec_core, 'expired', rhex, np_r, rec_now)))
    rec_neg.append(('filename suffix not hex',
                    f'{rec_core}:cosign_request:xyz.json',
                    _mkrec(rec_core, 'cosign_request', rhex, np_r,
                           rec_now)))
    rec_neg.append(('core_hash mismatch with filename',
                    f'{rec_core}:expired.json',
                    _mkrec(rec_core2, 'expired', rhex, np_r, rec_now)))
    rec_neg.append(('reason mismatch with filename',
                    f'{rec_core}:expired.json',
                    _mkrec(rec_core, 'expiring_soon', rhex, np_r,
                           rec_now)))
    rec_neg.append(('recipient suffix mismatch',
                    f'{rec_core}:cosign_request:{"ef" * 32}.json',
                    _mkrec(rec_core, 'cosign_request', rhex, np_r,
                           rec_now)))
    rec_neg.append(('recipient_hex not hex', f'{rec_core}:expired.json',
                    _mkrec(rec_core, 'expired', 'nope', np_r, rec_now)))
    rec_neg.append(('sender_npub invalid', f'{rec_core}:expired.json',
                    _mkrec(rec_core, 'expired', rhex, 'npub1bogus',
                           rec_now)))
    rec_neg.append(('sent_at bool', f'{rec_core}:expired.json',
                    _mkrec(rec_core, 'expired', rhex, np_r, True)))
    rec_neg.append(('sent_at not int', f'{rec_core}:expired.json',
                    _mkrec(rec_core, 'expired', rhex, np_r, 'now')))
    rec_neg.append(('gift_wrap_id not a string',
                    f'{rec_core}:expired.json',
                    _mkrec(rec_core, 'expired', rhex, np_r, rec_now,
                           gift_wrap_id=42)))
    rec_neg.append(('record not a JSON object',
                    f'{rec_core}:expired.json', ['not', 'a', 'dict']))

    for name, fn, rec in rec_neg:
        ok, errs, info = conform_notif_record(fn, rec)
        good = not ok
        print(f'record-negative/{name}: '
              f'{"PASS (rejected)" if good else "FAIL (accepted!)"}')
        if not good:
            rec_fails += 1

    # E2E: the real CLI primitive draft_notif_record writes the
    # record; the whole notif dir must pass check_notif_record_files
    # (directory expansion included). A corrupted record in the
    # same dir must be flagged while the good one still passes.
    import tempfile
    with tempfile.TemporaryDirectory() as tmpd:
        nakama.draft_notif_record(tmpd, rec_core, 'expiring_soon', rhex,
                                  np_r, rec_now, recipient_file=False,
                                  gift_wrap_id='ab' * 32,
                                  rumor_id='cd' * 32)
        nakama.draft_notif_record(tmpd, rec_core, 'cosign_request', rhex,
                                  np_r, rec_now, recipient_file=True)
        rc = check_notif_record_files([tmpd])
        print(f'record/e2e real draft_notif_record dir: '
              f'{"PASS" if rc == 0 else "FAIL"}')
        rec_fails += 0 if rc == 0 else 1
        bad = os.path.join(tmpd, f'{rec_core}:expired.json')
        with open(bad, 'w', encoding='utf-8') as f:
            f.write('{broken json')
        rc = check_notif_record_files([tmpd])
        print(f'record/e2e corrupted record flagged: '
              f'{"PASS (flagged)" if rc == 1 else "FAIL (missed!)"}')
        rec_fails += 0 if rc == 1 else 1

    # ---------- check_key_status: key_status report consistency ----------
    # Real key_status reports are produced in-process with nakama.py's own
    # cmd_key_status (throwaway keyfiles + registry + bonds) and must pass;
    # hand-mutated reports that break the grammar or the internal
    # consistency (counts, categories, verdict/threshold, migration dates,
    # exit code) must be rejected.
    ks_fails = 0
    import tempfile
    import io
    import contextlib
    from types import SimpleNamespace

    def _ks_keyfile(secret, tmpd, name):
        kf = os.path.join(tmpd, name)
        with open(kf, 'w') as f:
            json.dump({'secret_hex': secret.hex()}, f)
        os.chmod(kf, 0o600)
        return kf

    def _ks_run(npub, keyfile, registry, threshold=2, bonds=(),
                rotation=(), liveness=None, max_age=7 * 86400):
        args = SimpleNamespace(npub=npub, threshold=threshold,
                               bond=list(bonds), liveness=liveness,
                               max_age=max_age, registry=registry,
                               rotation=list(rotation), keyfile=keyfile)
        buf = io.StringIO()
        code = 0
        with contextlib.redirect_stdout(buf):
            try:
                nakama.cmd_key_status(args)
            except SystemExit as e:
                code = e.code if isinstance(e.code, int) else 1
        return buf.getvalue(), code

    def _ks_hdr(npb, n, m):
        return (f'subject: {npb[:16]}... の侵害宣言: {n} 件'
                f'（有効な宣言、撤回済み {m} 件を除く）')

    def _ks_row(npb, cat, date, wd=False, reason=None):
        s = f'  {npb[:16]}...  [{cat}] ({date})'
        if wd:
            s += '（撤回済み）'
        if reason:
            s += f'  理由: {reason}'
        return s

    ks_e2e = []
    with tempfile.TemporaryDirectory() as tmpd:
        s_me, np_me = _key()
        s_sub, np_sub = _key()
        s_sub2, np_sub2 = _key()
        s_c, np_c = _key()      # companion (直接の仲間)
        s_out, np_out = _key()  # outsider (参考情報)
        ks_now = int(time.time())
        keyfile_me = _ks_keyfile(s_me, tmpd, 'me.json')
        reg = os.path.join(tmpd, 'registry')

        rep, code = _ks_run(np_sub, keyfile_me, reg)
        ks_e2e.append(('empty registry -> no declarations', rep, code))

        bondf = os.path.join(tmpd, 'bond.json')
        with open(bondf, 'w') as f:
            json.dump({'protocol': 'nakama', 'version': 1, 'type': 'bond',
                       'companions': [np_me, np_c],
                       'created_at': ks_now - 1000, 'nonce': 'aa' * 32}, f)

        decl_c = nakama.build_compromise_declaration(
            s_c, np_sub, ks_now - 100, reason='conformance selftest')
        nakama.import_compromise_event(decl_c, reg)
        rep, code = _ks_run(np_sub, keyfile_me, reg, bonds=[bondf])
        ks_e2e.append(('one companion declaration -> below threshold',
                       rep, code))

        decl_me = nakama.build_compromise_declaration(
            s_me, np_sub, ks_now - 90, reason='self report')
        nakama.import_compromise_event(decl_me, reg)
        rep, code = _ks_run(np_sub, keyfile_me, reg, bonds=[bondf])
        ks_e2e.append(('two counted declarations -> suspected', rep, code))

        decl_o = nakama.build_compromise_declaration(s_out, np_sub,
                                                     ks_now - 80)
        nakama.import_compromise_event(decl_o, reg)
        decl_o_wd = nakama.build_compromise_declaration(
            s_out, np_sub, ks_now - 80, withdrawn=True)
        nakama.import_compromise_event(decl_o_wd, reg)
        rep, code = _ks_run(np_sub, keyfile_me, reg, bonds=[bondf])
        ks_e2e.append(('withdrawn declaration shown as 撤回済み', rep, code))

        rot = {'protocol': 'nakama', 'version': 1, 'type': 'rotation',
               'old_npub': np_sub, 'new_npub': np_sub2,
               'created_at': ks_now - 50}
        rot['old_sig'] = nakama.sign_schnorr(
            s_sub, nakama.rotation_message(np_sub, np_sub2,
                                           ks_now - 50)).hex()
        rotf = os.path.join(tmpd, 'rotation.json')
        with open(rotf, 'w') as f:
            json.dump(rot, f)
        rep, code = _ks_run(np_sub, keyfile_me, reg, bonds=[bondf],
                            rotation=[rotf])
        ks_e2e.append(('migration complete after latest declaration',
                       rep, code))

        keyfile_sub = _ks_keyfile(s_sub, tmpd, 'sub.json')
        livef = os.path.join(tmpd, 'liveness.json')
        with contextlib.redirect_stdout(io.StringIO()):
            nakama.cmd_liveness(SimpleNamespace(bond=None, out=livef,
                                                keyfile=keyfile_sub))
        rep, code = _ks_run(np_sub, keyfile_me, reg, bonds=[bondf],
                            liveness=livef)
        ks_e2e.append(('counter-evidence 反証あり', rep, code))

        rp = nakama.compromise_registry_path(
            reg, nakama.npub_to_hex(np_sub))
        with open(rp) as f:
            decls = json.load(f)
        decls.append({'protocol': 'nakama', 'version': 1,
                      'type': 'key-compromise-declaration',
                      'subject': np_sub, 'declarant': np_out,
                      'created_at': ks_now - 70, 'sig': '00' * 128})
        with open(rp, 'w') as f:
            json.dump(decls, f)
        rep, code = _ks_run(np_sub, keyfile_me, reg, bonds=[bondf])
        ks_e2e.append(('invalid declaration ignored note', rep, code))

    for name, rep, code in ks_e2e:
        ok, errs, info = conform_key_status_report(rep, code)
        print(f'key-status-e2e/{name}: {"PASS" if ok else "FAIL"} '
              f'({"; ".join(info)})')
        for e in errs:
            print(f'    - {e}')
        ks_fails += 0 if ok else 1

    # hand-crafted positives
    _, np_k1 = _key()
    _, np_k2 = _key()
    hdr_k = _ks_hdr(np_k1, 1, 0)
    row_ref = _ks_row(np_k2, '参考情報', '2026-09-30', reason='note')
    ks_pos = [
        ('below-threshold outsider verdict',
         f'{hdr_k}\n{row_ref}\n'
         f'判定: 宣言はあるが閾値未満（0 / 2）— 警告として扱ってください。\n',
         0),
        ('broken migration chain',
         f'{_ks_hdr(np_k1, 0, 0)}\n'
         f'migration: broken — チェーンが連鎖していない (link 1)\n'
         f'判定: 侵害宣言はありません。\n',
         0),
    ]
    for name, rep, code in ks_pos:
        ok, errs, info = conform_key_status_report(rep, code)
        print(f'key-status/{name}: {"PASS" if ok else "FAIL"} '
              f'({"; ".join(info)})')
        for e in errs:
            print(f'    - {e}')
        ks_fails += 0 if ok else 1

    # negatives — all must be rejected
    ks_neg = []
    ks_neg.append(('header malformed', 'subject: nope\n', 0))
    ks_neg.append(('unknown category',
                   f'{hdr_k}\n{_ks_row(np_k2, "第三者", "2026-09-30")}\n'
                   f'判定: 宣言はあるが閾値未満（0 / 2）— 警告として扱ってください。\n',
                   0))
    ks_neg.append(('row count mismatch',
                   f'{hdr_k}\n{row_ref}\n{row_ref}\n'
                   f'判定: 宣言はあるが閾値未満（0 / 2）— 警告として扱ってください。\n',
                   0))
    ks_neg.append(('withdrawn count mismatch',
                   f'{hdr_k}\n{_ks_row(np_k2, "撤回済み", "2026-09-30", wd=True)}\n'
                   f'判定: 宣言はあるが閾値未満（0 / 2）— 警告として扱ってください。\n',
                   0))
    ks_neg.append(('withdrawn row with wrong category',
                   f'{_ks_hdr(np_k1, 1, 1)}\n'
                   f'{_ks_row(np_k2, "直接の仲間", "2026-09-30", wd=True)}\n'
                   f'判定: 侵害宣言はありません。\n',
                   0))
    ks_neg.append(('撤回済み category without marker',
                   f'{hdr_k}\n{_ks_row(np_k2, "撤回済み", "2026-09-30")}\n'
                   f'判定: 宣言はあるが閾値未満（0 / 2）— 警告として扱ってください。\n',
                   0))
    ks_neg.append(('invalid date',
                   f'{hdr_k}\n{_ks_row(np_k2, "参考情報", "2026-13-40")}\n'
                   f'判定: 宣言はあるが閾値未満（0 / 2）— 警告として扱ってください。\n',
                   0))
    ks_neg.append(('suspected verdict below threshold',
                   f'{hdr_k}\n{_ks_row(np_k2, "直接の仲間", "2026-09-30")}\n'
                   f'判定: 疑わしい（compromised suspected）— bond graph 内の宣言者 1 人 ≥ 閾値 2\n',
                   1))
    ks_neg.append(('warn verdict at threshold',
                   f'{_ks_hdr(np_k1, 2, 0)}\n'
                   f'{_ks_row(np_k1, "直接の仲間", "2026-09-30")}\n'
                   f'{_ks_row(np_k2, "自分自身", "2026-09-30")}\n'
                   f'判定: 宣言はあるが閾値未満（2 / 2）— 警告として扱ってください。\n',
                   0))
    ks_neg.append(('verdict count differs from rows',
                   f'{_ks_hdr(np_k1, 2, 0)}\n'
                   f'{_ks_row(np_k1, "直接の仲間", "2026-09-30")}\n'
                   f'{_ks_row(np_k2, "自分自身", "2026-09-30")}\n'
                   f'判定: 疑わしい（compromised suspected）— bond graph 内の宣言者 3 人 ≥ 閾値 2\n',
                   1))
    ks_neg.append(('exit code mismatch on suspected',
                   f'{_ks_hdr(np_k1, 2, 0)}\n'
                   f'{_ks_row(np_k1, "直接の仲間", "2026-09-30")}\n'
                   f'{_ks_row(np_k2, "自分自身", "2026-09-30")}\n'
                   f'判定: 疑わしい（compromised suspected）— bond graph 内の宣言者 2 人 ≥ 閾値 2\n',
                   0))
    ks_neg.append(('verdict not the final line',
                   f'{_ks_hdr(np_k1, 0, 0)}\n判定: 侵害宣言はありません。\nextra line\n',
                   0))
    ks_neg.append(('missing verdict', f'{_ks_hdr(np_k1, 0, 0)}\n', 0))
    ks_neg.append(('unknown middle line',
                   f'{_ks_hdr(np_k1, 0, 0)}\nrandom garbage\n判定: 侵害宣言はありません。\n',
                   0))
    ks_neg.append(('complete migration with inverted dates',
                   f'{_ks_hdr(np_k1, 1, 0)}\n{row_ref}\n'
                   f'migration: complete ({np_k1[:12]}... -> {np_k2[:12]}...) '
                   f'— rotated at 2026-09-01, after latest declaration at '
                   f'2026-09-30 — 新鍵への有効な宣言はありません\n'
                   f'判定: 宣言はあるが閾値未満（0 / 2）— 警告として扱ってください。\n',
                   0))
    ks_neg.append(('counter-evidence without declarations',
                   f'{_ks_hdr(np_k1, 0, 0)}\n'
                   f'反証あり: subject の新しい生存証明（5 秒前）が宣言より新しい — 判断はあなたに委ねます。\n'
                   f'判定: 侵害宣言はありません。\n',
                   0))

    for name, rep, code in ks_neg:
        ok, errs, info = conform_key_status_report(rep, code)
        good = not ok
        print(f'key-status-negative/{name}: '
              f'{"PASS (rejected)" if good else "FAIL (accepted!)"}')
        if not good:
            ks_fails += 1

    ks_total = len(ks_e2e) + len(ks_pos) + len(ks_neg)
    print(f'--- key-status {ks_total - ks_fails}/{ks_total} passed ---')
    fails += ks_fails

    # ---------- check_revoke_list: revoke_list report consistency ----------
    # Real revoke_list reports are produced in-process with nakama.py's own
    # cmd_revoke / cmd_revoke_list (throwaway keyfiles + registry) and must
    # pass; hand-mutated reports that break the grammar or the header/row
    # count consistency must be rejected.
    rl_fails = 0

    def _rl_keyfile(secret, tmpd, name):
        kf = os.path.join(tmpd, name)
        with open(kf, 'w') as f:
            json.dump({'secret_hex': secret.hex()}, f)
        os.chmod(kf, 0o600)
        return kf

    def _rl_bondf(tmpd, name, companions, nonce):
        bf = os.path.join(tmpd, name)
        with open(bf, 'w') as f:
            json.dump({'protocol': 'nakama', 'version': 1, 'type': 'bond',
                       'companions': companions,
                       'created_at': int(time.time()) - 1000,
                       'nonce': nonce}, f)
        return bf

    def _rl_revoke(bondf, keyfile, reg, out, reason=''):
        with contextlib.redirect_stdout(io.StringIO()):
            nakama.cmd_revoke(SimpleNamespace(bond=bondf, keyfile=keyfile,
                                              reason=reason, registry=reg,
                                              no_registry=False, out=out))

    def _rl_list(reg):
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            nakama.cmd_revoke_list(SimpleNamespace(registry=reg))
        return buf.getvalue()

    rl_e2e = []
    with tempfile.TemporaryDirectory() as tmpd:
        s_a, np_a = _key()
        s_b, np_b = _key()
        s_c, np_c = _key()
        reg = os.path.join(tmpd, 'revocations')
        rl_e2e.append(('missing registry -> empty line', _rl_list(reg)))

        bond1 = _rl_bondf(tmpd, 'bond1.json', [np_a, np_b], 'cc' * 32)
        _rl_revoke(bond1, _rl_keyfile(s_a, tmpd, 'a.json'), reg,
                   os.path.join(tmpd, 'rev1.json'))
        rl_e2e.append(('one revocation, no reason', _rl_list(reg)))

        bond2 = _rl_bondf(tmpd, 'bond2.json', [np_b, np_c], 'dd' * 32)
        _rl_revoke(bond2, _rl_keyfile(s_b, tmpd, 'b.json'), reg,
                   os.path.join(tmpd, 'rev2.json'),
                   reason='引っ越しのため')
        rl_e2e.append(('two revocations, one with reason', _rl_list(reg)))

        # registry dir exists but holds no valid revocation -> empty line
        reg2 = os.path.join(tmpd, 'empty-reg')
        os.makedirs(reg2)
        with open(os.path.join(reg2, 'junk.txt'), 'w') as f:
            f.write('not json\n')
        rl_e2e.append(('registry with no valid revocations -> empty line',
                       _rl_list(reg2)))

    for name, rep in rl_e2e:
        ok, errs, info = conform_revoke_list_report(rep)
        print(f'revoke-list-e2e/{name}: {"PASS" if ok else "FAIL"} '
              f'({"; ".join(info)})')
        for e in errs:
            print(f'    - {e}')
        rl_fails += 0 if ok else 1

    # hand-crafted positives
    _, np_r1 = _key()
    _, np_r2 = _key()
    bh1, bh2 = 'ab' * 8, 'cd' * 8
    rl_pos = [
        ('empty report', 'revocation registry は空です\n'),
        ('two rows with reason',
         f'解消済み bond: 2 件\n'
         f'  {bh1}...  解消: {np_r1[:16]}...  (2026-09-30)  理由: test note\n'
         f'  {bh2}...  解消: {np_r2[:16]}...  (2026-10-01)\n'),
    ]
    for name, rep in rl_pos:
        ok, errs, info = conform_revoke_list_report(rep)
        print(f'revoke-list/{name}: {"PASS" if ok else "FAIL"} '
              f'({"; ".join(info)})')
        for e in errs:
            print(f'    - {e}')
        rl_fails += 0 if ok else 1

    # negatives — all must be rejected
    rl_hdr2 = ('解消済み bond: 2 件\n'
               f'  {bh1}...  解消: {np_r1[:16]}...  (2026-09-30)\n'
               f'  {bh2}...  解消: {np_r2[:16]}...  (2026-10-01)\n')
    rl_neg = []
    rl_neg.append(('header malformed', 'garbage line\n'))
    rl_neg.append(('empty report', ''))
    rl_neg.append(('empty line plus row',
                   'revocation registry は空です\n'
                   f'  {bh1}...  解消: {np_r1[:16]}...  (2026-09-30)\n'))
    rl_neg.append(('row count mismatch',
                   '解消済み bond: 2 件\n'
                   f'  {bh1}...  解消: {np_r1[:16]}...  (2026-09-30)\n'))
    rl_neg.append(('zero-row header', '解消済み bond: 0 件\n'))
    rl_neg.append(('bond prefix not hex',
                   rl_hdr2.replace(bh1, 'zz' * 8, 1)))
    rl_neg.append(('bond prefix short',
                   rl_hdr2.replace(bh1, 'ab' * 7 + 'a', 1)))
    rl_neg.append(('revoker prefix short',
                   rl_hdr2.replace(np_r1[:16], np_r1[:15], 1)))
    rl_neg.append(('invalid date',
                   rl_hdr2.replace('2026-09-30', '2026-13-40', 1)))
    rl_neg.append(('trailing garbage', rl_hdr2 + 'extra line\n'))
    rl_neg.append(('row missing ellipsis',
                   rl_hdr2.replace(f'{bh1}...', bh1, 1)))

    for name, rep in rl_neg:
        ok, errs, info = conform_revoke_list_report(rep)
        good = not ok
        print(f'revoke-list-negative/{name}: '
              f'{"PASS (rejected)" if good else "FAIL (accepted!)"}')
        if not good:
            rl_fails += 1

    rl_total = len(rl_e2e) + len(rl_pos) + len(rl_neg)
    print(f'--- revoke-list {rl_total - rl_fails}/{rl_total} passed ---')
    fails += rl_fails

    # ---------- check_notif_status: board_notif_status report consistency ----------
    # Real board_notif_status reports are produced in-process with nakama.py's
    # own draft_notif_record + cmd_board_notif_status (offline: relay=None,
    # policy=None — stderr warning, records-only display) and must pass;
    # hand-mutated reports that break the grammar or the footer/column
    # consistency must be rejected.
    import tempfile
    ns_fails = 0

    def _ns_keyfile(secret, tmpd, name):
        kf = os.path.join(tmpd, name)
        with open(kf, 'w') as f:
            json.dump({'secret_hex': secret.hex()}, f)
        os.chmod(kf, 0o600)
        return kf

    def _ns_status(notif_dir, keyfile):
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf), \
                contextlib.redirect_stderr(io.StringIO()):
            nakama.cmd_board_notif_status(SimpleNamespace(
                board_id='conformance-board', relay=None, since=None,
                limit=20, auth=False, policy=None, decisions=None,
                dir=notif_dir, keyfile=keyfile))
        return buf.getvalue()

    ns_e2e = []
    with tempfile.TemporaryDirectory() as tmpd:
        s_n, np_n = _key()
        ns_kf = _ns_keyfile(s_n, tmpd, 'n.json')
        ns_dir = os.path.join(tmpd, 'notifs')
        ns_e2e.append(('empty dir -> empty line', _ns_status(ns_dir, ns_kf)))

        s_a, _np_a = _key()
        hx_a = nakama.hexpub_of(s_a)
        c1, c2, c3 = 'ab' * 16, 'cd' * 16, 'ef' * 16
        nakama.draft_notif_record(ns_dir, c1, 'cosign_request', hx_a, np_n,
                                  now, recipient_file=True)
        ns_e2e.append(('one record', _ns_status(ns_dir, ns_kf)))

        s_b, _np_b = _key()
        hx_b = nakama.hexpub_of(s_b)
        nakama.draft_notif_record(ns_dir, c2, 'expiring_soon', hx_b, np_n,
                                  now - 3600, recipient_file=True)
        nakama.draft_notif_record(ns_dir, c3, 'expired', None, np_n,
                                  now - 7200)
        ns_e2e.append(('three records incl. issuer-style to=?',
                       _ns_status(ns_dir, ns_kf)))

    for name, rep in ns_e2e:
        ok, errs, info = conform_notif_status_report(rep)
        print(f'notif-status-e2e/{name}: {"PASS" if ok else "FAIL"} '
              f'({"; ".join(info)})')
        for e in errs:
            print(f'    - {e}')
        ns_fails += 0 if ok else 1

    # hand-crafted positives
    _, np_p1 = _key()
    _, np_p2 = _key()
    p1, p2 = 'ab' * 16, 'cd' * 16
    ns_pos = [
        ('empty report', '送信記録はありませんでした\n'),
        ('one row, sent=? ack=-',
         f'[cosign_request] {p1} to={np_p1} sent=? ack=-\n{_RE_NS_FOOTER}\n'),
        ('ack=yes + to=?',
         f'[expiring_soon] {p2} to=? sent=2026-10-01 12:00:00 UTC '
         f'ack=yes(2026-10-02 01:02:03 UTC)\n{_RE_NS_FOOTER}\n'),
        ('two rows with cosigned column',
         f'[cosign_request] {p1} to={np_p1} sent=2026-10-01 12:00:00 UTC '
         f'ack=- cosigned=yes\n'
         f'[expired] {p2} to={np_p2} sent=? ack=- cosigned=-\n'
         f'{_RE_NS_FOOTER}\n'),
    ]
    for name, rep in ns_pos:
        ok, errs, info = conform_notif_status_report(rep)
        print(f'notif-status/{name}: {"PASS" if ok else "FAIL"} '
              f'({"; ".join(info)})')
        for e in errs:
            print(f'    - {e}')
        ns_fails += 0 if ok else 1

    # negatives — all must be rejected
    ns_base = (f'[cosign_request] {p1} to={np_p1} '
               f'sent=2026-10-01 12:00:00 UTC ack=-\n{_RE_NS_FOOTER}\n')
    ns_neg = []
    ns_neg.append(('empty report', ''))
    ns_neg.append(('empty line plus row',
                   '送信記録はありませんでした\n' + ns_base))
    ns_neg.append(('footer on empty report',
                   f'送信記録はありませんでした\n{_RE_NS_FOOTER}\n'))
    ns_neg.append(('missing footer', ns_base.split('\n')[0] + '\n'))
    ns_neg.append(('reason outside vocabulary',
                   ns_base.replace('[cosign_request]', '[read_it]', 1)))
    ns_neg.append(('core not hex', ns_base.replace(p1, 'zz' * 16, 1)))
    ns_neg.append(('core short', ns_base.replace(p1, 'ab' * 15, 1)))
    ns_neg.append(('to= garbage', ns_base.replace(f'to={np_p1}', 'to=bogus',
                                                  1)))
    ns_neg.append(('invalid sent date',
                   ns_base.replace('2026-10-01 12:00:00',
                                   '2026-13-40 99:99:99', 1)))
    ns_neg.append(('invalid ack date',
                   ns_base.replace('ack=-',
                                   'ack=yes(2026-13-40 12:00:00 UTC)', 1)))
    ns_neg.append(('cosigned column mixed',
                   f'[cosign_request] {p1} to={np_p1} '
                   f'sent=2026-10-01 12:00:00 UTC ack=- cosigned=yes\n'
                   f'[expired] {p2} to={np_p2} sent=? ack=-\n'
                   f'{_RE_NS_FOOTER}\n'))
    ns_neg.append(('trailing garbage', ns_base + 'extra line\n'))

    for name, rep in ns_neg:
        ok, errs, info = conform_notif_status_report(rep)
        good = not ok
        print(f'notif-status-negative/{name}: '
              f'{"PASS (rejected)" if good else "FAIL (accepted!)"}')
        if not good:
            ns_fails += 1

    ns_total = len(ns_e2e) + len(ns_pos) + len(ns_neg)
    print(f'--- notif-status {ns_total - ns_fails}/{ns_total} passed ---')
    fails += ns_fails

    # ---------- check_dm_fetch: dm_fetch report consistency ----------
    # Reference reports are produced in-process with nakama.py's own
    # cmd_dm_fetch, with dm_incoming monkeypatched to return crafted
    # rumors (no relay contact); hand-mutated reports that break the
    # header/content grammar must be rejected.
    dmf_fails = 0

    def _dmf_keyfile(secret, tmpd, name):
        kf = os.path.join(tmpd, name)
        with open(kf, 'w') as f:
            json.dump({'secret_hex': secret.hex()}, f)
        os.chmod(kf, 0o600)
        return kf

    def _dmf_fetch(rumors, keyfile):
        orig = nakama.dm_incoming
        nakama.dm_incoming = lambda s, r, since, auth, limit=500: rumors
        try:
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf), \
                    contextlib.redirect_stderr(io.StringIO()):
                nakama.cmd_dm_fetch(SimpleNamespace(
                    relay='wss://example.invalid', since=None, auth=False,
                    limit=20, keyfile=keyfile))
            return buf.getvalue()
        finally:
            nakama.dm_incoming = orig

    dmf_e2e = []
    with tempfile.TemporaryDirectory() as tmpd:
        s_d, _np_d = _key()
        dmf_kf = _dmf_keyfile(s_d, tmpd, 'd.json')
        dmf_e2e.append(('no rumors -> empty line', _dmf_fetch([], dmf_kf)))

        s_1, _np_1 = _key()
        hx_1 = nakama.hexpub_of(s_1)
        dmf_e2e.append(('one rumor', _dmf_fetch(
            [{'pubkey': hx_1, 'created_at': 1759276800,
              'content': 'hello, nakama'}], dmf_kf)))

        s_2, _np_2 = _key()
        hx_2 = nakama.hexpub_of(s_2)
        dmf_e2e.append(('two rumors, multi-line incl. blank', _dmf_fetch(
            [{'pubkey': hx_1, 'created_at': 1759276800,
              'content': 'first'},
             {'pubkey': hx_2, 'created_at': 1759363200,
              'content': 'line one\n\nline three\n--- not a header'}],
            dmf_kf)))

    for name, rep in dmf_e2e:
        ok, errs, info = conform_dm_fetch_report(rep)
        print(f'dm-fetch-e2e/{name}: {"PASS" if ok else "FAIL"} '
              f'({"; ".join(info)})')
        for e in errs:
            print(f'    - {e}')
        dmf_fails += 0 if ok else 1

    # hand-crafted positives
    dh1 = '--- [2026-10-01 12:00:00] from ' + 'ab' * 8 + '...'
    dh2 = '--- [2026-10-02 01:02:03] from ' + 'CD' * 8 + '...'
    dmf_pos = [
        ('empty report', '新しい DM はありませんでした\n'),
        ('one block', dh1 + '\nhello\n'),
        ('multi-line incl. blank', dh1 + '\nline one\n\nline three\n'),
        ('uppercase hex sender', dh2 + '\nupper hex ok\n'),
        ('content line starting with ---', dh1 + '\n--- not a header\n'),
    ]
    for name, rep in dmf_pos:
        ok, errs, info = conform_dm_fetch_report(rep)
        print(f'dm-fetch/{name}: {"PASS" if ok else "FAIL"} '
              f'({"; ".join(info)})')
        for e in errs:
            print(f'    - {e}')
        dmf_fails += 0 if ok else 1

    # negatives — all must be rejected
    dmf_neg = []
    dmf_neg.append(('empty report', ''))
    dmf_neg.append(('empty line plus block',
                    '新しい DM はありませんでした\n' + dh1 + '\nhello\n'))
    dmf_neg.append(('invalid timestamp',
                    dh1.replace('2026-10-01 12:00:00',
                                '2026-13-40 99:99:99') + '\nhello\n'))
    dmf_neg.append(('sender not hex',
                    '--- [2026-10-01 12:00:00] from ' + 'zz' * 8 +
                    '...\nhello\n'))
    dmf_neg.append(('sender short',
                    '--- [2026-10-01 12:00:00] from ' + 'ab' * 7 +
                    '...\nhello\n'))
    dmf_neg.append(('missing ellipsis',
                    '--- [2026-10-01 12:00:00] from ' + 'ab' * 8 +
                    '\nhello\n'))
    dmf_neg.append(('empty content block', dh1 + '\n' + dh2 + '\nsecond\n'))
    dmf_neg.append(('garbage first line', 'hello\n' + dh1 + '\ncontent\n'))
    dmf_neg.append(('leading blank line', '\n' + dh1 + '\nhello\n'))

    for name, rep in dmf_neg:
        ok, errs, info = conform_dm_fetch_report(rep)
        good = not ok
        print(f'dm-fetch-negative/{name}: '
              f'{"PASS (rejected)" if good else "FAIL (accepted!)"}')
        if not good:
            dmf_fails += 1

    dmf_total = len(dmf_e2e) + len(dmf_pos) + len(dmf_neg)
    print(f'--- dm-fetch {dmf_total - dmf_fails}/{dmf_total} passed ---')
    fails += dmf_fails

    # ---------- check_dm_recv: dm_recv report consistency ----------
    # Reference reports are produced in-process with nakama.py's own
    # cmd_dm_recv (offline: real key pairs, in-process NIP-44
    # seal/gift-wrap written to a temp file, receiver keyfile on disk —
    # no relay contact); hand-mutated reports that break the sender-line
    # or decrypt-failure-line grammar must be rejected.
    dmr_fails = 0
    _dmr_s_a, _dmr_npub_a = _key()  # sender
    _dmr_s_b, _dmr_npub_b = _key()  # receiver
    _dmr_recv_hex = nakama.hexpub_of(_dmr_s_b)
    _dmr_send_hex = nakama.hexpub_of(_dmr_s_a)

    def _dmr_recv(tmpd, content, tamper=False):
        kf = os.path.join(tmpd, 'recv-key.json')
        nakama.save_key(kf, _dmr_s_b)
        seal = nakama.nip17_build_seal(_dmr_s_a, _dmr_recv_hex, content)
        wrap = nakama.nip17_build_gift_wrap(seal, _dmr_recv_hex)
        if tamper:
            wrap = json.loads(json.dumps(wrap))
            wrap['sig'] = '00' * 64
        gw = os.path.join(tmpd, 'giftwrap.json')
        with open(gw, 'w') as f:
            json.dump(wrap, f)
        buf = io.StringIO()
        code = 0
        with contextlib.redirect_stdout(buf), \
                contextlib.redirect_stderr(io.StringIO()):
            try:
                nakama.cmd_dm_recv(SimpleNamespace(giftwrap=gw,
                                                    keyfile=kf))
            except SystemExit as e:
                code = e.code if isinstance(e.code, int) else 0
        return buf.getvalue(), code

    with tempfile.TemporaryDirectory() as _dmr_tmpd:
        _dmr_e2e = []
        _rep, _code = _dmr_recv(_dmr_tmpd, 'hello, nakama')
        _dmr_e2e.append(('one-line content', _rep, _code, 0,
                         f'from {_dmr_send_hex[:16]}...:\n'
                         'hello, nakama\n'))
        _rep, _code = _dmr_recv(_dmr_tmpd,
                                'line one\n\nline three\n--- not a header')
        _dmr_e2e.append(('multi-line incl. blank', _rep, _code, 0,
                         f'from {_dmr_send_hex[:16]}...:\n'
                         'line one\n\nline three\n--- not a header\n'))
        _rep, _code = _dmr_recv(_dmr_tmpd, 'tampered', tamper=True)
        _dmr_e2e.append(('decrypt failure', _rep, _code, 1,
                         'DM の復号に失敗しました: '
                         'gift wrap の署名が無効です\n'))
    for name, rep, code, want_code, want_rep in _dmr_e2e:
        exact = (rep == want_rep) and (code == want_code)
        ok, errs, info = conform_dm_recv_report(rep)
        good = exact and ok
        print(f'dm-recv-e2e/{name}: '
              f'{"PASS" if good else "FAIL"} ({ "; ".join(info) })')
        if not good:
            if not exact:
                print(f'    - stdout/exit mismatch: {rep!r} code={code}')
            for e in errs:
                print(f'    - {e}')
            dmr_fails += 1

    # hand-crafted positives
    dh_dr = 'from ' + 'ab' * 8 + '...:'
    dh_dr_up = 'from ' + 'CD' * 8 + '...:'
    dmr_pos = [
        ('one-line content', dh_dr + '\nhello\n'),
        ('multi-line incl. blank', dh_dr + '\nline one\n\nline three\n'),
        ('uppercase hex sender', dh_dr_up + '\nupper hex ok\n'),
        ('failure line', 'DM の復号に失敗しました: '
                         'gift wrap の署名が無効です\n'),
        ('no trailing newline', dh_dr + '\nhello'),
        ('trailing blanks', dh_dr + '\nhello\n\n  \n'),
        ('empty content', dh_dr + '\n\n'),
        ('sender line + failure-line-like content', dh_dr + '\n'
         'DM の復号に失敗しました: boom\n'),
    ]
    for name, rep in dmr_pos:
        ok, errs, info = conform_dm_recv_report(rep)
        print(f'dm-recv/{name}: {"PASS" if ok else "FAIL"} '
              f'({"; ".join(info)})')
        for e in errs:
            print(f'    - {e}')
        dmr_fails += 0 if ok else 1

    # negatives — all must be rejected
    dmr_neg = []
    dmr_neg.append(('empty report', ''))
    dmr_neg.append(('garbage first line', 'hello\n' + dh_dr + '\ncontent\n'))
    dmr_neg.append(('sender not hex',
                    'from ' + 'zz' * 8 + '...:\nhello\n'))
    dmr_neg.append(('sender short',
                    'from ' + 'ab' * 7 + '...:\nhello\n'))
    dmr_neg.append(('missing ellipsis', 'from ' + 'ab' * 8 + ':\nhello\n'))
    dmr_neg.append(('missing colon', 'from ' + 'ab' * 8 + '...\nhello\n'))
    dmr_neg.append(('failure line with empty reason',
                    'DM の復号に失敗しました: \n'))
    dmr_neg.append(('failure line plus extra line',
                    'DM の復号に失敗しました: boom\nmore\n'))
    dmr_neg.append(('failure line followed by sender line',
                    'DM の復号に失敗しました: boom\n' + dh_dr + '\n'))
    dmr_neg.append(('two failure lines',
                    'DM の復号に失敗しました: a\n'
                    'DM の復号に失敗しました: b\n'))
    dmr_neg.append(('dm_fetch header line',
                    '--- [2026-10-01 12:00:00] from ' + 'ab' * 8 +
                    '...\nhello\n'))
    dmr_neg.append(('leading blank line', '\n' + dh_dr + '\nhello\n'))

    for name, rep in dmr_neg:
        ok, errs, info = conform_dm_recv_report(rep)
        good = not ok
        print(f'dm-recv-negative/{name}: '
              f'{"PASS (rejected)" if good else "FAIL (accepted!)"}')
        if not good:
            dmr_fails += 1

    dmr_total = len(_dmr_e2e) + len(dmr_pos) + len(dmr_neg)
    print(f'--- dm-recv {dmr_total - dmr_fails}/{dmr_total} passed ---')
    fails += dmr_fails

    # ---------- check_dm_send: dm_send --out report consistency ----------
    # Reference reports are produced in-process with nakama.py's own
    # cmd_dm_send (offline: real key pairs, seal/gift-wrap built in-process
    # and written to a temp --out file — no relay contact); hand-mutated
    # reports that break the single confirmation-line grammar must be
    # rejected. A real key_compromise_warnings hit is exercised to prove
    # the §14.2 stderr warnings stay separated from the stdout report.
    dms_fails = 0
    _dms_s_a, _dms_npub_a = _key()  # sender
    _dms_s_b, _dms_npub_b = _key()  # recipient

    def _dms_send(tmpd, outname, msg='hello', warn=False):
        kf = os.path.join(tmpd, 'send-key.json')
        nakama.save_key(kf, _dms_s_a)
        outp = os.path.join(tmpd, outname)
        orig_warn = nakama.key_compromise_warnings
        if warn:
            nakama.key_compromise_warnings = (
                lambda n, r=None: ['⚠ 宛先 npub に侵害宣言があります'])
        buf = io.StringIO()
        code = 0
        try:
            with contextlib.redirect_stdout(buf), \
                    contextlib.redirect_stderr(io.StringIO()):
                nakama.cmd_dm_send(SimpleNamespace(
                    npub=_dms_npub_b, message=msg, out=outp,
                    keyfile=kf, compromise_registry=tmpd))
        except SystemExit as e:
            code = e.code if isinstance(e.code, int) else 0
        finally:
            nakama.key_compromise_warnings = orig_warn
        return buf.getvalue(), code, os.path.exists(outp), outp

    _dms_e2e = []
    with tempfile.TemporaryDirectory() as _dms_tmpd:
        _rep, _code, _exists, _outp = _dms_send(_dms_tmpd, 'wrap.json')
        _dms_e2e.append(('plain --out', _rep, _code, 0, _exists,
                        f'gift wrap (kind 1059) を {_outp} に保存しました。'
                        'publish は dm_pub で実行してください。\n'))
        _rep, _code, _exists, _outp = _dms_send(_dms_tmpd, 'out 1.json')
        _dms_e2e.append(('spaces in out path', _rep, _code, 0, _exists,
                        f'gift wrap (kind 1059) を {_outp} に保存しました。'
                        'publish は dm_pub で実行してください。\n'))
        _rep, _code, _exists, _outp = _dms_send(_dms_tmpd, 'wrap2.json',
                                               warn=True)
        _dms_e2e.append(('compromised recipient (stderr separated)',
                        _rep, _code, 0, _exists,
                        f'gift wrap (kind 1059) を {_outp} に保存しました。'
                        'publish は dm_pub で実行してください。\n'))
    for name, rep, code, want_code, exists, want_rep in _dms_e2e:
        exact = (rep == want_rep) and (code == want_code) and exists
        ok, errs, info = conform_dm_send_report(rep)
        good = exact and ok
        print(f'dm-send-e2e/{name}: '
              f'{"PASS" if good else "FAIL"} ("{"; ".join(info)}")')
        if not good:
            if not exact:
                print(f'    - stdout/exit/file mismatch: {rep!r} '
                      f'code={code} exists={exists}')
            for e in errs:
                print(f'    - {e}')
            dms_fails += 1

    # hand-crafted positives
    dms_pos = [
        ('minimal', 'gift wrap (kind 1059) を wrap.json に保存しました。'
         'publish は dm_pub で実行してください。\n'),
        ('no trailing newline',
         'gift wrap (kind 1059) を wrap.json に保存しました。'
         'publish は dm_pub で実行してください。'),
        ('trailing blanks',
         'gift wrap (kind 1059) を wrap.json に保存しました。'
         'publish は dm_pub で実行してください。\n\n\n'),
        ('spaces in path',
         'gift wrap (kind 1059) を my wraps/out 1.json に保存しました。'
         'publish は dm_pub で実行してください。\n'),
        ('japanese path',
         'gift wrap (kind 1059) を 受信箱/ラップ.json に保存しました。'
         'publish は dm_pub で実行してください。\n'),
        ('absolute path',
         'gift wrap (kind 1059) を /tmp/wrap.json に保存しました。'
         'publish は dm_pub で実行してください。\n'),
    ]
    for name, rep in dms_pos:
        ok, errs, info = conform_dm_send_report(rep)
        print(f'dm-send/{name}: {"PASS" if ok else "FAIL"} '
              f'("{"; ".join(info)}")')
        for e in errs:
            print(f'    - {e}')
        dms_fails += 0 if ok else 1

    # negatives — all must be rejected
    dms_neg = []
    dms_neg.append(('empty report', ''))
    dms_neg.append(('garbage', 'hello\n'))
    dms_neg.append(('empty out',
                    'gift wrap (kind 1059) を  に保存しました。'
                    'publish は dm_pub で実行してください。\n'))
    dms_neg.append(('out with leading space',
                    'gift wrap (kind 1059) を  wrap.json に保存しました。'
                    'publish は dm_pub で実行してください。\n'))
    dms_neg.append(('stale pre-v0.73 sentence',
                    'gift wrap (kind 1059) を wrap.json に保存しました。'
                    'リレー publish は未実装（次の単位）。\n'))
    dms_neg.append(('missing publish sentence',
                    'gift wrap (kind 1059) を wrap.json に保存しました。\n'))
    dms_neg.append(('raw gift wrap JSON (no --out form)',
                    '{"id": "ab12", "kind": 1059}\n'))
    dms_neg.append(('dm_recv sender line', 'from ' + 'ab' * 8 + '...:\n'
                    'hello\n'))
    dms_neg.append(('dm_recv failure line',
                    'DM の復号に失敗しました: boom\n'))
    dms_neg.append(('leading blank line',
                    '\ngift wrap (kind 1059) を wrap.json に保存しました。'
                    'publish は dm_pub で実行してください。\n'))
    dms_neg.append(('trailing junk line',
                    'gift wrap (kind 1059) を wrap.json に保存しました。'
                    'publish は dm_pub で実行してください。\nextra\n'))
    dms_neg.append(('two reports concatenated',
                    'gift wrap (kind 1059) を a.json に保存しました。'
                    'publish は dm_pub で実行してください。\n'
                    'gift wrap (kind 1059) を b.json に保存しました。'
                    'publish は dm_pub で実行してください。\n'))
    dms_neg.append(('truncated sentence',
                    'gift wrap (kind 1059) を wrap.json に保存しました。'
                    'publish は\n'))

    for name, rep in dms_neg:
        ok, errs, info = conform_dm_send_report(rep)
        good = not ok
        print(f'dm-send-negative/{name}: '
              f'{"PASS (rejected)" if good else "FAIL (accepted!)"}')
        if not good:
            dms_fails += 1

    dms_total = len(_dms_e2e) + len(dms_pos) + len(dms_neg)
    print(f'--- dm-send {dms_total - dms_fails}/{dms_total} passed ---')
    fails += dms_fails

    # ---------- check_verify_rotation: verify_rotation report consistency --
    # Reference reports are produced in-process with nakama.py's own
    # cmd_verify_rotation (offline: real key pairs, real Schnorr-signed
    # rotation certs written to a temp file — valid, and a tampered
    # new_npub invalid case); hand-mutated reports that break the
    # single-verdict-line grammar must be rejected.
    vrt_fails = 0
    _vrt_old_s, _vrt_old_np = _key()
    _vrt_new_s, _vrt_new_np = _key()

    def _vrt_cert(tamper=False):
        created = 1759280000
        msg = nakama.rotation_message(_vrt_old_np, _vrt_new_np, created)
        cert = {
            'protocol': 'nakama', 'version': 1, 'type': 'rotation',
            'old_npub': _vrt_old_np, 'new_npub': _vrt_new_np,
            'created_at': created,
            'old_sig': nakama.sign_schnorr(_vrt_old_s, msg).hex(),
        }
        if tamper:
            cert = json.loads(json.dumps(cert))
            cert['new_npub'] = nakama.npub_of(_vrt_old_s)  # old == new
        return cert

    def _vrt_run(cert):
        with tempfile.TemporaryDirectory() as td:
            rp = os.path.join(td, 'rotation.json')
            with open(rp, 'w') as f:
                json.dump(cert, f)
            buf = io.StringIO()
            code = 0
            with contextlib.redirect_stdout(buf), \
                    contextlib.redirect_stderr(io.StringIO()):
                try:
                    nakama.cmd_verify_rotation(
                        SimpleNamespace(rotation=rp))
                except SystemExit as e:
                    code = e.code if isinstance(e.code, int) else 0
            return buf.getvalue(), code

    _vrt_e2e = []
    _rep, _code = _vrt_run(_vrt_cert())
    _vrt_e2e.append(('valid', _rep, _code, 0,
                     f'rotation は有効です: {_vrt_old_np[:16]}... → '
                     f'{_vrt_new_np[:16]}...\n'))
    _rep, _code = _vrt_run(_vrt_cert(tamper=True))
    _vrt_e2e.append(('invalid (tampered new_npub)', _rep, _code, 1,
                     'rotation は無効です\n'))
    for name, rep, code, want_code, want_rep in _vrt_e2e:
        exact = (rep == want_rep) and (code == want_code)
        ok, errs, info = conform_verify_rotation_report(rep)
        good = exact and ok
        print(f'verify-rotation-e2e/{name}: '
              f'{"PASS" if good else "FAIL"} ({ "; ".join(info) })')
        if not good:
            if not exact:
                print(f'    - stdout/exit mismatch: {rep!r} code={code}')
            for e in errs:
                print(f'    - {e}')
            vrt_fails += 1

    # hand-crafted positives
    _dh_s, _dh_np = _key()
    dh_vr = _dh_np[:16]  # real npub prefix: 16 bech32 chars
    vrt_pos = [
        ('valid line', f'rotation は有効です: {dh_vr}... → {dh_vr}...\n'),
        ('invalid line', 'rotation は無効です\n'),
        ('no trailing newline',
         f'rotation は有効です: {dh_vr}... → {dh_vr}...'),
        ('trailing blanks',
         'rotation は無効です\n\n\n'),
    ]
    for name, rep in vrt_pos:
        ok, errs, info = conform_verify_rotation_report(rep)
        print(f'verify-rotation/{name}: {"PASS" if ok else "FAIL"} '
              f'({"; ".join(info)})')
        for e in errs:
            print(f'    - {e}')
        vrt_fails += 0 if ok else 1

    # negatives — all must be rejected
    vrt_neg = []
    vrt_neg.append(('empty report', ''))
    vrt_neg.append(('garbage line', 'hello\n'))
    vrt_neg.append(('two lines', 'rotation は無効です\nrotation は無効です\n'))
    vrt_neg.append(('missing ellipsis after old prefix',
                    f'rotation は有効です: {dh_vr} → {dh_vr}...\n'))
    vrt_neg.append(('missing arrow',
                    f'rotation は有効です: {dh_vr}... {dh_vr}...\n'))
    vrt_neg.append(('short old prefix',
                    f'rotation は有効です: npub1abc... → {dh_vr}...\n'))
    vrt_neg.append(('short new prefix',
                    f'rotation は有効です: {dh_vr}... → npub1abc...\n'))
    vrt_neg.append(('space inside prefix',
                    'rotation は有効です: npub1abcd efgh... → '
                    f'{dh_vr}...\n'))
    vrt_neg.append(('invalid verdict with suffix',
                    'rotation は無効です: ほげ\n'))
    vrt_neg.append(('invalid with extra line',
                    'rotation は無効です\n' + dh_vr + '\n'))
    vrt_neg.append(('rotate issuance report (different grammar)',
                    f'rotation 証明書: rotation.json\n'
                    f'{dh_vr}... → {dh_vr}...\n注意: のこり\n'))
    vrt_neg.append(('bare arrow line (rotate second line alone)',
                    f'{dh_vr}... → {dh_vr}...\n'))
    vrt_neg.append(('leading blank line',
                    '\nrotation は無効です\n'))

    for name, rep in vrt_neg:
        ok, errs, info = conform_verify_rotation_report(rep)
        good = not ok
        print(f'verify-rotation-negative/{name}: '
              f'{"PASS (rejected)" if good else "FAIL (accepted!)"}')
        if not good:
            vrt_fails += 1

    vrt_total = len(_vrt_e2e) + len(vrt_pos) + len(vrt_neg)
    print(f'--- verify-rotation {vrt_total - vrt_fails}/{vrt_total} '
          f'passed ---')
    fails += vrt_fails

    # ---------- check_verify_revocation: verify_revocation report consistency
    # Reference reports are produced in-process with nakama.py's own
    # cmd_propose + cmd_accept (real bond) + cmd_verify_revocation
    # (offline: real key pairs + temp keyfiles, real Schnorr-signed
    # revocation events — valid, and a tampered-signature invalid case);
    # hand-mutated reports that break the single-verdict-line grammar must
    # be rejected, as must the sibling verify_rotation verdict lines and
    # the revoke issuance report.
    vrv_fails = 0
    _vrv_sa, _vrv_npa = _key()
    _vrv_sb, _vrv_npb = _key()

    def _vrv_bond(tmpd):
        # offline: real key pairs + temp keyfiles, propose -> accept -> bond
        kfa = os.path.join(tmpd, 'key_a.json')
        nakama.save_key(kfa, _vrv_sa)
        kfb = os.path.join(tmpd, 'key_b.json')
        nakama.save_key(kfb, _vrv_sb)
        ppath = os.path.join(tmpd, 'proposal.json')
        bpath = os.path.join(tmpd, 'bond.json')
        with contextlib.redirect_stdout(io.StringIO()), \
                contextlib.redirect_stderr(io.StringIO()):
            nakama.cmd_propose(SimpleNamespace(
                npub=_vrv_npb, keyfile=kfa, out=ppath,
                expires_days=30, no_expiry=False, markdown=False))
            nakama.cmd_accept(SimpleNamespace(
                proposal=ppath, from_b64=None, keyfile=kfb, out=bpath,
                markdown=False, compromise_registry=tmpd))
        with open(bpath) as f:
            return json.load(f), bpath

    def _vrv_rev(bond, tamper=False):
        bh = nakama.bond_hash(bond)
        created = 1759280000
        msg = nakama.revocation_message(bh, _vrv_npa, created)
        rev = {
            'protocol': 'nakama', 'version': 1, 'type': 'revocation',
            'bond_hash': bh, 'revoker': _vrv_npa, 'created_at': created,
            'sig': nakama.sign_schnorr(_vrv_sa, msg).hex(),
        }
        if tamper:
            sig = rev['sig']
            rev['sig'] = sig[:-1] + ('0' if sig[-1] != '0' else '1')
        return rev

    def _vrv_run(rev, bpath):
        with tempfile.TemporaryDirectory() as td:
            rp = os.path.join(td, 'revocation.json')
            with open(rp, 'w') as f:
                json.dump(rev, f)
            buf = io.StringIO()
            code = 0
            with contextlib.redirect_stdout(buf), \
                    contextlib.redirect_stderr(io.StringIO()):
                try:
                    nakama.cmd_verify_revocation(
                        SimpleNamespace(revocation=rp, bond=bpath))
                except SystemExit as e:
                    code = e.code if isinstance(e.code, int) else 0
            return buf.getvalue(), code

    _vrv_e2e = []
    with tempfile.TemporaryDirectory() as _vrv_td:
        _vrv_bond_d, _vrv_bpath = _vrv_bond(_vrv_td)
        _vrv_bh16 = nakama.bond_hash(_vrv_bond_d)[:16]
        _vrv_rev_ok = _vrv_rev(_vrv_bond_d)
        _rep, _code = _vrv_run(_vrv_rev_ok, _vrv_bpath)
        _vrv_e2e.append(('valid', _rep, _code, 0,
                         f'revocation は有効です — bond {_vrv_bh16}... は '
                         f'{_vrv_npa[:16]}... により解消されました。\n'))
        _rep, _code = _vrv_run(_vrv_rev(_vrv_bond_d, tamper=True),
                               _vrv_bpath)
        _vrv_e2e.append(('invalid (tampered sig)', _rep, _code, 1,
                         'revocation は無効です\n'))
    for name, rep, code, want_code, want_rep in _vrv_e2e:
        exact = (rep == want_rep) and (code == want_code)
        ok, errs, info = conform_verify_revocation_report(rep)
        good = exact and ok
        print(f'verify-revocation-e2e/{name}: '
              f'{"PASS" if good else "FAIL"} ({"; ".join(info)})')
        if not good:
            if not exact:
                print(f'    - stdout/exit mismatch: {rep!r} code={code}')
            for e in errs:
                print(f'    - {e}')
            vrv_fails += 1

    # hand-crafted positives
    _vrv_bh = '0123456789abcdef' * 4  # 64 lowercase hex
    _vrv_rp = _vrv_npa[:16]  # real npub prefix: 16 bech32 chars
    vrv_pos = [
        ('valid line',
         f'revocation は有効です — bond {_vrv_bh[:16]}... は '
         f'{_vrv_rp}... により解消されました。\n'),
        ('invalid line', 'revocation は無効です\n'),
        ('no trailing newline',
         f'revocation は有効です — bond {_vrv_bh[:16]}... は '
         f'{_vrv_rp}... により解消されました。'),
        ('trailing blanks', 'revocation は無効です\n\n\n'),
    ]
    for name, rep in vrv_pos:
        ok, errs, info = conform_verify_revocation_report(rep)
        print(f'verify-revocation/{name}: {"PASS" if ok else "FAIL"} '
              f'({"; ".join(info)})')
        for e in errs:
            print(f'    - {e}')
        vrv_fails += 0 if ok else 1

    # negatives — all must be rejected
    vrv_neg = []
    vrv_neg.append(('empty report', ''))
    vrv_neg.append(('garbage line', 'hello\n'))
    vrv_neg.append(('two verdict lines',
                    'revocation は無効です\nrevocation は無効です\n'))
    vrv_neg.append(('missing ellipsis after bond prefix',
                    f'revocation は有効です — bond {_vrv_bh[:16]} は '
                    f'{_vrv_rp}... により解消されました。\n'))
    vrv_neg.append(('colon instead of em dash',
                    f'revocation は有効です: bond {_vrv_bh[:16]}... は '
                    f'{_vrv_rp}... により解消されました。\n'))
    vrv_neg.append(('short bond prefix',
                    f'revocation は有効です — bond 0123456789abcde... は '
                    f'{_vrv_rp}... により解消されました。\n'))
    vrv_neg.append(('non-hex bond prefix',
                    f'revocation は有効です — bond zzzzzzzzzzzzzzzz... は '
                    f'{_vrv_rp}... により解消されました。\n'))
    vrv_neg.append(('space inside revoker prefix',
                    f'revocation は有効です — bond {_vrv_bh[:16]}... は '
                    f'npub1abcd efghijkl... により解消されました。\n'))
    vrv_neg.append(('invalid verdict with suffix',
                    'revocation は無効です: ほげ\n'))
    vrv_neg.append(('verify_rotation valid verdict (different grammar)',
                    f'rotation は有効です: {_vrv_rp}... → {_vrv_rp}...\n'))
    vrv_neg.append(('verify_rotation invalid verdict (different grammar)',
                    'rotation は無効です\n'))
    vrv_neg.append(('revoke issuance report (future checker candidate)',
                    f'revocation イベント: revocation.json — bond '
                    f'{_vrv_bh[:16]}... の解消を宣言しました。\n'))
    vrv_neg.append(('wrong verb',
                    f'revocation は成功です — bond {_vrv_bh[:16]}... は '
                    f'{_vrv_rp}... により解消されました。\n'))
    vrv_neg.append(('leading blank line',
                    '\nrevocation は無効です\n'))

    for name, rep in vrv_neg:
        ok, errs, info = conform_verify_revocation_report(rep)
        good = not ok
        print(f'verify-revocation-negative/{name}: '
              f'{"PASS (rejected)" if good else "FAIL (accepted!)"}')
        if not good:
            vrv_fails += 1

    vrv_total = len(_vrv_e2e) + len(vrv_pos) + len(vrv_neg)
    print(f'--- verify-revocation {vrv_total - vrv_fails}/{vrv_total} '
          f'passed ---')
    fails += vrv_fails

    # ---------- check_revoke: revoke issuance-report consistency
    # Reference reports are produced in-process with nakama.py's own
    # cmd_propose + cmd_accept (real bond) + cmd_revoke (offline: real
    # key pair + temp keyfile, real Schnorr-signed revocation event —
    # the plain 3-line form, the --no-registry 2-line form, a
    # spaces-in-out-name variant, and a --reason variant, each with
    # exact stdout match); hand-mutated reports that break the 2/3-line
    # grammar must be rejected, as must the verify_revocation verdict
    # lines and the sibling revoke_* reports.
    rvk_fails = 0
    _rvk_sa, _rvk_npa = _key()
    _rvk_sb, _rvk_npb = _key()

    def _rvk_bond(tmpd):
        # offline: real key pairs + temp keyfiles, propose -> accept -> bond
        kfa = os.path.join(tmpd, 'key_a.json')
        nakama.save_key(kfa, _rvk_sa)
        kfb = os.path.join(tmpd, 'key_b.json')
        nakama.save_key(kfb, _rvk_sb)
        ppath = os.path.join(tmpd, 'proposal.json')
        bpath = os.path.join(tmpd, 'bond.json')
        with contextlib.redirect_stdout(io.StringIO()), \
                contextlib.redirect_stderr(io.StringIO()):
            nakama.cmd_propose(SimpleNamespace(
                npub=_rvk_npb, keyfile=kfa, out=ppath,
                expires_days=30, no_expiry=False, markdown=False))
            nakama.cmd_accept(SimpleNamespace(
                proposal=ppath, from_b64=None, keyfile=kfb, out=bpath,
                markdown=False, compromise_registry=tmpd))
        with open(bpath) as f:
            return json.load(f), bpath

    _rvk_reminder = ('解消イベントは公開チャネルで共有してください'
                     '（仲間の公開記録に残ります）。')

    def _rvk_run(bond_d, bpath, tmpd, out_name='revocation.json',
                 no_registry=False, reason=''):
        kf = os.path.join(tmpd, 'key_revk.json')
        nakama.save_key(kf, _rvk_sa)
        op = os.path.join(tmpd, out_name)
        reg = os.path.join(tmpd, 'revocations')
        bh = nakama.bond_hash(bond_d)
        rp = os.path.join(reg, bh + '.json')
        buf = io.StringIO()
        code = 0
        with contextlib.redirect_stdout(buf), \
                contextlib.redirect_stderr(io.StringIO()):
            try:
                nakama.cmd_revoke(SimpleNamespace(
                    bond=bpath, keyfile=kf, reason=reason, out=op,
                    no_registry=no_registry, registry=reg))
            except SystemExit as e:
                code = e.code if isinstance(e.code, int) else 0
        return buf.getvalue(), code, op, rp, bh[:16]

    _rvk_e2e = []
    with tempfile.TemporaryDirectory() as _rvk_td:
        _rvk_bond_d, _rvk_bpath = _rvk_bond(_rvk_td)
        _rep, _code, _op, _rp, _bh16 = _rvk_run(_rvk_bond_d, _rvk_bpath,
                                               _rvk_td)
        _rvk_e2e.append(('plain 3-line', _rep, _code,
                         f'revocation イベント: {_op} — bond {_bh16}... '
                         f'の解消を宣言しました。\n'
                         f'ローカル registry に記録しました: {_rp}\n'
                         f'{_rvk_reminder}\n'))
        _rep, _code, _op2, _rp2, _bh16 = _rvk_run(
            _rvk_bond_d, _rvk_bpath, _rvk_td, no_registry=True)
        _rvk_e2e.append(('--no-registry 2-line', _rep, _code,
                         f'revocation イベント: {_op2} — bond {_bh16}... '
                         f'の解消を宣言しました。\n'
                         f'{_rvk_reminder}\n'))
        _rep, _code, _op3, _rp3, _bh16 = _rvk_run(
            _rvk_bond_d, _rvk_bpath, _rvk_td,
            out_name='my revocation.json')
        _rvk_e2e.append(('spaces in out name', _rep, _code,
                         f'revocation イベント: {_op3} — bond {_bh16}... '
                         f'の解消を宣言しました。\n'
                         f'ローカル registry に記録しました: {_rp3}\n'
                         f'{_rvk_reminder}\n'))
        _rep, _code, _op4, _rp4, _bh16 = _rvk_run(
            _rvk_bond_d, _rvk_bpath, _rvk_td, reason='別プロジェクトに移行')
        _rvk_e2e.append(('--reason (report unchanged)', _rep, _code,
                         f'revocation イベント: {_op4} — bond {_bh16}... '
                         f'の解消を宣言しました。\n'
                         f'ローカル registry に記録しました: {_rp4}\n'
                         f'{_rvk_reminder}\n'))
    for name, rep, code, want_rep in _rvk_e2e:
        exact = (rep == want_rep) and (code == 0)
        ok, errs, info = conform_revoke_report(rep)
        good = exact and ok
        print(f'revoke-e2e/{name}: '
              f'{"PASS" if good else "FAIL"} ({"; ".join(info)})')
        if not good:
            if not exact:
                print(f'    - stdout/exit mismatch: {rep!r} code={code}')
            for e in errs:
                print(f'    - {e}')
            rvk_fails += 1

    # hand-crafted positives
    _rvk_bh16 = '0123456789ABCDEF'  # uppercase tolerated, like v0.74
    _rvk_l1 = (f'revocation イベント: revocation.json — bond {_rvk_bh16}... '
               f'の解消を宣言しました。')
    _rvk_l2 = ('ローカル registry に記録しました: '
               '/tmp/revocations/0123456789abcdef.json')
    rvk_pos = [
        ('plain 3-line', f'{_rvk_l1}\n{_rvk_l2}\n{_rvk_reminder}\n'),
        ('no-registry 2-line', f'{_rvk_l1}\n{_rvk_reminder}\n'),
        ('no trailing newline', f'{_rvk_l1}\n{_rvk_reminder}'),
        ('trailing blanks', f'{_rvk_l1}\n{_rvk_l2}\n{_rvk_reminder}\n\n\n'),
    ]
    for name, rep in rvk_pos:
        ok, errs, info = conform_revoke_report(rep)
        print(f'revoke/{name}: {"PASS" if ok else "FAIL"} '
              f'({"; ".join(info)})')
        for e in errs:
            print(f'    - {e}')
        rvk_fails += 0 if ok else 1

    # negatives — all must be rejected
    rvk_neg = []
    rvk_neg.append(('empty report', ''))
    rvk_neg.append(('garbage line', 'hello\n'))
    rvk_neg.append(('line 1 only (missing reminder)',
                    f'{_rvk_l1}\n'))
    rvk_neg.append(('four lines (extra tail)',
                    f'{_rvk_l1}\n{_rvk_l2}\n{_rvk_reminder}\n余計な行\n'))
    rvk_neg.append(('swapped order (reminder first)',
                    f'{_rvk_reminder}\n{_rvk_l1}\n{_rvk_l2}\n'))
    rvk_neg.append(('missing ellipsis after bond prefix',
                    'revocation イベント: revocation.json — bond '
                    f'{_rvk_bh16} の解消を宣言しました。\n{_rvk_reminder}\n'))
    rvk_neg.append(('colon instead of em dash',
                    'revocation イベント: revocation.json: bond '
                    f'{_rvk_bh16}... の解消を宣言しました。\n'
                    f'{_rvk_reminder}\n'))
    rvk_neg.append(('short bond prefix',
                    'revocation イベント: revocation.json — bond '
                    '0123456789abcde... の解消を宣言しました。\n'
                    f'{_rvk_reminder}\n'))
    rvk_neg.append(('non-hex bond prefix',
                    'revocation イベント: revocation.json — bond '
                    'zzzzzzzzzzzzzzzz... の解消を宣言しました。\n'
                    f'{_rvk_reminder}\n'))
    rvk_neg.append(('blank out',
                    'revocation イベント:  — bond '
                    f'{_rvk_bh16}... の解消を宣言しました。\n'
                    f'{_rvk_reminder}\n'))
    rvk_neg.append(('out with trailing whitespace',
                    'revocation イベント: revocation.json  — bond '
                    f'{_rvk_bh16}... の解消を宣言しました。\n'
                    f'{_rvk_reminder}\n'))
    rvk_neg.append(('registry line with empty rp',
                    f'{_rvk_l1}\n'
                    'ローカル registry に記録しました:\n'
                    f'{_rvk_reminder}\n'))
    rvk_neg.append(('registry line with whitespace-padded rp',
                    f'{_rvk_l1}\n'
                    'ローカル registry に記録しました:  /tmp/x.json \n'
                    f'{_rvk_reminder}\n'))
    rvk_neg.append(('reminder line with suffix',
                    f'{_rvk_l1}\n{_rvk_reminder}ほげ\n'))
    rvk_neg.append(('verify_revocation valid verdict',
                    'revocation は有効です — bond 0123456789abcdef... は '
                    'npub1abcd1234efgh... により解消されました。\n'))
    rvk_neg.append(('verify_revocation invalid verdict',
                    'revocation は無効です\n'))
    rvk_neg.append(('revoke_import stored one-liner',
                    'revocation を registry に記録しました: '
                    '/tmp/revocations/0123456789abcdef.json\n'))
    rvk_neg.append(('revoke_import duplicate one-liner',
                    '既に registry に記録済みです: '
                    '/tmp/revocations/0123456789abcdef.json\n'))
    rvk_neg.append(('revoke_pub publish line',
                    'publish: 受理 (ok) id=abcdef0123456789\n'))
    rvk_neg.append(('revoke_list empty line',
                    'revocation registry は空です\n'))
    rvk_neg.append(('leading blank line',
                    f'\n{_rvk_l1}\n{_rvk_reminder}\n'))

    for name, rep in rvk_neg:
        ok, errs, info = conform_revoke_report(rep)
        good = not ok
        print(f'revoke-negative/{name}: '
              f'{"PASS (rejected)" if good else "FAIL (accepted!)"}')
        if not good:
            rvk_fails += 1

    rvk_total = len(_rvk_e2e) + len(rvk_pos) + len(rvk_neg)
    print(f'--- revoke {rvk_total - rvk_fails}/{rvk_total} passed ---')
    fails += rvk_fails

    # ---------- check_revoke_import: revoke_import report consistency
    # The reference CLI prints one of two single-line reports to stdout
    # (exit 0): `revocation を registry に記録しました: <path>` (stored) or
    # `既に registry に記録済みです: <path>` (duplicate), where <path> is
    # `<registry>/<bond_hash>.json`. Real-CLI in-process E2E below:
    # cmd_revoke (real bond via cmd_propose+cmd_accept, real Schnorr-signed
    # revocation) -> cmd_revoke_import, stdout captured exactly.
    rvi_fails = 0
    import tempfile as _rvi_tf
    import io as _rvi_io
    import contextlib as _rvi_ctx
    from types import SimpleNamespace as _rvi_NS

    _rvi_sa, _rvi_npa = _key()
    _rvi_sb, _rvi_npb = _key()

    def _rvi_setup(tmpd):
        kfa = os.path.join(tmpd, 'key_a.json')
        nakama.save_key(kfa, _rvi_sa)
        kfb = os.path.join(tmpd, 'key_b.json')
        nakama.save_key(kfb, _rvi_sb)
        ppath = os.path.join(tmpd, 'proposal.json')
        bpath = os.path.join(tmpd, 'bond.json')
        with _rvi_ctx.redirect_stdout(_rvi_io.StringIO()), \
                _rvi_ctx.redirect_stderr(_rvi_io.StringIO()):
            nakama.cmd_propose(_rvi_NS(
                npub=_rvi_npb, keyfile=kfa, out=ppath,
                expires_days=30, no_expiry=False, markdown=False))
            nakama.cmd_accept(_rvi_NS(
                proposal=ppath, from_b64=None, keyfile=kfb, out=bpath,
                markdown=False, compromise_registry=tmpd))
        return bpath

    def _rvi_make_revocation(bpath, tmpd):
        # issue one real revocation through cmd_revoke (no registry write)
        rpath = os.path.join(tmpd, 'revocation.json')
        kf = os.path.join(tmpd, 'key_revk.json')
        nakama.save_key(kf, _rvi_sa)
        with _rvi_ctx.redirect_stdout(_rvi_io.StringIO()), \
                _rvi_ctx.redirect_stderr(_rvi_io.StringIO()):
            nakama.cmd_revoke(_rvi_NS(
                bond=bpath, keyfile=kf, reason='', out=rpath,
                no_registry=True, registry=None))
        return rpath

    def _rvi_import(rpath, tmpd, registry=None):
        buf = _rvi_io.StringIO()
        err = _rvi_io.StringIO()
        code = 0
        with _rvi_ctx.redirect_stdout(buf), _rvi_ctx.redirect_stderr(err):
            try:
                nakama.cmd_revoke_import(_rvi_NS(
                    revocation=rpath, bond=None,
                    registry=registry or os.path.join(tmpd, 'revocations')))
            except SystemExit as e:
                code = e.code if isinstance(e.code, int) else 0
        return buf.getvalue(), err.getvalue(), code

    _rvi_e2e = []
    with _rvi_tf.TemporaryDirectory() as _rvi_td:
        _rvi_bpath = _rvi_setup(_rvi_td)
        with open(_rvi_bpath) as f:
            _rvi_bh = nakama.bond_hash(json.load(f))
        _rvi_rpath = _rvi_make_revocation(_rvi_bpath, _rvi_td)
        _rvi_reg = os.path.join(_rvi_td, 'revocations')
        _rvi_rp = os.path.join(_rvi_reg, _rvi_bh + '.json')
        _rep, _err, _code = _rvi_import(_rvi_rpath, _rvi_td)
        _rvi_e2e.append(('stored (fresh registry)', _rep, _err, _code,
                         f'revocation を registry に記録しました: '
                         f'{_rvi_rp}\n'))
        _rep, _err, _code = _rvi_import(_rvi_rpath, _rvi_td)
        _rvi_e2e.append(('duplicate (second import)', _rep, _err, _code,
                         f'既に registry に記録済みです: {_rvi_rp}\n'))
        _rvi_reg2 = os.path.join(_rvi_td, 'other registry')
        _rvi_rp2 = os.path.join(_rvi_reg2, _rvi_bh + '.json')
        _rep, _err, _code = _rvi_import(_rvi_rpath, _rvi_td,
                                        registry=_rvi_reg2)
        _rvi_e2e.append(('stored (custom --registry with space)', _rep,
                         _err, _code,
                         f'revocation を registry に記録しました: '
                         f'{_rvi_rp2}\n'))
        # tampered signature: stderr verdict + exit 1, empty stdout
        with open(_rvi_rpath) as f:
            _rvi_r = json.load(f)
        _rvi_r['sig'] = ('00' if _rvi_r['sig'][:2] != '00' else 'ff') \
            + _rvi_r['sig'][2:]
        _rvi_bad = os.path.join(_rvi_td, 'revocation-bad.json')
        with open(_rvi_bad, 'w') as f:
            json.dump(_rvi_r, f)
        _rep, _err, _code = _rvi_import(_rvi_bad, _rvi_td)
        _rvi_e2e.append(('invalid sig (stderr verdict, exit 1)', _rep,
                         _err, _code, None))
    for name, rep, err, code, want_rep in _rvi_e2e:
        if want_rep is None:
            # invalid case: stdout must be empty, exit 1, stderr the
            # refusal verdict — and the empty stdout is rejected by the
            # checker (the invalid case has no report)
            good = (rep == '') and (code == 1) and \
                (err == 'revocation は無効です（registry には記録しません）\n') and \
                not conform_revoke_import_report(rep)[0]
            info = ['invalid import refused on stderr (no stdout report)']
        else:
            exact = (rep == want_rep) and (code == 0) and (err == '')
            ok, errs, info = conform_revoke_import_report(rep)
            good = exact and ok
        print(f'revoke-import-e2e/{name}: '
              f'{"PASS" if good else "FAIL"} ({"; ".join(info)})')
        if not good:
            if want_rep is not None and rep != want_rep:
                print(f'    - stdout/exit mismatch: {rep!r} code={code} '
                      f'stderr={err!r}')
            if want_rep is None:
                print(f'    - got stdout={rep!r} code={code} stderr={err!r}')
            for e in (errs if want_rep is not None else []):
                print(f'    - {e}')
            rvi_fails += 1

    # hand-crafted positives
    _rvi_bh = 'ab' * 32  # 64 lowercase hex
    _rvi_BH = 'AB' * 32  # uppercase tolerated, as with §12.5/§12.6
    _rvi_l1 = f'revocation を registry に記録しました: /tmp/r/{_rvi_bh}.json'
    _rvi_l2 = f'既に registry に記録済みです: /tmp/r/{_rvi_BH}.json'
    rvi_pos = [
        ('stored', f'{_rvi_l1}\n'),
        ('duplicate', f'{_rvi_l2}\n'),
        ('uppercase hex basename', f'{_rvi_l2}\n'),
        ('no trailing newline', _rvi_l1),
        ('trailing blanks', f'{_rvi_l1}\n\n\n'),
        ('relative registry dir', f'revocation を registry に記録しました: '
                                 f'revocations/{_rvi_bh}.json\n'),
        ('spaces in registry dir', f'revocation を registry に記録しました: '
                                   f'/tmp/my revocations/{_rvi_bh}.json\n'),
    ]
    for name, rep in rvi_pos:
        ok, errs, info = conform_revoke_import_report(rep)
        print(f'revoke-import/{name}: {"PASS" if ok else "FAIL"} '
              f'({"; ".join(info)})')
        for e in errs:
            print(f'    - {e}')
        rvi_fails += 0 if ok else 1

    # hand-crafted negatives
    rvi_neg = []
    rvi_neg.append(('empty report', ''))
    rvi_neg.append(('garbage line', 'hello\n'))
    rvi_neg.append(('two reports concatenated',
                    f'{_rvi_l1}\n{_rvi_l2}\n'))
    rvi_neg.append(('extra line after report',
                    f'{_rvi_l1}\n取り込み: 余計な行\n'))
    rvi_neg.append(('missing colon separator',
                    f'revocation を registry に記録しました /tmp/r/{_rvi_bh}.json\n'))
    rvi_neg.append(('wrong verb (保存しました)',
                    f'revocation を registry に保存しました: /tmp/r/{_rvi_bh}.json\n'))
    rvi_neg.append(('wrong duplicate verb (既に…記録しました)',
                    f'既に registry に記録しました: /tmp/r/{_rvi_bh}.json\n'))
    rvi_neg.append(('empty path', 'revocation を registry に記録しました: \n'))
    rvi_neg.append(('leading whitespace in path',
                    f'revocation を registry に記録しました:  /tmp/r/{_rvi_bh}.json\n'))
    rvi_neg.append(('trailing whitespace in path',
                    f'revocation を registry に記録しました: /tmp/r/{_rvi_bh}.json \n'))
    rvi_neg.append(('short bond_hash basename',
                    'revocation を registry に記録しました: /tmp/r/ab12.json\n'))
    rvi_neg.append(('non-hex bond_hash basename',
                    'revocation を registry に記録しました: /tmp/r/' +
                    'zz' * 32 + '.json\n'))
    rvi_neg.append(('no .json extension',
                    f'revocation を registry に記録しました: /tmp/r/{_rvi_bh}\n'))
    rvi_neg.append(('revoke issuance report (sibling)',
                    f'revocation イベント: revocation.json — bond abcd1234abcd1234... '
                    f'の解消を宣言しました。\n'
                    f'ローカル registry に記録しました: /tmp/r/{_rvi_bh}.json\n'
                    f'解消イベントは公開チャネルで共有してください'
                    f'（仲間の公開記録に残ります）。\n'))
    rvi_neg.append(('verify_revocation valid verdict (sibling)',
                    f'revocation は有効です — bond abcd1234abcd1234... は '
                    f'npub1abc... により解消されました。\n'))
    rvi_neg.append(('revoke_pub publish line (sibling)',
                    'publish: 受理 (OK) id=0123456789abcdef\n'))
    rvi_neg.append(('revoke_fetch footer (sibling)',
                    '3 件のイベントを取得: 1 件を取り込み、2 件をスキップ\n'))
    rvi_neg.append(('revoke_list empty line (sibling)',
                    'revocation registry は空です\n'))
    rvi_neg.append(('leading blank line', f'\n{_rvi_l1}\n'))

    for name, rep in rvi_neg:
        ok, errs, info = conform_revoke_import_report(rep)
        good = not ok
        print(f'revoke-import-negative/{name}: '
              f'{"PASS (rejected)" if good else "FAIL (accepted!)"}')
        if not good:
            rvi_fails += 1

    rvi_total = len(_rvi_e2e) + len(rvi_pos) + len(rvi_neg)
    print(f'--- revoke-import {rvi_total - rvi_fails}/{rvi_total} passed ---')
    fails += rvi_fails

    # ---------- check_compromise_import: compromise_import report consistency
    # The reference CLI prints one of three single-line reports to stdout
    # (exit 0): `侵害宣言を registry に記録しました: <path>` (stored),
    # `既に registry に記録済みです: <path>` (duplicate), or
    # `registry を更新しました（撤回・復活）: <path>` (updated), where
    # <path> is `<registry>/<subject_hex>.json`. Real-CLI in-process E2E
    # below: in-process-signed declarations via build_compromise_declaration
    # (the same constructor cmd_compromise_declare uses) ->
    # cmd_compromise_import, stdout captured exactly. The 'updated' case
    # re-imports the same declaration with withdrawn flipped (the
    # declarant+created_at first-win rule: only the withdrawn flag change
    # is an update).
    cpi_fails = 0
    import tempfile as _cpi_tf
    import io as _cpi_io
    import contextlib as _cpi_ctx
    from types import SimpleNamespace as _cpi_NS

    _cpi_sa, _cpi_npa = _key()
    _cpi_sb, _cpi_npb = _key()
    _cpi_now = int(time.time())
    _cpi_shex = nakama.npub_to_hex(_cpi_npb)

    def _cpi_import(dpath, tmpd, registry=None, subject=None):
        buf = _cpi_io.StringIO()
        err = _cpi_io.StringIO()
        code = 0
        with _cpi_ctx.redirect_stdout(buf), _cpi_ctx.redirect_stderr(err):
            try:
                nakama.cmd_compromise_import(_cpi_NS(
                    declaration=dpath, subject=subject,
                    registry=registry or os.path.join(tmpd, 'compromises')))
            except SystemExit as e:
                code = e.code if isinstance(e.code, int) else 0
        return buf.getvalue(), err.getvalue(), code

    _cpi_e2e = []
    with _cpi_tf.TemporaryDirectory() as _cpi_td:
        _cpi_d1 = nakama.build_compromise_declaration(
            _cpi_sa, _cpi_npb, _cpi_now)
        _cpi_dpath = os.path.join(_cpi_td, 'decl.json')
        with open(_cpi_dpath, 'w') as f:
            json.dump(_cpi_d1, f)
        _cpi_reg = os.path.join(_cpi_td, 'compromises')
        _cpi_rp = os.path.join(_cpi_reg, _cpi_shex + '.json')
        _rep, _err, _code = _cpi_import(_cpi_dpath, _cpi_td)
        _cpi_e2e.append(('stored (fresh registry)', _rep, _err, _code,
                         f'侵害宣言を registry に記録しました: '
                         f'{_cpi_rp}\n'))
        _rep, _err, _code = _cpi_import(_cpi_dpath, _cpi_td)
        _cpi_e2e.append(('duplicate (second import)', _rep, _err, _code,
                         f'既に registry に記録済みです: {_cpi_rp}\n'))
        # withdrawn re-issue, same declarant+created_at -> updated
        _cpi_d2 = nakama.build_compromise_declaration(
            _cpi_sa, _cpi_npb, _cpi_now, True)
        _cpi_dpath2 = os.path.join(_cpi_td, 'decl-withdrawn.json')
        with open(_cpi_dpath2, 'w') as f:
            json.dump(_cpi_d2, f)
        _rep, _err, _code = _cpi_import(_cpi_dpath2, _cpi_td)
        _cpi_e2e.append(('updated (withdrawn re-issue)', _rep, _err, _code,
                         f'registry を更新しました（撤回・復活）: '
                         f'{_cpi_rp}\n'))
        # custom --registry with a space in the dir name
        _cpi_reg2 = os.path.join(_cpi_td, 'other registry')
        _cpi_rp2 = os.path.join(_cpi_reg2, _cpi_shex + '.json')
        _rep, _err, _code = _cpi_import(_cpi_dpath2, _cpi_td,
                                        registry=_cpi_reg2)
        _cpi_e2e.append(('stored (custom --registry with space)', _rep,
                         _err, _code,
                         f'侵害宣言を registry に記録しました: '
                         f'{_cpi_rp2}\n'))
        # tampered signature: stderr verdict + exit 1, empty stdout
        _cpi_bad = dict(_cpi_d1)
        _cpi_bad['sig'] = ('00' if _cpi_d1['sig'][:2] != '00' else 'ff') \
            + _cpi_d1['sig'][2:]
        _cpi_badpath = os.path.join(_cpi_td, 'decl-bad.json')
        with open(_cpi_badpath, 'w') as f:
            json.dump(_cpi_bad, f)
        _rep, _err, _code = _cpi_import(_cpi_badpath, _cpi_td)
        _cpi_e2e.append(('invalid sig (stderr verdict, exit 1)', _rep,
                         _err, _code, None))
    for name, rep, err, code, want_rep in _cpi_e2e:
        if want_rep is None:
            # invalid case: stdout must be empty, exit 1, stderr the
            # refusal verdict — and the empty stdout is rejected by the
            # checker (the invalid case has no report)
            good = (rep == '') and (code == 1) and \
                (err == '侵害宣言は無効です（registry には記録しません）\n') and \
                not conform_compromise_import_report(rep)[0]
            info = ['invalid import refused on stderr (no stdout report)']
        else:
            exact = (rep == want_rep) and (code == 0) and (err == '')
            ok, errs, info = conform_compromise_import_report(rep)
            good = exact and ok
        print(f'compromise-import-e2e/{name}: '
              f'{"PASS" if good else "FAIL"} ("; ".join(info))')
        if not good:
            if want_rep is not None and rep != want_rep:
                print(f'    - stdout/exit mismatch: {rep!r} code={code} '
                      f'stderr={err!r}')
            if want_rep is None:
                print(f'    - got stdout={rep!r} code={code} stderr={err!r}')
            for e in (errs if want_rep is not None else []):
                print(f'    - {e}')
            cpi_fails += 1

    # hand-crafted positives
    _cpi_hx = 'cd' * 32  # 64 lowercase hex (subject x-only pubkey)
    _cpi_HX = 'CD' * 32  # uppercase tolerated, as with §12.7
    _cpi_l1 = f'侵害宣言を registry に記録しました: /tmp/c/{_cpi_hx}.json'
    _cpi_l2 = f'既に registry に記録済みです: /tmp/c/{_cpi_hx}.json'
    _cpi_l3 = f'registry を更新しました（撤回・復活）: /tmp/c/{_cpi_hx}.json'
    cpi_pos = [
        ('stored', f'{_cpi_l1}\n'),
        ('duplicate', f'{_cpi_l2}\n'),
        ('updated', f'{_cpi_l3}\n'),
        ('uppercase hex basename', f'侵害宣言を registry に記録しました: '
                                  f'/tmp/c/{_cpi_HX}.json\n'),
        ('revoke_import duplicate line (grammatically identical, accepted)',
         f'{_cpi_l2}\n'),
        ('no trailing newline', _cpi_l1),
        ('trailing blanks', f'{_cpi_l1}\n\n\n'),
        ('relative registry dir', f'侵害宣言を registry に記録しました: '
                                  f'compromises/{_cpi_hx}.json\n'),
        ('spaces in registry dir', f'侵害宣言を registry に記録しました: '
                                   f'/tmp/my compromises/{_cpi_hx}.json\n'),
    ]
    for name, rep in cpi_pos:
        ok, errs, info = conform_compromise_import_report(rep)
        print(f'compromise-import/{name}: {"PASS" if ok else "FAIL"} '
              f'({"; ".join(info)})')
        for e in errs:
            print(f'    - {e}')
        cpi_fails += 0 if ok else 1

    # hand-crafted negatives
    cpi_neg = []
    cpi_neg.append(('empty report', ''))
    cpi_neg.append(('garbage line', 'hello\n'))
    cpi_neg.append(('two reports concatenated',
                    f'{_cpi_l1}\n{_cpi_l2}\n'))
    cpi_neg.append(('extra line after report',
                    f'{_cpi_l1}\n余計な行\n'))
    cpi_neg.append(('missing colon separator',
                    f'侵害宣言を registry に記録しました /tmp/c/{_cpi_hx}.json\n'))
    cpi_neg.append(('wrong verb (保存しました)',
                    f'侵害宣言を registry に保存しました: /tmp/c/{_cpi_hx}.json\n'))
    cpi_neg.append(('wrong duplicate verb (既に…記録しました)',
                    f'既に registry に記録しました: /tmp/c/{_cpi_hx}.json\n'))
    cpi_neg.append(('wrong updated verb (撤回・復活なし)',
                    f'registry を更新しました: /tmp/c/{_cpi_hx}.json\n'))
    cpi_neg.append(('empty path', '侵害宣言を registry に記録しました: \n'))
    cpi_neg.append(('leading whitespace in path',
                    f'侵害宣言を registry に記録しました:  /tmp/c/{_cpi_hx}.json\n'))
    cpi_neg.append(('trailing whitespace in path',
                    f'侵害宣言を registry に記録しました: /tmp/c/{_cpi_hx}.json \n'))
    cpi_neg.append(('short subject basename',
                    '侵害宣言を registry に記録しました: /tmp/c/cd12.json\n'))
    cpi_neg.append(('non-hex subject basename',
                    '侵害宣言を registry に記録しました: /tmp/c/' +
                    'zz' * 32 + '.json\n'))
    cpi_neg.append(('no .json extension',
                    f'侵害宣言を registry に記録しました: /tmp/c/{_cpi_hx}\n'))
    cpi_neg.append(('revoke_import stored line (sibling, verb differs)',
                    f'revocation を registry に記録しました: '
                    f'/tmp/c/{_cpi_hx}.json\n'))
    cpi_neg.append(('compromise_declare report (sibling)',
                    f'侵害宣言: compromise.json — npub1abc... が npub1def... '
                    f'の鍵は危ないと宣言しました。\n'
                    f'ローカル registry に記録しました: /tmp/c/{_cpi_hx}.json\n'
                    f'宣言は公開チャネルで共有してください'
                    f'（仲間の公開記録に残ります）。虚偽の宣言はあなたの署名付きで'
                    f'残ることを忘れずに。\n'))
    cpi_neg.append(('compromise_withdraw report (sibling)',
                    f'侵害宣言を撤回しました: compromise_withdrawn.json'
                    f'（registry の記録を withdrawn: true に更新）\n'
                    f'公開済みの宣言は compromise_pub で上書きしてください'
                    f'（kind 30108 の replaceable で撤回が効きます）。\n'))
    cpi_neg.append(('compromise_fetch footer (sibling)',
                    '5 件のイベントを取得: 1 件を取り込み、1 件を更新、'
                    '3 件をスキップ\n'))
    cpi_neg.append(('compromise_pub publish line (sibling)',
                    'publish: 受理 (OK) id=0123456789abcdef0123456789abcdef'
                    '0123456789abcdef0123456789abcdef\n'))
    cpi_neg.append(('leading blank line', f'\n{_cpi_l1}\n'))

    for name, rep in cpi_neg:
        ok, errs, info = conform_compromise_import_report(rep)
        good = not ok
        print(f'compromise-import-negative/{name}: '
              f'{"PASS (rejected)" if good else "FAIL (accepted!)"}')
        if not good:
            cpi_fails += 1

    cpi_total = len(_cpi_e2e) + len(cpi_pos) + len(cpi_neg)
    print(f'--- compromise-import {cpi_total - cpi_fails}/{cpi_total} passed ---')
    fails += cpi_fails

    # ---------- check_compromise_declare: compromise_declare report consistency
    # The reference CLI prints a 2-3 line issuance report to stdout
    # (exit 0): line 1 `侵害宣言: <out> — <declarant16>... が
    # <subject16>... の鍵は危ないと宣言しました。`, optional line 2
    # `ローカル registry に記録しました: <path>` (fresh declare without
    # --no-registry), final line the advisory literal. Real-CLI
    # in-process E2E below: real keyfile (nakama.save_key on a _key()
    # secret, the same constructor path cmd_init uses) ->
    # cmd_compromise_declare, stdout captured exactly. Separate registry
    # dirs per case so same-second created_at dedup can never hide line 2.
    cpd_fails = 0
    import tempfile as _cpd_tf
    import io as _cpd_io
    import contextlib as _cpd_ctx
    from types import SimpleNamespace as _cpd_NS

    _cpd_sa, _cpd_npa = _key()
    _cpd_sb, _cpd_npb = _key()
    _cpd_shex = nakama.npub_to_hex(_cpd_npb)

    def _cpd_declare(keyfile, out, registry=None, no_registry=False,
                     subject=None):
        buf = _cpd_io.StringIO()
        err = _cpd_io.StringIO()
        code = 0
        with _cpd_ctx.redirect_stdout(buf), _cpd_ctx.redirect_stderr(err):
            try:
                nakama.cmd_compromise_declare(_cpd_NS(
                    keyfile=keyfile, subject=subject or _cpd_npb,
                    bond=None, reason='', evidence='', out=out,
                    no_registry=no_registry, registry=registry))
            except SystemExit as e:
                code = e.code if isinstance(e.code, int) else 0
        return buf.getvalue(), err.getvalue(), code

    _cpd_l3 = ('宣言は公開チャネルで共有してください'
               '（仲間の公開記録に残ります）。虚偽の宣言はあなたの'
               '署名付きで残ることを忘れずに。\n')

    def _cpd_l1(out):
        return (f'侵害宣言: {out} — {_cpd_npa[:16]}... が '
                f'{_cpd_npb[:16]}... の鍵は危ないと宣言しました。\n')

    def _cpd_l2(reg):
        return (f'ローカル registry に記録しました: '
                f'{os.path.join(reg, _cpd_shex + ".json")}\n')

    _cpd_e2e = []
    with _cpd_tf.TemporaryDirectory() as _cpd_td:
        _cpd_kf = os.path.join(_cpd_td, 'keyfile.json')
        nakama.save_key(_cpd_kf, _cpd_sa)
        _cpd_reg1 = os.path.join(_cpd_td, 'compromises')
        _cpd_out1 = os.path.join(_cpd_td, 'compromise.json')
        _rep, _err, _code = _cpd_declare(_cpd_kf, _cpd_out1,
                                        registry=_cpd_reg1)
        _cpd_e2e.append(('fresh declare (3 lines)', _rep, _err, _code,
                         _cpd_l1(_cpd_out1) + _cpd_l2(_cpd_reg1) +
                         _cpd_l3))
        # --no-registry: 2 lines
        _cpd_out2 = os.path.join(_cpd_td, 'compromise2.json')
        _rep, _err, _code = _cpd_declare(_cpd_kf, _cpd_out2,
                                        no_registry=True)
        _cpd_e2e.append(('--no-registry (2 lines)', _rep, _err, _code,
                         _cpd_l1(_cpd_out2) + _cpd_l3))
        # custom --registry with a space in the dir name
        _cpd_reg3 = os.path.join(_cpd_td, 'other registry')
        _cpd_out3 = os.path.join(_cpd_td, 'compromise3.json')
        _rep, _err, _code = _cpd_declare(_cpd_kf, _cpd_out3,
                                        registry=_cpd_reg3)
        _cpd_e2e.append(('custom --registry with space', _rep, _err,
                         _code,
                         _cpd_l1(_cpd_out3) + _cpd_l2(_cpd_reg3) +
                         _cpd_l3))
        # custom --out with a space in the filename
        _cpd_reg4 = os.path.join(_cpd_td, 'compromises4')
        _cpd_out4 = os.path.join(_cpd_td, 'my decl.json')
        _rep, _err, _code = _cpd_declare(_cpd_kf, _cpd_out4,
                                        registry=_cpd_reg4)
        _cpd_e2e.append(('custom --out with space', _rep, _err, _code,
                         _cpd_l1(_cpd_out4) + _cpd_l2(_cpd_reg4) +
                         _cpd_l3))
        # invalid subject: stderr refusal + exit 1, empty stdout
        _rep, _err, _code = _cpd_declare(_cpd_kf, _cpd_out1,
                                        registry=_cpd_reg1,
                                        subject='npub1bad')
        _cpd_e2e.append(('invalid subject (stderr refusal, exit 1)',
                         _rep, _err, _code, None))
    for name, rep, err, code, want_rep in _cpd_e2e:
        if want_rep is None:
            # invalid case: stdout must be empty, exit 1, stderr the
            # refusal verdict — and the empty stdout is rejected by the
            # checker (the invalid case has no report)
            good = (rep == '') and (code == 1) and \
                (err == 'subject は有効な npub ではありません\n') and \
                not conform_compromise_declare_report(rep)[0]
            info = ['invalid subject refused on stderr (no stdout report)']
        else:
            exact = (rep == want_rep) and (code == 0) and (err == '')
            ok, errs, info = conform_compromise_declare_report(rep)
            good = exact and ok
        print(f'compromise-declare-e2e/{name}: '
              f'{"PASS" if good else "FAIL"} ("; ".join(info))')
        if not good:
            if want_rep is not None and rep != want_rep:
                print(f'    - stdout/exit mismatch: {rep!r} code={code} '
                      f'stderr={err!r}')
            if want_rep is None:
                print(f'    - got stdout={rep!r} code={code} stderr={err!r}')
            for e in (errs if want_rep is not None else []):
                print(f'    - {e}')
            cpd_fails += 1

    # hand-crafted positives
    _cpd_hx = 'ab' * 32  # 64 lowercase hex (subject x-only pubkey)
    _cpd_HX = 'AB' * 32  # uppercase tolerated, as with §13.9
    _cpd_p1 = 'npub1' + 'q' * 11  # 16 chars, npub truncation
    _cpd_p2 = 'npub1' + 'r' * 11
    _cpd_d1 = (f'侵害宣言: compromise.json — {_cpd_p1}... が '
               f'{_cpd_p2}... の鍵は危ないと宣言しました。')
    _cpd_d2 = (f'ローカル registry に記録しました: '
               f'/tmp/c/{_cpd_hx}.json')
    _cpd_d3 = ('宣言は公開チャネルで共有してください'
               '（仲間の公開記録に残ります）。虚偽の宣言はあなたの'
               '署名付きで残ることを忘れずに。')
    cpd_pos = [
        ('standard 3-line', f'{_cpd_d1}\n{_cpd_d2}\n{_cpd_d3}\n'),
        ('2-line (no-registry)', f'{_cpd_d1}\n{_cpd_d3}\n'),
        ('no trailing newline', f'{_cpd_d1}\n{_cpd_d2}\n{_cpd_d3}'),
        ('trailing blanks', f'{_cpd_d1}\n{_cpd_d2}\n{_cpd_d3}\n\n\n'),
        ('uppercase hex basename',
         f'{_cpd_d1}\nローカル registry に記録しました: '
         f'/tmp/c/{_cpd_HX}.json\n{_cpd_d3}\n'),
        ('out with space',
         f'侵害宣言: /tmp/my decl.json — {_cpd_p1}... が '
         f'{_cpd_p2}... の鍵は危ないと宣言しました。\n{_cpd_d2}\n'
         f'{_cpd_d3}\n'),
        ('relative registry dir',
         f'{_cpd_d1}\nローカル registry に記録しました: '
         f'compromises/{_cpd_hx}.json\n{_cpd_d3}\n'),
        ('spaces in registry dir',
         f'{_cpd_d1}\nローカル registry に記録しました: '
         f'/tmp/my compromises/{_cpd_hx}.json\n{_cpd_d3}\n'),
        ('self-declare (declarant == subject prefix, legitimate)',
         f'侵害宣言: compromise.json — {_cpd_p1}... が '
         f'{_cpd_p1}... の鍵は危ないと宣言しました。\n{_cpd_d2}\n'
         f'{_cpd_d3}\n'),
    ]
    for name, rep in cpd_pos:
        ok, errs, info = conform_compromise_declare_report(rep)
        print(f'compromise-declare/{name}: {"PASS" if ok else "FAIL"} '
              f'({"; ".join(info)})')
        for e in errs:
            print(f'    - {e}')
        cpd_fails += 0 if ok else 1

    # hand-crafted negatives
    cpd_neg = []
    cpd_neg.append(('empty report', ''))
    cpd_neg.append(('garbage line', 'hello\n'))
    cpd_neg.append(('line 1 only', f'{_cpd_d1}\n'))
    cpd_neg.append(('four lines (extra line)',
                    f'{_cpd_d1}\n{_cpd_d2}\n{_cpd_d3}\n余計な行\n'))
    cpd_neg.append(('two reports concatenated',
                    f'{_cpd_d1}\n{_cpd_d2}\n{_cpd_d3}\n'
                    f'{_cpd_d1}\n{_cpd_d3}\n'))
    cpd_neg.append(('line 1 wrong verb (import stored line)',
                    f'侵害宣言を registry に記録しました: '
                    f'/tmp/c/{_cpd_hx}.json\n'))
    cpd_neg.append(('line 1 ASCII dashes instead of em dash',
                    f'侵害宣言: compromise.json - {_cpd_p1}... が '
                    f'{_cpd_p2}... の鍵は危ないと宣言しました。\n'
                    f'{_cpd_d3}\n'))
    cpd_neg.append(('line 1 unicode ellipsis instead of ASCII',
                    f'侵害宣言: compromise.json — {_cpd_p1}… が '
                    f'{_cpd_p2}… の鍵は危ないと宣言しました。\n'
                    f'{_cpd_d3}\n'))
    cpd_neg.append(('line 1 short declarant prefix',
                    f'侵害宣言: compromise.json — {_cpd_p1[:15]}... が '
                    f'{_cpd_p2}... の鍵は危ないと宣言しました。\n'
                    f'{_cpd_d3}\n'))
    cpd_neg.append(('line 1 prefix with space',
                    f'侵害宣言: compromise.json — npub1qq qqqqqqq... が '
                    f'{_cpd_p2}... の鍵は危ないと宣言しました。\n'
                    f'{_cpd_d3}\n'))
    cpd_neg.append(('line 1 missing final 。',
                    f'侵害宣言: compromise.json — {_cpd_p1}... が '
                    f'{_cpd_p2}... の鍵は危ないと宣言しました\n'
                    f'{_cpd_d3}\n'))
    cpd_neg.append(('line 2 import stored line (verb differs, rejected)',
                    f'{_cpd_d1}\n'
                    f'侵害宣言を registry に記録しました: '
                    f'/tmp/c/{_cpd_hx}.json\n{_cpd_d3}\n'))
    cpd_neg.append(('line 2 basename short',
                    f'{_cpd_d1}\n'
                    f'ローカル registry に記録しました: /tmp/c/ab12.json\n'
                    f'{_cpd_d3}\n'))
    cpd_neg.append(('line 2 basename non-hex',
                    f'{_cpd_d1}\n'
                    f'ローカル registry に記録しました: /tmp/c/'
                    f'{"zz" * 32}.json\n{_cpd_d3}\n'))
    cpd_neg.append(('line 2 basename missing .json',
                    f'{_cpd_d1}\n'
                    f'ローカル registry に記録しました: /tmp/c/{_cpd_hx}\n'
                    f'{_cpd_d3}\n'))
    cpd_neg.append(('advisory line missing',
                    f'{_cpd_d1}\n{_cpd_d2}\n'))
    cpd_neg.append(('advisory line ASCII parens',
                    f'{_cpd_d1}\n{_cpd_d2}\n'
                    f'宣言は公開チャネルで共有してください(仲間の公開記録に'
                    f'残ります)。虚偽の宣言はあなたの署名付きで残ることを'
                    f'忘れずに。\n'))
    cpd_neg.append(('advisory line first (order swapped)',
                    f'{_cpd_d3}\n{_cpd_d1}\n'))
    cpd_neg.append(('compromise_withdraw report (sibling)',
                    f'侵害宣言を撤回しました: compromise_withdrawn.json'
                    f'（registry の記録を withdrawn: true に更新）\n'
                    f'公開済みの宣言は compromise_pub で上書きしてください'
                    f'（kind 30108 の replaceable で撤回が効きます）。\n'))
    cpd_neg.append(('compromise_import stored line (sibling)',
                    f'侵害宣言を registry に記録しました: '
                    f'/tmp/c/{_cpd_hx}.json\n'))
    cpd_neg.append(('leading blank line', f'\n{_cpd_d1}\n{_cpd_d3}\n'))

    for name, rep in cpd_neg:
        ok, errs, info = conform_compromise_declare_report(rep)
        good = not ok
        print(f'compromise-declare-negative/{name}: '
              f'{"PASS (rejected)" if good else "FAIL (accepted!)"}')
        if not good:
            cpd_fails += 1

    cpd_total = len(_cpd_e2e) + len(cpd_pos) + len(cpd_neg)
    print(f'--- compromise-declare {cpd_total - cpd_fails}/{cpd_total} passed ---')
    fails += cpd_fails

    # ---------- check_compromise_withdraw: compromise_withdraw report consistency
    # The reference CLI prints a 2-line withdrawal report to stdout
    # (exit 0): line 1 `侵害宣言を撤回しました: <out>（registry の記録を
    # withdrawn: true に更新）`, line 2 `公開済みの宣言は compromise_pub
    # で上書きしてください（kind 30108 の replaceable で撤回が効きます）。`.
    # Real-CLI in-process E2E below: declare first (real keyfile ->
    # cmd_compromise_declare, the same declare path the v0.82 E2E
    # exercises) then cmd_compromise_withdraw, stdout captured exactly.
    # Separate registry dirs per case so same-second created_at dedup
    # can never cross-contaminate. The failure paths (already withdrawn,
    # never declared, invalid subject) print to stderr — their empty
    # stdout is rejected by the checker.
    cpw_fails = 0
    import tempfile as _cpw_tf
    import io as _cpw_io
    import contextlib as _cpw_ctx
    from types import SimpleNamespace as _cpw_NS

    _cpw_sa, _cpw_npa = _key()
    _cpw_sb, _cpw_npb = _key()
    _cpw_sc, _cpw_npc = _key()

    def _cpw_declare(keyfile, out, registry):
        buf = _cpw_io.StringIO()
        err = _cpw_io.StringIO()
        with _cpw_ctx.redirect_stdout(buf), _cpw_ctx.redirect_stderr(err):
            nakama.cmd_compromise_declare(_cpw_NS(
                keyfile=keyfile, subject=_cpw_npb,
                bond=None, reason='', evidence='', out=out,
                no_registry=False, registry=registry))
        return buf.getvalue(), err.getvalue()

    def _cpw_withdraw(keyfile, out, registry, subject):
        buf = _cpw_io.StringIO()
        err = _cpw_io.StringIO()
        code = 0
        with _cpw_ctx.redirect_stdout(buf), _cpw_ctx.redirect_stderr(err):
            try:
                nakama.cmd_compromise_withdraw(_cpw_NS(
                    keyfile=keyfile, subject=subject, out=out,
                    registry=registry))
            except SystemExit as e:
                code = e.code if isinstance(e.code, int) else 0
        return buf.getvalue(), err.getvalue(), code

    def _cpw_l1(out):
        return (f'侵害宣言を撤回しました: {out}'
                f'（registry の記録を withdrawn: true に更新）\n')

    _cpw_l2 = ('公開済みの宣言は compromise_pub で上書きしてください'
               '（kind 30108 の replaceable で撤回が効きます）。\n')

    def _cpw_no_decl_err(me16, subj16):
        return (f'あなた（{me16}...）の有効な侵害宣言が registry にありません: '
                f'{subj16}...\n')

    _cpw_e2e = []
    with _cpw_tf.TemporaryDirectory() as _cpw_td:
        _cpw_kf = os.path.join(_cpw_td, 'keyfile.json')
        nakama.save_key(_cpw_kf, _cpw_sa)
        _cpw_reg1 = os.path.join(_cpw_td, 'compromises')
        _cpw_decl1 = os.path.join(_cpw_td, 'compromise.json')
        _cpw_out1 = os.path.join(_cpw_td, 'compromise_withdrawn.json')
        _cpw_declare(_cpw_kf, _cpw_decl1, _cpw_reg1)
        _rep, _err, _code = _cpw_withdraw(_cpw_kf, _cpw_out1, _cpw_reg1,
                                         _cpw_npb)
        _cpw_e2e.append(('fresh withdraw (2 lines)', _rep, _err, _code,
                         _cpw_l1(_cpw_out1) + _cpw_l2, None))
        # custom --out with a space in the filename
        _cpw_reg2 = os.path.join(_cpw_td, 'compromises2')
        _cpw_decl2 = os.path.join(_cpw_td, 'compromise2.json')
        _cpw_out2 = os.path.join(_cpw_td, 'my withdrawal.json')
        _cpw_declare(_cpw_kf, _cpw_decl2, _cpw_reg2)
        _rep, _err, _code = _cpw_withdraw(_cpw_kf, _cpw_out2, _cpw_reg2,
                                         _cpw_npb)
        _cpw_e2e.append(('custom --out with space', _rep, _err, _code,
                         _cpw_l1(_cpw_out2) + _cpw_l2, None))
        # double withdraw: the declaration is already withdrawn, so the
        # registry has no non-withdrawn declaration of mine — stderr
        # refusal + exit 1, empty stdout rejected by the checker
        _rep, _err, _code = _cpw_withdraw(_cpw_kf, _cpw_out1, _cpw_reg1,
                                         _cpw_npb)
        _cpw_e2e.append(('double withdraw (already withdrawn)', _rep, _err,
                         _code, None,
                         _cpw_no_decl_err(_cpw_npa[:16], _cpw_npb[:16])))
        # subject never declared: same-form refusal
        _cpw_out4 = os.path.join(_cpw_td, 'withdrawn4.json')
        _rep, _err, _code = _cpw_withdraw(_cpw_kf, _cpw_out4, _cpw_reg1,
                                         _cpw_npc)
        _cpw_e2e.append(('never-declared subject (stderr refusal, exit 1)',
                         _rep, _err, _code, None,
                         _cpw_no_decl_err(_cpw_npa[:16], _cpw_npc[:16])))
        # invalid subject: stderr refusal + exit 1, empty stdout
        _rep, _err, _code = _cpw_withdraw(_cpw_kf, _cpw_out1, _cpw_reg1,
                                         'npub1bad')
        _cpw_e2e.append(('invalid subject (stderr refusal, exit 1)',
                         _rep, _err, _code, None,
                         'subject は有効な npub ではありません\n'))
    for name, rep, err, code, want_rep, want_err in _cpw_e2e:
        if want_rep is None:
            # failure path: stdout must be empty, exit 1, stderr the
            # refusal verdict — and the empty stdout is rejected by the
            # checker (the failure path has no report)
            good = (rep == '') and (code == 1) and (err == want_err) and \
                not conform_compromise_withdraw_report(rep)[0]
            info = ['failure path refused on stderr (no stdout report)']
        else:
            exact = (rep == want_rep) and (code == 0) and (err == '')
            ok, errs, info = conform_compromise_withdraw_report(rep)
            good = exact and ok
        print(f'compromise-withdraw-e2e/{name}: '
              f'{"PASS" if good else "FAIL"} ({("; ".join(info))})')
        if not good:
            if want_rep is not None and rep != want_rep:
                print(f'    - stdout/exit mismatch: {rep!r} code={code} '
                      f'stderr={err!r}')
            if want_rep is None:
                print(f'    - got stdout={rep!r} code={code} stderr={err!r}')
            for e in (errs if want_rep is not None else []):
                print(f'    - {e}')
            cpw_fails += 1

    # hand-crafted positives
    _cpw_d1 = ('侵害宣言を撤回しました: compromise_withdrawn.json'
               '（registry の記録を withdrawn: true に更新）')
    _cpw_d2 = ('公開済みの宣言は compromise_pub で上書きしてください'
               '（kind 30108 の replaceable で撤回が効きます）。')
    cpw_pos = [
        ('standard 2-line', f'{_cpw_d1}\n{_cpw_d2}\n'),
        ('no trailing newline', f'{_cpw_d1}\n{_cpw_d2}'),
        ('trailing blanks', f'{_cpw_d1}\n{_cpw_d2}\n\n\n'),
        ('out with space and unicode',
         f'侵害宣言を撤回しました: /tmp/my 撤回.json'
         f'（registry の記録を withdrawn: true に更新）\n{_cpw_d2}\n'),
        ('relative out path',
         f'侵害宣言を撤回しました: w/compromise_withdrawn.json'
         f'（registry の記録を withdrawn: true に更新）\n{_cpw_d2}\n'),
    ]
    for name, rep in cpw_pos:
        ok, errs, info = conform_compromise_withdraw_report(rep)
        print(f'compromise-withdraw/{name}: {"PASS" if ok else "FAIL"} '
              f'({"; ".join(info)})')
        for e in errs:
            print(f'    - {e}')
        cpw_fails += 0 if ok else 1

    # hand-crafted negatives
    cpw_neg = []
    cpw_neg.append(('empty report', ''))
    cpw_neg.append(('garbage line', 'hello\n'))
    cpw_neg.append(('line 1 only', f'{_cpw_d1}\n'))
    cpw_neg.append(('three lines (extra line)',
                    f'{_cpw_d1}\n{_cpw_d2}\n余計な行\n'))
    cpw_neg.append(('two reports concatenated',
                    f'{_cpw_d1}\n{_cpw_d2}\n{_cpw_d1}\n{_cpw_d2}\n'))
    cpw_neg.append(('line 1 wrong verb (declare report, sibling)',
                    f'侵害宣言: compromise.json — npub1qqqqqqqqqqq... が '
                    f'npub1rrrrrrrrrrr... の鍵は危ないと宣言しました。\n'
                    f'{_cpw_d2}\n'))
    cpw_neg.append(('line 1 import stored line (sibling)',
                    f'侵害宣言を registry に記録しました: '
                    f'/tmp/c/{"ab" * 32}.json\n'))
    cpw_neg.append(('line 1 ASCII parens instead of full-width',
                    f'侵害宣言を撤回しました: compromise_withdrawn.json'
                    f'(registry の記録を withdrawn: true に更新)\n'
                    f'{_cpw_d2}\n'))
    cpw_neg.append(('line 1 withdrawn: false instead of true',
                    f'侵害宣言を撤回しました: compromise_withdrawn.json'
                    f'（registry の記録を withdrawn: false に更新）\n'
                    f'{_cpw_d2}\n'))
    cpw_neg.append(('line 1 trailing 。 added', f'{_cpw_d1}。\n{_cpw_d2}\n'))
    cpw_neg.append(('line 1 empty <out>',
                    f'侵害宣言を撤回しました: '
                    f'（registry の記録を withdrawn: true に更新）\n'
                    f'{_cpw_d2}\n'))
    cpw_neg.append(('line 1 <out> trailing space',
                    f'侵害宣言を撤回しました: compromise_withdrawn.json '
                    f'（registry の記録を withdrawn: true に更新）\n'
                    f'{_cpw_d2}\n'))
    cpw_neg.append(('line 2 missing final 。',
                    f'{_cpw_d1}\n'
                    f'公開済みの宣言は compromise_pub で上書きしてください'
                    f'（kind 30108 の replaceable で撤回が効きます）\n'))
    cpw_neg.append(('line 2 ASCII parens',
                    f'{_cpw_d1}\n'
                    f'公開済みの宣言は compromise_pub で上書きしてください'
                    f'(kind 30108 の replaceable で撤回が効きます)。\n'))
    cpw_neg.append(('line 2 wrong kind',
                    f'{_cpw_d1}\n'
                    f'公開済みの宣言は compromise_pub で上書きしてください'
                    f'（kind 30101 の replaceable で撤回が効きます）。\n'))
    cpw_neg.append(('line 2 wrong command',
                    f'{_cpw_d1}\n'
                    f'公開済みの宣言は compromise_push で上書きしてください'
                    f'（kind 30108 の replaceable で撤回が効きます）。\n'))
    cpw_neg.append(('line order swapped', f'{_cpw_d2}\n{_cpw_d1}\n'))
    cpw_neg.append(('leading blank line', f'\n{_cpw_d1}\n{_cpw_d2}\n'))
    cpw_neg.append(('compromise_fetch footer (sibling)',
                    '5 件のイベントを取得: 1 件を取り込み、1 件を更新、'
                    '3 件をスキップ\n'))
    cpw_neg.append(('compromise_pub publish line (sibling)',
                    'publish: 受理 (OK) id='
                    + '0123456789abcdef' * 4 + '\n'))

    for name, rep in cpw_neg:
        ok, errs, info = conform_compromise_withdraw_report(rep)
        good = not ok
        print(f'compromise-withdraw-negative/{name}: '
              f'{"PASS (rejected)" if good else "FAIL (accepted!)"}')
        if not good:
            cpw_fails += 1

    cpw_total = len(_cpw_e2e) + len(cpw_pos) + len(cpw_neg)
    print(f'--- compromise-withdraw {cpw_total - cpw_fails}/{cpw_total} passed ---')
    fails += cpw_fails

    # ---------- check_rotate: rotate issuance report consistency
    # The reference CLI prints a 4-line issuance report to stdout
    # (exit 0): line 1 `rotation 証明書: <out>`, line 2
    # `<old16>... → <new16>...`, lines 3-4 the two fixed advisory
    # lines. Real-CLI in-process E2E below: real keyfile ->
    # cmd_rotate. The --gen key-generation note and the failure
    # paths print to stderr — their empty stdout is rejected by the
    # checker.
    rti_fails = 0
    import tempfile as _rti_tf
    import io as _rti_io
    import contextlib as _rti_ctx
    from types import SimpleNamespace as _rti_NS

    _rti_sa, _rti_npa = _key()
    _rti_sb, _rti_npb = _key()

    def _rti_rotate(keyfile, out, gen, to_hex, to_keyfile):
        buf = _rti_io.StringIO()
        err = _rti_io.StringIO()
        code = 0
        with _rti_ctx.redirect_stdout(buf), _rti_ctx.redirect_stderr(err):
            try:
                nakama.cmd_rotate(_rti_NS(keyfile=keyfile, out=out,
                                         gen=gen, to_hex=to_hex,
                                         to_keyfile=to_keyfile))
            except SystemExit as e:
                code = e.code if isinstance(e.code, int) else 0
        return buf.getvalue(), err.getvalue(), code

    def _rti_rep(out, old16, new16):
        return (f'rotation 証明書: {out}\n'
                f'{old16}... → {new16}...\n'
                f'注意: この証明書は「旧鍵の保有者が新鍵への移行を宣言した」'
                f'ことの証拠です。\n'
                f'継続的な鍵の保有 (custody) の証明には、都度の challenge–response '
                f'を使ってください。\n')

    def _rti_cert_ok(path):
        try:
            import json as _rti_json
            return nakama.verify_rotation_cert(
                _rti_json.load(open(path)))
        except Exception:
            return False

    _rti_e2e = []  # (name, rep, err, code, kind, want)
    with _rti_tf.TemporaryDirectory() as _rti_td:
        _rti_kf = os.path.join(_rti_td, 'keyfile.json')
        nakama.save_key(_rti_kf, _rti_sa)
        # fresh rotation via --to-hex (deterministic new key)
        _rti_out1 = os.path.join(_rti_td, 'rotation.json')
        _rep, _err, _code = _rti_rotate(_rti_kf, _rti_out1, False,
                                       _rti_sb.hex(), None)
        _rti_e2e.append(('fresh rotation (4 lines)', _rep, _err, _code,
                         'exact',
                         (_rti_rep(_rti_out1, _rti_npa[:16], _rti_npb[:16]),
                          '', _rti_cert_ok(_rti_out1))))
        # --out with a space in the filename
        _rti_out2 = os.path.join(_rti_td, 'my rotation.json')
        _rep, _err, _code = _rti_rotate(_rti_kf, _rti_out2, False,
                                       _rti_sb.hex(), None)
        _rti_e2e.append(('custom --out with space', _rep, _err, _code,
                         'exact',
                         (_rti_rep(_rti_out2, _rti_npa[:16], _rti_npb[:16]),
                          '', _rti_cert_ok(_rti_out2))))
        # --gen: new key generated (stderr note + exit 0, 4-line stdout)
        _rti_out3 = os.path.join(_rti_td, 'rotation-gen.json')
        _rti_tkf = os.path.join(_rti_td, 'new-keyfile.json')
        _rep, _err, _code = _rti_rotate(_rti_kf, _rti_out3, True, None,
                                       _rti_tkf)
        _rti_e2e.append(('--gen (new keyfile)', _rep, _err, _code, 'gen',
                         (f'新しい鍵を生成しました: {_rti_tkf}\n',
                          _rti_npa[:16], _rti_out3,
                          _rti_cert_ok(_rti_out3))))
        # failure: neither --gen nor --to-hex
        _rep, _err, _code = _rti_rotate(_rti_kf, _rti_out1, False, None,
                                       None)
        _rti_e2e.append(('no --gen/--to-hex (stderr refusal, exit 1)',
                         _rep, _err, _code, 'fail',
                         ('--gen または --to-hex HEX が必要です\n',)))
        # failure: same key
        _rep, _err, _code = _rti_rotate(_rti_kf, _rti_out1, False,
                                       _rti_sa.hex(), None)
        _rti_e2e.append(('same key (stderr refusal, exit 1)',
                         _rep, _err, _code, 'fail',
                         ('同じ鍵です。ローテーションになりません。\n',)))
    for name, rep, err, code, kind, want in _rti_e2e:
        errs = []
        if kind == 'fail':
            # failure path: stdout must be empty, exit 1, stderr the
            # refusal — and the empty stdout is rejected by the
            # checker (the failure path has no report)
            good = (rep == '') and (code == 1) and (err == want[0]) and \
                not conform_rotate_report(rep)[0]
            info = ['failure path refused on stderr (no stdout report)']
        elif kind == 'gen':
            # --gen: the new key is random, so check the stdout grammar
            # plus line 1 byte-exact and the old16 prefix; the cert
            # itself was verified inside the tempdir
            want_err, old16, cert_out, cert_ok = want
            lines = rep.splitlines()
            good = (code == 0) and (err == want_err) and len(lines) == 4 \
                and lines[0] == f'rotation 証明書: {cert_out}' \
                and lines[1].startswith(old16 + '... → ') \
                and conform_rotate_report(rep)[0] and cert_ok
            info = ['--gen stdout report valid'
                    + ('' if cert_ok else ' (cert invalid!)')]
        else:
            want_rep, want_err, cert_ok = want
            exact = (rep == want_rep) and (code == 0) and (err == want_err)
            ok, errs, info = conform_rotate_report(rep)
            good = exact and ok and cert_ok
            if exact and ok and not cert_ok:
                info = ['cert failed verify_rotation_cert']
        print(f'rotate-e2e/{name}: '
              f'{"PASS" if good else "FAIL"} ({"; ".join(info)})')
        if not good:
            print(f'    - got stdout={rep!r} code={code} stderr={err!r}')
            if kind == 'exact' and rep != want[0]:
                print(f'    - want stdout={want[0]!r}')
            for e in errs:
                print(f'    - {e}')
            rti_fails += 1

    # hand-crafted positives
    _rti_d1 = 'rotation 証明書: rotation.json'
    _rti_d2 = 'npub1qqqqqqqqqqq... → npub1rrrrrrrrrrr...'
    _rti_d3 = ('注意: この証明書は「旧鍵の保有者が新鍵への移行を宣言した」'
               'ことの証拠です。')
    _rti_d4 = ('継続的な鍵の保有 (custody) の証明には、都度の challenge–response '
               'を使ってください。')
    rti_pos = [
        ('standard 4-line',
         f'{_rti_d1}\n{_rti_d2}\n{_rti_d3}\n{_rti_d4}\n'),
        ('no trailing newline',
         f'{_rti_d1}\n{_rti_d2}\n{_rti_d3}\n{_rti_d4}'),
        ('trailing blanks',
         f'{_rti_d1}\n{_rti_d2}\n{_rti_d3}\n{_rti_d4}\n\n\n'),
        ('out with space and unicode',
         f'rotation 証明書: /tmp/my 移行.json\n{_rti_d2}\n{_rti_d3}\n'
         f'{_rti_d4}\n'),
        ('relative out path',
         f'rotation 証明書: certs/rotation.json\n{_rti_d2}\n{_rti_d3}\n'
         f'{_rti_d4}\n'),
    ]
    for name, rep in rti_pos:
        ok, errs, info = conform_rotate_report(rep)
        print(f'rotate/{name}: {"PASS" if ok else "FAIL"} '
              f'({"; ".join(info)})')
        for e in errs:
            print(f'    - {e}')
        rti_fails += 0 if ok else 1

    # hand-crafted negatives
    rti_neg = []
    rti_neg.append(('empty report', ''))
    rti_neg.append(('garbage line', 'hello\n'))
    rti_neg.append(('three lines (line 4 missing)',
                    f'{_rti_d1}\n{_rti_d2}\n{_rti_d3}\n'))
    rti_neg.append(('five lines (extra line)',
                    f'{_rti_d1}\n{_rti_d2}\n{_rti_d3}\n{_rti_d4}\n'
                    f'余計な行\n'))
    rti_neg.append(('two reports concatenated',
                    f'{_rti_d1}\n{_rti_d2}\n{_rti_d3}\n{_rti_d4}\n'
                    f'{_rti_d1}\n{_rti_d2}\n{_rti_d3}\n{_rti_d4}\n'))
    rti_neg.append(('line 1 wrong verb (revoke issuance, sibling)',
                    f'revocation イベント: revocation.json — bond '
                    f'{"ab" * 8}... の解消を宣言しました。\n'
                    f'{_rti_d2}\n{_rti_d3}\n{_rti_d4}\n'))
    rti_neg.append(('line 1 empty <out>',
                    f'rotation 証明書: \n{_rti_d2}\n{_rti_d3}\n{_rti_d4}\n'))
    rti_neg.append(('line 1 <out> trailing space',
                    f'rotation 証明書: rotation.json \n{_rti_d2}\n'
                    f'{_rti_d3}\n{_rti_d4}\n'))
    rti_neg.append(('line 2 verify_rotation valid line (sibling)',
                    f'{_rti_d1}\n'
                    f'rotation は有効です: npub1qqqqqqqqqqq... → '
                    f'npub1rrrrrrrrrrr...\n'
                    f'{_rti_d3}\n{_rti_d4}\n'))
    rti_neg.append(('line 2 ASCII arrow instead of →',
                    f'{_rti_d1}\n'
                    f'npub1qqqqqqqqqqq... -> npub1rrrrrrrrrrr...\n'
                    f'{_rti_d3}\n{_rti_d4}\n'))
    rti_neg.append(('line 2 ellipsis missing',
                    f'{_rti_d1}\n'
                    f'npub1qqqqqqqqqqq → npub1rrrrrrrrrrr\n'
                    f'{_rti_d3}\n{_rti_d4}\n'))
    rti_neg.append(('line 2 old prefix short',
                    f'{_rti_d1}\n'
                    f'npub1qqqqqqq... → npub1rrrrrrrrrrr...\n'
                    f'{_rti_d3}\n{_rti_d4}\n'))
    rti_neg.append(('line 2 prefix with space',
                    f'{_rti_d1}\n'
                    f'npub1qq qq qqqq... → npub1rrrrrrrrrrr...\n'
                    f'{_rti_d3}\n{_rti_d4}\n'))
    rti_neg.append(('line 3 ASCII quotes instead of 「」',
                    f'{_rti_d1}\n{_rti_d2}\n'
                    f'注意: この証明書は"旧鍵の保有者が新鍵への移行を宣言した"'
                    f'ことの証拠です。\n{_rti_d4}\n'))
    rti_neg.append(('line 3 missing (line 4 moved up)',
                    f'{_rti_d1}\n{_rti_d2}\n{_rti_d4}\n'))
    rti_neg.append(('line 4 ASCII hyphen in challenge-response',
                    f'{_rti_d1}\n{_rti_d2}\n{_rti_d3}\n'
                    f'継続的な鍵の保有 (custody) の証明には、都度の '
                    f'challenge-response を使ってください。\n'))
    rti_neg.append(('line 4 final 。 missing',
                    f'{_rti_d1}\n{_rti_d2}\n{_rti_d3}\n'
                    f'継続的な鍵の保有 (custody) の証明には、都度の challenge–response '
                    f'を使ってください\n'))
    rti_neg.append(('line order swapped (advisory first)',
                    f'{_rti_d3}\n{_rti_d1}\n{_rti_d2}\n{_rti_d4}\n'))
    rti_neg.append(('leading blank line',
                    f'\n{_rti_d1}\n{_rti_d2}\n{_rti_d3}\n{_rti_d4}\n'))
    rti_neg.append(('rotate_fetch listing line (sibling)',
                    f'{_rti_d1}\n'
                    f'rotation 公開: npub1qqqqqqqqqqq... → '
                    f'npub1rrrrrrrrrrr... (created_at 2026-10-02)\n'
                    f'{_rti_d3}\n{_rti_d4}\n'))
    rti_neg.append(('rotate_pub publish line (sibling)',
                    'publish: 受理 (OK) id=' + '0123456789abcdef' * 4 + '\n'))

    for name, rep in rti_neg:
        ok, errs, info = conform_rotate_report(rep)
        good = not ok
        print(f'rotate-negative/{name}: '
              f'{"PASS (rejected)" if good else "FAIL (accepted!)"}')
        if not good:
            rti_fails += 1

    rti_total = len(_rti_e2e) + len(rti_pos) + len(rti_neg)
    print(f'--- rotate {rti_total - rti_fails}/{rti_total} passed ---')
    fails += rti_fails

    # ---------- check_init: init report consistency
    # The reference CLI prints the new identity's npub to stdout, one
    # line, exit 0 (cmd_init with --from-hex for a deterministic key;
    # the keyfile is a real temp keyfile). Real-CLI in-process E2E
    # below: cmd_init -> stdout byte-compared; second cmd_init without
    # --force -> stderr refusal + exit 1 (empty stdout rejected by the
    # checker); cmd_whoami on the same keyfile -> the same npub line,
    # which check_init accepts (grammatically identical, like
    # challenge/respond).
    ini_fails = 0
    import tempfile as _ini_tf
    import io as _ini_io
    import contextlib as _ini_ctx
    from types import SimpleNamespace as _ini_NS

    def _ini_run_init(tmpd, keyfile, from_hex=None, force=False):
        buf = _ini_io.StringIO()
        err = _ini_io.StringIO()
        code = 0
        with _ini_ctx.redirect_stdout(buf), _ini_ctx.redirect_stderr(err):
            try:
                nakama.cmd_init(_ini_NS(
                    keyfile=keyfile,
                    from_hex=from_hex, force=force))
            except SystemExit as e:
                code = e.code if isinstance(e.code, int) else 0
        return buf.getvalue(), err.getvalue(), code

    def _ini_run_whoami(keyfile):
        buf = _ini_io.StringIO()
        err = _ini_io.StringIO()
        code = 0
        with _ini_ctx.redirect_stdout(buf), _ini_ctx.redirect_stderr(err):
            try:
                nakama.cmd_whoami(_ini_NS(keyfile=keyfile))
            except SystemExit as e:
                code = e.code if isinstance(e.code, int) else 0
        return buf.getvalue(), err.getvalue(), code

    _ini_e2e = []
    with _ini_tf.TemporaryDirectory() as _ini_td:
        _ini_s, _ini_np = _key()
        _ini_kf = os.path.join(_ini_td, 'identity.json')
        _rep, _err, _code = _ini_run_init(_ini_td, _ini_kf,
                                          from_hex=_ini_s.hex())
        _ini_e2e.append(('init --from-hex', _rep, _err, _code,
                         f'{_ini_np}\n'))
        _rep, _err, _code = _ini_run_init(_ini_td, _ini_kf)
        _ini_e2e.append(('init again (refused, exit 1)', _rep, _err, _code,
                         None))
        _rep, _err, _code = _ini_run_whoami(_ini_kf)
        _ini_e2e.append(('whoami (same grammar, accepted)', _rep, _err,
                         _code, f'{_ini_np}\n'))
    for name, rep, err, code, want_rep in _ini_e2e:
        if want_rep is None:
            # refusal case: stderr verdict + exit 1, empty stdout — and
            # the empty stdout is rejected by the checker (the refusal
            # has no stdout report)
            good = (rep == '') and (code == 1) and \
                (err == f'既に鍵があります: {_ini_kf}（--force で上書き）\n') and \
                not conform_init_report(rep)[0]
            info = ['refusal on stderr, no stdout report (rejected)']
        else:
            exact = (rep == want_rep) and (code == 0) and (err == '')
            ok, errs, info = conform_init_report(rep)
            good = exact and ok
        print(f'init-e2e/{name}: {"PASS" if good else "FAIL"} '
              f'({"; ".join(info)})')
        if not good:
            print(f'    - got stdout={rep!r} code={code} stderr={err!r}')
            for e in (errs if want_rep is not None else []):
                print(f'    - {e}')
            ini_fails += 1

    # hand-crafted positives
    _ini_np2 = _ini_np
    _ini_no_nl = _ini_np2
    ini_pos = [
        ('single npub line', f'{_ini_np2}\n'),
        ('no trailing newline', _ini_no_nl),
        ('trailing blanks', f'{_ini_np2}\n\n\n'),
        ('whoami-shaped report', f'{_ini_np2}\n'),
    ]
    for name, rep in ini_pos:
        ok, errs, info = conform_init_report(rep)
        print(f'init/{name}: {"PASS" if ok else "FAIL"} '
              f'({"; ".join(info)})')
        for e in errs:
            print(f'    - {e}')
        ini_fails += 0 if ok else 1

    # hand-crafted negatives
    ini_neg = [
        ('empty report', ''),
        ('garbage line', 'hello\n'),
        ('two reports concatenated', f'{_ini_np2}\n{_ini_np2}\n'),
        ('npub with trailing space', f'{_ini_np2} \n'),
        ('npub with leading space', f' {_ini_np2}\n'),
        ('npub short (62 chars)', f'{_ini_np2[:-1]}\n'),
        ('npub long (64 chars)', f'{_ini_np2}a\n'),
        ('wrong hrp (nsec)', 'nsec1' + _ini_np2[5:] + '\n'),
        ('uppercase npub (bech32 is lowercase-only)',
         _ini_np2.upper() + '\n'),
        ('non-bech32 char (o)', _ini_np2[:5] + 'o' + _ini_np2[6:] + '\n'),
        ('challenge line (sibling)', 'ab' * 32 + '\n'),
        ('check verdict (sibling)', '本人です 🤝\n'),
        ('propose report first line (sibling)',
         f'proposal を proposal.json に保存しました。相手に渡してください。\n'),
        ('publish-result line (sibling)',
         'publish: 受理 (OK) id=0123456789abcdef\n'),
        ('leading blank line', f'\n{_ini_np2}\n'),
    ]
    for name, rep in ini_neg:
        ok, errs, info = conform_init_report(rep)
        good = not ok
        print(f'init-negative/{name}: '
              f'{"PASS (rejected)" if good else "FAIL (accepted!)"}')
        if not good:
            ini_fails += 1

    ini_total = len(_ini_e2e) + len(ini_pos) + len(ini_neg)
    print(f'--- init {ini_total - ini_fails}/{ini_total} passed ---')
    fails += ini_fails

    # ---------- check_draft_notify: board_draft_notify report consistency
    # The reference CLI prints one stdout line per target draft (§25.5):
    # the issuer loop first, then (with --cosigners) the cosigner loop.
    # The selftest runs the real cmd_board_draft_notify in-process with
    # nostr_request monkeypatched to return crafted kind-30111 draft
    # events (no relay contact): dry-run (byte-exact stdout, nothing
    # sent or recorded), skip (a pre-written send record suppresses the
    # send, byte-exact stdout), and sent (nostr_publish monkeypatched,
    # byte-exact stdout with the captured gift wrap id, record written).
    # Hand-crafted positives exercise issuer/cosigner blocks, R3 order,
    # and skip+sent mixing; negatives must all be rejected.
    dno_fails = 0
    import tempfile as _dno_tf
    import io as _dno_io
    import contextlib as _dno_ctx
    from types import SimpleNamespace as _dno_NS

    def _dno_signer():
        s = secrets.token_bytes(32)
        return (s, nakama.npub_of(s), nakama.hexpub_of(s))

    def _dno_approve(d, signer):
        msg = nakama.board_decision_message(d['board_id'], d['relay'],
                                            d['decision'], d['payload'],
                                            d['created_at'])
        d['approvals'].append({'npub': signer[1],
                               'sig': nakama.sign_schnorr(signer[0],
                                                          msg).hex()})
        return d

    _dno_relay = 'wss://example.invalid'
    _dno_board = 'dno-board-001'

    def _dno_decision(dtype, approvers, ts, expires_at):
        d = {'protocol': 'nakama', 'version': 1, 'type': 'board-decision',
             'board_id': _dno_board, 'relay': _dno_relay, 'decision': dtype,
             'payload': {'candidate': approvers[0][1],
                         'expires_at': expires_at},
             'created_at': ts, 'approvals': []}
        for a in approvers:
            _dno_approve(d, a)
        return d

    def _dno_event(d, publisher):
        content = json.dumps(d, sort_keys=True, separators=(',', ':'),
                             ensure_ascii=False)
        tags = [['d', nakama.decision_core_hash(d)], ['h', d['board_id']]]
        return nakama.sign_event(publisher[0], d['created_at'] + 60,
                                 nakama.DRAFT_NOSTR_KIND(), tags, content)

    def _dno_run(events, keyfile, notif_dir, dry_run=False, publish=None):
        orig_req = nakama.nostr_request
        nakama.nostr_request = lambda *a, **k: events
        orig_pub = nakama.nostr_publish
        if publish is not None:
            nakama.nostr_publish = publish
        code = 0
        try:
            buf = _dno_io.StringIO()
            err = _dno_io.StringIO()
            with _dno_ctx.redirect_stdout(buf), \
                    _dno_ctx.redirect_stderr(err):
                try:
                    nakama.cmd_board_draft_notify(_dno_NS(
                        relay=_dno_relay, board_id=_dno_board, limit=20,
                        auth=False, policy=None, within=86400,
                        include_expired=False, dry_run=dry_run,
                        resend=False, from_npub=None, notif_dir=notif_dir,
                        cosigners=False, keyfile=keyfile))
                except SystemExit as e:
                    code = e.code if isinstance(e.code, int) else 0
            return buf.getvalue(), err.getvalue(), code
        finally:
            nakama.nostr_request = orig_req
            nakama.nostr_publish = orig_pub

    with _dno_tf.TemporaryDirectory() as _dno_td:
        _dno_s_sender = secrets.token_bytes(32)
        _dno_kf = os.path.join(_dno_td, 'k.json')
        with open(_dno_kf, 'w') as f:
            json.dump({'secret_hex': _dno_s_sender.hex()}, f)
        os.chmod(_dno_kf, 0o600)
        _dno_m1 = _dno_signer()
        _dno_pub = _dno_signer()
        _dno_now = int(time.time())
        _dno_d1 = _dno_decision('admit', [_dno_m1], _dno_now - 100,
                                _dno_now + 3600)
        _dno_ev1 = _dno_event(_dno_d1, _dno_pub)
        _dno_core1 = nakama.decision_core_hash(_dno_d1)

        # E2E 1: dry-run — byte-exact stdout, nothing sent or recorded
        _dno_nd1 = os.path.join(_dno_td, 'notifs1')
        _rep, _err, _code = _dno_run([_dno_ev1], _dno_kf, _dno_nd1,
                                     dry_run=True)
        _want = (f'[dry-run] {_dno_core1[:12]} (expiring_soon) → '
                 f'{_dno_pub[2][:16]}... (admit)\n')
        _ok, _errs, _info = conform_draft_notify_report(_rep)
        _good = (_rep == _want) and (_code == 0) and (_err == '') and _ok \
            and not os.path.exists(_dno_nd1)
        print(f'draft-notify-e2e/dry-run: {"PASS" if _good else "FAIL"} '
              f'({"; ".join(_info)})')
        if not _good:
            print(f'    - got stdout={_rep!r} code={_code} stderr={_err!r}')
            for e in _errs:
                print(f'    - {e}')
            dno_fails += 1

        # E2E 2: skip — a pre-written send record suppresses the send
        _dno_nd2 = os.path.join(_dno_td, 'notifs2')
        nakama.draft_notif_record(_dno_nd2, _dno_core1, 'expiring_soon',
                                  _dno_pub[2],
                                  nakama.npub_of(_dno_s_sender), _dno_now,
                                  gift_wrap_id='00' * 32, rumor_id='11' * 32)
        _rep, _err, _code = _dno_run([_dno_ev1], _dno_kf, _dno_nd2)
        _want = (f'[skip] {_dno_core1[:12]} (expiring_soon) — '
                 f'86400s 以内に送信済み\n')
        _ok, _errs, _info = conform_draft_notify_report(_rep)
        _good = (_rep == _want) and (_code == 0) and (_err == '') and _ok
        print(f'draft-notify-e2e/skip: {"PASS" if _good else "FAIL"} '
              f'({"; ".join(_info)})')
        if not _good:
            print(f'    - got stdout={_rep!r} code={_code} stderr={_err!r}')
            for e in _errs:
                print(f'    - {e}')
            dno_fails += 1

        # E2E 3: sent — publish mocked, byte-exact stdout with the real
        # captured gift wrap id, and the send record is written
        _dno_nd3 = os.path.join(_dno_td, 'notifs3')
        _dno_cap = {}

        def _dno_fake_pub(url, event, timeout=15, auth_secret=None):
            _dno_cap['wrap'] = event
            return True, ''

        _rep, _err, _code = _dno_run([_dno_ev1], _dno_kf, _dno_nd3,
                                     publish=_dno_fake_pub)
        _wid = _dno_cap['wrap']['id']
        _want = (f'[sent] {_dno_core1[:12]} (expiring_soon) → '
                 f'{_dno_pub[2][:16]}... (id={_wid})\n')
        _ok, _errs, _info = conform_draft_notify_report(_rep)
        _rec = nakama.draft_notif_record_path(_dno_nd3, _dno_core1,
                                               'expiring_soon')
        _good = (_rep == _want) and (_code == 0) and (_err == '') and _ok \
            and len(_wid) == 64 \
            and all(c in '0123456789abcdef' for c in _wid) \
            and os.path.exists(_rec)
        print(f'draft-notify-e2e/sent: {"PASS" if _good else "FAIL"} '
              f'({"; ".join(_info)})')
        if not _good:
            print(f'    - got stdout={_rep!r} code={_code} stderr={_err!r}')
            for e in _errs:
                print(f'    - {e}')
            dno_fails += 1

    # hand-crafted positives
    _dno_h1, _dno_h2 = 'ab' * 6, 'cd' * 6
    _dno_p1, _dno_p2 = 'ef' * 8, '01' * 8
    _dno_id = 'ab' * 32
    _dno_l_dry = (f'[dry-run] {_dno_h1} (expiring_soon) → {_dno_p1}... '
                  f'(admit)')
    _dno_l_dry2 = (f'[dry-run] {_dno_h2} (expired) → {_dno_p2}... (remove)')
    _dno_l_skip = (f'[skip] {_dno_h1} (expiring_soon) — '
                   f'86400s 以内に送信済み')
    _dno_l_skip_c = (f'[skip] cosigner {_dno_h2} (expired) — '
                     f'86400s 以内に送信済み')
    _dno_l_sent = (f'[sent] {_dno_h1} (expiring_soon) → {_dno_p1}... '
                   f'(id={_dno_id})')
    _dno_l_sent_c = (f'[sent] cosigner {_dno_h2} (expired) → {_dno_p2}... '
                     f'(id={_dno_id})')
    dno_pos = [
        ('issuer dry-run lines',
         _dno_l_dry + '\n' + _dno_l_dry2 + '\n'),
        ('cosigner lines only', _dno_l_sent_c + '\n' + _dno_l_skip_c + '\n'),
        ('issuer block then cosigner block (R3)',
         _dno_l_sent + '\n' + _dno_l_skip_c + '\n'),
        ('skip+sent mixed (R1 constrains dry-run only)',
         _dno_l_skip + '\n' + _dno_l_sent.replace(_dno_h1, _dno_h2) + '\n'),
        ('no trailing newline', _dno_l_sent),
        ('trailing blank lines tolerated', _dno_l_dry + '\n\n'),
        ('no-target line alone (R4)',
         '通知対象の草案はありませんでした\n'),
    ]
    for name, rep in dno_pos:
        ok, errs, info = conform_draft_notify_report(rep)
        print(f'draft-notify/{name}: {"PASS" if ok else "FAIL"} '
              f'({"; ".join(info)})')
        for e in errs:
            print(f'    - {e}')
        dno_fails += 0 if ok else 1

    # negatives — all must be rejected
    dno_neg = [
        ('empty report', ''),
        ('garbage line', 'hello\n'),
        ('leading blank line', '\n' + _dno_l_sent + '\n'),
        ('trailing garbage line', _dno_l_sent + '\nunexpected\n'),
        ('two no-target reports concatenated',
         '通知対象の草案はありませんでした\n'
         '通知対象の草案はありませんでした\n'),
        ('no-target line followed by a notify line',
         '通知対象の草案はありませんでした\n' + _dno_l_sent + '\n'),
        ('R3 violated (issuer line after a cosigner line)',
         _dno_l_skip_c + '\n' + _dno_l_sent + '\n'),
        ('R1 violated (dry-run mixed with sent)',
         _dno_l_dry + '\n' + _dno_l_sent + '\n'),
        ('R2 violated (skip N mismatch)',
         _dno_l_skip + '\n'
         + _dno_l_skip.replace('86400s', '3600s')
                      .replace(_dno_h1, _dno_h2) + '\n'),
        ('unknown reason vocabulary',
         _dno_l_dry.replace('(expiring_soon)', '(expiring_later)') + '\n'),
        ('core12 too short (11 hex)',
         _dno_l_dry.replace(_dno_h1, _dno_h1[:-1]) + '\n'),
        ('hex16 not hex',
         _dno_l_sent.replace(_dno_p1, 'zz' * 8) + '\n'),
        ('unknown decision vocabulary',
         _dno_l_dry.replace('(admit)', '(banish)') + '\n'),
        ('sent id too short (63 hex)',
         _dno_l_sent.replace(_dno_id, _dno_id[:-1]) + '\n'),
        ('tag variant ([send])',
         _dno_l_sent.replace('[sent]', '[send]') + '\n'),
        ('ASCII arrow instead of →',
         _dno_l_dry.replace('→', '->') + '\n'),
        ('ASCII hyphen instead of em dash',
         _dno_l_skip.replace('—', '-') + '\n'),
        ('stderr line mixed into the report',
         f'DM の構築に失敗しました ({_dno_h1} (expiring_soon)): boom\n'),
    ]
    for name, rep in dno_neg:
        ok, errs, info = conform_draft_notify_report(rep)
        good = not ok
        print(f'draft-notify-negative/{name}: '
              f'{"PASS (rejected)" if good else "FAIL (accepted!)"}')
        if not good:
            dno_fails += 1

    dno_total = 3 + len(dno_pos) + len(dno_neg)
    print(f'--- draft-notify {dno_total - dno_fails}/{dno_total} passed ---')
    fails += dno_fails

    # ---------- check_compromise_warnings: compromise WARN-line consistency
    # The reference CLI prints compromise warnings to stderr (never
    # blocking, exit code unchanged) from verify / challenge / check /
    # board_verify / board_send / dm_send (§14.2), accept (§15), and
    # verify_binding (§16). The selftest builds real Schnorr-signed
    # declarations, imports them into a temp registry, and runs the real
    # `cmd_dm_send` in-process, capturing stderr byte-for-byte.
    wrn_fails = 0

    def _wrn_keys():
        import secrets as _secrets
        s1 = _secrets.token_bytes(32)
        s2 = _secrets.token_bytes(32)
        s3 = _secrets.token_bytes(32)
        return (s1, nakama.npub_of(s1)), (s2, nakama.npub_of(s2)), \
            (s3, nakama.npub_of(s3))

    (_wrn_ds, _wrn_dn), (_wrn_ss, _wrn_sn), (_wrn_ts, _wrn_tn) = _wrn_keys()
    _WRN_TS = 1759370000

    def _wrn_declare(decl_secret, subject_npub, ts, withdrawn=False):
        return nakama.build_compromise_declaration(
            decl_secret, subject_npub, ts, withdrawn, '', 'test', '')

    def _wrn_run(registry):
        # real CLI: dm_send to the subject key, stderr captured
        kf = os.path.join(registry, '..', 'key_wrn.json')
        kf = os.path.normpath(kf)
        nakama.save_key(kf, _wrn_ts)
        out = os.path.join(registry, '..', 'wrap.json')
        out = os.path.normpath(out)
        err = io.StringIO()
        code = 0
        with contextlib.redirect_stdout(io.StringIO()), \
                contextlib.redirect_stderr(err):
            try:
                nakama.cmd_dm_send(SimpleNamespace(
                    npub=_wrn_sn, message='hi', out=out, keyfile=kf,
                    compromise_registry=registry))
            except SystemExit as e:
                code = e.code if isinstance(e.code, int) else 0
        return err.getvalue(), code

    _wrn_e2e = []
    with tempfile.TemporaryDirectory() as _wrn_td:
        _wrn_reg = os.path.join(_wrn_td, 'compromises')
        # E2E 1: two active declarations -> N=2
        nakama.import_compromise_event(
            _wrn_declare(_wrn_ds, _wrn_sn, _WRN_TS), _wrn_reg)
        nakama.import_compromise_event(
            _wrn_declare(_wrn_ss, _wrn_sn, _WRN_TS + 60), _wrn_reg)
        _err, _code = _wrn_run(_wrn_reg)
        _wrn_e2e.append(('two active declarations', _err, _code,
                         f'WARN: {_wrn_sn[:12]}... has 2 active '
                         f'compromise declaration(s) — see: nakama.py '
                         f'key_status {_wrn_sn}\n'))
        # E2E 2: withdrawn-only registry -> no warnings
        _wrn_reg2 = os.path.join(_wrn_td, 'compromises2')
        nakama.import_compromise_event(
            _wrn_declare(_wrn_ds, _wrn_sn, _WRN_TS + 120, True), _wrn_reg2)
        _err2, _code2 = _wrn_run(_wrn_reg2)
        _wrn_e2e.append(('withdrawn-only (silent)', _err2, _code2, ''))
        # E2E 3: single active declaration -> N=1
        _wrn_reg3 = os.path.join(_wrn_td, 'compromises3')
        nakama.import_compromise_event(
            _wrn_declare(_wrn_ts, _wrn_sn, _WRN_TS + 180), _wrn_reg3)
        _err3, _code3 = _wrn_run(_wrn_reg3)
        _wrn_e2e.append(('single active declaration', _err3, _code3,
                         f'WARN: {_wrn_sn[:12]}... has 1 active '
                         f'compromise declaration(s) — see: nakama.py '
                         f'key_status {_wrn_sn}\n'))
    for name, rep, code, want_rep in _wrn_e2e:
        exact = (rep == want_rep) and (code == 0)
        ok, errs, info = conform_compromise_warnings(rep)
        good = exact and ok
        print(f'warnings-e2e/{name}: '
              f'{"PASS" if good else "FAIL"} ({"; ".join(info)})')
        if not good:
            if not exact:
                print(f'    - stderr/exit mismatch: {rep!r} code={code}')
            for e in errs:
                print(f'    - {e}')
            wrn_fails += 1

    # hand-crafted positives
    _wrn_npub = _wrn_sn
    _wrn_l = (f'WARN: {_wrn_npub[:12]}... has 1 active compromise '
              f'declaration(s) — see: nakama.py key_status {_wrn_npub}')
    wrn_pos = [
        ('single warn', f'{_wrn_l}\n'),
        ('two warns (two subjects)',
         f'{_wrn_l}\n{_wrn_l}\n'),
        ('multi-digit N',
         f'WARN: {_wrn_npub[:12]}... has 12 active compromise '
         f'declaration(s) — see: nakama.py key_status {_wrn_npub}\n'),
        ('no trailing newline', f'{_wrn_l}'),
        ('trailing blanks', f'{_wrn_l}\n\n\n'),
        ('empty capture (no warnings)', ''),
    ]
    for name, rep in wrn_pos:
        ok, errs, info = conform_compromise_warnings(rep)
        print(f'warnings/{name}: {"PASS" if ok else "FAIL"} '
              f'({"; ".join(info)})')
        for e in errs:
            print(f'    - {e}')
        wrn_fails += 0 if ok else 1

    # negatives — all must be rejected
    wrn_neg = []
    wrn_neg.append(('garbage line', 'hello\n'))
    wrn_neg.append(('missing WARN prefix',
                    f'{_wrn_l[6:]}\n'))
    wrn_neg.append(('INFO rotation downgrade (sibling grammar)',
                    f'INFO: {_wrn_npub[:12]}... has 1 active compromise '
                    f'declaration(s) — see: nakama.py key_status '
                    f'{_wrn_npub} — 旧鍵への宣言'
                    f'（ローテーション済みのため情報扱い）\n'))
    wrn_neg.append(('board_read note (sibling grammar)',
                    f'⚠ compromised?\n'))
    wrn_neg.append(('prefix mismatch',
                    f'WARN: npub1xxxxxxxx... has 1 active compromise '
                    f'declaration(s) — see: nakama.py key_status '
                    f'{_wrn_npub}\n'))
    wrn_neg.append(('N=0 (never emitted)',
                    f'WARN: {_wrn_npub[:12]}... has 0 active compromise '
                    f'declaration(s) — see: nakama.py key_status '
                    f'{_wrn_npub}\n'))
    wrn_neg.append(('N with leading zero',
                    f'WARN: {_wrn_npub[:12]}... has 01 active compromise '
                    f'declaration(s) — see: nakama.py key_status '
                    f'{_wrn_npub}\n'))
    wrn_neg.append(('unicode ellipsis instead of ASCII dots',
                    f'WARN: {_wrn_npub[:12]}… has 1 active compromise '
                    f'declaration(s) — see: nakama.py key_status '
                    f'{_wrn_npub}\n'))
    wrn_neg.append(('colon instead of em dash',
                    f'WARN: {_wrn_npub[:12]}... has 1 active compromise '
                    f'declaration(s): see: nakama.py key_status '
                    f'{_wrn_npub}\n'))
    wrn_neg.append(('short prefix (11 chars)',
                    f'WARN: {_wrn_npub[:11]}... has 1 active compromise '
                    f'declaration(s) — see: nakama.py key_status '
                    f'{_wrn_npub}\n'))
    wrn_neg.append(('non-npub subject',
                    f'WARN: deadbeefcafe... has 1 active compromise '
                    f'declaration(s) — see: nakama.py key_status '
                    f'deadbeefcafe0123456789\n'))
    wrn_neg.append(('truncated npub at end',
                    f'WARN: {_wrn_npub[:12]}... has 1 active compromise '
                    f'declaration(s) — see: nakama.py key_status '
                    f'{_wrn_npub[:12]}\n'))
    wrn_neg.append(('board_policy report (other grammar)',
                    'board-policy 案: /tmp/p.json — あなたの署名 1/2'
                    '（初回は全員 2/2 の署名が必要）\n'))
    wrn_neg.append(('leading blank line',
                    f'\n{_wrn_l}\n'))
    wrn_neg.append(('second line garbage',
                    f'{_wrn_l}\nhogehoge\n'))

    for name, rep in wrn_neg:
        ok, errs, info = conform_compromise_warnings(rep)
        good = not ok
        print(f'warnings-negative/{name}: '
              f'{"PASS (rejected)" if good else "FAIL (accepted!)"}')
        if not good:
            wrn_fails += 1

    wrn_total = len(_wrn_e2e) + len(wrn_pos) + len(wrn_neg)
    print(f'--- compromise-warnings {wrn_total - wrn_fails}/{wrn_total} '
          f'passed ---')
    fails += wrn_fails

    # ---------- check_rotation_downgrade: INFO rotation-downgrade consistency
    # The reference CLI prints INFO downgrade lines to stderr from
    # `nakama.py verify --rotation` (one per active compromise
    # declaration against an old key that the rotation chain maps).
    # The selftest builds real key pairs, a real bond, a real rotation
    # cert (old→new), and real Schnorr-signed declarations, then runs
    # the real `cmd_verify` in-process with --rotation, capturing
    # stderr byte-for-byte.
    crgd_fails = 0

    def _crgd_keys():
        import secrets as _secrets
        return [(s, nakama.npub_of(s))
                for s in (_secrets.token_bytes(32) for _ in range(4))]

    (_crgd_old_s, _crgd_old_np), (_crgd_new_s, _crgd_new_np), \
        (_crgd_ds, _crgd_dnp), (_crgd_os, _crgd_onp) = _crgd_keys()
    _CRGD_TS = 1759371000

    def _crgd_declare(decl_secret, subject_npub, ts, withdrawn=False):
        return nakama.build_compromise_declaration(
            decl_secret, subject_npub, ts, withdrawn, '', 'test', '')

    def _crgd_make_bond():
        nonce = __import__('secrets').token_hex(32)
        comps = sorted([_crgd_old_np, _crgd_onp])
        msg = nakama.bond_message(comps, _CRGD_TS, nonce, None)
        return {'protocol': 'nakama', 'version': 1, 'companions': comps,
                'created_at': _CRGD_TS, 'nonce': nonce,
                'signatures': {
                    _crgd_old_np: nakama.sign_schnorr(_crgd_old_s,
                                                      msg).hex(),
                    _crgd_onp: nakama.sign_schnorr(_crgd_os, msg).hex(),
                }}

    def _crgd_make_rotation():
        rm = nakama.rotation_message(_crgd_old_np, _crgd_new_np, _CRGD_TS)
        return {'protocol': 'nakama', 'version': 1, 'type': 'rotation',
                'old_npub': _crgd_old_np, 'new_npub': _crgd_new_np,
                'created_at': _CRGD_TS,
                'old_sig': nakama.sign_schnorr(_crgd_old_s, rm).hex()}

    def _crgd_run_verify(registry):
        # real CLI: verify --rotation, stderr captured
        with tempfile.TemporaryDirectory() as td:
            bf = os.path.join(td, 'bond.json')
            rf = os.path.join(td, 'rotation.json')
            with open(bf, 'w') as f:
                json.dump(_crgd_make_bond(), f)
            with open(rf, 'w') as f:
                json.dump(_crgd_make_rotation(), f)
            err = io.StringIO()
            code = 0
            with contextlib.redirect_stdout(io.StringIO()), \
                    contextlib.redirect_stderr(err):
                try:
                    nakama.cmd_verify(SimpleNamespace(
                        bond=bf, rotation=[rf], skip_expiry=True,
                        skip_registry=True, registry=None,
                        compromise_registry=registry))
                except SystemExit as e:
                    code = e.code if isinstance(e.code, int) else 0
            return err.getvalue(), code

    def _crgd_expect(old_npub, n):
        return (f'INFO: {old_npub[:12]}... has {n} active compromise '
                f'declaration(s) — see: nakama.py key_status {old_npub} '
                f'— 旧鍵への宣言（ローテーション済みのため情報扱い）\n')

    _crgd_e2e = []
    with tempfile.TemporaryDirectory() as _crgd_td:
        _crgd_reg = os.path.join(_crgd_td, 'compromises')
        # E2E 1: two active declarations on the OLD key -> N=2
        nakama.import_compromise_event(
            _crgd_declare(_crgd_ds, _crgd_old_np, _CRGD_TS - 100), _crgd_reg)
        nakama.import_compromise_event(
            _crgd_declare(_crgd_os, _crgd_old_np, _CRGD_TS - 50), _crgd_reg)
        _err, _code = _crgd_run_verify(_crgd_reg)
        _crgd_e2e.append(('two declarations on old key', _err, _code,
                         _crgd_expect(_crgd_old_np, 2)))
        # E2E 2: withdrawn-only registry -> no downgrade at all
        _crgd_reg2 = os.path.join(_crgd_td, 'compromises2')
        nakama.import_compromise_event(
            _crgd_declare(_crgd_ds, _crgd_old_np, _CRGD_TS - 100, True),
            _crgd_reg2)
        _err2, _code2 = _crgd_run_verify(_crgd_reg2)
        _crgd_e2e.append(('withdrawn-only (silent)', _err2, _code2, ''))
        # E2E 3: single declaration on the OLD key -> N=1
        _crgd_reg3 = os.path.join(_crgd_td, 'compromises3')
        nakama.import_compromise_event(
            _crgd_declare(_crgd_ds, _crgd_old_np, _CRGD_TS - 100),
            _crgd_reg3)
        _err3, _code3 = _crgd_run_verify(_crgd_reg3)
        _crgd_e2e.append(('single declaration on old key', _err3, _code3,
                         _crgd_expect(_crgd_old_np, 1)))
        # E2E 4: declaration only on the NEW key -> WARN (not INFO)
        _crgd_reg4 = os.path.join(_crgd_td, 'compromises4')
        nakama.import_compromise_event(
            _crgd_declare(_crgd_ds, _crgd_new_np, _CRGD_TS - 100),
            _crgd_reg4)
        _err4, _code4 = _crgd_run_verify(_crgd_reg4)
        _crgd_e2e.append(('new-key declaration (WARN, no INFO)',
                         _err4, _code4,
                         f'WARN: {_crgd_new_np[:12]}... has 1 active '
                         f'compromise declaration(s) — see: nakama.py '
                         f'key_status {_crgd_new_np}\n'))
    for name, rep, code, want_rep in _crgd_e2e:
        exact = (rep == want_rep) and (code == 0)
        ok, errs, info = conform_rotation_downgrade(rep)
        # E2E 4's WARN line is sibling grammar: exact stderr required,
        # but the downgrade conformer must REJECT it
        want_ok = not name.endswith('(WARN, no INFO)')
        good = exact and (ok == want_ok)
        print(f'rotation-downgrade-e2e/{name}: '
              f'{"PASS" if good else "FAIL"} ({"; ".join(info)})')
        if not good:
            if not exact:
                print(f'    - stderr/exit mismatch: {rep!r} code={code}')
            for e in errs:
                print(f'    - {e}')
            crgd_fails += 1

    # hand-crafted positives
    _crgd_npub = _crgd_old_np
    _crgd_l = (f'INFO: {_crgd_npub[:12]}... has 1 active compromise '
               f'declaration(s) — see: nakama.py key_status {_crgd_npub} '
               f'— 旧鍵への宣言（ローテーション済みのため情報扱い）')
    crgd_pos = [
        ('single downgrade', f'{_crgd_l}\n'),
        ('two downgrades (two old keys)',
         f'{_crgd_l}\n{_crgd_l}\n'),
        ('multi-digit N',
         f'INFO: {_crgd_npub[:12]}... has 12 active compromise '
         f'declaration(s) — see: nakama.py key_status {_crgd_npub} '
         f'— 旧鍵への宣言（ローテーション済みのため情報扱い）\n'),
        ('no trailing newline', f'{_crgd_l}'),
        ('trailing blanks', f'{_crgd_l}\n\n\n'),
        ('empty capture (no downgrades)', ''),
    ]
    for name, rep in crgd_pos:
        ok, errs, info = conform_rotation_downgrade(rep)
        print(f'rotation-downgrade/{name}: {"PASS" if ok else "FAIL"} '
              f'({"; ".join(info)})')
        for e in errs:
            print(f'    - {e}')
        crgd_fails += 0 if ok else 1

    # negatives — all must be rejected
    crgd_neg = []
    crgd_neg.append(('garbage line', 'hello\n'))
    crgd_neg.append(('missing INFO prefix',
                     f'{_crgd_l[6:]}\n'))
    crgd_neg.append(('WARN compromise line (sibling grammar)',
                     f'WARN: {_crgd_npub[:12]}... has 1 active compromise '
                     f'declaration(s) — see: nakama.py key_status '
                     f'{_crgd_npub}\n'))
    crgd_neg.append(('board_read note (sibling grammar)',
                     f'⚠ compromised?\n'))
    crgd_neg.append(('prefix mismatch',
                     f'INFO: npub1xxxxxxxx... has 1 active compromise '
                     f'declaration(s) — see: nakama.py key_status '
                     f'{_crgd_npub} — 旧鍵への宣言'
                     f'（ローテーション済みのため情報扱い）\n'))
    crgd_neg.append(('N=0 (never emitted)',
                     f'INFO: {_crgd_npub[:12]}... has 0 active compromise '
                     f'declaration(s) — see: nakama.py key_status '
                     f'{_crgd_npub} — 旧鍵への宣言'
                     f'（ローテーション済みのため情報扱い）\n'))
    crgd_neg.append(('N with leading zero',
                     f'INFO: {_crgd_npub[:12]}... has 01 active compromise '
                     f'declaration(s) — see: nakama.py key_status '
                     f'{_crgd_npub} — 旧鍵への宣言'
                     f'（ローテーション済みのため情報扱い）\n'))
    crgd_neg.append(('unicode ellipsis instead of ASCII dots',
                     f'INFO: {_crgd_npub[:12]}… has 1 active compromise '
                     f'declaration(s) — see: nakama.py key_status '
                     f'{_crgd_npub} — 旧鍵への宣言'
                     f'（ローテーション済みのため情報扱い）\n'))
    crgd_neg.append(('colon instead of em dash',
                     f'INFO: {_crgd_npub[:12]}... has 1 active compromise '
                     f'declaration(s): see: nakama.py key_status '
                     f'{_crgd_npub} — 旧鍵への宣言'
                     f'（ローテーション済みのため情報扱い）\n'))
    crgd_neg.append(('short prefix (11 chars)',
                     f'INFO: {_crgd_npub[:11]}... has 1 active compromise '
                     f'declaration(s) — see: nakama.py key_status '
                     f'{_crgd_npub} — 旧鍵への宣言'
                     f'（ローテーション済みのため情報扱い）\n'))
    crgd_neg.append(('non-npub subject',
                     f'INFO: deadbeefcafe... has 1 active compromise '
                     f'declaration(s) — see: nakama.py key_status '
                     f'deadbeefcafe0123456789 — 旧鍵への宣言'
                     f'（ローテーション済みのため情報扱い）\n'))
    crgd_neg.append(('truncated npub at end',
                     f'INFO: {_crgd_npub[:12]}... has 1 active compromise '
                     f'declaration(s) — see: nakama.py key_status '
                     f'{_crgd_npub[:12]} — 旧鍵への宣言'
                     f'（ローテーション済みのため情報扱い）\n'))
    crgd_neg.append(('missing Japanese suffix',
                     f'INFO: {_crgd_npub[:12]}... has 1 active compromise '
                     f'declaration(s) — see: nakama.py key_status '
                     f'{_crgd_npub}\n'))
    crgd_neg.append(('abbreviated prose form (no key_status middle)',
                     f'INFO: {_crgd_npub[:12]}... has 1 active compromise '
                     f'declaration(s) — 旧鍵への宣言'
                     f'（ローテーション済みのため情報扱い）\n'))
    crgd_neg.append(('ascii dash before suffix instead of em dash',
                     f'INFO: {_crgd_npub[:12]}... has 1 active compromise '
                     f'declaration(s) — see: nakama.py key_status '
                     f'{_crgd_npub} - 旧鍵への宣言'
                     f'（ローテーション済みのため情報扱い）\n'))
    crgd_neg.append(('verify_rotation verdict (other grammar)',
                     'rotation は有効です\n'))
    crgd_neg.append(('leading blank line',
                     f'\n{_crgd_l}\n'))
    crgd_neg.append(('second line garbage',
                     f'{_crgd_l}\nhogehoge\n'))

    for name, rep in crgd_neg:
        ok, errs, info = conform_rotation_downgrade(rep)
        good = not ok
        print(f'rotation-downgrade-negative/{name}: '
              f'{"PASS (rejected)" if good else "FAIL (accepted!)"}')
        if not good:
            crgd_fails += 1

    crgd_total = len(_crgd_e2e) + len(crgd_pos) + len(crgd_neg)
    print(f'--- rotation-downgrade {crgd_total - crgd_fails}/{crgd_total} '
          f'passed ---')
    fails += crgd_fails

    # ---------- check_board_policy: board_policy creation-report consistency
    # Reference reports are produced in-process with nakama.py's own
    # cmd_board_policy (offline: real key pair, temp keyfile, 3 eligible
    # npubs — plain, and the --markdown variant which is conform-checked
    # only since the payload embeds the current timestamp); hand-mutated
    # reports that break the two-line grammar (or the markdown section)
    # must be rejected, as must the sibling board-policy reports
    # (board_policy_sign, verify_board_policy).
    bpl_fails = 0
    _bpl_s, _bpl_np = _key()
    _bpl_ns = [nakama.npub_of(_key()[0]) for _ in range(2)]
    _bpl_eligible = [_bpl_np] + _bpl_ns

    def _bpl_run(markdown=False, out_name='board-policy.json'):
        with tempfile.TemporaryDirectory() as td:
            kf = os.path.join(td, 'key.json')
            with open(kf, 'w') as f:
                json.dump({'secret_hex': _bpl_s.hex()}, f)
            op = os.path.join(td, out_name)
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf), \
                    contextlib.redirect_stderr(io.StringIO()):
                nakama.cmd_board_policy(SimpleNamespace(
                    board_id='nakama-bpl', relay='wss://example.invalid',
                    threshold=2, eligible=_bpl_eligible, out=op,
                    keyfile=kf, markdown=markdown))
            return buf.getvalue(), op

    _bpl_note = ('運用: このファイルを eligible 全員に回覧し、'
                 '`board_policy_sign` で署名を集めてください。')
    _bpl_e2e = []
    _rep, _op = _bpl_run(markdown=False)
    _bpl_l1 = (f'board-policy 案: {_op} — あなたの署名 1/3'
               '（初回は全員 3/3 の署名が必要）')
    _bpl_e2e.append(('plain', _rep, f'{_bpl_l1}\n{_bpl_note}\n'))
    _rep_md, _op_md = _bpl_run(markdown=True, out_name='policy2.json')
    for name, rep, want_rep in _bpl_e2e:
        exact = (rep == want_rep)
        ok, errs, info = conform_board_policy_report(rep)
        good = exact and ok
        print(f'board-policy-e2e/{name}: '
              f'{"PASS" if good else "FAIL"} ({"; ".join(info)})')
        if not good:
            if not exact:
                print(f'    - stdout mismatch: {rep!r}')
            for e in errs:
                print(f'    - {e}')
            bpl_fails += 1
    # the --markdown variant: conform-check only (payload embeds time.time())
    _md_lines = _rep_md.splitlines()
    _md_ok = (len(_md_lines) == 8 and _md_lines[0] == _bpl_l1.replace(
        _op, _op_md) and _md_lines[1] == _bpl_note and _md_lines[2] == ''
        and _md_lines[3] == '投稿用ブロック（コメント欄に貼る）:'
        and _md_lines[4] == '<!-- nakama-board-policy:v1 -->'
        and _md_lines[5] == '```nakama-board-policy'
        and _md_lines[7] == '```')
    ok, errs, info = conform_board_policy_report(_rep_md)
    good = _md_ok and ok
    print(f'board-policy-e2e/markdown: '
          f'{"PASS" if good else "FAIL"} ({"; ".join(info)})')
    if not good:
        if not _md_ok:
            print(f'    - stdout shape mismatch: {_rep_md!r}')
        for e in errs:
            print(f'    - {e}')
        bpl_fails += 1

    # hand-crafted positives
    bpl_pos = [
        ('plain', f'{_bpl_l1}\n{_bpl_note}\n'),
        ('no trailing newline', f'{_bpl_l1}\n{_bpl_note}'),
        ('trailing blanks', f'{_bpl_l1}\n{_bpl_note}\n\n\n'),
        ('markdown variant', f'{_bpl_l1}\n{_bpl_note}\n\n'
         '投稿用ブロック（コメント欄に貼る）:\n'
         '<!-- nakama-board-policy:v1 -->\n'
         '```nakama-board-policy\n'
         'eyJ0eXBlIjoiYm9hcmQtcG9saWN5In0\n'
         '```\n'),
    ]
    for name, rep in bpl_pos:
        ok, errs, info = conform_board_policy_report(rep)
        print(f'board-policy/{name}: {"PASS" if ok else "FAIL"} '
              f'({"; ".join(info)})')
        for e in errs:
            print(f'    - {e}')
        bpl_fails += 0 if ok else 1

    # negatives — all must be rejected
    bpl_neg = []
    bpl_neg.append(('empty report', ''))
    bpl_neg.append(('garbage line', 'hello\n'))
    bpl_neg.append(('line 1 only', f'{_bpl_l1}\n'))
    bpl_neg.append(('mismatched eligible counts',
                    'board-policy 案: x.json — あなたの署名 1/3'
                    '（初回は全員 2/2 の署名が必要）\n' + _bpl_note + '\n'))
    bpl_neg.append(('zero eligible',
                    'board-policy 案: x.json — あなたの署名 1/0'
                    '（初回は全員 0/0 の署名が必要）\n' + _bpl_note + '\n'))
    bpl_neg.append(('wrong numerator (not 1)',
                    'board-policy 案: x.json — あなたの署名 2/3'
                    '（初回は全員 3/3 の署名が必要）\n' + _bpl_note + '\n'))
    bpl_neg.append(('out empty',
                    'board-policy 案:  — あなたの署名 1/3'
                    '（初回は全員 3/3 の署名が必要）\n' + _bpl_note + '\n'))
    bpl_neg.append(('line 2 altered', f'{_bpl_l1}\n運用: 回覧してね\n'))
    bpl_neg.append(('line 2 missing colon', f'{_bpl_l1}\n'))
    bpl_neg.append(('board_policy_sign report (different grammar)',
                    'board-policy: policy.json — 署名 3/3'
                    '（発効条件（全員署名）を満たしています）\n'))
    bpl_neg.append(('verify_board_policy valid (different grammar)',
                    'board-policy は有効です: eligible 3 名全員の署名を確認'
                    '（threshold 2）\n'))
    bpl_neg.append(('verify_board_policy invalid (different grammar)',
                    'board-policy は無効です: 全員の有効署名が揃っていないか、'
                    '形式が不正です\n'))
    bpl_neg.append(('markdown missing blank line',
                    f'{_bpl_l1}\n{_bpl_note}\n'
                    '投稿用ブロック（コメント欄に貼る）:\n'
                    '<!-- nakama-board-policy:v1 -->\n'
                    '```nakama-board-policy\n'
                    'eyJ0eXBlIjoiYm9hcmQtcG9saWN5In0\n```\n'))
    bpl_neg.append(('markdown wrong fence kind',
                    f'{_bpl_l1}\n{_bpl_note}\n\n'
                    '投稿用ブロック（コメント欄に貼る）:\n'
                    '<!-- nakama-board-policy:v1 -->\n'
                    '```nakama-board-decision\n'
                    'eyJ0eXBlIjoiYm9hcmQtcG9saWN5In0\n```\n'))
    bpl_neg.append(('markdown payload not base64url',
                    f'{_bpl_l1}\n{_bpl_note}\n\n'
                    '投稿用ブロック（コメント欄に貼る）:\n'
                    '<!-- nakama-board-policy:v1 -->\n'
                    '```nakama-board-policy\n'
                    'not base64 at all!!!\n```\n'))
    bpl_neg.append(('markdown truncated (no fence close)',
                    f'{_bpl_l1}\n{_bpl_note}\n\n'
                    '投稿用ブロック（コメント欄に貼る）:\n'
                    '<!-- nakama-board-policy:v1 -->\n'
                    '```nakama-board-policy\n'
                    'eyJ0eXBlIjoiYm9hcmQtcG9saWN5In0\n'))
    bpl_neg.append(('extra line after markdown block',
                    f'{_bpl_l1}\n{_bpl_note}\n\n'
                    '投稿用ブロック（コメント欄に貼る）:\n'
                    '<!-- nakama-board-policy:v1 -->\n'
                    '```nakama-board-policy\n'
                    'eyJ0eXBlIjoiYm9hcmQtcG9saWN5In0\n```\nゴミ行\n'))
    bpl_neg.append(('leading blank line', f'\n{_bpl_l1}\n{_bpl_note}\n'))
    for name, rep in bpl_neg:
        ok, _errs, _info = conform_board_policy_report(rep)
        good = not ok
        print(f'board-policy-negative/{name}: '
              f'{"PASS (rejected)" if good else "FAIL (accepted!)"}')
        if not good:
            bpl_fails += 1

    bpl_total = len(_bpl_e2e) + 1 + len(bpl_pos) + len(bpl_neg)
    print(f'--- board-policy {bpl_total - bpl_fails}/{bpl_total} '
          f'passed ---')
    fails += bpl_fails

    # ---------- check_board_policy_sign: board_policy_sign report consistency
    # Reference reports are produced in-process with nakama.py's own
    # cmd_board_policy + cmd_board_policy_sign (offline: 3 real key pairs,
    # temp keyfiles, one policy signed up to 3/3, then a duplicate sign —
    # exact stdout+exit matches); hand-mutated reports that break the
    # one-line grammar (or the m >= 1 / n >= 1 arithmetic rules) must be
    # rejected, as must the sibling board-policy reports (creation,
    # verify_board_policy).
    bps_fails = 0
    _bps_secs = [_key()[0] for _ in range(3)]
    _bps_npbs = [nakama.npub_of(s) for s in _bps_secs]
    _bps_effective = '（発効条件（全員署名）を満たしています）'
    _bps_pending = '（まだ全員分が揃っていません）'

    def _bps_setup(tmpd):
        kfs = []
        for i, s in enumerate(_bps_secs):
            kf = os.path.join(tmpd, f'key{i}.json')
            with open(kf, 'w') as f:
                json.dump({'secret_hex': s.hex()}, f)
            kfs.append(kf)
        pol = os.path.join(tmpd, 'bps-policy.json')
        with contextlib.redirect_stdout(io.StringIO()), \
                contextlib.redirect_stderr(io.StringIO()):
            nakama.cmd_board_policy(SimpleNamespace(
                board_id='nakama-bps', relay='wss://example.invalid',
                threshold=2, eligible=_bps_npbs, out=pol,
                keyfile=kfs[0], markdown=False))
        return pol, kfs

    def _bps_sign(pol, kf):
        buf = io.StringIO()
        code = 0
        with contextlib.redirect_stdout(buf), \
                contextlib.redirect_stderr(io.StringIO()):
            try:
                nakama.cmd_board_policy_sign(SimpleNamespace(
                    policy=pol, out=None, keyfile=kf))
            except SystemExit as e:
                code = e.code if isinstance(e.code, int) else 0
        return buf.getvalue(), code

    _bps_e2e = []
    with tempfile.TemporaryDirectory() as _bps_td:
        _bps_pol, _bps_kfs = _bps_setup(_bps_td)
        _rep, _code = _bps_sign(_bps_pol, _bps_kfs[1])
        _bps_e2e.append(('partial 2/3', _rep, _code, 0,
                         f'board-policy: {_bps_pol} — 署名 2/3'
                         f'{_bps_pending}\n'))
        _rep, _code = _bps_sign(_bps_pol, _bps_kfs[2])
        _bps_e2e.append(('complete 3/3', _rep, _code, 0,
                         f'board-policy: {_bps_pol} — 署名 3/3'
                         f'{_bps_effective}\n'))
        _rep, _code = _bps_sign(_bps_pol, _bps_kfs[1])  # duplicate sign
        _bps_e2e.append(('duplicate sign keeps 3/3', _rep, _code, 0,
                         f'board-policy: {_bps_pol} — 署名 3/3'
                         f'{_bps_effective}\n'))
    for name, rep, code, want_code, want_rep in _bps_e2e:
        exact = (rep == want_rep) and (code == want_code)
        ok, errs, info = conform_board_policy_sign_report(rep)
        good = exact and ok
        print(f'board-policy-sign-e2e/{name}: '
              f'{"PASS" if good else "FAIL"} ({"; ".join(info)})')
        if not good:
            if not exact:
                print(f'    - stdout/exit mismatch: {rep!r} code={code}')
            for e in errs:
                print(f'    - {e}')
            bps_fails += 1

    # hand-crafted positives
    bps_pos = [
        ('partial 2/3',
         f'board-policy: pol.json — 署名 2/3{_bps_pending}\n'),
        ('complete 3/3',
         f'board-policy: pol.json — 署名 3/3{_bps_effective}\n'),
        ('no trailing newline',
         f'board-policy: pol.json — 署名 2/3{_bps_pending}'),
        ('trailing blanks',
         f'board-policy: pol.json — 署名 3/3{_bps_effective}\n\n\n'),
        ('spaced out path',
         f'board-policy: my dir/pol.json — 署名 1/3{_bps_pending}\n'),
        ('large counts',
         f'board-policy: pol.json — 署名 100/100{_bps_effective}\n'),
    ]
    for name, rep in bps_pos:
        ok, errs, info = conform_board_policy_sign_report(rep)
        print(f'board-policy-sign/{name}: {"PASS" if ok else "FAIL"} '
              f'({"; ".join(info)})')
        for e in errs:
            print(f'    - {e}')
        bps_fails += 0 if ok else 1

    # negatives — all must be rejected
    _bps_creation = ('board-policy 案: x.json — あなたの署名 1/3'
                     '（初回は全員 3/3 の署名が必要）\n'
                     '運用: このファイルを eligible 全員に回覧し、'
                     '`board_policy_sign` で署名を集めてください。\n')
    bps_neg = []
    bps_neg.append(('empty report', ''))
    bps_neg.append(('garbage line', 'hello\n'))
    bps_neg.append(('two reports concatenated',
                    f'board-policy: a.json — 署名 2/3{_bps_pending}\n'
                    f'board-policy: b.json — 署名 3/3{_bps_effective}\n'))
    bps_neg.append(('zero signatures (self-contradiction)',
                    f'board-policy: x.json — 署名 0/3{_bps_pending}\n'))
    bps_neg.append(('zero eligible',
                    f'board-policy: x.json — 署名 1/0{_bps_pending}\n'))
    bps_neg.append(('counts non-numeric',
                    f'board-policy: x.json — 署名 a/3{_bps_pending}\n'))
    bps_neg.append(('out empty',
                    f'board-policy: — 署名 2/3{_bps_pending}\n'))
    bps_neg.append(('out trailing space',
                    f'board-policy: x.json  — 署名 2/3{_bps_pending}\n'))
    bps_neg.append(('suffix typo',
                    'board-policy: x.json — 署名 2/3'
                    '（発効条件を満たしています）\n'))
    bps_neg.append(('english suffix',
                    'board-policy: x.json — 署名 2/3 (effective)\n'))
    bps_neg.append(('dash instead of em-dash',
                    f'board-policy: x.json - 署名 2/3{_bps_pending}\n'))
    bps_neg.append(('署名 kanji missing',
                    f'board-policy: x.json — 2/3{_bps_pending}\n'))
    bps_neg.append(('prefix noun differs',
                    f'board-decision: x.json — 署名 2/3{_bps_pending}\n'))
    bps_neg.append(('board_policy creation report (different grammar)',
                    _bps_creation))
    bps_neg.append(('verify_board_policy valid (different grammar)',
                    'board-policy は有効です: eligible 3 名全員の署名を確認'
                    '（threshold 2）\n'))
    bps_neg.append(('verify_board_policy invalid (different grammar)',
                    'board-policy は無効です: 全員の有効署名が揃っていないか、'
                    '形式が不正です\n'))
    bps_neg.append(('leading blank line',
                    f'\nboard-policy: x.json — 署名 2/3{_bps_pending}\n'))
    for name, rep in bps_neg:
        ok, _errs, _info = conform_board_policy_sign_report(rep)
        good = not ok
        print(f'board-policy-sign-negative/{name}: '
              f'{"PASS (rejected)" if good else "FAIL (accepted!)"}')
        if not good:
            bps_fails += 1

    bps_total = len(_bps_e2e) + len(bps_pos) + len(bps_neg)
    print(f'--- board-policy-sign {bps_total - bps_fails}/{bps_total} '
          f'passed ---')
    fails += bps_fails

    # ---------- check_verify_board_policy: verify_board_policy report consistency
    # Reference reports are produced in-process with nakama.py's own
    # cmd_board_policy + cmd_board_policy_sign + cmd_verify_board_policy
    # (offline: 3 real key pairs, temp keyfiles — a partially signed 1/3
    # policy (invalid, exit 1), the fully signed 3/3 policy (valid, exit
    # 0), and a signature-stripped tampered policy (invalid, exit 1) —
    # exact stdout+exit matches); hand-mutated reports that break the
    # one-line grammar (or the n >= 1 / 1 <= t <= n arithmetic rules)
    # must be rejected, as must the sibling board-policy reports
    # (creation, board_policy_sign).
    vbp_fails = 0
    _vbp_secs = [_key()[0] for _ in range(3)]
    _vbp_npbs = [nakama.npub_of(s) for s in _vbp_secs]
    _vbp_valid = 'board-policy は有効です: eligible 3 名全員の署名を確認（threshold 2）\n'
    _vbp_invalid = ('board-policy は無効です: 全員の有効署名が揃っていないか、'
                    '形式が不正です\n')

    def _vbp_setup(tmpd):
        kfs = []
        for i, s in enumerate(_vbp_secs):
            kf = os.path.join(tmpd, f'key{i}.json')
            with open(kf, 'w') as f:
                json.dump({'secret_hex': s.hex()}, f)
            kfs.append(kf)
        pol = os.path.join(tmpd, 'vbp-policy.json')
        with contextlib.redirect_stdout(io.StringIO()), \
                contextlib.redirect_stderr(io.StringIO()):
            nakama.cmd_board_policy(SimpleNamespace(
                board_id='nakama-vbp', relay='wss://example.invalid',
                threshold=2, eligible=_vbp_npbs, out=pol,
                keyfile=kfs[0], markdown=False))
        return pol, kfs

    def _vbp_verify(pol):
        buf = io.StringIO()
        code = 0
        with contextlib.redirect_stdout(buf), \
                contextlib.redirect_stderr(io.StringIO()):
            try:
                nakama.cmd_verify_board_policy(SimpleNamespace(policy=pol))
            except SystemExit as e:
                code = e.code if isinstance(e.code, int) else 0
        return buf.getvalue(), code

    _vbp_e2e = []
    with tempfile.TemporaryDirectory() as _vbp_td:
        _vbp_pol, _vbp_kfs = _vbp_setup(_vbp_td)
        _rep, _code = _vbp_verify(_vbp_pol)
        _vbp_e2e.append(('partial 1/3 -> invalid', _rep, _code, 1,
                         _vbp_invalid))
        for _kf in (_vbp_kfs[1], _vbp_kfs[2]):
            with contextlib.redirect_stdout(io.StringIO()), \
                    contextlib.redirect_stderr(io.StringIO()):
                try:
                    nakama.cmd_board_policy_sign(SimpleNamespace(
                        policy=_vbp_pol, out=None, keyfile=_kf))
                except SystemExit:
                    pass
        _rep, _code = _vbp_verify(_vbp_pol)
        _vbp_e2e.append(('complete 3/3 -> valid', _rep, _code, 0,
                         _vbp_valid))
        with open(_vbp_pol) as _f:
            _tampered = json.load(_f)
        _tampered['signatures'] = _tampered['signatures'][:-1]  # strip one
        _tpol = os.path.join(_vbp_td, 'vbp-policy-tampered.json')
        with open(_tpol, 'w') as _f:
            json.dump(_tampered, _f)
        _rep, _code = _vbp_verify(_tpol)
        _vbp_e2e.append(('signature stripped -> invalid', _rep, _code, 1,
                         _vbp_invalid))
    for name, rep, code, want_code, want_rep in _vbp_e2e:
        exact = (rep == want_rep) and (code == want_code)
        ok, errs, info = conform_verify_board_policy_report(rep)
        good = exact and ok
        print(f'verify-board-policy-e2e/{name}: '
              f'{"PASS" if good else "FAIL"} ({"; ".join(info)})')
        if not good:
            if not exact:
                print(f'    - stdout/exit mismatch: {rep!r} code={code}')
            for e in errs:
                print(f'    - {e}')
            vbp_fails += 1

    # hand-crafted positives
    vbp_pos = [
        ('valid 3/2',
         'board-policy は有効です: eligible 3 名全員の署名を確認'
         '（threshold 2）\n'),
        ('valid 1/1 (t == n allowed)',
         'board-policy は有効です: eligible 1 名全員の署名を確認'
         '（threshold 1）\n'),
        ('valid 2/1 (t < n allowed)',
         'board-policy は有効です: eligible 2 名全員の署名を確認'
         '（threshold 1）\n'),
        ('invalid fixed line',
         'board-policy は無効です: 全員の有効署名が揃っていないか、'
         '形式が不正です\n'),
        ('no trailing newline (valid)',
         'board-policy は有効です: eligible 3 名全員の署名を確認'
         '（threshold 2）'),
        ('trailing blanks (invalid)',
         'board-policy は無効です: 全員の有効署名が揃っていないか、'
         '形式が不正です\n\n\n'),
    ]
    for name, rep in vbp_pos:
        ok, errs, info = conform_verify_board_policy_report(rep)
        print(f'verify-board-policy/{name}: {"PASS" if ok else "FAIL"} '
              f'({"; ".join(info)})')
        for e in errs:
            print(f'    - {e}')
        vbp_fails += 0 if ok else 1

    # negatives — all must be rejected
    _vbp_creation = ('board-policy 案: x.json — あなたの署名 1/3'
                     '（初回は全員 3/3 の署名が必要）\n'
                     '運用: このファイルを eligible 全員に回覧し、'
                     '`board_policy_sign` で署名を集めてください。\n')
    _vbp_sign = ('board-policy: x.json — 署名 2/3'
                 '（まだ全員分が揃っていません）\n')
    vbp_neg = []
    vbp_neg.append(('empty report', ''))
    vbp_neg.append(('garbage line', 'hello\n'))
    vbp_neg.append(('two reports concatenated',
                    'board-policy は無効です: 全員の有効署名が揃っていないか、'
                    '形式が不正です\n'
                    'board-policy は有効です: eligible 3 名全員の署名を確認'
                    '（threshold 2）\n'))
    vbp_neg.append(('valid, eligible 0 (self-contradiction)',
                    'board-policy は有効です: eligible 0 名全員の署名を確認'
                    '（threshold 0）\n'))
    vbp_neg.append(('valid, threshold 0',
                    'board-policy は有効です: eligible 3 名全員の署名を確認'
                    '（threshold 0）\n'))
    vbp_neg.append(('valid, threshold > n (self-contradiction)',
                    'board-policy は有効です: eligible 3 名全員の署名を確認'
                    '（threshold 4）\n'))
    vbp_neg.append(('counts non-numeric',
                    'board-policy は有効です: eligible a 名全員の署名を確認'
                    '（threshold 2）\n'))
    vbp_neg.append(('valid suffix typo',
                    'board-policy は有効です: eligible 3 名全員の署名を確認'
                    '（threshold 2）\n'.replace('確認', '確認済み')))
    vbp_neg.append(('invalid suffix typo',
                    'board-policy は無効です: 全員の有効署名が揃っていないか、'
                    '形式が不正である\n'))
    vbp_neg.append(('english valid',
                    'board-policy is valid: eligible 3 all signed '
                    '(threshold 2)\n'))
    vbp_neg.append(('invalid prefixed differently',
                    'board-policy は有効ではありません: 全員の有効署名が'
                    '揃っていないか、形式が不正です\n'))
    vbp_neg.append(('board_policy creation report (different grammar)',
                    _vbp_creation))
    vbp_neg.append(('board_policy_sign report (different grammar)',
                    _vbp_sign))
    vbp_neg.append(('valid line + extra line',
                    'board-policy は有効です: eligible 3 名全員の署名を確認'
                    '（threshold 2）\nextra\n'))
    vbp_neg.append(('missing closing paren',
                    'board-policy は有効です: eligible 3 名全員の署名を確認'
                    '（threshold 2\n'))
    vbp_neg.append(('leading blank line',
                    '\nboard-policy は有効です: eligible 3 名全員の署名を確認'
                    '（threshold 2）\n'))
    for name, rep in vbp_neg:
        ok, _errs, _info = conform_verify_board_policy_report(rep)
        good = not ok
        print(f'verify-board-policy-negative/{name}: '
              f'{"PASS (rejected)" if good else "FAIL (accepted!)"}')
        if not good:
            vbp_fails += 1

    vbp_total = len(_vbp_e2e) + len(vbp_pos) + len(vbp_neg)
    print(f'--- verify-board-policy {vbp_total - vbp_fails}/{vbp_total} '
          f'passed ---')
    fails += vbp_fails

    # ---------- check_verify: verify report consistency ----------
    # Reference reports are produced in-process with nakama.py's own
    # cmd_verify (offline: real key pairs — a valid 2-companion bond (exit
    # 0), a signature-stripped bond (invalid, exit 1), an expired bond
    # (expiry 2-line block, exit 1, no final verdict), an expiry-approaching
    # bond (warn 2-line block + valid verdict, exit 0), a rotated companion
    # (rotation note on one companion line, exit 0), and a registry-revoked
    # bond (revocation pair after the valid verdict, exit 1) — exact
    # stdout+exit matches); hand-mutated reports that break the grammar or
    # the consistency rules (verdict mismatch, expiry block with an invalid
    # companion, warn/revocation blocks in the wrong position) must be
    # rejected, as must the sibling `verify_binding` report.
    vrf_fails = 0
    _vrf_sa, _vrf_npa = _key()
    _vrf_sb, _vrf_npb = _key()
    _vrf_sn, _vrf_npn = _key()  # rotation target for _vrf_npa

    def _vrf_setup(tmpd, expires_at=None, strip_sig=False, rotation=False):
        comps = sorted([_vrf_npa, _vrf_npb])
        nonce = secrets.token_hex(32)
        msg = nakama.bond_message(comps, 1700000000, nonce, expires_at)
        bond = {'protocol': 'nakama', 'version': 1, 'companions': comps,
                'created_at': 1700000000,
                'nonce': nonce,
                'signatures': {
                    _vrf_npa: nakama.sign_schnorr(_vrf_sa, msg).hex(),
                    _vrf_npb: nakama.sign_schnorr(_vrf_sb, msg).hex()}}
        if expires_at is not None:
            bond['expires_at'] = expires_at
        if strip_sig:
            del bond['signatures'][comps[1]]
        bp = os.path.join(tmpd, 'bond.json')
        with open(bp, 'w') as f:
            json.dump(bond, f)
        rot = None
        if rotation:
            rmsg = nakama.rotation_message(_vrf_npa, _vrf_npn, 1700000000)
            rot = {'protocol': 'nakama', 'version': 1, 'type': 'rotation',
                   'old_npub': _vrf_npa, 'new_npub': _vrf_npn,
                   'created_at': 1700000000,
                   'old_sig': nakama.sign_schnorr(_vrf_sa, rmsg).hex()}
            rp = os.path.join(tmpd, 'rotation.json')
            with open(rp, 'w') as f:
                json.dump(rot, f)
            rot = [rp]
        return bond, bp, comps, rot

    def _vrf_run(bp, registry=None, skip_registry=True, skip_expiry=True,
                 rotation=None, creg=None):
        buf = io.StringIO()
        code = 0
        with contextlib.redirect_stdout(buf), \
                contextlib.redirect_stderr(io.StringIO()):
            try:
                nakama.cmd_verify(SimpleNamespace(
                    bond=bp, rotation=rotation or [], registry=registry,
                    skip_registry=skip_registry, skip_expiry=skip_expiry,
                    compromise_registry=creg or os.devnull))
            except SystemExit as e:
                code = e.code if isinstance(e.code, int) else 0
        return buf.getvalue(), code

    _vrf_e2e = []
    with tempfile.TemporaryDirectory() as _vrf_td:
        _vrf_creg = os.path.join(_vrf_td, 'creg')
        os.makedirs(_vrf_creg)
        # 1. valid bond, no expiry
        _vb, _vbp, _vc, _ = _vrf_setup(_vrf_td)
        _rep, _code = _vrf_run(_vbp, creg=_vrf_creg)
        _want = (f'{_vc[0][:24]}... : 有効\n'
                 f'{_vc[1][:24]}... : 有効\n'
                 'bond は有効です 🤝\n')
        _vrf_e2e.append(('valid 2/2', _rep, _code, 0, _want))
        # 2. signature stripped -> invalid
        _vb2, _vbp2, _vc2, _ = _vrf_setup(_vrf_td, strip_sig=True)
        _rep, _code = _vrf_run(_vbp2, creg=_vrf_creg)
        _want = (f'{_vc2[0][:24]}... : 有効\n'
                 f'{_vc2[1][:24]}... : 無効/欠落\n'
                 'bond は無効です\n')
        _vrf_e2e.append(('stripped sig -> invalid', _rep, _code, 1, _want))
        # 3. expired bond
        _vexp = 1000000000
        _vb3, _vbp3, _vc3, _ = _vrf_setup(_vrf_td, expires_at=_vexp)
        _rep, _code = _vrf_run(_vbp3, creg=_vrf_creg, skip_expiry=False)
        _vdate = time.strftime('%Y-%m-%d', time.localtime(_vexp))
        _want = (f'{_vc3[0][:24]}... : 有効\n'
                 f'{_vc3[1][:24]}... : 有効\n'
                 f'bond の有効期限が切れています（期限: {_vdate}）\n'
                 'bond は無効です — `renew` で更新してください\n')
        _vrf_e2e.append(('expired', _rep, _code, 1, _want))
        # 4. expiry approaching -> warn block + valid verdict
        _vwarn = int(time.time()) + 86400
        _vb4, _vbp4, _vc4, _ = _vrf_setup(_vrf_td, expires_at=_vwarn)
        _rep, _code = _vrf_run(_vbp4, creg=_vrf_creg, skip_expiry=False)
        _wdate = time.strftime('%Y-%m-%d', time.localtime(_vwarn))
        _want = (f'{_vc4[0][:24]}... : 有効\n'
                 f'{_vc4[1][:24]}... : 有効\n'
                 f'⚠ bond の有効期限が近づいています（期限: {_wdate}）\n'
                 '  `renew` で更新し、更新後 `liveness --bond` '
                 'で生存証明を取り直すと良いでしょう\n'
                 'bond は有効です 🤝\n')
        _vrf_e2e.append(('warn', _rep, _code, 0, _want))
        # 5. rotated companion -> rotation note on one line
        _vb5, _vbp5, _vc5, _vrot = _vrf_setup(_vrf_td, rotation=True)
        _rep, _code = _vrf_run(_vbp5, creg=_vrf_creg, rotation=_vrot)
        _rlines = []
        for _c in _vc5:
            _note = ''
            if _c == _vrf_npa:
                _note = (f'  (鍵は {_vrf_npn[:24]}... へローテーション済み — '
                         '署名自体は旧鍵のまま有効)')
            _rlines.append(f'{_c[:24]}... : 有効{_note}\n')
        _want = ''.join(_rlines) + 'bond は有効です 🤝\n'
        _vrf_e2e.append(('rotation note', _rep, _code, 0, _want))
        # 6. registry-revoked bond
        _vb6, _vbp6, _vc6, _ = _vrf_setup(_vrf_td)
        _bh = nakama.bond_hash(_vb6)
        _rc = 1700000001
        _rmsg = nakama.revocation_message(_bh, _vrf_npa, _rc)
        _rev = {'protocol': 'nakama', 'version': 1, 'type': 'revocation',
                'bond_hash': _bh, 'revoker': _vrf_npa, 'created_at': _rc,
                'sig': nakama.sign_schnorr(_vrf_sa, _rmsg).hex()}
        _regd = os.path.join(_vrf_td, 'reg')
        os.makedirs(_regd)
        with open(nakama.revocation_registry_path(_regd, _bh), 'w') as _f:
            json.dump(_rev, _f)
        _rep, _code = _vrf_run(_vbp6, creg=_vrf_creg, registry=_regd,
                              skip_registry=False)
        _rdate = time.strftime('%Y-%m-%d', time.localtime(_rc))
        _want = (f'{_vc6[0][:24]}... : 有効\n'
                 f'{_vc6[1][:24]}... : 有効\n'
                 'bond は有効です 🤝\n'
                 f'⚠ ただしこの bond は解消されています: '
                 f'{_vrf_npa[:24]}... が {_rdate} に解消を宣言\n'
                 'bond は無効です\n')
        _vrf_e2e.append(('revoked-in-registry', _rep, _code, 1, _want))
    for _name, _rep, _code, _want_code, _want_rep in _vrf_e2e:
        _exact = (_rep == _want_rep) and (_code == _want_code)
        _ok, _errs, _info = conform_verify_report(_rep)
        _good = _exact and _ok
        print(f'verify-e2e/{_name}: '
              f'{"PASS" if _good else "FAIL"} ("{"; ".join(_info)}")')
        if not _good:
            if not _exact:
                print(f'    - stdout/exit mismatch: {_rep!r} code={_code}')
                print(f'    - expected: {_want_rep!r} code={_want_code}')
            for _e in _errs:
                print(f'    - {_e}')
            vrf_fails += 1

    # hand-crafted positives
    _np1 = 'npub1aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
    _np2 = 'npub1bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb'
    _np3 = 'npub1cccccccccccccccccccccccccccccccccccccccccccccccccccccccc'
    vrf_pos = [
        ('valid 2/2', f'{_np1[:24]}... : 有効\n{_np2[:24]}... : 有効\n'
         'bond は有効です 🤝\n'),
        ('valid 2/2, trailing blanks', f'{_np1[:24]}... : 有効\n'
         f'{_np2[:24]}... : 有効\nbond は有効です 🤝\n\n\n'),
        ('valid 2/2, no trailing newline', f'{_np1[:24]}... : 有効\n'
         f'{_np2[:24]}... : 有効\nbond は有効です 🤝'),
        ('invalid 1/1', f'{_np1[:24]}... : 無効/欠落\nbond は無効です\n'),
        ('mixed 2/3 invalid', f'{_np1[:24]}... : 有効\n'
         f'{_np2[:24]}... : 無効/欠落\n{_np3[:24]}... : 有効\nbond は無効です\n'),
        ('rotation note', f'{_np1[:24]}... : 有効  (鍵は {_np2[:24]}... '
         'へローテーション済み — 署名自体は旧鍵のまま有効)\n'
         f'{_np2[:24]}... : 有効\nbond は有効です 🤝\n'),
        ('warn block', f'{_np1[:24]}... : 有効\n'
         '⚠ bond の有効期限が近づいています（期限: 2026-11-01）\n'
         '  `renew` で更新し、更新後 `liveness --bond` '
         'で生存証明を取り直すと良いでしょう\nbond は有効です 🤝\n'),
        ('expiry block', f'{_np1[:24]}... : 有効\n'
         'bond の有効期限が切れています（期限: 2026-09-01）\n'
         'bond は無効です — `renew` で更新してください\n'),
        ('revocation pair', f'{_np1[:24]}... : 有効\nbond は有効です 🤝\n'
         f'⚠ ただしこの bond は解消されています: {_np2[:24]}... '
         'が 2026-10-01 に解消を宣言\nbond は無効です\n'),
    ]
    for _name, _rep in vrf_pos:
        _ok, _errs, _info = conform_verify_report(_rep)
        print(f'verify-pos/{_name}: '
              f'{"PASS" if _ok else "FAIL"} ("{"; ".join(_info)}")')
        if not _ok:
            for _e in _errs:
                print(f'    - {_e}')
            vrf_fails += 1

    # hand-crafted negatives (must be rejected)
    vrf_neg = [
        ('empty', ''),
        ('garbage', 'hello\n'),
        ('two reports concatenated',
         f'{_np1[:24]}... : 有効\nbond は有効です 🤝\n'
         f'{_np1[:24]}... : 有効\nbond は有効です 🤝\n'),
        ('companion prefix short',
         f'{_np1[:23]}... : 有効\nbond は有効です 🤝\n'),
        ('companion prefix with space',
         f'{_np1[:23]} ... : 有効\nbond は有効です 🤝\n'),
        ('english verdict word',
         f'{_np1[:24]}... : valid\nbond は有効です 🤝\n'),
        ('valid verdict without emoji',
         f'{_np1[:24]}... : 有効\nbond は有効です\n'),
        ('all-valid but invalid verdict',
         f'{_np1[:24]}... : 有効\nbond は無効です\n'),
        ('invalid companion but valid verdict',
         f'{_np1[:24]}... : 無効/欠落\nbond は有効です 🤝\n'),
        ('expiry block with invalid companion',
         f'{_np1[:24]}... : 無効/欠落\n'
         'bond の有効期限が切れています（期限: 2026-09-01）\n'
         'bond は無効です — `renew` で更新してください\n'),
        ('expiry block followed by verdict',
         f'{_np1[:24]}... : 有効\n'
         'bond の有効期限が切れています（期限: 2026-09-01）\n'
         'bond は無効です — `renew` で更新してください\nbond は有効です 🤝\n'),
        ('expiry date malformed',
         f'{_np1[:24]}... : 有効\n'
         'bond の有効期限が切れています（期限: 2026-13-99）\n'
         'bond は無効です — `renew` で更新してください\n'),
        ('expiry 2nd line truncated',
         f'{_np1[:24]}... : 有効\n'
         'bond の有効期限が切れています（期限: 2026-09-01）\n'
         'bond は無効です\n'),
        ('warn block followed by invalid verdict',
         f'{_np1[:24]}... : 有効\n'
         '⚠ bond の有効期限が近づいています（期限: 2026-11-01）\n'
         '  `renew` で更新し、更新後 `liveness --bond` '
         'で生存証明を取り直すと良いでしょう\nbond は無効です\n'),
        ('warn 2nd line altered',
         f'{_np1[:24]}... : 有効\n'
         '⚠ bond の有効期限が近づいています（期限: 2026-11-01）\n'
         '  renew してください\nbond は有効です 🤝\n'),
        ('revocation pair after invalid verdict',
         f'{_np1[:24]}... : 無効/欠落\nbond は無効です\n'
         f'⚠ ただしこの bond は解消されています: {_np2[:24]}... '
         'が 2026-10-01 に解消を宣言\nbond は無効です\n'),
        ('revocation line malformed',
         f'{_np1[:24]}... : 有効\nbond は有効です 🤝\n'
         '⚠ ただしこの bond は解消されています\nbond は無効です\n'),
        ('verify_binding report (mutual rejection)',
         'binding は有効です\n'
         '（運用手順）: この binding が実際に該当ハンドルのアカウントから'
         '投稿されていることを確認してください\n'),
        ('leading blank line',
         f'\n{_np1[:24]}... : 有効\nbond は有効です 🤝\n'),
        ('rotation note with short new prefix',
         f'{_np1[:24]}... : 有効  (鍵は {_np2[:23]}... へローテーション済み — '
         '署名自体は旧鍵のまま有効)\nbond は有効です 🤝\n'),
    ]
    for _name, _rep in vrf_neg:
        _ok, _errs, _info = conform_verify_report(_rep)
        _good = not _ok
        print(f'verify-neg/{_name}: '
              f'{"PASS (rejected)" if _good else "FAIL (accepted!)"}')
        if not _good:
            vrf_fails += 1

    vrf_total = len(_vrf_e2e) + len(vrf_pos) + len(vrf_neg)
    print(f'--- verify {vrf_total - vrf_fails}/{vrf_total} passed ---')
    fails += vrf_fails

    # ---------- check_propose: propose report consistency ----------
    # Reference reports are produced in-process with nakama.py's own
    # cmd_propose (offline: real key pairs + temp keyfiles — a plain report
    # (custom out, --expires-days 30, exit 0), a --no-expiry report
    # (exit 0), a --markdown report (exit 0), and a zero-day report
    # (exit 0) — each with exact stdout+exit matches; the expected stdout
    # is rebuilt from the proposal file the reference CLI itself wrote, so
    # the comparison stays exact despite time-dependent fields);
    # hand-crafted reports that break the grammar (saved-file line, npub
    # line, expiry line, markdown block) must be rejected, as must the
    # sibling `accept` report (`bond 完成: …`).
    pr_fails = 0
    _pr_sa, _pr_npa = _key()
    _pr_sb, _pr_npb = _key()

    def _pr_run(secret, me_npub, tmpd, out_name, expires_days=30,
                no_expiry=False, markdown=False):
        kf = os.path.join(tmpd, 'key.json')
        nakama.save_key(kf, secret)
        out = os.path.join(tmpd, out_name)
        buf = io.StringIO()
        code = 0
        with contextlib.redirect_stdout(buf), \
                contextlib.redirect_stderr(io.StringIO()):
            try:
                nakama.cmd_propose(SimpleNamespace(
                    npub=_pr_npb, keyfile=kf, out=out,
                    expires_days=expires_days, no_expiry=no_expiry,
                    markdown=markdown))
            except SystemExit as e:
                code = e.code if isinstance(e.code, int) else 0
        rep = buf.getvalue()
        with open(out) as f:
            prop = json.load(f)
        want = [f'proposal を {out} に保存しました。相手に渡してください。',
                f'あなたの npub: {me_npub}']
        if no_expiry:
            want.append('有効期限: なし（--no-expiry）')
        else:
            ed = time.strftime('%Y-%m-%d',
                               time.localtime(prop['expires_at']))
            want.append(f'有効期限: {ed}（{expires_days} 日後）')
        if markdown:
            want += ['', '投稿用ブロック（相手のスレッド/コメント欄に貼る）:',
                     '<!-- nakama-proposal:v1 -->',
                     '```nakama-proposal',
                     nakama.b64u_encode(prop), '```']
        return rep, code, '\n'.join(want) + '\n'

    _pr_e2e = []
    with tempfile.TemporaryDirectory() as _pr_td:
        _rep, _code, _want = _pr_run(_pr_sa, _pr_npa, _pr_td, 'p1.json')
        _pr_e2e.append(('plain', _rep, _code, 0, _want))
        _rep, _code, _want = _pr_run(_pr_sa, _pr_npa, _pr_td, 'p2.json',
                                    no_expiry=True)
        _pr_e2e.append(('no-expiry', _rep, _code, 0, _want))
        _rep, _code, _want = _pr_run(_pr_sa, _pr_npa, _pr_td, 'p3.json',
                                    markdown=True)
        _pr_e2e.append(('markdown', _rep, _code, 0, _want))
        _rep, _code, _want = _pr_run(_pr_sa, _pr_npa, _pr_td, 'p4.json',
                                    expires_days=0)
        _pr_e2e.append(('zero days', _rep, _code, 0, _want))
    for _name, _rep, _code, _want_code, _want_rep in _pr_e2e:
        _exact = (_rep == _want_rep) and (_code == _want_code)
        _ok, _errs, _info = conform_propose_report(_rep)
        _good = _exact and _ok
        print(f'propose-e2e/{_name}: '
              f'{"PASS" if _good else "FAIL"} ("{"; ".join(_info)}")')
        if not _good:
            if not _exact:
                print(f'    - stdout/exit mismatch: {_rep!r} code={_code}')
                print(f'    - expected: {_want_rep!r} code={_want_code}')
            for _e in _errs:
                print(f'    - {_e}')
            pr_fails += 1

    # hand-crafted positives
    _pnp = 'npub1' + 'a' * 58
    _ppay = 'e30'  # short base64url payload shape (b64u of `{}`)
    pr_pos = [
        ('minimal',
         f'proposal を proposal.json に保存しました。相手に渡してください。\n'
         f'あなたの npub: {_pnp}\n'
         '有効期限: 2026-10-02（30 日後）\n'),
        ('no-expiry',
         f'proposal を p.json に保存しました。相手に渡してください。\n'
         f'あなたの npub: {_pnp}\n'
         '有効期限: なし（--no-expiry）\n'),
        ('trailing blanks',
         f'proposal を p.json に保存しました。相手に渡してください。\n'
         f'あなたの npub: {_pnp}\n有効期限: なし（--no-expiry）\n\n\n'),
        ('no trailing newline',
         f'proposal を p.json に保存しました。相手に渡してください。\n'
         f'あなたの npub: {_pnp}\n有効期限: 2026-10-02（30 日後）'),
        ('markdown',
         f'proposal を p.json に保存しました。相手に渡してください。\n'
         f'あなたの npub: {_pnp}\n有効期限: 2026-10-02（30 日後）\n\n'
         '投稿用ブロック（相手のスレッド/コメント欄に貼る）:\n'
         '<!-- nakama-proposal:v1 -->\n```nakama-proposal\n'
         f'{_ppay}\n```\n'),
        ('zero days',
         f'proposal を p.json に保存しました。相手に渡してください。\n'
         f'あなたの npub: {_pnp}\n有効期限: 2026-10-02（0 日後）\n'),
        ('out with spaces',
         f'proposal を my proposal.json に保存しました。相手に渡してください。\n'
         f'あなたの npub: {_pnp}\n有効期限: なし（--no-expiry）\n'),
    ]
    for _name, _rep in pr_pos:
        _ok, _errs, _info = conform_propose_report(_rep)
        print(f'propose-pos/{_name}: '
              f'{"PASS" if _ok else "FAIL"} ("{"; ".join(_info)}")')
        if not _ok:
            for _e in _errs:
                print(f'    - {_e}')
            pr_fails += 1

    # hand-crafted negatives (must be rejected)
    pr_neg = [
        ('empty', ''),
        ('garbage', 'hello\n'),
        ('accept report (mutual rejection)',
         'bond 完成: bond.json — 仲間の証です。大切に保管してください。\n'),
        ('one line only',
         'proposal を p.json に保存しました。相手に渡してください。\n'),
        ('two lines only',
         f'proposal を p.json に保存しました。相手に渡してください。\n'
         f'あなたの npub: {_pnp}\n'),
        ('npub too short',
         f'proposal を p.json に保存しました。相手に渡してください。\n'
         'あなたの npub: npub1abc\n有効期限: なし（--no-expiry）\n'),
        ('npub without npub1 prefix',
         f'proposal を p.json に保存しました。相手に渡してください。\n'
         f'あなたの npub: {"0" * 64}\n有効期限: なし（--no-expiry）\n'),
        ('npub with space',
         f'proposal を p.json に保存しました。相手に渡してください。\n'
         f'あなたの npub: {_pnp[:40]} xxx\n有効期限: なし（--no-expiry）\n'),
        ('expiry line altered (no space)',
         f'proposal を p.json に保存しました。相手に渡してください。\n'
         f'あなたの npub: {_pnp}\n有効期限: 2026-10-02（30日後）\n'),
        ('expiry date impossible',
         f'proposal を p.json に保存しました。相手に渡してください。\n'
         f'あなたの npub: {_pnp}\n有効期限: 2026-13-99（30 日後）\n'),
        ('expiry days negative',
         f'proposal を p.json に保存しました。相手に渡してください。\n'
         f'あなたの npub: {_pnp}\n有効期限: 2026-10-02（-1 日後）\n'),
        ('expiry days non-numeric',
         f'proposal を p.json に保存しました。相手に渡してください。\n'
         f'あなたの npub: {_pnp}\n有効期限: 2026-10-02（三十 日後）\n'),
        ('no-expiry line truncated',
         f'proposal を p.json に保存しました。相手に渡してください。\n'
         f'あなたの npub: {_pnp}\n有効期限: なし\n'),
        ('markdown without blank separator',
         f'proposal を p.json に保存しました。相手に渡してください。\n'
         f'あなたの npub: {_pnp}\n有効期限: なし（--no-expiry）\n'
         '投稿用ブロック（相手のスレッド/コメント欄に貼る）:\n'
         '<!-- nakama-proposal:v1 -->\n```nakama-proposal\n'
         f'{_ppay}\n```\n'),
        ('markdown header altered',
         f'proposal を p.json に保存しました。相手に渡してください。\n'
         f'あなたの npub: {_pnp}\n有効期限: なし（--no-expiry）\n\n'
         '投稿用ブロック:\n'
         '<!-- nakama-proposal:v1 -->\n```nakama-proposal\n'
         f'{_ppay}\n```\n'),
        ('markdown marker wrong kind',
         f'proposal を p.json に保存しました。相手に渡してください。\n'
         f'あなたの npub: {_pnp}\n有効期限: なし（--no-expiry）\n\n'
         '投稿用ブロック（相手のスレッド/コメント欄に貼る）:\n'
         '<!-- nakama-bond:v1 -->\n```nakama-proposal\n'
         f'{_ppay}\n```\n'),
        ('markdown fence wrong kind',
         f'proposal を p.json に保存しました。相手に渡してください。\n'
         f'あなたの npub: {_pnp}\n有効期限: なし（--no-expiry）\n\n'
         '投稿用ブロック（相手のスレッド/コメント欄に貼る）:\n'
         '<!-- nakama-proposal:v1 -->\n```nakama-bond\n'
         f'{_ppay}\n```\n'),
        ('markdown payload not base64url',
         f'proposal を p.json に保存しました。相手に渡してください。\n'
         f'あなたの npub: {_pnp}\n有効期限: なし（--no-expiry）\n\n'
         '投稿用ブロック（相手のスレッド/コメント欄に貼る）:\n'
         '<!-- nakama-proposal:v1 -->\n```nakama-proposal\n'
         'hello world!\n```\n'),
        ('markdown closing fence missing',
         f'proposal を p.json に保存しました。相手に渡してください。\n'
         f'あなたの npub: {_pnp}\n有効期限: なし（--no-expiry）\n\n'
         '投稿用ブロック（相手のスレッド/コメント欄に貼る）:\n'
         '<!-- nakama-proposal:v1 -->\n```nakama-proposal\n'
         f'{_ppay}\n'),
        ('text after closing fence',
         f'proposal を p.json に保存しました。相手に渡してください。\n'
         f'あなたの npub: {_pnp}\n有効期限: なし（--no-expiry）\n\n'
         '投稿用ブロック（相手のスレッド/コメント欄に貼る）:\n'
         '<!-- nakama-proposal:v1 -->\n```nakama-proposal\n'
         f'{_ppay}\n```\nextra\n'),
    ]
    for _name, _rep in pr_neg:
        _ok, _errs, _info = conform_propose_report(_rep)
        _good = not _ok
        print(f'propose-neg/{_name}: '
              f'{"PASS (rejected)" if _good else "FAIL (accepted!)"}')
        if not _good:
            pr_fails += 1

    pr_total = len(_pr_e2e) + len(pr_pos) + len(pr_neg)
    print(f'--- propose {pr_total - pr_fails}/{pr_total} passed ---')
    fails += pr_fails

    # ---------- check_accept: accept report consistency ----------
    # Reference reports are produced in-process with nakama.py's own
    # cmd_propose + cmd_accept (offline: real key pairs + temp keyfiles —
    # a plain accept, a --markdown accept, a spaces-in-out-name accept,
    # and a --from-b64 accept (paste form), each with exact stdout+exit
    # matches; the expected stdout is rebuilt from the bond file the
    # reference CLI itself wrote, so the comparison stays exact despite
    # time-dependent fields); hand-crafted reports that break the grammar
    # (completion line, markdown block) must be rejected, as must the
    # sibling `propose` report (`proposal を …`).
    ac_fails = 0
    _ac_sa, _ac_npa = _key()
    _ac_sb, _ac_npb = _key()

    def _ac_run(tmpd, name, markdown=False, from_b64=False):
        kfa = os.path.join(tmpd, 'key_a.json')
        nakama.save_key(kfa, _ac_sa)
        kfb = os.path.join(tmpd, 'key_b.json')
        nakama.save_key(kfb, _ac_sb)
        ppath = os.path.join(tmpd, f'{name}.proposal.json')
        with contextlib.redirect_stderr(io.StringIO()):
            nakama.cmd_propose(SimpleNamespace(
                npub=_ac_npb, keyfile=kfa, out=ppath,
                expires_days=30, no_expiry=False, markdown=False))
        with open(ppath) as f:
            prop = json.load(f)
        bpath = os.path.join(tmpd, f'{name}.bond.json')
        buf = io.StringIO()
        code = 0
        with contextlib.redirect_stdout(buf), \
                contextlib.redirect_stderr(io.StringIO()):
            try:
                nakama.cmd_accept(SimpleNamespace(
                    proposal=None if from_b64 else ppath,
                    from_b64=nakama.b64u_encode(prop) if from_b64 else None,
                    keyfile=kfb, out=bpath, markdown=markdown,
                    compromise_registry=tmpd))
            except SystemExit as e:
                code = e.code if isinstance(e.code, int) else 0
        rep = buf.getvalue()
        with open(bpath) as f:
            bond = json.load(f)
        want = [f'bond 完成: {bpath} — 仲間の証です。大切に保管してください。']
        if markdown:
            want += ['', '投稿用ブロック（返信に貼る）:',
                     '<!-- nakama-bond:v1 -->',
                     '```nakama-bond',
                     nakama.b64u_encode(bond), '```']
        return rep, code, '\n'.join(want) + '\n'

    _ac_e2e = []
    with tempfile.TemporaryDirectory() as _ac_td:
        _rep, _code, _want = _ac_run(_ac_td, 'plain')
        _ac_e2e.append(('plain', _rep, _code, 0, _want))
        _rep, _code, _want = _ac_run(_ac_td, 'markdown', markdown=True)
        _ac_e2e.append(('markdown', _rep, _code, 0, _want))
        _rep, _code, _want = _ac_run(_ac_td, 'my bond', markdown=True)
        _ac_e2e.append(('out with spaces', _rep, _code, 0, _want))
        _rep, _code, _want = _ac_run(_ac_td, 'fromb64', from_b64=True)
        _ac_e2e.append(('from-b64', _rep, _code, 0, _want))
    for _name, _rep, _code, _want_code, _want_rep in _ac_e2e:
        _exact = (_rep == _want_rep) and (_code == _want_code)
        _ok, _errs, _info = conform_accept_report(_rep)
        _good = _exact and _ok
        print(f'accept-e2e/{_name}: '
              f'{"PASS" if _good else "FAIL"} ("{"; ".join(_info)}")')
        if not _good:
            if not _exact:
                print(f'    - stdout/exit mismatch: {_rep!r} code={_code}')
                print(f'    - expected: {_want_rep!r} code={_want_code}')
            for _e in _errs:
                print(f'    - {_e}')
            ac_fails += 1

    # hand-crafted positives
    _apay = 'e30'  # short base64url payload shape (b64u of `{}`)
    ac_pos = [
        ('minimal',
         'bond 完成: bond.json — 仲間の証です。大切に保管してください。\n'),
        ('markdown',
         'bond 完成: bond.json — 仲間の証です。大切に保管してください。\n\n'
         '投稿用ブロック（返信に貼る）:\n'
         '<!-- nakama-bond:v1 -->\n```nakama-bond\n'
         f'{_apay}\n```\n'),
        ('trailing blanks',
         'bond 完成: bond.json — 仲間の証です。大切に保管してください。\n\n\n'),
        ('no trailing newline',
         'bond 完成: bond.json — 仲間の証です。大切に保管してください。'),
        ('markdown, payload with padding',
         'bond 完成: bond.json — 仲間の証です。大切に保管してください。\n\n'
         '投稿用ブロック（返信に貼る）:\n'
         '<!-- nakama-bond:v1 -->\n```nakama-bond\n'
         'e30=\n```\n'),
        ('out with spaces',
         'bond 完成: my bond.json — 仲間の証です。大切に保管してください。\n'),
        ('markdown, trailing blanks',
         'bond 完成: bond.json — 仲間の証です。大切に保管してください。\n\n'
         '投稿用ブロック（返信に貼る）:\n'
         '<!-- nakama-bond:v1 -->\n```nakama-bond\n'
         f'{_apay}\n```\n\n'),
    ]
    for _name, _rep in ac_pos:
        _ok, _errs, _info = conform_accept_report(_rep)
        print(f'accept-pos/{_name}: '
              f'{"PASS" if _ok else "FAIL"} ("{"; ".join(_info)}")')
        if not _ok:
            for _e in _errs:
                print(f'    - {_e}')
            ac_fails += 1

    # hand-crafted negatives (must be rejected)
    ac_neg = [
        ('empty', ''),
        ('garbage', 'hello\n'),
        ('propose report (mutual rejection)',
         'proposal を proposal.json に保存しました。相手に渡してください。\n'
         f'あなたの npub: npub1{"a" * 58}\n有効期限: なし（--no-expiry）\n'),
        ('line 1 truncated', 'bond 完成: bond.json\n'),
        ('dash instead of em-dash',
         'bond 完成: bond.json - 仲間の証です。大切に保管してください。\n'),
        ('suffix altered',
         'bond 完成: bond.json — 仲間の証です。大切に保存してください。\n'),
        ('out empty',
         'bond 完成:  — 仲間の証です。大切に保管してください。\n'),
        ('completion verb altered',
         'bond 完成しました: bond.json — 仲間の証です。大切に保管してください。\n'),
        ('markdown without blank separator',
         'bond 完成: bond.json — 仲間の証です。大切に保管してください。\n'
         '投稿用ブロック（返信に貼る）:\n'
         '<!-- nakama-bond:v1 -->\n```nakama-bond\n'
         f'{_apay}\n```\n'),
        ('markdown header altered (propose header)',
         'bond 完成: bond.json — 仲間の証です。大切に保管してください。\n\n'
         '投稿用ブロック（相手のスレッド/コメント欄に貼る）:\n'
         '<!-- nakama-bond:v1 -->\n```nakama-bond\n'
         f'{_apay}\n```\n'),
        ('markdown marker wrong kind',
         'bond 完成: bond.json — 仲間の証です。大切に保管してください。\n\n'
         '投稿用ブロック（返信に貼る）:\n'
         '<!-- nakama-proposal:v1 -->\n```nakama-bond\n'
         f'{_apay}\n```\n'),
        ('markdown fence wrong kind',
         'bond 完成: bond.json — 仲間の証です。大切に保管してください。\n\n'
         '投稿用ブロック（返信に貼る）:\n'
         '<!-- nakama-bond:v1 -->\n```nakama-proposal\n'
         f'{_apay}\n```\n'),
        ('markdown payload not base64url',
         'bond 完成: bond.json — 仲間の証です。大切に保管してください。\n\n'
         '投稿用ブロック（返信に貼る）:\n'
         '<!-- nakama-bond:v1 -->\n```nakama-bond\n'
         'hello world!\n```\n'),
        ('markdown closing fence missing',
         'bond 完成: bond.json — 仲間の証です。大切に保管してください。\n\n'
         '投稿用ブロック（返信に貼る）:\n'
         '<!-- nakama-bond:v1 -->\n```nakama-bond\n'
         f'{_apay}\n'),
        ('closing fence with trailing space',
         'bond 完成: bond.json — 仲間の証です。大切に保管してください。\n\n'
         '投稿用ブロック（返信に貼る）:\n'
         '<!-- nakama-bond:v1 -->\n```nakama-bond\n'
         f'{_apay}\n``` \n'),
        ('text after closing fence',
         'bond 完成: bond.json — 仲間の証です。大切に保管してください。\n\n'
         '投稿用ブロック（返信に貼る）:\n'
         '<!-- nakama-bond:v1 -->\n```nakama-bond\n'
         f'{_apay}\n```\nextra\n'),
        ('leading blank',
         '\nbond 完成: bond.json — 仲間の証です。大切に保管してください。\n'),
        ('second line without markdown',
         'bond 完成: bond.json — 仲間の証です。大切に保管してください。\n'
         '余計な行\n'),
        ('markdown tail too short',
         'bond 完成: bond.json — 仲間の証です。大切に保管してください。\n\n'
         '投稿用ブロック（返信に貼る）:\n'
         '<!-- nakama-bond:v1 -->\n```nakama-bond\n'
         f'{_apay}\n'),
        ('junk line instead of blank separator',
         'bond 完成: bond.json — 仲間の証です。大切に保管してください。\n'
         'つづき\n'
         '投稿用ブロック（返信に貼る）:\n'
         '<!-- nakama-bond:v1 -->\n```nakama-bond\n'
         f'{_apay}\n```\n'),
        ('two reports concatenated',
         'bond 完成: bond.json — 仲間の証です。大切に保管してください。\n'
         'bond 完成: bond2.json — 仲間の証です。大切に保管してください。\n'),
    ]
    for _name, _rep in ac_neg:
        _ok, _errs, _info = conform_accept_report(_rep)
        _good = not _ok
        print(f'accept-neg/{_name}: '
              f'{"PASS (rejected)" if _good else "FAIL (accepted!)"}')
        if not _good:
            ac_fails += 1

    ac_total = len(_ac_e2e) + len(ac_pos) + len(ac_neg)
    print(f'--- accept {ac_total - ac_fails}/{ac_total} passed ---')
    fails += ac_fails

    # ---------- check_challenge: challenge report consistency ----------
    # Reference reports are produced in-process with nakama.py's own
    # cmd_challenge (no relay contact — it only draws 32 random bytes);
    # hand-mutated reports that break the single-line 64-hex grammar must
    # be rejected.
    ch_fails = 0

    def _ch_run(tmpd, to=None):
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf), \
                contextlib.redirect_stderr(io.StringIO()):
            nakama.cmd_challenge(SimpleNamespace(
                to=to, compromise_registry=tmpd))
        return buf.getvalue()

    _ch_e2e = []
    with tempfile.TemporaryDirectory() as _ch_td:
        _rep = _ch_run(_ch_td)
        _ch_e2e.append(('plain', _rep))
        # --to with an empty compromise registry: §14.2's stderr warnings
        # are separated off, the stdout report shape is unchanged.
        _npub = nakama.hex_to_npub('ab' * 32)
        _rep = _ch_run(_ch_td, to=_npub)
        _ch_e2e.append(('--to, no warnings', _rep))
    for _name, _rep in _ch_e2e:
        _exact = re.fullmatch(r'[0-9a-f]{64}\n', _rep) is not None
        _ok, _errs, _info = conform_challenge_report(_rep)
        _good = _exact and _ok
        print(f'challenge-e2e/{_name}: '
              f'{"PASS" if _good else "FAIL"} ("{"; ".join(_info)}")')
        if not _good:
            if not _exact:
                print(f'    - stdout shape mismatch: {_rep!r}')
            for _e in _errs:
                print(f'    - {_e}')
            ch_fails += 1

    # hand-crafted positives
    _cnonce = 'ab' * 32  # 64 lowercase hex
    ch_pos = [
        ('minimal', f'{_cnonce}\n'),
        ('no trailing newline', _cnonce),
        ('trailing blanks', f'{_cnonce}\n\n\n'),
        ('all zeros', '00' * 32 + '\n'),
        ('all f', 'ff' * 32 + '\n'),
        # a respond report is grammatically identical (64 hex signature) —
        # check_challenge cannot and must not reject it
        ('respond-shaped report (indistinguishable)',
         'cd' * 32 + '\n'),
    ]
    for _name, _rep in ch_pos:
        _ok, _errs, _info = conform_challenge_report(_rep)
        print(f'challenge-pos/{_name}: '
              f'{"PASS" if _ok else "FAIL"} ("{"; ".join(_info)}")')
        if not _ok:
            for _e in _errs:
                print(f'    - {_e}')
            ch_fails += 1

    # hand-crafted negatives (must be rejected)
    ch_neg = [
        ('empty', ''),
        ('garbage', 'hello\n'),
        ('too short (63)', 'ab' * 31 + 'a' + '\n'),
        ('too long (65)', 'ab' * 32 + 'a' + '\n'),
        ('uppercase hex', 'AB' * 32 + '\n'),
        ('mixed case', 'aB' * 32 + '\n'),
        ('non-hex char', 'ab' * 31 + 'zz' + '\n'),
        ('inner whitespace', 'ab' * 16 + ' ' + 'ab' * 16 + '\n'),
        ('0x prefix', '0x' + 'ab' * 32 + '\n'),
        ('two reports concatenated', f'{_cnonce}\n{_cnonce}\n'),
        ('leading blank', f'\n{_cnonce}\n'),
        ('trailing junk line', f'{_cnonce}\nextra\n'),
        # check's reports are a different grammar — rejected
        ('check success report', '本人です 🤝\n'),
        ('check failure report', '検証失敗\n'),
    ]
    for _name, _rep in ch_neg:
        _ok, _errs, _info = conform_challenge_report(_rep)
        _good = not _ok
        print(f'challenge-neg/{_name}: '
              f'{"PASS (rejected)" if _good else "FAIL (accepted!)"}')
        if not _good:
            ch_fails += 1

    ch_total = len(_ch_e2e) + len(ch_pos) + len(ch_neg)
    print(f'--- challenge {ch_total - ch_fails}/{ch_total} passed ---')
    fails += ch_fails

    # ---------- check_check: check report consistency ----------
    # Reference reports are produced in-process with nakama.py's own
    # cmd_check (no relay contact — pure Schnorr verification); hand-mutated
    # reports that break the two-vocabulary single-line grammar must be
    # rejected.
    ck_fails = 0

    def _ck_run(tmpd, npub, nonce, sig):
        buf = io.StringIO()
        _code = None
        with contextlib.redirect_stdout(buf), \
                contextlib.redirect_stderr(io.StringIO()):
            try:
                nakama.cmd_check(SimpleNamespace(
                    npub=npub, nonce=nonce, sig=sig,
                    compromise_registry=tmpd))
            except SystemExit as _e:
                _code = _e.code
        return buf.getvalue(), _code

    _ck_e2e = []
    with tempfile.TemporaryDirectory() as _ck_td:
        _s, _np = _key()
        _nonce = 'cd' * 32
        _good_sig = nakama.sign_schnorr(_s, bytes.fromhex(_nonce)).hex()
        _rep, _code = _ck_run(_ck_td, _np, _nonce, _good_sig)
        _ck_e2e.append(('valid signature (success, exit 0)',
                        _rep, _code, '本人です 🤝\n', 0))
        # a tampered signature byte no longer verifies
        _bad = bytearray.fromhex(_good_sig)
        _bad[-1] ^= 0x01
        _rep, _code = _ck_run(_ck_td, _np, _nonce, bytes(_bad).hex())
        _ck_e2e.append(('tampered signature (failure, exit 1)',
                        _rep, _code, '検証失敗\n', 1))
        # a signature by a different key does not verify against this npub
        _s2, _ = _key()
        _other_sig = nakama.sign_schnorr(_s2, bytes.fromhex(_nonce)).hex()
        _rep, _code = _ck_run(_ck_td, _np, _nonce, _other_sig)
        _ck_e2e.append(('wrong-key signature (failure, exit 1)',
                        _rep, _code, '検証失敗\n', 1))
    for _name, _rep, _code, _want_rep, _want_code in _ck_e2e:
        _exact = _rep == _want_rep and _code == _want_code
        _ok, _errs, _info = conform_check_report(_rep)
        _good = _exact and _ok
        print(f'check-e2e/{_name}: '
              f'{"PASS" if _good else "FAIL"} ("{"; ".join(_info)}")')
        if not _good:
            if not _exact:
                print(f'    - stdout/exit mismatch: {_rep!r} exit={_code}')
            for _e in _errs:
                print(f'    - {_e}')
            ck_fails += 1

    # hand-crafted positives
    ck_pos = [
        ('minimal success', '本人です 🤝\n'),
        ('success, no trailing newline', '本人です 🤝'),
        ('success, trailing blanks', '本人です 🤝\n\n\n'),
        ('minimal failure', '検証失敗\n'),
        ('failure, no trailing newline', '検証失敗'),
        ('failure, trailing blanks', '検証失敗\n\n'),
    ]
    for _name, _rep in ck_pos:
        _ok, _errs, _info = conform_check_report(_rep)
        print(f'check-pos/{_name}: '
              f'{"PASS" if _ok else "FAIL"} ("{"; ".join(_info)}")')
        if not _ok:
            for _e in _errs:
                print(f'    - {_e}')
            ck_fails += 1

    # hand-crafted negatives (must be rejected)
    ck_neg = [
        ('empty', ''),
        ('garbage', 'hello\n'),
        ('whitespace only', '  \n'),
        ('two reports concatenated', '本人です 🤝\n検証失敗\n'),
        ('two failures concatenated', '検証失敗\n検証失敗\n'),
        ('leading blank', '\n本人です 🤝\n'),
        ('trailing junk line', '本人です 🤝\nextra\n'),
        ('success with trailing space', '本人です 🤝 \n'),
        ('success missing emoji', '本人です\n'),
        ('success with suffix', '本人です 🤝 です\n'),
        ('failure with suffix', '検証失敗 です\n'),
        ('english verdict', 'verified\n'),
        # challenge/respond reports are a different grammar — rejected
        ('challenge report (64 hex)', 'ab' * 32 + '\n'),
        ('leading space', ' 本人です 🤝\n'),
    ]
    for _name, _rep in ck_neg:
        _ok, _errs, _info = conform_check_report(_rep)
        _good = not _ok
        print(f'check-neg/{_name}: '
              f'{"PASS (rejected)" if _good else "FAIL (accepted!)"}')
        if not _good:
            ck_fails += 1

    ck_total = len(_ck_e2e) + len(ck_pos) + len(ck_neg)
    print(f'--- check {ck_total - ck_fails}/{ck_total} passed ---')
    fails += ck_fails

    # ---------- check_board_read: board_read report consistency ----------
    # Reference reports are produced in-process with nakama.py's own
    # cmd_board_read, with nostr_request monkeypatched to return crafted
    # kind-9 events (no relay contact); hand-mutated reports that break the
    # header/content grammar must be rejected.
    brd_fails = 0

    def _brd_read(events, compromised_npub=None):
        orig_req = nakama.nostr_request
        orig_warn = nakama.key_compromise_warnings
        nakama.nostr_request = lambda *a, **k: events
        if compromised_npub is not None:
            nakama.key_compromise_warnings = (
                lambda n, r=None: ['warn'] if n == compromised_npub else [])
        try:
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf), \
                    contextlib.redirect_stderr(io.StringIO()):
                nakama.cmd_board_read(SimpleNamespace(
                    relay='wss://example.invalid', board_id='nakama-abc123',
                    since=None, limit=20, governance=None, auth=False))
            return buf.getvalue()
        finally:
            nakama.nostr_request = orig_req
            nakama.key_compromise_warnings = orig_warn

    brd_e2e = []
    _brd_s_1, _np_brd_1 = _key()
    _brd_hx_1 = nakama.hexpub_of(_brd_s_1)
    _brd_s_2, _np_brd_2 = _key()
    _brd_hx_2 = nakama.hexpub_of(_brd_s_2)
    _brd_s_c, _np_brd_c = _key()
    _brd_hx_c = nakama.hexpub_of(_brd_s_c)

    def _brd_ev(secret, hexpub, ts, content):
        return nakama.sign_event(secret, ts, 9, [['h', 'nakama-abc123']],
                                 content)

    brd_e2e.append(('no events -> empty line', _brd_read([])))
    brd_e2e.append(('one event',
                    _brd_read([_brd_ev(_brd_s_1, _brd_hx_1, 1759276800,
                                       'hello, board')])))
    brd_e2e.append(('two events, multi-line incl. blank',
                    _brd_read([_brd_ev(_brd_s_1, _brd_hx_1, 1759276800,
                                       'first post'),
                               _brd_ev(_brd_s_2, _brd_hx_2, 1759363200,
                                       'line one\n\nline three\n'
                                       '--- not a header')])))
    brd_e2e.append(('compromised issuer suffix',
                    _brd_read([_brd_ev(_brd_s_c, _brd_hx_c, 1759276800,
                                       'flagged post')],
                               compromised_npub=_np_brd_c)))

    for name, rep in brd_e2e:
        ok, errs, info = conform_board_read_report(rep)
        print(f'board-read-e2e/{name}: {"PASS" if ok else "FAIL"} '
              f'({"; ".join(info)})')
        for e in errs:
            print(f'    - {e}')
        brd_fails += 0 if ok else 1

    # hand-crafted positives
    bh1 = '--- [2026-10-01 12:00:00] ' + 'ab' * 8 + '...'
    bh2 = '--- [2026-10-02 01:02:03] ' + 'CD' * 8 + '...'
    brd_pos = [
        ('empty report', '投稿はまだありません\n'),
        ('one block', bh1 + '\nhello\n'),
        ('multi-line incl. blank', bh1 + '\nline one\n\nline three\n'),
        ('uppercase hex author', bh2 + '\nupper hex ok\n'),
        ('content line starting with ---', bh1 + '\n--- not a header\n'),
        ('compromised suffix',
         bh1 + ' ⚠ compromised?\nflagged content\n'),
    ]
    for name, rep in brd_pos:
        ok, errs, info = conform_board_read_report(rep)
        print(f'board-read/{name}: {"PASS" if ok else "FAIL"} '
              f'({"; ".join(info)})')
        for e in errs:
            print(f'    - {e}')
        brd_fails += 0 if ok else 1

    # negatives — all must be rejected
    brd_neg = []
    brd_neg.append(('empty report', ''))
    brd_neg.append(('empty line plus block',
                    '投稿はまだありません\n' + bh1 + '\nhello\n'))
    brd_neg.append(('invalid timestamp',
                    bh1.replace('2026-10-01 12:00:00',
                                '2026-13-40 99:99:99') + '\nhello\n'))
    brd_neg.append(('author not hex',
                    '--- [2026-10-01 12:00:00] ' + 'zz' * 8 +
                    '...\nhello\n'))
    brd_neg.append(('author short',
                    '--- [2026-10-01 12:00:00] ' + 'ab' * 7 +
                    '...\nhello\n'))
    brd_neg.append(('missing ellipsis',
                    '--- [2026-10-01 12:00:00] ' + 'ab' * 8 +
                    '\nhello\n'))
    brd_neg.append(('empty content block', bh1 + '\n' + bh2 + '\nsecond\n'))
    brd_neg.append(('garbage first line', 'hello\n' + bh1 + '\ncontent\n'))
    brd_neg.append(('leading blank line', '\n' + bh1 + '\nhello\n'))
    brd_neg.append(('bad suffix spelling',
                    bh1 + ' ⚠ compromised!\nhello\n'))

    for name, rep in brd_neg:
        ok, errs, info = conform_board_read_report(rep)
        good = not ok
        print(f'board-read-negative/{name}: '
              f'{"PASS (rejected)" if good else "FAIL (accepted!)"}')
        if not good:
            brd_fails += 1

    brd_total = len(brd_e2e) + len(brd_pos) + len(brd_neg)
    print(f'--- board-read {brd_total - brd_fails}/{brd_total} passed ---')
    fails += brd_fails

    # ---------- check_board_decide_fetch: board_decide_fetch report consistency ----------
    # Reference reports are produced in-process with nakama.py's own
    # cmd_board_decide_fetch, with nostr_request monkeypatched to return
    # crafted kind-30110 decision events (no relay contact); hand-mutated
    # reports that break the grammar must be rejected.
    bdf_fails = 0

    def _bdf_kf(tmpd):
        s = secrets.token_bytes(32)
        kf = os.path.join(tmpd, 'k.json')
        with open(kf, 'w') as f:
            json.dump({'secret_hex': s.hex()}, f)
        os.chmod(kf, 0o600)
        return kf

    def _bdf_signer():
        s = secrets.token_bytes(32)
        return (s, nakama.npub_of(s), nakama.hexpub_of(s))

    _bdf_relay = 'wss://example.invalid'
    _bdf_board = 'bdf-board-001'

    def _bdf_approve(d, signer):
        msg = nakama.board_decision_message(d['board_id'], d['relay'],
                                            d['decision'], d['payload'],
                                            d['created_at'])
        d['approvals'].append({'npub': signer[1],
                               'sig': nakama.sign_schnorr(signer[0], msg).hex()})
        return d

    def _bdf_decision(dtype, approvers, ts, payload=None):
        d = {'protocol': 'nakama', 'version': 1, 'type': 'board-decision',
             'board_id': _bdf_board, 'relay': _bdf_relay, 'decision': dtype,
             'payload': payload if payload is not None
             else {'candidate': approvers[0][1]},
             'created_at': ts, 'approvals': []}
        for a in approvers:
            _bdf_approve(d, a)
        return d

    def _bdf_event(d, publisher):
        content = json.dumps(d, sort_keys=True, separators=(',', ':'),
                             ensure_ascii=False)
        tags = [['d', nakama.decision_core_hash(d)], ['h', d['board_id']]]
        return nakama.sign_event(publisher[0], d['created_at'] + 60,
                                 nakama.DECISION_NOSTR_KIND(), tags, content)

    def _bdf_policy(members, threshold):
        eligible = [m[1] for m in members]
        ts = 1760000000
        msg = nakama.board_policy_message(_bdf_board, _bdf_relay, threshold,
                                          eligible, ts)
        return {'protocol': 'nakama', 'version': 1, 'type': 'board-policy',
                'board_id': _bdf_board, 'relay': _bdf_relay,
                'threshold': threshold, 'eligible': eligible,
                'created_at': ts,
                'signatures': [{'npub': m[1],
                                'sig': nakama.sign_schnorr(m[0], msg).hex()}
                               for m in members]}

    def _bdf_run(events, keyfile, policy=None, out=None):
        orig = nakama.nostr_request
        nakama.nostr_request = lambda *a, **k: events
        try:
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf), \
                    contextlib.redirect_stderr(io.StringIO()):
                nakama.cmd_board_decide_fetch(SimpleNamespace(
                    relay=_bdf_relay, board_id=_bdf_board, limit=20,
                    auth=False, out=out, policy=policy, keyfile=keyfile))
            return buf.getvalue()
        finally:
            nakama.nostr_request = orig

    bdf_e2e = []
    with tempfile.TemporaryDirectory() as tmpd:
        _bdf_kf_path = _bdf_kf(tmpd)
        bdf_e2e.append(('no events -> empty line',
                        _bdf_run([], _bdf_kf_path)))
        _m1, _m2, _m3 = _bdf_signer(), _bdf_signer(), _bdf_signer()
        _pub = _bdf_signer()
        _d1 = _bdf_decision('admit', [_m1, _m2], 1760000000)
        bdf_e2e.append(('one decision', _bdf_run([_bdf_event(_d1, _pub)],
                                                 _bdf_kf_path)))
        _bad = nakama.sign_event(_pub[0], 1760000000,
                                 nakama.DECISION_NOSTR_KIND(),
                                 [['d', '0' * 32], ['h', _bdf_board]], '{}')
        _d2 = _bdf_decision('remove', [_m1], 1760010000)
        bdf_e2e.append(('three events, one skipped',
                        _bdf_run([_bdf_event(_d1, _pub), _bad,
                                  _bdf_event(_d2, _pub)], _bdf_kf_path)))
        _pol = _bdf_policy([_m1, _m2, _m3], 2)
        _pf = os.path.join(tmpd, 'policy.json')
        with open(_pf, 'w') as f:
            json.dump(_pol, f)
        _outd = os.path.join(tmpd, 'out')
        _d3 = _bdf_decision('admit', [_m1, _m2], 1760020000)
        _d4 = _bdf_decision('remove', [_m1], 1760030000)
        bdf_e2e.append(('policy + out -> disclaimer, thresholds, save lines',
                        _bdf_run([_bdf_event(_d3, _pub), _bdf_event(_d4, _pub)],
                                 _bdf_kf_path, policy=_pf, out=_outd)))

    for name, rep in bdf_e2e:
        ok, errs, info = conform_board_decide_fetch_report(rep)
        print(f'decide-fetch-e2e/{name}: {"PASS" if ok else "FAIL"} '
              f'({"; ".join(info)})')
        for e in errs:
            print(f'    - {e}')
        bdf_fails += 0 if ok else 1

    # hand-crafted positives
    _bd_h = 'ab' * 16
    _bd_dis = ('threshold 表示は取得できた決定に基づく暫定です'
               '（権威ある判定は board_read --governance）')
    _bd_l1 = (f'[{_bd_h}] admit (created_at 2026-10-01, approvals 2 つ)')
    _bd_l1t = (f'[{_bd_h}] admit (created_at 2026-10-01, approvals 2 つ, '
               f'threshold 2/3 充足)')
    _bd_l2t = (f'[cd{"ef" * 15}] remove (created_at 2026-10-02, approvals 1 つ, '
               f'threshold 1/3 不足)')
    _bd_l2 = f'[cd{"ef" * 15}] remove (created_at 2026-10-02, approvals 1 つ)'
    _bd_f1 = '2 件のイベントを取得: 有効 2 件、スキップ 0 件、マージ後 1 件'
    _bd_f2 = '3 件のイベントを取得: 有効 2 件、スキップ 1 件、マージ後 2 件'
    _bd_save1 = ('1 件の決定を decisions/ に保存しました'
                 '（board_read --governance --decisions にそのまま渡せます）')
    _bd_save2 = ('2 件の決定を decisions/ に保存しました'
                 '（board_read --governance --decisions にそのまま渡せます）')
    _bd_snap = ('fetch 時点の政策スナップショットを decisions/'
                'policy-snapshot-1760000000.json に保存しました'
                '（検証者はこのファイルを --policy に指定して threshold '
                '判定を再現できます）')
    bdf_pos = [
        ('empty report',
         '2 件のイベントを取得: 有効な board-decision 公開はありませんでした'
         '（1 件をスキップ）\n'),
        ('one plain line', _bd_l1 + '\n' + _bd_f1 + '\n'),
        ('policy display', _bd_dis + '\n' + _bd_l1t + '\n' + _bd_l2t + '\n'
         + _bd_f2 + '\n'),
        ('out without policy', _bd_l1 + '\n' + _bd_l2 + '\n' + _bd_f2 + '\n'
         + _bd_save2 + '\n'),
        ('out with policy and snapshot',
         _bd_dis + '\n' + _bd_l1t + '\n' + _bd_l2t + '\n' + _bd_f2 + '\n'
         + _bd_save2 + '\n' + _bd_snap + '\n'),
        ('uppercase core hash',
         ('[' + 'AB' * 16 + '] handover (created_at 2026-09-30, '
          'approvals 1 つ)\n'
          '1 件のイベントを取得: 有効 1 件、スキップ 0 件、マージ後 1 件\n')),
    ]
    for name, rep in bdf_pos:
        ok, errs, info = conform_board_decide_fetch_report(rep)
        print(f'decide-fetch/{name}: {"PASS" if ok else "FAIL"} '
              f'({"; ".join(info)})')
        for e in errs:
            print(f'    - {e}')
        bdf_fails += 0 if ok else 1

    # negatives — all must be rejected
    bdf_neg = []
    bdf_neg.append(('empty report', ''))
    bdf_neg.append(('empty line plus lines',
                    '2 件のイベントを取得: 有効な board-decision 公開はありません'
                    'でした（1 件をスキップ）\n' + _bd_l1 + '\n' + _bd_f1 + '\n'))
    bdf_neg.append(('invalid date',
                    _bd_l1.replace('2026-10-01', '2026-13-40') + '\n'
                    + _bd_f1 + '\n'))
    bdf_neg.append(('core not hex',
                    _bd_l1.replace(_bd_h, 'zz' * 16) + '\n' + _bd_f1 + '\n'))
    bdf_neg.append(('unknown decision type',
                    _bd_l1.replace('admit', 'banish') + '\n' + _bd_f1 + '\n'))
    bdf_neg.append(('approvals/threshold mismatch',
                    _bd_dis + '\n'
                    + _bd_l1t.replace('approvals 2 つ', 'approvals 3 つ')
                    + '\n' + _bd_f1 + '\n'))
    bdf_neg.append(('threshold numerator > denominator',
                    _bd_dis + '\n' + _bd_l1t.replace('2/3', '6/3') + '\n'
                    + _bd_f1 + '\n'))
    bdf_neg.append(('threshold clause without disclaimer',
                    _bd_l1t + '\n' + _bd_f1 + '\n'))
    bdf_neg.append(('plain line under disclaimer',
                    _bd_dis + '\n' + _bd_l1 + '\n' + _bd_f1 + '\n'))
    bdf_neg.append(('footer merged count mismatch',
                    _bd_l1 + '\n' + _bd_f1.replace('マージ後 1 件',
                                                    'マージ後 2 件') + '\n'))
    bdf_neg.append(('missing footer', _bd_l1 + '\n'))
    bdf_neg.append(('trailing garbage', _bd_l1 + '\n' + _bd_f1 + '\n'
                    + 'unexpected\n'))
    bdf_neg.append(('snapshot without save line',
                    _bd_dis + '\n' + _bd_l1t + '\n' + _bd_f2 + '\n'
                    + _bd_snap + '\n'))
    bdf_neg.append(('duplicate core hash',
                    _bd_l1 + '\n' + _bd_l1 + '\n'
                    + '2 件のイベントを取得: 有効 2 件、スキップ 0 件、'
                      'マージ後 2 件\n'))

    for name, rep in bdf_neg:
        ok, errs, info = conform_board_decide_fetch_report(rep)
        good = not ok
        print(f'decide-fetch-negative/{name}: '
              f'{"PASS (rejected)" if good else "FAIL (accepted!)"}')
        if not good:
            bdf_fails += 1

    bdf_total = len(bdf_e2e) + len(bdf_pos) + len(bdf_neg)
    print(f'--- decide-fetch {bdf_total - bdf_fails}/{bdf_total} passed ---')
    fails += bdf_fails

    # ---------- check_board_draft_fetch: board_draft_fetch report consistency ----------
    # Reference reports are produced in-process with nakama.py's own
    # cmd_board_draft_fetch, with nostr_request monkeypatched to return
    # crafted kind-30111 draft events (no relay contact); hand-mutated
    # reports that break the grammar must be rejected.
    ddf_fails = 0

    def _ddf_kf(tmpd):
        s = secrets.token_bytes(32)
        kf = os.path.join(tmpd, 'k.json')
        with open(kf, 'w') as f:
            json.dump({'secret_hex': s.hex()}, f)
        os.chmod(kf, 0o600)
        return kf

    def _ddf_signer():
        s = secrets.token_bytes(32)
        return (s, nakama.npub_of(s), nakama.hexpub_of(s))

    _ddf_relay = 'wss://example.invalid'
    _ddf_board = 'ddf-board-001'

    def _ddf_approve(d, signer):
        msg = nakama.board_decision_message(d['board_id'], d['relay'],
                                            d['decision'], d['payload'],
                                            d['created_at'])
        d['approvals'].append({'npub': signer[1],
                               'sig': nakama.sign_schnorr(signer[0], msg).hex()})
        return d

    def _ddf_decision(dtype, approvers, ts, payload=None, expires_at=None):
        d = {'protocol': 'nakama', 'version': 1, 'type': 'board-decision',
             'board_id': _ddf_board, 'relay': _ddf_relay, 'decision': dtype,
             'payload': payload if payload is not None
             else {'candidate': approvers[0][1]},
             'created_at': ts, 'approvals': []}
        if expires_at is not None:
            d['payload'] = dict(d['payload'])
            d['payload']['expires_at'] = expires_at
        for a in approvers:
            _ddf_approve(d, a)
        return d

    def _ddf_event(d, publisher):
        content = json.dumps(d, sort_keys=True, separators=(',', ':'),
                             ensure_ascii=False)
        tags = [['d', nakama.decision_core_hash(d)], ['h', d['board_id']]]
        return nakama.sign_event(publisher[0], d['created_at'] + 60,
                                 nakama.DRAFT_NOSTR_KIND(), tags, content)

    def _ddf_policy(members, threshold):
        eligible = [m[1] for m in members]
        ts = 1760000000
        msg = nakama.board_policy_message(_ddf_board, _ddf_relay, threshold,
                                          eligible, ts)
        return {'protocol': 'nakama', 'version': 1, 'type': 'board-policy',
                'board_id': _ddf_board, 'relay': _ddf_relay,
                'threshold': threshold, 'eligible': eligible,
                'created_at': ts,
                'signatures': [{'npub': m[1],
                                'sig': nakama.sign_schnorr(m[0], msg).hex()}
                               for m in members]}

    def _ddf_run(events, keyfile, policy=None, out=None):
        orig = nakama.nostr_request
        nakama.nostr_request = lambda *a, **k: events
        try:
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf), \
                    contextlib.redirect_stderr(io.StringIO()):
                nakama.cmd_board_draft_fetch(SimpleNamespace(
                    relay=_ddf_relay, board_id=_ddf_board, limit=20,
                    auth=False, out=out, policy=policy, keyfile=keyfile))
            return buf.getvalue()
        finally:
            nakama.nostr_request = orig

    ddf_e2e = []
    with tempfile.TemporaryDirectory() as tmpd:
        _ddf_kf_path = _ddf_kf(tmpd)
        ddf_e2e.append(('no events -> empty line',
                        _ddf_run([], _ddf_kf_path)))
        _m1, _m2, _m3 = _ddf_signer(), _ddf_signer(), _ddf_signer()
        _pub = _ddf_signer()
        _d1 = _ddf_decision('admit', [_m1, _m2], 1760000000)
        ddf_e2e.append(('one draft',
                        _ddf_run([_ddf_event(_d1, _pub)], _ddf_kf_path)))
        _bad = nakama.sign_event(_pub[0], 1760000000,
                                 nakama.DRAFT_NOSTR_KIND(),
                                 [['d', '0' * 32], ['h', _ddf_board]], '{}')
        _d2 = _ddf_decision('remove', [_m1], 1760010000)
        ddf_e2e.append(('three events, one skipped',
                        _ddf_run([_ddf_event(_d1, _pub), _bad,
                                  _ddf_event(_d2, _pub)], _ddf_kf_path)))
        _exp = _ddf_decision('admit', [_m1], 1760020000,
                             expires_at=int(time.time()) - 100)
        ddf_e2e.append(('expired draft -> [期限切れ] marker',
                        _ddf_run([_ddf_event(_exp, _pub)], _ddf_kf_path)))
        _pol = _ddf_policy([_m1, _m2, _m3], 2)
        _pf = os.path.join(tmpd, 'policy.json')
        with open(_pf, 'w') as f:
            json.dump(_pol, f)
        _outd = os.path.join(tmpd, 'out')
        _d3 = _ddf_decision('admit', [_m1, _m2], 1760030000)
        _d4 = _ddf_decision('remove', [_m1], 1760040000)
        _pu = _ddf_decision('policy-update', [_m1, _m2], 1760050000,
                            payload={'threshold': 2,
                                     'eligible': [m[1] for m in
                                                  (_m1, _m2, _m3)]})
        ddf_e2e.append(('policy + out -> disclaimer, thresholds, save '
                        'lines (incl. policy-update proposal)',
                        _ddf_run([_ddf_event(_d3, _pub), _ddf_event(_d4, _pub),
                                  _ddf_event(_pu, _pub)],
                                 _ddf_kf_path, policy=_pf, out=_outd)))

    for name, rep in ddf_e2e:
        ok, errs, info = conform_board_draft_fetch_report(rep)
        print(f'draft-fetch-e2e/{name}: {"PASS" if ok else "FAIL"} '
              f'({"; ".join(info)})')
        for e in errs:
            print(f'    - {e}')
        ddf_fails += 0 if ok else 1

    # hand-crafted positives
    _dd_h = 'ab' * 16
    _dd_dis = ('草案（回覧中）の threshold 表示は取得できた草案に基づく暫定です'
               '（草案は成立の証拠ではありません — 成立の公開宣言は kind 30110）')
    _dd_l1 = f'[草案 {_dd_h}] admit (created_at 2026-10-01, approvals 2 つ)'
    _dd_l1e = (f'[草案 {_dd_h}] [期限切れ] admit '
               f'(created_at 2026-10-01, approvals 1 つ)')
    _dd_l1t = (f'[草案 {_dd_h}] admit (created_at 2026-10-01, approvals 2 つ, '
               f'草案: threshold 2/3 不足)')
    _dd_l2t = (f'[草案 cd{"ef" * 15}] remove (created_at 2026-10-02, '
               f'approvals 3 つ, 草案: threshold 3/3 '
               f'充足（成立可能 — board_decide_pub で成立公開）)')
    _dd_l3t = (f'[草案 ef{"ab" * 15}] policy-update (created_at 2026-10-03, '
               f'approvals 2 つ, 草案: threshold 2/3 不足（現行規約の判定）'
               f' — 提案値: threshold 2/5)')
    _dd_l2 = (f'[草案 cd{"ef" * 15}] remove '
              f'(created_at 2026-10-02, approvals 1 つ)')
    _dd_f1 = '2 件のイベントを取得: 有効 2 件、スキップ 0 件、マージ後 1 件'
    _dd_f2 = '3 件のイベントを取得: 有効 2 件、スキップ 1 件、マージ後 2 件'
    _dd_f3 = '3 件のイベントを取得: 有効 3 件、スキップ 0 件、マージ後 3 件'
    _dd_save2 = ('2 件の草案を drafts/ に保存しました'
                 '（board_cosign で追記 → board_draft_pub にそのまま渡せます）')
    _dd_snap = ('fetch 時点の政策スナップショットを drafts/'
                'policy-snapshot-1760000000.json に保存しました'
                '（検証者はこのファイルを --policy に指定して threshold '
                '判定を再現できます）')
    ddf_pos = [
        ('empty report',
         '2 件のイベントを取得: 有効な草案はありませんでした'
         '（1 件をスキップ）\n'),
        ('one plain line', _dd_l1 + '\n' + _dd_f1 + '\n'),
        ('expired marker line', _dd_l1e + '\n' + _dd_f1 + '\n'),
        ('policy display with proposal clause',
         _dd_dis + '\n' + _dd_l1t + '\n' + _dd_l2t + '\n' + _dd_l3t + '\n'
         + _dd_f3 + '\n'),
        ('out without policy',
         _dd_l1 + '\n' + _dd_l2 + '\n' + _dd_f2 + '\n' + _dd_save2 + '\n'),
        ('out with policy and snapshot',
         _dd_dis + '\n' + _dd_l1t + '\n' + _dd_l2t + '\n' + _dd_f2 + '\n'
         + _dd_save2 + '\n' + _dd_snap + '\n'),
        ('uppercase core hash',
         ('[草案 ' + 'AB' * 16 + '] handover (created_at 2026-09-30, '
          'approvals 1 つ)\n'
          '1 件のイベントを取得: 有効 1 件、スキップ 0 件、マージ後 1 件\n')),
    ]
    for name, rep in ddf_pos:
        ok, errs, info = conform_board_draft_fetch_report(rep)
        print(f'draft-fetch/{name}: {"PASS" if ok else "FAIL"} '
              f'({"; ".join(info)})')
        for e in errs:
            print(f'    - {e}')
        ddf_fails += 0 if ok else 1

    # negatives — all must be rejected
    ddf_neg = []
    ddf_neg.append(('empty report', ''))
    ddf_neg.append(('empty line plus lines',
                    '2 件のイベントを取得: 有効な草案はありませんでした'
                    '（1 件をスキップ）\n' + _dd_l1 + '\n' + _dd_f1 + '\n'))
    ddf_neg.append(('decide-fetch line (no [草案] prefix)',
                    _dd_l1.replace('[草案 ', '[') + '\n' + _dd_f1 + '\n'))
    ddf_neg.append(('invalid date',
                    _dd_l1.replace('2026-10-01', '2026-13-40') + '\n'
                    + _dd_f1 + '\n'))
    ddf_neg.append(('core not hex',
                    _dd_l1.replace(_dd_h, 'zz' * 16) + '\n' + _dd_f1 + '\n'))
    ddf_neg.append(('unknown decision type',
                    _dd_l1.replace('admit', 'banish') + '\n' + _dd_f1 + '\n'))
    ddf_neg.append(('approvals/threshold mismatch',
                    _dd_dis + '\n'
                    + _dd_l1t.replace('approvals 2 つ', 'approvals 3 つ')
                    + '\n' + _dd_f1 + '\n'))
    ddf_neg.append(('threshold numerator > denominator',
                    _dd_dis + '\n' + _dd_l1t.replace('2/3', '6/3') + '\n'
                    + _dd_f1 + '\n'))
    ddf_neg.append(('threshold clause without disclaimer',
                    _dd_l1t + '\n' + _dd_f1 + '\n'))
    ddf_neg.append(('plain line under disclaimer',
                    _dd_dis + '\n' + _dd_l1 + '\n' + _dd_f1 + '\n'))
    ddf_neg.append(('footer merged count mismatch',
                    _dd_l1 + '\n' + _dd_f1.replace('マージ後 1 件',
                                                    'マージ後 2 件') + '\n'))
    ddf_neg.append(('missing footer', _dd_l1 + '\n'))
    ddf_neg.append(('trailing garbage', _dd_l1 + '\n' + _dd_f1 + '\n'
                    + 'unexpected\n'))
    ddf_neg.append(('snapshot without save line',
                    _dd_dis + '\n' + _dd_l1t + '\n' + _dd_f2 + '\n'
                    + _dd_snap + '\n'))
    ddf_neg.append(('duplicate core hash',
                    _dd_l1 + '\n' + _dd_l1 + '\n'
                    + '2 件のイベントを取得: 有効 2 件、スキップ 0 件、'
                      'マージ後 2 件\n'))
    ddf_neg.append(('proposal clause on non-policy-update draft',
                    _dd_dis + '\n'
                    + _dd_l1t.replace('草案: threshold 2/3 不足',
                                      '草案: threshold 2/3 不足'
                                      '（現行規約の判定） — 提案値: '
                                      'threshold 2/5')
                    + '\n' + _dd_f1 + '\n'))

    for name, rep in ddf_neg:
        ok, errs, info = conform_board_draft_fetch_report(rep)
        good = not ok
        print(f'draft-fetch-negative/{name}: '
              f'{"PASS (rejected)" if good else "FAIL (accepted!)"}')
        if not good:
            ddf_fails += 1

    ddf_total = len(ddf_e2e) + len(ddf_pos) + len(ddf_neg)
    print(f'--- draft-fetch {ddf_total - ddf_fails}/{ddf_total} passed ---')
    fails += ddf_fails

    # ---------- check_board_fetch_all: board_fetch_all report consistency ----------
    # Reference reports are produced in-process with nakama.py's own
    # cmd_board_fetch_all, with nostr_request monkeypatched to return
    # crafted kind-30110/30111 events (no relay contact); hand-mutated
    # reports that break the grammar must be rejected.
    bfa_fails = 0

    def _bfa_signer():
        s = secrets.token_bytes(32)
        return (s, nakama.npub_of(s), nakama.hexpub_of(s))

    _bfa_relay = 'wss://example.invalid'
    _bfa_board = 'bfa-board-001'

    def _bfa_approve(d, signer):
        msg = nakama.board_decision_message(d['board_id'], d['relay'],
                                           d['decision'], d['payload'],
                                           d['created_at'])
        d['approvals'].append({'npub': signer[1],
                               'sig': nakama.sign_schnorr(signer[0],
                                                          msg).hex()})
        return d

    def _bfa_decision(dtype, approvers, ts, payload=None, expires_at=None):
        d = {'protocol': 'nakama', 'version': 1, 'type': 'board-decision',
             'board_id': _bfa_board, 'relay': _bfa_relay, 'decision': dtype,
             'payload': payload if payload is not None
             else {'candidate': approvers[0][1]},
             'created_at': ts, 'approvals': []}
        if expires_at is not None:
            d['payload'] = dict(d['payload'])
            d['payload']['expires_at'] = expires_at
        for a in approvers:
            _bfa_approve(d, a)
        return d

    def _bfa_event(d, publisher, kind):
        content = json.dumps(d, sort_keys=True, separators=(',', ':'),
                             ensure_ascii=False)
        tags = [['d', nakama.decision_core_hash(d)], ['h', d['board_id']]]
        return nakama.sign_event(publisher[0], d['created_at'] + 60,
                                 kind, tags, content)

    def _bfa_policy(members, threshold):
        eligible = [m[1] for m in members]
        ts = 1760000000
        msg = nakama.board_policy_message(_bfa_board, _bfa_relay, threshold,
                                          eligible, ts)
        return {'protocol': 'nakama', 'version': 1, 'type': 'board-policy',
                'board_id': _bfa_board, 'relay': _bfa_relay,
                'threshold': threshold, 'eligible': eligible,
                'created_at': ts,
                'signatures': [{'npub': m[1],
                                'sig': nakama.sign_schnorr(m[0], msg).hex()}
                               for m in members]}

    def _bfa_kf(tmpd):
        s = secrets.token_bytes(32)
        kf = os.path.join(tmpd, 'k.json')
        with open(kf, 'w') as f:
            json.dump({'secret_hex': s.hex()}, f)
        os.chmod(kf, 0o600)
        return kf

    def _bfa_run(events, keyfile, policy=None, out=None):
        orig = nakama.nostr_request
        nakama.nostr_request = lambda *a, **k: events
        try:
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf), \
                    contextlib.redirect_stderr(io.StringIO()):
                nakama.cmd_board_fetch_all(SimpleNamespace(
                    relay=_bfa_relay, board_id=_bfa_board, limit=20,
                    auth=False, out=out, policy=policy, keyfile=keyfile))
            return buf.getvalue()
        finally:
            nakama.nostr_request = orig

    bfa_e2e = []
    with tempfile.TemporaryDirectory() as tmpd:
        _bfa_kf_path = _bfa_kf(tmpd)
        bfa_e2e.append(('no events -> empty line',
                        _bfa_run([], _bfa_kf_path)))
        _m1, _m2, _m3 = _bfa_signer(), _bfa_signer(), _bfa_signer()
        _pub = _bfa_signer()
        _f1 = _bfa_decision('admit', [_m1, _m2], 1760000000)
        bfa_e2e.append(('one finalized decision',
                        _bfa_run([_bfa_event(_f1, _pub,
                                            nakama.DECISION_NOSTR_KIND())],
                                 _bfa_kf_path)))
        # the same core published as a draft (30111) and as finalized
        # (30110) merges into a single 成立済み record
        _f2 = _bfa_decision('admit', [_m1], 1760010000)
        bfa_e2e.append(('draft + finalized same core -> merged finalized',
                        _bfa_run([_bfa_event(_f2, _pub,
                                            nakama.DRAFT_NOSTR_KIND()),
                                  _bfa_event(_f2, _pub,
                                            nakama.DECISION_NOSTR_KIND())],
                                 _bfa_kf_path)))
        _exp = _bfa_decision('remove', [_m1], 1760020000,
                             expires_at=int(time.time()) - 100)
        bfa_e2e.append(('expired draft -> [期限切れ] marker',
                        _bfa_run([_bfa_event(_exp, _pub,
                                            nakama.DRAFT_NOSTR_KIND())],
                                 _bfa_kf_path)))
        _pol = _bfa_policy([_m1, _m2, _m3], 2)
        _pf = os.path.join(tmpd, 'policy.json')
        with open(_pf, 'w') as f:
            json.dump(_pol, f)
        _outd = os.path.join(tmpd, 'out')
        _g1 = _bfa_decision('admit', [_m1, _m2], 1760030000)
        _g2 = _bfa_decision('remove', [_m1], 1760040000)
        _g3 = _bfa_decision('policy-update', [_m1, _m2], 1760050000,
                            payload={'threshold': 2,
                                     'eligible': [m[1] for m in
                                                  (_m1, _m2, _m3)]})
        bfa_e2e.append(('policy + out -> two disclaimers, thresholds, save '
                        'and snapshot lines (incl. policy-update proposal)',
                        _bfa_run([_bfa_event(_g1, _pub,
                                            nakama.DECISION_NOSTR_KIND()),
                                  _bfa_event(_g2, _pub,
                                            nakama.DRAFT_NOSTR_KIND()),
                                  _bfa_event(_g3, _pub,
                                            nakama.DRAFT_NOSTR_KIND())],
                                 _bfa_kf_path, policy=_pf, out=_outd)))

    for name, rep in bfa_e2e:
        ok, errs, info = conform_board_fetch_all_report(rep)
        print(f'fetch-all-e2e/{name}: {"PASS" if ok else "FAIL"} '
              f'({"; ".join(info)})')
        for e in errs:
            print(f'    - {e}')
        bfa_fails += 0 if ok else 1

    # hand-crafted positives
    _bf_h, _bf_h2, _bf_h3 = 'ab' * 16, 'cd' * 16, 'ef' * 16
    _bf_dis1 = ('threshold 表示は取得できた決定に基づく暫定です'
                '（権威ある判定は board_read --governance）')
    _bf_dis2 = ('草案（回覧中）の threshold 表示は取得できた草案に基づく暫定です'
                '（草案は成立の証拠ではありません — 成立の公開宣言は kind 30110）')
    _bf_l1 = (f'[成立済み {_bf_h}] admit (created_at 2026-10-01, '
              'approvals 2 つ)')
    _bf_l2 = (f'[草案（回覧中） {_bf_h2}] remove (created_at 2026-10-02, '
              'approvals 1 つ)')
    _bf_f1 = ('5 件のイベントを取得: 有効 2 件、スキップ 1 件、マージ後 2 件')
    _bf_f0 = ('5 件のイベントを取得: 有効 1 件、スキップ 0 件、マージ後 1 件')
    _bf_e1 = ('0 件のイベントを取得: 有効な決定（30110/30111）はありませんでした'
              '（0 件をスキップ）')
    _bf_l1t = (f'[成立済み {_bf_h}] admit (created_at 2026-10-01, '
               'approvals 2 つ, threshold 2/3 充足)')
    _bf_l2t = (f'[草案（回覧中） {_bf_h2}] remove (created_at 2026-10-02, '
               'approvals 1 つ, 草案: threshold 1/3 不足)')
    _bf_l3t = (f'[草案（回覧中） {_bf_h3}] policy-update '
               '(created_at 2026-10-03, approvals 2 つ, '
               '草案: threshold 2/3 充足（成立可能 — board_decide_pub で成立公開）'
               '（現行規約の判定） — 提案値: threshold 2/5)')
    _bf_sv = (f'3 件の決定を /tmp/out/ に保存しました'
              '（board_read --governance --decisions / board_cosign に'
              'そのまま渡せます。fetch 時点のスナップショット — '
              '草案の approvals は増える可能性があります）')
    _bf_sn = ('fetch 時点の政策スナップショットを '
              '/tmp/out/policy-snapshot-123.json に保存しました'
              '（検証者はこのファイルを --policy に指定して threshold 判定を'
              '再現できます）')
    _bf_f2 = ('5 件のイベントを取得: 有効 3 件、スキップ 0 件、マージ後 3 件')

    bfa_pos = [
        ('empty report', _bf_e1 + '\n'),
        ('plain finalized', _bf_l1 + '\n' + _bf_f0 + '\n'),
        ('plain draft with expired marker',
         _bf_l2.replace('remove (created_at',
                        '[期限切れ] remove (created_at')
         + '\n' + _bf_f0 + '\n'),
        ('policy + all finalized',
         _bf_dis1 + '\n' + _bf_l1t + '\n' + _bf_f0 + '\n'),
        ('policy + mixed + save + snapshot',
         _bf_dis1 + '\n' + _bf_dis2 + '\n' + _bf_l1t + '\n' + _bf_l2t + '\n'
         + _bf_l3t + '\n' + _bf_f2 + '\n' + _bf_sv + '\n' + _bf_sn + '\n'),
        ('uppercase hex core',
         _bf_l1.replace(_bf_h, _bf_h.upper()) + '\n' + _bf_f0 + '\n'),
    ]

    for name, rep in bfa_pos:
        ok, errs, info = conform_board_fetch_all_report(rep)
        print(f'fetch-all/{name}: {"PASS" if ok else "FAIL"} '
              f'({"; ".join(info)})')
        for e in errs:
            print(f'    - {e}')
        bfa_fails += 0 if ok else 1

    # negatives — all must be rejected
    bfa_neg = []
    bfa_neg.append(('empty report', ''))
    bfa_neg.append(('empty line plus lines',
                    _bf_e1 + '\n' + _bf_l1 + '\n' + _bf_f1 + '\n'))
    bfa_neg.append(('[期限切れ] on finalized',
                    _bf_l1.replace('admit (created_at',
                                   '[期限切れ] admit (created_at')
                    + '\n' + _bf_f0 + '\n'))
    bfa_neg.append(('draft disclaimer without policy disclaimer',
                    _bf_dis2 + '\n' + _bf_l2t + '\n' + _bf_f0 + '\n'))
    bfa_neg.append(('draft records without draft disclaimer',
                    _bf_dis1 + '\n' + _bf_l2t + '\n' + _bf_f0 + '\n'))
    bfa_neg.append(('draft disclaimer but no draft records',
                    _bf_dis1 + '\n' + _bf_dis2 + '\n' + _bf_l1t + '\n'
                    + _bf_f0 + '\n'))
    bfa_neg.append(('threshold clause without disclaimer',
                    _bf_l1t + '\n' + _bf_f0 + '\n'))
    bfa_neg.append(('plain line under disclaimer',
                    _bf_dis1 + '\n' + _bf_l1 + '\n' + _bf_f0 + '\n'))
    bfa_neg.append(('draft threshold form on finalized',
                    _bf_dis1 + '\n'
                    + _bf_l1t.replace('threshold 2/3 充足',
                                      '草案: threshold 2/3 不足')
                    + '\n' + _bf_f0 + '\n'))
    bfa_neg.append(('plain threshold form on draft',
                    _bf_dis1 + '\n' + _bf_dis2 + '\n'
                    + _bf_l2t.replace('草案: threshold 1/3 不足',
                                      'threshold 1/3 不足')
                    + '\n' + _bf_f0 + '\n'))
    bfa_neg.append(('proposal clause on finalized',
                    _bf_dis1 + '\n'
                    + _bf_l1t.replace('threshold 2/3 充足',
                                      'threshold 2/3 充足'
                                      '（現行規約の判定） — 提案値: '
                                      'threshold 2/5')
                    + '\n' + _bf_f0 + '\n'))
    bfa_neg.append(('proposal clause on non-policy-update draft',
                    _bf_dis1 + '\n' + _bf_dis2 + '\n'
                    + _bf_l2t.replace('草案: threshold 1/3 不足',
                                      '草案: threshold 1/3 不足'
                                      '（現行規約の判定） — 提案値: '
                                      'threshold 1/5')
                    + '\n' + _bf_f0 + '\n'))
    bfa_neg.append(('proposed threshold numerator > denominator',
                    _bf_dis1 + '\n' + _bf_dis2 + '\n'
                    + _bf_l3t.replace('提案値: threshold 2/5',
                                      '提案値: threshold 6/5')
                    + '\n' + _bf_f0 + '\n'))
    bfa_neg.append(('duplicate core hash',
                    _bf_l1 + '\n' + _bf_l1 + '\n'
                    + '2 件のイベントを取得: 有効 2 件、スキップ 0 件、'
                      'マージ後 2 件\n'))
    bfa_neg.append(('unknown decision type',
                    _bf_l1.replace('admit', 'banish') + '\n'
                    + _bf_f0 + '\n'))
    bfa_neg.append(('invalid date',
                    _bf_l1.replace('2026-10-01', '2026-13-40') + '\n'
                    + _bf_f0 + '\n'))
    bfa_neg.append(('core not hex',
                    _bf_l1.replace(_bf_h, 'zz' * 16) + '\n'
                    + _bf_f0 + '\n'))
    bfa_neg.append(('approvals/threshold mismatch',
                    _bf_dis1 + '\n'
                    + _bf_l1t.replace('approvals 2 つ', 'approvals 3 つ')
                    + '\n' + _bf_f0 + '\n'))
    bfa_neg.append(('threshold numerator > denominator',
                    _bf_dis1 + '\n' + _bf_l1t.replace('2/3', '6/3') + '\n'
                    + _bf_f0 + '\n'))
    bfa_neg.append(('decide-fetch style line (no state tag)',
                    _bf_l1.replace('[成立済み ', '[') + '\n'
                    + _bf_f0 + '\n'))
    bfa_neg.append(('footer merged count mismatch',
                    _bf_l1 + '\n' + _bf_f0.replace('マージ後 1 件',
                                                    'マージ後 2 件') + '\n'))
    bfa_neg.append(('missing footer', _bf_l1 + '\n'))
    bfa_neg.append(('trailing garbage', _bf_l1 + '\n' + _bf_f0 + '\n'
                    + 'unexpected\n'))
    bfa_neg.append(('snapshot without save line',
                    _bf_dis1 + '\n' + _bf_dis2 + '\n' + _bf_l1t + '\n'
                    + _bf_l2t + '\n' + _bf_f1 + '\n' + _bf_sn + '\n'))

    for name, rep in bfa_neg:
        ok, errs, info = conform_board_fetch_all_report(rep)
        good = not ok
        print(f'fetch-all-negative/{name}: '
              f'{"PASS (rejected)" if good else "FAIL (accepted!)"}')
        if not good:
            bfa_fails += 1

    bfa_total = len(bfa_e2e) + len(bfa_pos) + len(bfa_neg)
    print(f'--- fetch-all {bfa_total - bfa_fails}/{bfa_total} passed ---')
    fails += bfa_fails

    # ---------- check_pub: publish-result line consistency ----------
    # Reference reports are produced in-process with nakama.py's own
    # cmd_rotate_pub / cmd_revoke_pub / cmd_compromise_pub / cmd_dm_pub /
    # cmd_board_decide_pub / cmd_board_draft_pub, with nostr_publish
    # monkeypatched to return crafted (accepted, reason) pairs (no relay
    # contact); hand-mutated reports that break the single-line grammar
    # must be rejected.
    import io
    import contextlib
    import tempfile
    from types import SimpleNamespace

    pub_fails = 0
    _pub_now = int(time.time())

    def _pub_signer():
        s = secrets.token_bytes(32)
        return (s, nakama.npub_of(s))

    _pub_relay = 'wss://example.invalid'

    def _pub_kf(tmpd, secret):
        kf = os.path.join(tmpd, 'k.json')
        with open(kf, 'w') as f:
            json.dump({'secret_hex': secret.hex()}, f)
        os.chmod(kf, 0o600)
        return kf

    def _pub_run(cmd, args, accepted, reason):
        orig = nakama.nostr_publish
        nakama.nostr_publish = lambda *a, **k: (accepted, reason)
        code = None
        try:
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf), \
                    contextlib.redirect_stderr(io.StringIO()):
                try:
                    cmd(args)
                except SystemExit as e:
                    code = e.code
            return buf.getvalue(), code
        finally:
            nakama.nostr_publish = orig

    pub_e2e = []
    with tempfile.TemporaryDirectory() as tmpd:
        _s_old, _np_old = _pub_signer()
        _s_new, _np_new = _pub_signer()
        _s_sub, _np_sub = _pub_signer()
        _pub_kf_path = _pub_kf(tmpd, _s_old)

        _rot = {'protocol': 'nakama', 'version': 1, 'type': 'rotation',
                'old_npub': _np_old, 'new_npub': _np_new,
                'created_at': _pub_now, 'reason': 'selftest rotation'}
        _rot['old_sig'] = nakama.sign_schnorr(
            _s_old,
            nakama.rotation_message(_np_old, _np_new, _pub_now)).hex()
        _rot_path = os.path.join(tmpd, 'rotation.json')
        with open(_rot_path, 'w') as f:
            json.dump(_rot, f)

        _bh = 'ab' * 32
        _rev_msg = nakama.revocation_message(_bh, _np_old, _pub_now,
                                             'selftest revoke')
        _rev = {'protocol': 'nakama', 'version': 1, 'type': 'revocation',
                'bond_hash': _bh, 'revoker': _np_old, 'created_at': _pub_now,
                'reason': 'selftest revoke',
                'sig': nakama.sign_schnorr(_s_old, _rev_msg).hex()}
        _rev_path = os.path.join(tmpd, 'revocation.json')
        with open(_rev_path, 'w') as f:
            json.dump(_rev, f)

        _decl = nakama.build_compromise_declaration(
            _s_old, _np_sub, _pub_now, reason='selftest compromise')
        _decl_path = os.path.join(tmpd, 'decl.json')
        with open(_decl_path, 'w') as f:
            json.dump(_decl, f)

        _wrap = {'id': 'cd' * 32, 'kind': 1059, 'content': 'x'}
        _wrap_path = os.path.join(tmpd, 'wrap.json')
        with open(_wrap_path, 'w') as f:
            json.dump(_wrap, f)

        _dec = {'protocol': 'nakama', 'version': 1,
                'type': 'board-decision', 'board_id': 'pub-board-001',
                'relay': _pub_relay, 'decision': 'admit',
                'payload': {'candidate': _np_sub},
                'proposer_npub': _np_old, 'approvals': [],
                'publisher_npub': _np_old, 'created_at': _pub_now}
        _dec_path = os.path.join(tmpd, 'decision.json')
        with open(_dec_path, 'w') as f:
            json.dump(_dec, f)

        _pub_cases = [
            ('rotate_pub accepted', nakama.cmd_rotate_pub,
             SimpleNamespace(relay=_pub_relay, rotation=_rot_path,
                             auth=False, keyfile=_pub_kf_path),
             True, 'test-accepted', 0),
            ('revoke_pub accepted', nakama.cmd_revoke_pub,
             SimpleNamespace(relay=_pub_relay, revocation=_rev_path,
                             auth=False, keyfile=_pub_kf_path),
             True, 'test-accepted', 0),
            ('compromise_pub accepted', nakama.cmd_compromise_pub,
             SimpleNamespace(relay=_pub_relay, declaration=_decl_path,
                             auth=False, keyfile=_pub_kf_path),
             True, 'test-accepted', 0),
            ('dm_pub accepted', nakama.cmd_dm_pub,
             SimpleNamespace(relay=_pub_relay, in_file=_wrap_path,
                             to_npub=None, message=None,
                             auth=False, keyfile=_pub_kf_path),
             True, 'test-accepted', 0),
            ('board_decide_pub accepted', nakama.cmd_board_decide_pub,
             SimpleNamespace(relay=_pub_relay, decision=_dec_path,
                             auth=False, keyfile=_pub_kf_path),
             True, 'test-accepted', 0),
            ('board_draft_pub accepted', nakama.cmd_board_draft_pub,
             SimpleNamespace(relay=_pub_relay, draft=_dec_path,
                             auth=False, keyfile=_pub_kf_path),
             True, 'test-accepted', 0),
            ('dm_pub rejected', nakama.cmd_dm_pub,
             SimpleNamespace(relay=_pub_relay, in_file=_wrap_path,
                             to_npub=None, message=None,
                             auth=False, keyfile=_pub_kf_path),
             False, 'blocked: relay policy test', 1),
            ('revoke_pub rejected', nakama.cmd_revoke_pub,
             SimpleNamespace(relay=_pub_relay, revocation=_rev_path,
                             auth=False, keyfile=_pub_kf_path),
             False, 'blocked: relay policy test', 1),
        ]
        for name, cmd, args, accepted, reason, exp_code in _pub_cases:
            text, code = _pub_run(cmd, args, accepted, reason)
            ok, errs, info = conform_pub_report(text)
            good = ok and code == exp_code and \
                (('受理' in info[0]) == accepted if ok else False)
            print(f'check_pub e2e {name}: {"PASS" if good else "FAIL"}')
            for e in errs:
                print(f'    - {e}')
            if not good and ok:
                print(f'    - exit={code} (expected {exp_code})')
            pub_fails += 0 if good else 1
            pub_e2e.append(name)

    pub_pos = [
        ('accept minimal', 'publish: 受理 (accepted) id=' + 'ab' * 32),
        ('reject', 'publish: 拒否 (blocked: auth-required) id=' + 'cd' * 32),
        ('uppercase id', 'publish: 受理 (ok) id=' + 'AB' * 32),
        ('reason with parens',
         'publish: 受理 (duplicate: (seen)) id=' + 'ef' * 32),
        ('reason japanese',
         'publish: 拒否 (リレーからの OK 応答がありませんでした) id='
         + '12' * 32),
        ('empty reason', 'publish: 受理 () id=' + '34' * 32),
        ('trailing newline', 'publish: 受理 (ok) id=' + '56' * 32 + '\n'),
    ]
    for name, text in pub_pos:
        ok, errs, _info = conform_pub_report(text)
        print(f'check_pub pos {name}: {"PASS" if ok else "FAIL"}')
        for e in errs:
            print(f'    - {e}')
        pub_fails += 0 if ok else 1

    _pid = 'ab' * 32
    pub_neg = [
        ('empty text', ''),
        ('blank text', '\n'),
        ('two lines', f'publish: 受理 (ok) id={_pid}\nextra'),
        ('wrong verdict word', f'publish: 送信 (ok) id={_pid}'),
        ('english verdict', f'publish: accepted (ok) id={_pid}'),
        ('missing colon', f'publish 受理 (ok) id={_pid}'),
        ('missing space after colon', f'publish:受理 (ok) id={_pid}'),
        ('no parens', f'publish: 受理 ok id={_pid}'),
        ('id short', f'publish: 受理 (ok) id={"ab" * 31}'),
        ('id long', f'publish: 受理 (ok) id={"ab" * 32}ab'),
        ('id not hex', f'publish: 受理 (ok) id={"zz" * 32}'),
        ('no id part', 'publish: 受理 (ok)'),
        ('trailing space', f'publish: 受理 (ok) id={_pid} '),
        ('leading garbage', f'note\npublish: 受理 (ok) id={_pid}'),
        ('board_create line shape', 'kind 9002: 受理 (ok)'),
    ]
    for name, text in pub_neg:
        ok, _errs, _info = conform_pub_report(text)
        good = not ok
        print(f'check_pub neg {name}: {"PASS" if good else "FAIL"}')
        pub_fails += 0 if good else 1

    pub_total = len(pub_e2e) + len(pub_pos) + len(pub_neg)
    print(f'--- pub {pub_total - pub_fails}/{pub_total} passed ---')
    fails += pub_fails

    # ---------- check_governance: governance report consistency ----------
    # Reference reports are produced in-process with nakama.py's own
    # cmd_board_governance, with nostr_request monkeypatched to return
    # in-process-signed management events (no relay contact); hand-mutated
    # reports that break the fixed display grammar (spec §9.5) must be
    # rejected.
    gov_fails = 0
    _gov_now = int(time.time())

    def _gov_signer():
        s = secrets.token_bytes(32)
        return (s, nakama.npub_of(s), nakama.hexpub_of(s))

    _gov_relay = 'wss://example.invalid'
    _gov_board = 'gov-selftest-board'

    def _gov_run(tmpd, pol_path, dec_dir, events):
        orig = nakama.nostr_request
        nakama.nostr_request = lambda *a, **k: events
        code = None
        try:
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf), \
                    contextlib.redirect_stderr(io.StringIO()):
                try:
                    nakama.cmd_board_governance(SimpleNamespace(
                        governance=pol_path, decisions=[dec_dir],
                        board_id=_gov_board, relay=_gov_relay,
                        limit=20, since=None, auth=False, keyfile=None))
                except SystemExit as e:
                    code = e.code
            return buf.getvalue(), code
        finally:
            nakama.nostr_request = orig

    _gov_ts = '2026-10-01 09:00:00'
    _gov_pub = 'ab' * 8
    _gov_sub = 'cd' * 8
    gov_e2e = []
    with tempfile.TemporaryDirectory() as tmpd:
        _gA, _gB, _gC, _gD, _gE, _gF = [_gov_signer() for _ in range(6)]
        _gpm = nakama.board_policy_message(
            _gov_board, _gov_relay, 2, [_gA[1], _gB[1], _gC[1]], _gov_now)
        _gpol = {'protocol': 'nakama', 'version': 1,
                 'type': 'board-policy', 'board_id': _gov_board,
                 'relay': _gov_relay, 'threshold': 2,
                 'eligible': [_gA[1], _gB[1], _gC[1]], 'created_at': _gov_now,
                 'signatures': [{'npub': m[1],
                                 'sig': nakama.sign_schnorr(m[0], _gpm).hex()}
                                for m in (_gA, _gB, _gC)]}
        _gpol_path = os.path.join(tmpd, 'policy.json')
        with open(_gpol_path, 'w') as f:
            json.dump(_gpol, f)
        assert nakama.verify_board_policy_cert(_gpol), \
            'governance selftest policy invalid'
        _gdm = nakama.board_decision_message(
            _gov_board, _gov_relay, 'admit', {'candidate': _gD[1]}, _gov_now)
        _gdec = {'protocol': 'nakama', 'version': 1,
                 'type': 'board-decision', 'board_id': _gov_board,
                 'relay': _gov_relay, 'decision': 'admit',
                 'payload': {'candidate': _gD[1]}, 'created_at': _gov_now,
                 'approvals': [{'npub': m[1],
                                'sig': nakama.sign_schnorr(m[0], _gdm).hex()}
                               for m in (_gA, _gB)]}
        _gdec_dir = os.path.join(tmpd, 'decisions')
        os.mkdir(_gdec_dir)
        with open(os.path.join(_gdec_dir, 'admit.json'), 'w') as f:
            json.dump(_gdec, f)

        _gev_ok = nakama.sign_event(_gA[0], _gov_now, 9000,
                                    [['p', _gD[2]]], 'add D')
        _gev_warn = nakama.sign_event(_gE[0], _gov_now, 9000,
                                      [['p', _gF[2]]], 'add F no decision')
        _gev_info = nakama.sign_event(_gF[0], _gov_now, 9007,
                                      [['p', _gA[2]]], 'request join')
        _gev_badsig = nakama.sign_event(_gA[0], _gov_now, 9001,
                                        [['p', _gE[2]]], 'remove E')
        _gev_badsig['sig'] = '00' * 64
        _gev_leave = nakama.sign_event(_gF[0], _gov_now, 9008,
                                       [['p', _gF[2]]], 'leave')
        for name, events, exp_code in (
                ('mixed 4 blocks + invalid-sig',
                 [_gev_ok, _gev_warn, _gev_info, _gev_badsig, _gev_leave], 1),
                ('empty events', [], 0)):
            text, code = _gov_run(tmpd, _gpol_path, _gdec_dir, events)
            ok, errs, info = conform_governance_report(text)
            good = ok and code == exp_code
            print(f'check_governance e2e {name}: '
                  f'{"PASS" if good else "FAIL"}')
            for e in errs:
                print(f'    - {e}')
            if not good and ok:
                print(f'    - exit={code} (expected {exp_code})')
            gov_fails += 0 if good else 1
            gov_e2e.append(name)

    def _gov_block(mark, kind, name, subject=_gov_sub, ts=_gov_ts,
                   detail=('detail text',), issuer=_gov_pub):
        subj = f'{subject}...' if subject != '?' else '?...'
        lines = [f'--- [{ts}] kind {kind} ({name}) 発行: {issuer}... '
                 f'対象: {subj} [{mark}]']
        lines.extend(f'    {d}' for d in detail)
        return lines

    _gov_h1 = f'ガバナンス照合: {_gov_board} @ {_gov_relay}'
    _gov_h2 = '規約: eligible 3 名、threshold 2、決定 1 件を読み込み'
    gov_pos = [
        ('empty events', [_gov_h1, _gov_h2,
                          '管理イベント 0 件中、要確認 0 件']),
        ('single ok uppercase', [_gov_h1, _gov_h2]
         + _gov_block('OK', 9000, 'Add User', issuer='AB' * 8)
         + ['管理イベント 1 件中、要確認 0 件']),
        ('unknown subject', [_gov_h1, _gov_h2]
         + _gov_block('警告', 9001, 'Remove User', subject='?')
         + ['管理イベント 1 件中、要確認 1 件']),
        ('unknown kind fallback', [_gov_h1, _gov_h2]
         + _gov_block('警告', 9050, 'kind 9050')
         + ['管理イベント 1 件中、要確認 1 件']),
        ('multi-line detail', [_gov_h1, _gov_h2]
         + _gov_block('情報', 9007, 'Join Request',
                      detail=('line one', 'line two'))
         + ['管理イベント 1 件中、要確認 0 件']),
        ('mixed marks', [_gov_h1, _gov_h2]
         + _gov_block('OK', 9008, 'Leave Group')
         + _gov_block('署名無効', 9003, 'Edit Group')
         + _gov_block('情報', 9007, 'Join Request')
         + ['管理イベント 3 件中、要確認 1 件']),
    ]
    for name, lines in gov_pos:
        ok, errs, _info = conform_governance_report('\n'.join(lines) + '\n')
        print(f'check_governance pos {name}: {"PASS" if ok else "FAIL"}')
        for e in errs:
            print(f'    - {e}')
        gov_fails += 0 if ok else 1

    gov_neg = [
        ('empty text', []),
        ('broken header', ['governance', _gov_h2,
                           '管理イベント 0 件中、要確認 0 件']),
        ('policy eligible 0', [_gov_h1,
                               '規約: eligible 0 名、threshold 2、'
                               '決定 1 件を読み込み',
                               '管理イベント 0 件中、要確認 0 件']),
        ('event line not matching', [_gov_h1, _gov_h2, 'bogus line',
                                     '管理イベント 0 件中、要確認 0 件']),
        ('no detail lines', [_gov_h1, _gov_h2]
         + _gov_block('OK', 9000, 'Add User', detail=())
         + ['管理イベント 1 件中、要確認 0 件']),
        ('detail not indented', [_gov_h1, _gov_h2,
                                 f'--- [{_gov_ts}] kind 9000 (Add User) '
                                 f'発行: {_gov_pub}... 対象: {_gov_sub}... '
                                 '[OK]',
                                 'detail without indent',
                                 '管理イベント 1 件中、要確認 0 件']),
        ('footer event count mismatch', [_gov_h1, _gov_h2]
         + _gov_block('OK', 9000, 'Add User')
         + ['管理イベント 2 件中、要確認 0 件']),
        ('footer warn count mismatch', [_gov_h1, _gov_h2]
         + _gov_block('警告', 9000, 'Add User')
         + ['管理イベント 1 件中、要確認 0 件']),
        ('warn > event count', [_gov_h1, _gov_h2,
                                '管理イベント 0 件中、要確認 1 件']),
        ('missing footer', [_gov_h1, _gov_h2]
         + _gov_block('OK', 9000, 'Add User')),
        ('footer not last', [_gov_h1, _gov_h2,
                             '管理イベント 0 件中、要確認 0 件',
                             'trailing garbage']),
        ('invalid timestamp', [_gov_h1, _gov_h2]
         + _gov_block('OK', 9000, 'Add User', ts='2026-13-40 99:99:99')
         + ['管理イベント 1 件中、要確認 0 件']),
        ('wrong verdict word', [_gov_h1, _gov_h2]
         + _gov_block('VALID', 9000, 'Add User')
         + ['管理イベント 1 件中、要確認 0 件']),
        ('wrong kind name', [_gov_h1, _gov_h2]
         + _gov_block('OK', 9000, 'Remove User')
         + ['管理イベント 1 件中、要確認 0 件']),
        ('unknown kind wrong fallback', [_gov_h1, _gov_h2]
         + _gov_block('警告', 9050, 'Mystery Kind')
         + ['管理イベント 1 件中、要確認 1 件']),
        ('subject hex short', [_gov_h1, _gov_h2]
         + _gov_block('OK', 9000, 'Add User', subject='ab' * 7)
         + ['管理イベント 1 件中、要確認 0 件']),
        ('issuer not hex', [_gov_h1, _gov_h2]
         + _gov_block('OK', 9000, 'Add User', issuer='zz' * 8)
         + ['管理イベント 1 件中、要確認 0 件']),
        ('single footer without events line', [_gov_h1, _gov_h2,
                                               '管理イベント 0 件']),
    ]
    for name, lines in gov_neg:
        text = '\n'.join(lines) + ('\n' if lines else '')
        ok, _errs, _info = conform_governance_report(text)
        good = not ok
        print(f'check_governance neg {name}: {"PASS" if good else "FAIL"}')
        gov_fails += 0 if good else 1

    gov_total = len(gov_e2e) + len(gov_pos) + len(gov_neg)
    print(f'--- governance {gov_total - gov_fails}/{gov_total} passed ---')
    fails += gov_fails

    # ---------- check_revoke_fetch: revoke_fetch report consistency ----------
    # Reference reports are produced in-process with nakama.py's own
    # cmd_revoke_fetch, with nostr_request monkeypatched to return
    # in-process-signed revocation events (no relay contact); hand-mutated
    # reports that break the fixed display grammar (spec §12.4) or the
    # take-line/footer count consistency must be rejected.
    rf_fails = 0
    _rf_now = int(time.time())

    def _rf_keyfile(secret, tmpd, name):
        kf = os.path.join(tmpd, name)
        with open(kf, 'w') as f:
            json.dump({'secret_hex': secret.hex()}, f)
        os.chmod(kf, 0o600)
        return kf

    def _rf_rev(secret, bond_hash, created_at, reason=''):
        npub = nakama.npub_of(secret)
        rev = {'protocol': 'nakama', 'version': 1, 'type': 'revocation',
               'bond_hash': bond_hash, 'revoker': npub,
               'created_at': created_at,
               'sig': nakama.sign_schnorr(
                   secret, nakama.revocation_message(
                       bond_hash, npub, created_at, reason)).hex()}
        if reason:
            rev['reason'] = reason
        return nakama.revocation_nostr_event(rev, secret)

    def _rf_run(tmpd, bond_hash, keyfile, events):
        orig = nakama.nostr_request
        nakama.nostr_request = lambda *a, **k: events
        try:
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf), \
                    contextlib.redirect_stderr(io.StringIO()):
                nakama.cmd_revoke_fetch(SimpleNamespace(
                    relay='wss://example.invalid', bond_hash=bond_hash,
                    limit=20, auth=False,
                    registry=os.path.join(tmpd, 'revocations'),
                    keyfile=keyfile))
            return buf.getvalue()
        finally:
            nakama.nostr_request = orig

    _rf_bh = 'ab' * 32
    rf_e2e = []
    with tempfile.TemporaryDirectory() as tmpd:
        _rsA, _npA = _key()
        _kf = _rf_keyfile(_rsA, tmpd, 'a.json')
        _ev1 = _rf_rev(_rsA, _rf_bh, _rf_now)
        _ev_dup = json.loads(json.dumps(_ev1))  # same bond -> duplicate
        _ev_badsig = json.loads(json.dumps(_ev1))
        _ev_badsig['sig'] = '00' * 64
        _ev_other = _rf_rev(_rsA, 'cd' * 32, _rf_now)  # bond mismatch
        _rf_take = (f'取り込み: revocation を registry に記録しました '
                    f'(bond {_rf_bh[:16]}..., revoker {_npA[:16]}...)\n')
        for name, events, exp in (
                ('1 stored + 3 skipped (bad sig, bond mismatch, duplicate)',
                 [_ev1, _ev_dup, _ev_badsig, _ev_other],
                 _rf_take
                 + '4 件のイベントを取得: 1 件を取り込み、3 件をスキップ\n'),
                ('empty events', [],
                 '0 件のイベントを取得: 0 件を取り込み、0 件をスキップ\n')):
            text = _rf_run(tmpd, _rf_bh, _kf, events)
            ok, errs, info = conform_revoke_fetch_report(text)
            good = ok and text == exp
            print(f'check_revoke_fetch e2e {name}: '
                  f'{"PASS" if good else "FAIL"}')
            for e in errs:
                print(f'    - {e}')
            if not good and not errs:
                print(f'    - stdout mismatch: {text!r} '
                      f'(expected {exp!r})')
            rf_fails += 0 if good else 1
            rf_e2e.append(name)

    _rf_bh1, _rf_bh2 = 'ab' * 8, 'cd' * 8
    _, _rf_np1 = _key()
    _, _rf_np2 = _key()
    _rf_foot1 = '1 件のイベントを取得: 1 件を取り込み、0 件をスキップ'
    rf_pos = [
        ('empty events',
         '0 件のイベントを取得: 0 件を取り込み、0 件をスキップ\n'),
        ('one take',
         f'取り込み: revocation を registry に記録しました '
         f'(bond {_rf_bh1}..., revoker {_rf_np1[:16]}...)\n{_rf_foot1}\n'),
        ('uppercase bond hex',
         f'取り込み: revocation を registry に記録しました '
         f'(bond {(_rf_bh1).upper()}..., revoker {_rf_np1[:16]}...)\n'
         f'{_rf_foot1}\n'),
        ('two takes consistent',
         f'取り込み: revocation を registry に記録しました '
         f'(bond {_rf_bh1}..., revoker {_rf_np1[:16]}...)\n'
         f'取り込み: revocation を registry に記録しました '
         f'(bond {_rf_bh2}..., revoker {_rf_np2[:16]}...)\n'
         '3 件のイベントを取得: 2 件を取り込み、1 件をスキップ\n'),
    ]
    for name, rep in rf_pos:
        ok, errs, info = conform_revoke_fetch_report(rep)
        print(f'check_revoke_fetch pos {name}: {"PASS" if ok else "FAIL"} '
              f'({"; ".join(info)})')
        for e in errs:
            print(f'    - {e}')
        rf_fails += 0 if ok else 1

    _rf_one = (f'取り込み: revocation を registry に記録しました '
               f'(bond {_rf_bh1}..., revoker {_rf_np1[:16]}...)\n')
    rf_neg = [
        ('empty text', ''),
        ('broken footer', _rf_one + 'garbage line\n'),
        ('stray line before footer', 'note line\n' + _rf_one + _rf_foot1 + '\n'),
        ('take count != stored',
         _rf_one + _rf_one + _rf_foot1 + '\n'),
        ('counts do not add up',
         _rf_one + '2 件のイベントを取得: 1 件を取り込み、0 件をスキップ\n'),
        ('bond prefix not hex',
         _rf_one.replace(_rf_bh1, 'zz' * 8, 1) + _rf_foot1 + '\n'),
        ('bond prefix short',
         _rf_one.replace(_rf_bh1, 'ab' * 7 + 'a', 1) + _rf_foot1 + '\n'),
        ('revoker prefix short',
         _rf_one.replace(_rf_np1[:16], _rf_np1[:15], 1) + _rf_foot1 + '\n'),
        ('footer not last', _rf_foot1 + '\ntrailing garbage\n'),
        ('missing footer', _rf_one),
        ('missing ellipsis on bond',
         _rf_one.replace(f'{_rf_bh1}...', _rf_bh1, 1) + _rf_foot1 + '\n'),
        ('blank line inside body',
         _rf_one + '\n' + _rf_foot1 + '\n'),
    ]
    for name, rep in rf_neg:
        ok, _errs, _info = conform_revoke_fetch_report(rep)
        good = not ok
        print(f'check_revoke_fetch neg {name}: '
              f'{"PASS" if good else "FAIL"}')
        rf_fails += 0 if good else 1

    rf_total = len(rf_e2e) + len(rf_pos) + len(rf_neg)
    print(f'--- revoke-fetch {rf_total - rf_fails}/{rf_total} passed ---')
    fails += rf_fails

    # ---------- check_rotate_fetch: rotate_fetch report consistency ----------
    # Reference reports are produced in-process with nakama.py's own
    # cmd_rotate_fetch, with nostr_request monkeypatched to return
    # in-process-signed rotation events (no relay contact); hand-mutated
    # reports that break the fixed display grammar (spec §17.9) or the
    # link/footer/index consistency must be rejected.
    rtf_fails = 0
    _rtf_now = int(time.time())

    def _rtf_keyfile(secret, tmpd, name):
        kf = os.path.join(tmpd, name)
        with open(kf, 'w') as f:
            json.dump({'secret_hex': secret.hex()}, f)
        os.chmod(kf, 0o600)
        return kf

    def _rtf_rot(old_secret, new_npub, created_at):
        old_npub = nakama.npub_of(old_secret)
        rot = {'protocol': 'nakama', 'version': 1, 'type': 'rotation',
               'old_npub': old_npub, 'new_npub': new_npub,
               'created_at': created_at,
               'old_sig': nakama.sign_schnorr(
                   old_secret,
                   nakama.rotation_message(old_npub, new_npub,
                                           created_at)).hex()}
        return nakama.rotation_nostr_event(rot, old_secret)

    def _rtf_run(tmpd, old_npub, keyfile, by_d, chain=False, out=None):
        orig = nakama.nostr_request

        def fake(*a, **k):
            target = a[1][2]['#d'][0]
            return by_d.get(target, [])

        nakama.nostr_request = fake
        try:
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf), \
                    contextlib.redirect_stderr(io.StringIO()):
                nakama.cmd_rotate_fetch(SimpleNamespace(
                    relay='wss://example.invalid', old_npub=old_npub,
                    limit=20, auth=False, out=out, chain=chain,
                    keyfile=keyfile))
            return buf.getvalue()
        finally:
            nakama.nostr_request = orig

    def _rtf_date(ts):
        return time.strftime('%Y-%m-%d', time.localtime(ts))

    rtf_e2e = []
    with tempfile.TemporaryDirectory() as tmpd:
        _rsA, _npA = _key()
        _rsB, _npB = _key()
        _rsC, _npC = _key()
        _kf = _rtf_keyfile(_rsA, tmpd, 'a.json')
        _ev_ok = _rtf_rot(_rsA, _npB, _rtf_now)
        _ev_badsig = json.loads(json.dumps(_ev_ok))
        _ev_badsig['sig'] = '00' * 64
        _ev_wrongd = _rtf_rot(_rsA, _npB, _rtf_now)
        _ev_wrongd['tags'] = [['d', 'ff' * 32]]
        _rtf_hexA = nakama.npub_to_hex(_npA)
        _rtf_hexB = nakama.npub_to_hex(_npB)
        _ev_b2c = _rtf_rot(_rsB, _npC, _rtf_now + 60)
        _rtf_by_d = {_rtf_hexA: [_ev_ok, _ev_badsig, _ev_wrongd],
                     _rtf_hexB: [_ev_b2c]}
        _rtf_link = (f'rotation 公開: {_npA[:16]}... → {_npB[:16]}... '
                     f'(created_at {_rtf_date(_rtf_now)})\n')
        _rtf_chain = (f'[0] {_npA[:16]}... → {_npB[:16]}... '
                      f'(created_at {_rtf_date(_rtf_now)})\n'
                      f'[1] {_npB[:16]}... → {_npC[:16]}... '
                      f'(created_at {_rtf_date(_rtf_now + 60)})\n')
        for name, old_npub, by_d, chain, out, exp in (
                ('1 valid + 2 skipped (bad Nostr sig, wrong d)',
                 _npA, _rtf_by_d, False, None,
                 _rtf_link
                 + '3 件のイベントを取得: 有効 1 件、スキップ 2 件\n'),
                ('empty events', _npA, {}, False, None,
                 '0 件のイベントを取得: 有効な rotation 公開はありませんでした'
                 '（0 件をスキップ）\n'),
                ('all skipped', _npA,
                 {_rtf_hexA: [_ev_badsig, _ev_wrongd]}, False, None,
                 '2 件のイベントを取得: 有効な rotation 公開はありませんでした'
                 '（2 件をスキップ）\n'),
                ('--chain two links', _npA, _rtf_by_d, True, None,
                 _rtf_chain),
                ('--chain empty', _npC, {}, True, None,
                 'rotation 公開イベントは見つかりませんでした\n'),
                ('--out saves rotation', _npA,
                 {_rtf_hexA: [_ev_ok]}, False,
                 os.path.join(tmpd, 'rotation.json'),
                 _rtf_link
                 + '1 件のイベントを取得: 有効 1 件、スキップ 0 件\n'
                 + f'rotation を {os.path.join(tmpd, "rotation.json")}'
                   f' に保存しました（mode 600）\n'),
                ('--chain --out saves latest', _npA, _rtf_by_d, True,
                 os.path.join(tmpd, 'chain.json'),
                 _rtf_chain
                 + f'最新の rotation を {os.path.join(tmpd, "chain.json")}'
                   f' に保存しました（mode 600）\n')):
            text = _rtf_run(tmpd, old_npub, _kf, by_d, chain=chain, out=out)
            ok, errs, info = conform_rotate_fetch_report(text)
            good = ok and text == exp
            if out and good:
                try:
                    good = (os.stat(out).st_mode & 0o777) == 0o600
                    if not good:
                        print(f'    - save file mode is not 600')
                except OSError as e:
                    good = False
                    print(f'    - save file missing: {e}')
            print(f'check_rotate_fetch e2e {name}: '
                  f'{"PASS" if good else "FAIL"}')
            for e in errs:
                print(f'    - {e}')
            if not good and not errs:
                print(f'    - stdout mismatch: {text!r} '
                      f'(expected {exp!r})')
            rtf_fails += 0 if good else 1
            rtf_e2e.append(name)

    _rtf_np1 = 'npub1' + 'a' * 58
    _rtf_np2 = 'npub1' + 'b' * 58
    _rtf_d = '2026-10-02'
    _rtf_link1 = (f'rotation 公開: {_rtf_np1[:16]}... → {_rtf_np2[:16]}... '
                  f'(created_at {_rtf_d})')
    _rtf_foot1 = '3 件のイベントを取得: 有効 1 件、スキップ 2 件'
    _rtf_chain1 = (f'[0] {_rtf_np1[:16]}... → {_rtf_np2[:16]}... '
                   f'(created_at {_rtf_d})')
    rtf_pos = [
        ('one valid + footer',
         f'{_rtf_link1}\n{_rtf_foot1}\n'),
        ('with save line',
         f'{_rtf_link1}\n{_rtf_foot1}\n'
         f'rotation を /tmp/rotation.json に保存しました（mode 600）\n'),
        ('empty single line',
         '0 件のイベントを取得: 有効な rotation 公開はありませんでした'
         '（0 件をスキップ）\n'),
        ('chain two links',
         f'[0] {_rtf_np1[:16]}... → {_rtf_np2[:16]}... '
         f'(created_at {_rtf_d})\n'
         f'[1] {_rtf_np2[:16]}... → {_rtf_np1[:16]}... '
         f'(created_at {_rtf_d})\n'),
        ('chain one link + latest save',
         f'{_rtf_chain1}\n'
         f'最新の rotation を /tmp/chain.json に保存しました（mode 600）\n'),
        ('chain empty',
         'rotation 公開イベントは見つかりませんでした\n'),
    ]
    rtf_neg = [
        ('missing ellipsis',
         _rtf_link1.replace('...', '..') + f'\n{_rtf_foot1}\n'),
        ('有効 2 件 (only 1 valid is shown)',
         f'{_rtf_link1}\n'
         f'3 件のイベントを取得: 有効 2 件、スキップ 2 件\n'),
        ('footer fetched 0 but rotation shown',
         f'{_rtf_link1}\n'
         f'0 件のイベントを取得: 有効 1 件、スキップ 0 件\n'),
        ('missing footer',
         f'{_rtf_link1}\n'),
        ('invalid date',
         f'rotation 公開: {_rtf_np1[:16]}... → {_rtf_np2[:16]}... '
         f'(created_at 2026-13-99)\n{_rtf_foot1}\n'),
        ('chain index skips (0, 2)',
         f'[0] {_rtf_np1[:16]}... → {_rtf_np2[:16]}... '
         f'(created_at {_rtf_d})\n'
         f'[2] {_rtf_np2[:16]}... → {_rtf_np1[:16]}... '
         f'(created_at {_rtf_d})\n'),
        ('chain index starts at 1',
         f'[1] {_rtf_np1[:16]}... → {_rtf_np2[:16]}... '
         f'(created_at {_rtf_d})\n'),
        ('empty line with link lines',
         '0 件のイベントを取得: 有効な rotation 公開はありませんでした'
         '（0 件をスキップ）\n'
         f'{_rtf_link1}\n'),
        ('trailing line after footer',
         f'{_rtf_link1}\n{_rtf_foot1}\n'
         f'rotation を /tmp/r.json に保存しました（mode 600）\n'
         f'余計な行\n'),
        ('chain save line without latest',
         f'{_rtf_chain1}\n'
         f'rotation を /tmp/r.json に保存しました（mode 600）\n'),
        ('garbage first line',
         'なんか違う出力\n'),
    ]
    for name, rep in rtf_pos:
        ok, errs, info = conform_rotate_fetch_report(rep)
        good = ok
        print(f'check_rotate_fetch pos {name}: {"PASS" if good else "FAIL"} '
              f'({"; ".join(info)})')
        for e in errs:
            print(f'    - {e}')
        rtf_fails += 0 if good else 1
    for name, rep in rtf_neg:
        ok, _errs, _info = conform_rotate_fetch_report(rep)
        good = not ok
        print(f'check_rotate_fetch neg {name}: '
              f'{"PASS" if good else "FAIL"}')
        if not good:
            print(f'    - report wrongly accepted')
        rtf_fails += 0 if good else 1
    rtf_total = len(rtf_e2e) + len(rtf_pos) + len(rtf_neg)
    print(f'--- rotate-fetch {rtf_total - rtf_fails}/{rtf_total} passed ---')
    fails += rtf_fails

    # ---------- check_compromise_fetch: compromise_fetch report consistency ----------
    # Reference reports are produced in-process with nakama.py's own
    # cmd_compromise_fetch, with nostr_request monkeypatched to return
    # in-process-signed compromise declarations (no relay contact);
    # hand-mutated reports that break the fixed display grammar
    # (spec §13.8) or the take/update/footer count consistency must be
    # rejected.
    cf_fails = 0
    _cf_now = int(time.time())

    def _cf_keyfile(secret, tmpd, name):
        kf = os.path.join(tmpd, name)
        with open(kf, 'w') as f:
            json.dump({'secret_hex': secret.hex()}, f)
        os.chmod(kf, 0o600)
        return kf

    def _cf_decl(secret, subject_npub, created_at, withdrawn=False):
        decl = nakama.build_compromise_declaration(
            secret, subject_npub, created_at, withdrawn)
        return nakama.compromise_nostr_event(decl, secret)

    def _cf_run(tmpd, slug, subject_npub, keyfile, events):
        orig = nakama.nostr_request
        nakama.nostr_request = lambda *a, **k: events
        try:
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf), \
                    contextlib.redirect_stderr(io.StringIO()):
                nakama.cmd_compromise_fetch(SimpleNamespace(
                    relay='wss://example.invalid', npub=subject_npub,
                    limit=20, auth=False,
                    registry=os.path.join(tmpd, 'compromises-' + slug),
                    keyfile=keyfile))
            return buf.getvalue()
        finally:
            nakama.nostr_request = orig

    cf_e2e = []
    with tempfile.TemporaryDirectory() as tmpd:
        _csA, _npA = _key()
        _csB, _npB = _key()
        _csS, _npS = _key()
        _csO, _npO = _key()
        _kf = _cf_keyfile(_csA, tmpd, 'a.json')
        _ev_ok = _cf_decl(_csA, _npS, _cf_now)
        _ev_dup = json.loads(json.dumps(_ev_ok))  # same declarant+created_at
        _ev_badsig = json.loads(json.dumps(_ev_ok))
        _ev_badsig['sig'] = '00' * 64
        _ev_withdrawn = _cf_decl(_csA, _npS, _cf_now, withdrawn=True)
        _ev_subj_mismatch = _cf_decl(_csB, _npO, _cf_now)
        _ev_subj_mismatch['tags'] = [
            ['d', f'{nakama.npub_to_hex(_npS)}:{nakama.npub_to_hex(_npB)}']]
        _hexS = nakama.npub_to_hex(_npS)
        _cf_takeA = (f'取り込み: 侵害宣言を registry に記録しました '
                     f'(subject {_hexS[:16]}..., declarant {_npA[:16]}...)\n')
        _cf_updA = (f'更新: 侵害宣言の撤回・復活を反映しました '
                    f'(declarant {_npA[:16]}...)\n')
        _cf_takeB = (f'取り込み: 侵害宣言を registry に記録しました '
                     f'(subject {_hexS[:16]}..., declarant {_npB[:16]}...)\n')
        for name, events, exp in (
                ('1 stored + 1 updated + 3 skipped '
                 '(bad sig, subject mismatch, duplicate)',
                 [_ev_ok, _ev_dup, _ev_badsig, _ev_subj_mismatch,
                  _ev_withdrawn],
                 _cf_takeA + _cf_updA
                 + '5 件のイベントを取得: 1 件を取り込み、1 件を更新、'
                   '3 件をスキップ\n'),
                ('1 stored, no updates',
                 [_ev_ok],
                 _cf_takeA
                 + '1 件のイベントを取得: 1 件を取り込み、0 件を更新、'
                   '0 件をスキップ\n'),
                ('two declarants stored',
                 [_ev_ok, _cf_decl(_csB, _npS, _cf_now + 1)],
                 _cf_takeA + _cf_takeB
                 + '2 件のイベントを取得: 2 件を取り込み、0 件を更新、'
                   '0 件をスキップ\n'),
                ('empty events', [],
                 '0 件のイベントを取得: 0 件を取り込み、0 件を更新、'
                 '0 件をスキップ\n')):
            text = _cf_run(tmpd, f'e2e{len(cf_e2e)}', _npS, _kf, events)
            ok, errs, info = conform_compromise_fetch_report(text)
            good = ok and text == exp
            print(f'check_compromise_fetch e2e {name}: '
                  f'{"PASS" if good else "FAIL"}')
            for e in errs:
                print(f'    - {e}')
            if not good and not errs:
                print(f'    - stdout mismatch: {text!r} '
                      f'(expected {exp!r})')
            cf_fails += 0 if good else 1
            cf_e2e.append(name)

    _cf_sub1 = 'ab' * 8
    _cf_np1 = 'npub1' + 'a' * 58
    _cf_np2 = 'npub1' + 'b' * 58
    _cf_foot0 = ('0 件のイベントを取得: 0 件を取り込み、0 件を更新、'
                 '0 件をスキップ')
    _cf_take1 = (f'取り込み: 侵害宣言を registry に記録しました '
                 f'(subject {_cf_sub1}..., declarant {_cf_np1[:16]}...)\n')
    _cf_upd1 = (f'更新: 侵害宣言の撤回・復活を反映しました '
                f'(declarant {_cf_np1[:16]}...)\n')
    _cf_foot1 = ('1 件のイベントを取得: 1 件を取り込み、0 件を更新、'
                 '0 件をスキップ')
    _cf_foot_tu = ('2 件のイベントを取得: 1 件を取り込み、1 件を更新、'
                   '0 件をスキップ')
    cf_pos = [
        ('empty events',
         f'{_cf_foot0}\n'),
        ('one take',
         f'{_cf_take1}{_cf_foot1}\n'),
        ('uppercase subject hex',
         f'{_cf_take1.replace(_cf_sub1, _cf_sub1.upper(), 1)}'
         f'{_cf_foot1}\n'),
        ('take + update',
         f'{_cf_take1}{_cf_upd1}{_cf_foot_tu}\n'),
        ('two takes consistent',
         f'{_cf_take1}'
         f'取り込み: 侵害宣言を registry に記録しました '
         f'(subject {"cd" * 8}..., declarant {_cf_np2[:16]}...)\n'
         f'3 件のイベントを取得: 2 件を取り込み、0 件を更新、'
         f'1 件をスキップ\n'),
    ]
    cf_neg = [
        ('empty text', ''),
        ('broken footer', _cf_take1 + 'garbage line\n'),
        ('stray line before footer',
         'note line\n' + _cf_take1 + _cf_foot1 + '\n'),
        ('take count != stored',
         _cf_take1 + _cf_take1 + _cf_foot1 + '\n'),
        ('update count != updated',
         _cf_take1 + _cf_upd1 + _cf_foot1 + '\n'),
        ('counts do not add up',
         _cf_take1 + '2 件のイベントを取得: 1 件を取り込み、0 件を更新、'
         '0 件をスキップ\n'),
        ('subject prefix not hex',
         _cf_take1.replace(_cf_sub1, 'zz' * 8, 1) + _cf_foot1 + '\n'),
        ('subject prefix short',
         _cf_take1.replace(_cf_sub1, 'ab' * 7 + 'a', 1) + _cf_foot1 + '\n'),
        ('declarant prefix short',
         _cf_take1.replace(_cf_np1[:16], _cf_np1[:15], 1) + _cf_foot1 + '\n'),
        ('footer not last', _cf_foot1 + '\ntrailing garbage\n'),
        ('missing footer', _cf_take1),
        ('missing ellipsis on subject',
         _cf_take1.replace(f'{_cf_sub1}...', _cf_sub1, 1) + _cf_foot1 + '\n'),
        ('blank line inside body',
         _cf_take1 + '\n' + _cf_foot1 + '\n'),
    ]
    for name, rep in cf_pos:
        ok, errs, info = conform_compromise_fetch_report(rep)
        good = ok
        print(f'check_compromise_fetch pos {name}: '
              f'{"PASS" if good else "FAIL"} ({"; ".join(info)})')
        for e in errs:
            print(f'    - {e}')
        cf_fails += 0 if good else 1
    for name, rep in cf_neg:
        ok, _errs, _info = conform_compromise_fetch_report(rep)
        good = not ok
        print(f'check_compromise_fetch neg {name}: '
              f'{"PASS" if good else "FAIL"}')
        if not good:
            print(f'    - report wrongly accepted')
        cf_fails += 0 if good else 1
    cf_total = len(cf_e2e) + len(cf_pos) + len(cf_neg)
    print(f'--- compromise-fetch {cf_total - cf_fails}/{cf_total} passed ---')
    fails += cf_fails

    # ---------- check_liveness_verify: verify_liveness report consistency ----------
    # Reference reports are produced in-process with nakama.py's own
    # cmd_verify_liveness, with time.time monkeypatched to a fixed now
    # (no key/network I/O beyond the local proof file and the revocation
    # registry); hand-mutated reports that break the fixed display
    # grammar (spec §5.6.2) or the single-line shape must be rejected.
    import unittest.mock
    lv_fails = 0
    _lv_now = 1759280000

    def _lv_proof(secret, npub, created_at, tmpd, name, bond_hash=None):
        nonce = secrets.token_hex(32)
        sig = nakama.sign_schnorr(
            secret, nakama.liveness_message(npub, created_at, nonce,
                                            bond_hash))
        p = {'protocol': 'nakama', 'version': 1, 'type': 'liveness',
             'npub': npub, 'created_at': created_at, 'nonce': nonce,
             'sig': sig.hex()}
        if bond_hash is not None:
            p['bond_hash'] = bond_hash
        fp = os.path.join(tmpd, name)
        with open(fp, 'w') as f:
            json.dump(p, f)
        return fp

    def _lv_run(tmpd, proof_path, max_age=7 * 86400, registry=None,
                skip_registry=False, bond=None):
        buf = io.StringIO()
        with unittest.mock.patch('time.time', return_value=_lv_now):
            try:
                with contextlib.redirect_stdout(buf), \
                        contextlib.redirect_stderr(io.StringIO()):
                    nakama.cmd_verify_liveness(SimpleNamespace(
                        proof=proof_path, bond=bond, max_age=max_age,
                        registry=registry, skip_registry=skip_registry))
                code = 0
            except SystemExit as e:
                code = e.code
        return buf.getvalue(), code

    lv_e2e = []
    with tempfile.TemporaryDirectory() as tmpd:
        _lsA, _lnA = _key()
        _ok_fp = _lv_proof(_lsA, _lnA, _lv_now - 42, tmpd, 'ok.json')
        _bad_fp = _lv_proof(_lsA, _lnA, _lv_now - 42, tmpd, 'bad.json')
        with open(_bad_fp) as f:
            _badp = json.load(f)
        _badp['sig'] = '00' * 64
        with open(_bad_fp, 'w') as f:
            json.dump(_badp, f)
        _fut_fp = _lv_proof(_lsA, _lnA, _lv_now + 301, tmpd, 'fut.json')
        _old_fp = _lv_proof(_lsA, _lnA, _lv_now - 10, tmpd, 'old.json')
        _bh = 'cd' * 32
        _rsig = nakama.sign_schnorr(
            _lsA, nakama.revocation_message(_bh, _lnA, _lv_now, ''))
        _rev = {'protocol': 'nakama', 'version': 1, 'type': 'revocation',
                'bond_hash': _bh, 'revoker': _lnA, 'created_at': _lv_now,
                'sig': _rsig.hex()}
        _reg = os.path.join(tmpd, 'revocations')
        os.makedirs(_reg)
        with open(nakama.revocation_registry_path(_reg, _bh), 'w') as f:
            json.dump(_rev, f)
        _rvk_fp = _lv_proof(_lsA, _lnA, _lv_now - 7, tmpd, 'rvk.json',
                            bond_hash=_bh)
        _ok_line = (f'生存証明は有効です — {_lnA[:16]}... が 42 秒前に'
                    f'鍵を保持していたことを確認。\n')
        for name, fp, kw, exp_text, exp_code in (
                ('valid proof',
                 _ok_fp, {}, _ok_line, 0),
                ('invalid signature',
                 _bad_fp, {}, '生存証明は無効です\n', 1),
                ('future timestamp',
                 _fut_fp, {},
                 '生存証明の日付が未来です'
                 '（時計のずれの許容範囲を超えています）\n', 1),
                ('too old',
                 _old_fp, {'max_age': 5},
                 '生存証明は古すぎます（10 秒前、許容 5 秒）\n', 1),
                ('revoked bond',
                 _rvk_fp, {'registry': _reg},
                 'bond は解消済みです — 生存証明は無効です\n', 1)):
            text, code = _lv_run(tmpd, fp, **kw)
            ok, errs, info = conform_liveness_verify_report(text)
            good = ok and text == exp_text and code == exp_code
            print(f'check_liveness_verify e2e {name}: '
                  f'{"PASS" if good else "FAIL"}')
            for e in errs:
                print(f'    - {e}')
            if not good and not errs:
                print(f'    - stdout/exit mismatch: {text!r} '
                      f'(exit {code}), expected {exp_text!r} '
                      f'(exit {exp_code})')
            lv_fails += 0 if good else 1
            lv_e2e.append(name)

    _lv_np = 'npub1' + 'a' * 58
    _lv_ok = (f'生存証明は有効です — {_lv_np[:16]}... が 42 秒前に'
              f'鍵を保持していたことを確認。\n')
    lv_pos = [
        ('valid report', _lv_ok),
        ('negative age (clock skew)',
         _lv_ok.replace('42 秒前', '-5 秒前', 1)),
        ('invalid signature', '生存証明は無効です\n'),
        ('future timestamp',
         '生存証明の日付が未来です（時計のずれの許容範囲を超えています）\n'),
        ('too old', '生存証明は古すぎます（10 秒前、許容 5 秒）\n'),
        ('revoked bond', 'bond は解消済みです — 生存証明は無効です\n'),
    ]
    lv_neg = [
        ('empty text', ''),
        ('two lines', _lv_ok + _lv_ok),
        ('missing ellipsis on npub',
         _lv_ok.replace(f'{_lv_np[:16]}...', _lv_np[:16], 1)),
        ('npub prefix short',
         _lv_ok.replace(_lv_np[:16], _lv_np[:15], 1)),
        ('npub prefix with space',
         _lv_ok.replace(_lv_np[:16], 'npub1abc defghi', 1)),
        ('age not numeric', _lv_ok.replace('42 秒前', 'たくさん 秒前', 1)),
        ('ascii hyphen instead of em dash',
         _lv_ok.replace(' — ', ' - ', 1)),
        ('unknown verdict line', '生存証明は不明です\n'),
        ('invalid line with extra', '生存証明は無効です（再確認）\n'),
        ('too-old missing max-age', '生存証明は古すぎます（10 秒前）\n'),
        ('future line truncated', '生存証明の日付が未来です\n'),
        ('trailing garbage', _lv_ok + 'trailing garbage\n'),
        ('blank line before report', '\n' + _lv_ok),
    ]
    for name, rep in lv_pos:
        ok, errs, info = conform_liveness_verify_report(rep)
        good = ok
        print(f'check_liveness_verify pos {name}: '
              f'{"PASS" if good else "FAIL"} ({"; ".join(info)})')
        for e in errs:
            print(f'    - {e}')
        lv_fails += 0 if good else 1
    for name, rep in lv_neg:
        ok, _errs, _info = conform_liveness_verify_report(rep)
        good = not ok
        print(f'check_liveness_verify neg {name}: '
              f'{"PASS" if good else "FAIL"}')
        if not good:
            print(f'    - report wrongly accepted')
        lv_fails += 0 if good else 1
    lv_total = len(lv_e2e) + len(lv_pos) + len(lv_neg)
    print(f'--- liveness-verify {lv_total - lv_fails}/{lv_total} passed ---')
    fails += lv_fails

    # ---------- check_liveness_report: liveness generation report consistency ----------
    # Reference reports are produced in-process with nakama.py's own
    # cmd_liveness (key/network-free: proof file + stdout only,
    # time.time monkeypatched for determinism); hand-mutated reports
    # that break the fixed display grammar (spec §5.6.3) or the
    # one/two-line shape must be rejected.
    lr_fails = 0
    _lr_now = 1759280000

    def _lr_run(tmpd, secret, bond=None, out=None):
        keyfile = os.path.join(tmpd, 'key.json')
        nakama.save_key(keyfile, secret)
        out = out or os.path.join(tmpd, 'liveness.json')
        buf = io.StringIO()
        code = 0
        with unittest.mock.patch('time.time', return_value=_lr_now):
            try:
                with contextlib.redirect_stdout(buf), \
                        contextlib.redirect_stderr(io.StringIO()):
                    nakama.cmd_liveness(SimpleNamespace(
                        keyfile=keyfile, bond=bond, out=out))
            except SystemExit as e:
                code = e.code
        return buf.getvalue(), code

    lr_e2e = []
    with tempfile.TemporaryDirectory() as tmpd:
        _lrs, _lrnp = _key()
        _lrs2, _lrnp2 = _key()
        # minimal bond file: cmd_liveness only checks protocol/version
        # and that the prover is a companion (bond_hash also needs
        # created_at/nonce)
        _bond = {'protocol': 'nakama', 'version': 1,
                 'companions': [_lrnp, _lrnp2],
                 'created_at': _lr_now, 'nonce': '00' * 32}
        _bond_fp = os.path.join(tmpd, 'bond.json')
        with open(_bond_fp, 'w') as f:
            json.dump(_bond, f)
        _bh = nakama.bond_hash(_bond)
        _solo_bond = {'protocol': 'nakama', 'version': 1,
                      'companions': [_lrnp2]}
        _solo_fp = os.path.join(tmpd, 'solo.json')
        with open(_solo_fp, 'w') as f:
            json.dump(_solo_bond, f)
        _o1 = os.path.join(tmpd, 'live1.json')
        _o2 = os.path.join(tmpd, 'live2.json')
        _o3 = os.path.join(tmpd, 'live3.json')
        _gen1 = (f'生存証明: {_o1} — {_lrnp[:16]}... '
                 f'が鍵を保持していることを宣言しました。\n')
        _gen2 = (f'生存証明: {_o2} — {_lrnp[:16]}... '
                 f'が鍵を保持していることを宣言しました。\n')
        _bnd2 = (f'bond {_bh[:16]}... に紐付けました。'
                 f'仲間に送って「まだここにいる」と伝えましょう。\n')
        for name, kw, exp_text, exp_code, exp_ok in (
                ('no bond', {'out': _o1}, _gen1, 0, True),
                ('with bond', {'bond': _bond_fp, 'out': _o2},
                 _gen1.replace(_o1, _o2) + _bnd2, 0, True),
                ('not a companion', {'bond': _solo_fp, 'out': _o3},
                 '', 1, False)):
            text, code = _lr_run(tmpd, _lrs, **kw)
            ok, errs, info = conform_liveness_report(text)
            good = (ok == exp_ok) and text == exp_text and code == exp_code
            print(f'check_liveness_report e2e {name}: '
                  f'{"PASS" if good else "FAIL"}')
            for e in errs:
                if exp_ok:
                    print(f'    - {e}')
            if not good and exp_ok and not errs:
                print(f'    - stdout/exit mismatch: {text!r} '
                      f'(exit {code}), expected {exp_text!r} '
                      f'(exit {exp_code})')
            lr_fails += 0 if good else 1
            lr_e2e.append(name)

    _lr_np = 'npub1' + 'a' * 58
    _lr_bh = 'cd' * 32
    _lr_gen = (f'生存証明: proof.json — {_lr_np[:16]}... '
               f'が鍵を保持していることを宣言しました。\n')
    _lr_bond = (f'bond {_lr_bh[:16]}... に紐付けました。'
                f'仲間に送って「まだここにいる」と伝えましょう。\n')
    lr_pos = [
        ('plain generation', _lr_gen),
        ('with bond linkage', _lr_gen + _lr_bond),
        ('out path with dirs', _lr_gen.replace(
            'proof.json', 'out/2026-10-02/liveness.json', 1)),
        ('trailing blank lines', _lr_gen + '\n\n'),
        ('bond linkage after blanks stripped',
         _lr_gen + _lr_bond + '\n'),
    ]
    lr_neg = [
        ('empty text', ''),
        ('two reports concatenated', _lr_gen + _lr_gen),
        ('generation plus bond plus extra line',
         _lr_gen + _lr_bond + 'ゴミ行\n'),
        ('missing ellipsis on npub',
         _lr_gen.replace(f'{_lr_np[:16]}...', _lr_np[:16], 1)),
        ('npub prefix short',
         _lr_gen.replace(_lr_np[:16], _lr_np[:15], 1)),
        ('npub prefix with space',
         _lr_gen.replace(_lr_np[:16], 'npub1abc defghi', 1)),
        ('ascii hyphen instead of em dash',
         _lr_gen.replace(' — ', ' - ', 1)),
        ('missing report prefix',
         _lr_gen.replace('生存証明: ', '', 1)),
        ('empty filename',
         _lr_gen.replace('生存証明: proof.json', '生存証明: ', 1)),
        ('bond line first (wrong order)', _lr_bond + _lr_gen),
        ('bond prefix non-hex',
         _lr_bond.replace(_lr_bh[:16], 'g' * 16, 1)),
        ('bond prefix short',
         _lr_bond.replace(_lr_bh[:16], _lr_bh[:15], 1)),
        ('bond line truncated',
         'bond ' + _lr_bh[:16] + '... に紐付けました。\n'),
        ('bond line with extra suffix',
         _lr_bond.replace('ましょう。', 'ましょう。（追記）', 1)),
        ('unknown second line', _lr_gen + '何かが起きました\n'),
        ('leading blank line', '\n' + _lr_gen),
    ]
    for name, rep in lr_pos:
        ok, errs, info = conform_liveness_report(rep)
        good = ok
        print(f'check_liveness_report pos {name}: '
              f'{"PASS" if good else "FAIL"} ({"; ".join(info)})')
        for e in errs:
            print(f'    - {e}')
        lr_fails += 0 if good else 1
    for name, rep in lr_neg:
        ok, _errs, _info = conform_liveness_report(rep)
        good = not ok
        print(f'check_liveness_report neg {name}: '
              f'{"PASS" if good else "FAIL"}')
        if not good:
            print(f'    - report wrongly accepted')
        lr_fails += 0 if good else 1
    lr_total = len(lr_e2e) + len(lr_pos) + len(lr_neg)
    print(f'--- liveness-report {lr_total - lr_fails}/{lr_total} passed ---')
    fails += lr_fails

    vb_fails = 0

    def _vb_run(tmpd, binding_dict, platform=None, handle=None,
                registry=None):
        bfp = os.path.join(tmpd, 'binding.json')
        with open(bfp, 'w') as f:
            json.dump(binding_dict, f, ensure_ascii=False)
        buf = io.StringIO()
        code = 0
        args = SimpleNamespace(binding=bfp, platform=platform,
                               handle=handle,
                               compromise_registry=registry or '')
        with contextlib.redirect_stdout(buf), \
                contextlib.redirect_stderr(io.StringIO()):
            try:
                nakama.cmd_verify_binding(args)
            except SystemExit as e:
                code = e.code
        return buf.getvalue(), code

    vb_e2e = []
    with tempfile.TemporaryDirectory() as tmpd:
        _vbs, _vbnp = _key()
        _vb_time = 1759280000
        _msg = nakama.binding_message('moltbook', 'alex', _vbnp, _vb_time)
        _binding = {'protocol': 'nakama', 'version': 1,
                    'type': 'platform-binding',
                    'platform': 'moltbook', 'handle': 'alex',
                    'npub': _vbnp, 'created_at': _vb_time,
                    'sig': nakama.sign_schnorr(_vbs, _msg).hex()}
        _valid = (_VB_VALID + '\n' + _VB_NOTE + '\n')
        _invalid = (_VB_INVALID + '\n')
        _tampered = dict(_binding, handle='someone_else')
        for name, kw, exp_text, exp_code, exp_ok in (
                ('valid minimal', {'binding_dict': _binding},
                 _valid, 0, True),
                ('valid with platform/handle match',
                 {'binding_dict': _binding, 'platform': 'moltbook',
                  'handle': 'alex'}, _valid, 0, True),
                ('tampered handle (invalid)',
                 {'binding_dict': _tampered}, _invalid, 1, True),
                ('platform mismatch (stderr warn, invalid)',
                 {'binding_dict': _binding, 'platform': 'the-colony'},
                 _invalid, 1, True),
                ('handle mismatch (stderr warn, invalid)',
                 {'binding_dict': _binding, 'handle': 'not_alex'},
                 _invalid, 1, True)):
            text, code = _vb_run(tmpd, **kw)
            ok, errs, info = conform_verify_binding_report(text)
            good = (ok == exp_ok) and text == exp_text and code == exp_code
            print(f'check_verify_binding e2e {name}: '
                  f'{"PASS" if good else "FAIL"}')
            for e in errs:
                if exp_ok:
                    print(f'    - {e}')
            if not good and exp_ok and not errs:
                print(f'    - stdout/exit mismatch: {text!r} '
                      f'(exit {code}), expected {exp_text!r} '
                      f'(exit {exp_code})')
            vb_fails += 0 if good else 1
            vb_e2e.append(name)

    vb_pos = [
        ('valid minimal', _VB_VALID + '\n' + _VB_NOTE + '\n'),
        ('invalid minimal', _VB_INVALID + '\n'),
        ('trailing blank lines', _VB_VALID + '\n' + _VB_NOTE + '\n\n'),
        ('no trailing newline', _VB_INVALID),
    ]
    vb_neg = [
        ('empty text', ''),
        ('two reports concatenated',
         _VB_VALID + '\n' + _VB_NOTE + '\n' + _VB_INVALID + '\n'),
        ('three lines', _VB_VALID + '\n' + _VB_NOTE + '\nゴミ行\n'),
        ('operational note on invalid verdict',
         _VB_INVALID + '\n' + _VB_NOTE + '\n'),
        ('note truncated',
         _VB_VALID + '\n（運用手順）: この binding が投稿されています\n'),
        ('note with extra suffix',
         _VB_VALID + '\n' + _VB_NOTE + '（追記）\n'),
        ('unknown verdict', 'binding は確認中です\n'),
        ('verdict with extra suffix', _VB_VALID + '（要確認）\n'),
        ('verdict lowercase latin', 'binding is valid\n'),
        ('leading blank line', '\n' + _VB_INVALID + '\n'),
        ('note before verdict', _VB_NOTE + '\n' + _VB_VALID + '\n'),
    ]
    for name, rep in vb_pos:
        ok, errs, info = conform_verify_binding_report(rep)
        good = ok
        print(f'check_verify_binding pos {name}: '
              f'{"PASS" if good else "FAIL"} ({"; ".join(info)})')
        for e in errs:
            print(f'    - {e}')
        vb_fails += 0 if good else 1
    for name, rep in vb_neg:
        ok, _errs, _info = conform_verify_binding_report(rep)
        good = not ok
        print(f'check_verify_binding neg {name}: '
              f'{"PASS" if good else "FAIL"}')
        if not good:
            print(f'    - report wrongly accepted')
        vb_fails += 0 if good else 1
    vb_total = len(vb_e2e) + len(vb_pos) + len(vb_neg)
    print(f'--- verify-binding {vb_total - vb_fails}/{vb_total} passed ---')
    fails += vb_fails

    vu_fails = 0

    def _vu_run(tmpd, unbinding_dict, platform=None, handle=None):
        ufp = os.path.join(tmpd, 'unbinding.json')
        with open(ufp, 'w') as f:
            json.dump(unbinding_dict, f, ensure_ascii=False)
        buf = io.StringIO()
        code = 0
        args = SimpleNamespace(unbinding=ufp, platform=platform,
                               handle=handle)
        with contextlib.redirect_stdout(buf), \
                contextlib.redirect_stderr(io.StringIO()):
            try:
                nakama.cmd_verify_unbinding(args)
            except SystemExit as e:
                code = e.code
        return buf.getvalue(), code

    vu_e2e = []
    with tempfile.TemporaryDirectory() as tmpd:
        _vus, _vunp = _key()
        _vu_time = 1759280000
        _vu_msg = nakama.unbinding_message('moltbook', 'alex', _vunp,
                                           _vu_time - 100, 'handle change',
                                           _vu_time)
        _unbinding = {'protocol': 'nakama', 'version': 1,
                      'type': 'platform-binding-revocation',
                      'platform': 'moltbook', 'handle': 'alex',
                      'npub': _vunp,
                      'binding_created_at': _vu_time - 100,
                      'reason': 'handle change', 'created_at': _vu_time,
                      'sig': nakama.sign_schnorr(_vus, _vu_msg).hex()}
        _vu_valid = (_VU_VALID + '\n' + _VU_NOTE + '\n')
        _vu_invalid = (_VU_INVALID + '\n')
        _vu_tampered = dict(_unbinding, handle='someone_else')
        for name, kw, exp_text, exp_code, exp_ok in (
                ('valid minimal', {'unbinding_dict': _unbinding},
                 _vu_valid, 0, True),
                ('valid with platform/handle match',
                 {'unbinding_dict': _unbinding, 'platform': 'moltbook',
                  'handle': 'alex'}, _vu_valid, 0, True),
                ('tampered handle (invalid)',
                 {'unbinding_dict': _vu_tampered}, _vu_invalid, 1, True),
                ('platform mismatch (stderr warn, invalid)',
                 {'unbinding_dict': _unbinding, 'platform': 'the-colony'},
                 _vu_invalid, 1, True),
                ('handle mismatch (stderr warn, invalid)',
                 {'unbinding_dict': _unbinding, 'handle': 'not_alex'},
                 _vu_invalid, 1, True)):
            text, code = _vu_run(tmpd, **kw)
            ok, errs, info = conform_verify_unbinding_report(text)
            good = (ok == exp_ok) and text == exp_text and code == exp_code
            print(f'check_verify_unbinding e2e {name}: '
                  f'{"PASS" if good else "FAIL"}')
            for e in errs:
                if exp_ok:
                    print(f'    - {e}')
            if not good and exp_ok and not errs:
                print(f'    - stdout/exit mismatch: {text!r} '
                      f'(exit {code}), expected {exp_text!r} '
                      f'(exit {exp_code})')
            vu_fails += 0 if good else 1
            vu_e2e.append(name)

    vu_pos = [
        ('valid minimal', _VU_VALID + '\n' + _VU_NOTE + '\n'),
        ('invalid minimal', _VU_INVALID + '\n'),
        ('trailing blank lines', _VU_VALID + '\n' + _VU_NOTE + '\n\n'),
        ('no trailing newline', _VU_INVALID),
    ]
    vu_neg = [
        ('empty text', ''),
        ('two reports concatenated',
         _VU_VALID + '\n' + _VU_NOTE + '\n' + _VU_INVALID + '\n'),
        ('three lines', _VU_VALID + '\n' + _VU_NOTE + '\nゴミ行\n'),
        ('operational note on invalid verdict',
         _VU_INVALID + '\n' + _VU_NOTE + '\n'),
        ('note truncated',
         _VU_VALID + '\n（運用手順）: 取り消し対象の binding を確認してください\n'),
        ('note with extra suffix',
         _VU_VALID + '\n' + _VU_NOTE + '（追記）\n'),
        ('unknown verdict', 'unbinding は確認中です\n'),
        ('verdict with extra suffix', _VU_VALID + '（要確認）\n'),
        ('verdict lowercase latin', 'unbinding is valid\n'),
        ('leading blank line', '\n' + _VU_INVALID + '\n'),
        ('note before verdict', _VU_NOTE + '\n' + _VU_VALID + '\n'),
    ]
    for name, rep in vu_pos:
        ok, errs, info = conform_verify_unbinding_report(rep)
        good = ok
        print(f'check_verify_unbinding pos {name}: '
              f'{"PASS" if good else "FAIL"} ({"; ".join(info)})')
        for e in errs:
            print(f'    - {e}')
        vu_fails += 0 if good else 1
    for name, rep in vu_neg:
        ok, _errs, _info = conform_verify_unbinding_report(rep)
        good = not ok
        print(f'check_verify_unbinding neg {name}: '
              f'{"PASS" if good else "FAIL"}')
        if not good:
            print(f'    - report wrongly accepted')
        vu_fails += 0 if good else 1
    vu_total = len(vu_e2e) + len(vu_pos) + len(vu_neg)
    print(f'--- verify-unbinding {vu_total - vu_fails}/{vu_total} passed ---')
    fails += vu_fails

    # check_renew: renew report consistency (v0.55). E2E runs the real
    # `nakama.py cmd_renew` in-process on a reference bond: once without
    # --markdown, once with it. The checker must accept both reports;
    # the old bond hash and the out filename must round-trip.
    rn_fails = 0
    rn_e2e = []
    import tempfile as _tempfile
    from types import SimpleNamespace as _SimpleNamespace

    def _rn_run(tmpd, markdown, expires_days):
        s_x, np_x = _key()
        s_y, np_y = _key()
        r_now = int(time.time())
        r_nonce = secrets.token_hex(32)
        r_msg = nakama.bond_message([np_x, np_y], r_now, r_nonce,
                                    r_now + 365 * 86400)
        bond = {
            'protocol': 'nakama', 'version': 1,
            'companions': sorted([np_x, np_y]),
            'created_at': r_now, 'nonce': r_nonce,
            'expires_at': r_now + 365 * 86400,
            'signatures': {
                np_x: nakama.sign_schnorr(s_x, r_msg).hex(),
                np_y: nakama.sign_schnorr(s_y, r_msg).hex()},
        }
        bpath = os.path.join(tmpd, 'bond.json')
        with open(bpath, 'w') as f:
            json.dump(bond, f)
        kpath = os.path.join(tmpd, 'key.txt')
        nakama.save_key(kpath, s_x)
        out = os.path.join(tmpd, 'renewal-proposal.json')
        buf = io.StringIO()
        args = _SimpleNamespace(bond=bpath, keyfile=kpath,
                                expires_days=expires_days, out=out,
                                markdown=markdown)
        with contextlib.redirect_stdout(buf), \
                contextlib.redirect_stderr(io.StringIO()):
            nakama.cmd_renew(args)
        return buf.getvalue(), bond, out

    with _tempfile.TemporaryDirectory() as tmpd:
        for name, markdown in (('no markdown', False),
                              ('with markdown', True)):
            text, bond, out = _rn_run(tmpd, markdown, 30)
            ok, errs, info = conform_renew_report(text)
            exp_hash = nakama.bond_hash(bond)
            l1 = text.splitlines()[0]
            l2 = text.splitlines()[1]
            good = ok and out in l1 and exp_hash in l2
            print(f'check_renew e2e {name}: {"PASS" if good else "FAIL"} '
                  f'({"; ".join(info)})')
            for e in errs:
                if ok:
                    print(f'    - {e}')
            if not good:
                print(f'    - stdout was: {text!r}')
            rn_fails += 0 if good else 1
            rn_e2e.append(name)

    _rn_base = ('更新 proposal を RENEW-OUT に保存しました。相手に渡し、'
                '`accept` で更新 bond を完成させてください。\n'
                '旧 bond hash: ' + 'ab' * 32 + '\n'
                '新しい有効期限: 2027-10-02（365 日後）\n')
    _rn_md = ('\n' + _RN_MD_HEADER + '\n' + _RN_MD_MARKER + '\n'
              + _RN_MD_FENCE + '\n' + 'QUJD' + '\n' + '```' + '\n')
    rn_pos = [
        ('minimal', _rn_base),
        ('with markdown block', _rn_base + _rn_md),
        ('no trailing newline', _rn_base.rstrip('\n')),
        ('trailing blank lines', _rn_base + '\n\n'),
        ('markdown with trailing blanks', _rn_base + _rn_md + '\n\n'),
        ('zero days', _rn_base.replace('365 日後', '0 日後')
         .replace('2027-10-02', '2026-10-02')),
        ('base64 padding', _rn_base + _rn_md.replace('QUJD', 'QUI=')),
        ('filename with spaces',
         _rn_base.replace('RENEW-OUT', 'my renew proposal.json')),
    ]
    rn_neg = [
        ('empty text', ''),
        ('one line only', _rn_base.splitlines()[0] + '\n'),
        ('two lines only', '\n'.join(_rn_base.splitlines()[:2]) + '\n'),
        ('uppercase hash',
         _rn_base.replace('ab' * 32, 'AB' * 32)),
        ('short hash', _rn_base.replace('ab' * 32, 'ab' * 31)),
        ('non-hex hash', _rn_base.replace('ab' * 32, 'zz' * 32)),
        ('impossible date',
         _rn_base.replace('2027-10-02', '2027-02-30')),
        ('date wrong shape',
         _rn_base.replace('2027-10-02', '02/10/2027')),
        ('days not int', _rn_base.replace('365 日後', 'lots 日後')),
        ('markdown header only, no blank',
         _rn_base + _RN_MD_HEADER + '\n'),
        ('markdown missing marker',
         _rn_base + '\n' + _RN_MD_HEADER + '\n' + _RN_MD_FENCE + '\n'
         + 'QUJD' + '\n' + '```' + '\n'),
        ('markdown missing fence',
         _rn_base + '\n' + _RN_MD_HEADER + '\n' + _RN_MD_MARKER + '\n'
         + 'QUJD' + '\n' + '```' + '\n'),
        ('markdown body not base64url',
         _rn_base + '\n' + _RN_MD_HEADER + '\n' + _RN_MD_MARKER + '\n'
         + _RN_MD_FENCE + '\n' + 'not base64!' + '\n' + '```' + '\n'),
        ('markdown unclosed fence',
         _rn_base + '\n' + _RN_MD_HEADER + '\n' + _RN_MD_MARKER + '\n'
         + _RN_MD_FENCE + '\n' + 'QUJD' + '\n'),
        ('markdown extra line after fence',
         _rn_base + _rn_md + '追記\n'),
    ]
    for name, rep in rn_pos:
        ok, errs, info = conform_renew_report(rep)
        good = ok
        print(f'check_renew pos {name}: {"PASS" if good else "FAIL"} '
              f'({"; ".join(info)})')
        for e in errs:
            print(f'    - {e}')
        rn_fails += 0 if good else 1
    for name, rep in rn_neg:
        ok, _errs, _info = conform_renew_report(rep)
        good = not ok
        print(f'check_renew neg {name}: {"PASS" if good else "FAIL"}')
        if not good:
            print(f'    - report wrongly accepted')
        rn_fails += 0 if good else 1
    rn_total = len(rn_e2e) + len(rn_pos) + len(rn_neg)
    print(f'--- renew {rn_total - rn_fails}/{rn_total} passed ---')
    fails += rn_fails

    # check_board_join: board_join report consistency (v0.56). E2E runs the
    # real `nakama.py cmd_board_join` in-process with `nostr_publish`
    # monkeypatched (accepted / rejected / a reason containing parens).
    # The reported event id must equal the published kind 9007 event's id,
    # and the exit code must match the verdict.
    bj_fails = 0
    bj_e2e = []

    def _bj_run(tmpd, accepted, reason):
        captured = {}

        def _fake_publish(url, event, timeout=15, auth_secret=None):
            captured['event'] = event
            return (accepted, reason)

        real_publish = nakama.nostr_publish
        nakama.nostr_publish = _fake_publish
        try:
            kpath = os.path.join(tmpd, 'key.txt')
            nakama.save_key(kpath, secrets.token_bytes(32))
            buf = io.StringIO()
            args = _SimpleNamespace(keyfile=kpath,
                                    relay='wss://relay.example',
                                    board_id='nakama-x7q2', auth=False)
            code = 0
            with contextlib.redirect_stdout(buf), \
                    contextlib.redirect_stderr(io.StringIO()):
                try:
                    nakama.cmd_board_join(args)
                except SystemExit as e:
                    code = e.code
        finally:
            nakama.nostr_publish = real_publish
        return buf.getvalue(), captured.get('event'), code

    with _tempfile.TemporaryDirectory() as tmpd:
        for name, accepted, reason, exp_code in (
                ('accepted', True, 'OK', 0),
                ('rejected', False,
                 'auth-required: join requests are moderated', 1),
                ('reason with parens', True, '承認 (auto)', 0)):
            text, ev, code = _bj_run(tmpd, accepted, reason)
            ok, errs, info = conform_board_join_report(text)
            exp_verdict = '受理' if accepted else '拒否'
            good = (ok and code == exp_code and ev is not None
                    and ev['id'] in text
                    and f'参加申請: {exp_verdict}' in text)
            print(f'check_board_join e2e {name}: '
                  f'{"PASS" if good else "FAIL"} ({"; ".join(info)})')
            for e in errs:
                if ok:
                    print(f'    - {e}')
            if not good:
                print(f'    - stdout was: {text!r}, exit: {code}')
            bj_fails += 0 if good else 1
            bj_e2e.append(name)

    _bj_base = ('参加申請: 受理 (OK) id=' + 'ab' * 32 + '\n')
    _bj_rej = ('参加申請: 拒否 (relay: not a member) id=' + 'cd' * 32 + '\n')
    bj_pos = [
        ('accepted', _bj_base),
        ('rejected', _bj_rej),
        ('empty reason', _bj_base.replace('(OK)', '()')),
        ('reason with parens',
         _bj_base.replace('(OK)', '(承認 (auto))')),
        ('uppercase id', _bj_base.replace('ab' * 32, 'AB' * 32)),
        ('japanese reason',
         _bj_base.replace('(OK)', '(広場は満員です)')),
        ('no trailing newline', _bj_base.rstrip('\n')),
        ('trailing blank lines', _bj_base + '\n\n'),
    ]
    bj_neg = [
        ('empty text', ''),
        ('two reports', _bj_base + _bj_rej),
        ('wrong verdict vocab',
         _bj_base.replace('受理', '承認')),
        ('english verdict',
         _bj_base.replace('受理', 'accepted')),
        ('publish prefix (check_pub shape)',
         _bj_base.replace('参加申請:', 'publish:')),
        ('board_send prefix',
         _bj_base.replace('参加申請:', '投稿:')),
        ('missing colon',
         _bj_base.replace('参加申請:', '参加申請')),
        ('missing space after colon',
         _bj_base.replace('参加申請: ', '参加申請:')),
        ('missing parens',
         _bj_base.replace('(OK)', 'OK')),
        ('short id', _bj_base.replace('ab' * 32, 'ab' * 31)),
        ('long id', _bj_base.replace('ab' * 32, 'ab' * 33)),
        ('non-hex id', _bj_base.replace('ab' * 32, 'zz' * 32)),
        ('missing id part', '参加申請: 受理 (OK)\n'),
        ('leading garbage', 'log line\n' + _bj_base),
    ]
    for name, rep in bj_pos:
        ok, errs, info = conform_board_join_report(rep)
        good = ok
        print(f'check_board_join pos {name}: '
              f'{"PASS" if good else "FAIL"} ({"; ".join(info)})')
        for e in errs:
            print(f'    - {e}')
        bj_fails += 0 if good else 1
    for name, rep in bj_neg:
        ok, _errs, _info = conform_board_join_report(rep)
        good = not ok
        print(f'check_board_join neg {name}: {"PASS" if good else "FAIL"}')
        if not good:
            print(f'    - report wrongly accepted')
        bj_fails += 0 if good else 1
    bj_total = len(bj_e2e) + len(bj_pos) + len(bj_neg)
    print(f'--- board-join {bj_total - bj_fails}/{bj_total} passed ---')
    fails += bj_fails

    # check_board_send: board_send report consistency (v0.57). E2E runs the
    # real `nakama.py cmd_board_send` in-process with `nostr_publish`
    # monkeypatched (accepted / rejected / a reason containing parens).
    # A fresh empty compromise registry keeps the §14.2 stderr warnings
    # out of the stdout report. The reported event id must equal the
    # published kind 9 event's id, and the exit code must match the
    # verdict.
    bs_fails = 0
    bs_e2e = []

    def _bs_run(tmpd, accepted, reason):
        captured = {}

        def _fake_publish(url, event, timeout=15, auth_secret=None):
            captured['event'] = event
            return (accepted, reason)

        real_publish = nakama.nostr_publish
        nakama.nostr_publish = _fake_publish
        try:
            kpath = os.path.join(tmpd, 'key.txt')
            nakama.save_key(kpath, secrets.token_bytes(32))
            creg = os.path.join(tmpd, 'compromises')
            os.makedirs(creg, exist_ok=True)
            buf = io.StringIO()
            args = _SimpleNamespace(keyfile=kpath,
                                    relay='wss://relay.example',
                                    board_id='nakama-x7q2',
                                    message='hello board', auth=False,
                                    descriptor=None,
                                    compromise_registry=creg)
            code = 0
            with contextlib.redirect_stdout(buf), \
                    contextlib.redirect_stderr(io.StringIO()):
                try:
                    nakama.cmd_board_send(args)
                except SystemExit as e:
                    code = e.code
        finally:
            nakama.nostr_publish = real_publish
        return buf.getvalue(), captured.get('event'), code

    with _tempfile.TemporaryDirectory() as tmpd:
        for name, accepted, reason, exp_code in (
                ('accepted', True, 'OK', 0),
                ('rejected', False,
                 'auth-required: chat posts are moderated', 1),
                ('reason with parens', True, '承認 (auto)', 0)):
            text, ev, code = _bs_run(tmpd, accepted, reason)
            ok, errs, info = conform_board_send_report(text)
            exp_verdict = '受理' if accepted else '拒否'
            good = (ok and code == exp_code and ev is not None
                    and ev['id'] in text
                    and f'投稿: {exp_verdict}' in text
                    and ev['kind'] == 9)
            print(f'check_board_send e2e {name}: '
                  f'{"PASS" if good else "FAIL"} ({"; ".join(info)})')
            for e in errs:
                if ok:
                    print(f'    - {e}')
            if not good:
                print(f'    - stdout was: {text!r}, exit: {code}')
            bs_fails += 0 if good else 1
            bs_e2e.append(name)

    _bs_base = ('投稿: 受理 (OK) id=' + 'ab' * 32 + '\n')
    _bs_rej = ('投稿: 拒否 (relay: not a member) id=' + 'cd' * 32 + '\n')
    bs_pos = [
        ('accepted', _bs_base),
        ('rejected', _bs_rej),
        ('empty reason', _bs_base.replace('(OK)', '()')),
        ('reason with parens',
         _bs_base.replace('(OK)', '(承認 (auto))')),
        ('uppercase id', _bs_base.replace('ab' * 32, 'AB' * 32)),
        ('japanese reason',
         _bs_base.replace('(OK)', '(投稿は凍結中です)')),
        ('no trailing newline', _bs_base.rstrip('\n')),
        ('trailing blank lines', _bs_base + '\n\n'),
    ]
    bs_neg = [
        ('empty text', ''),
        ('two reports', _bs_base + _bs_rej),
        ('wrong verdict vocab',
         _bs_base.replace('受理', '承認')),
        ('english verdict',
         _bs_base.replace('受理', 'accepted')),
        ('publish prefix (check_pub shape)',
         _bs_base.replace('投稿:', 'publish:')),
        ('board_join prefix',
         _bs_base.replace('投稿:', '参加申請:')),
        ('missing colon',
         _bs_base.replace('投稿:', '投稿')),
        ('missing space after colon',
         _bs_base.replace('投稿: ', '投稿:')),
        ('missing parens',
         _bs_base.replace('(OK)', 'OK')),
        ('short id', _bs_base.replace('ab' * 32, 'ab' * 31)),
        ('long id', _bs_base.replace('ab' * 32, 'ab' * 33)),
        ('non-hex id', _bs_base.replace('ab' * 32, 'zz' * 32)),
        ('missing id part', '投稿: 受理 (OK)\n'),
        ('leading garbage', 'log line\n' + _bs_base),
    ]
    for name, rep in bs_pos:
        ok, errs, info = conform_board_send_report(rep)
        good = ok
        print(f'check_board_send pos {name}: '
              f'{"PASS" if good else "FAIL"} ({"; ".join(info)})')
        for e in errs:
            print(f'    - {e}')
        bs_fails += 0 if good else 1
    for name, rep in bs_neg:
        ok, _errs, _info = conform_board_send_report(rep)
        good = not ok
        print(f'check_board_send neg {name}: {"PASS" if good else "FAIL"}')
        if not good:
            print(f'    - report wrongly accepted')
        bs_fails += 0 if good else 1
    bs_total = len(bs_e2e) + len(bs_pos) + len(bs_neg)
    print(f'--- board-send {bs_total - bs_fails}/{bs_total} passed ---')
    fails += bs_fails

    # check_board_create: board_create report consistency (v0.58). E2E runs
    # the real `nakama.py cmd_board_create` in-process with `nostr_publish`
    # monkeypatched (both accepted / rejected at 9002 / rejected at 34550).
    # The reported board_id must equal the h/d tags of the captured kind
    # 9002/34550 events, and the exit code must match the verdicts.
    bc_fails = 0
    bc_e2e = []

    def _bc_run(tmpd, results, name, out=None):
        captured = []

        def _fake_publish(url, event, timeout=15, auth_secret=None):
            captured.append(event)
            return results[len(captured) - 1]

        real_publish = nakama.nostr_publish
        nakama.nostr_publish = _fake_publish
        try:
            kpath = os.path.join(tmpd, 'key.txt')
            nakama.save_key(kpath, secrets.token_bytes(32))
            buf = io.StringIO()
            args = _SimpleNamespace(keyfile=kpath,
                                    relay='wss://relay.example',
                                    name='テスト広場', about='e2e 用',
                                    admission='open', out=out,
                                    auth=False)
            code = 0
            with contextlib.redirect_stdout(buf), \
                    contextlib.redirect_stderr(io.StringIO()):
                try:
                    nakama.cmd_board_create(args)
                except SystemExit as e:
                    code = e.code
        finally:
            nakama.nostr_publish = real_publish
        return buf.getvalue(), captured, code

    with _tempfile.TemporaryDirectory() as tmpd:
        outp = os.path.join(tmpd, 'descriptor.json')
        for name, results, exp_code, want_events in (
                ('accepted (out)', [(True, 'OK'), (True, 'OK')], 0, 2),
                ('rejected at 9002', [(False, 'auth-required')], 1, 1),
                ('rejected at 34550',
                 [(True, 'OK'), (False, 'duplicate')], 1, 2)):
            text, evs, code = _bc_run(tmpd, results, name,
                                       outp if name == 'accepted (out)' else None)
            ok, errs, info = conform_board_create_report(text)
            good = ok and code == exp_code and len(evs) == want_events
            if good and want_events == 2 and exp_code == 0:
                # board_id consistency across the summary line and both
                # events' tags; kinds must be 9002 then 34550.
                m_bid = re.search(
                    r'board_id=(nakama-[0-9a-f]{6})', text)
                tags_ok = (
                    m_bid is not None
                    and evs[0]['kind'] == 9002
                    and evs[1]['kind'] == 34550
                    and any(t == ['h', m_bid.group(1)]
                            for t in evs[0]['tags'])
                    and any(t == ['d', m_bid.group(1)]
                            for t in evs[1]['tags']))
                good = good and tags_ok
            if good and name == 'accepted (out)':
                good = good and os.path.isfile(outp) \
                    and 'descriptor を' in text
            print(f'check_board_create e2e {name}: '
                  f'{"PASS" if good else "FAIL"} ({ "; ".join(info) })')
            for e in errs:
                if ok:
                    print(f'    - {e}')
            if not good:
                print(f'    - stdout was: {text!r}, exit: {code}, '
                      f'events: {len(evs)}')
            bc_fails += 0 if good else 1
            bc_e2e.append(name)

    _bc_json_mid = '{\n  "protocol": "nakama"\n}\n'
    _bc_ok_head = 'kind 9002: 受理 (OK)\nkind 34550: 受理 (OK)\n'
    _bc_ok_save = (_bc_ok_head
                   + 'descriptor を /tmp/desc.json に保存しました\n'
                   + '広場 "仲間の広場" を作りました: board_id=nakama-a1b2c3\n')
    bc_pos = [
        ('accepted with save line', _bc_ok_save),
        ('accepted with json middle', _bc_ok_head + _bc_json_mid
         + '広場 "仲間の広場" を作りました: board_id=nakama-a1b2c3\n'),
        ('accepted no trailing newline', _bc_ok_save.rstrip('\n')),
        ('accepted trailing blank lines', _bc_ok_save + '\n\n'),
        ('accepted empty reasons',
         'kind 9002: 受理 ()\nkind 34550: 受理 ()\n'
         'descriptor を /tmp/x.json に保存しました\n'
         '広場 "広場" を作りました: board_id=nakama-000000\n'),
        ('accepted reason with parens',
         'kind 9002: 受理 (承認 (auto))\nkind 34550: 受理 (OK)\n'
         'descriptor を /tmp/x.json に保存しました\n'
         '広場 "広場" を作りました: board_id=nakama-abcdef\n'),
        ('rejected at 9002', 'kind 9002: 拒否 (auth-required)\n'),
        ('rejected at 9002 no newline', 'kind 9002: 拒否 ()'),
        ('rejected at 34550',
         'kind 9002: 受理 (OK)\nkind 34550: 拒否 (duplicate)\n'),
        ('quoted board name', _bc_ok_save.replace(
            '広場 "仲間の広場" を作りました',
            '広場 "a "b" c" を作りました')),
    ]
    bc_neg = [
        ('empty text', ''),
        ('two reports', _bc_ok_save + _bc_ok_save),
        ('34550 first', 'kind 34550: 受理 (OK)\n'
         'kind 9002: 受理 (OK)\n'
         '広場 "広場" を作りました: board_id=nakama-a1b2c3\n'),
        ('9002 line twice', 'kind 9002: 受理 (OK)\nkind 9002: 受理 (OK)\n'
         '広場 "広場" を作りました: board_id=nakama-a1b2c3\n'),
        ('wrong verdict vocab', _bc_ok_save.replace('受理', '承認', 1)),
        ('publish prefix (check_pub shape)',
         'publish: 受理 (OK) id=' + 'ab' * 32 + '\n'),
        ('board_join prefix', '参加申請: 受理 (OK) id=' + 'ab' * 32 + '\n'),
        ('board_send prefix', '投稿: 受理 (OK) id=' + 'ab' * 32 + '\n'),
        ('missing 34550 line',
         'kind 9002: 受理 (OK)\n'
         '広場 "広場" を作りました: board_id=nakama-a1b2c3\n'),
        ('extra line after 9002 rejection',
         'kind 9002: 拒否 (x)\nkind 34550: 受理 (OK)\n'),
        ('extra line after 34550 rejection',
         'kind 9002: 受理 (OK)\nkind 34550: 拒否 (x)\n'
         '広場 "広場" を作りました: board_id=nakama-a1b2c3\n'),
        ('missing summary line', _bc_ok_head
         + 'descriptor を /tmp/desc.json に保存しました\n'),
        ('board_id without prefix', _bc_ok_save.replace(
            'board_id=nakama-a1b2c3', 'board_id=a1b2c3')),
        ('board_id hex too long', _bc_ok_save.replace(
            'board_id=nakama-a1b2c3', 'board_id=nakama-a1b2c3d4')),
        ('descriptor board_id mismatch',
         _bc_ok_head + '{\n  "protocol": "nakama",\n  "board_id": "nakama-deadbe"\n}\n'
         + '広場 "広場" を作りました: board_id=nakama-a1b2c3\n'),
        ('descriptor middle not json',
         _bc_ok_head + 'some garbage middle\n'
         + '広場 "広場" を作りました: board_id=nakama-a1b2c3\n'),
    ]
    for name, rep in bc_pos:
        ok, errs, info = conform_board_create_report(rep)
        good = ok
        print(f'check_board_create pos {name}: '
              f'{"PASS" if good else "FAIL"} ({ "; ".join(info) })')
        for e in errs:
            print(f'    - {e}')
        bc_fails += 0 if good else 1
    for name, rep in bc_neg:
        ok, _errs, _info = conform_board_create_report(rep)
        good = not ok
        print(f'check_board_create neg {name}: {"PASS" if good else "FAIL"}')
        if not good:
            print(f'    - report wrongly accepted')
        bc_fails += 0 if good else 1
    bc_total = len(bc_e2e) + len(bc_pos) + len(bc_neg)
    print(f'--- board-create {bc_total - bc_fails}/{bc_total} passed ---')
    fails += bc_fails

    # ---------- check_verify_board_decision: verify_board_decision report consistency ----------
    # Reference reports are produced in-process with nakama.py's own
    # cmd_verify_board_decision (offline: policy and decision fixtures
    # built in-process with real Schnorr signatures — a 2-of-3 policy,
    # a valid admit decision, a threshold-short decision, and a
    # tampered-signature decision); hand-mutated reports that break the
    # single-line grammar must be rejected.
    vbd_fails = 0
    _vbd_now = int(time.time())
    _vbd_relay = 'wss://example.invalid'
    _vbd_bid = 'vbd-board-001'

    def _vbd_signer():
        s = secrets.token_bytes(32)
        return (s, nakama.npub_of(s))

    _vbd_a, _vbd_b, _vbd_c = _vbd_signer(), _vbd_signer(), _vbd_signer()

    def _vbd_policy():
        msg = nakama.board_policy_message(_vbd_bid, _vbd_relay, 2,
                                          [_vbd_a[1], _vbd_b[1], _vbd_c[1]],
                                          _vbd_now)
        return {
            'protocol': 'nakama', 'version': 1, 'type': 'board-policy',
            'board_id': _vbd_bid, 'relay': _vbd_relay, 'threshold': 2,
            'eligible': [_vbd_a[1], _vbd_b[1], _vbd_c[1]],
            'created_at': _vbd_now,
            'signatures': [
                {'npub': m[1],
                 'sig': nakama.sign_schnorr(m[0], msg).hex()}
                for m in (_vbd_a, _vbd_b, _vbd_c)],
        }

    def _vbd_decision(decname, payload, approvers):
        msg = nakama.board_decision_message(_vbd_bid, _vbd_relay, decname,
                                            payload, _vbd_now)
        return {
            'protocol': 'nakama', 'version': 1, 'type': 'board-decision',
            'board_id': _vbd_bid, 'relay': _vbd_relay, 'decision': decname,
            'payload': payload, 'created_at': _vbd_now,
            'approvals': [{'npub': a[1],
                           'sig': nakama.sign_schnorr(a[0], msg).hex()}
                          for a in approvers],
        }

    def _vbd_run(dec, pol):
        buf = io.StringIO()
        code = None
        with tempfile.TemporaryDirectory() as tmpd:
            dec_path = os.path.join(tmpd, 'decision.json')
            pol_path = os.path.join(tmpd, 'policy.json')
            with open(dec_path, 'w') as f:
                json.dump(dec, f)
            with open(pol_path, 'w') as f:
                json.dump(pol, f)
            with contextlib.redirect_stdout(buf), \
                    contextlib.redirect_stderr(io.StringIO()):
                try:
                    nakama.cmd_verify_board_decision(
                        SimpleNamespace(decision=dec_path, policy=pol_path))
                except SystemExit as e:
                    code = e.code
        return buf.getvalue(), code

    _vbd_pol = _vbd_policy()
    assert nakama.verify_board_policy_cert(_vbd_pol), 'vbd policy fixture'
    _vbd_d = _vbd_signer()
    _vbd_dec_ok = _vbd_decision('admit', {'candidate': _vbd_d[1]},
                               [_vbd_a, _vbd_b])
    _vbd_dec_short = _vbd_decision('admit', {'candidate': _vbd_d[1]},
                                  [_vbd_a])
    _vbd_dec_bad = _vbd_decision('admit', {'candidate': _vbd_d[1]},
                                [_vbd_a, _vbd_b])
    _vbd_dec_bad['approvals'][1]['sig'] = '00' * 64

    _vbd_rep_ok, _vbd_code_ok = _vbd_run(_vbd_dec_ok, _vbd_pol)
    _vbd_rep_short, _vbd_code_short = _vbd_run(_vbd_dec_short, _vbd_pol)
    _vbd_rep_bad, _vbd_code_bad = _vbd_run(_vbd_dec_bad, _vbd_pol)

    vbd_e2e = [
        ('valid decision', _vbd_rep_ok, _vbd_code_ok, 0,
         'board-decision は有効です: 承認署名 2/2（決定 "admit"）\n'),
        ('threshold short', _vbd_rep_short, _vbd_code_short, 1,
         'board-decision は無効です: 承認署名 1/2（threshold 未達または署名不正）\n'),
        ('tampered signature', _vbd_rep_bad, _vbd_code_bad, 1,
         'board-decision は無効です: 承認署名 1/2（threshold 未達または署名不正）\n'),
    ]
    for name, rep, code, want_code, want_rep in vbd_e2e:
        exact = (rep == want_rep) and (code == want_code)
        ok, errs, info = conform_verify_board_decision_report(rep)
        good = exact and ok
        print(f'verify-board-decision-e2e/{name}: '
              f'{"PASS" if good else "FAIL"} ({ "; ".join(info) })')
        if not good:
            if not exact:
                print(f'    - stdout/exit mismatch: {rep!r} code={code}')
            for e in errs:
                print(f'    - {e}')
            vbd_fails += 1

    _vbd_ok_line = ('board-decision は有効です: '
                    '承認署名 2/2（決定 "policy-update"）')
    _vbd_bad_line = ('board-decision は無効です: '
                     '承認署名 1/3（threshold 未達または署名不正）')
    vbd_pos = [
        ('valid', _vbd_ok_line + '\n'),
        ('valid no trailing newline', _vbd_ok_line),
        ('valid trailing blanks', _vbd_ok_line + '\n\n  \n'),
        ('valid n > threshold', 'board-decision は有効です: '
                                '承認署名 3/2（決定 "admit"）\n'),
        ('valid zero approvals zero threshold',
         'board-decision は有効です: 承認署名 0/0（決定 "close"）\n'),
        ('valid unicode decision name', 'board-decision は有効です: '
                                        '承認署名 2/2（決定 "緊急 措置"）\n'),
        ('invalid', _vbd_bad_line + '\n'),
        ('invalid no trailing newline', _vbd_bad_line),
        ('invalid trailing blanks', _vbd_bad_line + '\n\n'),
        ('invalid zero/zero', 'board-decision は無効です: '
                              '承認署名 0/0（threshold 未達または署名不正）\n'),
    ]
    vbd_neg = [
        ('empty text', ''),
        ('two reports', _vbd_ok_line + '\n' + _vbd_ok_line + '\n'),
        ('wrong verdict vocab',
         _vbd_ok_line.replace('有効です', '成立です') + '\n'),
        ('english verdict',
         'board-decision is valid: 2/2 ("admit")\n'),
        ('valid n < threshold',
         'board-decision は有効です: 承認署名 1/2（決定 "admit"）\n'),
        ('invalid with decision tail',
         'board-decision は無効です: 承認署名 1/2（決定 "admit"）\n'),
        ('valid with invalid tail',
         'board-decision は有効です: 承認署名 2/2（threshold 未達または署名不正）\n'),
        ('missing quotes around decision',
         'board-decision は有効です: 承認署名 2/2（決定 admit）\n'),
        ('empty decision name',
         'board-decision は有効です: 承認署名 2/2（決定 ""）\n'),
        ('decision name with quote',
         'board-decision は有効です: 承認署名 2/2（決定 "a"b"）\n'),
        ('non-numeric counts',
         'board-decision は有効です: 承認署名 x/2（決定 "admit"）\n'),
        ('missing decision tail',
         'board-decision は有効です: 承認署名 2/2\n'),
        ('trailing garbage', _vbd_ok_line + '\nおまけ\n'),
        ('leading garbage', '前置き\n' + _vbd_ok_line + '\n'),
        ('swapped order',
         'board-decision は有効です: 承認署名 2/3（決定） "admit"\n'),
        ('verdict word truncated',
         'board-decision は有効で: 承認署名 2/2（決定 "admit"）\n'),
    ]
    for name, rep in vbd_pos:
        ok, errs, info = conform_verify_board_decision_report(rep)
        good = ok
        print(f'check_verify_board_decision pos {name}: '
              f'{"PASS" if good else "FAIL"} ({ "; ".join(info) })')
        for e in errs:
            print(f'    - {e}')
        vbd_fails += 0 if good else 1
    for name, rep in vbd_neg:
        ok, _errs, _info = conform_verify_board_decision_report(rep)
        good = not ok
        print(f'check_verify_board_decision neg {name}: '
              f'{"PASS" if good else "FAIL"}')
        if not good:
            print(f'    - report wrongly accepted')
        vbd_fails += 0 if good else 1
    vbd_total = len(vbd_e2e) + len(vbd_pos) + len(vbd_neg)
    print(f'--- verify-board-decision {vbd_total - vbd_fails}/{vbd_total} '
          f'passed ---')
    fails += vbd_fails

    # ---------- check_board_verify: board_verify report consistency ----------
    # Reference reports are produced in-process with nakama.py's own
    # cmd_board_verify (offline: a board descriptor fixture built
    # in-process with a real Schnorr signature, plus a tampered-sig one);
    # hand-mutated reports that break the single-line grammar must be
    # rejected.
    bvr_fails = 0

    def _bv_descriptor(sig_secret, now, board_id, tamper=False):
        s, npub = sig_secret
        mods = [npub]
        msg = nakama.board_descriptor_message(board_id, 'wss://relay.damus.io',
                                             mods, now)
        sig = nakama.sign_schnorr(s, msg).hex()
        if tamper:
            sig = '00' * 128
        return {'protocol': 'nakama', 'version': 1, 'type': 'board',
                'board_id': board_id, 'relay': 'wss://relay.damus.io',
                'moderators': mods, 'admission': 'open',
                'created_at': now, 'sig': sig}

    def _bv_run(desc):
        buf = io.StringIO()
        with tempfile.TemporaryDirectory() as tmpd:
            desc_path = os.path.join(tmpd, 'descriptor.json')
            with open(desc_path, 'w') as f:
                json.dump(desc, f)
            with contextlib.redirect_stdout(buf), \
                    contextlib.redirect_stderr(io.StringIO()):
                try:
                    nakama.cmd_board_verify(
                        SimpleNamespace(descriptor=desc_path,
                                        compromise_registry=tmpd))
                except SystemExit as e:
                    code = e.code
        return buf.getvalue(), code

    _bv_now = int(time.time())
    _bv_id = 'nakama-' + secrets.token_hex(3)
    _bv_desc_ok = _bv_descriptor(_key(), _bv_now, _bv_id)
    _bv_desc_bad = _bv_descriptor(_key(), _bv_now, _bv_id, tamper=True)

    _bv_rep_ok, _bv_code_ok = _bv_run(_bv_desc_ok)
    _bv_rep_bad, _bv_code_bad = _bv_run(_bv_desc_bad)

    bvr_e2e = [
        ('valid descriptor', _bv_rep_ok, _bv_code_ok, 0,
         'board descriptor は有効です\n'),
        ('tampered signature', _bv_rep_bad, _bv_code_bad, 1,
         'board descriptor は無効です\n'),
    ]
    for name, rep, code, want_code, want_rep in bvr_e2e:
        exact = (rep == want_rep) and (code == want_code)
        ok, errs, info = conform_board_verify_report(rep)
        good = exact and ok
        print(f'board-verify-e2e/{name}: '
              f'{"PASS" if good else "FAIL"} ({ "; ".join(info) })')
        if not good:
            if not exact:
                print(f'    - stdout/exit mismatch: {rep!r} code={code}')
            for e in errs:
                print(f'    - {e}')
            bvr_fails += 1

    bvr_pos = [
        ('valid', 'board descriptor は有効です\n'),
        ('valid no trailing newline', 'board descriptor は有効です'),
        ('valid trailing blanks', 'board descriptor は有効です\n\n  \n'),
        ('invalid', 'board descriptor は無効です\n'),
        ('invalid no trailing newline', 'board descriptor は無効です'),
        ('invalid trailing blanks', 'board descriptor は無効です\n\n'),
    ]
    bvr_neg = [
        ('empty text', ''),
        ('two reports', 'board descriptor は有効です\n'
                        'board descriptor は無効です\n'),
        ('wrong verdict vocab',
         'board descriptor は成立です\n'),
        ('english verdict', 'board descriptor is valid\n'),
        ('verdict word truncated', 'board descriptor は有効で\n'),
        ('leading garbage', '前置き\nboard descriptor は有効です\n'),
        ('trailing garbage', 'board descriptor は有効です\nおまけ\n'),
        ('missing command noun', 'は有効です\n'),
        ('wrong command noun', 'board-decision は有効です\n'),
        ('verdict swapped vocabulary', 'board descriptor は無効です!\n'),
        ('extra inner space', 'board descriptor  は有効です\n'),
        ('missing の particle', 'board descriptor は有効 です\n'),
    ]
    for name, rep in bvr_pos:
        ok, errs, info = conform_board_verify_report(rep)
        good = ok
        print(f'check_board_verify pos {name}: '
              f'{"PASS" if good else "FAIL"} ({ "; ".join(info) })')
        for e in errs:
            print(f'    - {e}')
        bvr_fails += 0 if good else 1
    for name, rep in bvr_neg:
        ok, _errs, _info = conform_board_verify_report(rep)
        good = not ok
        print(f'check_board_verify neg {name}: '
              f'{"PASS" if good else "FAIL"}')
        if not good:
            print(f'    - report wrongly accepted')
        bvr_fails += 0 if good else 1
    bvr_total = len(bvr_e2e) + len(bvr_pos) + len(bvr_neg)
    print(f'--- board-verify {bvr_total - bvr_fails}/{bvr_total} '
          f'passed ---')
    fails += bvr_fails

    # ---------- check_board_decide: board_decide report consistency ----------
    # Reference reports are produced in-process with nakama.py's own
    # cmd_board_decide (offline: a temp keyfile written with a real
    # keypair, Schnorr-signed draft decisions for each decision type);
    # hand-mutated reports that break the two-line grammar must be
    # rejected.
    bdc_fails = 0
    _bdc_now = int(time.time())
    _bdc_s, _bdc_npub = _key()
    _bdc_s2, _bdc_npub2 = _key()

    def _bdc_run(decision, payload, out_name):
        buf = io.StringIO()
        with tempfile.TemporaryDirectory() as tmpd:
            kf = os.path.join(tmpd, 'key.json')
            nakama.save_key(kf, _bdc_s)
            out = os.path.join(tmpd, out_name)
            ns = SimpleNamespace(
                keyfile=kf, board_id='bdc-board',
                relay='wss://relay.example', decision=decision,
                payload=json.dumps(payload), out=out,
                expires_in=None, expires_at=None, old_moderators=None)
            code = 0
            with contextlib.redirect_stdout(buf), \
                    contextlib.redirect_stderr(io.StringIO()):
                try:
                    nakama.cmd_board_decide(ns)
                except SystemExit as e:
                    code = e.code if isinstance(e.code, int) else 0
            ok_file = os.path.exists(out)
        return buf.getvalue(), code, out, ok_file

    _bdc_e2e_raw = [
        ('admit', {'candidate': _bdc_npub}, 'dec-admit.json'),
        ('policy-update', {'threshold': 2,
                          'eligible': [_bdc_npub, _bdc_npub2]},
         'dec-policy.json'),
    ]
    bdc_e2e = []
    for _dname, _payload, _oname in _bdc_e2e_raw:
        _rep, _code, _outp, _okf = _bdc_run(_dname, _payload, _oname)
        _want = (f'board-decision 案: {_outp} — 決定 "{_dname}"、'
                 f'あなたの承認署名 1 つ\n{_BD_LINE2}\n')
        bdc_e2e.append((_dname, _rep, _code, 0, _want, _okf))
    for name, rep, code, want_code, want_rep, ok_file in bdc_e2e:
        exact = (rep == want_rep) and (code == want_code) and ok_file
        ok, errs, info = conform_board_decide_report(rep)
        good = exact and ok
        print(f'board-decide-e2e/{name}: '
              f'{"PASS" if good else "FAIL"} ({ "; ".join(info) })')
        if not good:
            if not exact:
                print(f'    - stdout/exit/file mismatch: {rep!r} '
                      f'code={code} file={ok_file}')
            for e in errs:
                print(f'    - {e}')
            bdc_fails += 1

    bdc_pos = [
        ('admit', 'board-decision 案: dec.json — 決定 "admit"、'
                  'あなたの承認署名 1 つ\n' + _BD_LINE2 + '\n'),
        ('handover', 'board-decision 案: dec.json — 決定 "handover"、'
                     'あなたの承認署名 1 つ\n' + _BD_LINE2 + '\n'),
        ('out with spaces', 'board-decision 案: /tmp/my dir/dec draft.json '
                            '— 決定 "close"、あなたの承認署名 1 つ\n'
                            + _BD_LINE2 + '\n'),
        ('no trailing newline', 'board-decision 案: dec.json — 決定 '
                                '"remove"、あなたの承認署名 1 つ\n'
                                + _BD_LINE2),
        ('trailing blanks', 'board-decision 案: dec.json — 決定 "admit"、'
                            'あなたの承認署名 1 つ\n' + _BD_LINE2
                            + '\n\n  \n'),
    ]
    bdc_neg = [
        ('empty text', ''),
        ('one line only', 'board-decision 案: dec.json — 決定 "admit"、'
                          'あなたの承認署名 1 つ\n'),
        ('two reports', 'board-decision 案: dec.json — 決定 "admit"、'
                        'あなたの承認署名 1 つ\n' + _BD_LINE2 + '\n'
                        'board-decision 案: dec.json — 決定 "admit"、'
                        'あなたの承認署名 1 つ\n' + _BD_LINE2 + '\n'),
        ('unknown decision vocabulary', 'board-decision 案: dec.json — 決定 '
                                        '"elect"、あなたの承認署名 1 つ\n'
                                        + _BD_LINE2 + '\n'),
        ('empty decision name', 'board-decision 案: dec.json — 決定 '
                                '"あなたの承認署名 1 つ\n'
                                + _BD_LINE2 + '\n'),
        ('decision name with quote', 'board-decision 案: dec.json — 決定 '
                                     '"ad"mit"、あなたの承認署名 1 つ\n'
                                     + _BD_LINE2 + '\n'),
        ('count 2 instead of 1', 'board-decision 案: dec.json — 決定 '
                                 '"admit"、あなたの承認署名 2 つ\n'
                                 + _BD_LINE2 + '\n'),
        ('empty out file name', 'board-decision 案:  — 決定 "admit"、'
                                'あなたの承認署名 1 つ\n'
                                + _BD_LINE2 + '\n'),
        ('missing operational line', 'board-decision 案: dec.json — 決定 '
                                     '"admit"、あなたの承認署名 1 つ\n'
                                     '報告の記録は省略\n'),
        ('operational line truncated', 'board-decision 案: dec.json — 決定 '
                                       '"admit"、あなたの承認署名 1 つ\n'
                                       '運用: このファイルを回覧し\n'),
        ('leading garbage', '前置き\nboard-decision 案: dec.json — 決定 '
                            '"admit"、あなたの承認署名 1 つ\n'
                            + _BD_LINE2 + '\n'),
        ('trailing garbage', 'board-decision 案: dec.json — 決定 "admit"、'
                             'あなたの承認署名 1 つ\n' + _BD_LINE2
                             + '\nおまけ\n'),
        ('verify_board_decision report line',
         'board-decision は有効です: 承認署名 1/2（決定 "admit"）\n'),
    ]
    for name, rep in bdc_pos:
        ok, errs, info = conform_board_decide_report(rep)
        good = ok
        print(f'check_board_decide pos {name}: '
              f'{"PASS" if good else "FAIL"} ({ "; ".join(info) })')
        for e in errs:
            print(f'    - {e}')
        bdc_fails += 0 if good else 1
    for name, rep in bdc_neg:
        ok, _errs, _info = conform_board_decide_report(rep)
        good = not ok
        print(f'check_board_decide neg {name}: '
              f'{"PASS" if good else "FAIL"}')
        if not good:
            print(f'    - report wrongly accepted')
        bdc_fails += 0 if good else 1
    bdc_total = len(bdc_e2e) + len(bdc_pos) + len(bdc_neg)
    print(f'--- board-decide {bdc_total - bdc_fails}/{bdc_total} '
          f'passed ---')
    fails += bdc_fails

    # ---------- check_board_cosign: board_cosign report consistency ----------
    # Reference reports are produced in-process with nakama.py's own
    # cmd_board_decide + cmd_board_cosign (offline: a draft admit decision
    # created with one temp keyfile, then cosigned by a second and a
    # third key — fresh, duplicate-signature, and --out-to-new-file
    # cases); hand-mutated reports that break the one-line grammar must
    # be rejected.
    bcs_fails = 0
    _bcs_s_a, _bcs_npub_a = _key()
    _bcs_s_b, _bcs_npub_b = _key()
    _bcs_s_c, _bcs_npub_c = _key()

    def _bcs_make_draft(tmpd):
        kf = os.path.join(tmpd, 'key-a.json')
        nakama.save_key(kf, _bcs_s_a)
        dec = os.path.join(tmpd, 'draft.json')
        ns = SimpleNamespace(
            keyfile=kf, board_id='bcs-board',
            relay='wss://relay.example', decision='admit',
            payload=json.dumps({'candidate': _bcs_npub_b}), out=dec,
            expires_in=None, expires_at=None, old_moderators=None)
        with contextlib.redirect_stdout(io.StringIO()), \
                contextlib.redirect_stderr(io.StringIO()):
            nakama.cmd_board_decide(ns)
        return dec

    def _bcs_cosign(key_bytes, decision_path, out=None):
        buf = io.StringIO()
        err = io.StringIO()
        with tempfile.TemporaryDirectory() as tmpd:
            kf = os.path.join(tmpd, 'key.json')
            nakama.save_key(kf, key_bytes)
            ns = SimpleNamespace(keyfile=kf, decision=decision_path,
                                 out=out)
            code = 0
            with contextlib.redirect_stdout(buf), \
                    contextlib.redirect_stderr(err):
                try:
                    nakama.cmd_board_cosign(ns)
                except SystemExit as e:
                    code = e.code if isinstance(e.code, int) else 0
        return buf.getvalue(), err.getvalue(), code

    with tempfile.TemporaryDirectory() as _bcs_tmpd:
        _bcs_draft = _bcs_make_draft(_bcs_tmpd)
        _bcs_e2e = []
        # fresh cosign by a second key: 1 (creator) + 1 = 2
        _rep, _err, _code = _bcs_cosign(_bcs_s_b, _bcs_draft)
        _bcs_e2e.append(('fresh cosign (2)', _rep, _err, _code, 0,
                         f'board-decision: {_bcs_draft} — 承認署名 2 つ\n',
                         ''))
        # duplicate cosign by the same key: stderr warning, count unchanged
        _rep, _err, _code = _bcs_cosign(_bcs_s_b, _bcs_draft)
        _bcs_e2e.append(('duplicate cosign (2)', _rep, _err, _code, 0,
                         f'board-decision: {_bcs_draft} — 承認署名 2 つ\n',
                         '既に承認署名済みです'))
        # third key with --out to a new file: 3
        _bcs_new = os.path.join(_bcs_tmpd, 'draft-3.json')
        _rep, _err, _code = _bcs_cosign(_bcs_s_c, _bcs_draft,
                                       out=_bcs_new)
        _bcs_e2e.append(('third key --out (3)', _rep, _err, _code, 0,
                         f'board-decision: {_bcs_new} — 承認署名 3 つ\n',
                         ''))
    for name, rep, err, code, want_code, want_rep, want_err_sub in _bcs_e2e:
        exact = (rep == want_rep) and (code == want_code) and \
            (want_err_sub in err)
        ok, errs, info = conform_board_cosign_report(rep)
        good = exact and ok
        print(f'board-cosign-e2e/{name}: '
              f'{"PASS" if good else "FAIL"} ({ "; ".join(info) })')
        if not good:
            if not exact:
                print(f'    - stdout/stderr/exit mismatch: {rep!r} '
                      f'code={code} stderr={err!r}')
            for e in errs:
                print(f'    - {e}')
            bcs_fails += 1

    bcs_pos = [
        ('two approvals', 'board-decision: d.json — 承認署名 2 つ\n'),
        ('one approval', 'board-decision: d.json — 承認署名 1 つ\n'),
        ('no trailing newline', 'board-decision: d.json — 承認署名 3 つ'),
        ('trailing blanks', 'board-decision: d.json — 承認署名 2 つ\n\n  \n'),
        ('out with spaces', 'board-decision: /tmp/my dir/dec draft.json '
                            '— 承認署名 5 つ\n'),
        ('large count', 'board-decision: d.json — 承認署名 100 つ\n'),
    ]
    bcs_neg = [
        ('empty text', ''),
        ('two reports', 'board-decision: d.json — 承認署名 2 つ\n'
                        'board-decision: d.json — 承認署名 2 つ\n'),
        ('board_decide creation line', 'board-decision 案: d.json — 決定 '
                                       '"admit"、あなたの承認署名 1 つ\n'
                                       + _BD_LINE2 + '\n'),
        ('verify_board_decision valid line',
         'board-decision は有効です: 承認署名 1/2（決定 "admit"）\n'),
        ('verify_board_decision invalid line',
         'board-decision は無効です: 承認署名 1/2（threshold 未達または署名不正）\n'),
        ('zero approvals (self-contradictory)',
         'board-decision: d.json — 承認署名 0 つ\n'),
        ('non-numeric count', 'board-decision: d.json — 承認署名 数つ\n'),
        ('empty out', 'board-decision:  — 承認署名 2 つ\n'),
        ('missing prefix colon', 'board-decision d.json — 承認署名 2 つ\n'),
        ('missing separator', 'board-decision: d.json 承認署名 2 つ\n'),
        ('missing counter word', 'board-decision: d.json — 承認署名 2\n'),
        ('leading garbage', '前置き\nboard-decision: d.json — 承認署名 2 つ\n'),
        ('trailing garbage', 'board-decision: d.json — 承認署名 2 つ\nおまけ\n'),
    ]
    for name, rep in bcs_pos:
        ok, errs, info = conform_board_cosign_report(rep)
        good = ok
        print(f'check_board_cosign pos {name}: '
              f'{"PASS" if good else "FAIL"} ({ "; ".join(info) })')
        for e in errs:
            print(f'    - {e}')
        bcs_fails += 0 if good else 1
    for name, rep in bcs_neg:
        ok, _errs, _info = conform_board_cosign_report(rep)
        good = not ok
        print(f'check_board_cosign neg {name}: '
              f'{"PASS" if good else "FAIL"}')
        if not good:
            print(f'    - report wrongly accepted')
        bcs_fails += 0 if good else 1
    bcs_total = len(_bcs_e2e) + len(bcs_pos) + len(bcs_neg)
    print(f'--- board-cosign {bcs_total - bcs_fails}/{bcs_total} '
          f'passed ---')
    fails += bcs_fails

    rec_total = len(rec_pos) + len(rec_neg) + 2
    print(f'--- record {rec_total - rec_fails}/{rec_total} passed ---')
    fails += rec_fails

    grand = total + dm_total + board_total + dec_total + bond_total \
        + binding_total + live_total + cp_total + rt_total + rv_total \
        + ub_total + pl_total + dr_total + ack_total + rec_total + ks_total \
        + rl_total + ns_total + dmf_total + brd_total + bdf_total + ddf_total \
        + bfa_total + pub_total + gov_total + rf_total + rtf_total \
        + cf_total + lv_total + lr_total + vb_total + vu_total + rn_total \
        + bj_total + bs_total + bc_total + vbd_total + bvr_total \
        + bdc_total + bcs_total + dmr_total + dms_total + vrt_total + bpl_total \
        + bps_total + vbp_total + vrf_total + pr_total + ac_total \
        + ch_total + ck_total + vrv_total + rvk_total + wrn_total \
        + crgd_total + rvi_total + ini_total + dno_total + cpi_total \
        + cpd_total + cpw_total + rti_total
    print(f'=== {grand - fails}/{grand} passed (all) ===')
    return 0 if fails == 0 else 1


def main(argv: list[str]) -> int:
    if len(argv) >= 2 and argv[1] == 'check':
        if len(argv) < 3:
            print('usage: conformance.py check <event.json> [...]')
            return 2
        return check_files(argv[2:])
    if len(argv) >= 2 and argv[1] == 'check_dm':
        if len(argv) < 4:
            print('usage: conformance.py check_dm <recipient_secret_hex> '
                  '<wrap.json> [...]')
            return 2
        return check_dm_files(argv[2], argv[3:])
    if len(argv) >= 2 and argv[1] == 'check_board':
        if len(argv) < 3:
            print('usage: conformance.py check_board <descriptor.json> [...]')
            return 2
        return check_board_files(argv[2:])
    if len(argv) >= 2 and argv[1] == 'check_decision':
        policy_path = None
        rest = argv[2:]
        if rest[:1] == ['--policy']:
            if len(rest) < 3:
                print('usage: conformance.py check_decision [--policy policy.json] '
                      '<decision.json> [...]')
                return 2
            policy_path, rest = rest[1], rest[2:]
        if not rest:
            print('usage: conformance.py check_decision [--policy policy.json] '
                  '<decision.json> [...]')
            return 2
        return check_decision_files(policy_path, rest)
    if len(argv) >= 2 and argv[1] == 'check_bond':
        if len(argv) < 3:
            print('usage: conformance.py check_bond <bond.json> [...]')
            return 2
        return check_bond_files(argv[2:])
    if len(argv) >= 2 and argv[1] == 'check_binding':
        if len(argv) < 3:
            print('usage: conformance.py check_binding <binding.json> [...]')
            return 2
        return check_binding_files(argv[2:])
    if len(argv) >= 2 and argv[1] == 'check_unbinding':
        if len(argv) < 3:
            print('usage: conformance.py check_unbinding <unbinding.json> [...]')
            return 2
        return check_unbinding_files(argv[2:])
    if len(argv) >= 2 and argv[1] == 'check_liveness':
        bond_path = None
        max_age = 7 * 86400
        now = None
        rest = argv[2:]
        while rest and rest[0].startswith('--'):
            opt = rest[0]
            if opt == '--bond' and len(rest) >= 2:
                bond_path, rest = rest[1], rest[2:]
            elif opt == '--max-age' and len(rest) >= 2:
                try:
                    max_age = int(rest[1])
                except ValueError:
                    print('--max-age must be an int (seconds)')
                    return 2
                rest = rest[2:]
            elif opt == '--now' and len(rest) >= 2:
                try:
                    now = int(rest[1])
                except ValueError:
                    print('--now must be an int (unix time)')
                    return 2
                rest = rest[2:]
            else:
                break
        if not rest:
            print('usage: conformance.py check_liveness [--bond bond.json] '
                  '[--max-age secs] [--now unixts] <liveness.json> [...]')
            return 2
        return check_liveness_files(bond_path, max_age, now, rest)
    if len(argv) >= 2 and argv[1] == 'check_compromise':
        if len(argv) < 3:
            print('usage: conformance.py check_compromise <decl1.json> [...]')
            return 2
        return check_compromise_files(argv[2:])
    if len(argv) >= 2 and argv[1] == 'check_rotation':
        if len(argv) < 3:
            print('usage: conformance.py check_rotation <rotation1.json> [...]')
            return 2
        return check_rotation_files(argv[2:])
    if len(argv) >= 2 and argv[1] == 'check_revocation':
        if len(argv) < 3:
            print('usage: conformance.py check_revocation <rev1.json> [...]')
            return 2
        return check_revocation_files(argv[2:])
    if len(argv) >= 2 and argv[1] == 'check_policy':
        if len(argv) < 3:
            print('usage: conformance.py check_policy <policy1.json> [...]')
            return 2
        return check_policy_files(argv[2:])
    if len(argv) >= 2 and argv[1] == 'check_draft':
        policy_path = None
        now = None
        rest = argv[2:]
        while rest and rest[0].startswith('--'):
            opt = rest[0]
            if opt == '--policy' and len(rest) >= 2:
                policy_path, rest = rest[1], rest[2:]
            elif opt == '--now' and len(rest) >= 2:
                try:
                    now = int(rest[1])
                except ValueError:
                    print('--now must be an int (unix time)')
                    return 2
                rest = rest[2:]
            else:
                break
        if not rest:
            print('usage: conformance.py check_draft [--policy policy.json] '
                  '[--now unixts] <draft.json> [...]')
            return 2
        return check_draft_files(policy_path, now, rest)
    if len(argv) >= 2 and argv[1] == 'check_notif_ack':
        if len(argv) < 3:
            print('usage: conformance.py check_notif_ack <ack1.txt> [...]')
            return 2
        return check_notif_ack_files(argv[2:])
    if len(argv) >= 2 and argv[1] == 'check_notif_record':
        if len(argv) < 3:
            print('usage: conformance.py check_notif_record '
                  '<record1.json | notif_dir> [...]')
            return 2
        return check_notif_record_files(argv[2:])
    if len(argv) >= 2 and argv[1] == 'check_key_status':
        rest = argv[2:]
        exit_code = None
        paths = []
        i = 0
        while i < len(rest):
            if rest[i] == '--exit-code' and i + 1 < len(rest):
                exit_code = int(rest[i + 1])
                i += 2
            else:
                paths.append(rest[i])
                i += 1
        if not paths:
            print('usage: conformance.py check_key_status [--exit-code N] '
                  '<report1.txt> [...]')
            return 2
        return check_key_status_files(paths, exit_code)
    if len(argv) >= 2 and argv[1] == 'check_revoke_list':
        if len(argv) < 3:
            print('usage: conformance.py check_revoke_list <report1.txt> [...]')
            return 2
        return check_revoke_list_files(argv[2:])
    if len(argv) >= 2 and argv[1] == 'check_notif_status':
        if len(argv) < 3:
            print('usage: conformance.py check_notif_status <report.txt> [...]')
            return 2
        return check_notif_status_files(argv[2:])
    if len(argv) >= 2 and argv[1] == 'check_dm_fetch':
        if len(argv) < 3:
            print('usage: conformance.py check_dm_fetch <report.txt> [...]')
            return 2
        return check_dm_fetch_files(argv[2:])
    if len(argv) >= 2 and argv[1] == 'check_board_read':
        if len(argv) < 3:
            print('usage: conformance.py check_board_read <report.txt> [...]')
            return 2
        return check_board_read_files(argv[2:])
    if len(argv) >= 2 and argv[1] == 'check_board_decide_fetch':
        if len(argv) < 3:
            print('usage: conformance.py check_board_decide_fetch '
                  '<report.txt> [...]')
            return 2
        return check_board_decide_fetch_files(argv[2:])
    if len(argv) >= 2 and argv[1] == 'check_board_draft_fetch':
        if len(argv) < 3:
            print('usage: conformance.py check_board_draft_fetch '
                  '<report.txt> [...]')
            return 2
        return check_board_draft_fetch_files(argv[2:])
    if len(argv) >= 2 and argv[1] == 'check_board_fetch_all':
        if len(argv) < 3:
            print('usage: conformance.py check_board_fetch_all '
                  '<report.txt> [...]')
            return 2
        return check_board_fetch_all_files(argv[2:])
    if len(argv) >= 2 and argv[1] == 'check_pub':
        if len(argv) < 3:
            print('usage: conformance.py check_pub <report.txt> [...]')
            return 2
        return check_pub_files(argv[2:])
    if len(argv) >= 2 and argv[1] == 'check_governance':
        if len(argv) < 3:
            print('usage: conformance.py check_governance <report.txt> [...]')
            return 2
        return check_governance_files(argv[2:])
    if len(argv) >= 2 and argv[1] == 'check_revoke_fetch':
        if len(argv) < 3:
            print('usage: conformance.py check_revoke_fetch '
                  '<report.txt> [...]')
            return 2
        return check_revoke_fetch_files(argv[2:])
    if len(argv) >= 2 and argv[1] == 'check_rotate_fetch':
        if len(argv) < 3:
            print('usage: conformance.py check_rotate_fetch '
                  '<report.txt> [...]')
            return 2
        return check_rotate_fetch_files(argv[2:])
    if len(argv) >= 2 and argv[1] == 'check_compromise_fetch':
        if len(argv) < 3:
            print('usage: conformance.py check_compromise_fetch '
                  '<report.txt> [...]')
            return 2
        return check_compromise_fetch_files(argv[2:])
    if len(argv) >= 2 and argv[1] == 'check_liveness_verify':
        if len(argv) < 3:
            print('usage: conformance.py check_liveness_verify '
                  '<report.txt> [...]')
            return 2
        return check_liveness_verify_files(argv[2:])
    if len(argv) >= 2 and argv[1] == 'check_liveness_report':
        if len(argv) < 3:
            print('usage: conformance.py check_liveness_report '
                  '<report.txt> [...]')
            return 2
        return check_liveness_report_files(argv[2:])
    if len(argv) >= 2 and argv[1] == 'check_verify_binding':
        if len(argv) < 3:
            print('usage: conformance.py check_verify_binding '
                  '<report.txt> [...]')
            return 2
        return check_verify_binding_files(argv[2:])
    if len(argv) >= 2 and argv[1] == 'check_verify_unbinding':
        if len(argv) < 3:
            print('usage: conformance.py check_verify_unbinding '
                  '<report.txt> [...]')
            return 2
        return check_verify_unbinding_files(argv[2:])
    if len(argv) >= 2 and argv[1] == 'check_renew':
        if len(argv) < 3:
            print('usage: conformance.py check_renew '
                  '<report.txt> [...]')
            return 2
        return check_renew_files(argv[2:])
    if len(argv) >= 2 and argv[1] == 'check_board_join':
        if len(argv) < 3:
            print('usage: conformance.py check_board_join '
                  '<report.txt> [...]')
            return 2
        return check_board_join_files(argv[2:])
    if len(argv) >= 2 and argv[1] == 'check_board_send':
        if len(argv) < 3:
            print('usage: conformance.py check_board_send '
                  '<report.txt> [...]')
            return 2
        return check_board_send_files(argv[2:])
    if len(argv) >= 2 and argv[1] == 'check_board_create':
        if len(argv) < 3:
            print('usage: conformance.py check_board_create '
                  '<report.txt> [...]')
            return 2
        return check_board_create_files(argv[2:])
    if len(argv) >= 2 and argv[1] == 'check_verify_board_decision':
        if len(argv) < 3:
            print('usage: conformance.py check_verify_board_decision '
                  '<report.txt> [...]')
            return 2
        return check_verify_board_decision_files(argv[2:])
    if len(argv) >= 2 and argv[1] == 'check_board_verify':
        if len(argv) < 3:
            print('usage: conformance.py check_board_verify '
                  '<report.txt> [...]')
            return 2
        return check_board_verify_files(argv[2:])
    if len(argv) >= 2 and argv[1] == 'check_board_decide':
        if len(argv) < 3:
            print('usage: conformance.py check_board_decide '
                  '<report.txt> [...]')
            return 2
        return check_board_decide_files(argv[2:])
    if len(argv) >= 2 and argv[1] == 'check_board_cosign':
        if len(argv) < 3:
            print('usage: conformance.py check_board_cosign '
                  '<report.txt> [...]')
            return 2
        return check_board_cosign_files(argv[2:])
    if len(argv) >= 2 and argv[1] == 'check_dm_recv':
        if len(argv) < 3:
            print('usage: conformance.py check_dm_recv <report.txt> [...]')
            return 2
        return check_dm_recv_files(argv[2:])
    if len(argv) >= 2 and argv[1] == 'check_dm_send':
        if len(argv) < 3:
            print('usage: conformance.py check_dm_send <report.txt> [...]')
            return 2
        return check_dm_send_files(argv[2:])
    if len(argv) >= 2 and argv[1] == 'check_revoke_import':
        if len(argv) < 3:
            print('usage: conformance.py check_revoke_import <report.txt> [...]')
            return 2
        return check_revoke_import_files(argv[2:])
    if len(argv) >= 2 and argv[1] == 'check_compromise_import':
        if len(argv) < 3:
            print('usage: conformance.py check_compromise_import <report.txt> [...]')
            return 2
        return check_compromise_import_files(argv[2:])
    if len(argv) >= 2 and argv[1] == 'check_compromise_declare':
        if len(argv) < 3:
            print('usage: conformance.py check_compromise_declare <report.txt> [...]')
            return 2
        return check_compromise_declare_files(argv[2:])
    if len(argv) >= 2 and argv[1] == 'check_compromise_withdraw':
        if len(argv) < 3:
            print('usage: conformance.py check_compromise_withdraw <report.txt> [...]')
            return 2
        return check_compromise_withdraw_files(argv[2:])
    if len(argv) >= 2 and argv[1] == 'check_init':
        if len(argv) < 3:
            print('usage: conformance.py check_init <report.txt> [...]')
            return 2
        return check_init_files(argv[2:])
    if len(argv) >= 2 and argv[1] == 'check_draft_notify':
        if len(argv) < 3:
            print('usage: conformance.py check_draft_notify <report.txt> [...]')
            return 2
        return check_draft_notify_files(argv[2:])
    if len(argv) >= 2 and argv[1] == 'check_rotation_downgrade':
        if len(argv) < 3:
            print('usage: conformance.py check_rotation_downgrade '
                  '<stderr.txt> [...]')
            return 2
        return check_rotation_downgrade_files(argv[2:])
    if len(argv) >= 2 and argv[1] == 'check_warnings':
        if len(argv) < 3:
            print('usage: conformance.py check_warnings <stderr.txt> [...]')
            return 2
        return check_compromise_warnings_files(argv[2:])
    if len(argv) >= 2 and argv[1] == 'check_verify_rotation':
        if len(argv) < 3:
            print('usage: conformance.py check_verify_rotation '
                  '<report.txt> [...]')
            return 2
        return check_verify_rotation_files(argv[2:])
    if len(argv) >= 2 and argv[1] == 'check_rotate':
        if len(argv) < 3:
            print('usage: conformance.py check_rotate '
                  '<report.txt> [...]')
            return 2
        return check_rotate_files(argv[2:])
    if len(argv) >= 2 and argv[1] == 'check_verify_revocation':
        if len(argv) < 3:
            print('usage: conformance.py check_verify_revocation '
                  '<report.txt> [...]')
            return 2
        return check_verify_revocation_files(argv[2:])
    if len(argv) >= 2 and argv[1] == 'check_revoke':
        if len(argv) < 3:
            print('usage: conformance.py check_revoke <report.txt> [...]')
            return 2
        return check_revoke_files(argv[2:])
    if len(argv) >= 2 and argv[1] == 'check_board_policy':
        if len(argv) < 3:
            print('usage: conformance.py check_board_policy '
                  '<report.txt> [...]')
            return 2
        return check_board_policy_files(argv[2:])
    if len(argv) >= 2 and argv[1] == 'check_board_policy_sign':
        if len(argv) < 3:
            print('usage: conformance.py check_board_policy_sign '
                  '<report.txt> [...]')
            return 2
        return check_board_policy_sign_files(argv[2:])
    if len(argv) >= 2 and argv[1] == 'check_verify_board_policy':
        if len(argv) < 3:
            print('usage: conformance.py check_verify_board_policy '
                  '<report.txt> [...]')
            return 2
        return check_verify_board_policy_files(argv[2:])
    if len(argv) >= 2 and argv[1] == 'check_verify':
        if len(argv) < 3:
            print('usage: conformance.py check_verify <report.txt> [...]')
            return 2
        return check_verify_files(argv[2:])
    if len(argv) >= 2 and argv[1] == 'check_propose':
        if len(argv) < 3:
            print('usage: conformance.py check_propose <report.txt> [...]')
            return 2
        return check_propose_files(argv[2:])
    if len(argv) >= 2 and argv[1] == 'check_accept':
        if len(argv) < 3:
            print('usage: conformance.py check_accept <report.txt> [...]')
            return 2
        return check_accept_files(argv[2:])
    if len(argv) >= 2 and argv[1] == 'check_challenge':
        if len(argv) < 3:
            print('usage: conformance.py check_challenge <report.txt> [...]')
            return 2
        return check_challenge_files(argv[2:])
    if len(argv) >= 2 and argv[1] == 'check_check':
        if len(argv) < 3:
            print('usage: conformance.py check_check <report.txt> [...]')
            return 2
        return check_check_files(argv[2:])
    if len(argv) >= 2 and argv[1] == 'selftest':
        return selftest()
    print('usage: conformance.py check <event.json> [...] | '
          'check_dm <recipient_secret_hex> <wrap.json> [...] | '
          'check_board <descriptor.json> [...] | '
          'check_decision [--policy policy.json] <decision.json> [...] | '
          'check_bond <bond.json> [...] | '
          'check_binding <binding.json> [...] | '
          'check_unbinding <unbinding.json> [...] | '
          'check_liveness [--bond bond.json] [--max-age secs] [--now unixts] '
          '<liveness.json> [...] | '
          'check_compromise <decl.json> [...] | '
          'check_rotation <rotation.json> [...] | '
          'check_revocation <rev.json> [...] | '
          'check_policy <policy.json> [...] | '
          'check_draft [--policy policy.json] [--now unixts] '
          '<draft.json> [...] | '
          'check_notif_ack <ack1.txt> [...] | '
          'check_notif_record <record1.json | notif_dir> [...] | '
          'check_key_status [--exit-code N] <report.txt> [...] | '
          'check_revoke_list <report.txt> [...] | '
          'check_notif_status <report.txt> [...] | '
          'check_dm_fetch <report.txt> [...] | '
          'check_board_read <report.txt> [...] | '
          'check_board_decide_fetch <report.txt> [...] | '
          'check_board_draft_fetch <report.txt> [...] | '
          'check_board_fetch_all <report.txt> [...] | '
          'check_pub <report.txt> [...] | '
          'check_governance <report.txt> [...] | '
          'check_revoke_fetch <report.txt> [...] | '
          'check_rotate_fetch <report.txt> [...] | '
          'check_compromise_fetch <report.txt> [...] | '
          'check_compromise_import <report.txt> [...] | '
          'check_compromise_declare <report.txt> [...] | '
          'check_compromise_withdraw <report.txt> [...] | '
          'check_liveness_verify <report.txt> [...] | '
          'check_liveness_report <report.txt> [...] | '
          'check_verify_binding <report.txt> [...] | '
          'check_verify_unbinding <report.txt> [...] | '
          'check_renew <report.txt> [...] | '
          'check_board_join <report.txt> [...] | '
          'check_board_send <report.txt> [...] | '
          'check_board_create <report.txt> [...] | '
          'check_verify_board_decision <report.txt> [...] | '
          'check_board_verify <report.txt> [...] | '
          'check_board_decide <report.txt> [...] | '
          'check_board_cosign <report.txt> [...] | '
          'check_dm_recv <report.txt> [...] | '
          'check_dm_send <report.txt> [...] | '
          'check_verify_rotation <report.txt> [...] | '
          'check_rotate <report.txt> [...] | '
          'check_verify_revocation <report.txt> [...] | '
          'check_board_policy <report.txt> [...] | '
          'check_board_policy_sign <report.txt> [...] | '
          'check_verify_board_policy <report.txt> [...] | '
          'check_verify <report.txt> [...] | '
          'check_propose <report.txt> [...] | '
          'check_accept <report.txt> [...] | '
          'check_challenge <report.txt> [...] | '
          'check_check <report.txt> [...] | '
          'selftest')
    return 2


if __name__ == '__main__':
    raise SystemExit(main(sys.argv))
