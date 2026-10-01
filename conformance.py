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

    rec_total = len(rec_pos) + len(rec_neg) + 2
    print(f'--- record {rec_total - rec_fails}/{rec_total} passed ---')
    fails += rec_fails

    grand = total + dm_total + board_total + dec_total + bond_total \
        + binding_total + live_total + cp_total + rt_total + rv_total \
        + ub_total + pl_total + dr_total + ack_total + rec_total + ks_total \
        + rl_total + ns_total + dmf_total + brd_total + bdf_total + ddf_total \
        + bfa_total + pub_total + gov_total + rf_total + rtf_total \
        + cf_total + lv_total + lr_total
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
          'check_liveness_verify <report.txt> [...] | '
          'check_liveness_report <report.txt> [...] | '
          'selftest')
    return 2


if __name__ == '__main__':
    raise SystemExit(main(sys.argv))
