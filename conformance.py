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
signatures over the canonical bond message).
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


# ---------- selftest: reference events built by nakama.py ----------

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

    grand = total + dm_total + board_total + dec_total + bond_total
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
    if len(argv) >= 2 and argv[1] == 'selftest':
        return selftest()
    print('usage: conformance.py check <event.json> [...] | '
          'check_dm <recipient_secret_hex> <wrap.json> [...] | '
          'check_board <descriptor.json> [...] | '
          'check_decision [--policy policy.json] <decision.json> [...] | '
          'check_bond <bond.json> [...] | '
          'selftest')
    return 2


if __name__ == '__main__':
    raise SystemExit(main(sys.argv))
