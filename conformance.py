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

For the second implementer: passing `check` on your own events is the
criterion-1 evidence the NIP-F5 draft PR needs, passing `check_dm`
on wraps addressed to a nakama-built keypair proves NIP-17 wire
compatibility, and passing `check_board` on your descriptors proves
NIP-29 board wire compatibility with the reference implementation.
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

    grand = total + dm_total + board_total
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
    if len(argv) >= 2 and argv[1] == 'selftest':
        return selftest()
    print('usage: conformance.py check <event.json> [...] | '
          'check_dm <recipient_secret_hex> <wrap.json> [...] | '
          'check_board <descriptor.json> [...] | selftest')
    return 2


if __name__ == '__main__':
    raise SystemExit(main(sys.argv))
