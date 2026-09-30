"""cosign 回覧の Nostr 化 (spec §21 / v0.16) のオフライン検証。

decision_nostr_event の kind パラメータ化（30103/30104）、
verify_board_decision_nostr_event の kind 引数化、DRAFT_NOSTR_KIND=30104 の
草案イベント構築・検証、方式 B の往復（cosign 追記 → 自分のスロットに再公開 →
fetch マージで approvals 増）、board_draft_pub の無効草案拒否、board_draft_fetch
--policy の「草案」マーカー表示、草案 → board_decide_pub（30103）の core_hash 一致
をテストする。リレーへの接続は不要（nostr_request / nostr_publish をモック）。
使い方: python3 test_draft_nostr.py
"""
import contextlib
import io
import json
import os
import secrets
import sys
import tempfile
import time
from types import SimpleNamespace

sys.path.insert(0, __file__.rsplit('/', 1)[0] or '.')
import nakama as n

TS = 1760000000
BOARD_ID = 'board-draft-001'
RELAY = 'wss://relay.example'
passed = []


def keypair():
    s = secrets.token_bytes(32)
    return s, n.npub_of(s), n.hexpub_of(s)


def make_policy(members, threshold=2, board_id=BOARD_ID, ts=TS):
    eligible = [m[1] for m in members]
    msg = n.board_policy_message(board_id, RELAY, threshold, eligible, ts)
    return {'protocol': 'nakama', 'version': 1, 'type': 'board-policy',
            'board_id': board_id, 'relay': RELAY, 'threshold': threshold,
            'eligible': eligible, 'created_at': ts,
            'signatures': [{'npub': m[1], 'sig': n.sign_schnorr(m[0], msg).hex()}
                           for m in members]}


def make_draft(signer, board_id=BOARD_ID, ts=TS, extra_approvals=()):
    d = {'protocol': 'nakama', 'version': 1, 'type': 'board-decision',
         'board_id': board_id, 'relay': RELAY, 'decision': 'admit',
         'payload': {'candidate': signer[1]}, 'created_at': ts,
         'approvals': []}
    for ap in (signer,) + tuple(extra_approvals):
        msg = n.board_decision_message(d['board_id'], d['relay'], d['decision'],
                                       d['payload'], d['created_at'])
        d['approvals'].append({'npub': ap[1],
                               'sig': n.sign_schnorr(ap[0], msg).hex()})
    return d


def run_cmd(fn, ns):
    out = io.StringIO()
    err = io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        try:
            fn(ns)
        except SystemExit as e:
            return (e.code if isinstance(e.code, int) else 0), out.getvalue(), err.getvalue()
    return 0, out.getvalue(), err.getvalue()


def ok(name):
    passed.append(name)
    print(f'  ok: {name}')


def make_keyfile(tmpd, secret):
    kf = os.path.join(tmpd, 'key.json')
    n.save_key(kf, secret)
    return kf


def main():
    a, b, c = keypair(), keypair(), keypair()
    d = make_draft(a)

    # 1. draft イベント構築（kind 30104・d タグ=core_hash・h タグ=board_id・署名者 == publisher）
    ev = n.decision_nostr_event(d, a[0], kind=n.DRAFT_NOSTR_KIND)
    assert ev['kind'] == 30104
    dtags = [t[1] for t in ev['tags'] if t[0] == 'd']
    htags = [t[1] for t in ev['tags'] if t[0] == 'h']
    assert dtags == [n.decision_core_hash(d)], 'd タグは core_hash'
    assert htags == [BOARD_ID], 'h タグは board_id'
    assert ev['pubkey'] == a[2], '署名者は publisher'
    assert n.verify_event_sig(ev)
    ok('draft イベント構築（kind 30104・d=core_hash・h=board_id・署名者=publisher）')

    # 2. 正常な draft イベントの検証通過（kind 引数化）
    back = n.verify_board_decision_nostr_event(ev, BOARD_ID, expect_kind=n.DRAFT_NOSTR_KIND)
    assert back is not None and back['decision'] == 'admit'
    # kind が違えば拒否（既定値 30103 で草案は通らない）
    assert n.verify_board_decision_nostr_event(ev, BOARD_ID) is None
    # kind 30103 イベントを草案期待で拒否
    ev103 = n.board_decision_nostr_event(d, a[0])
    assert n.verify_board_decision_nostr_event(ev103, BOARD_ID, expect_kind=n.DRAFT_NOSTR_KIND) is None
    ok('kind 引数化した verify（30104 通過・既定 30103 で草案拒否・30103 を草案期待で拒否）')

    # 3. 別の publisher の同コア草案 2 イベントの approvals マージ
    d2 = make_draft(a, extra_approvals=(b,))  # 承認 b つきの同コア版
    ev2 = n.decision_nostr_event(d2, b[0], kind=n.DRAFT_NOSTR_KIND)
    got = [n.verify_board_decision_nostr_event(e, BOARD_ID, expect_kind=n.DRAFT_NOSTR_KIND)
           for e in (ev, ev2)]
    assert all(got)
    merged = n.merge_decision_approvals(got)
    assert len(merged) == 1, '同一コアは 1 件にマージ'
    npubs = {x['npub'] for x in merged[0]['approvals']}
    assert npubs == {a[1], b[1]}, f'approvals の和集合: {npubs}'
    ok('別 publisher の同コア草案 2 イベントの approvals マージ（重複除去・和集合）')

    # 4. threshold 不足の草案に --policy 表示 → 草案マーカー
    tmpd = tempfile.mkdtemp()
    pol = make_policy([a, b, c], threshold=2)
    pol_path = os.path.join(tmpd, 'policy.json')
    with open(pol_path, 'w') as f:
        json.dump(pol, f)
    evs = [ev]
    real_req = n.nostr_request
    n.nostr_request = lambda url, req, **k: list(evs) if req[2]['kinds'] == [30104] else []
    try:
        ns = SimpleNamespace(keyfile=make_keyfile(tmpd, c[0]), relay=RELAY,
                             board_id=BOARD_ID, limit=20, auth=False, out=None,
                             policy=pol_path)
        code, out, _ = run_cmd(n.cmd_board_draft_fetch, ns)
        assert code == 0
        assert '草案: threshold 1/3 不足' in out, out
        assert '草案（回覧中）' in out
    finally:
        n.nostr_request = real_req
    ok('--policy の草案表示（草案: threshold 1/3 不足 + 回覧中マーカー）')

    # 5. cosign 追記 → 再公開 → fetch マージで approvals が増える（方式 B の往復）
    tmpd = tempfile.mkdtemp()
    draft_path = os.path.join(tmpd, 'draft.json')
    with open(draft_path, 'w') as f:
        json.dump(d, f)
    ns_cos = SimpleNamespace(keyfile=make_keyfile(tmpd, b[0]),
                             decision=draft_path, out=draft_path)
    code, out, _ = run_cmd(n.cmd_board_cosign, ns_cos)
    assert code == 0
    with open(draft_path) as f:
        d_cosigned = json.load(f)
    assert len(d_cosigned['approvals']) == 2
    published = []
    real_pub = n.nostr_publish
    n.nostr_publish = lambda *a, **k: published.append(a) or (True, 'ok')
    try:
        ns_pub = SimpleNamespace(keyfile=make_keyfile(tmpd, b[0]), relay=RELAY,
                                 draft=draft_path, auth=False)
        code, out, _ = run_cmd(n.cmd_board_draft_pub, ns_pub)
        assert code == 0 and published
        ev_rep = published[0][1]
        assert ev_rep['kind'] == 30104 and ev_rep['pubkey'] == b[2]
        # fetch: publisher a の旧版 + publisher b の追記版
        evs = [ev, ev_rep]
        n.nostr_request = lambda url, req, **k: list(evs)
        ns2 = SimpleNamespace(keyfile=make_keyfile(tmpd, c[0]), relay=RELAY,
                              board_id=BOARD_ID, limit=20, auth=False, out=None,
                              policy=None)
        code, out, _ = run_cmd(n.cmd_board_draft_fetch, ns2)
        assert code == 0 and 'approvals 2 つ' in out, out
    finally:
        n.nostr_publish = real_pub
        n.nostr_request = real_req
    ok('方式 B の往復（cosign 追記 → 自分のスロットに再公開 → fetch マージで approvals 2）')

    # 6. 無効な草案（payload 違反）の publish 拒否（exit 1）
    tmpd = tempfile.mkdtemp()
    bad = dict(d)
    bad['payload'] = {'candidate': 'not-an-npub'}
    bad_path = os.path.join(tmpd, 'bad.json')
    with open(bad_path, 'w') as f:
        json.dump(bad, f)
    n.nostr_publish = lambda *a, **k: (False, 'should-not-reach')
    try:
        ns_bad = SimpleNamespace(keyfile=make_keyfile(tmpd, a[0]), relay=RELAY,
                                 draft=bad_path, auth=False)
        code, _, _ = run_cmd(n.cmd_board_draft_pub, ns_bad)
        assert code == 1, '無効な草案は exit 1'
    finally:
        n.nostr_publish = real_pub
    ok('無効な草案の publish 拒否（exit 1、publish 到達なし）')

    # 7. d タグ改ざんの拒否
    tampered = dict(ev)
    tampered['tags'] = [['d', 'deadbeef' * 4], ['h', BOARD_ID]]
    tampered = n.sign_event(a[0], int(time.time()), n.DRAFT_NOSTR_KIND,
                            tampered['tags'],
                            json.dumps(d, sort_keys=True, separators=(',', ':'),
                                       ensure_ascii=False))
    assert n.verify_board_decision_nostr_event(tampered, BOARD_ID,
                                              expect_kind=n.DRAFT_NOSTR_KIND) is None
    ok('d タグ改ざんの拒否')

    # 8. 草案 → threshold 達成 → board_decide_pub（30103）→ core_hash 一致
    d_full = make_draft(a, extra_approvals=(b,))
    pol2 = make_policy([a, b, c], threshold=2)
    tmpd = tempfile.mkdtemp()
    pol2_path = os.path.join(tmpd, 'policy2.json')
    with open(pol2_path, 'w') as f:
        json.dump(pol2, f)
    draft_full = n.decision_nostr_event(d_full, a[0], kind=n.DRAFT_NOSTR_KIND)
    n.nostr_request = lambda url, req, **k: list([draft_full])
    try:
        ns3 = SimpleNamespace(keyfile=make_keyfile(tmpd, c[0]), relay=RELAY,
                              board_id=BOARD_ID, limit=20, auth=False, out=None,
                              policy=pol2_path)
        code, out, _ = run_cmd(n.cmd_board_draft_fetch, ns3)
        assert '草案: threshold 2/3 充足' in out, out
    finally:
        n.nostr_request = real_req
    core_draft = n.decision_core_hash(d_full)
    final_path = os.path.join(tmpd, 'final.json')
    with open(final_path, 'w') as f:
        json.dump(d_full, f)
    published = []
    n.nostr_publish = lambda *a, **k: published.append(a) or (True, 'ok')
    try:
        ns4 = SimpleNamespace(keyfile=make_keyfile(tmpd, a[0]), relay=RELAY,
                              decision=final_path, auth=False)
        code, out, _ = run_cmd(n.cmd_board_decide_pub, ns4)
        assert code == 0
        ev103 = published[0][1]
        assert ev103['kind'] == 30103
        d103 = n.verify_board_decision_nostr_event(ev103, BOARD_ID)
        assert d103 is not None
        assert n.decision_core_hash(d103) == core_draft, '草案と完成決定の core_hash 一致'
    finally:
        n.nostr_publish = real_pub
    ok('草案 → threshold 達成 → board_decide_pub（30103）→ core_hash 一致')

    print(f'\n{len(passed)} tests passed.')


if __name__ == '__main__':
    main()
