"""草案の期限 (spec §24 / v0.19) のオフライン検証。

board_decide --expires-in/--expires-at（expires_at の換算・優先順位・
created_at 以下の拒否・非 int の拒否）、期限なし草案の後方互換、期限切れ草案
への board_cosign / board_draft_pub の拒否（exit 1）、board_draft_fetch /
board_fetch_all の [期限切れ] マーカー表示、fetch_all での同一コア混在時の
「成立済み」優先、純粋関数 draft_is_expired の分離をテストする。
リレーへの接続は不要（nostr_request / nostr_publish をモック）。
使い方: python3 test_draft_expiry.py
"""
import contextlib
import io
import json
import os
import secrets
import sys
import time
from types import SimpleNamespace

sys.path.insert(0, __file__.rsplit('/', 1)[0] or '.')
import nakama as n

TS = 1760000000
BOARD_ID = 'board-expiry-001'
RELAY = 'wss://relay.example'
passed = []


def keypair():
    s = secrets.token_bytes(32)
    return s, n.npub_of(s), n.hexpub_of(s)


def make_keyfile(secret):
    tmpd = secrets.token_hex(4)
    kf = os.path.join('/tmp', f'key-expiry-{tmpd}.json')
    n.save_key(kf, secret)
    return kf


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


def make_draft(signer, expires_at=None, board_id=BOARD_ID, ts=TS, extra_approvals=()):
    payload = {'candidate': signer[1]}
    if expires_at is not None:
        payload['expires_at'] = expires_at
    d = {'protocol': 'nakama', 'version': 1, 'type': 'board-decision',
         'board_id': board_id, 'relay': RELAY, 'decision': 'admit',
         'payload': payload, 'created_at': ts,
         'approvals': []}
    for ap in (signer,) + tuple(extra_approvals):
        msg = n.board_decision_message(d['board_id'], d['relay'], d['decision'],
                                       d['payload'], d['created_at'])
        d['approvals'].append({'npub': ap[1],
                               'sig': n.sign_schnorr(ap[0], msg).hex()})
    return d


def write_json(path, obj):
    with open(path, 'w') as f:
        json.dump(obj, f, indent=2, ensure_ascii=False)


def read_json(path):
    with open(path) as f:
        return json.load(f)


def main():
    a, b = keypair(), keypair()
    kf_a = make_keyfile(a[0])
    kf_b = make_keyfile(b[0])
    out_dir = f'/tmp/expiry-{secrets.token_hex(4)}'
    os.makedirs(out_dir, exist_ok=True)

    # 1. board_decide --expires-in 3600 → payload に expires_at = created_at + 3600
    p1 = os.path.join(out_dir, 'd1.json')
    ns = SimpleNamespace(board_id=BOARD_ID, relay=RELAY, decision='admit',
                         payload=json.dumps({'candidate': a[1]}),
                         old_moderators=None, expires_in=3600, expires_at=None,
                         out=p1, keyfile=kf_a)
    code, _, _ = run_cmd(n.cmd_board_decide, ns)
    assert code == 0, f'exit {code}'
    d1 = read_json(p1)
    assert d1['payload']['expires_at'] == d1['created_at'] + 3600, 'expires-in の換算'
    ok('1: --expires-in 3600 → expires_at = created_at + 3600')

    # 2. --expires-at のまま記録、両指定時は --expires-at が優先
    ts2 = int(time.time()) + 7200
    p2 = os.path.join(out_dir, 'd2.json')
    ns = SimpleNamespace(board_id=BOARD_ID, relay=RELAY, decision='admit',
                         payload=json.dumps({'candidate': a[1]}),
                         old_moderators=None, expires_in=999, expires_at=ts2,
                         out=p2, keyfile=kf_a)
    code, _, _ = run_cmd(n.cmd_board_decide, ns)
    assert code == 0, f'exit {code}'
    d2 = read_json(p2)
    assert d2['payload']['expires_at'] == ts2, '--expires-at が優先'
    ok('2: --expires-at はそのまま記録、両指定時は --expires-at が優先')

    # 3. expires_at が非 int（文字列）→ 拒否
    assert not n.validate_decision_payload(
        'admit', {'candidate': a[1], 'expires_at': 'tomorrow'}), '文字列 expires_at'
    p3 = os.path.join(out_dir, 'd3.json')
    ns = SimpleNamespace(board_id=BOARD_ID, relay=RELAY, decision='admit',
                         payload=json.dumps({'candidate': a[1], 'expires_at': 'tomorrow'}),
                         old_moderators=None, expires_in=None, expires_at=None,
                         out=p3, keyfile=kf_a)
    code, _, err = run_cmd(n.cmd_board_decide, ns)
    assert code == 1, f'exit {code}'
    ok('3: 非 int の expires_at → board_decide が拒否（exit 1）')

    # 4. expires_at <= created_at → 拒否（--expires-at 過去・--expires-in 0/負）
    for label, kw in (('past', {'expires_in': None, 'expires_at': int(time.time()) - 60}),
                      ('zero', {'expires_in': 0, 'expires_at': None}),
                      ('negative', {'expires_in': -10, 'expires_at': None})):
        p4 = os.path.join(out_dir, f'd4-{label}.json')
        ns = SimpleNamespace(board_id=BOARD_ID, relay=RELAY, decision='admit',
                             payload=json.dumps({'candidate': a[1]}),
                             old_moderators=None, out=p4, keyfile=kf_a, **kw)
        code, _, _ = run_cmd(n.cmd_board_decide, ns)
        assert code == 1, f'{label}: exit {code}'
    ok('4: expires_at <= created_at（過去・0・負）→ board_decide が拒否（exit 1）')

    # 5. 期限なし草案 → 従来通り作成・cosign 可（後方互換）
    p5 = os.path.join(out_dir, 'd5.json')
    ns = SimpleNamespace(board_id=BOARD_ID, relay=RELAY, decision='admit',
                         payload=json.dumps({'candidate': a[1]}),
                         old_moderators=None, expires_in=None, expires_at=None,
                         out=p5, keyfile=kf_a)
    code, _, _ = run_cmd(n.cmd_board_decide, ns)
    assert code == 0, f'exit {code}'
    d5 = read_json(p5)
    assert 'expires_at' not in d5['payload'], '期限なし草案に expires_at を付けない'
    p5b = os.path.join(out_dir, 'd5b.json')
    ns = SimpleNamespace(decision=p5, out=p5b, keyfile=kf_b)
    code, _, _ = run_cmd(n.cmd_board_cosign, ns)
    assert code == 0, f'cosign exit {code}'
    d5b = read_json(p5b)
    assert len(d5b['approvals']) == 2, 'cosign で承認 2'
    ok('5: 期限なし草案 → 作成・cosign 従来通り（後方互換）')

    # 6. 期限切れ草案への board_cosign → 拒否（exit 1）、署名は追加されない
    #    （手書き JSON の想定 — 過去時刻の expires_at を直接埋め込む）
    expired = make_draft(a, expires_at=TS - 3600)
    p6 = os.path.join(out_dir, 'd6.json')
    write_json(p6, expired)
    p6b = os.path.join(out_dir, 'd6b.json')
    ns = SimpleNamespace(decision=p6, out=p6b, keyfile=kf_b)
    code, _, err = run_cmd(n.cmd_board_cosign, ns)
    assert code == 1, f'exit {code}'
    assert not os.path.exists(p6b), '拒否時は出力ファイルを作らない'
    d6 = read_json(p6)
    assert len(d6['approvals']) == 1, '署名は追加されない'
    ok('6: 期限切れ草案への board_cosign → 拒否（exit 1）、署名追加なし')

    # 7. 期限内草案への board_cosign → 正常
    live = make_draft(a, expires_at=int(time.time()) + 3600)
    p7 = os.path.join(out_dir, 'd7.json')
    write_json(p7, live)
    p7b = os.path.join(out_dir, 'd7b.json')
    ns = SimpleNamespace(decision=p7, out=p7b, keyfile=kf_b)
    code, _, _ = run_cmd(n.cmd_board_cosign, ns)
    assert code == 0, f'exit {code}'
    assert len(read_json(p7b)['approvals']) == 2, '承認 2'
    ok('7: 期限内草案への board_cosign → 正常')

    # 8. 期限切れ草案の board_draft_pub → 拒否（exit 1、publish せず）
    real_pub = n.nostr_publish
    calls = []
    n.nostr_publish = lambda relay, ev, **k: (calls.append(ev), (True, 'ok'))[1]
    try:
        ns = SimpleNamespace(relay=RELAY, draft=p6, auth=False, keyfile=kf_a)
        code, _, err = run_cmd(n.cmd_board_draft_pub, ns)
        assert code == 1, f'exit {code}'
        assert not calls, '期限切れ草案は publish されない'
        # 期限内草案は publish される（回帰）
        ns = SimpleNamespace(relay=RELAY, draft=p7b, auth=False, keyfile=kf_a)
        code, _, _ = run_cmd(n.cmd_board_draft_pub, ns)
        assert code == 0 and len(calls) == 1, f'期限内草案 publish: exit {code}'
    finally:
        n.nostr_publish = real_pub
    ok('8: 期限切れ草案の board_draft_pub → 拒否（exit 1、publish せず）')

    # 9. board_draft_fetch / board_fetch_all で期限切れ草案に [期限切れ] マーカー
    ev_expired = n.decision_nostr_event(expired, a[0], kind=n.DRAFT_NOSTR_KIND)
    ev_live = n.decision_nostr_event(live, a[0], kind=n.DRAFT_NOSTR_KIND)
    real_req = n.nostr_request
    n.nostr_request = lambda url, req, **k: [ev_expired, ev_live]
    try:
        ns = SimpleNamespace(keyfile=kf_a, relay=RELAY, board_id=BOARD_ID,
                             limit=20, auth=False, out=None, policy=None)
        code, out, _ = run_cmd(n.cmd_board_draft_fetch, ns)
        assert code == 0, f'exit {code}'
        assert out.count('[期限切れ]') == 1, f'マーカーは期限切れ草案のみ:\n{out}'
        core_expired = n.decision_core_hash(expired)
        line = [ln for ln in out.splitlines() if core_expired in ln][0]
        assert '[期限切れ]' in line, '期限切れ草案の行にマーカー'

        code, out, _ = run_cmd(n.cmd_board_fetch_all, ns)
        assert code == 0, f'exit {code}'
        assert out.count('[期限切れ]') == 1, f'fetch_all のマーカー:\n{out}'
    finally:
        n.nostr_request = real_req
    ok('9: board_draft_fetch / board_fetch_all で期限切れ草案に [期限切れ] マーカー')

    # 10. fetch_all で同一コアに期限切れ 30104 ＋ 30103 混在 → 「成立済み」が優先
    ev_final = n.decision_nostr_event(expired, a[0], kind=n.DECISION_NOSTR_KIND)
    n.nostr_request = lambda url, req, **k: [ev_expired, ev_final]
    try:
        ns = SimpleNamespace(keyfile=kf_a, relay=RELAY, board_id=BOARD_ID,
                             limit=20, auth=False, out=None, policy=None)
        code, out, _ = run_cmd(n.cmd_board_fetch_all, ns)
        assert code == 0, f'exit {code}'
        assert '成立済み' in out, f'成立済み表示:\n{out}'
        assert '[期限切れ]' not in out, f'成立済みにはマーカーなし:\n{out}'
        assert 'マージ後 1 件' in out, '同一コアでマージ'
    finally:
        n.nostr_request = real_req
    ok('10: 同一コアに期限切れ 30104 ＋ 30103 混在 → 「成立済み」が優先')

    # 11. 純粋関数 draft_is_expired の分離 — 明示 now での判定
    now = int(time.time())
    assert n.draft_is_expired(make_draft(a, expires_at=now - 1), now) is True
    assert n.draft_is_expired(make_draft(a, expires_at=now), now) is True  # 境界
    assert n.draft_is_expired(make_draft(a, expires_at=now + 1), now) is False
    assert n.draft_is_expired(make_draft(a), now) is False  # 期限なし
    assert n.draft_is_expired({}, now) is False  # 壊れた入力
    assert n.draft_is_expired(make_draft(a, expires_at='tomorrow'), now) is False
    ok('11: draft_is_expired(d, now) — 境界・期限なし・不正型の純粋判定')

    print(f'\n{len(passed)} tests passed.')


if __name__ == '__main__':
    main()
