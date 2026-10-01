"""board_decide_fetch --policy の threshold 表示 (spec §20 / v0.15) のオフライン検証。

fetch_threshold_status（純粋関数）の充足/不足判定、時点解決（fetch 集合内の
policy-update 決定で決定時点の政策を解決）、--policy の事前検証（n-of-n
署名無効・board_id 不一致は拒否で exit 1）、--policy なしの回帰をテストする。
リレーへの接続は不要（nostr_request をモック）。使い方: python3 test_board_decision_fetch_policy.py
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
BOARD_ID = 'board-pol-001'
RELAY = 'wss://relay.example'
passed = []


def keypair():
    s = secrets.token_bytes(32)
    return s, n.npub_of(s), n.hexpub_of(s)


def make_policy(members, threshold=2, board_id=BOARD_ID, ts=TS):
    """n-of-n 署名つきの有効な board-policy cert。"""
    eligible = [m[1] for m in members]
    msg = n.board_policy_message(board_id, RELAY, threshold, eligible, ts)
    return {'protocol': 'nakama', 'version': 1, 'type': 'board-policy',
            'board_id': board_id, 'relay': RELAY, 'threshold': threshold,
            'eligible': eligible, 'created_at': ts,
            'signatures': [{'npub': m[1], 'sig': n.sign_schnorr(m[0], msg).hex()}
                           for m in members]}


def approve(d, signer):
    """決定 dict に signer の承認署名を追記する（msg は決定のもの）。"""
    msg = n.board_decision_message(d['board_id'], d['relay'], d['decision'],
                                   d['payload'], d['created_at'])
    d['approvals'].append({'npub': signer[1],
                           'sig': n.sign_schnorr(signer[0], msg).hex()})
    return d


def make_decision(signer, board_id=BOARD_ID, ts=TS, kind='admit', payload=None):
    d = {'protocol': 'nakama', 'version': 1, 'type': 'board-decision',
         'board_id': board_id, 'relay': RELAY, 'decision': kind,
         'payload': payload if payload is not None else {'candidate': signer[1]},
         'created_at': ts, 'approvals': []}
    return approve(d, signer)


def pub_event(d, publisher, ts=None):
    content = json.dumps(d, sort_keys=True, separators=(',', ':'), ensure_ascii=False)
    tags = [['d', n.decision_core_hash(d)], ['h', d['board_id']]]
    return n.sign_event(publisher, ts or int(time.time()), n.DECISION_NOSTR_KIND(),
                        tags, content)


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


def fetch_with(policy_path, evs):
    """--policy あり/なしの board_decide_fetch をモック実行し (code, out, err) を返す。"""
    n.nostr_request = lambda url, req, **k: list(evs)
    tmpd = tempfile.mkdtemp()
    kf = os.path.join(tmpd, 'key.json')
    n.save_key(kf, secrets.token_bytes(32))
    try:
        ns = SimpleNamespace(keyfile=kf, relay='wss://x', board_id=BOARD_ID,
                             limit=20, auth=False, out=None, policy=policy_path)
        return run_cmd(n.cmd_board_decide_fetch, ns)
    finally:
        del n.nostr_request


def main():
    A = keypair()
    B = keypair()
    C = keypair()
    OUT = keypair()  # 部外者・publisher
    P = keypair()    # publisher
    tmpd = tempfile.mkdtemp()

    def policy_file(pol):
        fp = os.path.join(tmpd, f'policy-{secrets.token_hex(4)}.json')
        with open(fp, 'w') as f:
            json.dump(pol, f)
        return fp

    pol23 = make_policy([A, B, C], threshold=2)
    pf = policy_file(pol23)

    print('case 1: threshold 2/3、有効 approvals 2 → threshold 2/3 充足')
    d = make_decision(A)
    approve(d, B)
    code, out, err = fetch_with(pf, [pub_event(d, P[0])])
    assert code == 0, (code, err)
    assert 'threshold 2/3 充足' in out, out
    ok('充足表示')

    print('case 2: 有効 approvals 1 → threshold 1/3 不足')
    d = make_decision(A)
    code, out, err = fetch_with(pf, [pub_event(d, P[0])])
    assert code == 0, (code, err)
    assert 'threshold 1/3 不足' in out, out
    ok('不足表示')

    print('case 3: 部外者の署名は無視（eligible のみ数える）')
    d = make_decision(A)
    approve(d, OUT)  # 部外者
    code, out, err = fetch_with(pf, [pub_event(d, P[0])])
    assert code == 0, (code, err)
    assert 'threshold 1/3 不足' in out, out
    assert 'approvals 1 つ' in out, out
    ok('部外者無視')

    print('case 4: 同一 npub の重複署名は 1 と数える（純粋関数）')
    d = make_decision(A)
    approve(d, A)  # 同一 npub の 2 つ目の署名
    assert len(d['approvals']) == 2
    is_ok, cnt, th = n.fetch_threshold_status(d, pol23, [d])
    assert (is_ok, cnt, th) == (False, 1, 3), (is_ok, cnt, th)
    ok('重複は 1')

    print('case 5: policy-update 決定があると決定時点の政策で解決される')
    # 初回政策 2/3 → policy-update で 1/3 に変更。変更前の決定は旧政策で裁かれる。
    pu = make_decision(A, ts=TS + 100, kind='policy-update',
                       payload={'threshold': 1, 'eligible': [A[1], B[1], C[1]]})
    approve(pu, B)  # policy-update は 2/3 で成立
    d_old = make_decision(A, ts=TS + 50)      # 変更前: 承認 1 → 旧 2/3 で不足
    d_new = make_decision(B, ts=TS + 150)    # 変更後: 承認 1 → 新 1/3 で充足
    code, out, err = fetch_with(pf, [pub_event(pu, P[0]), pub_event(d_old, P[0]),
                                     pub_event(d_new, P[0])])
    assert code == 0, (code, err)
    assert out.count('threshold 1/3 不足') == 1, out      # d_old: 旧政策 2/3 のまま
    assert out.count('threshold 1/3 充足') == 1, out       # d_new: 新政策 1/3 で充足
    assert 'threshold 2/3 充足' in out, out              # pu 自身: 自分は除外し旧政策で充足
    ok('時点解決')

    print('case 6: 無効な policy cert（n-of-n 署名不足）→ 拒否で exit 1')
    bad_pol = make_policy([A, B, C], threshold=2)
    bad_pol['signatures'] = bad_pol['signatures'][:2]  # 全員の署名が必要だが 2/3 のみ
    assert not n.verify_board_policy_cert(bad_pol)
    code, out, err = fetch_with(policy_file(bad_pol), [pub_event(d, P[0])])
    assert code == 1, (code, out, err)
    assert '検証に失敗' in err, err
    ok('無効 policy は拒否')

    print('case 7: board_id 不一致の policy → 拒否で exit 1')
    other_pol = make_policy([A, B, C], threshold=2, board_id='other-board')
    code, out, err = fetch_with(policy_file(other_pol), [pub_event(d, P[0])])
    assert code == 1, (code, out, err)
    assert '一致しません' in err, err
    ok('board_id 不一致は拒否')

    print('case 8: --policy なし → 従来通りの表示（回帰）')
    d = make_decision(A)
    approve(d, B)
    code, out, err = fetch_with(None, [pub_event(d, P[0])])
    assert code == 0, (code, err)
    assert 'threshold' not in out, out
    assert 'approvals 2 つ' in out, out
    assert '暫定' not in out, out
    ok('--policy なし回帰')

    print(f'{len(passed)} ケース通過')
    return 0


if __name__ == '__main__':
    sys.exit(main())
