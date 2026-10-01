"""board-decision の Nostr 公開 (spec §19 / v0.14) のオフライン検証。

decision_core_hash（approvals 追記でも不変）、board_decision_nostr_event
（kind 30110、d タグ=コアハッシュ、h タグ=board_id、署名者=publisher）、
verify_board_decision_nostr_event（三段階検証）、merge_decision_approvals
（同一コアの approvals マージ・npub で dedup）、board_decide_fetch
（モックイベントのパース＋ --out の <core_hash>.json 保存）をテストする。
リレーへの接続は不要。使い方: python3 test_board_decision_nostr.py
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
BOARD_ID = 'board-abc-123'
RELAY = 'wss://relay.example'
passed = []


def keypair():
    s = secrets.token_bytes(32)
    return s, n.npub_of(s), n.hexpub_of(s)


def make_decision(signer, board_id=BOARD_ID, ts=TS):
    """承認署名 1 つつきの admit 決定を作る（cmd_board_decide と同型）。"""
    payload = {'candidate': signer[1]}
    msg = n.board_decision_message(board_id, RELAY, 'admit', payload, ts)
    return {'protocol': 'nakama', 'version': 1, 'type': 'board-decision',
            'board_id': board_id, 'relay': RELAY, 'decision': 'admit',
            'payload': payload, 'created_at': ts,
            'approvals': [{'npub': signer[1],
                           'sig': n.sign_schnorr(signer[0], msg).hex()}]}


def pub_event_for(d, signer, ts=None, kind=n.DECISION_NOSTR_KIND(),
                  d_tag=None, h_tag=None):
    """board-decision を包む Nostr イベントを署名つきで作る（リレー経由相当）。"""
    content = json.dumps(d, sort_keys=True, separators=(',', ':'),
                         ensure_ascii=False)
    core = n.decision_core_hash(d)
    tags = [['d', d_tag if d_tag is not None else core],
            ['h', h_tag if h_tag is not None else d['board_id']]]
    return n.sign_event(signer, ts or int(time.time()), kind, tags, content)


def run_cmd(fn, ns):
    """cmd_* を実行し、(exit_code, stdout, stderr) を返す。"""
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


def main():
    A = keypair()  # 決定案の作成者
    B = keypair()  # 承認者
    C = keypair()  # 第三者 publisher
    D = keypair()  # 承認者 2
    d = make_decision(A)
    core = n.decision_core_hash(d)

    print('case 1: approvals 追記前後で core_hash が不変')
    msg = n.board_decision_message(BOARD_ID, RELAY, 'admit',
                                   {'candidate': A[1]}, TS)
    d2 = json.loads(json.dumps(d))
    d2['approvals'].append({'npub': B[1], 'sig': n.sign_schnorr(B[0], msg).hex()})
    assert n.decision_core_hash(d2) == core
    ok('cosign 追記でも d スロット安定')

    print('case 2: board_decision_nostr_event — kind 30110、d/h タグ、署名者は publisher')
    ev = n.board_decision_nostr_event(d, C[0])  # publisher は第三者 C（意図的）
    assert ev['kind'] == n.DECISION_NOSTR_KIND() == 30110
    assert ev['tags'] == [['d', core], ['h', BOARD_ID]]
    assert n.verify_event_sig(ev), 'Nostr 署名が無効'
    assert ev['pubkey'] == C[2], '署名者は publisher（決定の署名者ではない、§19.3）'
    assert json.loads(ev['content']) == d
    assert ev['content'] == json.dumps(d, sort_keys=True, separators=(',', ':'),
                                       ensure_ascii=False), 'content は canonical'
    ok('board_decision_nostr_event 構築')

    print('case 3: 正常イベントの検証通過')
    assert n.verify_board_decision_nostr_event(ev, BOARD_ID) == d
    ok('三段階検証を通過')

    print('case 4: d タグ改ざん → 拒否')
    bad_d = pub_event_for(d, C[0], d_tag='ff' * 16)
    assert n.verify_board_decision_nostr_event(bad_d, BOARD_ID) is None
    ok('d タグ不一致はスキップ')

    print('case 5: h タグ≠board_id → 拒否')
    bad_h = pub_event_for(d, C[0], h_tag='other-board')
    assert n.verify_board_decision_nostr_event(bad_h, BOARD_ID) is None
    # h タグと content の board_id の二重チェック: h=content の board_id だが指定 board と不一致
    bad_h2 = pub_event_for(make_decision(A, board_id='other-board'), C[0])
    assert n.verify_board_decision_nostr_event(bad_h2, BOARD_ID) is None
    ok('h タグ/board_id 不一致はスキップ')

    print('case 6: payload 形式違反の決定 → 拒否（構造検証、publish 前も同じ関数）')
    bad_d2 = json.loads(json.dumps(d))
    bad_d2['payload'] = {'reason': 'x'}  # admit は {'candidate'} のみ
    assert not n.decision_structure_ok(bad_d2)
    assert n.verify_board_decision_nostr_event(pub_event_for(bad_d2, C[0]), BOARD_ID) is None
    # unknown decision type
    bad_d3 = json.loads(json.dumps(d)); bad_d3['decision'] = 'vote'
    assert not n.decision_structure_ok(bad_d3)
    ok('payload 形式違反は拒否')

    print('case 7: Nostr 署名無効 → スキップ')
    bad_sig = pub_event_for(d, C[0])
    bad_sig['sig'] = '00' * 64
    assert n.verify_board_decision_nostr_event(bad_sig, BOARD_ID) is None
    ok('署名無効はスキップ')

    print('case 8: 同一コア 2 イベント（別 publisher）の approvals マージ — 和集合・重複除去')
    d_a = make_decision(A)
    d_a['approvals'].append({'npub': B[1], 'sig': n.sign_schnorr(B[0], msg).hex()})
    d_c = json.loads(json.dumps(d))
    d_c['approvals'] = [{'npub': B[1], 'sig': n.sign_schnorr(B[0], msg).hex()},
                        {'npub': D[1], 'sig': n.sign_schnorr(D[0], msg).hex()}]
    ev_a = n.board_decision_nostr_event(d_a, A[0])
    ev_c = n.board_decision_nostr_event(d_c, C[0])
    assert n.verify_board_decision_nostr_event(ev_a, BOARD_ID) is not None
    assert n.verify_board_decision_nostr_event(ev_c, BOARD_ID) is not None
    merged = n.merge_decision_approvals([d_a, d_c])
    assert len(merged) == 1, '同一コアは 1 件にマージ'
    assert {a['npub'] for a in merged[0]['approvals']} == {A[1], B[1], D[1]}, '和集合・重複除去'
    assert n.decision_core_hash(merged[0]) == core, 'マージ後もコアハッシュ一致'
    assert len(d_a['approvals']) == 2 and len(d_c['approvals']) == 2, '入力は破壊しない'
    ok('同一コアの approvals マージ')

    print('case 8+: fetch モック — 検証→マージ→表示→--out 保存の往復')
    tmpd = tempfile.mkdtemp()
    keyf = os.path.join(tmpd, 'key.json')
    n.save_key(keyf, C[0])
    evs = [pub_event_for(d_a, A[0]), pub_event_for(d_c, C[0]),
           pub_event_for(d_a, A[0], d_tag='ff' * 16)]  # 無効 1 件
    n.nostr_request = lambda url, req, **k: list(evs) if req[2].get('#h') == [BOARD_ID] else []
    outd = os.path.join(tmpd, 'decisions')
    try:
        ns = SimpleNamespace(keyfile=keyf, relay='wss://x', board_id=BOARD_ID,
                             limit=20, auth=False, out=outd)
        code, out, err = run_cmd(n.cmd_board_decide_fetch, ns)
    finally:
        del n.nostr_request
    assert code == 0, (code, err)
    assert 'マージ後 1 件' in out and 'スキップ 1 件' in out, out
    saved = os.listdir(outd)
    assert saved == [f'{core}.json'], saved
    with open(os.path.join(outd, saved[0])) as f:
        back = json.load(f)
    assert {a['npub'] for a in back['approvals']} == {A[1], B[1], D[1]}
    assert back['protocol'] == 'nakama' and back['type'] == 'board-decision'
    ok('fetch の --out 保存は board_read --governance --decisions に渡せる形')

    print('case 9: board_decide_pub の事前検証 — 無効な決定は publish せず exit 1')
    df = os.path.join(tmpd, 'bad-decision.json')
    with open(df, 'w') as f:
        json.dump(bad_d2, f)
    called = []
    real_publish = n.nostr_publish
    n.nostr_publish = lambda *a, **k: called.append(a) or (True, 'ok')
    try:
        ns = SimpleNamespace(keyfile=keyf, relay='wss://x', decision=df, auth=False)
        code, out, err = run_cmd(n.cmd_board_decide_pub, ns)
    finally:
        n.nostr_publish = real_publish
    assert code == 1, f'exit 1 を期待、得た: {code}'
    assert called == [], 'publish してはいけない'
    ok('board_decide_pub は無効な決定を拒否')

    print(f'\n{len(passed)} cases passed')


if __name__ == '__main__':
    main()
