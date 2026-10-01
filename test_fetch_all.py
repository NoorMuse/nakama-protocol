"""board_fetch_all（30110+30111 横断 fetch、spec §22 / v0.17）のオフライン検証。

1 回の REQ で kinds=[30110, 30111] を購読すること、kind 横断の approvals
マージ（npub dedup）、finalized 判定（30110 あり→成立済み、30111 のみ→草案）、
--policy の意味論分離（成立済みは時点解決、草案は現行政策のみ）、--out の
内部マーカー剥がし、無効イベントのスキップをテストする。
リレーへの接続は不要（nostr_request をモック）。
使い方: python3 test_fetch_all.py
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
BOARD_ID = 'board-all-001'
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


def make_decision(signer, ts=TS, kind='admit', payload=None):
    d = {'protocol': 'nakama', 'version': 1, 'type': 'board-decision',
         'board_id': BOARD_ID, 'relay': RELAY, 'decision': kind,
         'payload': payload if payload is not None else {'candidate': signer[1]},
         'created_at': ts, 'approvals': []}
    return approve(d, signer)


def same_core_variant(signer, ref):
    """ref と同一コアハッシュ（board_id/decision/created_at/payload 一致）の
    別 approvals 版。30110/30111 の横断マージ用。"""
    d = {'protocol': 'nakama', 'version': 1, 'type': 'board-decision',
         'board_id': ref['board_id'], 'relay': ref['relay'],
         'decision': ref['decision'], 'payload': ref['payload'],
         'created_at': ref['created_at'], 'approvals': []}
    return approve(d, signer)


def pub_event(d, publisher, kind=n.DECISION_NOSTR_KIND(), ts=None):
    content = json.dumps(d, sort_keys=True, separators=(',', ':'), ensure_ascii=False)
    tags = [['d', n.decision_core_hash(d)], ['h', d['board_id']]]
    return n.sign_event(publisher, ts or int(time.time()), kind, tags, content)


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


def fetch_all(evs, policy_path=None, out_dir=None):
    """board_fetch_all をモック実行し (code, out, err, captured_req) を返す。"""
    captured = {}

    def fake_request(url, req, **k):
        captured['req'] = req
        return list(evs)

    n.nostr_request = fake_request
    tmpd = tempfile.mkdtemp()
    kf = os.path.join(tmpd, 'key.json')
    n.save_key(kf, secrets.token_bytes(32))
    try:
        ns = SimpleNamespace(keyfile=kf, relay='wss://x', board_id=BOARD_ID,
                             limit=20, auth=False, out=out_dir, policy=policy_path)
        code, out, err = run_cmd(n.cmd_board_fetch_all, ns)
        return code, out, err, captured.get('req')
    finally:
        del n.nostr_request


def main():
    A = keypair()
    B = keypair()
    C = keypair()
    P = keypair()  # publisher
    tmpd = tempfile.mkdtemp()

    def policy_file(pol):
        fp = os.path.join(tmpd, f'policy-{secrets.token_hex(4)}.json')
        with open(fp, 'w') as f:
            json.dump(pol, f)
        return fp

    print('case 1: 混在 fetch — 30110 と 30111 が受理され、他 kind はスキップ。'
          '1 回の REQ で両 kind を購読')
    d1 = make_decision(A)
    approve(d1, B)
    d2 = make_decision(C, ts=TS + 10)
    ev_fin = pub_event(d1, P[0])
    ev_draft = pub_event(d2, P[0], kind=n.DRAFT_NOSTR_KIND())
    ev_other = pub_event(d1, P[0], kind=9000)  # whitlist 外
    code, out, err, req = fetch_all([ev_fin, ev_draft, ev_other])
    assert code == 0, (code, err)
    assert req[0] == 'REQ', req
    assert req[2]['kinds'] == [n.DECISION_NOSTR_KIND(), n.DRAFT_NOSTR_KIND()], req[2]
    assert req[2]['#h'] == [BOARD_ID], req[2]
    assert '成立済み' in out, out
    assert '草案（回覧中）' in out, out
    assert '有効 2 件' in out, out
    assert 'スキップ 1 件' in out, out
    ok('混在 fetch + 他 kind スキップ + 単一 REQ')

    print('case 2: kind 横断マージ — 同一コアの 30110 と 30111 の approvals が '
          'npub dedup で統合される')
    base = make_decision(A)
    approve(base, B)                      # 30110 版: A, B
    draft_v = same_core_variant(C, base)  # 30111 版: C → 合計 {A,B,C}
    ev1 = pub_event(base, P[0])
    ev2 = pub_event(draft_v, P[0], kind=n.DRAFT_NOSTR_KIND())
    code, out, err, _ = fetch_all([ev1, ev2])
    assert code == 0, (code, err)
    assert 'approvals 3 つ' in out, out
    assert 'マージ後 1 件' in out, out
    ok('横断マージ')

    print('case 3: finalized 判定 — 30110 含むコアは成立済み、30111 のみは草案（回覧中）')
    d_fin = make_decision(A)
    d_draft = make_decision(B, ts=TS + 20)
    code, out, err, _ = fetch_all([pub_event(d_fin, P[0]),
                                   pub_event(d_draft, P[0], kind=n.DRAFT_NOSTR_KIND())])
    assert code == 0, (code, err)
    fin_line = [l for l in out.splitlines() if '成立済み' in l]
    draft_line = [l for l in out.splitlines() if '草案（回覧中）' in l]
    assert len(fin_line) == 1 and len(draft_line) == 1, out
    assert n.decision_core_hash(d_fin) in fin_line[0], out
    assert n.decision_core_hash(d_draft) in draft_line[0], out
    ok('finalized 判定')

    print('case 4: --policy — 成立済みは threshold n/m 充足/不足、'
          '草案は「草案: threshold n/m」マーカー＋注記')
    pol23 = make_policy([A, B, C], threshold=2)
    pf = policy_file(pol23)
    d_ok = make_decision(A)
    approve(d_ok, B)                       # 30110、承認 2 → 2/3 充足
    d_draft_pol = make_decision(C, ts=TS + 30)
    # 30111、承認 1 → 現行政策で 1/3 不足
    evs = [pub_event(d_ok, P[0]),
           pub_event(d_draft_pol, P[0], kind=n.DRAFT_NOSTR_KIND())]
    code, out, err, _ = fetch_all(evs, policy_path=pf)
    assert code == 0, (code, err)
    assert 'threshold 2/3 充足' in out, out
    assert '草案: threshold 1/3 不足' in out, out
    assert '草案は成立の証拠ではありません' in out, out
    assert '暫定です' in out, out
    ok('--policy 表示')

    print('case 5: 草案→成立の対応付け — 同一コアの草案と 30110 は 1 レコードに'
          '統合され二重表示されない')
    base5 = make_decision(A)
    approve(base5, B)
    draft5 = same_core_variant(C, base5)
    code, out, err, _ = fetch_all([pub_event(base5, P[0]),
                                   pub_event(draft5, P[0], kind=n.DRAFT_NOSTR_KIND())])
    assert code == 0, (code, err)
    assert out.count('admit') == 1, out   # 決定行は 1 行のみ
    assert '成立済み' in out and '草案（回覧中）' not in out, out
    assert 'マージ後 1 件' in out, out
    ok('草案と成立の統合')

    print('case 6: expect_kind 不一致 — 30111 イベントを 30110 として検証すると拒否')
    ev304 = pub_event(make_decision(A), P[0], kind=n.DRAFT_NOSTR_KIND())
    assert n.verify_board_decision_nostr_event(ev304, BOARD_ID,
                                               expect_kind=n.DECISION_NOSTR_KIND()) is None
    # sanity: 期待 kind が一致すれば受理
    assert n.verify_board_decision_nostr_event(ev304, BOARD_ID,
                                               expect_kind=n.DRAFT_NOSTR_KIND()) is not None
    ok('expect_kind チェック')

    print('case 7: --out — 保存 JSON に内部マーカーがなく、プレーン決定として'
          'board_cosign 互換')
    base7 = make_decision(A)
    approve(base7, B)
    draft7 = same_core_variant(C, base7)
    od = os.path.join(tmpd, 'out7')
    code, out, err, _ = fetch_all([pub_event(base7, P[0]),
                                   pub_event(draft7, P[0], kind=n.DRAFT_NOSTR_KIND())],
                                  out_dir=od)
    assert code == 0, (code, err)
    files = os.listdir(od)
    assert files == [f'{n.decision_core_hash(base7)}.json'], files
    with open(os.path.join(od, files[0])) as f:
        saved = json.load(f)
    assert 'nostr_kind' not in saved and 'finalized' not in saved, saved
    assert n.decision_structure_ok(saved), saved
    assert len(saved['approvals']) == 3, saved  # 横断マージ済み approvals
    ok('--out プリーン保存')

    print('case 8: 無効イベントのスキップ — 署名無効 / d タグ改ざんはスキップ、'
          '有効レコードに影響なし')
    good = make_decision(A)
    approve(good, B)
    ev_good = pub_event(good, P[0])
    # 署名無効
    ev_badsig = pub_event(make_decision(C, ts=TS + 40), P[0])
    ev_badsig = dict(ev_badsig)
    ev_badsig['sig'] = '00' * 64
    # d タグ改ざん（署名自体は有効、d タグがコアハッシュと不一致）
    tampered = make_decision(C, ts=TS + 50)
    content = json.dumps(tampered, sort_keys=True, separators=(',', ':'),
                         ensure_ascii=False)
    ev_badd = n.sign_event(P[0], int(time.time()), n.DECISION_NOSTR_KIND(),
                           [['d', 'ff' * 16], ['h', BOARD_ID]], content)
    code, out, err, _ = fetch_all([ev_good, ev_badsig, ev_badd])
    assert code == 0, (code, err)
    assert '有効 1 件' in out, out
    assert 'スキップ 2 件' in out, out
    assert '成立済み' in out and 'approvals 2 つ' in out, out
    ok('無効イベントのスキップ')

    print(f'{len(passed)} ケース通過')
    return 0


if __name__ == '__main__':
    sys.exit(main())
