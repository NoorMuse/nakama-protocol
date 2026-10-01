"""policy-update 決定の草案化 (spec §29 / v0.26) のオフライン検証。

§21.8 と §27.3 のスコープ外だった「policy-update 決定の草案化」を解禁。
新規コマンド・新規純粋関数なし（既存の board_decide / board_draft_pub /
board_draft_fetch / board_cosign / board_decide_pub / fetch_threshold_status /
resolve_policy_at の組み合わせ）。核心判断: 草案の承認（threshold・eligible
の判定）は現行政策の下で行い、草案の payload が提案する値は判定に使わない
（§29.2）。fetch 表示には判定基準と提案値の両方を出す（§29.4）。

テスト計画（spec §29.8）のケース 1〜6・8 をここで実装。ケース 7（v0.6 の
30 ケース governance 回帰）は test_governance.py の回帰維持で担保、
ケース 9（全ファイル回帰）は run_all で担保する。
リレーへの接続は不要（nostr_request / nostr_publish をモック）。
使い方: python3 test_policy_update_draft.py
"""
import contextlib
import io
import json
import os
import secrets
import sys
import tempfile
from types import SimpleNamespace

sys.path.insert(0, __file__.rsplit('/', 1)[0] or '.')
import nakama as n

TS = 1760000000  # 2026-09-28 相当（現時刻より過去 → 期限切れテストに使う）
BOARD_ID = 'board-polupd-001'
RELAY = 'wss://relay.example'
passed = []


def keypair():
    s = secrets.token_bytes(32)
    return s, n.npub_of(s), n.hexpub_of(s)


def make_policy(members, threshold, ts=TS, board_id=BOARD_ID):
    eligible = [m[1] for m in members]
    msg = n.board_policy_message(board_id, RELAY, threshold, eligible, ts)
    return {'protocol': 'nakama', 'version': 1, 'type': 'board-policy',
            'board_id': board_id, 'relay': RELAY, 'threshold': threshold,
            'eligible': eligible, 'created_at': ts,
            'signatures': [{'npub': m[1], 'sig': n.sign_schnorr(m[0], msg).hex()}
                           for m in members]}


def make_draft(decision, payload, signers, ts=TS, board_id=BOARD_ID):
    d = {'protocol': 'nakama', 'version': 1, 'type': 'board-decision',
         'board_id': board_id, 'relay': RELAY, 'decision': decision,
         'payload': payload, 'created_at': ts, 'approvals': []}
    for s in signers:
        msg = n.board_decision_message(board_id, RELAY, decision, payload, ts)
        d['approvals'].append({'npub': s[1], 'sig': n.sign_schnorr(s[0], msg).hex()})
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


def mock_relay(evs, published):
    """nostr_request / nostr_publish をモック（発行イベントを captured に記録）。"""
    real_req, real_pub = n.nostr_request, n.nostr_publish
    n.nostr_request = lambda url, req, **k: list(evs)
    n.nostr_publish = lambda *a, **k: published.append(a) or (True, 'ok')
    return real_req, real_pub


def main():
    members = [keypair() for _ in range(7)]   # a..g
    a, b, c = members[0], members[1], members[2]
    # 現行政策: threshold 3 / eligible 7（a..g）
    old_pol = make_policy(members, threshold=3)
    tmpd = tempfile.mkdtemp()
    pol_path = os.path.join(tmpd, 'policy.json')
    with open(pol_path, 'w') as f:
        json.dump(old_pol, f)

    # 規約変更案: threshold 2 / eligible 5（a,b,c,d,e）
    new_members = members[:5]
    new_elig_npubs = [m[1] for m in new_members]
    payload = {'threshold': 2, 'eligible': new_elig_npubs}

    # 1. policy-update 草案の pub→fetch 往復（kind 30111、三段階検証）
    d = make_draft('policy-update', payload, [a])
    draft_path = os.path.join(tmpd, 'draft.json')
    with open(draft_path, 'w') as f:
        json.dump(d, f)
    published = []
    real_req, real_pub = mock_relay([], published)
    try:
        ns = SimpleNamespace(keyfile=make_keyfile(tmpd, a[0]), relay=RELAY,
                             draft=draft_path, auth=False)
        code, out, _ = run_cmd(n.cmd_board_draft_pub, ns)
        assert code == 0 and published, out
        ev = published[0][1]
        assert ev['kind'] == 30111, f'草案は kind 30111: {ev["kind"]}'
        assert ev['pubkey'] == a[2], '署名者は publisher'
        assert n.verify_event_sig(ev), 'Nostr 署名（一段階）'
        dtags = [t[1] for t in ev['tags'] if t[0] == 'd']
        assert dtags == [n.decision_core_hash(d)], 'd タグ = core_hash'
        # fetch: 三段階検証（Nostr 署名→JSON パース→決定署名）を通る
        real_req2 = n.nostr_request
        n.nostr_request = lambda url, req, **k: [ev]
        ns2 = SimpleNamespace(keyfile=make_keyfile(tmpd, c[0]), relay=RELAY,
                              board_id=BOARD_ID, limit=20, auth=False,
                              out=None, policy=None)
        code, out, _ = run_cmd(n.cmd_board_draft_fetch, ns2)
        assert code == 0
        assert 'policy-update' in out, out
        n.nostr_request = real_req2
        back = n.verify_board_decision_nostr_event(ev, BOARD_ID,
                                                   expect_kind=n.DRAFT_NOSTR_KIND())
        assert back is not None and back['decision'] == 'policy-update'
        assert back['payload'] == payload
    finally:
        n.nostr_request, n.nostr_publish = real_req, real_pub
    ok('1: policy-update 草案の pub→fetch 往復（kind 30111・三段階検証）')

    # 2. 草案の threshold 表示は現行政策のみ（提案 2/5 でも現行 3/7 で判定）
    d2 = make_draft('policy-update', payload, [a, b])
    ev2 = n.decision_nostr_event(d2, a[0], kind=n.DRAFT_NOSTR_KIND())
    real_req, real_pub = mock_relay([ev2], [])
    try:
        ns = SimpleNamespace(keyfile=make_keyfile(tmpd, c[0]), relay=RELAY,
                             board_id=BOARD_ID, limit=20, auth=False,
                             out=None, policy=pol_path)
        code, out, _ = run_cmd(n.cmd_board_draft_fetch, ns)
        assert code == 0, out
        # 判定は現行規約のみ: approvals 2 / eligible 7、不足（threshold 3）
        assert '草案: threshold 2/7 不足' in out, out
        # 提案値は表示だけで判定に使わない
        assert '提案値: threshold 2/5' in out, out
        assert '現行規約の判定' in out, out
    finally:
        n.nostr_request, n.nostr_publish = real_req, real_pub
    ok('2: threshold 判定は現行政策のみ（2/5 提案でも 2/7 で表示・不足）')

    # 8. 提案値の表示: 判定基準と提案値の両方（表示形式は §29.4 で確定）
    line = n.draft_threshold_line(d2, False, 2, 7)
    assert line == '草案: threshold 2/7 不足（現行規約の判定） — 提案値: threshold 2/5', line
    # 非 policy-update 草案は従来形式のまま（既存テストの substring 互換）
    admit_d = make_draft('admit', {'candidate': a[1]}, [a])
    line2 = n.draft_threshold_line(admit_d, False, 1, 3)
    assert line2 == '草案: threshold 1/3 不足', line2
    ok('8: policy-update 草案の表示は「判定基準（現行規約）＋提案値」の両方')

    # 3. cosign フロー: 旧 eligible の署名 → 再公開 → fetch マージで統合
    d3 = make_draft('policy-update', payload, [a])
    d3_path = os.path.join(tmpd, 'draft3.json')
    with open(d3_path, 'w') as f:
        json.dump(d3, f)
    published = []
    real_req, real_pub = mock_relay([], published)
    try:
        # b（旧 eligible）が cosign
        ns = SimpleNamespace(keyfile=make_keyfile(tmpd, b[0]),
                             decision=d3_path, out=d3_path)
        code, out, _ = run_cmd(n.cmd_board_cosign, ns)
        assert code == 0, out
        with open(d3_path) as f:
            d3s = json.load(f)
        assert len(d3s['approvals']) == 2
        # b が自分のスロットに再公開（方式 B）
        ns = SimpleNamespace(keyfile=make_keyfile(tmpd, b[0]), relay=RELAY,
                             draft=d3_path, auth=False)
        code, out, _ = run_cmd(n.cmd_board_draft_pub, ns)
        assert code == 0 and published
        ev_rep = published[0][1]
        assert ev_rep['kind'] == 30111 and ev_rep['pubkey'] == b[2]
        # fetch: a の旧版 + b の追記版 → マージで approvals 統合
        ev_a = n.decision_nostr_event(d3, a[0], kind=n.DRAFT_NOSTR_KIND())
        n.nostr_request = lambda url, req, **k: [ev_a, ev_rep]
        ns = SimpleNamespace(keyfile=make_keyfile(tmpd, c[0]), relay=RELAY,
                             board_id=BOARD_ID, limit=20, auth=False,
                             out=None, policy=pol_path)
        code, out, _ = run_cmd(n.cmd_board_draft_fetch, ns)
        assert code == 0 and '草案: threshold 2/7 不足' in out, out
        merged = n.merge_decision_approvals(
            [n.verify_board_decision_nostr_event(e, BOARD_ID,
                                                 expect_kind=n.DRAFT_NOSTR_KIND())
             for e in (ev_a, ev_rep)])
        assert len(merged) == 1 and len(merged[0]['approvals']) == 2
    finally:
        n.nostr_request, n.nostr_publish = real_req, real_pub
    ok('3: cosign（旧 eligible）→ 再公開 → fetch マージで approvals 統合')

    # 4. 成立: board_decide_pub で 30110 を公開 → resolve_policy_at が新政策を返す
    #    → verify_board_decision が新政策で検証
    d4 = make_draft('policy-update', payload, [a, b, c])  # 旧規約 3/7 を満たす
    d4_path = os.path.join(tmpd, 'dec4.json')
    with open(d4_path, 'w') as f:
        json.dump(d4, f)
    published = []
    real_req, real_pub = mock_relay([], published)
    try:
        ns = SimpleNamespace(keyfile=make_keyfile(tmpd, a[0]), relay=RELAY,
                             decision=d4_path, auth=False)
        code, out, _ = run_cmd(n.cmd_board_decide_pub, ns)
        assert code == 0 and published, out
        ev4 = published[0][1]
        assert ev4['kind'] == 30110, '成立宣言は kind 30110'
        finalized = n.verify_board_decision_nostr_event(ev4, BOARD_ID)
        assert finalized is not None
        # resolve_policy_at が新政策を返す
        th, elig = n.resolve_policy_at(old_pol, [finalized], TS + 1)
        assert (th, elig) == (2, new_elig_npubs), (th, elig)
        # 新政策で検証: a,b,c は新 eligible 内の有効署名 → 3 ≥ 2 で充足
        new_pol = make_policy(new_members, threshold=2, ts=TS + 1)
        ok4, nn, mm = n.verify_board_decision(finalized, new_pol)
        assert ok4 and (nn, mm) == (3, 2), (ok4, nn, mm)
    finally:
        n.nostr_request, n.nostr_publish = real_req, real_pub
    ok('4: 成立（30110）→ resolve_policy_at が新政策（2/5）→ 新政策で検証充足')

    # 5. 成立後の草案再評価: 新政策で fetch し直すと threshold 表示が再計算
    new_pol = make_policy(new_members, threshold=2, ts=TS + 1)
    new_pol_path = os.path.join(tmpd, 'policy-new.json')
    with open(new_pol_path, 'w') as f:
        json.dump(new_pol, f)
    # 回覧中の admit 草案（a の署名 1 つ）を新政策で fetch
    d5 = make_draft('admit', {'candidate': c[1]}, [a])
    ev5 = n.decision_nostr_event(d5, a[0], kind=n.DRAFT_NOSTR_KIND())
    real_req, real_pub = mock_relay([ev5], [])
    try:
        ns = SimpleNamespace(keyfile=make_keyfile(tmpd, b[0]), relay=RELAY,
                             board_id=BOARD_ID, limit=20, auth=False,
                             out=None, policy=new_pol_path)
        code, out, _ = run_cmd(n.cmd_board_draft_fetch, ns)
        assert code == 0
        # 新政策 2/5 で再計算: a は新 eligible 内 → threshold 1/5 不足
        assert '草案: threshold 1/5 不足' in out, out
        assert '草案: threshold 1/7' not in out, out
    finally:
        n.nostr_request, n.nostr_publish = real_req, real_pub
    ok('5: 成立後の fetch で回覧中草案の threshold 表示が新政策（1/5）で再計算')

    # 6. 期限: expires_at 付き policy-update 草案の期限切れで board_draft_pub が拒否
    exp_payload = dict(payload)
    exp_payload['expires_at'] = TS - 100  # 現時刻より過去
    d6 = make_draft('policy-update', exp_payload, [a])
    d6_path = os.path.join(tmpd, 'draft6.json')
    with open(d6_path, 'w') as f:
        json.dump(d6, f)
    assert n.draft_is_expired(d6, 1 << 31), '期限切れ判定が効くこと'
    real_req, real_pub = mock_relay([], [])
    try:
        n.nostr_publish = lambda *a_, **k: (False, 'should-not-reach')
        ns = SimpleNamespace(keyfile=make_keyfile(tmpd, a[0]), relay=RELAY,
                             draft=d6_path, auth=False)
        code, out, err = run_cmd(n.cmd_board_draft_pub, ns)
        assert code == 1 and '期限切れ' in err, (code, out, err)
    finally:
        n.nostr_request, n.nostr_publish = real_req, real_pub
    ok('6: 期限切れ policy-update 草案の board_draft_pub は拒否（exit 1）')

    print(f'\n{len(passed)} cases passed.')
    # ケース 7 は test_governance.py（30 ケース）の回帰維持で担保、
    # ケース 9 は全テストファイルの回帰維持で担保。


if __name__ == '__main__':
    main()
