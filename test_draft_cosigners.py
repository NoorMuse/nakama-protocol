"""承認者への草案通知 board_draft_notify --cosigners (spec §27 / v0.24) のオフライン検証。

§25.1 の既定動作（発行者通知）は不変のまま、--cosigners 指定時に
threshold 未達・期限間近の草案について未署名の eligible 承認者にも
NIP-17 DM で通知する。--policy 必須、宛先ごとの送信記録
(<core>:<reason>:<recipient_hex>.json)、発行者通知の記録とは独立。
リレーへの接続は不要（nostr_request / nostr_publish をモック）。
使い方: python3 test_draft_cosigners.py
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

BOARD_ID = 'board-cosigner-001'
RELAY = 'wss://relay.example'
passed = []


def keypair():
    s = secrets.token_bytes(32)
    return s, n.npub_of(s), n.hexpub_of(s)


def make_draft(signer, expires_at=None, board_id=BOARD_ID, ts=None,
               extra_approvals=()):
    payload = {'candidate': signer[1]}
    if expires_at is not None:
        payload['expires_at'] = expires_at
    d = {'protocol': 'nakama', 'version': 1, 'type': 'board-decision',
         'board_id': board_id, 'relay': RELAY, 'decision': 'admit',
         'payload': payload, 'created_at': ts or int(time.time()),
         'approvals': []}
    for ap in (signer,) + tuple(extra_approvals):
        msg = n.board_decision_message(d['board_id'], d['relay'], d['decision'],
                                       d['payload'], d['created_at'])
        d['approvals'].append({'npub': ap[1],
                               'sig': n.sign_schnorr(ap[0], msg).hex()})
    return d


def pub_draft_event(d, publisher_secret, created_at=None):
    """草案 (kind 30111) を publisher_secret で署名した Nostr イベント。"""
    return n.decision_nostr_event(d, publisher_secret, kind=n.DRAFT_NOSTR_KIND())


def make_policy(members, threshold=2, board_id=BOARD_ID):
    eligible = [m[1] for m in members]
    ts = int(time.time())
    msg = n.board_policy_message(board_id, RELAY, threshold, eligible, ts)
    return {'protocol': 'nakama', 'version': 1, 'type': 'board-policy',
            'board_id': board_id, 'relay': RELAY, 'threshold': threshold,
            'eligible': eligible, 'created_at': ts,
            'signatures': [{'npub': m[1], 'sig': n.sign_schnorr(m[0], msg).hex()}
                           for m in members]}


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


def notify_ns(keyfile, notif_dir, policy_file=None, cosigners=False, **kw):
    d = dict(relay=RELAY, board_id=BOARD_ID, limit=20, auth=False,
             policy=policy_file, within=86400, include_expired=False,
             dry_run=False, resend=False, from_npub=None,
             notif_dir=notif_dir, keyfile=keyfile, cosigners=cosigners)
    d.update(kw)
    return SimpleNamespace(**d)


def main():
    issuer = keypair()    # 草案の発行者（eligible の一員でもある）
    cos_a = keypair()     # 未署名の承認者
    cos_b = keypair()     # 未署名の承認者
    sender = keypair()    # 通知の送信者（eligible 外 — DM 数を明確にするため）
    tmpd = tempfile.mkdtemp()
    kf = os.path.join(tmpd, 'key.json')
    n.save_key(kf, sender[0])
    now = int(time.time())
    polf = os.path.join(tmpd, 'policy.json')
    with open(polf, 'w') as f:
        json.dump(make_policy([issuer, cos_a, cos_b], threshold=2), f)

    real_req, real_pub = n.nostr_request, n.nostr_publish

    # threshold 未達・期限間近の草案（approvals は発行者のみ: 1/3 不足）
    d1 = make_draft(issuer, expires_at=now + 3600)
    ev1 = pub_draft_event(d1, issuer[0])

    # 1. threshold 未達・期限間近 + --policy + --cosigners → 未署名 eligible 全員に DM
    wraps = []
    n.nostr_request = lambda url, req, **k: [ev1]
    n.nostr_publish = lambda relay, ev, **k: (wraps.append(ev), (True, 'ok'))[1]
    try:
        nd = os.path.join(tmpd, 'c1')
        ns = notify_ns(kf, nd, policy_file=polf, cosigners=True)
        code, out, _ = run_cmd(n.cmd_board_draft_notify, ns)
        assert code == 0, f'exit {code}'
        dests = [w['tags'] for w in wraps]
        assert len(wraps) == 3, f'発行者 1 + 承認者 2 の 3 件: {len(wraps)}'
        assert [['p', issuer[2]]] in dests, f'発行者通知あり: {dests}'
        assert [['p', cos_a[2]]] in dests, f'承認者 A への DM: {dests}'
        assert [['p', cos_b[2]]] in dests, f'承認者 B への DM: {dests}'
        core1 = n.decision_core_hash(d1)
        # 発行者通知の記録（§25.1 の既定形）
        assert os.path.exists(os.path.join(nd, f'{core1}:expiring_soon.json')), \
            '発行者通知の記録'
        # 承認者通知の記録は宛先ごと（§27.1）
        for cos in (cos_a, cos_b):
            rp = os.path.join(nd, f'{core1}:expiring_soon:{cos[2]}.json')
            assert os.path.exists(rp), f'承認者ごとの記録: {rp}'
            recd = json.load(open(rp))
            assert recd['recipient_hex'] == cos[2] and recd['sender_npub'] == sender[1], recd
    finally:
        n.nostr_request, n.nostr_publish = real_req, real_pub
    ok('1: 未達・期限間近 + --cosigners → 未署名 eligible 全員に DM（発行者通知と並行）')

    # 2. threshold 達成済み → cosigner 通知なし（発行者通知のみ）
    d2 = make_draft(issuer, expires_at=now + 3600, extra_approvals=(cos_a,))
    ev2 = pub_draft_event(d2, issuer[0])
    wraps2 = []
    n.nostr_request = lambda url, req, **k: [ev2]
    n.nostr_publish = lambda relay, ev, **k: (wraps2.append(ev), (True, 'ok'))[1]
    try:
        nd = os.path.join(tmpd, 'c2')
        ns = notify_ns(kf, nd, policy_file=polf, cosigners=True)
        code, out, _ = run_cmd(n.cmd_board_draft_notify, ns)
        assert code == 0, f'exit {code}'
        dests = [w['tags'] for w in wraps2]
        assert dests == [[['p', issuer[2]]]], f'発行者通知のみ: {dests}'
        assert 'cosigner' not in out, out
    finally:
        n.nostr_request, n.nostr_publish = real_req, real_pub
    ok('2: threshold 達成済み → cosigner 通知なし（発行者通知のみ）')

    # 3. 既に approvals にある eligible → 対象外（threshold 3 の未達草案）
    pol3f = os.path.join(tmpd, 'policy3.json')
    with open(pol3f, 'w') as f:
        json.dump(make_policy([issuer, cos_a, cos_b], threshold=3), f)
    d3 = make_draft(issuer, expires_at=now + 3600, extra_approvals=(cos_a,))
    ev3 = pub_draft_event(d3, issuer[0])
    wraps3 = []
    n.nostr_request = lambda url, req, **k: [ev3]
    n.nostr_publish = lambda relay, ev, **k: (wraps3.append(ev), (True, 'ok'))[1]
    try:
        nd = os.path.join(tmpd, 'c3')
        ns = notify_ns(kf, nd, policy_file=pol3f, cosigners=True)
        code, _, _ = run_cmd(n.cmd_board_draft_notify, ns)
        assert code == 0, f'exit {code}'
        dests = [w['tags'] for w in wraps3]
        # 発行者 + 署名済みでない cos_b のみ
        assert [['p', issuer[2]]] in dests and [['p', cos_b[2]]] in dests, dests
        assert [['p', cos_a[2]]] not in dests, f'署名済みは対象外: {dests}'
    finally:
        n.nostr_request, n.nostr_publish = real_req, real_pub
    ok('3: approvals にある eligible → cosigner 通知の対象外')

    # 4. --policy なしで --cosigners → exit 1 で拒否（送信せず）
    called = []
    n.nostr_publish = lambda relay, ev, **k: (called.append(ev), (True, 'ok'))[1]
    try:
        nd = os.path.join(tmpd, 'c4')
        ns = notify_ns(kf, nd, cosigners=True)  # policy なし
        code, _, err = run_cmd(n.cmd_board_draft_notify, ns)
        assert code == 1, f'exit {code}'
        assert not called, '拒否時は送信しない'
        assert '--policy' in err, err
    finally:
        n.nostr_publish = real_pub
    ok('4: --policy なしの --cosigners → exit 1 で拒否（送信せず）')

    # 5. 純粋関数: publisher は eligible に含まれていても cosigner 通知の対象外
    # （approvals に issuer がいない人工ケース — publisher-hex 除外の明示経路を検証）
    d5 = make_draft(cos_a, expires_at=now + 3600)  # approvals は cos_a のみ
    tgts = n.draft_cosigner_targets([(d5, issuer[2], now)], now, 86400,
                                    make_policy([issuer, cos_a, cos_b],
                                                threshold=2), False)
    dest_hex = [t[2] for t in tgts]
    assert issuer[2] not in dest_hex, f'publisher は対象外: {dest_hex}'
    assert cos_a[2] not in dest_hex, '署名済みは対象外'
    assert dest_hex == [cos_b[2]], f'cos_b のみ: {dest_hex}'
    assert tgts[0][3] == 'expiring_soon'
    ok('5: 純粋関数 — publisher は eligible でも cosigner 通知の対象外')

    # 6. 期限なし草案 → cosigner 通知なし（発行者通知もなし）
    d6 = make_draft(issuer)
    ev6 = pub_draft_event(d6, issuer[0])
    called6 = []
    n.nostr_request = lambda url, req, **k: [ev6]
    n.nostr_publish = lambda relay, ev, **k: (called6.append(ev), (True, 'ok'))[1]
    try:
        nd = os.path.join(tmpd, 'c6')
        ns = notify_ns(kf, nd, policy_file=polf, cosigners=True)
        code, out, _ = run_cmd(n.cmd_board_draft_notify, ns)
        assert code == 0 and '通知対象の草案はありませんでした' in out, out
        assert not called6, '期限なしは送信しない'
    finally:
        n.nostr_request, n.nostr_publish = real_req, real_pub
    ok('6: 期限なし草案 → cosigner 通知なし（発行者通知もなし）')

    # 7. 二重送信防止 → 宛先ごとの記録ありで [skip]、--resend で再送
    n.nostr_request = lambda url, req, **k: [ev1]
    n.nostr_publish = lambda relay, ev, **k: (True, 'ok')
    try:
        nd = os.path.join(tmpd, 'c7')
        ns = notify_ns(kf, nd, policy_file=polf, cosigners=True)
        code, _, _ = run_cmd(n.cmd_board_draft_notify, ns)  # 1 回目: 3 件送信
        assert code == 0
        n_calls = []
        n.nostr_publish = lambda relay, ev, **k: (n_calls.append(ev), (True, 'ok'))[1]
        code, out, _ = run_cmd(n.cmd_board_draft_notify, ns)  # 2 回目: 全 skip
        assert code == 0 and not n_calls, f'2 回目は送らない: {len(n_calls)}'
        assert out.count('[skip]') == 3, f'発行者 1 + 承認者 2 の skip: {out}'
        # cos_b の記録だけ消す → cos_b のみに再送（発行者・cos_a は skip）
        os.remove(os.path.join(nd, f'{core1}:expiring_soon:{cos_b[2]}.json'))
        code, out, _ = run_cmd(n.cmd_board_draft_notify, ns)
        assert code == 0 and len(n_calls) == 1, f'cos_b のみに再送: {len(n_calls)}'
        assert n_calls[0]['tags'] == [['p', cos_b[2]]], n_calls[0]['tags']
        assert out.count('[skip]') == 2, out
        # --resend: 全員に再送
        ns = notify_ns(kf, nd, policy_file=polf, cosigners=True, resend=True)
        code, out, _ = run_cmd(n.cmd_board_draft_notify, ns)
        assert code == 0 and len(n_calls) == 4, f'resend で 3 件再送: {len(n_calls)}'
    finally:
        n.nostr_request, n.nostr_publish = real_req, real_pub
    ok('7: 宛先ごとの二重送信防止 → skip／個別再送／--resend で再送')

    # 8. --dry-run → 送信せず一覧のみ（発行者＋承認者の宛先表示）
    called8 = []
    n.nostr_request = lambda url, req, **k: [ev1]
    n.nostr_publish = lambda relay, ev, **k: (called8.append(ev), (True, 'ok'))[1]
    try:
        nd = os.path.join(tmpd, 'c8')
        ns = notify_ns(kf, nd, policy_file=polf, cosigners=True, dry_run=True)
        code, out, _ = run_cmd(n.cmd_board_draft_notify, ns)
        assert code == 0, f'exit {code}'
        assert not called8, 'dry-run では publish しない'
        assert not os.path.exists(nd), 'dry-run では記録ディレクトリも作らない'
        assert out.count('[dry-run]') == 3, f'発行者 1 + 承認者 2 の一覧: {out}'
        assert issuer[2][:16] in out and cos_a[2][:16] in out and \
            cos_b[2][:16] in out, out
        assert 'cosigner' in out, '承認者の宛先が明示される'
    finally:
        n.nostr_request, n.nostr_publish = real_req, real_pub
    ok('8: --dry-run → 送信せず一覧のみ（発行者＋承認者）、記録なし')

    # 9. メッセージ形式の確認
    pol = make_policy([issuer, cos_a, cos_b], threshold=2)
    core1 = n.decision_core_hash(d1)
    msg = n.draft_cosigner_message(d1, core1, 'expiring_soon', RELAY, pol)
    lines = msg.splitlines()
    assert lines[0] == '[nakama] draft needs cosignatures', msg
    assert f'board: {BOARD_ID}' in msg
    assert f'decision: admit ({core1[:12]})' in msg
    ea = d1['payload']['expires_at']
    assert f'expires_at: {ea} ' in msg
    utc = time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime(ea))
    assert f'({utc})' in msg, msg
    assert 'threshold: 1/3 不足' in msg, msg  # 承認 1（issuer のみ）→ 未達
    assert 'you are eligible to cosign this draft but have not yet.' in msg
    assert f'board_draft_fetch {RELAY} {BOARD_ID}' in msg, 'cosign 手順への誘導'
    assert f'verify the draft yourself with: board_draft_fetch {RELAY} {BOARD_ID}' in msg
    ok('9: cosigner 向け DM 形式（1 行目・threshold 不足・cosign 手順の誘導）')

    print(f'\n{len(passed)} tests passed.')


if __name__ == '__main__':
    main()
