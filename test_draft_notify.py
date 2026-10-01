"""草案への自動通知 board_draft_notify (spec §25 / v0.20) のオフライン検証。

対象選択（0 < expires_at - now <= --within → expiring_soon、期限切れ →
expired）、宛先 = 草案イベントの publisher（原発行者）のみ、期限なし・
within 外は対象外、期限切れは既定で対象外（--include-expired で reason=expired）、
--dry-run、送信記録による二重送信防止と --resend、DM メッセージ形式、
--from の取り違え防止をテストする。
リレーへの接続は不要（nostr_request / nostr_publish をモック）。
使い方: python3 test_draft_notify.py
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

BOARD_ID = 'board-notify-001'
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
    """草案 (kind 30104) を publisher_secret で署名した Nostr イベント。"""
    return n.decision_nostr_event(d, publisher_secret, kind=n.DRAFT_NOSTR_KIND)


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


def notify_ns(keyfile, notif_dir, **kw):
    d = dict(relay=RELAY, board_id=BOARD_ID, limit=20, auth=False,
             policy=None, within=86400, include_expired=False,
             dry_run=False, resend=False, from_npub=None,
             notif_dir=notif_dir, keyfile=keyfile)
    d.update(kw)
    return SimpleNamespace(**d)


def main():
    issuer = keypair()    # 草案の発行者（宛先になるべき相手）
    cosigner = keypair()  # 承認者（宛先外）
    sender = keypair()    # 通知の送信者（keyfile）
    tmpd = tempfile.mkdtemp()
    kf = os.path.join(tmpd, 'key.json')
    n.save_key(kf, sender[0])
    now = int(time.time())

    real_req, real_pub = n.nostr_request, n.nostr_publish

    def draft_within(extra_approvals=()):
        return make_draft(issuer, expires_at=now + 3600,
                          extra_approvals=extra_approvals)

    # 1. 期限が 24h 以内の草案 → 対象に含まれる、宛先 = 草案イベントの publisher
    d1 = draft_within()
    ev1 = pub_draft_event(d1, issuer[0])
    wraps = []
    n.nostr_request = lambda url, req, **k: [ev1]
    n.nostr_publish = lambda relay, ev, **k: (wraps.append(ev), (True, 'ok'))[1]
    try:
        nd = os.path.join(tmpd, 'n1')
        ns = notify_ns(kf, nd)
        code, out, _ = run_cmd(n.cmd_board_draft_notify, ns)
        assert code == 0, f'exit {code}'
        assert len(wraps) == 1, f'1 件送信: {len(wraps)}'
        # gift wrap の p タグは平文 — 宛先が発行者の hexpub であることを確認
        assert wraps[0]['tags'] == [['p', issuer[2]]], \
            f'宛先は発行者のみ: {wraps[0]["tags"]}'
        assert '[sent]' in out and 'expiring_soon' in out, out
        core1 = n.decision_core_hash(d1)
        rec = os.path.join(nd, f'{core1}:expiring_soon.json')
        assert os.path.exists(rec), '送信記録が保存される'
        recd = json.load(open(rec))
        assert recd['recipient_hex'] == issuer[2] and recd['sender_npub'] == sender[1]
    finally:
        n.nostr_request, n.nostr_publish = real_req, real_pub
    ok('1: 24h 以内の草案 → 対象、宛先 = 草案イベントの publisher、記録保存')

    # 2. 期限が --within 外の草案 → 対象外
    d2 = make_draft(issuer, expires_at=now + 90000)  # 25h 後
    ev2 = pub_draft_event(d2, issuer[0])
    n.nostr_request = lambda url, req, **k: [ev2]
    n.nostr_publish = lambda relay, ev, **k: (True, 'ok')
    try:
        nd = os.path.join(tmpd, 'n2')
        ns = notify_ns(kf, nd)
        code, out, _ = run_cmd(n.cmd_board_draft_notify, ns)
        assert code == 0 and '通知対象の草案はありませんでした' in out, out
        # --within を広げれば対象になる
        ns2 = notify_ns(kf, nd, within=100000)
        wraps2 = []
        n.nostr_publish = lambda relay, ev, **k: (wraps2.append(ev), (True, 'ok'))[1]
        code, _, _ = run_cmd(n.cmd_board_draft_notify, ns2)
        assert code == 0 and len(wraps2) == 1, 'within を広げれば対象'
    finally:
        n.nostr_request, n.nostr_publish = real_req, real_pub
    ok('2: --within 外の草案 → 対象外（within を広げれば対象）')

    # 3. 期限なし草案 → 対象外
    d3 = make_draft(issuer)
    ev3 = pub_draft_event(d3, issuer[0])
    n.nostr_request = lambda url, req, **k: [ev3]
    try:
        nd = os.path.join(tmpd, 'n3')
        ns = notify_ns(kf, nd)
        code, out, _ = run_cmd(n.cmd_board_draft_notify, ns)
        assert code == 0 and '通知対象の草案はありませんでした' in out, out
    finally:
        n.nostr_request = real_req
    ok('3: 期限なし草案 → 対象外')

    # 4. 期限切れ草案 → 既定で対象外、--include-expired で reason=expired として対象
    d4 = make_draft(issuer, expires_at=now - 60)
    ev4 = pub_draft_event(d4, issuer[0])
    n.nostr_request = lambda url, req, **k: [ev4]
    n.nostr_publish = lambda relay, ev, **k: (True, 'ok')
    try:
        nd = os.path.join(tmpd, 'n4')
        ns = notify_ns(kf, nd)
        code, out, _ = run_cmd(n.cmd_board_draft_notify, ns)
        assert code == 0 and '通知対象の草案はありませんでした' in out, out
        ns = notify_ns(kf, nd, include_expired=True)
        wraps4 = []
        n.nostr_publish = lambda relay, ev, **k: (wraps4.append(ev), (True, 'ok'))[1]
        code, out, _ = run_cmd(n.cmd_board_draft_notify, ns)
        assert code == 0 and len(wraps4) == 1, f'include-expired で送信: {code}'
        assert 'expired' in out, out
        core4 = n.decision_core_hash(d4)
        assert os.path.exists(os.path.join(nd, f'{core4}:expired.json')), \
            'reason=expired の記録'
    finally:
        n.nostr_request, n.nostr_publish = real_req, real_pub
    ok('4: 期限切れ草案 → 既定で対象外、--include-expired で reason=expired')

    # 5. --dry-run → 送信せず一覧のみ表示、nostr_publish 不呼び出し、記録なし
    n.nostr_request = lambda url, req, **k: [ev1]
    called = []
    n.nostr_publish = lambda relay, ev, **k: (called.append(ev), (True, 'ok'))[1]
    try:
        nd = os.path.join(tmpd, 'n5')
        ns = notify_ns(kf, nd, dry_run=True)
        code, out, _ = run_cmd(n.cmd_board_draft_notify, ns)
        assert code == 0, f'exit {code}'
        assert not called, 'dry-run では publish しない'
        assert '[dry-run]' in out and issuer[2][:16] in out, out
        assert not os.path.exists(nd), 'dry-run では記録ディレクトリも作らない'
    finally:
        n.nostr_request, n.nostr_publish = real_req, real_pub
    ok('5: --dry-run → 送信せず一覧のみ、publish 不呼び出し・記録なし')

    # 6. 二重送信防止 → 送信記録あり（--within 以内）でスキップ、--resend で再送
    n.nostr_request = lambda url, req, **k: [ev1]
    n.nostr_publish = lambda relay, ev, **k: (True, 'ok')
    try:
        nd = os.path.join(tmpd, 'n6')
        ns = notify_ns(kf, nd)
        code, _, _ = run_cmd(n.cmd_board_draft_notify, ns)  # 1 回目: 送信
        assert code == 0
        n_calls = []
        n.nostr_publish = lambda relay, ev, **k: (n_calls.append(ev), (True, 'ok'))[1]
        code, out, _ = run_cmd(n.cmd_board_draft_notify, ns)  # 2 回目: スキップ
        assert code == 0 and not n_calls, f'2 回目は送らない: {len(n_calls)}'
        assert '[skip]' in out, out
        ns = notify_ns(kf, nd, resend=True)  # --resend: 再送
        code, out, _ = run_cmd(n.cmd_board_draft_notify, ns)
        assert code == 0 and len(n_calls) == 1, f'resend で再送: {len(n_calls)}'
        assert '[sent]' in out, out
    finally:
        n.nostr_request, n.nostr_publish = real_req, real_pub
    ok('6: 二重送信防止 → 記録ありで skip、--resend で再送')

    # 7. DM 内容のフォーマット確認
    pol = make_policy([issuer, cosigner, sender], threshold=2)
    core1 = n.decision_core_hash(d1)
    msg = n.draft_notify_message(d1, core1, 'expiring_soon', RELAY, pol)
    assert msg.splitlines()[0] == '[nakama] draft expiring soon', msg
    assert f'board: {BOARD_ID}' in msg
    assert f'decision: admit ({core1[:12]})' in msg
    assert f'expires_at: {d1["payload"]["expires_at"]} ' in msg
    utc = time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime(d1['payload']['expires_at']))
    assert f'({utc})' in msg, msg
    # 承認 1（issuer のみ）→ threshold 2/3 不足
    assert 'threshold: 1/3 不足' in msg, msg
    d7 = draft_within(extra_approvals=(cosigner,))  # 承認 2 → 充足
    core7 = n.decision_core_hash(d7)
    msg7 = n.draft_notify_message(d7, core7, 'expiring_soon', RELAY, pol)
    assert 'threshold: 2/3 充足' in msg7, msg7
    assert f'verify the draft yourself with: board_draft_fetch {RELAY} {BOARD_ID}' in msg
    msg_e = n.draft_notify_message(d4, core4, 'expired', RELAY)
    assert msg_e.splitlines()[0] == '[nakama] draft expired', msg_e
    assert 'threshold:' not in msg_e, 'policy なしでは threshold 行なし'
    ok('7: DM 形式（decision・core 先頭 12・expires_at UTC・threshold 充足/不足）')

    # 7b. 純粋関数: 方式 B（承認者が再公開）でも宛先は原発行者
    ev_cos = pub_draft_event(d1, cosigner[0], created_at=int(time.time()) + 5)
    verified = [(d1, ev1['pubkey'], ev1['created_at']),
                (d1, ev_cos['pubkey'], ev_cos['created_at'])]
    tgts = n.draft_notify_targets(verified, now, 86400)
    assert len(tgts) == 1, f'同一コアは 1 件にマージ: {len(tgts)}'
    assert tgts[0][2] == issuer[2], f'宛先は原発行者: {tgts[0][2][:16]}'
    assert tgts[0][3] == 'expiring_soon'
    ok('7b: 方式 B の再公開混在でも宛先は原発行者（最も古い event の publisher）')

    # 8. keyfile の鍵と異なる --from → 拒否（exit 1、送信せず）
    n.nostr_request = lambda url, req, **k: [ev1]
    called = []
    n.nostr_publish = lambda relay, ev, **k: (called.append(ev), (True, 'ok'))[1]
    try:
        nd = os.path.join(tmpd, 'n8')
        ns = notify_ns(kf, nd, from_npub=cosigner[1])  # sender の鍵と不一致
        code, _, err = run_cmd(n.cmd_board_draft_notify, ns)
        assert code == 1, f'exit {code}'
        assert not called, '拒否時は送信しない'
        assert '一致しません' in err, err
        # 一致する --from は通る
        ns = notify_ns(kf, nd, from_npub=sender[1])
        code, _, _ = run_cmd(n.cmd_board_draft_notify, ns)
        assert code == 0 and len(called) == 1, f'一致 --from は送信: {code}'
    finally:
        n.nostr_request, n.nostr_publish = real_req, real_pub
    ok('8: 不一致の --from → 拒否（exit 1、送信せず）。一致なら送信')

    print(f'\n{len(passed)} tests passed.')


if __name__ == '__main__':
    main()
