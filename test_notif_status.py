"""board_notif_status の突き合わせ表示 (spec §28.7 テスト計画ケース 3・4・5・6・8・9) のオフライン検証。

- ケース 3: ack の突き合わせ（core＋sender 一致で yes、reason 不一致・core 不正・sender 不一致は無視。
  64 hex の ack core は 32 hex に正規化して突き合わせ — §28.8 の補正）
- ケース 4: 同一 (core, sender, reason) への複数 ack は最初の 1 件のみ（dedup）
- ケース 5: cosign 列（approvals に recipient npub があれば yes、なければ -）
- ケース 6: --policy なしの status（sent/ack のみ、cosigned 列なし）
- ケース 8: 記録のない core への ack は status に現れない
- ケース 9: exit コード（fetch 失敗でも status は exit 0。
  ack 送信失敗の exit 1 は test_notif_ack で検証済み）
リレーへの接続は不要 (nostr_request をモック)。
使い方: python3 test_notif_status.py
"""
import contextlib
import io
import json
import os
import secrets
import tempfile
import time
from types import SimpleNamespace
from unittest import mock

sys_path_hack = __file__.rsplit('/', 1)[0] or '.'
import sys
sys.path.insert(0, sys_path_hack)
import nakama as n

RELAY = 'wss://relay.example'
BOARD_ID = 'test-board-notif-status'
passed = []
C1 = 'cc' * 16  # 32 hex（decision_core_hash 形式）
C2 = 'dd' * 16
C3 = 'ee' * 16


def keypair():
    s = secrets.token_bytes(32)
    return s, n.npub_of(s), n.hexpub_of(s)


def make_keyfile(tmpd, secret):
    kf = f'{tmpd}/key.json'
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


def make_draft(signer, extra_approvals=(), ts=None):
    d = {'protocol': 'nakama', 'version': 1, 'type': 'board-decision',
         'board_id': BOARD_ID, 'relay': RELAY, 'decision': 'admit',
         'payload': {'candidate': signer[1]}, 'created_at': ts or int(time.time()),
         'approvals': []}
    for ap in (signer,) + tuple(extra_approvals):
        msg = n.board_decision_message(d['board_id'], d['relay'], d['decision'],
                                       d['payload'], d['created_at'])
        d['approvals'].append({'npub': ap[1],
                               'sig': n.sign_schnorr(ap[0], msg).hex()})
    return d


def make_policy(members):
    eligible = [m[1] for m in members]
    ts = int(time.time())
    msg = n.board_policy_message(BOARD_ID, RELAY, 2, eligible, ts)
    return {'protocol': 'nakama', 'version': 1, 'type': 'board-policy',
            'board_id': BOARD_ID, 'relay': RELAY, 'threshold': 2,
            'eligible': eligible, 'created_at': ts,
            'signatures': [{'npub': m[1], 'sig': n.sign_schnorr(m[0], msg).hex()}
                           for m in members]}


def write_record(notif_dir, core, reason, recipient_hex, sender_npub, now):
    n.draft_notif_record(notif_dir, core, reason, recipient_hex, sender_npub,
                         now, recipient_file=True,
                         gift_wrap_id='g' * 64, rumor_id='r' * 64)


def ack_wrap(from_secret, to_hex, core, reason, note=None, rumor_ts=None):
    seal = n.nip17_build_seal(from_secret, to_hex,
                              n.notif_ack_message(core, reason, note),
                              created_at=rumor_ts)
    return n.nip17_build_gift_wrap(seal, to_hex)


def status_ns(keyfile, notif_dir, **kw):
    d = dict(board_id=BOARD_ID, relay=RELAY, since=None, limit=20, auth=False,
             policy=None, decisions=None, dir=notif_dir, keyfile=keyfile)
    d.update(kw)
    return SimpleNamespace(**d)


def main():
    me = keypair()       # status 実行者（DM 受信者＝通知の送信者）
    cosigner = keypair()  # ack 送信者（通知の受信者）
    stranger = keypair()
    now = int(time.time())
    real_req = n.nostr_request

    with tempfile.TemporaryDirectory() as tmpd:
        kf = make_keyfile(tmpd, me[0])
        notif_dir = os.path.join(tmpd, 'notifs')

        # --- 純粋関数の単体検証 ---
        assert n.normalize_notif_core(C1) == C1
        assert n.normalize_notif_core(C1 + '00' * 16) == C1  # 64 hex → 先頭 32
        for bad in ('ab', 'zz' * 16, '', C1 + '0'):
            assert n.normalize_notif_core(bad) is None, bad
        assert n.normalize_notif_core(C1.upper()) == C1  # hex は case-insensitive
        ok('normalize_notif_core: 32/64 hex 受付、不正は None')

        p = n.parse_notif_ack(n.notif_ack_message(C1, 'cosign_request', note='ok'))
        assert p == {'core': C1, 'reason': 'cosign_request'}, p
        p64 = n.parse_notif_ack('[nakama] notif-ack\ncore: ' + C1 + '00' * 16 +
                                '\nreason: expired\n---')
        assert p64 == {'core': C1, 'reason': 'expired'}, p64
        for bad in ('hello\ncore: %s\nreason: cosign_request\n---' % C1,   # ヘッダ不一致
                    '[nakama] notif-ack\ncore: zz\nreason: cosign_request\n---',  # core 不正
                    '[nakama] notif-ack\ncore: %s\nreason: read_it\n---' % C1,   # reason 語彙外
                    '[nakama] notif-ack\ncore: %s' % C1):  # 行不足
            assert n.parse_notif_ack(bad) is None, bad
        ok('parse_notif_ack: 正常系・64hex 正規化・形式不正の無視')

        # --- ケース 3: ack の突き合わせ ---
        write_record(notif_dir, C1, 'cosign_request', cosigner[2], me[1], now)
        write_record(notif_dir, C2, 'expiring_soon', me[2], me[1], now)
        wraps = [
            ack_wrap(cosigner[0], me[2], C1, 'cosign_request', rumor_ts=now - 100),  # 一致
            ack_wrap(cosigner[0], me[2], C1, 'expired', rumor_ts=now - 90),          # reason 不一致
            ack_wrap(cosigner[0], me[2], 'zz', 'cosign_request', rumor_ts=now - 80),  # core 不正
            ack_wrap(stranger[0], me[2], C1, 'cosign_request', rumor_ts=now - 70),    # sender 不一致
        ]
        n.nostr_request = lambda url, req, timeout=15, auth_secret=None: list(wraps)
        code, out, err = run_cmd(n.cmd_board_notif_status, status_ns(kf, notif_dir))
        assert code == 0, (code, out, err)
        line1 = [l for l in out.split('\n') if C1 in l and 'cosign_request' in l]
        line2 = [l for l in out.split('\n') if C2 in l]
        assert len(line1) == 1 and 'ack=yes(' in line1[0], out
        assert len(line2) == 1 and 'ack=-' in line2[0], out
        ok('ケース 3: core＋sender 一致で yes、reason/core/sender 不一致は無視')

        # 64 hex の ack core は 32 hex に正規化して突き合わせ
        nd64 = os.path.join(tmpd, 'notifs64')
        write_record(nd64, C2, 'expiring_soon', cosigner[2], me[1], now)
        n.nostr_request = lambda url, req, timeout=15, auth_secret=None: [
            ack_wrap(cosigner[0], me[2], C2 + 'ff' * 16, 'expiring_soon',
                     rumor_ts=now - 50)]
        code, out, err = run_cmd(n.cmd_board_notif_status, status_ns(kf, nd64))
        assert code == 0, (code, out, err)
        line2 = [l for l in out.split('\n') if C2 in l]
        assert len(line2) == 1 and 'ack=yes(' in line2[0], out
        ok('64 hex の ack core は 32 hex に正規化して突き合わせ')

        # --- ケース 4: dedup（最初の 1 件のみ）---
        nd = os.path.join(tmpd, 'notifs4')
        write_record(nd, C1, 'cosign_request', cosigner[2], me[1], now)
        with mock.patch.object(n.secrets, 'randbelow', side_effect=[100, 500]):
            # wrap の created_at: 1 件目 = now-100（新しい）、2 件目 = now-500（古い）
            w_new = ack_wrap(cosigner[0], me[2], C1, 'cosign_request', rumor_ts=1111)
            w_old = ack_wrap(cosigner[0], me[2], C1, 'cosign_request', rumor_ts=2222)
        assert w_new['created_at'] > w_old['created_at']
        n.nostr_request = lambda url, req, timeout=15, auth_secret=None: [w_new, w_old]
        code, out, err = run_cmd(n.cmd_board_notif_status, status_ns(kf, nd))
        assert code == 0, (code, out, err)
        # 昇順整列で w_old（rumor_ts=2222 = 00:37:02）が先 → 最初の 1 件が有効
        assert 'ack=yes(' in out and '00:37:02' in out and '00:18:31' not in out, out
        ok('ケース 4: 同一 (core, sender, reason) の複数 ack は最初の 1 件のみ')

        # --- ケース 5: cosign 列（--policy + 30111 購読）---
        nd5 = os.path.join(tmpd, 'notifs5')
        d = make_draft(me, extra_approvals=(cosigner,))
        core5 = n.decision_core_hash(d)
        ev = n.decision_nostr_event(d, me[0], kind=n.DRAFT_NOSTR_KIND())
        write_record(nd5, core5, 'cosign_request', cosigner[2], me[1], now)
        write_record(nd5, C3, 'cosign_request', stranger[2], me[1], now)  # approvals 外
        pol_path = os.path.join(tmpd, 'policy.json')
        with open(pol_path, 'w') as f:
            json.dump(make_policy([me, cosigner]), f)

        def fake_req5(url, req, timeout=15, auth_secret=None):
            kinds = req[2].get('kinds', [])
            if kinds == [1059]:
                return []
            if n.DRAFT_NOSTR_KIND() in kinds:
                return [ev]
            return []
        n.nostr_request = fake_req5
        code, out, err = run_cmd(n.cmd_board_notif_status,
                                status_ns(kf, nd5, policy=pol_path))
        assert code == 0, (code, out, err)
        l_cos = [l for l in out.split('\n') if core5 in l]
        l_str = [l for l in out.split('\n') if C3 in l]
        assert len(l_cos) == 1 and 'cosigned=yes' in l_cos[0], out
        assert len(l_str) == 1 and 'cosigned=-' in l_str[0], out
        ok('ケース 5: approvals に recipient npub があれば cosigned=yes、なければ -')

        # --decisions（ローカル）でも cosigned 列が出る
        dec_dir = os.path.join(tmpd, 'decisions')
        os.makedirs(dec_dir)
        with open(os.path.join(dec_dir, f'{core5}.json'), 'w') as f:
            json.dump(d, f)
        code, out, err = run_cmd(n.cmd_board_notif_status,
                                status_ns(kf, nd5, policy=pol_path,
                                          decisions=dec_dir, relay=None))
        assert code == 0, (code, out, err)
        l_cos = [l for l in out.split('\n') if core5 in l]
        assert len(l_cos) == 1 and 'cosigned=yes' in l_cos[0], out
        ok('--decisions（ローカル決定 JSON）での cosigned 列')

        # --- ケース 6: --policy なし（sent/ack のみ）---
        n.nostr_request = lambda url, req, timeout=15, auth_secret=None: []
        code, out, err = run_cmd(n.cmd_board_notif_status, status_ns(kf, nd5))
        assert code == 0, (code, out, err)
        assert 'cosigned' not in out and 'sent=' in out and 'ack=' in out, out
        ok('ケース 6: --policy なしは sent/ack のみ（cosigned 列なし）')

        # --- ケース 8: 記録のない core への ack は現れない ---
        n.nostr_request = lambda url, req, timeout=15, auth_secret=None: [
            ack_wrap(cosigner[0], me[2], 'ff' * 16, 'cosign_request',
                     rumor_ts=now - 10)]
        code, out, err = run_cmd(n.cmd_board_notif_status, status_ns(kf, nd5))
        assert code == 0, (code, out, err)
        assert 'ff' * 16 not in out, out
        assert core5 in out and C3 in out, out
        ok('ケース 8: 記録のない core への ack は status に現れない')

        # --- ケース 9: fetch 失敗でも exit 0 ---
        def boom(url, req, timeout=15, auth_secret=None):
            raise RuntimeError('relay down')
        n.nostr_request = boom
        code, out, err = run_cmd(n.cmd_board_notif_status,
                                status_ns(kf, nd5, policy=pol_path))
        assert code == 0, (code, out, err)
        assert core5 in out and '警告' in err or '失敗' in err, (out, err)
        ok('ケース 9: fetch 失敗時も exit 0（stderr 警告＋記録のみ表示）')

        # --relay 未指定でも exit 0
        n.nostr_request = real_req
        code, out, err = run_cmd(n.cmd_board_notif_status,
                                status_ns(kf, nd5, relay=None))
        assert code == 0 and core5 in out, (code, out, err)
        ok('--relay 未指定でも exit 0（記録のみ表示）')

        # 壊れた記録ファイルは読み飛ばす
        with open(os.path.join(nd5, 'broken.json'), 'w') as f:
            f.write('{not json')
        with open(os.path.join(nd5, 'skip.txt'), 'w') as f:
            f.write('x')
        code, out, err = run_cmd(n.cmd_board_notif_status,
                                status_ns(kf, nd5, relay=None))
        assert code == 0 and core5 in out, (code, out, err)
        ok('壊れた記録・非 JSON ファイルの読み飛ばし')

    n.nostr_request = real_req
    print(f'{len(passed)} cases passed: ' + ', '.join(passed))


if __name__ == '__main__':
    main()
