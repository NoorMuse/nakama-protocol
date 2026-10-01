"""board_notif_ack の DM 構築 (spec §28.7 テスト計画ケース 1) のオフライン検証。

- ack DM 平文のヘッダ形式（[nakama] notif-ack / core / reason / --- / 任意の自由文）
- --core の 64 hex 形式検証（不正は exit 1）
- --reason の語彙外拒否（既定は cosign_request、exit 1）
- seal が ack 送信者（通知の受信者）の実鍵で署名されること（復号で検証）
リレーへの接続は不要 (nostr_publish をモック)。
使い方: python3 test_notif_ack.py
"""
import contextlib
import io
import secrets
import tempfile
from types import SimpleNamespace

sys_path_hack = __file__.rsplit('/', 1)[0] or '.'
import sys
sys.path.insert(0, sys_path_hack)
import nakama as n

RELAY = 'wss://relay.example'
passed = []
CORE = 'ab' * 32  # 64 hex


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


def base_ns(tmpd, recipient_npub, sender_secret, **kw):
    d = dict(relay=RELAY, npub=recipient_npub, keyfile=make_keyfile(tmpd, sender_secret),
             core=CORE, reason='cosign_request', note=None, auth=False, from_npub=None)
    d.update(kw)
    return SimpleNamespace(**d)


def ok(name):
    passed.append(name)


def main():
    issuer = keypair()   # 通知の発行者（ack の宛先）
    me = keypair()       # ack 送信者（通知の受信者）
    real_pub = n.nostr_publish

    with tempfile.TemporaryDirectory() as tmpd:
        # 1. ヘッダ形式: 機械可読ヘッダ + 任意の自由文
        m = n.notif_ack_message(CORE, 'expiring_soon', note='今夜 cosign します')
        assert m.split('\n') == ['[nakama] notif-ack', f'core: {CORE}',
                                 'reason: expiring_soon', '---', '今夜 cosign します'], m
        ok('ack ヘッダ形式 (core/reason/---/自由文)')

        # 2. note なし: '---' で終わる
        m2 = n.notif_ack_message(CORE, 'cosign_request')
        assert m2 == f'[nakama] notif-ack\ncore: {CORE}\nreason: cosign_request\n---', m2
        ok('note なしの ack 形式')

        # 3. reason 語彙: 3 語彙すべて構築可
        for r in ('expiring_soon', 'expired', 'cosign_request'):
            n.notif_ack_message(CORE, r)
        ok('reason 語彙 3 種の構築')

        # 4. e2e: publish モックで ack DM を送り、復号して形式・署名者を検証
        captured = {}

        def fake_pub(url, event, timeout=15, auth_secret=None):
            captured['url'] = url
            captured['wrap'] = event
            captured['auth_secret'] = auth_secret
            return True, ''
        n.nostr_publish = fake_pub
        code, out, err = run_cmd(n.cmd_board_notif_ack,
                                base_ns(tmpd, issuer[1], me[0], note='今夜 cosign します'))
        assert code == 0, (code, out, err)
        wrap = captured['wrap']
        assert wrap['kind'] == 1059
        rumor = n.nip17_unwrap(wrap, issuer[0])
        assert rumor['content'] == n.notif_ack_message(CORE, 'cosign_request', note='今夜 cosign します')
        assert rumor['pubkey'] == me[2], 'seal/rumor の署名者は ack 送信者の実鍵'
        assert me[2] != issuer[2]
        ok('e2e: ack DM の構築・seal は ack 送信者の実鍵署名')

        # 5. --auth: auth_secret の受け渡し
        n.nostr_publish = fake_pub
        code, out, err = run_cmd(n.cmd_board_notif_ack,
                                base_ns(tmpd, issuer[1], me[0], auth=True))
        assert code == 0 and captured['auth_secret'] == me[0], (code, out, err)
        ok('--auth の auth_secret 受け渡し')

        # 6. --core 形式不正は exit 1（短い / 非 hex / 大文字）
        for bad in ('ab', 'zz' * 32, 'AB' * 32, '', CORE + '0'):
            code, out, err = run_cmd(n.cmd_board_notif_ack,
                                    base_ns(tmpd, issuer[1], me[0], core=bad))
            assert code == 1 and 'core' in (out + err), (bad, code, out, err)
        ok('--core 形式不正の拒否 (exit 1)')

        # 7. --reason 語彙外は exit 1
        code, out, err = run_cmd(n.cmd_board_notif_ack,
                                base_ns(tmpd, issuer[1], me[0], reason='read_it'))
        assert code == 1 and 'reason' in (out + err).lower(), (code, out, err)
        ok('--reason 語彙外の拒否 (exit 1)')

        # 8. publish 拒否は exit 1
        n.nostr_publish = lambda url, event, timeout=15, auth_secret=None: (False, 'nope')
        code, out, err = run_cmd(n.cmd_board_notif_ack,
                                base_ns(tmpd, issuer[1], me[0]))
        assert code == 1 and '拒否' in out, (code, out, err)
        ok('publish 拒否で exit 1')

        # 9. npub 形式不正は exit 1
        n.nostr_publish = fake_pub
        code, out, err = run_cmd(n.cmd_board_notif_ack,
                                base_ns(tmpd, 'npub1broken', me[0]))
        assert code == 1, (code, out, err)
        ok('npub 形式不正の拒否 (exit 1)')

        # 10. --from の取り違え防止（§25.1 と同一）
        code, out, err = run_cmd(n.cmd_board_notif_ack,
                                base_ns(tmpd, issuer[1], me[0], from_npub=issuer[1]))
        assert code == 1, (code, out, err)
        code, out, err = run_cmd(n.cmd_board_notif_ack,
                                base_ns(tmpd, issuer[1], me[0], from_npub=me[1]))
        assert code == 0, (code, out, err)  # 一致すれば正常送信
        ok('--from の取り違え防止')

        # 11. exit 0 時の出力に publish 受理が含まれる
        code, out, err = run_cmd(n.cmd_board_notif_ack,
                                base_ns(tmpd, issuer[1], me[0]))
        assert code == 0 and '受理' in out, (code, out, err)
        ok('受理時の exit 0 と出力')
    n.nostr_publish = real_pub

    print(f'{len(passed)} cases passed: ' + ', '.join(passed))


if __name__ == '__main__':
    main()
