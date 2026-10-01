"""dm_incoming の切り出し (spec §28.7 テスト計画ケース 7) のオフライン検証。

cmd_dm_fetch の fetch+unwrap ロジックを純粋関数 dm_incoming(secret, relay, since, auth)
に切り出した回帰: dm_fetch の既存動作が不変であること。
リレーへの接続は不要 (nostr_request をモック)。
使い方: python3 test_dm_incoming.py
"""
import contextlib
import io
import secrets
import tempfile
import time
from types import SimpleNamespace

sys_path_hack = __file__.rsplit('/', 1)[0] or '.'
import sys
sys.path.insert(0, sys_path_hack)
import nakama as n

RELAY = 'wss://relay.example'
passed = []


def keypair():
    s = secrets.token_bytes(32)
    return s, n.npub_of(s), n.hexpub_of(s)


def make_wrap(sender_secret, recipient_hexpub, plaintext, created_at=None):
    seal = n.nip17_build_seal(sender_secret, recipient_hexpub, plaintext,
                              created_at=created_at)
    return n.nip17_build_gift_wrap(seal, recipient_hexpub)


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


def main():
    me = keypair()
    alice = keypair()
    bob = keypair()
    real_req = n.nostr_request

    def fake(capture, events):
        def _fake(url, request, timeout=15, auth_secret=None):
            capture['url'] = url
            capture['request'] = request
            capture['auth_secret'] = auth_secret
            return events
        return _fake

    try:
        with tempfile.TemporaryDirectory() as tmpd:
            # 1. gift wrap の created_at 昇順で rumor を返す（イベントは順不同で与える）
            #    ※ NIP-17 の wrap の created_at は ±2 日のランダム値（タイミング解析対策）のため、
            #      rumor の created_at ではなく wrap の created_at で整列する — 旧実装と同一。
            ts1, ts2 = int(time.time()) - 300, int(time.time()) - 100
            w1 = make_wrap(alice[0], me[2], 'あとで読む', created_at=ts1)
            w2 = make_wrap(bob[0], me[2], 'さきに読む？', created_at=ts2)
            exp = sorted([w1, w2], key=lambda w: w['created_at'])
            exp_contents = [n.nip17_unwrap(w, me[0])['content'] for w in exp]
            cap = {}
            n.nostr_request = fake(cap, [w1, w2])
            rumors = n.dm_incoming(me[0], RELAY, None, False)
            assert [r['content'] for r in rumors] == exp_contents, rumors
            ok('rumor を gift wrap の created_at 昇順で返す（旧実装と同一の整列）')

            # 2. 復号できない wrap は無視する
            garbage = {'kind': 9000, 'id': 'x', 'pubkey': 'y', 'created_at': ts1,
                       'tags': [], 'content': '', 'sig': 'z'}
            for_other = make_wrap(alice[0], bob[2], '他人宛', created_at=ts2)
            tampered = dict(w1)
            tampered['content'] = '00' + tampered['content'][2:]
            n.nostr_request = fake({}, [garbage, for_other, tampered, w1])
            rumors = n.dm_incoming(me[0], RELAY, None, False)
            assert len(rumors) == 1 and rumors[0]['content'] == 'あとで読む', rumors
            ok('復号できない wrap（種別違い・他人宛・改ざん）は無視')

            # 3. REQ フィルタ: kinds/#p/since/limit
            cap = {}
            n.nostr_request = fake(cap, [])
            n.dm_incoming(me[0], RELAY, 1234567890, False, limit=7)
            req = cap['request']
            assert req[0] == 'REQ' and len(req[1]) == 16, req
            filt = req[2]
            assert filt['kinds'] == [1059] and filt['#p'] == [me[2]], filt
            assert filt['since'] == 1234567890 and filt['limit'] == 7, filt
            assert cap['auth_secret'] is None
            # since 省略時は since キーなし、limit 既定は 500
            cap = {}
            n.nostr_request = fake(cap, [])
            n.dm_incoming(me[0], RELAY, None, False)
            filt = cap['request'][2]
            assert 'since' not in filt and filt['limit'] == 500, filt
            ok('REQ フィルタに kinds/#p/since/limit を正しく載せる')

            # 4. auth フラグ → auth_secret の受け渡し
            cap = {}
            n.nostr_request = fake(cap, [])
            n.dm_incoming(me[0], RELAY, None, True)
            assert cap['auth_secret'] == me[0], cap
            ok('auth=True で auth_secret=secret を渡す')

            # 5. cmd_dm_fetch の回帰: 既存の表示形式が不変
            exp = sorted([w1, w2], key=lambda w: w['created_at'])
            exp_contents = [n.nip17_unwrap(w, me[0])['content'] for w in exp]
            exp_senders = [n.nip17_unwrap(w, me[0])['pubkey'][:16] for w in exp]
            n.nostr_request = fake({}, [w1, w2])
            ns = SimpleNamespace(keyfile=make_keyfile(tmpd, me[0]), relay=RELAY,
                                 since=None, limit=20, auth=False)
            code, out, _ = run_cmd(n.cmd_dm_fetch, ns)
            assert code == 0
            lines = out.strip().split('\n')
            assert len(lines) == 4, lines
            for i, (sender16, content) in enumerate(zip(exp_senders, exp_contents)):
                assert lines[2 * i].startswith('--- [') and sender16 in lines[2 * i], lines[2 * i]
                assert lines[2 * i + 1] == content, lines[2 * i + 1]
            ok('cmd_dm_fetch の表示形式（ヘッダ+本文の順序）が不変')

            # 6. 空の購読 → 既存メッセージ
            n.nostr_request = fake({}, [])
            code, out, _ = run_cmd(n.cmd_dm_fetch, ns)
            assert code == 0 and '新しい DM はありませんでした' in out, out
            ok('空の購読時のメッセージが不変')

            # 7. 例外の伝播: ネットワーク失敗はそのまま上げる（握りつぶさない）
            def _boom(url, request, timeout=15, auth_secret=None):
                raise ConnectionError('relay down')
            n.nostr_request = _boom
            try:
                n.dm_incoming(me[0], RELAY, None, False)
                raise AssertionError('例外が上がらなかった')
            except ConnectionError:
                pass
            ok('ネットワーク失敗は例外として伝播する')
    finally:
        n.nostr_request = real_req

    print(f'{len(passed)} passed: ' + ', '.join(passed))


if __name__ == '__main__':
    main()
