"""v0.9: 侵害宣言の統合と移行完了の表示 (spec §14 / test plan 10 cases) のオフライン検証。

verify / challenge / check / board_verify / board_send / board_read / dm_send への
stderr 警告（exit コード不変）と、key_status --rotation の migration 表示をテストする。
リレーへの接続は不要（board_send の nostr_publish はモンキーパッチ）。
使い方: python3 test_compromise_integration.py
"""
import io
import json
import os
import secrets
import sys
import tempfile
import time
from contextlib import redirect_stderr, redirect_stdout
from types import SimpleNamespace

sys.path.insert(0, __file__.rsplit('/', 1)[0] or '.')
import nakama as n

TS = 1759370000
DECL_T = TS + 1000


def keypair():
    s = secrets.token_bytes(32)
    return s, n.npub_of(s), n.hexpub_of(s)


def check(name, cond):
    print(('PASS' if cond else 'FAIL') + ' ' + name)
    if not cond:
        sys.exit(1)


def run_cmd(fn, **kwargs):
    """CLI コマンドを SimpleNamespace で呼び出す。(exit_code, stdout, stderr) を返す。"""
    ns = SimpleNamespace(**kwargs)
    out, err = io.StringIO(), io.StringIO()
    try:
        with redirect_stdout(out), redirect_stderr(err):
            fn(ns)
    except SystemExit as e:
        return e.code, out.getvalue(), err.getvalue()
    return 0, out.getvalue(), err.getvalue()


def declare_on(declarant_secret, subject_npub, registry, ts=DECL_T, withdrawn=False):
    decl = n.build_compromise_declaration(declarant_secret, subject_npub, ts, withdrawn)
    res = n.import_compromise_event(decl, registry)
    assert res in ('stored', 'updated'), res
    return decl


def make_bond(secret_a, secret_b, ts=TS):
    comps = sorted([n.npub_of(secret_a), n.npub_of(secret_b)])
    nonce = secrets.token_hex(32)
    msg = n.bond_message(comps, ts, nonce, None)
    return {'protocol': 'nakama', 'version': 1, 'companions': comps,
            'created_at': ts, 'nonce': nonce,
            'signatures': {n.npub_of(secret_a): n.sign_schnorr(secret_a, msg).hex(),
                           n.npub_of(secret_b): n.sign_schnorr(secret_b, msg).hex()}}


def make_rotation(old_secret, new_secret, ts):
    msg = n.rotation_message(n.npub_of(old_secret), n.npub_of(new_secret), ts)
    return {'protocol': 'nakama', 'version': 1, 'type': 'rotation',
            'old_npub': n.npub_of(old_secret), 'new_npub': n.npub_of(new_secret),
            'created_at': ts, 'old_sig': n.sign_schnorr(old_secret, msg).hex()}


def make_descriptor(operator_secret, board_id='nakama-x7q2', relay='wss://example', ts=TS):
    msg = n.board_descriptor_message(board_id, relay, [n.npub_of(operator_secret)], ts)
    return {'protocol': 'nakama', 'version': 1, 'type': 'board',
            'board_id': board_id, 'relay': relay,
            'moderators': [n.npub_of(operator_secret)],
            'admission': 'approval', 'created_at': ts,
            'sig': n.sign_schnorr(operator_secret, msg).hex()}


def main():
    tmp = tempfile.mkdtemp()
    registry = os.path.join(tmp, 'compromises')
    a_s, a_npub, a_hex = keypair()   # subject A
    b_s, b_npub, _ = keypair()       # bond 相手 B
    c_s, c_npub, _ = keypair()       # 宣言者 C
    d_s, d_npub, _ = keypair()       # その他 D

    def write(name, obj):
        p = os.path.join(tmp, name)
        with open(p, 'w') as f:
            json.dump(obj, f)
        return p

    # 1. verify: 当事者に宣言あり → stderr 警告、exit 0（検証結果は変わらない）
    declare_on(c_s, a_npub, registry)
    bond_path = write('bond.json', make_bond(a_s, b_s))
    code, out, err = run_cmd(n.cmd_verify, bond=bond_path, rotation=[],
                             registry=None, skip_registry=True, skip_expiry=True,
                             compromise_registry=registry)
    check('1 verify: 宣言あり→stderr 警告', 'WARN:' in err and 'key_status' in err)
    check('1 verify: exit 0（検証結果不変）', code == 0 and 'bond は有効です' in out)

    # 2. verify: 宣言が withdrawn のみ → 警告なし
    declare_on(c_s, a_npub, registry, ts=DECL_T, withdrawn=True)  # 撤回で上書き
    code, out, err = run_cmd(n.cmd_verify, bond=bond_path, rotation=[],
                             registry=None, skip_registry=True, skip_expiry=True,
                             compromise_registry=registry)
    check('2 verify: withdrawn のみ→警告なし', 'WARN:' not in err)
    check('2 verify: exit 0', code == 0)

    # 3. verify --rotation: 新鍵に宣言なし・旧鍵に宣言あり → INFO「移行済み」、WARN なし
    declare_on(c_s, a_npub, registry, ts=DECL_T, withdrawn=False)  # 宣言を復活
    a2_s, a2_npub, _ = keypair()
    rot = make_rotation(a_s, a2_s, DECL_T + 100)
    rot_path = write('rotation.json', rot)
    code, out, err = run_cmd(n.cmd_verify, bond=bond_path, rotation=[rot_path],
                             registry=None, skip_registry=True, skip_expiry=True,
                             compromise_registry=registry)
    check('3 verify --rotation: INFO あり', 'INFO:' in err and '旧鍵' in err)
    check('3 verify --rotation: WARN なし（新鍵は無事）', 'WARN:' not in err)
    check('3 verify --rotation: exit 0', code == 0)

    # 4a. challenge --to: 対手に宣言あり → 警告
    code, out, err = run_cmd(n.cmd_challenge, to=a_npub, compromise_registry=registry)
    nonce = out.strip()
    check('4a challenge --to: 警告あり', 'WARN:' in err)
    check('4a challenge: nonce 出力（exit 0）', code == 0 and len(bytes.fromhex(nonce)) == 32)

    # 4b. check: 対手に宣言あり → 警告、exit 0
    sig = n.sign_schnorr(a_s, bytes.fromhex(nonce)).hex()
    code, out, err = run_cmd(n.cmd_check, npub=a_npub, nonce=nonce, sig=sig,
                             compromise_registry=registry)
    check('4b check: 警告あり', 'WARN:' in err)
    check('4b check: exit 0（本人確認は成功）', code == 0 and '本人です' in out)

    # 5. board_verify: signer に宣言あり → 警告
    declare_on(c_s, d_npub, registry)  # 運営者 D に宣言
    desc_path = write('descriptor.json', make_descriptor(d_s))
    code, out, err = run_cmd(n.cmd_board_verify, descriptor=desc_path,
                             compromise_registry=registry)
    check('5 board_verify: 警告あり', 'WARN:' in err)
    check('5 board_verify: exit 0（descriptor 自体は有効）', code == 0 and '有効です' in out)

    # 6. board_send: 送信者に宣言あり → 警告（nostr_publish はモンキーパッチ）
    real_pub = n.nostr_publish
    n.nostr_publish = lambda *a, **k: (True, 'ok')
    try:
        kf = os.path.join(tmp, 'a.json')
        n.save_key(kf, a_s)
        code, out, err = run_cmd(n.cmd_board_send, relay='wss://example',
                                 board_id='nakama-x7q2', message='hi', auth=False,
                                 descriptor=None, keyfile=kf,
                                 compromise_registry=registry)
        check('6 board_send: 送信者に警告あり', 'WARN:' in err)
        check('6 board_send: exit 0（投稿は受理）', code == 0)
        # 運営鍵にも宣言 → 「この板の運営鍵に疑念あり」
        code, out, err = run_cmd(n.cmd_board_send, relay='wss://example',
                                 board_id='nakama-x7q2', message='hi', auth=False,
                                 descriptor=desc_path, keyfile=kf,
                                 compromise_registry=registry)
        check('6 board_send: 運営鍵の警告あり', '運営鍵' in err)
        check('6 board_send: exit 0', code == 0)
    finally:
        n.nostr_publish = real_pub

    # 7. dm_send: 宛先に宣言あり → 警告（stdout の gift wrap は汚さない）
    declare_on(c_s, b_npub, registry)  # 宛先 B に宣言
    kf_b = os.path.join(tmp, 'b.json')
    n.save_key(kf_b, a_s)
    gw_path = os.path.join(tmp, 'gw.json')
    code, out, err = run_cmd(n.cmd_dm_send, npub=b_npub, message='hello',
                             out=gw_path, keyfile=kf_b,
                             compromise_registry=registry)
    check('7 dm_send: 宛先に警告あり', 'WARN:' in err)
    check('7 dm_send: gift wrap 構築成功', code == 0 and os.path.exists(gw_path)
          and json.load(open(gw_path))['kind'] == 1059)

    # 8. key_status --rotation: 宣言後の有効なチェーン → migration: complete
    kf_none = os.path.join(tmp, 'nope.json')
    code, out, err = run_cmd(n.cmd_key_status, npub=a_npub, threshold=2, bond=[],
                             liveness=None, max_age=7 * 86400, registry=registry,
                             rotation=[rot_path], keyfile=kf_none)
    check('8 key_status --rotation: migration: complete', 'migration: complete' in out)
    check('8 key_status: 新鍵に宣言なし表示', '新鍵への有効な宣言はありません' in out)
    check('8 key_status: exit 0（complete でも exit 不変）', code == 0)

    # 9. key_status --rotation: 宣言前のチェーン → migration: stale
    rot_old = make_rotation(a_s, a2_s, DECL_T - 100)
    rot_old_path = write('rotation_old.json', rot_old)
    code, out, err = run_cmd(n.cmd_key_status, npub=a_npub, threshold=2, bond=[],
                             liveness=None, max_age=7 * 86400, registry=registry,
                             rotation=[rot_old_path], keyfile=kf_none)
    check('9 key_status --rotation: migration: stale', 'migration: stale' in out)
    check('9 key_status: exit 0', code == 0)

    # 10. key_status --rotation: 署名無効のチェーン → migration: broken
    rot_bad = dict(rot)
    rot_bad['old_sig'] = n.sign_schnorr(d_s, n.rotation_message(
        rot['old_npub'], rot['new_npub'], rot['created_at'])).hex()  # 他人の署名
    rot_bad_path = write('rotation_bad.json', rot_bad)
    code, out, err = run_cmd(n.cmd_key_status, npub=a_npub, threshold=2, bond=[],
                             liveness=None, max_age=7 * 86400, registry=registry,
                             rotation=[rot_bad_path], keyfile=kf_none)
    check('10 key_status --rotation: migration: broken', 'migration: broken' in out)
    check('10 key_status: exit 0', code == 0)

    print('ALL PASS')


if __name__ == '__main__':
    main()
