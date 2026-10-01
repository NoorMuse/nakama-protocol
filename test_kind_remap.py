"""kind 再マップ (spec §26.10 / v0.23) のオフライン検証。

1. 既定値: 5 定数が 30107–30111 であること
2. 環境変数で 1 つだけ上書き → その kind のみ変更、他は既定のまま
3. 不正値（非 int / 29999 / 40000）→ 対象操作が exit 1 で拒否（使用時検証）
4. decision_nostr_event(d, secret) の kind 既定が新定数（30110）を使うこと
5. board_fetch_all の kind ホワイトリストが定数ベースであること

リレーへの接続は不要。使い方: python3 test_kind_remap.py
"""
import os
import secrets
import subprocess
import sys
import time

sys.path.insert(0, __file__.rsplit('/', 1)[0] or '.')
import nakama as n

failed = 0


def ok(name):
    print('PASS', name)


def ng(name, detail=''):
    global failed
    failed += 1
    print('FAIL', name, detail)


def run_child(code, env_extra=None):
    """子プロセスで nakama を import してコードを実行（環境変数の分離用）。"""
    env = dict(os.environ)
    env.update(env_extra or {})
    return subprocess.run(
        [sys.executable, '-c',
         'import sys; sys.path.insert(0, "."); import nakama as n\n' + code],
        env=env, capture_output=True, text=True)


def keypair():
    s = secrets.token_bytes(32)
    return s, n.npub_of(s), n.hexpub_of(s)


def make_decision(board_id='board1', ts=1759370000):
    return {'protocol': 'nakama', 'version': 1, 'type': 'board-decision',
            'board_id': board_id, 'decision': 'admit',
            'payload': {'candidate': keypair()[1]},
            'created_at': ts, 'approvals': []}


def main():
    global failed
    s, npub, hexpub = keypair()

    # 1. 既定値
    defaults = (n.REVOCATION_NOSTR_KIND(), n.COMPROMISE_NOSTR_KIND(),
                n.ROTATION_NOSTR_KIND(), n.DECISION_NOSTR_KIND(),
                n.DRAFT_NOSTR_KIND())
    if defaults == (30107, 30108, 30109, 30110, 30111):
        ok('1 既定値: 5 定数が 30107–30111')
    else:
        ng('1 既定値', f'got={defaults}')

    # 2. 環境変数で 1 つだけ上書き → その kind のみ変更
    p = run_child('print(n.DECISION_NOSTR_KIND(), n.DRAFT_NOSTR_KIND(), n.REVOCATION_NOSTR_KIND())',
                  {'NAKAMA_KIND_DECISION': '39999'})
    if p.returncode == 0 and p.stdout.strip() == '39999 30111 30107':
        ok('2 環境変数上書き: DECISION のみ 39999、他は既定のまま')
    else:
        ng('2 環境変数上書き', f'rc={p.returncode} out={p.stdout.strip()!r}')

    # 3. 不正値 → 使用時に exit 1
    for bad, label in [('abc', '非int'), ('29999', '範囲下限外'), ('40000', '範囲上限外')]:
        p = run_child('print(n.REVOCATION_NOSTR_KIND())',
                      {'NAKAMA_KIND_REVOCATION': bad})
        if p.returncode == 1:
            ok(f'3 不正値({label}={bad!r}) → exit 1 で拒否')
        else:
            ng(f'3 不正値({label}={bad!r})', f'rc={p.returncode} (exit 1 を期待)')
    # 空文字は「未設定」と同等（既定に戻る）
    p = run_child('print(n.REVOCATION_NOSTR_KIND())',
                  {'NAKAMA_KIND_REVOCATION': ''})
    if p.returncode == 0 and p.stdout.strip() == '30107':
        ok('3b 空文字: 既定 30107 に戻る')
    else:
        ng('3b 空文字', f'rc={p.returncode} out={p.stdout.strip()!r}')
    # 3c. 無効な環境変数があっても無関係の定数は壊れない（使用時検証の証明）
    p = run_child('print(n.DECISION_NOSTR_KIND())',
                  {'NAKAMA_KIND_REVOCATION': 'xxx'})
    if p.returncode == 0 and p.stdout.strip() == '30110':
        ok('3c 無関係の定数は無効な環境変数に影響されない（使用時検証）')
    else:
        ng('3c 使用時検証', f'rc={p.returncode}')

    # 4. decision_nostr_event の既定 kind が新定数
    d = make_decision()
    ev = n.decision_nostr_event(d, s)
    if ev['kind'] == 30110:
        ok('4 decision_nostr_event の既定 kind = 30110（新定数）')
    else:
        ng('4 既定 kind', f'got={ev["kind"]}')
    ev2 = n.decision_nostr_event(d, s, kind=30000)
    if ev2['kind'] == 30000:
        ok('4b 明示 kind は尊重される')
    else:
        ng('4b 明示 kind', f'got={ev2["kind"]}')
    if n.verify_board_decision_nostr_event(ev, 'board1') is not None:
        ok('4c 既定 expect_kind で検証通過')
    else:
        ng('4c 既定 expect_kind 検証')
    # 4d. 環境変数上書き下で構築→検証が往復
    code = (
        'import secrets; s2 = secrets.token_bytes(32); '
        'd2 = {"protocol": "nakama", "version": 1, "type": "board-decision", '
        '"board_id": "b1", "decision": "admit", '
        '"payload": {"candidate": n.npub_of(s2)}, "created_at": 1759370000, "approvals": []}; '
        'ev2 = n.decision_nostr_event(d2, s2); '
        'assert ev2["kind"] == 30050, ev2["kind"]; '
        'assert n.verify_board_decision_nostr_event(ev2, "b1") is not None; '
        'print("roundtrip ok")')
    p = run_child(code, {'NAKAMA_KIND_DECISION': '30050'})
    if p.returncode == 0 and 'roundtrip ok' in p.stdout:
        ok('4d 環境変数上書き下で構築→検証が往復')
    else:
        ng('4d 上書き下の往復', f'rc={p.returncode} err={p.stderr.strip()[-200:]!r}')

    # 5. board_fetch_all の購読 kind が定数ベース（環境変数が fetch に反映される）
    code = (
        'def _mk():\n'
        '    reqs = []\n'
        '    def fake(url, req, **k):\n'
        '        reqs.append(req)\n'
        '        return []\n'
        '    return reqs, fake\n'
        'reqs, fake = _mk(); n.nostr_request = fake; '
        'import argparse, json, tempfile, secrets; '
        'kf = tempfile.NamedTemporaryFile("w", suffix=".json", delete=False); '
        'json.dump({"secret_hex": secrets.token_bytes(32).hex()}, kf); kf.close(); '
        'args = argparse.Namespace(relay="wss://x", board_id="b1", limit=50, '
        'auth=False, out=None, policy=None, keyfile=kf.name); '
        'n.cmd_board_fetch_all(args); '
        'kinds = reqs[0][2]["kinds"]; '
        'assert kinds == [30050, 30111], kinds; '
        'print("whitelist ok", kinds)')
    p = run_child(code, {'NAKAMA_KIND_DECISION': '30050'})
    if p.returncode == 0 and 'whitelist ok' in p.stdout:
        ok('5 board_fetch_all の購読 kind が定数ベース（環境変数反映）')
    else:
        ng('5 ホワイトリスト定数ベース', f'rc={p.returncode} out={p.stdout.strip()[-200:]!r} err={p.stderr.strip()[-200:]!r}')

    print('全 5 ケース群', 'すべて通過' if failed == 0 else f'{failed} 件失敗')
    sys.exit(1 if failed else 0)


if __name__ == '__main__':
    main()
