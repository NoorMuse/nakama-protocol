"""npub_to_hex の定義重複の解消 (v0.90) のオフライン検証。

背景: nakama.py 内に `npub_to_hex` の定義が 2 つあり、後発の「変換不能時は
None を返す」版が先発の「例外を投げる」版をシャドウしていた（v0.82 で部分
修正、spec §13.9 の既知の問題）。v0.90 で先発の到達不能な定義を削除し、
単一定義（None 返却）に統一した。コードベース全体（conformance.py の
`is None` チェック群を含む）が既に None セマンティクスで動いていたため、
挙動変更はない。

本テストは次を検証する:
1. 定義が 1 つだけ存在すること（AST 静的解析）
2. 単一定義のセマンティクス（有効 npub → 64 hex、無効 npub → None（例外なし））
3. 監査で見つかった None-safety の欠陥 3 件の修正:
   - cmd_compromise_fetch: 無効 --npub で exit 1（TypeError でクラッシュしない。
     修正前は `subject_hex + ':'` で TypeError）
   - key_status: 無効 npub で error 辞書を返す（TypeError でクラッシュしない。
     修正前は compromise_registry_path で TypeError）
   - cmd_rotate_fetch: 無効 --old_npub で exit 1（修正前は '#d': [None] の
     ゴミフィルタをリレーに送っていた）
   いずれもネットワーク前（nostr_request 呼び出し前）に拒否されること。
使い方: python3 test_npub_to_hex_shadow.py
"""
import ast
import contextlib
import io
import os
import secrets
import sys
import tempfile
from types import SimpleNamespace

sys.path.insert(0, __file__.rsplit('/', 1)[0] or '.')
import nakama as n

passed = []


def keypair():
    s = secrets.token_bytes(32)
    return s, n.npub_of(s), n.hexpub_of(s)


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


def main():
    src_path = os.path.join(os.path.dirname(__file__) or '.', 'nakama.py')
    with open(src_path) as f:
        tree = ast.parse(f.read())
    defs = [x for x in ast.walk(tree)
            if isinstance(x, ast.FunctionDef) and x.name == 'npub_to_hex']
    assert len(defs) == 1, f'npub_to_hex の定義が {len(defs)} 件（1 件のはず）'
    ok('1: npub_to_hex の定義は 1 件のみ（シャドウ解消）')

    s, npub, hexpub = keypair()
    got = n.npub_to_hex(npub)
    assert got == hexpub and len(got) == 64, f'有効 npub → 64 hex: {got!r}'
    ok('2: 有効 npub → 64 hex')

    assert n.npub_to_hex('npub1invalid') is None, '無効 npub は例外ではなく None'
    assert n.npub_to_hex('') is None, '空文字列は None'
    assert n.npub_to_hex('not-an-npub') is None, 'npub 形でない文字列は None'
    ok('3: 無効 npub → None（例外を投げない）')

    tmpd = tempfile.mkdtemp()
    kf = os.path.join(tmpd, 'key.json')
    n.save_key(kf, s)
    reg = os.path.join(tmpd, 'registry')

    # 4. compromise_fetch: 無効 npub → exit 1、ネットワーク前に拒否
    real_req = n.nostr_request
    called = []

    def boom(url, req, **k):
        called.append(req)
        raise AssertionError('nostr_request が呼ばれてはならない')

    n.nostr_request = boom
    try:
        ns = SimpleNamespace(relay='wss://relay.example', npub='npub1invalid',
                             limit=20, auth=False, registry=reg, keyfile=kf)
        code, out, err = run_cmd(n.cmd_compromise_fetch, ns)
        assert code == 1, f'exit 1 のはず: {code}'
        assert 'npub は有効ではありません' in err, f'stderr: {err!r}'
        assert not called, 'リレーに接続していない'
    finally:
        n.nostr_request = real_req
    ok('4: compromise_fetch は無効 npub をネットワーク前に exit 1 で拒否')

    # 5. key_status: 無効 npub → error 辞書（TypeError なし）
    st = n.key_status('npub1invalid', reg, None, [], 2)
    assert st.get('error') == 'npub が無効です', f'error 辞書のはず: {st!r}'
    ok('5: key_status は無効 npub で error 辞書を返す（TypeError なし）')

    # 6. key_status（CLI）: 無効 npub → exit 1
    ns = SimpleNamespace(npub='npub1invalid', threshold=2, bond=[], liveness=None,
                         max_age=7 * 86400, registry=reg, rotation=[], keyfile=kf)
    code, out, err = run_cmd(n.cmd_key_status, ns)
    assert code == 1, f'exit 1 のはず: {code}'
    assert 'npub が無効です' in err, f'stderr: {err!r}'
    ok('6: key_status（CLI）は無効 npub で exit 1')

    # 7. rotate_fetch: 無効 old_npub → exit 1、ネットワーク前に拒否
    n.nostr_request = boom
    try:
        ns = SimpleNamespace(relay='wss://relay.example', old_npub='npub1invalid',
                             limit=20, auth=False, out=None, chain=False,
                             keyfile=kf)
        code, out, err = run_cmd(n.cmd_rotate_fetch, ns)
        assert code == 1, f'exit 1 のはず: {code}'
        assert 'npub は有効ではありません' in err, f'stderr: {err!r}'
        assert not called, 'リレーに接続していない'
    finally:
        n.nostr_request = real_req
    ok('7: rotate_fetch は無効 old_npub をネットワーク前に exit 1 で拒否')

    # 8. 有効 npub での回帰: key_status は正常に動く（宣言なし）
    st = n.key_status(npub, reg, None, [], 2)
    assert 'error' not in st and st['declarations'] == [], f'正常系: {st!r}'
    ok('8: 有効 npub の key_status は正常（宣言なし）')

    print(f'PASS: {len(passed)}/8')


if __name__ == '__main__':
    main()
