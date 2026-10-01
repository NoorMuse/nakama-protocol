"""rotation 証明書の Nostr 公開 (spec §17 / v0.12) のオフライン検証。

rotation_nostr_event（kind 30109 のオフライン構築）、verify_rotation_nostr_event
（三段階検証）、rotation_chain_fetch（チェーン走査・循環/上限ガード）、
rotate_pub の事前検証（keyfile の鍵 ≠ old_npub → publish しない）、
rotate_fetch（モックイベントのパース＋ --out の mode 600 保存）をテストする。
リレーへの接続は不要。使い方: python3 test_rotation_nostr.py
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
passed = []


def keypair():
    s = secrets.token_bytes(32)
    return s, n.npub_of(s), n.hexpub_of(s)


def make_rotation(old, new, ts=TS):
    """旧鍵で署名した rotation 証明書を作る（cmd_rotate と同型）。"""
    msg = n.rotation_message(old[1], new[1], ts)
    return {'protocol': 'nakama', 'version': 1, 'type': 'rotation',
            'old_npub': old[1], 'new_npub': new[1], 'created_at': ts,
            'old_sig': n.sign_schnorr(old[0], msg).hex()}


def pub_event_for(rot, old, ts=None, kind=n.ROTATION_NOSTR_KIND(),
                  d_tag=None, signer=None):
    """rotation 証明書を包む Nostr イベントを署名つきで作る（リレー経由相当）。"""
    content = json.dumps(rot, sort_keys=True, separators=(',', ':'))
    old_hex = n.npub_to_hex(rot['old_npub'])
    signer = signer or old[0]
    tags = [['d', old_hex]] if d_tag is None else d_tag
    return n.sign_event(signer, ts or int(time.time()), kind, tags, content)


def run_cmd(fn, ns):
    """cmd_* を実行し、(exit_code, stdout, stderr) を返す。"""
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
    A = keypair()  # old
    B = keypair()  # new
    C = keypair()  # 部外者（第三者スロット用）
    rot = make_rotation(A, B)
    old_hex = n.npub_to_hex(A[1])

    print('case 1: rotation_nostr_event — kind=30109、d タグ=old_hex、id/sig 有効、content=canonical JSON')
    ev = n.rotation_nostr_event(rot, A[0])
    assert ev['kind'] == n.ROTATION_NOSTR_KIND() == 30109
    assert ev['tags'] == [['d', old_hex]]
    assert n.verify_event_sig(ev), 'Nostr 署名が無効'
    assert json.loads(ev['content']) == rot
    assert ev['content'] == json.dumps(rot, sort_keys=True, separators=(',', ':'))
    assert ev['pubkey'] == old_hex, '署名者は旧鍵であること（§17.3）'
    ok('rotation_nostr_event 構築')

    print('case 2: rotate_pub の事前検証 — keyfile の鍵 ≠ old_npub → publish せず exit 1')
    tmpd = tempfile.mkdtemp()
    keyf_c = os.path.join(tmpd, 'key-c.json')
    n.save_key(keyf_c, C[0])  # 部外者 C の鍵を keyfile に
    rotf = os.path.join(tmpd, 'rotation.json')
    with open(rotf, 'w') as f:
        json.dump(rot, f)
    called = []
    real_publish = n.nostr_publish
    n.nostr_publish = lambda *a, **k: called.append(a) or (True, 'ok')
    try:
        ns = SimpleNamespace(keyfile=keyf_c, relay='wss://x', rotation=rotf, auth=False)
        code, out, err = run_cmd(n.cmd_rotate_pub, ns)
    finally:
        n.nostr_publish = real_publish
    assert code == 1, f'exit 1 を期待、得た: {code}'
    assert called == [], 'publish してはいけない'
    assert '一致しません' in err
    ok('rotate_pub は keyfile の鍵≠old_npub を拒否')

    print('case 3: fetch パース — モックイベント → 有効なものを表示、無効 Nostr 署名はスキップ')
    bad = pub_event_for(rot, A)
    bad['sig'] = '00' * 64  # Nostr 署名を破壊
    good = pub_event_for(rot, A)
    evs = {old_hex: [bad, good]}
    n.nostr_request = lambda url, req, **k: list(evs[n.npub_to_hex(A[1])]) if req[2].get('#d') == [old_hex] else []
    try:
        ns = SimpleNamespace(keyfile=keyf_c, relay='wss://x', old_npub=A[1],
                             limit=20, auth=False, out=None, chain=False)
        code, out, err = run_cmd(n.cmd_rotate_fetch, ns)
    finally:
        del n.nostr_request
    assert code == 0
    assert 'スキップ 1 件' in out, out
    assert B[1][:16] in out, '有効な rotation（A→B）が表示されること'
    ok('fetch は無効 Nostr 署名をスキップし有効なものを表示')

    print('case 4: fetch — content の old_npub と d タグの不一致 → スキップ')
    rot_b = make_rotation(B, C)  # B→C の証明書
    wrong_d = pub_event_for(rot_b, B, d_tag=[['d', old_hex]])  # d タグは A の old_hex
    assert n.verify_rotation_nostr_event(wrong_d, old_hex) is None
    ok('d タグ不一致はスキップ')

    print('case 5: fetch — イベント pubkey ≠ old_hex（第三者スロット）→ スキップ')
    third = pub_event_for(rot, A, signer=C[0])  # C が A の d スロットに publish（署名者は C）
    assert n.verify_event_sig(third), 'イベント自体の署名は有効'
    assert n.verify_rotation_nostr_event(third, old_hex) is None
    ok('第三者スロットは無視')

    print('case 6: rotation_chain_fetch — モック 3 リンク → 全チェーン取得、順序正しい')
    D = keypair()
    r1 = make_rotation(A, B, TS)
    r2 = make_rotation(B, C, TS + 10)
    r3 = make_rotation(C, D, TS + 20)
    store = {n.npub_to_hex(x[1]): r for x, r in [(A, r1), (B, r2), (C, r3)]}
    chain = n.rotation_chain_fetch(old_hex, lambda h: store.get(h))
    assert [r['new_npub'] for r in chain] == [B[1], C[1], D[1]]
    ok('3 リンクのチェーン走査')

    print('case 7: rotation_chain_fetch — 循環（A→B→A）と上限 16 リンク')
    r_loop1 = make_rotation(A, B, TS)
    r_loop2 = make_rotation(B, A, TS + 10)
    store_loop = {old_hex: r_loop1, n.npub_to_hex(B[1]): r_loop2}
    chain = n.rotation_chain_fetch(old_hex, lambda h: store_loop.get(h))
    assert len(chain) == 1 and chain[0]['new_npub'] == B[1], '循環で停止（A→B のみ）'
    # 長いチェーンは 16 で打ち切り
    keys = [keypair() for _ in range(20)]
    long_store = {}
    for i in range(19):
        src = A if i == 0 else keys[i - 1]
        dst = keys[i]
        r = make_rotation(src, dst, TS + i)
        long_store[n.npub_to_hex(src[1])] = r
    chain = n.rotation_chain_fetch(old_hex, lambda h: long_store.get(h))
    assert len(chain) == 16, f'上限 16 で打ち切り、得た: {len(chain)}'
    ok('循環検出・上限 16 リンク')

    print('case 8: --out — 保存ファイルは mode 600、再読込で verify_rotation_cert 有効')
    evs2 = {old_hex: [pub_event_for(rot, A)]}
    n.nostr_request = lambda url, req, **k: list(evs2[old_hex])
    try:
        outf = os.path.join(tmpd, 'fetched-rotation.json')
        ns = SimpleNamespace(keyfile=keyf_c, relay='wss://x', old_npub=A[1],
                             limit=20, auth=False, out=outf, chain=False)
        code, out, err = run_cmd(n.cmd_rotate_fetch, ns)
    finally:
        del n.nostr_request
    assert code == 0, out + err
    assert os.path.exists(outf)
    mode = os.stat(outf).st_mode & 0o777
    assert mode == 0o600, f'mode 600 を期待、得た: {oct(mode)}'
    with open(outf) as f:
        assert n.verify_rotation_cert(json.load(f)), '再読込で署名有効'
    ok('--out は mode 600 で保存し再検証可')

    print(f'\n{len(passed)} ケース通過')


if __name__ == '__main__':
    main()
