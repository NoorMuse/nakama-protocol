"""鍵スコープの侵害宣言 (spec §13 / v0.8) のオフライン検証。

declare の署名、改ざん・偽造の検出、import（registry 取り込み＋dedup＋--subject）、
withdraw（撤回→上書き）、compromise_pub（kind 30108 のオフライン構築）、
key_status の評価、旧形式（evidence なし）の後方互換をテストする。
リレーへの接続は不要。使い方: python3 test_compromise.py
"""
import io
import json
import os
import secrets
import sys
import tempfile
import time
from contextlib import redirect_stdout
from types import SimpleNamespace

sys.path.insert(0, __file__.rsplit('/', 1)[0] or '.')
import nakama as n

TS = 1759370000


def keypair():
    s = secrets.token_bytes(32)
    return s, n.npub_of(s), n.hexpub_of(s)


def make_declaration(declarant_secret, declarant_npub, subject_npub, ts=TS,
                     reason='', evidence='', withdrawn=False, bond_hash=''):
    return n.build_compromise_declaration(declarant_secret, subject_npub, ts,
                                          withdrawn, bond_hash, reason, evidence)


def check(name, cond):
    print(('PASS' if cond else 'FAIL') + ' ' + name)
    if not cond:
        sys.exit(1)


def run_cmd(fn, **kwargs):
    """CLI コマンドを SimpleNamespace で呼び出す。SystemExit の code を返す。"""
    ns = SimpleNamespace(**kwargs)
    buf = io.StringIO()
    try:
        with redirect_stdout(buf):
            fn(ns)
    except SystemExit as e:
        return e.code, buf.getvalue()
    return 0, buf.getvalue()


def main():
    tmp = tempfile.mkdtemp()
    registry = os.path.join(tmp, 'compromises')
    ds, dnpub, _ = keypair()       # declarant
    ss, snpub, _ = keypair()       # subject
    ts, tnpub, _ = keypair()       # third party

    # 1. declare: 有効な宣言 → 署名検証 OK
    decl = make_declaration(ds, dnpub, snpub, reason='saw impostor posting',
                            evidence='nostr:event:abc123')
    check('1 declare 署名検証 OK', n.verify_compromise_event(decl))

    # 2. 改ざん: reason 変更 → 検証失敗（署名対象であることの確認）
    tampered = dict(decl)
    tampered['reason'] = 'just kidding'
    check('2 reason 改ざんで検証失敗', not n.verify_compromise_event(tampered))
    tampered2 = dict(decl)
    tampered2['withdrawn'] = True
    check('2b withdrawn 改ざんで検証失敗', not n.verify_compromise_event(tampered2))

    # 3. 他鍵偽造: declarant と異なる鍵で署名 → 検証失敗
    forged = make_declaration(ts, tnpub, snpub)
    forged['declarant'] = dnpub  # 宣言者を偽装（署名は第三者の鍵）
    check('3 他鍵偽造で検証失敗', not n.verify_compromise_event(forged))

    # 4. import: 有効 → registry 保存、再読込で署名有効
    check('4 import 有効→stored', n.import_compromise_event(decl, registry) == 'stored')
    rp = n.compromise_registry_path(registry, n.npub_to_hex(snpub))
    check('4 registry ファイル存在', os.path.exists(rp))
    with open(rp) as f:
        saved = json.load(f)
    check('4 再読込で署名有効', isinstance(saved, list) and len(saved) == 1
          and n.verify_compromise_event(saved[0]))

    # 5. import: 重複（declarant + created_at 同一）→ duplicate、上書きなし
    dup = make_declaration(ds, dnpub, snpub, reason='書き換えようとした理由')
    check('5 重複→duplicate', n.import_compromise_event(dup, registry) == 'duplicate')
    with open(rp) as f:
        saved = json.load(f)
    check('5 先勝ちで上書きなし', len(saved) == 1 and saved[0].get('reason') == 'saw impostor posting')

    # 6. import --subject: subject 不一致 → 拒否（CLI レベル、exit 1）
    decl_path = os.path.join(tmp, 'decl.json')
    with open(decl_path, 'w') as f:
        json.dump(decl, f)
    code, _ = run_cmd(n.cmd_compromise_import, declaration=decl_path,
                      subject=tnpub, registry=registry)
    check('6 --subject 不一致で拒否', code == 1)

    # 7. withdraw: withdrawn=true 再発行 → import で上書き、key_status が撤回済みを表示
    with_path = os.path.join(tmp, 'withdrawn.json')
    kf = os.path.join(tmp, 'identity.json')
    n.save_key(kf, ds)
    code, out = run_cmd(n.cmd_compromise_withdraw, subject=snpub, registry=registry,
                        out=with_path, keyfile=kf)
    check('7b withdraw 成功', code == 0)
    check('7c withdrawn=true の宣言が出力', json.load(open(with_path)).get('withdrawn') is True)
    with open(rp) as f:
        saved = json.load(f)
    check('7d registry が撤回で上書き', len(saved) == 1 and saved[0].get('withdrawn') is True)
    st = n.key_status(snpub, registry, dnpub, [], 2)
    check('7e key_status が撤回済みを表示', st['withdrawn_count'] == 1 and not st['suspected'])
    check('7f key_status 行の category が撤回済み',
          len(st['declarations']) == 1 and st['declarations'][0]['category'] == '撤回済み')

    # 8. Nostr 構築（オフライン）: kind=30108、d タグ、id／sig 有効
    fresh = make_declaration(ds, dnpub, snpub, ts=TS + 100)
    ev = n.compromise_nostr_event(fresh, ds)
    check('8 kind=30108', ev['kind'] == 30108)
    dtag = [t for t in ev['tags'] if t[0] == 'd']
    check('8 d タグ = subject_hex:declarant_hex',
          len(dtag) == 1 and dtag[0][1] == n.npub_to_hex(snpub) + ':' + n.npub_to_hex(dnpub))
    check('8 id／sig 有効', n.verify_event_sig(ev))

    # 9. 後方互換: evidence なし旧形式 → 検証 OK
    old = make_declaration(ds, dnpub, snpub, ts=TS + 200)
    old.pop('evidence', None)  # build は空ならキーを作らないが、念のため
    check('9 旧形式（evidence なし）検証 OK', n.verify_compromise_event(old))
    old2 = make_declaration(ds, dnpub, snpub, ts=TS + 300, reason='古い宣言')
    check('9b 旧形式 import OK', n.import_compromise_event(old2, registry) == 'stored')

    # + key_status の重みづけ: 仲間2人で threshold 2 → suspected
    registry2 = os.path.join(tmp, 'compromises2')
    d2s, d2npub, _ = keypair()
    decl2 = make_declaration(d2s, d2npub, snpub, ts=TS + 400)
    n.import_compromise_event(decl2, registry2)
    # me の bond ファイル（me + 宣言者2人）
    me_s, me_npub, _ = keypair()
    bond = {'protocol': 'nakama', 'version': 1, 'companions': sorted([me_npub, dnpub, d2npub]),
            'created_at': TS - 1000, 'nonce': secrets.token_hex(32), 'signatures': {}}
    # 両宣言者を registry2 に（withdrawn 前の fresh を再利用）
    n.import_compromise_event(make_declaration(ds, dnpub, snpub, ts=TS + 500), registry2)
    st = n.key_status(snpub, registry2, me_npub, [bond], 2)
    cats = sorted(r['category'] for r in st['declarations'])
    check('+ 仲間の宣言は「直接の仲間」', cats == ['直接の仲間', '直接の仲間'])
    check('+ threshold 2 到達で suspected', st['suspected'] and st['suspected_count'] == 2)
    # 無関係な第三者の宣言は参考情報（カウントしない）
    decl3 = make_declaration(ts, tnpub, snpub, ts=TS + 600)
    n.import_compromise_event(decl3, registry2)
    st = n.key_status(snpub, registry2, me_npub, [bond], 3)
    cats = sorted(r['category'] for r in st['declarations'])
    check('+ 第三者は参考情報', cats == ['参考情報', '直接の仲間', '直接の仲間'])
    check('+ threshold 3 未達で suspected ではない', not st['suspected'])

    print('ALL PASS')


if __name__ == '__main__':
    main()
