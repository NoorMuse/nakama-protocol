"""revocation UX 改善 (spec §12 / v0.7) のオフライン検証。

revoke --reason、revoke_import、revoke_pub（kind 30107 のオフライン構築）、
revoke_fetch（モックイベントのパース＋取り込み）をテストする。
リレーへの接続は不要。使い方: python3 test_revocation.py
"""
import json
import os
import secrets
import sys
import tempfile
import time

sys.path.insert(0, __file__.rsplit('/', 1)[0] or '.')
import nakama as n

TS = 1759370000
BOND_HASH = 'ab' * 32


def keypair():
    s = secrets.token_bytes(32)
    return s, n.npub_of(s), n.hexpub_of(s)


def make_revocation(s, npub, bond_hash=BOND_HASH, ts=TS, reason=''):
    """revocation イベントを署名して作る（reason='' の場合は旧形式 = reason キーなし）。"""
    msg = n.revocation_message(bond_hash, npub, ts, reason)
    r = {'protocol': 'nakama', 'version': 1, 'type': 'revocation',
         'bond_hash': bond_hash, 'revoker': npub, 'created_at': ts,
         'sig': n.sign_schnorr(s, msg).hex()}
    if reason:
        r['reason'] = reason
    return r


def make_bond(companions, ts=TS - 1000):
    return {'protocol': 'nakama', 'version': 1, 'companions': sorted(companions),
            'created_at': ts, 'nonce': secrets.token_hex(32),
            'signatures': {}}


passed = []


def ok(name):
    passed.append(name)
    print(f'  ok: {name}')


def main():
    A = keypair()   # bond 当事者
    B = keypair()   # 部外者
    bond = make_bond([A[1], B[1]])
    real_bond_hash = n.bond_hash(bond)

    print('case 1: import — 有効な revocation → 保存され、再読込で署名有効')
    reg = tempfile.mkdtemp()
    rev = make_revocation(A[0], A[1])
    assert n.import_revocation_event(rev, reg) == 'stored'
    rp = n.revocation_registry_path(reg, BOND_HASH)
    assert os.path.exists(rp) and (os.stat(rp).st_mode & 0o777) == 0o600
    with open(rp) as f:
        assert n.verify_revocation_event(json.load(f)), '再読込で検証失敗'
    ok('import 有効 → stored')

    print('case 2: import — 改ざん revocation（sig 破損）→ 拒否、registry に残らない')
    reg2 = tempfile.mkdtemp()
    bad = make_revocation(A[0], A[1])
    bad['sig'] = '00' * 64
    assert n.import_revocation_event(bad, reg2) == 'invalid'
    assert not os.listdir(reg2), 'registry に何か残っている'
    ok('import 改ざん → invalid')

    print('case 3: import — 重複 →「既に記録済み」、上書きしない（先勝ち）')
    sentinel = json.dumps({'sentinel': True})
    rp3 = n.revocation_registry_path(reg, BOND_HASH)
    with open(rp3, 'w') as f:
        f.write(sentinel)  # 先に別内容で記録
    dup = make_revocation(A[0], A[1], reason='あとの理由')
    assert n.import_revocation_event(dup, reg) == 'duplicate'
    with open(rp3) as f:
        assert f.read() == sentinel, '既存記録が上書きされた'
    ok('import 重複 → duplicate、先勝ち')

    print('case 4: import --bond — bond_hash 不一致 → 拒否')
    wrong_bond = make_bond([A[1], B[1]])
    rev4 = make_revocation(A[0], A[1])
    assert not n.verify_revocation_event(rev4, wrong_bond), '不一致の bond が通った'
    assert n.verify_revocation_event(rev4), 'bond なしの検証が通らない'
    # --bond ありで一致する場合は通る
    bond4 = make_bond([A[1], B[1]])
    rev4ok = make_revocation(A[0], A[1], bond_hash=n.bond_hash(bond4))
    assert n.verify_revocation_event(rev4ok, bond4), '--bond ありの正常系が通らない'
    # revoker が bond 当事者でない場合も拒否
    outsider = keypair()
    rev4out = make_revocation(outsider[0], outsider[1], bond_hash=n.bond_hash(bond4))
    assert not n.verify_revocation_event(rev4out, bond4), '部外者の revocation が通った'
    ok('import --bond の対応検証')

    print('case 5: reason — revoke --reason 相当の発行 → reason 改ざんで検証失敗')
    rev5 = make_revocation(A[0], A[1], reason='mutual parting')
    assert n.verify_revocation_event(rev5), 'reason 付き正常系が通らない'
    tampered = dict(rev5, reason='key compromised')
    assert not n.verify_revocation_event(tampered), 'reason 改ざんが通った（署名対象でない）'
    # reason 付きと reason なしでは署名対象が変わる
    rev5b = make_revocation(A[0], A[1])
    assert rev5['sig'] != rev5b['sig'], 'reason の有無で署名対象が変わっていない'
    ok('reason の署名対象化')

    print('case 6: 後方互換 — reason なし旧形式イベント → 検証 OK')
    old = make_revocation(A[0], A[1])  # reason キーなし = 旧形式
    assert 'reason' not in old
    assert n.verify_revocation_event(old), '旧形式イベントが検証を通らない'
    # revocation_message の既定引数で従来のメッセージと一致
    assert n.revocation_message(BOND_HASH, A[1], TS) == n.revocation_message(BOND_HASH, A[1], TS, ''), \
        'reason="" と旧形式のメッセージが不一致'
    ok('後方互換')

    print('case 7: revoke_pub 構築（オフライン）— kind=30107、d タグ = bond_hash、id/sig 有効')
    rev7 = make_revocation(A[0], A[1], reason='互いの合意')
    ev = n.revocation_nostr_event(rev7, A[0])
    assert ev['kind'] == 30107, f"kind が 30107 でない: {ev['kind']}"
    assert ev['tags'] == [['d', BOND_HASH]], f"d タグ不正: {ev['tags']}"
    assert n.verify_event_sig(ev), '構築イベントの id/sig が無効'
    assert json.loads(ev['content']) == rev7, 'content から revocation が復元できない'
    ok('revocation_nostr_event')

    print('case 8: revoke_fetch パース＋取り込み（モックイベント）— 有効→保存、署名無効→スキップ')
    reg8 = tempfile.mkdtemp()
    rev8 = make_revocation(A[0], A[1])
    ev_ok = n.revocation_nostr_event(rev8, A[0])
    ev_bad = n.revocation_nostr_event(rev8, A[0])
    ev_bad['content'] = json.dumps(dict(rev8, reason='後付け'))  # content 改ざん → Nostr 署名無効
    stored = skipped = 0
    for mev in [ev_ok, ev_bad]:
        if not n.verify_event_sig(mev):
            skipped += 1
            continue
        try:
            r = json.loads(mev['content'])
        except ValueError:
            skipped += 1
            continue
        if not isinstance(r, dict) or r.get('bond_hash') != BOND_HASH:
            skipped += 1
            continue
        res = n.import_revocation_event(r, reg8)
        if res == 'stored':
            stored += 1
        else:
            skipped += 1
    assert stored == 1 and skipped == 1, f'想定外: stored={stored} skipped={skipped}'
    with open(n.revocation_registry_path(reg8, BOND_HASH)) as f:
        assert n.verify_revocation_event(json.load(f))
    ok('fetch モックの取り込み')

    print(f'\n{len(passed)} ケース通過')


if __name__ == '__main__':
    main()
