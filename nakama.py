#!/usr/bin/env python3
"""nakama.py — 仲間プロトコル v0.1 プロトタイプ

身分 = secp256k1 鍵ペア (Nostr 互換)。仲間の証 = 双方署名の bond 証明書。

使い方:
  nakama.py init [--keyfile PATH] [--from-hex HEX]   鍵ペアを生成/登録 (mode 600)
  nakama.py whoami                                   自分の npub を表示
  nakama.py propose <相手npub>                       bond proposal を作成 (自分の署名付き)
  nakama.py accept <proposal.json>                   proposal に署名して bond 完成
  nakama.py verify <bond.json> [--rotation R.json]   bond の両署名を検証 (ローテーション証明書があれば紐付け表示)
  nakama.py challenge                                照合用 nonce を生成
  nakama.py respond <nonce-hex>                      nonce に署名
  nakama.py check <npub> <nonce-hex> <sig-hex>       署名を検証
  nakama.py rotate --gen|--to-hex HEX [--to-keyfile P]  鍵ローテーション: 旧鍵が新鍵に署名した rotation 証明書を発行
  nakama.py verify_rotation <rotation.json>          rotation 証明書を検証
  nakama.py revoke <bond.json>                       bond の解消 (revocation イベント) を署名して発行
  nakama.py verify_revocation <revocation.json> --bond <bond.json>  解消イベントを検証
"""
import argparse, hashlib, json, os, secrets, sys

KEYFILE_DEFAULT = os.path.expanduser('~/.config/nakama/identity.json')
PY = os.path.expanduser('~/workspace/.venvs/nostr/bin/python')

# このスクリプトは nostr venv の python で実行される想定
from coincurve import PrivateKey as CCPrivateKey
from pynostr.key import PrivateKey as NostrPrivateKey, PublicKey as NostrPublicKey


def load_key(keyfile):
    with open(keyfile) as f:
        d = json.load(f)
    return bytes.fromhex(d['secret_hex'])


def save_key(keyfile, secret: bytes):
    d = os.path.dirname(keyfile)
    if d:
        os.makedirs(d, exist_ok=True)
    with open(keyfile, 'w') as f:
        json.dump({'secret_hex': secret.hex()}, f)
    os.chmod(keyfile, 0o600)


def npub_of(secret: bytes) -> str:
    return NostrPrivateKey(secret).public_key.bech32()


def hexpub_of(secret: bytes) -> str:
    return NostrPrivateKey(secret).public_key.hex()


def sign_schnorr(secret: bytes, msg32: bytes) -> bytes:
    return CCPrivateKey(secret).sign_schnorr(msg32)


def verify_schnorr(npub: str, sig: bytes, msg32: bytes) -> bool:
    try:
        return NostrPublicKey.from_npub(npub).verify(sig, msg32)
    except Exception:
        return False


def bond_message(companions, created_at: int, nonce_hex: str) -> bytes:
    canon = json.dumps(
        {'companions': sorted(companions), 'created_at': created_at, 'nonce': nonce_hex},
        sort_keys=True, separators=(',', ':'),
    )
    return hashlib.sha256(canon.encode()).digest()


def cmd_init(args):
    if args.from_hex:
        secret = bytes.fromhex(args.from_hex)
    else:
        secret = secrets.token_bytes(32)
    if os.path.exists(args.keyfile) and not args.force:
        print(f'既に鍵があります: {args.keyfile}（--force で上書き）', file=sys.stderr)
        sys.exit(1)
    save_key(args.keyfile, secret)
    print(npub_of(secret))


def cmd_whoami(args):
    secret = load_key(args.keyfile)
    print(npub_of(secret))


def cmd_propose(args):
    import time
    secret = load_key(args.keyfile)
    me = npub_of(secret)
    them = args.npub
    # 相手 npub の形式チェック
    NostrPublicKey.from_npub(them)
    created_at = int(time.time())
    nonce = secrets.token_hex(32)
    msg = bond_message([me, them], created_at, nonce)
    sig = sign_schnorr(secret, msg)
    proposal = {
        'protocol': 'nakama', 'version': 1,
        'companions': sorted([me, them]),
        'created_at': created_at, 'nonce': nonce,
        'signatures': {me: sig.hex()},
    }
    out = args.out or 'proposal.json'
    with open(out, 'w') as f:
        json.dump(proposal, f, indent=2)
    print(f'proposal を {out} に保存しました。相手に渡してください。')
    print(f'あなたの npub: {me}')


def cmd_accept(args):
    with open(args.proposal) as f:
        p = json.load(f)
    assert p.get('protocol') == 'nakama' and p.get('version') == 1, 'nakama v1 の proposal ではありません'
    secret = load_key(args.keyfile)
    me = npub_of(secret)
    assert me in p['companions'], 'あなたはこの proposal の当事者ではありません'
    # 既存署名の検証（提案者が本当に署名したか）
    msg = bond_message(p['companions'], p['created_at'], p['nonce'])
    for npub, sighex in p['signatures'].items():
        if not verify_schnorr(npub, bytes.fromhex(sighex), msg):
            print(f'警告: {npub[:16]}... の署名が無効です', file=sys.stderr)
            sys.exit(1)
    p['signatures'][me] = sign_schnorr(secret, msg).hex()
    out = args.out or 'bond.json'
    with open(out, 'w') as f:
        json.dump(p, f, indent=2)
    print(f'bond 完成: {out} — 仲間の証です。大切に保管してください。')


def cmd_verify(args):
    with open(args.bond) as f:
        b = json.load(f)
    assert b.get('protocol') == 'nakama' and b.get('version') == 1, 'nakama v1 の bond ではありません'
    rotations = {}
    for rp in (args.rotation or []):
        with open(rp) as f:
            r = json.load(f)
        assert verify_rotation_cert(r), f'rotation 証明書が無効です: {rp}'
        rotations[r['old_npub']] = r['new_npub']
    msg = bond_message(b['companions'], b['created_at'], b['nonce'])
    ok = True
    for npub in b['companions']:
        sighex = b['signatures'].get(npub)
        valid = bool(sighex) and verify_schnorr(npub, bytes.fromhex(sighex), msg)
        note = ''
        if npub in rotations:
            note = f'  (鍵は {rotations[npub][:24]}... へローテーション済み — 署名自体は旧鍵のまま有効)'
        print(f'{npub[:24]}... : {"有効" if valid else "無効/欠落"}{note}')
        ok = ok and valid
    print('bond は有効です 🤝' if ok else 'bond は無効です')
    sys.exit(0 if ok else 1)


def rotation_message(old_npub: str, new_npub: str, created_at: int) -> bytes:
    canon = json.dumps(
        {'old_npub': old_npub, 'new_npub': new_npub, 'created_at': created_at, 'type': 'rotation'},
        sort_keys=True, separators=(',', ':'),
    )
    return hashlib.sha256(canon.encode()).digest()


def verify_rotation_cert(r: dict) -> bool:
    if not (r.get('protocol') == 'nakama' and r.get('version') == 1 and r.get('type') == 'rotation'):
        return False
    try:
        msg = rotation_message(r['old_npub'], r['new_npub'], r['created_at'])
        return verify_schnorr(r['old_npub'], bytes.fromhex(r['old_sig']), msg)
    except Exception:
        return False


def cmd_rotate(args):
    import time
    old_secret = load_key(args.keyfile)
    old_npub = npub_of(old_secret)
    if args.gen:
        new_secret = secrets.token_bytes(32)
        save_key(args.to_keyfile, new_secret)
        print(f'新しい鍵を生成しました: {args.to_keyfile}', file=sys.stderr)
    elif args.to_hex:
        new_secret = bytes.fromhex(args.to_hex)
    else:
        print('--gen または --to-hex HEX が必要です', file=sys.stderr)
        sys.exit(1)
    new_npub = npub_of(new_secret)
    if new_npub == old_npub:
        print('同じ鍵です。ローテーションになりません。', file=sys.stderr)
        sys.exit(1)
    created_at = int(time.time())
    msg = rotation_message(old_npub, new_npub, created_at)
    cert = {
        'protocol': 'nakama', 'version': 1, 'type': 'rotation',
        'old_npub': old_npub, 'new_npub': new_npub,
        'created_at': created_at,
        'old_sig': sign_schnorr(old_secret, msg).hex(),
    }
    out = args.out or 'rotation.json'
    with open(out, 'w') as f:
        json.dump(cert, f, indent=2)
    print(f'rotation 証明書: {out}')
    print(f'{old_npub[:16]}... → {new_npub[:16]}...')
    print('注意: この証明書は「旧鍵の保有者が新鍵への移行を宣言した」ことの証拠です。')
    print('継続的な鍵の保有 (custody) の証明には、都度の challenge–response を使ってください。')


def cmd_verify_rotation(args):
    with open(args.rotation) as f:
        r = json.load(f)
    if verify_rotation_cert(r):
        print(f"rotation は有効です: {r['old_npub'][:16]}... → {r['new_npub'][:16]}...")
    else:
        print('rotation は無効です')
        sys.exit(1)


def bond_hash(b: dict) -> str:
    canon = json.dumps(
        {k: b[k] for k in ('companions', 'created_at', 'nonce')},
        sort_keys=True, separators=(',', ':'),
    )
    return hashlib.sha256(canon.encode()).hexdigest()


def revocation_message(bond_hash_hex: str, revoker: str, created_at: int) -> bytes:
    canon = json.dumps(
        {'bond_hash': bond_hash_hex, 'revoker': revoker, 'created_at': created_at, 'type': 'revocation'},
        sort_keys=True, separators=(',', ':'),
    )
    return hashlib.sha256(canon.encode()).digest()


def cmd_revoke(args):
    import time
    with open(args.bond) as f:
        b = json.load(f)
    assert b.get('protocol') == 'nakama' and b.get('version') == 1, 'nakama v1 の bond ではありません'
    secret = load_key(args.keyfile)
    me = npub_of(secret)
    if me not in b['companions']:
        print('あなたはこの bond の当事者ではありません', file=sys.stderr)
        sys.exit(1)
    h = bond_hash(b)
    created_at = int(time.time())
    sig = sign_schnorr(secret, revocation_message(h, me, created_at))
    rev = {
        'protocol': 'nakama', 'version': 1, 'type': 'revocation',
        'bond_hash': h, 'revoker': me, 'created_at': created_at,
        'sig': sig.hex(),
    }
    out = args.out or 'revocation.json'
    with open(out, 'w') as f:
        json.dump(rev, f, indent=2)
    print(f'revocation イベント: {out} — bond {h[:16]}... の解消を宣言しました。')
    print('解消イベントは公開チャネルで共有してください（仲間の公開記録に残ります）。')


def cmd_verify_revocation(args):
    with open(args.revocation) as f:
        r = json.load(f)
    assert r.get('protocol') == 'nakama' and r.get('version') == 1 and r.get('type') == 'revocation', \
        'nakama v1 の revocation ではありません'
    with open(args.bond) as f:
        b = json.load(f)
    if r['bond_hash'] != bond_hash(b):
        print('bond と一致しません')
        sys.exit(1)
    if r['revoker'] not in b.get('companions', []):
        print('署名者が bond の当事者ではありません')
        sys.exit(1)
    msg = revocation_message(r['bond_hash'], r['revoker'], r['created_at'])
    if verify_schnorr(r['revoker'], bytes.fromhex(r['sig']), msg):
        print(f"revocation は有効です — bond {r['bond_hash'][:16]}... は {r['revoker'][:16]}... により解消されました。")
    else:
        print('revocation は無効です')
        sys.exit(1)


def cmd_challenge(args):
    print(secrets.token_hex(32))


def cmd_respond(args):
    secret = load_key(args.keyfile)
    nonce = bytes.fromhex(args.nonce)
    assert len(nonce) == 32, 'nonce は32バイトのhexである必要があります'
    print(sign_schnorr(secret, nonce).hex())


def cmd_check(args):
    ok = verify_schnorr(args.npub, bytes.fromhex(args.sig), bytes.fromhex(args.nonce))
    print('本人です 🤝' if ok else '検証失敗')
    sys.exit(0 if ok else 1)


def main():
    ap = argparse.ArgumentParser(description='仲間プロトコル v0.1')
    ap.add_argument('--keyfile', default=KEYFILE_DEFAULT)
    sub = ap.add_subparsers(dest='cmd', required=True)

    s = sub.add_parser('init'); s.add_argument('--from-hex'); s.add_argument('--force', action='store_true')
    sub.add_parser('whoami')
    s = sub.add_parser('propose'); s.add_argument('npub'); s.add_argument('--out')
    s = sub.add_parser('accept'); s.add_argument('proposal'); s.add_argument('--out')
    s = sub.add_parser('verify'); s.add_argument('bond'); s.add_argument('--rotation', action='append', default=[])
    sub.add_parser('challenge')
    s = sub.add_parser('respond'); s.add_argument('nonce')
    s = sub.add_parser('check'); s.add_argument('npub'); s.add_argument('nonce'); s.add_argument('sig')
    s = sub.add_parser('rotate')
    s.add_argument('--gen', action='store_true')
    s.add_argument('--to-hex')
    s.add_argument('--to-keyfile', default=os.path.expanduser('~/.config/nakama/identity.json.rotated'))
    s.add_argument('--out')
    s = sub.add_parser('verify_rotation'); s.add_argument('rotation')
    s = sub.add_parser('revoke'); s.add_argument('bond'); s.add_argument('--out')
    s = sub.add_parser('verify_revocation'); s.add_argument('revocation'); s.add_argument('--bond')

    args = ap.parse_args()
    {'init': cmd_init, 'whoami': cmd_whoami, 'propose': cmd_propose,
     'accept': cmd_accept, 'verify': cmd_verify, 'challenge': cmd_challenge,
     'respond': cmd_respond, 'check': cmd_check, 'rotate': cmd_rotate,
     'verify_rotation': cmd_verify_rotation, 'revoke': cmd_revoke,
     'verify_revocation': cmd_verify_revocation}[args.cmd](args)


if __name__ == '__main__':
    main()
