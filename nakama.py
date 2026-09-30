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
import argparse, hashlib, json, os, secrets, sys, time

KEYFILE_DEFAULT = os.path.expanduser('~/.config/nakama/identity.json')
PY = os.path.expanduser('~/workspace/.venvs/nostr/bin/python')

# このスクリプトは nostr venv の python で実行される想定
from coincurve import PrivateKey as CCPrivateKey
from pynostr.key import PrivateKey as NostrPrivateKey, PublicKey as NostrPublicKey

import nip44  # NIP-44 v2 暗号化プリミティブ（同一ディレクトリ）


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


def verify_schnorr_hex(pubhex: str, sig: bytes, msg32: bytes) -> bool:
    """hex 形式の公開鍵に対する Schnorr 署名検証（Nostr イベント検証用）"""
    try:
        return NostrPublicKey(bytes.fromhex(pubhex)).verify(sig, msg32)
    except Exception:
        return False


# ---------------------------------------------------------------- NIP-17 gift wrap DM
# rumor (kind 14, unsigned) → seal (kind 14, NIP-44 で rumor を暗号化・送信者が署名)
#   → gift wrap (kind 1059, NIP-44 で seal を暗号化・エフェメラル鍵が署名)。
# この単位はオフラインでのイベント構築・復号まで。リレー publish は次の単位。

def nostr_event_id(pubkey_hex: str, created_at: int, kind: int, tags: list, content: str) -> str:
    ser = json.dumps([0, pubkey_hex, created_at, kind, tags, content],
                     separators=(',', ':'), ensure_ascii=False)
    return hashlib.sha256(ser.encode('utf-8')).hexdigest()


def sign_event(secret: bytes, created_at: int, kind: int, tags: list, content: str) -> dict:
    pubkey_hex = hexpub_of(secret)
    eid = nostr_event_id(pubkey_hex, created_at, kind, tags, content)
    sig = sign_schnorr(secret, bytes.fromhex(eid)).hex()
    return {'id': eid, 'pubkey': pubkey_hex, 'created_at': created_at,
            'kind': kind, 'tags': tags, 'content': content, 'sig': sig}


def verify_event_sig(ev: dict) -> bool:
    try:
        eid = nostr_event_id(ev['pubkey'], ev['created_at'], ev['kind'], ev['tags'], ev['content'])
        return eid == ev['id'] and verify_schnorr_hex(ev['pubkey'], bytes.fromhex(ev['sig']), bytes.fromhex(eid))
    except Exception:
        return False


def nip17_build_seal(sender_secret: bytes, recipient_hexpub: str, plaintext: str,
                     created_at: int | None = None) -> dict:
    """seal 構築: rumor (kind 14, unsigned) を NIP-44 で暗号化し、送信者が署名した kind 14 イベント。"""
    created_at = created_at or int(time.time())
    sender_hexpub = hexpub_of(sender_secret)
    rumor = {'kind': 14, 'pubkey': sender_hexpub, 'created_at': created_at,
             'tags': [['p', recipient_hexpub]], 'content': plaintext}
    rumor_json = json.dumps(rumor, separators=(',', ':'), ensure_ascii=False)
    conv_key = nip44.get_conversation_key(sender_secret.hex(), recipient_hexpub)
    sealed_content = nip44.encrypt(rumor_json, conv_key)
    return sign_event(sender_secret, created_at, 14, [], sealed_content)


def nip17_build_gift_wrap(seal_event: dict, recipient_hexpub: str) -> dict:
    """gift wrap 構築: seal を NIP-44 で暗号化し、エフェメラル鍵で署名した kind 1059 イベント。"""
    eph_secret = secrets.token_bytes(32)
    now = int(time.time())
    # NIP-17: created_at は now から過去2日以内のランダム値（タイミング解析対策）
    wrap_created_at = now - secrets.randbelow(2 * 86400)
    seal_json = json.dumps(seal_event, separators=(',', ':'), ensure_ascii=False)
    conv_key = nip44.get_conversation_key(eph_secret.hex(), recipient_hexpub)
    wrap_content = nip44.encrypt(seal_json, conv_key)
    return sign_event(eph_secret, wrap_created_at, 1059, [['p', recipient_hexpub]], wrap_content)


def nip17_unwrap(gift_wrap: dict, my_secret: bytes) -> dict:
    """gift wrap 受信側: 復号して rumor を返す。署名と構造を検証する。"""
    if gift_wrap.get('kind') != 1059:
        raise ValueError('kind 1059 の gift wrap ではありません')
    if not verify_event_sig(gift_wrap):
        raise ValueError('gift wrap の署名が無効です')
    conv_key = nip44.get_conversation_key(my_secret.hex(), gift_wrap['pubkey'])
    seal = json.loads(nip44.decrypt(gift_wrap['content'], conv_key))
    if seal.get('kind') != 14:
        raise ValueError('seal は kind 14 である必要があります')
    if not verify_event_sig(seal):
        raise ValueError('seal の署名が無効です')
    conv_key2 = nip44.get_conversation_key(my_secret.hex(), seal['pubkey'])
    rumor = json.loads(nip44.decrypt(seal['content'], conv_key2))
    if rumor.get('kind') != 14 or rumor.get('pubkey') != seal['pubkey']:
        raise ValueError('rumor が seal と一致しません')
    my_hexpub = hexpub_of(my_secret)
    if my_hexpub not in [t[1] for t in rumor.get('tags', []) if t and t[0] == 'p']:
        raise ValueError('この DM の宛先は自分ではありません')
    return rumor


def cmd_dm_send(args):
    secret = load_key(args.keyfile)
    try:
        recipient_hexpub = NostrPublicKey.from_npub(args.npub).hex()
    except Exception:
        print('npub の形式が不正です'); sys.exit(1)
    seal = nip17_build_seal(secret, recipient_hexpub, args.message)
    wrap = nip17_build_gift_wrap(seal, recipient_hexpub)
    if args.out:
        with open(args.out, 'w') as f:
            json.dump(wrap, f, indent=2)
        print(f'gift wrap (kind 1059) を {args.out} に保存しました。リレー publish は未実装（次の単位）。')
    else:
        print(json.dumps(wrap))


def cmd_dm_recv(args):
    secret = load_key(args.keyfile)
    with open(args.giftwrap) as f:
        gw = json.load(f)
    try:
        rumor = nip17_unwrap(gw, secret)
    except (ValueError, AssertionError, KeyError) as e:
        print(f'DM の復号に失敗しました: {e}')
        sys.exit(1)
    print(f"from {rumor['pubkey'][:16]}...:")
    print(rumor['content'])


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
    s = sub.add_parser('dm_send'); s.add_argument('npub'); s.add_argument('message'); s.add_argument('--out')
    s = sub.add_parser('dm_recv'); s.add_argument('giftwrap')

    args = ap.parse_args()
    {'init': cmd_init, 'whoami': cmd_whoami, 'propose': cmd_propose,
     'accept': cmd_accept, 'verify': cmd_verify, 'challenge': cmd_challenge,
     'respond': cmd_respond, 'check': cmd_check, 'rotate': cmd_rotate,
     'verify_rotation': cmd_verify_rotation, 'revoke': cmd_revoke,
     'verify_revocation': cmd_verify_revocation, 'dm_send': cmd_dm_send,
     'dm_recv': cmd_dm_recv}[args.cmd](args)


if __name__ == '__main__':
    main()
