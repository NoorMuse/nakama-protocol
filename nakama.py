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
  nakama.py dm_send <相手npub> <メッセージ> [--out FILE]  gift wrap (kind 1059) を構築
  nakama.py dm_recv <giftwrap.json>                    gift wrap を復号して rumor を表示
  nakama.py dm_pub <relay> [--in FILE|--to-npub NPUB --message MSG]  gift wrap をリレーに publish
  nakama.py dm_fetch <relay> [--since TS] [--limit N]  自分宛 gift wrap を購読・復号
  nakama.py board_create <relay> --name "広場名" [--about 説明] [--admission open|approval] [--out FILE]  NIP-29 広場を作る（kind 9002 + 34550 を publish、descriptor を出力）
  nakama.py board_verify <descriptor.json>        board descriptor の署名を検証
  nakama.py board_join <relay> <board_id>         広場に参加申請（kind 9007 を publish）
  nakama.py board_send <relay> <board_id> "MSG"   広場に投稿（kind 9 平文を publish）
  nakama.py board_read <relay> <board_id> [--since TS] [--limit N]  広場の投稿を購読・表示
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


def nostr_relay_ws(url: str, timeout: int = 15):
    """Nostr リレーへの websocket 接続（websocket-client を使用、遅延 import）。"""
    try:
        from websocket import create_connection
    except ImportError:
        print('websocket-client が必要です: pip install websocket-client'); sys.exit(1)
    try:
        return create_connection(url, timeout=timeout)
    except Exception as e:
        print(f'リレー {url} への接続に失敗しました: {e}'); sys.exit(1)


def nip42_auth_event(secret: bytes, relay_url: str, challenge: str) -> dict:
    """NIP-42 認証イベント (kind 22242) を構築・署名する。"""
    return sign_event(secret, int(time.time()), 22242,
                      [['relay', relay_url], ['challenge', challenge]], '')


def nostr_maybe_auth(ws, url: str, secret: bytes | None, wait: float = 1.5) -> bool:
    """接続直後の ["AUTH", challenge] を拾い、認証イベントで応答する (NIP-42)。
    応答したら OK を待って True、不要・失敗なら False。"""
    if secret is None:
        return False
    ws.settimeout(wait)
    deadline = time.time() + wait
    try:
        while time.time() < deadline:
            try:
                msg = json.loads(ws.recv())
            except Exception:
                return False
            if isinstance(msg, list) and msg and msg[0] == 'AUTH' and len(msg) > 1:
                ev = nip42_auth_event(secret, url, str(msg[1]))
                ws.send(json.dumps(['AUTH', ev]))
                ws.settimeout(5)
                try:
                    while True:
                        m2 = json.loads(ws.recv())
                        if isinstance(m2, list) and m2 and m2[0] == 'OK' and len(m2) > 1 \
                                and m2[1] == ev['id']:
                            return bool(m2[2])
                        if isinstance(m2, list) and m2 and m2[0] == 'NOTICE':
                            return False
                except Exception:
                    return False
            # AUTH 以外は読み捨て（後段の REQ/EVENT フローが再送する）
    except Exception:
        return False
    return False


def nostr_request(url: str, request: list, timeout: int = 15, auth_secret: bytes | None = None) -> list:
    """REQ を投げ、EOSE までイベントを収集して返す（短い余裕時間つき）。"""
    ws = nostr_relay_ws(url, timeout)
    try:
        nostr_maybe_auth(ws, url, auth_secret)
        ws.send(json.dumps(request))
        events, eose = [], False
        deadline = time.time() + timeout
        while time.time() < deadline:
            try:
                msg = json.loads(ws.recv())
            except Exception:
                break
            if not isinstance(msg, list) or len(msg) < 2:
                continue
            kind = msg[0]
            if kind == 'EVENT':
                events.append(msg[2] if len(msg) > 2 else msg[-1])
            elif kind == 'EOSE':
                eose = True
                break
            elif kind == 'AUTH' and auth_secret is not None and len(msg) > 1:
                # リレーが購読途中で認証を要求した場合: 応答して REQ を再送
                ev = nip42_auth_event(auth_secret, url, str(msg[1]))
                ws.send(json.dumps(['AUTH', ev]))
                ws.send(json.dumps(request))
            elif kind == 'CLOSED':
                break
        # EOSE 後の余裕: 直前に届いた EVENT を拾い漏らさないよう少し待つ
        ws.settimeout(2)
        try:
            while True:
                msg = json.loads(ws.recv())
                if isinstance(msg, list) and msg and msg[0] == 'EVENT':
                    events.append(msg[2] if len(msg) > 2 else msg[-1])
        except Exception:
            pass
        ws.send(json.dumps(['CLOSE', request[1]]))
        return events
    finally:
        ws.close()


def cmd_dm_pub(args):
    """gift wrap を Nostr リレーに publish: ["EVENT", <event>] → ["OK", id, ok, msg]。"""
    secret = load_key(args.keyfile)
    if args.in_file:
        with open(args.in_file) as f:
            wrap = json.load(f)
    else:
        if not args.to_npub or not args.message:
            print('--in か (--to-npub + --message) のどちらかが必要です'); sys.exit(1)
        try:
            recipient_hexpub = NostrPublicKey.from_npub(args.to_npub).hex()
        except Exception:
            print('npub の形式が不正です'); sys.exit(1)
        seal = nip17_build_seal(secret, recipient_hexpub, args.message)
        wrap = nip17_build_gift_wrap(seal, recipient_hexpub)
    accepted, reason = nostr_publish(args.relay, wrap, auth_secret=secret if args.auth else None)
    print(f'publish: {"受理" if accepted else "拒否"} ({reason}) id={wrap["id"]}')
    sys.exit(0 if accepted else 1)


def cmd_dm_fetch(args):
    """自分宛の gift wrap (kind 1059, #p 自分) を購読し、復号して rumor を表示。"""
    secret = load_key(args.keyfile)
    my_hexpub = hexpub_of(secret)
    filt = {'kinds': [1059], '#p': [my_hexpub], 'limit': args.limit}
    if args.since:
        filt['since'] = args.since
    sub_id = secrets.token_hex(8)
    events = nostr_request(args.relay, ['REQ', sub_id, filt], auth_secret=secret if args.auth else None)
    shown = 0
    for ev in sorted(events, key=lambda e: e.get('created_at', 0)):
        try:
            rumor = nip17_unwrap(ev, secret)
        except (ValueError, AssertionError, KeyError):
            continue  # 自分向けに復号できない gift wrap は無視
        shown += 1
        ts = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(rumor.get('created_at', 0)))
        print(f"--- [{ts}] from {rumor['pubkey'][:16]}...")
        print(rumor['content'])
    if not shown:
        print('新しい DM はありませんでした')


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


# ---------------------------------------------------------------- NIP-29 group boards
# 広場（board）はリレーベースのグループ: kind 9002（Create Group）+ kind 34550（メタデータ）、
# kind 9（チャット投稿、h タグでグループ指定）、kind 9007（参加申請）。投稿は平文（§4.2 の選択）。

def nostr_publish(url: str, event: dict, timeout: int = 15, auth_secret: bytes | None = None) -> tuple:
    """単一イベントをリレーに publish し (accepted, reason) を返す。"""
    ws = nostr_relay_ws(url, timeout)
    try:
        nostr_maybe_auth(ws, url, auth_secret)
        ws.send(json.dumps(['EVENT', event]))
        ws.settimeout(timeout)
        deadline = time.time() + timeout
        while time.time() < deadline:
            try:
                msg = json.loads(ws.recv())
            except Exception:
                break
            if isinstance(msg, list) and msg and msg[0] == 'OK' and len(msg) > 1 and msg[1] == event['id']:
                return (bool(msg[2]), msg[3] if len(msg) > 3 else '')
            if isinstance(msg, list) and msg and msg[0] == 'AUTH' and auth_secret is not None and len(msg) > 1:
                # publish 時に認証を要求された場合: 応答して EVENT を再送
                ev = nip42_auth_event(auth_secret, url, str(msg[1]))
                ws.send(json.dumps(['AUTH', ev]))
                ws.send(json.dumps(['EVENT', event]))
                continue
            if isinstance(msg, list) and msg and msg[0] in ('NOTICE', 'CLOSED'):
                return (False, ' '.join(str(x) for x in msg[1:]))
    finally:
        ws.close()
    return (False, 'リレーからの OK 応答がありませんでした')


def board_descriptor_message(board_id: str, relay: str, moderators: list, created_at: int) -> bytes:
    """board descriptor の署名対象: (board_id, relay, moderators, created_at) の canonical hash。"""
    canon = json.dumps([board_id, relay, sorted(moderators), created_at],
                       separators=(',', ':'), ensure_ascii=False)
    return hashlib.sha256(canon.encode('utf-8')).digest()


def cmd_board_create(args):
    """広場を作る: kind 9002 + kind 34550 を publish し、board descriptor を出力する。"""
    secret = load_key(args.keyfile)
    my_npub = npub_of(secret)
    board_id = 'nakama-' + secrets.token_hex(3)
    created_at = int(time.time())
    ev_create = sign_event(secret, created_at, 9002, [['h', board_id]], '')
    meta = {'name': args.name, 'about': args.about or '', 'picture': ''}
    ev_meta = sign_event(secret, created_at, 34550, [['d', board_id]],
                         json.dumps(meta, ensure_ascii=False, separators=(',', ':')))
    for label, ev in (('9002', ev_create), ('34550', ev_meta)):
        accepted, reason = nostr_publish(args.relay, ev, auth_secret=secret if args.auth else None)
        print(f'kind {label}: {"受理" if accepted else "拒否"} ({reason})')
        if not accepted:
            sys.exit(1)
    moderators = [my_npub]
    msg = board_descriptor_message(board_id, args.relay, moderators, created_at)
    descriptor = {
        'protocol': 'nakama', 'version': 1, 'type': 'board',
        'board_id': board_id, 'relay': args.relay,
        'moderators': moderators, 'admission': args.admission,
        'created_at': created_at,
        'sig': sign_schnorr(secret, msg).hex(),
    }
    if args.out:
        with open(args.out, 'w') as f:
            json.dump(descriptor, f, indent=2, ensure_ascii=False)
        print(f'descriptor を {args.out} に保存しました')
    else:
        print(json.dumps(descriptor, indent=2, ensure_ascii=False))
    print(f'広場 "{args.name}" を作りました: board_id={board_id}')


def cmd_board_verify(args):
    """board descriptor の署名を検証する。"""
    with open(args.descriptor) as f:
        d = json.load(f)
    try:
        msg = board_descriptor_message(d['board_id'], d['relay'], d['moderators'], d['created_at'])
        ok = bool(d['moderators']) and verify_schnorr(d['moderators'][0], bytes.fromhex(d['sig']), msg)
    except (KeyError, ValueError, TypeError):
        ok = False
    print('board descriptor は有効です' if ok else 'board descriptor は無効です')
    sys.exit(0 if ok else 1)


def cmd_board_join(args):
    """広場に参加申請: kind 9007 を publish。"""
    secret = load_key(args.keyfile)
    ev = sign_event(secret, int(time.time()), 9007, [['h', args.board_id]], '')
    accepted, reason = nostr_publish(args.relay, ev, auth_secret=secret if args.auth else None)
    print(f'参加申請: {"受理" if accepted else "拒否"} ({reason}) id={ev["id"]}')
    sys.exit(0 if accepted else 1)


def cmd_board_send(args):
    """広場に投稿: kind 9（平文、投稿者署名が発言の証）を publish。"""
    secret = load_key(args.keyfile)
    ev = sign_event(secret, int(time.time()), 9, [['h', args.board_id]], args.message)
    accepted, reason = nostr_publish(args.relay, ev, auth_secret=secret if args.auth else None)
    print(f'投稿: {"受理" if accepted else "拒否"} ({reason}) id={ev["id"]}')
    sys.exit(0 if accepted else 1)


def cmd_board_read(args):
    """広場の投稿を購読・表示: kind 9 + #h フィルタ。署名の無効なイベントは無視する。"""
    sub_id = secrets.token_hex(8)
    filt = {'kinds': [9], '#h': [args.board_id], 'limit': args.limit}
    if args.since:
        filt['since'] = args.since
    auth_secret = load_key(args.keyfile) if args.auth else None
    events = nostr_request(args.relay, ['REQ', sub_id, filt], auth_secret=auth_secret)
    shown = 0
    for ev in sorted(events, key=lambda e: e.get('created_at', 0)):
        if not verify_event_sig(ev):
            continue
        shown += 1
        ts = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(ev.get('created_at', 0)))
        print(f"--- [{ts}] {ev['pubkey'][:16]}...")
        print(ev['content'])
    if not shown:
        print('投稿はまだありません')


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
    s = sub.add_parser('dm_pub'); s.add_argument('relay'); s.add_argument('--in', dest='in_file')
    s.add_argument('--to-npub'); s.add_argument('--message')
    s.add_argument('--auth', action='store_true', help='NIP-42 認証を使う (keyfile の鍵で署名)')
    s = sub.add_parser('dm_fetch'); s.add_argument('relay'); s.add_argument('--since', type=int)
    s.add_argument('--limit', type=int, default=20)
    s.add_argument('--auth', action='store_true', help='NIP-42 認証を使う (keyfile の鍵で署名)')
    s = sub.add_parser('board_create'); s.add_argument('relay'); s.add_argument('--name', default='仲間の広場')
    s.add_argument('--about', default=''); s.add_argument('--admission', choices=['open', 'approval'], default='approval')
    s.add_argument('--out')
    s.add_argument('--auth', action='store_true', help='NIP-42 認証を使う (keyfile の鍵で署名)')
    s = sub.add_parser('board_verify'); s.add_argument('descriptor')
    s = sub.add_parser('board_join'); s.add_argument('relay'); s.add_argument('board_id')
    s.add_argument('--auth', action='store_true', help='NIP-42 認証を使う (keyfile の鍵で署名)')
    s = sub.add_parser('board_send'); s.add_argument('relay'); s.add_argument('board_id'); s.add_argument('message')
    s.add_argument('--auth', action='store_true', help='NIP-42 認証を使う (keyfile の鍵で署名)')
    s = sub.add_parser('board_read'); s.add_argument('relay'); s.add_argument('board_id')
    s.add_argument('--since', type=int); s.add_argument('--limit', type=int, default=20)
    s.add_argument('--auth', action='store_true', help='NIP-42 認証を使う (keyfile の鍵で署名)')

    args = ap.parse_args()
    {'init': cmd_init, 'whoami': cmd_whoami, 'propose': cmd_propose,
     'accept': cmd_accept, 'verify': cmd_verify, 'challenge': cmd_challenge,
     'respond': cmd_respond, 'check': cmd_check, 'rotate': cmd_rotate,
     'verify_rotation': cmd_verify_rotation, 'revoke': cmd_revoke,
     'verify_revocation': cmd_verify_revocation, 'dm_send': cmd_dm_send,
     'dm_recv': cmd_dm_recv, 'dm_pub': cmd_dm_pub,
     'dm_fetch': cmd_dm_fetch, 'board_create': cmd_board_create,
     'board_verify': cmd_board_verify, 'board_join': cmd_board_join,
     'board_send': cmd_board_send, 'board_read': cmd_board_read}[args.cmd](args)


if __name__ == '__main__':
    main()
