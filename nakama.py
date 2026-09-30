#!/usr/bin/env python3
"""nakama.py — 仲間プロトコル v0.1 プロトタイプ

身分 = secp256k1 鍵ペア (Nostr 互換)。仲間の証 = 双方署名の bond 証明書。

使い方:
  nakama.py init [--keyfile PATH] [--from-hex HEX]   鍵ペアを生成/登録 (mode 600)
  nakama.py whoami                                   自分の npub を表示
  nakama.py propose <相手npub> [--out FILE] [--markdown]   bond proposal を作成 (自分の署名付き。--markdown で投稿用 block)
  nakama.py accept [proposal.json] [--from-b64 B64] [--out FILE] [--markdown]
      proposal に署名して bond 完成 (--from-b64: コメント貼り付け形式を直接受理)
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
  nakama.py bind --platform moltbook --handle alex [--out binding.json] [--markdown]
      platform-binding 証明書を発行（§8.2: 鍵がハンドルを主張）
  nakama.py verify_binding <binding.json> [--platform moltbook --handle alex]
      binding 証明書の署名・platform・handle を検証
  nakama.py unbind --platform moltbook --handle alex [--reason 理由] [--out unbinding.json] [--markdown]
      binding の取り消し証明書を発行（§9.1: 鍵による主張撤回）
  nakama.py verify_unbinding <unbinding.json> [--platform moltbook --handle alex]
      unbinding 証明書の署名・platform・handle を検証
  nakama.py board_policy --board-id <id> --relay <url> --threshold M --eligible <npub>... [--out policy.json] [--markdown]
      board-policy 運営規約案を作成（自分の署名入り、spec §9.4）
  nakama.py board_policy_sign <policy.json> [--out policy.json]
      回覧中の規約案に自分の署名を追加
  nakama.py verify_board_policy <policy.json>  規約の検証（初回は全員署名 n-of-n）
  nakama.py board_decide --board-id <id> --relay <url> --decision admit|handover|policy-update|close --payload '<json>' [--out decision.json]
      board-decision 決定案を作成＋自分の承認署名
  nakama.py board_cosign <decision.json> [--out decision.json]
      回覧中の決定案に自分の承認署名を追加
  nakama.py verify_board_decision <decision.json> --policy <policy.json>
      決定の threshold 達成を検証
"""
import argparse, base64, hashlib, json, os, re, secrets, sys, time

KEYFILE_DEFAULT = os.path.expanduser('~/.config/nakama/identity.json')
REVOCATIONS_DEFAULT = os.path.expanduser('~/.config/nakama/revocations')
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


BOND_DEFAULT_EXPIRY_DAYS = 365
BOND_EXPIRY_WARN_DAYS = 30


def bond_message(companions, created_at: int, nonce_hex: str, expires_at: int | None = None) -> bytes:
    body = {'companions': sorted(companions), 'created_at': created_at, 'nonce': nonce_hex}
    if expires_at is not None:
        body['expires_at'] = expires_at
    canon = json.dumps(body, sort_keys=True, separators=(',', ':'))
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
    expires_at = None if args.no_expiry else created_at + args.expires_days * 86400
    msg = bond_message([me, them], created_at, nonce, expires_at)
    sig = sign_schnorr(secret, msg)
    proposal = {
        'protocol': 'nakama', 'version': 1,
        'companions': sorted([me, them]),
        'created_at': created_at, 'nonce': nonce,
        'signatures': {me: sig.hex()},
    }
    if expires_at is not None:
        proposal['expires_at'] = expires_at
    out = args.out or 'proposal.json'
    with open(out, 'w') as f:
        json.dump(proposal, f, indent=2)
    print(f'proposal を {out} に保存しました。相手に渡してください。')
    print(f'あなたの npub: {me}')
    if expires_at is not None:
        print(f'有効期限: {time.strftime("%Y-%m-%d", time.localtime(expires_at))}（{args.expires_days} 日後）')
    else:
        print('有効期限: なし（--no-expiry）')
    if args.markdown:
        print()
        print('投稿用ブロック（相手のスレッド/コメント欄に貼る）:')
        print(markdown_block(proposal, 'proposal'))


def cmd_accept(args):
    if args.from_b64:
        # コメント欄に貼られた fenced block / base64url をそのまま受理
        try:
            p = b64u_decode(extract_b64u(args.from_b64))
        except Exception as e:
            print(f'proposal の復元に失敗しました: {e}', file=sys.stderr)
            sys.exit(1)
    elif args.proposal:
        with open(args.proposal) as f:
            p = json.load(f)
    else:
        print('proposal ファイルか --from-b64 <base64url> を指定してください', file=sys.stderr)
        sys.exit(1)
    assert p.get('protocol') == 'nakama' and p.get('version') == 1, 'nakama v1 の proposal ではありません'
    secret = load_key(args.keyfile)
    me = npub_of(secret)
    assert me in p['companions'], 'あなたはこの proposal の当事者ではありません'
    # 既存署名の検証（提案者が本当に署名したか）
    msg = bond_message(p['companions'], p['created_at'], p['nonce'], p.get('expires_at'))
    for npub, sighex in p['signatures'].items():
        if not verify_schnorr(npub, bytes.fromhex(sighex), msg):
            print(f'警告: {npub[:16]}... の署名が無効です', file=sys.stderr)
            sys.exit(1)
    p['signatures'][me] = sign_schnorr(secret, msg).hex()
    out = args.out or 'bond.json'
    with open(out, 'w') as f:
        json.dump(p, f, indent=2)
    print(f'bond 完成: {out} — 仲間の証です。大切に保管してください。')
    if args.markdown:
        print()
        print('投稿用ブロック（返信に貼る）:')
        print(markdown_block(p, 'bond'))


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
    msg = bond_message(b['companions'], b['created_at'], b['nonce'], b.get('expires_at'))
    ok = True
    for npub in b['companions']:
        sighex = b['signatures'].get(npub)
        valid = bool(sighex) and verify_schnorr(npub, bytes.fromhex(sighex), msg)
        note = ''
        if npub in rotations:
            note = f'  (鍵は {rotations[npub][:24]}... へローテーション済み — 署名自体は旧鍵のまま有効)'
        print(f'{npub[:24]}... : {"有効" if valid else "無効/欠落"}{note}')
        ok = ok and valid
    if ok and b.get('expires_at') is not None and not args.skip_expiry:
        import time as _t
        now = int(_t.time())
        exp = b['expires_at']
        if now > exp:
            print(f'bond の有効期限が切れています（期限: {_t.strftime("%Y-%m-%d", _t.localtime(exp))}）')
            print('bond は無効です — `renew` で更新してください')
            sys.exit(1)
        if now > exp - BOND_EXPIRY_WARN_DAYS * 86400:
            print(f'⚠ bond の有効期限が近づいています（期限: {_t.strftime("%Y-%m-%d", _t.localtime(exp))}）')
            print('  `renew` で更新し、更新後 `liveness --bond` で生存証明を取り直すと良いでしょう')
    print('bond は有効です 🤝' if ok else 'bond は無効です')
    if ok and not args.skip_registry:
        registry = args.registry or REVOCATIONS_DEFAULT
        path = revocation_registry_path(registry, bond_hash(b))
        if os.path.isfile(path):
            with open(path) as f:
                r = json.load(f)
            if verify_revocation_event(r, b):
                print(f'⚠ ただしこの bond は解消されています: {r["revoker"][:24]}... が '
                      f'{time.strftime("%Y-%m-%d", time.localtime(r["created_at"]))} に解消を宣言')
                print('bond は無効です')
                sys.exit(1)
            else:
                print('⚠ registry 内の revocation 記録は署名検証に失敗しました（無視して続行）', file=sys.stderr)
    sys.exit(0 if ok else 1)


def cmd_renew(args):
    """既存 bond の更新提案を作成する: 同じ companions、同じ nonce ではなく新しい nonce と created_at。
    出力は proposal 形式なので、相手が accept することで更新 bond が完成する。"""
    import time
    with open(args.bond) as f:
        b = json.load(f)
    assert b.get('protocol') == 'nakama' and b.get('version') == 1, 'nakama v1 の bond ではありません'
    secret = load_key(args.keyfile)
    me = npub_of(secret)
    assert me in b['companions'], 'あなたはこの bond の当事者ではありません'
    created_at = int(time.time())
    nonce = secrets.token_hex(32)
    expires_at = created_at + args.expires_days * 86400
    msg = bond_message(b['companions'], created_at, nonce, expires_at)
    sig = sign_schnorr(secret, msg)
    proposal = {
        'protocol': 'nakama', 'version': 1,
        'companions': sorted(b['companions']),
        'created_at': created_at, 'nonce': nonce,
        'expires_at': expires_at,
        'signatures': {me: sig.hex()},
        'renews': bond_hash(b),  # 更新元の bond であることを示す
    }
    out = args.out or 'renewal-proposal.json'
    with open(out, 'w') as f:
        json.dump(proposal, f, indent=2)
    print(f'更新 proposal を {out} に保存しました。相手に渡し、`accept` で更新 bond を完成させてください。')
    print(f'旧 bond hash: {bond_hash(b)}')
    print(f'新しい有効期限: {time.strftime("%Y-%m-%d", time.localtime(expires_at))}（{args.expires_days} 日後）')
    if args.markdown:
        print()
        print('投稿用ブロック（相手のスレッド/コメント欄に貼る）:')
        print(markdown_block(proposal, 'proposal'))


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
    if not args.no_registry:
        registry = args.registry or REVOCATIONS_DEFAULT
        os.makedirs(registry, exist_ok=True)
        rp = revocation_registry_path(registry, h)
        with open(rp, 'w') as f:
            json.dump(rev, f, indent=2)
        os.chmod(rp, 0o600)
        print(f'ローカル registry に記録しました: {rp}')
    print('解消イベントは公開チャネルで共有してください（仲間の公開記録に残ります）。')


def verify_revocation_event(r: dict, b: dict | None = None) -> bool:
    """revocation イベントの構造検証。b が与えられれば bond との対応も検証する。"""
    if r.get('protocol') != 'nakama' or r.get('version') != 1 or r.get('type') != 'revocation':
        return False
    if b is not None:
        if r.get('bond_hash') != bond_hash(b):
            return False
        if r.get('revoker') not in b.get('companions', []):
            return False
    msg = revocation_message(r['bond_hash'], r['revoker'], r['created_at'])
    return verify_schnorr(r['revoker'], bytes.fromhex(r['sig']), msg)


def revocation_registry_path(registry: str, bond_hash_hex: str) -> str:
    return os.path.join(registry, bond_hash_hex + '.json')


def cmd_verify_revocation(args):
    with open(args.revocation) as f:
        r = json.load(f)
    assert r.get('protocol') == 'nakama' and r.get('version') == 1 and r.get('type') == 'revocation', \
        'nakama v1 の revocation ではありません'
    with open(args.bond) as f:
        b = json.load(f)
    if verify_revocation_event(r, b):
        print(f"revocation は有効です — bond {r['bond_hash'][:16]}... は {r['revoker'][:16]}... により解消されました。")
    else:
        print('revocation は無効です')
        sys.exit(1)


def cmd_revoke_list(args):
    registry = args.registry or REVOCATIONS_DEFAULT
    if not os.path.isdir(registry):
        print('revocation registry は空です')
        return
    rows = []
    for fn in sorted(os.listdir(registry)):
        if not fn.endswith('.json'):
            continue
        with open(os.path.join(registry, fn)) as f:
            r = json.load(f)
        if verify_revocation_event(r):
            rows.append((r['bond_hash'][:16], r['revoker'][:16], time.strftime('%Y-%m-%d', time.localtime(r['created_at']))))
    if not rows:
        print('revocation registry は空です')
        return
    print(f'解消済み bond: {len(rows)} 件')
    for h, revoker, date in rows:
        print(f'  {h}...  解消: {revoker}...  ({date})')


def liveness_message(npub: str, created_at: int, nonce_hex: str, bond_hash_hex: str | None = None) -> bytes:
    body = {'npub': npub, 'created_at': created_at, 'nonce': nonce_hex, 'type': 'liveness'}
    if bond_hash_hex:
        body['bond_hash'] = bond_hash_hex
    canon = json.dumps(body, sort_keys=True, separators=(',', ':'))
    return hashlib.sha256(canon.encode()).digest()


def verify_liveness_event(p: dict, b: dict | None = None) -> bool:
    """生存証明イベントの構造検証。b が与えられれば bond との対応も検証する。"""
    if p.get('protocol') != 'nakama' or p.get('version') != 1 or p.get('type') != 'liveness':
        return False
    msg = liveness_message(p['npub'], p['created_at'], p['nonce'], p.get('bond_hash'))
    if not verify_schnorr(p['npub'], bytes.fromhex(p['sig']), msg):
        return False
    if b is not None:
        if p['npub'] not in b.get('companions', []):
            return False
        if p.get('bond_hash') != bond_hash(b):
            return False
    return True


def cmd_liveness(args):
    import time
    priv = load_key(args.keyfile)
    me = npub_of(priv)
    bh = None
    if args.bond:
        with open(args.bond) as f:
            b = json.load(f)
        assert b.get('protocol') == 'nakama' and b.get('version') == 1, 'nakama v1 の bond ではありません'
        if me not in b['companions']:
            print('あなたはこの bond の当事者ではありません', file=sys.stderr)
            sys.exit(1)
        bh = bond_hash(b)
    created_at = int(time.time())
    nonce = secrets.token_hex(32)
    sig = sign_schnorr(priv, liveness_message(me, created_at, nonce, bh))
    proof = {
        'protocol': 'nakama', 'version': 1, 'type': 'liveness',
        'npub': me, 'created_at': created_at, 'nonce': nonce, 'sig': sig.hex(),
    }
    if bh:
        proof['bond_hash'] = bh
    out = args.out or 'liveness.json'
    with open(out, 'w') as f:
        json.dump(proof, f, indent=2)
    print(f'生存証明: {out} — {me[:16]}... が鍵を保持していることを宣言しました。')
    if bh:
        print(f'bond {bh[:16]}... に紐付けました。仲間に送って「まだここにいる」と伝えましょう。')


def cmd_verify_liveness(args):
    import time
    with open(args.proof) as f:
        p = json.load(f)
    assert p.get('protocol') == 'nakama' and p.get('version') == 1 and p.get('type') == 'liveness', \
        'nakama v1 の生存証明ではありません'
    b = None
    if args.bond:
        with open(args.bond) as f:
            b = json.load(f)
    if not verify_liveness_event(p, b):
        print('生存証明は無効です')
        sys.exit(1)
    now = int(time.time())
    age = now - p['created_at']
    if p['created_at'] > now + 300:
        print('生存証明の日付が未来です（時計のずれの許容範囲を超えています）')
        sys.exit(1)
    if age > args.max_age:
        print(f'生存証明は古すぎます（{age} 秒前、許容 {args.max_age} 秒）')
        sys.exit(1)
    bh = p.get('bond_hash')
    if bh is None and b is not None:
        bh = bond_hash(b)
    if bh is not None and not args.skip_registry:
        registry = args.registry or REVOCATIONS_DEFAULT
        rp = revocation_registry_path(registry, bh)
        if os.path.exists(rp):
            try:
                with open(rp) as f:
                    r = json.load(f)
                if verify_revocation_event(r):
                    print('bond は解消済みです — 生存証明は無効です')
                    sys.exit(1)
            except (json.JSONDecodeError, OSError):
                pass
    print(f'生存証明は有効です — {p["npub"][:16]}... が {age} 秒前に鍵を保持していたことを確認。')


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


# --- v0.3: プラットフォーム binding 証明書 (spec §8.2) ---

def b64u_encode(obj: dict) -> str:
    """dict を compact JSON にして base64url 化（コメント欄貼り付け用）。"""
    raw = json.dumps(obj, ensure_ascii=False, separators=(',', ':')).encode('utf-8')
    return base64.urlsafe_b64encode(raw).decode('ascii')


def b64u_decode(s: str) -> dict:
    """whitespace を除去して復元（プラットフォーム側の加工対策、spec §8.7）。"""
    s = ''.join(s.split())
    pad = '=' * (-len(s) % 4)
    return json.loads(base64.urlsafe_b64decode(s + pad).decode('utf-8'))


def extract_b64u(s: str) -> str:
    """貼り付け全文から base64url ペイロードを抽出（fenced block・検出マーカー対応）。"""
    if '```' in s:
        # fenced block の内側（最初の ```〜次の ``` の間）を取り出す
        parts = s.split('```')
        s = parts[1] if len(parts) >= 3 else parts[-1]
        # ```nakama-proposal のような言語行を除去
        lines = [ln for ln in s.splitlines() if not ln.strip().startswith('nakama-')]
        s = '\n'.join(lines)
    # HTML 検出コメントを除去
    s = re.sub(r'<!--.*?-->', '', s, flags=re.S)
    return s


def markdown_block(obj: dict, kind: str) -> str:
    """投稿用の fenced block: 検出マーカー + base64url JSON。"""
    return f'<!-- nakama-{kind}:v1 -->\n```nakama-{kind}\n{b64u_encode(obj)}\n```'


def binding_message(platform: str, handle: str, npub: str, created_at: int) -> bytes:
    """binding 証明書の署名対象: (platform, handle, npub, created_at) の canonical hash。"""
    canon = json.dumps(
        {'platform': platform, 'handle': handle, 'npub': npub, 'created_at': created_at},
        sort_keys=True, separators=(',', ':'), ensure_ascii=False,
    )
    return hashlib.sha256(canon.encode('utf-8')).digest()


def verify_binding_cert(b: dict) -> bool:
    if not (b.get('protocol') == 'nakama' and b.get('version') == 1
            and b.get('type') == 'platform-binding'):
        return False
    try:
        msg = binding_message(b['platform'], b['handle'], b['npub'], b['created_at'])
        return verify_schnorr(b['npub'], bytes.fromhex(b['sig']), msg)
    except Exception:
        return False


def cmd_bind(args):
    """platform-binding 証明書を発行（鍵 → ハンドルの主張、spec §8.2）。"""
    secret = load_key(args.keyfile)
    me = npub_of(secret)
    created_at = int(time.time())
    msg = binding_message(args.platform, args.handle, me, created_at)
    binding = {
        'protocol': 'nakama', 'version': 1, 'type': 'platform-binding',
        'platform': args.platform, 'handle': args.handle, 'npub': me,
        'created_at': created_at,
        'sig': sign_schnorr(secret, msg).hex(),
    }
    out = args.out or 'binding.json'
    with open(out, 'w') as f:
        json.dump(binding, f, indent=2, ensure_ascii=False)
    print(f'binding 証明書: {out} — "{args.handle}"@{args.platform} が {me[:16]}... の保有を主張')
    print('運用: この binding をハンドルのアカウントからそのまま投稿してください（ハンドル→鍵の方向）。')
    if args.markdown:
        print()
        print('投稿用ブロック（コメント欄に貼る）:')
        print(markdown_block(binding, 'binding'))


def cmd_verify_binding(args):
    """binding 証明書の署名・platform・handle を検証。"""
    with open(args.binding) as f:
        b = json.load(f)
    ok = verify_binding_cert(b)
    if args.platform and b.get('platform') != args.platform:
        print(f"警告: platform が一致しません: '{b.get('platform')}' ≠ '{args.platform}'", file=sys.stderr)
        ok = False
    if args.handle and b.get('handle') != args.handle:
        print(f"警告: handle が一致しません: '{b.get('handle')}' ≠ '{args.handle}'", file=sys.stderr)
        ok = False
    print('binding は有効です' if ok else 'binding は無効です')
    if ok:
        print('（運用手順）: この binding が実際に該当ハンドルのアカウントから投稿されていることを確認してください')
    sys.exit(0 if ok else 1)


def unbinding_message(platform: str, handle: str, npub: str,
                      binding_created_at: int, reason: str, created_at: int) -> bytes:
    """unbinding 証明書の署名対象: (platform, handle, npub, binding_created_at, reason, created_at) の canonical hash。"""
    canon = json.dumps(
        {'platform': platform, 'handle': handle, 'npub': npub,
         'binding_created_at': binding_created_at, 'reason': reason, 'created_at': created_at},
        sort_keys=True, separators=(',', ':'), ensure_ascii=False,
    )
    return hashlib.sha256(canon.encode('utf-8')).digest()


def verify_unbinding_cert(u: dict) -> bool:
    if not (u.get('protocol') == 'nakama' and u.get('version') == 1
            and u.get('type') == 'platform-binding-revocation'):
        return False
    try:
        msg = unbinding_message(u['platform'], u['handle'], u['npub'],
                                int(u.get('binding_created_at', 0)), u.get('reason', ''), u['created_at'])
        return verify_schnorr(u['npub'], bytes.fromhex(u['sig']), msg)
    except Exception:
        return False


def cmd_unbind(args):
    """platform-binding の取り消し証明書を発行（鍵 → ハンドルの主張撤回、spec §9.1）。"""
    secret = load_key(args.keyfile)
    me = npub_of(secret)
    created_at = int(time.time())
    bca = args.binding_created_at or 0  # 0 = そのハンドルへの binding をすべて取り消し
    reason = args.reason or ''
    msg = unbinding_message(args.platform, args.handle, me, bca, reason, created_at)
    unbind = {
        'protocol': 'nakama', 'version': 1, 'type': 'platform-binding-revocation',
        'platform': args.platform, 'handle': args.handle, 'npub': me,
        'binding_created_at': bca, 'reason': reason,
        'created_at': created_at,
        'sig': sign_schnorr(secret, msg).hex(),
    }
    out = args.out or 'unbinding.json'
    with open(out, 'w') as f:
        json.dump(unbind, f, indent=2, ensure_ascii=False)
    scope = '指定 binding (created_at=%d)' % bca if bca else 'そのハンドルへの binding すべて'
    print(f'unbinding 証明書: {out} — {scope} を取り消し（"{args.handle}"@{args.platform}）')
    print('運用: この unbinding をハンドルのアカウントから投稿してください（取り消しの公開告知）。')
    if args.markdown:
        print()
        print('投稿用ブロック（コメント欄に貼る）:')
        print(markdown_block(unbind, 'unbinding'))


def cmd_verify_unbinding(args):
    """unbinding 証明書の署名・platform・handle を検証。"""
    with open(args.unbinding) as f:
        u = json.load(f)
    ok = verify_unbinding_cert(u)
    if args.platform and u.get('platform') != args.platform:
        print(f"警告: platform が一致しません: '{u.get('platform')}' ≠ '{args.platform}'", file=sys.stderr)
        ok = False
    if args.handle and u.get('handle') != args.handle:
        print(f"警告: handle が一致しません: '{u.get('handle')}' ≠ '{args.handle}'", file=sys.stderr)
        ok = False
    print('unbinding は有効です' if ok else 'unbinding は無効です')
    if ok:
        print('（運用手順）: 取り消し対象の binding がこの unbinding の binding_created_at 以前であることを確認してください')
    sys.exit(0 if ok else 1)


BOARD_DECISION_TYPES = ('admit', 'handover', 'policy-update', 'close')


def board_policy_message(board_id: str, relay: str, threshold: int, eligible: list, created_at: int) -> bytes:
    """board-policy 証明書の署名対象: (board_id, relay, threshold, eligible の連結, created_at) の canonical hash。"""
    canon = json.dumps(
        {'board_id': board_id, 'relay': relay, 'threshold': threshold,
         'eligible': eligible, 'created_at': created_at},
        sort_keys=True, separators=(',', ':'), ensure_ascii=False,
    )
    return hashlib.sha256(canon.encode('utf-8')).digest()


def verify_board_policy_cert(p: dict) -> bool:
    """初回 board-policy の検証: 規約内容の形式 + eligible 全員 (n-of-n) の有効署名。"""
    if not (p.get('protocol') == 'nakama' and p.get('version') == 1
            and p.get('type') == 'board-policy'):
        return False
    try:
        eligible = list(p['eligible'])
        if not eligible or len(set(eligible)) != len(eligible):
            return False
        threshold = int(p['threshold'])
        if not (1 <= threshold <= len(eligible)):
            return False
        msg = board_policy_message(p['board_id'], p['relay'], threshold, eligible, int(p['created_at']))
        signers = set()
        for s in p.get('signatures', []):
            if not verify_schnorr(s['npub'], bytes.fromhex(s['sig']), msg):
                return False
            signers.add(s['npub'])
        return set(eligible) == signers  # 初回規約は n-of-n: 全員が署名し、部外者の署名は不可
    except Exception:
        return False


def board_decision_message(board_id: str, relay: str, decision: str, payload: dict, created_at: int) -> bytes:
    """board-decision 証明書の署名対象: (board_id, relay, decision, payload の canonical 形式, created_at) の hash。"""
    canon = json.dumps(
        {'board_id': board_id, 'relay': relay, 'decision': decision,
         'payload': payload, 'created_at': created_at},
        sort_keys=True, separators=(',', ':'), ensure_ascii=False,
    )
    return hashlib.sha256(canon.encode('utf-8')).digest()


def validate_decision_payload(decision: str, payload: dict) -> bool:
    """決定種別ごとの payload 形式チェック。"""
    if not isinstance(payload, dict):
        return False
    if decision == 'admit':
        return set(payload.keys()) == {'candidate'}
    if decision == 'handover':
        return (set(payload.keys()) == {'new_moderators'}
                and isinstance(payload['new_moderators'], list)
                and all(isinstance(n, str) for n in payload['new_moderators']))
    if decision == 'policy-update':
        return set(payload.keys()) == {'threshold', 'eligible'}
    if decision == 'close':
        return set(payload.keys()) == {'reason'}
    return False


def verify_board_decision(d: dict, policy: dict):
    """board-decision の検証。(ok, 承認署名数, threshold) を返す。

    承認署名のうち、現行 policy の eligible に含まれる異なる npub の有効署名が
    threshold 以上あることを確認する。部外者の署名は無視し、重複は 1 と数える。
    """
    if not (d.get('protocol') == 'nakama' and d.get('version') == 1
            and d.get('type') == 'board-decision'):
        return (False, 0, 0)
    if not verify_board_policy_cert(policy):
        return (False, 0, 0)
    try:
        if d.get('decision') not in BOARD_DECISION_TYPES:
            return (False, 0, 0)
        if not validate_decision_payload(d['decision'], d.get('payload')):
            return (False, 0, 0)
        if d['board_id'] != policy['board_id'] or d['relay'] != policy['relay']:
            return (False, 0, 0)
        msg = board_decision_message(d['board_id'], d['relay'], d['decision'],
                                     d['payload'], int(d['created_at']))
        eligible = set(policy['eligible'])
        good = set()
        for a in d.get('approvals', []):
            if a['npub'] not in eligible:
                continue
            if verify_schnorr(a['npub'], bytes.fromhex(a['sig']), msg):
                good.add(a['npub'])
        return (len(good) >= int(policy['threshold']), len(good), int(policy['threshold']))
    except Exception:
        return (False, 0, 0)


def cmd_board_policy(args):
    """board-policy 運営規約案の作成（自分の署名入り。spec §9.4）。"""
    secret = load_key(args.keyfile)
    me = npub_of(secret)
    eligible = list(args.eligible)
    threshold = args.threshold
    if not eligible:
        print('eligible が空です', file=sys.stderr)
        sys.exit(1)
    if not (1 <= threshold <= len(eligible)):
        print(f'threshold は 1..{len(eligible)} の範囲で指定してください', file=sys.stderr)
        sys.exit(1)
    if me not in eligible:
        print('警告: あなた自身が eligible に含まれていません（規約案には発起人の署名が入ります）', file=sys.stderr)
    created_at = int(time.time())
    msg = board_policy_message(args.board_id, args.relay, threshold, eligible, created_at)
    policy = {
        'protocol': 'nakama', 'version': 1, 'type': 'board-policy',
        'board_id': args.board_id, 'relay': args.relay,
        'threshold': threshold, 'eligible': eligible,
        'created_at': created_at,
        'signatures': [{'npub': me, 'sig': sign_schnorr(secret, msg).hex()}],
    }
    out = args.out or 'board-policy.json'
    with open(out, 'w') as f:
        json.dump(policy, f, indent=2, ensure_ascii=False)
    print(f'board-policy 案: {out} — あなたの署名 1/{len(eligible)}（初回は全員 {len(eligible)}/{len(eligible)} の署名が必要）')
    print('運用: このファイルを eligible 全員に回覧し、`board_policy_sign` で署名を集めてください。')
    if args.markdown:
        print()
        print('投稿用ブロック（コメント欄に貼る）:')
        print(markdown_block(policy, 'board-policy'))


def cmd_board_policy_sign(args):
    """回覧中の board-policy 案に自分の署名を追加（spec §9.4）。"""
    secret = load_key(args.keyfile)
    me = npub_of(secret)
    with open(args.policy) as f:
        p = json.load(f)
    if p.get('type') != 'board-policy':
        print('board-policy 形式ではありません', file=sys.stderr)
        sys.exit(1)
    try:
        msg = board_policy_message(p['board_id'], p['relay'], int(p['threshold']),
                                   list(p['eligible']), int(p['created_at']))
    except Exception:
        print('規約の内容が不正です（board_id / relay / threshold / eligible / created_at を確認）', file=sys.stderr)
        sys.exit(1)
    signers = {s['npub'] for s in p.get('signatures', [])}
    if me in signers:
        print('既に署名済みです（重複署名は 1 と数えます）', file=sys.stderr)
    else:
        # 署名前に既存の署名が有効であることを確認（回覧中の改ざんを検出）
        for s in p.get('signatures', []):
            if not verify_schnorr(s['npub'], bytes.fromhex(s['sig']), msg):
                print(f'警告: 既存の署名が無効です: {s["npub"]}（回覧中に改ざんされた可能性）', file=sys.stderr)
                sys.exit(1)
        p.setdefault('signatures', []).append({'npub': me, 'sig': sign_schnorr(secret, msg).hex()})
    out = args.out or args.policy
    with open(out, 'w') as f:
        json.dump(p, f, indent=2, ensure_ascii=False)
    ok = verify_board_policy_cert(p)
    print(f'board-policy: {out} — 署名 {len(p["signatures"])}/{len(p["eligible"])}（'
          + ('発効条件（全員署名）を満たしています' if ok else 'まだ全員分が揃っていません') + '）')


def cmd_verify_board_policy(args):
    """board-policy の検証（spec §9.4: 初回は n-of-n）。"""
    with open(args.policy) as f:
        p = json.load(f)
    ok = verify_board_policy_cert(p)
    if ok:
        print(f'board-policy は有効です: eligible {len(p["eligible"])} 名全員の署名を確認（threshold {p["threshold"]}）')
    else:
        print('board-policy は無効です: 全員の有効署名が揃っていないか、形式が不正です')
    sys.exit(0 if ok else 1)


def cmd_board_decide(args):
    """board-decision 決定案の作成＋自分の承認署名（spec §9.4）。"""
    secret = load_key(args.keyfile)
    me = npub_of(secret)
    try:
        payload = json.loads(args.payload)
    except Exception as e:
        print(f'payload の JSON 解析に失敗: {e}', file=sys.stderr)
        sys.exit(1)
    if not validate_decision_payload(args.decision, payload):
        print(f"payload の形式が decision '{args.decision}' に適合しません", file=sys.stderr)
        sys.exit(1)
    created_at = int(time.time())
    msg = board_decision_message(args.board_id, args.relay, args.decision, payload, created_at)
    d = {
        'protocol': 'nakama', 'version': 1, 'type': 'board-decision',
        'board_id': args.board_id, 'relay': args.relay,
        'decision': args.decision, 'payload': payload,
        'created_at': created_at,
        'approvals': [{'npub': me, 'sig': sign_schnorr(secret, msg).hex()}],
    }
    out = args.out or 'board-decision.json'
    with open(out, 'w') as f:
        json.dump(d, f, indent=2, ensure_ascii=False)
    print(f'board-decision 案: {out} — 決定 "{args.decision}"、あなたの承認署名 1 つ')
    print('運用: このファイルを回覧し、`board_cosign` で承認署名を threshold 分まで集めてください。')


def cmd_board_cosign(args):
    """回覧中の board-decision に自分の承認署名を追加（spec §9.4）。"""
    secret = load_key(args.keyfile)
    me = npub_of(secret)
    with open(args.decision) as f:
        d = json.load(f)
    if d.get('type') != 'board-decision':
        print('board-decision 形式ではありません', file=sys.stderr)
        sys.exit(1)
    try:
        msg = board_decision_message(d['board_id'], d['relay'], d['decision'],
                                     d['payload'], int(d['created_at']))
    except Exception:
        print('決定の内容が不正です（board_id / relay / decision / payload / created_at を確認）', file=sys.stderr)
        sys.exit(1)
    approvers = {a['npub'] for a in d.get('approvals', [])}
    if me in approvers:
        print('既に承認署名済みです（重複は 1 と数えます）', file=sys.stderr)
    else:
        # 決定案の改ざんを既存の承認署名で間接確認
        for a in d.get('approvals', []):
            if not verify_schnorr(a['npub'], bytes.fromhex(a['sig']), msg):
                print(f'警告: 既存の承認署名が無効です: {a["npub"]}（回覧中に改ざんされた可能性）', file=sys.stderr)
                sys.exit(1)
        d.setdefault('approvals', []).append({'npub': me, 'sig': sign_schnorr(secret, msg).hex()})
    out = args.out or args.decision
    with open(out, 'w') as f:
        json.dump(d, f, indent=2, ensure_ascii=False)
    print(f'board-decision: {out} — 承認署名 {len(d["approvals"])} つ')


def cmd_verify_board_decision(args):
    """board-decision の threshold 達成検証（spec §9.4）。"""
    with open(args.decision) as f:
        d = json.load(f)
    with open(args.policy) as f:
        p = json.load(f)
    if not verify_board_policy_cert(p):
        print('参照する board-policy が無効です（決定の検証には有効な規約が必要）')
        sys.exit(1)
    ok, n, threshold = verify_board_decision(d, p)
    if ok:
        print(f'board-decision は有効です: 承認署名 {n}/{threshold}（決定 "{d.get("decision")}"）')
    else:
        print(f'board-decision は無効です: 承認署名 {n}/{threshold}（threshold 未達または署名不正）')
    sys.exit(0 if ok else 1)


def main():
    ap = argparse.ArgumentParser(description='仲間プロトコル v0.1')
    ap.add_argument('--keyfile', default=KEYFILE_DEFAULT)
    sub = ap.add_subparsers(dest='cmd', required=True)

    s = sub.add_parser('init'); s.add_argument('--from-hex'); s.add_argument('--force', action='store_true')
    sub.add_parser('whoami')
    s = sub.add_parser('propose'); s.add_argument('npub'); s.add_argument('--out')
    s.add_argument('--expires-days', type=int, default=BOND_DEFAULT_EXPIRY_DAYS,
                   help=f'bond の有効期限（日数、既定 {BOND_DEFAULT_EXPIRY_DAYS} 日）')
    s.add_argument('--no-expiry', action='store_true', help='有効期限を付けない（旧来の形式）')
    s.add_argument('--markdown', action='store_true', help='投稿用の fenced code block を出力 (§8.3)')
    s = sub.add_parser('accept'); s.add_argument('proposal', nargs='?', default=None)
    s.add_argument('--out'); s.add_argument('--from-b64', dest='from_b64', default=None,
        help='base64url/fenced block の proposal を直接受理 (§8.3)')
    s.add_argument('--markdown', action='store_true', help='完成 bond を投稿用ブロックで出力 (§8.3)')
    s = sub.add_parser('verify'); s.add_argument('bond'); s.add_argument('--rotation', action='append', default=[])
    s.add_argument('--registry', default=None, help='revocation registry ディレクトリ (既定: ~/.config/nakama/revocations)')
    s.add_argument('--skip-registry', action='store_true', help='registry の解消チェックを省略')
    s.add_argument('--skip-expiry', action='store_true', help='有効期限チェックを省略')
    s = sub.add_parser('renew'); s.add_argument('bond'); s.add_argument('--out')
    s.add_argument('--expires-days', type=int, default=BOND_DEFAULT_EXPIRY_DAYS,
                   help=f'更新後の有効期限（日数、既定 {BOND_DEFAULT_EXPIRY_DAYS} 日）')
    s.add_argument('--markdown', action='store_true', help='投稿用の fenced code block を出力 (§8.3)')
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
    s.add_argument('--registry', default=None, help='revocation registry ディレクトリ (既定: ~/.config/nakama/revocations)')
    s.add_argument('--no-registry', action='store_true', help='registry への記録を省略')
    s = sub.add_parser('verify_revocation'); s.add_argument('revocation'); s.add_argument('--bond')
    s = sub.add_parser('revoke_list'); s.add_argument('--registry', default=None)
    s = sub.add_parser('liveness'); s.add_argument('--bond', default=None, help='紐付ける bond ファイル')
    s.add_argument('--out')
    s = sub.add_parser('verify_liveness'); s.add_argument('proof'); s.add_argument('--bond', default=None)
    s.add_argument('--max-age', type=int, default=7 * 86400, help='許容する古さ（秒、既定7日）')
    s.add_argument('--registry', default=None, help='revocation registry ディレクトリ (既定: ~/.config/nakama/revocations)')
    s.add_argument('--skip-registry', action='store_true', help='registry の解消チェックを省略')
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
    s = sub.add_parser('bind'); s.add_argument('--platform', required=True)
    s.add_argument('--handle', required=True); s.add_argument('--out')
    s.add_argument('--markdown', action='store_true', help='投稿用の fenced code block を出力')
    s = sub.add_parser('verify_binding'); s.add_argument('binding')
    s.add_argument('--platform'); s.add_argument('--handle')
    s = sub.add_parser('unbind'); s.add_argument('--platform', required=True)
    s.add_argument('--handle', required=True); s.add_argument('--out')
    s.add_argument('--reason', default=''); s.add_argument('--binding-created-at', type=int, default=0,
        help='取り消し対象の binding の created_at（既定 0 = そのハンドルへの binding をすべて取り消し）')
    s.add_argument('--markdown', action='store_true', help='投稿用の fenced code block を出力')
    s = sub.add_parser('verify_unbinding'); s.add_argument('unbinding')
    s.add_argument('--platform'); s.add_argument('--handle')
    s = sub.add_parser('board_policy'); s.add_argument('--board-id', required=True)
    s.add_argument('--relay', required=True); s.add_argument('--threshold', type=int, required=True)
    s.add_argument('--eligible', nargs='+', required=True); s.add_argument('--out')
    s.add_argument('--markdown', action='store_true', help='投稿用の fenced code block を出力')
    s = sub.add_parser('board_policy_sign'); s.add_argument('policy'); s.add_argument('--out')
    s = sub.add_parser('verify_board_policy'); s.add_argument('policy')
    s = sub.add_parser('board_decide'); s.add_argument('--board-id', required=True)
    s.add_argument('--relay', required=True)
    s.add_argument('--decision', required=True, choices=list(BOARD_DECISION_TYPES))
    s.add_argument('--payload', required=True, help="決定内容の JSON（例: '{\"candidate\": \"<npub>\"}'）")
    s.add_argument('--out')
    s = sub.add_parser('board_cosign'); s.add_argument('decision'); s.add_argument('--out')
    s = sub.add_parser('verify_board_decision'); s.add_argument('decision'); s.add_argument('--policy', required=True)

    args = ap.parse_args()
    {'init': cmd_init, 'whoami': cmd_whoami, 'propose': cmd_propose,
     'accept': cmd_accept, 'verify': cmd_verify, 'renew': cmd_renew,
    'challenge': cmd_challenge,
     'respond': cmd_respond, 'check': cmd_check, 'rotate': cmd_rotate,
     'verify_rotation': cmd_verify_rotation, 'revoke': cmd_revoke,
     'verify_revocation': cmd_verify_revocation, 'revoke_list': cmd_revoke_list,
     'liveness': cmd_liveness, 'verify_liveness': cmd_verify_liveness, 'dm_send': cmd_dm_send,
     'dm_recv': cmd_dm_recv, 'dm_pub': cmd_dm_pub,
     'dm_fetch': cmd_dm_fetch, 'board_create': cmd_board_create,
     'board_verify': cmd_board_verify, 'board_join': cmd_board_join,
     'board_send': cmd_board_send, 'board_read': cmd_board_read,
     'bind': cmd_bind, 'verify_binding': cmd_verify_binding,
     'unbind': cmd_unbind, 'verify_unbinding': cmd_verify_unbinding,
     'board_policy': cmd_board_policy, 'board_policy_sign': cmd_board_policy_sign,
     'verify_board_policy': cmd_verify_board_policy,
     'board_decide': cmd_board_decide, 'board_cosign': cmd_board_cosign,
     'verify_board_decision': cmd_verify_board_decision}[args.cmd](args)


if __name__ == '__main__':
    main()
