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
  nakama.py challenge [--to <npub>]                   照合用 nonce を生成（--to で宛先の侵害宣言を警告 §14.2）
  nakama.py respond <nonce-hex>                      nonce に署名
  nakama.py check <npub> <nonce-hex> <sig-hex>       署名を検証（対手の侵害宣言を警告 §14.2）
  nakama.py rotate --gen|--to-hex HEX [--to-keyfile P]  鍵ローテーション: 旧鍵が新鍵に署名した rotation 証明書を発行
  nakama.py verify_rotation <rotation.json>          rotation 証明書を検証
  nakama.py rotate_pub <relay> <rotation.json> [--auth]  rotation 証明書を Nostr に公開（kind 30109、d タグ = old_hex）
  nakama.py rotate_fetch <relay> <old_npub> [--limit N] [--auth] [--out FILE] [--chain]
      公開された rotation 証明書を購読・追跡（--chain: new→old のチェーン全体をたどる）
  nakama.py revoke <bond.json> [--reason 理由]        bond の解消 (revocation イベント) を署名して発行
  nakama.py verify_revocation <revocation.json> --bond <bond.json>  解消イベントを検証
  nakama.py revoke_import <revocation.json> [--bond <bond.json>]  受け取った revocation を検証して registry に取り込む
  nakama.py revoke_pub <relay> <revocation.json> [--auth]  revocation を Nostr に公開（kind 30107、d タグ = bond_hash）
  nakama.py revoke_fetch <relay> <bond_hash> [--limit N] [--auth]  公開された revocation を購読して registry に取り込む
  nakama.py revoke_list                            解消済み bond の一覧を表示（理由つき）
  nakama.py compromise_declare --subject <npub> [--reason 理由] [--evidence 証拠] [--bond bond.json]
      鍵スコープの侵害宣言を発行（§13: 「この npub はもう本人ではない」と仲間が宣言）
  nakama.py compromise_import <declaration.json> [--subject <npub>]  受け取った侵害宣言を検証して registry に取り込む
  nakama.py compromise_pub <relay> <declaration.json> [--auth]  侵害宣言を Nostr に公開（kind 30108、d タグ = subject_hex:declarant_hex）
  nakama.py compromise_fetch <relay> <npub> [--limit N] [--auth]  公開された侵害宣言を購読して registry に取り込む
  nakama.py compromise_withdraw --subject <npub>  自分の侵害宣言を withdrawn: true で再発行（撤回）
  nakama.py key_status <npub> [--threshold N] [--bond bond.json ...] [--liveness proof.json] [--max-age 秒] [--rotation R.json ...]
      侵害宣言の状態を照会（bond graph で重みづけ、閾値到達で「疑わしい」。--rotation で移行完了を表示 §14.3）
  nakama.py dm_send <相手npub> <メッセージ> [--out FILE]  gift wrap (kind 1059) を構築（宛先の侵害宣言を警告 §14.2）
  nakama.py dm_recv <giftwrap.json>                    gift wrap を復号して rumor を表示
  nakama.py dm_pub <relay> [--in FILE|--to-npub NPUB --message MSG]  gift wrap をリレーに publish
  nakama.py dm_fetch <relay> [--since TS] [--limit N]  自分宛 gift wrap を購読・復号
  nakama.py board_create <relay> --name "広場名" [--about 説明] [--admission open|approval] [--out FILE]  NIP-29 広場を作る（kind 9002 + 34550 を publish、descriptor を出力）
  nakama.py board_verify <descriptor.json>        board descriptor の署名を検証（運営鍵の侵害宣言を警告 §14.2）
  nakama.py board_join <relay> <board_id>         広場に参加申請（kind 9007 を publish）
  nakama.py board_send <relay> <board_id> "MSG" [--descriptor D.json]  広場に投稿（kind 9 平文を publish、侵害宣言を警告 §14.2）
  nakama.py board_read <relay> <board_id> [--since TS] [--limit N]  広場の投稿を購読・表示（投稿者に侵害宣言があれば注記 §14.2）
  nakama.py board_read <relay> <board_id> --governance <policy.json> [--decisions <file|dir>...]
      管理イベント (kind 9000/9001) と board-decision の合意照合（spec §9.4）
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
  nakama.py board_decide --board-id <id> --relay <url> --decision admit|handover|policy-update|close --payload '<json>' [--expires-in SECS] [--expires-at TS] [--out decision.json]
      board-decision 決定案を作成＋自分の承認署名
  nakama.py board_cosign <decision.json> [--out decision.json]
      回覧中の決定案に自分の承認署名を追加
  nakama.py verify_board_decision <decision.json> --policy <policy.json>
      決定の threshold 達成を検証
  nakama.py board_decide_pub <relay> <decision.json> [--auth]
      board-decision を Nostr に公開（kind 30110、d タグ = コアハッシュ。署名者は publisher）
  nakama.py board_decide_fetch <relay> <board_id> [--limit N] [--auth] [--out DIR] [--policy POLICY]
      公開された board-decision を購読・検証・マージして表示（--out: <core_hash>.json で保存、--policy: threshold 充足・不足の表示）
  nakama.py board_draft_pub <relay> <draft.json> [--auth]
      決定前の草案を Nostr に公開（kind 30111、d タグ = コアハッシュ。署名者は publisher。各承認者が自分のスロットに再公開する方式 B）
  nakama.py board_draft_fetch <relay> <board_id> [--limit N] [--auth] [--out DIR] [--policy POLICY]
      公開された草案を購読・検証・マージして表示（--out: <core_hash>.json で保存 — board_cosign にそのまま渡せる、--policy: 草案の threshold 充足・不足の表示）
  nakama.py board_fetch_all <relay> <board_id> [--limit N] [--auth] [--out DIR] [--policy POLICY]
      30110+30111 を 1 回の REQ で購読し同一コアの草案・完成を統合表示（--out: 内部マーカーを剥がした <core_hash>.json、--policy: 成立済みは時点解決・草案は現行政策のみで threshold 表示）
  nakama.py board_draft_notify <relay> <board_id> [--limit N] [--auth] [--policy POLICY] [--within SECS] [--include-expired] [--dry-run] [--resend] [--from NPUB] [--cosigners]
      期限間近の草案を発行者に NIP-17 DM で通知（--within 既定 24h、送信記録で二重送信防止、宛先は草案イベントの publisher のみ — spec §25）。
      --cosigners で threshold 未達・期限間近の草案の未署名 eligible 承認者にも通知（--policy 必須 — spec §27）
  nakama.py board_notif_ack <relay> <npub> --core <core_hash> [--reason 語彙] [--note 自由文] [--auth] [--from NPUB]
      通知を受け取った側が通知の発行者に自発・手動で ack DM を送る（--reason の既定: cosign_request。
      語彙は expiring_soon/expired/cosign_request。--core は 32 hex（decision_core_hash）または 64 hex を受付 — spec §28）
  nakama.py board_notif_status <board_id> [--relay RELAY] [--since UNIX] [--limit N] [--auth] [--policy POLICY] [--decisions DIR] [--dir DIR]
      送信記録の突き合わせ表示: 各記録に sent（UTC）/ ack（受信 DM の notif-ack と突き合わせ）/
      cosigned（--policy 時のみ、同一 core の 30111 approvals に recipient の npub）を表示（spec §28）。
      fetch 失敗時は記録のみ表示。exit は常に 0
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
    # §15: accept 時の侵害警告 — proposal 検証の後・自分の署名前。
    # 自分以外の当事者に非撤回宣言があれば stderr に WARN（advisory、exit コード不変）。
    creg = getattr(args, 'compromise_registry', None) or COMPROMISES_DEFAULT
    for npub in p['companions']:
        if npub == me:
            continue
        for w in key_compromise_warnings(npub, creg):
            print(w, file=sys.stderr)
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
    # §14.2: 侵害宣言の警告（advisory — exit コードは不変）。
    # --rotation 指定時は移行後の有効 npub を検査対象とし、旧鍵への宣言は INFO に格下げする。
    creg = args.compromise_registry or COMPROMISES_DEFAULT
    for npub in b['companions']:
        for w in key_compromise_warnings(rotations.get(npub, npub), creg):
            print(w, file=sys.stderr)
        if npub in rotations:
            for w in key_compromise_warnings(npub, creg):
                print('INFO: ' + w[len('WARN: '):] + ' — 旧鍵への宣言（ローテーション済みのため情報扱い）',
                      file=sys.stderr)
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


# --- v0.23 §26.10: Nostr kind の環境変数上書き ---

def _kind_from_env(env_name: str, default: int) -> int:
    """Nostr kind 定数の環境変数上書きを解決する（spec §26.10）。

    無効値（非 int / 30000–39999 の範囲外）は起動時ではなく使用時に検証し、
    その操作を exit 1 で拒否する（無関係なコマンドまで壊さないため）。
    正直な注記: 環境変数は足元の運用（自分が発行・購読する kind）のための
    もので、他者の kind 使用を変える力はない。
    """
    raw = os.environ.get(env_name)
    if raw is None or raw.strip() == '':
        return default
    v = None
    try:
        v = int(raw.strip(), 10)
    except ValueError:
        pass
    if v is None or not 30000 <= v <= 39999:
        sys.stderr.write(
            f'error: {env_name}={raw!r} は無効です。'
            f'30000–39999 の整数を指定してください。\n')
        sys.exit(1)
    return v


# --- v0.12: rotation 証明書の Nostr 公開（spec §17） ---
# §12 の revoke_pub パターン（kind 30107）を流用。Nostr の既存リレーヘルパ
# （nostr_publish / nostr_request / --auth）をそのまま使い、kind 30109 を定義する。

def ROTATION_NOSTR_KIND() -> int:
    """rotation 証明書の Nostr kind。既定 30109（v0.23 で 30102 から再マップ）。

    NAKAMA_KIND_ROTATION で上書き可能。使用時に環境変数を読んで検証する。"""
    return _kind_from_env('NAKAMA_KIND_ROTATION', 30109)


def rotation_nostr_event(rot: dict, secret: bytes) -> dict:
    """rotation 証明書を Nostr 公開用イベント (kind 30109) として構築・署名する（純粋）。

    kind 30109 は parameterized replaceable: d タグ = old_hex。イベントの署名者は
    旧鍵（正規スロット (pubkey, kind, d) を一つに定める。§17.3）。
    """
    content = json.dumps(rot, sort_keys=True, separators=(',', ':'))
    old_hex = npub_to_hex(rot['old_npub'])
    return sign_event(secret, int(time.time()), ROTATION_NOSTR_KIND(),
                      [['d', old_hex]], content)


def verify_rotation_nostr_event(ev: dict, old_hex: str) -> dict | None:
    """Nostr イベントから rotation 証明書を取り出す三段階検証（純粋）。

    1. Nostr イベント署名の検証
    2. content の JSON パース
    3. verify_rotation_cert（旧鍵署名）＋ d タグ / cert の old_hex の一致
       ＋イベント pubkey == old_hex（正規スロットのみ受理、第三者スロットは無視）
    受理なら rotation dict、無効なら None。"""
    if not verify_event_sig(ev):
        return None
    try:
        r = json.loads(ev['content'])
    except (ValueError, TypeError):
        return None
    if not isinstance(r, dict):
        return None
    try:
        content_old_hex = npub_to_hex(r['old_npub'])
    except Exception:
        return None
    if content_old_hex != old_hex:
        return None  # 指定の旧鍵と関係ない証明書（リレーのフィルタが緩い場合の二重チェック）
    dtags = [t[1] for t in ev.get('tags', []) if len(t) >= 2 and t[0] == 'd']
    if old_hex not in dtags:
        return None  # d タグと content の old_hex の不一致
    if ev.get('pubkey') != old_hex:
        return None  # 正規スロットのみ受理
    if not verify_rotation_cert(r):
        return None
    return r


def rotation_chain_fetch(old_hex: str, fetch_one, max_links: int = 16) -> list:
    """rotation チェーンをたどる（純粋、I/O なし）。

    fetch_one(hex) -> rotation dict | None（その old_hex に対する最新の有効証明書）。
    戻り値は古い順の rotation list。循環検出と上限 max_links で停止する。
    """
    chain = []
    seen = {old_hex}
    cur = old_hex
    for _ in range(max_links):
        r = fetch_one(cur)
        if r is None:
            break
        try:
            new_hex = npub_to_hex(r['new_npub'])
        except Exception:
            break
        if new_hex in seen:
            break  # 循環（自己ループ含む）
        chain.append(r)
        seen.add(new_hex)
        cur = new_hex
    return chain


def cmd_rotate_pub(args):
    """rotation 証明書を Nostr リレーに publish (kind 30109, d タグ = old_hex)。署名者は旧鍵。"""
    secret = load_key(args.keyfile)
    with open(args.rotation) as f:
        rot = json.load(f)
    assert rot.get('protocol') == 'nakama' and rot.get('version') == 1 and rot.get('type') == 'rotation', \
        'nakama v1 の rotation ではありません'
    if not verify_rotation_cert(rot):
        print('rotation は無効です（publish しません）', file=sys.stderr)
        sys.exit(1)
    me = npub_of(secret)
    if me != rot['old_npub']:
        print('keyfile の鍵は rotation の old_npub と一致しません（鍵の取り違え防止のため publish しません）',
              file=sys.stderr)
        sys.exit(1)
    ev = rotation_nostr_event(rot, secret)
    accepted, reason = nostr_publish(args.relay, ev, auth_secret=secret if args.auth else None)
    print(f'publish: {"受理" if accepted else "拒否"} ({reason}) id={ev["id"]}')
    sys.exit(0 if accepted else 1)


def cmd_rotate_fetch(args):
    """old_npub に対する rotation 公開イベント (kind 30109, #d=old_hex) を購読し、有効なものを表示する。"""
    secret = load_key(args.keyfile)
    try:
        old_hex = npub_to_hex(args.old_npub)
    except Exception:
        print('npub は有効ではありません', file=sys.stderr)
        sys.exit(1)

    def fetch_one(target_hex):
        filt = {'kinds': [ROTATION_NOSTR_KIND()], '#d': [target_hex], 'limit': args.limit}
        sub_id = secrets.token_hex(8)
        events = nostr_request(args.relay, ['REQ', sub_id, filt], auth_secret=secret if args.auth else None)
        best = None
        skipped = 0
        for ev in events:
            r = verify_rotation_nostr_event(ev, target_hex)
            if r is None:
                skipped += 1
            elif best is None or r['created_at'] > best['created_at']:
                best = r
        return best, skipped, len(events)

    if args.chain:
        chain = rotation_chain_fetch(old_hex, lambda h: fetch_one(h)[0])
        if not chain:
            print('rotation 公開イベントは見つかりませんでした')
            return
        for i, r in enumerate(chain):
            print(f'[{i}] {r["old_npub"][:16]}... → {r["new_npub"][:16]}...'
                  f' (created_at {time.strftime("%Y-%m-%d", time.localtime(r["created_at"]))})')
        if args.out:
            with open(args.out, 'w') as f:
                json.dump(chain[-1], f, indent=2)
            os.chmod(args.out, 0o600)
            print(f'最新の rotation を {args.out} に保存しました（mode 600）')
        return

    best, skipped, total = fetch_one(old_hex)
    if best is None:
        print(f'{total} 件のイベントを取得: 有効な rotation 公開はありませんでした（{skipped} 件をスキップ）')
        return
    print(f'rotation 公開: {best["old_npub"][:16]}... → {best["new_npub"][:16]}...'
          f' (created_at {time.strftime("%Y-%m-%d", time.localtime(best["created_at"]))})')
    print(f'{total} 件のイベントを取得: 有効 1 件、スキップ {skipped} 件')
    if args.out:
        with open(args.out, 'w') as f:
            json.dump(best, f, indent=2)
        os.chmod(args.out, 0o600)
        print(f'rotation を {args.out} に保存しました（mode 600）')


def bond_hash(b: dict) -> str:
    canon = json.dumps(
        {k: b[k] for k in ('companions', 'created_at', 'nonce')},
        sort_keys=True, separators=(',', ':'),
    )
    return hashlib.sha256(canon.encode()).hexdigest()


def revocation_message(bond_hash_hex: str, revoker: str, created_at: int, reason: str = '') -> bytes:
    body = {'bond_hash': bond_hash_hex, 'revoker': revoker, 'created_at': created_at, 'type': 'revocation'}
    if reason:
        body['reason'] = reason
    canon = json.dumps(body, sort_keys=True, separators=(',', ':'))
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
    reason = args.reason or ''
    sig = sign_schnorr(secret, revocation_message(h, me, created_at, reason))
    rev = {
        'protocol': 'nakama', 'version': 1, 'type': 'revocation',
        'bond_hash': h, 'revoker': me, 'created_at': created_at,
        'sig': sig.hex(),
    }
    if reason:
        rev['reason'] = reason
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
    msg = revocation_message(r['bond_hash'], r['revoker'], r['created_at'], r.get('reason', ''))
    return verify_schnorr(r['revoker'], bytes.fromhex(r['sig']), msg)


def import_revocation_event(r: dict, registry: str) -> str:
    """受け取った revocation を registry に取り込む。戻り値: 'stored' | 'duplicate' | 'invalid'。

    無効な署名のイベントは registry に触れず 'invalid'。既存記録は上書きしない（先勝ち）。
    """
    if not verify_revocation_event(r):
        return 'invalid'
    os.makedirs(registry, exist_ok=True)
    rp = revocation_registry_path(registry, r['bond_hash'])
    if os.path.exists(rp):
        return 'duplicate'
    with open(rp, 'w') as f:
        json.dump(r, f, indent=2)
    os.chmod(rp, 0o600)
    return 'stored'


def REVOCATION_NOSTR_KIND() -> int:
    """revocation の Nostr kind。既定 30107（v0.23 で 30100 から再マップ）。

    NAKAMA_KIND_REVOCATION で上書き可能。使用時に環境変数を読んで検証する。"""
    return _kind_from_env('NAKAMA_KIND_REVOCATION', 30107)


def revocation_nostr_event(rev: dict, secret: bytes) -> dict:
    """revocation イベントを Nostr 公開用イベント (kind 30107) として構築・署名する。

    kind 30107 は parameterized replaceable: d タグ = bond_hash。再発行で上書き（reason の追記訂正）できる。
    """
    content = json.dumps(rev, sort_keys=True, separators=(',', ':'))
    return sign_event(secret, int(time.time()), REVOCATION_NOSTR_KIND(),
                      [['d', rev['bond_hash']]], content)


def cmd_revoke_import(args):
    with open(args.revocation) as f:
        r = json.load(f)
    assert r.get('protocol') == 'nakama' and r.get('version') == 1 and r.get('type') == 'revocation', \
        'nakama v1 の revocation ではありません'
    b = None
    if args.bond:
        with open(args.bond) as f:
            b = json.load(f)
    if not verify_revocation_event(r, b):
        print('revocation は無効です（registry には記録しません）', file=sys.stderr)
        sys.exit(1)
    registry = args.registry or REVOCATIONS_DEFAULT
    result = import_revocation_event(r, registry)
    if result == 'duplicate':
        print(f'既に registry に記録済みです: {revocation_registry_path(registry, r["bond_hash"])}')
    else:
        print(f'revocation を registry に記録しました: {revocation_registry_path(registry, r["bond_hash"])}')


def cmd_revoke_pub(args):
    """revocation イベントを Nostr リレーに publish (kind 30107, d タグ = bond_hash)。"""
    secret = load_key(args.keyfile)
    with open(args.revocation) as f:
        rev = json.load(f)
    assert rev.get('protocol') == 'nakama' and rev.get('version') == 1 and rev.get('type') == 'revocation', \
        'nakama v1 の revocation ではありません'
    if not verify_revocation_event(rev):
        print('revocation は無効です（publish しません）', file=sys.stderr)
        sys.exit(1)
    ev = revocation_nostr_event(rev, secret)
    accepted, reason = nostr_publish(args.relay, ev, auth_secret=secret if args.auth else None)
    print(f'publish: {"受理" if accepted else "拒否"} ({reason}) id={ev["id"]}')
    sys.exit(0 if accepted else 1)


def cmd_revoke_fetch(args):
    """bond_hash に対する revocation 公開イベント (kind 30107, #d) を購読し、有効なものを registry に取り込む。"""
    secret = load_key(args.keyfile)
    filt = {'kinds': [REVOCATION_NOSTR_KIND()], '#d': [args.bond_hash], 'limit': args.limit}
    sub_id = secrets.token_hex(8)
    events = nostr_request(args.relay, ['REQ', sub_id, filt], auth_secret=secret if args.auth else None)
    registry = args.registry or REVOCATIONS_DEFAULT
    stored = skipped = 0
    for ev in sorted(events, key=lambda e: e.get('created_at', 0)):
        if not verify_event_sig(ev):
            skipped += 1
            continue  # Nostr 署名の無効なイベントは無視
        try:
            r = json.loads(ev['content'])
        except (ValueError, TypeError):
            skipped += 1
            continue  # content が JSON でないイベントは無視
        if not isinstance(r, dict) or r.get('bond_hash') != args.bond_hash:
            skipped += 1
            continue  # bond_hash 不一致（リレーのフィルタが緩い場合の二重チェック）
        result = import_revocation_event(r, registry)
        if result == 'stored':
            stored += 1
            print(f'取り込み: revocation を registry に記録しました (bond {r["bond_hash"][:16]}..., revoker {r["revoker"][:16]}...)')
        else:
            skipped += 1  # duplicate / invalid
    print(f'{len(events)} 件のイベントを取得: {stored} 件を取り込み、{skipped} 件をスキップ')


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
            rows.append((r['bond_hash'][:16], r['revoker'][:16],
                         time.strftime('%Y-%m-%d', time.localtime(r['created_at'])),
                         r.get('reason', '')))
    if not rows:
        print('revocation registry は空です')
        return
    print(f'解消済み bond: {len(rows)} 件')
    for h, revoker, date, reason in rows:
        suffix = f'  理由: {reason}' if reason else ''
        print(f'  {h}...  解消: {revoker}...  ({date}){suffix}')


COMPROMISES_DEFAULT = os.path.expanduser('~/.config/nakama/compromises')
def COMPROMISE_NOSTR_KIND() -> int:
    """key-compromise-declaration の Nostr kind。既定 30108（v0.23 で 30101 から再マップ）。

    NAKAMA_KIND_COMPROMISE で上書き可能。使用時に環境変数を読んで検証する。"""
    return _kind_from_env('NAKAMA_KIND_COMPROMISE', 30108)


def compromise_message(subject_hex: str, declarant_hex: str, created_at: int, withdrawn: bool = False,
                       bond_hash_hex: str = '', reason: str = '', evidence: str = '') -> bytes:
    """key-compromise-declaration の署名対象メッセージ（canonical bytes）。

    bond_hash / reason / evidence は空ならメッセージから除外する（v0.7 の reason 拡張と対称）。
    withdrawn は常に含める（撤回の署名対象になるため）。
    """
    body = {'subject': subject_hex, 'declarant': declarant_hex,
            'created_at': created_at, 'withdrawn': withdrawn,
            'type': 'key-compromise-declaration'}
    if bond_hash_hex:
        body['bond_hash'] = bond_hash_hex
    if reason:
        body['reason'] = reason
    if evidence:
        body['evidence'] = evidence
    canon = json.dumps(body, sort_keys=True, separators=(',', ':'))
    return hashlib.sha256(canon.encode()).digest()


def compromise_registry_path(registry: str, subject_hex: str) -> str:
    return os.path.join(registry, subject_hex + '.json')


def npub_to_hex(npub: str) -> str:
    return NostrPublicKey.from_npub(npub).hex()


def verify_compromise_event(decl: dict) -> bool:
    """key-compromise-declaration イベントの構造・署名検証。"""
    if decl.get('protocol') != 'nakama' or decl.get('version') != 1 or \
            decl.get('type') != 'key-compromise-declaration':
        return False
    try:
        subject_hex = npub_to_hex(decl['subject'])
        declarant_hex = npub_to_hex(decl['declarant'])
    except Exception:
        return False
    bh = decl.get('bond_hash', '')
    if bh and not (isinstance(bh, str) and len(bh) == 64
                   and all(c in '0123456789abcdef' for c in bh)):
        return False
    reason = decl.get('reason', '')
    evidence = decl.get('evidence', '')
    if not isinstance(reason, str) or not isinstance(evidence, str):
        return False
    if not isinstance(decl.get('created_at'), int) or not isinstance(decl.get('withdrawn'), bool):
        return False
    msg = compromise_message(subject_hex, declarant_hex, decl['created_at'],
                             decl['withdrawn'], bh, reason, evidence)
    try:
        return verify_schnorr(decl['declarant'], bytes.fromhex(decl['sig']), msg)
    except Exception:
        return False


# --- v0.9: 侵害宣言の統合（spec §14） ---
# 信頼モデルは §13 のまま（記録はプロトコル、評価は検証者）。ここにあるのは
# ローカル registry を参照するだけの advisory な警告であり、exit コードは変えない。

def hex_to_npub(hexpub: str) -> str | None:
    """64 hex pubkey → npub。変換不能なら None。"""
    try:
        h = (hexpub or '').strip().lower()
        assert len(h) == 64 and all(c in '0123456789abcdef' for c in h)
        return NostrPublicKey.from_hex(h).npub
    except Exception:
        return None


def load_compromise_declarations(subject_hex: str, registry: str | None = None) -> list:
    """subject に対する registry 内の侵害宣言（署名有効、撤回含む）のリスト（オフライン）。"""
    registry = registry or COMPROMISES_DEFAULT
    rp = compromise_registry_path(registry, subject_hex)
    decls = []
    if os.path.exists(rp):
        try:
            with open(rp) as f:
                decls = json.load(f)
        except (json.JSONDecodeError, OSError):
            decls = []
        if not isinstance(decls, list):
            decls = []
    return [d for d in decls if isinstance(d, dict) and verify_compromise_event(d)]


def active_compromise_declarations(subject_hex: str, registry: str | None = None) -> list:
    """subject に対する有効（署名有効・非撤回）の侵害宣言のリスト（オフライン）。"""
    return [d for d in load_compromise_declarations(subject_hex, registry) if not d.get('withdrawn')]


def key_compromise_warnings(npub_or_hex: str, registry_dir: str | None = None) -> list:
    """§14.2: npub に対する侵害宣言（非撤回）が 1 件以上あれば警告文字列のリストを返す。

    参照するのはローカル registry（明示的に compromise_fetch / import 済みの分）のみ — リレーから自動 fetch はしない。
    宣言なし・撤回済みのみ → 空リスト。呼び出し側は stderr に出すだけで、exit コードは変えないこと。
    """
    npub = npub_or_hex if (npub_or_hex or '').startswith('npub1') else hex_to_npub(npub_or_hex or '')
    if not npub:
        return []
    hexpub = npub_to_hex(npub)
    if not hexpub:
        return []
    decls = active_compromise_declarations(hexpub, registry_dir)
    if not decls:
        return []
    n = len(decls)
    return [f'WARN: {npub[:12]}... has {n} active compromise declaration(s) — see: nakama.py key_status {npub}']


def migration_status(subject_hex: str, rotation_chain: list, declarations: list) -> dict:
    """§14.3: rotation チェーンと侵害宣言から「移行完了」状態を判定する（純粋）。

    rotation_chain: rotation 証明書のリスト（チェーン順）。declarations: key-compromise-declaration のリスト。
    戻り値: {'status': 'complete'|'stale'|'broken'|'none', 'chain_npubs': [...], 'rotated_at': int|None,
             'latest_declaration_at': int|None, 'at': int|None, 'reason': str, 'final_hex': str|None}
    """
    empty = {'status': 'none', 'chain_npubs': [], 'rotated_at': None,
             'latest_declaration_at': None, 'at': None, 'reason': '', 'final_hex': None}
    if not rotation_chain:
        return empty
    expected_old = (subject_hex or '').lower()
    chain_npubs = []
    for i, cert in enumerate(rotation_chain):
        if not isinstance(cert, dict) or not verify_rotation_cert(cert):
            return {**empty, 'status': 'broken', 'chain_npubs': chain_npubs,
                    'at': i, 'reason': 'rotation 証明書の署名が無効'}
        old_hex = npub_to_hex(cert.get('old_npub', ''))
        new_hex = npub_to_hex(cert.get('new_npub', ''))
        if not old_hex or not new_hex:
            return {**empty, 'status': 'broken', 'chain_npubs': chain_npubs,
                    'at': i, 'reason': 'npub 形式が不正'}
        if old_hex != expected_old:
            return {**empty, 'status': 'broken', 'chain_npubs': chain_npubs,
                    'at': i, 'reason': 'チェーンが連鎖していない（old_npub != 前リンクの new_npub）'}
        chain_npubs.append(cert['old_npub'])
        expected_old = new_hex
    chain_npubs.append(rotation_chain[-1]['new_npub'])
    final_hex = npub_to_hex(rotation_chain[-1]['new_npub'])
    active = [d for d in declarations
              if isinstance(d, dict) and verify_compromise_event(d) and not d.get('withdrawn')]
    if not active:
        return empty  # 宣言なし → 移行の文脈なし（既存の宣言表示のみ）
    latest_decl = max(d['created_at'] for d in active)
    first_rot = rotation_chain[0].get('created_at')
    status = 'complete' if first_rot is not None and first_rot >= latest_decl else 'stale'
    return {'status': status, 'chain_npubs': chain_npubs, 'rotated_at': first_rot,
            'latest_declaration_at': latest_decl, 'at': None, 'reason': '',
            'final_hex': final_hex}


def import_compromise_event(decl: dict, registry: str) -> str:
    """受け取った侵害宣言を registry に取り込む。戻り値: 'stored' | 'duplicate' | 'updated' | 'invalid'。

    無効な署名のイベントは registry に触れず 'invalid'。declarant + created_at の一致は
    dedup（先勝ち）だが、withdrawn フラグだけが違う場合は撤回・復活の更新として上書きする。
    """
    if not verify_compromise_event(decl):
        return 'invalid'
    subject_hex = npub_to_hex(decl['subject'])
    declarant_hex = npub_to_hex(decl['declarant'])
    os.makedirs(registry, exist_ok=True)
    rp = compromise_registry_path(registry, subject_hex)
    decls = []
    if os.path.exists(rp):
        try:
            with open(rp) as f:
                decls = json.load(f)
        except (json.JSONDecodeError, OSError):
            decls = []
        if not isinstance(decls, list):
            decls = []
    for i, old in enumerate(decls):
        try:
            old_declarant_hex = npub_to_hex(old['declarant'])
        except Exception:
            continue
        if old_declarant_hex == declarant_hex and old.get('created_at') == decl['created_at']:
            if old.get('withdrawn') == decl.get('withdrawn'):
                return 'duplicate'
            decls[i] = decl
            with open(rp, 'w') as f:
                json.dump(decls, f, indent=2)
            os.chmod(rp, 0o600)
            return 'updated'
    decls.append(decl)
    with open(rp, 'w') as f:
        json.dump(decls, f, indent=2)
    os.chmod(rp, 0o600)
    return 'stored'


def compromise_nostr_event(decl: dict, secret: bytes) -> dict:
    """侵害宣言を Nostr 公開用イベント (kind 30108) として構築・署名する。

    kind 30108 は parameterized replaceable: d タグ = subject_hex:declarant_hex。
    同一宣言者の再発行で上書き（withdrawn による撤回）ができる。
    """
    content = json.dumps(decl, sort_keys=True, separators=(',', ':'))
    subject_hex = npub_to_hex(decl['subject'])
    declarant_hex = npub_to_hex(decl['declarant'])
    return sign_event(secret, int(time.time()), COMPROMISE_NOSTR_KIND(),
                      [['d', f'{subject_hex}:{declarant_hex}']], content)


def build_compromise_declaration(secret: bytes, subject: str, created_at: int,
                                 withdrawn: bool = False, bond_hash_hex: str = '',
                                 reason: str = '', evidence: str = '') -> dict:
    """宣言者の鍵で key-compromise-declaration を構築・署名する（純粋、I/O なし）。"""
    me = npub_of(secret)
    msg = compromise_message(npub_to_hex(subject), hexpub_of(secret), created_at,
                             withdrawn, bond_hash_hex, reason, evidence)
    decl = {
        'protocol': 'nakama', 'version': 1, 'type': 'key-compromise-declaration',
        'subject': subject, 'declarant': me,
        'created_at': created_at, 'withdrawn': withdrawn,
        'sig': sign_schnorr(secret, msg).hex(),
    }
    if bond_hash_hex:
        decl['bond_hash'] = bond_hash_hex
    if reason:
        decl['reason'] = reason
    if evidence:
        decl['evidence'] = evidence
    return decl


def cmd_compromise_declare(args):
    secret = load_key(args.keyfile)
    me = npub_of(secret)
    try:
        subject_hex = npub_to_hex(args.subject)
        if subject_hex is None:
            # npub_to_hex の後発の定義は変換不能時に None を返す（例外を
            # 投げない）ため、None も無効として拒否する。None のまま進むと
            # import_compromise_event 内で TypeError になる。
            raise ValueError('invalid npub')
    except Exception:
        print('subject は有効な npub ではありません', file=sys.stderr)
        sys.exit(1)
    bh = ''
    if args.bond:
        with open(args.bond) as f:
            b = json.load(f)
        assert b.get('protocol') == 'nakama' and b.get('version') == 1, 'nakama v1 の bond ではありません'
        if me not in b.get('companions', []):
            print('あなたはこの bond の当事者ではありません', file=sys.stderr)
            sys.exit(1)
        bh = bond_hash(b)
    import time
    decl = build_compromise_declaration(secret, args.subject, int(time.time()),
                                        False, bh, args.reason or '', args.evidence or '')
    out = args.out or 'compromise.json'
    with open(out, 'w') as f:
        json.dump(decl, f, indent=2)
    print(f'侵害宣言: {out} — {me[:16]}... が {args.subject[:16]}... の鍵は危ないと宣言しました。')
    if not args.no_registry:
        registry = args.registry or COMPROMISES_DEFAULT
        result = import_compromise_event(decl, registry)
        if result == 'stored':
            print(f'ローカル registry に記録しました: {compromise_registry_path(registry, subject_hex)}')
    print('宣言は公開チャネルで共有してください（仲間の公開記録に残ります）。虚偽の宣言はあなたの署名付きで残ることを忘れずに。')


def cmd_compromise_import(args):
    with open(args.declaration) as f:
        decl = json.load(f)
    assert decl.get('protocol') == 'nakama' and decl.get('version') == 1 and \
        decl.get('type') == 'key-compromise-declaration', \
        'nakama v1 の key-compromise-declaration ではありません'
    if not verify_compromise_event(decl):
        print('侵害宣言は無効です（registry には記録しません）', file=sys.stderr)
        sys.exit(1)
    if args.subject:
        try:
            if npub_to_hex(args.subject) != npub_to_hex(decl['subject']):
                print('侵害宣言の subject が指定と一致しません（registry には記録しません）', file=sys.stderr)
                sys.exit(1)
        except Exception:
            print('subject は有効な npub ではありません', file=sys.stderr)
            sys.exit(1)
    registry = args.registry or COMPROMISES_DEFAULT
    result = import_compromise_event(decl, registry)
    rp = compromise_registry_path(registry, npub_to_hex(decl['subject']))
    if result == 'duplicate':
        print(f'既に registry に記録済みです: {rp}')
    elif result == 'updated':
        print(f'registry を更新しました（撤回・復活）: {rp}')
    else:
        print(f'侵害宣言を registry に記録しました: {rp}')


def cmd_compromise_pub(args):
    """侵害宣言を Nostr リレーに publish (kind 30108, d タグ = subject_hex:declarant_hex)。"""
    secret = load_key(args.keyfile)
    with open(args.declaration) as f:
        decl = json.load(f)
    assert decl.get('protocol') == 'nakama' and decl.get('version') == 1 and \
        decl.get('type') == 'key-compromise-declaration', \
        'nakama v1 の key-compromise-declaration ではありません'
    if not verify_compromise_event(decl):
        print('侵害宣言は無効です（publish しません）', file=sys.stderr)
        sys.exit(1)
    ev = compromise_nostr_event(decl, secret)
    accepted, reason = nostr_publish(args.relay, ev, auth_secret=secret if args.auth else None)
    print(f'publish: {"受理" if accepted else "拒否"} ({reason}) id={ev["id"]}')
    sys.exit(0 if accepted else 1)


def cmd_compromise_fetch(args):
    """subject に対する侵害宣言の公開イベント (kind 30108) を購読し、有効なものを registry に取り込む。"""
    secret = load_key(args.keyfile)
    try:
        subject_hex = npub_to_hex(args.npub)
    except Exception:
        print('npub は有効ではありません', file=sys.stderr)
        sys.exit(1)
    filt = {'kinds': [COMPROMISE_NOSTR_KIND()], 'limit': args.limit}
    sub_id = secrets.token_hex(8)
    events = nostr_request(args.relay, ['REQ', sub_id, filt], auth_secret=secret if args.auth else None)
    registry = args.registry or COMPROMISES_DEFAULT
    stored = updated = skipped = 0
    prefix = subject_hex + ':'
    for ev in sorted(events, key=lambda e: e.get('created_at', 0)):
        if not verify_event_sig(ev):
            skipped += 1
            continue  # Nostr 署名の無効なイベントは無視
        dtags = [t[1] for t in ev.get('tags', []) if len(t) >= 2 and t[0] == 'd']
        if not any(d.startswith(prefix) for d in dtags):
            skipped += 1
            continue  # subject と関係ない宣言は無視（クライアント側 prefix フィルタ、§13.5）
        try:
            decl = json.loads(ev['content'])
        except (ValueError, TypeError):
            skipped += 1
            continue  # content が JSON でないイベントは無視
        if not isinstance(decl, dict):
            skipped += 1
            continue
        try:
            if npub_to_hex(decl.get('subject', '')) != subject_hex:
                skipped += 1
                continue  # subject 不一致（二重チェック）
        except Exception:
            skipped += 1
            continue
        result = import_compromise_event(decl, registry)
        if result == 'stored':
            stored += 1
            print(f'取り込み: 侵害宣言を registry に記録しました (subject {subject_hex[:16]}..., declarant {decl["declarant"][:16]}...)')
        elif result == 'updated':
            updated += 1
            print(f'更新: 侵害宣言の撤回・復活を反映しました (declarant {decl["declarant"][:16]}...)')
        else:
            skipped += 1  # duplicate / invalid
    print(f'{len(events)} 件のイベントを取得: {stored} 件を取り込み、{updated} 件を更新、{skipped} 件をスキップ')


def cmd_compromise_withdraw(args):
    """自分の侵害宣言を withdrawn: true で再発行する（公開済みなら compromise_pub で上書き）。"""
    secret = load_key(args.keyfile)
    me = npub_of(secret)
    try:
        subject_hex = npub_to_hex(args.subject)
        if subject_hex is None:
            # npub_to_hex の後発の定義は変換不能時に None を返す（例外を
            # 投げない）ため、None も無効として拒否する。None のまま進むと
            # compromise_registry_path 内で TypeError になる。
            raise ValueError('invalid npub')
    except Exception:
        print('subject は有効な npub ではありません', file=sys.stderr)
        sys.exit(1)
    registry = args.registry or COMPROMISES_DEFAULT
    rp = compromise_registry_path(registry, subject_hex)
    target = None
    if os.path.exists(rp):
        try:
            with open(rp) as f:
                decls = json.load(f)
        except (json.JSONDecodeError, OSError):
            decls = []
        mine = [d for d in decls if isinstance(d, dict) and not d.get('withdrawn')
                and verify_compromise_event(d) and d.get('declarant') == me]
        if mine:
            target = max(mine, key=lambda d: d['created_at'])
    if target is None:
        print(f'あなた（{me[:16]}...）の有効な侵害宣言が registry にありません: {args.subject[:16]}...', file=sys.stderr)
        sys.exit(1)
    import time
    decl = build_compromise_declaration(secret, target['subject'], target['created_at'],
                                        True, target.get('bond_hash', ''),
                                        target.get('reason', ''), target.get('evidence', ''))
    result = import_compromise_event(decl, registry)
    out = args.out or 'compromise_withdrawn.json'
    with open(out, 'w') as f:
        json.dump(decl, f, indent=2)
    if result == 'updated':
        print(f'侵害宣言を撤回しました: {out}（registry の記録を withdrawn: true に更新）')
        print('公開済みの宣言は compromise_pub で上書きしてください（kind 30108 の replaceable で撤回が効きます）。')
    else:
        print(f'撤回を記録しました: {result}', file=sys.stderr)


def key_status(subject_npub: str, registry: str, me_npub: str | None,
               bonds: list, threshold: int = 2) -> dict:
    """subject の侵害宣言状態を評価する（純粋に近い: registry 読み＋判定）。

    戻り値: {'declarations': [...], 'suspected_count': int, 'suspected': bool,
             'withdrawn_count': int, 'invalid_count': int}
    宣言は自分の bond graph（me の当事者である bond ファイル）で重みづける（§13.3）。
    """
    try:
        subject_hex = npub_to_hex(subject_npub)
    except Exception:
        return {'declarations': [], 'suspected_count': 0, 'suspected': False,
                'withdrawn_count': 0, 'invalid_count': 0, 'error': 'npub が無効です'}
    rp = compromise_registry_path(registry, subject_hex)
    decls = []
    if os.path.exists(rp):
        try:
            with open(rp) as f:
                decls = json.load(f)
        except (json.JSONDecodeError, OSError):
            decls = []
        if not isinstance(decls, list):
            decls = []
    # 自分の bond graph: me が当事者の bond の相手たち
    companions = set()
    bond_by_hash = {}
    for b in bonds:
        if not isinstance(b, dict) or b.get('protocol') != 'nakama' or b.get('version') != 1:
            continue
        comps = b.get('companions', [])
        if me_npub is not None and me_npub in comps:
            companions.update(c for c in comps if c != me_npub)
        bond_by_hash[bond_hash(b)] = comps
    rows = []
    counted = set()
    withdrawn_count = invalid_count = 0
    for d in decls:
        if not isinstance(d, dict) or not verify_compromise_event(d):
            invalid_count += 1
            continue
        declarant = d['declarant']
        withdrawn = d.get('withdrawn', False)
        if withdrawn:
            withdrawn_count += 1
            rows.append({'declarant': declarant, 'created_at': d['created_at'],
                         'reason': d.get('reason', ''), 'withdrawn': True,
                         'category': '撤回済み'})
            continue
        # 重みづけカテゴリ（§13.3）
        if me_npub is not None and declarant == me_npub:
            cat = '自分自身'
        elif declarant in companions:
            cat = '直接の仲間'
        elif d.get('bond_hash') and d['bond_hash'] in bond_by_hash \
                and declarant in bond_by_hash[d['bond_hash']] \
                and subject_npub in bond_by_hash[d['bond_hash']]:
            cat = 'subject を知る仲間'
        else:
            cat = '参考情報'
        rows.append({'declarant': declarant, 'created_at': d['created_at'],
                     'reason': d.get('reason', ''), 'withdrawn': False,
                     'category': cat})
        if cat != '参考情報':
            counted.add(declarant)
    suspected_count = len(counted)
    return {'declarations': sorted(rows, key=lambda r: r['created_at']),
            'suspected_count': suspected_count,
            'suspected': suspected_count >= threshold,
            'withdrawn_count': withdrawn_count, 'invalid_count': invalid_count}


def cmd_key_status(args):
    me = None
    if os.path.exists(args.keyfile):
        try:
            me = npub_of(load_key(args.keyfile))
        except Exception:
            me = None
    bonds = []
    for bp in args.bond or []:
        try:
            with open(bp) as f:
                bonds.append(json.load(f))
        except (OSError, json.JSONDecodeError):
            print(f'bond ファイルを読めません: {bp}', file=sys.stderr)
    registry = args.registry or COMPROMISES_DEFAULT
    st = key_status(args.npub, registry, me, bonds, args.threshold)
    if 'error' in st:
        print(st['error'], file=sys.stderr)
        sys.exit(1)
    print(f'subject: {args.npub[:16]}... の侵害宣言: {len(st["declarations"])} 件（有効な宣言、撤回済み {st["withdrawn_count"]} 件を除く）')
    for r in st['declarations']:
        date = time.strftime('%Y-%m-%d', time.localtime(r['created_at']))
        suffix = f'  理由: {r["reason"]}' if r['reason'] else ''
        w = '（撤回済み）' if r['withdrawn'] else ''
        print(f'  {r["declarant"][:16]}...  [{r["category"]}] ({date}){w}{suffix}')
    if st['invalid_count']:
        print(f'  ※ 署名無効な宣言 {st["invalid_count"]} 件は無視しました')
    # §14.3: rotation チェーンによる「移行完了」の表示
    if args.rotation:
        chain = []
        for rp in args.rotation:
            try:
                with open(rp) as f:
                    chain.append(json.load(f))
            except (OSError, json.JSONDecodeError):
                print(f'rotation ファイルを読めません: {rp}', file=sys.stderr)
                chain.append(None)
        subject_hex = npub_to_hex(args.npub)
        decls = load_compromise_declarations(subject_hex, registry)
        mig = migration_status(subject_hex, chain, decls)
        arrow = ' -> '.join(n[:12] + '...' for n in mig['chain_npubs'])
        if mig['status'] == 'complete':
            rd = time.strftime('%Y-%m-%d', time.localtime(mig['rotated_at']))
            ld = time.strftime('%Y-%m-%d', time.localtime(mig['latest_declaration_at']))
            new_active = active_compromise_declarations(mig['final_hex'], registry)
            extra = ' — 新鍵への有効な宣言はありません' if not new_active \
                else f' — 注意: 新鍵にも {len(new_active)} 件の有効な宣言があります'
            print(f'migration: complete ({arrow}) — rotated at {rd}, after latest declaration at {ld}{extra}')
        elif mig['status'] == 'stale':
            rd = time.strftime('%Y-%m-%d', time.localtime(mig['rotated_at']))
            ld = time.strftime('%Y-%m-%d', time.localtime(mig['latest_declaration_at']))
            print(f'migration: stale ({arrow}) — rotation は {rd}、最新の宣言は {ld} より新しい。'
                  '今回の移行の証拠になりません')
        elif mig['status'] == 'broken':
            print(f'migration: broken — {mig["reason"]} (link {mig["at"]})')
        # none: 宣言の表示のみ（セクションなし）
    # 反証: subject の liveness が宣言より新しいか
    if args.liveness:
        try:
            with open(args.liveness) as f:
                p = json.load(f)
            now = int(time.time())
            if verify_liveness_event(p) and p.get('npub') == args.npub \
                    and p['created_at'] <= now + 300 and now - p['created_at'] <= args.max_age:
                newest = max((r['created_at'] for r in st['declarations'] if not r['withdrawn']), default=0)
                if p['created_at'] > newest:
                    print(f'反証あり: subject の新しい生存証明（{now - p["created_at"]} 秒前）が宣言より新しい — 判断はあなたに委ねます。')
                else:
                    print('生存証明は宣言より古いため反証になりません。')
            else:
                print('生存証明は無効または期限切れです（反証として使えません）。')
        except (OSError, json.JSONDecodeError):
            print('生存証明ファイルを読めません', file=sys.stderr)
    if st['suspected']:
        print(f'判定: 疑わしい（compromised suspected）— bond graph 内の宣言者 {st["suspected_count"]} 人 ≥ 閾値 {args.threshold}')
        sys.exit(1)
    if any(not r['withdrawn'] for r in st['declarations']):
        print(f'判定: 宣言はあるが閾値未満（{st["suspected_count"]} / {args.threshold}）— 警告として扱ってください。')
    else:
        print('判定: 侵害宣言はありません。')


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


def dm_incoming(secret: bytes, relay: str, since: int | None, auth: bool,
                limit: int = 500) -> list:
    """自分宛の gift wrap (kind 1059, #p 自分) を購読し、復号できた rumor を created_at 昇順で返す。
    cmd_dm_fetch と board_notif_status (spec §28.4) が共有する fetch+unwrap ロジック。
    復号できない wrap は無視する。ネットワーク失敗は nostr_request の例外をそのまま伝える。"""
    my_hexpub = hexpub_of(secret)
    filt = {'kinds': [1059], '#p': [my_hexpub], 'limit': limit}
    if since:
        filt['since'] = since
    sub_id = secrets.token_hex(8)
    events = nostr_request(relay, ['REQ', sub_id, filt],
                           auth_secret=secret if auth else None)
    rumors = []
    for ev in sorted(events, key=lambda e: e.get('created_at', 0)):
        try:
            rumors.append(nip17_unwrap(ev, secret))
        except (ValueError, AssertionError, KeyError):
            continue  # 自分向けに復号できない gift wrap は無視
    return rumors


def cmd_dm_fetch(args):
    """自分宛の gift wrap (kind 1059, #p 自分) を購読し、復号して rumor を表示。"""
    secret = load_key(args.keyfile)
    rumors = dm_incoming(secret, args.relay, args.since, args.auth, limit=args.limit)
    for rumor in rumors:
        ts = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(rumor.get('created_at', 0)))
        print(f"--- [{ts}] from {rumor['pubkey'][:16]}...")
        print(rumor['content'])
    if not rumors:
        print('新しい DM はありませんでした')


def cmd_dm_send(args):
    secret = load_key(args.keyfile)
    try:
        recipient_hexpub = NostrPublicKey.from_npub(args.npub).hex()
    except Exception:
        print('npub の形式が不正です'); sys.exit(1)
    # §14.2: 宛先への侵害宣言の警告（stderr のみ — stdout の gift wrap JSON は汚さない。exit コード不変）
    for w in key_compromise_warnings(args.npub, getattr(args, 'compromise_registry', None) or COMPROMISES_DEFAULT):
        print(w, file=sys.stderr)
    seal = nip17_build_seal(secret, recipient_hexpub, args.message)
    wrap = nip17_build_gift_wrap(seal, recipient_hexpub)
    if args.out:
        with open(args.out, 'w') as f:
            json.dump(wrap, f, indent=2)
        print(f'gift wrap (kind 1059) を {args.out} に保存しました。publish は dm_pub で実行してください。')
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
    # §14.2: descriptor の signer（board 運営者）への侵害宣言の警告（advisory — exit コード不変）
    if d.get('moderators'):
        for w in key_compromise_warnings(d['moderators'][0],
                                         getattr(args, 'compromise_registry', None) or COMPROMISES_DEFAULT):
            print(w, file=sys.stderr)
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
    # §14.2: 送信者・（--descriptor 指定時は）board 運営鍵への侵害宣言の警告（advisory — exit コード不変）
    creg = getattr(args, 'compromise_registry', None) or COMPROMISES_DEFAULT
    for w in key_compromise_warnings(npub_of(secret), creg):
        print(w, file=sys.stderr)
    if getattr(args, 'descriptor', None):
        try:
            with open(args.descriptor) as f:
                d = json.load(f)
            mods = d.get('moderators') or []
            if mods:
                for w in key_compromise_warnings(mods[0], creg):
                    print(w + ' — この板の運営鍵（board descriptor の signer）に疑念あり', file=sys.stderr)
        except (OSError, json.JSONDecodeError, KeyError):
            print('descriptor を読めません（警告を省略）', file=sys.stderr)
    ev = sign_event(secret, int(time.time()), 9, [['h', args.board_id]], args.message)
    accepted, reason = nostr_publish(args.relay, ev, auth_secret=secret if args.auth else None)
    print(f'投稿: {"受理" if accepted else "拒否"} ({reason}) id={ev["id"]}')
    sys.exit(0 if accepted else 1)


def cmd_board_read(args):
    """広場の投稿を購読・表示: kind 9 + #h フィルタ。署名の無効なイベントは無視する。"""
    if args.governance:
        cmd_board_governance(args)
        return
    sub_id = secrets.token_hex(8)
    filt = {'kinds': [9], '#h': [args.board_id], 'limit': args.limit}
    if args.since:
        filt['since'] = args.since
    auth_secret = load_key(args.keyfile) if args.auth else None
    events = nostr_request(args.relay, ['REQ', sub_id, filt], auth_secret=auth_secret)
    creg = getattr(args, 'compromise_registry', None) or COMPROMISES_DEFAULT
    warn_cache = {}  # §14.2: issuer ごとの侵害宣言チェック結果（registry 読みは 1 鍵 1 回）

    def _issuer_flag(pubkey_hex):
        if pubkey_hex not in warn_cache:
            npub = hex_to_npub(pubkey_hex)
            warn_cache[pubkey_hex] = bool(npub and key_compromise_warnings(npub, creg))
        return ' ⚠ compromised?' if warn_cache[pubkey_hex] else ''

    shown = 0
    for ev in sorted(events, key=lambda e: e.get('created_at', 0)):
        if not verify_event_sig(ev):
            continue
        shown += 1
        ts = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(ev.get('created_at', 0)))
        print(f"--- [{ts}] {ev['pubkey'][:16]}...{_issuer_flag(ev['pubkey'])}")
        print(ev['content'])
    if not shown:
        print('投稿はまだありません')


def cmd_challenge(args):
    print(secrets.token_hex(32))
    # §14.2: --to で宛先 npub が分かれば侵害宣言の警告（advisory — exit コード不変）
    if getattr(args, 'to', None):
        for w in key_compromise_warnings(args.to, getattr(args, 'compromise_registry', None) or COMPROMISES_DEFAULT):
            print(w, file=sys.stderr)


def cmd_respond(args):
    secret = load_key(args.keyfile)
    nonce = bytes.fromhex(args.nonce)
    assert len(nonce) == 32, 'nonce は32バイトのhexである必要があります'
    print(sign_schnorr(secret, nonce).hex())


def cmd_check(args):
    ok = verify_schnorr(args.npub, bytes.fromhex(args.sig), bytes.fromhex(args.nonce))
    print('本人です 🤝' if ok else '検証失敗')
    # §14.2: response 署名者（対手）への侵害宣言の警告（advisory — exit コード不変）
    for w in key_compromise_warnings(args.npub, getattr(args, 'compromise_registry', None) or COMPROMISES_DEFAULT):
        print(w, file=sys.stderr)
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
    # §16: verify_binding 時の侵害警告 — 署名・platform・handle 検証の後、対象 npub への
    # 非撤回宣言があれば stderr に WARN（advisory、exit コード不変）。署名無効でも出す（情報は直交）。
    creg = getattr(args, 'compromise_registry', None) or COMPROMISES_DEFAULT
    subj = b.get('npub')
    if subj:
        for w in key_compromise_warnings(subj, creg):
            print(w, file=sys.stderr)
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


BOARD_DECISION_TYPES = ('admit', 'handover', 'policy-update', 'close', 'remove')


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


def _expires_at_ok(payload: dict) -> bool:
    """payload の任意フィールド expires_at の型チェック（spec §24.1）。

    キーなし → True（後方互換・無期限）。int（bool 除外）のみ受理。
    """
    if 'expires_at' not in payload:
        return True
    exp = payload['expires_at']
    return isinstance(exp, int) and not isinstance(exp, bool)


def validate_decision_payload(decision: str, payload: dict) -> bool:
    """決定種別ごとの payload 形式チェック。

    v0.19 (spec §24.1): 全決定種別で任意フィールド expires_at（unix 時刻 int、
    署名対象）を許可。キー集合のチェックは expires_at を除いたベースで行い、
    型チェックは _expires_at_ok に委譲。"""
    if not isinstance(payload, dict):
        return False
    if decision == 'admit':
        if set(payload.keys()) - {'expires_at'} != {'candidate'}:
            return False
        return _expires_at_ok(payload)
    if decision == 'handover':
        keys = set(payload.keys()) - {'expires_at'}
        if keys not in ({'new_moderators'}, {'new_moderators', 'old_moderators'}):
            return False
        if not (isinstance(payload['new_moderators'], list)
                and all(isinstance(n, str) for n in payload['new_moderators'])):
            return False
        if 'old_moderators' in payload:
            if not (isinstance(payload['old_moderators'], list)
                    and all(isinstance(n, str) for n in payload['old_moderators'])):
                return False
            return _expires_at_ok(payload)
        return _expires_at_ok(payload)
    if decision == 'policy-update':
        # v0.6 (spec §11.2): 範囲検証。threshold は 1..len(eligible) の int、
        # eligible は空・重複なしの npub リスト。
        if set(payload.keys()) - {'expires_at'} != {'threshold', 'eligible'}:
            return False
        elig = payload['eligible']
        if not (isinstance(elig, list) and elig
                and all(isinstance(x, str) for x in elig)
                and len(set(elig)) == len(elig)):
            return False
        th = payload['threshold']
        return ((isinstance(th, int) and not isinstance(th, bool)
                and 1 <= th <= len(elig))
                and _expires_at_ok(payload))
    if decision == 'close':
        if set(payload.keys()) - {'expires_at'} != {'reason'}:
            return False
        return _expires_at_ok(payload)
    if decision == 'remove':
        # v0.13 (spec §18.3): キー集合 {'candidate'} または {'candidate','reason'}。
        # candidate は文字列。npub 形式の厳密検証はしない — 照合時の
        # npub_to_hex が None を返して自然に不整合になる (admit と同型)。
        # reason は署名対象に含める（改ざん検出 — §18.2）。
        keys = set(payload.keys()) - {'expires_at'}
        if keys not in ({'candidate'}, {'candidate', 'reason'}):
            return False
        if not isinstance(payload['candidate'], str):
            return False
        if 'reason' in payload and not isinstance(payload['reason'], str):
            return False
        return _expires_at_ok(payload)
    return False


def draft_is_expired(d: dict, now: int) -> bool:
    """草案の期限切れ判定（純粋、spec §24.2）。

    payload の任意フィールド expires_at（unix 時刻 int）が now 以下なら
    True。期限なし（キーなし）→ False（無期限・後方互換）。
    不正な型（非 int）は validate 側の管轄 — ここでは期限なし扱い（False）。
    時計ずれへの注記: now は呼び出し側のホスト時刻（NTP 前提）。テストでは
    time.time() をモック可能にするためこの分離が必要。
    """
    try:
        exp = d.get('payload', {}).get('expires_at')
    except AttributeError:
        return False
    if exp is None:
        return False
    if not (isinstance(exp, int) and not isinstance(exp, bool)):
        return False
    return exp <= now


def _verify_decision_core(d: dict, threshold: int, eligible: list,
                        board_id: str, relay: str):
    """board-decision 検証の政策依存コア (spec §11.2)。

    政策 (threshold, eligible) を外部から与えることで、決定時点の政策で
    決定の有効性を判定できる（時点政策の解決）。規約 cert の有効性は
    呼び出し側の前提とする。
    """
    if not (d.get('protocol') == 'nakama' and d.get('version') == 1
            and d.get('type') == 'board-decision'):
        return (False, 0, 0)
    try:
        if d.get('decision') not in BOARD_DECISION_TYPES:
            return (False, 0, 0)
        if not validate_decision_payload(d['decision'], d.get('payload')):
            return (False, 0, 0)
        if d['board_id'] != board_id or d['relay'] != relay:
            return (False, 0, 0)
        msg = board_decision_message(d['board_id'], d['relay'], d['decision'],
                                     d['payload'], int(d['created_at']))
        elig = set(eligible)
        good = set()
        for a in d.get('approvals', []):
            if a['npub'] not in elig:
                continue
            if verify_schnorr(a['npub'], bytes.fromhex(a['sig']), msg):
                good.add(a['npub'])
        return (len(good) >= int(threshold), len(good), int(threshold))
    except Exception:
        return (False, 0, 0)


def verify_board_decision(d: dict, policy: dict):
    """board-decision の検証。(ok, 承認署名数, threshold) を返す。

    承認署名のうち、現行 policy の eligible に含まれる異なる npub の有効署名が
    threshold 以上あることを確認する。部外者の署名は無視し、重複は 1 と数える。
    v0.6: _verify_decision_core の薄いラッパ（既存の呼び出し互換を維持）。
    時点政策で検証したい場合は resolve_policy_at + _verify_decision_core を使う。
    """
    if not verify_board_policy_cert(policy):
        return (False, 0, 0)
    return _verify_decision_core(d, int(policy['threshold']), policy['eligible'],
                                 policy['board_id'], policy['relay'])


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
    # v0.5 (spec §10.2): handover の旧運営リストを --old-moderators で明示できる。
    # payload の JSON よりコマンドラインが優先（指定時のみ上書き）。
    if args.decision == 'handover' and args.old_moderators is not None:
        payload = dict(payload)
        payload['old_moderators'] = list(args.old_moderators)
    if not validate_decision_payload(args.decision, payload):
        print(f"payload の形式が decision '{args.decision}' に適合しません", file=sys.stderr)
        sys.exit(1)
    created_at = int(time.time())
    # v0.19 (spec §24.1): 草案の期限。--expires-at が --expires-in に優先。
    # --expires-in は created_at + 秒で換算。expires_at <= created_at は
    # clean fail（生まれてすぐ死ぬ草案は作らせない）。
    expires_at = None
    if getattr(args, 'expires_at', None) is not None:
        expires_at = args.expires_at
    elif getattr(args, 'expires_in', None) is not None:
        expires_at = created_at + args.expires_in
    if expires_at is not None:
        if expires_at <= created_at:
            print(f'expires_at ({expires_at}) は created_at ({created_at})'
                  ' より未来の時刻である必要があります', file=sys.stderr)
            sys.exit(1)
        payload = dict(payload)
        payload['expires_at'] = expires_at
        if not validate_decision_payload(args.decision, payload):
            print(f"payload の形式が decision '{args.decision}' に適合しません",
                  file=sys.stderr)
            sys.exit(1)
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
    # v0.19 (spec §24.2): 期限切れの草案には署名しない — ゾンビ草案対策の主軸。
    if draft_is_expired(d, int(time.time())):
        print(f'草案は期限切れです（expires_at {d["payload"]["expires_at"]}）'
              ' — 署名しません', file=sys.stderr)
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


# --- v0.14: board-decision の Nostr 公開（spec §19） ---

# §12 / §13 / §17 の *_pub パターン（parameterized replaceable kind ＋
# nostr_publish / nostr_request / --auth ヘルパ）の流用。kind 30110 を定義する。
# 決定の有効性は threshold の approvals が証明するものであり、Nostr イベントの
# 署名者 = publisher（決定の署名者ではない）。決定を保持する任意の仲間が
# publish できる — keyfile の鍵と決定の関係は問わない（意図的な設計、§19.3）。

def DECISION_NOSTR_KIND() -> int:
    """board-decision（成立済み）の Nostr kind。既定 30110（v0.23 で 30103 から再マップ）。

    NAKAMA_KIND_DECISION で上書き可能。使用時に環境変数を読んで検証する。"""
    return _kind_from_env('NAKAMA_KIND_DECISION', 30110)


def DRAFT_NOSTR_KIND() -> int:
    """決定前の草案（cosign 回覧中）の Nostr kind。既定 30111（v0.23 で 30104 から再マップ）。

    NAKAMA_KIND_DRAFT で上書き可能。使用時に環境変数を読んで検証する。
    parameterized replaceable、nakama 独自割当。d タグは DECISION_NOSTR_KIND() と同一の
    decision_core_hash（草案→完成の対応付け）。"""
    return _kind_from_env('NAKAMA_KIND_DRAFT', 30111)


def decision_core_hash(d: dict) -> str:
    """決定の不変部分の sha256 の先頭 32 hex（§19.2）。

    board_cosign で approvals が後から追加されるため、決定全体のハッシュは
    スロットを安定させない。不変部分（board_id / decision / created_at /
    payload の canonical JSON）だけをハッシュする純粋関数。
    """
    canon = json.dumps(
        {'board_id': d['board_id'], 'decision': d['decision'],
         'created_at': d['created_at'], 'payload': d['payload']},
        sort_keys=True, separators=(',', ':'), ensure_ascii=False,
    )
    return hashlib.sha256(canon.encode('utf-8')).hexdigest()[:32]


def decision_structure_ok(d: dict) -> bool:
    """board-decision の構造検証（§19.4 の 3）。threshold 検証はしない — 政策が
    必要なため board_read --governance の管轄。"""
    if not (isinstance(d, dict) and d.get('protocol') == 'nakama'
            and d.get('version') == 1 and d.get('type') == 'board-decision'):
        return False
    try:
        if d.get('decision') not in BOARD_DECISION_TYPES:
            return False
        if not validate_decision_payload(d['decision'], d.get('payload')):
            return False
        return True
    except Exception:
        return False


def decision_nostr_event(d: dict, secret: bytes, kind: int | None = None) -> dict:
    """board-decision を Nostr 公開用イベントとして構築・署名する（純粋、spec §21.4）。

    kind 既定値の 30110 は完成決定（§19）、30111 は決定前の草案（§21）。
    既定は DECISION_NOSTR_KIND() を使用時に解決する（環境変数上書きに対応）。
    d タグ = decision_core_hash（approvals 追記でもスロット安定）、
    h タグ = board_id、content = 決定 JSON の canonical（approvals を含む最新版）。
    イベントの署名者は publisher（§19.3 — keyfile の鍵をそのまま使う。
    草案も同一の設計判断: 草案の有効性は threshold approvals が証明する）。
    """
    core = decision_core_hash(d)
    if kind is None:
        kind = DECISION_NOSTR_KIND()
    content = json.dumps(d, sort_keys=True, separators=(',', ':'),
                         ensure_ascii=False)
    return sign_event(secret, int(time.time()), kind,
                      [['d', core], ['h', d['board_id']]], content)


def board_decision_nostr_event(d: dict, secret: bytes) -> dict:
    """完成決定 (kind 30110) のイベント構築 — decision_nostr_event の既定値ラッパー（互換用）。"""
    return decision_nostr_event(d, secret)


def verify_board_decision_nostr_event(ev: dict, board_id: str,
                                      expect_kind: int | None = None) -> dict | None:
    """Nostr イベントから board-decision を取り出す三段階検証（純粋）。

    1. Nostr イベント署名の検証
    2. content の JSON パース
    3. 構造検証（decision_structure_ok）＋ d タグ == decision_core_hash(content)
       の再計算一致 ＋ h タグ == content の board_id == 指定 board_id（リレーの
       フィルタが緩い場合の二重チェック）
    threshold の検証はしない（policy が必要）。受理なら決定 dict、無効なら None。
    草案 (kind 30111) は expect_kind=DRAFT_NOSTR_KIND() で検証する（§21）——
    承認不足の草案は正常状態であり、threshold 検証は行わない。
    既定の expect_kind は DECISION_NOSTR_KIND() を使用時に解決する（環境変数上書きに対応）。
    """
    if expect_kind is None:
        expect_kind = DECISION_NOSTR_KIND()
    if ev.get('kind') != expect_kind:
        return None  # kind が期待と違う（30110/30111 の混入を拒否）
    if not verify_event_sig(ev):
        return None
    try:
        d = json.loads(ev['content'])
    except (ValueError, TypeError):
        return None
    if not decision_structure_ok(d):
        return None
    try:
        if d['board_id'] != board_id:
            return None  # 指定の board と関係ない決定（二重チェック）
    except KeyError:
        return None
    dtags = [t[1] for t in ev.get('tags', []) if len(t) >= 2 and t[0] == 'd']
    if decision_core_hash(d) not in dtags:
        return None  # d タグと content のコアハッシュの不一致
    htags = [t[1] for t in ev.get('tags', []) if len(t) >= 2 and t[0] == 'h']
    if board_id not in htags:
        return None  # h タグと content の board_id の不一致
    return d


def merge_decision_approvals(decisions: list) -> list:
    """同一コアハッシュの決定を approvals マージした一覧にする（純粋、§19.4）。

    第三者が別 pubkey で publish した、または追記後に再 publish した同一コアの
    決定を収集し、npub で dedup（重複は 1 つに）した approvals の和集合を取る。
    署名の有効性判定は governance 側（board_read --governance）の管轄。入力の
    dict は破壊しない。created_at 昇順で返す。
    """
    merged = {}
    order = {}
    for d in decisions:
        core = decision_core_hash(d)
        if core not in merged:
            merged[core] = dict(d)
            merged[core]['approvals'] = []
            order[core] = d.get('created_at', 0)
        seen = {a.get('npub') for a in merged[core]['approvals']}
        for a in d.get('approvals', []):
            if a.get('npub') not in seen:
                merged[core]['approvals'].append(a)
                seen.add(a.get('npub'))
    return [merged[c] for c in sorted(order, key=lambda c: order[c])]


def cmd_board_decide_pub(args):
    """board-decision を Nostr リレーに publish (kind 30110, d タグ = コアハッシュ)。署名者は publisher。"""
    secret = load_key(args.keyfile)
    with open(args.decision) as f:
        d = json.load(f)
    if not decision_structure_ok(d):
        print('board-decision は無効です（構造違反 — publish しません）',
              file=sys.stderr)
        sys.exit(1)
    ev = board_decision_nostr_event(d, secret)
    accepted, reason = nostr_publish(args.relay, ev, auth_secret=secret if args.auth else None)
    print(f'publish: {"受理" if accepted else "拒否"} ({reason}) id={ev["id"]}')
    sys.exit(0 if accepted else 1)


def fetch_threshold_status(d: dict, policy: dict, decisions: list):
    """fetch した決定の threshold 充足状態 (spec §20.3)。純粋・オフライン。

    決定時点の政策を resolve_policy_at で解決（自分自身の policy-update は
    除外 — governance の temporal_valid_decisions と同一の意味論）、
    _verify_decision_core で充足を判定し、(ok, n, m) を返す。
    n = eligible 中の有効署名数（部外者は無視・重複は 1）、
    m = 決定時点の eligible 数。規約 cert の有効性は呼び出し側
    （--policy の事前検証）の前提とする。
    """
    others = [o for o in decisions if o is not d]
    threshold, eligible = resolve_policy_at(policy, others, int(d.get('created_at', 0)))
    ok, n, _ = _verify_decision_core(d, threshold, eligible,
                                     policy['board_id'], policy['relay'])
    return ok, n, len(eligible)


def draft_threshold_line(d: dict, ok: bool, n: int, m: int) -> str:
    """草案の threshold 表示行（spec §21.5 / §29.4）。純粋。

    n/m は fetch_threshold_status で現行政策のみで判定した値（草案の
    payload が提案する値は判定に使わない — 提案は効力ではない、§29.2）。
    policy-update 草案には判定基準と提案値の両方を出す:
    例 `草案: threshold 2/3 不足（現行規約の判定） — 提案値: threshold 2/5`。
    """
    status = '充足（成立可能 — board_decide_pub で成立公開）' if ok else '不足'
    line = f'草案: threshold {n}/{m} {status}'
    if d.get('decision') == 'policy-update':
        p = d.get('payload') or {}
        elig = p.get('eligible') or []
        line += (f'（現行規約の判定） — '
                 f'提案値: threshold {p.get("threshold")}/{len(elig)}')
    return line


def save_policy_snapshot(out_dir, policy):
    """fetch 時点の政策スナップショットを保存する (spec §23)。

    --policy で指定・検証済みの政策 dict をそのまま
    <out_dir>/policy-snapshot-<unixts>.json> にコピー保存し、パスを返す。
    検証者はこのファイルを --policy に再指定することで、fetch 時点の
    threshold 判定を再現できる（§20 の「--policy の検証者入手前提」を明示化）。
    --out + --policy の両指定時のみ呼ぶこと。
    """
    os.makedirs(out_dir, exist_ok=True)
    path = os.path.join(out_dir, f'policy-snapshot-{int(time.time())}.json')
    with open(path, 'w') as f:
        json.dump(policy, f, indent=2, ensure_ascii=False)
    return path


def cmd_board_decide_fetch(args):
    """board の board-decision 公開イベント (kind 30110, #h=board_id) を購読し、有効なものを表示する。

    --policy <policy.json> 指定時のみ、各決定の threshold 充足・不足を
    表示する（spec §20。policy は verify_board_policy_cert で事前検証し、
    無効 / board_id 不一致なら拒否で exit 1。exit コードは不変）。
    --out と --policy の両指定時は fetch 時点の政策スナップショットを
    policy-snapshot-<ts>.json として保存する（spec §23）。
    """
    secret = load_key(args.keyfile)
    policy = None
    if getattr(args, 'policy', None):
        try:
            with open(args.policy) as f:
                policy = json.load(f)
        except Exception as e:
            print(f'policy ファイルの読み込みに失敗しました: {e}', file=sys.stderr)
            sys.exit(1)
        if not verify_board_policy_cert(policy):
            print('policy の検証に失敗しました（n-of-n 署名が無効）', file=sys.stderr)
            sys.exit(1)
        if policy.get('board_id') != args.board_id:
            print('policy の board_id が取得対象の board_id と一致しません',
                  file=sys.stderr)
            sys.exit(1)
    filt = {'kinds': [DECISION_NOSTR_KIND()], '#h': [args.board_id], 'limit': args.limit}
    sub_id = secrets.token_hex(8)
    events = nostr_request(args.relay, ['REQ', sub_id, filt], auth_secret=secret if args.auth else None)
    valid, skipped = [], 0
    for ev in events:
        d = verify_board_decision_nostr_event(ev, args.board_id)
        if d is None:
            skipped += 1
        else:
            valid.append(d)
    merged = merge_decision_approvals(valid)
    if not merged:
        print(f'{len(events)} 件のイベントを取得: 有効な board-decision 公開はありませんでした（{skipped} 件をスキップ）')
        return
    if policy is not None:
        print('threshold 表示は取得できた決定に基づく暫定です'
              '（権威ある判定は board_read --governance）')
    for d in merged:
        ca = time.strftime('%Y-%m-%d', time.localtime(d['created_at']))
        if policy is None:
            print(f'[{decision_core_hash(d)}] {d["decision"]}'
                  f' (created_at {ca}, approvals {len(d.get("approvals", []))} つ)')
        else:
            ok, n, m = fetch_threshold_status(d, policy, merged)
            status = '充足' if ok else '不足'
            print(f'[{decision_core_hash(d)}] {d["decision"]}'
                  f' (created_at {ca}, approvals {n} つ, threshold {n}/{m} {status})')
    print(f'{len(events)} 件のイベントを取得: 有効 {len(valid)} 件、スキップ {skipped} 件、'
          f'マージ後 {len(merged)} 件')
    if args.out:
        os.makedirs(args.out, exist_ok=True)
        for d in merged:
            path = os.path.join(args.out, f'{decision_core_hash(d)}.json')
            with open(path, 'w') as f:
                json.dump(d, f, indent=2, ensure_ascii=False)
        print(f'{len(merged)} 件の決定を {args.out}/ に保存しました'
              '（board_read --governance --decisions にそのまま渡せます）')
        if policy is not None:
            spath = save_policy_snapshot(args.out, policy)
            print(f'fetch 時点の政策スナップショットを {spath} に保存しました'
                  '（検証者はこのファイルを --policy に指定して threshold 判定を再現できます）')


def cmd_board_draft_pub(args):
    """決定前の草案を Nostr リレーに publish (kind 30111, d タグ = コアハッシュ、spec §21)。

    board_decide_pub と同型。署名者は publisher。各承認者が cosign した版を
    自分のスロットに再公開する方式 B（§21.2）—— 新規の cosign コマンドは不要で、
    board_draft_fetch --out で保存した <core_hash>.json に board_cosign で
    追記して board_draft_pub する。
    """
    secret = load_key(args.keyfile)
    with open(args.draft) as f:
        d = json.load(f)
    if not decision_structure_ok(d):
        print('草案は無効です（構造違反 — publish しません）', file=sys.stderr)
        sys.exit(1)
    # v0.19 (spec §24.2): 期限切れの草案はリレーに置かない。
    if draft_is_expired(d, int(time.time())):
        print(f'草案は期限切れです（expires_at {d["payload"]["expires_at"]}）'
              ' — publish しません', file=sys.stderr)
        sys.exit(1)
    ev = decision_nostr_event(d, secret, kind=DRAFT_NOSTR_KIND())
    accepted, reason = nostr_publish(args.relay, ev, auth_secret=secret if args.auth else None)
    print(f'publish: {"受理" if accepted else "拒否"} ({reason}) id={ev["id"]}')
    sys.exit(0 if accepted else 1)


def cmd_board_draft_fetch(args):
    """board の草案公開イベント (kind 30111, #h=board_id) を購読し、有効なものを表示する（spec §21）。

    board_decide_fetch と同型（kinds=[30111]。三段階検証＋同一コアの approvals
    マージ＋ --out の <core_hash>.json 保存）。--policy 指定時のみ各草案の
    threshold 充足・不足を表示するが、草案には「草案（回覧中）」のマーカーをつける
    （§21.5）。草案の時点解決は現行政策のみ — v0.26（§29）で policy-update
    草案の回覧を解禁: 判定は現行規約の threshold・eligible のみ（草案の
    提案する値は使わない）、表示は判定基準と提案値の両方を出す。
    30110 決定はこの fetch には含まれないため resolve_policy_at は空集合で呼ぶ
    （§21.5）。成立の公開宣言は kind 30110 の存在（§21.3）。
    --out と --policy の両指定時は fetch 時点の政策スナップショットを
    policy-snapshot-<ts>.json として保存する（spec §23）。
    """
    secret = load_key(args.keyfile)
    policy = None
    if getattr(args, 'policy', None):
        try:
            with open(args.policy) as f:
                policy = json.load(f)
        except Exception as e:
            print(f'policy ファイルの読み込みに失敗しました: {e}', file=sys.stderr)
            sys.exit(1)
        if not verify_board_policy_cert(policy):
            print('policy の検証に失敗しました（n-of-n 署名が無効）', file=sys.stderr)
            sys.exit(1)
        if policy.get('board_id') != args.board_id:
            print('policy の board_id が取得対象の board_id と一致しません',
                  file=sys.stderr)
            sys.exit(1)
    filt = {'kinds': [DRAFT_NOSTR_KIND()], '#h': [args.board_id], 'limit': args.limit}
    sub_id = secrets.token_hex(8)
    events = nostr_request(args.relay, ['REQ', sub_id, filt], auth_secret=secret if args.auth else None)
    valid, skipped = [], 0
    for ev in events:
        d = verify_board_decision_nostr_event(ev, args.board_id, expect_kind=DRAFT_NOSTR_KIND())
        if d is None:
            skipped += 1
        else:
            valid.append(d)
    merged = merge_decision_approvals(valid)
    if not merged:
        print(f'{len(events)} 件のイベントを取得: 有効な草案はありませんでした（{skipped} 件をスキップ）')
        return
    if policy is not None:
        print('草案（回覧中）の threshold 表示は取得できた草案に基づく暫定です'
              '（草案は成立の証拠ではありません — 成立の公開宣言は kind 30110）')
    for d in merged:
        ca = time.strftime('%Y-%m-%d', time.localtime(d['created_at']))
        # v0.19 (spec §24.2): 期限切れ草案に [期限切れ] マーカー（表示のみ、
        # exit 不変。threshold 表示は維持）。
        expired = ' [期限切れ]' if draft_is_expired(d, int(time.time())) else ''
        if policy is None:
            print(f'[草案 {decision_core_hash(d)}]{expired} {d["decision"]}'
                  f' (created_at {ca}, approvals {len(d.get("approvals", []))} つ)')
        else:
            ok, n, m = fetch_threshold_status(d, policy, [])
            print(f'[草案 {decision_core_hash(d)}]{expired} {d["decision"]}'
                  f' (created_at {ca}, approvals {n} つ, {draft_threshold_line(d, ok, n, m)})')
    print(f'{len(events)} 件のイベントを取得: 有効 {len(valid)} 件、スキップ {skipped} 件、'
          f'マージ後 {len(merged)} 件')
    if args.out:
        os.makedirs(args.out, exist_ok=True)
        for d in merged:
            path = os.path.join(args.out, f'{decision_core_hash(d)}.json')
            with open(path, 'w') as f:
                json.dump(d, f, indent=2, ensure_ascii=False)
        print(f'{len(merged)} 件の草案を {args.out}/ に保存しました'
              '（board_cosign で追記 → board_draft_pub にそのまま渡せます）')
        if policy is not None:
            spath = save_policy_snapshot(args.out, policy)
            print(f'fetch 時点の政策スナップショットを {spath} に保存しました'
                  '（検証者はこのファイルを --policy に指定して threshold 判定を再現できます）')


def cmd_board_fetch_all(args):
    """board の決定公開イベントを kind 横断 (30110+30111) で 1 回の REQ で購読し、
    同一コアの草案・完成を統合表示する（spec §22）。

    board_decide_fetch / board_draft_fetch は残し、これは統合ビュー。検証は
    verify_board_decision_nostr_event(ev, board_id, expect_kind=ev['kind']) で
    kind ホワイトリスト {30110, 30111} のみ受理。検証済み決定のコピーに
    nostr_kind を付与して merge_decision_approvals に渡し（新規純粋関数なし）、
    merged レコードに finalized（30110 を含むか）を付記する。
    --policy: 成立済みは fetch 集合内の 30110 決定で時点解決（§20.2）、
    草案は現行政策のみ（§21.5）。--out は内部マーカーを剥がしたプレーン決定
    JSON を <core_hash>.json で保存（board_cosign / board_read --governance
    --decisions 互換。fetch 時点のスナップショット）。
    --out と --policy の両指定時は fetch 時点の政策スナップショットを
    policy-snapshot-<ts>.json として保存する（spec §23）。
    """
    secret = load_key(args.keyfile)
    policy = None
    if getattr(args, 'policy', None):
        try:
            with open(args.policy) as f:
                policy = json.load(f)
        except Exception as e:
            print(f'policy ファイルの読み込みに失敗しました: {e}', file=sys.stderr)
            sys.exit(1)
        if not verify_board_policy_cert(policy):
            print('policy の検証に失敗しました（n-of-n 署名が無効）', file=sys.stderr)
            sys.exit(1)
        if policy.get('board_id') != args.board_id:
            print('policy の board_id が取得対象の board_id と一致しません',
                  file=sys.stderr)
            sys.exit(1)
    kinds = [DECISION_NOSTR_KIND(), DRAFT_NOSTR_KIND()]
    filt = {'kinds': kinds, '#h': [args.board_id], 'limit': args.limit}
    sub_id = secrets.token_hex(8)
    events = nostr_request(args.relay, ['REQ', sub_id, filt], auth_secret=secret if args.auth else None)
    valid, skipped = [], 0
    for ev in events:
        if ev.get('kind') not in (DECISION_NOSTR_KIND(), DRAFT_NOSTR_KIND()):
            skipped += 1
            continue
        d = verify_board_decision_nostr_event(ev, args.board_id,
                                              expect_kind=ev['kind'])
        if d is None:
            skipped += 1
        else:
            dc = dict(d)  # 入力の破壊なし
            dc['nostr_kind'] = ev['kind']
            valid.append(dc)
    # kind 横断マージ: merge_decision_approvals は余分なキーを無視して
    # コアハッシュ単位で approvals を npub dedup 統合する（§19.4）。
    kinds_by_core = {}
    for dc in valid:
        kinds_by_core.setdefault(decision_core_hash(dc), set()).add(dc['nostr_kind'])
    merged = merge_decision_approvals(valid)
    for rec in merged:
        rec['finalized'] = DECISION_NOSTR_KIND() in kinds_by_core[decision_core_hash(rec)]
    if not merged:
        print(f'{len(events)} 件のイベントを取得: 有効な決定（30110/30111）はありませんでした（{skipped} 件をスキップ）')
        return
    if policy is not None:
        print('threshold 表示は取得できた決定に基づく暫定です'
              '（権威ある判定は board_read --governance）')
        if any(not r.get('finalized') for r in merged):
            print('草案（回覧中）の threshold 表示は取得できた草案に基づく暫定です'
                  '（草案は成立の証拠ではありません — 成立の公開宣言は kind 30110）')
    finalized_only = [r for r in merged if r.get('finalized')]
    for rec in merged:
        ca = time.strftime('%Y-%m-%d', time.localtime(rec['created_at']))
        core = decision_core_hash(rec)
        tag = '成立済み' if rec['finalized'] else '草案（回覧中）'
        # v0.19 (spec §24.2): 草案フェーズのみに [期限切れ]。同一コアに期限切れ
        # 30111 と 30110 が混在した場合は「成立済み」表示が優先（期限は草案
        # フェーズを殺しただけ — 成立は §20 の不変性ルールで恒久的）。
        expired = (' [期限切れ]'
                   if (not rec['finalized']
                       and draft_is_expired(rec, int(time.time()))) else '')
        if policy is None:
            print(f'[{tag} {core}]{expired} {rec["decision"]}'
                  f' (created_at {ca}, approvals {len(rec.get("approvals", []))} つ)')
        elif rec['finalized']:
            ok, n, m = fetch_threshold_status(rec, policy, finalized_only)
            status = '充足' if ok else '不足'
            print(f'[{tag} {core}] {rec["decision"]}'
                  f' (created_at {ca}, approvals {n} つ, threshold {n}/{m} {status})')
        else:
            ok, n, m = fetch_threshold_status(rec, policy, [])
            print(f'[{tag} {core}]{expired} {rec["decision"]}'
                  f' (created_at {ca}, approvals {n} つ, {draft_threshold_line(rec, ok, n, m)})')
    print(f'{len(events)} 件のイベントを取得: 有効 {len(valid)} 件、スキップ {skipped} 件、'
          f'マージ後 {len(merged)} 件')
    if args.out:
        os.makedirs(args.out, exist_ok=True)
        for rec in merged:
            plain = {k: v for k, v in rec.items()
                     if k not in ('nostr_kind', 'finalized')}
            path = os.path.join(args.out, f'{decision_core_hash(plain)}.json')
            with open(path, 'w') as f:
                json.dump(plain, f, indent=2, ensure_ascii=False)
        print(f'{len(merged)} 件の決定を {args.out}/ に保存しました'
              '（board_read --governance --decisions / board_cosign にそのまま渡せます。'
              'fetch 時点のスナップショット — 草案の approvals は増える可能性があります）')
        if policy is not None:
            spath = save_policy_snapshot(args.out, policy)
            print(f'fetch 時点の政策スナップショットを {spath} に保存しました'
                  '（検証者はこのファイルを --policy に指定して threshold 判定を再現できます）')


# --- v0.20: 草案への自動通知 (spec §25: board_draft_notify) ---

DRAFT_NOTIFS_DEFAULT = os.path.expanduser('~/.config/nakama/draft_notifs')


def draft_notify_targets(verified, now, within):
    """通知対象の草案を選ぶ（純粋、spec §25.1）。

    verified: [(決定 dict（verify_board_decision_nostr_event 済み）、
                event の pubkey hex（草案の publisher）、event の created_at)]
    同一コアは merge_decision_approvals で approvals マージした代表 1 件にまとめ、
    宛先は最も古い event の publisher（原発行者）とする — 承認者は宛先外（spam 抑制）。
    返り値: [(core_hash, d, publisher_hex, reason)]（created_at 昇順）。
    reason は 'expiring_soon'（0 < expires_at - now <= within）または
    'expired'（expires_at <= now）。期限なし・within 外は対象外。
    """
    merged = merge_decision_approvals([d for d, _, _ in verified])
    first_pub = {}
    for d, pub, ca in verified:
        core = decision_core_hash(d)
        if core not in first_pub or ca < first_pub[core][1]:
            first_pub[core] = (pub, ca)
    out = []
    for md in merged:
        core = decision_core_hash(md)
        ea = md.get('payload', {}).get('expires_at')
        if not isinstance(ea, int) or isinstance(ea, bool):
            continue  # 期限なし・不正型は対象外
        rem = ea - now
        if rem > within:
            continue
        reason = 'expiring_soon' if rem > 0 else 'expired'
        out.append((core, md, first_pub[core][0], reason))
    return out


def draft_notify_message(d, core, reason, relay, policy=None):
    """DM 平文（kind 14 rumor の content）。形式は spec §25.1 に固定（純粋）。

    policy 指定時のみ threshold 行（fetch_threshold_status で判定 —
    §21.5 と同じく草案は現行政策のみ。v0.26（§29）で policy-update 草案の
    回覧を解禁 — 判定は現行規約のみ、提案値は判定に使わない）。
    """
    header = '[nakama] draft expiring soon' if reason == 'expiring_soon' \
        else '[nakama] draft expired'
    ea = d['payload']['expires_at']
    utc = time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime(ea))
    lines = [header,
             f'board: {d["board_id"]}',
             f'decision: {d["decision"]} ({core[:12]})',
             f'expires_at: {ea} ({utc})']
    if policy is not None:
        ok, n_, m = fetch_threshold_status(d, policy, [])
        lines.append(f'threshold: {n_}/{m} {"充足" if ok else "不足"}')
    lines += ['---',
              'this is a courtesy notification. re-issue the draft to extend the deadline.',
              f'verify the draft yourself with: board_draft_fetch {relay} {d["board_id"]}']
    return '\n'.join(lines)


def draft_cosigner_targets(verified, now, within, policy, include_expired):
    """未署名の eligible 承認者への通知対象を選ぶ（純粋、spec §27.1）。

    verified: draft_notify_targets と同じ [(決定 dict、event の pubkey hex（草案の
    publisher）、event の created_at)]。
    policy（検証済み board-policy cert）の eligible・threshold で判定する。
    返り値: [(core_hash, d, recipient_hex, reason)]（草案は created_at 昇順、
    宛先は eligible 順）。reason の意味論は draft_notify_targets と同一。
    対象は (1) 期限間近（--within）または --include-expired 時の期限切れのみ、
    (2) threshold 未達の草案のみ。宛先はマージ済み approvals に含まれず、
    かつ publisher でもない eligible の npub（hex 変換）。
    """
    merged = merge_decision_approvals([d for d, _, _ in verified])
    first_pub = {}
    for d, pub, ca in verified:
        core = decision_core_hash(d)
        if core not in first_pub or ca < first_pub[core][1]:
            first_pub[core] = (pub, ca)
    out = []
    eligible = list(policy['eligible'])
    for md in merged:
        core = decision_core_hash(md)
        ea = md.get('payload', {}).get('expires_at')
        if not isinstance(ea, int) or isinstance(ea, bool):
            continue  # 期限なし・不正型は対象外
        rem = ea - now
        if rem > within:
            continue
        reason = 'expiring_soon' if rem > 0 else 'expired'
        if reason == 'expired' and not include_expired:
            continue
        # §21.5: 草案の threshold 判定は現行政策のみ（時点解決は現行で十分）
        ok, _, _ = fetch_threshold_status(md, policy, [])
        if ok:
            continue  # threshold 達成済み → 承認者にやることはない
        approved = {a.get('npub') for a in md.get('approvals', [])}
        publisher_hex = first_pub[core][0]
        for enpub in eligible:
            if enpub in approved:
                continue  # 署名済みは対象外
            ehex = npub_to_hex(enpub)
            if ehex is None or ehex == publisher_hex:
                continue  # publisher は発行者通知（§25.1）でカバー / 形式不正
            out.append((core, md, ehex, reason))
    return out


def draft_cosigner_message(d, core, reason, relay, policy):
    """未署名の承認者宛ての DM 平文（kind 14 rumor の content）。形式は spec §27.1
    に固定（純粋）。--cosigners 時のみ使う（--policy 必須のため threshold 行は
    常に表示）。命令形を避け、現状の告知にとどめる（§27.2）。"""
    ok, n_, m = fetch_threshold_status(d, policy, [])
    ea = d['payload']['expires_at']
    utc = time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime(ea))
    lines = ['[nakama] draft needs cosignatures',
             f'board: {d["board_id"]}',
             f'decision: {d["decision"]} ({core[:12]})',
             f'expires_at: {ea} ({utc})',
             f'threshold: {n_}/{m} {"充足" if ok else "不足"}',
             '---',
             'you are eligible to cosign this draft but have not yet.',
             f'to cosign: board_draft_fetch {relay} {d["board_id"]} --out <dir> '
             '→ board_cosign → board_draft_pub',
             f'verify the draft yourself with: board_draft_fetch {relay} {d["board_id"]}']
    return '\n'.join(lines)


def draft_notif_record_path(notif_dir, core, reason, recipient_hex=None):
    """送信記録のパス（spec §25.1 / §27.1）。

    発行者通知は <notif_dir>/<core_hash>:<reason>.json（§25.1 の既定形）。
    --cosigners の承認者宛て通知は宛先ごとに <core_hash>:<reason>:<recipient_hex>.json
    とし、発行者通知の記録とファイル名で区別して互いに干渉しない（§27.1）。
    """
    name = f'{core}:{reason}'
    if recipient_hex:
        name += f':{recipient_hex}'
    return os.path.join(notif_dir, f'{name}.json')


def draft_notif_read_record(notif_dir, core, reason, recipient_hex=None):
    """送信記録を読み込む（spec §28.2）。

    旧形式の記録（gift_wrap_id / rumor_id なし）も読み飛ばさず読み込み、
    欠けているフィールドは空文字として扱う（後方互換）。ファイルなし・
    壊れた JSON のときは None。"""
    try:
        with open(draft_notif_record_path(notif_dir, core, reason,
                                          recipient_hex)) as f:
            rec = json.load(f)
    except (OSError, ValueError):
        return None
    if not isinstance(rec, dict):
        return None
    rec.setdefault('gift_wrap_id', '')
    rec.setdefault('rumor_id', '')
    return rec


def draft_notif_already_sent(notif_dir, core, reason, now, within,
                             recipient_hex=None):
    """同一草案・同一 reason（--cosigners 時は同一宛先も）の送信記録が
    --within 以内にあれば True（I/O のみ）。
    記録なし・壊れた記録・記録が古ければ False（＝送ってよい）。"""
    rec = draft_notif_read_record(notif_dir, core, reason, recipient_hex)
    if rec is None:
        return False
    sent_at = rec.get('sent_at')
    return isinstance(sent_at, int) and (now - sent_at) < within


def draft_notif_record(notif_dir, core, reason, recipient_hex, sender_npub, now,
                       recipient_file=False, gift_wrap_id='', rumor_id=''):
    """送信記録を保存（送信時刻・宛先・送信者の npub）。通知は主張であり到達の
    証明ではない — 受け手は board_draft_fetch で自分で確認する（§25.2）。
    recipient_file=True のときは宛先ごとに別記録（§27.1 の --cosigners 用）。
    gift_wrap_id（kind 1059 の id）・rumor_id（seal = kind 14 の id）は
    §28.2 の追加 — board_notif_status の突き合わせ用。--dry-run 時は記録しない。"""
    os.makedirs(notif_dir, exist_ok=True)
    path = draft_notif_record_path(notif_dir, core, reason,
                                   recipient_hex if recipient_file else None)
    with open(path, 'w') as f:
        json.dump({'core_hash': core, 'reason': reason,
                   'recipient_hex': recipient_hex,
                   'sender_npub': sender_npub, 'sent_at': now,
                   'gift_wrap_id': gift_wrap_id, 'rumor_id': rumor_id},
                  f, indent=2, ensure_ascii=False)


def cmd_board_draft_notify(args):
    """期限間近の草案を発行者（草案イベントの publisher）に NIP-17 DM で通知する（spec §25）。

    board_draft_fetch と同一の REQ（kinds=[30111]・#h=[board_id]、三段階検証＋
    同一コアの approvals マージ）を流用。対象は 0 < expires_at - now <= --within
    （既定 86400 = 24h）の草案（reason=expiring_soon）。期限切れは既定で対象外 —
    --include-expired 時のみ対象（reason=expired）。承認者は宛先外（spam 抑制）。
    送信は nip17_build_seal/gift_wrap ＋ nostr_publish（dm_pub と同型、--auth 対応）。
    同一 reason の再送は送信記録で --within 以内は抑制（--resend で強制再送）。
    --dry-run は対象草案と宛先の一覧のみ表示（送信も記録もしない）。
    --cosigners（spec §27）指定時は、さらに threshold 未達・期限間近の草案に
    ついて未署名の eligible 承認者にも NIP-17 DM で通知する。--cosigners 時は
    --policy が必須（eligible 集合・threshold の判定に必要なため、なしでは
    exit 1）。承認者通知の送信記録は宛先ごと（<core>:<reason>:<hex>.json）で、
    発行者通知の記録とは独立。--cosigners なしの既定動作は不変（opt-in）。
    exit: 送信成功・対象なし・スキップのみで 0、fetch 失敗・DM 構築失敗・
    publish 拒否は 1（既存の publish 系と同型の clean fail）。
    """
    secret = load_key(args.keyfile)
    now = int(time.time())
    from_npub = getattr(args, 'from_npub', None)
    if from_npub:
        try:
            NostrPublicKey.from_npub(from_npub)
        except Exception:
            print('--from の npub が不正です', file=sys.stderr)
            sys.exit(1)
        # rotate_pub と同じ思想: 送信者の取り違え防止
        if npub_of(secret) != from_npub:
            print('--from と keyfile の鍵が一致しません（鍵の取り違え防止のため送信しません）',
                  file=sys.stderr)
            sys.exit(1)
    policy = None
    if getattr(args, 'policy', None):
        try:
            with open(args.policy) as f:
                policy = json.load(f)
        except Exception as e:
            print(f'policy ファイルの読み込みに失敗しました: {e}', file=sys.stderr)
            sys.exit(1)
        if not verify_board_policy_cert(policy):
            print('policy の検証に失敗しました（n-of-n 署名が無効）', file=sys.stderr)
            sys.exit(1)
        if policy.get('board_id') != args.board_id:
            print('policy の board_id が取得対象の board_id と一致しません',
                  file=sys.stderr)
            sys.exit(1)
    if getattr(args, 'cosigners', False) and policy is None:
        print('--cosigners には --policy が必須です（eligible 集合・threshold の判定に必要）',
              file=sys.stderr)
        sys.exit(1)
    filt = {'kinds': [DRAFT_NOSTR_KIND()], '#h': [args.board_id], 'limit': args.limit}
    sub_id = secrets.token_hex(8)
    events = nostr_request(args.relay, ['REQ', sub_id, filt],
                           auth_secret=secret if args.auth else None)
    verified = []
    for ev in events:
        d = verify_board_decision_nostr_event(ev, args.board_id,
                                              expect_kind=DRAFT_NOSTR_KIND())
        if d is None:
            continue
        verified.append((d, ev.get('pubkey', ''), ev.get('created_at', 0)))
    targets = draft_notify_targets(verified, now, args.within)
    if not args.include_expired:
        targets = [t for t in targets if t[3] == 'expiring_soon']
    cosigner_targets = []
    if getattr(args, 'cosigners', False):
        # --policy なしの拒否は fetch 前に済んでいる（fail-fast）
        cosigner_targets = draft_cosigner_targets(verified, now, args.within,
                                                  policy, args.include_expired)
    if not targets and not cosigner_targets:
        print('通知対象の草案はありませんでした')
        return
    notif_dir = getattr(args, 'notif_dir', None) or DRAFT_NOTIFS_DEFAULT
    sender_npub = npub_of(secret)
    failed = 0
    for core, d, publisher_hex, reason in targets:
        tag = f'{core[:12]} ({reason})'
        if args.dry_run:
            print(f'[dry-run] {tag} → {publisher_hex[:16]}... ({d["decision"]})')
            continue
        if not args.resend and draft_notif_already_sent(notif_dir, core, reason, now,
                                                        args.within):
            print(f'[skip] {tag} — {args.within}s 以内に送信済み')
            continue
        msg = draft_notify_message(d, core, reason, args.relay, policy)
        try:
            seal = nip17_build_seal(secret, publisher_hex, msg)
            wrap = nip17_build_gift_wrap(seal, publisher_hex)
        except Exception as e:
            print(f'DM の構築に失敗しました ({tag}): {e}', file=sys.stderr)
            failed += 1
            continue
        accepted, r = nostr_publish(args.relay, wrap,
                                    auth_secret=secret if args.auth else None)
        if not accepted:
            print(f'publish 拒否 ({tag}): {r}', file=sys.stderr)
            failed += 1
            continue
        draft_notif_record(notif_dir, core, reason, publisher_hex, sender_npub, now,
                           gift_wrap_id=wrap['id'], rumor_id=seal['id'])
        print(f'[sent] {tag} → {publisher_hex[:16]}... (id={wrap["id"]})')
    # --- v0.24: 承認者への草案通知 (spec §27: --cosigners) ---
    for core, d, recipient_hex, reason in cosigner_targets:
        tag = f'{core[:12]} ({reason})'
        if args.dry_run:
            print(f'[dry-run] cosigner {tag} → {recipient_hex[:16]}... '
                  f'({d["decision"]})')
            continue
        if not args.resend and draft_notif_already_sent(
                notif_dir, core, reason, now, args.within,
                recipient_hex=recipient_hex):
            print(f'[skip] cosigner {tag} — {args.within}s 以内に送信済み')
            continue
        msg = draft_cosigner_message(d, core, reason, args.relay, policy)
        try:
            seal = nip17_build_seal(secret, recipient_hex, msg)
            wrap = nip17_build_gift_wrap(seal, recipient_hex)
        except Exception as e:
            print(f'DM の構築に失敗しました (cosigner {tag}): {e}',
                  file=sys.stderr)
            failed += 1
            continue
        accepted, r = nostr_publish(args.relay, wrap,
                                    auth_secret=secret if args.auth else None)
        if not accepted:
            print(f'publish 拒否 (cosigner {tag}): {r}', file=sys.stderr)
            failed += 1
            continue
        draft_notif_record(notif_dir, core, reason, recipient_hex,
                           sender_npub, now, recipient_file=True,
                           gift_wrap_id=wrap['id'], rumor_id=seal['id'])
        print(f'[sent] cosigner {tag} → {recipient_hex[:16]}... (id={wrap["id"]})')
    if failed:
        sys.exit(1)


# --- v0.25: 通知の既読追跡・返信連携 — 受信者側の ack 送信 (spec §28.3・§28.4) ---

# ack の reason 語彙は通知の送信記録の reason と同一（突き合わせのキー一致のため）。
NOTIF_ACK_REASONS = ('expiring_soon', 'expired', 'cosign_request')
NOTIF_ACK_HEADER = '[nakama] notif-ack'


def notif_ack_message(core: str, reason: str, note: str | None = None) -> str:
    """ack DM 平文（kind 14 rumor の content）。形式は spec §28.3 に固定（純粋）。

    core は normalize_notif_core で 32 hex（decision_core_hash 形式）に正規化
    して格納する（突き合わせのキー一致のため、§28.8）。reason は NOTIF_ACK_REASONS。
    形式の検証は呼び出し側（cmd）が担う。
    """
    core = normalize_notif_core(core) or core
    lines = [NOTIF_ACK_HEADER,
             f'core: {core}',
             f'reason: {reason}',
             '---']
    if note:
        lines.append(note)
    return '\n'.join(lines)


def cmd_board_notif_ack(args):
    """受信者側が通知の発行者に自発・手動で ack DM を送る（spec §28.4）。

    ack は受信者→発行者の通常の NIP-17 DM（§28.1 の判断 5: 返信ではなく新規 DM）。
    seal は ack 送信者（＝通知の受信者）の実鍵で署名されるため、誰が ack したかは
    検証可能。ただし「読んだ」ことの証明にはならない（ack は主張 — §28.3）。
    自動 ack は設けない（§28.1 の判断 2）。
    exit: publish 受理で 0、構築失敗・拒否で 1（ack の到達は保証しない — §28.1）。
    """
    secret = load_key(args.keyfile)
    from_npub = getattr(args, 'from_npub', None)
    if from_npub:
        try:
            NostrPublicKey.from_npub(from_npub)
        except Exception:
            print('--from の npub が不正です', file=sys.stderr)
            sys.exit(1)
        if npub_of(secret) != from_npub:
            print('--from と keyfile の鍵が一致しません（鍵の取り違え防止のため送信しません）',
                  file=sys.stderr)
            sys.exit(1)
    try:
        recipient_hexpub = NostrPublicKey.from_npub(args.npub).hex()
    except Exception:
        print('npub の形式が不正です', file=sys.stderr)
        sys.exit(1)
    core = normalize_notif_core(args.core or '')
    if core is None:
        print('--core は 32 hex（decision_core_hash）または 64 hex である必要があります',
              file=sys.stderr)
        sys.exit(1)
    reason = args.reason or 'cosign_request'
    if reason not in NOTIF_ACK_REASONS:
        print(f'--reason は {"/".join(NOTIF_ACK_REASONS)} のいずれかである必要があります',
              file=sys.stderr)
        sys.exit(1)
    msg = notif_ack_message(core, reason, getattr(args, 'note', None))
    try:
        seal = nip17_build_seal(secret, recipient_hexpub, msg)
        wrap = nip17_build_gift_wrap(seal, recipient_hexpub)
    except Exception as e:
        print(f'DM の構築に失敗しました: {e}', file=sys.stderr)
        sys.exit(1)
    accepted, r = nostr_publish(args.relay, wrap,
                                auth_secret=secret if args.auth else None)
    print(f'publish: {"受理" if accepted else "拒否"} ({r}) id={wrap["id"]}')
    sys.exit(0 if accepted else 1)


    sys.exit(0 if accepted else 1)


# --- v0.25: 通知の突き合わせ表示 (spec §28.4) ---

def normalize_notif_core(core: str) -> str | None:
    """通知系の core を decision_core_hash 形式（32 hex）に正規化する（純粋）。

    32 hex はそのまま、64 hex は先頭 32 文字を取る（後方互換）。それ以外は None。
    §28.3 の「64 hex のみ」は記録側の core_hash（decision_core_hash = 32 hex）と
    突き合わせ不能だったため §28.8 で補正: 記録の 32 hex を正とする。
    """
    c = (core or '').strip().lower()
    if re.fullmatch(r'[0-9a-f]{32}', c):
        return c
    if re.fullmatch(r'[0-9a-f]{64}', c):
        return c[:32]
    return None


def parse_notif_ack(content: str) -> dict | None:
    """ack DM 平文（kind 14 rumor の content）をパースする（純粋、spec §28.3）。

    成功時は {'core': 32hex, 'reason': 語彙}。形式不正（ヘッダ不一致・core 不正・
    reason 語彙外）は None を返す — 突き合わせで無視する（spam 耐性、§28.4）。
    """
    lines = [(l or '').strip() for l in (content or '').split('\n')]
    if len(lines) < 4 or lines[0] != NOTIF_ACK_HEADER or lines[3] != '---':
        return None
    m_core = re.fullmatch(r'core:\s*(\S+)', lines[1])
    m_reason = re.fullmatch(r'reason:\s*(\S+)', lines[2])
    if not m_core or not m_reason:
        return None
    core = normalize_notif_core(m_core.group(1))
    reason = m_reason.group(1)
    if core is None or reason not in NOTIF_ACK_REASONS:
        return None
    return {'core': core, 'reason': reason}


def collect_notif_acks(rumors: list) -> dict:
    """受信 rumor から (core32, ack 送信者 hex, reason) → rumor created_at の辞書を作る（純粋）。

    rumors は dm_incoming の返り値（wrap created_at 昇順）想定。同一キーへの
    複数 ack は最初の 1 件のみ有効（dedup、§28.4）。形式不正の ack は無視。
    """
    out = {}
    for r in rumors:
        if not isinstance(r, dict):
            continue
        p = parse_notif_ack(r.get('content', ''))
        if p is None:
            continue
        key = (p['core'], r.get('pubkey', ''), p['reason'])
        if key not in out:
            out[key] = r.get('created_at', 0)
    return out


def load_notif_records(notif_dir: str) -> list:
    """送信記録ディレクトリの *.json を読み、妥当な記録の dict を返す（ファイル名昇順）。

    core は 32 hex に正規化。reason 語彙外・core 不正・JSON 破損・dict 以外は
    読み飛ばす。draft_notif_read_record と同じ後方互換（gift_wrap_id / rumor_id
    の既定は空文字）。発行者通知・承認者通知の両形式に対応（spec §25.1/§27.1）。
    """
    out = []
    try:
        names = sorted(os.listdir(notif_dir))
    except OSError:
        return []
    for fn in names:
        if not fn.endswith('.json'):
            continue
        try:
            with open(os.path.join(notif_dir, fn)) as f:
                rec = json.load(f)
        except (OSError, ValueError):
            continue
        if not isinstance(rec, dict):
            continue
        core = normalize_notif_core(rec.get('core_hash', ''))
        if core is None or rec.get('reason') not in NOTIF_ACK_REASONS:
            continue
        rec = dict(rec)
        rec['core_hash'] = core
        rec.setdefault('gift_wrap_id', '')
        rec.setdefault('rumor_id', '')
        out.append(rec)
    return out


def notif_cosigned_by_core_from_decisions(decisions_dir: str) -> dict:
    """ローカル決定 JSON（board_fetch_all --out 形式）から core → approvals の npub 集合。"""
    out = {}
    try:
        names = sorted(os.listdir(decisions_dir))
    except OSError:
        return {}
    for fn in names:
        if not fn.endswith('.json'):
            continue
        try:
            with open(os.path.join(decisions_dir, fn)) as f:
                d = json.load(f)
        except (OSError, ValueError):
            continue
        if not isinstance(d, dict):
            continue
        try:
            core = decision_core_hash(d)
        except Exception:
            continue
        npubs = {a.get('npub') for a in d.get('approvals', [])
                 if isinstance(a, dict) and a.get('npub')}
        out.setdefault(core, set()).update(npubs)
    return out


def notif_cosigned_by_core_from_relay(secret: bytes, relay: str, board_id: str,
                                      limit: int, auth: bool) -> dict:
    """30111 を購読・検証・マージし、core → approvals の npub 集合を返す（spec §28.4）。"""
    filt = {'kinds': [DRAFT_NOSTR_KIND()], '#h': [board_id], 'limit': limit}
    events = nostr_request(relay, ['REQ', secrets.token_hex(8), filt],
                           auth_secret=secret if auth else None)
    valid = []
    for ev in events:
        d = verify_board_decision_nostr_event(ev, board_id,
                                             expect_kind=DRAFT_NOSTR_KIND())
        if d is not None:
            valid.append(d)
    out = {}
    for md in merge_decision_approvals(valid):
        out[decision_core_hash(md)] = {
            a.get('npub') for a in md.get('approvals', [])
            if isinstance(a, dict) and a.get('npub')}
    return out


def cmd_board_notif_status(args):
    """送信者側の通知突き合わせ表示（spec §28.4）。

    --dir（既定 ~/.config/nakama/draft_notifs）の送信記録を読み、各記録について
    sent（UTC）/ ack（受信 DM の [nakama] notif-ack と突き合わせ）/
    cosigned（--policy 時のみ: 同一 core の 30111 approvals に recipient の npub）
    を表示する。ack 列は「読んだ」の証明ではなく受信者本人の主張の記録（§28.5）。
    fetch 失敗時は stderr に警告して記録のみ表示。exit は常に 0（表示機能）。
    """
    secret = load_key(args.keyfile)
    notif_dir = getattr(args, 'dir', None) or DRAFT_NOTIFS_DEFAULT
    records = load_notif_records(notif_dir)
    relay = getattr(args, 'relay', None)
    # 1. ack の突き合わせ（dm_incoming を流用）
    acks = {}
    if relay:
        try:
            rumors = dm_incoming(secret, relay, getattr(args, 'since', None),
                                 args.auth)
        except Exception as e:
            print(f'DM の取得に失敗しました: {e}（送信記録のみ表示します）',
                  file=sys.stderr)
            rumors = []
        acks = collect_notif_acks(rumors)
    else:
        print('--relay 未指定のため ack DM の取得を省略します（送信記録のみ表示）',
              file=sys.stderr)
    # 2. cosigned 列（--policy 時のみ）
    cosigned = None
    if getattr(args, 'policy', None):
        policy = None
        try:
            with open(args.policy) as f:
                policy = json.load(f)
            if not verify_board_policy_cert(policy):
                raise ValueError('n-of-n 署名が無効')
            if policy.get('board_id') != args.board_id:
                raise ValueError('board_id が取得対象と一致しません')
        except Exception as e:
            print(f'policy の読み込み・検証に失敗しました: {e}'
                  '（cosigned 列を省略します）', file=sys.stderr)
        else:
            try:
                if getattr(args, 'decisions', None):
                    cosigned = notif_cosigned_by_core_from_decisions(
                        args.decisions)
                elif relay:
                    cosigned = notif_cosigned_by_core_from_relay(
                        secret, relay, args.board_id, args.limit, args.auth)
                else:
                    print('--relay も --decisions も未指定のため cosigned 列を省略します',
                          file=sys.stderr)
            except Exception as e:
                print(f'30111 の取得に失敗しました: {e}'
                      '（cosigned 列を省略します）', file=sys.stderr)
    if not records:
        print('送信記録はありませんでした')
    for rec in records:
        core = rec['core_hash']
        reason = rec['reason']
        rhx = rec.get('recipient_hex') or ''
        rnpub = hex_to_npub(rhx) or '?'
        sent = rec.get('sent_at')
        sent_s = (time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime(sent)) + ' UTC'
                  if isinstance(sent, int) and not isinstance(sent, bool)
                  else '?')
        ack_ts = acks.get((core, rhx, reason))
        ack_s = ('yes(' + time.strftime('%Y-%m-%d %H:%M:%S',
                                        time.gmtime(ack_ts)) + ' UTC)'
                 if isinstance(ack_ts, int) and not isinstance(ack_ts, bool)
                 else '-')
        cols = f'sent={sent_s} ack={ack_s}'
        if cosigned is not None:
            cos = ('yes' if rnpub != '?' and rnpub in cosigned.get(core, set())
                   else '-')
            cols += f' cosigned={cos}'
        print(f'[{reason}] {core} to={rnpub} {cols}')
    if records:
        print('注: ack は「読んだ」の証明ではなく、受信者本人の主張の記録です（§28.5）')


# --- v0.4: ガバナンス照合 (spec §9.4: board_read --governance) ---

# 決定種別 → その決定が正当化できる NIP-29 管理イベントの kind。
# admit は kind 9000 (Add User) を対象にする。policy-update / close は
# リレー上のイベントに対応しない内部決定。handover は kind 9004
# (Delete Group) のみを照合する (spec §10.1: kind 9002 Create Group は
# board_verify の管轄であり governance の対象外)。
GOVERNANCE_COVERAGE = {
    'admit': {9000},
    'handover': {9004},
    'policy-update': set(),
    'close': set(),
    'remove': {9001},
}
GOVERNANCE_CHECK_KINDS = [9000, 9001, 9003, 9004, 9005, 9006, 9007, 9008]


def npub_to_hex(npub: str) -> str | None:
    """npub → 64 hex pubkey。変換不能なら None。"""
    try:
        return NostrPublicKey.from_npub(npub).hex()
    except Exception:
        return None


def resolve_policy_at(policy: dict, decisions: list, ts: int):
    """ts 時点の有効な (threshold, eligible) を返す純粋関数 (spec §11.2)。

    有効な policy-update 決定を created_at 昇順に適用し、政策のチェーンを
    時点解決する。各 policy-update 決定の検証には適用直前の政策を使う。
    無効な決定は無視する（政策は変わらない）。初回 policy は発効済みの
    board-policy cert（n-of-n 検証済み）であることが前提。
    """
    threshold = int(policy['threshold'])
    eligible = list(policy['eligible'])
    board_id, relay = policy['board_id'], policy['relay']
    chain = sorted(
        (d for d in decisions
         if d.get('decision') == 'policy-update'
         and d.get('type') == 'board-decision'
         and d.get('created_at', float('inf')) <= ts),
        key=lambda d: d['created_at'])
    for d in chain:
        ok, _, _ = _verify_decision_core(d, threshold, eligible, board_id, relay)
        if ok:
            threshold = d['payload']['threshold']
            eligible = list(d['payload']['eligible'])
    return threshold, eligible


def temporal_valid_decisions(policy: dict, decisions: list) -> list:
    """各決定を決定時点の政策で検証し、有効な (decision, n, m) だけを返す (spec §11.2)。

    policy-update が一度でも発効すると、旧来の verify_board_decision（現行政策で
    一律検証）では政策変更前の決定が新政策で裁き直されて壊れる。決定 D の有効性は
    D 自身を除いた政策チェーンを D の created_at まで解決した政策で判定する。
    規約 cert が無効なら全決定を無効扱い（旧来の前提を維持）。
    """
    if not verify_board_policy_cert(policy):
        return []
    valid = []
    for d in decisions:
        others = [o for o in decisions if o is not d]
        th, elig = resolve_policy_at(policy, others, d.get('created_at', 0))
        ok, n, m = _verify_decision_core(d, th, elig,
                                         policy['board_id'], policy['relay'])
        if ok:
            valid.append((d, n, m))
    return valid


def governance_match_events(events: list, policy: dict, decisions: list) -> list:
    """管理イベントごとに仲間内の合意の有無を判定する純粋関数 (spec §9.4 / §10.3 / §11.3)。

    各イベントについて dict(status, event, detail) を返す。
    status: 'ok'（対応する有効な board-decision あり）
          | 'warn'（対応する決定なし — 合意の証拠なし）
          | 'info'（警告なしの情報表示 — kind 9007 Join Request）
          | 'invalid-sig'（イベント署名が無効で帰属を特定できない）
    政策の時間変化に対応する (spec §11.2): 各決定の有効性は決定時点の政策で、
    各イベントの照合はイベント時点の政策で行う。
    """
    valid = temporal_valid_decisions(policy, decisions)
    # 有効な close 決定（決定時点の政策で検証済み）の無効化起点。
    # 複数あれば最初の閉鎖以降をすべて閉鎖後扱いにする。
    close_ts = min((d['created_at'] for d, _, _ in valid
                    if d['decision'] == 'close'), default=None)
    results = []
    for ev in sorted(events, key=lambda e: e.get('created_at', 0)):
        kind = ev.get('kind')
        if not verify_event_sig(ev):
            results.append({'status': 'invalid-sig', 'event': ev,
                            'detail': 'イベント署名が無効（帰属を特定できないため照合対象外）'})
            continue
        subject = next((t[1] for t in ev.get('tags', []) if t and t[0] == 'p'),
                       None)
        # v0.6 (spec §11.3): 有効な close 決定以降の管理イベントは警告
        # （閉鎖後の活動）。9007/9008 は影響なし。
        if (close_ts is not None and kind in (9000, 9001, 9003, 9004, 9005, 9006)
                and ev.get('created_at', 0) > close_ts):
            results.append({'status': 'warn', 'event': ev,
                            'detail': '閉鎖後の管理イベント（有効な close 決定より後の発行 — '
                                      f'close 時刻 {time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(close_ts))}）'})
            continue
        cover = None
        if kind == 9000:
            # admit 決定の payload.candidate がイベントの対象 (p タグ) と一致するか
            for d, n, m in valid:
                if d['decision'] != 'admit':
                    continue
                if kind not in GOVERNANCE_COVERAGE['admit']:
                    continue
                cand_hex = npub_to_hex(d['payload']['candidate'])
                if cand_hex and subject and cand_hex == subject:
                    cover = (d, n, m)
                    break
            if cover:
                d, n, m = cover
                results.append({'status': 'ok', 'event': ev,
                                'detail': f'admit 決定が対応（承認 {n}/{m}、決定時刻 '
                                          f'{time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(d["created_at"]))}）'})
            else:
                results.append({'status': 'warn', 'event': ev,
                                'detail': '対応する admit 決定なし（仲間内の合意なしの参加追加）'})
        elif kind == 9001:
            # v0.13 (spec §18.4): `remove` 決定のガバナンス照合。
            # kind 9001 の subject は p タグの対象、issuer は発行者。
            # 1. 自発的除名（発行者 == 対象）は自発的退会 (9008) と同型 → 常に OK
            #    （決定不要 — 退会の自由は仲間の合意を要しない）。
            # 2. 有効な remove 決定（決定時点の政策で検証済み —
            #    temporal_valid_decisions を流用）があり、対象一致 + 決定が除名に
            #    先行 → OK。
            # 3. それ以外 → WARN（対応する remove 決定なし — 合意の証拠なしの除名）。
            # remove 決定は政策変更を行わない（§18.5）: 除名対象がイベント時点で
            # eligible（運営者）でも OK に加えて INFO 注記だけ付ける
            # （policy-update による規約更新を推奨）。警告カウントには含めない。
            issuer = ev.get('pubkey')
            self_remove = bool(issuer and subject and issuer == subject)
            cover = None
            if not self_remove:
                for d, n, m in valid:
                    if d['decision'] != 'remove':
                        continue
                    if kind not in GOVERNANCE_COVERAGE['remove']:
                        continue
                    cand_hex = npub_to_hex(d['payload']['candidate'])
                    if not (cand_hex and subject and cand_hex == subject):
                        continue
                    if ev.get('created_at', 0) < d['created_at']:
                        continue
                    cover = (d, n, m)
                    break
            if self_remove:
                results.append({'status': 'ok', 'event': ev,
                                'detail': 'Remove User（自分による除名 = 自発的退会と同型）'})
            elif cover:
                d, n, m = cover
                detail = (f'remove 決定が対応（承認 {n}/{m}、決定時刻 '
                          f'{time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(d["created_at"]))}）')
                _, ev_eligible = resolve_policy_at(policy, decisions,
                                                  ev.get('created_at', 0))
                elig_hex = {h for h in (npub_to_hex(x) for x in ev_eligible) if h}
                if subject and subject in elig_hex:
                    detail += ' [注: 除名対象は運営者（eligible）でした — ' \
                              'policy-update による規約更新を推奨]'
                results.append({'status': 'ok', 'event': ev, 'detail': detail})
            else:
                results.append({'status': 'warn', 'event': ev,
                                'detail': '対応する remove 決定なし（合意の証拠なしの除名）'})
        elif kind == 9004:
            # handover 決定後の旧運営による Delete Group は正当な運用 (spec §10.3)。
            # 新運営・部外者・決定前の一方的な削除は警告。
            issuer = ev.get('pubkey')
            cover = None
            # v0.6 (spec §11.2): old_moderators 省略時のフォールバックはイベント時点の政策で解決。
            _, ev_eligible = resolve_policy_at(policy, decisions, ev.get('created_at', 0))
            for d, n, m in valid:
                if d['decision'] != 'handover':
                    continue
                if kind not in GOVERNANCE_COVERAGE['handover']:
                    continue
                if ev.get('created_at', 0) < d['created_at']:
                    continue
                old = d['payload'].get('old_moderators') or list(ev_eligible)
                old_hex = {h for h in (npub_to_hex(x) for x in old) if h}
                if issuer and issuer in old_hex:
                    cover = (d, n, m)
                    break
            if cover:
                d, n, m = cover
                results.append({'status': 'ok', 'event': ev,
                                'detail': f'handover 決定後の旧運営による削除（承認 {n}/{m}、決定時刻 '
                                          f'{time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(d["created_at"]))}）'})
            else:
                results.append({'status': 'warn', 'event': ev,
                                'detail': '対応する handover 決定なし（合意なしの削除、部外者・新運営による削除、'
                                          '決定より前の削除）'})
        elif kind in (9003, 9005, 9006):
            # v0.6 (spec §11.3): 運営権限の行使として扱う。発行者がイベント時点の
            # eligible に含まれていれば OK、部外者・旧運営なら WARN。
            # 特定の board-decision とは紐付けない。
            _, ev_eligible = resolve_policy_at(policy, decisions, ev.get('created_at', 0))
            elig_hex = {h for h in (npub_to_hex(x) for x in ev_eligible) if h}
            issuer = ev.get('pubkey')
            kind_name = {9003: 'Edit Group', 9005: 'Add Permission',
                         9006: 'Remove Permission'}.get(kind, f'kind {kind}')
            if issuer and issuer in elig_hex:
                results.append({'status': 'ok', 'event': ev,
                                'detail': f'{kind_name}: イベント時点の eligible による正当な運営行為'})
            else:
                results.append({'status': 'warn', 'event': ev,
                                'detail': f'{kind_name}: イベント時点の eligible 外の発行者による権限行使'
                                          '（部外者・旧運営 — 合意の証拠なし）'})
        elif kind == 9007:
            # Join Request は admit 照合の情報源として扱う。申請自体は害がないため
            # 警告にはしない（承認済みか未承認かを表示するだけ）。spec §10.3。
            issuer = ev.get('pubkey')
            admitted = False
            for d, n, m in valid:
                if d['decision'] != 'admit':
                    continue
                cand_hex = npub_to_hex(d['payload']['candidate'])
                if cand_hex and issuer and cand_hex == issuer:
                    admitted = True
                    break
            results.append({'status': 'info', 'event': ev,
                            'detail': '承認済みの申請（対応する admit 決定あり）' if admitted
                            else '未承認の申請（対応する admit 決定なし）'})
        elif kind == 9008:
            # 退会は本人の自由。常に OK。
            results.append({'status': 'ok', 'event': ev,
                            'detail': 'Leave Group は本人の自由な退会'})
        else:
            results.append({'status': 'warn', 'event': ev,
                            'detail': f'kind {kind} は照合対象外（未対応の管理イベント）'})
    return results


def load_decisions(paths) -> list:
    """--decisions のパス（ファイル or ディレクトリ）から board-decision を読み込む。"""
    decs = []
    for p in paths or []:
        if os.path.isdir(p):
            files = [os.path.join(p, f) for f in sorted(os.listdir(p))
                     if f.endswith('.json')]
        else:
            files = [p]
        for f in files:
            try:
                with open(f) as fh:
                    decs.append(json.load(fh))
            except Exception as e:
                print(f'警告: 決定ファイルの読み込みに失敗: {f} ({e})', file=sys.stderr)
    return decs


def cmd_board_governance(args):
    """board_read --governance: 管理イベント (kind 9000/9001/9003/9004/9005/9006/9007/9008)
    と board-decision の合意照合。

    リレーは管理イベントを発行者の鍵だけで受け付けるため、仲間内の合意は
    強制できない。合意を無視した管理イベントを警告表示することで社会的に
    抑止するのがこのコマンドの役割（spec §9.4「正直に書く」）。
    v0.6 (spec §11): 決定の有効性は決定時点の政策で、イベントの照合は
    イベント時点の政策で行う。有効な close 決定以降の管理イベントは警告。
    """
    with open(args.governance) as f:
        policy = json.load(f)
    if not verify_board_policy_cert(policy):
        print('board-policy が無効です（発効条件 n-of-n を満たしていません）', file=sys.stderr)
        sys.exit(1)
    decisions = load_decisions(args.decisions)
    valid_ids = {id(d) for d, _, _ in temporal_valid_decisions(policy, decisions)}
    for d in decisions:
        if id(d) not in valid_ids:
            print(f'注: 無効な board-decision を照合対象から除外: '
                  f'{d.get("decision", "?")} (created_at {d.get("created_at", "?")})',
                  file=sys.stderr)
    filt = {'kinds': GOVERNANCE_CHECK_KINDS, '#h': [args.board_id], 'limit': args.limit}
    if args.since:
        filt['since'] = args.since
    auth_secret = load_key(args.keyfile) if args.auth else None
    events = nostr_request(args.relay, ['REQ', secrets.token_hex(8), filt],
                           auth_secret=auth_secret)
    results = governance_match_events(events, policy, decisions)
    print(f'ガバナンス照合: {args.board_id} @ {args.relay}')
    print(f'規約: eligible {len(policy["eligible"])} 名、threshold {policy["threshold"]}'
          f'、決定 {len(decisions)} 件を読み込み')
    warns = 0
    for r in results:
        ev = r['event']
        kind_name = {9000: 'Add User', 9001: 'Remove User',
                     9003: 'Edit Group',
                     9004: 'Delete Group', 9005: 'Add Permission',
                     9006: 'Remove Permission',
                     9007: 'Join Request',
                     9008: 'Leave Group'}.get(ev.get('kind'), f'kind {ev.get("kind")}')
        ts = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(ev.get('created_at', 0)))
        subject = next((t[1] for t in ev.get('tags', []) if t and t[0] == 'p'), '?')
        mark = {'ok': 'OK', 'info': '情報', 'invalid-sig': '署名無効'}.get(r['status'], '警告')
        print(f'--- [{ts}] kind {ev.get("kind")} ({kind_name}) 発行: {ev.get("pubkey", "?")[:16]}... '
              f'対象: {subject[:16] if subject != "?" else "?"}... [{mark}]')
        print(f'    {r["detail"]}')
        if r['status'] not in ('ok', 'info'):
            warns += 1
    print(f'管理イベント {len(results)} 件中、要確認 {warns} 件')
    sys.exit(1 if warns else 0)


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
    s.add_argument('--compromise-registry', default=None, help='compromise registry ディレクトリ (既定: ~/.config/nakama/compromises)')
    s = sub.add_parser('verify'); s.add_argument('bond'); s.add_argument('--rotation', action='append', default=[])
    s.add_argument('--registry', default=None, help='revocation registry ディレクトリ (既定: ~/.config/nakama/revocations)')
    s.add_argument('--skip-registry', action='store_true', help='registry の解消チェックを省略')
    s.add_argument('--skip-expiry', action='store_true', help='有効期限チェックを省略')
    s.add_argument('--compromise-registry', default=None, help='compromise registry ディレクトリ (既定: ~/.config/nakama/compromises)')
    s = sub.add_parser('renew'); s.add_argument('bond'); s.add_argument('--out')
    s.add_argument('--expires-days', type=int, default=BOND_DEFAULT_EXPIRY_DAYS,
                   help=f'更新後の有効期限（日数、既定 {BOND_DEFAULT_EXPIRY_DAYS} 日）')
    s.add_argument('--markdown', action='store_true', help='投稿用の fenced code block を出力 (§8.3)')
    # 注意: challenge 自体は nonce 生成のみ。--to を付けると宛先 npub への侵害宣言を警告する (§14.2)
    sc = sub.add_parser('challenge')
    sc.add_argument('--to', default=None, help='対手の npub（侵害宣言の警告用、任意）')
    sc.add_argument('--compromise-registry', default=None, help='compromise registry ディレクトリ (既定: ~/.config/nakama/compromises)')
    s = sub.add_parser('respond'); s.add_argument('nonce')
    s = sub.add_parser('check'); s.add_argument('npub'); s.add_argument('nonce'); s.add_argument('sig')
    s.add_argument('--compromise-registry', default=None, help='compromise registry ディレクトリ (既定: ~/.config/nakama/compromises)')
    s = sub.add_parser('rotate')
    s.add_argument('--gen', action='store_true')
    s.add_argument('--to-hex')
    s.add_argument('--to-keyfile', default=os.path.expanduser('~/.config/nakama/identity.json.rotated'))
    s.add_argument('--out')
    s = sub.add_parser('verify_rotation'); s.add_argument('rotation')
    s = sub.add_parser('rotate_pub'); s.add_argument('relay'); s.add_argument('rotation')
    s.add_argument('--auth', action='store_true', help='NIP-42 認証を使う (keyfile の鍵で署名)')
    s = sub.add_parser('rotate_fetch'); s.add_argument('relay'); s.add_argument('old_npub')
    s.add_argument('--limit', type=int, default=20)
    s.add_argument('--auth', action='store_true', help='NIP-42 認証を使う (keyfile の鍵で署名)')
    s.add_argument('--out', default=None, help='rotation JSON を mode 600 で保存（key_status --rotation に渡せる）')
    s.add_argument('--chain', action='store_true', help='new_npub を次の old としてチェーン全体をたどる')
    s = sub.add_parser('revoke'); s.add_argument('bond'); s.add_argument('--out')
    s.add_argument('--reason', default='', help='解消理由（署名付きで記録、任意）')
    s.add_argument('--registry', default=None, help='revocation registry ディレクトリ (既定: ~/.config/nakama/revocations)')
    s.add_argument('--no-registry', action='store_true', help='registry への記録を省略')
    s = sub.add_parser('verify_revocation'); s.add_argument('revocation'); s.add_argument('--bond')
    s = sub.add_parser('revoke_list'); s.add_argument('--registry', default=None)
    s = sub.add_parser('revoke_import'); s.add_argument('revocation'); s.add_argument('--bond', default=None)
    s.add_argument('--registry', default=None, help='revocation registry ディレクトリ (既定: ~/.config/nakama/revocations)')
    s = sub.add_parser('revoke_pub'); s.add_argument('relay'); s.add_argument('revocation')
    s.add_argument('--auth', action='store_true', help='NIP-42 認証を使う (keyfile の鍵で署名)')
    s = sub.add_parser('revoke_fetch'); s.add_argument('relay'); s.add_argument('bond_hash')
    s.add_argument('--limit', type=int, default=20)
    s.add_argument('--auth', action='store_true', help='NIP-42 認証を使う (keyfile の鍵で署名)')
    s.add_argument('--registry', default=None, help='revocation registry ディレクトリ (既定: ~/.config/nakama/revocations)')
    s = sub.add_parser('compromise_declare'); s.add_argument('--subject', required=True, help='疑わしい鍵の npub')
    s.add_argument('--reason', default='', help='宣言理由（署名付きで記録、任意）')
    s.add_argument('--evidence', default='', help='証拠の参照: nostr event id / URL / メモ（任意）')
    s.add_argument('--bond', default=None, help='宣言者と subject の bond ファイル（当事者確認＋bond_hash 埋め込み）')
    s.add_argument('--out')
    s.add_argument('--registry', default=None, help='compromise registry ディレクトリ (既定: ~/.config/nakama/compromises)')
    s.add_argument('--no-registry', action='store_true', help='registry への記録を省略')
    s = sub.add_parser('compromise_import'); s.add_argument('declaration'); s.add_argument('--subject', default=None)
    s.add_argument('--registry', default=None, help='compromise registry ディレクトリ (既定: ~/.config/nakama/compromises)')
    s = sub.add_parser('compromise_pub'); s.add_argument('relay'); s.add_argument('declaration')
    s.add_argument('--auth', action='store_true', help='NIP-42 認証を使う (keyfile の鍵で署名)')
    s = sub.add_parser('compromise_fetch'); s.add_argument('relay'); s.add_argument('npub')
    s.add_argument('--limit', type=int, default=20)
    s.add_argument('--auth', action='store_true', help='NIP-42 認証を使う (keyfile の鍵で署名)')
    s.add_argument('--registry', default=None, help='compromise registry ディレクトリ (既定: ~/.config/nakama/compromises)')
    s = sub.add_parser('compromise_withdraw'); s.add_argument('--subject', required=True, help='撤回対象の鍵の npub')
    s.add_argument('--out')
    s.add_argument('--registry', default=None, help='compromise registry ディレクトリ (既定: ~/.config/nakama/compromises)')
    s = sub.add_parser('key_status'); s.add_argument('npub')
    s.add_argument('--threshold', type=int, default=2, help='「疑わしい」扱いの宣言者数（既定 2）')
    s.add_argument('--bond', action='append', default=[], help='自分の bond ファイル（bond graph 構築用、複数指定可）')
    s.add_argument('--liveness', default=None, help='subject の生存証明ファイル（反証として評価）')
    s.add_argument('--max-age', type=int, default=7 * 86400, help='反証に使う生存証明の許容する古さ（秒、既定7日）')
    s.add_argument('--registry', default=None, help='compromise registry ディレクトリ (既定: ~/.config/nakama/compromises)')
    s.add_argument('--rotation', action='append', default=[],
                   help='rotation 証明書ファイル（チェーン順に複数指定可、移行完了の表示用 §14.3）')
    s = sub.add_parser('liveness'); s.add_argument('--bond', default=None, help='紐付ける bond ファイル')
    s.add_argument('--out')
    s = sub.add_parser('verify_liveness'); s.add_argument('proof'); s.add_argument('--bond', default=None)
    s.add_argument('--max-age', type=int, default=7 * 86400, help='許容する古さ（秒、既定7日）')
    s.add_argument('--registry', default=None, help='revocation registry ディレクトリ (既定: ~/.config/nakama/revocations)')
    s.add_argument('--skip-registry', action='store_true', help='registry の解消チェックを省略')
    s = sub.add_parser('dm_send'); s.add_argument('npub'); s.add_argument('message'); s.add_argument('--out')
    s.add_argument('--compromise-registry', default=None, help='compromise registry ディレクトリ (既定: ~/.config/nakama/compromises)')
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
    s.add_argument('--compromise-registry', default=None, help='compromise registry ディレクトリ (既定: ~/.config/nakama/compromises)')
    s = sub.add_parser('board_join'); s.add_argument('relay'); s.add_argument('board_id')
    s.add_argument('--auth', action='store_true', help='NIP-42 認証を使う (keyfile の鍵で署名)')
    s = sub.add_parser('board_send'); s.add_argument('relay'); s.add_argument('board_id'); s.add_argument('message')
    s.add_argument('--auth', action='store_true', help='NIP-42 認証を使う (keyfile の鍵で署名)')
    s.add_argument('--descriptor', default=None, help='board descriptor ファイル（運営鍵の侵害宣言チェック用 §14.2、任意）')
    s.add_argument('--compromise-registry', default=None, help='compromise registry ディレクトリ (既定: ~/.config/nakama/compromises)')
    s = sub.add_parser('board_read'); s.add_argument('relay'); s.add_argument('board_id')
    s.add_argument('--since', type=int); s.add_argument('--limit', type=int, default=20)
    s.add_argument('--auth', action='store_true', help='NIP-42 認証を使う (keyfile の鍵で署名)')
    s.add_argument('--compromise-registry', default=None, help='compromise registry ディレクトリ (既定: ~/.config/nakama/compromises)')
    s.add_argument('--governance', metavar='POLICY',
                   help='ガバナンス照合モード: board-policy を読み込み、管理イベント (kind 9000/9001) と board-decision の合意を照合する (spec §9.4)')
    s.add_argument('--decisions', nargs='*', metavar='PATH',
                   help='board-decision のファイルまたはディレクトリ（--governance と併用）')
    s = sub.add_parser('bind'); s.add_argument('--platform', required=True)
    s.add_argument('--handle', required=True); s.add_argument('--out')
    s.add_argument('--markdown', action='store_true', help='投稿用の fenced code block を出力')
    s = sub.add_parser('verify_binding'); s.add_argument('binding')
    s.add_argument('--platform'); s.add_argument('--handle')
    s.add_argument('--compromise-registry', default=None, help='compromise registry ディレクトリ (既定: ~/.config/nakama/compromises)')
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
    s.add_argument('--expires-in', type=int, default=None,
                   help='草案の期限（秒）。created_at + 秒で expires_at を設定（spec §24）')
    s.add_argument('--expires-at', type=int, default=None,
                   help='草案の期限（unix 時刻）。--expires-in より優先（spec §24）')
    s.add_argument('--old-moderators', nargs='*', default=None,
                   help="handover 専用: 旧運営の npub 一覧（省略時は policy.eligible をフォールバック、spec §10.2）")
    s.add_argument('--out')
    s = sub.add_parser('board_cosign'); s.add_argument('decision'); s.add_argument('--out')
    s = sub.add_parser('verify_board_decision'); s.add_argument('decision'); s.add_argument('--policy', required=True)
    s = sub.add_parser('board_decide_pub'); s.add_argument('relay'); s.add_argument('decision')
    s.add_argument('--auth', action='store_true', help='NIP-42 認証を使う (keyfile の鍵で署名)')
    s = sub.add_parser('board_decide_fetch'); s.add_argument('relay'); s.add_argument('board_id')
    s.add_argument('--limit', type=int, default=20)
    s.add_argument('--auth', action='store_true', help='NIP-42 認証を使う (keyfile の鍵で署名)')
    s.add_argument('--out', default=None, help='決定 JSON を <core_hash>.json で保存（board_read --governance --decisions に渡せる）')
    s.add_argument('--policy', default=None, help='運営規約 JSON（指定時のみ各決定の threshold 充足・不足を表示）')
    s = sub.add_parser('board_draft_pub'); s.add_argument('relay'); s.add_argument('draft')
    s.add_argument('--auth', action='store_true', help='NIP-42 認証を使う (keyfile の鍵で署名)')
    s = sub.add_parser('board_draft_fetch'); s.add_argument('relay'); s.add_argument('board_id')
    s.add_argument('--limit', type=int, default=20)
    s.add_argument('--auth', action='store_true', help='NIP-42 認証を使う (keyfile の鍵で署名)')
    s.add_argument('--out', default=None, help='草案 JSON を <core_hash>.json で保存（board_cosign にそのまま渡せる）')
    s.add_argument('--policy', default=None, help='運営規約 JSON（指定時のみ各草案の threshold 充足・不足を「草案」マーカーつきで表示）')
    s = sub.add_parser('board_fetch_all'); s.add_argument('relay'); s.add_argument('board_id')
    s.add_argument('--limit', type=int, default=20)
    s.add_argument('--auth', action='store_true', help='NIP-42 認証を使う (keyfile の鍵で署名)')
    s.add_argument('--out', default=None, help='決定 JSON を <core_hash>.json で保存（内部マーカーを剥がしたプレーン決定 — board_read --governance --decisions / board_cosign に渡せる）')
    s.add_argument('--policy', default=None, help='運営規約 JSON（指定時のみ各決定の threshold 充足・不足を表示。成立済みは時点解決、草案は現行政策のみ）')
    s = sub.add_parser('board_draft_notify'); s.add_argument('relay'); s.add_argument('board_id')
    s.add_argument('--limit', type=int, default=20)
    s.add_argument('--auth', action='store_true', help='NIP-42 認証を使う (keyfile の鍵で署名)')
    s.add_argument('--policy', default=None, help='運営規約 JSON（指定時のみ DM に threshold 充足・不足を表示）')
    s.add_argument('--within', type=int, default=86400, help='期限までの残り秒数の上限 (既定: 86400 = 24h)。この範囲内の草案が通知対象')
    s.add_argument('--include-expired', action='store_true', help='期限切れの草案も通知対象にする (reason=expired)')
    s.add_argument('--dry-run', action='store_true', help='対象草案と宛先の一覧のみ表示し、送信も記録もしない')
    s.add_argument('--resend', action='store_true', help='送信記録があっても強制的に再送する')
    s.add_argument('--from', dest='from_npub', default=None, help='送信者の npub（keyfile の鍵と一致しなければ拒否 — 取り違え防止）')
    s.add_argument('--notif-dir', default=None, help='送信記録のディレクトリ (既定: ~/.config/nakama/draft_notifs)')
    s.add_argument('--cosigners', action='store_true', help='threshold 未達・期限間近の草案について、未署名の eligible 承認者にも通知する（--policy 必須、spec §27）')
    s = sub.add_parser('board_notif_ack'); s.add_argument('relay'); s.add_argument('npub')
    s.add_argument('--core', required=True, help='通知対象の core_hash（64 hex — §28.3）')
    s.add_argument('--reason', default='cosign_request',
                   help='ack の理由語彙: expiring_soon/expired/cosign_request（既定: cosign_request）')
    s.add_argument('--note', default=None, help='ack に添える任意の自由文')
    s.add_argument('--auth', action='store_true', help='NIP-42 認証を使う (keyfile の鍵で署名)')
    s.add_argument('--from', dest='from_npub', default=None, help='送信者の npub（keyfile の鍵と一致しなければ拒否 — 取り違え防止）')
    s = sub.add_parser('board_notif_status'); s.add_argument('board_id')
    s.add_argument('--relay', default=None, help='ack DM 取得・30111 購読のリレー（未指定時は送信記録のみ表示）')
    s.add_argument('--since', type=int, default=None, help='ack DM 取得の since（unix 秒、未指定時は全件）')
    s.add_argument('--limit', type=int, default=20, help='30111 購読の limit（既定 20）')
    s.add_argument('--auth', action='store_true', help='NIP-42 認証を使う (keyfile の鍵で署名)')
    s.add_argument('--policy', default=None, help='運営規約 JSON（指定時のみ cosigned 列を表示）')
    s.add_argument('--decisions', default=None, help='ローカルの決定 JSON ディレクトリ（board_fetch_all --out 形式。--policy 時の 30111 購読の代わり — spec §28.4）')
    s.add_argument('--dir', default=None, help='送信記録のディレクトリ (既定: ~/.config/nakama/draft_notifs)')

    args = ap.parse_args()
    {'init': cmd_init, 'whoami': cmd_whoami, 'propose': cmd_propose,
     'accept': cmd_accept, 'verify': cmd_verify, 'renew': cmd_renew,
    'challenge': cmd_challenge,
     'respond': cmd_respond, 'check': cmd_check, 'rotate': cmd_rotate,
     'verify_rotation': cmd_verify_rotation, 'rotate_pub': cmd_rotate_pub,
     'rotate_fetch': cmd_rotate_fetch, 'revoke': cmd_revoke,
     'verify_revocation': cmd_verify_revocation, 'revoke_list': cmd_revoke_list,
     'revoke_import': cmd_revoke_import, 'revoke_pub': cmd_revoke_pub,
     'revoke_fetch': cmd_revoke_fetch,
     'compromise_declare': cmd_compromise_declare, 'compromise_import': cmd_compromise_import,
     'compromise_pub': cmd_compromise_pub, 'compromise_fetch': cmd_compromise_fetch,
     'compromise_withdraw': cmd_compromise_withdraw, 'key_status': cmd_key_status,
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
     'verify_board_decision': cmd_verify_board_decision,
     'board_decide_pub': cmd_board_decide_pub,
     'board_decide_fetch': cmd_board_decide_fetch,
     'board_draft_pub': cmd_board_draft_pub,
     'board_draft_fetch': cmd_board_draft_fetch,
     'board_fetch_all': cmd_board_fetch_all,
     'board_draft_notify': cmd_board_draft_notify,
     'board_notif_ack': cmd_board_notif_ack,
     'board_notif_status': cmd_board_notif_status}[args.cmd](args)


if __name__ == '__main__':
    main()
