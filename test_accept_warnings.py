"""v0.10: `accept` への侵害警告統合 (spec §15) のオフライン検証。

- proposal のパース＋既存署名の検証の後・自分の署名前、当事者（自分以外）に
  非撤回侵害宣言があれば stderr に WARN（advisory、exit コード不変）。
- リレーへの接続は不要。使い方: python3 test_accept_warnings.py
"""
import io
import json
import os
import secrets
import sys
import tempfile
import time
from contextlib import redirect_stderr, redirect_stdout
from types import SimpleNamespace

sys.path.insert(0, __file__.rsplit('/', 1)[0] or '.')
import nakama as n

TS = 1759370000
DECL_T = TS + 1000


def keypair():
    s = secrets.token_bytes(32)
    return s, n.npub_of(s)


def check(name, cond):
    print(('PASS' if cond else 'FAIL') + ' ' + name)
    if not cond:
        sys.exit(1)


def run_cmd(fn, **kwargs):
    """CLI コマンドを SimpleNamespace で呼び出す。(exit_code, stdout, stderr) を返す。"""
    ns = SimpleNamespace(**kwargs)
    out, err = io.StringIO(), io.StringIO()
    try:
        with redirect_stdout(out), redirect_stderr(err):
            fn(ns)
    except SystemExit as e:
        return e.code, out.getvalue(), err.getvalue()
    return 0, out.getvalue(), err.getvalue()


def declare_on(declarant_secret, subject_npub, registry, ts=DECL_T, withdrawn=False):
    decl = n.build_compromise_declaration(declarant_secret, subject_npub, ts, withdrawn)
    res = n.import_compromise_event(decl, registry)
    assert res in ('stored', 'updated'), res
    return decl


def make_proposal(proposer_secret, companions, ts=TS):
    comps = sorted(companions)
    nonce = secrets.token_hex(32)
    msg = n.bond_message(comps, ts, nonce, None)
    return {'protocol': 'nakama', 'version': 1, 'companions': comps,
            'created_at': ts, 'nonce': nonce,
            'signatures': {n.npub_of(proposer_secret): n.sign_schnorr(proposer_secret, msg).hex()}}


def make_ctx():
    """一時鍵・registry・proposal 受け入れ用の引数を束ねる。"""
    d = tempfile.mkdtemp()
    registry = os.path.join(d, 'compromises')
    os.makedirs(registry)
    keydir = os.path.join(d, 'keys')
    os.makedirs(keydir)
    return d, registry, keydir


def accept_args(me_secret, keydir, proposal_path=None, registry=None, **extra):
    kf = os.path.join(keydir, secrets.token_hex(4) + '.key')
    n.save_key(kf, me_secret)
    kw = dict(proposal=proposal_path, from_b64=None, out=os.path.join(keydir, 'bond.json'),
              keyfile=kf, markdown=False, compromise_registry=registry)
    kw.update(extra)
    return kw


def main():
    # --- ケース 1: 提案者に非撤回宣言あり → WARN、bond は完成 ---
    d, registry, keydir = make_ctx()
    proposer_s, proposer_n = keypair()
    me_s, me_n = keypair()
    w_s, w_n = keypair()  # 宣言者（第三者）
    declare_on(w_s, proposer_n, registry)
    prop = make_proposal(proposer_s, [proposer_n, me_n])
    pp = os.path.join(d, 'proposal.json')
    json.dump(prop, open(pp, 'w'))
    code, out, err = run_cmd(n.cmd_accept, **accept_args(me_s, keydir, pp, registry))
    check('1: 宣言あり accept は exit 0', code == 0)
    check('1: stderr に WARN（提案者の npub[:12] を含む）',
          f'WARN: {proposer_n[:12]}...' in err and 'compromise declaration(s)' in err)
    bond = json.load(open(os.path.join(keydir, 'bond.json')))
    check('1: bond は両署名で完成',
          set(bond['signatures']) == {proposer_n, me_n}
          and all(bond['signatures'].values()))

    # --- ケース 2: withdrawn のみ → 警告なし ---
    d2, registry2, keydir2 = make_ctx()
    proposer_s, proposer_n = keypair()
    me_s, me_n = keypair()
    w_s, _ = keypair()
    declare_on(w_s, proposer_n, registry2, withdrawn=True)
    prop = make_proposal(proposer_s, [proposer_n, me_n])
    pp = os.path.join(d2, 'proposal.json')
    json.dump(prop, open(pp, 'w'))
    code, out, err = run_cmd(n.cmd_accept, **accept_args(me_s, keydir2, pp, registry2))
    check('2: withdrawn のみ accept は exit 0', code == 0)
    check('2: stderr に WARN なし', 'WARN' not in err)

    # --- ケース 3: 宣言なし → 警告なし ---
    d3, registry3, keydir3 = make_ctx()
    proposer_s, proposer_n = keypair()
    me_s, me_n = keypair()
    prop = make_proposal(proposer_s, [proposer_n, me_n])
    pp = os.path.join(d3, 'proposal.json')
    json.dump(prop, open(pp, 'w'))
    code, out, err = run_cmd(n.cmd_accept, **accept_args(me_s, keydir3, pp, registry3))
    check('3: 宣言なし accept は exit 0', code == 0)
    check('3: stderr に WARN なし', 'WARN' not in err)

    # --- ケース 4: --from-b64（fenced block 全文）経由でも WARN ---
    d4, registry4, keydir4 = make_ctx()
    proposer_s, proposer_n = keypair()
    me_s, me_n = keypair()
    w_s, _ = keypair()
    declare_on(w_s, proposer_n, registry4)
    prop = make_proposal(proposer_s, [proposer_n, me_n])
    fenced = n.markdown_block(prop, 'proposal')
    code, out, err = run_cmd(n.cmd_accept, **accept_args(me_s, keydir4, None, registry4, from_b64=fenced))
    check('4: from-b64 accept は exit 0', code == 0)
    check('4: from-b64 でも stderr に WARN',
          f'WARN: {proposer_n[:12]}...' in err)

    # --- ケース 5: 3 者 bond — 宣言ありの 1 人のみ WARN ---
    d5, registry5, keydir5 = make_ctx()
    proposer_s, proposer_n = keypair()
    me_s, me_n = keypair()
    c_s, c_n = keypair()
    w_s, _ = keypair()
    declare_on(w_s, c_n, registry5)
    prop = make_proposal(proposer_s, [proposer_n, me_n, c_n])
    pp = os.path.join(d5, 'proposal.json')
    json.dump(prop, open(pp, 'w'))
    code, out, err = run_cmd(n.cmd_accept, **accept_args(me_s, keydir5, pp, registry5))
    check('5: 3 者 accept は exit 0', code == 0)
    check('5: 宣言ありの当事者のみに WARN',
          f'WARN: {c_n[:12]}...' in err
          and f'WARN: {proposer_n[:12]}...' not in err
          and f'WARN: {me_n[:12]}...' not in err)

    # --- ケース 6: --markdown — WARN は stderr、投稿ブロックは stdout ---
    d6, registry6, keydir6 = make_ctx()
    proposer_s, proposer_n = keypair()
    me_s, me_n = keypair()
    w_s, _ = keypair()
    declare_on(w_s, proposer_n, registry6)
    prop = make_proposal(proposer_s, [proposer_n, me_n])
    pp = os.path.join(d6, 'proposal.json')
    json.dump(prop, open(pp, 'w'))
    code, out, err = run_cmd(n.cmd_accept, **accept_args(me_s, keydir6, pp, registry6, markdown=True))
    check('6: markdown accept は exit 0', code == 0)
    check('6: WARN は stderr にのみ',
          f'WARN: {proposer_n[:12]}...' in err and 'WARN' not in out)
    check('6: 投稿ブロックは stdout に混入なく出力',
          '```' in out and 'bond' in out)

    # --- 追加: 自分の鍵への宣言は警告対象外 ---
    d7, registry7, keydir7 = make_ctx()
    proposer_s, proposer_n = keypair()
    me_s, me_n = keypair()
    w_s, _ = keypair()
    declare_on(w_s, me_n, registry7)  # 自分への宣言は自覚済み扱いで警告なし
    prop = make_proposal(proposer_s, [proposer_n, me_n])
    pp = os.path.join(d7, 'proposal.json')
    json.dump(prop, open(pp, 'w'))
    code, out, err = run_cmd(n.cmd_accept, **accept_args(me_s, keydir7, pp, registry7))
    check('7: 自分への宣言では WARN なし', code == 0 and 'WARN' not in err)

    print('ALL PASS')


if __name__ == '__main__':
    main()
