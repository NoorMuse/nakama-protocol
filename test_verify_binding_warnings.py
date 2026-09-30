"""v0.11: `verify_binding` への侵害警告統合 (spec §16) のオフライン検証。

- binding の署名・platform・handle 検証の後、対象 npub への非撤回侵害宣言があれば
  stderr に WARN（advisory、exit コード不変）。
- リレーへの接続は不要。使い方: python3 test_verify_binding_warnings.py
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


def make_binding(binder_secret, platform='moltbook', handle='alex', ts=TS):
    me = n.npub_of(binder_secret)
    msg = n.binding_message(platform, handle, me, ts)
    return {'protocol': 'nakama', 'version': 1, 'type': 'platform-binding',
            'platform': platform, 'handle': handle, 'npub': me,
            'created_at': ts,
            'sig': n.sign_schnorr(binder_secret, msg).hex()}


def save_binding(d, binding, name='binding.json'):
    p = os.path.join(d, name)
    with open(p, 'w') as f:
        json.dump(binding, f)
    return p


def vb_args(path, registry, platform='moltbook', handle='alex'):
    return dict(binding=path, platform=platform, handle=handle,
                compromise_registry=registry)


def main():
    d = tempfile.mkdtemp()
    registry = os.path.join(d, 'compromises')
    os.makedirs(registry)

    binder_s, binder_npub = keypair()
    declarant_s, _ = keypair()
    other_s, other_npub = keypair()

    # 1. 宣言なし → 警告なし、有効な binding は「有効」+ exit 0
    p1 = save_binding(d, make_binding(binder_s), 'b1.json')
    code, out, err = run_cmd(n.cmd_verify_binding, **vb_args(p1, registry))
    check('1: no-declaration → valid + exit 0 + no WARN',
          code == 0 and 'binding は有効です' in out and 'WARN' not in err)

    # 2. 対象 npub に非撤回宣言あり → stderr に WARN、exit 0（警告は結果に影響しない）
    declare_on(declarant_s, binder_npub, registry)
    code, out, err = run_cmd(n.cmd_verify_binding, **vb_args(p1, registry))
    check('2: active-declaration → WARN on stderr + valid + exit 0',
          code == 0 and 'binding は有効です' in out
          and f'WARN: {binder_npub[:12]}...' in err)

    # 3. 宣言が withdrawn のみ → 警告なし
    r3 = os.path.join(d, 'compromises-withdrawn')
    os.makedirs(r3)
    declare_on(declarant_s, binder_npub, r3, withdrawn=True)
    code, out, err = run_cmd(n.cmd_verify_binding, **vb_args(p1, r3))
    check('3: withdrawn-only → no WARN + valid + exit 0',
          code == 0 and 'binding は有効です' in out and 'WARN' not in err)

    # 4. 署名改ざんの binding + 宣言あり → WARN は出るが「無効」+ exit 1
    bad = make_binding(binder_s)
    bad['sig'] = secrets.token_hex(64)
    p4 = save_binding(d, bad, 'b4.json')
    code, out, err = run_cmd(n.cmd_verify_binding, **vb_args(p4, registry))
    check('4: tampered-sig + declaration → WARN yet invalid + exit 1',
          code == 1 and 'binding は無効です' in out
          and f'WARN: {binder_npub[:12]}...' in err)

    # 5. --compromise-registry で切り替えた registry でも WARN
    r5 = os.path.join(d, 'compromises-alt')
    os.makedirs(r5)
    declare_on(declarant_s, binder_npub, r5)
    code, out, err = run_cmd(n.cmd_verify_binding, **vb_args(p1, r5))
    check('5: switched registry → WARN present',
          f'WARN: {binder_npub[:12]}...' in err)
    r5b = os.path.join(d, 'compromises-empty')
    os.makedirs(r5b)
    code, out, err = run_cmd(n.cmd_verify_binding, **vb_args(p1, r5b))
    check('5b: registry without declaration → no WARN',
          'WARN' not in err)

    # 6. 宣言の subject が binding の npub と別の鍵 → 警告なし
    r6 = os.path.join(d, 'compromises-other')
    os.makedirs(r6)
    declare_on(declarant_s, other_npub, r6)
    code, out, err = run_cmd(n.cmd_verify_binding, **vb_args(p1, r6))
    check('6: declaration for other key → no WARN',
          'WARN' not in err and code == 0)

    print('OK: all 6 cases pass')


if __name__ == '__main__':
    main()
