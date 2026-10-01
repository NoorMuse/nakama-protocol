"""fetch 時点の政策スナップショットの保存（spec §23 / v0.18）のオフライン検証。

board_decide_fetch / board_draft_fetch / board_fetch_all の 3 コマンドで
--out + --policy の両指定時のみ policy-snapshot-<ts>.json が保存され、
内容が入力の検証済み政策と同一（--policy への再指定で再利用可能）で、
決定ファイル (<core_hash>.json) と混同されないことをテストする。
リレーへの接続は不要（nostr_request をモック）。
使い方: python3 test_policy_snapshot.py
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
BOARD_ID = 'board-snap-001'
RELAY = 'wss://relay.example'
passed = []


def keypair():
    s = secrets.token_bytes(32)
    return s, n.npub_of(s), n.hexpub_of(s)


def make_policy(members, threshold=2, board_id=BOARD_ID, ts=TS):
    eligible = [m[1] for m in members]
    msg = n.board_policy_message(board_id, RELAY, threshold, eligible, ts)
    return {'protocol': 'nakama', 'version': 1, 'type': 'board-policy',
            'board_id': board_id, 'relay': RELAY, 'threshold': threshold,
            'eligible': eligible, 'created_at': ts,
            'signatures': [{'npub': m[1], 'sig': n.sign_schnorr(m[0], msg).hex()}
                           for m in members]}


def approve(d, signer):
    msg = n.board_decision_message(d['board_id'], d['relay'], d['decision'],
                                   d['payload'], d['created_at'])
    d['approvals'].append({'npub': signer[1],
                           'sig': n.sign_schnorr(signer[0], msg).hex()})
    return d


def make_decision(signer, ts=TS):
    d = {'protocol': 'nakama', 'version': 1, 'type': 'board-decision',
         'board_id': BOARD_ID, 'relay': RELAY, 'decision': 'admit',
         'payload': {'candidate': signer[1]},
         'created_at': ts, 'approvals': []}
    return approve(d, signer)


def pub_event(d, publisher, kind, ts=None):
    content = json.dumps(d, sort_keys=True, separators=(',', ':'), ensure_ascii=False)
    tags = [['d', n.decision_core_hash(d)], ['h', d['board_id']]]
    return n.sign_event(publisher, ts or int(time.time()), kind, tags, content)


def run_cmd(fn, ns):
    out = io.StringIO()
    err = io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        try:
            fn(ns)
        except SystemExit as e:
            return (e.code if isinstance(e.code, int) else 0), out.getvalue(), err.getvalue()
    return 0, out.getvalue(), err.getvalue()


def run_fetch(fn, evs, policy_path=None, out_dir=None):
    """fetch 系コマンドをモック実行。(code, out, err) を返す。"""
    def fake_request(url, req, **k):
        return list(evs)

    n.nostr_request = fake_request
    tmpd = tempfile.mkdtemp()
    kf = os.path.join(tmpd, 'key.json')
    n.save_key(kf, secrets.token_bytes(32))
    try:
        ns = SimpleNamespace(keyfile=kf, relay='wss://x', board_id=BOARD_ID,
                             limit=20, auth=False, out=out_dir, policy=policy_path)
        return run_cmd(fn, ns)
    finally:
        del n.nostr_request


def snapshot_files(out_dir):
    return [f for f in os.listdir(out_dir) if f.startswith('policy-snapshot-')]


def ok(name):
    passed.append(name)
    print(f'  ok: {name}')


def main():
    A = keypair()
    B = keypair()
    P = keypair()  # publisher
    tmpd = tempfile.mkdtemp()

    def policy_file(pol):
        fp = os.path.join(tmpd, f'policy-{secrets.token_hex(4)}.json')
        with open(fp, 'w') as f:
            json.dump(pol, f)
        return fp

    policy = make_policy([A, B])
    pol_path = policy_file(policy)
    d1 = make_decision(A)
    approve(d1, B)
    ev_fin = pub_event(d1, P[0], n.DECISION_NOSTR_KIND())
    d2 = make_decision(B, ts=TS + 10)
    ev_draft = pub_event(d2, P[0], n.DRAFT_NOSTR_KIND())

    cmds = {'decide_fetch': (n.cmd_board_decide_fetch, [ev_fin]),
            'draft_fetch': (n.cmd_board_draft_fetch, [ev_draft]),
            'fetch_all': (n.cmd_board_fetch_all, [ev_fin, ev_draft])}

    # 1. 3 コマンドとも --out + --policy でスナップショットが保存される
    for name, (fn, evs) in cmds.items():
        out_dir = tempfile.mkdtemp()
        code, out, err = run_fetch(fn, evs, policy_path=pol_path, out_dir=out_dir)
        assert code == 0, (name, code, err)
        snaps = snapshot_files(out_dir)
        assert len(snaps) == 1, (name, snaps)
        assert snaps[0].endswith('.json') and snaps[0].startswith('policy-snapshot-'), snaps
        with open(os.path.join(out_dir, snaps[0])) as f:
            saved = json.load(f)
        assert saved == policy, name
        assert 'policy-snapshot' in out, (name, out)  # 保存通知の表示
        ok(f'{name}: --out + --policy で policy-snapshot-<ts>.json を保存（内容は検証済み政策と同一）')

    # 2. スナップショットは --policy へ再指定して threshold 判定を再現できる
    out_dir = tempfile.mkdtemp()
    code, _, err = run_fetch(n.cmd_board_decide_fetch, [ev_fin],
                             policy_path=pol_path, out_dir=out_dir)
    assert code == 0, (code, err)
    snap_path = os.path.join(out_dir, snapshot_files(out_dir)[0])
    out_dir2 = tempfile.mkdtemp()
    code, out2, err2 = run_fetch(n.cmd_board_decide_fetch, [ev_fin],
                                 policy_path=snap_path, out_dir=out_dir2)
    assert code == 0, (code, err2)
    assert 'threshold' in out2, out2  # 再指定した政策で threshold 表示が出る
    ok('スナップショットは --policy へ再指定でき、threshold 判定を再現できる')

    # 3. --out のみ（--policy なし）ではスナップショットなし
    for name, (fn, evs) in cmds.items():
        out_dir = tempfile.mkdtemp()
        code, out, err = run_fetch(fn, evs, out_dir=out_dir)
        assert code == 0, (name, code, err)
        assert snapshot_files(out_dir) == [], (name, os.listdir(out_dir))
        ok(f'{name}: --out のみではスナップショットを保存しない')

    # 4. --policy のみ（--out なし）ではスナップショットなし
    out_dir4 = tempfile.mkdtemp()
    for name, (fn, evs) in cmds.items():
        code, out, err = run_fetch(fn, evs, policy_path=pol_path)
        assert code == 0, (name, code, err)
        assert snapshot_files(out_dir4) == [], name
        ok(f'{name}: --policy のみではスナップショットを保存しない')

    # 5. スナップショットは決定ファイルとファイル名が衝突しない
    out_dir = tempfile.mkdtemp()
    code, out, err = run_fetch(n.cmd_board_fetch_all, [ev_fin, ev_draft],
                               policy_path=pol_path, out_dir=out_dir)
    assert code == 0, (code, err)
    files = os.listdir(out_dir)
    core_files = [f for f in files if f.startswith('policy-snapshot-')]
    decision_files = [f for f in files if not f.startswith('policy-snapshot-')]
    assert len(core_files) == 1 and len(decision_files) == 2, files
    assert n.decision_core_hash(d1) + '.json' in decision_files, files
    assert n.decision_core_hash(d2) + '.json' in decision_files, files
    ok('スナップショットは <core_hash>.json と混同されない（prefix で区別）')

    # 6. save_policy_snapshot ヘルパ: ファイル名形式と mode/中身
    out_dir = tempfile.mkdtemp()
    sp = n.save_policy_snapshot(out_dir, policy)
    assert os.path.basename(sp).startswith('policy-snapshot-') and sp.endswith('.json'), sp
    with open(sp) as f:
        assert json.load(f) == policy
    ok('save_policy_snapshot: ファイル名 policy-snapshot-<ts>.json・中身は政策そのまま')

    print(f'passed: {len(passed)}')


if __name__ == '__main__':
    main()
