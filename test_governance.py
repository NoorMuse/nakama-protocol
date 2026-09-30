"""board_read --governance のオフライン検証 (spec §9.4)。

governance_match_events の純粋関数を合成イベント + board 証明書でテストする。
リレーへの接続は不要。使い方: python3 test_governance.py
"""
import secrets
import sys
import time

sys.path.insert(0, __file__.rsplit('/', 1)[0] or '.')
import nakama as n

TS = 1759370000
BOARD = 'nakama-test-board'
RELAY = 'wss://relay.example'


def keypair():
    s = secrets.token_bytes(32)
    return s, n.npub_of(s), n.hexpub_of(s)


def make_policy(board_id, relay, threshold, members, created_at=TS):
    msg = n.board_policy_message(board_id, relay, threshold,
                                 [m[1] for m in members], created_at)
    return {
        'protocol': 'nakama', 'version': 1, 'type': 'board-policy',
        'board_id': board_id, 'relay': relay, 'threshold': threshold,
        'eligible': [m[1] for m in members], 'created_at': created_at,
        'signatures': [{'npub': m[1], 'sig': n.sign_schnorr(m[0], msg).hex()}
                       for m in members],
    }


def make_decision(board_id, relay, decision, payload, approvers, created_at=TS):
    msg = n.board_decision_message(board_id, relay, decision, payload, created_at)
    return {
        'protocol': 'nakama', 'version': 1, 'type': 'board-decision',
        'board_id': board_id, 'relay': relay, 'decision': decision,
        'payload': payload, 'created_at': created_at,
        'approvals': [{'npub': a[1], 'sig': n.sign_schnorr(a[0], msg).hex()}
                      for a in approvers],
    }


def main():
    A, B, C = keypair(), keypair(), keypair()   # eligible
    D, E = keypair(), keypair()                  # D: 候補者, E: 部外者
    policy = make_policy(BOARD, RELAY, 2, [A, B, C])
    assert n.verify_board_policy_cert(policy), 'policy の前提が壊れている'

    admit_D = make_decision(BOARD, RELAY, 'admit', {'candidate': D[1]}, [A, B])
    admit_D_1sig = make_decision(BOARD, RELAY, 'admit', {'candidate': D[1]}, [A])
    admit_D_dup = make_decision(BOARD, RELAY, 'admit', {'candidate': D[1]}, [A, A])
    admit_D_outsider = make_decision(BOARD, RELAY, 'admit', {'candidate': D[1]}, [A, E])
    admit_D_wrongboard = make_decision('other-board', RELAY, 'admit', {'candidate': D[1]}, [A, B])

    ev_add_D = n.sign_event(A[0], TS, 9000, [['h', BOARD], ['p', D[2]]], '')
    ev_add_E = n.sign_event(A[0], TS, 9000, [['h', BOARD], ['p', E[2]]], '')
    ev_rm_D = n.sign_event(A[0], TS, 9001, [['h', BOARD], ['p', D[2]]], '')
    ev_tampered = n.sign_event(A[0], TS, 9000, [['h', BOARD], ['p', D[2]]], '')
    ev_tampered['content'] = 'tampered'

    cases = [
        # (名前, イベント, decisions, 期待 status)
        ('kind9000+有効admit→ok', [ev_add_D], [admit_D], 'ok'),
        ('kind9000+対象違い→warn', [ev_add_E], [admit_D], 'warn'),
        ('kind9000+決定なし→warn', [ev_add_D], [], 'warn'),
        ('kind9000+承認不足→warn', [ev_add_D], [admit_D_1sig], 'warn'),
        ('kind9000+重複承認→warn', [ev_add_D], [admit_D_dup], 'warn'),
        ('kind9000+部外者承認→warn', [ev_add_D], [admit_D_outsider], 'warn'),
        ('kind9000+別board決定→warn', [ev_add_D], [admit_D_wrongboard], 'warn'),
        ('kind9001→warn（決定語彙なし）', [ev_rm_D], [admit_D], 'warn'),
        ('署名改ざん→invalid-sig', [ev_tampered], [admit_D], 'invalid-sig'),
        ('複合: ok1+warn2', [ev_add_D, ev_add_E, ev_rm_D], [admit_D],
         ['ok', 'warn', 'warn']),
    ]

    failed = 0
    for name, events, decisions, expect in cases:
        got = [r['status'] for r in n.governance_match_events(events, policy, decisions)]
        want = expect if isinstance(expect, list) else [expect]
        ok = got == want
        failed += not ok
        print(('PASS' if ok else 'FAIL'), name, f'(got={got})')
    print(f'{len(cases) - failed}/{len(cases)} 通過')
    sys.exit(1 if failed else 0)


if __name__ == '__main__':
    main()
