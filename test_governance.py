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

    # v0.5 (§10): handover 決定。A が旧運営、D が新運営候補、E は部外者。
    handover = make_decision(BOARD, RELAY, 'handover',
                             {'new_moderators': [D[1]], 'old_moderators': [A[1]]},
                             [A, B])
    handover_no_old = make_decision(BOARD, RELAY, 'handover',
                                    {'new_moderators': [D[1]]}, [A, B])

    ev_add_D = n.sign_event(A[0], TS, 9000, [['h', BOARD], ['p', D[2]]], '')
    ev_add_E = n.sign_event(A[0], TS, 9000, [['h', BOARD], ['p', E[2]]], '')
    ev_rm_D = n.sign_event(A[0], TS, 9001, [['h', BOARD], ['p', D[2]]], '')
    ev_tampered = n.sign_event(A[0], TS, 9000, [['h', BOARD], ['p', D[2]]], '')
    ev_tampered['content'] = 'tampered'

    ev_del_old = n.sign_event(A[0], TS + 100, 9004, [['h', BOARD]], '')
    ev_del_out = n.sign_event(E[0], TS + 100, 9004, [['h', BOARD]], '')
    ev_del_new = n.sign_event(D[0], TS + 100, 9004, [['h', BOARD]], '')
    ev_del_before = n.sign_event(A[0], TS - 100, 9004, [['h', BOARD]], '')
    ev_join_D = n.sign_event(D[0], TS + 100, 9007, [['h', BOARD]], '')
    ev_join_E = n.sign_event(E[0], TS + 100, 9007, [['h', BOARD]], '')
    ev_leave = n.sign_event(D[0], TS + 100, 9008, [['h', BOARD]], '')

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
        # v0.5 (§10): 9004 / 9007 / 9008 の照合
        ('9004+旧運営(決定後)→ok', [ev_del_old], [handover], 'ok'),
        ('9004+決定なし→warn', [ev_del_old], [], 'warn'),
        ('9004+部外者→warn', [ev_del_out], [handover], 'warn'),
        ('9004+新運営(旧運営に非ず)→warn', [ev_del_new], [handover], 'warn'),
        ('9004+決定より前→warn', [ev_del_before], [handover], 'warn'),
        ('9004+old_moderators省略→policy.eligibleフォールバックok',
         [ev_del_old], [handover_no_old], 'ok'),
        ('9007+admitあり→info(承認済み)', [ev_join_D], [admit_D], 'info'),
        ('9007+決定なし→info(未承認、警告なし)', [ev_join_E], [], 'info'),
        ('9008→ok(退会は自由)', [ev_leave], [], 'ok'),
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
