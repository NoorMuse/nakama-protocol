"""`remove` 決定種別のガバナンス照合 (spec §18)。

governance_match_events の kind 9001 分岐をオフライン検証する。
リレーへの接続は不要。使い方: python3 test_remove.py
"""
import sys

sys.path.insert(0, __file__.rsplit('/', 1)[0] or '.')
import nakama as n
from test_governance import TS, BOARD, RELAY, keypair, make_policy, make_decision


def main():
    A, B, C = keypair(), keypair(), keypair()   # eligible
    D, E = keypair(), keypair()                  # D: 除名候補, E: 部外者
    policy = make_policy(BOARD, RELAY, 2, [A, B, C])
    assert n.verify_board_policy_cert(policy), 'policy の前提が壊れている'

    # §18.2 の決定形式: candidate 必須 + reason 任意（署名対象）。
    remove_D = make_decision(BOARD, RELAY, 'remove', {'candidate': D[1]}, [A, B])
    remove_D_reason = make_decision(BOARD, RELAY, 'remove',
                                    {'candidate': D[1], 'reason': '連日の荒らし'}, [A, B])
    remove_D_1sig = make_decision(BOARD, RELAY, 'remove', {'candidate': D[1]}, [A])
    remove_E = make_decision(BOARD, RELAY, 'remove', {'candidate': E[1]}, [A, B])
    remove_D_late = make_decision(BOARD, RELAY, 'remove', {'candidate': D[1]},
                                  [A, B], TS + 1000)
    remove_tampered = make_decision(BOARD, RELAY, 'remove',
                                    {'candidate': D[1], 'reason': '荒らし'}, [A, B])
    remove_tampered['payload']['reason'] = '運営と意見が違う'  # 署名後に改ざん
    remove_B = make_decision(BOARD, RELAY, 'remove', {'candidate': B[1]}, [A, B])

    ev_rm_D = n.sign_event(A[0], TS + 100, 9001, [['h', BOARD], ['p', D[2]]], '')
    ev_rm_D_early = n.sign_event(A[0], TS - 100, 9001, [['h', BOARD], ['p', D[2]]], '')
    ev_rm_self = n.sign_event(D[0], TS + 100, 9001, [['h', BOARD], ['p', D[2]]], '')
    ev_rm_B = n.sign_event(A[0], TS + 100, 9001, [['h', BOARD], ['p', B[2]]], '')
    close_d = make_decision(BOARD, RELAY, 'close', {'reason': '終わり'}, [A, B], TS + 4000)
    ev_rm_D_5k = n.sign_event(A[0], TS + 5000, 9001, [['h', BOARD], ['p', D[2]]], '')

    # §18.3: payload 形式検証
    assert n.validate_decision_payload('remove', {'candidate': D[1]})
    assert n.validate_decision_payload('remove', {'candidate': D[1], 'reason': '荒らし'})
    assert not n.validate_decision_payload('remove', {'reason': '候補者なし'})
    assert not n.validate_decision_payload('remove', {'candidate': D[1], 'extra': 1})
    assert not n.validate_decision_payload('remove', {'candidate': D[1], 'reason': 42})
    assert not n.validate_decision_payload('remove', {'candidate': 42})

    cases = [
        # §18.6 のテスト計画 10 ケース
        ('v0.13: 有効な remove 決定 + 対象一致の 9001（決定後の発行）→ ok',
         [ev_rm_D], [remove_D], 'ok'),
        ('v0.13: remove 決定なしの 9001 → warn',
         [ev_rm_D], [], 'warn'),
        ('v0.13: 対象の異なる remove 決定 → warn',
         [ev_rm_D], [remove_E], 'warn'),
        ('v0.13: 決定より前の created_at の 9001 → warn',
         [ev_rm_D_early], [remove_D_late], 'warn'),
        ('v0.13: 承認不足の remove 決定 → 無効 → warn',
         [ev_rm_D], [remove_D_1sig], 'warn'),
        ('v0.13: 発行者 == 対象の 9001（自発的除名）→ ok（決定不要）',
         [ev_rm_self], [], 'ok'),
        ('v0.13: 除名対象が eligible 内 → ok + INFO 注記（policy-update 推奨）',
         [ev_rm_B], [remove_B], 'ok'),
        ('v0.13: reason 改ざん → 決定の署名検証が失敗 → warn',
         [ev_rm_D], [remove_tampered], 'warn'),
        ('v0.13: reason 付きの有効な remove 決定 → ok',
         [ev_rm_D], [remove_D_reason], 'ok'),
        ('v0.13: close 決定後の 9001 → warn（close 無効化ルールが優先）',
         [ev_rm_D_5k], [close_d, remove_D], 'warn'),
    ]

    for name, evs, decs, want in cases:
        got = n.governance_match_events(evs, policy, decs)
        assert len(got) == 1, name
        assert got[0]['status'] == want, \
            f'{name}: expected {want}, got {got[0]["status"]} ({got[0]["detail"]})'
        print(f'OK: {name}')

    # ケース 7: INFO 注記は警告カウントに含まれず、detail に推奨文言が入る。
    got = n.governance_match_events([ev_rm_B], policy, [remove_B])
    assert 'policy-update' in got[0]['detail'], 'INFO 注記が欠けている'
    # ケース 1: 対象が eligible 外なら INFO 注記は付かない。
    got = n.governance_match_events([ev_rm_D], policy, [remove_D])
    assert 'policy-update' not in got[0]['detail'], '不要な INFO 注記が出ている'
    # ケース 6: 決定不要 — 対象が承認者集合外でも ok。
    got = n.governance_match_events([ev_rm_self], policy, [remove_D_1sig])
    assert got[0]['status'] == 'ok', '自発的除名が無効な決定に阻まれている'

    print(f'\n全 {len(cases)} ケース + 補足アサーション通過')


if __name__ == '__main__':
    main()
