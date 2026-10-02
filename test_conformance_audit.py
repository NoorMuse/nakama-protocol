"""conformance カバレッジ監査の自動化 (spec §30.4 の維持ルールの機械化)。

v0.88 の監査手順（add_parser 一覧 × check_* 分岐一覧 × §30.1 対応表の突き合わせ）
をテストとして固定。新規サブコマンド・checker を追加して §30 の表・本文を
更新し忘れるとこのテストが落ちる（ドリフト防止）。

検証内容:
  A. nakama.py の全サブコマンド（add_parser 登録）が §30.1 の表の第 1 列に載っている
  B. §30.1 の第 2 列の checker がすべて conformance.py の check_* 分岐に実在する
  C. conformance.py の全 check_* 分岐が §30.1（発行レポート）か §30.3
     （アーティファクト意味論）のどちらかに分類されている（orphan 分岐なし）
  D. §30.3 の表の checker 行がすべて conformance.py に実在する（dead 行なし）
  E. §30 本文のスナップショット数が表と一致する（「計 54 サブコマンド →
     47 の発行レポートチェッカー」「残り 17 分岐」）
  F. §30.2 の共有文法の例外が表と一致する（check_init は init/whoami のみ、
     check_pub は 7 publish 系のみが対象）

ネットワーク不要（ソースと仕様書の静的解析のみ）。
使い方: python3 test_conformance_audit.py
"""
import os
import re

sys_path_hack = __file__.rsplit('/', 1)[0] or '.'

passed = []

REPO = sys_path_hack


def read(name):
    with open(os.path.join(REPO, name), encoding='utf-8') as f:
        return f.read()


def section(text, heading, next_heading):
    """spec の見出し区間を切り出す。"""
    m = re.search(r'^' + re.escape(heading) + r'\s*$', text, re.M)
    assert m, f'見出しが見つからない: {heading}'
    start = m.end()
    m2 = re.search(r'^' + re.escape(next_heading) + r'\s*$', text[start:], re.M)
    end = start + m2.start() if m2 else len(text)
    return text[start:end]


def table_rows(md):
    rows = []
    for line in md.splitlines():
        m = re.match(r'^\| ([^|]+?) \| ([^|]+?) \|', line.strip())
        if m and m.group(1).strip() not in ('サブコマンド', 'チェッカー'):  # ヘッダ行を除外
            rows.append((m.group(1).strip(), m.group(2).strip()))
    return rows


def ok(name):
    passed.append(name)


def main():
    spec = read('NAKAMA-SPEC.md')
    nak = read('nakama.py')
    conf = read('conformance.py')

    # --- A: サブコマンドの列挙と §30.1 の対応 ---
    subs = re.findall(r'add_parser\(\s*["\']([a-z0-9_]+)["\']', nak)
    ok('add_parser 登録の検出 (%d 件)' % len(subs))
    assert len(subs) == 54, (len(subs), subs)

    s301 = section(spec, '### 30.1 対応表（54 サブコマンド → 発行レポートチェッカー）',
                   '### 30.2 共有文法の例外')
    rows = table_rows(s301)
    tab_sub = {r[0] for r in rows}
    tab_chk = {r[1] for r in rows}
    missing = sorted(set(subs) - tab_sub)
    assert not missing, f'§30.1 の表に載っていないサブコマンド: {missing}'
    ok('全サブコマンドが §30.1 の表に載っている (A)')
    assert len(rows) == 54, len(rows)
    assert len(tab_sub) == 54, len(tab_sub)

    # --- B: 表の checker が conformance.py に実在する ---
    branches = set(re.findall(r"argv\[1\] == '(check_[a-z0-9_]+)'", conf))
    ok('conformance.py の check_* 分岐の検出 (%d 件)' % len(branches))
    assert len(branches) == 64, len(branches)
    phantom = sorted(tab_chk - branches)
    assert not phantom, f'§30.1 の checker が conformance.py に存在しない: {phantom}'
    ok('§30.1 の checker はすべて conformance.py に実在する (B)')
    assert len(tab_chk) == 47, len(tab_chk)

    # --- C: orphan 分岐なし（§30.1 ∪ §30.3 で全分岐を分類） ---
    s303 = section(spec, '### 30.3 発行レポート以外の 17 チェッカー（アーティファクト意味論）',
                   '### 30.4 監査の維持ルール')
    rows303 = table_rows(s303)
    art_chk = set()
    for first, _ in rows303:
        for name in first.split('/'):
            name = name.strip()
            if name:
                art_chk.add(name)
    orphan = sorted(branches - tab_chk - art_chk)
    assert not orphan, f'§30.1/§30.3 のどちらにも分類されていない分岐: {orphan}'
    ok('orphan 分岐なし: 全 64 分岐が §30.1 か §30.3 に分類されている (C)')

    # --- D: §30.3 の dead 行なし ---
    dead = sorted(art_chk - branches)
    assert not dead, f'§30.3 の表の checker が conformance.py に存在しない: {dead}'
    ok('§30.3 の表の checker はすべて conformance.py に実在する (D)')
    assert len(art_chk) == 17, len(art_chk)

    # --- E: 本文のスナップショット数と表の一致 ---
    m = re.search(r'計 (\d+) サブコマンド → (\d+) の発行レポートチェッカー', spec)
    assert m, '§30 の「計 N サブコマンド → M の発行レポートチェッカー」行が見つからない'
    assert (int(m.group(1)), int(m.group(2))) == (len(rows), len(tab_chk)), m.groups()
    m2 = re.search(r'残り (\d+) 分岐を分類', spec)
    assert m2, '§30 の「残り N 分岐を分類」行が見つからない'
    assert int(m2.group(1)) == len(art_chk), m2.group(1)
    ok('§30 本文のスナップショット数（54→47、残り 17）が表と一致する (E)')

    # --- F: 共有文法の例外が表と一致する ---
    rev = {}
    for s, c in rows:
        rev.setdefault(c, set()).add(s)
    expected_shared = {
        'check_init': {'init', 'whoami'},
        'check_pub': {'rotate_pub', 'revoke_pub', 'compromise_pub', 'dm_pub',
                      'board_decide_pub', 'board_draft_pub', 'board_notif_ack'},
    }
    for c, want in expected_shared.items():
        assert rev.get(c) == want, (c, rev.get(c), want)
    ok('共有文法の例外が §30.2 の記述と一致する '
       '(check_init=init/whoami、check_pub=7 publish 系) (F)')

    print(f'{len(passed)} cases passed: ' + ', '.join(passed))


if __name__ == '__main__':
    main()
