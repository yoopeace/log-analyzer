"""log_analyzer.py 테스트 (pytest 스타일)

로그 한 줄이 처리되는 순서대로 묶었다.
정제(sanitize) → 파일 열기 → 시각·항목 읽기 → 스캔 → 집계 → 브루트포스 판정
→ 경고 문장 만들기 → analyze() 로 한 번에 분석

명령줄 동작은 test_cli.py, AI 보고서는 test_ai_report.py 에 있다.
"""

from datetime import datetime, timedelta

import pytest

from log_analyzer import (
    FAST_ATTACK_FAILS,
    FAST_ATTACK_WINDOW_MINUTES,
    SLOW_ATTACK_FAILS,
    SLOW_ATTACK_WINDOW_MINUTES,
    BruteforceAlert,
    FileAccessAlert,
    analyze,
    build_report_body,
    count_by_ip,
    count_undated,
    detect_bruteforce,
    extract_field,
    format_bruteforce,
    format_file_access,
    open_log,
    parse_timestamp,
    sanitize_line,
    scan_log,
)


def ts(text):
    """테스트에서 시각을 짧게 쓰기 위한 도우미."""
    return datetime.strptime(text, '%Y-%m-%d %H:%M:%S')


def burst(ip, count, start="2024-01-15 09:00:00"):
    """같은 IP가 1초 간격으로 count번 실패한 로그 줄 (몰아서 시도하는 공격)."""
    base = ts(start)
    return [
        f"{(base + timedelta(seconds=i)):%Y-%m-%d %H:%M:%S} LOGIN_FAIL user=root ip={ip}\n"
        for i in range(count)
    ]


def spread(ip, count, every_minutes, start="2024-01-15 09:00:00"):
    """같은 IP가 every_minutes 분 간격으로 count번 실패한 로그 줄 (천천히 시도하는 공격)."""
    base = ts(start)
    return [
        f"{(base + timedelta(minutes=i * every_minutes)):%Y-%m-%d %H:%M:%S} LOGIN_FAIL user=root ip={ip}\n"
        for i in range(count)
    ]


# ─────────────────────────────────────────
# 1. sanitize_line: 로그에 심어진 제어문자 제거
# ─────────────────────────────────────────

def test_ANSI_이스케이프와_제어문자를_제거한다():
    result = sanitize_line("\x1b[31mLOGIN_FAIL\x1b[0m user=root ip=10.0.0.5\x07")
    assert result == "LOGIN_FAIL user=root ip=10.0.0.5"


def test_개행과_탭은_남긴다():
    assert sanitize_line("a\tb\n") == "a\tb\n"


def test_일반_텍스트는_그대로_둔다():
    line = "2024-01-15 09:25:01 LOGIN_FAIL user=root ip=10.0.0.5"
    assert sanitize_line(line) == line


# ─────────────────────────────────────────
# 2. open_log: 로그 파일 열기
# ─────────────────────────────────────────

def test_UTF8이_아닌_바이트가_있어도_크래시하지_않는다(tmp_path):
    log = tmp_path / "broken.log"
    log.write_bytes(b'\x80\x81\xff LOGIN_FAIL ip=1.2.3.4\n')

    with open_log(str(log)) as f:
        lines = list(f)

    assert len(lines) == 1
    assert 'LOGIN_FAIL' in lines[0]


def test_BOM이_붙은_파일도_첫_줄의_시각을_읽는다(tmp_path):
    # 윈도우 메모장 등은 파일 맨 앞에 보이지 않는 BOM(\ufeff)을 붙인다
    log = tmp_path / "bom.log"
    log.write_bytes("\ufeff2024-01-15 09:25:01 LOGIN_FAIL user=root ip=10.0.0.5\n".encode("utf-8"))

    with open_log(str(log)) as f:
        first = next(f)

    assert parse_timestamp(first) == ts("2024-01-15 09:25:01")


def test_파일이_없으면_입력오류_종료코드로_끝낸다():
    with pytest.raises(SystemExit) as exc:
        open_log('/no/such/file.log')
    assert exc.value.code == 2


# ─────────────────────────────────────────
# 3. parse_timestamp: 줄 앞머리의 시각 읽기
# ─────────────────────────────────────────

def test_표준_형식의_시각을_읽는다():
    line = "2024-01-15 09:25:01 LOGIN_FAIL user=root ip=10.0.0.5"
    assert parse_timestamp(line) == ts("2024-01-15 09:25:01")


def test_ISO_형식의_T_구분자도_읽는다():
    assert parse_timestamp("2024-01-15T09:25:01 LOGIN_FAIL") == ts("2024-01-15 09:25:01")


def test_시각이_없는_줄은_None을_돌려준다():
    assert parse_timestamp("LOGIN_FAIL user=root ip=10.0.0.5") is None


def test_존재하지_않는_날짜는_None을_돌려준다():
    # 형식은 맞지만 2월 30일은 없는 날짜다
    assert parse_timestamp("2024-02-30 09:25:01 LOGIN_FAIL") is None


# ─────────────────────────────────────────
# 4. extract_field: 로그 한 줄에서 값 뽑아내기
# ─────────────────────────────────────────

def test_정상적인_로그에서_IP를_뽑아낸다():
    line = "2024-01-15 09:25:01 LOGIN_FAIL user=root ip=10.0.0.5"
    assert extract_field(line, 'ip') == '10.0.0.5'


def test_뒤에_다른_항목이_붙어도_IP만_뽑아낸다():
    line = "LOGIN_FAIL user=root ip=10.0.0.5 session=abc123"
    assert extract_field(line, 'ip') == '10.0.0.5'


def test_찾는_항목이_없으면_None을_돌려준다():
    assert extract_field("LOGIN_FAIL user=root", 'ip') is None


def test_client_ip를_ip로_착각하지_않는다():
    # 'client_ip=' 안에 'ip=' 가 들어 있지만 다른 항목이다
    assert extract_field("LOGIN_FAIL client_ip=10.0.0.5", 'ip') is None


def test_profile을_file로_착각하지_않는다():
    # 'profile=' 안에 'file=' 가 들어 있지만 다른 항목이다
    assert extract_field("FILE_ACCESS profile=/etc/passwd", 'file') is None


def test_빈_문자열을_넣어도_터지지_않는다():
    assert extract_field("", 'ip') is None


def test_등호_뒤에_값이_없으면_None을_돌려준다():
    assert extract_field("LOGIN_FAIL ip=", 'ip') is None


# ─────────────────────────────────────────
# 5. scan_log: 로그를 한 번 훑어 실패 이벤트와 민감파일 경고 모으기
# ─────────────────────────────────────────

def test_한_번의_순회로_실패_이벤트와_민감파일_경고를_모은다():
    # iter()로 감싸 한 번만 순회 가능한 스트림임을 보장 (파일 객체와 같은 조건)
    lines = iter([
        "2024-01-15 09:23:11 LOGIN_SUCCESS user=admin ip=192.168.1.10\n",
        "2024-01-15 09:25:01 LOGIN_FAIL user=root ip=10.0.0.5\n",
        "2024-01-15 09:24:33 FILE_ACCESS file=/etc/passwd user=admin\n",
    ])

    fail_events, file_alerts = scan_log(lines)

    assert fail_events == [(ts("2024-01-15 09:25:01"), '10.0.0.5')]
    assert [a.path for a in file_alerts] == ['/etc/passwd']


def test_민감파일_경고에_경로와_원본_줄을_담는다():
    line = "2024-01-15 09:24:33 FILE_ACCESS file=/etc/shadow user=admin\n"
    _, file_alerts = scan_log(iter([line]))
    assert file_alerts == [FileAccessAlert('/etc/shadow', line.strip())]


def test_시각이_없는_실패_줄은_시각을_None으로_담는다():
    fail_events, _ = scan_log(iter(["LOGIN_FAIL user=root ip=10.0.0.5\n"]))
    assert fail_events == [(None, '10.0.0.5')]


def test_비슷한_경로는_민감파일로_오탐하지_않는다():
    _, file_alerts = scan_log(iter(["FILE_ACCESS file=/etc/passwd.bak user=admin\n"]))
    assert file_alerts == []


def test_일반_파일_접근은_무시한다():
    _, file_alerts = scan_log(iter(["FILE_ACCESS file=/home/user/memo.txt user=admin\n"]))
    assert file_alerts == []


def test_NOT_LOGIN_FAIL을_로그인_실패로_착각하지_않는다():
    fail_events, _ = scan_log(iter(["INFO message=NOT_LOGIN_FAIL ip=1.2.3.4\n"]))
    assert fail_events == []


def test_profile_항목을_민감파일_접근으로_착각하지_않는다():
    _, file_alerts = scan_log(iter(["FILE_ACCESS profile=/etc/passwd user=x\n"]))
    assert file_alerts == []


def test_색상_코드로_감싼_이벤트도_탐지한다():
    # ANSI 색상 코드로 이벤트 이름을 감싸 탐지를 피하려는 경우
    lines = iter(["2024-01-15 09:25:01 \x1b[31mLOGIN_FAIL\x1b[0m user=root ip=10.0.0.5\n"])
    fail_events, _ = scan_log(lines)
    assert fail_events == [(ts("2024-01-15 09:25:01"), '10.0.0.5')]


# ─────────────────────────────────────────
# 6. count_by_ip / count_undated: 집계
# ─────────────────────────────────────────

def test_IP별로_실패_횟수를_센다():
    events = [
        (ts("2024-01-15 09:25:01"), '10.0.0.5'),
        (ts("2024-01-15 09:25:02"), '10.0.0.5'),
        (ts("2024-01-15 09:31:10"), '172.16.0.99'),
    ]
    assert count_by_ip(events) == {'10.0.0.5': 2, '172.16.0.99': 1}


def test_시각을_못_읽은_줄도_총계에는_포함한다():
    events = [(None, '10.0.0.5'), (ts("2024-01-15 09:25:01"), '10.0.0.5')]
    assert count_by_ip(events) == {'10.0.0.5': 2}


def test_로그가_하나도_없으면_빈_결과를_돌려준다():
    assert count_by_ip([]) == {}


def test_시각을_못_읽은_건수를_센다():
    events = [(None, '1.1.1.1'), (ts("2024-01-15 09:00:00"), '1.1.1.1'), (None, '2.2.2.2')]
    assert count_undated(events) == 2


def test_모두_시각을_읽었으면_0을_돌려준다():
    assert count_undated([(ts("2024-01-15 09:00:00"), '1.1.1.1')]) == 0


# ─────────────────────────────────────────
# 7. detect_bruteforce: 시간 창 기반 판정
# ─────────────────────────────────────────

def test_짧은_시간에_몰린_실패는_경고한다():
    events = [(ts(f"2024-01-15 09:25:0{i}"), '10.0.0.5') for i in range(1, 4)]
    alerts = detect_bruteforce(events, threshold=3, window_minutes=10)
    assert [a.ip for a in alerts] == ['10.0.0.5']


def test_경고에_IP_등급_창_횟수_시각_범위를_담는다():
    events = [(ts(f"2024-01-15 09:25:0{i}"), '10.0.0.5') for i in range(1, 4)]
    alert = detect_bruteforce(events, threshold=3, window_minutes=10, tier='급속')[0]
    assert alert == BruteforceAlert(
        ip='10.0.0.5', tier='급속', window_minutes=10, count=3,
        start=ts("2024-01-15 09:25:01"), end=ts("2024-01-15 09:25:03"),
    )


def test_기간을_두고_흩어진_실패는_경고하지_않는다():
    # 같은 IP가 세 달에 걸쳐 한 번씩 실패한 경우
    events = [
        (ts("2024-01-15 09:00:00"), '10.0.0.5'),
        (ts("2024-03-20 14:00:00"), '10.0.0.5'),
        (ts("2024-07-02 21:00:00"), '10.0.0.5'),
    ]
    assert detect_bruteforce(events, threshold=3, window_minutes=10) == []


def test_창_경계에_걸친_실패는_창_안으로_인정한다():
    # 정확히 10분 간격이면 창(10분) 안에 포함된다
    events = [
        (ts("2024-01-15 09:00:00"), '10.0.0.5'),
        (ts("2024-01-15 09:05:00"), '10.0.0.5'),
        (ts("2024-01-15 09:10:00"), '10.0.0.5'),
    ]
    assert len(detect_bruteforce(events, threshold=3, window_minutes=10)) == 1


def test_창을_벗어난_실패는_세지_않는다():
    # 첫 실패와 마지막 실패가 10분을 넘어 벌어져 있어 동시 3회가 되지 않는다
    events = [
        (ts("2024-01-15 09:00:00"), '10.0.0.5'),
        (ts("2024-01-15 09:06:00"), '10.0.0.5'),
        (ts("2024-01-15 09:12:00"), '10.0.0.5'),
    ]
    assert detect_bruteforce(events, threshold=3, window_minutes=10) == []


def test_기준치보다_한_번_적으면_경고하지_않는다():
    events = [(ts(f"2024-01-15 09:25:0{i}"), '10.0.0.5') for i in range(1, 4)]
    assert detect_bruteforce(events, threshold=4, window_minutes=10) == []


def test_기준치와_정확히_같으면_경고한다():
    events = [(ts(f"2024-01-15 09:25:0{i}"), '10.0.0.5') for i in range(1, 5)]
    assert len(detect_bruteforce(events, threshold=4, window_minutes=10)) == 1


def test_시각을_못_읽은_줄은_시간_창_판정에서_제외한다():
    events = [(None, '10.0.0.5')] * 10
    assert detect_bruteforce(events, threshold=3, window_minutes=10) == []


def test_로그_순서가_뒤바뀌어_있어도_판정한다():
    events = [
        (ts("2024-01-15 09:25:03"), '10.0.0.5'),
        (ts("2024-01-15 09:25:01"), '10.0.0.5'),
        (ts("2024-01-15 09:25:02"), '10.0.0.5'),
    ]
    assert len(detect_bruteforce(events, threshold=3, window_minutes=10)) == 1


def test_다른_IP의_실패는_합산하지_않는다():
    events = [
        (ts("2024-01-15 09:25:01"), '10.0.0.5'),
        (ts("2024-01-15 09:25:02"), '10.0.0.6'),
        (ts("2024-01-15 09:25:03"), '10.0.0.7'),
    ]
    assert detect_bruteforce(events, threshold=3, window_minutes=10) == []


def test_집계_결과가_비어_있으면_경고하지_않는다():
    assert detect_bruteforce([]) == []


# ─────────────────────────────────────────
# 8. 경고 문장과 보고서 만들기
# ─────────────────────────────────────────

def test_브루트포스_경고_문장_형식():
    alert = BruteforceAlert('10.0.0.5', '급속', 10, 3,
                            ts("2024-01-15 09:25:01"), ts("2024-01-15 09:25:03"))
    assert format_bruteforce(alert) == (
        "[경고] 브루트포스 의심(급속) - IP: 10.0.0.5 / 10분 내 최다 3회 "
        "(2024-01-15 09:25:01 ~ 09:25:03)"
    )


def test_날짜가_바뀌면_끝_시각에도_날짜를_붙인다():
    # 24시간 창에서는 시작과 끝이 다른 날일 수 있다. 끝에 시각만 쓰면
    # '23:00:00 ~ 00:59:00' 처럼 시간이 거꾸로 흐르는 것처럼 보인다.
    alert = BruteforceAlert('9.9.9.9', '누적', 1440, 8,
                            ts("2024-01-01 23:00:00"), ts("2024-01-02 00:59:00"))
    assert format_bruteforce(alert).endswith("(2024-01-01 23:00:00 ~ 2024-01-02 00:59:00)")


def test_등급이_없으면_괄호를_붙이지_않는다():
    alert = BruteforceAlert('10.0.0.5', '', 10, 3,
                            ts("2024-01-15 09:25:01"), ts("2024-01-15 09:25:03"))
    assert format_bruteforce(alert).startswith("[경고] 브루트포스 의심 - IP: 10.0.0.5")


def test_민감파일_경고_문장_형식():
    alert = FileAccessAlert('/etc/passwd',
                            '2024-01-15 09:24:33 FILE_ACCESS file=/etc/passwd user=admin')
    assert format_file_access(alert) == (
        "[경고] 민감파일 접근 - 2024-01-15 09:24:33 FILE_ACCESS file=/etc/passwd user=admin"
    )


def test_보고서_본문_형식():
    body = build_report_body(
        {'10.0.0.5': 5},
        [BruteforceAlert('10.0.0.5', '', 10, 5, ts("2024-01-15 09:25:01"), ts("2024-01-15 09:25:05"))],
        [],
    )
    assert "IP별 로그인 실패 횟수:\n  10.0.0.5 → 5회" in body
    assert "=== 브루트포스 탐지 결과 ===\n[경고] 브루트포스 의심" in body
    assert "=== 민감파일 접근 탐지 결과 ===\n이상 없음" in body


# ─────────────────────────────────────────
# 9. analyze: CLI 와 웹앱이 함께 쓰는 분석 한 번에 하기
# ─────────────────────────────────────────

def test_analyze는_탐지_결과를_한_번에_돌려준다():
    lines = burst('198.51.100.7', FAST_ATTACK_FAILS) + [
        "2024-01-15 10:00:00 FILE_ACCESS file=/etc/shadow user=admin\n",
        "LOGIN_FAIL user=root ip=10.0.0.9\n",   # 시각 없는 줄
    ]

    result = analyze(lines)

    assert result.ip_count == {'198.51.100.7': FAST_ATTACK_FAILS, '10.0.0.9': 1}
    assert any(a.tier == '급속' and a.ip == '198.51.100.7' for a in result.brute_alerts)
    assert len(result.file_alerts) == 1
    assert result.undated_count == 1
    assert result.alerts == result.brute_alerts + result.file_alerts


def test_analyze는_기준치를_바꿀_수_있다():
    lines = burst('10.0.0.5', 3)
    assert analyze(lines).alerts == []
    assert analyze(lines, slow_threshold=3).brute_alerts != []


def test_같은_IP가_두_단계에_모두_걸리면_급속_경고_하나만_남긴다():
    # 10분에 40회면 24시간에 8회도 반드시 넘으므로, 묶지 않으면 같은 공격에 경고가 2개 나온다
    result = analyze(burst('198.51.100.7', FAST_ATTACK_FAILS))

    assert [(a.ip, a.tier) for a in result.brute_alerts] == [('198.51.100.7', '급속')]


def test_누적에만_걸린_IP는_누적_경고가_남는다():
    # 30분 간격으로 8회: 10분 창에는 1회씩만 들어가 급속 기준에 못 미친다
    result = analyze(spread('203.0.113.7', SLOW_ATTACK_FAILS, every_minutes=30))

    assert [(a.ip, a.tier) for a in result.brute_alerts] == [('203.0.113.7', '누적')]


def test_서로_다른_IP는_각자_경고를_받는다():
    lines = burst('198.51.100.7', FAST_ATTACK_FAILS) + spread('203.0.113.7', SLOW_ATTACK_FAILS, 30)

    alerts = analyze(lines).brute_alerts

    assert {a.ip: a.tier for a in alerts} == {'198.51.100.7': '급속', '203.0.113.7': '누적'}
    assert len(alerts) == 2


def test_analyze_보고서는_기존_보고서_형식과_같다():
    report = analyze(burst('10.0.0.5', 2)).report()
    assert report.startswith("IP별 로그인 실패 횟수:")
    assert "=== 브루트포스 탐지 결과 ===\n이상 없음" in report


# ─────────────────────────────────────────
# 10. 기본 설정값
# ─────────────────────────────────────────

def test_기본_설정값이_정의되어_있다():
    assert FAST_ATTACK_FAILS == 40
    assert FAST_ATTACK_WINDOW_MINUTES == 10
    assert SLOW_ATTACK_FAILS == 8
    assert SLOW_ATTACK_WINDOW_MINUTES == 1440
