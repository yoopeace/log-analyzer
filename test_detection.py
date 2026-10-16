"""브루트포스 탐지 파이프라인 테스트 (pytest 스타일)

extract_field → count_by_ip → detect_bruteforce 순서로
로그 한 줄에서 IP를 뽑아 집계하고 공격 여부를 판정한다.
"""

from datetime import datetime, timedelta

from log_analyzer import (
    FAST_ATTACK_FAILS,
    FAST_ATTACK_WINDOW_MINUTES,
    SLOW_ATTACK_FAILS,
    SLOW_ATTACK_WINDOW_MINUTES,
    BruteforceAlert,
    analyze,
    count_by_ip,
    count_undated,
    detect_bruteforce,
    extract_field,
    format_bruteforce,
    open_log,
    parse_timestamp,
)


def ts(text):
    """테스트에서 시각을 짧게 쓰기 위한 도우미."""
    return datetime.strptime(text, '%Y-%m-%d %H:%M:%S')


# ─────────────────────────────────────────
# 1. extract_field: 로그 한 줄에서 값 뽑아내기
# ─────────────────────────────────────────

def test_정상적인_로그에서_IP를_뽑아낸다():
    line = "2024-01-15 09:25:01 LOGIN_FAIL user=root ip=10.0.0.5"
    assert extract_field(line, 'ip') == '10.0.0.5'


def test_뒤에_다른_항목이_붙어도_IP만_뽑아낸다():
    line = "LOGIN_FAIL user=root ip=10.0.0.5 session=abc123"
    assert extract_field(line, 'ip') == '10.0.0.5'


def test_찾는_항목이_없으면_None을_돌려준다():
    line = "LOGIN_FAIL user=root"
    assert extract_field(line, 'ip') is None


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
# 2. count_by_ip: IP별 실패 횟수 집계
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
# 4. detect_bruteforce: 시간 창 기반 판정
# ─────────────────────────────────────────

def test_짧은_시간에_몰린_실패는_경고한다():
    events = [(ts(f"2024-01-15 09:25:0{i}"), '10.0.0.5') for i in range(1, 4)]
    alerts = detect_bruteforce(events, threshold=3, window_minutes=10)
    assert len(alerts) == 1
    assert alerts[0].ip == '10.0.0.5'


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


def test_경고에_창_기간과_시각_범위를_담는다():
    events = [(ts(f"2024-01-15 09:25:0{i}"), '10.0.0.5') for i in range(1, 4)]
    alert = detect_bruteforce(events, threshold=3, window_minutes=10, tier='급속')[0]
    assert alert == BruteforceAlert(
        ip='10.0.0.5', tier='급속', window_minutes=10, count=3,
        start=ts("2024-01-15 09:25:01"), end=ts("2024-01-15 09:25:03"),
    )


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
    alert = BruteforceAlert('9.9.9.9', '완속', 1440, 8,
                            ts("2024-01-01 23:00:00"), ts("2024-01-02 00:59:00"))
    assert format_bruteforce(alert).endswith("(2024-01-01 23:00:00 ~ 2024-01-02 00:59:00)")


def test_등급이_없으면_괄호를_붙이지_않는다():
    alert = BruteforceAlert('10.0.0.5', '', 10, 3,
                            ts("2024-01-15 09:25:01"), ts("2024-01-15 09:25:03"))
    assert format_bruteforce(alert).startswith("[경고] 브루트포스 의심 - IP: 10.0.0.5")


# ─────────────────────────────────────────
# 5. count_undated: 시각을 못 읽은 건수
# ─────────────────────────────────────────

def test_시각을_못_읽은_건수를_센다():
    events = [(None, '1.1.1.1'), (ts("2024-01-15 09:00:00"), '1.1.1.1'), (None, '2.2.2.2')]
    assert count_undated(events) == 2


def test_모두_시각을_읽었으면_0을_돌려준다():
    assert count_undated([(ts("2024-01-15 09:00:00"), '1.1.1.1')]) == 0


def test_기본_설정값이_정의되어_있다():
    assert FAST_ATTACK_FAILS == 40
    assert FAST_ATTACK_WINDOW_MINUTES == 10
    assert SLOW_ATTACK_FAILS == 8
    assert SLOW_ATTACK_WINDOW_MINUTES == 1440


# ─────────────────────────────────────────
# 6. analyze: CLI 와 웹앱이 함께 쓰는 분석 한 번에 하기
# ─────────────────────────────────────────

def burst(ip, count, start="2024-01-15 09:00:00"):
    """같은 IP가 1초 간격으로 count번 실패한 로그 줄."""
    base = ts(start)
    return [
        f"{(base + timedelta(seconds=i)):%Y-%m-%d %H:%M:%S} LOGIN_FAIL user=root ip={ip}\n"
        for i in range(count)
    ]


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


def test_analyze_보고서는_기존_보고서_형식과_같다():
    lines = burst('10.0.0.5', 2)
    report = analyze(lines).report()
    assert report.startswith("IP별 로그인 실패 횟수:")
    assert "=== 브루트포스 탐지 결과 ===\n이상 없음" in report


# ─────────────────────────────────────────
# 7. BOM 이 붙은 파일
# ─────────────────────────────────────────

def test_BOM이_붙은_파일도_첫_줄의_시각을_읽는다(tmp_path):
    # 윈도우 메모장 등은 파일 맨 앞에 보이지 않는 BOM(﻿)을 붙인다
    log = tmp_path / "bom.log"
    log.write_bytes("﻿2024-01-15 09:25:01 LOGIN_FAIL user=root ip=10.0.0.5\n".encode("utf-8"))

    with open_log(str(log)) as f:
        first = next(f)

    assert parse_timestamp(first) == ts("2024-01-15 09:25:01")
