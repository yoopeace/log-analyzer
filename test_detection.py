"""브루트포스 탐지 파이프라인 테스트 (pytest 스타일)

extract_field → count_by_ip → detect_bruteforce 순서로
로그 한 줄에서 IP를 뽑아 집계하고 공격 여부를 판정한다.
"""

from log_analyzer import THRESHOLD, count_by_ip, detect_bruteforce, extract_field


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
    logs = [
        "LOGIN_FAIL user=root ip=10.0.0.5",
        "LOGIN_FAIL user=root ip=10.0.0.5",
        "LOGIN_FAIL user=john ip=172.16.0.99",
    ]
    assert count_by_ip(logs) == {'10.0.0.5': 2, '172.16.0.99': 1}


def test_IP가_없는_줄은_세지_않고_건너뛴다():
    logs = [
        "LOGIN_FAIL user=root ip=10.0.0.5",
        "LOGIN_FAIL user=root",
    ]
    assert count_by_ip(logs) == {'10.0.0.5': 1}


def test_로그가_하나도_없으면_빈_결과를_돌려준다():
    assert count_by_ip([]) == {}


# ─────────────────────────────────────────
# 3. detect_bruteforce: 공격 여부 판정
# ─────────────────────────────────────────

def test_기준치를_넘으면_경고를_만든다():
    alerts = detect_bruteforce({'10.0.0.5': 5})
    assert len(alerts) == 1
    assert '10.0.0.5' in alerts[0]


def test_기준치보다_한_번_적으면_경고하지_않는다():
    assert detect_bruteforce({'10.0.0.5': THRESHOLD - 1}) == []


def test_기준치와_정확히_같으면_경고한다():
    assert len(detect_bruteforce({'10.0.0.5': THRESHOLD})) == 1


def test_집계_결과가_비어_있으면_경고하지_않는다():
    assert detect_bruteforce({}) == []
