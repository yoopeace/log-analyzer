import argparse
import re
import sys
from collections import deque
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path

NORMAL_MAX_FAILS = 5              # 참고값: 정상 사용자 최대 시도 (CLI 기본값 아님)
FAST_ATTACK_FAILS = 40
FAST_ATTACK_WINDOW_MINUTES = 10
SLOW_ATTACK_FAILS = 8
SLOW_ATTACK_WINDOW_MINUTES = 1440  # 24시간
SENSITIVE_FILES = ['/etc/passwd', '/etc/shadow', '/etc/sudoers']

# 종료 코드: 0 탐지 없음 / 1 탐지됨 / 2 입력 오류
EXIT_CLEAN = 0
EXIT_DETECTED = 1
EXIT_INPUT_ERROR = 2

# ANSI 이스케이프 시퀀스 전체 (예: \x1b[31m) — 앞의 \x1b만 지우면 '[31m' 이 남는다
ANSI_ESCAPE = re.compile(r'\x1b\[[0-9;?]*[ -/]*[@-~]')
# 개행/탭을 제외한 제어문자
CONTROL_CHARS = re.compile(r'[\x00-\x08\x0b-\x1f\x7f]')

def sanitize_line(line):
    # 로그는 공격자가 내용을 심을 수 있는 신뢰할 수 없는 입력이므로 제어문자를 제거한다.
    # 이벤트 이름을 색상 코드로 감싸 탐지를 피하는 것도 막기 위해 시퀀스 전체를 지운다.
    line = ANSI_ESCAPE.sub('', line)
    return CONTROL_CHARS.sub('', line)

def open_log(filename):
    # utf-8-sig: 윈도우 메모장 등이 붙이는 BOM(﻿)을 떼고 읽는다.
    #            떼지 않으면 첫 줄 맨 앞에 보이지 않는 글자가 남아 시각을 못 읽는다.
    # errors='replace': UTF-8이 아닌 바이트가 섞여 있어도 분석을 계속한다
    try:
        return open(filename, 'r', encoding='utf-8-sig', errors='replace')
    except FileNotFoundError:
        print(f"❌ 로그 파일을 찾을 수 없습니다: {filename}")
        sys.exit(EXIT_INPUT_ERROR)
    except PermissionError:
        print(f"❌ 로그 파일을 읽을 권한이 없습니다: {filename}")
        sys.exit(EXIT_INPUT_ERROR)


# 줄 앞머리의 '2024-01-15 09:25:01' 또는 '2024-01-15T09:25:01' 형태
TIMESTAMP = re.compile(r'^\s*(\d{4}-\d{2}-\d{2})[ T](\d{2}:\d{2}:\d{2})')

def parse_timestamp(line):
    """줄 앞머리의 시각을 읽는다. 읽을 수 없으면 None."""
    match = TIMESTAMP.match(line)
    if match is None:
        return None
    try:
        return datetime.strptime(f"{match.group(1)} {match.group(2)}", '%Y-%m-%d %H:%M:%S')
    except ValueError:
        # 형식은 맞지만 2월 30일처럼 존재하지 않는 날짜인 경우
        return None

def extract_field(line, field):
    # (?<!\S): 항목 이름 앞이 공백이거나 줄 시작이어야 한다.
    # 이 조건이 없으면 'client_ip=' 의 'ip=' 나 'profile=' 의 'file=' 을 잘못 집어낸다.
    pattern = rf'(?<!\S){re.escape(field)}=(\S+)'
    match = re.search(pattern, line)
    return match.group(1) if match else None

def scan_log(lines):
    """로그를 한 줄씩 훑어 (시각, IP) 실패 이벤트와 민감파일 경고를 모은다.

    대용량 로그도 처리할 수 있도록 전체를 메모리에 올리지 않고 한 번만 순회한다.
    시각을 읽을 수 없는 줄은 시각을 None으로 담아 호출한 쪽이 판단하게 한다.
    """
    fail_events = []
    file_alerts = []
    for raw_line in lines:
        line = sanitize_line(raw_line)
        # 이벤트 이름은 독립된 토큰으로만 인정한다.
        # 부분 문자열로 찾으면 'NOT_LOGIN_FAIL' 같은 값도 실패로 세게 된다.
        tokens = line.split()
        if 'LOGIN_FAIL' in tokens:
            ip = extract_field(line, 'ip')
            if ip is not None:
                fail_events.append((parse_timestamp(line), ip))
        if 'FILE_ACCESS' in tokens:
            accessed_file = extract_field(line, 'file')
            if accessed_file in SENSITIVE_FILES:
                file_alerts.append(f"[경고] 민감파일 접근 - {line.strip()}")
    return fail_events, file_alerts

def count_by_ip(fail_events):
    """IP별 총 실패 횟수. 시각을 못 읽은 건도 총계에는 포함한다."""
    ip_count = {}
    for _, ip in fail_events:
        ip_count[ip] = ip_count.get(ip, 0) + 1
    return ip_count

def count_undated(fail_events):
    """시각을 읽을 수 없어 시간 창 판정에서 빠지는 건수."""
    return sum(1 for timestamp, _ in fail_events if timestamp is None)

def detect_bruteforce(fail_events, threshold=FAST_ATTACK_FAILS, window_minutes=FAST_ATTACK_WINDOW_MINUTES, label=''):
    """같은 IP가 시간 창 안에서 기준치 이상 실패했는지 판정한다.

    브루트포스는 '짧은 시간에 몰아서 시도한다'는 것이 본질이므로
    전체 기간의 누적 횟수가 아니라 창 안의 최다 횟수를 기준으로 삼는다.
    시각을 읽을 수 없는 이벤트는 창 판정에 쓸 수 없어 제외한다.
    """
    window = timedelta(minutes=window_minutes)

    times_by_ip = {}
    for timestamp, ip in fail_events:
        if timestamp is None:
            continue
        times_by_ip.setdefault(ip, []).append(timestamp)

    alerts = []
    for ip, times in times_by_ip.items():
        times.sort()   # 로그 순서가 뒤바뀌어 있어도 판정할 수 있게 정렬한다

        # 창을 밀면서 동시에 창 안에 들어오는 최다 실패 횟수를 찾는다
        recent = deque()
        peak_count = 0
        peak_range = None
        for current in times:
            recent.append(current)
            while recent and current - recent[0] > window:
                recent.popleft()
            if len(recent) > peak_count:
                peak_count = len(recent)
                peak_range = (recent[0], current)

        if peak_count >= threshold:
            start, end = peak_range
            label_part = f"({label})" if label else ""
            alerts.append(
                f"[경고] 브루트포스 의심{label_part} - IP: {ip} / "
                f"{window_minutes}분 내 최다 {peak_count}회 "
                f"({start.strftime('%Y-%m-%d %H:%M:%S')} ~ {end.strftime('%H:%M:%S')})"
            )
    return alerts

def format_ip_counts(ip_count):
    lines = ["IP별 로그인 실패 횟수:"]
    for ip, count in ip_count.items():
        lines.append(f"  {ip} → {count}회")
    return "\n".join(lines)

def format_alerts(title, alerts):
    lines = [f"=== {title} ==="]
    lines.extend(alerts if alerts else ["이상 없음"])
    return "\n".join(lines)

def format_undated(undated_count):
    # 조용히 버리지 않고 몇 건이 판정에서 빠졌는지 알려 사람이 판단하게 한다
    return f"※ 시각을 읽을 수 없어 시간 창 판정에서 제외된 로그인 실패: {undated_count}건"

def build_report_body(ip_count, brute_alerts, file_alerts, undated_count=0):
    sections = [
        format_ip_counts(ip_count),
        format_alerts("브루트포스 탐지 결과", brute_alerts),
        format_alerts("민감파일 접근 탐지 결과", file_alerts),
    ]
    if undated_count:
        sections.append(format_undated(undated_count))
    return "\n\n".join(sections)


@dataclass
class Analysis:
    """분석 결과 한 묶음. CLI 와 웹앱이 같은 결과를 쓰도록 analyze() 가 만든다."""
    ip_count: dict
    brute_alerts: list
    file_alerts: list
    undated_count: int

    @property
    def alerts(self):
        return self.brute_alerts + self.file_alerts

    def report(self):
        return build_report_body(self.ip_count, self.brute_alerts,
                                 self.file_alerts, self.undated_count)

def analyze(lines,
            fast_threshold=FAST_ATTACK_FAILS, fast_window=FAST_ATTACK_WINDOW_MINUTES,
            slow_threshold=SLOW_ATTACK_FAILS, slow_window=SLOW_ATTACK_WINDOW_MINUTES):
    """로그 줄들을 받아 탐지를 모두 수행한다.

    분석 흐름을 이 함수 한 곳에만 둔다. CLI 와 웹앱이 각자 흐름을 복사해 두면
    한쪽만 고쳐졌을 때 두 결과가 서로 달라진다.
    """
    fail_events, file_alerts = scan_log(lines)
    fast = detect_bruteforce(fail_events, fast_threshold, fast_window, label='급속')
    slow = detect_bruteforce(fail_events, slow_threshold, slow_window, label='완속')
    return Analysis(count_by_ip(fail_events), fast + slow, file_alerts,
                    count_undated(fail_events))

def save_report(body, output_file):
    now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    try:
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(f"=== 로그 분석 보고서 ===\n분석 시각: {now}\n\n{body}\n")
    except OSError as e:
        print(f"❌ 보고서를 저장할 수 없습니다: {output_file} → {e}")
        sys.exit(EXIT_INPUT_ERROR)
    print(f"보고서 저장 완료: {output_file}")

def main():
    parser = argparse.ArgumentParser(description='로그 분석 도구')
    parser.add_argument('logfile', help='분석할 로그 파일 경로')
    parser.add_argument('--output', default='report.txt', help='보고서 저장 파일명')
    parser.add_argument('--fast-threshold', type=int, default=FAST_ATTACK_FAILS,
                        help=f'급속 탐지 기준 실패 횟수 (기본 {FAST_ATTACK_FAILS}회)')
    parser.add_argument('--fast-window', type=int, default=FAST_ATTACK_WINDOW_MINUTES,
                        help=f'급속 탐지 시간 창 (기본 {FAST_ATTACK_WINDOW_MINUTES}분)')
    parser.add_argument('--slow-threshold', type=int, default=SLOW_ATTACK_FAILS,
                        help=f'완속 탐지 기준 실패 횟수 (기본 {SLOW_ATTACK_FAILS}회)')
    parser.add_argument('--slow-window', type=int, default=SLOW_ATTACK_WINDOW_MINUTES,
                        help=f'완속 탐지 시간 창 (기본 {SLOW_ATTACK_WINDOW_MINUTES}분)')
    args = parser.parse_args()

    if args.fast_threshold < 1:
        parser.error("--fast-threshold 는 1 이상이어야 합니다.")
    if args.fast_window < 1:
        parser.error("--fast-window 는 1 이상이어야 합니다.")
    if args.slow_threshold < 1:
        parser.error("--slow-threshold 는 1 이상이어야 합니다.")
    if args.slow_window < 1:
        parser.error("--slow-window 는 1 이상이어야 합니다.")

    # 분석 대상 로그를 보고서로 덮어쓰면 원본이 복구 불가능하게 사라진다
    if Path(args.logfile).resolve() == Path(args.output).resolve():
        parser.error("입력 로그와 출력 보고서는 서로 다른 파일이어야 합니다.")

    with open_log(args.logfile) as f:
        result = analyze(f, args.fast_threshold, args.fast_window,
                         args.slow_threshold, args.slow_window)

    body = result.report()
    print(body)
    save_report(body, args.output)

    # 탐지 결과를 종료 코드로 알려 자동화 도구가 판단할 수 있게 한다
    return EXIT_DETECTED if result.alerts else EXIT_CLEAN

if __name__ == '__main__':
    sys.exit(main())
