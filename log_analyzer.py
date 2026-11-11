import argparse
import os
import posixpath
import re
import sys
from collections import deque
from dataclasses import dataclass, replace
from datetime import datetime, timedelta
from pathlib import Path

# 실험 기록용 가정: 정상 사용자는 한 번에 최대 5회까지 틀린다 (experiments/README.md).
# 판정에는 쓰지 않는다. 누적 기준(8회)은 이 값보다 크게 잡되, 하루에 두 번 크게
# 틀린 정상 사용자(5+5회)는 경고될 수 있음을 감수하고 정했다 (README 알려진 한계).
NORMAL_MAX_FAILS = 5

SENSITIVE_FILES = ['/etc/passwd', '/etc/shadow', '/etc/sudoers']

# 종료 코드: 0 탐지 없음 / 1 탐지됨 / 2 입력 오류
EXIT_CLEAN = 0
EXIT_DETECTED = 1
EXIT_INPUT_ERROR = 2

# ANSI 이스케이프 시퀀스 전체 (예: \x1b[31m) — 앞의 \x1b만 지우면 '[31m' 이 남는다
ANSI_ESCAPE = re.compile(r'\x1b\[[0-9;?]*[ -/]*[@-~]')
# 화면을 속일 수 있는 보이지 않는 문자
#   - C0·C1 제어문자 (개행·탭 제외). C1 의 0x9b 는 일부 터미널에서 ESC [ 와 같은 명령 시작이다
#   - 글자 방향을 바꾸는 문자 (U+200E·200F, U+202A~202E, U+2066~2069): 'nimda' 를 'admin' 처럼 보이게 한다
#   - 폭 0 문자 (U+200B~200D, U+2060, U+FEFF): 'LOGIN' 과 '_FAIL' 사이에 끼워 넣어 탐지를 피한다
CONTROL_CHARS = re.compile(r'[\x00-\x08\x0b-\x1f\x7f-\x9f\u200b-\u200f\u202a-\u202e\u2060\u2066-\u2069\ufeff]')

def sanitize_line(line):
    # 로그는 공격자가 내용을 심을 수 있는 신뢰할 수 없는 입력이므로 보이지 않는 문자를 제거한다.
    # 탐지 전에 지우므로, 이벤트 이름을 색상 코드나 폭 0 문자로 쪼개 탐지를 피하는 것도 막는다.
    line = ANSI_ESCAPE.sub('', line)
    return CONTROL_CHARS.sub('', line)

def open_log(filename):
    # utf-8-sig: 윈도우 메모장 등이 붙이는 BOM(\ufeff)을 떼고 읽는다.
    #            떼지 않으면 첫 줄 맨 앞에 보이지 않는 글자가 남아 시각을 못 읽는다.
    # errors='replace': UTF-8이 아닌 바이트가 섞여 있어도 분석을 계속한다
    # 열 수 없으면 예외(FileNotFoundError 등)를 그대로 올려보낸다.
    # 안내문과 종료 코드는 main() 이 정한다.
    return open(filename, 'r', encoding='utf-8-sig', errors='replace')


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

def normalize_path(path):
    """'/etc//shadow', '/etc/./passwd', '/etc/../etc/sudoers' 처럼 표기만 다른 경로를 한 모양으로 맞춘다.

    로그를 남긴 시스템의 실제 파일은 볼 수 없으므로 링크는 따라가지 않고 글자로만 정리한다.
    """
    normalized = posixpath.normpath(path)
    # POSIX 규칙상 normpath 는 맨 앞의 '//' 를 그대로 둔다
    if normalized.startswith('//'):
        normalized = '/' + normalized.lstrip('/')
    return normalized

def extract_field(line, field):
    # (?<!\S): 항목 이름 앞이 공백이거나 줄 시작이어야 한다.
    # 이 조건이 없으면 'client_ip=' 의 'ip=' 나 'profile=' 의 'file=' 을 잘못 집어낸다.
    pattern = rf'(?<!\S){re.escape(field)}=(\S+)'
    match = re.search(pattern, line)
    return match.group(1) if match else None


# 시간 창으로 쓸 수 있는 가장 큰 값(분). 이보다 크면 파이썬이 시간 길이로 표현하지 못한다.
MAX_WINDOW_MINUTES = timedelta.max // timedelta(minutes=1)


@dataclass(frozen=True)
class DetectionTier:
    """브루트포스 탐지 등급 하나: 시간 창 안에서 기준 횟수 이상 실패하면 경고한다.

    기준 횟수·시간 창·이름을 한 값으로 묶어, 어디서 만들든 같은 검사를 거치게 한다.
    기준이 0회면 실패 한 번에도 경고하고, 창이 0 이하면 아무것도 탐지하지 못한다.
    """
    name: str             # 경고에 붙는 등급 이름 ('급속' / '누적')
    threshold: int        # 기준 실패 횟수
    window_minutes: int   # 시간 창 (분)

    def __post_init__(self):
        if self.threshold < 1:
            raise ValueError(f"{self.name} 탐지 기준 횟수는 1 이상이어야 합니다: {self.threshold}")
        if self.window_minutes < 1:
            raise ValueError(f"{self.name} 탐지 시간 창은 1분 이상이어야 합니다: {self.window_minutes}")
        if self.window_minutes > MAX_WINDOW_MINUTES:
            raise ValueError(f"{self.name} 탐지 시간 창은 최대 {MAX_WINDOW_MINUTES}분입니다: {self.window_minutes}")

# 급속: 짧은 시간에 몰아서 시도하는 공격
FAST_TIER = DetectionTier('급속', threshold=40, window_minutes=10)
# 누적: 하루 동안 쌓인 실패 횟수로 보는 공격 (속도와 관계없이 횟수 기준)
# 이름의 SLOW 와 옵션 이름 --slow-* 는 예전 등급 이름 '완속'에서 왔다.
SLOW_TIER = DetectionTier('누적', threshold=8, window_minutes=1440)   # 24시간
# 앞에 있을수록 심한 등급이다. 같은 IP가 여러 등급에 걸리면 가장 앞 등급만 남긴다.
DEFAULT_TIERS = (FAST_TIER, SLOW_TIER)


# 경고는 문장이 아니라 데이터로 다룬다. 문장은 화면·보고서에 찍는 순간에만 만든다.
# 문장으로 흘려보내면 같은 IP의 경고를 묶거나, 등급별로 세거나, 테스트에서
# 값을 비교할 수 없고 '10분' in alert 처럼 글자를 찾는 수밖에 없다.
@dataclass(frozen=True)
class BruteforceAlert:
    ip: str
    tier: str             # '급속' / '누적' (빈 문자열이면 등급 표시 없음)
    window_minutes: int
    count: int            # 창 안의 최다 실패 횟수
    start: datetime
    end: datetime

@dataclass(frozen=True)
class FileAccessAlert:
    path: str             # 접근한 민감파일 경로
    line: str             # 정제된 원본 로그 줄

def format_bruteforce(alert):
    tier_part = f"({alert.tier})" if alert.tier else ""
    # 끝 시각은 같은 날이면 시각만, 날짜가 바뀌면 날짜까지 쓴다.
    # (24시간 창에서 '23:00:00 ~ 00:59:00' 처럼 거꾸로 보이는 것을 막는다)
    end_format = '%H:%M:%S' if alert.start.date() == alert.end.date() else '%Y-%m-%d %H:%M:%S'
    return (f"[경고] 브루트포스 의심{tier_part} - IP: {alert.ip} / "
            f"{alert.window_minutes}분 내 최다 {alert.count}회 "
            f"({alert.start:%Y-%m-%d %H:%M:%S} ~ {alert.end.strftime(end_format)})")

def format_file_access(alert):
    return f"[경고] 민감파일 접근 - {alert.line}"


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
            if accessed_file is not None:
                # 표기만 바꿔(/etc//shadow 등) 탐지를 피하지 못하게 정리한 뒤 비교한다
                accessed_file = normalize_path(accessed_file)
                if accessed_file in SENSITIVE_FILES:
                    file_alerts.append(FileAccessAlert(accessed_file, line.strip()))
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

def detect_bruteforce(fail_events, tier):
    """같은 IP가 등급의 시간 창 안에서 기준 횟수 이상 실패했는지 판정한다.

    브루트포스는 '짧은 시간에 몰아서 시도한다'는 것이 본질이므로
    전체 기간의 누적 횟수가 아니라 창 안의 최다 횟수를 기준으로 삼는다.
    시각을 읽을 수 없는 이벤트는 창 판정에 쓸 수 없어 제외한다.
    """
    window = timedelta(minutes=tier.window_minutes)

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

        if peak_count >= tier.threshold:
            start, end = peak_range
            alerts.append(BruteforceAlert(ip, tier.name, tier.window_minutes, peak_count, start, end))
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
        format_alerts("브루트포스 탐지 결과", [format_bruteforce(a) for a in brute_alerts]),
        format_alerts("민감파일 접근 탐지 결과", [format_file_access(a) for a in file_alerts]),
    ]
    if undated_count:
        sections.append(format_undated(undated_count))
    return "\n\n".join(sections)


@dataclass
class Analysis:
    """분석 결과 한 묶음. analyze() 가 만든다."""
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

def analyze(lines, tiers=DEFAULT_TIERS):
    """로그 줄들을 받아 탐지를 모두 수행한다.

    분석 흐름을 이 함수 한 곳에만 둔다. 호출하는 쪽이 흐름을 복사해 두면
    한쪽만 고쳐졌을 때 결과가 서로 달라진다.
    tiers 는 심한 등급부터 나열한다 (기본: 급속, 누적).
    """
    fail_events, file_alerts = scan_log(lines)

    # 같은 IP가 여러 등급에 걸리면 가장 앞(가장 심한) 등급 경고 하나만 남긴다.
    # 급속 기준(10분 40회)을 넘으면 누적 기준(24시간 8회)도 반드시 넘으므로,
    # 묶지 않으면 공격 하나에 경고가 2개씩 나와 건수가 부풀려진다.
    brute_alerts = []
    alerted_ips = set()
    for tier in tiers:
        for alert in detect_bruteforce(fail_events, tier):
            if alert.ip not in alerted_ips:
                brute_alerts.append(alert)
                alerted_ips.add(alert.ip)

    return Analysis(count_by_ip(fail_events), brute_alerts, file_alerts,
                    count_undated(fail_events))

def save_report(body, output_file):
    """보고서 파일을 쓴다. 쓸 수 없으면 OSError 를 그대로 올려보낸다."""
    now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    with open(output_file, 'w', encoding='utf-8') as f:
        f.write(f"=== 로그 분석 보고서 ===\n분석 시각: {now}\n\n{body}\n")


def positive_int(text):
    """탐지 기준 옵션 값: 1 이상의 정수만 받는다."""
    try:
        value = int(text)
    except ValueError:
        value = 0
    if value < 1:
        raise argparse.ArgumentTypeError(f"1 이상의 정수여야 합니다 (입력값: {text})")
    return value

def window_minutes_option(text):
    """시간 창 옵션 값: 1 이상, 파이썬이 시간 길이로 표현할 수 있는 크기까지."""
    value = positive_int(text)
    if value > MAX_WINDOW_MINUTES:
        raise argparse.ArgumentTypeError(
            f"시간 창은 최대 {MAX_WINDOW_MINUTES}분까지 지정할 수 있습니다 (입력값: {text})")
    return value

def is_same_file(a, b):
    """경로 표기·심볼릭 링크·하드링크와 관계없이 실제로 같은 파일인지 확인한다."""
    if Path(a).resolve() == Path(b).resolve():
        return True
    try:
        return os.path.samefile(a, b)
    except OSError:
        return False   # 둘 중 하나가 아직 없으면 같은 파일일 수 없다

def build_parser():
    parser = argparse.ArgumentParser(description='로그 분석 도구')
    parser.add_argument('logfile', help='분석할 로그 파일 경로')
    parser.add_argument('--output', default='report.txt', help='보고서 저장 파일명')
    parser.add_argument('--fast-threshold', type=positive_int, default=FAST_TIER.threshold,
                        help=f'급속 탐지 기준 실패 횟수 (기본 {FAST_TIER.threshold}회)')
    parser.add_argument('--fast-window', type=window_minutes_option, default=FAST_TIER.window_minutes,
                        help=f'급속 탐지 시간 창 (기본 {FAST_TIER.window_minutes}분)')
    parser.add_argument('--slow-threshold', type=positive_int, default=SLOW_TIER.threshold,
                        help=f'누적 탐지 기준 실패 횟수 (기본 {SLOW_TIER.threshold}회)')
    parser.add_argument('--slow-window', type=window_minutes_option, default=SLOW_TIER.window_minutes,
                        help=f'누적 탐지 시간 창 (기본 {SLOW_TIER.window_minutes}분)')
    return parser

def main(argv=None):
    """명령줄 진입점. argv 를 주지 않으면 실제 명령줄 인자를 읽는다.

    화면 안내문과 종료 코드는 모두 이 함수가 정한다.
    아래 함수들은 실패를 예외로 알리기만 하고 프로그램을 끝내지 않는다.
    """
    parser = build_parser()
    args = parser.parse_args(argv)

    # 분석 대상 로그를 보고서로 덮어쓰면 원본이 복구 불가능하게 사라진다.
    # 경로 글자만 비교하면 하드링크(같은 파일의 다른 이름)를 놓친다.
    if is_same_file(args.logfile, args.output):
        parser.error("입력 로그와 출력 보고서는 서로 다른 파일이어야 합니다.")

    tiers = (
        replace(FAST_TIER, threshold=args.fast_threshold, window_minutes=args.fast_window),
        replace(SLOW_TIER, threshold=args.slow_threshold, window_minutes=args.slow_window),
    )

    try:
        log = open_log(args.logfile)
    except FileNotFoundError:
        print(f"❌ 로그 파일을 찾을 수 없습니다: {args.logfile}")
        return EXIT_INPUT_ERROR
    except PermissionError:
        print(f"❌ 로그 파일을 읽을 권한이 없습니다: {args.logfile}")
        return EXIT_INPUT_ERROR
    except IsADirectoryError:
        print(f"❌ 로그 파일이 아니라 폴더입니다: {args.logfile}")
        return EXIT_INPUT_ERROR
    except OSError as e:
        # 위에서 따로 안내하지 않는 그 밖의 열기 실패 (열린 파일 수 한도 등)
        print(f"❌ 로그 파일을 열 수 없습니다: {args.logfile} → {e}")
        return EXIT_INPUT_ERROR
    with log:
        result = analyze(log, tiers)

    body = result.report()
    print(body)
    try:
        save_report(body, args.output)
    except OSError as e:
        print(f"❌ 보고서를 저장할 수 없습니다: {args.output} → {e}")
        return EXIT_INPUT_ERROR
    print(f"보고서 저장 완료: {args.output}")

    # 탐지 결과를 종료 코드로 알려 자동화 도구가 판단할 수 있게 한다
    return EXIT_DETECTED if result.alerts else EXIT_CLEAN

if __name__ == '__main__':
    sys.exit(main())
