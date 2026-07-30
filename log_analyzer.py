import argparse
import re
import sys
from datetime import datetime
from pathlib import Path

THRESHOLD = 3
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
    # errors='replace': UTF-8이 아닌 바이트가 섞여 있어도 분석을 계속한다
    try:
        return open(filename, 'r', errors='replace')
    except FileNotFoundError:
        print(f"❌ 로그 파일을 찾을 수 없습니다: {filename}")
        sys.exit(EXIT_INPUT_ERROR)
    except PermissionError:
        print(f"❌ 로그 파일을 읽을 권한이 없습니다: {filename}")
        sys.exit(EXIT_INPUT_ERROR)

def extract_field(line, field):
    # (?<!\S): 항목 이름 앞이 공백이거나 줄 시작이어야 한다.
    # 이 조건이 없으면 'client_ip=' 의 'ip=' 나 'profile=' 의 'file=' 을 잘못 집어낸다.
    pattern = rf'(?<!\S){re.escape(field)}=(\S+)'
    match = re.search(pattern, line)
    return match.group(1) if match else None

def scan_log(lines):
    # 대용량 로그도 처리할 수 있도록 전체를 메모리에 올리지 않고 한 줄씩 한 번만 순회한다
    suspicious = []
    file_alerts = []
    for raw_line in lines:
        line = sanitize_line(raw_line)
        # 이벤트 이름은 독립된 토큰으로만 인정한다.
        # 부분 문자열로 찾으면 'NOT_LOGIN_FAIL' 같은 값도 실패로 세게 된다.
        tokens = line.split()
        if 'LOGIN_FAIL' in tokens:
            suspicious.append(line.strip())
        if 'FILE_ACCESS' in tokens:
            accessed_file = extract_field(line, 'file')
            if accessed_file in SENSITIVE_FILES:
                file_alerts.append(f"[경고] 민감파일 접근 - {line.strip()}")
    return suspicious, file_alerts

def count_by_ip(suspicious_logs):
    ip_count = {}
    for line in suspicious_logs:
        ip = extract_field(line, 'ip')
        if ip is None:
            continue
        ip_count[ip] = ip_count.get(ip, 0) + 1
    return ip_count

def detect_bruteforce(ip_count):
    alerts = []
    for ip, count in ip_count.items():
        if count >= THRESHOLD:
            alerts.append(f"[경고] 브루트포스 의심 - IP: {ip} / 실패횟수: {count}회")
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

def build_report_body(ip_count, brute_alerts, file_alerts):
    return "\n\n".join([
        format_ip_counts(ip_count),
        format_alerts("브루트포스 탐지 결과", brute_alerts),
        format_alerts("민감파일 접근 탐지 결과", file_alerts),
    ])

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
    args = parser.parse_args()

    # 분석 대상 로그를 보고서로 덮어쓰면 원본이 복구 불가능하게 사라진다
    if Path(args.logfile).resolve() == Path(args.output).resolve():
        parser.error("입력 로그와 출력 보고서는 서로 다른 파일이어야 합니다.")

    with open_log(args.logfile) as f:
        suspicious, file_alerts = scan_log(f)
    ip_count = count_by_ip(suspicious)
    brute_alerts = detect_bruteforce(ip_count)

    body = build_report_body(ip_count, brute_alerts, file_alerts)
    print(body)
    save_report(body, args.output)

    # 탐지 결과를 종료 코드로 알려 자동화 도구가 판단할 수 있게 한다
    return EXIT_DETECTED if (brute_alerts or file_alerts) else EXIT_CLEAN

if __name__ == '__main__':
    sys.exit(main())
