import argparse
import re
import sys
from datetime import datetime

THRESHOLD = 3
SENSITIVE_FILES = ['/etc/passwd', '/etc/shadow', '/etc/sudoers']

# 개행/탭을 제외한 제어문자 (ANSI 이스케이프 등 터미널 출력 조작에 쓰일 수 있음)
CONTROL_CHARS = re.compile(r'[\x00-\x08\x0b-\x1f\x7f]')

def sanitize_line(line):
    # 로그는 공격자가 내용을 심을 수 있는 신뢰할 수 없는 입력이므로 제어문자를 제거한다
    return CONTROL_CHARS.sub('', line)

def open_log(filename):
    # errors='replace': UTF-8이 아닌 바이트가 섞여 있어도 분석을 계속한다
    try:
        return open(filename, 'r', errors='replace')
    except FileNotFoundError:
        print(f"❌ 로그 파일을 찾을 수 없습니다: {filename}")
        sys.exit(1)
    except PermissionError:
        print(f"❌ 로그 파일을 읽을 권한이 없습니다: {filename}")
        sys.exit(1)

def extract_field(line, field):
    marker = f"{field}="
    if marker not in line:
        return None
    value = line.split(marker, 1)[1].strip()
    return value.split()[0] if value else None

def scan_log(lines):
    # 대용량 로그도 처리할 수 있도록 전체를 메모리에 올리지 않고 한 줄씩 한 번만 순회한다
    suspicious = []
    file_alerts = []
    for raw_line in lines:
        line = sanitize_line(raw_line)
        if 'LOGIN_FAIL' in line:
            suspicious.append(line.strip())
        if 'FILE_ACCESS' in line:
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
    with open(output_file, 'w') as f:
        f.write(f"=== 로그 분석 보고서 ===\n분석 시각: {now}\n\n{body}\n")
    print(f"보고서 저장 완료: {output_file}")

def main():
    parser = argparse.ArgumentParser(description='로그 분석 도구')
    parser.add_argument('logfile', help='분석할 로그 파일 경로')
    parser.add_argument('--output', default='report.txt', help='보고서 저장 파일명')
    args = parser.parse_args()

    with open_log(args.logfile) as f:
        suspicious, file_alerts = scan_log(f)
    ip_count = count_by_ip(suspicious)
    brute_alerts = detect_bruteforce(ip_count)

    body = build_report_body(ip_count, brute_alerts, file_alerts)
    print(body)
    save_report(body, args.output)

if __name__ == '__main__':
    main()
