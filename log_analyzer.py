import argparse
import sys
from datetime import datetime

THRESHOLD = 3
SENSITIVE_FILES = ['/etc/passwd', '/etc/shadow', '/etc/sudoers']

def read_log(filename):
    try:
        with open(filename, 'r') as f:
            return f.readlines()
    except FileNotFoundError:
        print(f"❌ 로그 파일을 찾을 수 없습니다: {filename}")
        sys.exit(1)

def extract_field(line, field):
    marker = f"{field}="
    if marker not in line:
        return None
    value = line.split(marker, 1)[1].strip()
    return value.split()[0] if value else None

def find_suspicious(logs):
    suspicious = []
    for line in logs:
        if 'LOGIN_FAIL' in line:
            suspicious.append(line.strip())
    return suspicious

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

def detect_sensitive_access(logs):
    alerts = []
    for line in logs:
        if 'FILE_ACCESS' in line:
            accessed_file = extract_field(line, 'file')
            if accessed_file in SENSITIVE_FILES:
                alerts.append(f"[경고] 민감파일 접근 - {line.strip()}")
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

    logs = read_log(args.logfile)
    suspicious = find_suspicious(logs)
    ip_count = count_by_ip(suspicious)
    brute_alerts = detect_bruteforce(ip_count)
    file_alerts = detect_sensitive_access(logs)

    body = build_report_body(ip_count, brute_alerts, file_alerts)
    print(body)
    save_report(body, args.output)

if __name__ == '__main__':
    main()
