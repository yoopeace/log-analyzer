import argparse
from datetime import datetime

THRESHOLD = 3
SENSITIVE_FILES = ['/etc/passwd', '/etc/shadow', '/etc/sudoers']

def read_log(filename):
    with open(filename, 'r') as f:
        lines = f.readlines()
    return lines

def find_suspicious(logs):
    suspicious = []
    for line in logs:
        if 'LOGIN_FAIL' in line:
            suspicious.append(line.strip())
    return suspicious

def count_by_ip(suspicious_logs):
    ip_count = {}
    for line in suspicious_logs:
        ip = line.split('ip=')[1]
        if ip in ip_count:
            ip_count[ip] += 1
        else:
            ip_count[ip] = 1
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
            for sensitive in SENSITIVE_FILES:
                if sensitive in line:
                    alerts.append(f"[경고] 민감파일 접근 - {line.strip()}")
    return alerts

def save_report(ip_count, brute_alerts, file_alerts, output_file):
    now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

    with open(output_file, 'w') as f:
        f.write(f"=== 로그 분석 보고서 ===\n")
        f.write(f"분석 시각: {now}\n\n")

        f.write("IP별 로그인 실패 횟수:\n")
        for ip, count in ip_count.items():
            f.write(f"  {ip} → {count}회\n")

        f.write("\n=== 브루트포스 탐지 결과 ===\n")
        if brute_alerts:
            for alert in brute_alerts:
                f.write(f"{alert}\n")
        else:
            f.write("이상 없음\n")

        f.write("\n=== 민감파일 접근 탐지 결과 ===\n")
        if file_alerts:
            for alert in file_alerts:
                f.write(f"{alert}\n")
        else:
            f.write("이상 없음\n")

    print(f"보고서 저장 완료: {output_file}")

parser = argparse.ArgumentParser(description='로그 분석 도구')
parser.add_argument('logfile', help='분석할 로그 파일 경로')
parser.add_argument('--output', default='report.txt', help='보고서 저장 파일명')
args = parser.parse_args()

logs = read_log(args.logfile)
suspicious = find_suspicious(logs)
ip_count = count_by_ip(suspicious)
brute_alerts = detect_bruteforce(ip_count)
file_alerts = detect_sensitive_access(logs)

print("IP별 로그인 실패 횟수:")
for ip, count in ip_count.items():
    print(f"  {ip} → {count}회")

print()
print("=== 브루트포스 탐지 결과 ===")
if brute_alerts:
    for alert in brute_alerts:
        print(alert)
else:
    print("이상 없음")

print()
print("=== 민감파일 접근 탐지 결과 ===")
if file_alerts:
    for alert in file_alerts:
        print(alert)
else:
    print("이상 없음")

save_report(ip_count, brute_alerts, file_alerts, args.output)