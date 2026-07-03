# 로그 분석 도구 (Log Analyzer)

## 개요

Python으로 개발한 보안 로그 분석 도구.
시스템 로그에서 브루트포스 공격과 민감파일 접근을 자동으로 탐지함.

## 주요 기능

- 로그인 실패 횟수를 IP별로 집계
- 임계값(기본 3회) 초과 시 브루트포스 공격 경고
- `/etc/passwd` 등 민감파일 접근 탐지 (정확한 경로 일치 기준)
- 분석 결과를 보고서 파일로 저장
- 로그 파일이 없거나 필드가 누락된 경우에도 오류 없이 안내 후 처리

## 사용법

```bash
python3 log_analyzer.py [로그파일] --output [보고서파일명]
```

## 사용 예시

```bash
python3 log_analyzer.py sample.log
python3 log_analyzer.py sample.log --output result.txt
```

## 실행 결과 예시

```
IP별 로그인 실패 횟수:
  10.0.0.5 → 5회
  172.16.0.99 → 1회

=== 브루트포스 탐지 결과 ===
[경고] 브루트포스 의심 - IP: 10.0.0.5 / 실패횟수: 5회

=== 민감파일 접근 탐지 결과 ===
[경고] 민감파일 접근 - 2024-01-15 09:24:33 FILE_ACCESS file=/etc/passwd user=admin
보고서 저장 완료: report.txt
```

## 유의사항

- 지정한 로그 파일이 존재하지 않으면 `❌ 로그 파일을 찾을 수 없습니다` 메시지를 출력하고 종료함
- `ip=`, `file=` 필드가 없는 로그 줄은 집계에서 제외하며 오류를 발생시키지 않음

## 기술 스택

- Python 3
- 라이브러리: argparse, datetime

## 탐지 가능한 공격 패턴

| 공격 유형 | 탐지 방법 |
|----------|----------|
| 브루트포스 | 동일 IP 로그인 실패 3회 이상 |
| 민감파일 접근 | /etc/passwd, /etc/shadow, /etc/sudoers 경로 정확히 일치 시 감지 |

## 개발자

- GitHub: [yoopeace](https://github.com/yoopeace)
- 현직 경찰관 재직
