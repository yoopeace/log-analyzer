# 로그 분석 도구 (Log Analyzer)

## 개요
Python으로 개발한 보안 로그 분석 도구입니다.
시스템 로그에서 **브루트포스 공격**과 **민감파일 접근**을 자동으로 탐지합니다.

## 주요 기능
- 로그인 실패 횟수를 IP별로 집계
- 임계값(기본 3회) 초과 시 브루트포스 공격 경고
- `/etc/passwd` 등 민감파일 접근 탐지
- 분석 결과를 보고서 파일로 저장

## 사용법
```bash
python3 log_analyzer.py [로그파일] --output [보고서파일명]
```

## 사용 예시
```bash
python3 log_analyzer.py sample.log
python3 log_analyzer.py sample.log --output result.txt
```

## 기술 스택
- Python 3
- 라이브러리: argparse, datetime

## 탐지 가능한 공격 패턴
| 공격 유형 | 탐지 방법 |
|----------|----------|
| 브루트포스 | 동일 IP 로그인 실패 3회 이상 |
| 민감파일 접근 | /etc/passwd, /etc/shadow, /etc/sudoers 접근 감지 |