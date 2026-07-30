# 로그 분석 도구 (Log Analyzer)

[![CI](https://github.com/yoopeace/log-analyzer/actions/workflows/ci.yml/badge.svg)](https://github.com/yoopeace/log-analyzer/actions/workflows/ci.yml)

## 개요

Python으로 개발한 보안 로그 분석 도구.
시스템 로그에서 브루트포스 공격과 민감파일 접근을 자동으로 탐지함.

## 주요 기능

- 시간 창 기반 브루트포스 탐지 (기본: 10분 내 3회 이상 실패)
- 로그인 실패 횟수를 IP별로 집계
- `/etc/passwd` 등 민감파일 접근 탐지 (정확한 경로 일치 기준)
- 분석 결과를 보고서 파일로 저장
- 로그 파일이 없거나 필드가 누락된 경우에도 오류 없이 안내 후 처리
- 결과를 종료 코드로 구분해 자동화 도구와 연동 가능

## 사용법

```bash
python3 log_analyzer.py [로그파일] --output [보고서파일명]
```

| 옵션 | 기본값 | 설명 |
|------|--------|------|
| `--output` | `report.txt` | 보고서 저장 파일명 |
| `--threshold` | `3` | 브루트포스 판정 기준 실패 횟수 |
| `--window-minutes` | `10` | 판정에 쓰는 시간 창 (분) |

## 사용 예시

```bash
python3 log_analyzer.py sample.log
python3 log_analyzer.py sample.log --output result.txt
```

10분 내 5회 이상으로 기준을 높이려면:

```bash
python3 log_analyzer.py access.log --threshold 5 --window-minutes 10
```

## 탐지 방식

브루트포스는 짧은 시간에 시도를 몰아서 한다는 점이 본질이므로, 전체 기간의 누적
횟수가 아니라 **시간 창 안의 최다 실패 횟수**를 기준으로 판정함.

창을 한 칸씩 밀면서 동시에 창 안에 들어오는 실패 횟수를 세고, 그 최댓값이 기준치
이상이면 경고함. 따라서 몇 달에 걸쳐 드문드문 실패한 IP는 누적 횟수가 기준치를
넘어도 경고하지 않음.

로그 순서가 뒤바뀌어 있어도 시각 기준으로 정렬해 판정함.

## 실행 결과 예시

```
IP별 로그인 실패 횟수:
  10.0.0.5 → 5회
  172.16.0.99 → 1회

=== 브루트포스 탐지 결과 ===
[경고] 브루트포스 의심 - IP: 10.0.0.5 / 10분 내 최다 5회 (2024-01-15 09:25:01 ~ 09:25:05)

=== 민감파일 접근 탐지 결과 ===
[경고] 민감파일 접근 - 2024-01-15 09:24:33 FILE_ACCESS file=/etc/passwd user=admin
보고서 저장 완료: report.txt
```

## 종료 코드

자동화 도구에서 결과를 판단할 수 있도록 종료 코드를 구분함.

| 코드 | 의미 |
|------|------|
| 0 | 탐지된 항목 없음 |
| 1 | 브루트포스 또는 민감파일 접근 탐지 |
| 2 | 입력 오류 (파일 없음, 권한 없음, 입출력 경로 동일) |

## 유의사항

- 지정한 로그 파일이 존재하지 않거나 읽기 권한이 없으면 안내 메시지를 출력하고 종료함
- 입력 로그와 `--output` 경로가 같으면 원본이 덮어써지므로 실행을 거부함
- 항목 이름은 경계를 구분해 인식함 (`client_ip=`를 `ip=`로, `profile=`을 `file=`로 잘못 읽지 않음)
- 이벤트 이름은 독립된 토큰으로만 인정함 (`NOT_LOGIN_FAIL`을 로그인 실패로 세지 않음)
- `ip=`, `file=` 필드가 없는 로그 줄은 집계에서 제외하며 오류를 발생시키지 않음
- UTF-8이 아닌 바이트가 섞인 로그도 오류 없이 처리함 (해당 문자는 대체 문자로 표시)
- 로그에 심어진 ANSI 이스케이프 시퀀스는 제거 후 분석함 (터미널 출력 조작 및 탐지 회피 방지)
- 로그 파일 자체는 한 줄씩 순회하므로 파일 크기와 무관하게 읽을 수 있음

## 알려진 한계

- 로그 형식은 `시각 이벤트이름 항목=값` 형태를 전제함. 다른 형식(JSON 로그 등)은 지원하지 않음
- 시각은 `YYYY-MM-DD HH:MM:SS` 또는 `YYYY-MM-DDTHH:MM:SS` 형태만 읽음. 시간대(timezone) 표기는 해석하지 않으므로 여러 시간대가 섞인 로그는 창 판정이 어긋날 수 있음
- 시각을 읽을 수 없는 줄은 시간 창 판정에서 제외하되, 몇 건이 제외됐는지 보고서에 표기함
- 로그인 실패 이벤트는 집계를 위해 메모리에 보관하므로, 실패 건수가 매우 많으면 사용량이 함께 증가함

## 테스트

전체 테스트(59건 = pytest 38건 + unittest 21건) 실행:

```bash
python3 -m venv .venv
.venv/bin/pip install pytest
.venv/bin/pytest
```

pytest 없이 실행 (unittest 21건만 해당):

```bash
python3 -m unittest test_log_analyzer
```

`test_detection.py`, `test_cli.py`는 pytest 기능을 사용하므로 pytest로만 실행됨.

`main` 브랜치에 push하거나 PR을 올리면 GitHub Actions에서 테스트가 자동 실행됨.

## 기술 스택

- Python 3
- 라이브러리: argparse, collections, datetime, pathlib, re

## 탐지 가능한 공격 패턴

| 공격 유형 | 탐지 방법 |
|----------|----------|
| 브루트포스 | 동일 IP가 시간 창(기본 10분) 안에서 기준치(기본 3회) 이상 로그인 실패 |
| 민감파일 접근 | /etc/passwd, /etc/shadow, /etc/sudoers 경로 정확히 일치 시 감지 |

## 라이선스

MIT License — [LICENSE](LICENSE) 참고

## 개발자

- GitHub: [yoopeace](https://github.com/yoopeace)
- 현직 경찰관 재직
