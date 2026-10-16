# 로그 분석 도구 (Log Analyzer)

[![CI](https://github.com/yoopeace/log-analyzer/actions/workflows/ci.yml/badge.svg)](https://github.com/yoopeace/log-analyzer/actions/workflows/ci.yml)

## 개요

Python으로 개발한 보안 로그 분석 도구.
시스템 로그에서 브루트포스 공격과 민감파일 접근을 자동으로 탐지함.

## 주요 기능

- 2단계 브루트포스 탐지: 급속(10분 내 40회↑) · 누적(24시간 내 8회↑)
- 로그인 실패 횟수를 IP별로 집계
- `/etc/passwd` 등 민감파일 접근 탐지 (정확한 경로 일치 기준)
- 분석 결과를 보고서 파일로 저장
- 로그 파일이 없거나 필드가 누락된 경우에도 오류 없이 안내 후 처리
- 결과를 종료 코드로 구분해 자동화 도구와 연동 가능
- 웹앱: 브라우저에서 로그를 올리면 탐지 결과와 AI 해설을 함께 표시 (아래 "웹앱" 참고)

## 파일 구성

| 파일 | 역할 |
|------|------|
| `log_analyzer.py` | 탐지 로직과 CLI (판정의 근거) |
| `streamlit_app.py` | 웹앱 화면 |
| `ai_report.py` | AI 에 보낼 보고서·프롬프트 생성 |
| `sample.log`, `demo_attack.log` | 예시 로그 |
| `test_*.py` | 테스트 |
| `experiments/` | 브루트포스 임계값을 정할 때 쓴 실험 기록 ([설명](experiments/README.md)) |

## 사용법

```bash
python3 log_analyzer.py [로그파일] --output [보고서파일명]
```

| 옵션 | 기본값 | 설명 |
|------|--------|------|
| `--output` | `report.txt` | 보고서 저장 파일명 |
| `--fast-threshold` | `40` | 급속 탐지 기준 실패 횟수 |
| `--fast-window` | `10` | 급속 탐지 시간 창 (분) |
| `--slow-threshold` | `8` | 누적 탐지 기준 실패 횟수 |
| `--slow-window` | `1440` | 누적 탐지 시간 창 (분, 기본 24시간) |

## 사용 예시

```bash
python3 log_analyzer.py sample.log
python3 log_analyzer.py sample.log --output result.txt
```

급속 기준을 낮추거나 누적 기준을 바꾸려면:

```bash
python3 log_analyzer.py access.log --fast-threshold 20 --slow-threshold 5
```

## 탐지 방식

브루트포스는 짧은 시간에 시도를 몰아서 한다는 점이 본질이므로, 전체 기간의 누적
횟수가 아니라 **시간 창 안의 최다 실패 횟수**를 기준으로 판정함.

창을 한 칸씩 밀면서 동시에 창 안에 들어오는 실패 횟수를 세고, 그 최댓값이 기준치
이상이면 경고함. 따라서 몇 달에 걸쳐 드문드문 실패한 IP는 누적 횟수가 기준치를
넘어도 경고하지 않음.

로그 순서가 뒤바뀌어 있어도 시각 기준으로 정렬해 판정함.

같은 IP가 급속·누적 기준을 모두 넘으면 **더 심한 급속 경고 하나만** 표시함. 급속 기준
(10분 40회)을 넘으면 누적 기준(24시간 8회)도 반드시 넘기 때문에, 묶지 않으면 공격 하나에
경고가 2개씩 나와 건수가 부풀려짐.

"누적"은 속도가 아니라 **24시간 동안 쌓인 횟수**로 판정함. 그래서 짧은 시간에 몰린 실패라도
급속 기준(40회)에 못 미치면 누적 경고로 표시됨 (예: 5분 동안 8회 실패).

## 실행 결과 예시

급속·누적 공격과 민감파일 접근이 들어 있는 예시 로그(`demo_attack.log`)로 실행한 결과:

```bash
python3 log_analyzer.py demo_attack.log
```

```
IP별 로그인 실패 횟수:
  192.168.1.20 → 2회
  10.0.0.5 → 45회
  203.0.113.7 → 10회

=== 브루트포스 탐지 결과 ===
[경고] 브루트포스 의심(급속) - IP: 10.0.0.5 / 10분 내 최다 45회 (2026-10-01 09:10:00 ~ 09:13:40)
[경고] 브루트포스 의심(누적) - IP: 203.0.113.7 / 1440분 내 최다 10회 (2026-10-01 09:30:00 ~ 18:30:00)

=== 민감파일 접근 탐지 결과 ===
[경고] 민감파일 접근 - 2026-10-01 20:02:00 FILE_ACCESS file=/etc/shadow user=admin
보고서 저장 완료: report.txt
```

- `10.0.0.5`: 3분 40초 동안 45회 실패 → 급속 공격
- `203.0.113.7`: 9시간에 걸쳐 10회 실패 → 한 번에 몰리지 않아 급속 기준에는 안 걸리지만, 하루 누적 횟수로 잡힘
- `192.168.1.20`: 2회 실패 → 정상 사용자의 비밀번호 실수로 보고 경고하지 않음

## 웹앱 (AI 해설)

Streamlit 웹앱으로 로그 파일을 올리면 왼쪽에 규칙 기반 탐지 결과, 오른쪽에 AI 해설을 보여줌.

```bash
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
.venv/bin/streamlit run streamlit_app.py
```

**역할 분리:** 판정은 `log_analyzer.py`의 규칙이 하고, AI 는 그 결과를 한국어로 풀어 설명만 함. AI 가 틀리더라도 탐지 결과는 바뀌지 않으며, 화면에도 "판정은 왼쪽 결과가 기준"임을 표시함.

**AI 엔진**

| 엔진 | 설명 | 준비물 |
|------|------|--------|
| HF API (기본) | Hugging Face Inference Providers 서버의 모델 사용 | `.streamlit/secrets.toml`에 `HF_TOKEN = "..."` (크레딧 필요) |
| 로컬 | 작은 모델을 내 컴퓨터에서 직접 실행 | `pip install torch transformers` 별도 설치, 첫 실행 시 모델 약 3GB 내려받음 |

`HF_TOKEN`이 없으면 AI 해설만 건너뛰고 탐지 결과는 정상 표시함. `.streamlit/secrets.toml`은 `.gitignore`로 저장소에서 제외됨.

**AI 에 보내는 내용의 보안 처리** (`ai_report.py`)

- 로그 문구는 공격자가 조작할 수 있는 데이터이므로, 시스템 프롬프트에서 그 안의 지시를 따르지 말라고 명시함
- 로그에 심은 ` ``` `로 코드블록을 일찍 닫아 지시문을 끼워 넣지 못하도록 백틱을 치환함
- 길이 제한(6000자)으로 잘리더라도 판정 근거가 남도록, 경고 요약과 경고 목록을 앞에 두고 IP 목록을 맨 뒤에 둠

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
- 누적 기준(24시간 내 8회)은 정상 사용자의 한 번 실수(최대 5회)보다 크게 잡았지만, 하루에 두 번 크게 틀린 정상 사용자(예: 오전 5회 + 오후 5회)는 경고될 수 있음. 기준을 올리면 천천히 시도하는 공격자에게 그만큼 여유를 주게 되므로, 경고를 관제 요원이 확인하는 쪽을 택함
- 로그인 실패 이벤트는 집계를 위해 메모리에 보관하므로, 실패 건수가 매우 많으면 사용량이 함께 증가함

## 테스트

전체 테스트(81건 = pytest 58건 + unittest 23건) 실행:

```bash
python3 -m venv .venv
.venv/bin/pip install pytest
.venv/bin/pytest
```

pytest 없이 실행 (unittest 23건만 해당):

```bash
python3 -m unittest test_log_analyzer
```

`test_detection.py`, `test_cli.py`, `test_ai_report.py`는 pytest 기능을 사용하므로 pytest로만 실행됨.
테스트에는 Streamlit 이 필요 없음 (CI 에서는 pytest 만 설치).

`main` 브랜치에 push하거나 PR을 올리면 GitHub Actions에서 테스트가 자동 실행됨.

## 기술 스택

- Python 3
- CLI: 표준 라이브러리만 사용 (argparse, collections, dataclasses, datetime, pathlib, re)
- 웹앱: streamlit, huggingface_hub

## 탐지 가능한 공격 패턴

| 공격 유형 | 탐지 방법 |
|----------|----------|
| 브루트포스(급속) | 동일 IP가 10분 내 40회 이상 로그인 실패 |
| 브루트포스(누적) | 동일 IP가 24시간 내 8회 이상 로그인 실패 |
| 민감파일 접근 | /etc/passwd, /etc/shadow, /etc/sudoers 경로 정확히 일치 시 감지 |

## 라이선스

MIT License — [LICENSE](LICENSE) 참고

## 개발자

- GitHub: [yoopeace](https://github.com/yoopeace)
- 현직 경찰관 재직
