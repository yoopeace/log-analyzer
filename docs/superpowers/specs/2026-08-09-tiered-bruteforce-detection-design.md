# 브루트포스 탐지 2단계(fast/slow) 설계

## 배경

현재 `log_analyzer.py`는 단일 `--threshold`/`--window-minutes` 창 안에서 실패 횟수가
기준치를 넘으면 브루트포스로 판정한다. 이 방식은 다음 두 가지를 동시에 만족하는
기준을 고르기 어렵다:

- 정상 사용자는 가끔 비밀번호를 틀려 최대 `NORMAL_MAX_FAILS = 5`회 정도 실패한다.
- 계정 잠금 정책을 의식해 천천히 시도하는 공격자는 짧은 창 안에서는 기준을 넘지
  않도록 속도를 조절할 수 있다 (`SLOW_ATTACK_FAILS = 8`, 긴 창에서만 드러남).
- 반대로 스크립트로 빠르게 몰아치는 공격(`FAST_ATTACK_FAILS = 40`)은 짧은 창에서
  뚜렷하게 드러나지만, 창을 길게 잡으면 완속 공격과 구분이 흐려진다.

하나의 창/기준치로는 이 세 가지를 모두 구분할 수 없으므로, 서로 다른 창 길이를
가진 두 개의 독립된 판정(fast/slow)으로 나눈다.

## 상수

```python
NORMAL_MAX_FAILS = 5             # 참고값: 정상 사용자 최대 시도 (CLI 기본값 아님)
FAST_ATTACK_FAILS = 40
FAST_ATTACK_WINDOW_MINUTES = 10
SLOW_ATTACK_FAILS = 8
SLOW_ATTACK_WINDOW_MINUTES = 1440   # 24시간
```

## CLI

기존 `--threshold`/`--window-minutes`를 제거하고 다음으로 교체한다 (하위 호환 유지
안 함 — 개인 프로젝트이며 테스트·README도 함께 갱신):

- `--fast-threshold` (기본 `FAST_ATTACK_FAILS`)
- `--fast-window` (기본 `FAST_ATTACK_WINDOW_MINUTES`, 분 단위)
- `--slow-threshold` (기본 `SLOW_ATTACK_FAILS`)
- `--slow-window` (기본 `SLOW_ATTACK_WINDOW_MINUTES`, 분 단위)

네 값 모두 1 미만이면 `parser.error`로 거부한다 (기존 검증 방식 유지).

## 탐지 로직

`detect_bruteforce(fail_events, threshold, window_minutes)`의 시그니처는 그대로
둔다. `main()`에서 이를 두 번 호출한다 — 한 번은 fast 파라미터로, 한 번은 slow
파라미터로. 각 호출 결과 알림 문자열에 어느 단계에서 잡혔는지 표시한다:

```
[경고] 브루트포스 의심(급속) - IP: 1.2.3.4 / 10분 내 최다 40회 (...)
[경고] 브루트포스 의심(완속) - IP: 5.6.7.8 / 1440분 내 최다 8회 (...)
```

같은 IP가 두 단계 모두에서 잡히면 두 알림을 모두 보여준다 (억제하지 않음 — 서로
다른 패턴을 나타내므로 둘 다 유의미한 정보).

두 호출의 알림을 하나의 `brute_alerts` 리스트로 합쳐 기존과 동일하게
`build_report_body`에 전달한다. 리포트 형식·종료 코드(`EXIT_DETECTED`) 로직은
변경하지 않는다.

## 영향받는 파일

- `log_analyzer.py`: 상수, CLI 인자, `main()`의 이중 호출, 알림 라벨링
- `test_cli.py`, `test_detection.py`, `test_log_analyzer.py`: `--threshold` 사용처를
  `--fast-threshold`/`--slow-threshold`로 교체
- `README.md`: 옵션 설명 갱신

## 테스트용 로그 생성기 (`gen_log.py`)

2단계 탐지를 눈으로 확인하기 위한 테스트 픽스처 스크립트를 새로 만든다.
`test.log`를 생성하며 다음 네 그룹의 이벤트를 섞어 넣는다. IP 대역은 그룹의 정체를
바로 알아볼 수 있도록 문서 예약 대역을 쓴다 (192.168.0.0/16 = 사설/정상,
203.0.113.0/24 · 198.51.100.7 = TEST-NET 예약 대역/공격).

- **정상 사용자 — 그룹 A "한 번에 여러 번 실수"** (192.168.1.10~192.168.1.14, 5개
  IP): 각 IP가 2분 이내에 정확히 3회 실패. 오탐이 threshold 값에 얼마나 민감한지
  보여주는 그룹 — threshold=3에서는 잡히고, 5 이상에서는 잡히지 않아야 정상
  (과거 커밋에서 threshold를 3→5로 올린 이유와 같은 케이스).
- **정상 사용자 — 그룹 B "흩어진 정상 사용"** (192.168.1.20~192.168.1.29, 10개
  IP): 각 IP가 여러 날에 걸쳐 1~2회만 실패. 어떤 threshold에서도 잡히면 안 된다.
- **완속·분산(rotating) 공격자** (203.0.113.10~203.0.113.24, 15개 IP): 하나의
  공격자가 IP를 돌려가며 시도한다고 가정하고, 각 IP는 정확히 2회만 실패시킨다.
  per-IP 기준으로 판정하는 한 threshold를 아무리 낮춰도(3 이상) 잡을 수 없다는
  것을 보여주는 그룹 — 즉 이 그룹은 모든 threshold에서 "놓침(missed)" 상태로
  남는 것이 기대값이다 (per-IP 탐지의 구조적 한계를 드러내는 용도).
- **급속(fast) 단일 공격자** (198.51.100.7, 고정 IP 1개): `FAST_ATTACK_WINDOW_MINUTES`
  (10분) 이내에 `FAST_ATTACK_FAILS`(40)회 실패. threshold 3/5/6/8 어디서도 반드시
  잡혀야 한다.
- 민감파일 접근(`FILE_ACCESS file=/etc/passwd`) 한 줄도 포함해 기존 탐지도 함께
  확인한다.

각 줄은 `log_analyzer.py`가 읽는 형식을 따른다:
`YYYY-MM-DD HH:MM:SS LOGIN_FAIL ip=<ip>` / `... FILE_ACCESS file=<path> user=<user>`.
시각은 스크립트 실행 시점 기준 상대 시각으로 생성해 항상 최신 로그처럼 보이게 한다.
고정 시드(`random.seed`)를 써서 실행할 때마다 같은 로그가 나오게 한다 (재현 가능한
디버깅을 위해).

출력 파일명은 인자 없이 고정으로 `test.log` (현재 사용 명령과 일치시킴).

## 범위 밖

- 세 번째 이상의 탐지 단계나 설정 가능한 임의 개수의 tier는 다루지 않는다
  (YAGNI — 현재 필요한 건 fast/slow 둘뿐).
- `gen_log.py`에 CLI 옵션(개수·시드 조정 등)을 추가하지 않는다. 필요해지면 그때
  추가한다.
