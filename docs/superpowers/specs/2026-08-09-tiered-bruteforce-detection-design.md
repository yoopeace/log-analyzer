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
`test.log`를 생성하며 다음 세 그룹의 `LOGIN_FAIL` 이벤트를 섞어 넣는다:

- **정상 사용자**: IP 여러 개, 각각 `NORMAL_MAX_FAILS`(5) 이하로 무작위 시각에 흩어진
  실패. 어느 단계에서도 걸리지 않아야 한다.
- **완속(slow) 공격자**: 고정 IP 하나, `SLOW_ATTACK_FAILS`(8)회 실패를
  `SLOW_ATTACK_WINDOW_MINUTES`(24시간) 안에 걸쳐 분산 — 짧은 fast 창에서는 절대
  기준을 넘지 않도록 각 실패 사이 간격을 fast 창(10분)보다 충분히 길게 벌린다.
  slow 단계에서만 잡혀야 한다.
- **급속(fast) 공격자**: 고정 IP 하나, `FAST_ATTACK_FAILS`(40)회 실패를
  `FAST_ATTACK_WINDOW_MINUTES`(10분) 안에 몰아넣음. fast 단계에서 잡혀야 한다
  (같은 창 안에 몰려 있으므로 slow 단계에서도 당연히 잡힘 — 정상적인 중복).
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
