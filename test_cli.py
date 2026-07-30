"""명령줄 동작 테스트 (pytest 스타일)

실제로 프로그램을 실행해서 종료 코드와 파일 보호 동작을 확인한다.

종료 코드 약속
  0: 탐지 없음
  1: 브루트포스 또는 민감파일 접근 탐지
  2: 입력 오류 (파일 없음, 권한 없음, 입출력 경로 동일)
"""

import subprocess
import sys
from pathlib import Path

# cwd를 바꿔 실행해도 스크립트를 찾을 수 있도록 절대 경로로 고정
ANALYZER = str(Path(__file__).parent / "log_analyzer.py")


def run(*args, cwd=None):
    """분석기를 하위 프로세스로 실행하고 결과를 돌려준다."""
    return subprocess.run(
        [sys.executable, ANALYZER, *args],
        cwd=cwd,
        capture_output=True,
        text=True,
    )


def test_입력_로그와_출력_경로가_같으면_거부한다(tmp_path):
    log = tmp_path / "events.log"
    log.write_text("2024-01-15 09:25:01 LOGIN_FAIL user=root ip=10.0.0.5\n")
    original = log.read_text()

    result = run(str(log), "--output", str(log))

    assert result.returncode == 2
    assert log.read_text() == original, "원본 로그가 덮어써졌다"


def test_상대경로와_절대경로로_같은_파일을_가리켜도_거부한다(tmp_path):
    log = tmp_path / "events.log"
    log.write_text("LOGIN_FAIL user=root ip=10.0.0.5\n")
    original = log.read_text()

    # 같은 파일을 서로 다른 표기로 지정
    result = run("events.log", "--output", str(log), cwd=tmp_path)

    assert result.returncode == 2
    assert log.read_text() == original


def test_탐지된_항목이_있으면_종료코드_1(tmp_path):
    log = tmp_path / "attack.log"
    log.write_text(
        "2024-01-15 09:25:01 LOGIN_FAIL user=root ip=10.0.0.5\n"
        "2024-01-15 09:25:02 LOGIN_FAIL user=root ip=10.0.0.5\n"
        "2024-01-15 09:25:03 LOGIN_FAIL user=root ip=10.0.0.5\n"
    )

    result = run(str(log), "--output", str(tmp_path / "report.txt"))

    assert result.returncode == 1


def test_탐지된_항목이_없으면_종료코드_0(tmp_path):
    log = tmp_path / "clean.log"
    log.write_text("2024-01-15 09:23:11 LOGIN_SUCCESS user=admin ip=192.168.1.10\n")

    result = run(str(log), "--output", str(tmp_path / "report.txt"))

    assert result.returncode == 0


def test_로그_파일이_없으면_종료코드_2(tmp_path):
    result = run(str(tmp_path / "no_such.log"), "--output", str(tmp_path / "r.txt"))

    assert result.returncode == 2
    assert "찾을 수 없습니다" in result.stdout


# ─────────────────────────────────────────
# 시간 창 옵션
# ─────────────────────────────────────────

def test_기간을_두고_흩어진_실패는_탐지하지_않는다(tmp_path):
    log = tmp_path / "spread.log"
    log.write_text(
        "2024-01-15 09:00:00 LOGIN_FAIL user=root ip=10.0.0.5\n"
        "2024-03-20 14:00:00 LOGIN_FAIL user=root ip=10.0.0.5\n"
        "2024-07-02 21:00:00 LOGIN_FAIL user=root ip=10.0.0.5\n"
    )

    result = run(str(log), "--output", str(tmp_path / "r.txt"))

    assert result.returncode == 0, "오랜 기간에 흩어진 실패를 브루트포스로 오판함"
    assert "이상 없음" in result.stdout


def test_window_minutes_옵션으로_창을_넓히면_탐지된다(tmp_path):
    log = tmp_path / "slow.log"
    log.write_text(
        "2024-01-15 09:00:00 LOGIN_FAIL user=root ip=10.0.0.5\n"
        "2024-01-15 09:20:00 LOGIN_FAIL user=root ip=10.0.0.5\n"
        "2024-01-15 09:40:00 LOGIN_FAIL user=root ip=10.0.0.5\n"
    )
    report = str(tmp_path / "r.txt")

    # 기본 창(10분)에서는 탐지되지 않는다
    assert run(str(log), "--output", report).returncode == 0
    # 창을 60분으로 넓히면 탐지된다
    assert run(str(log), "--output", report, "--window-minutes", "60").returncode == 1


def test_threshold_옵션으로_기준치를_바꿀_수_있다(tmp_path):
    log = tmp_path / "two.log"
    log.write_text(
        "2024-01-15 09:25:01 LOGIN_FAIL user=root ip=10.0.0.5\n"
        "2024-01-15 09:25:02 LOGIN_FAIL user=root ip=10.0.0.5\n"
    )
    report = str(tmp_path / "r.txt")

    assert run(str(log), "--output", report).returncode == 0
    assert run(str(log), "--output", report, "--threshold", "2").returncode == 1


def test_잘못된_옵션값은_거부한다(tmp_path):
    log = tmp_path / "a.log"
    log.write_text("2024-01-15 09:25:01 LOGIN_FAIL user=root ip=10.0.0.5\n")

    assert run(str(log), "--threshold", "0").returncode == 2
    assert run(str(log), "--window-minutes", "-5").returncode == 2


def test_시각을_못_읽은_실패는_보고서에_별도_표기한다(tmp_path):
    log = tmp_path / "undated.log"
    log.write_text("LOGIN_FAIL user=root ip=10.0.0.5\n")

    result = run(str(log), "--output", str(tmp_path / "r.txt"))

    assert "시각을 읽을 수 없어" in result.stdout
