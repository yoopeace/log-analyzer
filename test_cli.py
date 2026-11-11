"""명령줄 동작 테스트 (pytest 스타일)

대부분은 main() 에 인자 목록을 넘겨 같은 프로세스 안에서 확인한다.
실제로 `python3 log_analyzer.py` 를 실행하는 테스트는 맨 앞의 몇 건만 둔다
(진입점이 살아 있고 종료 코드가 운영체제까지 전달되는지 확인용).

종료 코드 약속
  0: 탐지 없음
  1: 브루트포스 또는 민감파일 접근 탐지
  2: 입력 오류 (파일 없음, 권한 없음, 저장 실패, 잘못된 옵션, 입출력 경로 동일)
"""

import os
import subprocess
import sys
from pathlib import Path

import pytest

from log_analyzer import main

# cwd를 바꿔 실행해도 스크립트를 찾을 수 있도록 절대 경로로 고정
ANALYZER = str(Path(__file__).parent / "log_analyzer.py")

ONE_FAIL = "2024-01-15 09:25:01 LOGIN_FAIL user=root ip=10.0.0.5\n"
CLEAN = "2024-01-15 09:23:11 LOGIN_SUCCESS user=admin ip=192.168.1.10\n"
# 누적 기본 기준(24시간 8회)을 넘는 실패
EIGHT_FAILS = "".join(
    f"2024-01-15 09:25:0{i} LOGIN_FAIL user=root ip=10.0.0.5\n" for i in range(1, 9)
)


def run(*args, cwd=None):
    """분석기를 하위 프로세스로 실행하고 결과를 돌려준다."""
    return subprocess.run(
        [sys.executable, ANALYZER, *args],
        cwd=cwd,
        capture_output=True,
        text=True,
        timeout=30,
    )


def write_log(tmp_path, text, name="a.log"):
    log = tmp_path / name
    log.write_text(text, encoding="utf-8")
    return log


def analyze_cli(tmp_path, log, *options):
    """main() 을 직접 부른다. 보고서는 tmp_path 안에 저장한다."""
    return main([str(log), "--output", str(tmp_path / "r.txt"), *options])


def rejected_option(capsys, argv):
    """argparse 가 거부한 옵션의 종료 코드와 오류 문구를 돌려준다."""
    with pytest.raises(SystemExit) as exc:
        main(argv)
    return exc.value.code, capsys.readouterr().err


# ─────────────────────────────────────────
# 1. 실제 실행 (진입점과 종료 코드 전달)
# ─────────────────────────────────────────

def test_실행하면_탐지_시_종료코드_1(tmp_path):
    log = write_log(tmp_path, EIGHT_FAILS)
    assert run(str(log), "--output", str(tmp_path / "r.txt")).returncode == 1


def test_실행하면_탐지_없을_때_종료코드_0(tmp_path):
    log = write_log(tmp_path, CLEAN)
    assert run(str(log), "--output", str(tmp_path / "r.txt")).returncode == 0


def test_실행하면_입력_오류_시_종료코드_2와_안내문(tmp_path):
    result = run(str(tmp_path / "no_such.log"), "--output", str(tmp_path / "r.txt"))

    assert result.returncode == 2
    assert "찾을 수 없습니다" in result.stdout


# ─────────────────────────────────────────
# 2. 종료 코드와 보고서
# ─────────────────────────────────────────

def test_탐지된_항목이_있으면_종료코드_1(tmp_path):
    assert analyze_cli(tmp_path, write_log(tmp_path, EIGHT_FAILS)) == 1


def test_탐지된_항목이_없으면_종료코드_0(tmp_path):
    assert analyze_cli(tmp_path, write_log(tmp_path, CLEAN)) == 0


def test_결과를_화면에_보여주고_보고서_파일로_저장한다(tmp_path, capsys):
    analyze_cli(tmp_path, write_log(tmp_path, EIGHT_FAILS))

    out = capsys.readouterr().out
    report = (tmp_path / "r.txt").read_text(encoding="utf-8")
    assert "브루트포스 의심(누적) - IP: 10.0.0.5" in out
    assert "브루트포스 의심(누적) - IP: 10.0.0.5" in report
    assert f"보고서 저장 완료: {tmp_path / 'r.txt'}" in out


# ─────────────────────────────────────────
# 3. 입력 오류
# ─────────────────────────────────────────

def test_로그_파일이_없으면_종료코드_2(tmp_path, capsys):
    missing = tmp_path / "no_such.log"

    assert analyze_cli(tmp_path, missing) == 2
    assert capsys.readouterr().out == f"❌ 로그 파일을 찾을 수 없습니다: {missing}\n"


@pytest.mark.skipif(os.geteuid() == 0, reason="root 는 권한과 관계없이 읽을 수 있다")
def test_로그_파일을_읽을_권한이_없으면_종료코드_2(tmp_path, capsys):
    log = write_log(tmp_path, ONE_FAIL)
    log.chmod(0o000)
    try:
        assert analyze_cli(tmp_path, log) == 2
    finally:
        log.chmod(0o644)
    assert capsys.readouterr().out == f"❌ 로그 파일을 읽을 권한이 없습니다: {log}\n"


def test_로그_경로가_폴더면_종료코드_2와_안내문(tmp_path, capsys):
    folder = tmp_path / "logs"
    folder.mkdir()

    assert analyze_cli(tmp_path, folder) == 2
    assert capsys.readouterr().out == f"❌ 로그 파일이 아니라 폴더입니다: {folder}\n"


def test_그_밖의_이유로_로그를_열_수_없어도_종료코드_2와_안내문(tmp_path, capsys, monkeypatch):
    # 위에서 따로 안내하는 경우 말고도 운영체제가 파일 열기를 거부할 수 있다
    # (예: 열린 파일 수 한도 초과). 이때도 오류 추적 화면 대신 안내문으로 끝나야 한다.
    import log_analyzer

    def refuse(filename):
        raise OSError(24, "Too many open files")
    monkeypatch.setattr(log_analyzer, "open_log", refuse)
    log = write_log(tmp_path, ONE_FAIL)

    assert analyze_cli(tmp_path, log) == 2
    assert capsys.readouterr().out == (
        f"❌ 로그 파일을 열 수 없습니다: {log} → [Errno 24] Too many open files\n"
    )


def test_보고서를_저장할_수_없으면_결과는_보여주고_종료코드_2(tmp_path, capsys):
    log = write_log(tmp_path, ONE_FAIL)
    output = tmp_path / "no_such_dir" / "r.txt"

    assert main([str(log), "--output", str(output)]) == 2

    out = capsys.readouterr().out
    assert "IP별 로그인 실패 횟수:" in out          # 분석 결과는 화면에 남는다
    assert f"❌ 보고서를 저장할 수 없습니다: {output} → " in out
    assert "보고서 저장 완료" not in out


def test_입력_로그와_출력_경로가_같으면_거부한다(tmp_path, capsys):
    log = write_log(tmp_path, ONE_FAIL, name="events.log")

    code, err = rejected_option(capsys, [str(log), "--output", str(log)])

    assert code == 2
    assert "서로 다른 파일이어야 합니다" in err
    assert log.read_text() == ONE_FAIL, "원본 로그가 덮어써졌다"


def test_출력이_로그의_하드링크면_거부한다(tmp_path, capsys):
    # 경로는 달라도 실제로는 같은 파일이다. 저장하면 원본 로그가 사라진다.
    log = write_log(tmp_path, ONE_FAIL, name="events.log")
    link = tmp_path / "report.txt"
    os.link(log, link)

    code, err = rejected_option(capsys, [str(log), "--output", str(link)])

    assert code == 2
    assert "서로 다른 파일이어야 합니다" in err
    assert log.read_text() == ONE_FAIL, "원본 로그가 덮어써졌다"


def test_출력이_로그를_가리키는_심볼릭_링크면_거부한다(tmp_path, capsys):
    log = write_log(tmp_path, ONE_FAIL, name="events.log")
    link = tmp_path / "report.txt"
    link.symlink_to(log)

    code, _ = rejected_option(capsys, [str(log), "--output", str(link)])

    assert code == 2
    assert log.read_text() == ONE_FAIL


def test_상대경로와_절대경로로_같은_파일을_가리켜도_거부한다(tmp_path, capsys, monkeypatch):
    log = write_log(tmp_path, "LOGIN_FAIL user=root ip=10.0.0.5\n", name="events.log")
    monkeypatch.chdir(tmp_path)

    # 같은 파일을 서로 다른 표기로 지정
    code, _ = rejected_option(capsys, ["events.log", "--output", str(log)])

    assert code == 2
    assert log.read_text() == "LOGIN_FAIL user=root ip=10.0.0.5\n"


# ─────────────────────────────────────────
# 4. 탐지 기준 옵션
# ─────────────────────────────────────────

def test_기간을_두고_흩어진_실패는_탐지하지_않는다(tmp_path, capsys):
    log = write_log(tmp_path,
                    "2024-01-15 09:00:00 LOGIN_FAIL user=root ip=10.0.0.5\n"
                    "2024-03-20 14:00:00 LOGIN_FAIL user=root ip=10.0.0.5\n"
                    "2024-07-02 21:00:00 LOGIN_FAIL user=root ip=10.0.0.5\n")

    assert analyze_cli(tmp_path, log) == 0, "오랜 기간에 흩어진 실패를 브루트포스로 오판함"
    assert "이상 없음" in capsys.readouterr().out


def test_slow_threshold_옵션으로_누적_기준을_낮추면_탐지된다(tmp_path):
    log = write_log(tmp_path,
                    "2024-01-15 09:00:00 LOGIN_FAIL user=root ip=10.0.0.5\n"
                    "2024-01-15 09:20:00 LOGIN_FAIL user=root ip=10.0.0.5\n"
                    "2024-01-15 09:40:00 LOGIN_FAIL user=root ip=10.0.0.5\n")

    # 기본 설정에서는 탐지되지 않는다 (급속 40회·누적 8회 미만)
    assert analyze_cli(tmp_path, log) == 0
    # 누적 기준치를 3으로 낮추면 40분 동안의 3회가 탐지된다
    assert analyze_cli(tmp_path, log, "--slow-threshold", "3") == 1


def test_slow_window_옵션으로_창을_좁히면_탐지되지_않는다(tmp_path):
    log = write_log(tmp_path,
                    "2024-01-15 09:00:00 LOGIN_FAIL user=root ip=10.0.0.5\n"
                    "2024-01-15 09:20:00 LOGIN_FAIL user=root ip=10.0.0.5\n"
                    "2024-01-15 09:40:00 LOGIN_FAIL user=root ip=10.0.0.5\n")

    assert analyze_cli(tmp_path, log, "--slow-threshold", "3") == 1
    # 창을 30분으로 좁히면 3회가 한 창에 들어가지 않는다
    assert analyze_cli(tmp_path, log, "--slow-threshold", "3", "--slow-window", "30") == 0


def test_fast_threshold_옵션으로_기준치를_바꿀_수_있다(tmp_path, capsys):
    log = write_log(tmp_path,
                    "2024-01-15 09:25:01 LOGIN_FAIL user=root ip=10.0.0.5\n"
                    "2024-01-15 09:25:02 LOGIN_FAIL user=root ip=10.0.0.5\n")

    assert analyze_cli(tmp_path, log) == 0
    assert analyze_cli(tmp_path, log, "--fast-threshold", "2") == 1
    assert "브루트포스 의심(급속)" in capsys.readouterr().out


@pytest.mark.parametrize("option", ["--fast-threshold", "--fast-window",
                                    "--slow-threshold", "--slow-window"])
@pytest.mark.parametrize("value", ["0", "-5", "abc"])
def test_탐지_기준_옵션은_1_이상의_정수만_받는다(tmp_path, capsys, option, value):
    log = write_log(tmp_path, ONE_FAIL)

    code, err = rejected_option(capsys, [str(log), option, value])

    assert code == 2
    assert f"argument {option}: 1 이상의 정수여야 합니다 (입력값: {value})" in err


@pytest.mark.parametrize("option", ["--fast-window", "--slow-window"])
def test_너무_큰_시간_창은_안내문과_함께_거부한다(tmp_path, capsys, option):
    log = write_log(tmp_path, ONE_FAIL)

    code, err = rejected_option(capsys, [str(log), option, "99999999999999"])

    assert code == 2, "오류 추적 화면으로 끝나면 종료 코드가 1(탐지됨)로 보인다"
    assert f"argument {option}: 시간 창은 최대 1439999999999분까지 지정할 수 있습니다" in err


def test_시각을_못_읽은_실패는_보고서에_별도_표기한다(tmp_path, capsys):
    analyze_cli(tmp_path, write_log(tmp_path, "LOGIN_FAIL user=root ip=10.0.0.5\n"))

    assert "시각을 읽을 수 없어" in capsys.readouterr().out


def test_긴_시간에_걸친_실패는_누적_경고로_표시된다(tmp_path, capsys):
    # 등급 이름은 실제 판정 기준(24시간 동안 쌓인 횟수)을 나타내야 한다
    log = write_log(tmp_path, "".join(
        f"2024-01-15 {9 + i:02d}:00:00 LOGIN_FAIL user=root ip=203.0.113.7\n" for i in range(8)
    ))

    analyze_cli(tmp_path, log)

    out = capsys.readouterr().out
    assert "브루트포스 의심(누적) - IP: 203.0.113.7" in out
    assert "완속" not in out
