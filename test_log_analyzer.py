import os
import tempfile
import unittest
from datetime import datetime

from log_analyzer import (
    build_report_body,
    count_by_ip,
    detect_bruteforce,
    extract_field,
    open_log,
    sanitize_line,
    scan_log,
)


class TestSanitizeLine(unittest.TestCase):
    def test_ANSI_이스케이프_등_제어문자_제거(self):
        line = "\x1b[31mLOGIN_FAIL\x1b[0m user=root ip=10.0.0.5\x07"
        result = sanitize_line(line)
        self.assertNotIn('\x1b', result)
        self.assertNotIn('\x07', result)
        self.assertIn('LOGIN_FAIL', result)
        self.assertIn('ip=10.0.0.5', result)

    def test_개행과_탭은_유지(self):
        self.assertEqual(sanitize_line("a\tb\n"), "a\tb\n")

    def test_일반_텍스트는_그대로(self):
        line = "2024-01-15 09:25:01 LOGIN_FAIL user=root ip=10.0.0.5"
        self.assertEqual(sanitize_line(line), line)


class TestOpenLog(unittest.TestCase):
    def test_UTF8이_아닌_바이트가_있어도_크래시하지_않음(self):
        with tempfile.NamedTemporaryFile(delete=False, suffix='.log') as f:
            f.write(b'\x80\x81\xff LOGIN_FAIL ip=1.2.3.4\n')
            path = f.name
        try:
            with open_log(path) as log_file:
                lines = list(log_file)
            self.assertEqual(len(lines), 1)
            self.assertIn('LOGIN_FAIL', lines[0])
        finally:
            os.unlink(path)

    def test_파일이_없으면_입력오류_종료코드로_종료(self):
        with self.assertRaises(SystemExit) as ctx:
            open_log('/no/such/file.log')
        self.assertEqual(ctx.exception.code, 2)


class TestExtractField(unittest.TestCase):
    def test_기본_필드_추출(self):
        line = "2024-01-15 09:25:01 LOGIN_FAIL user=root ip=10.0.0.5"
        self.assertEqual(extract_field(line, 'ip'), '10.0.0.5')

    def test_뒤에_다른_필드가_있어도_공백_전까지만_추출(self):
        line = "LOGIN_FAIL user=root ip=10.0.0.5 session=abc123"
        self.assertEqual(extract_field(line, 'ip'), '10.0.0.5')

    def test_필드가_없으면_None(self):
        line = "2024-01-15 09:25:01 LOGIN_FAIL user=root"
        self.assertIsNone(extract_field(line, 'ip'))

    def test_값이_비어있으면_None(self):
        line = "LOGIN_FAIL user=root ip="
        self.assertIsNone(extract_field(line, 'ip'))


class TestCountByIp(unittest.TestCase):
    def test_IP별_집계(self):
        events = [
            (datetime(2024, 1, 15, 9, 25, 1), '10.0.0.5'),
            (datetime(2024, 1, 15, 9, 25, 2), '10.0.0.5'),
            (datetime(2024, 1, 15, 9, 31, 10), '172.16.0.99'),
        ]
        self.assertEqual(count_by_ip(events), {'10.0.0.5': 2, '172.16.0.99': 1})

    def test_이벤트가_없으면_빈_집계(self):
        self.assertEqual(count_by_ip([]), {})


class TestDetectBruteforce(unittest.TestCase):
    def test_임계값_이상이_창_안에_몰리면_경고(self):
        events = [(datetime(2024, 1, 15, 9, 25, s), '10.0.0.5') for s in (1, 2, 3)]
        alerts = detect_bruteforce(events, threshold=3, window_minutes=10)
        self.assertEqual(len(alerts), 1)
        self.assertIn('10.0.0.5', alerts[0])
        self.assertIn('3회', alerts[0])

    def test_임계값_미만이면_경고_없음(self):
        events = [(datetime(2024, 1, 15, 9, 25, s), '10.0.0.5') for s in (1, 2)]
        self.assertEqual(detect_bruteforce(events, threshold=3, window_minutes=10), [])


class TestScanLog(unittest.TestCase):
    def test_한_번의_순회로_실패이벤트와_민감파일_경고를_모두_수집(self):
        # iter()로 감싸 한 번만 순회 가능한 스트림임을 보장 (파일 객체와 동일한 조건)
        lines = iter([
            "2024-01-15 09:23:11 LOGIN_SUCCESS user=admin ip=192.168.1.10\n",
            "2024-01-15 09:25:01 LOGIN_FAIL user=root ip=10.0.0.5\n",
            "2024-01-15 09:24:33 FILE_ACCESS file=/etc/passwd user=admin\n",
        ])
        fail_events, file_alerts = scan_log(lines)
        self.assertEqual(
            fail_events,
            [(datetime(2024, 1, 15, 9, 25, 1), '10.0.0.5')],
        )
        self.assertEqual(len(file_alerts), 1)
        self.assertIn('/etc/passwd', file_alerts[0])

    def test_시각이_없는_실패줄은_시각을_None으로_담는다(self):
        fail_events, _ = scan_log(iter(["LOGIN_FAIL user=root ip=10.0.0.5\n"]))
        self.assertEqual(fail_events, [(None, '10.0.0.5')])

    def test_유사한_경로는_오탐하지_않음(self):
        _, file_alerts = scan_log(iter(["FILE_ACCESS file=/etc/passwd.bak user=admin\n"]))
        self.assertEqual(file_alerts, [])

    def test_일반_파일은_무시(self):
        _, file_alerts = scan_log(iter(["FILE_ACCESS file=/home/user/memo.txt user=admin\n"]))
        self.assertEqual(file_alerts, [])

    def test_NOT_LOGIN_FAIL을_로그인_실패로_착각하지_않음(self):
        logs = iter(["INFO message=NOT_LOGIN_FAIL ip=1.2.3.4\n"])
        suspicious, _ = scan_log(logs)
        self.assertEqual(suspicious, [])

    def test_profile_필드를_민감파일_접근으로_착각하지_않음(self):
        logs = iter(["FILE_ACCESS profile=/etc/passwd user=x\n"])
        _, file_alerts = scan_log(logs)
        self.assertEqual(file_alerts, [])

    def test_제어문자가_섞인_줄도_새니타이즈되어_처리(self):
        # ANSI 색상 코드로 이벤트 이름을 감싸 탐지를 피하려는 경우
        lines = iter(["2024-01-15 09:25:01 \x1b[31mLOGIN_FAIL\x1b[0m user=root ip=10.0.0.5\n"])
        fail_events, _ = scan_log(lines)
        self.assertEqual(fail_events, [(datetime(2024, 1, 15, 9, 25, 1), '10.0.0.5')])


class TestBuildReportBody(unittest.TestCase):
    def test_보고서_본문_형식(self):
        body = build_report_body(
            {'10.0.0.5': 5},
            ["[경고] 브루트포스 의심 - IP: 10.0.0.5 / 실패횟수: 5회"],
            [],
        )
        self.assertIn("IP별 로그인 실패 횟수:", body)
        self.assertIn("  10.0.0.5 → 5회", body)
        self.assertIn("=== 브루트포스 탐지 결과 ===", body)
        self.assertIn("[경고] 브루트포스 의심", body)
        self.assertIn("=== 민감파일 접근 탐지 결과 ===\n이상 없음", body)


if __name__ == '__main__':
    unittest.main()
