import os
import tempfile
import unittest

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

    def test_파일이_없으면_종료코드_1로_종료(self):
        with self.assertRaises(SystemExit) as ctx:
            open_log('/no/such/file.log')
        self.assertEqual(ctx.exception.code, 1)


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
        logs = [
            "LOGIN_FAIL user=root ip=10.0.0.5",
            "LOGIN_FAIL user=root ip=10.0.0.5",
            "LOGIN_FAIL user=john ip=172.16.0.99",
        ]
        self.assertEqual(count_by_ip(logs), {'10.0.0.5': 2, '172.16.0.99': 1})

    def test_ip_필드가_없는_줄은_건너뜀(self):
        logs = ["LOGIN_FAIL user=root"]
        self.assertEqual(count_by_ip(logs), {})


class TestDetectBruteforce(unittest.TestCase):
    def test_임계값_이상이면_경고(self):
        alerts = detect_bruteforce({'10.0.0.5': 3})
        self.assertEqual(len(alerts), 1)
        self.assertIn('10.0.0.5', alerts[0])
        self.assertIn('3회', alerts[0])

    def test_임계값_미만이면_경고_없음(self):
        self.assertEqual(detect_bruteforce({'10.0.0.5': 2}), [])


class TestScanLog(unittest.TestCase):
    def test_한_번의_순회로_의심줄과_민감파일_경고를_모두_수집(self):
        # iter()로 감싸 한 번만 순회 가능한 스트림임을 보장 (파일 객체와 동일한 조건)
        lines = iter([
            "LOGIN_SUCCESS user=admin ip=192.168.1.10\n",
            "LOGIN_FAIL user=root ip=10.0.0.5\n",
            "2024-01-15 09:24:33 FILE_ACCESS file=/etc/passwd user=admin\n",
        ])
        suspicious, file_alerts = scan_log(lines)
        self.assertEqual(suspicious, ["LOGIN_FAIL user=root ip=10.0.0.5"])
        self.assertEqual(len(file_alerts), 1)
        self.assertIn('/etc/passwd', file_alerts[0])

    def test_유사한_경로는_오탐하지_않음(self):
        _, file_alerts = scan_log(iter(["FILE_ACCESS file=/etc/passwd.bak user=admin\n"]))
        self.assertEqual(file_alerts, [])

    def test_일반_파일은_무시(self):
        _, file_alerts = scan_log(iter(["FILE_ACCESS file=/home/user/memo.txt user=admin\n"]))
        self.assertEqual(file_alerts, [])

    def test_제어문자가_섞인_줄도_새니타이즈되어_처리(self):
        suspicious, _ = scan_log(iter(["\x1b[31mLOGIN_FAIL\x1b[0m user=root ip=10.0.0.5\n"]))
        self.assertEqual(len(suspicious), 1)
        self.assertNotIn('\x1b', suspicious[0])
        self.assertEqual(extract_field(suspicious[0], 'ip'), '10.0.0.5')


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
