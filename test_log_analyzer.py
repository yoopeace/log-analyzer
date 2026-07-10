import unittest

from log_analyzer import (
    build_report_body,
    count_by_ip,
    detect_bruteforce,
    detect_sensitive_access,
    extract_field,
    find_suspicious,
)


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


class TestDetectSensitiveAccess(unittest.TestCase):
    def test_민감파일_접근_탐지(self):
        logs = ["2024-01-15 09:24:33 FILE_ACCESS file=/etc/passwd user=admin"]
        alerts = detect_sensitive_access(logs)
        self.assertEqual(len(alerts), 1)
        self.assertIn('/etc/passwd', alerts[0])

    def test_유사한_경로는_오탐하지_않음(self):
        logs = ["FILE_ACCESS file=/etc/passwd.bak user=admin"]
        self.assertEqual(detect_sensitive_access(logs), [])

    def test_일반_파일은_무시(self):
        logs = ["FILE_ACCESS file=/home/user/memo.txt user=admin"]
        self.assertEqual(detect_sensitive_access(logs), [])


class TestFindSuspicious(unittest.TestCase):
    def test_LOGIN_FAIL_줄만_추출(self):
        logs = [
            "LOGIN_SUCCESS user=admin ip=192.168.1.10\n",
            "LOGIN_FAIL user=root ip=10.0.0.5\n",
        ]
        result = find_suspicious(logs)
        self.assertEqual(result, ["LOGIN_FAIL user=root ip=10.0.0.5"])


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
