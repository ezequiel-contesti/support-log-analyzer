import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from log_analyzer import analyze_lines, build_findings, detect_level, normalize_message


class LevelAndNormalizeTests(unittest.TestCase):
    def test_detect_level_aliases(self):
        self.assertEqual(detect_level("2026-10-23 10:00:00 WARN slow query"), "WARNING")
        self.assertEqual(detect_level("2026-10-23 10:00:00 FATAL crash"), "CRITICAL")
        self.assertEqual(detect_level("2026-10-23 10:00:00 ERROR timeout"), "ERROR")
        self.assertIsNone(detect_level("a line without a level"))

    def test_normalize_clusters_same_failure(self):
        a = normalize_message(
            "2026-10-23 10:15:08 ERROR database connection timeout host=db-primary:5432 attempt=1 request_id=7f3a21"
        )
        b = normalize_message(
            "2026-10-23 10:16:31 ERROR database connection timeout host=db-primary:5432 attempt=3 request_id=99bc00"
        )
        self.assertEqual(a, b)
        self.assertIn("<n>", a)


class AnalyzeTests(unittest.TestCase):
    SAMPLE = [
        "2026-10-23 09:00:01 INFO service started",
        "2026-10-23 10:15:08 ERROR database connection timeout attempt=1",
        "2026-10-23 10:16:31 ERROR database connection timeout attempt=2",
        "2026-10-23 10:17:02 ERROR api request failed status=502 client=10.0.0.5",
        "2026-10-23 10:29:33 CRITICAL database failover initiated",
        "a line without a level or timestamp",
        "",
    ]

    def test_counts(self):
        report = analyze_lines(self.SAMPLE)
        self.assertEqual(report.total_lines, 6)
        self.assertEqual(report.parsed_lines, 5)
        self.assertEqual(report.level_counts["INFO"], 1)
        self.assertEqual(report.level_counts["ERROR"], 3)
        self.assertEqual(report.error_lines, 4)

    def test_clusters_and_5xx(self):
        report = analyze_lines(self.SAMPLE)
        top_message, top_count = report.error_clusters.most_common(1)[0]
        self.assertEqual(top_count, 2)
        self.assertIn("database connection timeout", top_message)
        self.assertEqual(report.http_5xx["502"], 1)
        self.assertEqual(report.error_ips["10.0.0.5"], 1)

    def test_errors_per_hour_and_findings(self):
        report = analyze_lines(self.SAMPLE)
        self.assertEqual(report.errors_per_hour["2026-10-23 10:00"], 4)
        findings = build_findings(report)
        self.assertTrue(any("dominant failure" in f for f in findings))
        self.assertTrue(any("5xx" in f for f in findings))

    def test_no_errors(self):
        report = analyze_lines(["2026-10-23 09:00:01 INFO all good"])
        self.assertEqual(report.error_lines, 0)
        self.assertTrue(build_findings(report))


if __name__ == "__main__":
    unittest.main()
