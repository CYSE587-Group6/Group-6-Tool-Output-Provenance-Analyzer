import copy
import unittest
from pathlib import Path

from analyzer import analyze_logs, load_logs


ROOT = Path(__file__).resolve().parents[1]


def load_reference_log(filename):
    matches = sorted(ROOT.rglob(filename))

    if len(matches) != 1:
        raise AssertionError(
            f"Expected one reference file named {filename}, "
            f"found {len(matches)}."
        )

    return load_logs(matches[0])


class TestSecurityDetection(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.clean_records = load_reference_log(
            "session-01(clean).jsonl"
        )

        cls.poisoned_records = load_reference_log(
            "poisoned-file.jsonl"
        )

        cls.clean_report = analyze_logs(cls.clean_records)
        cls.poisoned_report = analyze_logs(cls.poisoned_records)

        cls.alerts = {
            alert["evidence_reference"]["seq"]: alert
            for alert in cls.poisoned_report["alerts"]
        }

    def assert_finding(self, seq, category):
        self.assertIn(seq, self.alerts)

        categories = {
            finding["category"]
            for finding in self.alerts[seq]["findings"]
        }

        self.assertIn(category, categories)

    def test_clean_session(self):
        self.assertEqual(
            self.clean_report["records_analyzed"], 10
        )
        self.assertEqual(
            self.clean_report["alerts_found"], 0
        )

    def test_poisoned_session(self):
        self.assertEqual(
            self.poisoned_report["records_analyzed"], 12
        )

        self.assertTrue(
            {12, 18, 21, 22}.issubset(self.alerts)
        )

    def test_git_argument_injection(self):
        self.assert_finding(
            12, "suspicious_tool_argument"
        )

    def test_harmless_output_mention(self):
        records = [{
            "tool_name": "write_file",
            "arguments": {
                "path": "README.md",
                "content": "Documentation for --output"
            },
            "result_status": "success"
        }]

        report = analyze_logs(records)

        self.assertEqual(report["alerts_found"], 0)

    def test_path_containment(self):
        self.assert_finding(
            21, "path_containment_violation"
        )

    def test_outcome_score_reduction(self):
        self.assertLess(
            self.alerts[12]["outcome_adjustment"], 0
        )

    def test_outcome_score_increase(self):
        self.assertGreater(
            self.alerts[21]["outcome_adjustment"], 0
        )

    def test_behavioral_injection_risk(self):
        self.assert_finding(
            12, "behavioral_injection_risk"
        )

    def test_unvetted_dependency(self):
        self.assert_finding(
            18, "unvetted_dependency_risk"
        )

    def test_suspicious_memory(self):
        self.assert_finding(
            22, "suspicious_memory_activity"
        )

    def test_memory_source_reference(self):
        findings = self.alerts[22]["findings"]

        sources = [
            finding.get("source_seq")
            for finding in findings
            if finding["category"]
            == "suspicious_memory_activity"
        ]

        self.assertIn(21, sources)

    def test_alert_ranking(self):
        alerts = self.poisoned_report["alerts"]

        expected = sorted(
            alerts,
            key=lambda alert: (
                -alert["heuristic_score"],
                alert["record_index"]
            )
        )

        self.assertEqual(alerts, expected)

    def test_score_bounds(self):
        for alert in self.poisoned_report["alerts"]:
            self.assertGreaterEqual(
                alert["heuristic_score"], 0
            )

            self.assertLessEqual(
                alert["heuristic_score"], 100
            )

    def test_annotation_independence(self):
        records = copy.deepcopy(self.poisoned_records)

        for record in records:
            record.pop("annotations", None)
            record.pop("scenario_tag", None)

        report = analyze_logs(records)

        self.assertEqual(
            report["alerts"],
            self.poisoned_report["alerts"]
        )

    def test_original_records_unchanged(self):
        records = copy.deepcopy(self.poisoned_records)
        original = copy.deepcopy(records)

        analyze_logs(records)

        self.assertEqual(records, original)


if __name__ == "__main__":
    unittest.main()
