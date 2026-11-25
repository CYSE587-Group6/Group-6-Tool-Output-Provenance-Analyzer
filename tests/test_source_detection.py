import unittest
from pathlib import Path
from analyzer import analyze_logs, load_logs


class TestSourceDetection(unittest.TestCase):

    def make_record(self, preview, status="success"):
        return {
            "seq": 1,
            "session_id": "test-session",
            "task_id": "test-task",
            "tool_name": "fetch",
            "arguments": {
                "url": "https://example.com/package"
            },
            "result_status": status,
            "result_summary": preview
        }

    def categories(self, record):
        report = analyze_logs([record])

        return {
            finding["category"]
            for alert in report["alerts"]
            for finding in alert["findings"]
        }

    def test_unvetted_source_detected(self):
        record = self.make_record(
            "Package is not present in "
            "https://intranet.example/vetted-source-registry"
        )

        self.assertIn(
            "unvetted_dependency_source",
            self.categories(record)
        )

    def test_approved_source_not_flagged(self):
        record = self.make_record(
            "Package is listed in "
            "https://intranet.example/vetted-source-registry"
        )

        self.assertNotIn(
            "unvetted_dependency_source",
            self.categories(record)
        )

    def test_failed_fetch_not_flagged(self):
        record = self.make_record(
            "Package is not present in the vetted-source registry",
            status="error"
        )

        self.assertNotIn(
            "unvetted_dependency_source",
            self.categories(record)
        )

    def test_url_alone_not_flagged(self):
        record = self.make_record(
            "Standard package documentation."
        )

        record["arguments"]["url"] = (
            "https://example.com/unvetted-dependency"
        )

        self.assertNotIn(
            "unvetted_dependency_source",
            self.categories(record)
        )

    def test_reference_source_detection(self):
        root = Path(__file__).resolve().parents[1]
        log = next(root.rglob("poisoned-file.jsonl"))

        report = analyze_logs(load_logs(log))

        alert = next(
            alert for alert in report["alerts"]
            if alert["evidence_reference"]["seq"] == 16
        )

        self.assertEqual(alert["risk"], "MEDIUM")
        self.assertEqual(alert["heuristic_score"], 35)

        self.assertIn(
            "unvetted_dependency_source",
            {
                finding["category"]
                for finding in alert["findings"]
            }
        )


if __name__ == "__main__":
    unittest.main()
