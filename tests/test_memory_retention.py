import unittest
from pathlib import Path
from analyzer import analyze_logs, load_logs


class TestMemoryRetention(unittest.TestCase):

    def setUp(self):
        self.code = (
            "export function calculateTotal(items) {\n"
            "    const subtotal = items.reduce("
            "(sum, item) => sum + item.price, 0);\n"
            "    return subtotal;\n"
            "}\n"
        )

        self.source = {
            "seq": 1,
            "session_id": "test-session",
            "task_id": "test-task",
            "tool_name": "read_text_file",
            "arguments": {"path": "src/example.js"},
            "result_status": "success",
            "result_summary": self.code
        }

        self.memory = {
            "seq": 2,
            "session_id": "test-session",
            "task_id": "test-task",
            "tool_name": "memory_set",
            "arguments": {
                "namespace": "cache",
                "key": "export",
                "value": self.code
            },
            "result_status": "success",
            "result_summary": "stored cache/export"
        }

    def findings(self):
        report = analyze_logs([self.source, self.memory])

        return [
            finding
            for alert in report["alerts"]
            for finding in alert["findings"]
            if finding["category"] == "source_code_retention"
        ]

    def test_source_code_retention_detected(self):
        findings = self.findings()

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["source_seq"], 1)
        self.assertTrue(
            findings[0]["content_overlap_verified"]
        )

    def test_short_summary_not_flagged(self):
        self.memory["arguments"]["value"] = (
            "Calculates the total price of items."
        )

        self.assertEqual(self.findings(), [])

    def test_cross_session_not_correlated(self):
        self.memory["session_id"] = "different-session"

        self.assertEqual(self.findings(), [])

    def test_cross_task_not_correlated(self):
        self.memory["task_id"] = "different-task"

        self.assertEqual(self.findings(), [])

    def test_failed_read_not_correlated(self):
        self.source["result_status"] = "error"

        self.assertEqual(self.findings(), [])

    def test_failed_memory_write_not_flagged(self):
        self.memory["result_status"] = "error"

        self.assertEqual(self.findings(), [])

    def test_non_code_file_not_flagged(self):
        self.source["arguments"]["path"] = "README.md"

        self.assertEqual(self.findings(), [])

    def test_unrelated_content_not_flagged(self):
        self.memory["arguments"]["value"] = "x" * 150

        self.assertEqual(self.findings(), [])

    def test_reference_memory_retention(self):
        root = Path(__file__).resolve().parents[1]
        log = next(root.rglob("poisoned-file.jsonl"))

        report = analyze_logs(load_logs(log))

        alert = next(
            alert for alert in report["alerts"]
            if alert["evidence_reference"]["seq"] == 14
        )

        self.assertEqual(alert["risk"], "MEDIUM")
        self.assertEqual(alert["heuristic_score"], 50)

        finding = next(
            finding for finding in alert["findings"]
            if finding["category"] == "source_code_retention"
        )

        self.assertEqual(finding["source_seq"], 13)
        self.assertTrue(finding["content_overlap_verified"])
        self.assertGreaterEqual(finding["matched_length"], 100)


if __name__ == "__main__":
    unittest.main()
