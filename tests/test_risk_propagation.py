import unittest
from pathlib import Path
from analyzer import (
    analyze_logs,
    load_logs,
    propagate_dependency_risk
)


class TestRiskPropagation(unittest.TestCase):

    def setUp(self):
        self.records = [
            self.record(
                1, "write_file",
                {"path": "package.json"}
            ),
            self.record(
                2, "git_add",
                {"path": "package.json"}
            ),
            self.record(
                3, "git_commit",
                {"message": "Update dependencies"}
            )
        ]

        self.alerts = [{
            "record_index": 0,
            "heuristic_score": 65,
            "risk": "HIGH",
            "findings": [{
                "category": "unvetted_dependency_risk"
            }]
        }]

    def record(self, seq, tool, arguments):
        return {
            "seq": seq,
            "session_id": "test-session",
            "task_id": "test-task",
            "tool_name": tool,
            "arguments": arguments,
            "result_status": "success"
        }

    def findings(self):
        propagate_dependency_risk(
            self.records, self.alerts
        )

        return [
            finding
            for alert in self.alerts
            for finding in alert["findings"]
            if finding.get("risk_propagation")
        ]

    def test_risk_propagates_to_staging(self):
        findings = self.findings()

        finding = next(
            f for f in findings
            if f["category"] == "risky_dependency_staged"
        )

        self.assertEqual(finding["source_seq"], 1)
        self.assertEqual(finding["origin_seq"], 1)

    def test_risk_propagates_to_commit(self):
        findings = self.findings()

        finding = next(
            f for f in findings
            if f["category"] == "risky_dependency_committed"
        )

        self.assertEqual(finding["source_seq"], 2)
        self.assertEqual(finding["origin_seq"], 1)

    def test_unrelated_file_not_flagged(self):
        self.records[1]["arguments"]["path"] = "README.md"

        self.assertEqual(self.findings(), [])

    def test_cross_session_not_correlated(self):
        self.records[1]["session_id"] = "other-session"

        self.assertEqual(self.findings(), [])

    def test_cross_task_not_correlated(self):
        self.records[1]["task_id"] = "other-task"

        self.assertEqual(self.findings(), [])

    def test_failed_staging_not_propagated(self):
        self.records[1]["result_status"] = "error"

        self.assertEqual(self.findings(), [])

    def test_failed_commit_not_flagged(self):
        self.records[2]["result_status"] = "error"

        findings = self.findings()

        self.assertEqual(len(findings), 1)
        self.assertEqual(
            findings[0]["category"],
            "risky_dependency_staged"
        )

    def test_missing_registry_alone_not_propagated(self):
        self.alerts[0]["findings"][0]["category"] = (
            "missing_registry_verification"
        )

        self.assertEqual(self.findings(), [])

    def test_commit_without_staging_not_flagged(self):
        self.records.pop(1)

        self.assertEqual(self.findings(), [])

    def test_reset_clears_staging_state(self):
        self.records.insert(
            2, self.record(3, "git_reset", {})
        )

        self.records[-1]["seq"] = 4

        findings = self.findings()

        self.assertEqual(len(findings), 1)
        self.assertEqual(
            findings[0]["category"],
            "risky_dependency_staged"
        )

    def test_later_write_supersedes_pending_risk(self):
        self.records.insert(
            1, self.record(
                2, "write_file",
                {"path": "package.json"}
            )
        )

        self.records[2]["seq"] = 3
        self.records[3]["seq"] = 4

        self.assertEqual(self.findings(), [])

    def test_reference_risk_propagation(self):
        root = Path(__file__).resolve().parents[1]
        log = next(root.rglob("poisoned-file.jsonl"))

        report = analyze_logs(load_logs(log))

        alerts = {
            alert["evidence_reference"]["seq"]: alert
            for alert in report["alerts"]
        }

        self.assertEqual(alerts[19]["heuristic_score"], 50)
        self.assertEqual(alerts[20]["heuristic_score"], 65)

        for seq, category, source in (
            (19, "risky_dependency_staged", 18),
            (20, "risky_dependency_committed", 19)
        ):
            finding = next(
                f for f in alerts[seq]["findings"]
                if f["category"] == category
            )

            self.assertEqual(finding["source_seq"], source)
            self.assertEqual(finding["origin_seq"], 18)
            self.assertTrue(finding["risk_propagation"])


if __name__ == "__main__":
    unittest.main()
