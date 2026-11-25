import unittest
from pathlib import Path
from analyzer import analyze_logs, load_logs


class TestPathDeduplication(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        root = Path(__file__).resolve().parents[1]
        log = next(root.rglob("poisoned-file.jsonl"))
        report = analyze_logs(load_logs(log))

        cls.alerts = {
            alert["evidence_reference"]["seq"]: alert
            for alert in report["alerts"]
        }

    def path_findings(self, seq):
        return [
            finding
            for finding in self.alerts[seq]["findings"]
            if finding["category"] == "path_containment_violation"
        ]

    def test_git_diff_deduplication(self):
        self.assertEqual(len(self.path_findings(12)), 1)

    def test_worktree_deduplication(self):
        self.assertEqual(len(self.path_findings(21)), 1)

    def test_evidence_fields_preserved(self):
        self.assertEqual(
            set(self.path_findings(12)[0]["evidence_fields"]),
            {"pathspec", "target_resource"}
        )

        self.assertEqual(
            set(self.path_findings(21)[0]["evidence_fields"]),
            {"path", "target_resource"}
        )

    def test_risk_scores_preserved(self):
        self.assertEqual(
            self.alerts[12]["heuristic_score"], 65
        )

        self.assertEqual(
            self.alerts[21]["heuristic_score"], 75
        )


if __name__ == "__main__":
    unittest.main()
