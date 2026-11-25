import unittest
from pathlib import Path
from analyzer import analyze_logs, load_logs


class TestProvenanceVerification(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        root = Path(__file__).resolve().parents[1]
        log = next(root.rglob("poisoned-file.jsonl"))
        cls.report = analyze_logs(load_logs(log))
        cls.alerts = {
            alert["evidence_reference"]["seq"]: alert
            for alert in cls.report["alerts"]
        }

    def test_dependency_content_overlap(self):
        findings = self.alerts[18]["findings"]
        self.assertTrue(any(
            f["category"] == "content_provenance_overlap"
            and f.get("source_seq") == 16
            and f.get("matched_length") == 18
            for f in findings
        ))

    def test_memory_content_overlap(self):
        findings = self.alerts[22]["findings"]
        self.assertTrue(any(
            f["category"] == "suspicious_memory_activity"
            and f.get("source_seq") == 21
            and f.get("content_overlap_verified") is True
            for f in findings
        ))

    def test_memory_overlap_length(self):
        findings = self.alerts[22]["findings"]
        self.assertTrue(any(
            f["category"] == "suspicious_memory_activity"
            and f.get("matched_length") == 119
            for f in findings
        ))

    def test_missing_registry_verification(self):
        findings = self.alerts[18]["findings"]
        self.assertTrue(any(
            f["category"] == "missing_registry_verification"
            and f.get("dependency") == "quick-currency-fmt"
            and f.get("registry_status") == "NOT_CHECKED"
            for f in findings
        ))


if __name__ == "__main__":
    unittest.main()
