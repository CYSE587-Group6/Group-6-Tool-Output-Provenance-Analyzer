import json
import unittest
from analyzer import analyze_logs


class TestRegistryIntegration(unittest.TestCase):

    def setUp(self):
        self.registry = {
            "seq": 1,
            "session_id": "session-test",
            "task_id": "task-test",
            "tool_name": "fetch",
            "result_status": "success",
            "arguments": {
                "url": "https://intranet.example/vetted-source-registry"
            },
            "result_summary": (
                "# Vetted Source Registry\n"
                "- approved-package (trusted-publisher)\n"
                "Any dependency not on this list requires a "
                "supply-chain review before addition to package.json."
            )
        }

    def manifest(self, dependencies, seq=2):
        return {
            "seq": seq,
            "session_id": "session-test",
            "task_id": "task-test",
            "tool_name": "write_file",
            "result_status": "success",
            "arguments": {
                "path": "package.json",
                "content": json.dumps({
                    "dependencies": dependencies
                })
            }
        }

    def baseline(self, dependencies):
        return {
            "seq": 1,
            "session_id": "session-test",
            "task_id": "task-test",
            "tool_name": "read_text_file",
            "result_status": "success",
            "arguments": {
                "path": "package.json"
            },
            "result_summary": json.dumps({
                "dependencies": dependencies
            })
        }

    def findings(self, records):
        report = analyze_logs(records)
        return [
            finding
            for alert in report["alerts"]
            for finding in alert["findings"]
        ]

    def test_approved_dependency(self):
        findings = self.findings([
            self.registry,
            self.manifest({"approved-package": "1.0.0"})
        ])
        self.assertFalse(any(
            f.get("registry_status") in (
                "NOT_CHECKED", "NOT_LISTED", "INCONCLUSIVE"
            )
            for f in findings
        ))

    def test_unlisted_dependency(self):
        report = analyze_logs([
            self.registry,
            self.manifest({"unknown-package": "1.0.0"})
        ])
        self.assertTrue(any(
            alert["risk"] == "HIGH"
            and any(
                f["category"] == "dependency_not_in_registry"
                and f.get("dependency") == "unknown-package"
                for f in alert["findings"]
            )
            for alert in report["alerts"]
        ))

    def test_incomplete_registry(self):
        self.registry["result_summary"] = (
            "# Vetted Source Registry\n" + "x" * 200
        )[:200]

        findings = self.findings([
            self.registry,
            self.manifest({"unknown-package": "1.0.0"})
        ])
        self.assertTrue(any(
            f["category"] == "incomplete_registry_verification"
            for f in findings
        ))

    def test_missing_registry(self):
        findings = self.findings([
            self.manifest({"unknown-package": "1.0.0"})
        ])
        self.assertTrue(any(
            f["category"] == "missing_registry_verification"
            for f in findings
        ))

    def test_existing_dependency_excluded(self):
        findings = self.findings([
            self.baseline({"existing-package": "1.0.0"}),
            self.manifest({"existing-package": "1.0.0"})
        ])
        self.assertFalse(any(
            f.get("dependency") == "existing-package"
            and "registry" in f["category"]
            for f in findings
        ))

    def test_new_dependency_requires_verification(self):
        findings = self.findings([
            self.baseline({"existing-package": "1.0.0"}),
            self.manifest({
                "existing-package": "1.0.0",
                "new-package": "1.0.0"
            })
        ])
        self.assertTrue(any(
            f["category"] == "missing_registry_verification"
            and f.get("dependency") == "new-package"
            and f.get("dependency_baseline_available") is True
            for f in findings
        ))
        self.assertFalse(any(
            f.get("dependency") == "existing-package"
            and "registry" in f["category"]
            for f in findings
        ))


if __name__ == "__main__":
    unittest.main()
