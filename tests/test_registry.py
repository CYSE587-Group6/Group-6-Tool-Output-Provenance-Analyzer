import unittest
from analyzer import verify_dependency_registry


class TestRegistryVerification(unittest.TestCase):

    def setUp(self):
        self.source = {
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

        self.action = {
            "seq": 2,
            "session_id": "session-test",
            "task_id": "task-test",
            "tool_name": "write_file",
            "result_status": "success",
            "arguments": {
                "path": "package.json"
            }
        }

    def verify(self, dependency):
        return verify_dependency_registry(
            [self.source, self.action], 1, dependency
        )

    def test_approved_dependency(self):
        result = self.verify("approved-package")
        self.assertEqual(result["registry_status"], "APPROVED")
        self.assertEqual(result["registry_source_seq"], 1)

    def test_unlisted_dependency(self):
        result = self.verify("unknown-package")
        self.assertEqual(result["registry_status"], "NOT_LISTED")

    def test_truncated_registry(self):
        self.source["result_summary"] = (
            "# Vetted Source Registry\n"
            "- approved-package (trusted-publisher)\n"
            + "x" * 200
        )[:200]

        result = self.verify("unknown-package")
        self.assertEqual(result["registry_status"], "INCONCLUSIVE")

    def test_missing_registry(self):
        result = verify_dependency_registry(
            [self.action], 0, "unknown-package"
        )
        self.assertEqual(result["registry_status"], "NOT_CHECKED")

    def test_failed_registry_fetch(self):
        self.source["result_status"] = "error"
        result = self.verify("approved-package")
        self.assertEqual(result["registry_status"], "NOT_CHECKED")

    def test_cross_session_isolation(self):
        self.source["session_id"] = "different-session"
        result = self.verify("approved-package")
        self.assertEqual(result["registry_status"], "NOT_CHECKED")

    def test_cross_task_isolation(self):
        self.source["task_id"] = "different-task"
        result = self.verify("approved-package")
        self.assertEqual(result["registry_status"], "NOT_CHECKED")

    def test_registry_fetch_after_action(self):
        result = verify_dependency_registry(
            [self.action, self.source], 0, "approved-package"
        )
        self.assertEqual(result["registry_status"], "NOT_CHECKED")


if __name__ == "__main__":
    unittest.main()
