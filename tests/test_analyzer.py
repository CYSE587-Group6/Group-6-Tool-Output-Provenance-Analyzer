import unittest

from analyzer import (
    parse_logs,
    calculate_log_hash,
    redact_sensitive_data,
)


class TestLogParsing(unittest.TestCase):

    def test_json_object(self):
        records = parse_logs('{"seq": 1}')
        self.assertEqual(records, [{"seq": 1}])

    def test_json_array(self):
        records = parse_logs('[{"seq": 1}, {"seq": 2}]')
        self.assertEqual(len(records), 2)

    def test_jsonl(self):
        records = parse_logs('{"seq": 1}\n{"seq": 2}')
        self.assertEqual(len(records), 2)

    def test_wrapped_json(self):
        records = parse_logs('{"events": [{"seq": 1}]}')
        self.assertEqual(records, [{"seq": 1}])

    def test_utf8_bom(self):
        records = parse_logs('\ufeff{"seq": 1}')
        self.assertEqual(records, [{"seq": 1}])

    def test_invalid_json(self):
        with self.assertRaises(ValueError):
            parse_logs('{"seq":')

    def test_invalid_record(self):
        with self.assertRaises(ValueError):
            parse_logs('[{"seq": 1}, 123]')

    def test_empty_input(self):
        with self.assertRaises(ValueError):
            parse_logs("")


class TestLogIntegrity(unittest.TestCase):

    def test_identical_records(self):
        records = [{"seq": 1}]
        self.assertEqual(
            calculate_log_hash(records),
            calculate_log_hash(records)
        )

    def test_modified_record(self):
        self.assertNotEqual(
            calculate_log_hash([{"seq": 1}]),
            calculate_log_hash([{"seq": 2}])
        )

    def test_key_order_independence(self):
        self.assertEqual(
            calculate_log_hash([{"a": 1, "b": 2}]),
            calculate_log_hash([{"b": 2, "a": 1}])
        )

    def test_record_order_matters(self):
        self.assertNotEqual(
            calculate_log_hash([{"seq": 1}, {"seq": 2}]),
            calculate_log_hash([{"seq": 2}, {"seq": 1}])
        )


class TestSensitiveDataRedaction(unittest.TestCase):

    def test_password_redaction(self):
        result = redact_sensitive_data({
            "password": "synthetic-password"
        })
        self.assertEqual(result["password"], "[REDACTED]")

    def test_api_key_redaction(self):
        result = redact_sensitive_data(
            "api_key=synthetic-key"
        )
        self.assertNotIn("synthetic-key", result)

    def test_bearer_token_redaction(self):
        result = redact_sensitive_data(
            "Bearer synthetic-token"
        )
        self.assertEqual(result, "Bearer [REDACTED]")

    def test_connection_url_redaction(self):
        result = redact_sensitive_data(
            "postgres://user:password@localhost/db"
        )
        self.assertNotIn("user:password", result)

    def test_preserve_evidence(self):
        evidence = {
            "record_index": 10,
            "heuristic_score": 75,
            "risk": "HIGH"
        }
        self.assertEqual(
            redact_sensitive_data(evidence),
            evidence
        )

    def test_original_data_unchanged(self):
        original = {"password": "synthetic-password"}
        redact_sensitive_data(original)

        self.assertEqual(
            original["password"],
            "synthetic-password"
        )


if __name__ == "__main__":
    unittest.main()
