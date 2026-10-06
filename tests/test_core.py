import unittest

from dns_discovery.failures import FailureSink, redact
from dns_discovery.models import IpRecord


class RedactionTests(unittest.TestCase):
    def test_key_value_secrets_are_removed(self):
        cases = [
            "api_key=super-secret",
            "token: abc123",
            "password = hunter2",
            "Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.payload.signature",
        ]
        for raw in cases:
            with self.subTest(raw=raw):
                cleaned = redact(raw)
                self.assertIn("[REDACTED]", cleaned)
                self.assertNotIn("super-secret", cleaned)
                self.assertNotIn("abc123", cleaned)
                self.assertNotIn("hunter2", cleaned)
                self.assertNotIn("eyJhbGciOiJIUzI1NiJ9", cleaned)

    def test_bearer_token_is_removed(self):
        cleaned = redact("request failed: Bearer top-secret-token")
        self.assertEqual(cleaned, "request failed: Bearer [REDACTED]")

    def test_failure_sink_stores_redacted_message(self):
        sink = FailureSink()
        rec = sink.record("dns", "lookup", "token=my-token", hostname="example.com")
        self.assertEqual(rec.message, "token=[REDACTED]")
        self.assertEqual(len(sink.records), 1)


class ModelTests(unittest.TestCase):
    def test_ip_record_status_is_unique(self):
        record = IpRecord(
            hostname="example.com",
            ip="203.0.113.10",
            first_seen="2026-10-06T00:00:00+00:00",
            last_seen="2026-10-06T00:00:00+00:00",
        )
        record.add_status("VALIDATED")
        record.add_status("VALIDATED")
        self.assertEqual(record.statuses, ["VALIDATED"])


if __name__ == "__main__":
    unittest.main()
