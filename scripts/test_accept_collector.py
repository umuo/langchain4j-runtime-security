"""验收器自身的反例：不能将缺失、重复或错误属性误判为通过。"""
import json
import tempfile
import unittest
from pathlib import Path

from accept_collector import verify_sink


class SinkVerificationTest(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.path = Path(self.temporary.name) / "logs.jsonl"
        self.expected = [{"security.event.id": "one", "security.outcome": "DENY"},
                         {"security.event.id": "two", "security.outcome": "ALLOW"}]

    def write(self, fields):
        records = []
        for item in fields:
            attributes = [{"key": key, "value": {"stringValue": value}} for key, value in item.items()]
            attributes.append({"key": "security.duration.nanos", "value": {"intValue": "1"}})
            records.append({"timeUnixNano": "1", "attributes": attributes})
        self.path.write_text(json.dumps({"resourceLogs": [{
            "resource": {"attributes": [{"key": "service.name", "value": {"stringValue": "collector-acceptance"}}]},
            "scopeLogs": [{"logRecords": records}]}]}) + "\n")

    def test_accepts_exact_set_independent_of_order(self):
        self.write(list(reversed(self.expected)))
        self.assertEqual(2, verify_sink(self.path, self.expected, True))

    def test_rejects_missing_event(self):
        self.write(self.expected[:1])
        with self.assertRaises(RuntimeError):
            verify_sink(self.path, self.expected, True)

    def test_rejects_duplicate_with_matching_count(self):
        self.write([self.expected[0], self.expected[0]])
        with self.assertRaises(RuntimeError):
            verify_sink(self.path, self.expected, True)

    def test_rejects_replaced_event_with_matching_count(self):
        self.write([self.expected[0], {"security.event.id": "other", "security.outcome": "ALLOW"}])
        with self.assertRaises(RuntimeError):
            verify_sink(self.path, self.expected, True)

    def test_rejects_changed_decision(self):
        self.write([dict(item, **{"security.outcome": "ALLOW"}) for item in self.expected])
        with self.assertRaises(RuntimeError):
            verify_sink(self.path, self.expected, True)

    def test_rejects_sensitive_marker(self):
        self.write([dict(item, prompt="secret-prompt") for item in self.expected])
        with self.assertRaises(RuntimeError):
            verify_sink(self.path, self.expected, True)

    def test_negative_case_requires_empty_sink(self):
        self.assertEqual(0, verify_sink(self.path, self.expected, False))
        self.write(self.expected)
        with self.assertRaises(RuntimeError):
            verify_sink(self.path, self.expected, False)


if __name__ == "__main__":
    unittest.main()
