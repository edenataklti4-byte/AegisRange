
import unittest
from datetime import datetime, timezone

from detection.backend_client import event_to_payload, _json_default


class TestBackendClient(unittest.TestCase):

    def test_ssh_event_conversion(self):
        event = {
            "timestamp": datetime(
                2026, 9, 21, tzinfo=timezone.utc
            ),
            "event_type": "ssh_failed_login",
            "source_ip": "172.16.134.1",
            "source_port": 35376,
            "username": "user1",
        }

        payload = event_to_payload(event)

        self.assertEqual(payload["source_ip"], "172.16.134.1")
        self.assertIsNone(payload["destination_ip"])
        self.assertEqual(payload["log_type"], "ssh_failed_login")
        self.assertEqual(payload["raw_data"], event)

    def test_sysmon_event_conversion(self):
        event = {
            "event_id": 3,
            "timestamp": "2026-09-21T09:30:00+00:00",
            "fields": {
                "SourceIp": "10.0.0.5",
                "DestinationIp": "10.0.0.10",
            },
        }

        payload = event_to_payload(event)

        self.assertEqual(payload["log_type"], "sysmon_event_3")
        self.assertEqual(payload["source_ip"], "10.0.0.5")
        self.assertEqual(payload["destination_ip"], "10.0.0.10")

    def test_invalid_event_raises_type_error(self):
        with self.assertRaises(TypeError):
            event_to_payload(None)

    def test_datetime_json_conversion(self):
        timestamp = datetime(2026, 9, 21, tzinfo=timezone.utc)

        self.assertEqual(
            _json_default(timestamp),
            "2026-09-21T00:00:00+00:00",
        )


if __name__ == "__main__":
    unittest.main()
