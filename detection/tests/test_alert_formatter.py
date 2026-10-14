
from datetime import datetime, timezone

from detection.utils.alert_formatter import format_alert


def test_formats_datetime_values():
    alert = {
        "alert_type": "ssh_success_after_failures",
        "severity": "critical",
        "successful_login": datetime(
            2026, 9, 21, 9, 23, 44, tzinfo=timezone.utc
        ),
        "failed_attempts": 5,
    }

    formatted = format_alert(alert)

    assert formatted["successful_login"] == "2026-09-21T09:23:44+00:00"
    assert isinstance(formatted["successful_login"], str)
    assert formatted["alert_type"] == "ssh_success_after_failures"
    assert formatted["failed_attempts"] == 5

    # Confirm that the original alert was not modified.
    assert isinstance(alert["successful_login"], datetime)


if __name__ == "__main__":
    test_formats_datetime_values()
    print("All alert formatter tests passed.")
