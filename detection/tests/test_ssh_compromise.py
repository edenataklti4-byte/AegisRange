
from datetime import datetime, timedelta, timezone

from detection.rules.ssh_compromise import detect_success_after_failures


base_time = datetime(2026, 9, 21, 9, 23, 20, tzinfo=timezone.utc)


def make_failed_event(seconds, source_ip="172.16.134.1"):
    return {
        "timestamp": base_time + timedelta(seconds=seconds),
        "event_type": "ssh_failed_login",
        "username": "user1",
        "source_ip": source_ip,
        "source_port": 35376,
    }


def make_success_event(seconds, source_ip="172.16.134.1"):
    return {
        "timestamp": base_time + timedelta(seconds=seconds),
        "event_type": "ssh_successful_login",
        "username": "bupuser",
        "source_ip": source_ip,
        "source_port": 58928,
    }


def test_detects_success_after_failures():
    events = [
        make_failed_event(0),
        make_failed_event(5),
        make_failed_event(10),
        make_failed_event(15),
        make_failed_event(20),
        make_success_event(25),
    ]

    alerts = detect_success_after_failures(events)

    assert len(alerts) == 1
    assert alerts[0]["alert_type"] == "ssh_success_after_failures"
    assert alerts[0]["severity"] == "critical"
    assert alerts[0]["failed_attempts"] == 5
    assert alerts[0]["username"] == "bupuser"


def test_no_alert_below_failure_threshold():
    events = [
        make_failed_event(0),
        make_failed_event(5),
        make_success_event(10),
    ]

    alerts = detect_success_after_failures(events)

    assert alerts == []


def test_no_alert_for_different_ip():
    events = [
        make_failed_event(0),
        make_failed_event(5),
        make_failed_event(10),
        make_failed_event(15),
        make_failed_event(20),
        make_success_event(25, "10.0.0.5"),
    ]

    alerts = detect_success_after_failures(events)

    assert alerts == []


if __name__ == "__main__":
    test_detects_success_after_failures()
    test_no_alert_below_failure_threshold()
    test_no_alert_for_different_ip()
    print("All SSH compromise detection tests passed.")

