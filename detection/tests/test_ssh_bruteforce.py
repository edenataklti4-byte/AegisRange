
from datetime import datetime, timedelta, timezone

from detection.rules.ssh_bruteforce import detect_ssh_bruteforce


base_time = datetime(2026, 9, 21, 9, 23, 20, tzinfo=timezone.utc)


def make_failed_event(seconds, source_ip="172.16.134.1"):
    return {
        "timestamp": base_time + timedelta(seconds=seconds),
        "event_type": "ssh_failed_login",
        "username": "user1",
        "source_ip": source_ip,
        "source_port": 35376,
    }


def test_detects_brute_force():
    events = [
        make_failed_event(0),
        make_failed_event(5),
        make_failed_event(10),
        make_failed_event(15),
        make_failed_event(20),
    ]

    alerts = detect_ssh_bruteforce(events)

    assert len(alerts) == 1
    assert alerts[0]["alert_type"] == "ssh_brute_force"
    assert alerts[0]["severity"] == "high"
    assert alerts[0]["source_ip"] == "172.16.134.1"
    assert alerts[0]["failed_attempts"] >= 5


def test_no_alert_below_threshold():
    events = [
        make_failed_event(0),
        make_failed_event(5),
        make_failed_event(10),
        make_failed_event(15),
    ]

    alerts = detect_ssh_bruteforce(events)

    assert alerts == []


def test_ignores_successful_logins():
    events = [
        {
            "timestamp": base_time,
            "event_type": "ssh_successful_login",
            "username": "bupuser",
            "source_ip": "172.16.134.1",
            "source_port": 58928,
        }
    ]

    alerts = detect_ssh_bruteforce(events)

    assert alerts == []


if __name__ == "__main__":
    test_detects_brute_force()
    test_no_alert_below_threshold()
    test_ignores_successful_logins()
    print("All SSH brute-force tests passed.")

