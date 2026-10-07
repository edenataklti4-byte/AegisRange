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


# Test 1: 5 failures followed by success
events = [
    make_failed_event(0),
    make_failed_event(5),
    make_failed_event(10),
    make_failed_event(15),
    make_failed_event(20),
    make_success_event(25),
]

alerts = detect_success_after_failures(events)

print("Test 1 - 5 failures + success:")
print(alerts)


# Test 2: Only 2 failures followed by success
events = [
    make_failed_event(0),
    make_failed_event(5),
    make_success_event(10),
]

alerts = detect_success_after_failures(events)

print("\nTest 2 - 2 failures + success:")
print(alerts)


# Test 3: 5 failures from one IP, success from another IP
events = [
    make_failed_event(0, "172.16.134.1"),
    make_failed_event(5, "172.16.134.1"),
    make_failed_event(10, "172.16.134.1"),
    make_failed_event(15, "172.16.134.1"),
    make_failed_event(20, "172.16.134.1"),
    make_success_event(25, "10.0.0.5"),
]

alerts = detect_success_after_failures(events)

print("\nTest 3 - Different IP:")
print(alerts)
