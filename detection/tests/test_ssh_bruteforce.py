from datetime import datetime, timezone, timedelta

from detection.rules.ssh_bruteforce import detect_ssh_bruteforce


base_time = datetime(
    2026, 9, 21, 9, 23, 20, tzinfo=timezone.utc
)

events = []

for i in range(5):
    events.append({
        "timestamp": base_time + timedelta(seconds=i * 5),
        "host": "linux",
        "event_type": "ssh_failed_login",
        "username": "user1",
        "source_ip": "172.16.134.1",
        "source_port": 35000 + i,
    })


alerts = detect_ssh_bruteforce(events)

print(alerts)

