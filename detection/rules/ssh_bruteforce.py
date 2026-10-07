from datetime import timedelta


def detect_ssh_bruteforce(events, threshold=5, window_seconds=60):
    alerts = []

    failed_events = [
        event for event in events
        if event.get("event_type") == "ssh_failed_login"
    ]

    # Group events by source IP
    events_by_ip = {}

    for event in failed_events:
        ip = event["source_ip"]
        events_by_ip.setdefault(ip, []).append(event)

    # Check each IP for repeated failures
    for ip, ip_events in events_by_ip.items():
        ip_events.sort(key=lambda event: event["timestamp"])

        for i in range(len(ip_events)):
            start_time = ip_events[i]["timestamp"]
            end_time = start_time + timedelta(seconds=window_seconds)

            matching_events = [
                event for event in ip_events[i:]
                if event["timestamp"] <= end_time
            ]

            if len(matching_events) >= threshold:
                alerts.append({
                    "alert_type": "ssh_brute_force",
                    "severity": "high",
                    "source_ip": ip,
                    "failed_attempts": len(matching_events),
                    "first_seen": start_time,
                    "last_seen": matching_events[-1]["timestamp"],
                })

                break

    return alerts
