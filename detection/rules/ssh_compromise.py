from datetime import timedelta


def detect_success_after_failures(
    events,
    failure_threshold=5,
    window_seconds=60,
):
    alerts = []

    failed_events = [
        event
        for event in events
        if event.get("event_type") == "ssh_failed_login"
    ]

    successful_events = [
        event
        for event in events
        if event.get("event_type") == "ssh_successful_login"
    ]

    for success in successful_events:
        matching_failures = [
            event
            for event in failed_events
            if event["source_ip"] == success["source_ip"]
            and event["timestamp"] <= success["timestamp"]
            and event["timestamp"]
            >= success["timestamp"] - timedelta(seconds=window_seconds)
        ]

        if len(matching_failures) >= failure_threshold:
            alerts.append({
                "alert_type": "ssh_success_after_failures",
                "severity": "critical",
                "source_ip": success["source_ip"],
                "username": success["username"],
                "failed_attempts": len(matching_failures),
                "first_failed": matching_failures[0]["timestamp"],
                "successful_login": success["timestamp"],
            })

    return alerts
