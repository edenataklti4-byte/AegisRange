from detection.backend_client import send_event
from detection.utils.alert_formatter import format_alert
from detection.parsers.ssh_parser import parse_ssh_log
from detection.rules.ssh_bruteforce import detect_ssh_bruteforce
from detection.rules.ssh_compromise import detect_success_after_failures


def run_detection(log_path="detection/data/auth.log"):
    events = []

    with open(log_path, "r") as log_file:
        for line in log_file:
            event = parse_ssh_log(line)

            if event:
                events.append(event)

    brute_force_alerts = detect_ssh_bruteforce(events)
    compromise_alerts = detect_success_after_failures(events)

    alerts = brute_force_alerts + compromise_alerts
    formatted_alerts = [format_alert(alert) for alert in alerts]

    return {
        "total_events": len(events),
        "failed_logins": sum(
            event["event_type"] == "ssh_failed_login"
            for event in events
        ),
        "successful_logins": sum(
            event["event_type"] == "ssh_successful_login"
            for event in events
        ),
        "alerts": formatted_alerts,
    }

def send_events_to_backend(log_path="detection/data/auth.log"):
    """Parse SSH logs and send each valid event to the backend."""
    results = []

    with open(log_path, "r") as log_file:
        for line in log_file:
            event = parse_ssh_log(line)

            if event:
                results.append(send_event(event))

    return {
        "total_events": len(results),
        "successful": sum(result["success"] for result in results),
        "failed": sum(not result["success"] for result in results),
        "results": results,
    }

if __name__ == "__main__":
    results = run_detection()

    print("Total parsed SSH events:", results["total_events"])
    print("Failed logins:", results["failed_logins"])
    print("Successful logins:", results["successful_logins"])
    print("Total alerts:", len(results["alerts"]))

    for alert in results["alerts"]:
        print(alert)
