from detection.parsers.ssh_parser import parse_ssh_log
from detection.rules.ssh_bruteforce import detect_ssh_bruteforce


events = []

with open("detection/data/auth.log", "r") as log_file:
    for line in log_file:
        event = parse_ssh_log(line)

        if event:
            events.append(event)


failed_events = [
    event for event in events
    if event["event_type"] == "ssh_failed_login"
]

successful_events = [
    event for event in events
    if event["event_type"] == "ssh_successful_login"
]

print("Total parsed SSH events:", len(events))
print("Failed logins:", len(failed_events))
print("Successful logins:", len(successful_events))
alerts = detect_ssh_bruteforce(events)

print("Alerts detected:")

for alert in alerts:
    print(alert)
