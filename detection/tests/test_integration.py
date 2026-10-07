from detection.parsers.ssh_parser import parse_ssh_log
from detection.rules.ssh_bruteforce import detect_ssh_bruteforce


events = []

with open("detection/data/auth.log", "r") as log_file:
    for line in log_file:
        event = parse_ssh_log(line)

        if event:
            events.append(event)


print("Parsed SSH failed-login events:", len(events))

alerts = detect_ssh_bruteforce(events)

print("Alerts detected:")

for alert in alerts:
    print(alert)

