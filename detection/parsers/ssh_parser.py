import re
from datetime import datetime


FAILED_LOGIN_PATTERN = re.compile(
    r"^(?P<timestamp>\S+)\s+"
    r"(?P<host>\S+)\s+"
    r"sshd\S*\[\d+\]:\s+"
    r"Failed password for (?:invalid user )?"
    r"(?P<username>\S+)\s+"
    r"from\s+(?P<source_ip>\S+)\s+"
    r"port\s+(?P<source_port>\d+)"
)


SUCCESSFUL_LOGIN_PATTERN = re.compile(
    r"^(?P<timestamp>\S+)\s+"
    r"(?P<host>\S+)\s+"
    r"sshd\S*\[\d+\]:\s+"
    r"Accepted password for "
    r"(?P<username>\S+)\s+"
    r"from\s+(?P<source_ip>\S+)\s+"
    r"port\s+(?P<source_port>\d+)"
)


def parse_ssh_log(line):
    match = FAILED_LOGIN_PATTERN.search(line)

    if match:
        data = match.groupdict()

        return {
            "timestamp": datetime.fromisoformat(data["timestamp"]),
            "host": data["host"],
            "event_type": "ssh_failed_login",
            "username": data["username"],
            "source_ip": data["source_ip"],
            "source_port": int(data["source_port"]),
        }

    match = SUCCESSFUL_LOGIN_PATTERN.search(line)

    if match:
        data = match.groupdict()

        return {
            "timestamp": datetime.fromisoformat(data["timestamp"]),
            "host": data["host"],
            "event_type": "ssh_successful_login",
            "username": data["username"],
            "source_ip": data["source_ip"],
            "source_port": int(data["source_port"]),
        }

    return None
