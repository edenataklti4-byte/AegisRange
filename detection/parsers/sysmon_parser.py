
import re
from datetime import datetime, timezone


EVENT_HEADER_PATTERN = re.compile(
    r"^(?P<display_time>\d{1,2}/\d{1,2}/\d{4}\s+"
    r"\d{1,2}:\d{2}:\d{2}\s+[AP]M)\s+"
    r"(?P<event_id>1|3|11)\s+"
    r"(?P<description>.*?):\s*$"
)

FIELD_PATTERN = re.compile(r"^(?P<key>[^:]+):\s*(?P<value>.*)$")


def parse_sysmon_event(block):
    """Parse one Sysmon event block in the supplied text format."""
    lines = block.strip().splitlines()

    if not lines:
        return None

    header = EVENT_HEADER_PATTERN.match(lines[0].strip())

    if not header:
        return None

    fields = {}

    for line in lines[1:]:
        match = FIELD_PATTERN.match(line.strip())

        if match:
            fields[match.group("key").strip()] = (
                match.group("value").strip()
            )

    try:
        display_time = datetime.strptime(
            header.group("display_time"),
            "%m/%d/%Y %I:%M:%S %p",
        )
    except ValueError:
        return None

    event_id = int(header.group("event_id"))

    event = {
        "event_id": event_id,
        "description": header.group("description").strip(),
        "display_time": display_time.isoformat(),
        "fields": fields,
    }

    utc_time = fields.get("UtcTime")

    if utc_time:
        try:
            parsed_time = datetime.fromisoformat(utc_time)

            if parsed_time.tzinfo is None:
                parsed_time = parsed_time.replace(tzinfo=timezone.utc)
            else:
                parsed_time = parsed_time.astimezone(timezone.utc)

            event["timestamp"] = parsed_time.isoformat()
        except ValueError:
            event["timestamp"] = None
    else:
        event["timestamp"] = None

    return event


def parse_sysmon_log(text):
    """Parse multiple events from the supplied Sysmon text."""
    events = []
    current_block = []

    for line in text.splitlines():
        if EVENT_HEADER_PATTERN.match(line.strip()):
            if current_block:
                event = parse_sysmon_event("\n".join(current_block))

                if event is not None:
                    events.append(event)

            current_block = [line]
        elif current_block:
            current_block.append(line)

    if current_block:
        event = parse_sysmon_event("\n".join(current_block))

        if event is not None:
            events.append(event)

    return events
