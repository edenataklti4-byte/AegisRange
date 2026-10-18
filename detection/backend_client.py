
import json
from datetime import datetime
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


def _json_default(value):
    if isinstance(value, datetime):
        return value.isoformat()

    raise TypeError(
        f"Object of type {type(value).__name__} is not JSON serializable"
    )





def event_to_payload(event):
    """Convert a parsed SSH or Sysmon event into the backend API format."""
    if not isinstance(event, dict):
        raise TypeError("event must be a dictionary")

    event_type = event.get("event_type")

    if event_type:
        log_type = event_type
    else:
        log_type = f"sysmon_event_{event.get('event_id', 'unknown')}"

    fields = event.get("fields", {})

    if not isinstance(fields, dict):
        fields = {}

    source_ip = (
        event.get("source_ip")
        or fields.get("SourceIp")
        or fields.get("SourceIP")
        or fields.get("SourceAddress")
    )

    destination_ip = (
        event.get("destination_ip")
        or fields.get("DestinationIp")
        or fields.get("DestinationIP")
        or fields.get("DestinationAddress")
    )

    return {
        "source_ip": source_ip,
        "destination_ip": destination_ip,
        "log_type": log_type,
        "raw_data": event,
    }



def send_event(event, base_url="http://127.0.0.1:8000"):
    """Send one parsed event to the AegisRange backend."""
    payload = event_to_payload(event)

    body = json.dumps(
        payload,
        default=_json_default,
    ).encode("utf-8")

    request = Request(
        f"{base_url.rstrip('/')}/api/logs",
        data=body,
        headers={"Content-Type": "application/json"},
        method="POST",
    )

    try:
        with urlopen(request, timeout=5) as response:
            return {
                "success": True,
                "status": response.status,
                "body": json.loads(response.read().decode("utf-8")),
            }

    except HTTPError as error:
        return {
            "success": False,
            "status": error.code,
            "body": error.read().decode("utf-8"),
        }

    except (URLError, TimeoutError) as error:
        return {
            "success": False,
            "status": None,
            "body": str(error),
        }
