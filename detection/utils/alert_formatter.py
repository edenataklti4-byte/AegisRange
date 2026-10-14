
from datetime import datetime


def format_alert(alert):
    """Return a copy of an alert with datetime values as ISO strings."""
    formatted_alert = {}

    for key, value in alert.items():
        if isinstance(value, datetime):
            formatted_alert[key] = value.isoformat()
        else:
            formatted_alert[key] = value

    return formatted_alert
