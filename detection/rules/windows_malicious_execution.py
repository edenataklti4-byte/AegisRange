from datetime import datetime


def _parse_timestamp(event):
    timestamp = event.get("timestamp")

    if not timestamp:
        return None

    try:
        return datetime.fromisoformat(timestamp)
    except (TypeError, ValueError):
        return None


def _normalize_path(value):
    return (value or "").replace("/", "\\").lower()


def detect_malicious_file_execution(events, window_seconds=10):
    """Detect a temporary batch file created and then launched by cmd.exe."""
    alerts = []

    file_events = [
        event for event in events
        if event.get("event_id") == 11
    ]

    process_events = [
        event for event in events
        if event.get("event_id") == 1
    ]

    for file_event in file_events:
        file_fields = file_event.get("fields", {})
        target = file_fields.get("TargetFilename", "")
        normalized_target = _normalize_path(target)
        file_time = _parse_timestamp(file_event)

        if not file_time or not normalized_target.endswith(".bat"):
            continue

        if "\\temp\\" not in normalized_target:
            continue

        creator = _normalize_path(file_fields.get("Image", ""))

        if not creator.endswith("\\powershell.exe"):
            continue

        for process_event in process_events:
            process_fields = process_event.get("fields", {})
            process_time = _parse_timestamp(process_event)
            image = _normalize_path(process_fields.get("Image", ""))
            parent_image = _normalize_path(
                process_fields.get("ParentImage", "")
            )
            command_line = _normalize_path(
                process_fields.get("CommandLine", "")
            )

            if not process_time or not image.endswith("\\cmd.exe"):
                continue

            elapsed = (process_time - file_time).total_seconds()

            if elapsed < 0 or elapsed > window_seconds:
                continue

            if not parent_image.endswith("\\powershell.exe"):
                continue

            if normalized_target not in command_line:
                continue

            file_user = file_fields.get("User")
            process_user = process_fields.get("User")

            if file_user and process_user and file_user != process_user:
                continue

            child_processes = []

            for child_event in process_events:
                child_fields = child_event.get("fields", {})
                child_time = _parse_timestamp(child_event)
                child_image = _normalize_path(
                    child_fields.get("Image", "")
                )
                child_parent = _normalize_path(
                    child_fields.get("ParentImage", "")
                )

                if not child_time:
                    continue

                child_elapsed = (child_time - process_time).total_seconds()

                if (
                    0 <= child_elapsed <= window_seconds
                    and child_parent.endswith("\\cmd.exe")
                    and child_image
                ):
                    child_processes.append(
                        child_fields.get("Image", "")
                    )

            alerts.append({
                "alert_type": "windows_malicious_file_execution",
                "severity": "high",
                "filename": target,
                "creator_image": file_fields.get("Image"),
                "executor_image": process_fields.get("Image"),
                "command_line": process_fields.get("CommandLine"),
                "user": process_user or file_user,
                "timestamp": process_event.get("timestamp"),
                "time_window_seconds": window_seconds,
                "child_processes": child_processes,
            })

    return alerts
