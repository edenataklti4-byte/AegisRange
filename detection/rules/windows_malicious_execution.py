
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
    """Detect a temporary batch file created by PowerShell and launched by cmd.exe."""
    alerts = []
    seen_executions = set()

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

            if not 0 <= elapsed <= window_seconds:
                continue

            if not parent_image.endswith("\\powershell.exe"):
                continue

            if normalized_target not in command_line:
                continue

            file_user = file_fields.get("User")
            process_user = process_fields.get("User")

            if file_user and process_user and file_user != process_user:
                continue

            process_guid = process_fields.get("ProcessGuid")

            execution_key = (
                normalized_target,
                process_guid or process_event.get("timestamp"),
            )

            if execution_key in seen_executions:
                continue

            seen_executions.add(execution_key)
            child_processes = []

            for child_event in process_events:
                child_fields = child_event.get("fields", {})
                child_time = _parse_timestamp(child_event)
                child_image = _normalize_path(
                    child_fields.get("Image", "")
                )

                if not child_time or not child_image:
                    continue

                child_elapsed = (
                    child_time - process_time
                ).total_seconds()

                if not 0 <= child_elapsed <= window_seconds:
                    continue

                child_parent_guid = child_fields.get("ParentProcessGuid")
                child_parent_image = _normalize_path(
                    child_fields.get("ParentImage", "")
                )

                # Use process GUIDs when both are present.
                if process_guid and child_parent_guid:
                    if child_parent_guid != process_guid:
                        continue
                else:
                    # Fallback for logs that don't include GUIDs.
                    if not child_parent_image.endswith("\\cmd.exe"):
                        continue

                child_user = child_fields.get("User")

                if (
                    process_user
                    and child_user
                    and process_user != child_user
                ):
                    continue

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
