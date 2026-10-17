# AegisRange Detection

This directory contains the detection component of AegisRange.

Responsibilities:
- Collect security logs
- Parse raw logs into structured events
- Detect suspicious behavior
- Generate security alerts

## Alert Contract

Detection rules return a list of alert dictionaries. Each alert identifies
the detection rule, its severity, and the evidence associated with the event.

### Shared Fields

All current alert types include:

| Field | Type | Description |
|---|---|---|
| `alert_type` | string | Identifier for the detection rule |
| `severity` | string | Alert severity: `high` or `critical` |

Fields beyond these depend on the detection rule. Consumers should not assume
that every alert contains the same fields.

### SSH Brute-Force Alert

Alert type: `ssh_brute_force`

| Field | Type | Description |
|---|---|---|
| `source_ip` | string | Source IP associated with failed logins |
| `failed_attempts` | integer | Number of matching failed attempts |
| `first_seen` | timestamp | Start of the detected failure window |
| `last_seen` | timestamp | Last matching failed attempt |

Severity: `high`

### SSH Successful Login After Failures

Alert type: `ssh_success_after_failures`

| Field | Type | Description |
|---|---|---|
| `source_ip` | string | Source IP associated with the login |
| `username` | string | Account used for the successful login |
| `failed_attempts` | integer | Matching failures before the success |
| `first_failed` | timestamp | Timestamp of the first matching failure |
| `successful_login` | timestamp | Timestamp of the successful login |

Severity: `critical`

### Windows Malicious File Execution

Alert type: `windows_malicious_file_execution`

| Field | Type | Description |
|---|---|---|
| `filename` | string | Path of the detected temporary batch file |
| `creator_image` | string or null | Image that created the file |
| `executor_image` | string or null | Image that executed the batch file |
| `command_line` | string or null | Command line used for execution |
| `user` | string or null | User associated with the events |
| `timestamp` | string | Timestamp copied from the execution event |
| `time_window_seconds` | integer | Maximum correlation window |
| `child_processes` | list of strings | Correlated child process image paths |

Severity: `high`

Child processes are associated only when their parent process GUID matches
the detected `cmd.exe` process GUID. If the required GUIDs are missing,
the alert may still be generated, but `child_processes` remains empty.

### Timestamp Formatting

The SSH integration applies `format_alert()` before returning its alerts.
That formatter converts top-level `datetime` values to ISO 8601 strings.

The Windows detection rule currently returns its `timestamp` as the original
event timestamp string. Its timestamps are parsed and normalized to UTC for
comparison, but the alert's output timestamp is not rewritten by that rule.

Consumers should preserve timestamp offsets when present and should not assume
that every alert timestamp has been normalized to UTC.

### Integration Notes

- Detection rules return alert dictionaries; the SSH integration combines
  alerts from both SSH rules.
- `format_alert()` returns a new dictionary and does not modify the original.
- Rule-specific fields must be preserved when alerts are passed to the backend.
- This contract documents the current implementation. Changes to alert fields
  should be coordinated with the backend consumer.
