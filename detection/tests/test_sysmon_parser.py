from datetime import datetime, timezone
from detection.parsers.sysmon_parser import (
    parse_sysmon_event,
    parse_sysmon_log,
)


FILE_EVENT = """10/12/2026 9:42:40 PM  11 File created:
UtcTime: 2026-10-12 18:42:40.320
ProcessGuid: {22252613-e353-6ac8-3d01-000000000800}
ProcessId: 1484
Image: C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe
TargetFilename: C:\\Users\\ciel\\AppData\\Local\\Temp\\update_service.bat
User: DESKTOP-HFJ597U\\ciel"""

PROCESS_EVENT = """10/12/2026 9:42:40 PM  1 Process Create:
UtcTime: 2026-10-12 18:42:40.416
ProcessGuid: {22252613-2a20-6acd-1b06-000000000800}
ProcessId: 11508
Image: C:\\Windows\\System32\\cmd.exe
CommandLine: cmd.exe /c update_service.bat
ParentImage: C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe
User: DESKTOP-HFJ597U\\ciel"""

NETWORK_EVENT = """10/12/2026 10:28:28 PM  3 Network connection detected:
UtcTime: 2026-10-09 22:59:46.409
ProcessGuid: {22252613-e32e-6ac8-3201-000000000800}
ProcessId: 4600
Image: C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe
Protocol: tcp
Initiated: true
SourceIp: 172.16.134.128
SourcePort: 64337
DestinationIp: 172.16.134.1
DestinationPort: 4444
User: DESKTOP-HFJ597U\\ciel"""


def test_parses_file_event():
    event = parse_sysmon_event(FILE_EVENT)

    assert event is not None
    assert event["event_id"] == 11
    assert event["fields"]["TargetFilename"].endswith(
        "update_service.bat"
    )
    assert event["fields"]["ProcessId"] == "1484"


def test_parses_process_event():
    event = parse_sysmon_event(PROCESS_EVENT)

    assert event is not None
    assert event["event_id"] == 1
    assert event["fields"]["Image"].endswith("cmd.exe")
    assert event["fields"]["ParentImage"].endswith("powershell.exe")


def test_parses_network_event():
    event = parse_sysmon_event(NETWORK_EVENT)

    assert event is not None
    assert event["event_id"] == 3
    assert event["fields"]["DestinationIp"] == "172.16.134.1"
    assert event["fields"]["DestinationPort"] == "4444"


def test_parses_multiple_events():
    events = parse_sysmon_log(
        FILE_EVENT + "\n\n" + PROCESS_EVENT + "\n\n" + NETWORK_EVENT
    )

    assert len(events) == 3
    assert [event["event_id"] for event in events] == [11, 1, 3]


def test_ignores_unrecognized_text():
    assert parse_sysmon_event("This is not a Sysmon event") is None


def test_utc_timestamp_is_timezone_aware():
    event = parse_sysmon_event(FILE_EVENT)

    assert event is not None
    timestamp = datetime.fromisoformat(event["timestamp"])

    assert timestamp.tzinfo is not None
    assert timestamp.utcoffset().total_seconds() == 0


def test_explicit_offset_is_normalized_to_utc():
    event_text = FILE_EVENT.replace(
        "2026-10-12 18:42:40.320",
        "2026-10-12T20:42:40.320+02:00",
    )

    event = parse_sysmon_event(event_text)

    assert event is not None
    assert event["timestamp"] == "2026-10-12T18:42:40.320000+00:00"


def test_malformed_utc_timestamp_becomes_none():
    event_text = FILE_EVENT.replace(
        "2026-10-12 18:42:40.320",
        "not-a-valid-timestamp",
    )

    event = parse_sysmon_event(event_text)

    assert event is not None
    assert event["timestamp"] is None


if __name__ == "__main__":
    test_parses_file_event()
    test_parses_process_event()
    test_parses_network_event()
    test_parses_multiple_events()
    test_ignores_unrecognized_text()
    print("All Sysmon parser tests passed.")

    test_utc_timestamp_is_timezone_aware()
    test_explicit_offset_is_normalized_to_utc()
    test_malformed_utc_timestamp_becomes_none()
