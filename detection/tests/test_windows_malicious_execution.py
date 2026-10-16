
from detection.rules.windows_malicious_execution import (
    detect_malicious_file_execution,
)


FILE_EVENT = {
    "event_id": 11,
    "timestamp": "2026-10-12T18:42:40.320000",
    "fields": {
        "Image": (
            r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
        ),
        "TargetFilename": (
            r"C:\Users\ciel\AppData\Local\Temp\update_service.bat"
        ),
        "User": r"DESKTOP-HFJ597U\ciel",
    },
}

CMD_EVENT = {
    "event_id": 1,
    "timestamp": "2026-10-12T18:42:40.416000",
    "fields": {
        "Image": r"C:\Windows\System32\cmd.exe",
        "CommandLine": (
            r'cmd.exe /c "C:\Users\ciel\AppData\Local\Temp\update_service.bat"'
        ),
        "ParentImage": (
            r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
        ),
        "ProcessGuid": "{CMD-GUID}",
        "ParentProcessGuid": "{POWERSHELL-GUID}",
        "User": r"DESKTOP-HFJ597U\ciel",
    },
}

WHOAMI_EVENT = {
    "event_id": 1,
    "timestamp": "2026-10-12T18:42:40.664000",
    "fields": {
        "Image": r"C:\Windows\System32\whoami.exe",
        "ParentImage": r"C:\Windows\System32\cmd.exe",
        "ProcessGuid": "{WHOAMI-GUID}",
        "ParentProcessGuid": "{CMD-GUID}",
        "User": r"DESKTOP-HFJ597U\ciel",
    },
}

UNRELATED_CHILD_EVENT = {
    "event_id": 1,
    "timestamp": "2026-10-12T18:42:40.700000",
    "fields": {
        "Image": r"C:\Windows\System32\notepad.exe",
        "ParentImage": r"C:\Windows\System32\cmd.exe",
        "ProcessGuid": "{NOTEPAD-GUID}",
        "ParentProcessGuid": "{OTHER-CMD-GUID}",
        "User": r"DESKTOP-HFJ597U\ciel",
    },
}


def test_detects_temporary_batch_file_execution():
    alerts = detect_malicious_file_execution(
        [FILE_EVENT, CMD_EVENT, WHOAMI_EVENT]
    )

    assert len(alerts) == 1
    assert alerts[0]["alert_type"] == "windows_malicious_file_execution"
    assert alerts[0]["severity"] == "high"
    assert alerts[0]["filename"].endswith("update_service.bat")
    assert any(
        image.endswith("whoami.exe")
        for image in alerts[0]["child_processes"]
    )


def test_ignores_file_without_matching_execution():
    alerts = detect_malicious_file_execution([FILE_EVENT])

    assert alerts == []


def test_ignores_batch_file_outside_temp_directory():
    file_event = {
        **FILE_EVENT,
        "fields": {
            **FILE_EVENT["fields"],
            "TargetFilename": (
                r"C:\Users\ciel\Documents\update_service.bat"
            ),
        },
    }

    alerts = detect_malicious_file_execution([file_event, CMD_EVENT])

    assert alerts == []


def test_ignores_execution_before_file_creation():
    earlier_cmd = {
        **CMD_EVENT,
        "timestamp": "2026-10-12T18:42:39.000000",
    }

    alerts = detect_malicious_file_execution([FILE_EVENT, earlier_cmd])

    assert alerts == []


def test_ignores_child_process_from_unrelated_command():
    alerts = detect_malicious_file_execution(
        [
            FILE_EVENT,
            CMD_EVENT,
            WHOAMI_EVENT,
            UNRELATED_CHILD_EVENT,
        ]
    )

    assert len(alerts) == 1

    assert any(
        image.endswith("whoami.exe")
        for image in alerts[0]["child_processes"]
    )

    assert not any(
        image.endswith("notepad.exe")
        for image in alerts[0]["child_processes"]
    )

def test_ignores_malformed_timestamp():
    bad_file_event = {
        **FILE_EVENT,
        "timestamp": "not-a-valid-timestamp",
    }

    alerts = detect_malicious_file_execution(
        [bad_file_event, CMD_EVENT]
    )

    assert alerts == []


def test_ignores_missing_file_fields():
    incomplete_file_event = {
        "event_id": 11,
        "timestamp": "2026-10-12T18:42:40.320000",
        "fields": {},
    }

    alerts = detect_malicious_file_execution(
        [incomplete_file_event, CMD_EVENT]
    )

    assert alerts == []


def test_ignores_missing_process_fields():
    incomplete_process_event = {
        "event_id": 1,
        "timestamp": "2026-10-12T18:42:40.416000",
        "fields": {},
    }

    alerts = detect_malicious_file_execution(
        [FILE_EVENT, incomplete_process_event]
    )

    assert alerts == []


def test_ignores_execution_outside_time_window():
    late_cmd = {
        **CMD_EVENT,
        "timestamp": "2026-10-12T18:43:00.000000",
    }

    alerts = detect_malicious_file_execution(
        [FILE_EVENT, late_cmd]
    )

    assert alerts == []


def test_handles_mixed_timezone_formats():
    utc_file_event = {
        **FILE_EVENT,
        "timestamp": "2026-10-12T18:42:40.320000+00:00",
    }

    offset_cmd_event = {
        **CMD_EVENT,
        "timestamp": "2026-10-12T20:42:40.416000+02:00",
    }

    alerts = detect_malicious_file_execution(
        [utc_file_event, offset_cmd_event, WHOAMI_EVENT]
    )

    assert len(alerts) == 1
    assert alerts[0]["alert_type"] == "windows_malicious_file_execution"
    assert any(
        image.endswith("whoami.exe")
        for image in alerts[0]["child_processes"]
    )


if __name__ == "__main__":
    test_detects_temporary_batch_file_execution()
    test_ignores_file_without_matching_execution()
    test_ignores_batch_file_outside_temp_directory()
    test_ignores_execution_before_file_creation()
    test_ignores_child_process_from_unrelated_command()
    test_ignores_malformed_timestamp()
    test_ignores_missing_file_fields()
    test_handles_mixed_timezone_formats()
    test_ignores_missing_process_fields()
    test_ignores_execution_outside_time_window()

    print("All Windows malicious execution tests passed.")
