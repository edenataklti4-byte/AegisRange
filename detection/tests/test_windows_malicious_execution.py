from detection.rules.windows_malicious_execution import (
    detect_malicious_file_execution,
)


FILE_EVENT = {
    "event_id": 11,
    "timestamp": "2026-10-12T18:42:40.320000",
    "fields": {
        "Image": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
        "TargetFilename": r"C:\Users\ciel\AppData\Local\Temp\update_service.bat",
        "User": r"DESKTOP-HFJ597U\ciel",
    },
}

CMD_EVENT = {
    "event_id": 1,
    "timestamp": "2026-10-12T18:42:40.416000",
    "fields": {
        "Image": r"C:\Windows\System32\cmd.exe",
        "CommandLine": r'cmd.exe /c "C:\Users\ciel\AppData\Local\Temp\update_service.bat"',
        "ParentImage": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
        "User": r"DESKTOP-HFJ597U\ciel",
    },
}

WHOAMI_EVENT = {
    "event_id": 1,
    "timestamp": "2026-10-12T18:42:40.664000",
    "fields": {
        "Image": r"C:\Windows\System32\whoami.exe",
        "ParentImage": r"C:\Windows\System32\cmd.exe",
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
            "TargetFilename": r"C:\Users\ciel\Documents\update_service.bat",
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


if __name__ == "__main__":
    test_detects_temporary_batch_file_execution()
    test_ignores_file_without_matching_execution()
    test_ignores_batch_file_outside_temp_directory()
    test_ignores_execution_before_file_creation()
    print("All Windows malicious execution tests passed.")
