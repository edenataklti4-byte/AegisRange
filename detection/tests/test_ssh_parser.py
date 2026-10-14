
from detection.parsers.ssh_parser import parse_ssh_log


failed_login = (
    "2026-09-21T09:23:24.869930+00:00 "
    "linux sshd-session[2829]: "
    "Failed password for invalid user user1 "
    "from 172.16.134.1 port 35376 ssh2"
)

successful_login = (
    "2026-09-21T09:23:44.374968+00:00 "
    "linux sshd-session[2833]: "
    "Accepted password for bupuser "
    "from 172.16.134.1 port 58928 ssh2"
)


def test_failed_login():
    event = parse_ssh_log(failed_login)

    assert event is not None
    assert event["event_type"] == "ssh_failed_login"
    assert event["username"] == "user1"
    assert event["source_ip"] == "172.16.134.1"
    assert event["source_port"] == 35376


def test_successful_login():
    event = parse_ssh_log(successful_login)

    assert event is not None
    assert event["event_type"] == "ssh_successful_login"
    assert event["username"] == "bupuser"
    assert event["source_ip"] == "172.16.134.1"
    assert event["source_port"] == 58928


def test_unrecognized_line():
    event = parse_ssh_log("This is not an SSH authentication log")

    assert event is None


if __name__ == "__main__":
    test_failed_login()
    test_successful_login()
    test_unrecognized_line()
    print("All SSH parser tests passed.")

