from detection.parsers.ssh_parser import parse_ssh_log


log = (
    "2026-09-21T09:23:24.869930+00:00 linux "
    "sshd-session[2829]: Failed password for invalid user "
    "user1 from 172.16.134.1 port 35376 ssh2"
)

event = parse_ssh_log(log)

print(event)
