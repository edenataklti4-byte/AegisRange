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


failed_event = parse_ssh_log(failed_login)
successful_event = parse_ssh_log(successful_login)


print("Failed login event:")
print(failed_event)

print("\nSuccessful login event:")
print(successful_event)
