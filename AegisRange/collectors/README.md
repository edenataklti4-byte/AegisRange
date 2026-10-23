# AegisRange — Collectors (Member 3)

> **Owner**: Member 3 (Detection)
> **Main Output**: Log collectors, parsers, and detection rules

## Purpose

The collector subsystem is responsible for:
1. **Collecting** raw logs from both target VMs (Linux + Windows)
2. **Parsing** raw logs into a normalized event schema
3. **Forwarding** normalized events to the backend API

## What to Collect

Refer to [evidence-mapping.md](../docs/evidence-mapping.md) for the complete list of evidence sources.

### From `aegis-linux` (10.10.10.20)
| Source | Path | Events |
|---|---|---|
| SSH auth logs | `/var/log/auth.log` | Failed/successful logins |
| Audit logs | `/var/log/audit/audit.log` | Command execution (execve) |
| System logs | `/var/log/syslog` | General system events |

### From `aegis-windows` (10.10.10.30)
| Source | Event Log | Events |
|---|---|---|
| Sysmon | `Microsoft-Windows-Sysmon/Operational` | EID 1, 3, 7, 11, 13, 15, 22 |
| PowerShell | `Microsoft-Windows-PowerShell/Operational` | EID 4104 (ScriptBlock) |
| Security | `Security` | EID 4688 (Process Creation), 4624/4625 (Logon) |

## Normalized Event Schema

Normalize each raw log line into a dictionary before sending it, then post it inside the
backend's `raw_data` field. The backend accepts **only four top-level keys** — `source_ip`,
`destination_ip`, `log_type` and `raw_data` — and `raw_data` is a schemaless JSON object, so
that is where all the parsed detail belongs. See
[api-contracts.md](../docs/api-contracts.md) §1.3 for the authoritative contract.

```json
{
  "source_ip": "10.10.10.10",
  "destination_ip": "10.10.10.20",
  "log_type": "auth",
  "raw_data": {
    "event_type": "auth_failure",
    "source_host": "aegis-linux",
    "timestamp": "2026-10-21T14:23:01.000Z",
    "message": "Oct 21 14:23:01 aegis-linux sshd[4521]: Failed password for labuser from 10.10.10.10 port 45678 ssh2",
    "username": "labuser",
    "source_port": 45678,
    "service": "sshd"
  }
}
```

> [!IMPORTANT]
> `source_ip` must be the **attacker's** IP (`10.10.10.10`), not the victim host's address.
> Correlation groups logs by `source_ip` alone, so putting the victim's IP there would merge
> every alert on that host into one meaningless incident.
>
> Do **not** send a top-level `severity`, `timestamp`, `event_id`, `event_type`,
> `source_host` or `message`. The backend ignores unknown top-level keys, assigns
> `created_at` itself, and derives incident severity from log volume (`low` / `medium` /
> `high`) rather than from anything a collector sends.

## Suggested Architecture

```
┌──────────────┐     ┌──────────────┐
│ Linux Target │     │ Windows Tgt  │
│              │     │              │
│  collector   │     │  collector   │
│  agent.py    │     │  agent.py    │
└──────┬───────┘     └──────┬───────┘
       │                     │
       │  POST /api/logs     │
       └─────────┬───────────┘
                 │
         ┌───────▼───────┐
         │   Backend     │
         │   main.py     │
         │  (Member 4)   │
         └───────────────┘
```

### Suggested approach
- **Python agent** running on each target VM
- Tails log files (Linux) or queries Event Log (Windows) at intervals
- Parses each entry into JSON format
- POSTs **one log per request** to `http://10.10.10.1:8000/api/logs` — there is no batch
  endpoint, so loop over the parsed entries and send them individually

### API Endpoint
```
POST /api/logs
Content-Type: application/json

{
  "source_ip": "10.10.10.10",
  "destination_ip": "10.10.10.20",
  "log_type": "auth",
  "raw_data": {
    "event_type": "auth_failure",
    "source_host": "aegis-linux",
    "timestamp": "2026-10-21T08:30:15Z",
    "message": "Failed password for labuser from 10.10.10.10 port 49820 ssh2"
  }
}
```

Returns `201 Created` with `{"id": <int>, "log_type": …, "created_at": …, "processed": true}`.
A missing `log_type` or `raw_data` gives `422`.

Probe backend reachability with `GET /` (returns
`{"message": "Aegisrange Local Correlation Engine is online", "status": "active"}`). Do not
probe with `GET /api/logs` — that path is POST-only and answers `405`, and there is no
endpoint for reading logs back at all.

## Getting Started

```bash
# Install dependencies on the target VM.
# (These are the collector agent's own dependencies and are deliberately not in the
#  repository-root requirements.txt, which covers only the host-side API and dashboard.)
pip install requests watchdog

# Structure
collectors/
├── README.md          # This file
├── linux_collector.py # Collector for aegis-linux
├── windows_collector.py # Collector for aegis-windows
├── parsers/
│   ├── auth_log.py    # Parser for /var/log/auth.log
│   ├── audit_log.py   # Parser for audit.log
│   └── sysmon.py      # Parser for Sysmon XML events
├── rules/
│   ├── rule_001_ssh_bruteforce.py
│   ├── rule_002_auth_after_failures.py
│   ├── rule_010_powershell_bypass.py
│   └── ...
└── config.yaml        # Collector configuration
```

## References
- [Architecture](../docs/architecture.md)
- [Evidence Mapping](../docs/evidence-mapping.md)
- [API Contracts](../docs/api-contracts.md)
