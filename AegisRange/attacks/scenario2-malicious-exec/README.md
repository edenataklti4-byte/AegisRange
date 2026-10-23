# Scenario 2: Simulated Malicious File Download & Execution

> **⚠️ EDUCATIONAL USE ONLY — Run exclusively in the AegisRange isolated lab environment.**
> All "payloads" are benign binaries that print a message and exit. No actual malware is used.

## Overview

| Field | Value |
|---|---|
| **Scenario** | Simulated Malicious File Delivery, Execution & Persistence |
| **MITRE ATT&CK** | T1059.001 (PowerShell), T1105 (Ingress Tool Transfer), T1547.001 (Registry Run Keys) |
| **Objective** | Demonstrate a multi-stage attack chain on Windows and the resulting Sysmon/event log evidence |
| **Target** | `aegis-windows` (10.10.10.30) |
| **Attacker** | `aegis-kali` (10.10.10.10) |

## Attack Chain

```
┌──────────┐     HTTP GET      ┌──────────────┐
│ Kali     │◄─────────────────│ Windows      │
│ Attacker │  (payload.exe)    │ Target       │
│          │                   │              │
│ HTTP :8080├──────────────────►│ Downloads    │
│ NC  :4444│◄──────────────────│ Executes     │
│          │   TCP callback    │ Persists     │
└──────────┘                   └──────────────┘
```

### Step-by-Step

| Step | Action | On | Evidence Generated |
|---|---|---|---|
| 1 | Start HTTP server hosting payload | Kali | — |
| 2 | Start netcat listener for callback | Kali | — |
| 3 | PowerShell downloads payload from Kali | Windows | Sysmon EID 1, 3 + PS ScriptBlock |
| 4 | Payload saved to `C:\Users\Public\payload.exe` | Windows | Sysmon EID 11 |
| 5 | Payload executed (child process) | Windows | Sysmon EID 1 |
| 6 | Registry Run key set for persistence | Windows | Sysmon EID 13 |
| 7 | Outbound TCP callback to Kali | Windows | Sysmon EID 3 |

## Running the Scenario

### On Kali (Attacker)
```bash
cd /opt/aegisrange/attacks/scenario2-malicious-exec

# Run the full orchestration script
bash execute-payload.sh
```

### On Windows (Target) — if triggering manually
```powershell
# Run the dropper script
powershell.exe -ExecutionPolicy Bypass -File C:\vagrant\attacks\scenario2-malicious-exec\payload-dropper.ps1
```

## Expected Evidence

| # | Evidence | Sysmon Event ID | Key Fields |
|---|---|---|---|
| 1 | PowerShell process start | EID 1 (Process Create) | Image: `powershell.exe`, CommandLine contains dropper script |
| 2 | Outbound HTTP to Kali | EID 3 (Network Connect) | DestinationIp: `10.10.10.10`, DestinationPort: `8080` |
| 3 | File written to Public folder | EID 11 (File Create) | TargetFilename: `C:\Users\Public\payload.exe` |
| 4 | Payload process execution | EID 1 (Process Create) | Image: `C:\Users\Public\payload.exe`, ParentImage: `powershell.exe` |
| 5 | Registry Run key modified | EID 13 (Registry Value Set) | TargetObject contains `CurrentVersion\Run`, Details: payload path |
| 6 | Outbound callback to Kali | EID 3 (Network Connect) | DestinationIp: `10.10.10.10`, DestinationPort: `4444` |
| 7 | PowerShell ScriptBlock log | PS Operational Log | Full script content logged |

## Detection Rules That Should Fire

> [!NOTE]
> These `AEGIS-RULE-*` identifiers are **planned** detection content; they are not in
> `main.py` and nothing stores a rule id. What the backend does today is count logs per
> source IP: 3 or more from the same `source_ip` within 5 minutes raise one incident titled
> `Suspicious activity from <source_ip>`, with severity `low` (3-4), `medium` (5-9) or
> `high` (10+) — lowercase, and no `critical`. Verify this run with
> `curl "http://localhost:8000/api/incidents?source_ip=10.10.10.10"` or on the dashboard at
> <http://localhost:8501>.

1. **AEGIS-RULE-010**: PowerShell executing script with `-ExecutionPolicy Bypass`
2. **AEGIS-RULE-011**: File created in `C:\Users\Public\` by PowerShell
3. **AEGIS-RULE-012**: Process execution from `C:\Users\Public\`
4. **AEGIS-RULE-013**: Registry Run key modification (persistence)
5. **AEGIS-RULE-014**: Outbound network connection to non-standard port from user process

## Cleanup / Reset

```powershell
# On Windows target:
Remove-Item "C:\Users\Public\payload.exe" -Force -ErrorAction SilentlyContinue
Remove-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -Name "AegisRangeTest" -ErrorAction SilentlyContinue
```

Or restore from snapshot: `vagrant snapshot restore aegis-windows clean`
