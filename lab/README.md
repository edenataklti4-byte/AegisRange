# AegisRange Lab Architecture

## Network
All three VMs run on an isolated VMware network (vmnet8, host-only/NAT-isolated),
subnet 172.16.134.0/24.

| Machine        | Role            | IP              | OS              |
|----------------|-----------------|-----------------|-----------------|
| Kali (host)    | Attacker        | 172.16.134.1    | Kali Linux      |
| Linux server   | Target (Attack 1) | 172.16.134.132 | Ubuntu 26.04 LTS |
| Windows target | Target (Attack 2) | 172.16.134.128 | Windows 11      |

## Isolation
VMs communicate only with each other on this subnet — no route to the
real internet or host network beyond what's needed for setup (Sysmon
download, package installs).

## Accounts
Linux server test users: admin, bupuser, devuser, testuser (plain accounts,
no sudo) — targets for the SSH brute-force scenario.

## Evidence Collection
- Linux: /var/log/auth.log (SSH authentication events)
- Windows: Sysmon Operational log (Event IDs 1, 3, 11), via
  Microsoft-Windows-Sysmon/Operational
