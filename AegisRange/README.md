# AegisRange: Lightweight Attack Detection & Investigation Cyber Range

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Platform](https://img.shields.io/badge/Platform-VirtualBox%20%7C%20Vagrant-blue.svg)]()
[![Target OS](https://img.shields.io/badge/Targets-Ubuntu%2022.04%20%7C%20Windows%2010-orange.svg)]()
[![Attacker](https://img.shields.io/badge/Attacker-Kali%20Linux-red.svg)]()
[![Status](https://img.shields.io/badge/Status-Active%20Development-green.svg)]()

AegisRange is a self-contained, reproducible, lightweight cyber range and incident investigation platform. Designed for practical cybersecurity training, blue team defense validation, and digital forensics & incident response (DFIR), AegisRange simulates real-world adversary behavior in a controlled multi-VM environment and delivers end-to-end telemetry collection, automated detection, correlation, and interactive web-based timeline investigation through the **Aegis-Local** engine.

---

## Architecture Overview

AegisRange provisions a fully isolated host-only network (`10.10.10.0/24`) housing three purpose-configured virtual machines alongside a centralized host-based analysis engine:

```
+-----------------------------------------------------------------------------------+
| Host Machine (10.10.10.1)                                                         |
|                                                                                   |
|  +--------------------+        +--------------------+        +-----------------+  |
|  |  Aegis Dashboard   |        |  Aegis-Local Core  |<-------| Telemetry Ingest|  |
|  |  (Streamlit)       |        |  (FastAPI main.py) |  HTTP  | POST /api/logs  |  |
|  |  dashboard.py      |        |  uvicorn :8000     |  :8000 | (one log/req)   |  |
|  |  Port 8501         |        +----------+---------+        +--------^--------+  |
|  +---------+----------+                   |                           |           |
|            |          sqlite3 reads/writes|  SQLAlchemy writes        |           |
|            |         +--------------------v--------------------+      |           |
|            +-------->|  app.db  (SQLite: raw_logs, incidents)  |      |           |
|                      +-----------------------------------------+      |           |
+-----------------------------------------------------------------------|-----------+
                                                                        |
                       Host-Only Subnet: 10.10.10.0/24                  |
+--------------------------+-------------------------+------------------|-----------+
|                          |                         |                  |           |
|                          | SSH Brute-Force         | Malicious Exec   |           |
|                          v                         v                  |           |
|  +--------------------+  +----------------------+  +------------------+--------+  |
|  | aegis-kali         |  | aegis-linux          |  | aegis-windows             |  |
|  | 10.10.10.10        |  | 10.10.10.20          |  | 10.10.10.30               |  |
|  | Attacker Node      |  | Ubuntu 22.04 LTS     |  | Windows 10 Enterprise     |  |
|  | - Hydra / Nmap     |  | - OpenSSH Server     |  | - Sysmon v14+ / Winlog    |  |
|  | - Custom Exploit   |  | - auth.log collector |  | - PowerShell Stager       |  |
|  |   Scripts          |  |   forwarding logs    |  | - Win Event Collector     |  |
|  +--------------------+  +----------------------+  +---------------------------+  |
|                                                                                   |
+-----------------------------------------------------------------------------------+
```

1. **Adversary Emulation**: An automated attacking node (`aegis-kali`) executes scripted attack workflows against Linux and Windows victim machines.
2. **Telemetry Generation**: Victim systems record kernel and service events, including Linux `/var/log/auth.log` authentication attempts and Windows Microsoft-Windows-Sysmon/Operational events (process creation, file modification, network connection).
3. **Log Collection**: Lightweight endpoint agents continuously tail native logs, parse structures, normalize schemas, and push events over HTTP batch requests to the management host.
4. **Detection & Correlation**: The **Aegis-Local Core Engine** evaluates incoming normalized events against MITRE ATT&CK-mapped detection rules, correlates alerts within sliding time windows, and synthesizes multi-stage attack incidents.
5. **Investigation & Triage**: Security analysts use the **Streamlit dashboard** (`dashboard.py`) to inspect incident severity, walk the chronological log timeline, drill into raw forensic artifacts and triage attacker actions. The dashboard opens `app.db` with `sqlite3` and reads the `incidents` and `raw_logs` tables **directly** — it makes no HTTP calls to the backend — and writes `status = "closed"` back when an incident is marked investigated.

> [!NOTE]
> **What is implemented today.** The backend (`main.py`) exposes exactly four routes: `GET /`,
> `GET /api/scenarios`, `POST /api/logs` and `GET /api/incidents`. Correlation is a single
> volume rule — 3 or more logs from one `source_ip` inside 5 minutes raise one incident, whose
> severity escalates through the lowercase values `low` → `medium` → `high`. There is no alert
> layer, no rule engine, no MITRE field in the database, no endpoint for reading logs back, and
> no `critical` severity. Rule IDs and MITRE mappings in `docs/evidence-mapping.md` are
> detection-engineering reference material, not code. See
> [`docs/api-contracts.md`](docs/api-contracts.md) for the implemented contract and the
> planned-work backlog.

---

## Team Roles & Responsibilities

| Role | Member | Component Ownership | Primary Deliverables / Outputs |
| :--- | :--- | :--- | :--- |
| **Range Infrastructure & Networking** | Member 1 | Virtualization, network segmentation, environment provisioning | `infrastructure/Vagrantfile`, VirtualBox host-only network (`10.10.10.0/24`), static IP allocations, provisioning scripts (`infrastructure/scripts/provision-{kali,linux}.sh`, `provision-windows.ps1`, `setup-network.sh`), configs (`sshd_config`, `sysmon-config.xml`), and the smoke test in `tests/smoke/`. |
| **Adversary Emulation & Attacks** | Member 2 | Attack playbooks, tooling, scenario automation | Scenario 1: automated Hydra SSH brute-force (`attacks/scenario1-bruteforce/bruteforce.sh`, `wordlist.txt`); Scenario 2: PowerShell payload stager and runner (`attacks/scenario2-malicious-exec/payload-dropper.ps1`, `execute-payload.sh`); per-scenario `expected-evidence.md`. |
| **Telemetry Collection & Forwarding** | Member 3 | Endpoint monitoring agents, log parsing, normalization | Linux Auth log collector daemon (`linux_collector.py`), Windows Sysmon / Event Log collector (`windows_collector.ps1` / `.py`), JSON log normalization pipeline, batch queue delivery. |
| **Backend / Correlation** | Member 4 | Database, correlation logic, REST API | `main.py` (FastAPI) exposing `POST /api/logs` (ingestion) and `GET /api/incidents` (correlated incidents), plus `models.py`, `database.py` and `schema.py` backing the SQLite file `app.db`. |
| **Frontend Dashboard** | Member 5 | Streamlit dashboard UI, incident timelines, investigation interface | `dashboard.py` — a Streamlit app that reads `app.db` directly with `sqlite3`/pandas, giving incident cards, a log timeline, charts, Markdown incident reports and CSV export. |

---

## Quick Start Guide

### 1. Prerequisites Check
Ensure your host meets the minimum system specifications and software prerequisites:
- **Hypervisor**: Oracle VirtualBox (v7.0+)
- **Provisioning**: HashiCorp Vagrant (v2.3+)
- **Host Specs**: Minimum 16 GB RAM (32 GB recommended), 80 GB available SSD storage, 4+ CPU cores with VT-x/AMD-V hardware virtualization enabled in BIOS.
- **Runtime Tools**: Python 3.10+ and Git. (No Node.js — both the API and the dashboard are Python.)

### 2. Clone Repository & Boot Cyber Range
```bash
# Clone the repository
git clone https://github.com/edenataklti4-byte/AegisRange.git
cd AegisRange

# Provision all three virtual machines (takes 10-20 minutes on first run).
# The Vagrantfile lives in infrastructure/, so run vagrant from there:
cd infrastructure
vagrant up
cd ..
```

### 3. Verify Lab Connectivity
```bash
# Run automated network smoke test
bash tests/smoke/test-vm-connectivity.sh
```

### 4. Start Aegis-Local Services (Host Machine)

Both services are Python and both live at the repository root.

```bash
python -m venv venv
source venv/bin/activate  # On Windows: .\venv\Scripts\Activate.ps1
pip install -r requirements.txt

# Terminal 1: backend API + correlation engine.
# `python main.py` does nothing - main.py has no __main__ block. Use uvicorn:
uvicorn main:app --reload                      # localhost only
# uvicorn main:app --host 0.0.0.0 --port 8000  # also reachable from the lab VMs

# Terminal 2: Streamlit investigation dashboard (same directory, so it sees app.db)
streamlit run dashboard.py
```

The API serves `http://localhost:8000` (Swagger UI at `/docs`); the dashboard opens at
`http://localhost:8501`. The dashboard reads the `app.db` file the backend creates in its
working directory, so run both from the repository root — or set `DB_FILE` at the top of
`dashboard.py` to the absolute path of the backend's `app.db`.

### 5. Launch Attack Scenarios
```bash
# Scenario 1: SSH Brute-Force against Linux Target (10.10.10.20)
vagrant ssh aegis-kali -c "bash /vagrant/attacks/scenario1-bruteforce/bruteforce.sh"

# Scenario 2: Malicious PowerShell Dropper against Windows Target (10.10.10.30)
vagrant ssh aegis-kali -c "bash /vagrant/attacks/scenario2-malicious-exec/execute-payload.sh"
```

### 6. Investigate on the Dashboard
- Open `http://localhost:8501`.
- Watch for incidents titled `Suspicious activity from 10.10.10.10` once 3+ logs arrive from
  the attacker inside 5 minutes; severity climbs from `low` to `medium` (5+) to `high` (10+).
- Expand an incident to see the raw logs correlated to that source IP, download a Markdown
  incident report, or tick **Mark as investigated** to set its status to `closed`.
- Switch to the **Log Timeline** tab for every stored log in time order, plus CSV export.

---

## Project Structure Tree

```text
AegisRange/
├── README.md                           # Main project documentation & quickstart
├── LICENSE                             # MIT License
├── PROJECT_OVERVIEW.md                 # Plain-language team & executive guide
├── AegisRange_Guide.html               # Single-page visual project guide
│
│   # --- Member 4: backend, correlation engine & database (repository root) ---
├── main.py                             # FastAPI app: GET /, /api/scenarios,
│                                       #   POST /api/logs, GET /api/incidents
├── models.py                           # SQLAlchemy models: raw_logs, incidents
├── database.py                         # Engine & session (sqlite:///./app.db)
├── schema.py                           # Startup SQLite schema sync + backup
├── Test                                # Standalone self-test (`python Test`)
├── requirements.txt                    # Python dependencies (API + dashboard)
│
│   # --- Member 5: investigation dashboard (repository root) ---
├── dashboard.py                        # Streamlit app; reads app.db via sqlite3
├── .streamlit/
│   └── config.toml                     # toolbarMode = "minimal"
│
│   # --- app.db is created at runtime next to these files (git-ignored) ---
│
├── docs/                               # Detailed technical documentation
│   ├── architecture.md                 # System architecture, dataflow & sequence diagrams
│   ├── network-topology.md             # IP allocation, routing, firewall & isolation
│   ├── evidence-mapping.md             # Attack-to-telemetry & MITRE ATT&CK mapping
│   ├── api-contracts.md                # Implemented REST contract + planned backlog
│   └── integration-guide.md            # Step-by-step setup, verification, and runbook
├── backend/
│   └── README.md                       # Member 4's component notes
├── frontend/
│   └── README.md                       # Member 5's component notes
├── collectors/
│   └── README.md                       # Member 3's collector spec (code not yet written)
├── infrastructure/                     # VM provisioning and base configuration
│   ├── Vagrantfile                     # Multi-machine Vagrant definition
│   ├── scripts/                        # provision-kali.sh, provision-linux.sh,
│   │                                   #   provision-windows.ps1, setup-network.sh
│   └── configs/                        # sshd_config, sysmon-config.xml
├── attacks/                            # Attack playbooks and emulation automation
│   ├── scenario1-bruteforce/           # bruteforce.sh, wordlist.txt, expected-evidence.md
│   └── scenario2-malicious-exec/       # payload-dropper.ps1, execute-payload.sh,
│                                       #   expected-evidence.md
└── tests/
    ├── smoke/test-vm-connectivity.sh   # Range connectivity checker
    └── integration/                    # test-e2e-scenario1.sh, test-e2e-scenario2.sh
```

> [!NOTE]
> `main.py`, `models.py`, `database.py`, `schema.py`, `dashboard.py`, `Test` and
> `requirements.txt` sit at the **repository root**, not under `aegis-local/backend/` or
> `aegis-local/frontend/`. There is no `aegis-local/`, `scenarios/`, `scripts/` or `infra/`
> directory, and no Node.js/Next.js frontend. `backend/`, `frontend/` and `collectors/` hold
> component documentation only.

---

## Prerequisites & System Requirements

| Resource | Minimum Requirement | Recommended Specification |
| :--- | :--- | :--- |
| **CPU** | Quad-core Intel Core i5/i7 or AMD Ryzen 5 (VT-x/AMD-V required) | 8 cores / 16 threads |
| **RAM** | 16 GB Total System Memory | 32 GB System Memory |
| **Disk Storage** | 80 GB available space on SSD | 150 GB NVMe SSD |
| **Host OS** | Windows 10/11 64-bit, macOS 12+, or Ubuntu 22.04 LTS | Windows 11 64-bit / Linux |
| **Hypervisor** | VirtualBox 7.0.x | VirtualBox 7.0.14+ |
| **Vagrant** | HashiCorp Vagrant 2.3.x+ | Vagrant 2.4+ |
| **Software Runtimes** | Python 3.10+ (FastAPI, SQLAlchemy 2.x, Streamlit, pandas) | Python 3.11+ |

### Memory Allocation Breakdown Across Virtual Machines
- **`aegis-kali`**: 2048 MB RAM, 2 vCPUs
- **`aegis-linux`**: 2048 MB RAM, 2 vCPUs
- **`aegis-windows`**: 4096 MB RAM, 2 vCPUs
- **Host OS, API & Streamlit dashboard**: ~8000 MB RAM

---

## Security & Educational Disclaimer

> [!CAUTION]
> **LAB ENVIRONMENT ONLY**: The scripts, tools, and attack simulations provided in AegisRange are intended strictly for educational, defensive research, and authorized training purposes. 
> 
> - The virtual machines are isolated within a host-only private network (`10.10.10.0/24`) with outbound routing disabled on target systems to prevent unintentional egress.
> - Do not deploy these attack scripts or vulnerable machine configurations on production networks or non-consenting systems.
> - All payloads included in this repository are simulated, benign-action payloads designed only to generate characteristic forensic evidence.

---

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
