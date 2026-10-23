# AegisRange End-to-End Integration & Operator Guide

This guide provides step-by-step instructions for booting the AegisRange virtual environment, verifying connectivity, initiating collectors, running detection services, launching attack scenarios, investigating detections in the dashboard, and cleanly tearing down the laboratory.

> [!IMPORTANT]
> Two services run on the host, both Python, both started from the repository root:
> `uvicorn main:app` (the API, port **8000**) and `streamlit run dashboard.py` (the
> dashboard, port **8501**). The dashboard reads the SQLite file **`app.db`** directly — it
> does not call the API. There is no Node.js frontend, no port 3000 and no port 8080.

---

## 1. Prerequisites Checklist

Before proceeding, verify that your host machine satisfies all requirements:

- [ ] **Hardware**:
  - Minimum 16 GB physical RAM (32 GB strongly recommended).
  - 80 GB free SSD disk space.
  - VT-x (Intel) or AMD-V (AMD) hardware virtualization enabled in system BIOS/UEFI.
- [ ] **Virtualization & CLI**:
  - Oracle VirtualBox 7.0+ installed and available in system PATH (`VBoxManage --version`).
  - HashiCorp Vagrant 2.3+ installed (`vagrant --version`).
  - Vagrant VirtualBox provider plugin installed (`vagrant plugin list`).
- [ ] **Development Runtimes**:
  - Python 3.10 or higher (`python --version` or `py -3 --version`).
  - Git CLI (`git --version`).
  - *(No Node.js or npm required — the dashboard is Streamlit.)*
- [ ] **Network & Privileges**:
  - Administrative/sudo privileges on host to allow VirtualBox to create host-only virtual network adapters (`10.10.10.1`).

---

## 2. Step 1: Boot the Cyber Range (`vagrant up`)

Open a terminal or PowerShell prompt with administrative privileges and navigate to the project root:

```bash
cd AegisRange/infrastructure     # the Vagrantfile lives here, not at the repository root
```

Provision and boot all three virtual machines simultaneously:

```bash
vagrant up
```

> [!NOTE]
> On the first execution, Vagrant will download base boxes for Kali Linux, Ubuntu Server 22.04, and Windows 10. Depending on your internet bandwidth, this initial download and provision takes between 15 and 35 minutes. Subsequent boots take less than 60 seconds.

Verify that all three machines are running:

```bash
vagrant status
```

Expected output:
```text
Current machine states:

aegis-kali                running (virtualbox)
aegis-linux               running (virtualbox)
aegis-windows             running (virtualbox)
```

---

## 3. Step 2: Verify Network Connectivity & Smoke Tests

Ensure that the host can reach each VM, and that each VM can communicate across the `10.10.10.0/24` subnet:

### 3.1 Automated Smoke Test
Run the included verification script:

```bash
bash ../tests/smoke/test-vm-connectivity.sh     # from infrastructure/, or tests/smoke/... from the root
```

Expected output:
```text
==================================================
           AegisRange Lab Connectivity Test
==================================================
[+] Checking Host-Only Interface (10.10.10.1)... OK
[+] Pinging aegis-kali (10.10.10.10)... OK (RTT: 0.8ms)
[+] Pinging aegis-linux (10.10.10.20)... OK (RTT: 0.6ms)
[+] Pinging aegis-windows (10.10.10.30)... OK (RTT: 1.2ms)
[+] Testing SSH to aegis-linux (10.10.10.20:22)... OPEN
[+] Testing WinRM to aegis-windows (10.10.10.30:5985)... OPEN
[+] Verifying Attacker Isolation (Kali -> Internet)... BLOCKED (Confirmed Isolated)
==================================================
All connectivity tests passed! Lab is ready.
==================================================
```

### 3.2 Manual Ping Verification (Optional)
```bash
ping -n 2 10.10.10.10
ping -n 2 10.10.10.20
ping -n 2 10.10.10.30
```

---

## 4. Step 3: Start Aegis-Local Backend & Detection Engine

On your **host machine**, start the backend API server and detection engine.

```bash
cd AegisRange            # main.py, dashboard.py and requirements.txt are at the root

# Set up Python virtual environment
python -m venv venv

# Activate virtual environment
# Windows:
.\venv\Scripts\Activate.ps1
# Linux/macOS:
# source venv/bin/activate

# Install dependencies (FastAPI, SQLAlchemy, uvicorn, Streamlit, pandas)
pip install -r requirements.txt

# Start the FastAPI server on all interfaces so the lab VMs can reach it
# (`python main.py` exits silently - main.py has no __main__ block)
uvicorn main:app --host 0.0.0.0 --port 8000
```

Expected output — the `[schema]` lines appear only when `app.db` needs a rebuild:
```text
INFO:     Started server process [18920]
INFO:     Waiting for application startup.
INFO:     Application startup complete.
INFO:     Uvicorn running on http://0.0.0.0:8000 (Press CTRL+C to quit)
```

`sync_schema()` creates `app.db` in the current working directory on import. Note that
directory — the dashboard has to read the same file.

Verify backend health in a browser or with curl:
```bash
curl http://localhost:8000/
# {"message":"Aegisrange Local Correlation Engine is online","status":"active"}
```

Swagger UI listing all four routes: <http://localhost:8000/docs>

---

## 5. Step 4: Start the Streamlit Investigation Dashboard

In a second terminal on the **host machine**, from the same directory that holds `app.db`:

```bash
cd AegisRange
source venv/bin/activate        # Windows: .\venv\Scripts\Activate.ps1

streamlit run dashboard.py
```

Open your browser to:
```text
http://localhost:8501
```

Before any logs arrive you will see one of the dashboard's own guard messages — "No data
yet" if `app.db` does not exist, or "No incidents have been created yet" once the backend has
created the tables. Both are expected at this stage.

> [!TIP]
> If the dashboard reports that `app.db` was not found, it is running in a different
> directory from the backend. Either start both from the repository root, or edit
> `DB_FILE` at the top of `dashboard.py` to the absolute path of the backend's `app.db`.
> The dashboard does not need the API process to be running — only the file.

---

## 6. Step 5: Start Telemetry Collectors on Targets

With the backend running at `10.10.10.1:8000`, start the forwarder agents on the target
machines. Each collector sends **one `POST /api/logs` request per log line** — there is no
batch endpoint, and no endpoint for reading logs back.

### 6.1 Start Linux Forwarder (`aegis-linux`)
In a new terminal:

```bash
vagrant ssh aegis-linux
```

Inside the VM, start the collector daemon:
```bash
sudo systemctl status aegis-collector
# If running manually:
sudo python3 /vagrant/collectors/linux/linux_collector.py --backend http://10.10.10.1:8000
```
Expected output:
```text
[2026-10-21 08:35:01] [INFO] Aegis Linux Collector v1.0.0 initialized.
[2026-10-21 08:35:01] [INFO] Tailing /var/log/auth.log...
[2026-10-21 08:35:01] [INFO] Backend reachable at http://10.10.10.1:8000/ - posting to /api/logs
```

> [!NOTE]
> Collector code is Member 3's deliverable and is not in the repository yet; see
> [`../collectors/README.md`](../collectors/README.md) for the payload shape it must send.
> Until it exists, you can drive the pipeline by hand from the host:
> ```bash
> for i in 1 2 3 4 5; do
>   curl -s -X POST http://localhost:8000/api/logs \
>     -H "Content-Type: application/json" \
>     -d '{"source_ip":"10.10.10.10","destination_ip":"10.10.10.20","log_type":"auth",
>          "raw_data":{"message":"Failed password for root from 10.10.10.10 port 49820 ssh2"}}'
> done
> ```
> Three such logs inside 5 minutes raise an incident; five make it `medium`.

### 6.2 Start Windows Forwarder (`aegis-windows`)
Open a PowerShell prompt on the host and run the remote agent launcher:

```powershell
vagrant winrm aegis-windows -c "powershell -ExecutionPolicy Bypass -File C:\vagrant\collectors\windows\windows_collector.ps1 -BackendUrl http://10.10.10.1:8000"
```
Or connect via WinRM session / GUI to verify that the `AegisSysmonForwarder` Windows Service or scheduled task is in `Running` state.

---

## 7. Step 6: Execute Attack Scenarios

### Scenario 1: SSH Brute-Force & Compromise (Linux)
Log into the attacker node (`aegis-kali`):

```bash
vagrant ssh aegis-kali
```

Execute the automated Scenario 1 attack script:
```bash
bash /vagrant/attacks/scenario1-bruteforce/bruteforce.sh
```

**What the script does**:
1. Performs rapid TCP port probe against `10.10.10.20:22`.
2. Executes Hydra dictionary attack with 50 failed password attempts across `root`, `admin`, `guest`.
3. Discovers valid credential (`vagrant:vagrant`).
4. Establishes an interactive SSH session and executes post-compromise commands (`whoami`, `sudo -l`, `cat /etc/passwd`).

### Scenario 2: Malicious PowerShell Dropper & Persistence (Windows)
From `aegis-kali` (or triggered via host orchestrator):

```bash
bash /vagrant/attacks/scenario2-malicious-exec/execute-payload.sh
```

**What the script does**:
1. Serves mock payload `aegis_beacon.exe` from Kali HTTP server (`10.10.10.10:80`).
2. Triggers remote execution on `aegis-windows` (`10.10.10.30`) invoking `powershell.exe -NoP -NonI -W Hidden -Enc ...`.
3. PowerShell issues an outbound HTTP request, downloads the payload into `C:\Windows\Temp\beacon.exe`, and runs it.
4. Payload creates a registry entry under `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`.

---

## 8. Step 7: Investigate Detections in Dashboard

1. Open `http://localhost:8501` on your host browser and click **Refresh data** in the
   sidebar.
2. Both scenarios attack from the same Kali host, so correlation (which keys on `source_ip`
   alone) produces **one** incident per attacking IP:
   - **`Suspicious activity from 10.10.10.10`**, `status: open`, with `log_count` equal to the
     logs received in the last 5 minutes and severity `low` (3–4), `medium` (5–9) or
     `high` (10+).
3. Expand the incident card to investigate:
   - Read the description: `"<n> logs received from 10.10.10.10 within the last 5 minutes."`
   - Review **Related logs from 10.10.10.10** — the first 20 raw log rows for that IP, each
     showing its `log_type`, destination and full `raw_data` payload.
   - Click **Download incident report** for a Markdown summary with every related log.
   - Tick **Mark as investigated** to write `status = "closed"` back into `app.db`.
4. Switch to the **Log Timeline** tab for every stored log in chronological order, filterable
   by log type, source IP and free-text search, plus a raw log table and CSV download.
5. Use the sidebar **Severity** / **Status** / **Source IP** filters and the right-hand charts
   (incidents by severity, by status, raw logs by type, incidents per hour) for triage.

> [!NOTE]
> The UI shows severity upper-cased (`HIGH`), but the stored value is lowercase `high`; filter
> `GET /api/incidents?severity=high` accordingly. There is no incident-detail page, no MITRE
> ATT&CK tag and no process-tree view — `incidents` stores no technique or host columns, so
> there is nothing for the dashboard to render. Scenario-specific evidence lives in
> `attacks/*/expected-evidence.md`.

---

## 9. Troubleshooting & FAQ

### Issue 1: `vagrant up` Fails with "Host-only adapter cannot be created"
- **Cause**: VirtualBox network driver permission or IP conflict with an existing VirtualBox network adapter.
- **Solution**:
  1. Open VirtualBox GUI $\rightarrow$ **Tools** $\rightarrow$ **Network Manager**.
  2. Inspect host-only networks. Delete unused adapters or ensure one adapter is assigned IPv4 `10.10.10.1` / Mask `255.255.255.0`.
  3. Run PowerShell as Administrator:
     ```powershell
     net stop vboxdrvr
     net start vboxdrvr
     ```

### Issue 2: VM Boots but `10.10.10.x` is Unreachable (Ping Request Timed Out)
- **Cause**: Target OS interface not acquiring static configuration or firewall blocking ICMP.
- **Solution**:
  - For Linux: SSH via default NAT (`vagrant ssh aegis-linux`) and verify interface:
    ```bash
    ip addr show
    sudo ip addr add 10.10.10.20/24 dev eth1
    ```
  - For Windows: Windows Defender Firewall blocks ICMP by default. Ensure rule `AegisRange-ICMP` is active:
    ```powershell
    vagrant winrm aegis-windows -c "netsh advfirewall firewall add rule name=\"ICMP Allow\" protocol=icmpv4:8,any dir=in action=allow"
    ```

### Issue 3: Collectors Running but No Logs Reach the Backend
- **Cause**: Host firewall blocking port `8000`, or uvicorn bound to loopback only.
- **Solution**:
  1. Start the server with `uvicorn main:app --host 0.0.0.0 --port 8000`. The default
     `uvicorn main:app` listens on `127.0.0.1` only and the VMs cannot reach it.
  2. Add a Windows Firewall inbound exception for port 8000 on the host:
     ```powershell
     New-NetFirewallRule -DisplayName "AegisRange-Backend-8000" -Direction Inbound -LocalPort 8000 -Protocol TCP -Action Allow
     ```
  3. Test connectivity from inside a target VM — use `/`, since there is no stats endpoint:
     ```bash
     curl -v http://10.10.10.1:8000/
     ```
  4. Confirm logs are landing by checking for incidents after 3+ posts from one IP:
     ```bash
     curl -s "http://10.10.10.1:8000/api/incidents?source_ip=10.10.10.10"
     ```
     An empty `[]` with logs flowing means fewer than 3 logs arrived inside the 5-minute
     window, or the collector is sending the victim's IP as `source_ip` instead of the
     attacker's.

### Issue 3b: Backend Receiving Logs but the Dashboard Shows Nothing
- **Cause**: The dashboard is reading a different `app.db` from the one the backend writes.
  `database.py` uses the relative URL `sqlite:///./app.db`, so the file lands in whichever
  directory the server was started from.
- **Solution**:
  1. Run `uvicorn main:app` and `streamlit run dashboard.py` from the **same** directory, or
     set `DB_FILE` in `dashboard.py` to the backend's absolute `app.db` path.
  2. Click **Refresh data** in the sidebar; the dashboard reads the file on each run, it does
     not poll.
  3. If it reports missing columns, the two schemas have diverged — restart the backend so
     `sync_schema()` rebuilds the table (it writes an `app.db.bak-*` backup first).

### Issue 4: Windows 10 VM Fails to Complete Sysmon Provisioning
- **Cause**: Evaluation image requires reboot or Sysmon installation failed.
- **Solution**:
  - Run provisioner manually via WinRM:
    ```powershell
    vagrant provision aegis-windows
    ```
  - Confirm Sysmon service is operational inside Windows:
    ```powershell
    Get-Service Sysmon
    ```

---

## 10. Environment Teardown & Reset

When training sessions or testing rounds are complete, use the following procedures to safely shut down or reset the range:

### 10.1 Suspend or Stop VMs (Preserve State)
```bash
# Save memory state and suspend execution
vagrant suspend

# Or shut down VMs gracefully
vagrant halt
```

### 10.2 Revert to Clean Baseline Snapshot
To discard all attack residue and restore pristine state without re-downloading images:
```bash
vagrant snapshot restore baseline-ready
```

### 10.3 Complete Lab Destruction
To release all disk space and delete virtual machine disks:
```bash
vagrant destroy -f
```
To purge the backend database state, delete the SQLite file and any schema backups from the
directory you started the server in:
```bash
rm app.db
rm app.db.bak-*          # backups written by schema.py before a table rebuild
```
Both are git-ignored, and `sync_schema()` recreates the tables on the next start.
