# AegisRange — Frontend Dashboard (Member 5)

> **Owner**: Member 5 (Frontend)
> **Framework**: **Streamlit** (Python)
> **File on `main`**: `dashboard.py` (plus `.streamlit/config.toml`)
> **Main Output**: Interactive incident investigation dashboard & log timeline

> [!IMPORTANT]
> **The dashboard reads the SQLite database directly. It does not call the REST API.**
> `dashboard.py` opens `app.db` with Python's `sqlite3` module and queries the `incidents`
> and `raw_logs` tables with `pandas.read_sql_query`. There is no `requests` call, no
> `httpx` call and no `API_BASE` anywhere in it — and there could not be one for logs, since
> the backend exposes no `GET /api/logs`. Do not write new dashboard code against
> `requests.get("http://localhost:8000/api/...")`; it will not match what is on `main`.

---

## Purpose

`dashboard.py` is the visual operational interface for AegisRange:

1. **Overview metrics** — incident count, open incidents, high-severity count, raw log count, distinct source IPs.
2. **Incidents tab** — expandable incident cards with the related raw logs for that source IP, a "Mark as investigated" toggle, and a downloadable Markdown incident report.
3. **Log Timeline tab** — every stored log in time order with the incident(s) it links to, plus a raw log table and CSV export.
4. **Charts** — incidents by severity, incidents by status, raw logs by type, incidents per hour.

---

## Data Access

| What | How `dashboard.py` gets it |
| :--- | :--- |
| Incidents | `sqlite3` → `SELECT * FROM incidents` on `app.db` |
| Raw logs | `sqlite3` → `SELECT id, source_ip, destination_ip, log_type, raw_data, created_at FROM raw_logs` |
| Closing an incident | `UPDATE incidents SET status = ?, updated_at = ? WHERE id = ?`, committed straight to `app.db` |

```python
DB_FILE = "app.db"
```

The dashboard therefore has to see the **same** `app.db` the backend writes. Either run
`streamlit run dashboard.py` from the directory where the backend created `app.db`, or edit
`DB_FILE` at the top of `dashboard.py` to the absolute path of that file. The dashboard shows
a warning and stops when the file is missing, when there is no `incidents` table, or when the
`incidents` table is missing any of the columns it needs.

### Schema the dashboard expects

It hard-checks for exactly the columns Member 4's model defines:

```python
INCIDENT_COLS = {"id", "title", "description", "severity", "status",
                 "source_ip", "log_count", "created_at", "updated_at"}
LOG_COLS = ["id", "source_ip", "destination_ip", "log_type", "raw_data", "created_at"]
```

If `raw_logs` is absent or shaped differently, the timeline and related-log panels render
empty and a sidebar warning appears — incidents still display.

### Severity handling

The database stores **lowercase** `low` / `medium` / `high` (there is no `critical` value in
`models.py`). `dashboard.py` only upper-cases it for display:

```python
incidents["severity"] = incidents["severity"].fillna("low").str.upper()
```

`ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]` and the colour map include `CRITICAL` purely
so a legacy or hand-inserted row would still render; the backend never writes it. The
"high-severity" metric and the red banner count `CRITICAL` **or** `HIGH`.

### Fields the dashboard cannot show

There is no MITRE ATT&CK column in the UI, because `incidents` has no `mitre_technique`
column to read. Same for a target host: the model stores only `source_ip`. If the team wants
those on screen, Member 4 has to add the columns to `models.py` first.

---

## Running the Streamlit Dashboard

```bash
# Dependencies (requirements.txt already pins streamlit and pandas — `requests` is not needed)
pip install -r requirements.txt

# Launch from the directory that holds app.db
streamlit run dashboard.py
```

It opens at `http://localhost:8501`. `.streamlit/config.toml` sets
`toolbarMode = "minimal"`.

The backend does not have to be running for the dashboard to work — it only needs an
`app.db` with data in it. Starting the backend is simply how `app.db` gets populated. The
sidebar "Refresh data" button re-runs the script and re-reads the file.

---

## How it Connects with Other Members

* **Member 1 & 2** run attacks on Kali → logs are generated on Linux & Windows.
* **Member 3** forwards each log with `POST /api/logs`.
* **Member 4** runs `uvicorn main:app`, correlates logs and writes `incidents` into `app.db`.
* **Member 5 (You)** read that same `app.db` with Streamlit and investigate — and write
  `status = "closed"` back into it when an incident has been triaged.
