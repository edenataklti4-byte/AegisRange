# AegisRange — Backend (Member 4)

> **Owner**: Member 4 (Backend / Correlation)
> **Files on `main`**: `main.py`, `models.py`, `database.py`, `schema.py`, `requirements.txt`
> **Main Output**: SQLite database, log ingestion, correlation engine, incidents, REST API

> [!IMPORTANT]
> This document describes the backend **exactly as it exists on `main`**. Every field name,
> value and endpoint below was taken from `main.py` and `models.py`. If you change the code,
> change this file in the same commit.

---

## Purpose

The backend is the central intelligence engine of AegisRange. It stores logs in a local
SQLite database, runs correlation logic on every ingested log, and raises **incidents** when
one source IP becomes noisy. The Streamlit dashboard (Member 5) reads the same SQLite file
directly — see [`../frontend/README.md`](../frontend/README.md).

---

## Endpoints implemented in `main.py`

FastAPI app: title `Aegisrange Local API`, version `1.1.0`. Interactive docs at `/docs`.

| Method | Path | Purpose |
| :--- | :--- | :--- |
| `GET` | `/` | Liveness check |
| `GET` | `/api/scenarios` | Static list of the lab's attack scenarios |
| `POST` | `/api/logs` | Ingest one log and run correlation |
| `GET` | `/api/incidents` | List correlated incidents |

> [!WARNING]
> **There is no `GET /api/logs`.** `/api/logs` is POST-only, so a GET against it returns
> `405 Method Not Allowed`. There is also no `GET /api/incidents/{id}`, no `/api/events`,
> no `/api/alerts`, no `/api/dashboard/stats` and no `/api/timeline` — those return `404`.
> Stored logs can only be read straight out of `app.db` (which is what the dashboard does).

---

### 1. `GET /`

```json
{
  "message": "Aegisrange Local Correlation Engine is online",
  "status": "active"
}
```

---

### 2. `GET /api/scenarios`

Hard-coded in `main.py`; not read from the database.

```json
[
  { "id": 1, "name": "SSH Brute Force", "difficulty": "Easy" },
  { "id": 2, "name": "SQL Injection Attack", "difficulty": "Medium" }
]
```

---

### 3. `POST /api/logs`

Ingests **one** log object (not a batch) and immediately runs correlation on its `source_ip`.

#### Request body (`LogIngestRequest`)

| Field | Type | Required | Notes |
| :--- | :--- | :--- | :--- |
| `source_ip` | string \| null | No | Defaults to `"127.0.0.1"` when omitted. Correlation keys off this. |
| `destination_ip` | string \| null | No | Defaults to `null`. |
| `log_type` | string | **Yes** | Free-form, e.g. `"auth"`, `"syslog"`, `"web_access"`. Not an enum. |
| `raw_data` | object | **Yes** | Any JSON object. Stored verbatim in a JSON column. |

Anything else you send is ignored — there is no `timestamp`, `source_host`, `event_type`,
`message`, `severity` or `mitre_technique` field on this endpoint. Put whatever extra detail
you have inside `raw_data`.

```bash
curl -X POST http://localhost:8000/api/logs \
  -H "Content-Type: application/json" \
  -d '{
        "source_ip": "10.10.10.10",
        "destination_ip": "10.10.10.20",
        "log_type": "auth",
        "raw_data": {
          "message": "Failed password for root from 10.10.10.10 port 49820 ssh2",
          "user": "root",
          "service": "sshd"
        }
      }'
```

#### Response: `201 Created` (`LogIngestResponse`)

```json
{
  "id": 1,
  "log_type": "auth",
  "created_at": "2026-10-21T08:30:15",
  "processed": true
}
```

`processed` is `true` because the correlator has already evaluated this log. The response
deliberately does **not** echo the incident; poll `GET /api/incidents` for that.

#### Errors

* `422 Unprocessable Entity` — missing or wrongly typed `log_type` / `raw_data` (Pydantic).
* `500 Internal Server Error` — `{"detail": "Failed to ingest log: <error>"}`; the whole
  transaction is rolled back.

---

### 4. `GET /api/incidents`

Returns a **plain JSON array** (no `total` / `incidents` envelope), newest first
(`created_at DESC, id DESC`).

#### Query parameters

| Parameter | Type | Default | Notes |
| :--- | :--- | :--- | :--- |
| `severity` | string | — | Exact match on `low`, `medium` or `high` |
| `status` | string | — | Exact match on `open` or `closed` |
| `source_ip` | string | — | Exact match |
| `limit` | int | `100` | Must be 1–500, otherwise `422` |
| `offset` | int | `0` | Must be ≥ 0 |

Filters are exact, case-sensitive string comparisons: `?severity=High` matches nothing.

#### Response: `200 OK` (`IncidentResponse[]`)

```json
[
  {
    "id": 1,
    "title": "Suspicious activity from 10.10.10.10",
    "description": "3 logs received from 10.10.10.10 within the last 5 minutes.",
    "severity": "low",
    "status": "open",
    "source_ip": "10.10.10.10",
    "log_count": 3,
    "created_at": "2026-10-21T08:30:15",
    "updated_at": "2026-10-21T08:30:15"
  }
]
```

Note what is **not** there: no `target` / `target_host`, no `attacker_ip`, no
`mitre_technique`, no `event_count`, no `alert_count`, no `timestamp`. The `id` is an
auto-incrementing **integer** (`1`, `2`, `3`…) — not a string like `"inc-001"`.

---

## Database schema (`models.py`)

SQLite file `app.db`, created next to whatever directory you start the server from
(`database.py`: `sqlite:///./app.db`).

### `raw_logs`

| Column | Type | Null | Default |
| :--- | :--- | :--- | :--- |
| `id` | Integer, PK, indexed | No | autoincrement |
| `source_ip` | String | Yes | — |
| `destination_ip` | String | Yes | — |
| `log_type` | String | **No** | — |
| `raw_data` | JSON | **No** | — |
| `processed` | Boolean | Yes | `false` |
| `created_at` | DateTime (tz) | Yes | `now()` server-side |

### `incidents`

| Column | Type | Null | Default |
| :--- | :--- | :--- | :--- |
| `id` | Integer, PK, indexed | No | autoincrement |
| `title` | String | **No** | — |
| `description` | Text | Yes | — |
| `severity` | String | **No** | `"low"` |
| `status` | String | **No** | `"open"` |
| `source_ip` | String, indexed | **No** | — |
| `log_count` | Integer | **No** | `0` |
| `created_at` | DateTime (tz) | Yes | `now()` |
| `updated_at` | DateTime (tz) | Yes | `now()`, refreshed on update |

Composite index `ix_incidents_ip_status` on (`source_ip`, `status`).

### Permitted values

| Column | Values the code can write |
| :--- | :--- |
| `severity` | `low`, `medium`, `high` — **lowercase, and there is no `critical`** |
| `status` | `open`, `closed` |

The dashboard upper-cases severity for display only; the stored value stays lowercase.
`status` is only ever set to `closed` by the dashboard's "Mark as investigated" checkbox.

There is **no** `mitre_technique`, `target`, `target_host`, `attacker_ip`, `rule_id`,
`event_id` or `alert` table anywhere in the model. MITRE technique IDs appear in
[`../docs/evidence-mapping.md`](../docs/evidence-mapping.md) as analyst reference material
only, and the dashboard cannot display them because they are not stored.

---

## Correlation logic (`main.py`)

Constants at the top of `main.py`:

```python
LOG_THRESHOLD = 3                   # logs from one source_ip needed to raise an incident
TIME_WINDOW = timedelta(minutes=5)  # ...within this window
SEVERITY_STEPS = [(10, "high"), (5, "medium"), (LOG_THRESHOLD, "low")]
```

On **every** `POST /api/logs`:

1. Count rows in `raw_logs` with the same `source_ip` and `created_at` within the last 5 minutes.
2. If the count is below `3`, do nothing.
3. Otherwise look for an **open** incident for that `source_ip`:
   * found → refresh its `log_count`, `severity` and `description` (no duplicate rows);
   * not found → create one with
     `title = "Suspicious activity from <source_ip>"` and
     `description = "<count> logs received from <source_ip> within the last 5 minutes."`
4. Mark the log `processed = True` and commit log + incident together.

Severity ladder, by log count in the window:

| Logs in window | Severity |
| :--- | :--- |
| 0–2 | *(no incident)* |
| 3–4 | `low` |
| 5–9 | `medium` |
| 10+ | `high` |

A log with no `source_ip` is stored but never correlated. Closing an incident lets a later
burst from the same IP open a fresh one.

---

## Automatic schema migration (`schema.py`)

`main.py` calls `sync_schema(engine, models.Base.metadata)` at import time. On SQLite it:

1. runs `create_all()` for missing tables;
2. compares each table's live columns against the model;
3. if any differ, copies `app.db` to `app.db.bak-YYYYmmdd-HHMMSS`, then drops and recreates
   the table and copies the rows across;
4. fills gaps using `COLUMN_ALIASES` — currently `incidents.created_at` inherits a legacy
   `timestamp` column — then column defaults, then `NULL`/`0`/`"unknown"`.

On a non-SQLite database only `create_all()` runs; use Alembic there instead.

---

## Running the Backend

```bash
pip install -r requirements.txt

# Serve the API (there is no __main__ block in main.py, so `python main.py` does nothing)
uvicorn main:app --reload

# To accept logs from the lab VMs, bind all interfaces instead:
uvicorn main:app --host 0.0.0.0 --port 8000
```

Default address `http://localhost:8000`, reachable from the VMs as `http://10.10.10.1:8000`.
Swagger UI: `http://localhost:8000/docs`.

### Self-test

`Test` (no file extension) is a standalone script covering migration, ingestion,
correlation, escalation, filtering and paging against a temporary database:

```bash
python Test
```

---

## How it Connects with Other Members

* **Member 3 (Collectors)** → one `POST /api/logs` per log record (no batch endpoint yet).
* **Member 4 (Backend)** → correlates on every ingest: 3+ logs from one IP in 5 minutes
  raises or updates an incident.
* **Member 5 (Dashboard)** → **does not call this API.** `dashboard.py` opens `app.db` with
  `sqlite3` and reads `incidents` and `raw_logs` directly, and writes `status` back the same
  way. The dashboard must therefore run with `app.db` in its working directory (or have
  `DB_FILE` pointed at the backend's copy).
