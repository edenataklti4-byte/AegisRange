# AegisRange API Contracts & Schema Specification

This document defines the interfaces between:

1. **Endpoint telemetry collectors** and the **Aegis-Local backend** (`main.py`)
2. The **correlation engine** and the **incident store** (`app.db`)
3. The **incident store** and the **Streamlit investigation dashboard** (`dashboard.py`)

> [!IMPORTANT]
> **Part 1 is the implemented contract.** Every endpoint, field name, type and value in it was
> read off `main.py` and `models.py` on `main` and verified against a running server. Build
> against Part 1.
>
> **Part 2 is a design backlog — none of it is implemented.** It is kept because it is the
> target design, but any code written against it today will fail. Each section says what the
> current behaviour is instead.
>
> Note also that link 3 is **not** an HTTP interface: the dashboard reads `app.db` with
> `sqlite3` directly. See [`../frontend/README.md`](../frontend/README.md).

Base URL: `http://localhost:8000`, or `http://10.10.10.1:8000` from the lab VMs when the
server is started with `--host 0.0.0.0`. Interactive docs: `/docs`. OpenAPI: `/openapi.json`.

---

# Part 1 — Implemented Contract

FastAPI app `Aegisrange Local API`, version `1.1.0`.

| Method | Path | Purpose |
| :--- | :--- | :--- |
| `GET` | `/` | Liveness check |
| `GET` | `/api/scenarios` | Static scenario catalogue |
| `POST` | `/api/logs` | Ingest a single log; runs correlation |
| `GET` | `/api/incidents` | List correlated incidents |

Those four are the complete route table. Everything else returns an error:

| Request | Actual result |
| :--- | :--- |
| `GET /api/logs` | `405 Method Not Allowed` — the path exists, but POST-only |
| `GET /api/incidents/1` | `404 Not Found` |
| `POST /api/events` / `GET /api/events` | `404 Not Found` |
| `POST /api/alerts` / `GET /api/alerts` | `404 Not Found` |
| `GET /api/dashboard/stats` | `404 Not Found` |
| `GET /api/timeline/{id}` | `404 Not Found` |

There is **no way to read stored logs back over HTTP.** Consumers that need log rows read
`app.db` directly, which is what `dashboard.py` does.

---

## 1.1 `GET /`

#### Response: `200 OK`
```json
{
  "message": "Aegisrange Local Correlation Engine is online",
  "status": "active"
}
```

Use this as the collector's connectivity probe — it is the only cheap GET that always exists.

---

## 1.2 `GET /api/scenarios`

Hard-coded in `main.py`, not database-backed.

#### Response: `200 OK`
```json
[
  { "id": 1, "name": "SSH Brute Force", "difficulty": "Easy" },
  { "id": 2, "name": "SQL Injection Attack", "difficulty": "Medium" }
]
```

---

## 1.3 `POST /api/logs` — Ingest one log

Ingests **one** log object per request. There is no batching, no `batch_id`, no envelope.

* **Headers**: `Content-Type: application/json`
* **Model**: `LogIngestRequest` in `main.py`

### Request body

| Field | Type | Required | Default | Notes |
| :--- | :--- | :--- | :--- | :--- |
| `source_ip` | string \| null | No | `"127.0.0.1"` | Correlation key. Not validated as an IP. |
| `destination_ip` | string \| null | No | `null` | Stored only. |
| `log_type` | string | **Yes** | — | Free-form string, e.g. `auth`, `syslog`, `web_access`. Not an enum. |
| `raw_data` | object | **Yes** | — | Any JSON object; stored verbatim in a JSON column. |

Unknown keys at the top level are ignored. The endpoint accepts no `timestamp`,
`event_id`, `source_host`, `event_type`, `message`, `severity` or `parsed_fields` field —
the server timestamps the row itself and derives severity from volume. Put every extra
attribute inside `raw_data`, where the dashboard will render it.

```json
{
  "source_ip": "10.10.10.10",
  "destination_ip": "10.10.10.20",
  "log_type": "auth",
  "raw_data": {
    "message": "Oct 21 08:30:15 aegis-linux sshd[14221]: Failed password for invalid user admin from 10.10.10.10 port 49822 ssh2",
    "source_host": "aegis-linux",
    "event_type": "auth_failure",
    "service": "sshd",
    "user_name": "admin",
    "is_valid_user": false,
    "destination_port": 22,
    "source_port": 49822,
    "process_id": 14221
  }
}
```

### Response: `201 Created`

`LogIngestResponse` — four fields, nothing more:

```json
{
  "id": 1,
  "log_type": "auth",
  "created_at": "2026-10-21T08:30:15",
  "processed": true
}
```

`id` is the `raw_logs` integer primary key. `processed` is `true` because correlation has
already run. The response does not tell you whether an incident was raised — poll
`GET /api/incidents` for that.

### Errors

`422 Unprocessable Entity` when `log_type` or `raw_data` is missing or wrongly typed —
standard FastAPI/Pydantic shape:

```json
{
  "detail": [
    {
      "type": "missing",
      "loc": ["body", "log_type"],
      "msg": "Field required",
      "input": { "source_ip": "10.10.10.10" }
    }
  ]
}
```

`500 Internal Server Error` on a database failure; the transaction is rolled back:

```json
{ "detail": "Failed to ingest log: <exception text>" }
```

---

## 1.4 `GET /api/incidents` — List incidents

### Query parameters

| Parameter | Type | Default | Validation |
| :--- | :--- | :--- | :--- |
| `severity` | string | — | Exact match against `low` \| `medium` \| `high` |
| `status` | string | — | Exact match against `open` \| `closed` |
| `source_ip` | string | — | Exact match |
| `limit` | int | `100` | `1 ≤ limit ≤ 500`, else `422` |
| `offset` | int | `0` | `offset ≥ 0`, else `422` |

Matching is exact and case-sensitive: `?severity=High` and `?severity=critical` both return
`[]`. Ordering is `created_at DESC, id DESC`.

### Response: `200 OK`

A bare JSON array — there is no `{"total": …, "incidents": […]}` wrapper:

```json
[
  {
    "id": 2,
    "title": "Suspicious activity from 10.10.10.10",
    "description": "12 logs received from 10.10.10.10 within the last 5 minutes.",
    "severity": "high",
    "status": "open",
    "source_ip": "10.10.10.10",
    "log_count": 12,
    "created_at": "2026-10-21T08:30:15",
    "updated_at": "2026-10-21T08:31:02"
  },
  {
    "id": 1,
    "title": "Suspicious activity from 10.10.10.30",
    "description": "4 logs received from 10.10.10.30 within the last 5 minutes.",
    "severity": "low",
    "status": "closed",
    "source_ip": "10.10.10.30",
    "log_count": 4,
    "created_at": "2026-10-21T08:12:44",
    "updated_at": "2026-10-21T08:20:10"
  }
]
```

### `IncidentResponse` field definitions

| Field | Type | Null | Notes |
| :--- | :--- | :--- | :--- |
| `id` | **integer** | No | Auto-incrementing `1, 2, 3…`. **Not** a string, and not `"inc-001"` or a UUID. |
| `title` | string | No | Generated as `Suspicious activity from <source_ip>`. |
| `description` | string | Yes | `<count> logs received from <ip> within the last 5 minutes.` |
| `severity` | string | No | `low` \| `medium` \| `high`. Lowercase. **No `critical`.** |
| `status` | string | No | `open` \| `closed`. **No `investigating` or `resolved`.** |
| `source_ip` | string | No | The correlated attacker IP. |
| `log_count` | integer | No | Logs seen from that IP inside the window. |
| `created_at` | string (ISO 8601) | Yes | Server-generated. The column is `created_at`, not `timestamp`. |
| `updated_at` | string (ISO 8601) | Yes | Refreshed whenever the incident is re-correlated. |

Those nine fields are the entire payload. Fields that older drafts of this document showed
and that **do not exist**: `incident_id`, `target`, `target_host`, `attacker_ip`,
`mitre_technique`, `mitre_techniques`, `compromised_account`, `alert_count`, `event_count`,
`start_time`, `last_updated`, `summary`, `entities`, `tactics_observed`, `alerts`,
`timestamp`.

---

## 1.5 Correlation Contract

Implemented in `correlate_source_ip()` in `main.py`, re-evaluated on every ingest.

```python
LOG_THRESHOLD = 3                   # logs from one source_ip...
TIME_WINDOW = timedelta(minutes=5)  # ...inside this window
SEVERITY_STEPS = [(10, "high"), (5, "medium"), (LOG_THRESHOLD, "low")]
```

| Logs from one `source_ip` in 5 min | Result |
| :--- | :--- |
| 0–2 | No incident |
| 3–4 | Incident, `severity: "low"` |
| 5–9 | Existing open incident updated to `"medium"` |
| 10+ | Existing open incident updated to `"high"` |

* One **open** incident per `source_ip` at a time; later bursts update it rather than
  inserting duplicates (`log_count`, `severity` and `description` are refreshed, and
  `updated_at` moves).
* Correlation keys on `source_ip` only — not on host, user or process.
* A log posted without `source_ip` defaults to `127.0.0.1` and correlates under that IP.
* Closing an incident allows a later burst from the same IP to open a new one.

---

## 1.6 Stored Schema (`models.py`)

SQLite, `sqlite:///./app.db`, relative to the server's working directory. Both tables are
created and kept in sync by `sync_schema()` in `schema.py` at import time, which backs the
file up to `app.db.bak-<timestamp>` before any rebuild.

### `raw_logs`

| Column | Type | Nullable | Default |
| :--- | :--- | :--- | :--- |
| `id` | Integer PK (indexed) | No | autoincrement |
| `source_ip` | String | Yes | — |
| `destination_ip` | String | Yes | — |
| `log_type` | String | No | — |
| `raw_data` | JSON | No | — |
| `processed` | Boolean | Yes | `false` |
| `created_at` | DateTime (tz) | Yes | `now()` |

### `incidents`

| Column | Type | Nullable | Default |
| :--- | :--- | :--- | :--- |
| `id` | Integer PK (indexed) | No | autoincrement |
| `title` | String | No | — |
| `description` | Text | Yes | — |
| `severity` | String | No | `"low"` |
| `status` | String | No | `"open"` |
| `source_ip` | String (indexed) | No | — |
| `log_count` | Integer | No | `0` |
| `created_at` | DateTime (tz) | Yes | `now()` |
| `updated_at` | DateTime (tz) | Yes | `now()`, `onupdate=now()` |

Composite index `ix_incidents_ip_status` on (`source_ip`, `status`).

There is no `alerts` table, no `events` table, and no MITRE, rule, host or user column
anywhere in the schema.

---

## 1.7 HTTP Status Codes Actually Returned

| Code | When |
| :--- | :--- |
| `200 OK` | `GET /`, `GET /api/scenarios`, `GET /api/incidents` |
| `201 Created` | `POST /api/logs` succeeded |
| `404 Not Found` | Any unrouted path (`/api/events`, `/api/alerts`, `/api/incidents/{id}`, …) |
| `405 Method Not Allowed` | `GET`, `PUT` or `DELETE` on `/api/logs` |
| `422 Unprocessable Entity` | Pydantic validation failure in body or query params |
| `500 Internal Server Error` | Database failure during ingest |

Errors use FastAPI's default envelope — `{"detail": …}`, a string for `HTTPException` and a
list of validation objects for `422`. There is no `{"error": {"code": …}}` wrapper.

---

# Part 2 — Planned / Not Implemented

> [!CAUTION]
> Nothing in Part 2 exists in the code. These are design notes for future work. Do not write
> collectors, dashboards or tests against them.

## 2.1 Normalized Event Schema *(planned)*

The intended richer collector-side envelope:

```json
{
  "event_id": "d8e3b4a2-7b19-48c2-a9b0-318e8031d24f",
  "timestamp": "2026-10-21T08:30:15.123Z",
  "source_host": "aegis-linux",
  "source_ip": "10.10.10.10",
  "event_type": "auth_failure",
  "severity": "medium",
  "raw_log": "Oct 21 08:30:15 aegis-linux sshd[14221]: Failed password for invalid user admin from 10.10.10.10 port 49822 ssh2",
  "parsed_fields": {
    "service": "sshd",
    "user_name": "admin",
    "is_valid_user": false,
    "destination_ip": "10.10.10.20",
    "destination_port": 22,
    "source_port": 49822,
    "process_id": 14221,
    "protocol": "ssh2"
  }
}
```

**Today instead**: `POST /api/logs` takes only `source_ip`, `destination_ip`, `log_type` and
`raw_data`. Collectors that already build the envelope above should send
`{"source_ip": …, "destination_ip": …, "log_type": <event_type or source>, "raw_data": <the whole envelope>}`
so nothing is lost — `raw_data` is schemaless and the dashboard prints it.

## 2.2 Batch ingestion — `POST /api/events` *(planned)*

An array of normalized events under a `batch_id` envelope, answering with
`received_count` / `processed_count` / `errors`.

**Today instead**: `404`. Send one `POST /api/logs` per record.

## 2.3 Event query — `GET /api/events` *(planned)*

Filtering by `source_host`, `event_type`, `source_ip`, `start_time`, `end_time`, with
`limit` / `offset` paging.

**Today instead**: `404`, and `GET /api/logs` is `405`. Query `raw_logs` in `app.db`.

## 2.4 Alerts — `POST /api/alerts`, `GET /api/alerts` *(planned)*

A rule-level alert object (`rule_id`, `rule_name`, `mitre_id`, `mitre_tactic`,
`triggering_event_ids`, `context`) sitting between events and incidents.

**Today instead**: `404`. There is no alert layer and no rule engine — correlation is the
single volume threshold in §1.5, and no rule or MITRE identifier is persisted. The rule IDs
in [`evidence-mapping.md`](evidence-mapping.md) are detection-engineering notes, not code.

## 2.5 Incident detail — `GET /api/incidents/:id` *(planned)*

Per-incident entities, observed tactics and contributing alerts.

**Today instead**: `404`. `GET /api/incidents?source_ip=…&limit=1` is the closest thing, and
it returns the same nine fields as the list.

## 2.6 Incident events — `GET /api/incidents/:id/events` *(planned)*

The raw events behind one incident.

**Today instead**: `404`. Incidents and logs are joined only by `source_ip`, which is exactly
how the dashboard assembles an incident's related logs — there is no foreign key between
`incidents` and `raw_logs`.

## 2.7 Dashboard statistics — `GET /api/dashboard/stats` *(planned)*

Aggregate counters, endpoint heartbeats and MITRE coverage.

**Today instead**: `404`. The dashboard computes its five metrics in pandas after reading
`app.db`; nothing tracks uptime, ingestion rate or endpoint heartbeats.

## 2.8 Reconstructed timeline — `GET /api/timeline/:incident_id` *(planned)*

Ordered forensic milestones with stage labels, actors, confidence and MITRE IDs.

**Today instead**: `404`. The dashboard's "Log Timeline" tab orders `raw_logs` by
`created_at` and labels each row with the incident titles for its `source_ip`. There are no
stage, actor, confidence or MITRE fields to show.

## 2.9 Structured error envelope *(planned)*

```json
{ "error": { "code": "RESOURCE_NOT_FOUND", "message": "…", "details": null, "timestamp": "…" } }
```

**Today instead**: FastAPI's `{"detail": …}` as described in §1.7.
