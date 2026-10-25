# AegisRange

AegisRange is a controlled, self-hosted cybersecurity training platform that simulates a small enterprise network. Red Team scenarios generate realistic security events, including brute-force credential attacks and malicious file execution, while the integrated Aegis-Local monitoring system collects logs, correlates them into incidents, and presents them to the Blue Team through an investigation dashboard.

## How it works

1. Attack scenarios are launched on a restricted lab environment (Linux server, attacker machine, Windows client), producing authentic logs such as user login attempts, process execution logs and network activity logs.
2. Backend (FastAPI and SQLAlchemy) consumes logs using an API and correlates them automatically. Logs with the same source, which were produced in a short time interval, are correlated to form an incident with a certain severity level.
3. Dashboard (Streamlit) loads the incidents database and shows every incident along with logs related to it, the timeline reconstruction, and tools to mark incidents as investigated and report generation capabilities.

## Tech stack

Backend: FastAPI, SQLAlchemy, SQLite
Dashboard: Streamlit, Pandas
Attack environment: isolated virtual network with Linux, Windows, and an attacker machine
##project demo
https://youtu.be/5f_OvplOO8c?si=ScqVVdOBExa_RbDF
## Team Members

| Name | CTC ID |
|------|--------|
| Amiel Abebe | CTC-7183-26 |
| Frehiwot Kiros | CTC-3254-26 |
| Eden Ataklti | CTC-1017-26 |
| Seblewerk Hailemariam | CTC-1187-26 |
| Eyeruasalem Worku | CTC-3078-26 |

