import os
import sqlite3
from datetime import datetime, timezone
import pandas as pd
import streamlit as st

DB_FILE = "app.db"
ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
SEV_COLOR = {"CRITICAL": "red", "HIGH": "red", "MEDIUM": "orange", "LOW": "green"}
INCIDENT_COLS = {"id", "title", "description", "severity", "status", "source_ip", "log_count", "created_at", "updated_at"}
LOG_COLS = ["id", "source_ip", "destination_ip", "log_type", "raw_data", "created_at"]

st.set_page_config(page_title="AegisRange", page_icon=":material/shield:", layout="wide")

st.title("AegisRange")
st.caption("Incident investigation dashboard")

st.sidebar.button("Refresh data", help="Reload everything from the database")

if not os.path.exists(DB_FILE):
    st.warning(f"No data yet. The database file ({DB_FILE}) was not found next to this dashboard.\n\nStart the backend so it creates {DB_FILE}, or change DB_FILE at the top of dashboard.py to the full path of the backend's {DB_FILE}. Then click Refresh data.")
    st.stop()

con = sqlite3.connect(DB_FILE)
tables = {r[0] for r in con.execute("SELECT name FROM sqlite_master WHERE type = 'table'")}
if "incidents" not in tables:
    st.warning(f"No data yet. {DB_FILE} exists but has no incidents table. Start the backend and send some logs first, then click Refresh data.")
    st.stop()

inc_cols = {r[1] for r in con.execute("PRAGMA table_info(incidents)")}
missing = INCIDENT_COLS - inc_cols
if missing:
    st.error(f"The incidents table is missing these columns: {', '.join(sorted(missing))}. The dashboard and backend schemas no longer match.")
    st.stop()

log_cols = {r[1] for r in con.execute("PRAGMA table_info(raw_logs)")} if "raw_logs" in tables else set()
if set(LOG_COLS) <= log_cols:
    logs = pd.read_sql_query("SELECT id, source_ip, destination_ip, log_type, raw_data, created_at FROM raw_logs", con)
else:
    logs = pd.DataFrame(columns=LOG_COLS)
    st.sidebar.warning("raw_logs table not found. Timeline and related logs will be empty.")

incidents = pd.read_sql_query("SELECT * FROM incidents", con)
if incidents.empty:
    st.info("No incidents have been created yet. They appear here once the backend correlates some logs.")
    st.stop()

incidents["severity"] = incidents["severity"].fillna("low").str.upper()
incidents["status"] = incidents["status"].fillna("open").str.lower()
incidents["description"] = incidents["description"].fillna("No description provided.")
incidents["source_ip"] = incidents["source_ip"].fillna("unknown")
incidents["created_dt"] = pd.to_datetime(incidents["created_at"], format="mixed", errors="coerce")
incidents["updated_dt"] = pd.to_datetime(incidents["updated_at"], format="mixed", errors="coerce")
incidents["created_str"] = incidents["created_dt"].dt.strftime("%Y-%m-%d %H:%M:%S").fillna("unknown time")
incidents["updated_str"] = incidents["updated_dt"].dt.strftime("%Y-%m-%d %H:%M:%S").fillna("unknown time")

logs["source_ip"] = logs["source_ip"].fillna("unknown")
logs["destination_ip"] = logs["destination_ip"].fillna("unknown")
logs["log_type"] = logs["log_type"].fillna("unknown").astype(str)
logs["raw_data"] = logs["raw_data"].astype(str)
logs["created_dt"] = pd.to_datetime(logs["created_at"], format="mixed", errors="coerce")
logs["time_str"] = logs["created_dt"].dt.strftime("%Y-%m-%d %H:%M:%S").fillna("unknown time")
logs = logs.sort_values("created_dt")

st.sidebar.header("Filters")
sev_options = ORDER + sorted(set(incidents["severity"]) - set(ORDER))
sel_sev = st.sidebar.multiselect("Severity", sev_options, default=sev_options)
status_options = sorted(set(incidents["status"]) | {"open", "closed"})
sel_status = st.sidebar.multiselect("Status", status_options, default=status_options)
all_ips = sorted(set(incidents["source_ip"]) | set(logs["source_ip"]))
sel_ips = st.sidebar.multiselect("Source IP", all_ips, default=all_ips)
search = st.sidebar.text_input("Search (title / description / IP / log content)").lower()
sort_by = st.sidebar.radio("Sort incidents by", ["Newest first", "Oldest first", "Severity (highest first)"])

view = incidents[incidents["severity"].isin(sel_sev) & incidents["status"].isin(sel_status) & incidents["source_ip"].isin(sel_ips)]
if search:
    ip_hits = set(
        logs[
            logs["raw_data"].str.lower().str.contains(search, regex=False)
            | logs["log_type"].str.lower().str.contains(search, regex=False)
        ]["source_ip"]
    )
    view = view[
        view["title"].str.lower().str.contains(search, regex=False)
        | view["description"].str.lower().str.contains(search, regex=False)
        | view["source_ip"].str.lower().str.contains(search, regex=False)
        | view["source_ip"].isin(ip_hits)
    ]

if sort_by == "Oldest first":
    view = view.sort_values("created_dt")
elif sort_by == "Severity (highest first)":
    view = view.assign(_r=view["severity"].map({s: i for i, s in enumerate(sev_options)})).sort_values(["_r", "created_dt"], ascending=[True, False])
else:
    view = view.sort_values("created_dt", ascending=False)

is_high = incidents["severity"].isin(["CRITICAL", "HIGH"])
is_open = incidents["status"] == "open"
if int((is_high & is_open).sum()):
    st.error(f"{int((is_high & is_open).sum())} high-severity incident(s) still open. Review them first.")

c1, c2, c3, c4, c5 = st.columns(5)
c1.metric("Incidents", len(incidents), border=True)
c2.metric("Open", int(is_open.sum()), border=True)
c3.metric("High Severity", int(is_high.sum()), border=True)
c4.metric("Raw Logs", len(logs), border=True)
c5.metric("Source IPs", incidents["source_ip"].nunique(), border=True)

st.write("")
tab_inc, tab_time = st.tabs(["Incidents", "Log Timeline"])

with tab_inc:
    left, right = st.columns([2, 1])

    with left:
        st.subheader(f"Incidents ({len(view)} shown)")
        if view.empty:
            st.info("No incidents match the current filters.")

        for _, inc in view.iterrows():
            inc_logs = logs[logs["source_ip"] == inc["source_ip"]]
            sev_tag = f":{SEV_COLOR.get(inc['severity'], 'gray')}[**{inc['severity']}**]"
            status_tag = ":green[Closed]" if inc["status"] == "closed" else ":gray[Open]"

            with st.expander(f"{sev_tag}  {inc['title']}  |  {status_tag}", expanded=(inc["status"] == "open")):
                st.write(f"**Source IP:** {inc['source_ip']}   |   **Logs correlated:** {inc['log_count']}   |   **Created:** {inc['created_str']}   |   **Last updated:** {inc['updated_str']}")
                st.info(f"**Description:** {inc['description']}")

                st.markdown(f"**Related logs from {inc['source_ip']}** ({len(inc_logs)} stored)")
                if inc_logs.empty:
                    st.caption("No raw logs stored for this IP.")
                for _, l in inc_logs.head(20).iterrows():
                    st.markdown(f"- `{l['time_str']}`  **{l['log_type']}**  {l['source_ip']} to {l['destination_ip']}  \n  &nbsp;&nbsp;`{l['raw_data']}`")
                if len(inc_logs) > 20:
                    st.caption(f"Showing the first 20 of {len(inc_logs)}. The Log Timeline tab shows all of them.")

                report = "\n".join(
                    [
                        f"# Incident Report #{inc['id']}: {inc['title']}",
                        "",
                        f"- **Severity:** {inc['severity']}",
                        f"- **Status:** {inc['status']}",
                        f"- **Source IP:** {inc['source_ip']}",
                        f"- **Logs correlated:** {inc['log_count']}",
                        f"- **Created (UTC):** {inc['created_str']}",
                        f"- **Last updated (UTC):** {inc['updated_str']}",
                        "",
                        "## Description",
                        inc["description"],
                        "",
                        f"## Related logs ({len(inc_logs)} stored)",
                    ]
                    + [f"{n}. `{l['time_str']}` {l['log_type']} {l['source_ip']} to {l['destination_ip']}: {l['raw_data']}" for n, (_, l) in enumerate(inc_logs.iterrows(), start=1)]
                    + ["", "_Generated by AegisRange._", ""]
                )

                b1, b2 = st.columns(2)
                with b1:
                    closed = st.checkbox("Mark as investigated (sets status to closed)", value=(inc["status"] == "closed"), key=f"inv_{inc['id']}")
                with b2:
                    st.download_button("Download incident report", report, file_name=f"incident_{inc['id']}_report.md", mime="text/markdown", key=f"dl_{inc['id']}")

                if closed != (inc["status"] == "closed"):
                    con.execute(
                        "UPDATE incidents SET status = ?, updated_at = ? WHERE id = ?",
                        ("closed" if closed else "open", datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S"), int(inc["id"])),
                    )
                    con.commit()
                    st.rerun()

    with right:
        st.subheader("Incidents by Severity")
        sev_counts = incidents["severity"].value_counts().reindex([s for s in sev_options if s in set(incidents["severity"])])
        st.bar_chart(sev_counts)

        st.subheader("Incidents by Status")
        st.bar_chart(incidents["status"].value_counts())

        st.subheader("Raw Logs by Type")
        if logs.empty:
            st.caption("No raw logs stored yet.")
        else:
            st.bar_chart(logs["log_type"].value_counts())

        st.subheader("Incidents over Time")
        timed = incidents.dropna(subset=["created_dt"])
        if timed.empty:
            st.caption("No timestamps to plot.")
        else:
            st.bar_chart(timed.groupby(timed["created_dt"].dt.floor("h")).size())

with tab_time:
    st.subheader("Log Timeline")
    st.caption("Every stored log in time order, with the incident it belongs to. Times are UTC. Uses the sidebar filters.")

    if logs.empty:
        st.info("No raw logs stored yet.")
    else:
        log_types = sorted(logs["log_type"].unique())
        sel_types = st.multiselect("Log type", log_types, default=log_types)

        tl = logs[logs["source_ip"].isin(sel_ips) & logs["log_type"].isin(sel_types)]
        if search:
            tl = tl[
                tl["raw_data"].str.lower().str.contains(search, regex=False)
                | tl["log_type"].str.lower().str.contains(search, regex=False)
                | tl["source_ip"].str.lower().str.contains(search, regex=False)
                | tl["destination_ip"].str.lower().str.contains(search, regex=False)
            ]
        tl = tl.sort_values("created_dt")
        ip_to_titles = incidents.groupby("source_ip")["title"].apply(list).to_dict()

        if tl.empty:
            st.info("No logs match the current filters.")
        else:
            st.caption(f"{len(tl)} logs match. Showing the latest {min(len(tl), 100)}.")

        for _, l in tl.tail(100).iterrows():
            with st.container(border=True):
                st.markdown(f"`{l['time_str']}`  **{l['log_type']}**  |  {l['source_ip']} to {l['destination_ip']}")
                st.code(l["raw_data"], language="json")
                linked = ip_to_titles.get(l["source_ip"], [])
                if linked:
                    st.caption("Linked incident(s): " + "; ".join(linked))

        st.divider()
        st.subheader("Raw Logs Table")
        table = tl.drop(columns=["created_dt", "time_str"])
        st.dataframe(table)
        st.download_button("Download logs as CSV", table.to_csv(index=False), "aegisrange_logs.csv", "text/csv")