 member--4-backend-correlation
from sqlalchemy import Column, Integer, String, Boolean, DateTime, JSON, Text, Index
from sqlalchemy.sql import func
from database import Base


class RawLog(Base):
    __tablename__ = "raw_logs"

    id = Column(Integer, primary_key=True, index=True)
    source_ip = Column(String, nullable=True)
    destination_ip = Column(String, nullable=True)
    log_type = Column(String, nullable=False)
    raw_data = Column(JSON, nullable=False)
    processed = Column(Boolean, default=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now())


class Incident(Base):
    """A security incident created automatically by the correlation logic."""
    __tablename__ = "incidents"
    __table_args__ = (Index("ix_incidents_ip_status", "source_ip", "status"),)

    id = Column(Integer, primary_key=True, index=True)
    title = Column(String, nullable=False)
    description = Column(Text, nullable=True)
    severity = Column(String, nullable=False, default="low")   # low | medium | high
    status = Column(String, nullable=False, default="open")    # open | closed
    source_ip = Column(String, nullable=False, index=True)
    log_count = Column(Integer, nullable=False, default=0)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())

from fastapi import FastAPI, Depends, HTTPException, Query, status
from sqlalchemy import func, select
from sqlalchemy.orm import Session
from pydantic import BaseModel, ConfigDict
from typing import Optional, Dict, Any, List
from datetime import datetime, timedelta, timezone

import models
from database import engine, get_db
from schema_sync import sync_schema
sync_schema(engine, models.Base.metadata)

app = FastAPI(
    title="Aegisrange Local API",
    description="Backend Correlation Engine & Cyber Range Ingestion Pipeline",
    version="1.1.0"
)

# --- Correlation settings ---

LOG_THRESHOLD = 3                 # logs from one source_ip needed to raise an incident
TIME_WINDOW = timedelta(minutes=5)  # ...within this time window
SEVERITY_STEPS = [(10, "high"), (5, "medium"), (LOG_THRESHOLD, "low")]


# --- Pydantic Schemas ---

class LogIngestRequest(BaseModel):
    source_ip: Optional[str] = "127.0.0.1"
    destination_ip: Optional[str] = None
    log_type: str  # e.g., 'syslog', 'auth', 'web_access'
    raw_data: Dict[str, Any]  # Flexible payload for attack log data

class LogIngestResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    log_type: str
    created_at: datetime
    processed: bool

class IncidentResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    title: str
    description: Optional[str]
    severity: str
    status: str
    source_ip: str
    log_count: int
    created_at: datetime
    updated_at: Optional[datetime]


# --- Correlation Logic ---

def severity_for(count: int) -> str:
    for minimum, label in SEVERITY_STEPS:
        if count >= minimum:
            return label
    return "low"


def correlate_source_ip(db: Session, source_ip: Optional[str]) -> Optional[models.Incident]:
    """
    If `source_ip` has sent >= LOG_THRESHOLD logs within TIME_WINDOW, create a
    security incident. If an open incident already exists for that IP, update it
    instead, so we never create duplicates.
    """
    if not source_ip:
        return None

    since = datetime.now(timezone.utc) - TIME_WINDOW
    count = db.scalar(
        select(func.count(models.RawLog.id)).where(
            models.RawLog.source_ip == source_ip,
            models.RawLog.created_at >= since,
        )
    )
    if count < LOG_THRESHOLD:
        return None

    minutes = int(TIME_WINDOW.total_seconds() // 60)
    description = f"{count} logs received from {source_ip} within the last {minutes} minutes."

    incident = db.scalar(
        select(models.Incident).where(
            models.Incident.source_ip == source_ip,
            models.Incident.status == "open",
        )
    )
    if incident:  # already open: refresh it
        incident.log_count = count
        incident.severity = severity_for(count)
        incident.description = description
    else:         # first time crossing the threshold: create it
        incident = models.Incident(
            title=f"Suspicious activity from {source_ip}",
            description=description,
            severity=severity_for(count),
            status="open",
            source_ip=source_ip,
            log_count=count,
        )
        db.add(incident)
    return incident


# --- API Routes ---

@app.get("/")
def read_root():
    return {
        "message": "Aegisrange Local Correlation Engine is online",
        "status": "active"
    }

@app.get("/api/scenarios")
def get_scenarios():
    return [
        {"id": 1, "name": "SSH Brute Force", "difficulty": "Easy"},
        {"id": 2, "name": "SQL Injection Attack", "difficulty": "Medium"}
    ]

# Log Ingestion Endpoint (now runs correlation on every new log)
@app.post("/api/logs", response_model=LogIngestResponse, status_code=status.HTTP_201_CREATED)
def ingest_log(log_payload: LogIngestRequest, db: Session = Depends(get_db)):
    """
    Ingest a raw attack log into the Aegisrange pipeline and run correlation.
    """
    try:
        new_log = models.RawLog(
            source_ip=log_payload.source_ip,
            destination_ip=log_payload.destination_ip,
            log_type=log_payload.log_type,
            raw_data=log_payload.raw_data,
            processed=False
        )
        db.add(new_log)
        db.flush()  # session has autoflush=False, so flush so the count query sees this log

        correlate_source_ip(db, new_log.source_ip)
        new_log.processed = True  # this log has now been evaluated by the correlator

        db.commit()  # log + incident are saved together
        db.refresh(new_log)
        return new_log
    except Exception as e:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to ingest log: {str(e)}"
        )

# NEW: View detected security incidents
@app.get("/api/incidents", response_model=List[IncidentResponse])
def list_incidents(
    severity: Optional[str] = Query(None, description="low | medium | high"),
    incident_status: Optional[str] = Query(None, alias="status", description="open | closed"),
    source_ip: Optional[str] = None,
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db),
):
    """
    List all detected security incidents, newest first.
    Optional filters: severity, status, source_ip.
    """
    stmt = select(models.Incident).order_by(models.Incident.created_at.desc(), models.Incident.id.desc())
    if severity:
        stmt = stmt.where(models.Incident.severity == severity)
    if incident_status:
        stmt = stmt.where(models.Incident.status == incident_status)
    if source_ip:
        stmt = stmt.where(models.Incident.source_ip == source_ip)
    return db.scalars(stmt.limit(limit).offset(offset)).all()
main
