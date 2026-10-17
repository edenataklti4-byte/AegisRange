from fastapi import FastAPI, Depends, HTTPException, status
from sqlalchemy.orm import Session
from pydantic import BaseModel, ConfigDict
from typing import Optional, Dict, Any, List
from datetime import datetime

import models
from database import engine, get_db

# Create database tables automatically if they don't exist
models.Base.metadata.create_all(bind=engine)

app = FastAPI(
    title="Aegisrange Local API",
    description="Backend Correlation Engine & Cyber Range Ingestion Pipeline",
    version="1.0.0"
)

# --- Pydantic Schemas for Log Ingestion ---

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

# NEW: Log Ingestion Endpoint
@app.post("/api/logs", response_model=LogIngestResponse, status_code=status.HTTP_201_CREATED)
def ingest_log(log_payload: LogIngestRequest, db: Session = Depends(get_db)):
    """
    Ingest a raw attack log into the Aegisrange pipeline.
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
        db.commit()
        db.refresh(new_log)
        return new_log
    except Exception as e:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to ingest log: {str(e)}"
        )