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
