from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from typing import Optional
from backend.auth import authenticate

from backend.database import(initialize_database, get_incidents, get_incident, get_recent_events) 
from backend.pipeline import process_event, verify_incident_integrity


app = FastAPI(
    title="Signal-Fused SOC API",
    description="Signal-Fused Intrusion Detection and Response Prioritization API",
    version="1.0.0",
)

@app.on_event("startup")
def startup():
    initialize_database()


class SecurityEvent(BaseModel):
    timestamp: str
    source_type: str
    source_ip: str
    destination_ip: Optional[str] = None
    username: Optional[str] = None
    event_type: str
    severity: Optional[str] = None
    asset_criticality: Optional[str] = None
    message: Optional[str] = None

class LoginRequest(BaseModel):
    username: str
    password: str

@app.get("/")
def root():
    return {
        "name": "Signal-Fused SOC API",
        "status": "running",
        "version": "1.0.0",
    }


@app.post("/api/events")
def create_event(event: SecurityEvent):
    try:
        result = process_event(event.model_dump())

        return {
            "status": "success",
            "result": result,
        }

    except Exception as error:
        raise HTTPException(
            status_code=500,
            detail=str(error),
        )


@app.get("/api/incidents")
def list_incidents():
    try:
        incidents = get_incidents()

        return {
            "count": len(incidents),
            "incidents": incidents,
        }

    except Exception as error:
        raise HTTPException(
            status_code=500,
            detail=str(error),
        )

@app.get("/api/events/recent")
def recent_events(limit: int = 20):
    try:
        limit = max(1, min(limit, 100))

        events = get_recent_events(limit)

        return {
            "count": len(events),
            "events": events
        }

    except Exception as error:
        raise HTTPException(
            status_code=500,
            detail=str(error)
        )
    
@app.get("/api/incidents/{incident_id}")
def incident_details(incident_id: str):
    incident = get_incident(incident_id)

    if not incident:
        raise HTTPException(
            status_code=404,
            detail="Incident not found",
        )

    return incident

@app.get("/api/dashboard/summary")
def dashboard_summary():
    incidents = get_incidents()

    severity_counts = {
        "CRITICAL": 0,
        "HIGH": 0,
        "MEDIUM": 0,
        "LOW": 0,
    }

    priority_counts = {
        "P1": 0,
        "P2": 0,
        "P3": 0,
        "P4": 0,
    }

    integrity_counts = {
        "VERIFIED": 0,
        "TAMPERED": 0,
        "OTHER": 0,
    }

    for incident in incidents:

        severity = incident.get("severity")
        if severity in severity_counts:
            severity_counts[severity] += 1

        priority = incident.get("priority_level")
        if priority in priority_counts:
            priority_counts[priority] += 1

        integrity = incident.get("integrity_status")

        if integrity == "INTEGRITY_VERIFIED":
            integrity_counts["VERIFIED"] += 1
        elif integrity == "TAMPERING_DETECTED":
            integrity_counts["TAMPERED"] += 1
        else:
            integrity_counts["OTHER"] += 1

    return {
        "total_incidents": len(incidents),
        "severity": severity_counts,
        "priority": priority_counts,
        "integrity": integrity_counts,
    }

@app.get("/api/trust/{incident_id}/verify")
def verify_trust(incident_id: str):

    incident = get_incident(incident_id)

    if not incident:
        raise HTTPException(
            status_code=404,
            detail="Incident not found",
        )

    return verify_incident_integrity(incident_id)

@app.post("/api/auth/login")
def analyst_login(request: LoginRequest):

    authenticated, analyst = authenticate(
        request.username,
        request.password
    )

    if not authenticated:

        raise HTTPException(
            status_code=401,
            detail="Invalid username or password"
        )

    return {
        "authenticated": True,
        "analyst": analyst
    }