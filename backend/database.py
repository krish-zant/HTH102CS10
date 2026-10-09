import sqlite3
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "data"
DB_PATH = DATA_DIR / "soc.db"


def get_connection():
    DATA_DIR.mkdir(exist_ok=True)

    connection = sqlite3.connect(
        DB_PATH,
        check_same_thread=False
    )

    connection.row_factory = sqlite3.Row

    return connection


def initialize_database():
    connection = get_connection()

    cursor = connection.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS events (
            event_id TEXT PRIMARY KEY,
            timestamp TEXT,
            source_type TEXT,
            source_ip TEXT,
            destination_ip TEXT,
            username TEXT,
            event_type TEXT,
            severity TEXT,
            asset_criticality TEXT,
            message TEXT
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS incidents (
            incident_id TEXT PRIMARY KEY,
            correlation_id TEXT,
            incident_type TEXT,
            incident_patterns TEXT,
            incident_title TEXT,
            incident_start TEXT,
            incident_end TEXT,
            source_ip TEXT,
            destination_ip TEXT,
            signal_types TEXT,
            source_types TEXT,
            signal_count INTEGER,
            unique_event_count INTEGER,
            fusion_strength REAL,
            risk_score REAL,
            severity TEXT,
            priority_score REAL,
            priority_level TEXT,
            queue_rank INTEGER,
            recommended_action TEXT,
            canonical_evidence TEXT,
            evidence_hash TEXT,
            integrity_status TEXT
        )
    """)

    connection.commit()
    connection.close()


def save_event(event):
    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute("""
        INSERT OR REPLACE INTO events (
            event_id,
            timestamp,
            source_type,
            source_ip,
            destination_ip,
            username,
            event_type,
            severity,
            asset_criticality,
            message
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        event["event_id"],
        event["timestamp"],
        event.get("source_type"),
        event.get("source_ip"),
        event.get("destination_ip"),
        event.get("username"),
        event.get("event_type"),
        event.get("severity"),
        event.get("asset_criticality"),
        event.get("message")
    ))

    connection.commit()
    connection.close()


def save_incident(incident):
    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute("""
        INSERT OR REPLACE INTO incidents (
            incident_id,
            correlation_id,
            incident_type,
            incident_patterns,
            incident_title,
            incident_start,
            incident_end,
            source_ip,
            destination_ip,
            signal_types,
            source_types,
            signal_count,
            unique_event_count,
            fusion_strength,
            risk_score,
            severity,
            priority_score,
            priority_level,
            queue_rank,
            recommended_action,
            canonical_evidence,
            evidence_hash,
            integrity_status
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        incident["incident_id"],
        incident["correlation_id"],
        incident["incident_type"],
        incident["incident_patterns"],
        incident["incident_title"],
        incident["incident_start"],
        incident["incident_end"],
        incident["source_ip"],
        incident.get("destination_ip"),
        incident["signal_types"],
        incident["source_types"],
        incident["signal_count"],
        incident["unique_event_count"],
        incident["fusion_strength"],
        incident["risk_score"],
        incident["severity"],
        incident["priority_score"],
        incident["priority_level"],
        incident["queue_rank"],
        incident["recommended_action"],
        incident["canonical_evidence"],
        incident["evidence_hash"],
        incident["integrity_status"]
    ))

    connection.commit()
    connection.close()


def get_incidents():
    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute("""
        SELECT *
        FROM incidents
        WHERE queue_rank > 0
        ORDER BY queue_rank ASC
    """)

    rows = cursor.fetchall()
    connection.close()

    return [dict(row) for row in rows]


def get_incident(incident_id):
    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute("""
        SELECT *
        FROM incidents
        WHERE incident_id = ?
    """, (incident_id,))

    row = cursor.fetchone()
    connection.close()

    return dict(row) if row else None
def get_recent_events(limit=20):
    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute("""
        SELECT
            event_id,
            timestamp,
            source_type,
            source_ip,
            destination_ip,
            username,
            event_type,
            severity,
            asset_criticality,
            message
        FROM events
        ORDER BY timestamp DESC
        LIMIT ?
    """, (limit,))

    rows = cursor.fetchall()
    connection.close()

    return [dict(row) for row in rows]