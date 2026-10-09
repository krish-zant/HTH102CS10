import hashlib
import json
import uuid

from datetime import datetime, timezone, timedelta
from pathlib import Path

from backend.database import (
    get_connection,
    save_event,
    save_incident,
    get_incident,
)




BASE_DIR = Path(__file__).resolve().parent.parent

CORRELATION_WINDOW_SECONDS = 300
ANALYST_CAPACITY = 10




def generate_id(prefix):
    return f"{prefix}-{uuid.uuid4().hex[:10].upper()}"


def parse_timestamp(timestamp):
    if not timestamp:
        return datetime.now(timezone.utc)

    value = timestamp.replace("Z", "+00:00")

    parsed = datetime.fromisoformat(value)

    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)

    return parsed


def normalize_timestamp(timestamp):
    return parse_timestamp(timestamp).isoformat()


SIGNAL_RULES = {
    "FAILED_LOGIN": ("AUTH_FAILURE_SIGNAL", 0.70),
    "AUTH_FAILURE": ("AUTH_FAILURE_SIGNAL", 0.70),

    "BRUTE_FORCE": ("BRUTE_FORCE_SIGNAL", 0.90),

    "CONNECTION_FAILURE": ("CONNECTION_FAILURE_SIGNAL", 0.60),

    "CONNECTION_ATTEMPT": ("CONNECTION_ATTEMPT_SIGNAL", 0.55),

    "PORT_SCAN": ("PORT_SCAN_SIGNAL", 0.85),

    "SCAN": ("SCAN_EVENT_SIGNAL", 0.70),

    "TRAFFIC_SPIKE": ("TRAFFIC_SPIKE_SIGNAL", 0.75),

    "LARGE_TRANSFER": ("LARGE_TRANSFER_SIGNAL", 0.75),

    "FIREWALL_DENY": ("FIREWALL_DENY_SIGNAL", 0.70),

    "IDS_ALERT": ("IDS_ALERT_SIGNAL", 0.80),

    "SENSITIVE_FILE_ACCESS": (
        "SENSITIVE_FILE_ACCESS_SIGNAL",
        0.90,
    ),
}

def detect_signals(event):
    signals = []

    event_type = str(event.get("event_type", "")).upper()

    if event_type in SIGNAL_RULES:
        signal_type, strength = SIGNAL_RULES[event_type]

        signals.append({
            "signal_id": generate_id("SIG"),
            "signal_type": signal_type,
            "signal_strength": strength,
            "event_id": event["event_id"],
        })

    severity = str(event.get("severity", "")).upper()

    if severity == "HIGH":
        signals.append({
            "signal_id": generate_id("SIG"),
            "signal_type": "HIGH_SEVERITY_SIGNAL",
            "signal_strength": 0.60,
            "event_id": event["event_id"],
        })

    elif severity == "CRITICAL":
        signals.append({
            "signal_id": generate_id("SIG"),
            "signal_type": "HIGH_SEVERITY_SIGNAL",
            "signal_strength": 0.90,
            "event_id": event["event_id"],
        })

    return signals


def get_recent_events(event):
    connection = get_connection()
    cursor = connection.cursor()

    current_time = parse_timestamp(event["timestamp"])

    lower_time = current_time - timedelta(
        seconds=CORRELATION_WINDOW_SECONDS
    )

    upper_time = current_time + timedelta(
        seconds=CORRELATION_WINDOW_SECONDS
    )

    cursor.execute("""
        SELECT *
        FROM events
        WHERE timestamp >= ?
          AND timestamp <= ?
        ORDER BY timestamp ASC
    """, (
        lower_time.isoformat(),
        upper_time.isoformat(),
    ))

    rows = cursor.fetchall()

    connection.close()

    recent_events = []

    for row in rows:
        item = dict(row)

        same_source_ip = (
            event.get("source_ip")
            and item.get("source_ip")
            and event["source_ip"] == item["source_ip"]
        )

        same_destination_ip = (
            event.get("destination_ip")
            and item.get("destination_ip")
            and event["destination_ip"] == item["destination_ip"]
        )

        same_username = (
            event.get("username")
            and item.get("username")
            and event["username"] == item["username"]
        )

        if (
            same_source_ip
            or same_destination_ip
            or same_username
        ):
            recent_events.append(item)

    return recent_events

def fuse_signals(events_with_signals):

    all_signals = []

    source_types = set()

    for item in events_with_signals:
        event = item["event"]

        source_type = event.get("source_type")

        if source_type:
            source_types.add(source_type)

        for signal in item["signals"]:
            all_signals.append(signal)

    signal_types = sorted(
        set(
            signal["signal_type"]
            for signal in all_signals
        )
    )

    source_types = sorted(source_types)

    signal_count = len(all_signals)
    event_count = len(events_with_signals)

    if all_signals:
        strengths = [
            signal["signal_strength"]
            for signal in all_signals
        ]

        mean_signal_strength = (
            sum(strengths) / len(strengths)
        )

        max_signal_strength = max(strengths)

    else:
        mean_signal_strength = 0.0
        max_signal_strength = 0.0

    cross_source_evidence = len(source_types) >= 2

    multi_event_evidence = event_count >= 2

    high_severity_context = (
        "HIGH_SEVERITY_SIGNAL" in signal_types
    )

    patterns = []



    if (
        "AUTH_FAILURE_SIGNAL" in signal_types
        or "BRUTE_FORCE_SIGNAL" in signal_types
    ):
        patterns.append("CREDENTIAL_ATTACK")


    if (
        "PORT_SCAN_SIGNAL" in signal_types
        or "SCAN_EVENT_SIGNAL" in signal_types
    ):
        patterns.append("RECON_SCANNING")



    network_signals = {
        "CONNECTION_FAILURE_SIGNAL",
        "CONNECTION_ATTEMPT_SIGNAL",
        "FIREWALL_DENY_SIGNAL",
        "IDS_ALERT_SIGNAL",
    }

    if network_signals.intersection(signal_types):
        patterns.append("NETWORK_ACCESS_ANOMALY")

    if "TRAFFIC_SPIKE_SIGNAL" in signal_types:
        patterns.append("TRAFFIC_ANOMALY")


    if (
        "SENSITIVE_FILE_ACCESS_SIGNAL" in signal_types
        or "LARGE_TRANSFER_SIGNAL" in signal_types
    ):
        patterns.append("DATA_ACCESS_MOVEMENT")


    credential_present = (
        "AUTH_FAILURE_SIGNAL" in signal_types
        or "BRUTE_FORCE_SIGNAL" in signal_types
    )

    data_access_present = (
        "SENSITIVE_FILE_ACCESS_SIGNAL" in signal_types
        or "LARGE_TRANSFER_SIGNAL" in signal_types
    )

    if credential_present and data_access_present:
        patterns.append("CREDENTIAL_TO_ACCESS_CHAIN")


    if not patterns:
        if signal_count == 1:
            patterns.append("SINGLE_SIGNAL")
        else:
            patterns.append("NO_DEFINED_PATTERN")



    if len(patterns) > 1:
        incident_type = "MULTI_PATTERN_SECURITY_ACTIVITY"
    else:
        incident_type = patterns[0]


    fusion_strength = mean_signal_strength

    if cross_source_evidence:
        fusion_strength += 0.10

    if multi_event_evidence:
        fusion_strength += 0.10

    fusion_strength = min(
        round(fusion_strength, 4),
        1.0,
    )

    return {
        "incident_type": incident_type,
        "patterns": patterns,
        "signal_types": signal_types,
        "source_types": source_types,
        "signal_count": signal_count,
        "event_count": event_count,
        "fusion_strength": fusion_strength,
        "mean_signal_strength": round(
            mean_signal_strength,
            4,
        ),
        "max_signal_strength": round(
            max_signal_strength,
            4,
        ),
        "cross_source_evidence": cross_source_evidence,
        "multi_event_evidence": multi_event_evidence,
        "high_severity_context": high_severity_context,
    }


# ============================================================
# STAGE 5 — INCIDENT CREATION / UPDATE
# ============================================================

def find_existing_incident(events_with_signals):

    if not events_with_signals:
        return None

    current_event = events_with_signals[-1]["event"]

    source_ip = current_event.get("source_ip")
    destination_ip = current_event.get("destination_ip")

    current_time = parse_timestamp(
        current_event["timestamp"]
    )

    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute("""
        SELECT *
        FROM incidents
        ORDER BY incident_end DESC
    """)

    rows = cursor.fetchall()

    connection.close()

    best_match = None

    for row in rows:

        incident = dict(row)

        if not incident.get("incident_end"):
            continue

        incident_end = parse_timestamp(
            incident["incident_end"]
        )

        time_difference = abs(
            (current_time - incident_end).total_seconds()
        )

        if time_difference > CORRELATION_WINDOW_SECONDS:
            continue

        same_source = (
            source_ip
            and incident.get("source_ip")
            and source_ip == incident["source_ip"]
        )

        same_destination = (
            destination_ip
            and incident.get("destination_ip")
            and destination_ip == incident["destination_ip"]
        )

        if same_source or same_destination:

            if best_match is None:
                best_match = incident
            else:
                best_end = parse_timestamp(
                    best_match["incident_end"]
                )

                if incident_end > best_end:
                    best_match = incident

    return best_match


def create_incident(
    correlation_id,
    events_with_signals,
    fusion,
    existing_incident=None,
):

    events = [
        item["event"]
        for item in events_with_signals
    ]

    timestamps = [
        parse_timestamp(event["timestamp"])
        for event in events
    ]

    incident_start = min(timestamps).isoformat()
    incident_end = max(timestamps).isoformat()

    source_ips = [
        event.get("source_ip")
        for event in events
        if event.get("source_ip")
    ]

    destination_ips = [
        event.get("destination_ip")
        for event in events
        if event.get("destination_ip")
    ]

    source_ip = (
        source_ips[0]
        if source_ips
        else None
    )

    destination_ip = (
        destination_ips[0]
        if destination_ips
        else None
    )

    if existing_incident:
        incident_id = existing_incident["incident_id"]
    else:
        incident_id = generate_id("INC")

    patterns_text = ", ".join(
        fusion["patterns"]
    )

    signal_types_text = ", ".join(
        fusion["signal_types"]
    )

    source_types_text = ", ".join(
        fusion["source_types"]
    )

    if fusion["incident_type"] == "CREDENTIAL_ATTACK":
        title = (
            f"Credential Attack from {source_ip}"
        )

    elif fusion["incident_type"] == "RECON_SCANNING":
        title = (
            f"Reconnaissance Activity from {source_ip}"
        )

    elif fusion["incident_type"] == "DATA_ACCESS_MOVEMENT":
        title = (
            f"Data Access Activity from {source_ip}"
        )

    elif fusion["incident_type"] == "CREDENTIAL_TO_ACCESS_CHAIN":
        title = (
            f"Credential-to-Access Chain from {source_ip}"
        )

    elif fusion["incident_type"] == "MULTI_PATTERN_SECURITY_ACTIVITY":
        title = (
            f"Multi Pattern Security Activity from {source_ip}"
        )

    else:
        title = (
            f"{fusion['incident_type']} from {source_ip}"
        )

    return {
        "incident_id": incident_id,
        "correlation_id": correlation_id,
        "incident_type": fusion["incident_type"],
        "incident_patterns": patterns_text,
        "incident_title": title,
        "incident_start": incident_start,
        "incident_end": incident_end,
        "source_ip": source_ip,
        "destination_ip": destination_ip,
        "signal_types": signal_types_text,
        "source_types": source_types_text,
        "signal_count": fusion["signal_count"],
        "unique_event_count": fusion["event_count"],
        "fusion_strength": fusion["fusion_strength"],
        "cross_source_evidence": fusion[
            "cross_source_evidence"
        ],
        "multi_event_evidence": fusion[
            "multi_event_evidence"
        ],
        "high_severity_context": fusion[
            "high_severity_context"
        ],
        "incident_summary": (
            f"{fusion['event_count']} correlated event(s) "
            f"produced {fusion['signal_count']} security "
            f"signal(s). Detected pattern: "
            f"{patterns_text}."
        ),
    }


# ============================================================
# STAGE 6 — RISK ASSESSMENT
# ============================================================

def calculate_risk(incident, fusion):

    fusion_strength_points = (
        fusion["fusion_strength"] * 25
    )

    signal_count = fusion["signal_count"]

    if signal_count <= 1:
        signal_diversity_points = 3
    elif signal_count == 2:
        signal_diversity_points = 6
    elif signal_count == 3:
        signal_diversity_points = 9
    elif signal_count == 4:
        signal_diversity_points = 12
    else:
        signal_diversity_points = 15

    source_count = len(
        fusion["source_types"]
    )

    if source_count <= 1:
        source_diversity_points = 3
    elif source_count == 2:
        source_diversity_points = 7
    elif source_count == 3:
        source_diversity_points = 10
    elif source_count == 4:
        source_diversity_points = 13
    else:
        source_diversity_points = 15

    multi_event_points = (
        10
        if fusion["multi_event_evidence"]
        else 0
    )

    cross_source_points = (
        10
        if fusion["cross_source_evidence"]
        else 0
    )

    pattern_points_map = {
        "CREDENTIAL_TO_ACCESS_CHAIN": 15,
        "DATA_ACCESS_MOVEMENT": 14,
        "CREDENTIAL_ATTACK": 12,
        "RECON_SCANNING": 8,
        "NETWORK_ACCESS_ANOMALY": 8,
        "TRAFFIC_ANOMALY": 8,
        "MULTI_PATTERN_SECURITY_ACTIVITY": 13,
        "SINGLE_SIGNAL": 3,
        "NO_DEFINED_PATTERN": 3,
    }

    pattern_points = 0

    for pattern in fusion["patterns"]:
        pattern_points = max(
            pattern_points,
            pattern_points_map.get(
                pattern,
                0,
            ),
        )

    high_severity_points = (
        10
        if fusion["high_severity_context"]
        else 0
    )

    risk_score = (
        fusion_strength_points
        + signal_diversity_points
        + source_diversity_points
        + multi_event_points
        + cross_source_points
        + pattern_points
        + high_severity_points
    )

    risk_score = min(
        round(risk_score, 2),
        100.0,
    )

    if risk_score >= 75:
        severity = "CRITICAL"
    elif risk_score >= 50:
        severity = "HIGH"
    elif risk_score >= 25:
        severity = "MEDIUM"
    else:
        severity = "LOW"

    risk_factors = []

    if fusion["multi_event_evidence"]:
        risk_factors.append(
            "multiple correlated events"
        )

    if fusion["cross_source_evidence"]:
        risk_factors.append(
            "cross-source evidence"
        )

    if fusion["high_severity_context"]:
        risk_factors.append(
            "high-severity context"
        )

    risk_factors.append(
        "pattern: " + ", ".join(fusion["patterns"])
    )

    return {
        "risk_score": risk_score,
        "severity": severity,
        "fusion_strength_points": round(
            fusion_strength_points,
            2,
        ),
        "signal_diversity_points":
            signal_diversity_points,
        "source_diversity_points":
            source_diversity_points,
        "multi_event_points":
            multi_event_points,
        "cross_source_points":
            cross_source_points,
        "incident_pattern_points":
            pattern_points,
        "high_severity_points":
            high_severity_points,
        "risk_factors":
            "; ".join(risk_factors),
    }


# ============================================================
# STAGE 7 — ANALYST PRIORITY
# ============================================================

def calculate_priority(incident, risk):

    risk_component = (
        risk["risk_score"] * 0.70
    )

    # No asset criticality is currently stored
    # directly inside the simplified incident.
    asset_criticality_points = 0

    now = datetime.now(timezone.utc)

    incident_end = parse_timestamp(
        incident["incident_end"]
    )

    age_seconds = (
        now - incident_end
    ).total_seconds()

    if age_seconds <= 300:
        recency_points = 10
    elif age_seconds <= 900:
        recency_points = 7
    elif age_seconds <= 3600:
        recency_points = 4
    else:
        recency_points = 1

    additional_context_points = 0

    priority_score = (
        risk_component
        + asset_criticality_points
        + recency_points
        + additional_context_points
    )

    priority_score = min(
        round(priority_score, 2),
        100.0,
    )

    if (
        priority_score >= 75
        or (
            risk["severity"] == "CRITICAL"
            and risk["risk_score"] >= 75
        )
    ):
        priority_level = "P1"
        recommended_action = (
            "IMMEDIATE_INVESTIGATION"
        )

    elif priority_score >= 50:
        priority_level = "P2"
        recommended_action = (
            "INVESTIGATE_NEXT"
        )

    elif priority_score >= 25:
        priority_level = "P3"
        recommended_action = (
            "NORMAL_INVESTIGATION"
        )

    else:
        priority_level = "P4"
        recommended_action = (
            "MONITOR_AND_DEFER"
        )

    return {
        "priority_score": priority_score,
        "priority_level": priority_level,
        "risk_component": round(
            risk_component,
            2,
        ),
        "asset_criticality_points":
            asset_criticality_points,
        "recency_points":
            recency_points,
        "additional_context_points":
            additional_context_points,
        "recommended_action":
            recommended_action,
        "priority_reason": (
            f"Risk contribution="
            f"{risk_component:.2f}; "
            f"recency={recency_points}; "
            f"asset criticality="
            f"{asset_criticality_points}."
        ),
    }


# ============================================================
# QUEUE RANKING
# ============================================================

def update_queue_ranks():

    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute("""
        SELECT *
        FROM incidents
        ORDER BY
            CASE priority_level
                WHEN 'P1' THEN 1
                WHEN 'P2' THEN 2
                WHEN 'P3' THEN 3
                WHEN 'P4' THEN 4
                ELSE 5
            END ASC,
            priority_score DESC,
            incident_end DESC
    """)

    rows = cursor.fetchall()

    for index, row in enumerate(rows, start=1):

        incident_id = row["incident_id"]

        cursor.execute("""
            UPDATE incidents
            SET queue_rank = ?
            WHERE incident_id = ?
        """, (
            index,
            incident_id,
        ))

    connection.commit()
    connection.close()


# ============================================================
# STAGE 8 — CRYPTOGRAPHIC TRUST
# ============================================================

def canonicalize_incident(
    incident,
    risk,
    priority,
):

    canonical_data = {
        "correlation_id":
            incident["correlation_id"],

        "cross_source_evidence":
            incident["cross_source_evidence"],

        "destination_ip":
            incident["destination_ip"],

        "fusion_strength":
            incident["fusion_strength"],

        "high_severity_context":
            incident["high_severity_context"],

        "incident_end":
            incident["incident_end"],

        "incident_id":
            incident["incident_id"],

        "incident_patterns":
            incident["incident_patterns"],

        "incident_start":
            incident["incident_start"],

        "incident_title":
            incident["incident_title"],

        "incident_type":
            incident["incident_type"],

        "multi_event_evidence":
            incident["multi_event_evidence"],

        "priority_level":
            priority["priority_level"],

        "priority_score":
            priority["priority_score"],

        "recommended_action":
            priority["recommended_action"],

        "risk_score":
            risk["risk_score"],

        "severity":
            risk["severity"],

        "signal_count":
            incident["signal_count"],

        "signal_types":
            incident["signal_types"],

        "source_ip":
            incident["source_ip"],

        "source_types":
            incident["source_types"],

        "unique_event_count":
            incident["unique_event_count"],
    }

    return json.dumps(
        canonical_data,
        sort_keys=True,
        separators=(",", ":"),
    )


def generate_hash(canonical_evidence):

    return hashlib.sha256(
        canonical_evidence.encode("utf-8")
    ).hexdigest()


def verify_incident_integrity(incident_id):
    incident = get_incident(incident_id)

    if not incident:
        return {
            "incident_id": incident_id,
            "integrity_status": "INCIDENT_NOT_FOUND",
        }

    stored_canonical = incident["canonical_evidence"]
    stored_hash = incident["evidence_hash"]

    calculated_hash = generate_hash(stored_canonical)

    if calculated_hash == stored_hash:
        integrity_status = "INTEGRITY_VERIFIED"
    else:
        integrity_status = "TAMPERING_DETECTED"

    return {
        "incident_id": incident_id,
        "stored_hash": stored_hash,
        "calculated_hash": calculated_hash,
        "integrity_status": integrity_status,
    }


def process_event(event):

    event = dict(event)

    if not event.get("event_id"):
        event["event_id"] = generate_id("EVT")

    event["timestamp"] = normalize_timestamp(
        event["timestamp"]
    )


    current_signals = detect_signals(event)



    save_event(event)



    recent_events = get_recent_events(event)

    events_with_signals = []

    for previous_event in recent_events:

        previous_signals = detect_signals(
            previous_event
        )

        events_with_signals.append({
            "event": previous_event,
            "signals": previous_signals,
        })

    # Make sure current event is included
    current_event_already_present = any(
        item["event"]["event_id"]
        == event["event_id"]
        for item in events_with_signals
    )

    if not current_event_already_present:
        events_with_signals.append({
            "event": event,
            "signals": current_signals,
        })

    # Remove duplicate events
    unique_events = {}

    for item in events_with_signals:
        unique_events[
            item["event"]["event_id"]
        ] = item

    events_with_signals = list(
        unique_events.values()
    )

    # Sort chronologically
    events_with_signals.sort(
        key=lambda item: parse_timestamp(
            item["event"]["timestamp"]
        )
    )


    fusion = fuse_signals(
        events_with_signals
    )


    existing_incident = find_existing_incident(
        events_with_signals
    )

    if existing_incident:
        correlation_id = existing_incident[
            "correlation_id"
        ]
    else:
        correlation_id = generate_id("COR")

    incident = create_incident(
        correlation_id=correlation_id,
        events_with_signals=events_with_signals,
        fusion=fusion,
        existing_incident=existing_incident,
    )



    risk = calculate_risk(
        incident,
        fusion,
    )

    incident["risk_score"] = risk[
        "risk_score"
    ]

    incident["severity"] = risk[
        "severity"
    ]



    priority = calculate_priority(
        incident,
        risk,
    )

    incident["priority_score"] = priority[
        "priority_score"
    ]

    incident["priority_level"] = priority[
        "priority_level"
    ]

    incident["recommended_action"] = priority[
        "recommended_action"
    ]

    incident["queue_rank"] = 0


    canonical_evidence = canonicalize_incident(
        incident,
        risk,
        priority,
    )

    evidence_hash = generate_hash(
        canonical_evidence
    )

    incident["canonical_evidence"] = (
        canonical_evidence
    )

    incident["evidence_hash"] = evidence_hash

    incident["integrity_status"] = "INITIALIZED"

    # --------------------------------------------------------
    # Save / update incident
    # --------------------------------------------------------

    save_incident(incident)

    # --------------------------------------------------------
    # Recalculate analyst queue
    # --------------------------------------------------------

    update_queue_ranks()

    # --------------------------------------------------------
    # Retrieve final queue rank
    # --------------------------------------------------------

    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute("""
        SELECT queue_rank
        FROM incidents
        WHERE incident_id = ?
    """, (
        incident["incident_id"],
    ))

    row = cursor.fetchone()

    connection.close()

    if row:
        incident["queue_rank"] = row[
            "queue_rank"
        ]

    # --------------------------------------------------------
    # Return complete result
    # --------------------------------------------------------

    return {
        "event": event,
        "signals": current_signals,
        "correlation_id": correlation_id,
        "fusion": fusion,
        "incident": incident,
        "risk": risk,
        "priority": priority,
        "trust": {
            "hash_algorithm": "SHA-256",
            "evidence_hash": evidence_hash,
            "integrity_status":
                "INITIALIZED",
        },
    }