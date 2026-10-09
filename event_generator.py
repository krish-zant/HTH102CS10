import requests
import time
from datetime import datetime, timezone


API_URL = "http://127.0.0.1:8001/api/events"


def send_event(
    source_type,
    source_ip,
    destination_ip,
    username,
    event_type,
    severity,
    asset_criticality,
    message,
):
    event = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "source_type": source_type,
        "source_ip": source_ip,
        "destination_ip": destination_ip,
        "username": username,
        "event_type": event_type,
        "severity": severity,
        "asset_criticality": asset_criticality,
        "message": message,
    }

    try:
        response = requests.post(
            API_URL,
            json=event,
            timeout=5,
        )

        print("\n----------------------------------------")
        print("EVENT SENT")
        print("----------------------------------------")
        print(f"Source      : {source_ip}")
        print(f"Source Type : {source_type}")
        print(f"Event Type  : {event_type}")
        print(f"Severity    : {severity}")
        print(f"Status      : {response.status_code}")

        try:
            result = response.json()

            print(f"Incident ID : {result.get('incident_id')}")
            print(f"Risk Score  : {result.get('risk_score')}")
            print(f"Priority    : {result.get('priority_level')}")
            print(f"Signals     : {result.get('signal_ids')}")

        except Exception:
            print(response.text)

    except requests.exceptions.RequestException as error:
        print(f"ERROR: {error}")


def main():

    source_ip = "192.168.1.99"
    destination_ip = "10.0.0.99"
    username = "admin"

    print("=" * 60)
    print("MAXIMUM-PRIORITY SIMULATED INCIDENT")
    print("=" * 60)
    print("This is a controlled SOC dashboard simulation.")
    print(f"Source IP      : {source_ip}")
    print(f"Destination IP : {destination_ip}")
    print(f"Username       : {username}")
    print("=" * 60)

    events = [

        # 1. Authentication failure
        (
            "AUTH",
            "FAILED_LOGIN",
            "HIGH",
            "Authentication failure detected for administrative account",
        ),

        # 2. Brute force
        (
            "IDS",
            "BRUTE_FORCE",
            "CRITICAL",
            "Repeated authentication attempts detected",
        ),

        # 3. IDS confirmation
        (
            "IDS",
            "IDS_ALERT",
            "CRITICAL",
            "IDS confirmed suspicious authentication activity",
        ),

        # 4. Network connection
        (
            "NETWORK",
            "CONNECTION_ATTEMPT",
            "HIGH",
            "Suspicious connection attempt toward protected asset",
        ),

        # 5. Reconnaissance
        (
            "NETWORK",
            "PORT_SCAN",
            "HIGH",
            "Multiple destination ports probed",
        ),

        # 6. Firewall confirmation
        (
            "FIREWALL",
            "FIREWALL_DENY",
            "CRITICAL",
            "Firewall blocked suspicious connection",
        ),

        # 7. Traffic anomaly
        (
            "NETWORK",
            "TRAFFIC_SPIKE",
            "HIGH",
            "Abnormal traffic increase detected",
        ),

        # 8. Possible data movement
        (
            "NETWORK",
            "LARGE_TRANSFER",
            "CRITICAL",
            "Large outbound transfer detected",
        ),

        # 9. Sensitive resource access
        (
            "SERVER",
            "SENSITIVE_FILE_ACCESS",
            "CRITICAL",
            "Sensitive resource accessed following suspicious activity",
        ),
    ]

    for index, (
        source_type,
        event_type,
        severity,
        message,
    ) in enumerate(events, start=1):

        print(f"\n[{index}/{len(events)}] Sending {event_type}...")

        send_event(
            source_type=source_type,
            source_ip=source_ip,
            destination_ip=destination_ip,
            username=username,
            event_type=event_type,
            severity=severity,
            asset_criticality="CRITICAL",
            message=message,
        )

        time.sleep(3)

    print("\n" + "=" * 60)
    print("SIMULATION COMPLETE")
    print("=" * 60)
    print("Watch the Analyst Priority Queue.")
    print("The new incident should appear after the pipeline processes it.")


if __name__ == "__main__":
    main()