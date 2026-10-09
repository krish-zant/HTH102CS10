from backend.database import get_connection

connection = get_connection()

cursor = connection.cursor()

cursor.execute(
    "SELECT canonical_evidence FROM incidents WHERE incident_id = ?",
    ("INC-D3C07FE5DD",)
)

row = cursor.fetchone()

if not row:
    print("INCIDENT NOT FOUND")
else:
    current = row["canonical_evidence"]

    restored = current.replace(
        "TAMPERED_DATA",
        "CREDENTIAL_ATTACK"
    )

    cursor.execute(
        """
        UPDATE incidents
        SET canonical_evidence = ?
        WHERE incident_id = ?
        """,
        (restored, "INC-D3C07FE5DD")
    )

    connection.commit()
    print("EVIDENCE RESTORED")

connection.close()