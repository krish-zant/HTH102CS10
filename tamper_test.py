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
    original = row["canonical_evidence"]

    tampered = original.replace(
        "CREDENTIAL_ATTACK",
        "TAMPERED_DATA"
    )

    cursor.execute(
        """
        UPDATE incidents
        SET canonical_evidence = ?
        WHERE incident_id = ?
        """,
        (tampered, "INC-D3C07FE5DD")
    )

    connection.commit()
    print("EVIDENCE TAMPERED")

connection.close()