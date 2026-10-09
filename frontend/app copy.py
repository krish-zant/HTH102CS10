import streamlit as st
import requests
import pandas as pd


# ============================================================
# CONFIGURATION
# ============================================================

API_URL = "http://127.0.0.1:8001"

st.set_page_config(
    page_title="Signal-Fused SOC",
    page_icon="🛡️",
    layout="wide"
)


# ============================================================
# API FUNCTIONS
# ============================================================

def get_summary():

    response = requests.get(
        f"{API_URL}/api/dashboard/summary",
        timeout=10
    )

    response.raise_for_status()

    return response.json()


def get_incidents():

    response = requests.get(
        f"{API_URL}/api/incidents",
        timeout=10
    )

    response.raise_for_status()

    data = response.json()

    # Current FastAPI endpoint returns the incident list directly
    if isinstance(data, list):
        return data

    # Also support {"incidents": [...]} format
    if isinstance(data, dict):
        return data.get("incidents", [])

    return []


def get_incident(incident_id):

    response = requests.get(
        f"{API_URL}/api/incidents/{incident_id}",
        timeout=10
    )

    response.raise_for_status()

    return response.json()


def verify_integrity(incident_id):

    response = requests.get(
        f"{API_URL}/api/trust/{incident_id}/verify",
        timeout=10
    )

    response.raise_for_status()

    return response.json()


# ============================================================
# HEADER
# ============================================================

st.title("🛡️ Signal-Fused SOC Dashboard")

st.caption(
    "Multi-source intrusion detection • "
    "Signal correlation • "
    "Risk assessment • "
    "Analyst prioritization • "
    "Cryptographic trust"
)


# ============================================================
# LOAD API DATA
# ============================================================

try:

    summary = get_summary()

except Exception as error:

    st.error("FastAPI request failed.")

    st.code(
        f"{type(error).__name__}: {error}"
    )

    st.info(
        "Make sure FastAPI is running:\n\n"
        "uvicorn backend.main:app --reload"
    )

    st.stop()


# ============================================================
# LOAD INCIDENTS
# ============================================================

try:

    incidents = get_incidents()

except Exception as error:

    st.error("Unable to load incidents.")

    st.code(
        f"{type(error).__name__}: {error}"
    )

    st.stop()


# ============================================================
# CONNECTION STATUS
# ============================================================

c1, c2, c3 = st.columns(3)

with c1:

    st.success("🟢 FastAPI Connected")

with c2:

    st.info(
        f"📊 {summary.get('total_incidents', 0)} incidents"
    )

with c3:

    st.success(
        f"🔐 {summary.get('integrity_records', 0)} integrity records"
    )


st.divider()


# ============================================================
# SECURITY OVERVIEW
# ============================================================

st.subheader("Security Overview")

c1, c2, c3, c4, c5 = st.columns(5)

with c1:

    st.metric(
        "Total Incidents",
        summary.get("total_incidents", 0)
    )

with c2:

    st.metric(
        "Critical",
        summary.get("critical", 0)
    )

with c3:

    st.metric(
        "High",
        summary.get("high", 0)
    )

with c4:

    st.metric(
        "Medium",
        summary.get("medium", 0)
    )

with c5:

    st.metric(
        "Low",
        summary.get("low", 0)
    )


# ============================================================
# PRIORITY
# ============================================================

st.subheader("Analyst Priority")

p1, p2, p3, p4 = st.columns(4)

with p1:

    st.metric(
        "P1 — Immediate",
        summary.get("p1", 0)
    )

with p2:

    st.metric(
        "P2 — Investigate",
        summary.get("p2", 0)
    )

with p3:

    st.metric(
        "P3 — Normal",
        summary.get("p3", 0)
    )

with p4:

    st.metric(
        "P4 — Monitor",
        summary.get("p4", 0)
    )


st.divider()


# ============================================================
# INCIDENT QUEUE
# ============================================================

st.subheader("🚨 Analyst Incident Queue")


if not incidents:

    st.info("No incidents found.")

    st.stop()


df = pd.DataFrame(incidents)


# ============================================================
# FILTER OPTIONS
# ============================================================

filter1, filter2, filter3, filter4 = st.columns(4)


# ------------------------------------------------------------
# Severity
# ------------------------------------------------------------

with filter1:

    severity_options = [
        "ALL",
        "CRITICAL",
        "HIGH",
        "MEDIUM",
        "LOW"
    ]

    selected_severity = st.selectbox(
        "Severity",
        severity_options
    )


# ------------------------------------------------------------
# Priority
# ------------------------------------------------------------

with filter2:

    priority_options = [
        "ALL",
        "P1",
        "P2",
        "P3",
        "P4"
    ]

    selected_priority = st.selectbox(
        "Priority",
        priority_options
    )


# ------------------------------------------------------------
# Pattern
# ------------------------------------------------------------

with filter3:

    pattern_values = set()

    if "incident_patterns" in df.columns:

        for value in df["incident_patterns"].fillna(""):

            for pattern in str(value).split(","):

                pattern = pattern.strip()

                if pattern:
                    pattern_values.add(pattern)

    pattern_options = [
        "ALL"
    ] + sorted(pattern_values)

    selected_pattern = st.selectbox(
        "Attack Pattern",
        pattern_options
    )


# ------------------------------------------------------------
# Source
# ------------------------------------------------------------

with filter4:

    source_values = set()

    if "source_types" in df.columns:

        for value in df["source_types"].fillna(""):

            for source in str(value).split(","):

                source = source.strip()

                if source:
                    source_values.add(source)

    source_options = [
        "ALL"
    ] + sorted(source_values)

    selected_source = st.selectbox(
        "Source Type",
        source_options
    )


# ============================================================
# APPLY FILTERS
# ============================================================

filtered_df = df.copy()


if selected_severity != "ALL":

    if "severity" in filtered_df.columns:

        filtered_df = filtered_df[
            filtered_df["severity"] == selected_severity
        ]


if selected_priority != "ALL":

    if "priority_level" in filtered_df.columns:

        filtered_df = filtered_df[
            filtered_df["priority_level"] == selected_priority
        ]


if selected_pattern != "ALL":

    if "incident_patterns" in filtered_df.columns:

        filtered_df = filtered_df[
            filtered_df["incident_patterns"]
            .fillna("")
            .str.contains(
                selected_pattern,
                regex=False
            )
        ]


if selected_source != "ALL":

    if "source_types" in filtered_df.columns:

        filtered_df = filtered_df[
            filtered_df["source_types"]
            .fillna("")
            .str.contains(
                selected_source,
                regex=False
            )
        ]


# ============================================================
# INCIDENT TABLE
# ============================================================

st.write(
    f"Showing **{len(filtered_df)}** incident(s)"
)


if len(filtered_df) > 0:

    display_columns = [
        "queue_rank",
        "incident_id",
        "incident_title",
        "severity",
        "risk_score",
        "priority_score",
        "priority_level",
        "signal_count",
        "unique_event_count",
        "source_types",
        "integrity_status"
    ]

    available_columns = [
        column
        for column in display_columns
        if column in filtered_df.columns
    ]

    table_df = filtered_df[
        available_columns
    ].copy()

    st.dataframe(
        table_df,
        use_container_width=True,
        hide_index=True
    )

else:

    st.info(
        "No incidents match the selected filters."
    )


st.divider()


# ============================================================
# INCIDENT INVESTIGATION
# ============================================================

st.subheader("🔎 Incident Investigation")


if len(filtered_df) == 0:

    st.info(
        "No incident is available for investigation."
    )

else:

    incident_ids = filtered_df[
        "incident_id"
    ].tolist()


    selected_incident = st.selectbox(
        "Select an incident",
        incident_ids
    )


    try:

        incident = get_incident(
            selected_incident
        )


        # ====================================================
        # INCIDENT SUMMARY
        # ====================================================

        st.markdown(
            "### Incident Summary"
        )

        a1, a2, a3, a4 = st.columns(4)


        with a1:

            st.metric(
                "Risk Score",
                incident.get("risk_score", "-")
            )


        with a2:

            st.metric(
                "Severity",
                incident.get("severity", "-")
            )


        with a3:

            st.metric(
                "Priority",
                incident.get("priority_level", "-")
            )


        with a4:

            st.metric(
                "Priority Score",
                incident.get("priority_score", "-")
            )


        # ====================================================
        # INCIDENT DETAILS
        # ====================================================

        d1, d2 = st.columns(2)


        with d1:

            st.markdown(
                "#### Identification"
            )

            st.write(
                f"**Incident ID:** "
                f"`{incident.get('incident_id', '-')}`"
            )

            st.write(
                f"**Correlation ID:** "
                f"`{incident.get('correlation_id', '-')}`"
            )

            st.write(
                f"**Incident Type:** "
                f"{incident.get('incident_type', '-')}"
            )

            st.write(
                f"**Title:** "
                f"{incident.get('incident_title', '-')}"
            )

            st.write(
                f"**Recommended Action:** "
                f"{incident.get('recommended_action', '-')}"
            )


        with d2:

            st.markdown(
                "#### Timeline / Entities"
            )

            st.write(
                f"**Start:** "
                f"{incident.get('incident_start', '-')}"
            )

            st.write(
                f"**End:** "
                f"{incident.get('incident_end', '-')}"
            )

            st.write(
                f"**Source IP:** "
                f"`{incident.get('source_ip', '-')}`"
            )

            st.write(
                f"**Destination IP:** "
                f"`{incident.get('destination_ip', '-')}`"
            )


        # ====================================================
        # SIGNAL FUSION
        # ====================================================

        st.markdown(
            "### 🔗 Correlation & Signal Fusion"
        )

        f1, f2, f3 = st.columns(3)


        with f1:

            st.metric(
                "Signals",
                incident.get("signal_count", 0)
            )


        with f2:

            st.metric(
                "Unique Events",
                incident.get("unique_event_count", 0)
            )


        with f3:

            st.metric(
                "Fusion Strength",
                incident.get("fusion_strength", 0)
            )


        st.write(
            f"**Signal Types:** "
            f"{incident.get('signal_types', '-')}"
        )

        st.write(
            f"**Source Types:** "
            f"{incident.get('source_types', '-')}"
        )

        st.write(
            f"**Detected Patterns:** "
            f"{incident.get('incident_patterns', '-')}"
        )


        # ====================================================
        # EVIDENCE
        # ====================================================

        st.markdown(
            "### 🧩 Evidence Chain"
        )

        st.code(
            incident.get(
                "canonical_evidence",
                ""
            ),
            language="text"
        )


        # ====================================================
        # CRYPTOGRAPHIC TRUST
        # ====================================================

        st.markdown(
            "### 🔐 Cryptographic Trust Layer"
        )

        t1, t2 = st.columns(2)


        with t1:

            st.write(
                "**Stored SHA-256 Hash**"
            )

            st.code(
                incident.get(
                    "evidence_hash",
                    "-"
                )
            )


        with t2:

            st.write(
                "**Integrity Status**"
            )

            integrity_status = incident.get(
                "integrity_status",
                "UNKNOWN"
            )


            if integrity_status == "INTEGRITY_VERIFIED":

                st.success(
                    "✓ INTEGRITY VERIFIED"
                )

            elif integrity_status == "TAMPERING_DETECTED":

                st.error(
                    "⚠ TAMPERING DETECTED"
                )

            else:

                st.warning(
                    integrity_status
                )


        # ====================================================
        # VERIFY BUTTON
        # ====================================================

        st.markdown(
            "#### Verify Evidence"
        )


        if st.button(
            "🔍 Verify SHA-256 Integrity",
            key=f"verify_{selected_incident}"
        ):

            try:

                verification = verify_integrity(
                    selected_incident
                )


                if (
                    verification.get(
                        "integrity_status"
                    )
                    == "INTEGRITY_VERIFIED"
                ):

                    st.success(
                        "✓ Evidence integrity verified."
                    )

                else:

                    st.error(
                        "⚠ Evidence tampering detected."
                    )


                st.write(
                    "**Stored Hash:**"
                )

                st.code(
                    verification.get(
                        "stored_hash",
                        "-"
                    )
                )


                st.write(
                    "**Calculated Hash:**"
                )

                st.code(
                    verification.get(
                        "calculated_hash",
                        "-"
                    )
                )


            except Exception as error:

                st.error(
                    "Verification request failed."
                )

                st.code(
                    f"{type(error).__name__}: {error}"
                )


    except Exception as error:

        st.error(
            "Unable to load incident details."
        )

        st.code(
            f"{type(error).__name__}: {error}"
        )


st.divider()


# ============================================================
# PIPELINE
# ============================================================

st.subheader(
    "⚙️ Detection Pipeline"
)


pipeline_steps = [
    ("1", "Raw Events"),
    ("2", "Signal Detection"),
    ("3", "Correlation"),
    ("4", "Signal Fusion"),
    ("5", "Composite Incident"),
    ("6", "Risk Assessment"),
    ("7", "Analyst Priority"),
    ("8", "SHA-256 Trust")
]


pipeline_cols = st.columns(
    len(pipeline_steps)
)


for column, (number, label) in zip(
    pipeline_cols,
    pipeline_steps
):

    with column:

        st.markdown(
            f"""
            <div style="
                text-align:center;
                padding:12px 5px;
                border:1px solid #444;
                border-radius:10px;
                min-height:70px;
            ">
                <strong>{number}</strong><br>
                {label}
            </div>
            """,
            unsafe_allow_html=True
        )


# ============================================================
# FOOTER
# ============================================================

st.divider()

st.caption(
    "Signal-Fused Intrusion Detection & Response Prioritization "
    "Dashboard with a Cryptographic Trust Layer"
)