import html
import re
from datetime import datetime

import requests
import streamlit as st

# ============================================================
# CONFIGURATION
# ============================================================

API_URL = "http://127.0.0.1:8001"
CACHE_TTL_SECONDS = 30  # how long incident/summary data is cached before refetching

st.set_page_config(
    page_title="Signal-Fused SOC",
    page_icon="◈",
    layout="wide",
    initial_sidebar_state="expanded"
)

# A shared session gives connection reuse across the many requests calls below.
_session = requests.Session()

# ============================================================
# CUSTOM UI STYLE
# ============================================================

# This preference changes only frontend styling; it does not affect SOC data.
st.session_state.setdefault("ui_theme", "Dark")
st.sidebar.radio(
    "Appearance",
    options=["Dark", "Light"],
    key="ui_theme",
    horizontal=True,
    help="Choose the dashboard colour mode.",
)

st.markdown(
    """
    <style>

    /* --------------------------------------------------------
       GLOBAL
    -------------------------------------------------------- */

    .stApp {
        background: #0B132B;
        color: #F8FAFC;
    }

    .main .block-container {
        padding-top: 1.5rem;
        padding-bottom: 2rem;
        max-width: 1500px;
    }

    html, body, [class*="css"] {
        font-family: "Segoe UI", sans-serif;
    }

    /* --------------------------------------------------------
       SIDEBAR
    -------------------------------------------------------- */

    section[data-testid="stSidebar"] {
        background: #081020;
        border-right: 1px solid #263451;
    }

    section[data-testid="stSidebar"] > div {
        padding-top: 2rem;
    }

    .sidebar-brand {
        padding: 10px 5px 20px 5px;
        border-bottom: 1px solid #263451;
        margin-bottom: 20px;
    }

    .sidebar-brand-title {
        font-size: 20px;
        font-weight: 700;
        color: #F8FAFC;
        letter-spacing: 0.5px;
    }

    .sidebar-brand-subtitle {
        color: #A3B1C6;
        font-size: 12px;
        margin-top: 4px;
    }

    .status-online {
        display: inline-block;
        padding: 4px 9px;
        border-radius: 12px;
        background: #12354A;
        color: #00FF88;
        font-size: 11px;
        font-weight: 600;
        margin-top: 12px;
    }

    /* --------------------------------------------------------
       HEADER
    -------------------------------------------------------- */

    .soc-header {
        background: #1C2541;
        border: 1px solid #2A385B;
        border-radius: 14px;
        padding: 22px 26px;
        margin-bottom: 22px;
    }

    .soc-title {
        font-size: 28px;
        font-weight: 700;
        color: #F8FAFC;
        letter-spacing: -0.5px;
    }

    .soc-subtitle {
        font-size: 13px;
        color: #A3B1C6;
        margin-top: 5px;
    }

    .analyst-box {
        text-align: right;
        padding-top: 3px;
    }

    .analyst-name {
        font-weight: 700;
        color: #F8FAFC;
        font-size: 14px;
    }

    .analyst-role {
        color: #A3B1C6;
        font-size: 11px;
        margin-top: 3px;
    }

    /* --------------------------------------------------------
       KPI CARDS
    -------------------------------------------------------- */

    .kpi-card {
        background: #1C2541;
        border: 1px solid #2A385B;
        border-radius: 12px;
        padding: 18px 19px;
        min-height: 118px;
        margin-bottom: 8px;
    }

    .kpi-label {
        color: #A3B1C6;
        font-size: 11px;
        text-transform: uppercase;
        letter-spacing: 1px;
        font-weight: 600;
    }

    .kpi-value {
        color: #F8FAFC;
        font-size: 31px;
        font-weight: 700;
        margin-top: 8px;
    }

    .kpi-note {
        color: #91A4C2;
        font-size: 11px;
        margin-top: 3px;
    }

    .kpi-critical {
        border-left: 4px solid #a95757;
    }

    .kpi-high {
        border-left: 4px solid #b68a4a;
    }

    .kpi-p1 {
        border-left: 4px solid #00FF88;
    }

    .kpi-risk {
        border-left: 4px solid #00C2FF;
    }

    .kpi-total {
        border-left: 4px solid #61718F;
    }

    /* --------------------------------------------------------
       SECTION HEADERS
    -------------------------------------------------------- */

    .section-title {
        font-size: 16px;
        font-weight: 700;
        color: #F8FAFC;
        margin-top: 8px;
        margin-bottom: 4px;
    }

    .section-subtitle {
        font-size: 11px;
        color: #91A4C2;
        margin-bottom: 14px;
    }

    /* --------------------------------------------------------
       PANELS
    -------------------------------------------------------- */

    .panel {
        background: #1C2541;
        border: 1px solid #2A385B;
        border-radius: 12px;
        padding: 18px;
        margin-bottom: 16px;
    }

    .panel-title {
        color: #F8FAFC;
        font-weight: 700;
        font-size: 14px;
        margin-bottom: 5px;
    }

    .panel-subtitle {
        color: #91A4C2;
        font-size: 11px;
    }

    /* --------------------------------------------------------
       INCIDENT BADGES
    -------------------------------------------------------- */

    .badge-critical {
        display: inline-block;
        background: #3b2325;
        color: #d88b8b;
        border: 1px solid #714344;
        border-radius: 5px;
        padding: 3px 8px;
        font-size: 10px;
        font-weight: 700;
    }

    .badge-high {
        display: inline-block;
        background: #3b3020;
        color: #d3ad70;
        border: 1px solid #705c37;
        border-radius: 5px;
        padding: 3px 8px;
        font-size: 10px;
        font-weight: 700;
    }

    .badge-medium {
        display: inline-block;
        background: #303329;
        color: #c2c58f;
        border: 1px solid #5a6043;
        border-radius: 5px;
        padding: 3px 8px;
        font-size: 10px;
        font-weight: 700;
    }

    .badge-low {
        display: inline-block;
        background: #202e2c;
        color: #8bb6ae;
        border: 1px solid #3c625c;
        border-radius: 5px;
        padding: 3px 8px;
        font-size: 10px;
        font-weight: 700;
    }

    /* --------------------------------------------------------
       INCIDENT DETAIL
    -------------------------------------------------------- */

    .detail-card {
        background: #111B35;
        border: 1px solid #344563;
        border-radius: 10px;
        padding: 14px;
        margin-bottom: 10px;
    }

    .detail-label {
        color: #91A4C2;
        font-size: 10px;
        text-transform: uppercase;
        letter-spacing: 0.8px;
    }

    .detail-value {
        color: #F1F5F9;
        font-size: 13px;
        margin-top: 4px;
        word-break: break-word;
    }

    /* --------------------------------------------------------
       BUTTONS
    -------------------------------------------------------- */

    .stButton > button {
        border-radius: 8px;
        border: 1px solid #00A6D6;
        background: #12354A;
        color: #F8FAFC;
        font-weight: 600;
    }

    .stButton > button:hover {
        border-color: #00C2FF;
        background: #173B5A;
        color: #ffffff;
    }

    /* --------------------------------------------------------
       SELECTBOX / INPUT
    -------------------------------------------------------- */

    div[data-baseweb="select"] > div {
        background: #111B35;
        border-color: #344563;
    }

    div[data-baseweb="input"] > div {
        background: #111B35;
        border-color: #344563;
    }

    /* --------------------------------------------------------
       DATAFRAME
    -------------------------------------------------------- */

    div[data-testid="stDataFrame"] {
        border: 1px solid #2A385B;
        border-radius: 10px;
        overflow: hidden;
    }



    div[data-testid="stProgress"] > div > div > div {
        background: #00C2FF;
    }



    .login-wrapper {
        max-width: 470px;
        margin: 90px auto 0 auto;
        background: #1C2541;
        border: 1px solid #2A385B;
        border-radius: 16px;
        padding: 35px;
    }

    .login-logo {
        text-align: center;
        font-size: 38px;
        color: #00FF88;
    }

    .login-title {
        text-align: center;
        font-size: 26px;
        font-weight: 700;
        color: #F8FAFC;
        margin-top: 10px;
    }

    .login-subtitle {
        text-align: center;
        color: #A3B1C6;
        font-size: 12px;
        margin-top: 6px;
        margin-bottom: 25px;
    }



    .footer {
        text-align: center;
        color: #8293B1;
        font-size: 10px;
        padding: 20px 0 5px 0;
    }

    </style>
    """,
    unsafe_allow_html=True
)

# Theme override for the optional light appearance. The dark theme remains the default.
if st.session_state.get("ui_theme", "Dark") == "Light":
    st.markdown(
        """
        <style>
        .stApp, [data-testid="stAppViewContainer"] { background: #F4F7FB !important; color: #172033 !important; }
        .main .block-container { color: #172033 !important; }
        section[data-testid="stSidebar"] { background: #E8EEF7 !important; border-right: 1px solid #CFD8E6 !important; }
        .soc-header, .kpi-card, .panel, .login-wrapper { background: #FFFFFF !important; border-color: #D5DEEB !important; box-shadow: 0 2px 8px rgba(20, 40, 80, 0.04); }
        .soc-title, .sidebar-brand-title, .analyst-name, .kpi-value, .section-title, .panel-title, .login-title, .detail-value { color: #172033 !important; }
        .soc-subtitle, .sidebar-brand-subtitle, .analyst-role, .kpi-label, .kpi-note, .section-subtitle, .panel-subtitle, .detail-label, .login-subtitle { color: #52627A !important; }
        .detail-card { background: #F8FAFD !important; border-color: #D5DEEB !important; }
        .stButton > button { background: #E4F6FC !important; color: #075985 !important; border-color: #7DD3FC !important; }
        .stButton > button:hover { background: #CFF0FC !important; border-color: #00A6D6 !important; }
        div[data-baseweb="select"] > div, div[data-baseweb="input"] > div { background: #FFFFFF !important; border-color: #C6D2E2 !important; }
        div[data-testid="stDataFrame"] { border-color: #D5DEEB !important; }
        [data-testid="stMarkdownContainer"], [data-testid="stWidgetLabel"] { color: #172033; }
        </style>
        """,
        unsafe_allow_html=True,
    )





def safe_float(value, default=0.0):
    """Best-effort float conversion. Never raises."""
    if value is None:
        return default
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def safe_int(value, default=0):
    """Best-effort int conversion (routes through float first to tolerate '5.0')."""
    return int(safe_float(value, default))


def esc(value) -> str:
    """HTML-escape any value before interpolating it into unsafe_allow_html markup."""
    return html.escape(str(value)) if value is not None else ""




class AuthError(Exception):
    """Raised when the backend reachable but credentials are rejected."""


class BackendUnavailable(Exception):
    """Raised when the backend cannot be reached at all (network/timeout)."""


def authenticate(username: str, password: str) -> dict:
    """
    Returns the login payload on success.
    Raises AuthError for a rejected login (so the UI can show a precise message)
    and BackendUnavailable for connection/timeout problems, instead of collapsing
    every possible failure into one generic message.
    """
    try:
        response = _session.post(
            f"{API_URL}/api/auth/login",
            json={"username": username, "password": password},
            timeout=5
        )
    except requests.exceptions.RequestException as exc:
        raise BackendUnavailable(str(exc)) from exc

    if response.status_code == 200:
        payload = response.json()
        if payload.get("authenticated"):
            return payload
        raise AuthError("Invalid Analyst ID or Password.")

    if response.status_code in (401, 403):
        raise AuthError("Invalid Analyst ID or Password.")

    raise BackendUnavailable(f"Backend returned HTTP {response.status_code}.")


@st.cache_data(ttl=CACHE_TTL_SECONDS, show_spinner=False)
def get_summary() -> dict:
    response = _session.get(f"{API_URL}/api/dashboard/summary", timeout=10)
    response.raise_for_status()
    return response.json()


@st.cache_data(ttl=CACHE_TTL_SECONDS, show_spinner=False)
def get_incidents() -> list:
    response = _session.get(f"{API_URL}/api/incidents", timeout=15)
    response.raise_for_status()
    data = response.json()

    if isinstance(data, list):
        return data
    if isinstance(data, dict):
        return data.get("incidents", [])
    return []

def get_live_incidents() -> list:
    """
    Fetch the latest incidents directly from FastAPI.

    This function is intentionally NOT cached because it is used by
    the live Incident Investigation section.
    """
    try:
        response = _session.get(
            f"{API_URL}/api/incidents",
            timeout=15
        )
        response.raise_for_status()

        data = response.json()

        if isinstance(data, list):
            return data

        if isinstance(data, dict):
            incidents = data.get("incidents", [])
            return incidents if isinstance(incidents, list) else []

        return []

    except requests.exceptions.RequestException:
        return []
    except (ValueError, TypeError):
        return []

def get_recent_events(limit=20):
    try:
        response = requests.get(
            f"{API_URL}/api/events/recent",
            params={"limit": limit},
            timeout=5
        )

        if response.status_code == 200:
            return response.json().get("events", [])

        return []

    except requests.RequestException:
        return []
def verify_integrity(incident_id: str) -> dict:
    response = _session.get(f"{API_URL}/api/trust/{incident_id}/verify", timeout=10)
    response.raise_for_status()
    return response.json()




st.session_state.setdefault("authenticated", False)
st.session_state.setdefault("analyst", None)




if not st.session_state.authenticated:

    st.markdown(
        """
        <div class="login-wrapper">
            <div class="login-logo">◈</div>
            <div class="login-title">Signal-Fused SOC</div>
            <div class="login-subtitle">
                Multi-source threat correlation & evidence intelligence
            </div>
        </div>
        """,
        unsafe_allow_html=True
    )

    login_col1, login_col2, login_col3 = st.columns([1, 2, 1])

    with login_col2:
        # A real form lets the analyst hit Enter in the password field to submit,
        # instead of forcing a click on a separate button.
        with st.form("login_form", clear_on_submit=False):
            username = st.text_input("Analyst ID", placeholder="Enter analyst ID")
            password = st.text_input("Password", type="password", placeholder="Enter password")
            login_button = st.form_submit_button("SIGN IN TO SOC", use_container_width=True)

        if login_button:
            if not username or not password:
                st.error("Please enter Analyst ID and Password.")
            else:
                try:
                    result = authenticate(username, password)
                    st.session_state.authenticated = True
                    st.session_state.analyst = result.get("analyst", {})
                    st.rerun()
                except AuthError:
                    st.error("Invalid Analyst ID or Password.")
                except BackendUnavailable as exc:
                    st.error(f"Unable to reach the SOC backend at {API_URL}. ({exc})")

    st.stop()




try:
    summary = get_summary()
    incidents = get_incidents()
except Exception as error:
    st.error(f"Unable to connect to SOC backend: {error}")
    st.stop()



analyst = st.session_state.analyst or {}
analyst_username = analyst.get("username", "Analyst")
analyst_role = analyst.get("role", "SOC Analyst")


with st.sidebar:

    st.markdown(
        """
        <div class="sidebar-brand">
            <div class="sidebar-brand-title">◈ SIGNAL-FUSED</div>
            <div class="sidebar-brand-subtitle">Security Operations Console</div>
            <span class="status-online">● SYSTEM ONLINE</span>
        </div>
        """,
        unsafe_allow_html=True
    )

    st.markdown("### Analyst")
    st.write(f"**{analyst_username}**")
    st.caption(analyst_role)

    st.divider()

    st.markdown("### System")
    st.caption(f"Incidents loaded: {len(incidents):,}")
    st.caption("Backend: FastAPI")
    st.caption("Storage: SQLite")
    st.caption("Evidence: SHA-256")

    st.divider()

    if st.button("↻ Refresh Data", use_container_width=True):
        # Data is cached for CACHE_TTL_SECONDS, so an explicit refresh needs to
        # drop the cache before rerunning, otherwise it just redisplays stale data.
        get_summary.clear()
        get_incidents.clear()
        st.rerun()

    if st.button("Logout", use_container_width=True):
        st.session_state.authenticated = False
        st.session_state.analyst = None
        st.rerun()



header_col1, header_col2 = st.columns([4, 1])

with header_col1:
    st.markdown(
        """
        <div class="soc-header">
            <div class="soc-title">Security Operations Dashboard</div>
            <div class="soc-subtitle">
                Multi-source intrusion detection,
                signal fusion, risk prioritization
                and cryptographic evidence trust
            </div>
        </div>
        """,
        unsafe_allow_html=True
    )

with header_col2:
    st.markdown(
        f"""
        <div class="analyst-box">
            <div class="analyst-name">{esc(analyst_username)}</div>
            <div class="analyst-role">{esc(analyst_role)}</div>
        </div>
        """,
        unsafe_allow_html=True
    )



# Backend returns nested dictionaries:
#   summary["severity"]["CRITICAL"]
#   summary["priority"]["P1"]
#   summary["integrity"]["VERIFIED"]

severity_summary = summary.get("severity", {})
priority_summary = summary.get("priority", {})
integrity_summary = summary.get("integrity", {})

total_incidents = safe_int(summary.get("total_incidents", len(incidents)))

critical = safe_int(severity_summary.get("CRITICAL", 0))
high = safe_int(severity_summary.get("HIGH", 0))
medium = safe_int(severity_summary.get("MEDIUM", 0))
low = safe_int(severity_summary.get("LOW", 0))

p1 = safe_int(priority_summary.get("P1", 0))
p2 = safe_int(priority_summary.get("P2", 0))
p3 = safe_int(priority_summary.get("P3", 0))
p4 = safe_int(priority_summary.get("P4", 0))

verified = safe_int(integrity_summary.get("VERIFIED", 0))
tampered = safe_int(integrity_summary.get("TAMPERED", 0))
other_integrity = safe_int(integrity_summary.get("OTHER", 0))




risk_values = []
unparsed_risk_count = 0

for incident in incidents:
    raw_risk = incident.get("risk_score")
    if raw_risk is None:
        unparsed_risk_count += 1
        continue
    try:
        risk_values.append(float(raw_risk))
    except (TypeError, ValueError):
        unparsed_risk_count += 1

if risk_values:
    average_risk = sum(risk_values) / len(risk_values)
    maximum_risk = max(risk_values)
    high_risk_count = sum(1 for r in risk_values if r >= 70)
else:
    average_risk = 0
    maximum_risk = 0
    high_risk_count = 0

# Denominator matches the numerator's population (parsed risk scores only),
# so the percentage stays mathematically consistent even if some incidents
# have a missing/malformed risk_score.
risk_rate = (high_risk_count / len(risk_values)) * 100 if risk_values else 0




st.markdown('<div class="section-title">Operational Overview</div>', unsafe_allow_html=True)
st.markdown(
    '<div class="section-subtitle">Current incident and analyst workload indicators</div>',
    unsafe_allow_html=True
)

k1, k2, k3, k4, k5 = st.columns(5)

with k1:
    st.markdown(
        f"""
        <div class="kpi-card kpi-total">
            <div class="kpi-label">Total Incidents</div>
            <div class="kpi-value">{total_incidents:,}</div>
            <div class="kpi-note">Correlated security incidents</div>
        </div>
        """,
        unsafe_allow_html=True
    )

with k2:
    st.markdown(
        f"""
        <div class="kpi-card kpi-critical">
            <div class="kpi-label">Critical</div>
            <div class="kpi-value">{critical:,}</div>
            <div class="kpi-note">Severity: CRITICAL</div>
        </div>
        """,
        unsafe_allow_html=True
    )

with k3:
    st.markdown(
        f"""
        <div class="kpi-card kpi-high">
            <div class="kpi-label">High</div>
            <div class="kpi-value">{high:,}</div>
            <div class="kpi-note">Severity: HIGH</div>
        </div>
        """,
        unsafe_allow_html=True
    )

with k4:
    st.markdown(
        f"""
        <div class="kpi-card kpi-p1">
            <div class="kpi-label">P1 Queue</div>
            <div class="kpi-value">{p1:,}</div>
            <div class="kpi-note">Immediate analyst attention</div>
        </div>
        """,
        unsafe_allow_html=True
    )

with k5:
    st.markdown(
        f"""
        <div class="kpi-card kpi-risk">
            <div class="kpi-label">Risk Rate</div>
            <div class="kpi-value">{risk_rate:.1f}%</div>
            <div class="kpi-note">Incidents with risk ≥ 70</div>
        </div>
        """,
        unsafe_allow_html=True
    )




st.write("")

ov1, ov2, ov3, ov4 = st.columns(4)

with ov1:
    st.metric("Medium", f"{medium:,}")

with ov2:
    st.metric("Low", f"{low:,}")

with ov3:
    st.metric("Average Risk", f"{average_risk:.1f}/100")

with ov4:
    st.metric("Maximum Risk", f"{maximum_risk:.1f}/100")

if unparsed_risk_count:
    st.caption(f"Note: {unparsed_risk_count:,} incident(s) had a missing/invalid risk_score and were excluded from the risk statistics above.")




st.markdown('<div class="section-title">Threat Distribution</div>', unsafe_allow_html=True)

dist_col1, dist_col2 = st.columns(2)

with dist_col1:
    st.markdown(
        """
        <div class="panel">
            <div class="panel-title">Severity Distribution</div>
            <div class="panel-subtitle">Incidents grouped by calculated severity</div>
        </div>
        """,
        unsafe_allow_html=True
    )

    severity_chart = {"Critical": critical, "High": high, "Medium": medium, "Low": low}
    st.bar_chart(severity_chart, height=250)

with dist_col2:
    st.markdown(
        """
        <div class="panel">
            <div class="panel-title">Analyst Priority Distribution</div>
            <div class="panel-subtitle">Queue classification generated by the prioritization layer</div>
        </div>
        """,
        unsafe_allow_html=True
    )

    priority_chart = {"P1": p1, "P2": p2, "P3": p3, "P4": p4}
    st.bar_chart(priority_chart, height=250)




st.markdown('<div class="section-title">Authentication Activity</div>', unsafe_allow_html=True)

auth_events = []

for incident in incidents:
    signals = str(incident.get("signal_types", "")).upper()

    if "AUTH_FAILURE_SIGNAL" in signals or "BRUTE_FORCE_SIGNAL" in signals:
        auth_events.append({
            "Source IP": incident.get("source_ip", "-"),
            "Incident": incident.get("incident_id", "-"),
            "Severity": incident.get("severity", "-"),
            "Priority": incident.get("priority_level", "-"),
            "Risk": incident.get("risk_score", "-"),
            "Status": "Suspicious authentication activity"
        })

if auth_events:
    st.dataframe(auth_events[:20], use_container_width=True, hide_index=True)

    if len(auth_events) > 20:
        st.caption(f"Showing first 20 of {len(auth_events):,} authentication-related incidents.")
else:
    st.info("No authentication-related incidents currently detected.")


# ============================================================
# LIVE SECURITY EVENT STREAM
# ============================================================

@st.fragment(run_every=8)
def render_live_security_events():

    st.markdown(
        '<div class="section-title">Live Security Event Stream</div>',
        unsafe_allow_html=True
    )

    st.markdown(
        '<div class="section-subtitle">'
        'Automatically refreshing every 5 seconds'
        '</div>',
        unsafe_allow_html=True
    )

    recent_events = get_recent_events(20)

    if recent_events:
        event_rows = []

        for event in recent_events:
            event_rows.append({
                "Time": event.get("timestamp", "-"),
                "Source": event.get("source_type", "-"),
                "Source IP": event.get("source_ip", "-"),
                "Destination IP": event.get("destination_ip", "-"),
                "User": event.get("username", "-"),
                "Event": event.get("event_type", "-"),
                "Severity": event.get("severity", "-")
            })

        st.dataframe(
            event_rows,
            use_container_width=True,
            hide_index=True
        )

        st.caption(
            f"Showing {len(event_rows)} most recent available events."
        )

    else:
        st.info("No recent security events available.")


render_live_security_events()

# ============================================================
# LIVE ANALYST PRIORITY QUEUE
# ============================================================

@st.fragment(run_every=8)
def render_priority_queue():

    st.markdown(
        '<div class="section-title">Analyst Priority Queue</div>',
        unsafe_allow_html=True
    )

    st.markdown(
        '<div class="section-subtitle">'
        'Live queue · automatically refreshing every 8 seconds'
        '</div>',
        unsafe_allow_html=True
    )

    # Fetch directly from the backend.
    # Do NOT use the cached get_incidents() here.
    live_incidents = get_live_incidents()

    # Defensive protection against incomplete queue ranks.
    priority_incidents = [
        incident
        for incident in live_incidents
        if safe_float(incident.get("queue_rank"), default=0) > 0
    ]

    priority_incidents = sorted(
        priority_incidents,
        key=lambda x: safe_float(
            x.get("queue_rank"),
            default=999_999
        )
    )

    if priority_incidents:
        queue_rows = []

        for incident in priority_incidents[:25]:
            queue_rows.append({
                "Rank": incident.get("queue_rank", "-"),
                "Priority": incident.get("priority_level", "-"),
                "Severity": incident.get("severity", "-"),
                "Risk": incident.get("risk_score", "-"),
                "Incident": incident.get("incident_id", "-"),
                "Source IP": incident.get("source_ip", "-"),
                "Pattern": incident.get("incident_patterns", "-")
            })

        st.dataframe(
            queue_rows,
            use_container_width=True,
            hide_index=True
        )

    else:
        st.info("No prioritized incidents available.")


render_priority_queue()


# ============================================================
# INCIDENT INVESTIGATION — LIVE
# ============================================================

st.markdown(
    '<div class="section-title">Incident Investigation</div>',
    unsafe_allow_html=True
)


@st.fragment(run_every=10)
def render_incident_investigation():

    # --------------------------------------------------------
    # FETCH FRESH INCIDENT DATA
    # --------------------------------------------------------
    live_incidents = get_live_incidents()

    if live_incidents:

        incident_ids = [
            incident.get("incident_id")
            for incident in live_incidents
            if incident.get("incident_id")
        ]

        if not incident_ids:
            st.info("No valid incidents are available for investigation.")
            return

        # ----------------------------------------------------
        # PRESERVE THE CURRENTLY SELECTED INCIDENT
        # ----------------------------------------------------
        current_selection = st.session_state.get(
            "incident_investigation_select"
        )

        if current_selection not in incident_ids:
            current_selection = incident_ids[0]

        selected_index = incident_ids.index(current_selection)

        selected_incident_id = st.selectbox(
            "Select incident",
            incident_ids,
            index=selected_index,
            key="incident_investigation_select"
        )

        selected = next(
            (
                incident
                for incident in live_incidents
                if incident.get("incident_id") == selected_incident_id
            ),
            None
        )

        if selected:

            # ------------------------------------------------
            # TOP INCIDENT METRICS
            # ------------------------------------------------

            d1, d2, d3, d4 = st.columns(4)

            with d1:
                st.metric(
                    "Risk Score",
                    selected.get("risk_score", "-")
                )

            with d2:
                st.metric(
                    "Severity",
                    selected.get("severity", "-")
                )

            with d3:
                st.metric(
                    "Priority",
                    selected.get("priority_level", "-")
                )

            with d4:
                st.metric(
                    "Fusion Strength",
                    selected.get("fusion_strength", "-")
                )


            # ------------------------------------------------
            # INCIDENT IDENTITY / TIMING
            # ------------------------------------------------

            info1, info2 = st.columns(2)

            with info1:

                st.markdown(
                    """
                    <div class="panel">
                        <div class="panel-title">Incident Identity</div>
                    </div>
                    """,
                    unsafe_allow_html=True
                )

                st.write(
                    f"**Incident ID:** "
                    f"{selected.get('incident_id', '-')}"
                )

                st.write(
                    f"**Correlation ID:** "
                    f"{selected.get('correlation_id', '-')}"
                )

                st.write(
                    f"**Source IP:** "
                    f"{selected.get('source_ip', '-')}"
                )

                st.write(
                    f"**Destination IP:** "
                    f"{selected.get('destination_ip', '-')}"
                )

                st.write(
                    f"**Incident Type:** "
                    f"{selected.get('incident_type', '-')}"
                )


            with info2:

                st.markdown(
                    """
                    <div class="panel">
                        <div class="panel-title">
                            Incident Timing & Volume
                        </div>
                    </div>
                    """,
                    unsafe_allow_html=True
                )

                duration = selected.get("duration_seconds")

                duration_display = (
                    f"{duration} seconds"
                    if duration not in (None, "")
                    else "-"
                )

                st.write(
                    f"**Events:** "
                    f"{selected.get('unique_event_count', '-')}"
                )

                st.write(
                    f"**Signals:** "
                    f"{selected.get('signal_count', '-')}"
                )

                st.write(
                    f"**Duration:** "
                    f"{duration_display}"
                )

                st.write(
                    f"**Start:** "
                    f"{selected.get('incident_start', '-')}"
                )

                st.write(
                    f"**End:** "
                    f"{selected.get('incident_end', '-')}"
                )


            # ------------------------------------------------
            # DETECTED SIGNALS
            # ------------------------------------------------

            st.markdown("#### Detected Signals")

            # Pull primary and supporting signals separately: some incident records
            # store corroborating detections in supporting_signal_types.
            def parse_signal_values(raw_value):
                if raw_value is None:
                    return []
                if isinstance(raw_value, (list, tuple, set)):
                    raw_text = "|".join(str(item) for item in raw_value)
                else:
                    raw_text = str(raw_value)
                raw_text = html.unescape(raw_text)
                raw_text = re.sub(r"(?is)<(script|style)[^>]*>.*?</\1>", " ", raw_text)
                raw_text = re.sub(r"<[^>]*>", " ", raw_text)
                # Normalize common separators and remove blank/placeholder values.
                pieces = re.split(r"[|,;\n]+", raw_text)
                cleaned = []
                for piece in pieces:
                    value = re.sub(r"\s+", " ", piece).strip(" \t\r\n\"'")
                    if value and value.upper() not in {"NULL", "NONE", "N/A", "-", "[]"}:
                        cleaned.append(value)
                return cleaned

            primary_signals = parse_signal_values(selected.get("signal_types"))
            supporting_signals = parse_signal_values(selected.get("supporting_signal_types"))
            signal_list = []
            seen_signals = set()
            for signal in primary_signals + supporting_signals:
                normalized = signal.casefold()
                if normalized not in seen_signals:
                    signal_list.append((signal, "Primary" if signal in primary_signals else "Supporting"))
                    seen_signals.add(normalized)

            if signal_list:
                st.caption(f"{len(signal_list)} distinct signal type(s) recorded for this incident")
                signal_columns = st.columns(min(len(signal_list), 3))
                for index, (signal, signal_kind) in enumerate(signal_list):
                    with signal_columns[index % len(signal_columns)]:
                        accent = "#00C2FF" if signal_kind == "Primary" else "#A78BFA"
                        background = "rgba(0,194,255,0.10)" if signal_kind == "Primary" else "rgba(167,139,250,0.10)"
                        st.markdown(
                            f"""
                            <div style="background:{background};border:1px solid {accent};
                                        border-left:4px solid {accent};border-radius:10px;
                                        padding:14px 12px;margin:0 0 10px 0;min-height:88px;">
                                <div style="font-size:10px;font-weight:800;letter-spacing:1px;
                                            color:{accent};text-transform:uppercase;margin-bottom:8px;">
                                    {signal_kind} SIGNAL
                                </div>
                                <div style="font-size:14px;font-weight:700;color:var(--text-color,#F8FAFC);
                                            overflow-wrap:anywhere;line-height:1.45;">
                                    {esc(signal)}
                                </div>
                            </div>
                            """,
                            unsafe_allow_html=True
                        )
            else:
                st.info("No signal information is stored for this incident. Try selecting another incident or check the backend incident data.")


            # ------------------------------------------------
            # CORRELATION & FUSION
            # ------------------------------------------------

            st.markdown("#### Correlation & Fusion")

            patterns = str(
                selected.get("incident_patterns", "")
            )

            pattern_list = [
                x.strip()
                for x in patterns
                .replace("|", ",")
                .split(",")
                if x.strip()
            ]

            if pattern_list:

                for pattern in pattern_list:

                    st.info(
                        f"Fusion Pattern: **{pattern}**"
                    )

            else:

                st.info(
                    "No fusion patterns available."
                )


            # ------------------------------------------------
            # FUSION EVIDENCE METRICS
            # ------------------------------------------------

            ev1, ev2, ev3, ev4 = st.columns(4)

            with ev1:

                st.metric(
                    "Fusion Evidence",
                    selected.get(
                        "fusion_evidence_count",
                        "-"
                    )
                )

            with ev2:

                st.metric(
                    "Signal Diversity",
                    selected.get(
                        "unique_signal_type_count",
                        "-"
                    )
                )

            with ev3:

                st.metric(
                    "Source Diversity",
                    selected.get(
                        "unique_source_type_count",
                        "-"
                    )
                )

            with ev4:

                st.metric(
                    "Mean Signal Strength",
                    selected.get(
                        "mean_signal_strength",
                        "-"
                    )
                )


            # ------------------------------------------------
            # RISK ASSESSMENT
            # ------------------------------------------------

            st.markdown("#### Risk Assessment")

            selected_risk = safe_float(
                selected.get("risk_score"),
                default=0.0
            )

            st.progress(
                min(
                    max(selected_risk / 100, 0),
                    1
                )
            )

            st.write(
                f"Risk Score: "
                f"**{selected_risk:.2f}/100**"
            )

            st.write(
                f"Severity: "
                f"**{selected.get('severity', '-')}**"
            )

            if selected.get("risk_factors"):

                st.write(
                    f"Risk Factors: "
                    f"**{selected.get('risk_factors')}**"
                )

            if selected.get("severity_reason"):

                st.write(
                    f"Severity Reason: "
                    f"**{selected.get('severity_reason')}**"
                )


            # ------------------------------------------------
            # RECOMMENDED RESPONSE
            # ------------------------------------------------

            st.markdown(
                "#### Recommended Analyst Response"
            )

            st.warning(
                selected.get(
                    "recommended_action",
                    "INVESTIGATE"
                )
            )


            # ------------------------------------------------
            # CRYPTOGRAPHIC TRUST
            # ------------------------------------------------

            st.markdown(
                "#### Cryptographic Trust Layer"
            )

            trust1, trust2 = st.columns(2)

            with trust1:

                st.write(
                    "**Integrity Status:**"
                )

                integrity_status = selected.get(
                    "integrity_status",
                    "-"
                )

                if integrity_status == "INTEGRITY_VERIFIED":

                    st.success(
                        "✓ INTEGRITY VERIFIED"
                    )

                elif integrity_status == "TAMPERING_DETECTED":

                    st.error(
                        "⚠ POSSIBLE TAMPERING DETECTED"
                    )

                else:

                    st.warning(
                        f"Status: {integrity_status}"
                    )


            with trust2:

                st.write(
                    f"**Hash Algorithm:** "
                    f"{selected.get('hash_algorithm', 'SHA-256')}"
                )

                st.write(
                    f"**Evidence Version:** "
                    f"{selected.get('evidence_version', '-')}"
                )


            stored_hash = selected.get(
                "evidence_hash",
                "-"
            )

            st.write(
                "**Stored SHA-256 Hash:**"
            )

            st.code(stored_hash)


            # ------------------------------------------------
            # VERIFY EVIDENCE
            # ------------------------------------------------

            verify_button = st.button(
                "VERIFY EVIDENCE INTEGRITY",
                use_container_width=True,
                key=f"verify_{selected_incident_id}"
            )

            if verify_button:

                try:

                    result = verify_integrity(
                        selected_incident_id
                    )

                    status = result.get(
                        "integrity_status"
                    )

                    calculated_hash = result.get(
                        "calculated_hash",
                        "-"
                    )

                    st.write(
                        "**Calculated SHA-256 Hash:**"
                    )

                    st.code(calculated_hash)

                    if status == "INTEGRITY_VERIFIED":

                        st.success(
                            "✓ INTEGRITY VERIFIED — "
                            "Stored evidence matches "
                            "its SHA-256 hash."
                        )

                    elif status == "TAMPERING_DETECTED":

                        st.error(
                            "⚠ POSSIBLE TAMPERING DETECTED — "
                            "Stored and calculated hashes "
                            "do not match."
                        )

                    else:

                        st.warning(
                            f"Integrity status: {status}"
                        )

                except Exception as error:

                    st.error(
                        f"Verification failed: {error}"
                    )


            # ------------------------------------------------
            # CANONICAL EVIDENCE
            # ------------------------------------------------

            with st.expander(
                "View Canonical Evidence"
            ):

                st.code(
                    selected.get(
                        "canonical_evidence",
                        "No evidence available."
                    ),
                    language="text"
                )

    else:

        st.info(
            "No incidents are available for investigation."
        )


# Run the live Incident Investigation section.
render_incident_investigation()




st.markdown('<div class="section-title">Evidence Integrity</div>', unsafe_allow_html=True)

integrity_col1, integrity_col2, integrity_col3 = st.columns(3)

with integrity_col1:
    st.metric("Verified", f"{verified:,}")

with integrity_col2:
    st.metric("Possible Tampering", f"{tampered:,}")

with integrity_col3:
    st.metric("Evidence Records", f"{len(incidents):,}")

if tampered > 0:
    st.error(f"⚠ {tampered:,} incident(s) have possible evidence-integrity violations.")
else:
    st.success("✓ No evidence-integrity violations currently recorded.")
    
st.markdown(
    f"""
    <div class="footer">
        SIGNAL-FUSED SOC · Multi-source threat correlation
        · Evidence fusion · Risk prioritization · SHA-256 trust
        <br><br>
        Last refreshed: {esc(datetime.now().strftime("%Y-%m-%d %H:%M:%S"))}
    </div>
    """,
    unsafe_allow_html=True
)