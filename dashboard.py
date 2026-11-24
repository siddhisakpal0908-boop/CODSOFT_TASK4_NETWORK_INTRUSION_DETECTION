
import json
from pathlib import Path

import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st


# =========================================================
# PAGE CONFIGURATION
# =========================================================

st.set_page_config(
    page_title="Violet Shield | Security Operations Center",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

BASE_DIR = Path(__file__).resolve().parent
LOG_FILE = BASE_DIR / "logs" / "eve.json"


# =========================================================
# DARK PURPLE THEME
# =========================================================

st.markdown("""
<style>
.stApp {
    background-color: #090817;
    color: #f5efff;
}

.block-container {
    max-width: 1600px;
    padding: 1.5rem 2rem 3rem;
}

header[data-testid="stHeader"] {
    background: transparent;
}

#MainMenu, footer {
    visibility: hidden;
}

/* SIDEBAR */

section[data-testid="stSidebar"] {
    background-color: #130e22;
    border-right: 1px solid #392653;
}

section[data-testid="stSidebar"] [data-testid="stMarkdownContainer"] p,
section[data-testid="stSidebar"] label,
section[data-testid="stSidebar"] [data-testid="stWidgetLabel"] {
    color: #e5d9f5 !important;
}

.side-brand {
    background: #392458;
    border: 1px solid #65448d;
    border-radius: 12px;
    padding: 18px;
    margin-bottom: 20px;
}

.side-logo {
    color: #ffffff;
    font-size: 21px;
    font-weight: 800;
}

.side-sub {
    color: #e0d1fa;
    font-size: 10px;
    margin-top: 6px;
}

.side-heading {
    color: #b58cff !important;
    font-size: 11px;
    font-weight: 800;
    margin: 22px 0 10px;
}

.side-info {
    background: #211738;
    border: 1px solid #49346c;
    border-radius: 9px;
    padding: 12px;
    color: #e5d9f5;
    font-size: 12px;
    margin-bottom: 9px;
}

/* HEADER */

.hero {
    background: #392458;
    border: 1px solid #65448d;
    border-radius: 14px;
    padding: 26px;
    margin-bottom: 25px;
}

.hero-title {
    color: #ffffff;
    font-size: 30px;
    font-weight: 900;
}

.hero-title span {
    color: #d8b4fe;
}

.hero-sub {
    color: #e0d1fa;
    font-size: 11px;
    letter-spacing: 1px;
    margin-top: 8px;
}

.hero-bottom {
    color: #eee5ff;
    font-size: 11px;
    margin-top: 16px;
}

.status-pill {
    display: inline-block;
    padding: 8px 13px;
    border-radius: 20px;
    background: #153c2b;
    color: #86efac;
    font-size: 11px;
    font-weight: 800;
    margin-top: 17px;
}

.status-off {
    background: #422b12;
    color: #fcd34d;
}

/* SECTION HEADINGS */

.section-title {
    color: #d8b4fe;
    font-size: 18px;
    font-weight: 900;
    margin: 27px 0 12px;
}

.section-subtitle {
    color: #aa9acb;
    font-size: 11px;
    margin-bottom: 18px;
}

/* KPI CARDS */

.kpi-card {
    background: #15112b;
    border: 1px solid #49346c;
    border-radius: 12px;
    padding: 18px;
    min-height: 130px;
}

.kpi-label {
    color: #b9a6da;
    font-size: 10px;
    font-weight: 800;
}

.kpi-icon {
    float: right;
    font-size: 21px;
}

.kpi-value {
    color: #d8b4fe;
    font-size: 31px;
    font-weight: 900;
    margin-top: 15px;
}

.kpi-foot {
    color: #9f8cbe;
    font-size: 10px;
    margin-top: 3px;
}

/* CHARTS AND TABLES */

.panel-title {
    background: #211738;
    color: #d8b4fe;
    border: 1px solid #49346c;
    border-radius: 9px;
    padding: 14px;
    font-size: 11px;
    font-weight: 900;
    margin-bottom: 10px;
}

div[data-testid="stPlotlyChart"] {
    background: #15112b;
    border: 1px solid #49346c;
    border-radius: 10px;
    padding: 5px;
}

div[data-testid="stDataFrame"] {
    background: #15112b;
    border: 1px solid #49346c;
    border-radius: 10px;
}

/* INPUTS */

section[data-testid="stSidebar"] input,
section[data-testid="stSidebar"] [data-baseweb="select"] > div {
    background-color: #211738;
    color: #ffffff;
    border-color: #65448d;
}

/* BUTTONS */

.stButton > button,
.stDownloadButton > button {
    background: #7040a5;
    color: #ffffff;
    border: 1px solid #7040a5;
    border-radius: 8px;
    font-weight: 700;
}

.stButton > button:hover,
.stDownloadButton > button:hover {
    background: #593681;
    color: #ffffff;
    border-color: #593681;
}

/* FOOTER */

.footer {
    text-align: center;
    color: #9683b8;
    font-size: 10px;
    padding: 22px;
    margin-top: 30px;
    border-top: 1px solid #392653;
}
</style>
""", unsafe_allow_html=True)


# =========================================================
# LOAD SURICATA LOGS
# =========================================================

alerts = []
flow_count = 0
stats_event = None
last_log_time = None

if not LOG_FILE.exists():
    st.error("logs/eve.json was not found. Check your project folder.")
    st.stop()

try:
    with LOG_FILE.open("r", encoding="utf-8") as file:

        for line in file:

            try:
                event = json.loads(line)
                timestamp = event.get("timestamp")

                if timestamp:
                    parsed_time = pd.to_datetime(
                        timestamp,
                        errors="coerce",
                        utc=True
                    )

                    if pd.notna(parsed_time):
                        if (
                            last_log_time is None
                            or parsed_time > last_log_time
                        ):
                            last_log_time = parsed_time

                event_type = event.get("event_type")

                if event_type == "alert":

                    alert = event.get("alert") or {}

                    alerts.append({
                        "Time": timestamp or "",
                        "Alert": alert.get("signature", "Unknown"),
                        "Source IP": event.get("src_ip", "Unknown"),
                        "Destination IP": event.get("dest_ip", "Unknown"),
                        "Protocol": event.get("proto", "Unknown"),
                        "Severity": alert.get("severity", "Unknown"),
                        "Destination Port": event.get("dest_port", "N/A")
                    })

                elif event_type == "flow":
                    flow_count += 1

                elif event_type == "stats":
                    stats_event = event

            except (json.JSONDecodeError, TypeError):
                continue

except OSError as error:
    st.error(f"Unable to read Suricata log: {error}")
    st.stop()


# =========================================================
# PREPARE DATA
# =========================================================

df = pd.DataFrame(alerts)

if not df.empty:
    df["Time"] = pd.to_datetime(
        df["Time"],
        errors="coerce",
        utc=True
    )

now = pd.Timestamp.now(tz="UTC")

seconds_since_log = (
    (now - last_log_time).total_seconds()
    if last_log_time is not None
    else None
)

recent_activity = (
    seconds_since_log is not None
    and 0 <= seconds_since_log <= 120
)


# =========================================================
# SIDEBAR
# =========================================================

with st.sidebar:

    st.markdown(
        '<div class="side-brand">'
        '<div class="side-logo">🛡️ VIOLET SHIELD</div>'
        '<div class="side-sub">SECURITY OPERATIONS CENTER</div>'
        '</div>',
        unsafe_allow_html=True
    )

    st.markdown(
        '<div class="side-heading">DISPLAY SETTINGS</div>',
        unsafe_allow_html=True
    )

    if st.button("↻ Refresh dashboard", use_container_width=True):
        st.rerun()

    st.markdown(
        '<div class="side-heading">NAVIGATION</div>',
        unsafe_allow_html=True
    )

    page = st.radio(
        "Dashboard sections",
        [
            "Security Overview",
            "Threat Analytics",
            "Security Events",
            "Source IP Analysis"
        ],
        label_visibility="collapsed"
    )

    if not df.empty:

        st.markdown(
            '<div class="side-heading">ALERT FILTERS</div>',
            unsafe_allow_html=True
        )

        alert_options = sorted(
            df["Alert"].dropna().unique().tolist()
        )

        selected_alerts = st.multiselect(
            "Alert types",
            options=alert_options,
            default=alert_options
        )

        source_options = sorted(
            df["Source IP"].dropna().unique().tolist()
        )

        selected_sources = st.multiselect(
            "Source IP addresses",
            options=source_options,
            default=source_options
        )

    else:
        selected_alerts = []
        selected_sources = []

    st.markdown(
        '<div class="side-heading">DISPLAY SETTINGS</div>',
        unsafe_allow_html=True
    )

    rows_to_show = st.selectbox(
        "Recent events to display",
        [10, 20, 50, 100],
        index=1
    )

    st.markdown(
        '<div class="side-heading">SYSTEM INFORMATION</div>',
        unsafe_allow_html=True
    )

    st.markdown(
        '<div class="side-info"><b>Detection Engine</b><br>Suricata 8.0.8</div>'
        '<div class="side-info"><b>Dashboard</b><br>Python + Streamlit + Plotly</div>'
        '<div class="side-info"><b>Log Source</b><br>logs/eve.json</div>',
        unsafe_allow_html=True
    )


# =========================================================
# MAIN HEADER
# =========================================================

status_class = "" if recent_activity else "status-off"

status_text = (
    "RECENT LOG ACTIVITY"
    if recent_activity
    else "NO RECENT LOG ACTIVITY"
)

st.markdown(
    f'<div class="hero">'
    f'<div class="hero-title">🛡️ VIOLET <span>SHIELD</span></div>'
    f'<div class="hero-sub">NETWORK DEFENSE CENTER • SECURITY OPERATIONS</div>'
    f'<div class="hero-bottom">THREAT DETECTION • NETWORK MONITORING</div>'
    f'<span class="status-pill {status_class}">● {status_text}</span>'
    f'</div>',
    unsafe_allow_html=True
)

if not recent_activity:
    st.caption(
        "The latest log entry is more than 120 seconds old. "
        "Start Suricata capture to generate fresh events."
    )


# =========================================================
# HANDLE EMPTY DATA
# =========================================================

if df.empty:

    st.warning("No alert events have been recorded yet.")

    st.info(
        "Start Suricata capture, generate network activity, "
        "and click Refresh dashboard."
    )

    st.stop()


# =========================================================
# APPLY FILTERS
# =========================================================

filtered = df[
    df["Alert"].isin(selected_alerts)
    & df["Source IP"].isin(selected_sources)
].copy()

if filtered.empty:
    st.warning("No alerts match the selected filters.")
    st.stop()


# =========================================================
# SUMMARY COUNTS
# =========================================================

counts = filtered["Alert"].value_counts()

icmp_count = sum(
    count for name, count in counts.items()
    if "ICMP" in name
)

tcp_count = sum(
    count for name, count in counts.items()
    if "TCP SYN" in name
)

http_count = sum(
    count for name, count in counts.items()
    if "HTTP" in name
)

unique_sources = filtered["Source IP"].nunique()

short_names = {
    "NIDS ALERT - Possible TCP SYN Scan": "TCP SYN Scan",
    "NIDS ALERT - ICMP Ping Detected": "ICMP Ping",
    "NIDS ALERT - Suspicious HTTP Sensitive Path Access":
        "HTTP Admin Access"
}

chart_counts = counts.rename(index=short_names)

purple_colors = [
    "#8b5cf6",
    "#a78bfa",
    "#c084fc",
    "#e879f9",
    "#d8b4fe"
]


# =========================================================
# PLOTLY DARK THEME
# =========================================================

plot_layout = {
    "paper_bgcolor": "#15112b",
    "plot_bgcolor": "#15112b",
    "font": {
        "color": "#e8ddff",
        "family": "Arial",
        "size": 11
    },
    "margin": {
        "l": 20,
        "r": 20,
        "t": 25,
        "b": 30
    },
    "height": 330
}


# =========================================================
# SECURITY OVERVIEW
# =========================================================

if page == "Security Overview":

    st.markdown(
        '<div class="section-title">SECURITY OVERVIEW</div>'
        '<div class="section-subtitle">'
        'SECURITY METRICS & DETECTION SUMMARY'
        '</div>',
        unsafe_allow_html=True
    )

    kpis = [
        ("TOTAL ALERTS", len(filtered), "🚨", "Recorded detections"),
        ("ICMP EVENTS", icmp_count, "📡", "Ping activity"),
        ("TCP SYN EVENTS", tcp_count, "🌐", "SYN rule matches"),
        ("HTTP EVENTS", http_count, "🔎", "Sensitive path matches"),
        ("SOURCE IPs", unique_sources, "🖥️", "Unique alert sources")
    ]

    cols = st.columns(5)

    for col, (label, value, icon, foot) in zip(cols, kpis):

        with col:

            st.markdown(
                f'<div class="kpi-card">'
                f'<div class="kpi-icon">{icon}</div>'
                f'<div class="kpi-label">{label}</div>'
                f'<div class="kpi-value">{value:,}</div>'
                f'<div class="kpi-foot">{foot}</div>'
                f'</div>',
                unsafe_allow_html=True
            )

    st.markdown(
        '<div class="section-title">THREAT LANDSCAPE</div>',
        unsafe_allow_html=True
    )

    col1, col2, col3 = st.columns(3)

    # ALERT DISTRIBUTION

    with col1:

        st.markdown(
            '<div class="panel-title">ALERT DISTRIBUTION</div>',
            unsafe_allow_html=True
        )

        pie = go.Figure(go.Pie(
            labels=chart_counts.index,
            values=chart_counts.values,
            hole=0.65,
            textinfo="percent",
            marker=dict(
                colors=purple_colors,
                line=dict(color="#15112b", width=2)
            )
        ))

        pie.update_layout(
            **plot_layout,
            showlegend=True,
            legend=dict(
                orientation="h",
                y=-0.18,
                x=0.5,
                xanchor="center",
                font=dict(size=9, color="#e8ddff")
            )
        )

        st.plotly_chart(
            pie,
            use_container_width=True,
            config={"displayModeBar": False}
        )

    # ATTACK VECTORS

    with col2:

        st.markdown(
            '<div class="panel-title">ATTACK VECTORS</div>',
            unsafe_allow_html=True
        )

        bar_data = chart_counts.sort_values().reset_index()
        bar_data.columns = ["Alert Type", "Count"]

        bar = px.bar(
            bar_data,
            x="Count",
            y="Alert Type",
            orientation="h",
            color="Alert Type",
            color_discrete_sequence=purple_colors,
            text="Count"
        )

        bar.update_layout(
            **plot_layout,
            showlegend=False,
            xaxis=dict(
                title="Alert Count",
                gridcolor="#382653",
                color="#d8c9ef"
            ),
            yaxis=dict(
                title="",
                showgrid=False,
                color="#d8c9ef"
            )
        )

        bar.update_traces(
            textposition="outside",
            cliponaxis=False
        )

        st.plotly_chart(
            bar,
            use_container_width=True,
            config={"displayModeBar": False}
        )

    # SOURCE IP ACTIVITY

    with col3:

        st.markdown(
            '<div class="panel-title">SOURCE IP ACTIVITY</div>',
            unsafe_allow_html=True
        )

        ip_counts = filtered["Source IP"].value_counts().head(8)

        ip_labels = [
            "IPv6 local" if ":" in str(ip) else str(ip)
            for ip in ip_counts.index
        ]

        ip_chart = go.Figure(go.Bar(
            x=ip_counts.values,
            y=ip_labels,
            orientation="h",
            marker=dict(color="#a78bfa"),
            text=ip_counts.values,
            textposition="outside"
        ))

        ip_chart.update_layout(
            **plot_layout,
            xaxis=dict(
                title="Alert Count",
                gridcolor="#382653",
                color="#d8c9ef"
            ),
            yaxis=dict(
                title="",
                showgrid=False,
                autorange="reversed",
                color="#d8c9ef"
            )
        )

        st.plotly_chart(
            ip_chart,
            use_container_width=True,
            config={"displayModeBar": False}
        )

    # INFRASTRUCTURE HEALTH

    st.markdown(
        '<div class="section-title">INFRASTRUCTURE HEALTH</div>',
        unsafe_allow_html=True
    )

    packet_count = "N/A"

    if stats_event:

        packet_count = (
            stats_event.get("stats", {})
            .get("capture", {})
            .get("kernel_packets", "N/A")
        )

    health = [
        ("DETECTION ENGINE", "Suricata 8.0.8", "🛡️"),
        ("RECORDED FLOWS", f"{flow_count:,}", "🔗"),
        (
            "CAPTURED PACKETS",
            f"{packet_count:,}" if isinstance(packet_count, int)
            else str(packet_count),
            "📊"
        )
    ]

    cols = st.columns(3)

    for col, (label, value, icon) in zip(cols, health):

        with col:

            st.markdown(
                f'<div class="kpi-card">'
                f'<div class="kpi-icon">{icon}</div>'
                f'<div class="kpi-label">{label}</div>'
                f'<div class="kpi-value" style="font-size:23px">{value}</div>'
                f'</div>',
                unsafe_allow_html=True
            )


# =========================================================
# THREAT ANALYTICS
# =========================================================

elif page == "Threat Analytics":

    st.markdown(
        '<div class="section-title">THREAT ANALYTICS</div>',
        unsafe_allow_html=True
    )

    col1, col2 = st.columns(2)

    with col1:

        st.markdown(
            '<div class="panel-title">ALERT TYPE DISTRIBUTION</div>',
            unsafe_allow_html=True
        )

        pie = px.pie(
            values=chart_counts.values,
            names=chart_counts.index,
            hole=0.60,
            color_discrete_sequence=purple_colors
        )

        pie.update_layout(**plot_layout)

        st.plotly_chart(pie, use_container_width=True)

    with col2:

        st.markdown(
            '<div class="panel-title">ATTACK VECTOR COMPARISON</div>',
            unsafe_allow_html=True
        )

        attack = chart_counts.sort_values().reset_index()
        attack.columns = ["Alert Type", "Count"]

        fig = px.bar(
            attack,
            x="Count",
            y="Alert Type",
            orientation="h",
            color="Alert Type",
            color_discrete_sequence=purple_colors,
            text="Count"
        )

        fig.update_layout(
            **plot_layout,
            showlegend=False,
            xaxis=dict(
                title="Alert Count",
                gridcolor="#382653",
                color="#d8c9ef"
            ),
            yaxis=dict(
                title="",
                showgrid=False,
                color="#d8c9ef"
            )
        )

        fig.update_traces(textposition="outside")

        st.plotly_chart(fig, use_container_width=True)

    st.markdown(
        '<div class="panel-title">ALERT TREND OVER TIME</div>',
        unsafe_allow_html=True
    )

    trend = (
        filtered.dropna(subset=["Time"])
        .set_index("Time")
        .resample("1min")
        .size()
        .reset_index(name="Alerts")
    )

    if not trend.empty:

        line = px.area(
            trend,
            x="Time",
            y="Alerts",
            color_discrete_sequence=["#a78bfa"]
        )

        line.update_layout(
            **plot_layout,
            xaxis=dict(
                title="Time",
                gridcolor="#382653",
                color="#d8c9ef"
            ),
            yaxis=dict(
                title="Alerts",
                gridcolor="#382653",
                color="#d8c9ef"
            )
        )

        st.plotly_chart(line, use_container_width=True)


# =========================================================
# SECURITY EVENTS
# =========================================================

elif page == "Security Events":

    st.markdown(
        '<div class="section-title">SECURITY EVENT LOG</div>',
        unsafe_allow_html=True
    )

    st.caption("Most recent recorded alert events")

    events = filtered.sort_values(
        "Time",
        ascending=False
    ).head(rows_to_show)

    st.dataframe(
        events,
        use_container_width=True,
        hide_index=True,
        height=480
    )

    csv = filtered.to_csv(index=False).encode("utf-8")

    st.download_button(
        "⬇ Download security events CSV",
        data=csv,
        file_name="violet_shield_security_events.csv",
        mime="text/csv"
    )


# =========================================================
# SOURCE IP ANALYSIS
# =========================================================

elif page == "Source IP Analysis":

    st.markdown(
        '<div class="section-title">SOURCE IP ANALYSIS</div>',
        unsafe_allow_html=True
    )

    ip_summary = (
        filtered.groupby("Source IP")
        .size()
        .reset_index(name="Alert Count")
        .sort_values("Alert Count", ascending=False)
    )

    ip_chart = px.bar(
        ip_summary.head(15),
        x="Alert Count",
        y="Source IP",
        orientation="h",
        color="Alert Count",
        color_continuous_scale=[
            "#38205f",
            "#8b5cf6",
            "#e879f9"
        ],
        text="Alert Count"
    )

    ip_chart.update_layout(
        **plot_layout,
        coloraxis_showscale=False,
        xaxis=dict(
            title="Alert Count",
            gridcolor="#382653",
            color="#d8c9ef"
        ),
        yaxis=dict(
            title="Source IP",
            autorange="reversed",
            color="#d8c9ef"
        )
    )

    st.plotly_chart(
        ip_chart,
        use_container_width=True
    )

    st.markdown(
        '<div class="panel-title">SOURCE IP SUMMARY TABLE</div>',
        unsafe_allow_html=True
    )

    st.dataframe(
        ip_summary,
        use_container_width=True,
        hide_index=True
    )


# =========================================================
# FOOTER
# =========================================================

st.markdown(
    '<div class="footer">'
    '🛡️ VIOLET SHIELD • SECURITY OPERATIONS CENTER'
    '<br><br>POWERED BY SURICATA • PYTHON • STREAMLIT • PLOTLY'
    '<br><br>EDUCATIONAL NETWORK MONITORING PROJECT'
    '<br>Rule matches indicate detected patterns, not confirmed attacks.'
    '</div>',
    unsafe_allow_html=True
)
