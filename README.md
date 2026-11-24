# Network Intrusion Detection System (NIDS) – VIOLET SHIELD

## Internship

**CodSoft Cyber Security Internship – Task 4**

## Project Overview

VIOLET SHIELD is a Network Intrusion Detection System (NIDS) developed using Suricata, Python, and Streamlit.

The project aims to monitor network activity, identify suspicious traffic patterns, and detect potential security threats using custom Suricata detection rules.

Suricata generates security events, which are stored in the `eve.json` log file. A Python-based Streamlit dashboard reads these events and presents security information through charts, metrics, and event tables.

The project provides practical experience in network monitoring, intrusion detection, security event analysis, and cybersecurity tools.

## Objectives

- Understand the fundamentals of Network Intrusion Detection Systems.
- Install and configure Suricata for network monitoring.
- Create and configure custom detection rules.
- Analyse network traffic and security events.
- Identify suspicious network activity through alerts.
- Visualise detected events using a dashboard.

## Tools and Technologies

| Tool / Technology | Purpose |
|---|---|
| Suricata 8.0.8 | Network intrusion detection |
| Python | Log processing and application development |
| Streamlit | Interactive security dashboard |
| Pandas | Data processing and analysis |
| Plotly | Data visualisation and charts |
| Windows | Development and monitoring environment |
| Visual Studio Code | Code development and editing |
| Npcap | Windows packet capture support |

## Key Features

### 1. Network Intrusion Detection
Uses Suricata to monitor network traffic and generate alerts based on configured detection rules.

### 2. Custom Detection Rules
Includes rules for detecting:
- ICMP ping activity.
- TCP SYN packets matching the configured detection rule.
- HTTP requests accessing the `/admin` path.

### 3. Security Dashboard
The VIOLET SHIELD dashboard provides four main sections:

- **Security Overview:** Displays total alerts, ICMP events, TCP SYN events, HTTP events, and unique source IP addresses.
- **Threat Analytics:** Visualises alert distribution, attack patterns, and alert trends.
- **Security Events:** Displays recorded alerts with timestamps, source IPs, destination IPs, protocols, and severity.
- **Source IP Analysis:** Displays and analyses source IP addresses associated with detected alerts.

### 4. Alert Filtering
Allows users to filter security events by alert type and source IP address.

### 5. CSV Export
Allows users to download security event records in CSV format for further analysis.

### 6. Manual Dashboard Refresh
Allows users to reload the latest Suricata log data when required.

## Project Structure

```text
TASK4_Network_Intrusion_Detection/
│
├── dashboard.py
│
├── rules/
│   └── local.rules
│
├── logs/
│   ├── eve.json
│   ├── fast.log
│   └── response_report.txt
│
├── response_action.py
│
├── requirements.txt
│
├── .gitignore
│
└── README.md
```

*Note: Log files are generated during monitoring and may be excluded from the GitHub repository.*

## Installation and Setup

### Prerequisites

- Python installed on Windows.
- Suricata installed and configured.
- Npcap installed for packet capture where required.
- Visual Studio Code or another Python editor.

### Step 1: Clone the Repository

```bash
git clone YOUR_GITHUB_REPOSITORY_URL
```

### Step 2: Open the Project Folder

```bash
cd TASK4_Network_Intrusion_Detection
```

### Step 3: Install Dependencies

```bash
pip install -r requirements.txt
```

### Step 4: Configure Suricata

Install and configure Suricata for your network interface.

Ensure that the Suricata configuration generates the `eve.json` file inside the project's `logs` directory.

Configure the custom detection rules in:

```text
rules/local.rules
```

### Step 5: Start Network Monitoring

Start Suricata with the appropriate configuration and detection rules for your system.

Generate network activity to test the configured detection rules.

### Step 6: Run the Dashboard

Open the project terminal and execute:

```bash
streamlit run dashboard.py
```

The VIOLET SHIELD dashboard will open in your default web browser.

Use the manual refresh button to load the latest recorded events.

## Detection Rules

The project uses custom Suricata rules to identify selected network traffic patterns.

| Detection Rule | Description |
|---|---|
| ICMP Ping Detection | Detects ICMP ping activity. |
| TCP SYN Detection | Matches TCP SYN packets according to the configured rule. |
| HTTP Sensitive Path Detection | Detects HTTP requests accessing the `/admin` path. |

**Note:** A rule match indicates that traffic matched a configured detection pattern. It does not automatically confirm a malicious attack. TCP SYN alerts, for example, can also occur during normal network connections.

## Project Outcome

This project demonstrates the practical implementation of network intrusion detection using Suricata and Python.

It provides experience in configuring detection rules, analysing security logs, understanding network traffic, and developing a dashboard for security event monitoring.

## Limitations

- Detection depends on the configured Suricata rules.
- The dashboard displays events recorded in the Suricata log file.
- New events appear after a manual refresh or another normal dashboard interaction.
- Detection alerts require further investigation before being classified as confirmed attacks.
- The response script records alert information; it does not automatically block network traffic.

## Author

**Siddhi Sunil Sakpal**

M.Sc. Computer Science – Cyber Security

**Internship:** CodSoft Cyber Security Internship

---

**VIOLET SHIELD – Monitor. Detect. Analyse.**