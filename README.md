# SentinelNode — Enterprise Network Traffic Analysis & IDS Platform

<div align="center">

![Python](https://img.shields.io/badge/Python-3.8%2B-3776AB?style=for-the-badge&logo=python&logoColor=white)
![Flask](https://img.shields.io/badge/Flask-3.x-000000?style=for-the-badge&logo=flask&logoColor=white)
![Scapy](https://img.shields.io/badge/Scapy-2.7-4EAA25?style=for-the-badge)
![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux-0078D4?style=for-the-badge&logo=windows&logoColor=white)
![License](https://img.shields.io/github/license/EONRaider/Packet-Sniffer?style=for-the-badge)
![Status](https://img.shields.io/badge/Status-Production--Ready-00e5a0?style=for-the-badge)

**A production-grade Network Operations & Security Monitoring Platform**  
*Real-time packet capture · Multi-level intrusion detection · Live analytics dashboard*

</div>

---

## 🔍 Overview

**SentinelNode** is a professional-grade Network Traffic Analysis and Intrusion Detection System (IDS) built for security engineers, network operations teams, and research environments. It transforms raw network traffic into actionable security intelligence through real-time packet inspection, behavioral anomaly detection, and live visual analytics — all served through a sleek, enterprise-class web dashboard.

The platform is architected as two tightly integrated components:

| Component | Purpose |
|-----------|---------|
| `packet_sniffer/` | Reusable Python library — capture, analysis, detection, logging |
| `webapp/` | Flask-powered web dashboard — real-time UI, charts, alert console |

---

## ✨ Feature Highlights

### 🛡️ Intrusion Detection Engine
- **4-Level Severity Classification**: `CRITICAL` → `HIGH` → `MEDIUM` → `LOW`
- **DDoS Pattern Detection**: Sliding time-window analysis flags IP addresses exceeding configurable packet-rate thresholds
- **Non-Standard Port Detection**: Identifies traffic on ephemeral and suspicious ports outside known service ranges
- **Unknown Protocol Flagging**: Detects and alerts on unrecognized or unexpected protocol usage
- **Real-Time Alert Console**: Color-coded security event log with source metadata

### 📊 Live Analytics Dashboard
- **Traffic Volume Timeline**: Packets-per-second line chart updating in real time
- **Protocol Distribution**: Doughnut chart showing TCP / UDP / ICMP / HTTP / HTTPS breakdown
- **Alert Severity Distribution**: Bar chart across all 4 severity tiers
- **KPI Cards**: Instant readout of packet count, critical alerts, high/medium events

### 🔄 Dual Capture Modes
| Mode | Description |
|------|-------------|
| **Live Capture** | Raw socket capture via Scapy on a selected network interface |
| **Simulation** | Synthetic traffic generator producing realistic patterns including attack bursts |

### 📝 Structured Event Logging
Every detected packet is logged to `logs/traffic.log` with full forensic metadata:
```
2026-04-05 17:00:00 | SRC=192.168.1.42    | DST=203.0.113.5   | PROTO=TCP    | PORT=443   | SEVERITY=SAFE
2026-04-05 17:00:01 | SRC=203.0.113.99    | DST=192.168.1.10  | PROTO=UDP    | PORT=4444  | SEVERITY=CRITICAL
```

---

## 🏗️ Architecture

```
Packet-Sniffer/
│
├── packet_sniffer/              # Core networking library (reusable)
│   ├── __init__.py              # Public package API
│   ├── sniffer.py               # Capture engine + IDS pipeline orchestrator
│   ├── analyzer.py              # Deep packet inspection (Scapy layer decode)
│   ├── alert_engine.py          # Multi-severity IDS rule engine
│   ├── logger.py                # Structured forensic event logger
│   └── simulator.py             # Synthetic traffic generator
│
├── webapp/                      # Web dashboard (Flask)
│   ├── app.py                   # REST API backend
│   ├── templates/
│   │   └── index.html           # Enterprise dashboard UI
│   └── static/
│       ├── style.css            # Premium dark UI stylesheet
│       └── script.js            # Real-time data engine + Chart.js
│
├── logs/
│   └── traffic.log              # Persistent structured event log
│
├── requirements.txt
├── pyproject.toml
└── README.md
```

### Data Flow
```
Network Interface / Simulator
         │
         ▼
    PacketAnalyzer          ← Decodes IP, TCP, UDP, ICMP headers
         │
         ▼
    AlertEngine             ← Applies IDS rules, assigns severity
         │
    ┌────┴────┐
    ▼         ▼
TrafficLogger  NetworkSniffer.packet_queue
(logs/traffic.log)          │
                             ▼
                       Flask REST API
                             │
                             ▼
                    Browser Dashboard
                  (Charts · Table · Alerts)
```

---

## ⚙️ Setup Instructions

### Prerequisites

| Requirement | Notes |
|-------------|-------|
| Python 3.8+ | Tested on 3.11 |
| pip | Included with Python |
| Npcap (Windows) | Required for **Live Capture** mode only |
| Admin / Root | Required for raw socket access |

**Windows only — Install Npcap for live capture:**  
👉 [https://nmap.org/npcap/](https://nmap.org/npcap/) — check *"WinPcap API-compatible Mode"*

---

### Installation

```bash
# 1. Clone the repository
git clone https://github.com/Yeshaswini-9848/Sentinel-Node
cd Packet-Sniffer

# 2. Create a virtual environment (Python 3.11 recommended on Windows)
py -3.11 -m venv venv

# 3. Activate the environment
# Windows:
venv\Scripts\activate
# Linux / macOS:
source venv/bin/activate

# 4. Install dependencies
pip install -r requirements.txt
```

---

### Running the Platform

```bash
# From the project root (with venv active):
cd webapp
python app.py
```

Open your browser:  
👉 **[http://127.0.0.1:5000](http://127.0.0.1:5000)**

---

### First Use — Quick Start

1. The dashboard loads in **idle** state
2. Select **Traffic Source Mode**:
   - **Simulation** — works immediately, no Npcap needed *(recommended for first run)*
   - **Live Capture** — requires Npcap + admin privileges
3. Click **Start Monitoring**
4. Watch the traffic table, charts, and alert console populate in real time

---

## 📡 REST API Reference

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/` | Dashboard UI |
| `POST` | `/api/start_monitoring` | Start capture/simulation |
| `POST` | `/api/stop_monitoring` | Stop active session |
| `GET` | `/api/traffic_data` | Latest 50 packets + aggregate stats |
| `GET` | `/api/status` | Lightweight heartbeat / status |

**`POST /api/start_monitoring` — payload:**
```json
{
  "simulate": true,
  "interface": "eth0"
}
```

---

## 🔐 IDS Rule Reference

| Rule | Severity | Trigger |
|------|----------|---------|
| High-Frequency Flood | `CRITICAL` | Source IP exceeds 2× rate threshold in sliding window |
| Elevated Traffic Volume | `HIGH` | Source IP exceeds rate threshold |
| Non-Standard Port Usage | `MEDIUM` | Traffic on registered but non-standard ports (1024–49151) |
| Ephemeral Port Usage | `LOW` | Traffic on dynamic ports (49152–65535) |
| Unknown Protocol | `MEDIUM` | Protocol not in known set |

---

## 🌐 Real-World Use Cases

### 1. Enterprise Network Monitoring
Deploy SentinelNode at a network perimeter to continuously monitor ingress/egress traffic volumes, detect abnormal communication patterns, and maintain a structured audit trail for compliance reporting.

### 2. Security Operations Centre (SOC) Analysis
Use the real-time alert console and severity classification to triage security events, prioritize incident response, and correlate attack vectors from IP behavioral analysis.

### 3. Intrusion Detection & Threat Hunting
The sliding-window DDoS detection and suspicious port alerting provide lightweight IDS functionality suitable for internal network segments where full SIEM tooling is not deployed.

### 4. Network Research & Education
The simulation mode generates realistic traffic patterns (including attack scenarios) making SentinelNode ideal for cybersecurity training, lab exercises, and academic demonstrations without requiring a live network environment.

### 5. Portfolio & Client Demonstration
The professional UI with live charts, color-coded severity levels, and structured logs makes SentinelNode suitable for showcasing network engineering and security capabilities to technical interviewers and clients.

