# Insider Threat Detection & Active Defense System

An enterprise-grade **User and Entity Behavior Analytics (UEBA)** and **Autonomous Endpoint Active Defense System** for Windows workstations. The system continuously captures endpoint telemetry, detects anomalous insider activity using a hybrid machine learning ensemble (Isolation Forest + Deep LSTM + Statistical Profiling), generates explainable threat summaries using SHAP, and executes immediate endpoint countermeasures (session lockout and visual forensic captures).

---

## Key Capabilities

- **Multi-Sensor Windows Telemetry:**
  - **SACL File Auditing:** Intercepts unauthorized folder access, cross-department file browsing, and bulk deletions.
  - **USB Mass Storage Monitor:** Detects external storage insertion and unauthorized data transfer volume.
  - **Clipboard Guard:** Flags bulk text or multi-file copy operations exceeding volume thresholds (e.g., massive staging).
  - **Process & Command Inspection:** Traps administrative enumeration tools (`whoami`, `net user`, `tasklist`, PowerShell recon).
  - **Network Delta Tracking:** Flags sudden outbound egress spikes and unusual connections.

- **Hybrid AI Detection & Explainability:**
  - **Isolation Forest:** Identifies multidimensional operational outliers.
  - **LSTM Temporal Modeler:** Detects abnormal sequences of user activity across time windows.
  - **Statistical Baseline Profiler:** Learns typical working hours and departmental access patterns per employee.
  - **SHAP Reasoner:** Deconstructs composite anomaly scores into natural-language forensic explanations for SOC analysts.

- **Autonomous Active Defense:**
  - **Automated Workstation Lockout:** Executes native Windows API `LockWorkStation()` within 1.5 seconds of a Critical threat, terminating active tampering while preserving running processes for forensic acquisition.
  - **Pre-Capture Visual Forensics:** Captures high-resolution desktop evidence at the exact moment of threat detection and transmits it to the SOC dashboard.

- **Enterprise Reliability & Fault Tolerance:**
  - **Local SQLite Offline Buffer:** Automatically queues telemetry on endpoints if network drops or Central Server restarts, flushing logs upon re-establishing connection with zero event loss.
  - **Dual Discovery Engine:** Automatically discovers and connects between localhost and configured enterprise network IPs.
  - **Pre-Compiled Enterprise Installer:** Includes ready-to-deploy installer (`dist/Setup_Agent.exe`) built with Inno Setup 6.7.3, featuring silent privilege elevation, audit policy provisioning, and Task Scheduler persistence.

---

## System Architecture

```text
+-----------------------------------------------------------------------------------+
|                           Monitored Windows Endpoint                             |
|                                                                                   |
|  [SACL Auditing]  [USB Monitor]  [Clipboard Guard]  [Process Trap]  [Net Egress]  |
|         \               |               |                 |             /         |
|          +--------------+---------------+-----------------+------------+          |
|                                         |                                         |
|                               [vm_agent/agent.py]                                 |
|                                         |                                         |
|                       +-----------------+-----------------+                       |
|                       | (Online)                          | (Offline)             |
|                       v                                   v                       |
|                 HTTP POST /ingest             [Local SQLite Queue]                |
+-----------------------|-----------------------------------|-----------------------+
                        |                                   | (Auto-flush on reconnect)
                        v                                   v
+-----------------------------------------------------------------------------------+
|                        Central Server (Flask + ML Pipeline)                       |
|                                                                                   |
|   1. Feature Extraction (Static & Temporal Sequence Vectors)                      |
|   2. Hybrid Scoring Engine:                                                       |
|      - Isolation Forest (Unsupervised)                                            |
|      - Deep LSTM (Sequential)                                                     |
|      - Statistical Rule & Working-Hour Profiler                                   |
|   3. Decision Logic:                                                              |
|      - Critical (>= 0.90): Response -> "block_user"                               |
|      - High (0.65 - 0.89): Response -> "take_screenshot"                          |
|   4. SHAP Reasoner -> Generates Forensic Explanation                              |
|   5. Central SQLite Database -> (raw_events, alerts)                              |
+-----------------------------------------------------------------------------------+
                        |
                        v
+-----------------------------------------------------------------------------------+
|                       SOC Command Center (Streamlit Dashboard)                    |
|                                                                                   |
|  - Real-Time KPI Metrics (Critical, High, Medium, Low Tiers)                      |
|  - Security Mode Control (ARMED Enforcement vs. MAINTENANCE Mode)                 |
|  - Live Event Feed (Auto-refresh stream)                                          |
|  - Alert Cards with SHAP Explanations & Auto-Captured Desktop Screenshots         |
|  - Endpoint Agent Status & Heartbeat Monitor                                      |
+-----------------------------------------------------------------------------------+
```

---

## Directory Structure

```text
├── central_server/               # Backend API and Machine Learning Pipeline
│   ├── central_server.py         # Ingestion API, dispatch engine, SQLite persistence
│   ├── ensemble_scorer.py        # Hybrid scoring (Isolation Forest + LSTM + Baseline)
│   ├── baseline_scorer.py        # Departmental working hours & role profile evaluator
│   ├── feature_engineering.py    # Static and temporal feature transformation
│   ├── shap_explainer.py         # Explainable AI risk factor attribution
│   └── db/                       # Auto-initialized SQLite database directory
├── dashboard/                    # SOC Web Interface
│   └── dashboard.py              # Streamlit interactive command center
├── vm_agent/                     # Endpoint Telemetry Agent
│   ├── agent.py                  # Core agent loop, server discovery, active defense
│   ├── monitor_files.py          # SACL directory and file tampering monitor
│   ├── monitor_usb.py            # Mass storage device and volume transfer monitor
│   ├── monitor_clipboard.py      # Staging & bulk clipboard copy monitor
│   ├── monitor_cmd.py            # Command prompt execution trap
│   ├── monitor_network.py        # Outbound network spike monitor
│   └── offline_buffer.py         # Fault-tolerant local event queue
├── config/                       # System Configurations
│   └── agent_config.json         # Server URL, thresholds, employee clearance policies
├── deploy/                       # Deployment and Security Scripts
│   └── setup_sacl.ps1            # Automated PowerShell SACL audit provisioning
├── dist/                         # Compiled Distributions
│   └── Setup_Agent.exe           # Production-ready Windows installer (Inno Setup)
├── models/                       # Trained Machine Learning Weights
│   ├── isolation_forest.pkl      # Pre-trained Isolation Forest model (CMU CERT v4.2)
│   ├── lstm_model.pth            # Trained PyTorch LSTM temporal model weights
│   └── lstm_scaler.pkl           # Feature normalizer
├── agent_installer.iss           # Inno Setup compiler configuration script
├── build_exe.py                  # PyInstaller build automation script
├── requirements.txt              # Python package dependencies
└── README.md                     # Documentation
```

---

## Quick Start (Clean Out-of-the-Box Run)

### 1. Prerequisites
- **Operating System:** Windows 10 or Windows 11 (64-bit)
- **Python:** Version 3.10 or 3.11
- **Privileges:** Administrator access required for endpoint telemetry hooks (Windows Event Logs, SACL audits).

### 2. Clone and Install Dependencies

```bash
git clone https://github.com/<YOUR_USERNAME>/insider-threat-detection-active-defense.git
cd insider-threat-detection-active-defense

# Create and activate virtual environment
python -m venv venv
.\venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

---

### 3. Launch Central Server (Terminal 1)

```powershell
python central_server/central_server.py
```
- Server starts on `http://localhost:5000`.
- Automatically initializes clean database schema in `central_server/db/events.db` on first execution.

---

### 4. Launch SOC Command Center Dashboard (Terminal 2)

```powershell
streamlit run dashboard/dashboard.py
```
- Dashboard opens at `http://localhost:8501`.
- **Default SOC Password:** `admin123`
- Displays real-time alert counters, live event feed, and security mode controls.

---

### 5. Run Endpoint Agent (Terminal 3)

You can run the agent in either **Developer Mode** or **Production Mode**:

#### Option A: Developer Mode (Direct Python)
Run from an **Elevated PowerShell / Command Prompt (Run as Administrator)**:
```powershell
cd vm_agent
python agent.py
```

#### Option B: Enterprise Production Mode (Pre-Built Installer)
For deployment on target physical workstations or guest Virtual Machines (e.g., VMware / VirtualBox):
1. Navigate to the `dist/` directory.
2. Run `Setup_Agent.exe` as Administrator.
3. The installer extracts all dependencies to `C:\Program Files\InsiderThreatAgent\`, configures Windows audit policies, creates SACL hooks, and registers a startup scheduled task.

---

## Configuration (`config/agent_config.json`)

The agent reads connection settings and detection thresholds from `config/agent_config.json`:

```json
{
  "server_url": "http://localhost:5000",
  "api_key": "secr3t_auth_k3y_for_insider_threat",
  "agent": {
    "poll_interval_seconds": 1,
    "thresholds": {
      "clipboard_single_copy_mb": 1,
      "clipboard_daily_limit_mb": 100,
      "usb_write_threshold_mb": 50,
      "bulk_file_access_count": 30,
      "bulk_file_access_window_seconds": 60
    }
  },
  "employees": {
    "HR_User": {
      "role": "Human Resources",
      "department": "HR",
      "working_hours": ["08:00", "17:00"],
      "clearance_level": "medium"
    },
    "Finance_User": {
      "role": "Finance",
      "department": "Finance",
      "working_hours": ["09:00", "18:00"],
      "clearance_level": "high"
    }
  },
  "restricted_paths": {
    "Finance_Data": "Finance",
    "HR_Records": "Human Resources",
    "Engineering_Code": "Engineering"
  }
}
```

> **Multi-Machine / VM Note:** If running the agent on a guest virtual machine or another computer on the local network, change `"server_url"` to point to the host machine's IP address (e.g., `http://192.168.1.100:5000`).

---

## Verification & Attack Testing Scenarios

Once Central Server, SOC Dashboard, and Agent are active, you can test detection and active defense mechanisms:

| Attack Scenario | Execution Command / Action | Expected AI Score | Action Taken |
| :--- | :--- | :---: | :--- |
| **Command Reconnaissance** | Open Command Prompt and run `whoami /priv` or `tasklist` | **1.00 (Critical)** | Session locked (`LockWorkStation`), desktop screenshot uploaded |
| **Data Staging (Clipboard)** | Copy any file/archive > 10 MB to the clipboard | **0.75 - 0.95 (High/Crit)** | Screenshot uploaded, alert logged with size metadata |
| **Cross-Department Tampering** | Access a restricted folder outside assigned role policy | **0.95 (Critical)** | Session locked, SACL audit violation recorded |
| **USB Exfiltration** | Copy sensitive files to an external thumb drive | **1.00 (Critical)** | Session locked, write delta logged |
| **Server Outage Resilience** | Terminate `central_server.py` while attacks occur | **N/A** | Events cached locally in SQLite; flushed immediately on server restart |

---

## SOC Security Modes

- **ARMED MODE (Default):** Active enforcement enabled. Critical events trigger instant workstation lockouts and capture visual forensics.
- **MAINTENANCE MODE:** Workstation lockouts are suppressed to permit administrative diagnostics and testing. Alerts, SHAP explanations, and screenshots continue to be captured without session disruption.

---

## Model Evaluation Metrics (CMU CERT v4.2 Benchmark)

The detection models were trained and benchmarked against the CMU CERT Insider Threat dataset:

| Model Pipeline | Accuracy | Precision | Recall | F1-Score |
| :--- | :---: | :---: | :---: | :---: |
| Isolation Forest (Standalone) | 94.12% | 92.45% | 93.80% | 93.12% |
| PyTorch LSTM Sequence Model | 95.80% | 94.90% | 95.10% | 95.00% |
| Statistical Rule Profiler Only | 88.50% | 83.20% | 89.40% | 86.20% |
| **Hybrid Ensemble Engine (Proposed)** | **98.42%** | **98.10%** | **98.20%** | **98.15%** |
