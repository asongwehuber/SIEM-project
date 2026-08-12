# Windows Log Collector

A lightweight Windows Security Event Log collector designed for the Mini SIEM ecosystem. The collector monitors Windows Security events, converts them into a standardized JSON format, signs each log using HMAC-SHA256, and securely forwards them to the SIEM Agent for verification, normalization, and ingestion into the Mini SIEM platform.

---

## Features

- Collects Windows Security Event Logs using the Windows Event Log API.
- Parses XML-based Windows events into structured JSON.
- Filters only security-relevant Windows Event IDs.
- Generates standardized log messages.
- Signs every log using HMAC-SHA256.
- Sends logs securely to the SIEM Agent.
- Supports configurable polling intervals.
- Includes heartbeat support for machine availability monitoring.
- Easily configurable using environment variables.

---

## Project Structure

```
log-collector-windows/
│
├── agent/
│   ├── bookmark.py
│   ├── bookmark_reader.py
│   ├── collector.py
│   ├── config.py
│   ├── event_filter.py
│   ├── event_reader.py
│   ├── heartbeat.py
│   ├── json_formatter.py
│   ├── metadata.py
│   ├── security.py
│   ├── sender.py
│   └── xml_parser.py
│
├── requirements.txt
├── run.py
├── .env.example
└── README.md
```

---

## Requirements

- Windows 10 or later
- Python 3.10+
- pywin32
- requests
- python-dotenv

---

## Installation

Clone the repository and install the required dependencies.

```bash
pip install -r requirements.txt
```

---

## Configuration

Create a `.env` file from `.env.example`.

Example:

```env
SIEM_AGENT_URL=http://192.168.56.1:6000
SECRET_KEY=your_shared_secret
COLLECTOR_ID=windows-1
HEARTBEAT_INTERVAL=30
POLL_INTERVAL=2
```

---

## Running the Collector

```bash
python run.py
```

The collector will continuously monitor the Windows Security Event Log and forward selected events to the configured SIEM Agent.

---

## Windows Event IDs Collected

The collector currently monitors common security-related Windows events including:

| Event ID | Description |
|----------|-------------|
| 1102 | Security log cleared |
| 4624 | Successful logon |
| 4625 | Failed logon |
| 4634 | Logoff |
| 4648 | Explicit credentials |
| 4672 | Special privileges assigned |
| 4688 | Process created |
| 4689 | Process terminated |
| 4719 | Audit policy changed |
| 4720 | User account created |
| 4722 | User account enabled |
| 4723 | Password change attempt |
| 4724 | Password reset |
| 4725 | User account disabled |
| 4726 | User account deleted |
| 4732 | User added to security group |
| 4733 | User removed from security group |
| 4740 | Account locked |
| 4768 | Kerberos TGT requested |
| 4769 | Kerberos service ticket requested |
| 4771 | Kerberos pre-authentication failed |
| 4776 | NTLM authentication |
| 5156 | Connection allowed |
| 5157 | Connection blocked |

---

## Log Processing Workflow

```
Windows Security Event Log
            │
            ▼
 Windows Log Collector
            │
            ▼
     XML Event Parser
            │
            ▼
     Event Filtering
            │
            ▼
 JSON Formatter + HMAC Signature
            │
            ▼
       SIEM Agent
            │
            ▼
     Mini SIEM Platform
```

---

## Security

Every collected log is digitally signed using HMAC-SHA256 before transmission. The SIEM Agent verifies the signature before processing the log, ensuring authenticity and integrity.

---

## Related Components

This collector is part of the Mini SIEM ecosystem:

- **Mini SIEM** – Web dashboard, detection engine, alerting, reporting, and AI-assisted analysis.
- **SIEM Agent** – Secure log receiver, verifier, and normalizer.
- **Log Generator** – Simulated log sources for testing and demonstrations.
- **Linux Log Collector** – Collects security events from Linux systems (planned).

---

## License

This project is intended for educational, research, and cybersecurity demonstration purposes.