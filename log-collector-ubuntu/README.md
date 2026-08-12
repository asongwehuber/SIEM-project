# Ubuntu Linux Log Collector

A lightweight Linux log collector designed to collect authentication and system security logs from an Ubuntu machine and securely forward them to the SIEM Agent.

The collector continuously monitors `/var/log/auth.log`, formats new log entries into a standardized SIEM event structure, signs them using HMAC-SHA256, and sends them to the SIEM Agent over HTTP.

---

## Architecture

```text
┌──────────────────────────────┐
│        Ubuntu Machine        │
│                              │
│      /var/log/auth.log       │
│              │               │
│              ▼               │
│        Log Reader            │
│              │               │
│              ▼               │
│        Log Formatter         │
│              │               │
│              ▼               │
│       HMAC-SHA256 Signer     │
│              │               │
└──────────────┼───────────────┘
               │
               │ HTTP POST
               │ /receive-log
               ▼
┌──────────────────────────────┐
│          SIEM Agent          │
│                              │
│ Signature Verification       │
│ Replay Protection            │
│ Duplicate Detection          │
│ Log Normalization             │
└──────────────┬───────────────┘
               │
               ▼
        Mini-SIEM Application