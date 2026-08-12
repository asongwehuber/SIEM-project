# AWS CloudTrail Log Collector

A lightweight Python-based log collector that retrieves AWS CloudTrail events, parses and normalizes them into the SIEM project's standard log format, signs them using HMAC-SHA256, and securely forwards them to the SIEM Agent.

The collector is designed to run continuously on a Windows host and integrates directly into the existing SIEM pipeline.

---

## Architecture

```text
AWS CloudTrail
      |
      | boto3
      v
+---------------------------+
| AWS CloudTrail Collector  |
|                           |
| Reader                    |
| Parser                    |
| Formatter                 |
| HMAC Sender               |
| State Manager             |
+-------------+-------------+
              |
              | HTTPS/HTTP
              | HMAC-SHA256
              v
+---------------------------+
|       SIEM Agent          |
|                           |
| Signature Verification    |
| Timestamp Validation      |
| Replay Protection         |
| Duplicate Detection       |
| Log Normalization         |
+-------------+-------------+
              |
              v
+---------------------------+
|        Mini-SIEM          |
|                           |
| Detection Engine          |
| Alert Engine              |
| Database                  |
| Dashboard                 |
+---------------------------+