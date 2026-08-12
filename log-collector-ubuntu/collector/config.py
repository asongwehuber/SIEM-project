import os
import socket

from dotenv import load_dotenv


load_dotenv()


SIEM_AGENT_URL = os.getenv(
    "SIEM_AGENT_URL"
)

SECRET_KEY = os.getenv(
    "SECRET_KEY"
)

COLLECTOR_ID = os.getenv(
    "COLLECTOR_ID",
    "ubuntu-1"
)

POLL_INTERVAL = float(
    os.getenv(
        "POLL_INTERVAL",
        "1"
    )
)

AUTH_LOG = os.getenv(
    "AUTH_LOG",
    "/var/log/auth.log"
)

SYSLOG = os.getenv(
    "SYSLOG",
    "/var/log/syslog"
)

STATE_FILE = os.getenv(
    "STATE_FILE",
    "state.json"
)

HOSTNAME = socket.gethostname()


if not SIEM_AGENT_URL:
    raise RuntimeError(
        "SIEM_AGENT_URL is not configured"
    )


if not SECRET_KEY:
    raise RuntimeError(
        "SECRET_KEY is not configured"
    )