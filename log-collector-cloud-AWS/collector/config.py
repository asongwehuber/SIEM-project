import os

from dotenv import load_dotenv


load_dotenv()


AWS_REGION = os.getenv(
    "AWS_REGION",
    "us-east-1"
)


AWS_PROFILE = os.getenv(
    "AWS_PROFILE",
    "siem-cloud-collector"
)


COLLECTOR_ID = os.getenv(
    "COLLECTOR_ID",
    "aws-cloudtrail-1"
)


POLL_INTERVAL = int(
    os.getenv(
        "POLL_INTERVAL",
        "30"
    )
)


STATE_FILE = os.getenv(
    "STATE_FILE",
    "state.json"
)


SIEM_AGENT_URL = os.getenv(
    "SIEM_AGENT_URL"
)


SECRET_KEY = os.getenv(
    "SECRET_KEY"
)


if not SIEM_AGENT_URL:
    raise RuntimeError(
        "SIEM_AGENT_URL is not configured"
    )


if not SECRET_KEY:
    raise RuntimeError(
        "SECRET_KEY is not configured"
    )