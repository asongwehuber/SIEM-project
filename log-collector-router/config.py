import os
from dotenv import load_dotenv

load_dotenv()


ROUTER_URL = os.getenv("ROUTER_URL", "http://192.168.1.1").rstrip("/")

ROUTER_USERNAME = os.getenv("ROUTER_USERNAME", "")
ROUTER_PASSWORD = os.getenv("ROUTER_PASSWORD", "")

SIEM_AGENT_URL = os.getenv(
    "SIEM_AGENT_URL",
    "http://127.0.0.1:6000"
).rstrip("/")

HMAC_SECRET = os.getenv("HMAC_SECRET", "")

POLL_INTERVAL = int(os.getenv("POLL_INTERVAL", "30"))

ROUTER_VERIFY_SSL = (
    os.getenv("ROUTER_VERIFY_SSL", "false").lower() == "true"
)