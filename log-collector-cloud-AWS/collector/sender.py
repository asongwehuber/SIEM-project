import hashlib
import hmac
import json

import requests

from collector.config import (
    SIEM_AGENT_URL,
    SECRET_KEY
)


def generate_signature(
    timestamp,
    event_id,
    generator_id,
    hostname,
    message
):
    """
    Generate HMAC-SHA256 signature compatible
    with the existing SIEM Agent.
    """

    if isinstance(message, dict):

        message = json.dumps(
            message,
            sort_keys=True,
            separators=(",", ":")
        )

    data = (
        f"{timestamp}|"
        f"{event_id}|"
        f"{generator_id}|"
        f"{hostname}|"
        f"{message}"
    )

    return hmac.new(
        SECRET_KEY.encode(),
        data.encode(),
        hashlib.sha256
    ).hexdigest()


def send_log(payload):
    """
    Sign and send a formatted log to the SIEM Agent.

    Returns:
        True  -> accepted
        False -> rejected or connection failed
    """

    payload = payload.copy()

    payload["signature"] = generate_signature(
        payload["timestamp"],
        payload["event_id"],
        payload["generator_id"],
        payload["hostname"],
        payload["message"]
    )

    try:

        response = requests.post(
            f"{SIEM_AGENT_URL}/receive-log",
            json=payload,
            timeout=10
        )

        if response.ok:

            print(
                f"[SENDER] Log accepted: "
                f"{response.status_code}"
            )

            return True

        print(
            f"[SENDER] SIEM Agent rejected log: "
            f"{response.status_code} "
            f"{response.text}"
        )

        return False

    except requests.RequestException as exc:

        print(
            f"[SENDER] Connection failed: "
            f"{exc}"
        )

        return False