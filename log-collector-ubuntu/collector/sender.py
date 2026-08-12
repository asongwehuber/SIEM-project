import hashlib
import hmac
import json

import requests

from collector.config import SIEM_AGENT_URL, SECRET_KEY


def generate_signature(
    timestamp,
    event_id,
    generator_id,
    hostname,
    message
):
    """
    Generate an HMAC-SHA256 signature compatible
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
    Sign and send a log to the SIEM Agent.

    Returns:

        "success"
            Log accepted by SIEM Agent.

        "retry"
            Temporary communication/server failure.
            The collector should retry.

        "duplicate"
            SIEM Agent already has this event.
            Treat it as successfully delivered.

        "rejected"
            Permanent rejection.
            Do not retry indefinitely.
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

        # ==========================================
        # SUCCESS
        # ==========================================

        if response.status_code == 200:

            print(
                f"[SENDER] Log accepted: "
                f"{response.status_code}"
            )

            return "success"

        # ==========================================
        # DUPLICATE EVENT
        # ==========================================

        if response.status_code == 401:

            try:
                data = response.json()
            except ValueError:
                data = {}

            reason = data.get("reason", "")

            if reason == "Duplicate event":

                print(
                    "[SENDER] Event already exists "
                    "in SIEM Agent. Treating as delivered."
                )

                return "duplicate"

            print(
                f"[SENDER] Permanent rejection: "
                f"{response.status_code} "
                f"{response.text}"
            )

            return "rejected"

        # ==========================================
        # TEMPORARY SERVER ERROR
        # ==========================================

        if response.status_code >= 500:

            print(
                f"[SENDER] SIEM Agent server error: "
                f"{response.status_code} "
                f"{response.text}"
            )

            return "retry"

        # ==========================================
        # OTHER PERMANENT REJECTION
        # ==========================================

        print(
            f"[SENDER] SIEM Agent rejected log: "
            f"{response.status_code} "
            f"{response.text}"
        )

        return "rejected"

    except requests.RequestException as exc:

        print(
            f"[SENDER] Connection failed: {exc}"
        )

        return "retry"