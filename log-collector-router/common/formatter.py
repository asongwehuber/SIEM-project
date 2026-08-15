import hashlib
import hmac
import json
import uuid
from datetime import datetime, timezone

from config import HMAC_SECRET


GENERATOR_ID = "router-mtn-homebox"


def _format_message(message):
    """
    Match the SIEM Agent's verifier exactly.

    Dictionaries must use:
        sort_keys=True
        separators=(",", ":")
    """

    if isinstance(message, dict):
        return json.dumps(
            message,
            sort_keys=True,
            separators=(",", ":")
        )

    return str(message)


def generate_signature(
    timestamp,
    event_id,
    generator_id,
    hostname,
    message
):
    """
    Generate the exact HMAC-SHA256 signature expected
    by the SIEM Agent.
    """

    message = _format_message(message)

    data = (
        f"{timestamp}|"
        f"{event_id}|"
        f"{generator_id}|"
        f"{hostname}|"
        f"{message}"
    )

    return hmac.new(
        HMAC_SECRET.encode(),
        data.encode(),
        hashlib.sha256
    ).hexdigest()


def format_router_log(record):
    """
    Convert a normalized MTN HomeBox record into the
    standard SIEM Agent log structure.

    The top-level timestamp is the collector timestamp.
    The original router event timestamps remain inside
    the message/details structure.
    """

    # Timestamp used by the SIEM Agent for freshness/replay
    # protection. This represents when the collector created
    # the event, not when the router session originally occurred.
    timestamp = datetime.now().strftime(
        "%d/%m/%Y %H:%M:%S"
    )

    event_id = str(uuid.uuid4())

    hostname = "mtn-homebox"

    message = {
        "source": record.get("source"),
        "event_type": record.get("event_type"),
        "event_category": record.get("event_category"),
        "message": record.get("message"),
        "details": record.get("details", {})
    }

    signature = generate_signature(
        timestamp=timestamp,
        event_id=event_id,
        generator_id=GENERATOR_ID,
        hostname=hostname,
        message=message
    )

    return {
        "timestamp": timestamp,
        "event_id": event_id,
        "generator_id": GENERATOR_ID,
        "hostname": hostname,
        "message": message,
        "signature": signature
    }