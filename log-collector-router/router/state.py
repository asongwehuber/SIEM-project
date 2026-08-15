import hashlib
import json
from pathlib import Path


STATE_FILE = (
    Path(__file__).resolve().parent.parent
    / "state"
    / "last_state.json"
)


def record_key(record):
    """
    Create a stable identity for a normalized router event.

    The identity represents the router session itself.
    State fields such as status and end_time are deliberately
    excluded so that changes to the same session can be detected.
    """

    details = record.get("details", {})

    identity = "|".join([
        str(details.get("pdp_name", "")),
        str(details.get("cid", "")),
        str(details.get("wan_index", "")),
        str(details.get("index", "")),
        str(details.get("start_time", "")),
        str(details.get("ipv4addr", "")),
        str(details.get("ipv6addr", "")),
    ])

    return hashlib.sha256(
        identity.encode("utf-8")
    ).hexdigest()


def load_state():
    """
    Load previously successfully processed router sessions.
    """

    if not STATE_FILE.exists():
        return {}

    try:
        with STATE_FILE.open(
            "r",
            encoding="utf-8"
        ) as file:

            return json.load(file)

    except (json.JSONDecodeError, OSError):

        return {}


def save_state(state):
    """
    Atomically save router session state.
    """

    STATE_FILE.parent.mkdir(
        parents=True,
        exist_ok=True
    )

    temporary_file = STATE_FILE.with_suffix(".tmp")

    with temporary_file.open(
        "w",
        encoding="utf-8"
    ) as file:

        json.dump(
            state,
            file,
            indent=4
        )

    temporary_file.replace(STATE_FILE)


def get_record_state(record):
    """
    Extract the state fields that should be remembered
    after successful delivery.
    """

    details = record.get("details", {})

    return {
        "end_time": details.get("end_time"),
        "status": details.get("status"),
    }


def detect_changes(records):
    """
    Compare current router records against saved state.

    State is NOT saved here.

    Returns:
        new_records
        updated_records
    """

    state = load_state()

    new_records = []
    updated_records = []

    for record in records:

        key = record_key(record)

        details = record.get("details", {})

        current_status = details.get("status")
        current_end_time = details.get("end_time")

        previous = state.get(key)

        # Completely new session.
        if previous is None:

            new_records.append(record)

            continue

        previous_status = previous.get("status")
        previous_end_time = previous.get("end_time")

        # Existing session changed.
        if (
            previous_status != current_status
            or previous_end_time != current_end_time
        ):

            updated_records.append(record)

    return new_records, updated_records


def commit_record(record):
    """
    Save the state of a router record only after
    successful delivery to the SIEM Agent.
    """

    state = load_state()

    key = record_key(record)

    state[key] = get_record_state(record)

    save_state(state)