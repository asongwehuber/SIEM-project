import json

from agent.metadata import (
    current_timestamp,
    generate_event_id
)

from agent.security import (
    generate_signature
)


def create_log(
    generator_id,
    hostname,
    message
):
    """
    Create a standardized secure log.
    The message may be either:
      - a string
      - a dictionary
    """

    timestamp = current_timestamp()

    event_id = generate_event_id()

    if isinstance(message, dict):

        message_for_signature = json.dumps(

            message,

            sort_keys=True,

            separators=(",", ":")

        )

    else:

        message_for_signature = message

    payload = (
        f"{timestamp}|"
        f"{event_id}|"
        f"{generator_id}|"
        f"{hostname}|"
        f"{message_for_signature}"
    )

    signature = generate_signature(
        payload
    )

    return {

        "timestamp": timestamp,

        "event_id": event_id,

        "generator_id": generator_id,

        "hostname": hostname,

        "message": message,

        "signature": signature

    }