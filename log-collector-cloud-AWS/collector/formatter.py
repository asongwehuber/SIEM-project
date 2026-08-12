import json
from datetime import datetime

from collector.config import COLLECTOR_ID


def format_log(parsed_event):
    """
    Convert a parsed CloudTrail event into the
    standard SIEM collector log format.
    """

    # IMPORTANT:
    # This is the timestamp used by the SIEM Agent
    # for replay protection and HMAC verification.
    timestamp = datetime.now().strftime(
        "%d/%m/%Y %H:%M:%S"
    )

    event_id = parsed_event["event_id"]

    hostname = (
        parsed_event.get("event_source")
        or "aws-cloudtrail"
    )

    message = json.dumps(
        {
            # Preserve the original AWS event time
            "event_time": (
                parsed_event.get("event_time").isoformat()
                if parsed_event.get("event_time")
                else None
            ),

            "event_name": parsed_event.get(
                "event_name"
            ),

            "event_source": parsed_event.get(
                "event_source"
            ),

            "username": parsed_event.get(
                "username"
            ),

            "user_type": parsed_event.get(
                "user_type"
            ),

            "source_ip": parsed_event.get(
                "source_ip"
            ),

            "aws_region": parsed_event.get(
                "aws_region"
            ),

            "read_only": parsed_event.get(
                "read_only"
            ),

            "request_parameters": parsed_event.get(
                "request_parameters"
            )
        },
        sort_keys=True
    )

    return {
        "timestamp": timestamp,
        "event_id": event_id,
        "generator_id": COLLECTOR_ID,
        "hostname": hostname,
        "message": message
    }