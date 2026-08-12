import json


def parse_event(event):
    """
    Parse a raw Boto3 CloudTrail event.

    Returns a normalized internal representation while
    preserving the original CloudTrail event.
    """

    cloudtrail_event = event.get(
        "CloudTrailEvent",
        "{}"
    )

    try:
        cloudtrail_data = json.loads(
            cloudtrail_event
        )

    except (TypeError, json.JSONDecodeError):

        cloudtrail_data = {}

    user_identity = cloudtrail_data.get(
        "userIdentity",
        {}
    )

    return {
        "event_id": event.get(
            "EventId"
        ),

        "event_name": event.get(
            "EventName"
        ),

        "event_source": event.get(
            "EventSource"
        ),

        "event_time": event.get(
            "EventTime"
        ),

        "username": event.get(
            "Username"
        ),

        "read_only": event.get(
            "ReadOnly"
        ),

        "aws_region": cloudtrail_data.get(
            "awsRegion"
        ),

        "source_ip": cloudtrail_data.get(
            "sourceIPAddress"
        ),

        "user_type": user_identity.get(
            "type"
        ),

        "user_arn": user_identity.get(
            "arn"
        ),

        "request_parameters": cloudtrail_data.get(
            "requestParameters"
        ),

        "original_event": cloudtrail_data
    }