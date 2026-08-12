import boto3
from datetime import datetime, timezone

from collector.config import (
    AWS_REGION,
    AWS_PROFILE
)


class CloudTrailReader:

    def __init__(self):

        session = boto3.Session(
            profile_name=AWS_PROFILE,
            region_name=AWS_REGION
        )

        self.client = session.client(
            "cloudtrail"
        )

    def get_events(
        self,
        start_time=None,
        max_results=50
    ):
        """
        Retrieve CloudTrail events.

        If start_time is provided, only events occurring
        from that time onward are requested.
        """

        params = {
            "MaxResults": max_results
        }

        if start_time:

            if isinstance(start_time, str):

                start_time = datetime.fromisoformat(
                    start_time
                )

            if start_time.tzinfo is None:

                start_time = start_time.replace(
                    tzinfo=timezone.utc
                )

            start_time = start_time.astimezone(
                timezone.utc
            )

            params["StartTime"] = start_time

        response = self.client.lookup_events(
            **params
        )

        events = response.get(
            "Events",
            []
        )

        # CloudTrail returns newest events first.
        # Process oldest → newest.
        events.sort(
            key=lambda event: event.get("EventTime")
        )

        return events