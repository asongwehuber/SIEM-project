from datetime import datetime
from collector.config import COLLECTOR_ID, HOSTNAME


def format_log(raw_log, position, inode):
    """
    Convert a raw Linux log line into the standard SIEM format.

    The event ID is deterministic:
    collector ID + log file position.

    This ensures the same log record gets the same event ID
    across retries and collector restarts.
    """

    timestamp = datetime.now().strftime(
        "%d/%m/%Y %H:%M:%S"
    )

    event_id = (
        f"{COLLECTOR_ID}-"
        f"{inode}-"
        f"{position}"
    )

    return {
        "timestamp": timestamp,
        "event_id": event_id,
        "generator_id": COLLECTOR_ID,
        "hostname": HOSTNAME,
        "message": raw_log
    }