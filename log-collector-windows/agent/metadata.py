import uuid

from datetime import datetime


DATE_FORMAT = "%d/%m/%Y %H:%M:%S"


def current_timestamp():
    """
    Return the current local system time.
    """

    return datetime.now().strftime(
        DATE_FORMAT
    )


def generate_event_id():
    """
    Generate a unique event ID.
    """

    return str(
        uuid.uuid4()
    )