import json
import hashlib
import hmac

from agent.config import Config


def generate_signature(message):
    """
    Generate an HMAC-SHA256 signature.
    Supports both string and dictionary messages.
    """

    if isinstance(message, dict):

        message = json.dumps(
            message,
            sort_keys=True,
            separators=(",", ":")
        )

    return hmac.new(

        Config.SECRET_KEY.encode(),

        message.encode(),

        hashlib.sha256

    ).hexdigest()