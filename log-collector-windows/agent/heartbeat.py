from agent.config import Config
from agent.metadata import current_timestamp
from agent.security import generate_signature
from agent.sender import Sender


def send_heartbeat():

    timestamp = current_timestamp()

    payload = (

        f"{timestamp}|"

        f"{Config.COLLECTOR_ID}|"

        f"{Config.HOSTNAME}"

    )

    signature = generate_signature(
        payload
    )

    heartbeat = {

        "type": "heartbeat",

        "timestamp": timestamp,

        "generator_id": Config.COLLECTOR_ID,

        "hostname": Config.HOSTNAME,

        "status": "online",

        "signature": signature

    }

    Sender.post(
        "receive-log",
        heartbeat
    )