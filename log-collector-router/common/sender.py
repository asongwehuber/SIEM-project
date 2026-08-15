import requests

from config import SIEM_AGENT_URL


def send_to_agent(log):
    """
    Send a formatted log to the SIEM Agent.

    Returns:
        response object on successful HTTP communication.

    Raises:
        requests.RequestException when the Agent cannot be reached.
    """

    url = f"{SIEM_AGENT_URL}/receive-log"

    response = requests.post(
        url,
        json=log,
        timeout=15
    )

    print(
        f"[HTTP] Status: {response.status_code}"
    )

    print(
        f"[HTTP] Response: {response.text}"
    )

    response.raise_for_status()

    return response