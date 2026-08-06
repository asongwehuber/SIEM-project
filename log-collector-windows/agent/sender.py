import json
import requests

from agent.config import Config


class Sender:
    """
    Sends logs and heartbeats to the SIEM Agent.
    """

    @staticmethod
    def post(endpoint, payload):

        try:

            response = requests.post(

                f"{Config.SIEM_AGENT_URL}/{endpoint}",

                json=payload,

                timeout=5

            )

            print(
                f"[{endpoint}]",
                response.status_code,
                response.text
            )

            return response

        except requests.exceptions.ConnectionError:

            print(
                "Unable to connect to SIEM Agent."
            )

        except Exception as error:

            print(error)