import json
import os


class StateManager:

    def __init__(self, filepath):
        self.filepath = filepath

    def exists(self):
        return os.path.exists(self.filepath)

    def load(self):
        """
        Load the last successfully processed CloudTrail event.

        Returns:
            dict with last_event_time and last_event_id,
            or None if no valid state exists.
        """

        if not self.exists():
            return None

        try:
            with open(
                self.filepath,
                "r",
                encoding="utf-8"
            ) as file:

                state = json.load(file)

            return {
                "last_event_time": state.get(
                    "last_event_time"
                ),
                "last_event_id": state.get(
                    "last_event_id"
                )
            }

        except (
            json.JSONDecodeError,
            OSError
        ) as exc:

            print(
                f"[STATE] Failed to load state: {exc}"
            )

            return None

    def save(
        self,
        event_time,
        event_id
    ):
        """
        Save the latest successfully processed
        CloudTrail event.
        """

        state = {
            "last_event_time": event_time,
            "last_event_id": event_id
        }

        try:

            with open(
                self.filepath,
                "w",
                encoding="utf-8"
            ) as file:

                json.dump(
                    state,
                    file,
                    indent=4
                )

            print(
                "[STATE] Saved event:"
            )

            print(
                f"        Time: {event_time}"
            )

            print(
                f"        ID:   {event_id}"
            )

        except OSError as exc:

            print(
                f"[STATE] Failed to save state: {exc}"
            )