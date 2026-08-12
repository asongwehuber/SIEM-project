import json
import os


class StateManager:
    def __init__(self, state_file):
        self.state_file = state_file

    def exists(self):
        """
        Return True if a saved state file exists.
        """

        return os.path.exists(self.state_file)

    def load(self):
        """
        Load the saved file position.

        Returns 0 if no state exists or the state
        cannot be read.
        """

        if not os.path.exists(self.state_file):
            return 0

        try:
            with open(self.state_file, "r") as file:
                state = json.load(file)

            return state.get("position", 0)

        except (json.JSONDecodeError, OSError):
            return 0

    def save(self, position):
        """
        Save the current file position.
        """

        directory = os.path.dirname(self.state_file)

        if directory:
            os.makedirs(directory, exist_ok=True)

        temp_file = self.state_file + ".tmp"

        with open(temp_file, "w") as file:
            json.dump(
                {
                    "position": position
                },
                file,
                indent=4
            )

        os.replace(temp_file, self.state_file)