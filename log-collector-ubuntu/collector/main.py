import time

from collector.config import (
    AUTH_LOG,
    STATE_FILE,
    POLL_INTERVAL
)

from collector.reader import LogReader
from collector.formatter import format_log
from collector.sender import send_log
from collector.state import StateManager


RETRY_DELAY = 5


def main():

    print("========================================")
    print("       UBUNTU LOG COLLECTOR")
    print("========================================")
    print(f"[CONFIG] Log file: {AUTH_LOG}")
    print(f"[CONFIG] State file: {STATE_FILE}")
    print("========================================")

    state_manager = StateManager(STATE_FILE)

    if state_manager.exists():

        start_position = state_manager.load()

        print(
            f"[STATE] Resuming from position: "
            f"{start_position}"
        )

    else:

        start_position = None

        print(
            "[STATE] No previous state found. "
            "Starting from the current end of the log."
        )

    reader = LogReader(
        filepath=AUTH_LOG,
        poll_interval=POLL_INTERVAL,
        start_position=start_position
    )

    print("[INFO] Collector started.")
    print("[INFO] Waiting for new Linux log entries...")

    try:

        for raw_log in reader.follow():


            position = reader.get_position()
            inode = reader.get_inode()

            print("\n[LOG] New log detected:")
            print(raw_log)

            formatted_log = format_log(
                raw_log,
                position,
                inode
            )


            print(
                f"[FORMAT] Event ID: "
                f"{formatted_log['event_id']}"
            )

            # =================================
            # SEND LOG
            # =================================

            while True:

                result = send_log(
                    formatted_log
                )

                # =================================
                # SUCCESS
                # =================================

                if result == "success":

                    state_manager.save(
                        position
                    )

                    print(
                        f"[STATE] Saved position: "
                        f"{position}"
                    )

                    break

                # =================================
                # DUPLICATE EVENT
                # =================================

                if result == "duplicate":

                    state_manager.save(
                        position
                    )

                    print(
                        f"[STATE] Event already exists "
                        f"in SIEM. Position saved: "
                        f"{position}"
                    )

                    break

                # =================================
                # TEMPORARY FAILURE
                # =================================

                if result == "retry":

                    print(
                        "[STATE] Position NOT saved "
                        "because log delivery failed."
                    )

                    print(
                        f"[RETRY] Retrying in "
                        f"{RETRY_DELAY} seconds..."
                    )

                    time.sleep(
                        RETRY_DELAY
                    )

                    continue

                # =================================
                # PERMANENT REJECTION
                # =================================

                if result == "rejected":

                    print(
                        "[ERROR] Log permanently rejected "
                        "by SIEM Agent."
                    )

                    print(
                        "[ERROR] Position NOT saved."
                    )

                    break

    except KeyboardInterrupt:

        print(
            "\n[INFO] Collector stopped by user."
        )

    finally:

        if reader.file is not None:
            reader.file.close()

        print(
            "[INFO] Collector shutdown complete."
        )


if __name__ == "__main__":
    main()