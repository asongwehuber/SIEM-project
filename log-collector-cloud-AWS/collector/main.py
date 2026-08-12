import time

from collector.config import (
    POLL_INTERVAL,
    STATE_FILE
)

from collector.reader import CloudTrailReader
from collector.parser import parse_event
from collector.formatter import format_log
from collector.sender import send_log
from collector.state import StateManager


def main():

    print("========================================")
    print("       AWS CLOUDTRAIL LOG COLLECTOR")
    print("========================================")
    print(f"[CONFIG] State file: {STATE_FILE}")
    print(f"[CONFIG] Poll interval: {POLL_INTERVAL}s")
    print("========================================")

    reader = CloudTrailReader()

    state_manager = StateManager(
        STATE_FILE
    )

    # =====================================
    # LOAD PREVIOUS STATE
    # =====================================

    state = state_manager.load()

    if state:

        last_event_time = state.get(
            "last_event_time"
        )

        last_event_id = state.get(
            "last_event_id"
        )

        print("[STATE] Resuming from:")

        print(
            f"        Time: {last_event_time}"
        )

        print(
            f"        ID:   {last_event_id}"
        )

    else:

        last_event_time = None
        last_event_id = None

        print(
            "[STATE] No previous state found."
        )

        print(
            "[STATE] Starting from recent "
            "CloudTrail events."
        )

    print()
    print("[INFO] Collector started.")
    print(
        "[INFO] Waiting for CloudTrail events..."
    )

    # =====================================
    # CONTINUOUS COLLECTION LOOP
    # =====================================

    try:

        while True:

            try:

                events = reader.get_events(
                    start_time=last_event_time,
                    max_results=50
                )

            except Exception as exc:

                print(
                    f"[ERROR] CloudTrail query failed: "
                    f"{exc}"
                )

                print(
                    f"[RETRY] Retrying in "
                    f"{POLL_INTERVAL} seconds..."
                )

                time.sleep(
                    POLL_INTERVAL
                )

                continue

            # =================================
            # NO EVENTS
            # =================================

            if not events:

                print(
                    "[INFO] No CloudTrail events."
                )

                time.sleep(
                    POLL_INTERVAL
                )

                continue

            print(
                f"[INFO] Received "
                f"{len(events)} CloudTrail event(s)."
            )

            # =================================
            # PROCESS OLDEST → NEWEST
            # =================================

            for event in events:

                event_id = event.get(
                    "EventId"
                )

                event_time = event.get(
                    "EventTime"
                )

                if not event_id:
                    print(
                        "[WARNING] Event has no EventId. "
                        "Skipping."
                    )
                    continue

                if not event_time:
                    print(
                        "[WARNING] Event has no EventTime. "
                        "Skipping."
                    )
                    continue

                # ---------------------------------
                # Skip the exact checkpoint event
                # ---------------------------------

                if (
                    last_event_id
                    and
                    event_id == last_event_id
                ):

                    print(
                        f"[SKIP] Already processed: "
                        f"{event_id}"
                    )

                    continue

                # ---------------------------------
                # Skip events older than checkpoint
                # ---------------------------------

                if last_event_time:

                    event_time_string = (
                        event_time.isoformat()
                    )

                    if event_time_string < last_event_time:

                        print(
                            f"[SKIP] Older event: "
                            f"{event_id}"
                        )

                        continue

                # =================================
                # DISPLAY EVENT
                # =================================

                print()
                print(
                    "========================================"
                )

                print(
                    "[EVENT] New CloudTrail event"
                )

                print(
                    "========================================"
                )

                print(
                    f"Event ID: {event_id}"
                )

                print(
                    f"Event Name: "
                    f"{event.get('EventName')}"
                )

                print(
                    f"Event Time: {event_time}"
                )

                print(
                    f"Event Source: "
                    f"{event.get('EventSource')}"
                )

                print(
                    f"Username: "
                    f"{event.get('Username')}"
                )

                # =================================
                # PARSE
                # =================================

                parsed_event = parse_event(
                    event
                )

                # =================================
                # FORMAT
                # =================================

                formatted_log = format_log(
                    parsed_event
                )

                print(
                    f"[FORMAT] Event ID: "
                    f"{formatted_log['event_id']}"
                )

                # =================================
                # SEND
                # =================================

                success = send_log(
                    formatted_log
                )

                # =================================
                # SAVE STATE ONLY AFTER SUCCESS
                # =================================

                if success:

                    event_time_string = (
                        event_time.isoformat()
                    )

                    state_manager.save(
                        event_time_string,
                        event_id
                    )

                    last_event_time = (
                        event_time_string
                    )

                    last_event_id = event_id

                else:

                    print(
                        "[STATE] Position NOT saved "
                        "because log delivery failed."
                    )

                    print(
                        "[ERROR] Stopping current batch "
                        "so the event can be retried."
                    )

                    break

            time.sleep(
                POLL_INTERVAL
            )

    except KeyboardInterrupt:

        print(
            "\n[INFO] Collector stopped by user."
        )

    finally:

        print(
            "[INFO] Collector shutdown complete."
        )


if __name__ == "__main__":
    main()