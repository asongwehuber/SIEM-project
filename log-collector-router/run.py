import time

from config import POLL_INTERVAL

from router.client import RouterClient
from router.parser import parse_network_activity
from router.normalizer import normalize_network_activity
from router.state import (
    detect_changes,
    commit_record
)

from common.formatter import format_router_log
from common.sender import send_to_agent


def collect_once():
    """
    Perform one complete router collection cycle.
    """

    print("\n" + "=" * 60)
    print("[COLLECTOR] Starting router collection")
    print("=" * 60)

    client = RouterClient()

    try:

        # -----------------------------------------
        # 1. Collect
        # -----------------------------------------

        xml_data = client.get_network_activity()

        # -----------------------------------------
        # 2. Parse
        # -----------------------------------------

        records = parse_network_activity(
            xml_data
        )

        print(
            f"[INFO] Received {len(records)} router record(s)."
        )

        if not records:

            print(
                "[INFO] No router records found."
            )

            return

        # -----------------------------------------
        # 3. Normalize
        # -----------------------------------------

        normalized_records = [
            normalize_network_activity(record)
            for record in records
        ]

        # -----------------------------------------
        # 4. Detect changes
        # -----------------------------------------

        new_records, updated_records = detect_changes(
            normalized_records
        )

        records_to_send = (
            new_records +
            updated_records
        )

        print(
            f"[STATE] New: {len(new_records)}"
        )

        print(
            f"[STATE] Updated: {len(updated_records)}"
        )

        print(
            f"[SEND] Total: {len(records_to_send)}"
        )

        # -----------------------------------------
        # 5. Send
        # -----------------------------------------

        for record in records_to_send:

            log = format_router_log(
                record
            )

            event_id = log["event_id"]

            print(
                f"[SEND] Sending event {event_id}"
            )

            try:

                response = send_to_agent(
                    log
                )

                # ---------------------------------
                # 6. Commit state ONLY after
                #    successful delivery
                # ---------------------------------

                commit_record(
                    record
                )

                print(
                    f"[STATE] Position saved for "
                    f"{event_id}"
                )

            except Exception as exc:

                print(
                    f"[ERROR] Delivery failed for "
                    f"{event_id}: {exc}"
                )

                print(
                    "[STATE] Position NOT saved."
                )

                print(
                    "[ERROR] Stopping current batch "
                    "so the event can be retried."
                )

                break

    except Exception as exc:

        print(
            f"[ERROR] Collection cycle failed: {exc}"
        )


def main():

    print(
        "[START] MTN HomeBox Router Log Collector"
    )

    print(
        f"[CONFIG] Poll interval: "
        f"{POLL_INTERVAL} seconds"
    )

    while True:

        collect_once()

        print(
            f"[WAIT] Sleeping for "
            f"{POLL_INTERVAL} seconds..."
        )

        time.sleep(
            POLL_INTERVAL
        )


if __name__ == "__main__":
    main()