from router.client import RouterClient
from router.parser import parse_network_activity
from router.normalizer import normalize_network_activity

from router.state import detect_changes

from common.formatter import format_router_log
from common.sender import send_to_agent


def main():

    client = RouterClient()

    print("[INFO] Collecting router activity...")

    xml_data = client.get_network_activity()

    records = parse_network_activity(
        xml_data
    )

    normalized_records = [
        normalize_network_activity(record)
        for record in records
    ]

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

    for record in records_to_send:

        log = format_router_log(record)

        print(
            f"[SEND] Sending event "
            f"{log['event_id']}"
        )

        response = send_to_agent(log)

        print(
            f"[SIEM] Status: "
            f"{response.status_code}"
        )

        print(
            f"[SIEM] Response: "
            f"{response.text}"
        )


if __name__ == "__main__":
    main()