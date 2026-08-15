from router.client import RouterClient
from router.parser import parse_network_activity
from router.normalizer import normalize_network_activity
from router.state import detect_changes


def main():

    client = RouterClient()

    xml_data = client.get_network_activity()

    records = parse_network_activity(xml_data)

    normalized_records = [
        normalize_network_activity(record)
        for record in records
    ]

    new_records, updated_records = detect_changes(
        normalized_records
    )

    print(
        f"[STATE] New records: "
        f"{len(new_records)}"
    )

    print(
        f"[STATE] Updated records: "
        f"{len(updated_records)}"
    )

    for record in new_records:
        print("\n[NEW]")
        print(record)

    for record in updated_records:
        print("\n[UPDATED]")
        print(record)


if __name__ == "__main__":
    main()