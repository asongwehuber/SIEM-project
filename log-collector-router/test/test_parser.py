from router.client import RouterClient
from router.parser import parse_network_activity


def main():

    client = RouterClient()

    print("[INFO] Getting router activity...")

    xml_data = client.get_network_activity()

    records = parse_network_activity(xml_data)

    print(f"\n[INFO] Parsed {len(records)} record(s)\n")

    for number, record in enumerate(records, start=1):

        print(f"--- Record {number} ---")

        for key, value in record.items():
            print(f"{key}: {value}")

        print()


if __name__ == "__main__":
    main()