from router.client import RouterClient
from router.parser import parse_network_activity
from router.normalizer import normalize_network_activity

import json


def main():

    client = RouterClient()

    xml_data = client.get_network_activity()

    records = parse_network_activity(xml_data)

    print(f"[INFO] Parsed {len(records)} record(s)\n")

    for record in records:

        normalized = normalize_network_activity(
            record
        )

        print(
            json.dumps(
                normalized,
                indent=4
            )
        )

        print("-" * 60)


if __name__ == "__main__":
    main()