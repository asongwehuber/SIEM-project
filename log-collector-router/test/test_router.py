from router.client import RouterClient


def main():
    client = RouterClient()

    print("[INFO] Starting MTN HomeBox authentication...")

    try:
        xml = client.get_network_activity()

        print("\n[INFO] Network activity response:")
        print(xml)

    except Exception as exc:
        print(
            f"[ERROR] Router collector test failed: {exc}"
        )


if __name__ == "__main__":
    main()