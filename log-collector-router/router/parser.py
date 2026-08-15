import xml.etree.ElementTree as ET
from datetime import datetime


def parse_network_activity(xml_data):
    """
    Parse MTN HomeBox network_activity XML.

    Returns a list of normalized dictionaries.
    """

    root = ET.fromstring(xml_data)

    records = []

    network_activity = root.find("network_activity")

    if network_activity is None:
        return records

    for item in network_activity.findall("Item"):

        # Each Item contains Item0, Item1, etc.
        record_element = None

        for child in item:
            record_element = child
            break

        if record_element is None:
            continue

        def get_text(name):
            element = record_element.find(name)

            if element is None:
                return ""

            return (element.text or "").strip()

        start_time = get_text("start_time")
        end_time = get_text("end_time")

        records.append({
            "index": get_text("index"),
            "pdp_name": get_text("pdp_name"),
            "cid": get_text("cid"),
            "wan_index": get_text("wan_index"),
            "start_time": start_time,
            "end_time": end_time,
            "ip_type": get_text("ip_type"),
            "ipv4addr": get_text("ipv4addr"),
            "ipv6addr": get_text("ipv6addr"),
        })

    return records