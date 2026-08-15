from datetime import datetime, timezone




def parse_router_time(value):
    """
    Convert the MTN HomeBox timestamp into the timestamp
    format expected by the SIEM Agent:

        DD/MM/YYYY HH:MM:SS

    Empty timestamps and the router's 1970 sentinel become None.
    """

    if not value:
        return None

    value = value.strip()

    # MTN firmware uses this as a sentinel/default timestamp.
    if value.startswith("Thu Jan  1 01:00:"):
        return None

    try:
        dt = datetime.strptime(
            value,
            "%a %b %d %H:%M:%S %Y"
        )

        return dt.strftime(
            "%d/%m/%Y %H:%M:%S"
        )

    except ValueError:
        return None


def normalize_network_activity(record):
    """
    Convert one MTN HomeBox network activity record
    into a SIEM-friendly event.
    """

    start_time = parse_router_time(
        record.get("start_time", "")
    )

    end_time = parse_router_time(
        record.get("end_time", "")
    )

    # Active session if there is a start time but no end time.
    status = (
        "active"
        if start_time and not end_time
        else "closed"
    )

    return {
        "source": "mtn_homebox",
        "event_type": "network_activity",
        "event_category": "router_access",

        "timestamp": start_time or end_time,

        "message": (
            f"Router network session "
            f"{status}: "
            f"{record.get('ipv4addr', '')}"
        ),

        "details": {
            "pdp_name": record.get("pdp_name"),
            "cid": record.get("cid"),
            "wan_index": record.get("wan_index"),
            "index": record.get("index"),
            "start_time": start_time,
            "end_time": end_time,
            "ip_type": record.get("ip_type"),
            "ipv4addr": record.get("ipv4addr"),
            "ipv6addr": record.get("ipv6addr"),
            "status": status,
        }
    }