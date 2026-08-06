import xml.etree.ElementTree as ET


class XMLParser:

    @staticmethod
    def parse(xml):

        root = ET.fromstring(xml)

        ns = {
            "e": "http://schemas.microsoft.com/win/2004/08/events/event"
        }

        system = root.find(
            "e:System",
            ns
        )

        event_data = root.find(
            "e:EventData",
            ns
        )

        data = {}

        if event_data is not None:

            for item in event_data.findall(
                "e:Data",
                ns
            ):

                name = item.attrib.get("Name")

                value = item.text

                data[name] = value

        provider = system.find(
            "e:Provider",
            ns
        )

        event_id = int(
            system.find(
                "e:EventID",
                ns
            ).text
        )

        record_number = int(
            system.find(
                "e:EventRecordID",
                ns
            ).text
        )

        computer = system.find(
            "e:Computer",
            ns
        ).text

        time_created = system.find(
            "e:TimeCreated",
            ns
        ).attrib.get(
            "SystemTime"
        )

        level_node = system.find(
            "e:Level",
            ns
        )

        level = (
            int(level_node.text)
            if level_node is not None
            else 0
        )

        return {

            "event_id": event_id,

            "record_number": record_number,

            "source": (
                provider.attrib.get("Name")
                if provider is not None
                else "Unknown"
            ),

            "computer": computer,

            "time_generated": time_created,

            "level": level,

            "strings": list(data.values()),

            "event_data": data

        }