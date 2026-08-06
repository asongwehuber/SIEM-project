import win32evtlog

from agent.config import Config
from agent.xml_parser import XMLParser


class WindowsEventLog:

    @staticmethod
    def read_security(last_record_number=0):
        """
        Read all Windows Security events newer than
        last_record_number using the modern
        Windows Event Log API.
        """

        handle = win32evtlog.EvtQuery(
            "Security",
            win32evtlog.EvtQueryReverseDirection,
            "*"
        )

        parsed_events = []

        while True:

            events = win32evtlog.EvtNext(
                handle,
                50
            )

            if not events:
                break

            stop = False

            for event in events:

                xml = win32evtlog.EvtRender(
                    event,
                    win32evtlog.EvtRenderEventXml
                )

                parsed = XMLParser.parse(xml)

                # FIRST: Stop once we reach the last processed record
                if parsed["record_number"] <= last_record_number:
                    stop = True
                    break

                # DEBUG: Accept every Security event
                parsed_events.append(parsed)

            if stop:
                break

        parsed_events.reverse()

        return parsed_events