from agent.config import Config

from agent.bookmark_reader import BookmarkReader

from agent.event_filter import EventFilter

from agent.json_formatter import create_log

from agent.sender import Sender


class WindowsCollector:

    def __init__(self):

        self.reader = BookmarkReader()

    def collect(self):
        """
        Read Windows Security events
        using a persistent BookmarkReader.
        """

        events = self.reader.read()

        print(f"[INFO] Found {len(events)} event(s).")

        for event, handle in events:

            if not EventFilter.should_process(event):
                continue

            log = create_log(

                generator_id=Config.COLLECTOR_ID,

                hostname=Config.HOSTNAME,

                message=event

            )

            response = Sender.post(
                "receive-log",
                log
            )

            if response is None:

                print(
                    f"[ERROR] Unable to reach SIEM Agent for Event ID {event['event_id']}"
                )
                continue

            if response.status_code == 200:

                self.reader.acknowledge(handle)

                print(
                    f"[BOOKMARK] Updated after Event ID {event['event_id']}"
                )

            else:

                print(
                    f"[ERROR] SIEM Agent returned {response.status_code} for Event ID {event['event_id']}"
                )