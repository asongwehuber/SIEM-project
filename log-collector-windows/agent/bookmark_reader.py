import win32evtlog

from agent.config import Config
from agent.xml_parser import XMLParser
from agent.bookmark import (
    load_bookmark,
    save_bookmark
)


class BookmarkReader:

    def __init__(self):

        bookmark_xml = load_bookmark()

        self.query = win32evtlog.EvtQuery(
            "Security",
            win32evtlog.EvtQueryReverseDirection,
            "*"
        )

        if bookmark_xml:

            print("[BOOKMARK] Existing bookmark found.")

            self.bookmark = win32evtlog.EvtCreateBookmark(
                bookmark_xml
            )

            win32evtlog.EvtSeek(
                self.query,
                1,
                win32evtlog.EvtSeekRelativeToBookmark,
                self.bookmark,
                0
            )

        else:

            print("[BOOKMARK] No bookmark found.")

            self.bookmark = win32evtlog.EvtCreateBookmark(None)

            # Consume the newest event only
            handles = win32evtlog.EvtNext(
                self.query,
                1
            )

            if handles:

                win32evtlog.EvtUpdateBookmark(
                    self.bookmark,
                    handles[0]
                )

                bookmark_xml = win32evtlog.EvtRender(
                    self.bookmark,
                    win32evtlog.EvtRenderBookmark
                )

                save_bookmark(bookmark_xml)

                print("[BOOKMARK] Initial bookmark created.")


    def read(self):

        events = []

        print(f"[QUERY ID] {id(self.query)}")

        handles = win32evtlog.EvtNext(
            self.query,
            Config.MAX_EVENTS_PER_READ
        )

        print(f"[HANDLES] {len(handles) if handles else 0}")

        if not handles:
            return events

        for handle in handles:

            xml = win32evtlog.EvtRender(
                handle,
                win32evtlog.EvtRenderEventXml
            )

            parsed = XMLParser.parse(xml)

            print(
                f"[FIRST RECORD] {parsed['record_number']}"
            )

            events.append(
                (
                    parsed,
                    handle
                )
            )

        events.reverse()

        return events







        

        for handle in handles:

            xml = win32evtlog.EvtRender(
                handle,
                win32evtlog.EvtRenderEventXml
            )

            parsed = XMLParser.parse(xml)

            events.append(
                (
                    parsed,
                    handle
                )
            )

        events.reverse()

        return events

    def acknowledge(
        self,
        handle
    ):

        win32evtlog.EvtUpdateBookmark(
            self.bookmark,
            handle
        )

        bookmark_xml = win32evtlog.EvtRender(
            self.bookmark,
            win32evtlog.EvtRenderBookmark
        )

        save_bookmark(
            bookmark_xml
        )