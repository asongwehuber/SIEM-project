import win32evtlog


class WindowsEventLog:

    @staticmethod
    def read_security(last_record_number=0):
        """
        Read all Security events newer than
        last_record_number.
        """

        server = "localhost"

        log_type = "Security"

        handle = win32evtlog.OpenEventLog(
            server,
            log_type
        )

        flags = (

            win32evtlog.EVENTLOG_BACKWARDS_READ |

            win32evtlog.EVENTLOG_SEQUENTIAL_READ

        )

        events = []

        while True:

            records = win32evtlog.ReadEventLog(
                handle,
                flags,
                0
            )
            print(len(records))

            if not records:

                break

            for event in records:

                record_number = event.RecordNumber

                if record_number <= last_record_number:

                    win32evtlog.CloseEventLog(handle)

                    events.reverse()

                    return events

                events.append({

                    "event_id":
                        event.EventID & 0xFFFF,

                    "record_number":
                        record_number,

                    "source":
                        event.SourceName,

                    "computer":
                        event.ComputerName,

                    "time_generated":
                        str(event.TimeGenerated),

                    "event_type":
                        event.EventType,

                    "strings":
                        list(event.StringInserts)
                        if event.StringInserts
                        else []

                })

        win32evtlog.CloseEventLog(handle)

        events.reverse()

        return events