from agent.config import Config


class EventFilter:
    """
    Responsible for deciding whether a Windows event
    should be processed by the collector.
    """

    @staticmethod
    def should_process(event):

        event_id = event.get("event_id")

        return event_id in Config.WINDOWS_EVENT_IDS