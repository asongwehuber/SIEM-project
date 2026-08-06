import os

BOOKMARK_FILE = os.path.join(
    os.path.dirname(__file__),
    "bookmark.xml"
)


def bookmark_exists():
    """
    Check whether a bookmark file already exists.
    """

    return os.path.exists(
        BOOKMARK_FILE
    )


def load_bookmark():
    """
    Load the saved bookmark XML.

    Returns:
        str | None
    """

    if not bookmark_exists():
        return None

    try:

        with open(
            BOOKMARK_FILE,
            "r",
            encoding="utf-8"
        ) as f:

            bookmark = f.read().strip()

            if bookmark:
                return bookmark

    except Exception:
        pass

    return None


def save_bookmark(bookmark_xml):
    """
    Save the current bookmark XML.
    """

    with open(
        BOOKMARK_FILE,
        "w",
        encoding="utf-8"
    ) as f:

        f.write(bookmark_xml)