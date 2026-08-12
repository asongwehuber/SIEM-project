import os
import time


class LogReader:

    def __init__(
        self,
        filepath,
        poll_interval=1,
        start_position=None
    ):
        self.filepath = filepath
        self.poll_interval = poll_interval
        self.start_position = start_position

        self.file = None
        self.current_inode = None
        self.current_position = 0

    def open(self, start_position=None):

        self.file = open(
            self.filepath,
            "r",
            encoding="utf-8",
            errors="replace"
        )

        self.current_inode = os.fstat(
            self.file.fileno()
        ).st_ino

        # Explicit position takes priority.
        if start_position is not None:

            self.file.seek(start_position)

            self.current_position = (
                start_position
            )

            return

        # Restore saved position.
        if self.start_position is not None:

            file_size = os.fstat(
                self.file.fileno()
            ).st_size

            if self.start_position <= file_size:

                self.file.seek(
                    self.start_position
                )

                self.current_position = (
                    self.start_position
                )

            else:

                print(
                    "[INFO] Saved position is beyond "
                    "current log size."
                )

                print(
                    "[INFO] Log was likely rotated "
                    "or truncated."
                )

                self.file.seek(0)

                self.current_position = 0

        else:

            # First run:
            # start at the current end so we don't
            # replay the existing auth.log history.

            self.file.seek(
                0,
                os.SEEK_END
            )

            self.current_position = (
                self.file.tell()
            )

    def seek_end(self):

        self.file.seek(
            0,
            os.SEEK_END
        )

        self.current_position = (
            self.file.tell()
        )

    def check_rotation(self):

        try:

            stat = os.stat(
                self.filepath
            )

        except FileNotFoundError:

            return False

        new_inode = stat.st_ino
        new_size = stat.st_size

        # ==========================================
        # NEW INODE
        # ==========================================

        if new_inode != self.current_inode:

            print(
                "[INFO] Log rotation detected "
                "(inode changed)."
            )

            self.file.close()

            self.file = None

            self.start_position = 0

            self.open(
                start_position=0
            )

            return True

        # ==========================================
        # SAME INODE BUT FILE SHRANK
        # ==========================================

        if new_size < self.current_position:

            print(
                "[INFO] Log truncation detected."
            )

            print(
                "[INFO] Current position: "
                f"{self.current_position}"
            )

            print(
                "[INFO] New file size: "
                f"{new_size}"
            )

            self.file.seek(0)

            self.current_position = 0

            self.start_position = 0

            return True

        return False

    def get_position(self):

        return self.current_position

    def get_inode(self):

        return self.current_inode

    def follow(self):

        if self.file is None:

            self.open()

        while True:

            self.check_rotation()

            line = self.file.readline()

            if line:

                self.current_position = (
                    self.file.tell()
                )

                yield line.rstrip("\n")

            else:

                time.sleep(
                    self.poll_interval
                )