from typing import Final
from . import Scanner, Options
from ..model import Date, File


# PNG IEND chunk
PNG_IEND: Final = b"\x00\x00\x00\x00\x49\x45\x4e\x44\xae\x42\x60\x82"


class ScanPngEof(Scanner):
    """Extract data embeded in PNG files.

    This scanner extracts data that is inserted past the PNG file end
    """

    def scan(self, data: bytes, file: File, options: Options, expire_at: Date) -> None:
        # A normal PNG file should end with the IEND chunk
        if data.endswith(PNG_IEND):
            self.add_flag("no_trailer")
        else:
            # Locate the first occurance of the IEND chunk, the end of PNG file
            if -1 != (start := data.find(PNG_IEND)):
                start += len(PNG_IEND)
                self.event["trailer_start"] = start
                self.emit_file(
                    data[start:],
                    name=":png-trailer",
                )
            else:
                self.add_flag("no_iend_chunk")
