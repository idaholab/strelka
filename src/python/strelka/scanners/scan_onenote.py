# Authors: Ryan Borre, Paul Hutelmyer

import binascii
import re

from . import Options, Scanner
from ..model import Date, File
from ..cstructs.onenote import FileDataStoreObject


# This is the binary string we're searching for in the data.
ONE_NOTE_GUID = binascii.unhexlify(b"e716e3bd65261145a4c48d4d0b7a9eac")


class ScanOnenote(Scanner):
    """Extracts embedded files in OneNote files."""

    def scan(self, data: bytes, file: File, options: Options, expire_at: Date) -> None:
        self.event.update(
            {
                "total": {
                    "files": 0,
                    "extracted": 0,
                },
            }
        )

        # search for the header GUID as a byte sequence within the data
        for match in re.finditer(ONE_NOTE_GUID, data):
            self.event["total"]["files"] += 1
            offset = match.span(0)[0]
            try:
                # try to parse the object at that offset
                obj = FileDataStoreObject.parse(data[offset:])
            except Exception:
                self.add_flag("onenote_file_parse_failure")
            else:
                if obj is None:
                    continue
                self.emit_file(
                    obj.fileData,
                    name=f":file_{offset}",
                    unique_key=(offset,),
                )

        # save the number of children we successfully extracted
        self.event["total"]["extracted"] = self.emitted_files
